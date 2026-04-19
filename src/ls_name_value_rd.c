
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <getopt.h>     /* non-standard, trips up AIX */

/*
 * This is a helper C function for the ls_name_value script that has its
 * own manpage. Inside a script it is difficult to try and read the contents
 * of an arbitrary filename. For example it may not be a regular file, it
 * report as a regular file but hangs (e.g. /proc/kmsg), it is regular but
 * contains binary or the (null) character, plus several other corner cases.
 * The Linux timeout command takes 100 milliseconds even when the contents is
 * provided immediately, making the use of timeout unsuitable.
 * So this command does the "hard work" in C. The idea is not to give an
 * exact rendering of the contents of a file, but give a useful single line
 * overview. Null characters ('\0') are squashed, ASCII control characters
 * and 0x7f are replaced by ' ' while any regular file contents (read up to
 * <num_bytes> bytes) with no top bits set are output to stdout. If the top
 * bit is set in any byte then the output is: <contains non-ASCII chars> .
 * As a bonus, if the top bit is set a check is made for a UTF-8 sequence
 * and if only valid UTF-8 codepoints are found <might be UTF-8> is output.
 * UTF-8 has a corner case where a codepoint is truncated by <num_bytes>:
 * if that happens on the first UTF-8 sequence then the output is
 * <contains non-ASCII chars>.
 * Output goes to stdout with no trailing \n, only errors associated with
 * the command line syntax cause error messages to be sent to stderr.
 *
 * The command line is shown in the usage() and show_help() functions below.
 */

static const char * version_str = "0.33  20260418 [svn: r206]";

static const char * my_name = "ls_name_value_rd";

static int num_retries = 100;    /* 10 milliseconds per try */

#define DEF_BUFF_SZ 256
#define DEF_NUM_BYTES 80


static struct option long_options[] = {
    {"empty", no_argument, 0, 'e'},
    {"help", no_argument, 0, 'h'},
    {"utf8", no_argument, 0, 'u'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
};

static void
usage()
{
    fprintf(stderr, "Usage: %s [-e] [-h] [-u] [-v] [-V] <filename> "
            "[<num_bytes>]\n", my_name);
}

static void
show_help()
{
    usage();
    fprintf(stderr, "\n    -e | --empty    output <empty> if contents "
            "are empty; use twice to\n");
    fprintf(stderr, "                    additionally output <LF> "
            "instead of contents='\\n'\n");
    fprintf(stderr, "    -h | --help     show this help message then "
            "exit\n");
    fprintf(stderr, "    -u | --utf8     if contents passes utf8 test, "
            "output it\n");
    fprintf(stderr, "    -v | --verbose  increase debug output\n");
    fprintf(stderr, "    -V | --version  show version string then exit\n");
    fprintf(stderr, "    <filename>      name of file to read\n");
    fprintf(stderr, "    <num_bytes>     maximum number of bytes to ");
    fprintf(stderr, "read [def: %d]\n\n", DEF_NUM_BYTES);
    fprintf(stderr, "Read <num_bytes> from <filename> skipping any null ");
    fprintf(stderr, "characters. Any\nbytes with the top bit set will ");
    fprintf(stderr, "cause <contains non-ASCII chars>\nto be output to ");
    fprintf(stderr, "stdout. Empty files (and those with null chars\nup ");
    fprintf(stderr, "to their EOF) output <empty>. Output to stdout does ");
    fprintf(stderr, "not\nhave a trailing \\n .\n");
}

/* Check if a sequence of bytes is valid UTF-8; if so return true and if
 * skip_nump is NON-NULL then write the number of bytes it stepped over. A
 * sequence of bytes for a UTF-8 codepoint may be truncated by sz . Return
 * true in that case if it was valid to that point. Returns false
 * if sequence is invalid, if skip_nump is NON-NULL write the number of
 * bytes stepped over at the point of failure. If skip_nump is NON-NULL
 * then *skip_nump is always >= 1 even if sz<=0 or s[0]=='\0' in which cases
 * true is returned. */
bool
utf8_valid_seq(const char *s, size_t sz, int * skip_nump)
{
    if ((sz > 0) && s[0]) {
        unsigned char c = (unsigned char)s[0];
        size_t len, j;

        if (c < 0x80)
            len = 1;
        else if ((c >> 5) == 0x6)
            len = 2;
        else if ((c >> 4) == 0xE)
            len = 3;
        else if ((c >> 3) == 0x1E)
            len = 4;
        else {
            if (skip_nump)
                *skip_nump = 1;
            return false;
        }

        for (j = 1; (j < len) && (j < sz); j++)
        {
            if ((s[j] & 0xC0) != 0x80) {
                if (skip_nump)
                    *skip_nump = j;
                return false;
            }
        }
        if (skip_nump)
            *skip_nump = j;
    } else if (skip_nump)
        *skip_nump = 1;
    return true;
}

int
main(int argc, char * argv[])
{
    int res, c, fd, off, len, b1len, k, j;
    int empty = 0;
    int num_bytes = DEF_NUM_BYTES;
    int utf8 = 0;
    int verbose = 0;
    int err = 0;
    int skip = 0;
    int num_utf8_codepoi = 0;
    int read_einval = 0;
    bool reg_file = false;
    bool non_ascii = false;
    bool incomplete_utf8 = false;
    bool not_retry = false;
    const char * fn = NULL;
    const char * num_bytes_str = NULL;
    char b1[DEF_BUFF_SZ + 2];
    char b2[DEF_BUFF_SZ + 2];
    char * b1p = b1;
    char * b2p = b2;
    struct stat st;
    /* setup duration for 10 milliseconds per EAGAIN from read() */
    struct timespec duration = { 0, 10 * 1000 * 1000 /* ns */};

    while (1) {
        c = getopt_long(argc, argv, "ehuvV", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'e':
            ++empty;
            break;
        case 'h':
            show_help();
            return 0;
        case 'u':
            ++utf8;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "%s version: %s\n", my_name, version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code: 0x%02x\n", c);
            usage();
            return EINVAL;

        }
    }
    while (optind < argc) {
        const char * avp = argv[optind];
        bool ok = true;

        if (NULL == fn) {
            fn = avp;
            optind++;
        } else if (NULL == num_bytes_str) {
            num_bytes_str = avp;
            optind++;
        } else if (optind < argc) {
            do {
                if (strlen(avp) > 0) {
                    ok = false;
                    fprintf(stderr, "Unexpected extra argument: %s\n", avp);
                } else if (verbose > 3 )
                    fprintf(stderr, "Empty command line argument at "
                            "optind=%d\n", optind);
                if (++optind >= argc)
                    break;
                avp = argv[optind];
            } while (true);
            if (! ok) {
                fprintf(stderr, "\n");
                usage();
                return EINVAL;
            }
        }
    }

    if (num_bytes_str) {
        if (1 != sscanf(num_bytes_str, "%d", &num_bytes)) {
            fprintf(stderr, "%s: bad <num_bytes>\n\n", my_name);
            usage();
            return EINVAL;
        }
        if (num_bytes < 0) {
            fprintf(stderr, "%s: negative <num_bytes>\n\n", my_name);
            usage();
            return EINVAL;
        }
    }
    if (NULL == fn) {
        fprintf(stderr, "%s: filename missing\n\n", my_name);
        usage();
        return EXDEV;  /* arbitrary error code for internal error */
    }
    if (num_bytes > DEF_BUFF_SZ) {
        b1p = malloc(num_bytes + 2);
        b2p = malloc(num_bytes + 2);
        if ((NULL == b1p) || (NULL == b2p)) {
            fprintf(stderr, "%s: out of memory\n", my_name);
            if (b1p)
                free(b1p);
            if (b2p)
                free(b2p);
            return ENOMEM;
        }
    }
    if (verbose > 0)
        fprintf(stderr, "filename: %s, num_bytes=%d, empty=%d, "
                "verbose=%d\n", fn, num_bytes, empty, verbose);

    /* Note; O_NONBLOCK that leads to EAGAIN errors on the later read()s */
    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        err = errno;
        if (verbose > 2)
            fprintf(stderr, "open(): errno=%d\n", err);
        if (ENOENT == err)
            printf("<not found>");
        else if (EACCES == err) {
            if (0 == access(fn, W_OK))
                printf("<write only>");
            else
                printf("<cannot access>");
        } else if (EPERM == err) {
            if (verbose > 0)
                fprintf(stderr, "<open: operation not permitted>");
            printf("<operation not permitted>");
        } else if (EINTR == err) {
            if (verbose > 0)
                fprintf(stderr, "<open: interrupted>");
            printf("<interrupted>");
        } else if (EIO == err) {
            if (verbose > 0)
                fprintf(stderr, "<open: IO error>");
            printf("<IO error>");
        } else if (ELOOP == err)
            printf("<too many symlinks>");
        else if (EINVAL == err) {
            if (verbose > 0)
                fprintf(stderr, "<open: EINVAL>");
            printf("<invalid argument>");
            /* printf("<bad character in filename>"); */
        } else
            printf("<open() errno=%d>", err);
        err = 0;
        goto cleanup;
    }
    if (fstat(fd, &st) < 0) {
        err = errno;

        if (verbose > 2)
            fprintf(stderr, "fstat(): errno=%d\n", err);
        if (EBADF == err) {
            if (verbose > 0)
                fprintf(stderr, "<fstat() bad file descriptor>");
            err = 0;
            fd = -1;
            goto cleanup;
        } else {
            if (verbose > 0)
                fprintf(stderr, "<fstat() errno=%d>", err);
            printf("<fstat() errno=%d>", err);
            err = 0;
            goto cleanup;
        }
    }
    switch (st.st_mode & S_IFMT) {
    case S_IFREG:
        reg_file = true;
        break;
    case S_IFBLK:
        printf("<block device>");
        break;
    case S_IFCHR:
        printf("<char device>");
        break;
    case S_IFDIR:
        printf("<directory>");
        break;
    case S_IFIFO:
        printf("<named pipe>");         /* FIFO/pipe */
        break;
    case S_IFLNK:
        printf("<symlink>");            /* shouldn't happen */
        break;
    case S_IFSOCK:
        printf("<socket>");
        break;
    default:
        printf("<fstat: unknown type>");
        break;
    }
    if (! reg_file)
        goto cleanup;

    for (len = 0, off = 0, k = 0; k < num_retries; not_retry ? k : ++k) {
        err = 0;
        not_retry = false;
        /* this read() should be fast due to O_NONBLOCK */
        res = read(fd, b1p + off, num_bytes - off);
        if (res > 0) {
            len += res;
            if (len >= num_bytes)
                break;
            off += res;
            not_retry = true;
        } else if (res == 0)
            break;
        else {
            err = errno;
            if (EAGAIN == err) {
                if (verbose > 3)
                    fprintf(stderr, "read: EAGAIN\n");
                nanosleep(&duration, NULL);     /* 10 ms */
                err = 0;
                continue;
            }
            if (verbose > 2)
                fprintf(stderr, "read(): errno=%d\n", err);
            if (EBADF == err)
                printf("<read() bad file descriptor>");
            else if (EINTR == err)
                printf("<read interrupted>");
            else if (EIO == err)
                printf("<IO error>");
            else if (EINVAL == err) {   /* sysfs special, treat like empty */
                ++read_einval;
                break;
            } else
                printf("<read() errno=%d>", err);
            err = 0;
            goto cleanup;
        }
    }           /* end of for loop over retries */
    b1len = len;
    if (k >= num_retries) {
        err = 0;
        if (len > 0)
            printf("%.*s <timeout>", len, b1p);
        else
            printf("<timeout>");
        goto cleanup;
    }
    for (k = 0, j = 0; k < len; ++k) {
        unsigned char c = *(b1p + k);

        incomplete_utf8 = false;
        if ('\0' == c)
            continue;   /* squash the null character */
        if (c < ' ')
            *(b2p + j++) = ' ';/* replace ASCII control characters with ' ' */
        else if (c > 0x7e) {
            if (0x7f == c)
                *(b2p + j++) = ' ';
            else {      /* top bit set */
                if (utf8_valid_seq(b1p + k, len - k, &skip)) {
                    if (skip >= (len - k))
                        incomplete_utf8 = true;
                    k += (skip - 1);
                    ++num_utf8_codepoi;
                } else {
                    non_ascii = true;
                    break;
                }
            }
        } else
            *(b2p + j++) = c;
    }                   /* end of for loop over input characters */
    if (non_ascii) {
        printf("<contains non-ASCII chars>");
        goto cleanup;
    } else if (num_utf8_codepoi > 0) {
        if ((1 == num_utf8_codepoi) && incomplete_utf8)
            printf("<contains non-ASCII chars>");       /* marginal ... */
        else {
            if (utf8 > 0)
                printf("%.*s", len, b1p);
            else
                printf("<might be UTF-8>");
        }
        goto cleanup;
    }
    len = j;
    if (0 == len) {
        if (empty > 0)
            printf("<empty>");
        else {
            ;   /* printf("");   gives warning */
        }
    } else if ((empty > 1) && (1 == b1len) && (b1p[0] == '\n')) {
        printf("<LF>");
    } else
        printf("%.*s", len, b2p);
    err = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    if (b2p != b2)
        free(b2p);
    if (b1p != b1)
        free(b1p);
    if ((verbose > 0) && (read_einval > 0))
        fprintf(stderr, "%s: read_einval=%d\n", my_name, read_einval);
    return err;
}
