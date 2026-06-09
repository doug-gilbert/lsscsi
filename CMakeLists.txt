cmake_minimum_required ( VERSION 3.10 )

project(lsscsi VERSION 0.32.9 LANGUAGES C )
# Use version number: x.y.9 to indicate pre-release of x.(y+1)
# Example: VERSION 0.91.9 is pre-release of 0.92.0

set ( CMAKE_C_STANDARD 11 )
set ( CMAKE_C_STANDARD_REQUIRED ON )
set ( CMAKE_C_EXTENSIONS OFF )
set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -Wall -W -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DHAVE_CONFIG_H" )

string(TIMESTAMP BUILD_TIME "%Y%m%d %H:%M:%S")

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)
option ( ENABLE_DEBUG "Turn on debugging (extra warnings)" OFF)
option ( DISABLE_NVME_SUPP "Remove all or most NVMe code" OFF)
option ( DISABLE_FAST_LEBE "Use generic little-endian/big-endian code instead" OFF)

include(GNUInstallDirs)

include ( CheckIncludeFile )
CHECK_INCLUDE_FILE( "linux/nvme_ioctl.h" NVME_PRESENT )
CHECK_INCLUDE_FILE( "byteswap.h" HAVE_BYTESWAP_H )
CHECK_INCLUDE_FILE( "getopt.h" HAVE_GETOPT_H )    # non-standard but common

include(CheckFunctionExists)
check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)

if ( NVME_PRESENT )
  add_definitions ( -DHAVE_NVME )
endif ( NVME_PRESENT )

if ( HAVE_BYTESWAP_H )
  add_definitions ( -DHAVE_BYTESWAP_H )
endif ( HAVE_BYTESWAP_H )

if ( DISABLE_NVME_SUPP )
  add_definitions ( -DIGNORE_NVME )
endif ( DISABLE_NVME_SUPP )

if ( DISABLE_FAST_LEBE )
  add_definitions ( -DIGNORE_FAST_LEBE )
endif ( DISABLE_FAST_LEBE )

message(STATUS ">> cmake System Name: ${CMAKE_SYSTEM_NAME}")
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS ">> Linux build")
    set(OS_LINUX 1)
    set(SG_LIB_LINUX 1)
    CHECK_INCLUDE_FILE( "linux/major.h" HAVE_LINUX_MAJOR_H )
    CHECK_INCLUDE_FILE( "linux/types.h" HAVE_LINUX_TYPES_H )
    CHECK_INCLUDE_FILE( "linux/bsg.h" HAVE_LINUX_BSG_H )
    CHECK_INCLUDE_FILE( "linux/kdev_t.h" HAVE_LINUX_KDEV_T_H )
    if (HAVE_LINUX_NVME_IOCTL_H)
        set(HAVE_NVME 1)
    endif ()
endif ()

# Locate platform's thread support, and set complier linker flags. See
# /usr/share/doc/cmake-data/html/module/FindThreads.html when
# cmake-doc package is installed.
find_package(Threads)

include(CheckLibraryExists)
check_library_exists(rt clock_gettime "" NEED_RT_LIB)

configure_file( ${CMAKE_SOURCE_DIR}/config.h.in.cmake ${CMAKE_BINARY_DIR}/config.h )

add_subdirectory( src )

add_subdirectory( scripts )

add_subdirectory( doc )

install(FILES ChangeLog DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES AUTHORS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES CREDITS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES INSTALL DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES README DESTINATION "${CMAKE_INSTALL_DOCDIR}")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Douglas Gilbert")
SET(CPACK_DEBIAN_PACKAGE_SECTION "admin")
SET(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Uses the sysfs pseudo file system to list SCSI devices (usually disks but also tape drives). (S)ATA devices, USB memory sticks and NVMe devices are also listed. Some storage types such as SD cards are not listed. Lists a larger variety of devices compared to lsblk.")
SET(CPACK_DEBIAN_PACKAGE_LICENSE "GPL-2.0")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS " ")

SET(CPACK_RPM_PACKAGE_DESCRIPTION "Uses the sysfs pseudo file system to list SCSI devices (usually disks but also tape drives). (S)ATA devices, USB memory sticks and NVMe devices are also listed. Some storage types such as SD cards are not listed. Lists a larger variety of devices compared to lsblk.")
SET(CPACK_RPM_PACKAGE_LICENSE "GPL-2.0")
SET(CPACK_RPM_PACKAGE_VENDOR "Douglas Gilbert")
SET(CPACK_RPM_PACKAGE_DEPENDS " ")

set(CPACK_GENERATOR "")
find_program(DPKG_EXECUTABLE dpkg)
if (DPKG_EXECUTABLE)
    list(APPEND CPACK_GENERATOR "DEB")
endif ()
find_program(RPMBUILD_EXECUTABLE rpmbuild)
if (RPMBUILD_EXECUTABLE)
    list(APPEND CPACK_GENERATOR "RPM")
endif ()

include(CPack)
include(CTest)
