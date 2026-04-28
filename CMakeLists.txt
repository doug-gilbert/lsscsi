cmake_minimum_required ( VERSION 3.10 )

project(lsscsi VERSION 0.32.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1)
# Example: VERSION 0.91.9 is pre-release of 0.92.0

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g" )

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)
option ( ENABLE_DEBUG "Turn on debugging (extra warnings)" OFF)
option ( DISABLE_NVME_SUPP "Remove all or most NVMe code" OFF)
option ( DISABLE_FAST_LEBE "Use generic little-endian/big-endian code instead" OFF)

include ( CheckIncludeFile )
CHECK_INCLUDE_FILE( "linux/nvme_ioctl.h" NVME_PRESENT )
CHECK_INCLUDE_FILE( "byteswap.h" HAVE_BYTESWAP_H )

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

set ( sourcefiles
	src/lsscsi.c
	src/sg_json_builder.c
	src/sg_json.c
	src/sg_pr2serr.c
)

set ( headerfiles
	src/sg_json.h
	src/sg_json_builder.h
	src/sg_pr2serr.h
	src/sg_unaligned.h
)

add_executable (lsscsi ${sourcefiles} ${headerfiles} )
add_executable (ls_name_value_rd src/ls_name_value_rd.c )

target_compile_definitions(lsscsi PRIVATE _LARGEFILE64_SOURCE _FILE_OFFSET_BITS=64)
target_compile_options(lsscsi PRIVATE -Wall -W)
target_include_directories(lsscsi PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_compile_definitions(ls_name_value_rd PRIVATE _LARGEFILE64_SOURCE _FILE_OFFSET_BITS=64)
target_compile_options(ls_name_value_rd PRIVATE -Wall -W)

if ( ENABLE_DEBUG )
  target_compile_definitions(lsscsi PRIVATE DEBUG)
  target_compile_options(lsscsi PRIVATE
    -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op
    -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument
    -Wduplicated-branches -Wjump-misses-init -Wparentheses)
  target_compile_definitions(ls_name_value_rd PRIVATE DEBUG)
  target_compile_options(ls_name_value_rd PRIVATE
    -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op
    -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument
    -Wduplicated-branches -Wjump-misses-init -Wparentheses)
endif ( ENABLE_DEBUG )

if ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Trying to build a static executable" )
    add_definitions ( -static )
    target_link_libraries(lsscsi -static)
endif ( BUILD_SHARED_LIBS )

include(GNUInstallDirs)

install(TARGETS lsscsi RUNTIME DESTINATION bin)
install(TARGETS ls_name_value_rd RUNTIME DESTINATION bin)
file(ARCHIVE_CREATE OUTPUT lsscsi.8.gz PATHS ${CMAKE_SOURCE_DIR}/doc/lsscsi.8 FORMAT raw COMPRESSION GZip)
install(FILES lsscsi.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT lsscsi_json.8.gz PATHS ${CMAKE_SOURCE_DIR}/doc/lsscsi_json.8 FORMAT raw COMPRESSION GZip)
install(FILES lsscsi_json.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT ls_name_value.8.gz PATHS ${CMAKE_SOURCE_DIR}/doc/ls_name_value.8 FORMAT raw COMPRESSION GZip)
install(FILES ls_name_value.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT ls_name_value_rd.8.gz PATHS ${CMAKE_SOURCE_DIR}/doc/ls_name_value_rd.8 FORMAT raw COMPRESSION GZip)
install(FILES ls_name_value_rd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
install(FILES scripts/ls_name_value
	PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
	DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES ChangeLog DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES AUTHORS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES CREDITS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES INSTALL DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES README DESTINATION "${CMAKE_INSTALL_DOCDIR}")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
SET(CPACK_GENERATOR "DEB;RPM")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Douglas Gilbert") #required
SET(CPACK_DEBIAN_PACKAGE_SECTION "admin")
SET(CPACK_RPM_PACKAGE_DESCRIPTION "Uses information provided by the sysfs pseudo file system in Linux kernel 2.6 series to list SCSI devices or all SCSI hosts. Includes a \"classic\" option to mimic the output of \"cat /proc/scsi/scsi\" that has been widely used prior to the lk 2.6 series.")
SET(CPACK_RPM_PACKAGE_LICENSE "GPL-2.0")
SET(CPACK_RPM_PACKAGE_VENDOR "Douglas Gilbert")

include(CPack)
include(CTest)
