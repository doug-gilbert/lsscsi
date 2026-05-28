cmake_minimum_required ( VERSION 3.10 )

project(lsscsi VERSION 0.32.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1)
# Example: VERSION 0.91.9 is pre-release of 0.92.0

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g" )

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)
option ( ENABLE_DEBUG "Turn on debugging (extra warnings)" OFF)
option ( DISABLE_NVME_SUPP "Remove all or most NVMe code" OFF)
option ( DISABLE_FAST_LEBE "Use generic little-endian/big-endian code instead" OFF)

include(GNUInstallDirs)

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
SET(CPACK_DEBIAN_PACKAGE_DEPENDS " ")

SET(CPACK_RPM_PACKAGE_DESCRIPTION "Uses information provided by the sysfs pseudo file system in Linux kernel 2.6 series to list SCSI devices or all SCSI hosts. Includes a 'classic' option to mimic the output of 'cat /proc/scsi/scsi' that has been widely used prior to the lk 2.6 series.")
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
