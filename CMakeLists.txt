cmake_minimum_required ( VERSION 3.5 )

project(lsscsi VERSION 0.32.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1) 
# Example: VERSION 0.91.9 is pre-release of 0.92.0

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)

include ( CheckIncludeFile )
CHECK_INCLUDE_FILE( "linux/nvme_ioctl.h" NVME_PRESENT )

if ( NVME_PRESENT )
  add_definitions ( -DHAVE_NVME )
endif ( NVME_PRESENT )

file ( GLOB sourcefiles "src/*.c" )
file ( GLOB headerfiles "src/*.h" )

add_executable (lsscsi ${sourcefiles} ${headerfiles} )

if ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Trying to build a static executable" )
    add_definitions ( -static )
    target_link_libraries(lsscsi -static)
endif ( BUILD_SHARED_LIBS )

install(TARGETS lsscsi RUNTIME DESTINATION bin)

include(GNUInstallDirs)
file(ARCHIVE_CREATE OUTPUT lsscsi.8.gz PATHS doc/lsscsi.8 FORMAT raw COMPRESSION GZip)
install(FILES lsscsi.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT lsscsi_json.8.gz PATHS doc/lsscsi_json.8 FORMAT raw COMPRESSION GZip)
install(FILES lsscsi_json.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "dpg") #required
include(CPack)
