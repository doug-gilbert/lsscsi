cmake_minimum_required ( VERSION 3.10 )

project(lsscsi VERSION 0.32.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1) 
# Example: VERSION 0.91.9 is pre-release of 0.92.0

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)

include ( CheckIncludeFile )
CHECK_INCLUDE_FILE( "linux/nvme_ioctl.h" NVME_PRESENT )

if ( NVME_PRESENT )
  add_definitions ( -DHAVE_NVME )
endif ( NVME_PRESENT )

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
SET(CPACK_RPM_PACKAGE_DESCRIPTION "List SCSI and associated storage devices, one device per line")
SET(CPACK_RPM_PACKAGE_LICENSE "BSD-2-clause")
SET(CPACK_RPM_PACKAGE_VENDOR "Douglas Gilbert")

include(CPack)
include(CTest)
