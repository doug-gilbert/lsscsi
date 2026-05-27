
MESSAGE( STATUS ">> Entering doc/CMakeLists.txt" )

file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/lsscsi.8.gz PATHS doc/lsscsi.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/lsscsi.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/lsscsi_json.8.gz PATHS doc/lsscsi_json.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/lsscsi_json.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/ls_name_value.8.gz PATHS doc/ls_name_value.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/ls_name_value.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/ls_name_value_rd.8.gz PATHS doc/ls_name_value_rd.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/ls_name_value_rd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")

