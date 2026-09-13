
MESSAGE( STATUS ">> Entering src/CMakeLists.txt" )

set ( sourcefiles
	lsscsi.c
	sg_json_builder.c
	sg_json.c
	sg_pr2serr.c
)

set ( headerfiles
	sg_json.h
	sg_json_builder.h
	sg_pr2serr.h
	sg_unaligned.h
)

add_executable (lsscsi ${sourcefiles} ${headerfiles} )
add_executable (ls_name_value_rd ls_name_value_rd.c )

l_set_compile_options( lsscsi )
l_set_compile_options( ls_name_value_rd )

target_include_directories(lsscsi PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(lsscsi PRIVATE ${CMAKE_BINARY_DIR})

target_include_directories(ls_name_value_rd PRIVATE ${CMAKE_BINARY_DIR})

if ( BUILD_SHARED_LIBS )
    MESSAGE( STATUS ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( STATUS ">> Trying to build a static executable" )
    add_definitions ( -static )
    target_link_libraries(lsscsi -static)
endif ( BUILD_SHARED_LIBS )


install(TARGETS lsscsi RUNTIME DESTINATION bin)
install(TARGETS ls_name_value_rd RUNTIME DESTINATION bin)

