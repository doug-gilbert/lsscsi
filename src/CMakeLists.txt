
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
    MESSAGE( STATUS ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( STATUS ">> Trying to build a static executable" )
    add_definitions ( -static )
    target_link_libraries(lsscsi -static)
endif ( BUILD_SHARED_LIBS )


install(TARGETS lsscsi RUNTIME DESTINATION bin)
install(TARGETS ls_name_value_rd RUNTIME DESTINATION bin)

