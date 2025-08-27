cmake_minimum_required(VERSION 3.0)

set(TARGET tl)

file(GLOB RESOURCE_FILES "*.h" "../essential/*.h")
set(TARGET_SOURCES 
	libtl.c 
	deserialize_table.c 
	methods.c  
	free.c
	../essential/gunzip.c	
	../essential/buf.c 
	../essential/serialize.c
	../essential/deserialize.c
)

add_library(${TARGET} ${TARGET_SOURCES} ${RESOURCE_FILES})
target_link_libraries(${TARGET} z)
