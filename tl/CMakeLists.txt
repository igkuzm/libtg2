cmake_minimum_required(VERSION 3.0)

set(TARGET libtl)

file(GLOB RESOURCE_FILES "*.h" "../essential/*.h")
set(TARGET_SOURCES 
	libtl.c methods.c  deserialize_table.c
	../essential/buf.c 
	../essential/serialize.c
	../essential/deserialize.c
	../essential/gunzip.c	
)

add_library(${TARGET} STATIC ${TARGET_SOURCES} ${RESOURCE_FILES})
