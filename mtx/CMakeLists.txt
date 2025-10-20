cmake_minimum_required(VERSION 3.0)

set(TARGET mtx)

file(GLOB RESOURCE_FILES "include/*.h")
set(TARGET_SOURCES 
	src/aes.c
	src/api.c
	src/app.c
	src/buf.c
	src/cmn.c
	src/crc.c
	src/cry.c
	src/enl.c
	src/hdl.c
	src/hsh.c
	src/log.c
	src/net.c
	src/rfc.c
	src/rsa.c
	src/scl.c
	src/sel.c
	src/sha1.c
	src/sil.c
	src/srl.c
	src/std.c
	src/stk.c
	src/tgt.c
	src/tml.c
	src/trl.c
	src/types.c
	src/sha256.c
	src/fact.cpp
)

if(APPLE)
	set(GETTIME darwin-posix-rt/clock_gettime.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -I../essential")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_library(${TARGET} 
	${TARGET_SOURCES} ${GETTIME} ${RESOURCE_FILES})
target_link_libraries(${TARGET} crypto curl)

add_executable(mtx_test src/main.c)
target_link_libraries(mtx_test mtx)
set_target_properties(mtx_test PROPERTIES 
	OUTPUT_NAME mtx
	ARCHIVE_OUTPUT_DIRECTORY test) 
