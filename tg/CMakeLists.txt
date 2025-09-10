cmake_minimum_required(VERSION 3.0)

set(TARGET tg)

file(GLOB RESOURCE_FILES "*.h" "crypto/*.h")
set(TARGET_SOURCES 
	crypto/aes.c
	crypto/cmn.c
	crypto/fact.cpp
	crypto/hsh.c
	crypto/rnd.c
	crypto/rsa.c
	crypto/sha1.c
	crypto/sha256.c
	transport/http.c
	transport/socket.c
  transport/header.c
	mtproto/ack.c
  mtproto/ds.c
  mtproto/header.c
  mtproto/encrypt.c
  mtproto/mtproto.c
  tg.c
  strerr.c
  send_query.c
  answer.c
  updates.c
	auth_key1.c
	auth_key_mtx.c
	auth.c
	connect.c
	2fa.c
)

if(APPLE)
	set(GETTIME mtproto/clock_gettime.c)
endif()

#build both shared and static libs
add_library(${TARGET} SHARED 
	${TARGET_SOURCES} ${GETTIME} ${RESOURCE_FILES})
target_link_libraries(${TARGET} crypto curl mtx tl)

add_library(${TARGET}_static STATIC 
	${TARGET_SOURCES} ${GETTIME} ${RESOURCE_FILES})
target_link_libraries(${TARGET}_static crypto curl mtx tl)
set_target_properties(${TARGET}_static PROPERTIES 
	OUTPUT_NAME tg
	ARCHIVE_OUTPUT_DIRECTORY static) 
