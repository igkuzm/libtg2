cmake_minimum_required(VERSION 3.0)

set(TARGET tg)

find_package(OpenSSL REQUIRED Crypto)

file(GLOB RESOURCE_FILES "*.h" "crypto/*.h" "mtproto/*.h" "database/*.h")
set(TARGET_SOURCES 
	crypto/aes.c
	crypto/cmn.c
	crypto/fact.cpp
	crypto/hsh.c
	crypto/rnd.c
	crypto/rsa.c
	crypto/sha1.c
	crypto/sha256.c
	crypto/pbkdf2.c
	transport/http.c
	transport/socket.c
	transport/header.c
	mtproto/ack.c
	mtproto/ds.c
	mtproto/header.c
	mtproto/encrypt.c
	mtproto/mtproto.c
	database/database.c
	tg.c
	strerr.c
	send_query.c
	answer.c
	updates.c
	auth_key1.c
	auth_key2.c
	auth_key_mtx.c
	auth.c
	connect.c
	2fa.c
	errors.c
	dialogs.c
	peer.c
)

if(APPLE)
	set(GETTIME mtproto/clock_gettime.c)
endif()

if (OPENSSL_VERSION VERSION_LESS 1.0)
	list(APPEND TARGET_SOURCES ../support/aes_ige.c)
endif()

if (MTX_SUPPORT)
	set(MTX mtx)
endif()

#build both shared and static libs
add_library(${TARGET} SHARED 
	${TARGET_SOURCES} ${GETTIME} ${RESOURCE_FILES})
target_link_libraries(${TARGET} OpenSSL::Crypto tl ${MTX})

add_library(${TARGET}_static STATIC 
	${TARGET_SOURCES} ${GETTIME} ${RESOURCE_FILES})
target_link_libraries(${TARGET}_static OpenSSL::Crypto tl ${MTX})
set_target_properties(${TARGET}_static PROPERTIES 
	OUTPUT_NAME tg
	ARCHIVE_OUTPUT_DIRECTORY static) 
