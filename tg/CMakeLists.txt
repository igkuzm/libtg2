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
)

#build both shared and static libs
add_library(${TARGET} SHARED ${TARGET_SOURCES} ${RESOURCE_FILES})
target_link_libraries(${TARGET} crypto)

add_library(${TARGET}_static STATIC ${TARGET_SOURCES} ${RESOURCE_FILES})
target_link_libraries(${TARGET}_static crypto)
set_target_properties(${TARGET}_static PROPERTIES 
	OUTPUT_NAME tg
	ARCHIVE_OUTPUT_DIRECTORY static) 
