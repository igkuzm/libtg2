cmake_minimum_required(VERSION 3.0)

project(tl_generator)
set(TARGET generator)

# build generator binary in tl_generator directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set(RESOURCE_FILES mtproto_api.tl telegram_api.tl)
set(TARGET_SOURCES generator.c tl_parser.c)

if (APPLE)
	set(STRNDUP strndup.c)
endif()

add_executable(${TARGET} ${TARGET_SOURCES} ${STRNDUP} ${RESOURCE_FILES})

# run generator to create headers and sources of tl
add_custom_command(
	TARGET ${TARGET}
	POST_BUILD 
	COMMAND ./generator ../tl
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMENT "generating tl"
)
