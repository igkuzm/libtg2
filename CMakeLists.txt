cmake_minimum_required(VERSION 3.0)

set(TARGET libtg)

# Declares and names the project.
project(${TARGET} VERSION 2.0 
	DESCRIPTION "C99 Telegram API"
	HOMEPAGE_URL "http://github.com/libtg2"
	LANGUAGES C CXX
)

add_subdirectory(tl_generator)
add_subdirectory(tl)
add_subdirectory(tg)

add_dependencies(tl tl_generator)

if (MAKE_TEST)
	add_executable(tgtest test.c)
	#add_dependencies(tgtest generator)
	target_link_libraries(tgtest tg tl sqlite3)
endif()

#copy public key to binary dir
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/pub.pkcs
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
