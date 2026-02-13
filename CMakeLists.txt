cmake_minimum_required(VERSION 3.0)

set(TARGET libtg)

# Declares and names the project.
project(${TARGET} VERSION 2.0 
	DESCRIPTION "C99 Telegram API"
	LANGUAGES C CXX
)

set(PACKAGE_NAME ${PROJECT_NAME})
set(PACKAGE_VERSION ${PROJECT_VERSION})
configure_file(config.h.in config.h)

add_subdirectory(essential)
add_subdirectory(tl_generator)
add_subdirectory(tl)
add_subdirectory(tg)

add_dependencies(generator essential)
add_dependencies(tl generator)

if (MTX_SUPPORT)
	add_subdirectory(mtx)	
endif()

if (MAKE_TEST)
	add_executable(tgtest test.c)
	target_link_libraries(tgtest tg)
endif()

#copy public key to binary dir
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/pub.pkcs
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
