cmake_minimum_required(VERSION 3.0)

set(TARGET essential)

file(GLOB RESOURCE_FILES "*.h")
file(GLOB TARGET_SOURCES "*c")

if (APPLE)
  list(APPEND TARGET_SOURCES ../darwin/strndup.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_library(${TARGET} ${TARGET_SOURCES} ${RESOURCE_FILES})
