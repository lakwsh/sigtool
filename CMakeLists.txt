cmake_minimum_required(VERSION 3.5.0)
project(sigtool VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
endif()

add_executable(sigtool mem.cpp sig.cpp sym.cpp test.cpp)
