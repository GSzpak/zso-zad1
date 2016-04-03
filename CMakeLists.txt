cmake_minimum_required(VERSION 3.5)
project(zso_zad1)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES raise.c)
add_executable(zso_zad1 ${SOURCE_FILES})