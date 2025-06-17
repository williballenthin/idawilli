cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(mysample)

set(CMAKE_CXX_STANDARD 17)

include($ENV{IDASDK}/ida-cmake/idasdk.cmake)

set(PLUGIN_NAME              mysample)
set(PLUGIN_SOURCES           mysample.cpp)

generate()
disable_ida_warnings(mysample)
