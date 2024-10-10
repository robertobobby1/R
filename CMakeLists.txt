cmake_minimum_required(VERSION 3.20)
project(R)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

file(GLOB MyCPPSources ${CMAKE_CURRENT_SOURCE_DIR}/R/Source/*.cpp)
add_executable(R ${MyCPPSources})

target_include_directories(R PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/R/Source/Vendor/Random)
target_include_directories(R PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/R/Source/Net)
target_include_directories(R PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/R/Source)

target_compile_options(R PRIVATE -O2 -Wall -g -Wno-missing-braces)
target_compile_options(R PRIVATE -Wall)
target_compile_options(R PRIVATE -g)
