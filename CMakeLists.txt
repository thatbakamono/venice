cmake_minimum_required(VERSION 3.10)

project(venice)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(venice src/PeFile.cc)
target_include_directories(venice PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
