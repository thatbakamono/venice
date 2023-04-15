cmake_minimum_required(VERSION 3.25)
project(venice)

set(CMAKE_CXX_STANDARD 20)

add_library(venice src/PeFile.cc src/PeFile.hpp)
