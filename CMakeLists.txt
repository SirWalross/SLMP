cmake_minimum_required(VERSION 3.14)
project(main CXX)
set(CMAKE_CXX_STANDARD 20)

# compiler flags
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  # using Visual Studio C++
    add_compile_options(-DNOMINMAX)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # using GCC
    add_compile_options()
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # using Clang
    add_compile_options(-Wall -O3 -Wextra -pedantic -Werror -fsanitize=address)
endif()

find_package(fmt)

add_executable(slmp main.cpp slmp.h)
target_link_libraries(slmp PRIVATE fmt::fmt)