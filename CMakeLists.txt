cmake_minimum_required(VERSION 3.16)

project(aes_ctr C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(aes STATIC aes.c)
target_include_directories(aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
  target_compile_options(aes PRIVATE /W4)
else()
  target_compile_options(aes PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(aes_ctr_test main.c)
target_link_libraries(aes_ctr_test PRIVATE aes)

if(MSVC)
  target_compile_options(aes_ctr_test PRIVATE /W4)
else()
  target_compile_options(aes_ctr_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME aes_ctr_test COMMAND aes_ctr_test)
