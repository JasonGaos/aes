cmake_minimum_required(VERSION 3.16)

project(aes_ctr C)

include(CheckCCompilerFlag)

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

set(AES_RUNTIME_BACKENDS "portable")
set(AES_ARM_CRYPTO_ENABLED OFF)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$" AND NOT MSVC)
  check_c_compiler_flag("-march=armv8-a+crypto" AES_COMPILER_SUPPORTS_ARM_CRYPTO)
  if(AES_COMPILER_SUPPORTS_ARM_CRYPTO)
    target_compile_options(aes PRIVATE -march=armv8-a+crypto)
    set(AES_ARM_CRYPTO_ENABLED ON)
  endif()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i[3-6]86)$")
  set(AES_RUNTIME_BACKENDS "portable + aesni(runtime)")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
  if(AES_ARM_CRYPTO_ENABLED)
    set(AES_RUNTIME_BACKENDS "portable + neon/runtime-crypto")
  else()
    set(AES_RUNTIME_BACKENDS "portable (ARM crypto backend requires compiler support)")
  endif()
endif()

message(STATUS "AES runtime backends compiled: ${AES_RUNTIME_BACKENDS}")

add_executable(aes_ctr_test main.c)
target_link_libraries(aes_ctr_test PRIVATE aes)

if(MSVC)
  target_compile_options(aes_ctr_test PRIVATE /W4)
else()
  target_compile_options(aes_ctr_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME aes_ctr_test COMMAND aes_ctr_test)
