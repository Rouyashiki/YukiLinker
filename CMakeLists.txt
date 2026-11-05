# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rouyashiki <https://rouyashiki.org>

cmake_minimum_required(VERSION 3.22)
project(YukiLinker VERSION 1.0.0 LANGUAGES C CXX ASM)

include(cmake/YukiLinkerOptions.cmake)

if(NOT ANDROID)
  message(FATAL_ERROR "YukiLinker requires an Android NDK toolchain")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Debug info and __FILE__ name the tree under fixed virtual roots, so an archive does not depend
# on where the source, the build directory or the NDK lie. The roots are absolute: with a relative
# source root the debugger joined it to comp_dir (build/./src/...). The build directory comes last:
# it lies inside the source tree, and the last matching map wins. gdb's substitute-path takes the
# first matching rule, so map /yukilinker/build before /yukilinker.
add_compile_options(
  "$<$<COMPILE_LANGUAGE:C,CXX,ASM>:-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=/yukilinker>"
  "$<$<COMPILE_LANGUAGE:C,CXX,ASM>:-ffile-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=/yukilinker/build>")
if(CMAKE_ANDROID_NDK)
  add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX,ASM>:-ffile-prefix-map=${CMAKE_ANDROID_NDK}=/ndk>")
endif()

include(cmake/YukiLinkerTargets.cmake)
