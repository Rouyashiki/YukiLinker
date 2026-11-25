# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rouyashiki <https://rouyashiki.org>

cmake_minimum_required(VERSION 3.22)
project(YukiLinkerHosts LANGUAGES C CXX ASM)
enable_testing()
add_subdirectory(.. sdk)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

add_library(linker_module SHARED module.c)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/module.map"
  "MODULE_API { global: module_answer; module_count_key_exit; __cfi_check*; local: *; };\n")
target_link_options(linker_module PRIVATE
  "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/module.map")
set_property(TARGET linker_module APPEND PROPERTY LINK_DEPENDS
  "${CMAKE_CURRENT_BINARY_DIR}/module.map")
add_library(linker_lifecycle SHARED lifecycle_module.c)
target_compile_options(linker_lifecycle PRIVATE -fno-emulated-tls)
foreach(module linker_module linker_lifecycle)
  target_link_options(${module} PRIVATE -Wl,-z,max-page-size=16384)
endforeach()
if(YUKILINKER_CFI)
  target_compile_options(linker_module PRIVATE -flto -fvisibility=hidden
    -fsanitize=cfi-icall -fsanitize-cfi-cross-dso)
  target_link_options(linker_module PRIVATE -flto -fsanitize=cfi-icall -fsanitize-cfi-cross-dso)
endif()

add_executable(c_host c_host.c)
add_dependencies(c_host linker_module)
target_link_libraries(c_host PRIVATE YukiLinker::runtime dl)
target_compile_options(c_host PRIVATE -Wall -Wextra -pedantic -Werror -UNDEBUG)
if(NOT YUKILINKER_CFI)
  # The dependency supplies its own version of one key function. The other
  # two are optional imports in a group with no dependency on libc.
  add_library(key_provider SHARED module.c)
  add_library(key_consumer SHARED module.c)
  target_compile_definitions(key_provider PRIVATE KEY_PROVIDER=1)
  target_compile_definitions(key_consumer PRIVATE KEY_CONSUMER=1)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/key_provider.map"
    "TEST_KEY { global: pthread_key_delete; fixture_key_provider; local: *; };\n")
  target_link_options(key_provider PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/key_provider.map")
  set_property(TARGET key_provider APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/key_provider.map")
  foreach(module key_provider key_consumer)
    target_compile_options(${module} PRIVATE -fno-stack-protector)
    target_link_options(${module} PRIVATE -nostdlib -Wl,--as-needed,-z,max-page-size=16384)
  endforeach()
  target_link_libraries(key_consumer PRIVATE key_provider)
  add_dependencies(c_host key_consumer)
endif()
add_executable(cpp_host cpp_host.cpp)
add_dependencies(cpp_host linker_module linker_lifecycle)
target_link_libraries(cpp_host PRIVATE YukiLinker::runtime dl)
target_compile_options(cpp_host PRIVATE -UNDEBUG)
target_link_options(cpp_host PRIVATE -Wl,--wrap=munmap,--wrap=pthread_setspecific)
if(NOT YUKILINKER_CFI)
  set(test_api "${ANDROID_PLATFORM_LEVEL}")
  if(NOT test_api)
    set(test_api "${CMAKE_SYSTEM_VERSION}")
  endif()
  # Ordinary pre-Q NDK output: a shared C++ runtime imports the accessor, while
  # a static one supplies a weak definition which can also be bound locally.
  foreach(form weak shared direct local wrapped_local wrapped_keys stripped consumer versioned lookup_root
               conflict managed_conflict key_conflict passive reader observer managed_version mixed_versions
               mixed_controls mixed_local aliases named_alias named_alias_mixed delegated delegated_reader)
    if(form STREQUAL "passive" OR form STREQUAL "observer")
      add_library(emutls_${form} SHARED module.c)
    else()
      add_library(emutls_${form} SHARED emutls_module.cpp)
      # Keep the weak and locally bound compiler-rt fixtures independent of the host's STL.
      if(NOT form STREQUAL "shared")
        target_link_options(emutls_${form} PRIVATE -static-libstdc++)
      endif()
    endif()
    if(test_api GREATER_EQUAL 29)
      target_compile_options(emutls_${form} PRIVATE -femulated-tls)
    endif()
    set_target_properties(emutls_${form} PROPERTIES CXX_VISIBILITY_PRESET hidden)
    target_compile_options(emutls_${form} PRIVATE -fno-exceptions)
    target_link_options(emutls_${form} PRIVATE -Wl,-z,max-page-size=16384
      -Wl,--exclude-libs,libc++_static.a -Wl,--exclude-libs,libc++abi.a)
    add_dependencies(cpp_host emutls_${form})
  endforeach()
  if(CMAKE_ANDROID_ARCH_ABI STREQUAL "riscv64")
    # NDK 30's riscv64 libc++_shared.so uses native ELF TLS and exports no __emutls_get_address.
    # Supply a page-aligned system provider for the shared-runtime emutls fixtures.
    add_library(emutls_runtime SHARED module.c)
    set_target_properties(emutls_runtime PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/sdk")
    target_compile_definitions(emutls_runtime PRIVATE EMUTLS_RUNTIME=1)
    target_compile_options(emutls_runtime PRIVATE -femulated-tls -fno-exceptions)
    target_link_options(emutls_runtime PRIVATE -Wl,-z,max-page-size=16384)
    target_link_libraries(emutls_shared PRIVATE emutls_runtime)
    add_dependencies(cpp_host emutls_runtime)
  else()
    find_library(test_shared_cxx c++_shared REQUIRED)
    target_link_libraries(emutls_shared PRIVATE "${test_shared_cxx}")
    # Keep it in the system linker's search path, outside the PRIVATE fixture directory.
    configure_file("${test_shared_cxx}" sdk/libc++_shared.so COPYONLY)
  endif()
  target_compile_definitions(emutls_weak PRIVATE EMUTLS_MANAGED_PROBE=1 EMUTLS_SECOND_CONTROL=1)
  target_compile_definitions(emutls_shared PRIVATE EMUTLS_MANAGED_PROBE=1)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/emutls_direct.map"
    "TEST_EMUTLS_OLD {};\nTEST_EMUTLS { global: __emutls_get_address; } TEST_EMUTLS_OLD;\n")
  target_compile_definitions(emutls_direct PRIVATE EMUTLS_VERSIONED_PROVIDER=1)
  target_link_options(emutls_direct PRIVATE -Wl,-Bsymbolic-functions
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/emutls_direct.map")
  set_property(TARGET emutls_direct APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/emutls_direct.map")
  target_compile_definitions(emutls_aliases PRIVATE EMUTLS_ACCESSOR_ALIASES=1 EMUTLS_MARK_CONSTRUCTOR=0)
  target_link_options(emutls_aliases PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/emutls_direct.map")
  set_property(TARGET emutls_aliases APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/emutls_direct.map")
  target_compile_definitions(emutls_named_alias PRIVATE EMUTLS_NAMED_ALIAS=1 EMUTLS_MARK_CONSTRUCTOR=0)
  target_link_options(emutls_named_alias PRIVATE -Wl,--defsym=fixture_named_accessor=__emutls_get_address)
  target_compile_definitions(emutls_named_alias_mixed PRIVATE EMUTLS_NAMED_ALIAS=1
    EMUTLS_NAMED_ALIAS_IMPORT=1)
  target_link_options(emutls_named_alias_mixed PRIVATE
    -Wl,--defsym=fixture_named_accessor=__emutls_get_address)
  target_link_libraries(emutls_named_alias_mixed PRIVATE emutls_direct)
  target_compile_definitions(emutls_versioned PRIVATE EMUTLS_VERSIONED_PROBE=1)
  target_link_libraries(emutls_versioned PRIVATE emutls_direct)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/emutls_managed.map"
    "TEST_EMUTLS_MANAGED { global: __emutls_get_address; };\n")
  target_compile_definitions(emutls_managed_version PRIVATE EMUTLS_MANAGED_VERSION=1)
  target_link_options(emutls_managed_version PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/emutls_managed.map")
  set_property(TARGET emutls_managed_version APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/emutls_managed.map")
  target_compile_definitions(emutls_mixed_versions PRIVATE EMUTLS_MIXED_VERSIONS=1 EMUTLS_MARK_CONSTRUCTOR=1)
  target_link_libraries(emutls_mixed_versions PRIVATE emutls_managed_version emutls_direct)
  # Resolve the compiler's unversioned call from its own archive before the versioned DSO.
  # Strip all local symbols and keep the control exported to other DSOs.
  execute_process(COMMAND "${CMAKE_CXX_COMPILER}" "--target=${CMAKE_CXX_COMPILER_TARGET}"
    --print-libgcc-file-name OUTPUT_VARIABLE emutls_builtins OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
  target_compile_definitions(emutls_mixed_local PRIVATE EMUTLS_MIXED_LOCAL=1 EMUTLS_MARK_CONSTRUCTOR=0)
  target_link_options(emutls_mixed_local PRIVATE -Wl,--exclude-libs,ALL,-s)
  target_link_libraries(emutls_mixed_local PRIVATE "${emutls_builtins}" emutls_managed_version)
  # The versioned accessor and the imported control come from different DT_NEEDED entries.
  target_compile_definitions(emutls_mixed_controls PRIVATE EMUTLS_IMPORT=1 EMUTLS_MARK_CONSTRUCTOR=1)
  target_link_libraries(emutls_mixed_controls PRIVATE emutls_managed_version emutls_shared)
  # The middle DSO defines the reader's control and imports its accessor from the versioned DSO.
  target_link_libraries(emutls_delegated PRIVATE emutls_managed_version)
  target_compile_definitions(emutls_delegated_reader PRIVATE EMUTLS_IMPORT=1 EMUTLS_MARK_CONSTRUCTOR=1)
  target_link_libraries(emutls_delegated_reader PRIVATE emutls_delegated)
  # A stripped local compiler-rt can still export its control to a prospective reader.
  foreach(form local wrapped_local wrapped_keys)
    target_link_options(emutls_${form} PRIVATE -Wl,--exclude-libs,ALL,-s)
    target_compile_definitions(emutls_${form} PRIVATE EMUTLS_MARK_CONSTRUCTOR=0)
  endforeach()
  target_compile_definitions(emutls_local PRIVATE EMUTLS_FINALIZER_PROBE=1)
  target_link_options(emutls_local PRIVATE -Wl,--wrap=pthread_key_create,--wrap=pthread_mutex_lock)
  target_link_libraries(emutls_local PRIVATE linker_module)
  target_compile_definitions(emutls_lookup_root PRIVATE EMUTLS_LOOKUP_ROOT=1)
  target_link_libraries(emutls_lookup_root PRIVATE emutls_local)
  target_compile_definitions(emutls_wrapped_local PRIVATE EMUTLS_WRAP_SERVICES=1)
  # This binding also removes the control's GOT relocation without setting DF_SYMBOLIC.
  target_link_options(emutls_wrapped_local PRIVATE
    -Wl,-Bsymbolic-non-weak,--wrap=realloc,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock
    -Wl,--wrap=pthread_setspecific)
  # This local accessor retains its control relocation but hides all three key operations.
  target_compile_definitions(emutls_wrapped_keys PRIVATE EMUTLS_WRAP_KEYS=1)
  target_link_options(emutls_wrapped_keys PRIVATE
    -Wl,--wrap=pthread_key_create,--wrap=pthread_getspecific,--wrap=pthread_setspecific)
  target_link_options(emutls_stripped PRIVATE -Wl,--exclude-libs,ALL,-s)
  # Release-style visibility with neither the local accessor nor its controls
  # in .dynsym. All references to those controls bind inside the module.
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/emutls_stripped.map"
    "{ global: emutls_slot; emutls_zero; emutls_on_exit; local: *; };\n")
  target_link_options(emutls_stripped PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/emutls_stripped.map")
  set_property(TARGET emutls_stripped APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/emutls_stripped.map")
  target_compile_definitions(emutls_consumer PRIVATE EMUTLS_IMPORT=1 EMUTLS_SECOND_CONTROL=1)
  target_link_libraries(emutls_consumer PRIVATE emutls_weak)
  foreach(form conflict managed_conflict key_conflict)
    target_compile_definitions(emutls_${form} PRIVATE EMUTLS_IMPORT=1 EMUTLS_MARK_CONSTRUCTOR=1)
  endforeach()
  target_link_libraries(emutls_conflict PRIVATE emutls_local)
  target_link_libraries(emutls_managed_conflict PRIVATE emutls_wrapped_local)
  target_link_libraries(emutls_key_conflict PRIVATE emutls_wrapped_keys)
  target_link_options(emutls_conflict PRIVATE -Wl,--exclude-libs,ALL,-s)
  target_compile_definitions(emutls_passive PRIVATE EMUTLS_PASSIVE=1)
  target_link_options(emutls_passive PRIVATE -Wl,-s)
  target_compile_definitions(emutls_reader PRIVATE EMUTLS_IMPORT=1 EMUTLS_MARK_CONSTRUCTOR=1)
  target_link_libraries(emutls_reader PRIVATE emutls_passive)
  target_compile_definitions(emutls_observer PRIVATE EMUTLS_OBSERVER=1)
  target_link_libraries(emutls_observer PRIVATE emutls_weak)
endif()
if(CMAKE_ANDROID_ARCH_ABI MATCHES "^(arm64-v8a|riscv64)$" AND NOT YUKILINKER_CFI)
  add_library(tlsdesc_importer SHARED module.c)
  add_library(tlsdesc_provider SHARED module.c)
  target_compile_definitions(tlsdesc_importer PRIVATE TLSDESC_IMPORTER=1)
  target_compile_definitions(tlsdesc_provider PRIVATE TLSDESC_PROVIDER=1)
  target_link_options(tlsdesc_provider PRIVATE -Wl,-z,global)
  foreach(module tlsdesc_importer tlsdesc_provider)
    target_compile_options(${module} PRIVATE -fno-emulated-tls -fno-stack-protector)
    target_link_options(${module} PRIVATE -nostdlib -Wl,--as-needed,-z,max-page-size=16384)
    add_dependencies(cpp_host ${module})
  endforeach()
endif()
if(CMAKE_ANDROID_ARCH_ABI MATCHES "^(x86(_64)?|riscv64)$" AND NOT YUKILINKER_CFI)
  # The narrow relocation / synthetic rewrite tests modify ordinary REL/RELA tables.
  target_link_options(linker_lifecycle PRIVATE -Wl,--pack-dyn-relocs=relr)
  add_library(linker_x86_calls SHARED x86_call_module.c)
  target_link_libraries(linker_x86_calls PRIVATE dl)
  # Exercise the packed tables on a module with both address and symbol relocations.
  target_link_options(linker_x86_calls PRIVATE -Wl,-z,max-page-size=16384
    -Wl,--pack-dyn-relocs=android+relr)
  target_sources(cpp_host PRIVATE x86_calls.cpp)
  target_compile_definitions(cpp_host PRIVATE YUKILINKER_TEST_X86_CALLS=1)
  add_dependencies(cpp_host linker_x86_calls)
  if(CMAKE_ANDROID_ARCH_ABI STREQUAL "riscv64")
    target_link_options(cpp_host PRIVATE -Wl,--wrap=__riscv_hwprobe,--wrap=fopen,--wrap=mmap
      -Wl,--wrap=mprotect,--wrap=pidfd_open
      -Wl,--wrap=pthread_getspecific
      -Wl,--wrap=pthread_key_create,--wrap=posix_memalign)
    # Compile the TLSDESC clobber check with -O2 so RVV and FP registers stay live across the call.
    target_compile_options(linker_lifecycle PRIVATE -O2)
    # Also test traditional dynamic TLS (-mtls-dialect=trad) alongside default TLSDESC.
    add_library(linker_lifecycle_trad SHARED lifecycle_module.c)
    target_compile_options(linker_lifecycle_trad PRIVATE -fno-emulated-tls -mtls-dialect=trad)
    target_link_options(linker_lifecycle_trad PRIVATE -Wl,-z,max-page-size=16384
      -Wl,--pack-dyn-relocs=relr)
    add_dependencies(cpp_host linker_lifecycle_trad)
  endif()
endif()
foreach(host c_host cpp_host)
  if(YUKILINKER_CFI)
    target_compile_definitions(${host} PRIVATE YUKILINKER_TEST_CFI=1)
    target_compile_options(${host} PRIVATE -flto -fvisibility=hidden
      -fsanitize=cfi-icall -fsanitize-cfi-cross-dso)
  endif()
  add_test(NAME ${host} COMMAND ${host} "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()

add_executable(bootstrap_host bootstrap_host.cpp)
target_link_libraries(bootstrap_host PRIVATE YukiLinker::headers dl)
target_compile_options(bootstrap_host PRIVATE -UNDEBUG)
target_link_options(bootstrap_host PRIVATE -Wl,--export-dynamic
  -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384)
if(TARGET YukiLinker::bootstrap AND NOT YUKILINKER_CFI)
  # Extra version records exercise metadata unmap failure on both pointer widths.
  set(core_versions "CORE { global: zygisk_*; local: *; };\n")
  foreach(index RANGE 1 256)
    string(APPEND core_versions "RECORD_${index} {};\n")
  endforeach()
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/core.map" "${core_versions}")
  foreach(form archive sources)
    add_library(core_${form} SHARED core.cpp)
    set_target_properties(core_${form} PROPERTIES OUTPUT_NAME linker_core_${form}
      CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
    target_compile_options(core_${form} PRIVATE -UNDEBUG -fno-stack-protector
      -fno-c++-static-destructors)
    target_link_options(core_${form} PRIVATE -nostdlib++
      "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/core.map")
    if(form STREQUAL "archive")
      target_link_libraries(core_${form} PRIVATE YukiLinker::runtime)
    else()
      yukilinker_add_runtime_sources(core_${form})
    endif()
    target_link_libraries(core_${form} PRIVATE dl)
  endforeach()
  add_test(NAME bootstrap_host COMMAND bootstrap_host "${CMAKE_CURRENT_BINARY_DIR}")
endif()
