// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../internal/enumeration.hpp"
#include "../internal/module_api.hpp"
#include "../internal/owner_api.hpp"

using namespace yukilinker::internal;

extern "C" uint32_t yukilinker_c_abi_version(void) { return YUKILINKER_C_ABI_VERSION; }

extern "C" uint32_t yukilinker_c_has_feature(uint32_t feature) {
  return feature == YUKILINKER_C_FEATURE_PACKED_RELOCS ||
         feature == YUKILINKER_C_FEATURE_SYMBOL_VERSIONS ||
         feature == YUKILINKER_C_FEATURE_PRIVATE_DEPENDENCIES ||
         feature == YUKILINKER_C_FEATURE_DYNAMIC_TLS ||
         feature == YUKILINKER_C_FEATURE_MODULE_PHDR ||
         feature == YUKILINKER_C_FEATURE_DLEXT_FD_OFFSET ||
         feature == YUKILINKER_C_FEATURE_DLEXT_RESERVED_ROOT ||
         feature == YUKILINKER_C_FEATURE_DLEXT_RELRO_ROOT ||
         feature == YUKILINKER_C_FEATURE_RUNTIME_OWNER ||
         feature == YUKILINKER_C_FEATURE_HOST_SERVICES ||
         feature == YUKILINKER_C_FEATURE_GENERATION_HANDLES;
}

extern "C" yukilinker_c_runtime* yukilinker_c_runtime_create(
    const yukilinker_c_host_services* services) {
  return reinterpret_cast<yukilinker_c_runtime*>(module_runtime_create(services));
}

extern "C" uint32_t yukilinker_c_runtime_destroy(yukilinker_c_runtime* runtime) {
  return module_runtime_destroy(runtime);
}

extern "C" yukilinker_c_handle yukilinker_c_open_path(yukilinker_c_runtime* runtime,
                                                      const char* path,
                                                      const yukilinker_c_open_options* options,
                                                      yukilinker_c_error* error) {
  return module_open_path(runtime, path, options, error);
}

extern "C" yukilinker_c_handle yukilinker_c_open_fd(yukilinker_c_runtime* runtime, int fd,
                                                    const yukilinker_c_open_options* options,
                                                    yukilinker_c_error* error) {
  return module_open_fd(runtime, fd, options, error);
}

extern "C" uint32_t yukilinker_c_query(yukilinker_c_runtime* runtime, yukilinker_c_handle handle,
                                       yukilinker_c_handle_info* output) {
  return module_query(runtime, handle, output);
}

extern "C" yukilinker_c_close_result yukilinker_c_close(yukilinker_c_runtime* runtime,
                                                        yukilinker_c_handle handle) {
  return module_close(runtime, handle);
}
