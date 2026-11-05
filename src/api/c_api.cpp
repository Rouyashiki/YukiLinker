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
         feature == YUKILINKER_C_FEATURE_GENERATION_HANDLES ||
         feature == YUKILINKER_C_FEATURE_TRUSTED_HANDOFF ||
         feature == YUKILINKER_C_FEATURE_CONTROLLED_FORK ||
         feature == YUKILINKER_C_FEATURE_HOST_BIND ||
         feature == YUKILINKER_C_FEATURE_SYSTEM_BACKEND ||
         feature == YUKILINKER_C_FEATURE_RESOURCE_LIMITS;
}

extern "C" yukilinker_c_runtime* yukilinker_c_runtime_create(
    const yukilinker_c_host_services* services) {
  return reinterpret_cast<yukilinker_c_runtime*>(module_runtime_create(services));
}

extern "C" uint32_t yukilinker_c_runtime_destroy(yukilinker_c_runtime* runtime) {
  return module_runtime_destroy(runtime);
}

extern "C" uint32_t yukilinker_c_try_shutdown(yukilinker_c_runtime* runtime,
                                              yukilinker_c_error_detail* error) {
  return module_try_shutdown(runtime, error);
}

extern "C" uint32_t yukilinker_c_host_services_bind(yukilinker_c_runtime* runtime,
                                                    const yukilinker_c_host_services* services) {
  return owner_host_services_bind(runtime, services);
}

extern "C" uint32_t yukilinker_c_set_limits(yukilinker_c_runtime* runtime, uint32_t handle_limit,
                                            uint64_t stub_bytes) {
  return module_set_limits(runtime, handle_limit, stub_bytes);
}

extern "C" uint32_t yukilinker_c_query_stats(yukilinker_c_runtime* runtime,
                                             yukilinker_c_runtime_stats* output) {
  return module_query_stats(runtime, output);
}

extern "C" yukilinker_c_context* yukilinker_c_context_create(
    yukilinker_c_runtime* runtime, const char* search_path,
    yukilinker_c_dependency_provider provider, void* user) {
  return reinterpret_cast<yukilinker_c_context*>(
      module_context_create(runtime, search_path, provider, user));
}

extern "C" uint32_t yukilinker_c_context_destroy(yukilinker_c_runtime* runtime,
                                                 yukilinker_c_context* context) {
  return owner_context_destroy(runtime, context);
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

extern "C" yukilinker_c_lookup_result yukilinker_c_lookup(yukilinker_c_runtime* runtime,
                                                          yukilinker_c_handle handle,
                                                          const char* name, const char* version) {
  return module_lookup(runtime, handle, name, version);
}

extern "C" uint32_t yukilinker_c_query(yukilinker_c_runtime* runtime, yukilinker_c_handle handle,
                                       yukilinker_c_handle_info* output) {
  return module_query(runtime, handle, output);
}

extern "C" uint32_t yukilinker_c_handles(yukilinker_c_runtime* runtime,
                                         yukilinker_c_handle_info* output, size_t capacity,
                                         size_t* count) {
  return module_handles(runtime, output, capacity, count);
}

extern "C" yukilinker_c_close_result yukilinker_c_close(yukilinker_c_runtime* runtime,
                                                        yukilinker_c_handle handle) {
  return module_close(runtime, handle);
}

extern "C" uint32_t yukilinker_c_forget(yukilinker_c_runtime* runtime, yukilinker_c_handle handle) {
  return module_forget(runtime, handle);
}

extern "C" uint32_t yukilinker_c_release_host(yukilinker_c_runtime* runtime,
                                              yukilinker_c_handle handle) {
  return module_release_host(runtime, handle);
}

extern "C" uint32_t yukilinker_c_handle_image(yukilinker_c_runtime* runtime,
                                              yukilinker_c_handle handle,
                                              yukilinker_c_image_record* output) {
  return module_image(runtime, handle, output);
}

extern "C" void yukilinker_c_prepare_fork(yukilinker_c_runtime* runtime) {
  if (runtime && runtime == reinterpret_cast<yukilinker_c_runtime*>(
                                __atomic_load_n(&g_runtime_owner, __ATOMIC_ACQUIRE)))
    loader_prepare_fork();
}

extern "C" void yukilinker_c_after_fork(yukilinker_c_runtime* runtime, int child) {
  if (runtime && runtime == reinterpret_cast<yukilinker_c_runtime*>(
                                __atomic_load_n(&g_runtime_owner, __ATOMIC_ACQUIRE)))
    loader_after_fork(child);
}
