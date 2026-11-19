// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <android/dlext.h>
#include <dlfcn.h>
#include <link.h>

// Export the module's own import pointers so the test calls each one with a
// return address in the host and again after the module has retired.
#define EXPORT_IMPORT(name) \
  __typeof__(&name) module_##name(void) { return name; }
EXPORT_IMPORT(dlopen)
EXPORT_IMPORT(android_dlopen_ext)
EXPORT_IMPORT(dlsym)
EXPORT_IMPORT(dlvsym)
EXPORT_IMPORT(dl_iterate_phdr)
EXPORT_IMPORT(dlclose)

static __typeof__(&dlsym) volatile lookup = dlsym;
void* module_tail_lookup(void* handle, const char* name) {
  __attribute__((musttail)) return lookup(handle, name);
}

// The same private TLS entry must be selected by an ELF import and by name.
#if defined(__i386__)
extern __attribute__((regparm(1))) void* ___tls_get_addr(void*);
int module_tls_lookup_matches(void) {
  return dlsym(RTLD_DEFAULT, "___tls_get_addr") == (void*)___tls_get_addr;
}
#else
extern void* __tls_get_addr(void*);
int module_tls_lookup_matches(void) {
  return dlsym(RTLD_DEFAULT, "__tls_get_addr") == (void*)__tls_get_addr;
}
#endif
