// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <string.h>

// This fixture always exercises native ELF TLS in PRIVATE. Older libc stubs
// omit this import, which the runtime supplies when it relocates the fixture.
#if __ANDROID_API__ < 29 && defined(__i386__)
__asm__(".weak ___tls_get_addr");
#elif __ANDROID_API__ < 29 && (defined(__arm__) || defined(__x86_64__))
__asm__(".weak __tls_get_addr");
#endif

int __cxa_atexit(void (*callback)(void*), void* data, void* owner);
void __cxa_finalize(void* owner);
int __cxa_thread_atexit_impl(void (*callback)(void*), void* data, void* owner);
extern void* __dso_handle;

__thread int module_value = 42;
static int* fork_calls;
static void (*close_step)(int);
static void count(void* value) { ++*(int*)value; }
static void child(void) {
  if (fork_calls) ++*fork_calls;
}

int* module_slot(void) { return &module_value; }
static void finish_cookie(void* unused) {
  (void)unused;
  close_step(2);
}
int module_watch_close(void (*step)(int)) {
  close_step = step;
  return __cxa_atexit(finish_cookie, NULL, &close_step);
}
__attribute__((destructor(201))) static void start_close(void) {
  if (close_step) {
    ++module_value;
    // The TLS hold parks this cookie before the host starts process exit.
    __cxa_finalize(&close_step);
    close_step(1);
  }
}
__attribute__((destructor(200))) static void finish_close(void) {
  if (close_step) close_step(3);
}
int module_lookup_emutls(const char* path, int expected) {
  void* handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
  if (!handle) return 0;
  dlerror();
  void* address = dlsym(handle, "__emutls_get_address");
  void* control = dlsym(handle, "__emutls_v.fixture_shared");
  const char* error = dlerror();
  void* (*access)(void*);
  memcpy(&access, &address, sizeof(access));
  int matched = expected ? access && control && !error && *(int*)access(control) == expected
                         : access && !control && error;
  return dlclose(handle) == 0 && matched;
}
int module_iterate(int (*visit)(struct dl_phdr_info*, size_t, void*), void* data) {
  return dl_iterate_phdr(visit, data);
}
int module_thread_exit(int* calls) { return __cxa_thread_atexit_impl(count, calls, &__dso_handle); }
int module_exit(int* calls) { return __cxa_atexit(count, calls, &__dso_handle); }
int module_fork(int* calls) {
  fork_calls = calls;
  return pthread_atfork(0, 0, child);
}

#if defined(__i386__) || defined(__x86_64__)
typedef int (*probe_function)(void);
static int probe_answer(void) { return 73; }
probe_function module_x86_resolver(void) { return probe_answer; }
int module_x86_ifunc(void) __attribute__((ifunc("module_x86_resolver")));
extern int module_x86_weak(void) __attribute__((weak));
// The host rewrites these five ordinary address relocations in a copy of this DSO. Android lld
// does not emit x86_64's narrow dynamic relocations from PIC input.
probe_function module_x86_slots[] = {module_x86_ifunc, module_x86_ifunc, module_x86_weak,
                                     module_x86_ifunc, module_x86_ifunc};
#endif
