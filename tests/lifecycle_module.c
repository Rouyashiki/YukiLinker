// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <pthread.h>

int __cxa_atexit(void (*callback)(void*), void* data, void* owner);
int __cxa_thread_atexit_impl(void (*callback)(void*), void* data, void* owner);
extern void* __dso_handle;

__thread int module_value = 42;
static int* fork_calls;
static void count(void* value) { ++*(int*)value; }
static void child(void) {
  if (fork_calls) ++*fork_calls;
}

int* module_slot(void) { return &module_value; }
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
