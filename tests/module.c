// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(TLSDESC_IMPORTER)
// All TLS comes from an optional global provider. This image has no PT_TLS or DT_NEEDED.
extern __thread int fixture_tls_value __attribute__((weak));
int* imported_tls_address(void) { return &fixture_tls_value; }
#elif defined(TLSDESC_PROVIDER)
__thread int fixture_tls_value = 42;
int* provided_tls_address(void) { return &fixture_tls_value; }
#elif defined(EMUTLS_RUNTIME)
__attribute__((visibility("default"))) __thread int emutls_runtime_anchor = 1;
__attribute__((visibility("default"))) int* emutls_runtime_slot(void) {
  return &emutls_runtime_anchor;
}
#elif defined(KEY_PROVIDER)
static int delete_key(pthread_key_t key) { return (int)key; }
extern __typeof__(delete_key) pthread_key_delete __attribute__((alias("delete_key")));
int (*fixture_key_provider(void))(pthread_key_t) { return delete_key; }
#elif defined(KEY_CONSUMER)
#pragma weak pthread_key_create
#pragma weak pthread_setspecific
extern int (*fixture_key_provider(void))(pthread_key_t);
int fixture_key_bindings(void) {
  return pthread_key_delete == fixture_key_provider() && !pthread_key_create &&
         !pthread_setspecific;
}
#elif defined(EMUTLS_OBSERVER)
// This caller imports an ordinary function but has no emutls relocations of its own.
extern int* emutls_slot(void);
int emutls_observe(void) {
  void* scopes[] = {RTLD_DEFAULT, RTLD_NEXT};
  for (unsigned i = 0; i < sizeof(scopes) / sizeof(scopes[0]); ++i) {
    void* (*access)(void*) = (void* (*)(void*))dlsym(scopes[i], "__emutls_get_address");
    void* control = dlsym(scopes[i], "__emutls_v.fixture_shared");
    if (!access || !control || access(control) != emutls_slot()) return 0;
  }
  return 1;
}
#elif defined(EMUTLS_PASSIVE)
// Plain C emits only a control and its initial bytes for an unused definition.
__attribute__((visibility("default"), aligned(128))) __thread int fixture_shared = 42;
__attribute__((visibility("default"))) __thread int fixture_unread = 17;
__asm__(
    ".globl __emutls_v.fixture_alias\n.set __emutls_v.fixture_alias, __emutls_v.fixture_shared");
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t key;
static int key_status = -1;

static void create_key(void) { key_status = pthread_key_create(&key, NULL); }
__attribute__((destructor)) static void delete_key(void) {
  if (key_status == 0 && pthread_key_delete(key) != 0) abort();
}

__attribute__((visibility("default"))) int emutls_passive_key(void) {
  int value;
  if (pthread_once(&once, create_key) || key_status || pthread_setspecific(key, &value)) return 0;
  const int matched = pthread_getspecific(key) == &value;
  return pthread_setspecific(key, NULL) == 0 && matched;
}
#else
static int value;
__attribute__((constructor)) static void initialize(void) {
  const char* address = getenv("YUKILINKER_TEST_WAIT_BARRIER");
  if (address) {
    pthread_barrier_t* barrier = (pthread_barrier_t*)(uintptr_t)strtoull(address, NULL, 16);
    for (unsigned i = 0; i < 2; ++i) {
      int status = pthread_barrier_wait(barrier);
      if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) abort();
    }
  }
  value = 42;
}
__attribute__((destructor)) static void finalize(void) { value = 0; }
__attribute__((visibility("default"))) int module_answer(void) { return value; }
__attribute__((visibility("default"))) void module_count_key_exit(void* calls) { ++*(int*)calls; }
#endif
