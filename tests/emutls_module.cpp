// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(EMUTLS_MANAGED_PROBE)
#include <utility>
#endif

#define EXPORTED extern "C" __attribute__((visibility("default")))

#if defined(EMUTLS_WRAP_SERVICES) || defined(EMUTLS_WRAP_KEYS)
// Link-time wrappers remove the original names from .dynsym while preserving their behavior.
template <typename F>
static F system_function(const char* name) {
  auto function = reinterpret_cast<F>(dlsym(RTLD_DEFAULT, name));
  if (!function) abort();
  return function;
}
extern "C" int __wrap_pthread_setspecific(pthread_key_t key, const void* value) {
  return system_function<decltype(&pthread_setspecific)>("pthread_setspecific")(key, value);
}
#endif
#if defined(EMUTLS_WRAP_KEYS)
extern "C" int __wrap_pthread_key_create(pthread_key_t* key, void (*destructor)(void*)) {
  return system_function<decltype(&pthread_key_create)>("pthread_key_create")(key, destructor);
}
extern "C" void* __wrap_pthread_getspecific(pthread_key_t key) {
  return system_function<decltype(&pthread_getspecific)>("pthread_getspecific")(key);
}
#endif
#if defined(EMUTLS_WRAP_SERVICES)
extern "C" void* __wrap_realloc(void* block, size_t bytes) {
  return system_function<decltype(&realloc)>("realloc")(block, bytes);
}
extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex) {
  return system_function<decltype(&pthread_mutex_lock)>("pthread_mutex_lock")(mutex);
}
extern "C" int __wrap_pthread_mutex_unlock(pthread_mutex_t* mutex) {
  return system_function<decltype(&pthread_mutex_unlock)>("pthread_mutex_unlock")(mutex);
}
#endif

extern "C" {
alignas(128) extern __attribute__((visibility("default"))) thread_local int fixture_shared;
#if defined(EMUTLS_SECOND_CONTROL)
extern __attribute__((visibility("default"))) thread_local int fixture_second;
#endif
}

#if defined(EMUTLS_MARK_CONSTRUCTOR)
__attribute__((constructor)) static void count_constructor() {
  const char* address = getenv("YUKILINKER_TEST_EMUTLS_CTORS");
  if (address) {
    auto* count = reinterpret_cast<int*>(static_cast<uintptr_t>(strtoull(address, nullptr, 16)));
    ++count[EMUTLS_MARK_CONSTRUCTOR];
  }
}
#endif

#if defined(EMUTLS_VERSIONED_PROVIDER)
extern "C" void* __emutls_get_address(void*);
EXPORTED void* emutls_legacy_accessor(void* control) { return __emutls_get_address(control); }
__asm__(".symver emutls_legacy_accessor,__emutls_get_address@TEST_EMUTLS_OLD");
#endif

#if defined(EMUTLS_ACCESSOR_ALIASES) || defined(EMUTLS_NAMED_ALIAS)
using Accessor = void* (*)(void*);
static Accessor native_accessor;
#if defined(EMUTLS_NAMED_ALIAS)
EXPORTED __attribute__((weak)) void* __emutls_get_address(void* control) {
  return native_accessor(control);
}
extern "C" void* fixture_named_accessor(void*);
#if defined(EMUTLS_NAMED_ALIAS_IMPORT)
extern "C" void* old_accessor(void*);
__asm__(".symver old_accessor,__emutls_get_address@TEST_EMUTLS_OLD");
EXPORTED void* emutls_old_slot(void* control) { return old_accessor(control); }
#endif
#else
EXPORTED __attribute__((weak)) void* fixture_current(void* control) {
  return native_accessor(control);
}
extern "C" __attribute__((visibility("hidden"), alias("fixture_current"))) void*
fixture_named_accessor(void*);
EXPORTED __attribute__((alias("fixture_current"))) void* fixture_previous(void*);
__asm__(".symver fixture_current,__emutls_get_address@@TEST_EMUTLS");
__asm__(".symver fixture_previous,__emutls_get_address@TEST_EMUTLS_OLD");
#endif
extern "C" {
#if defined(EMUTLS_NAMED_ALIAS_IMPORT)
__attribute__((visibility("default"))) __thread int alias_slot = 41;
#else
__attribute__((visibility("default"))) thread_local int alias_slot = 41;
#endif
}
EXPORTED int emutls_read_alias(void* control, Accessor native) {
  native_accessor = native;
#if !defined(EMUTLS_NAMED_ALIAS_IMPORT)
  alias_slot = 73;
#endif
  return *static_cast<int*>(fixture_named_accessor(control));
}
#elif defined(EMUTLS_MIXED_VERSIONS) || defined(EMUTLS_MANAGED_VERSION)
static thread_local int own_slot = 17;
EXPORTED int* emutls_own_slot() { return &own_slot; }
#if defined(EMUTLS_MIXED_VERSIONS)
extern "C" void* old_accessor(void*);
__asm__(".symver old_accessor,__emutls_get_address@TEST_EMUTLS_OLD");
EXPORTED void* emutls_old_slot(void* control) { return old_accessor(control); }
#endif
#elif defined(EMUTLS_MIXED_LOCAL)
alignas(128) thread_local int fixture_shared = 42;
extern "C" void* imported_accessor(void*);
__asm__(".symver imported_accessor,__emutls_get_address@TEST_EMUTLS_MANAGED");
EXPORTED int* emutls_slot() { return &fixture_shared; }
EXPORTED void* emutls_imported_slot(void* control) { return imported_accessor(control); }
#elif defined(EMUTLS_VERSIONED_PROBE)
extern "C" {
__attribute__((visibility("default"))) thread_local int versioned_slot = 42;
void* __emutls_get_address(void*);
}
// Both the explicit reference and Clang's TLS accesses import the non-default definition.
__asm__(".symver __emutls_get_address,__emutls_get_address@TEST_EMUTLS_OLD");
EXPORTED bool emutls_version_matches(void* public_accessor, void* default_accessor) {
  const auto direct = &__emutls_get_address;
  if (public_accessor != reinterpret_cast<void*>(direct) || versioned_slot != 42) return false;
  versioned_slot = 99;
  // A by-name control would be paired with the incompatible default accessor.
  dlerror();
  if (dlsym(RTLD_DEFAULT, "__emutls_v.versioned_slot") || !dlerror()) return false;
  void* scopes[] = {RTLD_DEFAULT, RTLD_NEXT};
  for (void* scope : scopes) {
    if (dlsym(scope, "__emutls_get_address") != default_accessor ||
        dlvsym(scope, "__emutls_get_address", "TEST_EMUTLS") != default_accessor)
      return false;
    const auto accessor = reinterpret_cast<decltype(direct)>(
        dlvsym(scope, "__emutls_get_address", "TEST_EMUTLS_OLD"));
    if (accessor != direct || versioned_slot != 99) return false;
  }
  return !dlvsym(RTLD_NEXT, "__emutls_get_address", "MISSING_EMUTLS") && dlerror();
}
#elif defined(EMUTLS_IMPORT)
EXPORTED int* emutls_consumer_slot() { return &fixture_shared; }
#if defined(EMUTLS_SECOND_CONTROL)
EXPORTED int* emutls_consumer_second() { return &fixture_second; }
#endif
EXPORTED int* emutls_consumer_local_slot() {
  static thread_local int value = 19;
  return &value;
}
#elif defined(EMUTLS_LOOKUP_ROOT)
extern "C" int* emutls_slot();
static thread_local int root_slot;
EXPORTED int* emutls_root_slot(bool dependency) { return dependency ? emutls_slot() : &root_slot; }
#else
alignas(128) thread_local int fixture_shared = 42;
#if defined(EMUTLS_SECOND_CONTROL)
thread_local int fixture_second = 19;
#endif
static thread_local int zero;
static thread_local int constructions;

#if defined(EMUTLS_FINALIZER_PROBE)
static int* finalizer_counts;
static int* global_destructor_calls;
static pthread_barrier_t* thread_exit_barrier;
static pthread_barrier_t* key_creation_barrier;
static pthread_barrier_t* index_lock_barrier;
EXPORTED void emutls_gate_key_creation(pthread_barrier_t* gate) {
  __atomic_store_n(&key_creation_barrier, gate, __ATOMIC_RELEASE);
}
EXPORTED void emutls_gate_index_lock(pthread_barrier_t* gate) {
  __atomic_store_n(&index_lock_barrier, gate, __ATOMIC_RELEASE);
}
EXPORTED int emutls_run_once(pthread_once_t* control, void (*initialize)()) {
  return pthread_once(control, initialize);
}
EXPORTED int emutls_nested_once(bool exit_thread) {
  static pthread_once_t outer = PTHREAD_ONCE_INIT, inner = PTHREAD_ONCE_INIT;
  static int completed;
  if (exit_thread)
    return pthread_once(&outer, [] { pthread_once(&inner, [] { pthread_exit(nullptr); }); });
  if (pthread_once(&outer, [] { ++completed; }) || pthread_once(&inner, [] { ++completed; }))
    return -1;
  return completed;
}
extern "C" int __real_pthread_key_create(pthread_key_t*, void (*)(void*));
static void pause_at(pthread_barrier_t*& armed) {
  if (auto* gate = __atomic_exchange_n(&armed, nullptr, __ATOMIC_ACQ_REL)) {
    pthread_barrier_wait(gate);
    pthread_barrier_wait(gate);
  }
}
extern "C" int __wrap_pthread_key_create(pthread_key_t* key, void (*destroy)(void*)) {
  pause_at(key_creation_barrier);
  return __real_pthread_key_create(key, destroy);
}
extern "C" int __real_pthread_mutex_lock(pthread_mutex_t*);
extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex) {
  const int error = __real_pthread_mutex_lock(mutex);
  if (!error) pause_at(index_lock_barrier);
  return error;
}
static void (*key_exit_hook)(void*);
static void* key_exit_data;
extern "C" int module_answer();
extern "C" void module_count_key_exit(void*);
EXPORTED int* emutls_slot();
static int contains_pc(dl_phdr_info* info, size_t, void* pc) {
  const auto address = reinterpret_cast<uintptr_t>(pc);
  for (size_t i = 0; i < info->dlpi_phnum; ++i) {
    const auto& segment = info->dlpi_phdr[i];
    const auto start = info->dlpi_addr + segment.p_vaddr;
    if (segment.p_type == PT_LOAD && address >= start && address - start < segment.p_memsz)
      return 1;
  }
  return 0;
}
static void check_finalizer_lookup() {
  void* self = reinterpret_cast<void*>(emutls_slot);
  void* dependency = reinterpret_cast<void*>(module_answer);
  if (dlsym(RTLD_DEFAULT, "emutls_slot") != self ||
      dlsym(RTLD_DEFAULT, "module_answer") != dependency || !dl_iterate_phdr(contains_pc, self) ||
      !dl_iterate_phdr(contains_pc, dependency))
    abort();
}
#endif
struct Counter {
  Counter() { ++constructions; }
  ~Counter() {
#if defined(EMUTLS_FINALIZER_PROBE)
    // The dependency clears its global in its own ELF finalizer.
    if (finalizer_counts && module_answer() != 42) abort();
    if (finalizer_counts) check_finalizer_lookup();
    if (global_destructor_calls && *global_destructor_calls) abort();
    if (thread_exit_barrier) {
      pthread_barrier_wait(thread_exit_barrier);
      pthread_barrier_wait(thread_exit_barrier);
    }
#endif
    if (result) __atomic_add_fetch(result, 1, __ATOMIC_RELAXED);
  }
  int* result = nullptr;
};
static thread_local Counter counter;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t key;
static bool key_created;

static void check_storage(void* opaque) {
#if defined(EMUTLS_FINALIZER_PROBE)
  if (key_exit_hook) {
    key_exit_hook(opaque);
    return;
  }
  if (finalizer_counts) check_finalizer_lookup();
#endif
  // pthread key destructors run after C++ thread_local objects. Trivial TLS is
  // still readable in the first round at the value stored before thread exit.
  static_cast<int*>(opaque)[1] = fixture_shared;
}
static void make_key() {
  if (pthread_key_create(&key, check_storage) != 0) abort();
  key_created = true;
}
__attribute__((destructor)) static void delete_key() {
  if (key_created && pthread_key_delete(key) != 0) abort();
}

EXPORTED int* emutls_slot() { return &fixture_shared; }
EXPORTED int* emutls_zero() { return &zero; }
EXPORTED int emutls_on_exit(int* result) {
  counter.result = result;
  if (pthread_once(&once, make_key) != 0 || pthread_setspecific(key, result) != 0) abort();
  return constructions;
}
#if defined(EMUTLS_FINALIZER_PROBE)
EXPORTED void emutls_arm_finalizer(int* counts) { finalizer_counts = counts; }
EXPORTED void emutls_wait_in_thread_destructor(pthread_barrier_t* barrier) {
  thread_exit_barrier = barrier;
}
EXPORTED void emutls_arm_key_finalizer(void (*hook)(void*), void* data) {
  key_exit_hook = hook;
  key_exit_data = data;
  if (pthread_once(&once, make_key) != 0) abort();
}
static void touch_finalizer_tls() {
  ++finalizer_counts[0];
  if (fixture_shared != 42) abort();
  fixture_shared = 83;
  if (emutls_on_exit(finalizer_counts + 1) != 1) abort();
}
__attribute__((destructor)) static void touch_tls_on_unload() {
  if (key_exit_hook && pthread_setspecific(key, key_exit_data) != 0) abort();
  if (!finalizer_counts || global_destructor_calls) return;
  pthread_key_t dependency_key;
  pthread_t peer;
  if (pthread_key_create(&dependency_key, module_count_key_exit) ||
      pthread_create(
          &peer, nullptr,
          [](void* opaque) -> void* {
            if (pthread_setspecific(*static_cast<pthread_key_t*>(opaque), finalizer_counts + 4))
              abort();
            return nullptr;
          },
          &dependency_key) ||
      pthread_join(peer, nullptr) || pthread_key_delete(dependency_key))
    abort();
  touch_finalizer_tls();
}
EXPORTED void emutls_arm_global_finalizers(int* counts) {
  finalizer_counts = counts;
  global_destructor_calls = counts + 3;
  // Both destructors use this DSO's __cxa_atexit cookie. The one registered last
  // acquires TLS; the earlier one must still be pending when the thread destructor runs.
  struct Global {
    ~Global() {
      check_finalizer_lookup();
      ++*global_destructor_calls;
    }
  };
  struct Touch {
    ~Touch() { touch_finalizer_tls(); }
  };
  static Global global;
  static Touch touch;
}
#endif
#if defined(EMUTLS_MANAGED_PROBE)
static pthread_key_t rearmed_key;
static pthread_key_t forwarded_key;
static int* key_rounds;
static void rearm_key(void* previous) {
  pthread_key_t next_key = rearmed_key;
  void* next = &rearmed_key;
  const int round = ++*key_rounds;
  if (round == 1) {
    zero = 73;
    next = &zero;
  } else if (round == 2) {
    if (zero != 73 || previous != &zero) abort();
    // Hand an existing block to a different key for the next dispatch round.
    fixture_shared = 91;
    next_key = forwarded_key;
    next = &fixture_shared;
  } else if (round == 3 && (fixture_shared != 91 || previous != &fixture_shared)) {
    abort();
  }
  if (pthread_setspecific(next_key, next) != 0) abort();
}
EXPORTED void* emutls_arm_key_rounds(pthread_key_t* number, int* rounds) {
  // Warm one block now. The first key callback creates a different block in the same table.
  if (fixture_shared != 42 || pthread_key_create(&rearmed_key, rearm_key) != 0 ||
      pthread_key_create(&forwarded_key, rearm_key) != 0 ||
      pthread_setspecific(rearmed_key, &rearmed_key) != 0)
    abort();
  key_rounds = rounds;
  *number = rearmed_key;
  return &rearmed_key;
}
__attribute__((destructor)) static void delete_rearmed_key() {
  if (key_rounds &&
      (pthread_key_delete(rearmed_key) != 0 || pthread_key_delete(forwarded_key) != 0))
    abort();
}

static int* finalizer_key_result;
static pthread_key_t finalizer_key;
EXPORTED void emutls_arm_finalizer_key(int* result) { finalizer_key_result = result; }

static void check_finalizer_key(void* saved) {
  // Read the current thread's live variable before comparing its address with the key.
  *finalizer_key_result = fixture_shared == 83 && &fixture_shared == saved ? 1 : -1;
  if (pthread_key_delete(finalizer_key) != 0) abort();
}

__attribute__((destructor)) static void publish_finalizer_tls() {
  if (!finalizer_key_result) return;
  if (fixture_shared != 42 || pthread_key_create(&finalizer_key, check_finalizer_key)) abort();
  fixture_shared = 83;
  if (pthread_setspecific(finalizer_key, &fixture_shared) != 0) abort();
}

template <size_t Index>
static int* numbered_slot() {
  static thread_local int value = Index;
  return &value;
}
template <size_t... Indices>
static int* slot_at(size_t index, std::index_sequence<Indices...>) {
  using Slot = int* (*)();
  static constexpr Slot slots[] = {numbered_slot<Indices>...};
  return index < sizeof...(Indices) ? slots[index]() : nullptr;
}
EXPORTED int* emutls_numbered_slot(size_t index) {
  return slot_at(index, std::make_index_sequence<64>{});
}

extern "C" void* __emutls_get_address(void*);
EXPORTED bool emutls_lookup_matches(bool has_next) {
  void* direct = reinterpret_cast<void*>(__emutls_get_address);
  if (dlsym(RTLD_DEFAULT, "__emutls_get_address") != direct || dlerror()) return false;
  void* next = dlsym(RTLD_NEXT, "__emutls_get_address");
  return has_next ? next == direct && !dlerror() : !next && dlerror();
}

EXPORTED bool emutls_system_storage(void* handle, void* expected_accessor, void* expected_control) {
  const auto accessor =
      reinterpret_cast<decltype(&__emutls_get_address)>(dlsym(handle, "__emutls_get_address"));
  void* control = dlsym(handle, "__emutls_v.fixture_shared");
  if (reinterpret_cast<void*>(accessor) != expected_accessor || accessor == &__emutls_get_address ||
      control != expected_control || dlerror())
    return false;
  auto* value = static_cast<int*>(accessor(control));
  if (!value || *value != 42) return false;
  *value = 93;
  return accessor(control) == value && *value == 93;
}

template <typename F>
static F lookup_key_function(void* scope, const char* name, const char* version) {
  if (dlvsym(scope, name, "YUKILINKER_MISSING_VERSION") || !dlerror()) abort();
  void* address = version ? dlvsym(scope, name, version) : dlsym(scope, name);
  if (!address || dlerror()) abort();
  return reinterpret_cast<F>(address);
}

EXPORTED bool emutls_explicit_key_lookup(void* libc, const char* name, const char* version,
                                         void* expected) {
  void* address = version ? dlvsym(libc, name, version) : dlsym(libc, name);
  return address == expected && !dlerror();
}

EXPORTED void emutls_count_key_exit(void* value) { ++*static_cast<int*>(value); }

static int* shutdown_key_result;
EXPORTED void emutls_arm_shutdown_key(int* result) { shutdown_key_result = result; }
__attribute__((destructor)) static void delete_shutdown_key_on_peer() {
  if (!shutdown_key_result) return;
  struct Keys {
    pthread_key_t erased, on_exit;
  } keys;
  if (pthread_key_create(&keys.erased, emutls_count_key_exit) ||
      pthread_setspecific(keys.erased, shutdown_key_result) ||
      pthread_key_create(&keys.on_exit, emutls_count_key_exit))
    abort();
  pthread_t peer;
  if (pthread_create(
          &peer, nullptr,
          [](void* opaque) -> void* {
            auto& keys = *static_cast<Keys*>(opaque);
            if (pthread_key_delete(keys.erased) ||
                pthread_setspecific(keys.on_exit, shutdown_key_result + 1) || fixture_shared != 42)
              abort();
            counter.result = shutdown_key_result + 2;
            return nullptr;
          },
          &keys) ||
      pthread_join(peer, nullptr) || pthread_key_delete(keys.on_exit))
    abort();
  ++*shutdown_key_result;
}

EXPORTED auto emutls_create_key(pthread_key_t* key, void (*destroy)(void*))
    -> decltype(&pthread_key_delete) {
  return pthread_key_create(key, destroy) == 0 ? &pthread_key_delete : nullptr;
}

EXPORTED int emutls_set_key(pthread_key_t key, const void* value) {
  return pthread_setspecific(key, value);
}
EXPORTED int emutls_delete_key(pthread_key_t key) { return pthread_key_delete(key); }

EXPORTED auto emutls_arm_key(pthread_key_t* key, int* calls) -> decltype(&pthread_key_delete) {
  if (pthread_key_create(key, emutls_count_key_exit) || pthread_setspecific(*key, calls)) abort();
  return &pthread_key_delete;
}

EXPORTED bool emutls_mixed_key_lookup(void* scope, const char* self_path, const char* version,
                                      int* calls) {
  if (self_path) {
    scope = dlopen(self_path, RTLD_NOW | RTLD_NOLOAD);
    if (!scope) abort();
  }
  const auto create =
      lookup_key_function<decltype(&pthread_key_create)>(scope, "pthread_key_create", version);
  const auto set =
      lookup_key_function<decltype(&pthread_setspecific)>(scope, "pthread_setspecific", version);
  const auto erase =
      lookup_key_function<decltype(&pthread_key_delete)>(scope, "pthread_key_delete", version);
  struct Worker {
    pthread_key_t direct, dynamic, deleted;
    decltype(set) set_value;
    decltype(erase) delete_key;
    int* calls;
  } worker{{}, {}, {}, set, erase, calls};
  if (pthread_key_create(&worker.direct, emutls_count_key_exit) ||
      create(&worker.dynamic, emutls_count_key_exit) ||
      pthread_key_create(&worker.deleted, emutls_count_key_exit))
    abort();
  pthread_t thread;
  if (pthread_create(
          &thread, nullptr,
          [](void* opaque) -> void* {
            auto& w = *static_cast<Worker*>(opaque);
            if (w.set_value(w.direct, w.calls) || pthread_setspecific(w.dynamic, w.calls + 1) ||
                pthread_setspecific(w.deleted, w.calls + 2) || w.delete_key(w.deleted))
              abort();
            return nullptr;
          },
          &worker) ||
      pthread_join(thread, nullptr))
    abort();
  if (pthread_key_delete(worker.dynamic) || erase(worker.direct)) abort();
  if (self_path && dlclose(scope)) abort();
  return create == &pthread_key_create && set == &pthread_setspecific &&
         erase == &pthread_key_delete;
}
#endif
static pthread_once_t external_once = PTHREAD_ONCE_INIT;
EXPORTED pthread_once_t* emutls_once_slot() { return &external_once; }
#endif
