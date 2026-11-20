// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// clang-format off: exercise mixed and repeated inclusion.
#include <yukilinker.h>
#include <yukilinker.hpp>
#include <yukilinker.hpp>
#include <yukilinker.h>
// clang-format on

#include <utility>

#include "../src/internal/operation_guards.hpp"
#include "control.hpp"
#include "host_services.h"
#include "relro_fixture.hpp"

#if (defined(__i386__) || defined(__x86_64__)) && !defined(YUKILINKER_TEST_CFI)
#include "x86_relocations.hpp"
#endif

#if defined(YUKILINKER_TEST_X86_CALLS)
void exercise_x86_calls(yukilinker::Runtime& runtime, const char* directory);
#endif

#if defined(YUKILINKER_TEST_NOEXCEPT)
#if defined(__EXCEPTIONS) || defined(__GXX_RTTI)
#error Consumer language flags were overridden
#endif
#else
#if !defined(__EXCEPTIONS) || !defined(__GXX_RTTI)
#error Runtime flags leaked into the consumer
#endif
#endif
static_assert(!std::is_copy_constructible_v<yukilinker::Module>);
static_assert(!std::is_move_assignable_v<yukilinker::Module>);
static_assert(!std::is_move_assignable_v<yukilinker::Runtime>);

#if !defined(YUKILINKER_TEST_CFI)
namespace {
using Slot = int* (*)();
using OnExit = int (*)(int*);
using VisitPhdr = int (*)(dl_phdr_info*, size_t, void*);
dl_phdr_info* short_phdr;
constexpr size_t short_size = offsetof(dl_phdr_info, dlpi_adds);

int iterate_host(void* user, VisitPhdr visit, void* data) {
  if (short_phdr) return visit(short_phdr, short_size, data);
  return test_iterate(user, visit, data);
}

void check_oreo_phdr(yukilinker::Module& module) {
  const auto iterate = module.symbol<int (*)(VisitPhdr, void*)>("module_iterate");
  assert(iterate);
  const size_t page = sysconf(_SC_PAGESIZE);
  auto* memory = static_cast<char*>(
      mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  assert(memory != MAP_FAILED && mprotect(memory + page, page, PROT_NONE) == 0);
  // The next page traps even read-only access beyond Oreo's callback record.
  dl_phdr_info sample{};
  sample.dlpi_name = "short-phdr";
  short_phdr = reinterpret_cast<dl_phdr_info*>(memory + page - short_size);
  memcpy(short_phdr, &sample, short_size);
  assert(iterate.value(
             [](dl_phdr_info* value, size_t size, void*) {
               assert(size == short_size && !strcmp(value->dlpi_name, "short-phdr"));
               return 79;
             },
             nullptr) == 79);
  short_phdr = nullptr;
  assert(munmap(memory, page * 2) == 0);
}

void check_signal_mask() {
  const auto bit = [](int signal) { return UINT64_C(1) << (signal - 1); };
  const auto mask = [](const uint64_t* set) {
    uint64_t previous = 0;
    assert(syscall(SYS_rt_sigprocmask, SIG_SETMASK, set, &previous, sizeof(previous)) == 0);
    return previous;
  };
  const uint64_t original = mask(nullptr);
  const uint64_t seed = original | bit(SIGUSR1) | bit(SIGRTMIN + 1);
  mask(&seed);
  const uint64_t initial = mask(nullptr);
  assert((initial & bit(SIGUSR1)) && (initial & bit(SIGRTMIN + 1)));
  uint64_t realtime = 0;
  for (int signal = SIGRTMIN; signal <= SIGRTMAX; ++signal) realtime |= bit(signal);
  // User-mode QEMU can reserve the guest's highest signals for its own use.
  const uint64_t all_realtime = initial | realtime;
  mask(&all_realtime);
  const uint64_t available = mask(&initial) & realtime;
  assert(available & bit(SIGRTMIN));
  {
    yukilinker::internal::ScopedSignalBlocker outer;
    const uint64_t active = mask(nullptr);
    assert((active & bit(SIGUSR2)) && (active & realtime) == available);
    for (int signal : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGSYS})
      assert((active & bit(signal)) == (initial & bit(signal)));
    for (int signal = __SIGRTMIN; signal < SIGRTMIN; ++signal)
      assert((active & bit(signal)) == (initial & bit(signal)));
    {
      yukilinker::internal::ScopedSignalBlocker nested;
    }
    assert(mask(nullptr) == active);
  }
  assert(mask(&original) == initial);
}

void meet(pthread_barrier_t& barrier) {
  const int status = pthread_barrier_wait(&barrier);
  assert(status == 0 || status == PTHREAD_BARRIER_SERIAL_THREAD);
}

uint64_t monotonic_now() {
  timespec now{};
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return static_cast<uint64_t>(now.tv_sec) * UINT64_C(1000000000) + now.tv_nsec;
}

void exercise_load_wait(yukilinker::Runtime& runtime, const char* path) {
  pthread_barrier_t barrier;
  assert(pthread_barrier_init(&barrier, nullptr, 2) == 0);
  char address[32];
  snprintf(address, sizeof(address), "%llx",
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&barrier)));
  assert(setenv("YUKILINKER_TEST_WAIT_BARRIER", address, 1) == 0);
  struct Open {
    yukilinker::Runtime& runtime;
    const char* path;
    yukilinker::Module module;
    static void* run(void* opaque) {
      auto& self = *static_cast<Open*>(opaque);
      auto result = self.runtime.open_path(self.path);
      assert(result);
      self.module.swap(result.value);
      return nullptr;
    }
  } first{runtime, path, {}}, second{runtime, path, {}};
  pthread_t loader, waiter;
  assert(pthread_create(&loader, nullptr, Open::run, &first) == 0);
  meet(barrier);
  constexpr uint64_t timeout = 30000000;
  assert(yukilinker_c_wait_timeout(runtime.native_handle(), timeout) == YUKILINKER_C_OK);
  const uint64_t start = monotonic_now();
  auto refused = runtime.open_path(path);
  assert(!refused && refused.error.code() == yukilinker::Code::Busy &&
         monotonic_now() - start >= timeout);
  assert(yukilinker_c_wait_timeout(runtime.native_handle(), 0) == YUKILINKER_C_OK);
  assert(pthread_create(&waiter, nullptr, Open::run, &second) == 0);
  const uint64_t limit = monotonic_now() + UINT64_C(10000000000);
  bool waiting = false;
  do {
    yukilinker_c_load_wait slots[8]{};
    slots[0].size = sizeof(slots[0]);
    size_t count = 0;
    assert(yukilinker_c_load_waits(runtime.native_handle(), slots, 8, &count) == YUKILINKER_C_OK);
    for (size_t i = 0; i < count; ++i) waiting |= slots[i].kind == YUKILINKER_C_LOAD_WAIT_WAIT;
    if (!waiting) usleep(1000);
  } while (!waiting && monotonic_now() < limit);
  assert(waiting);
  meet(barrier);
  assert(pthread_join(loader, nullptr) == 0 && pthread_join(waiter, nullptr) == 0);
  assert(unsetenv("YUKILINKER_TEST_WAIT_BARRIER") == 0 && pthread_barrier_destroy(&barrier) == 0);
  assert(first.module.close().handle_valid());
  assert(second.module.close().private_mapping_unmapped());
  assert(!first.module.close().handle_valid());
}

struct TlsWorker {
  Slot slot, zero, imported;
  OnExit on_exit;
  int* dtors;
  int* address = nullptr;
  pthread_t thread{};
  pthread_barrier_t barrier{};

  void start() {
    assert(pthread_barrier_init(&barrier, nullptr, 2) == 0);
    assert(pthread_create(&thread, nullptr, run, this) == 0);
    meet(barrier);
  }
  void finish() {
    meet(barrier);
    assert(pthread_join(thread, nullptr) == 0 && pthread_barrier_destroy(&barrier) == 0);
  }
  static void* run(void* opaque) {
    auto& self = *static_cast<TlsWorker*>(opaque);
    self.address = self.slot();
    assert(self.address && reinterpret_cast<uintptr_t>(self.address) % 128 == 0);
    assert(*self.address == 42 && *self.zero() == 0);
    if (self.imported) assert(self.imported() == self.address);
    *self.address = 74;
    *self.zero() = 13;
    assert(self.slot() == self.address && *self.slot() == 74 && *self.zero() == 13);
    if (self.dtors) assert(self.on_exit(self.dtors) == 1 && self.on_exit(self.dtors) == 1);
    meet(self.barrier);
    meet(self.barrier);
    return nullptr;
  }
};

auto open_fixture(yukilinker::Runtime& runtime, const char* directory, const char* form,
                  yukilinker::OpenOptions options = yukilinker::OpenOptions{}) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/libemutls_%s.so", directory, form);
  return runtime.open_path(path, options);
}

using NumberedSlot = int* (*)(size_t);
NumberedSlot signal_slot;

#if defined(__i386__)
// QEMU 8 enters an i386 signal handler with a different stack alignment from a normal call.
__attribute__((force_align_arg_pointer))
#endif
void grow_emutls_table_in_signal(int) {
  for (int i = 1; i < 64; ++i) {
    int* value = signal_slot(i);
    assert(*value == i);
    *value = -i;
  }
}

void check_emutls_table(yukilinker::Module& module) {
  const auto slot = module.symbol<NumberedSlot>("emutls_numbered_slot");
  assert(slot);
  signal_slot = slot.value;
  struct sigaction handler{}, previous{};
  handler.sa_handler = grow_emutls_table_in_signal;
  sigemptyset(&handler.sa_mask);
  assert(sigaction(SIGUSR2, &handler, &previous) == 0);
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void*) -> void* {
               sigset_t unblock;
               sigemptyset(&unblock);
               sigaddset(&unblock, SIGUSR2);
               assert(pthread_sigmask(SIG_UNBLOCK, &unblock, nullptr) == 0);
               int* first = signal_slot(0);
               assert(*first == 0);
               *first = 42;
               assert(raise(SIGUSR2) == 0 && signal_slot(0) == first && *first == 42);
               for (int i = 63; i > 0; --i) assert(*signal_slot(i) == -i);
               return nullptr;
             },
             nullptr) == 0);
  assert(pthread_join(worker, nullptr) == 0 && sigaction(SIGUSR2, &previous, nullptr) == 0);
  signal_slot = nullptr;
}

void check_mixed_key_lookup(yukilinker::Runtime& runtime, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/libemutls_weak.so", directory);
  auto module = runtime.open_path(path);
  assert(module);
  check_emutls_table(module.value);
  const auto keys = module.value.symbol<bool (*)(void*, const char*, const char*, int*)>(
      "emutls_mixed_key_lookup");
  const auto explicit_lookup =
      module.value.symbol<bool (*)(void*, const char*, const char*, void*)>(
          "emutls_explicit_key_lookup");
  // Borrow only symbols already present in Bionic; the module retains its own open reference
  // throughout pthread_join so the failure case is safe to inspect.
  void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
  assert(keys && explicit_lookup && libc);
  const struct {
    void* handle;
    const char* self_path;
  } scopes[] = {{RTLD_DEFAULT, nullptr}, {RTLD_NEXT, nullptr}, {nullptr, path}};
  const char* versions[] = {nullptr, "LIBC"};
  for (const char* version : versions) {
    for (const auto& scope : scopes) {
      int calls[3]{};
      const bool matches = keys.value(scope.handle, scope.self_path, version, calls);
      if (calls[0] != 1 || calls[1] != 1 || calls[2] != 0)
        fprintf(stderr, "pthread key destructors (%s): direct=%d dynamic=%d deleted=%d\n",
                version ? version : "unversioned", calls[0], calls[1], calls[2]);
      assert(calls[0] == 1 && calls[1] == 1 && calls[2] == 0);
      assert(matches);
    }
    for (const char* name : {"pthread_key_create", "pthread_setspecific", "pthread_key_delete"}) {
      void* expected = version ? dlvsym(libc, name, version) : dlsym(libc, name);
      assert(expected && explicit_lookup.value(libc, name, version, expected));
    }
  }
  assert(dlclose(libc) == 0 && module.value.close().private_mapping_unmapped());
  puts("PASS mixed pthread key lookup, destructor counts and unload");
}

void check_deleted_key_shutdown(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  using DeleteKey = int (*)(pthread_key_t);
  const auto arm = module.value.symbol<DeleteKey (*)(pthread_key_t*, int*)>("emutls_arm_key");
  assert(arm);
  int calls = 0;
  struct Release {
    yukilinker::Runtime& runtime;
    yukilinker::Module& module;
    pthread_key_t key;
    DeleteKey erase;
  } release{runtime, module.value, {}, nullptr};
  release.erase = arm.value(&release.key, &calls);
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* opaque) -> void* {
               auto& r = *static_cast<Release*>(opaque);
               assert(r.erase(r.key) == 0 && r.module.close().private_mapping_unmapped());
               // The main thread still has a Bionic dispatch callback armed for its empty record.
               const auto result = r.runtime.try_shutdown();
               assert(!result.complete && result.error.code == YUKILINKER_C_BUSY);
               return nullptr;
             },
             &release) == 0);
  assert(pthread_join(worker, nullptr) == 0 && calls == 0);
  auto scope = runtime.namespace_create();
  assert(scope && scope.link(nullptr, YUKILINKER_C_NAMESPACE_LINK_SYSTEM,
                             "libc.so:libdl.so:libm.so:libc++_shared.so") == yukilinker::Code::Ok);
  for (bool scoped : {true, false}) {
    yukilinker::OpenOptions global;
    global.native.flags |= RTLD_GLOBAL;
    if (scoped) global.native.namespace_scope = scope.native_handle();
    auto finalizer = open_fixture(runtime, directory, "shared", global);
    assert(finalizer);
    auto arm_shutdown = finalizer.value.symbol<void (*)(int*)>("emutls_arm_shutdown_key");
    assert(arm_shutdown);
    int counts[3]{};
    arm_shutdown.value(counts);
    assert(finalizer.value.close().handle_valid() &&
           finalizer.value.forget() == yukilinker::Code::Ok);
    if (scoped)
      assert(scope.destroy() == yukilinker::Code::Ok);
    else
      assert(runtime.try_shutdown().complete);
    assert(counts[0] == 1 && counts[1] == 1 && counts[2] == 1);
  }
}

void finish_thread_close(yukilinker::Module& module) {
  // The join can wake before the kernel stops recognizing the TID. Only an
  // ordinary retained reference may bridge that interval.
  const uint64_t deadline = monotonic_now() + UINT64_C(2000000000);
  auto done = module.close();
  while (done.handle_valid()) {
    assert(done.reference() == yukilinker::Reference::Released &&
           done.retention_reasons() == YUKILINKER_C_RETENTION_PRIVATE_HOLD &&
           done.native.error.detail.code == YUKILINKER_C_OK &&
           !done.native.error.detail.cleanup_incomplete && !done.private_mapping_unmapped() &&
           monotonic_now() < deadline);
    usleep(1000);
    done = module.close();
  }
  assert(done.private_mapping_unmapped() && done.native.error.detail.code == YUKILINKER_C_OK);
}

void check_late_tls_close(yukilinker::Module& module, Slot slot, OnExit on_exit = nullptr) {
  struct LateAccess {
    Slot slot;
    OnExit on_exit;
    int calls[2]{};
    pthread_key_t key{};
    pthread_barrier_t barrier{};
    unsigned round = 0;

    static void finalize(void* opaque) {
      auto& state = *static_cast<LateAccess*>(opaque);
      if (++state.round < PTHREAD_DESTRUCTOR_ITERATIONS) {
        assert(pthread_setspecific(state.key, &state) == 0);
        return;
      }
      // This is the thread's first access, in Bionic's final key destructor
      // round. A newly created key may never run its destructor on this thread.
      int* address = state.slot();
      assert(address && *address == 42);
      if (state.on_exit) assert(state.on_exit(state.calls) == 1);
      *address = 81;
      meet(state.barrier);
      meet(state.barrier);
      assert(*address == 81);
    }
  } state{slot, on_exit};
  assert(pthread_barrier_init(&state.barrier, nullptr, 2) == 0);
  assert(pthread_key_create(&state.key, LateAccess::finalize) == 0);
  pthread_t thread;
  assert(pthread_create(
             &thread, nullptr,
             [](void* opaque) -> void* {
               auto& value = *static_cast<LateAccess*>(opaque);
               assert(pthread_setspecific(value.key, &value) == 0);
               return nullptr;
             },
             &state) == 0);
  meet(state.barrier);
  const auto holding = module.close();
  assert(holding.handle_valid() && holding.reference() == yukilinker::Reference::Released &&
         !holding.private_mapping_unmapped());
  meet(state.barrier);
  assert(pthread_join(thread, nullptr) == 0 && state.round == PTHREAD_DESTRUCTOR_ITERATIONS);
  assert(pthread_key_delete(state.key) == 0 && pthread_barrier_destroy(&state.barrier) == 0);
  finish_thread_close(module);
  // Bionic's C++ destructor pass ended before the last key round registered this object.
  assert(state.calls[0] == 0);
}

void check_finalizer_tls(yukilinker::Runtime& runtime, const char* directory, bool global,
                         bool cxa_finalizers) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/libemutls_local.so", directory);
  auto scope = runtime.namespace_create();
  assert(scope && scope.link(nullptr, YUKILINKER_C_NAMESPACE_LINK_SYSTEM,
                             "libc.so:libdl.so:libm.so") == yukilinker::Code::Ok);
  yukilinker::OpenOptions options;
  options.native.namespace_scope = scope.native_handle();
  if (global) options.native.flags |= RTLD_GLOBAL;
  auto module = runtime.open_path(path, options);
  assert(module);
  const auto arm = module.value.symbol<void (*)(int*)>(
      cxa_finalizers ? "emutls_arm_global_finalizers" : "emutls_arm_finalizer");
  assert(arm);
  int counts[5]{};
  arm.value(counts);
  if (global)
    assert(module.value.close().handle_valid() && module.value.forget() == yukilinker::Code::Ok);
  struct Retirement {
    yukilinker::Namespace& scope;
    yukilinker::Module& module;
    int* counts;
  } state{scope, module.value, counts};
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* opaque) -> void* {
               auto& r = *static_cast<Retirement*>(opaque);
               // A retry while this thread still owns TLS must preserve its callbacks and token.
               for (int attempt = 0; attempt < 2; ++attempt) {
                 if (r.module) {
                   const auto held = r.module.close();
                   assert(held.code() == yukilinker::Code::Ok && held.handle_valid() &&
                          held.reference() == yukilinker::Reference::Released &&
                          held.retention_reasons() == YUKILINKER_C_RETENTION_PRIVATE_HOLD &&
                          !held.native.error.detail.cleanup_incomplete &&
                          !held.private_mapping_unmapped());
                 } else {
                   assert(r.scope.destroy() == yukilinker::Code::IoError && r.scope);
                 }
                 assert(r.counts[0] == 1 && !r.counts[1] && !r.counts[2] && !r.counts[3]);
               }
               return nullptr;
             },
             &state) == 0);
  assert(pthread_join(worker, nullptr) == 0);
  if (module.value) assert(module.value.close().private_mapping_unmapped() && !module.value);
  assert(scope.destroy() == yukilinker::Code::Ok && !scope);
  assert(counts[0] == 1 && counts[1] == 1 && counts[2] == 83 && counts[3] == cxa_finalizers);
  assert(counts[4] == !cxa_finalizers);
}

pid_t controlled_fork(yukilinker::Runtime& runtime) {
  yukilinker_c_prepare_fork(runtime.native_handle());
  const pid_t child = fork();
  assert(child >= 0);
  yukilinker_c_after_fork(runtime.native_handle(), child == 0);
  return child;
}

template <typename Check>
void run_on_worker(Check check) {
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* opaque) -> void* {
               (*static_cast<Check*>(opaque))();
               return nullptr;
             },
             &check) == 0);
  assert(pthread_join(worker, nullptr) == 0);
}

volatile sig_atomic_t key_updates_left, updating_key, signal_in_update, key_signals;

void check_key_frame_signals(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  using Delete = decltype(&pthread_key_delete);
  auto arm = module.value.symbol<Delete (*)(pthread_key_t*, int*)>("emutls_arm_key");
  assert(arm);
  struct sigaction handler{}, previous{};
  handler.sa_handler = [](int) {
    if (updating_key) signal_in_update = 1;
    ++key_signals;
  };
  assert(sigaction(SIGUSR1, &handler, &previous) == 0);
  pthread_key_t key;
  Delete erase = nullptr;
  int calls = 0;
  key_signals = signal_in_update = 0;
  run_on_worker([&] {
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    assert(pthread_sigmask(SIG_UNBLOCK, &signals, nullptr) == 0);
    erase = arm.value(&key, &calls);
    key_updates_left = 2;
  });
  assert(!key_updates_left && key_signals == 2 && calls == 1);
  assert(!signal_in_update);
  assert(erase(key) == 0 && module.value.close().private_mapping_unmapped());
  auto local = open_fixture(runtime, directory, "local");
  assert(local);
  auto once = local.value.symbol<decltype(&pthread_once)>("emutls_run_once");
  assert(once);
  run_on_worker([&] {
    pthread_once_t control = PTHREAD_ONCE_INIT;
    key_updates_left = 2;
    assert(once.value(&control, [] {
      sigset_t mask;
      assert(pthread_sigmask(SIG_BLOCK, nullptr, &mask) == 0 && !sigismember(&mask, SIGUSR1));
    }) == 0);
    assert(!key_updates_left && key_signals == 4 && !signal_in_update);
  });
  assert(sigaction(SIGUSR1, &previous, nullptr) == 0 &&
         local.value.close().private_mapping_unmapped());
}

OnExit initialize_in_prepare, initialize_in_child;
pthread_barrier_t* prepare_key_gate;
int prepare_counts[2];
bool child_once_checked;
void* child_unmap_page;
size_t child_unmap_size;

void prepare_thread_local() {
  if (prepare_key_gate) meet(*prepare_key_gate);
  if (initialize_in_prepare) assert(initialize_in_prepare(prepare_counts) == 1);
}

void child_thread_local() {
  // Also enforce DONTFORK for emulators that leave the guest mapping inherited.
  if (child_unmap_page) assert(munmap(child_unmap_page, child_unmap_size) == 0);
  if (initialize_in_child) {
    assert(initialize_in_child(prepare_counts) == 1);
    child_once_checked = true;
  }
}

enum class ForkTls { Managed, LocalPrepare, LocalChild };
void check_thread_local_at_fork(yukilinker::Runtime& runtime, const char* directory, ForkTls mode) {
  const bool local = mode != ForkTls::Managed;
  auto module = open_fixture(runtime, directory, local ? "local" : "weak");
  assert(module);
  auto initialize = module.value.symbol<OnExit>("emutls_on_exit");
  assert(initialize);
  pthread_t initializer{};
  pthread_barrier_t gate{};
  Slot slot = nullptr;
  if (local) {
    auto arm = module.value.symbol<void (*)(pthread_barrier_t*)>("emutls_gate_key_creation");
    auto lookup = module.value.symbol<Slot>("emutls_slot");
    assert(arm && lookup && pthread_barrier_init(&gate, nullptr, 2) == 0);
    slot = lookup.value;
    arm.value(&gate);
    assert(pthread_create(
               &initializer, nullptr,
               [](void* address) -> void* {
                 assert(*(*static_cast<Slot*>(address))() == 42);
                 return nullptr;
               },
               &slot) == 0);
    // The worker owns compiler-rt's once until the parent releases the gate.
    meet(gate);
  }
  prepare_counts[0] = prepare_counts[1] = 0;
  pthread_key_t report;
  assert(pthread_key_create(
             &report, [](void* count) { _exit(*static_cast<int*>(count) == 1 ? 42 : 1); }) == 0);
  run_on_worker([&] {
    const bool child_only = mode == ForkTls::LocalChild;
    initialize_in_child = initialize.value;
    initialize_in_prepare = child_only ? nullptr : initialize.value;
    prepare_key_gate = mode == ForkTls::LocalPrepare ? &gate : nullptr;
    const pid_t child = controlled_fork(runtime);
    prepare_key_gate = nullptr;
    initialize_in_prepare = initialize_in_child = nullptr;
    if (!child) {
      // Bionic runs C++ destructors before this key reports the child's result.
      assert(child_once_checked && pthread_setspecific(report, prepare_counts) == 0);
      return;
    }
    if (child_only) meet(gate);
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
  });
  if (local) assert(pthread_join(initializer, nullptr) == 0 && pthread_barrier_destroy(&gate) == 0);
  const bool ran_in_parent = mode != ForkTls::LocalChild;
  assert(pthread_key_delete(report) == 0 && prepare_counts[0] == (ran_in_parent ? 1 : 0) &&
         prepare_counts[1] == (ran_in_parent ? 42 : 0));
  assert(module.value.close().private_mapping_unmapped());
}

void check_quiescent_local_fork(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "local");
  assert(module);
  auto gate_lock = module.value.symbol<void (*)(pthread_barrier_t*)>("emutls_gate_index_lock");
  auto slot = module.value.symbol<Slot>("emutls_slot");
  auto zero = module.value.symbol<Slot>("emutls_zero");
  assert(gate_lock && slot && zero);
  struct Worker {
    Slot touch;
    pthread_barrier_t gate;
  } worker{slot.value, {}};
  assert(pthread_barrier_init(&worker.gate, nullptr, 2) == 0);
  gate_lock.value(&worker.gate);
  pthread_t peer;
  assert(
      pthread_create(
          &peer, nullptr,
          [](void* opaque) -> void* {
            auto& w = *static_cast<Worker*>(opaque);
            *w.touch() = 73;
            meet(w.gate);  // The module call has returned. Park until the parent admits work again.
            meet(w.gate);
            return nullptr;
          },
          &worker) == 0);
  meet(worker.gate);  // The peer is inside compiler-rt, holding its index mutex.
  meet(worker.gate);  // Let the in-flight access finish.
  meet(worker.gate);  // No other module call can start before fork.
  const pid_t child = controlled_fork(runtime);
  if (!child) {
    alarm(5);
    assert(*zero.value() == 0 && *slot.value() == 42);
    _exit(0);
  }
  meet(worker.gate);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  assert(pthread_join(peer, nullptr) == 0 && pthread_barrier_destroy(&worker.gate) == 0);
  assert(module.value.close().private_mapping_unmapped());
}

void check_linker_at_fork(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  auto initialize = module.value.symbol<OnExit>("emutls_on_exit");
  assert(initialize);
  // LIBC_P introduced getrandom and Bionic's linker pin for C++ thread destructors.
  const bool pins_dso = dlvsym(RTLD_DEFAULT, "getrandom", "LIBC_P") != nullptr;
  (void)dlerror();
  prepare_counts[0] = prepare_counts[1] = 0;
  run_on_worker([&] {
    if (pins_dso) assert(initialize.value(prepare_counts) == 1);
    pthread_barrier_t gate;
    assert(pthread_barrier_init(&gate, nullptr, 2) == 0);
    pthread_t peer;
    assert(pthread_create(
               &peer, nullptr,
               [](void* opaque) -> void* {
                 assert(dl_iterate_phdr(
                            [](dl_phdr_info*, size_t, void* opaque) {
                              auto& gate = *static_cast<pthread_barrier_t*>(opaque);
                              meet(gate);  // This thread owns Bionic's linker mutex.
                              meet(gate);  // The forking thread now owns Bionic's atfork mutex.
                              assert(pthread_atfork([] {}, nullptr, nullptr) == 0);
                              return 1;
                            },
                            opaque) == 1);
                 return nullptr;
               },
               &gate) == 0);
    meet(gate);
    prepare_key_gate = &gate;
    initialize_in_prepare = initialize.value;
    const pid_t child = controlled_fork(runtime);
    if (!child) _exit(0);
    initialize_in_prepare = nullptr;
    prepare_key_gate = nullptr;
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(pthread_join(peer, nullptr) == 0 && pthread_barrier_destroy(&gate) == 0);
  });
  assert(prepare_counts[0] == 1 && prepare_counts[1] == 42);
  assert(module.value.close().private_mapping_unmapped());
}

void check_once_owner(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "local");
  assert(module);
  auto once = module.value.symbol<decltype(&pthread_once)>("emutls_run_once");
  assert(once);
  static yukilinker::Runtime* forking_runtime;
  static pid_t child;
  static unsigned calls;
  forking_runtime = &runtime;
  calls = 0;
  pthread_once_t control = PTHREAD_ONCE_INIT;
  assert(once.value(&control, [] {
    ++calls;
    child = controlled_fork(*forking_runtime);
  }) == 0);
  assert(pthread_once(&control, [] { abort(); }) == 0 && calls == 1);
  if (!child) _exit(0);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  pthread_once_t abandoned = PTHREAD_ONCE_INIT;
  run_on_worker([&] { once.value(&abandoned, [] { pthread_exit(nullptr); }); });
  assert(once.value(&abandoned, [] { ++calls; }) == 0 && calls == 2);
  auto nested = module.value.symbol<int (*)(bool)>("emutls_nested_once");
  assert(nested);
  run_on_worker([&] { nested.value(true); });
  assert(nested.value(false) == 2);
  static pthread_barrier_t gate;
  assert(pthread_barrier_init(&gate, nullptr, 2) == 0);
  const size_t page = sysconf(_SC_PAGESIZE);
  for (bool shared : {true, false}) {
    auto* word = static_cast<pthread_once_t*>(
        mmap(nullptr, page, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | (shared ? MAP_SHARED : MAP_PRIVATE), -1, 0));
    assert(word != MAP_FAILED);
    *word = PTHREAD_ONCE_INIT;
    if (!shared) {
      assert(madvise(word, page, MADV_DONTFORK) == 0);
      child_unmap_page = word;
      child_unmap_size = page;
    }
    struct Worker {
      decltype(&pthread_once) run;
      pthread_once_t* word;
    } work{once.value, word};
    pthread_t peer;
    assert(pthread_create(
               &peer, nullptr,
               [](void* opaque) -> void* {
                 auto* w = static_cast<Worker*>(opaque);
                 assert(w->run(w->word, [] {
                   meet(gate);
                   meet(gate);
                 }) == 0);
                 return nullptr;
               },
               &work) == 0);
    meet(gate);
    const int running = __atomic_load_n(word, __ATOMIC_ACQUIRE);
    const pid_t pid = controlled_fork(runtime);
    if (!pid) _exit(0);
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(__atomic_load_n(word, __ATOMIC_ACQUIRE) == running);
    child_unmap_page = nullptr;
    meet(gate);
    assert(pthread_join(peer, nullptr) == 0);
    assert(pthread_once(word, [] { abort(); }) == 0 && munmap(word, page) == 0);
  }
  // A control residing in another PRIVATE image stays pinned until pthread_once finishes.
  auto control_module = open_fixture(runtime, directory, "weak");
  assert(control_module);
  auto once_slot = control_module.value.symbol<pthread_once_t* (*)()>("emutls_once_slot");
  assert(once_slot);
  pthread_once_t* remote_once = once_slot.value();
  // Exiting inside an initializer for a distinct PRIVATE control must drop the stack pin cleanly.
  run_on_worker([&] { once.value(remote_once, [] { pthread_exit(nullptr); }); });
  struct RemoteOnce {
    decltype(&pthread_once) run;
    pthread_once_t* word;
  } remote_work{once.value, remote_once};
  pthread_t remote_thread;
  assert(pthread_create(
             &remote_thread, nullptr,
             [](void* opaque) -> void* {
               auto* w = static_cast<RemoteOnce*>(opaque);
               assert(w->run(w->word, [] {
                 meet(gate);
                 meet(gate);
               }) == 0);
               return nullptr;
             },
             &remote_work) == 0);
  meet(gate);
  const auto held_control = control_module.value.close();
  assert(held_control.code() == yukilinker::Code::Ok && held_control.handle_valid() &&
         !held_control.private_mapping_unmapped());
  meet(gate);
  assert(pthread_join(remote_thread, nullptr) == 0);
  assert(pthread_once(remote_once, [] { abort(); }) == 0);
  assert(control_module.value.close().private_mapping_unmapped());
  assert(pthread_barrier_destroy(&gate) == 0);
  assert(module.value.close().private_mapping_unmapped());
}

void check_late_thread_destructor_at_exit(yukilinker::Runtime& runtime, const char* directory) {
  const pid_t child = controlled_fork(runtime);
  if (child) {
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return;
  }
  static int counts[2]{};
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  const auto initialize = module.value.symbol<OnExit>("emutls_on_exit");
  assert(initialize && atexit([] { assert(counts[0] == 1); }) == 0);
  struct Late {
    yukilinker::Module& module;
    OnExit initialize;
    pthread_key_t key{};
    unsigned round = 0;
    static void cleanup(void* opaque) {
      auto& state = *static_cast<Late*>(opaque);
      if (++state.round == 1) assert(state.initialize(counts) == 1);
      if (state.round < 3) {
        assert(pthread_setspecific(state.key, opaque) == 0);
        return;
      }
      // Core's storage key has had a turn since registration. Bionic still owns a callback.
      const auto image = state.module.image();
      assert(image && image.value.destructor_references == 1 && counts[0] == 0);
      exit(0);
    }
  } state{module.value, initialize.value};
  assert(pthread_key_create(&state.key, Late::cleanup) == 0);
  run_on_worker([&] { assert(pthread_setspecific(state.key, &state) == 0); });
  abort();
}

void check_emutls_from_exit_collection(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  const auto slot = module.value.symbol<Slot>("emutls_slot");
  const auto arm = module.value.symbol<void (*)(int*)>("emutls_arm_finalizer_key");
  assert(slot && arm);
  int result = 0;
  arm.value(&result);
  run_on_worker([&] {
    *slot.value() = 71;
    // Dropping the open reference leaves this thread's old TLS block as the last owner.
    const auto held = module.value.close();
    assert(held.handle_valid() && held.reference() == yukilinker::Reference::Released && !result);
  });
  assert(result == 1);
  assert(module.value.close().private_mapping_unmapped());
}

void check_rearmed_keys(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "weak");
  assert(module);
  const auto arm = module.value.symbol<void* (*)(pthread_key_t*, int*)>("emutls_arm_key_rounds");
  assert(arm);
  struct Exit {
    yukilinker::Module& module;
    pthread_key_t private_key{}, observer{};
    int rounds = 0, observed_rounds = 0;
    void* marker = nullptr;
    static void observe(void* opaque) {
      auto& state = *static_cast<Exit*>(opaque);
      if (++state.observed_rounds < PTHREAD_DESTRUCTOR_ITERATIONS) {
        assert(pthread_setspecific(state.observer, opaque) == 0);
        return;
      }
      assert(state.rounds == PTHREAD_DESTRUCTOR_ITERATIONS);
      const auto held = state.module.close();
      assert(held.handle_valid() && held.reference() == yukilinker::Reference::Released &&
             !held.private_mapping_unmapped() &&
             pthread_getspecific(state.private_key) == state.marker);
    }
  } state{module.value};
  run_on_worker([&] {
    state.marker = arm.value(&state.private_key, &state.rounds);
    // Allocate the observer after Core's dispatch key so it sees the last rearmed value.
    assert(state.marker && pthread_key_create(&state.observer, Exit::observe) == 0 &&
           pthread_setspecific(state.observer, &state) == 0);
    assert(module.value.close().handle_valid());
  });
  assert(state.observed_rounds == PTHREAD_DESTRUCTOR_ITERATIONS &&
         pthread_key_delete(state.observer) == 0);
  finish_thread_close(module.value);
}

void check_fork_in_key_destructor(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "local");
  assert(module);
  using Hook = void (*)(void*);
  const auto arm = module.value.symbol<void (*)(Hook, void*)>("emutls_arm_key_finalizer");
  assert(arm);
  struct Fork {
    yukilinker::Runtime& runtime;
    yukilinker::Module& module;
    pthread_key_t after_dispatch;
    bool parent_waited = false;
    static void during_dispatch(void* opaque) {
      auto& state = *static_cast<Fork*>(opaque);
      // The key callback disappears in this child and survives in the next one.
      run_on_worker([&] {
        const pid_t peer = controlled_fork(state.runtime);
        if (!peer) finish_child(opaque);
        int status = 0;
        assert(waitpid(peer, &status, 0) == peer && status == 0);
      });
      const pid_t child = controlled_fork(state.runtime);
      if (!child) {
        assert(pthread_setspecific(state.after_dispatch, opaque) == 0);
        return;
      }
      int status = 0;
      assert(waitpid(child, &status, 0) == child && status == 0);
      state.parent_waited = true;
    }
    static void finish_child(void* opaque) {
      const auto done = static_cast<Fork*>(opaque)->module.close();
      assert(done.code() == yukilinker::Code::Ok && done.private_mapping_unmapped() &&
             !done.handle_valid());
      _exit(0);
    }
  } state{runtime, module.value, {}};
  arm.value(Fork::during_dispatch, &state);
  assert(pthread_key_create(&state.after_dispatch, Fork::finish_child) == 0);
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* opaque) -> void* {
               assert(static_cast<Fork*>(opaque)->module.close().handle_valid());
               return nullptr;
             },
             &state) == 0);
  assert(pthread_join(worker, nullptr) == 0 && state.parent_waited);
  assert(pthread_key_delete(state.after_dispatch) == 0 &&
         module.value.close().private_mapping_unmapped());
}

void check_fork_during_thread_destructor(yukilinker::Runtime& runtime, const char* directory) {
  auto module = open_fixture(runtime, directory, "local");
  assert(module);
  const auto arm = module.value.symbol<void (*)(int*)>("emutls_arm_global_finalizers");
  const auto hold =
      module.value.symbol<void (*)(pthread_barrier_t*)>("emutls_wait_in_thread_destructor");
  pthread_barrier_t barrier;
  assert(arm && hold && pthread_barrier_init(&barrier, nullptr, 2) == 0);
  int counts[4]{};
  arm.value(counts);
  hold.value(&barrier);
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* opaque) -> void* {
               assert(static_cast<yukilinker::Module*>(opaque)->close().handle_valid());
               return nullptr;
             },
             &module.value) == 0);
  meet(barrier);
  // Both the original loader and an unrelated thread fork while the destructor is in flight.
  const auto fork_and_close = [&] {
    const pid_t child = controlled_fork(runtime);
    if (!child) {
      const auto done = module.value.close();
      assert(done.private_mapping_unmapped() && !done.handle_valid());
      assert(counts[0] == 1 && !counts[1] && !counts[2] && counts[3] == 1);
      _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && status == 0);
  };
  fork_and_close();
  run_on_worker(fork_and_close);
  meet(barrier);
  assert(pthread_join(worker, nullptr) == 0 && pthread_barrier_destroy(&barrier) == 0);
  assert(module.value.close().private_mapping_unmapped());
  assert(counts[0] == 1 && counts[1] == 1 && counts[2] == 83 && counts[3] == 1);
}

void check_system_emutls(yukilinker::Module& module, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/libemutls_shared.so", directory);
  void* system = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  assert(system);
  // A host executable can interpose the DSO's accessor relocation. Use Bionic's lookup
  // through the same handle as the reference for what the PRIVATE caller should receive.
  void* accessor = dlsym(system, "__emutls_get_address");
  void* control = dlsym(system, "__emutls_v.fixture_shared");
  const auto check = module.symbol<bool (*)(void*, void*, void*)>("emutls_system_storage");
  assert(accessor && control && check);
  run_on_worker([&] { assert(check.value(system, accessor, control)); });
  assert(dlclose(system) == 0);
}

void check_versioned_emutls(yukilinker::Runtime& runtime, const char* directory) {
  // A pre-Q host executable can itself preempt the fixture's weak default definition.
  // Have the local alias forward to that same native implementation in either host.
  using Accessor = void* (*)(void*);
  void* cxx = dlopen("libc++_shared.so", RTLD_NOW);
  assert(cxx);
  auto native = reinterpret_cast<Accessor>(dlsym(RTLD_DEFAULT, "__emutls_get_address"));
  if (!native) native = reinterpret_cast<Accessor>(dlsym(cxx, "__emutls_get_address"));
  assert(native);
  for (auto backend : {yukilinker::Backend::System, yukilinker::Backend::Private}) {
    yukilinker::OpenOptions options{backend};
    options.native.trusted_runtime = backend == yukilinker::Backend::Private;
    for (const char* form : {"aliases", "named_alias"}) {
      auto aliases = open_fixture(runtime, directory, form, options);
      assert(aliases);
      auto read_alias = aliases.value.symbol<int (*)(void*, Accessor)>("emutls_read_alias");
      auto alias_control = aliases.value.symbol<void*>("__emutls_v.alias_slot");
      assert(read_alias && alias_control);
      run_on_worker([&] { assert(read_alias.value(alias_control.value, native) == 73); });
      assert(!aliases.value.close().handle_valid());
    }
  }
  assert(dlclose(cxx) == 0);
  auto module = open_fixture(runtime, directory, "versioned");
  assert(module);
  const auto accessor = module.value.symbol<void*>("__emutls_get_address", "TEST_EMUTLS_OLD");
  const auto current = module.value.symbol<void*>("__emutls_get_address", "TEST_EMUTLS");
  const auto unversioned = module.value.symbol<void*>("__emutls_get_address");
  const auto missing = module.value.symbol<void*>("__emutls_get_address", "MISSING_EMUTLS");
  const auto control = module.value.symbol<void*>("__emutls_v.versioned_slot");
  const auto check = module.value.symbol<bool (*)(void*, void*)>("emutls_version_matches");
  assert(accessor && !missing && missing.error.code() == yukilinker::Code::SymbolMissing && check);
  assert(current && unversioned && current.value != accessor.value);
  assert(unversioned.value == current.value);
  assert(!control && control.error.code() == yukilinker::Code::Unsupported);
  run_on_worker([&] { assert(check.value(accessor.value, current.value)); });
  assert(module.value.close().private_mapping_unmapped());
}

void check_mixed_accessors(yukilinker::Runtime& runtime, const char* directory) {
  for (const char* form : {"aliases", "named_alias"}) {
    auto aliases = open_fixture(runtime, directory, form);
    assert(!aliases && aliases.error.code() == yukilinker::Code::Unsupported &&
           aliases.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
           !strcmp(aliases.error.native.detail.symbol, "__emutls_get_address"));
  }
  auto managed = open_fixture(runtime, directory, "managed_version");
  auto native = open_fixture(runtime, directory, "direct");
  assert(managed && native);
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  auto mixed = open_fixture(runtime, directory, "mixed_versions", trusted);
  assert(!mixed && mixed.error.code() == yukilinker::Code::Unsupported &&
         mixed.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
         !strcmp(mixed.error.native.detail.symbol, "__emutls_get_address"));
  for (const auto& options : {yukilinker::OpenOptions{}, trusted}) {
    auto local = open_fixture(runtime, directory, "mixed_local", options);
    assert(!local && local.error.code() == yukilinker::Code::Unsupported &&
           local.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
           !strcmp(local.error.native.detail.symbol, "__emutls_get_address"));
  }
  auto named_mixed = open_fixture(runtime, directory, "named_alias_mixed", trusted);
  assert(named_mixed);
  auto mixed_control = named_mixed.value.symbol<void*>("__emutls_v.alias_slot");
  assert(!mixed_control && mixed_control.error.code() == yukilinker::Code::Unsupported &&
         !strcmp(mixed_control.error.native.detail.symbol, "__emutls_v.alias_slot"));
  assert(named_mixed.value.close().private_mapping_unmapped());
  assert(native.value.close().private_mapping_unmapped() &&
         managed.value.close().private_mapping_unmapped());
}

auto open_trusted_reader(yukilinker::Runtime& runtime, const char* directory, const char* soname) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/%s", directory, soname);
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  // A named fd without a sibling search path uses the provider loaded for each case.
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  trusted.native.origin = soname;
  auto reader = runtime.open_fd(fd, trusted);
  assert(close(fd) == 0);
  return reader;
}

void check_trusted_control_providers(yukilinker::Runtime& runtime, const char* directory,
                                     const int& constructors) {
  auto accessor = open_fixture(runtime, directory, "managed_version");
  assert(accessor);
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  const int initial = constructors;
  for (const auto& options : {trusted, yukilinker::OpenOptions{yukilinker::Backend::System}}) {
    auto owner = open_fixture(runtime, directory, "shared", options);
    assert(owner);
    auto reader = open_trusted_reader(runtime, directory, "libemutls_mixed_controls.so");
    assert(!reader && reader.error.code() == yukilinker::Code::Unsupported &&
           reader.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
           !strcmp(reader.error.native.detail.symbol, "__emutls_v.fixture_shared") &&
           constructors == initial);
    assert(!owner.value.close().handle_valid());
  }
  auto owner = open_fixture(runtime, directory, "shared");
  auto reader = open_trusted_reader(runtime, directory, "libemutls_mixed_controls.so");
  assert(owner && reader && constructors == initial + 1);
  auto read = reader.value.symbol<Slot>("emutls_consumer_slot");
  auto direct = owner.value.symbol<Slot>("emutls_slot");
  assert(read && direct);
  run_on_worker([&] { assert(read.value() == direct.value() && *read.value() == 42); });
  assert(reader.value.release_host() == yukilinker::Code::Busy);
  assert(reader.value.close().private_mapping_unmapped() &&
         owner.value.close().private_mapping_unmapped() &&
         accessor.value.close().private_mapping_unmapped());

  // Use a fresh SYSTEM provider so that its weak accessor assigns the control's first index.
  // Calls from a separately linked host can otherwise preempt it with their own compiler-rt.
  auto system = open_fixture(runtime, directory, "weak",
                             yukilinker::OpenOptions{yukilinker::Backend::System});
  auto native = open_trusted_reader(runtime, directory, "libemutls_consumer.so");
  assert(system && native);
  auto imported = native.value.symbol<Slot>("emutls_consumer_slot");
  auto system_accessor = system.value.symbol<void* (*)(void*)>("__emutls_get_address");
  auto control = system.value.symbol<void*>("__emutls_v.fixture_shared");
  auto reader_accessor = native.value.symbol<void* (*)(void*)>("__emutls_get_address");
  auto reader_control = native.value.symbol<void*>("__emutls_v.fixture_shared");
  auto second = native.value.symbol<Slot>("emutls_consumer_second");
  auto second_control = native.value.symbol<void*>("__emutls_v.fixture_second");
  assert(second && second_control && second_control.value != reader_control.value);
  assert(imported && system_accessor && control && reader_accessor && reader_control);
  assert(reader_accessor.value == system_accessor.value && reader_control.value == control.value);
  run_on_worker([&] {
    int* value = imported.value();
    assert(value && value == reader_accessor.value(reader_control.value) && *value == 42);
    *value = 73;
    assert(*static_cast<int*>(system_accessor.value(control.value)) == 73);
    assert(second.value() == reader_accessor.value(second_control.value) && *second.value() == 19);
  });
  assert(native.value.close().private_mapping_unmapped() && !system.value.close().handle_valid());
}

void check_ordinary_control_reader(yukilinker::Runtime& runtime, const char* directory,
                                   const int& constructors) {
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  for (bool native : {true, false}) {
    const int before = constructors;
    auto accessor = open_fixture(runtime, directory, "managed_version",
                                 native ? trusted : yukilinker::OpenOptions{});
    auto owner = open_fixture(runtime, directory, "delegated", trusted);
    assert(accessor && owner);
    auto reader = open_fixture(runtime, directory, "delegated_reader");
    if (native) {
      assert(!reader && reader.error.code() == yukilinker::Code::Unsupported &&
             reader.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
             !strcmp(reader.error.native.detail.symbol, "__emutls_v.fixture_shared") &&
             constructors == before);
    } else {
      assert(reader && constructors == before + 1);
      const auto read = reader.value.symbol<Slot>("emutls_consumer_slot");
      const auto direct = owner.value.symbol<Slot>("emutls_slot");
      const auto control = reader.value.symbol<void*>("__emutls_v.fixture_shared");
      const auto bound = reader.value.symbol<void* (*)(void*)>("__emutls_get_address");
      assert(read && direct && control && bound);
      run_on_worker([&] {
        int* slot = direct.value();
        assert(slot && *slot == 42 && read.value() == slot && bound.value(control.value) == slot);
        *read.value() = 73;
        assert(*direct.value() == 73);
      });
      assert(reader.value.close().private_mapping_unmapped());
    }
    assert(owner.value.close().private_mapping_unmapped() &&
           accessor.value.close().private_mapping_unmapped());
  }
}

void check_emutls_handle_scope(yukilinker::Runtime& runtime, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  auto observer = runtime.open_path(path);
  assert(observer);
  const auto lookup = observer.value.symbol<int (*)(const char*, int)>("module_lookup_emutls");
  assert(lookup);
  for (bool mixed : {false, true}) {
    const char* form = mixed ? "lookup_root" : "weak";
    auto module = open_fixture(runtime, directory, form);
    assert(module);
    const auto control = module.value.symbol<void*>("__emutls_v.fixture_shared");
    assert(module.value.symbol<void*>("__emutls_get_address"));
    if (mixed)
      assert(!control && control.error.code() == yukilinker::Code::Unsupported);
    else
      assert(control);
    snprintf(path, sizeof(path), "%s/libemutls_%s.so", directory, form);
    run_on_worker([&] { assert(lookup.value(path, mixed ? 0 : 42)); });
    assert(module.value.close().private_mapping_unmapped());
  }
  assert(observer.value.close().private_mapping_unmapped());
  auto dependent = open_fixture(runtime, directory, "observer");
  assert(dependent);
  const auto observe = dependent.value.symbol<int (*)()>("emutls_observe");
  assert(observe);
  run_on_worker([&] { assert(observe.value()); });
  assert(dependent.value.close().private_mapping_unmapped());

  yukilinker::OpenOptions options;
  options.native.trusted_runtime = 1;
  auto trusted = open_fixture(runtime, directory, "shared", options);
  assert(trusted);
  const auto accessor = trusted.value.symbol<void* (*)(void*)>("__emutls_get_address");
  const auto control = trusted.value.symbol<void*>("__emutls_v.fixture_shared");
  const auto slot = trusted.value.symbol<Slot>("emutls_slot");
  assert(accessor && control && slot);
  run_on_worker(
      [&] { assert(accessor.value(control.value) == slot.value() && *slot.value() == 42); });
  assert(trusted.value.close().private_mapping_unmapped());

  // The trusted consumer imports both the control and the accessor from the same managed DSO.
  auto provider = open_fixture(runtime, directory, "weak");
  auto consumer = open_fixture(runtime, directory, "consumer", options);
  assert(provider && consumer);
  const auto read = consumer.value.symbol<Slot>("emutls_consumer_slot");
  const auto local = consumer.value.symbol<Slot>("emutls_consumer_local_slot");
  const auto direct = provider.value.symbol<Slot>("emutls_slot");
  assert(read && local && direct);
  for (int i = 0; i < 2; ++i)
    run_on_worker([&] {
      assert(read.value() == direct.value() && *direct.value() == 42);
      assert(local.value() != read.value() && *local.value() == 19);
      *read.value() = 73;
      *local.value() = 29;
      assert(*direct.value() == 73 && *local.value() == 29);
    });
  assert(consumer.value.release_host() == yukilinker::Code::Busy);
  assert(consumer.value.close().private_mapping_unmapped() &&
         provider.value.close().private_mapping_unmapped());
}

void check_paused_close_at_exit(yukilinker::Runtime& runtime, const char* directory) {
  const pid_t child = controlled_fork(runtime);
  if (child) {
    int status = 0;
    assert(waitpid(child, &status, 0) == child && status == 0);
    return;
  }

  static int counts[4]{};
  // Register before loading so this assertion runs after the module's process-exit entry.
  assert(atexit([] { assert(counts[0] == 1 && counts[1] == 1 && !counts[2] && counts[3] == 1); }) ==
         0);
  auto module = open_fixture(runtime, directory, "local");
  assert(module);
  const auto arm = module.value.symbol<void (*)(int*)>("emutls_arm_global_finalizers");
  assert(arm);
  arm.value(counts);
  const auto held = module.value.close();
  assert(held.handle_valid() && held.reference() == yukilinker::Reference::Released &&
         counts[0] == 1 && !counts[1] && !counts[2] && !counts[3]);

  struct Peer {
    yukilinker::Runtime& runtime;
    yukilinker::Module& module;
    static void* run(void* opaque) {
      auto& peer = *static_cast<Peer*>(opaque);
      const pid_t forked = controlled_fork(peer.runtime);
      if (!forked) {
        // The thread that acquired TLS in close is absent. Only the older global remains.
        assert(peer.module.close().private_mapping_unmapped());
        assert(counts[0] == 1 && !counts[1] && !counts[2] && counts[3] == 1);
        _exit(0);
      }
      int status = 0;
      assert(waitpid(forked, &status, 0) == forked && status == 0);
      return nullptr;
    }
  } peer{runtime, module.value};
  pthread_t thread;
  assert(pthread_create(&thread, nullptr, Peer::run, &peer) == 0);
  assert(pthread_join(thread, nullptr) == 0);
  exit(0);
}

void check_exit_during_close(yukilinker::Runtime& runtime, const char* directory) {
  const pid_t child = controlled_fork(runtime);
  if (child) {
    int status = 0;
    assert(waitpid(child, &status, 0) == child && status == 0);
    return;
  }
  static pthread_barrier_t gate;
  static pthread_t closer;
  static int last_step;
  assert(pthread_barrier_init(&gate, nullptr, 2) == 0);
  // Registered first, this releases the close after Bionic has consumed the module's exit entry.
  assert(atexit([] {
           meet(gate);
           assert(pthread_join(closer, nullptr) == 0 && last_step == 3);
         }) == 0);
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  auto module = runtime.open_path(path);
  assert(module);
  const auto watch = module.value.symbol<int (*)(void (*)(int))>("module_watch_close");
  assert(watch);
  assert(watch.value([](int step) {
    assert(++last_step == step);
    if (step == 1) {
      meet(gate);
      meet(gate);
    }
  }) == 0);
  assert(pthread_create(
             &closer, nullptr,
             [](void* opaque) -> void* {
               auto& module = *static_cast<yukilinker::Module*>(opaque);
               // TLS still holds the mapping after all three callbacks return.
               assert(module.close().handle_valid() && last_step == 3);
               return nullptr;
             },
             &module.value) == 0);
  meet(gate);
  exit(0);
}

void exercise_emutls(yukilinker::Runtime& runtime, const char* directory) {
  check_rearmed_keys(runtime, directory);
  for (bool global : {false, true})
    for (bool cxa_finalizers : {false, true})
      check_finalizer_tls(runtime, directory, global, cxa_finalizers);
  check_paused_close_at_exit(runtime, directory);
  check_exit_during_close(runtime, directory);
  check_emutls_from_exit_collection(runtime, directory);
  check_key_frame_signals(runtime, directory);
  for (auto mode : {ForkTls::Managed, ForkTls::LocalPrepare, ForkTls::LocalChild})
    check_thread_local_at_fork(runtime, directory, mode);
  check_linker_at_fork(runtime, directory);
  check_quiescent_local_fork(runtime, directory);
  check_once_owner(runtime, directory);
  check_late_thread_destructor_at_exit(runtime, directory);
  check_fork_in_key_destructor(runtime, directory);
  check_fork_during_thread_destructor(runtime, directory);
  check_versioned_emutls(runtime, directory);
  check_emutls_handle_scope(runtime, directory);
  check_mixed_key_lookup(runtime, directory);
  for (const char* form :
       {"weak", "shared", "direct", "local", "wrapped_local", "wrapped_keys", "stripped"}) {
    auto module = open_fixture(runtime, directory, form);
    if (!module)
      fprintf(stderr, "emutls %s: %u/%u %s %s\n", form, module.error.native.detail.code,
              module.error.native.detail.stage, module.error.native.detail.object,
              module.error.native.detail.symbol);
    assert(module);
    auto slot = module.value.symbol<Slot>("emutls_slot");
    auto zero = module.value.symbol<Slot>("emutls_zero");
    auto on_exit = module.value.symbol<OnExit>("emutls_on_exit");
    assert(slot && zero && on_exit);
    const auto first = module.value.image();
    assert(first);
    if (!strcmp(form, "weak") || !strcmp(form, "shared")) {
      const bool shared = !strcmp(form, "shared");
      const auto lookup = module.value.symbol<bool (*)(bool)>("emutls_lookup_matches");
      assert(lookup && lookup.value(shared));
      if (shared) check_system_emutls(module.value, directory);
    }
    yukilinker::Module consumer;
    Slot imported = nullptr;
    if (!strcmp(form, "weak")) {
      auto loaded = open_fixture(runtime, directory, "consumer");
      assert(loaded);
      consumer.swap(loaded.value);
      const auto lookup = consumer.symbol<Slot>("emutls_consumer_slot");
      assert(lookup && lookup.value);
      imported = lookup.value;
    }
    int dtors[2]{};
    TlsWorker object{slot.value, zero.value, imported, on_exit.value, dtors};
    TlsWorker trivial{slot.value, zero.value, imported, on_exit.value, nullptr};
    object.start();
    trivial.start();
    assert(object.address != trivial.address);
    if (consumer) assert(!consumer.close().handle_valid());
    // Drain the registered C++ destructor before the raw TLS block. Either user
    // alone keeps the image mapped while the host has released its reference.
    assert(module.value.close().handle_valid());
    if (!strcmp(form, "stripped") || !strcmp(form, "weak")) {
      const pid_t child = controlled_fork(runtime);
      if (!child) _exit(module.value.close().private_mapping_unmapped() ? 0 : 1);
      int status = 0;
      assert(waitpid(child, &status, 0) == child && status == 0);
    }
    object.finish();
    assert(dtors[0] == 1 && dtors[1] == 74 && module.value.close().handle_valid());
    trivial.finish();
    const auto done = module.value.close();
    assert(!done.handle_valid() && done.private_mapping_unmapped());

    auto fresh = open_fixture(runtime, directory, form);
    assert(fresh && fresh.value.image().value.id.generation != first.value.id.generation);
    const auto fresh_slot = fresh.value.symbol<Slot>("emutls_slot");
    const auto fresh_zero = fresh.value.symbol<Slot>("emutls_zero");
    const auto fresh_exit = fresh.value.symbol<OnExit>("emutls_on_exit");
    assert(fresh_slot && fresh_zero && fresh_exit);
    // Warm the local compiler-rt and Core keys before registering a last-round destructor.
    int warm_dtors[2]{};
    TlsWorker reloaded{fresh_slot.value, fresh_zero.value, nullptr, fresh_exit.value, warm_dtors};
    reloaded.start();
    reloaded.finish();
    assert(warm_dtors[0] == 1 && warm_dtors[1] == 74);
    if (!strcmp(form, "direct"))
      check_late_tls_close(fresh.value, fresh_slot.value, fresh_exit.value);
    else if (!strcmp(form, "weak") || !strcmp(form, "stripped"))
      check_late_tls_close(fresh.value, fresh_slot.value);
    else
      assert(fresh.value.close().private_mapping_unmapped());
  }
  int constructors[2]{};
  char address[32];
  snprintf(address, sizeof(address), "%llx",
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(constructors)));
  assert(setenv("YUKILINKER_TEST_EMUTLS_CTORS", address, 1) == 0);
  check_mixed_accessors(runtime, directory);
  assert(constructors[0] == 0 && constructors[1] == 0);
  // A cold open can enter the system linker for dependencies. Both PRIVATE
  // constructors must still be untouched when the control import is refused.
  for (const char* form : {"conflict", "managed_conflict", "key_conflict"}) {
    auto conflict = open_fixture(runtime, directory, form);
    assert(!conflict && conflict.error.code() == yukilinker::Code::Unsupported &&
           conflict.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
           !strcmp(conflict.error.native.detail.symbol, "__emutls_v.fixture_shared"));
    assert(constructors[0] == 0 && constructors[1] == 0);
  }
  auto provider = open_fixture(runtime, directory, "local");
  assert(provider && constructors[0] == 1 && constructors[1] == 0);
  auto warm = open_fixture(runtime, directory, "conflict");
  assert(!warm && warm.error.code() == yukilinker::Code::Unsupported &&
         !warm.error.native.detail.execution_started && constructors[1] == 0);
  // This provider reserves its controls for Core. The trusted reader binds its own compiler-rt.
  auto passive = open_fixture(runtime, directory, "passive");
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  auto incompatible = open_fixture(runtime, directory, "reader", trusted);
  assert(passive && !incompatible && incompatible.error.code() == yukilinker::Code::Unsupported &&
         incompatible.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
         !strcmp(incompatible.error.native.detail.symbol, "__emutls_v.fixture_shared") &&
         constructors[1] == 0);
  assert(passive.value.close().private_mapping_unmapped());
  check_trusted_control_providers(runtime, directory, constructors[1]);
  check_ordinary_control_reader(runtime, directory, constructors[1]);
  assert(unsetenv("YUKILINKER_TEST_EMUTLS_CTORS") == 0 &&
         provider.value.close().private_mapping_unmapped());

  for (const auto& options : {yukilinker::OpenOptions{}, trusted}) {
    auto reader = open_fixture(runtime, directory, "reader", options);
    assert(reader);
    const auto read = reader.value.symbol<Slot>("emutls_consumer_slot");
    const auto key = reader.value.symbol<int (*)()>("emutls_passive_key");
    const auto access = reader.value.symbol<void* (*)(void*)>("__emutls_get_address");
    const auto control = reader.value.symbol<void*>("__emutls_v.fixture_shared");
    const auto alias = reader.value.symbol<void*>("__emutls_v.fixture_alias");
    assert(read && key && key.value() && access && control && alias &&
           alias.value == control.value);
    if (options.native.trusted_runtime) {
      const auto unread = reader.value.symbol<void*>("__emutls_v.fixture_unread");
      assert(!unread && unread.error.code() == yukilinker::Code::Unsupported);
    }
    run_on_worker([&] {
      int* slot = read.value();
      assert(slot && access.value(control.value) == slot && *slot == 42 &&
             reinterpret_cast<uintptr_t>(slot) % 128 == 0);
    });
    assert(reader.value.close().private_mapping_unmapped());
  }
  puts("PASS passive emutls provider and local accessor isolation");

  auto system = open_fixture(runtime, directory, "weak",
                             yukilinker::OpenOptions{yukilinker::Backend::System});
  assert(system);
  const auto slot = system.value.symbol<Slot>("emutls_slot");
  const auto zero = system.value.symbol<Slot>("emutls_zero");
  const auto on_exit = system.value.symbol<OnExit>("emutls_on_exit");
  assert(slot && zero && on_exit);
  int dtors[2]{};
  TlsWorker native{slot.value, zero.value, nullptr, on_exit.value, dtors};
  native.start();
  native.finish();
  assert(dtors[0] == 1 && dtors[1] == 74 && !system.value.close().handle_valid());
  puts("PASS emulated TLS bindings, thread exit, retained close and reload");
}
}  // namespace

void exercise_lifecycle(yukilinker::Runtime& runtime, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  auto loaded = runtime.open_path(path);
  assert(loaded);
  auto& module = loaded.value;
  check_oreo_phdr(module);
  struct Thread {
    int* (*slot)();
    int (*on_exit)(int*);
    int calls = 0;
    static void* change_slot(void* opaque) {
      int* slot = static_cast<Thread*>(opaque)->slot();
      assert(*slot == 42);
      *slot = 93;
      return nullptr;
    }
  } work{module.symbol<int* (*)()>("module_slot").value,
         module.symbol<int (*)(int*)>("module_thread_exit").value};
  int exits = 0, forks = 0;
  assert(module.symbol<int (*)(int*)>("module_exit").value(&exits) == 0);
  assert(module.symbol<int (*)(int*)>("module_fork").value(&forks) == 0);
  pthread_t thread;
  assert(pthread_create(
             &thread, nullptr,
             [](void* opaque) -> void* {
               auto* value = static_cast<Thread*>(opaque);
               int* slot = value->slot();
               assert(*slot == 42 && value->on_exit(&value->calls) == 0);
               *slot = 71;
               pthread_t peer;
               assert(pthread_create(&peer, nullptr, Thread::change_slot, value) == 0);
               assert(pthread_join(peer, nullptr) == 0 && *value->slot() == 71);
               return nullptr;
             },
             &work) == 0);
  assert(pthread_join(thread, nullptr) == 0 && work.calls == 1);
  const pid_t child = controlled_fork(runtime);
  if (!child) _exit(forks == 1 ? 0 : 1);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && status == 0);
  assert(!module.close().handle_valid() && exits == 1);
  const pid_t retired = fork();
  assert(retired >= 0);
  if (!retired) _exit(forks == 0 ? 0 : 1);
  assert(waitpid(retired, &status, 0) == retired && status == 0);
}

void exercise_relro_mapping(yukilinker::Runtime& runtime, const char* directory, const char* path) {
  const int source = open(path, O_RDONLY | O_CLOEXEC);
  struct stat status{};
  assert(source >= 0 && fstat(source, &status) == 0 && status.st_size > 0);
  const size_t bytes = status.st_size;
  void* data = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, source, 0);
  assert(data != MAP_FAILED && close(source) == 0);
  const auto* header = static_cast<const ElfW(Ehdr)*>(data);
  auto* segments = reinterpret_cast<ElfW(Phdr)*>(static_cast<char*>(data) + header->e_phoff);
  const size_t page = sysconf(_SC_PAGESIZE);
  const auto page_end = [page](uintptr_t address) { return (address + page - 1) & ~(page - 1); };
  const ElfW(Phdr)* relro = nullptr;
  for (size_t i = 0; i < header->e_phnum; ++i)
    if (segments[i].p_type == PT_GNU_RELRO) relro = &segments[i];
  assert(relro && relro->p_memsz);
  bool trimmed = false;
  for (size_t i = 0; i < header->e_phnum; ++i) {
    auto& load = segments[i];
    if (load.p_type != PT_LOAD || load.p_vaddr != relro->p_vaddr) continue;
    assert(load.p_memsz == relro->p_memsz && load.p_filesz < load.p_memsz);
    assert(page_end(load.p_vaddr + load.p_filesz) == page_end(load.p_vaddr + load.p_memsz));
    // Remove only linker-generated zero padding, leaving every loaded page unchanged.
    load.p_memsz = load.p_filesz;
    trimmed = true;
  }
  assert(trimmed);
  const int fd = fixture_fd(directory, "relro-padding");
  assert(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC && lseek(fd, 0, SEEK_CUR) == 0);
  assert(write(fd, data, bytes) == static_cast<ssize_t>(bytes));
  for (const bool file_backed : {false, true}) {
    yukilinker::OpenOptions options;
    options.native.file_backed = file_backed;
    auto loaded = runtime.open_fd(fd, options);
    assert(loaded && loaded.value.symbol<int (*)()>("module_answer").value() == 42);
    const auto image = loaded.value.image();
    assert(image);
    uintptr_t cursor = (image.value.load_bias + relro->p_vaddr) & ~(page - 1);
    const uintptr_t end = page_end(image.value.load_bias + relro->p_vaddr + relro->p_memsz);
    FILE* maps = fopen("/proc/self/maps", "re");
    assert(maps);
    char line[4096];
    while (cursor < end && fgets(line, sizeof(line), maps)) {
      unsigned long long low = 0, high = 0;
      char permissions[5]{};
      if (sscanf(line, "%llx-%llx %4s", &low, &high, permissions) != 3 || high <= cursor) continue;
      assert(low <= cursor && permissions[0] == 'r' && permissions[1] == '-' &&
             permissions[2] == '-');
      cursor = high;
    }
    assert(cursor >= end && !ferror(maps) && fclose(maps) == 0);
    const auto closed = loaded.value.close();
    assert(!closed.handle_valid() && closed.private_mapping_unmapped());
  }
#if defined(__arm__) || defined(__aarch64__)
  constexpr uint16_t foreign = sizeof(void*) == 8 ? EM_X86_64 : EM_386;
#else
  constexpr uint16_t foreign = sizeof(void*) == 8 ? EM_AARCH64 : EM_ARM;
#endif
  assert(pwrite(fd, &foreign, sizeof(foreign), offsetof(ElfW(Ehdr), e_machine)) == sizeof(foreign));
  const auto wrong_machine = runtime.open_fd(fd);
  assert(!wrong_machine && wrong_machine.error.code() == yukilinker::Code::InvalidElf &&
         !wrong_machine.error.native.detail.execution_started &&
         wrong_machine.error.native.detail.machine == header->e_machine);
  assert(close(fd) == 0 && munmap(data, bytes) == 0);
  puts("PASS padded RELRO loading, constructors, page protection and unload");
}
#endif

namespace {
unsigned diagnostics;
void* fail_mapping;
yukilinker_c_runtime* transfer_owner;
yukilinker_c_handle transfer_handle;
bool transfer_active;
unsigned transfer_reentries;
using KeyDestructor = void (*)(void*);
using CreateKey = decltype (&pthread_key_delete) (*)(pthread_key_t*, KeyDestructor);
CreateKey create_during_transfer;
KeyDestructor transfer_destructor;
struct KeyWrite {
  decltype(&pthread_setspecific) set;
  pthread_key_t key;
};
KeyWrite* retiring_key;
void log_unreleased(void*, uint32_t, const char*, size_t) { ++diagnostics; }
int close_dependency(void* user, void* dependency) {
  if (retiring_key) {
    // The owner's mapping is gone, but the writer is a separately held PRIVATE module.
    auto* write = retiring_key;
    retiring_key = nullptr;
    int value = 0;
    const int error = write->set(write->key, &value);
    const bool empty = pthread_getspecific(write->key) == nullptr;
    assert(write->set(write->key, nullptr) == 0 && error == EINVAL && empty);
  }
  if (transfer_active) {
    transfer_active = false;
    pthread_key_t key;
    assert(!create_during_transfer(&key, transfer_destructor));
    const auto refused = yukilinker_c_close(transfer_owner, transfer_handle);
    assert(refused.handle_valid && refused.error.detail.code == YUKILINKER_C_BUSY);
    assert(refused.info.reference == YUKILINKER_C_REFERENCE_OWNED);
    assert(yukilinker_c_release_host(transfer_owner, transfer_handle) == YUKILINKER_C_BUSY);
    ++transfer_reentries;
  }
  return test_close(user, dependency);
}

#if !defined(YUKILINKER_TEST_CFI)
void check_trusted_key_writer(yukilinker::Runtime& runtime, const char* directory) {
  auto owner = open_fixture(runtime, directory, "weak");
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  auto writer = open_fixture(runtime, directory, "shared", trusted);
  assert(owner && writer);
  const auto create = owner.value.symbol<CreateKey>("emutls_create_key");
  const auto destroy = owner.value.symbol<KeyDestructor>("emutls_count_key_exit");
  const auto set = writer.value.symbol<decltype(&pthread_setspecific)>("emutls_set_key");
  const auto erase = writer.value.symbol<decltype(&pthread_key_delete)>("emutls_delete_key");
  assert(create && destroy && set && erase);
  assert(writer.value.release_host() == yukilinker::Code::Busy);
  int calls = 0;
  pthread_key_t key;
  assert(create.value(&key, destroy.value));
  run_on_worker([&] { assert(set.value(key, &calls) == 0); });
  assert(calls == 1);
  assert(set.value(key, &calls) == 0);
  assert(erase.value(key) == 0 && calls == 1);
  assert(owner.value.close().private_mapping_unmapped() &&
         writer.value.close().private_mapping_unmapped());
}

void check_key_retirement(yukilinker::Runtime& runtime, const char* directory, bool trusted) {
  yukilinker::OpenOptions options;
  options.native.trusted_runtime = trusted;
  auto owner = open_fixture(runtime, directory, "weak", options);
  auto writer = open_fixture(runtime, directory, "shared");
  assert(owner && writer);
  const auto destroy = owner.value.symbol<KeyDestructor>("emutls_count_key_exit");
  const auto create = writer.value.symbol<CreateKey>("emutls_create_key");
  const auto set = writer.value.symbol<decltype(&pthread_setspecific)>("emutls_set_key");
  assert(create && destroy && set);
  int calls = 0;
  KeyWrite write{set.value, {}};
  const auto erase = create.value(&write.key, destroy.value);
  assert(erase && write.set(write.key, &calls) == 0);
  assert(write.set(write.key, nullptr) == 0);

  if (trusted) {
    // A registered callback can acquire another value even while its key is empty.
    assert(owner.value.release_host() == yukilinker::Code::Busy);
    run_on_worker([&] {
      assert(write.set(write.key, &calls) == 0);
      const auto image = owner.value.image();
      assert(image && image.value.tls_references == 1);
      const auto held = owner.value.close();
      assert(held.code() == yukilinker::Code::Ok && held.handle_valid() &&
             held.reference() == yukilinker::Reference::Released &&
             held.retention_reasons() == YUKILINKER_C_RETENTION_PRIVATE_HOLD &&
             !held.private_mapping_unmapped() && !calls);
    });
    assert(calls == 1);
    finish_thread_close(owner.value);
  } else {
    const auto image = owner.value.image();
    assert(image);
    fail_mapping = reinterpret_cast<void*>(image.value.mapping_start);
    const auto failed = owner.value.close();
    assert(failed.code() == yukilinker::Code::IoError && failed.handle_valid() &&
           !failed.private_mapping_unmapped());
    assert(write.set(write.key, &calls) == EINVAL && pthread_getspecific(write.key) == nullptr);
    assert(write.set(write.key, nullptr) == 0);
    retiring_key = &write;
    assert(owner.value.close().private_mapping_unmapped() && !retiring_key && calls == 0);
  }
  assert(write.set(write.key, &calls) == EINVAL && write.set(write.key, nullptr) == 0);
  assert(erase(write.key) == 0);
  assert(writer.value.close().private_mapping_unmapped());
}
#endif
}  // namespace
// A consuming Core can wrap ordinary pthread calls at its final link. Symbol resolution in
// check_mixed_key_lookup must still recognize the actual libc provider selected for the DSO.
extern "C" int __real_pthread_setspecific(pthread_key_t, const void*);
extern "C" int __wrap_pthread_setspecific(pthread_key_t key, const void* value) {
#if !defined(YUKILINKER_TEST_CFI)
  if (key_updates_left && key == yukilinker::internal::g_callback_key &&
      (key_updates_left == 2) == (value != nullptr)) {
    // Interrupt just before publishing the frame or just after removing it.
    const int status = value ? 0 : __real_pthread_setspecific(key, value);
    --key_updates_left;
    updating_key = 1;
    assert(raise(SIGUSR1) == 0);
    updating_key = 0;
    return value ? __real_pthread_setspecific(key, value) : status;
  }
#endif
  return __real_pthread_setspecific(key, value);
}

extern "C" int __real_munmap(void*, size_t);
extern "C" int __wrap_munmap(void* mapping, size_t bytes) {
  if (mapping == fail_mapping && mapping) {
    fail_mapping = nullptr;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(mapping, bytes);
}

extern "C" __attribute__((visibility("default"))) int yukilinker_test_run(const char* directory) {
  exercise_relro_layouts();
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_module.so", directory);
  auto services = test_host_services();
#if !defined(YUKILINKER_TEST_CFI)
  // Bionic calls prepare handlers in reverse registration order.
  assert(pthread_atfork(prepare_thread_local, nullptr, child_thread_local) == 0);
  services.system_iterate_phdr = iterate_host;
#endif
  services.log = log_unreleased;
  services.system_dlclose = close_dependency;
  auto source = yukilinker::Runtime::create(services);
  assert(source);
  auto runtime = std::move(source);
  assert(!source && runtime);
#if defined(YUKILINKER_TEST_CFI)
  auto refused = runtime.open_path(path);
  assert(!refused && refused.error.code() == yukilinker::Code::Unsupported);
  auto module = runtime.open_path(path, yukilinker::OpenOptions{yukilinker::Backend::System});
  assert(module && module.value.symbol<int (*)()>("module_answer").value() == 42);
  auto address = module.value.symbol<int (*)()>("module_answer").value;
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    signal(SIGILL, [](int) { _exit(90); });
    signal(SIGTRAP, [](int) { _exit(90); });
    reinterpret_cast<int (*)(int)>(address)(7);
    _exit(91);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 90);
  assert(!module.value.close().handle_valid() && runtime.destroy());
  puts("PASS C++ SYSTEM Core and CFI rejection");
  return 0;
#else
  check_signal_mask();
  exercise_load_wait(runtime, path);
  const pid_t waiting_child = controlled_fork(runtime);
  if (!waiting_child) {
    exercise_load_wait(runtime, path);
    _exit(0);
  }
  int wait_status = 0;
  assert(waitpid(waiting_child, &wait_status, 0) == waiting_child && wait_status == 0);
#if defined(YUKILINKER_TEST_X86_CALLS)
  exercise_x86_calls(runtime, directory);
#endif
#if defined(__i386__) || defined(__x86_64__)
  exercise_x86_relocations(runtime, directory);
#endif
  exercise_relro_mapping(runtime, directory, path);
  auto context_source = runtime.context(directory);
  assert(context_source);
  auto context = std::move(context_source);
  assert(!context_source);
  auto namespace_source = runtime.namespace_create(&context);
  assert(namespace_source);
  auto scope = std::move(namespace_source);
  assert(!namespace_source);
  assert(scope.link(nullptr, YUKILINKER_C_NAMESPACE_LINK_SYSTEM |
                                 YUKILINKER_C_NAMESPACE_LINK_ALL) == yukilinker::Code::Ok);
  yukilinker::OpenOptions options;
  options.native.namespace_scope = scope.native_handle();
  auto opened = runtime.open_path(path, options);
  if (!opened)
    fprintf(stderr, "open failed %u/%u %s %s\n", opened.error.native.detail.code,
            opened.error.native.detail.stage, opened.error.native.detail.object,
            opened.error.native.detail.symbol);
  assert(opened && opened.value);
  auto module = std::move(opened.value);
  assert(!opened.value);
  yukilinker::Module swapped;
  swapped.swap(module);
  assert(!module && swapped);
  auto symbol = swapped.symbol<int (*)()>("module_answer");
  assert(symbol && symbol.value() == 42);
  auto record = swapped.image();
  assert(record);
  auto snapshot = runtime.snapshot(nullptr, &scope);
  assert(snapshot && snapshot.value.size());
  auto moved_snapshot = std::move(snapshot.value);
  assert(!snapshot.value);
  auto image = moved_snapshot.image(0);
  assert(image);
  auto lease = runtime.lease(record.value.id, yukilinker::LeaseKind::Execution);
  assert(lease);
  auto moved_lease = std::move(lease.value);
  assert(!lease.value);
  auto closed = swapped.close();
  assert(closed.handle_valid() && closed.reference() == yukilinker::Reference::Released);
  assert(closed.retention_reasons() && !closed.private_mapping_unmapped());
  assert(!runtime.destroy());
  assert(moved_snapshot.release() == yukilinker::Code::Ok);
  // The final lease release consumes its token despite a subsequent failed unmap.
  // A close of the retained module then retries cleanup without dropping a reference twice.
  fail_mapping = reinterpret_cast<void*>(record.value.mapping_start);
  assert(moved_lease.release() == yukilinker::Code::IoError);
  assert(!moved_lease && swapped);
  closed = swapped.close();
  assert(!closed.handle_valid() && closed.private_mapping_unmapped() && !swapped);

  // A missed destructor release must leave the original ownership recoverable.
  yukilinker_c_handle retained{};
  const auto before = diagnostics;
  {
    auto missed = runtime.open_path(path, options);
    assert(missed);
    retained = missed.value.native_handle();
  }
  assert(diagnostics == before + 1);
  auto stats = runtime.stats();
  assert(stats && stats.value.handles == 1);
  auto recovered = yukilinker::Module::adopt(runtime.native_handle(), retained);
  assert(recovered.symbol<int (*)()>("module_answer").value() == 42);
  assert(!recovered.close().handle_valid());

  auto private_again = runtime.open_path(path, options);
  assert(private_again);
  auto held = runtime.lease(private_again.value.image().value.id);
  assert(held);
  assert(private_again.value.close().handle_valid());
  assert(private_again.value.forget() == yukilinker::Code::Ok && !private_again.value);
  assert(held.value.release() == yukilinker::Code::Ok);
  exercise_lifecycle(runtime, directory);
  exercise_emutls(runtime, directory);
  check_trusted_key_writer(runtime, directory);
  for (bool trusted_owner : {false, true}) check_key_retirement(runtime, directory, trusted_owner);
  assert(scope.destroy() == yukilinker::Code::Ok && !scope);
  assert(context.destroy() && !context);
  auto system = runtime.open_path(path, yukilinker::OpenOptions{yukilinker::Backend::System});
  assert(system);
  closed = system.value.close();
  assert(!closed.handle_valid() && closed.reference() == yukilinker::Reference::Released);
  assert(!closed.private_mapping_unmapped());
  yukilinker::OpenOptions trusted;
  trusted.native.trusted_runtime = 1;
  auto transferred = runtime.open_path(path, trusted);
  assert(transferred);
  const auto mapping = transferred.value.image();
  const auto answer = transferred.value.symbol<int (*)()>("module_answer");
  assert(mapping && answer);
  auto writer = open_fixture(runtime, directory, "shared");
  assert(writer);
  const auto create = writer.value.symbol<CreateKey>("emutls_create_key");
  const auto destructor = transferred.value.symbol<KeyDestructor>("module_count_key_exit");
  assert(create && destructor);
  pthread_key_t key;
  const auto erase = create.value(&key, destructor.value);
  assert(erase && transferred.value.release_host() == yukilinker::Code::Busy && erase(key) == 0);
  create_during_transfer = create.value;
  transfer_destructor = destructor.value;
  transfer_owner = runtime.native_handle();
  transfer_handle = transferred.value.native_handle();
  transfer_active = true;
  assert(transferred.value.release_host() == yukilinker::Code::Ok);
  assert(!transfer_active && transfer_reentries == 1 && answer.value() == 42);
  assert(munmap(reinterpret_cast<void*>(mapping.value.mapping_start), mapping.value.mapping_size) ==
         0);
  assert(writer.value.close().private_mapping_unmapped());
  auto* identity = runtime.native_handle();
  const auto owner_diagnostics = diagnostics;
  {
    auto forgotten = std::move(runtime);
    assert(forgotten && !runtime);
  }
  assert(diagnostics == owner_diagnostics + 1);
  auto restored = yukilinker::Runtime::adopt(identity);
  runtime.swap(restored);
  assert(runtime.stats());
  check_deleted_key_shutdown(runtime, directory);
  assert(runtime.destroy() && !runtime);
  puts("PASS C++ ownership, cleanup retry and lifecycle");
  return 0;
#endif
}

#if !defined(YUKILINKER_TEST_SHARED)
int main(int argc, char** argv) {
  assert(argc == 2);
  return yukilinker_test_run(argv[1]);
}
#endif
