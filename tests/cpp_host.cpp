// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
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

#include "../src/internal/tls_model.hpp"
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
  yukilinker_c_prepare_fork(runtime.native_handle());
  const pid_t child = fork();
  assert(child >= 0);
  yukilinker_c_after_fork(runtime.native_handle(), child == 0);
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
void log_unreleased(void*, uint32_t, const char*, size_t) { ++diagnostics; }
int close_dependency(void* user, void* dependency) {
  if (transfer_active) {
    transfer_active = false;
    const auto refused = yukilinker_c_close(transfer_owner, transfer_handle);
    assert(refused.handle_valid && refused.error.detail.code == YUKILINKER_C_BUSY);
    assert(refused.info.reference == YUKILINKER_C_REFERENCE_OWNED);
    assert(yukilinker_c_release_host(transfer_owner, transfer_handle) == YUKILINKER_C_BUSY);
    ++transfer_reentries;
  }
  return test_close(user, dependency);
}
}  // namespace
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
  yukilinker_c_prepare_fork(runtime.native_handle());
  const pid_t waiting_child = fork();
  assert(waiting_child >= 0);
  yukilinker_c_after_fork(runtime.native_handle(), waiting_child == 0);
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
  transfer_owner = runtime.native_handle();
  transfer_handle = transferred.value.native_handle();
  transfer_active = true;
  assert(transferred.value.release_host() == yukilinker::Code::Ok);
  assert(!transfer_active && transfer_reentries == 1 && answer.value() == 42);
  assert(munmap(reinterpret_cast<void*>(mapping.value.mapping_start), mapping.value.mapping_size) ==
         0);
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
  assert(runtime.try_shutdown().complete);
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
