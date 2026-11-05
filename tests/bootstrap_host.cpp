// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <initializer_list>

#include "control.hpp"
#include "yukilinker.h"

namespace {
int (*real_munmap)(void*, size_t);
int (*real_dlclose)(void*);
uintptr_t loader_low, loader_high;
bool refuse_cleanup;
unsigned cleanup_failures;
void arm_cleanup() { refuse_cleanup = true; }
}  // namespace
extern "C" int munmap(void* address, size_t bytes) {
  const auto caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  if (refuse_cleanup && caller >= loader_low && caller < loader_high) {
    ++cleanup_failures;
    errno = EIO;
    return -1;
  }
  // ARM32 libc can call this interposed import before main resolves RTLD_NEXT.
  return real_munmap ? real_munmap(address, bytes) : syscall(__NR_munmap, address, bytes);
}
extern "C" int dlclose(void* handle) {
  if (!real_dlclose) real_dlclose = reinterpret_cast<int (*)(void*)>(dlsym(RTLD_NEXT, "dlclose"));
  assert(real_dlclose);
  return real_dlclose(handle);
}

namespace {
const char* fixtures;
const char* loader_name = sizeof(void*) == 8 ? "libyloader64.so" : "libyloader32.so";
int loader_visit(dl_phdr_info* info, size_t, void* value) {
  if (info->dlpi_name && strstr(info->dlpi_name, "libyloader")) {
    ++*static_cast<int*>(value);
    loader_low = info->dlpi_addr;
    loader_high = loader_low;
    for (size_t i = 0; i < info->dlpi_phnum; ++i)
      if (info->dlpi_phdr[i].p_type == PT_LOAD)
        loader_high = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
  }
  return 0;
}
int loader_count() {
  int count = 0;
  dl_iterate_phdr(loader_visit, &count);
  if (!count) {
    FILE* maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[4096];
    while (fgets(line, sizeof(line), maps)) assert(!strstr(line, loader_name));
    assert(!ferror(maps) && fclose(maps) == 0);
  }
  return count;
}
int open_core(const char* form) {
  char path[4096];
  const char* core_directory = getenv("YUKILINKER_TEST_CORE_DIRECTORY");
  snprintf(path, sizeof(path), "%s/liblinker_core_%s.so",
           core_directory ? core_directory : fixtures, form);
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  return fd;
}
void load(BootControl& control, const char* form, bool tango = false, bool retry = false) {
  char pointer[32];
  snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long)&control);
  assert(setenv("YUKILINKER_TEST_CONTROL", pointer, 1) == 0);
  void* library = dlopen(loader_name, RTLD_NOW | RTLD_LOCAL);
  if (!library) fprintf(stderr, "loader: %s\n", dlerror());
  assert(library);
  assert(loader_count() == 1);
  control.arm_cleanup_failure = arm_cleanup;
  control.bootstrap = reinterpret_cast<void (*)(int, int)>(dlsym(library, "yuki_bootstrap"));
  assert(control.bootstrap);
  if (retry) {
    control.bootstrap(-1, 0);
    assert(errno == EINVAL && loader_count() == 1);
    int bad = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(bad >= 0);
    control.bootstrap(bad, 0);
    assert(errno != 0 && fcntl(bad, F_GETFD) == -1 && errno == EBADF);
  }
  control.retry_fd = open_core(form);
  const int core = open_core(form);
#if defined(__arm__)
  if (tango) {
    auto call = reinterpret_cast<void (*)(uint32_t, uint32_t, uint32_t, int, int)>(
        dlsym(library, "yuki_bootstrap_tango"));
    assert(call);
    const size_t page = sysconf(_SC_PAGESIZE);
    auto* slot = static_cast<uint32_t*>(
        mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    assert(slot != MAP_FAILED);
    const uint32_t stub = reinterpret_cast<uintptr_t>(slot) + 64;
    *slot = stub | 1U;
    assert(mprotect(slot, page, PROT_READ) == 0);
    const pid_t process = getpid();
    call(reinterpret_cast<uintptr_t>(slot), 0x12345678U, stub, core, 0);
    if (getpid() != process)
      _exit(errno == EBUSY && control.adopted == 0 && control.entries == 0 &&
                    control.finalized == 0 && fcntl(control.retry_fd, F_GETFD) >= 0
                ? 0
                : 1);
    assert(*slot == 0x12345678U);
    assert(control.tango_stub == stub && control.tango_size == YUKILINKER_C_TANGO_BOOTSTRAP_SIZE &&
           control.tango_finalized == 1);
    FILE* maps = fopen("/proc/self/maps", "re");
    assert(maps);
    char line[512], permissions[5];
    unsigned long low, high;
    bool protected_again = false;
    while (fgets(line, sizeof(line), maps))
      if (sscanf(line, "%lx-%lx %4s", &low, &high, permissions) == 3 &&
          reinterpret_cast<uintptr_t>(slot) >= low && reinterpret_cast<uintptr_t>(slot) < high)
        protected_again = !strcmp(permissions, "r--p");
    fclose(maps);
    assert(protected_again);
    assert(munmap(slot, page) == 0);
  } else
#else
  (void)tango;
#endif
    control.bootstrap(core, control.packet_argument);
  assert(fcntl(core, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(control.retry_fd, F_GETFD) >= 0);  // reentry must not consume its input
  close(control.retry_fd);
  unsetenv("YUKILINKER_TEST_CONTROL");
  assert(control.constructors == 1);
}
void retire(BootControl& control);
struct EarlyPacket {
  int packet = memfd_create("early-packet", MFD_CLOEXEC);
  int endpoint = memfd_create("endpoint", MFD_CLOEXEC);
  int module = memfd_create("module", MFD_CLOEXEC);
  EarlyPacket() {
    assert(packet >= 0 && endpoint >= 0 && module >= 0);
    const yukilinker_c_early_packet_header header{YUKILINKER_C_EARLY_PACKET_MAGIC,
                                                  YUKILINKER_C_EARLY_PACKET_VERSION,
                                                  sizeof(header),
                                                  sizeof(yukilinker_c_early_packet_entry),
                                                  0,
                                                  1,
                                                  endpoint,
                                                  0};
    yukilinker_c_early_packet_entry entry{};
    entry.fd = module;
    assert(write(packet, &header, sizeof(header)) == sizeof(header));
    assert(write(packet, &entry, sizeof(entry)) == sizeof(entry));
  }
  void closed() {
    for (int fd : {packet, endpoint, module}) assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
  }
};
void packet_case() {
  EarlyPacket packet;
  BootControl control{};
  control.packet_argument = packet.packet + 1;
  load(control, "archive");
  packet.closed();
  assert(control.packet_transfers == 1 && loader_count() == 0);
  assert(control.exercise(fixtures));
  retire(control);
}
void malformed_core(const char* needle) {
  BootControl control{};
  char pointer[32];
  snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long)&control);
  assert(setenv("YUKILINKER_TEST_CONTROL", pointer, 1) == 0);
  void* library = dlopen(loader_name, RTLD_NOW);
  assert(library);
  auto entry = reinterpret_cast<void (*)(int, int)>(dlsym(library, "yuki_bootstrap"));
  int original = open_core("archive");
  struct stat status{};
  assert(fstat(original, &status) == 0);
  auto* bytes = static_cast<char*>(malloc(status.st_size));
  assert(bytes && read(original, bytes, status.st_size) == status.st_size);
  close(original);
  size_t changed = 0;
  for (size_t i = 0; needle && i + strlen(needle) < static_cast<size_t>(status.st_size); ++i)
    if (!memcmp(bytes + i, needle, strlen(needle) + 1)) {
      bytes[i] = 'x';
      ++changed;
    }
  assert(!needle || changed);
  int damaged = memfd_create("broken-core", MFD_CLOEXEC);
  assert(damaged >= 0 && write(damaged, bytes, status.st_size) == status.st_size);
  free(bytes);
  EarlyPacket packet;
  entry(damaged, packet.packet + 1);
  assert(errno && control.constructors == 0 && control.entries == 0);
  packet.closed();
  assert(fcntl(damaged, F_GETFD) == -1 && errno == EBADF);
  // Fully rolled back failures must admit a fresh Core on the same loader reference.
  entry(open_core("archive"), 0);
  assert(control.finalized == 1 && control.constructors == 1 && loader_count() == 0);
  assert(control.exercise(fixtures));
  retire(control);
  unsetenv("YUKILINKER_TEST_CONTROL");
}
void packet_reuse() {
  EarlyPacket packet;
  BootControl control{};
  control.mode = BootCase::ReusePacket;
  control.packet_argument = packet.packet + 1;
  control.reused_fd = packet.module;
  load(control, "archive");
  assert(control.finalized == 0 && loader_count() == 1);
  assert(fcntl(packet.packet, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(packet.endpoint, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(packet.module, F_GETFD) >= 0);
  close(packet.module);
}
void retire(BootControl& control) {
  assert(control.retire && control.retire() == 1 && control.exit_callbacks == 1);
  assert(munmap(reinterpret_cast<void*>(control.base), control.span) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) exit(0);  // exercises libc's remaining atfork and exit registrations
  int status = 0;
  assert(waitpid(child, &status, 0) == child && status == 0);
}
void success(const char* form, BootCase mode, bool tango, bool retry) {
  BootControl control{};
  control.mode = mode;
  load(control, form, tango, retry);
  assert(control.entries == 1 && control.adopted == 1 && control.takes == 1 &&
         control.finishes == 1 && control.finalized == 1 && control.dependencies != 0);
  assert(loader_count() == 0);
  assert(control.exercise(fixtures) == 1);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) _exit(control.exercise(fixtures) == 1 ? 0 : 1);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && status == 0);
  retire(control);
}
void refusal(BootCase mode) {
  BootControl control{};
  control.mode = mode;
  load(control, "archive");
  assert(control.finalized == 0 && loader_count() == 1);
  const int fd = open_core("archive");
  control.bootstrap(fd, 0);
  assert(errno == EBUSY && fcntl(fd, F_GETFD) >= 0);
  close(fd);
  assert(control.constructors == 1 && control.takes <= 1 && control.finishes <= 1);
  if (mode == BootCase::CleanupFailure) {
    assert(cleanup_failures && control.takes == 1 && control.finishes == 0);
    assert(control.exercise(fixtures));
  }
  // Deliberately retained failure state dies with this isolated subprocess.
}
void isolation() {
  BootControl first{}, second{};
  load(first, "archive");
  load(second, "sources");
  assert(loader_count() == 0 && first.api != second.api && first.owner != second.owner);
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_module.so", fixtures);
  yukilinker_c_open_options options{};
  options.size = sizeof(options);
  options.backend = YUKILINKER_C_BACKEND_PRIVATE;
  options.flags = RTLD_NOW;
  const auto a = first.open(first.owner, path, &options, nullptr);
  const auto b = second.open(second.owner, path, &options, nullptr);
  assert(a.generation && b.generation);
  yukilinker_c_handle_info info{};
  assert(first.query(first.owner, b, &info) == YUKILINKER_C_INVALID_HANDLE);
  assert(second.query(second.owner, a, &info) == YUKILINKER_C_INVALID_HANDLE);
  assert(first.query(second.owner, a, &info) == YUKILINKER_C_STALE_TOKEN);
  assert(!first.close(first.owner, a).handle_valid && !second.close(second.owner, b).handle_valid);
  assert(first.exercise(fixtures) && second.exercise(fixtures));
  retire(first);
  assert(second.exercise(fixtures));
  retire(second);
}
void concurrency() {
  BootControl control{};
  control.mode = BootCase::HoldConstructor;
  pthread_t thread;
  assert(pthread_create(
             &thread, nullptr,
             [](void* opaque) -> void* {
               load(*static_cast<BootControl*>(opaque), "archive");
               return nullptr;
             },
             &control) == 0);
  while (!__atomic_load_n(&control.entered, __ATOMIC_ACQUIRE)) usleep(1000);
  int fd = open_core("archive");
  control.bootstrap(fd, 0);
  assert(errno == EBUSY && fcntl(fd, F_GETFD) >= 0);
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    // Reuse the inherited fd: a rejected bootstrap must not close it by number.
    close(fd);
    int other = open("/dev/null", O_RDONLY);
    assert(other >= 0);
    control.bootstrap(other, 0);
    _exit(errno == EBUSY && fcntl(other, F_GETFD) >= 0 ? 0 : 1);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child && status == 0);
  close(fd);
  __atomic_store_n(&control.release, 1U, __ATOMIC_RELEASE);
  assert(pthread_join(thread, nullptr) == 0);
  assert(control.finalized == 1 && loader_count() == 0 && control.exercise(fixtures));
  retire(control);
}
template <typename F>
void isolated(const char* name, F body) {
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    alarm(30);
    body();
    // Refused handoffs deliberately retain Core callbacks whose test control was on
    // body's stack. Successful retirement checks libc exit separately before return.
    _exit(0);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  printf("REC two_stage.%s status=%d\n", name, status);
  fflush(stdout);
  assert(status == 0);
}
int system_image(dl_phdr_info* info, size_t, void* value) {
  const auto* name = static_cast<const char*>(value);
  return info->dlpi_name && !strcmp(info->dlpi_name, name);
}
void run_system_core(const char* path, const char* directory) {
  void* core = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!core) fprintf(stderr, "dlopen: %s\n", dlerror());
  assert(core);
  auto run = reinterpret_cast<int (*)(const char*)>(dlsym(core, "yukilinker_test_run"));
  assert(run && run(directory) == 0);
  assert(dlclose(core) == 0);
  assert(dl_iterate_phdr(system_image, const_cast<char*>(path)) == 0);
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) exit(0);
  int status = 0;
  assert(waitpid(child, &status, 0) == child && status == 0);
  puts("PASS system Core unload and callback retirement");
}
}  // namespace
int main(int argc, char** argv) {
  real_munmap = reinterpret_cast<int (*)(void*, size_t)>(dlsym(RTLD_NEXT, "munmap"));
  real_dlclose = reinterpret_cast<int (*)(void*)>(dlsym(RTLD_NEXT, "dlclose"));
  assert(real_munmap && real_dlclose);
  if (argc == 4 && !strcmp(argv[1], "--system")) {
    run_system_core(argv[2], argv[3]);
    return 0;
  }
  assert(argc == 2);
  fixtures = argv[1];
  isolated("archive", [] { success("archive", BootCase::Success, false, true); });
  isolated("sources", [] { success("sources", BootCase::Success, false, false); });
  isolated("reentry", [] { success("archive", BootCase::Reenter, false, false); });
  isolated("ready_refusal", [] { refusal(BootCase::RejectReady); });
  isolated("dependency_refusal", [] { refusal(BootCase::RejectDependencies); });
  isolated("finish_refusal", [] { refusal(BootCase::RejectFinish); });
  isolated("cleanup_failure", [] { refusal(BootCase::CleanupFailure); });
  isolated("missing_entry", [] { malformed_core("zygisk_bootstrap_handoff_ready"); });
  isolated("packet_transfer", packet_case);
  isolated("packet_reused_fd", packet_reuse);
  isolated("two_cores", isolation);
  isolated("concurrent_fork", concurrency);
#if defined(__arm__)
  isolated("tango", [] { success("archive", BootCase::Success, true, false); });
  isolated("tango_fork", [] { success("archive", BootCase::ForkTango, true, false); });
#endif
  puts("PASS two-stage handoff, unload, Core execution, retirement and isolation");
}
