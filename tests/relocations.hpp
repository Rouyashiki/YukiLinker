// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#include <assert.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <initializer_list>
#include <yukilinker.hpp>

#include "control.hpp"

#if defined(__i386__) || defined(__x86_64__)

inline void exercise_arch_relocations(yukilinker::Runtime& runtime, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  const int source = open(path, O_RDONLY | O_CLOEXEC);
  struct stat status{};
  assert(source >= 0 && fstat(source, &status) == 0 && status.st_size > 0);
  const size_t bytes = status.st_size;
  auto* data =
      static_cast<uint8_t*>(mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, source, 0));
  assert(data != MAP_FAILED && close(source) == 0);
  const auto* header = reinterpret_cast<ElfW(Ehdr)*>(data);
  const auto* sections = reinterpret_cast<ElfW(Shdr)*>(data + header->e_shoff);
  auto* programs = reinterpret_cast<ElfW(Phdr)*>(data + header->e_phoff);
  ElfW(Addr) slots = 0, resolver = 0;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    const auto& section = sections[i];
    if (section.sh_type != SHT_DYNSYM) continue;
    const auto* symbols = reinterpret_cast<const ElfW(Sym)*>(data + section.sh_offset);
    const char* names = reinterpret_cast<char*>(data + sections[section.sh_link].sh_offset);
    for (size_t j = 0; j < section.sh_size / sizeof(*symbols); ++j) {
      if (strcmp(names + symbols[j].st_name, "module_x86_slots") == 0) slots = symbols[j].st_value;
      if (strcmp(names + symbols[j].st_name, "module_x86_resolver") == 0)
        resolver = symbols[j].st_value;
    }
  }
  assert(slots && resolver);
  constexpr size_t word = sizeof(ElfW(Addr));
  uint8_t* initial = nullptr;
  ElfW(Addr) last = 0;
  for (unsigned i = 0; i < header->e_phnum; ++i) {
    auto& p = programs[i];
    if (p.p_type != PT_LOAD || !(p.p_flags & PF_W) || slots < p.p_vaddr ||
        slots + 5 * word > p.p_vaddr + p.p_filesz)
      continue;
    initial = data + p.p_offset + (slots - p.p_vaddr);
    // One narrow write ends exactly at the end of the writable segment, including during
    // deferred IFUNC replay. Its implicit addend on i386 comes from zero-initialized BSS.
    last = p.p_vaddr + p.p_memsz;
    p.p_memsz += sizeof(uint32_t);
  }
  assert(initial && last);
  memset(initial, 0xa5, 5 * word);
#if defined(__x86_64__)
  using Rel = Elf64_Rela;
  constexpr uint32_t section_type = SHT_RELA, abs32 = R_X86_64_32, pc32 = R_X86_64_PC32;
  constexpr uint32_t irelative = R_X86_64_IRELATIVE, unsupported = R_X86_64_32S;
#else
  using Rel = Elf32_Rel;
  constexpr uint32_t section_type = SHT_REL, abs32 = R_386_32, pc32 = R_386_PC32;
  constexpr uint32_t irelative = R_386_IRELATIVE, unsupported = R_386_16;
#endif
  const ElfW(Addr) offsets[] = {slots + 1, slots + 5, slots + 9, last, slots + 4 * word};
  const uint32_t types[] = {abs32, pc32, pc32, pc32, irelative};
  const ElfW(Addr) addends[] = {3, 7, 11, 0, resolver};
  Rel* weak = nullptr;
  Rel* at_end = nullptr;
  unsigned seen = 0;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    if (sections[i].sh_type != section_type) continue;
    auto* entries = reinterpret_cast<Rel*>(data + sections[i].sh_offset);
    for (size_t j = 0; j < sections[i].sh_size / sizeof(Rel); ++j) {
      auto& r = entries[j];
      if (r.r_offset < slots || r.r_offset >= slots + 5 * word) continue;
      const size_t index = (r.r_offset - slots) / word;
      assert(r.r_offset == slots + index * word && !(seen & (1u << index)));
      seen |= 1u << index;
      r.r_offset = offsets[index];
#if defined(__x86_64__)
      r.r_info = ELF64_R_INFO(index == 4 ? 0 : ELF64_R_SYM(r.r_info), types[index]);
      r.r_addend = addends[index];
#else
      r.r_info = ELF32_R_INFO(index == 4 ? 0 : ELF32_R_SYM(r.r_info), types[index]);
      if (r.r_offset != last)
        memcpy(initial + (r.r_offset - slots), &addends[index], sizeof(Elf32_Addr));
#endif
      if (index == 2) weak = &r;
      if (index == 3) at_end = &r;
    }
  }
  assert(seen == 31 && weak && at_end);
  const auto open_copy = [&] {
    const int fd = fixture_fd(directory, "x86-relocations");
    assert(fd >= 0 && write(fd, data, bytes) == static_cast<ssize_t>(bytes));
    auto result = runtime.open_fd(fd);
    assert(close(fd) == 0);
    return result;
  };
  auto loaded = open_copy();
  assert(loaded);
  auto function = loaded.value.symbol<int (*)()>("module_x86_ifunc");
  assert(function && function.value() == 73);
  const auto image = loaded.value.image();
  assert(image);
  const uintptr_t target = reinterpret_cast<uintptr_t>(function.value);
  const uintptr_t bias = image.value.load_bias;
  const auto narrow = [bias](ElfW(Addr) offset) {
    uint32_t value;
    memcpy(&value, reinterpret_cast<const void*>(bias + offset), sizeof(value));
    return value;
  };
  assert(narrow(offsets[0]) == static_cast<uint32_t>(target + 3));
  assert(narrow(offsets[1]) == static_cast<uint32_t>(target + 7 - (bias + offsets[1])));
  assert(narrow(offsets[2]) == 11);  // unresolved weak PC32
  assert(narrow(last) == static_cast<uint32_t>(target - (bias + last)));
  uintptr_t indirect;
  memcpy(&indirect, reinterpret_cast<const void*>(bias + offsets[4]), sizeof(indirect));
  assert(indirect == target);
  const auto* live = reinterpret_cast<const uint8_t*>(bias + slots);
  assert(live[0] == 0xa5 && live[13] == 0xa5);
  assert(loaded.value.close().private_mapping_unmapped());

  // Overlap the end of the second narrow write by one byte.
  weak->r_offset = offsets[1] + 3;
  auto refused = open_copy();
  assert(!refused && refused.error.native.detail.code == YUKILINKER_C_INVALID_ELF &&
         refused.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
         !refused.error.native.detail.execution_started);

  // The last four bytes hold the operand. An unsupported encoding reports its
  // own type and offset even when a native pointer would cross the boundary.
  weak->r_offset = offsets[2];
#if defined(__x86_64__)
  at_end->r_info = ELF64_R_INFO(ELF64_R_SYM(at_end->r_info), unsupported);
#else
  at_end->r_info = ELF32_R_INFO(ELF32_R_SYM(at_end->r_info), unsupported);
#endif
  auto unknown = open_copy();
  const auto& error = unknown.error.native.detail;
  assert(!unknown && error.code == YUKILINKER_C_UNSUPPORTED &&
         error.stage == YUKILINKER_C_RELOCATIONS && error.machine == header->e_machine &&
         error.relocation_type == unsupported && error.offset == last && !error.execution_started);
  assert(munmap(data, bytes) == 0);
  puts("PASS x86 narrow relocations, weak PC32, IFUNC and IRELATIVE");
}

#elif defined(__riscv) && __riscv_xlen == 64

#include <dlfcn.h>
#include <linux/pidfd.h>
#include <setjmp.h>
#include <sys/auxv.h>
#include <sys/eventfd.h>
#include <sys/hwprobe.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "../src/arch/riscv64/tlsdesc_layout.h"

using RiscvIfunc = uint64_t (*)();

// Stop ordinary borrowers at their first TLS-key read, after their vectors are saved.
struct SpillBurst {
  int* (*slot)();
  unsigned arrived = 0;
  bool release = false;
};
static thread_local SpillBurst* pending_spill_burst;
static size_t spill_mapping_bytes;
static size_t thread_spill_mapping_bytes;
static thread_local int spill_mapping_error;
static thread_local size_t spill_reservation_limit;
static thread_local int thread_spill_mapping_error;
static thread_local bool fail_relro_after_spill_setup;
static thread_local void** fail_spill_rollback_mapping;
static thread_local unsigned thread_maps_before_failure;
static thread_local bool fail_tls_storage;
static unsigned spill_reservation_allocations;
static unsigned thread_spill_allocations;
static void* last_thread_spill;
static void* spill_guard_page;
static size_t spill_guard_bytes;
static thread_local bool guard_spill_restore;
static thread_local sigjmp_buf* spill_jump;
static thread_local int* (*nested_spill_call)();
static thread_local bool nested_spill_restore;
namespace yukilinker::internal {
struct RiscvSpillBank;
extern "C" RiscvSpillBank* yuki_riscv_spill_banks;
extern "C" size_t yuki_riscv_spill_stride;
extern "C" uintptr_t yuki_riscv_spill_end;
extern "C" uintptr_t yuki_riscv_spill_key[2];
extern "C" uintptr_t* yuki_riscv_spill_pins;
extern "C" uintptr_t yuki_riscv_spill_pin_chunks[];
}  // namespace yukilinker::internal

// Return a different value for the probe's key to simulate incompatible key storage.
static thread_local bool redirect_spill_probe;
static thread_local pthread_key_t last_created_spill_key;
extern "C" int __real_pthread_key_create(pthread_key_t*, void (*)(void*));
extern "C" int __wrap_pthread_key_create(pthread_key_t* key, void (*destructor)(void*)) {
  const int result = __real_pthread_key_create(key, destructor);
  if (!result) last_created_spill_key = *key;
  return result;
}

extern "C" void* __real_mmap(void*, size_t, int, int, int, off_t);
extern "C" void* __wrap_mmap(void* address, size_t bytes, int prot, int flags, int fd, off_t off) {
  constexpr int reservation_flags = MAP_ANONYMOUS | MAP_NORESERVE;
  const bool spill = (flags & reservation_flags) == reservation_flags;
  const bool thread_spill = bytes == thread_spill_mapping_bytes && (flags & MAP_ANONYMOUS);
  if (thread_spill && thread_spill_mapping_error) {
    if (!thread_maps_before_failure) {
      errno = thread_spill_mapping_error;
      return MAP_FAILED;
    }
    --thread_maps_before_failure;
  }
  if (spill && spill_mapping_error) {
    errno = spill_mapping_error;
    return MAP_FAILED;
  }
  if (spill && spill_reservation_limit && bytes > spill_reservation_limit) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  void* mapping = __real_mmap(address, bytes, prot, flags, fd, off);
  if (spill && mapping != MAP_FAILED)
    __atomic_add_fetch(&spill_reservation_allocations, 1u, __ATOMIC_RELAXED);
  if (thread_spill && mapping != MAP_FAILED) {
    __atomic_add_fetch(&thread_spill_allocations, 1u, __ATOMIC_RELAXED);
    __atomic_store_n(&last_thread_spill, mapping, __ATOMIC_RELAXED);
  }
  return mapping;
}

extern "C" int __real_mprotect(void*, size_t, int);
extern "C" int __wrap_mprotect(void* address, size_t bytes, int protection) {
  if (fail_relro_after_spill_setup && protection == PROT_READ &&
      yukilinker::internal::yuki_riscv_spill_banks) {
    fail_relro_after_spill_setup = false;
    if (fail_spill_rollback_mapping)
      *fail_spill_rollback_mapping = yukilinker::internal::yuki_riscv_spill_banks;
    errno = EACCES;
    return -1;
  }
  return __real_mprotect(address, bytes, protection);
}

extern "C" int __real_posix_memalign(void**, size_t, size_t);
extern "C" int __wrap_posix_memalign(void** result, size_t alignment, size_t bytes) {
  if (fail_tls_storage) return ENOMEM;
  return __real_posix_memalign(result, alignment, bytes);
}

static constexpr struct {
  int cause;
  uint32_t code;
} spill_mapping_errors[] = {{EPERM, YUKILINKER_C_PERMISSION_DENIED},
                            {EACCES, YUKILINKER_C_PERMISSION_DENIED},
                            {EIO, YUKILINKER_C_IO_ERROR},
                            {ENOMEM, YUKILINKER_C_NO_MEMORY}};

inline void check_riscv_tls_symbol_errors(yukilinker::Module& image, int* (*slot)()) {
  run_on_worker([&] {
    const auto check_failure = [&](int cause, uint32_t code) {
      errno = EBUSY;
      const auto result = image.symbol<int*>("module_value");
      const auto& error = result.error.native.detail;
      assert(!result && error.code == code && error.system_errno == cause &&
             error.stage == YUKILINKER_C_METADATA && error.machine == EM_RISCV &&
             !strcmp(error.symbol, "module_value"));
    };
    for (const auto [cause, code] : spill_mapping_errors) {
      thread_spill_mapping_error = cause;
      check_failure(cause, code);
    }
    thread_spill_mapping_error = 0;
    fail_tls_storage = true;
    check_failure(ENOMEM, YUKILINKER_C_NO_MEMORY);
    fail_tls_storage = false;
    const auto result = image.symbol<int*>("module_value");
    assert(result && result.value == slot() && *result.value == 42);
  });
}

static int* (*lock_owner_slot)();
inline char* spill_successor(char* bank) {
  char* next;
  memcpy(&next, bank, sizeof(next));
  return next;
}

inline void check_warm_spill_reserve(yukilinker::Module& image, int* (*slot)()) {
  auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  auto* owners = reinterpret_cast<uintptr_t*>(bank + YUKI_RVV_OWNERS);
  lock_owner_slot = slot;
  struct sigaction action{}, previous{};
  action.sa_handler = [](int) {
    auto* value = lock_owner_slot();
    assert(value && *value == 117);
    *value = 118;
  };
  assert(sigaction(SIGUSR1, nullptr, &previous) == 0);
  assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, nullptr) == 0);
  run_on_worker([&] {
    sigset_t signal;
    sigemptyset(&signal);
    sigaddset(&signal, SIGUSR1);
    assert(pthread_sigmask(SIG_UNBLOCK, &signal, nullptr) == 0);
    auto value = image.symbol<int*>("module_value");
    assert(value && *value.value == 42);
    *value.value = 117;
    assert(!spill_successor(bank));
    for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 1;
    assert(pthread_kill(pthread_self(), SIGUSR1) == 0 && *value.value == 118);
    for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 0;
    assert(!spill_successor(bank));
  });
  assert(sigaction(SIGUSR1, &previous, nullptr) == 0);
}

inline void check_riscv_lock_owner_spill(int* (*slot)()) {
  lock_owner_slot = slot;
  struct sigaction action{}, previous{};
  action.sa_handler = [](int) {
    int* value = lock_owner_slot();
    assert(value && *value == 42);
    *value = 117;
  };
  assert(sigaction(SIGUSR1, nullptr, &previous) == 0);
  assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, nullptr) == 0);
  run_on_worker([&] {
    sigset_t signal;
    sigemptyset(&signal);
    sigaddset(&signal, SIGUSR1);
    assert(pthread_sigmask(SIG_UNBLOCK, &signal, nullptr) == 0);
    pthread_t borrowers[YUKI_RVV_SLOTS];
    {
      yukilinker::internal::OperationGuard operation;
      size_t waiting = 0;
      for (auto& borrower : borrowers) {
        assert(pthread_create(
                   &borrower, nullptr,
                   [](void*) -> void* {
                     assert(*lock_owner_slot() == 42);
                     return nullptr;
                   },
                   nullptr) == 0);
        ++waiting;
        while (__atomic_load_n(&yukilinker::internal::g_lock_waiters, __ATOMIC_ACQUIRE) < waiting)
          usleep(1000);
      }
      // Every ordinary file now belongs to a cold caller waiting for this mutex.
      auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
      assert(!spill_successor(bank));
      assert(pthread_kill(pthread_self(), SIGUSR1) == 0 && *slot() == 117);
      assert(!spill_successor(bank));
    }
    for (auto borrower : borrowers) assert(pthread_join(borrower, nullptr) == 0);
  });
  assert(sigaction(SIGUSR1, &previous, nullptr) == 0);
}

inline void check_initial_spill_rollback(yukilinker::Runtime& runtime, const char* directory,
                                         const char* wide_path, void*& fail_mapping) {
  const pid_t child = fork();
  assert(child >= 0);
  if (child) {
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    return;
  }
  alarm(15);
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle_trad.so", directory);
  auto traditional = runtime.open_path(path);
  assert(traditional);
  auto slot = traditional.value.symbol<int* (*)()>("module_slot");
  assert(slot && !yukilinker::internal::yuki_riscv_spill_banks);
  struct Peer {
    int* (*slot)();
    bool ready = false;
    bool finish = false;
  } peer{slot.value};
  pthread_t worker;
  assert(pthread_create(
             &worker, nullptr,
             [](void* arg) -> void* {
               auto& peer = *static_cast<Peer*>(arg);
               int* value = peer.slot();
               assert(value && *value == 42);
               *value = 73;
               __atomic_store_n(&peer.ready, true, __ATOMIC_RELEASE);
               while (!__atomic_load_n(&peer.finish, __ATOMIC_ACQUIRE)) usleep(100);
               assert(peer.slot() == value && *value == 73);
               return nullptr;
             },
             &peer) == 0);
  while (!__atomic_load_n(&peer.ready, __ATOMIC_ACQUIRE)) usleep(100);
  run_on_worker([&] {
    int* value = slot.value();
    assert(value && *value == 42);
    *value = 97;
    const auto before = runtime.stats();
    assert(before);
    for (bool fail_shared : {false, true}) {
      // Fail after one thread reserve, then after both reserves at the shared reservation.
      const auto count = thread_spill_allocations;
      thread_maps_before_failure = 1;
      thread_spill_mapping_error = fail_shared ? 0 : EACCES;
      spill_mapping_error = fail_shared ? EACCES : 0;
      auto failed = runtime.open_path(wide_path);
      thread_spill_mapping_error = spill_mapping_error = 0;
      const auto& error = failed.error.native.detail;
      assert(!failed && error.code == YUKILINKER_C_PERMISSION_DENIED &&
             error.system_errno == EACCES && error.stage == YUKILINKER_C_RELOCATIONS &&
             error.relocation_type == R_RISCV_TLSDESC && !error.cleanup_incomplete);
      assert(thread_spill_allocations == count + (fail_shared ? 2u : 1u));
      assert(!yukilinker::internal::yuki_riscv_spill_pins &&
             pthread_setspecific(last_created_spill_key, value) == EINVAL);
      const auto after = runtime.stats();
      assert(after && after.value.mapped_bytes == before.value.mapped_bytes &&
             slot.value() == value && *value == 97);
    }
    // The first reservation is provisional until the open returns a handle. Refuse RELRO
    // after pool creation in a fixture with no IFUNC or constructors that can retain the image.
    char provider_path[4096];
    snprintf(provider_path, sizeof(provider_path), "%s/libtlsdesc_provider.so", directory);
    for (bool fail_unmap : {true, false}) {
      fail_relro_after_spill_setup = true;
      fail_spill_rollback_mapping = fail_unmap ? &fail_mapping : nullptr;
      const auto failed = runtime.open_path(provider_path);
      fail_spill_rollback_mapping = nullptr;
      assert(!fail_relro_after_spill_setup && !fail_mapping && !failed);
      const auto& error = failed.error.native.detail;
      assert(error.code == YUKILINKER_C_PERMISSION_DENIED &&
             error.stage == YUKILINKER_C_PROTECTION && error.system_errno == EACCES &&
             static_cast<bool>(error.cleanup_incomplete) == fail_unmap);
      assert((yukilinker::internal::yuki_riscv_spill_banks != nullptr) == fail_unmap);
    }
    assert(!yukilinker::internal::yuki_riscv_spill_banks &&
           !yukilinker::internal::yuki_riscv_spill_pins &&
           pthread_setspecific(last_created_spill_key, value) == EINVAL);
    const auto after = runtime.stats();
    assert(after && after.value.mapped_bytes == before.value.mapped_bytes &&
           slot.value() == value && *value == 97);
    auto wide = runtime.open_path(wide_path);
    assert(wide);
    auto retried = wide.value.symbol<int* (*)()>("module_slot");
    assert(retried);
    run_on_worker([&] { assert(*retried.value() == 42); });
    assert(wide.value.close().private_mapping_unmapped());
  });
  __atomic_store_n(&peer.finish, true, __ATOMIC_RELEASE);
  assert(pthread_join(worker, nullptr) == 0 &&
         traditional.value.close().private_mapping_unmapped());
  while (!runtime.try_shutdown().complete) usleep(100);
  assert(runtime.destroy());
  _exit(0);
}

inline void check_spill_reserve_handoff(yukilinker::Runtime& runtime, const char* directory,
                                        const char* wide_path) {
  const pid_t child = fork();
  assert(child >= 0);
  if (child) {
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    return;
  }
  alarm(10);
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle_trad.so", directory);
  auto traditional = runtime.open_path(path);
  assert(traditional);
  // Bionic visits this key after the native TLS key and before the wide spill key.
  struct Exit {
    pthread_key_t middle, spill;
    char* old = nullptr;
    bool paused = false;
    bool finish = false;
  } state{};
  assert(pthread_key_create(&state.middle, [](void* arg) {
           auto* state = static_cast<Exit*>(arg);
           __atomic_store_n(&state->paused, true, __ATOMIC_RELEASE);
           while (!__atomic_load_n(&state->finish, __ATOMIC_ACQUIRE)) usleep(100);
         }) == 0);
  auto wide = runtime.open_path(wide_path);
  assert(wide);
  state.spill = last_created_spill_key;
  auto slot = wide.value.symbol<int* (*)()>("module_slot");
  assert(slot);
  pthread_t worker;
  auto exit_with_frames = [&] {
    auto value = wide.value.symbol<int*>("module_value");
    assert(value && *value.value == 42);
    state.old = static_cast<char*>(last_thread_spill);
    auto* owners = reinterpret_cast<uintptr_t*>(state.old + YUKI_RVV_OWNERS);
    const auto thread = reinterpret_cast<uintptr_t>(__builtin_thread_pointer());
    // Model the eight saved frames left behind when a nested handler calls pthread_exit.
    for (unsigned i = 0; i < YUKI_RVV_NESTED_SLOTS; ++i) owners[i] = thread;
    assert(pthread_setspecific(state.middle, &state) == 0 &&
           pthread_setspecific(state.spill, &state) == 0);
  };
  assert(pthread_create(
             &worker, nullptr,
             [](void* arg) -> void* {
               (*static_cast<decltype(exit_with_frames)*>(arg))();
               return nullptr;
             },
             &exit_with_frames) == 0);
  while (!__atomic_load_n(&state.paused, __ATOMIC_ACQUIRE)) usleep(100);
  assert(!*reinterpret_cast<uintptr_t*>(state.old + YUKI_RVV_THREAD_TAG));
  auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  auto* owners = reinterpret_cast<uintptr_t*>(bank + YUKI_RVV_OWNERS);
  for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 1;
  run_on_worker([&] {
    auto value = wide.value.symbol<int*>("module_value");
    assert(value && last_thread_spill != state.old && slot.value() == value.value);
  });
  for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 0;
  __atomic_store_n(&state.finish, true, __ATOMIC_RELEASE);
  assert(pthread_join(worker, nullptr) == 0 && pthread_key_delete(state.middle) == 0);
  assert(wide.value.close().private_mapping_unmapped() &&
         traditional.value.close().private_mapping_unmapped());
  while (!runtime.try_shutdown().complete) usleep(100);
  assert(runtime.destroy());
  _exit(0);
}

inline void exercise_riscv_spill_errors(yukilinker::Runtime& runtime, const char* directory,
                                        void*& fail_mapping) {
  size_t vlenb;
  asm("csrr %0, vlenb" : "=r"(vlenb));
  if (vlenb <= YUKI_RVV_INLINE_VLENB) return;
  spill_mapping_bytes = YUKI_RVV_FILES + YUKI_RVV_TOTAL_SLOTS * 32 * vlenb;
  thread_spill_mapping_bytes = YUKI_RVV_THREAD_FILES + YUKI_RVV_NESTED_SLOTS * 32 * vlenb;
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  int status;
  check_initial_spill_rollback(runtime, directory, path, fail_mapping);
  check_spill_reserve_handoff(runtime, directory, path);
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    alarm(15);
    auto image = runtime.open_path(path);
    assert(image);
    auto slot = image.value.symbol<int* (*)()>("module_slot");
    assert(slot);
    check_riscv_tls_symbol_errors(image.value, slot.value);
    check_warm_spill_reserve(image.value, slot.value);
    check_riscv_lock_owner_spill(slot.value);
    assert(image.value.close().private_mapping_unmapped());
    while (!runtime.try_shutdown().complete) usleep(100);
    assert(runtime.destroy());
    _exit(0);
  }
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
  for (bool single_bank : {false, true}) {
    const pid_t limited = fork();
    assert(limited >= 0);
    if (!limited) {
      alarm(15);
      snprintf(path, sizeof(path), "%s/libtlsdesc_provider.so", directory);
      const int fd = open(path, O_RDONLY | O_CLOEXEC);
      assert(fd >= 0);
      rlimit limit;
      assert(getrlimit(RLIMIT_NOFILE, &limit) == 0);
      // open selected the lowest available descriptor, so no further fd can be allocated.
      const rlimit small{static_cast<rlim_t>(fd) + 1, limit.rlim_max};
      assert(setrlimit(RLIMIT_NOFILE, &small) == 0);
      const size_t page = getauxval(AT_PAGESZ);
      if (single_bank) spill_reservation_limit = (spill_mapping_bytes + page - 1) & ~(page - 1);
      auto image = runtime.open_fd(fd);
      assert(image);
      auto slot = image.value.symbol<int* (*)()>("provided_tls_address");
      assert(slot);
      auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
      auto* owners = reinterpret_cast<uintptr_t*>(bank + YUKI_RVV_OWNERS);
      const auto reserved = yukilinker::internal::yuki_riscv_spill_end -
                            reinterpret_cast<uintptr_t>(bank);
      if (single_bank) assert(reserved == spill_reservation_limit);
      for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 1;
      int* under_pressure = slot.value();
      assert(under_pressure && *under_pressure == 42);
      if (single_bank) {
        *under_pressure = 73;
        owners[0] = 0;
        assert(slot.value() == under_pressure && *under_pressure == 73);
      }
      assert((spill_successor(bank) != nullptr) == !single_bank);
      for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 0;
      assert(setrlimit(RLIMIT_NOFILE, &limit) == 0 && close(fd) == 0);
      // This fixture sets DF_1_GLOBAL and retains its mapping after releasing the reference.
      const auto closed = image.value.close();
      assert(closed.handle_valid() && closed.reference() == yukilinker::Reference::Released &&
             image.value.forget() == yukilinker::Code::Ok);
      _exit(0);
    }
    assert(waitpid(limited, &status, 0) == limited && WIFEXITED(status) && !WEXITSTATUS(status));
  }
  redirect_spill_probe = true;
  auto incompatible = runtime.open_path(path);
  redirect_spill_probe = false;
  const auto& layout_error = incompatible.error.native.detail;
  assert(!incompatible && layout_error.code == YUKILINKER_C_UNSUPPORTED &&
         layout_error.stage == YUKILINKER_C_RELOCATIONS && layout_error.system_errno == 0 &&
         layout_error.relocation_type == R_RISCV_TLSDESC && layout_error.offset &&
         !yukilinker::internal::yuki_riscv_spill_banks);
  for (const auto [cause, code] : spill_mapping_errors) {
    spill_mapping_error = cause;
    auto result = runtime.open_path(path);
    spill_mapping_error = 0;
    const auto& error = result.error.native.detail;
    assert(!result && error.code == code && error.system_errno == cause &&
           error.stage == YUKILINKER_C_RELOCATIONS && error.machine == EM_RISCV &&
           error.relocation_type == R_RISCV_TLSDESC && error.offset);
  }
  puts("PASS RISC-V spill growth, saturation fallback and relocation errors");
}

static void interrupt_nested_spill(pthread_key_t key);

extern "C" void* __real_pthread_getspecific(pthread_key_t);
extern "C" void* __wrap_pthread_getspecific(pthread_key_t key) {
  // A key read during failed allocation rollback may change the caller's errno.
  if (thread_spill_mapping_error && key == yukilinker::internal::g_thread_tls_key) errno = EBUSY;
  if (nested_spill_call && !spill_jump && key == yukilinker::internal::g_thread_tls_key)
    assert(raise(SIGSYS) == 0);
  if (guard_spill_restore && key == yukilinker::internal::g_thread_tls_key) {
    guard_spill_restore = false;
    assert(mprotect(spill_guard_page, spill_guard_bytes, PROT_NONE) == 0);
  }
  interrupt_nested_spill(key);
  if (auto* burst = pending_spill_burst; burst && key == yukilinker::internal::g_thread_tls_key) {
    pending_spill_burst = nullptr;
    __atomic_add_fetch(&burst->arrived, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&burst->release, __ATOMIC_ACQUIRE)) usleep(1000);
  }
  return __real_pthread_getspecific(key);
}

struct NestedSpill {
  int* (*cold)();
  int* (*warm)();
  int* expected = nullptr;
  bool ready = false;
  bool start = false;
  bool last = false;
  bool handled = false;
  bool peer_ready = false;
  bool run_peer = false;
  bool peer_done = false;
};
static thread_local NestedSpill* interrupted_spill;
static NestedSpill* forking_spill;

static void interrupt_nested_spill(pthread_key_t key) {
  // Interrupt after the cold caller saves its registers and before it waits for the lock.
  static thread_local bool delivering;
  if (key != yukilinker::internal::g_thread_tls_key || !interrupted_spill || delivering ||
      __atomic_load_n(&interrupted_spill->handled, __ATOMIC_ACQUIRE))
    return;
  delivering = true;
  assert(raise(SIGUSR1) == 0);
  delivering = false;
}

inline void prepare_nested_spill() {
  if (!forking_spill) return;
  auto& test = *forking_spill;
  // Our prepare handler was registered before Core's, so Core now holds both locks.
  __atomic_store_n(&test.start, true, __ATOMIC_RELEASE);
  while (__atomic_load_n(&yukilinker::internal::g_lock_waiters, __ATOMIC_ACQUIRE) <
         YUKI_RVV_SLOTS - 1)
    usleep(1000);
  auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  assert(!spill_successor(bank));
  // Exercise YUKI_RVV_FORK_OWNERS while peer borrowers hold all 64 ordinary slots.
  assert(*test.cold() == 42 && !spill_successor(bank));
  __atomic_store_n(&test.last, true, __ATOMIC_RELEASE);
  for (unsigned i = 0; i < 3000 && !__atomic_load_n(&test.handled, __ATOMIC_ACQUIRE); ++i)
    usleep(1000);
  assert(__atomic_load_n(&test.handled, __ATOMIC_ACQUIRE));
  while (__atomic_load_n(&yukilinker::internal::g_lock_waiters, __ATOMIC_ACQUIRE) < YUKI_RVV_SLOTS)
    usleep(1000);
  __atomic_store_n(&test.run_peer, true, __ATOMIC_RELEASE);
  for (unsigned i = 0; i < 3000 && !__atomic_load_n(&test.peer_done, __ATOMIC_ACQUIRE); ++i)
    usleep(1000);
  assert(__atomic_load_n(&test.peer_done, __ATOMIC_ACQUIRE));
}

inline void exercise_riscv_nested_spill(yukilinker::Runtime& runtime, const char* directory,
                                        int* (*warm)()) {
  if (!spill_mapping_bytes) return;
  // Isolate the ELF-global provider, its threads and the signal handler from the remaining cases.
  const pid_t child = fork();
  assert(child >= 0);
  if (child) {
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS RISC-V nested signal and independent warm TLS lookup during fork");
    return;
  }
  alarm(30);
  char path[4096];
  snprintf(path, sizeof(path), "%s/libtlsdesc_provider.so", directory);
  auto provider = runtime.open_path(path);
  assert(provider);
  auto cold = provider.value.symbol<int* (*)()>("provided_tls_address");
  assert(cold);
  NestedSpill test{cold.value, warm};
  struct sigaction action{};
  action.sa_handler = [](int) {
    auto* test = interrupted_spill;
    int* value = test->warm();
    assert(value == test->expected && *value == 117);
    __atomic_store_n(&test->handled, true, __ATOMIC_RELEASE);
    assert(*test->cold() == 42);
  };
  assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, nullptr) == 0);
  pthread_t holders[YUKI_RVV_SLOTS - 1], last, peer;
  const auto warm_peer = [](void* arg) -> void* {
    auto& test = *static_cast<NestedSpill*>(arg);
    auto* value = test.warm();
    assert(value && *value == 42);
    *value = 119;
    __atomic_store_n(&test.peer_ready, true, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&test.run_peer, __ATOMIC_ACQUIRE)) usleep(1000);
    assert(test.warm() == value && *value == 119);
    __atomic_store_n(&test.peer_done, true, __ATOMIC_RELEASE);
    return nullptr;
  };
  assert(pthread_create(&peer, nullptr, warm_peer, &test) == 0);
  for (auto& holder : holders) {
    assert(pthread_create(
               &holder, nullptr,
               [](void* arg) -> void* {
                 auto* test = static_cast<NestedSpill*>(arg);
                 while (!__atomic_load_n(&test->start, __ATOMIC_ACQUIRE)) usleep(1000);
                 assert(*test->cold() == 42);
                 return nullptr;
               },
               &test) == 0);
  }
  assert(pthread_create(
             &last, nullptr,
             [](void* arg) -> void* {
               auto* test = static_cast<NestedSpill*>(arg);
               sigset_t signal;
               sigemptyset(&signal);
               sigaddset(&signal, SIGUSR1);
               assert(pthread_sigmask(SIG_UNBLOCK, &signal, nullptr) == 0);
               test->expected = test->warm();
               assert(test->expected && *test->expected == 42);
               *test->expected = 117;
               __atomic_store_n(&test->ready, true, __ATOMIC_RELEASE);
               while (!__atomic_load_n(&test->last, __ATOMIC_ACQUIRE)) usleep(1000);
               interrupted_spill = test;
               assert(*test->cold() == 42);
               interrupted_spill = nullptr;
               return nullptr;
             },
             &test) == 0);
  while (!__atomic_load_n(&test.ready, __ATOMIC_ACQUIRE)) usleep(1000);
  while (!__atomic_load_n(&test.peer_ready, __ATOMIC_ACQUIRE)) usleep(1000);
  auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  assert(!spill_successor(bank));
  forking_spill = &test;
  const pid_t copy = fork();
  assert(copy >= 0);
  if (!copy) _exit(0);
  forking_spill = nullptr;
  int status;
  assert(waitpid(copy, &status, 0) == copy && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  for (auto holder : holders) assert(pthread_join(holder, nullptr) == 0);
  assert(pthread_join(last, nullptr) == 0);
  assert(pthread_join(peer, nullptr) == 0);
  assert(!spill_successor(bank));
  _exit(0);
}

static thread_local bool exit_spill_wait;
static bool spill_wait_registered;
static bool spill_exit_delivered;

struct SpillExitObservation {
  pthread_key_t hold_key{};
  pid_t tid = 0;
  int fd = -1;
  int* (*reuse_slot)() = nullptr;
  bool ready = false;
  bool finish = false;
  bool tls_reused = false;
  bool done = false;
};
static thread_local SpillExitObservation* spill_exit_observation;
extern "C" int __real_pidfd_open(pid_t, unsigned);
extern "C" int __wrap_pidfd_open(pid_t tid, unsigned flags) {
  if (auto* observation = spill_exit_observation) {
    assert(flags == PIDFD_THREAD && observation->fd == -1);
    observation->tid = tid;
    observation->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    assert(observation->fd >= 0);
    return observation->fd;
  }
  return __real_pidfd_open(tid, flags);
}

inline void exercise_riscv_spill_exit(yukilinker::Runtime& runtime, int* (*slot)()) {
  if (!spill_mapping_bytes) return;
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    alarm(30);
    struct sigaction action{};
    action.sa_handler = [](int) {
      __atomic_store_n(&spill_exit_delivered, true, __ATOMIC_RELEASE);
      pthread_exit(&spill_exit_delivered);
    };
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR2, &action, nullptr) == 0);
    const auto before = runtime.stats();
    assert(before);
    SpillExitObservation observation;
    const auto spill_key_index =
        yukilinker::internal::yuki_riscv_spill_key[0] / (2 * sizeof(uintptr_t));
    do {
      assert(pthread_key_create(&observation.hold_key, [](void* opaque) {
               auto* observation = static_cast<SpillExitObservation*>(opaque);
               __atomic_store_n(&observation->ready, true, __ATOMIC_RELEASE);
               while (!__atomic_load_n(&observation->finish, __ATOMIC_ACQUIRE)) usleep(100);
               if (observation->reuse_slot) {
                 int* value = observation->reuse_slot();
                 assert(value && *value == 42);
                 __atomic_store_n(&observation->tls_reused, true, __ATOMIC_RELEASE);
                 while (!__atomic_load_n(&observation->done, __ATOMIC_ACQUIRE)) usleep(100);
               }
             }) == 0);
    } while ((static_cast<unsigned>(observation.hold_key) ^ (1u << 31)) <= spill_key_index);
    for (unsigned i = 0; i <= YUKI_RVV_SLOTS; ++i) {
      __atomic_store_n(&spill_wait_registered, false, __ATOMIC_RELAXED);
      __atomic_store_n(&spill_exit_delivered, false, __ATOMIC_RELAXED);
      yukilinker::internal::operation_lock();
      pthread_t worker;
      struct Borrow {
        decltype(slot) access;
        SpillExitObservation* observation;
      } borrow{slot, i == 0 ? &observation : nullptr};
      const auto wait_for_tls = [](void* arg) -> void* {
        const auto& borrow = *static_cast<const Borrow*>(arg);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR2);
        assert(pthread_sigmask(SIG_UNBLOCK, &set, nullptr) == 0);
        if (borrow.observation) {
          spill_exit_observation = borrow.observation;
          assert(pthread_setspecific(borrow.observation->hold_key, borrow.observation) == 0);
        }
        exit_spill_wait = true;
        borrow.access();
        return nullptr;
      };
      assert(pthread_create(&worker, nullptr, wait_for_tls, &borrow) == 0);
      while (!__atomic_load_n(&spill_wait_registered, __ATOMIC_ACQUIRE)) usleep(1000);
      assert(pthread_kill(worker, SIGUSR2) == 0);
      while (!__atomic_load_n(&spill_exit_delivered, __ATOMIC_ACQUIRE)) usleep(1000);
      yukilinker::internal::operation_unlock();
      if (borrow.observation) {
        while (!__atomic_load_n(&observation.ready, __ATOMIC_ACQUIRE)) usleep(100);
        assert(observation.fd >= 0);
        const auto* group =
            &yukilinker::internal::yuki_riscv_spill_pins[observation.tid / YUKI_RVV_PIN_GROUP];
        const auto bit = uintptr_t{1} << (observation.tid % YUKI_RVV_PIN_GROUP);
        assert(runtime.stats() && (__atomic_load_n(group, __ATOMIC_ACQUIRE) & bit));
        // Model a dead original task whose numeric TID now belongs to a live task.
        const uint64_t exited = 1;
        assert(write(observation.fd, &exited, sizeof(exited)) == sizeof(exited) &&
               syscall(SYS_tgkill, getpid(), observation.tid, 0) == 0);
        assert(runtime.stats() && !(__atomic_load_n(group, __ATOMIC_ACQUIRE) & bit) &&
               fcntl(observation.fd, F_GETFD) == -1 && errno == EBADF);
        __atomic_store_n(&observation.finish, true, __ATOMIC_RELEASE);
      }
      void* result;
      assert(pthread_join(worker, &result) == 0 && result == &spill_exit_delivered);
    }
    auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
    assert(!spill_successor(bank));
    const auto* owners = reinterpret_cast<const uintptr_t*>(bank + YUKI_RVV_OWNERS);
    for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) assert(!owners[i]);
    const auto after_loop = runtime.stats();
    assert(after_loop && after_loop.value.mapped_bytes == before.value.mapped_bytes);
    // Verify a normal TLSDESC call on a reused watched TID unpins immediately upon return.
    SpillExitObservation reuse_obs;
    reuse_obs.hold_key = observation.hold_key;
    reuse_obs.reuse_slot = slot;
    __atomic_store_n(&spill_wait_registered, false, __ATOMIC_RELAXED);
    __atomic_store_n(&spill_exit_delivered, false, __ATOMIC_RELAXED);
    yukilinker::internal::operation_lock();
    pthread_t reuse_worker;
    struct ReuseBorrow {
      decltype(slot) access;
      SpillExitObservation* observation;
    } reuse_borrow{slot, &reuse_obs};
    assert(pthread_create(
               &reuse_worker, nullptr,
               [](void* arg) -> void* {
                 const auto& borrow = *static_cast<const ReuseBorrow*>(arg);
                 sigset_t set;
                 sigemptyset(&set);
                 sigaddset(&set, SIGUSR2);
                 assert(pthread_sigmask(SIG_UNBLOCK, &set, nullptr) == 0);
                 spill_exit_observation = borrow.observation;
                 assert(pthread_setspecific(borrow.observation->hold_key, borrow.observation) == 0);
                 exit_spill_wait = true;
                 borrow.access();
                 return nullptr;
               },
               &reuse_borrow) == 0);
    while (!__atomic_load_n(&spill_wait_registered, __ATOMIC_ACQUIRE)) usleep(1000);
    assert(pthread_kill(reuse_worker, SIGUSR2) == 0);
    while (!__atomic_load_n(&spill_exit_delivered, __ATOMIC_ACQUIRE)) usleep(1000);
    yukilinker::internal::operation_unlock();
    while (!__atomic_load_n(&reuse_obs.ready, __ATOMIC_ACQUIRE)) usleep(100);
    assert(reuse_obs.fd >= 0);
    const auto* reuse_group =
        &yukilinker::internal::yuki_riscv_spill_pins[reuse_obs.tid / YUKI_RVV_PIN_GROUP];
    const auto reuse_bit = uintptr_t{1} << (reuse_obs.tid % YUKI_RVV_PIN_GROUP);
    assert(__atomic_load_n(reuse_group, __ATOMIC_ACQUIRE) & reuse_bit);
    __atomic_store_n(&reuse_obs.finish, true, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&reuse_obs.tls_reused, __ATOMIC_ACQUIRE)) usleep(100);
    assert(!(__atomic_load_n(reuse_group, __ATOMIC_ACQUIRE) & reuse_bit));
    assert(runtime.stats() && !(__atomic_load_n(reuse_group, __ATOMIC_ACQUIRE) & reuse_bit) &&
           fcntl(reuse_obs.fd, F_GETFD) == -1 && errno == EBADF);
    __atomic_store_n(&reuse_obs.done, true, __ATOMIC_RELEASE);
    void* reuse_result;
    assert(pthread_join(reuse_worker, &reuse_result) == 0 && reuse_result == &spill_exit_delivered);
    const size_t page = getauxval(AT_PAGESZ);
    const size_t thread_bank = (thread_spill_mapping_bytes + page - 1) & ~(page - 1);
    const auto after = runtime.stats();
    assert(after && after.value.mapped_bytes == before.value.mapped_bytes + thread_bank);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  puts("PASS RISC-V spill mappings are reused after pthread_exit in a TLS wait");
}

// Interrupt the actual vector store or load. The header stays writable so the same
// borrowed slot can be inspected after Bionic discards the worker's stack.
inline void exercise_riscv_spill_edges(yukilinker::Module& module, int* (*slot)()) {
  if (!spill_mapping_bytes) return;
  for (unsigned mode = 0; mode < 8; ++mode) {
    const bool final_pass = mode >= 6;
    const bool nested = mode == 4 || mode == 5;
    const bool restore = mode & 1;
    const pid_t child = fork();
    assert(child >= 0);
    if (!child) {
      alarm(15);
      auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
      const size_t page = getauxval(AT_PAGESZ);
      const size_t file_bytes = (spill_mapping_bytes - YUKI_RVV_FILES) / YUKI_RVV_TOTAL_SLOTS;
      // Start on a file containing a page boundary beyond the bank header.
      const size_t guard = nested ? (YUKI_RVV_FILES + file_bytes + page - 1) & ~(page - 1) : page;
      unsigned index = (guard - YUKI_RVV_FILES) / file_bytes;
      assert(index < YUKI_RVV_SLOTS / 2);
      auto* owners = reinterpret_cast<uintptr_t*>(bank + YUKI_RVV_OWNERS);
      for (unsigned i = 0; i < index - unsigned(nested); ++i) owners[i] = 1;
      spill_guard_page = bank + guard;
      spill_guard_bytes = page;
      struct sigaction action{};
      action.sa_flags = SA_SIGINFO | (nested ? SA_ONSTACK : 0);
      action.sa_sigaction = [](int, siginfo_t* info, void*) {
        const auto address = reinterpret_cast<uintptr_t>(info->si_addr);
        const auto begin = reinterpret_cast<uintptr_t>(spill_guard_page);
        assert(address >= begin && address - begin < spill_guard_bytes);
        if (spill_jump) siglongjmp(*spill_jump, 1);
        pthread_exit(spill_guard_page);
      };
      assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGSEGV, &action, nullptr) == 0);
      if (nested) {
        struct sigaction inner{};
        inner.sa_handler = [](int) {
          // Deliver the guarded vector fault on Bionic's separate signal stack.
          sigset_t faults;
          assert(sigemptyset(&faults) == 0 && sigaddset(&faults, SIGSEGV) == 0);
          assert(pthread_sigmask(SIG_UNBLOCK, &faults, nullptr) == 0);
          sigjmp_buf target;
          spill_jump = &target;
          if (!sigsetjmp(target, 1)) {
            if (nested_spill_restore)
              guard_spill_restore = true;
            else
              assert(mprotect(spill_guard_page, spill_guard_bytes, PROT_READ) == 0);
            nested_spill_call();
            abort();
          }
          assert(mprotect(spill_guard_page, spill_guard_bytes, PROT_READ | PROT_WRITE) == 0);
          spill_jump = nullptr;
          nested_spill_call = nullptr;
        };
        assert(sigemptyset(&inner.sa_mask) == 0 && sigaction(SIGSYS, &inner, nullptr) == 0);
      } else if (!restore) {
        assert(mprotect(spill_guard_page, page, PROT_READ) == 0);
      }
      struct Call {
        int* (*slot)();
        bool restore;
        bool jump;
        bool nested;
        bool final_pass;
        pthread_key_t key{};
        unsigned passes = 0;
        pid_t tid = 0;
        static void last_destructor(void* opaque) {
          auto* call = static_cast<Call*>(opaque);
          if (++call->passes < PTHREAD_DESTRUCTOR_ITERATIONS) {
            assert(pthread_setspecific(call->key, call) == 0);
            return;
          }
          sigjmp_buf target;
          spill_jump = &target;
          if (sigsetjmp(target, 1) == 0) {
            guard_spill_restore = call->restore;
            call->slot();
            abort();
          }
          spill_jump = nullptr;
        }
      } call{slot, restore, mode >= 2, nested, final_pass};
      if (final_pass) {
        // Bionic visits keys in index order. Keep earlier unused indices occupied in this child.
        const auto core_index =
            yukilinker::internal::yuki_riscv_spill_key[0] / (2 * sizeof(uintptr_t));
        do {
          assert(pthread_key_create(&call.key, Call::last_destructor) == 0);
        } while ((static_cast<unsigned>(call.key) ^ (1u << 31)) <= core_index);
      }
      pthread_t worker;
      assert(pthread_create(
                 &worker, nullptr,
                 [](void* arg) -> void* {
                   auto* call = static_cast<Call*>(arg);
                   if (call->final_pass) {
                     call->tid = gettid();
                     assert(pthread_setspecific(call->key, call) == 0);
                     return spill_guard_page;
                   }
                   if (call->nested) {
                     nested_spill_restore = call->restore;
                     nested_spill_call = call->slot;
                     assert(*call->slot() == 42 && !nested_spill_call);
                     return spill_guard_page;
                   }
                   if (call->jump) {
                     __pthread_cleanup_t outer;
                     __pthread_cleanup_push(&outer, [](void*) {}, nullptr);
                     sigjmp_buf target;
                     spill_jump = &target;
                     for (unsigned i = 0; i < YUKI_RVV_TOTAL_SLOTS + 1; ++i) {
                       if (sigsetjmp(target, 1) == 0) {
                         guard_spill_restore = call->restore;
                         call->slot();
                         abort();
                       }
                       // Inspect the link through libc before touching the discarded frame.
                       __pthread_cleanup_t check;
                       __pthread_cleanup_push(&check, [](void*) {}, nullptr);
                       if (check.__cleanup_prev != &outer) _exit(41);
                       __pthread_cleanup_pop(&check, 0);
                       if (call->restore)
                         assert(mprotect(spill_guard_page, spill_guard_bytes,
                                         PROT_READ | PROT_WRITE) == 0);
                     }
                     spill_jump = nullptr;
                     assert(mprotect(spill_guard_page, spill_guard_bytes, PROT_READ | PROT_WRITE) ==
                            0);
                     assert(*call->slot() == 42);
                     __pthread_cleanup_pop(&outer, 0);
                     return spill_guard_page;
                   }
                   guard_spill_restore = call->restore;
                   call->slot();
                   return nullptr;
                 },
                 &call) == 0);
      void* result;
      assert(pthread_join(worker, &result) == 0 && result == spill_guard_page);
      if (final_pass) {
        assert(call.passes == PTHREAD_DESTRUCTOR_ITERATIONS);
        while (syscall(SYS_tgkill, getpid(), call.tid, 0) == 0) usleep(100);
        assert(errno == ESRCH && module.close().private_mapping_unmapped());
        const auto bit = uintptr_t{1} << (call.tid % YUKI_RVV_PIN_GROUP);
        assert(!(yukilinker::internal::yuki_riscv_spill_pins[call.tid / YUKI_RVV_PIN_GROUP] & bit));
      }
      assert(!__atomic_load_n(&owners[index], __ATOMIC_ACQUIRE));
      _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  puts("PASS pthread_exit and siglongjmp during RISC-V vector save and restore");
}

inline void exercise_riscv_spill_contention(yukilinker::Runtime& runtime, int* (*slot)()) {
  if (!spill_mapping_bytes) return;
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    alarm(15);
    auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
    auto* owners = reinterpret_cast<uintptr_t*>(bank + YUKI_RVV_OWNERS);
    const auto stride = yukilinker::internal::yuki_riscv_spill_stride;
    assert(!spill_successor(bank) &&
           yukilinker::internal::yuki_riscv_spill_end - reinterpret_cast<uintptr_t>(bank) > stride);
    for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 1;
    const auto before = runtime.stats();
    assert(before);

    SpillBurst borrower{slot};
    pthread_t worker;
    assert(pthread_create(
               &worker, nullptr,
               [](void* arg) -> void* {
                 auto* borrower = static_cast<SpillBurst*>(arg);
                 pending_spill_burst = borrower;
                 int* value = borrower->slot();
                 assert(value && *value == 42);
                 *value = 127;
                 assert(borrower->slot() == value && *value == 127);
                 return nullptr;
               },
               &borrower) == 0);
    while (!__atomic_load_n(&borrower.arrived, __ATOMIC_ACQUIRE)) usleep(100);

    // The cold borrower used the next bank without allocating another mapping.
    char* next = spill_successor(bank);
    assert(next == bank + stride);
    auto* peer_owner = reinterpret_cast<uintptr_t*>(next + YUKI_RVV_OWNERS);
    const auto active = runtime.stats();
    assert(*peer_owner && active && active.value.mapped_bytes == before.value.mapped_bytes);

    // Fork must skip pin-table pages outside the chunks touched by borrowers.
    const auto pins = reinterpret_cast<uintptr_t>(yukilinker::internal::yuki_riscv_spill_pins);
    const auto page = getauxval(AT_PAGESZ);
    constexpr size_t table_bytes = size_t{1} << YUKI_RISCV_TID_BITS;
    void* untouched = nullptr;
    for (auto end = (pins + table_bytes) & ~(page - 1); end >= pins + page; end -= page) {
      const auto first = (end - page - pins) >> YUKI_RVV_PIN_CHUNK_SHIFT;
      const auto last = (end - 1 - pins) >> YUKI_RVV_PIN_CHUNK_SHIFT;
      bool used = false;
      for (auto chunk = first; chunk <= last; ++chunk)
        used |= (yukilinker::internal::yuki_riscv_spill_pin_chunks[chunk / 64] >> (chunk % 64)) & 1;
      if (!used) {
        untouched = reinterpret_cast<void*>(end - page);
        break;
      }
    }
    assert(untouched && mprotect(untouched, page, PROT_NONE) == 0);

    const pid_t copy = fork();
    assert(copy >= 0);
    if (!copy) {
      assert(spill_successor(bank) == next && !*peer_owner);
      const auto stats = runtime.stats();
      assert(stats && stats.value.mapped_bytes == before.value.mapped_bytes);
      assert(*slot() == 42);
      _exit(0);
    }
    assert(mprotect(untouched, page, PROT_READ | PROT_WRITE) == 0);
    int status;
    assert(waitpid(copy, &status, 0) == copy && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(*peer_owner);
    __atomic_store_n(&borrower.release, true, __ATOMIC_RELEASE);
    assert(pthread_join(worker, nullptr) == 0 && !*peer_owner);
    for (unsigned i = 0; i < YUKI_RVV_SLOTS; ++i) owners[i] = 0;
    _exit(0);
  }
  // A fork blocked with its signals masked cannot run its own alarm handler.
  int status = 0;
  pid_t done = 0;
  for (unsigned i = 0; i < 1500 && !done; ++i) {
    done = waitpid(child, &status, WNOHANG);
    assert(done >= 0);
    if (!done) usleep(10000);
  }
  if (!done) {
    assert(kill(child, SIGKILL) == 0 && waitpid(child, &status, 0) == child);
  }
  assert(WIFEXITED(status) && !WEXITSTATUS(status));
  puts("PASS RISC-V TLS under spill pressure and fork with an active second bank");
}

inline void exercise_riscv_spill_reuse(int* (*slot)()) {
  if (!spill_mapping_bytes) return;
  constexpr unsigned callers = YUKI_RVV_SLOTS + 1;
  auto* bank = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  assert(!spill_successor(bank));
  const auto reservations = __atomic_load_n(&spill_reservation_allocations, __ATOMIC_RELAXED);
  const auto stride = yukilinker::internal::yuki_riscv_spill_stride;
  for (unsigned round = 0; round < 3; ++round) {
    SpillBurst burst{slot};
    pthread_t workers[callers];
    for (auto& worker : workers) {
      assert(pthread_create(
                 &worker, nullptr,
                 [](void* arg) -> void* {
                   auto* burst = static_cast<SpillBurst*>(arg);
                   pending_spill_burst = burst;
                   int* value = burst->slot();
                   assert(value && *value == 42);
                   return nullptr;
                 },
                 &burst) == 0);
    }
    while (__atomic_load_n(&burst.arrived, __ATOMIC_ACQUIRE) < callers) usleep(1000);
    assert(spill_successor(bank) == bank + stride && !spill_successor(bank + stride));
    assert(__atomic_load_n(&spill_reservation_allocations, __ATOMIC_RELAXED) == reservations);
    __atomic_store_n(&burst.release, true, __ATOMIC_RELEASE);
    for (auto& worker : workers) assert(pthread_join(worker, nullptr) == 0);
  }
  puts("PASS RISC-V TLSDESC reuses pre-reserved spill banks across equal bursts");
}

inline void check_riscv_spill_stats(yukilinker::Runtime& runtime, void*& fail_mapping) {
  if (!spill_mapping_bytes) return;
  const size_t page = getauxval(AT_PAGESZ);
  const size_t thread_bank = (thread_spill_mapping_bytes + page - 1) & ~(page - 1);
  const auto thread_count = __atomic_load_n(&thread_spill_allocations, __ATOMIC_RELAXED);
  auto* reservation = reinterpret_cast<char*>(yukilinker::internal::yuki_riscv_spill_banks);
  const auto reserved = yukilinker::internal::yuki_riscv_spill_end -
                        reinterpret_cast<uintptr_t>(reservation);
  char* second = spill_successor(reservation);
  assert(reserved && second && thread_count);
  const auto check = [&](size_t expected) {
    auto stats = runtime.stats();
    assert(stats && !stats.value.images &&
           stats.value.mapped_bytes == stats.value.stub_mapped_bytes + expected);
  };
  const auto total = thread_count * thread_bank + reserved;
  check(total);
  // Fork may read idle headers. It should not copy their pages by writing to them.
  assert(mprotect(last_thread_spill, page, PROT_READ) == 0);
  assert(mprotect(second, page, PROT_READ) == 0);
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    fail_mapping = __atomic_load_n(&last_thread_spill, __ATOMIC_RELAXED);
    assert(!runtime.try_shutdown().complete && !fail_mapping);
    check(thread_bank + reserved);
    fail_mapping = reservation;
    assert(!runtime.try_shutdown().complete && !fail_mapping);
    check(reserved);
    assert(runtime.try_shutdown().complete);
    check(0);
    assert(runtime.destroy());
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
  assert(mprotect(second, page, PROT_READ | PROT_WRITE) == 0);
  assert(mprotect(last_thread_spill, page, PROT_READ | PROT_WRITE) == 0);
  check(total);
  puts("PASS RISC-V spill reservation statistics across partial shutdown and retry");
}

// Only the thread opening the synthetic Ztso image overrides the two topology inputs.
// IFUNC resolvers still get the real hwprobe results for their ordinary feature queries.
struct ZtsoTopology {
  unsigned matching_cpus;
  char possible[5] = "0-3\n";
  bool probed = false;
  bool read_possible = false;
};
static thread_local ZtsoTopology* ztso_topology;

extern "C" int __real___riscv_hwprobe(riscv_hwprobe*, size_t, size_t, cpu_set_t*, unsigned);
extern "C" int __wrap___riscv_hwprobe(riscv_hwprobe* pairs, size_t count, size_t bytes,
                                      cpu_set_t* cpus, unsigned flags) {
  if (!ztso_topology || flags != RISCV_HWPROBE_WHICH_CPUS)
    return __real___riscv_hwprobe(pairs, count, bytes, cpus, flags);
  assert(count == 1 && pairs[0].key == RISCV_HWPROBE_KEY_IMA_EXT_0 &&
         pairs[0].value == RISCV_HWPROBE_EXT_ZTSO && bytes == sizeof(*cpus) && cpus &&
         CPU_COUNT(cpus) == 0);
  for (unsigned cpu = 0; cpu < ztso_topology->matching_cpus; ++cpu) CPU_SET(cpu, cpus);
  ztso_topology->probed = true;
  return 0;
}

extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
  if (!ztso_topology || strcmp(path, "/sys/devices/system/cpu/possible") != 0)
    return __real_fopen(path, mode);
  ztso_topology->read_possible = true;
  return fmemopen(ztso_topology->possible, sizeof(ztso_topology->possible) - 1, "r");
}

inline void exercise_riscv64_tls(yukilinker::Runtime& runtime, const char* directory) {
  const auto hwcap = getauxval(AT_HWCAP);
  // Check the relocated slots before a named IFUNC lookup can rerun the resolver.
  const auto check_slots = [hwcap](const RiscvIfunc* slots) {
    assert(slots);
    assert(slots[0] && slots[0]() == hwcap);
    assert(slots[1] && slots[1]() == hwcap);
  };
  const auto open_fixture = [&](const char* name) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", directory, name);
    void* system = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    assert(system);
    check_slots(static_cast<const RiscvIfunc*>(dlsym(system, "module_riscv_slots")));
    assert(dlclose(system) == 0);

    auto module = runtime.open_path(path);
    assert(module);
    const auto slots = module.value.symbol<const RiscvIfunc*>("module_riscv_slots");
    assert(slots);
    check_slots(slots.value);
    return module;
  };

  auto desc = open_fixture("liblinker_lifecycle.so");
  auto ifunc = desc.value.symbol<RiscvIfunc>("module_riscv_ifunc");
  assert(ifunc && ifunc.value && ifunc.value() == hwcap);
  auto weak_tls = desc.value.symbol<int* (*)()>("module_riscv_weak_tls_addr");
  assert(weak_tls && weak_tls.value() == nullptr);
  auto slot_fn = desc.value.symbol<int* (*)()>("module_slot");
  auto clobber_fn = desc.value.symbol<int (*)(const int32_t*, size_t, double, double)>(
      "module_riscv_tls_clobber_check");
  auto vstart_fn = desc.value.symbol<int (*)()>("module_riscv_tls_vstart_check");
  assert(slot_fn && clobber_fn && vstart_fn);
  size_t vlenb;
  asm("csrr %0, vlenb" : "=r"(vlenb));
  if (vlenb <= YUKI_RVV_INLINE_VLENB)
    printf("SKIP RISC-V wide spill suites (vlenb=%zu <= %u)\n", vlenb, YUKI_RVV_INLINE_VLENB);
  exercise_riscv_spill_contention(runtime, slot_fn.value);
  exercise_riscv_spill_edges(desc.value, slot_fn.value);
  exercise_riscv_spill_exit(runtime, slot_fn.value);
  exercise_riscv_nested_spill(runtime, directory, slot_fn.value);
  exercise_riscv_spill_reuse(slot_fn.value);
  pthread_attr_t attributes;
  assert(pthread_attr_init(&attributes) == 0);
  assert(pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN) == 0);
  run_on_worker(
      [&] {
        static constexpr int32_t vec[8] = {1, 2, 3, 4, 10, 20, 30, 40};
        assert(vstart_fn.value() == 42);
        assert(clobber_fn.value(vec, 4, 1.25, 2.75) == 156);
        int* slot = slot_fn.value();
        assert(slot && *slot == 42);
        *slot = 88;
        assert(vstart_fn.value() == 88);
        assert(clobber_fn.value(vec, 4, 1.25, 2.75) == 202);
        auto sym = desc.value.symbol<int*>("module_value");
        assert(sym && sym.value == slot && *sym.value == 88);
      },
      &attributes);
  assert(pthread_attr_destroy(&attributes) == 0);
  assert(desc.value.close().private_mapping_unmapped());

  auto trad = open_fixture("liblinker_lifecycle_trad.so");
  auto trad_slot = trad.value.symbol<int* (*)()>("module_slot");
  auto trad_weak = trad.value.symbol<int* (*)()>("module_riscv_weak_tls_addr");
  assert(trad_slot && trad_weak && trad_weak.value() == nullptr);
  run_on_worker([&] {
    int* slot = trad_slot.value();
    assert(slot && *slot == 42);
    *slot = 91;
    auto sym = trad.value.symbol<int*>("module_value");
    assert(sym && sym.value == slot && *sym.value == 91);
  });
  assert(trad.value.close().private_mapping_unmapped());
}

inline void exercise_arch_relocations(yukilinker::Runtime& runtime, const char* directory) {
  exercise_riscv64_tls(runtime, directory);

  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle_trad.so", directory);
  const int source = open(path, O_RDONLY | O_CLOEXEC);
  struct stat status{};
  assert(source >= 0 && fstat(source, &status) == 0 && status.st_size > 0);
  const size_t bytes = status.st_size;
  auto* data =
      static_cast<uint8_t*>(mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, source, 0));
  assert(data != MAP_FAILED && close(source) == 0);

  auto* header = reinterpret_cast<Elf64_Ehdr*>(data);
  const auto* sections = reinterpret_cast<Elf64_Shdr*>(data + header->e_shoff);
  auto* programs = reinterpret_cast<Elf64_Phdr*>(data + header->e_phoff);
  Elf64_Addr slots = 0, resolver = 0, tls_value = 0;
  size_t tls_symbol = STN_UNDEF, weak_tls_symbol = STN_UNDEF;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    const auto& section = sections[i];
    if (section.sh_type != SHT_DYNSYM) continue;
    const auto* symbols = reinterpret_cast<const Elf64_Sym*>(data + section.sh_offset);
    const char* names = reinterpret_cast<char*>(data + sections[section.sh_link].sh_offset);
    for (size_t j = 0; j < section.sh_size / sizeof(*symbols); ++j) {
      if (strcmp(names + symbols[j].st_name, "module_riscv_slots") == 0)
        slots = symbols[j].st_value;
      if (strcmp(names + symbols[j].st_name, "module_riscv_resolver") == 0)
        resolver = symbols[j].st_value;
      if (strcmp(names + symbols[j].st_name, "module_value") == 0) {
        assert(ELF64_ST_TYPE(symbols[j].st_info) == STT_TLS && symbols[j].st_shndx != SHN_UNDEF);
        tls_symbol = j;
        tls_value = symbols[j].st_value;
      }
      if (strcmp(names + symbols[j].st_name, "module_riscv_weak_tls") == 0) {
        assert(ELF64_ST_TYPE(symbols[j].st_info) == STT_TLS &&
               ELF64_ST_BIND(symbols[j].st_info) == STB_WEAK && symbols[j].st_shndx == SHN_UNDEF);
        weak_tls_symbol = j;
      }
    }
  }
  assert(slots && resolver && tls_symbol != STN_UNDEF && weak_tls_symbol != STN_UNDEF);

  constexpr size_t word = sizeof(Elf64_Addr);
  Elf64_Rela* reloc0 = nullptr;
  Elf64_Rela* reloc1 = nullptr;
  const Elf64_Rela* dtprel = nullptr;
  const Elf64_Rela* weak_dtprel = nullptr;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    if (sections[i].sh_type != SHT_RELA) continue;
    auto* entries = reinterpret_cast<Elf64_Rela*>(data + sections[i].sh_offset);
    for (size_t j = 0; j < sections[i].sh_size / sizeof(Elf64_Rela); ++j) {
      auto& r = entries[j];
      if (r.r_offset == slots) reloc0 = &r;
      if (r.r_offset == slots + word) reloc1 = &r;
      if (ELF64_R_TYPE(r.r_info) == R_RISCV_TLS_DTPREL64) {
        if (ELF64_R_SYM(r.r_info) == tls_symbol) dtprel = &r;
        if (ELF64_R_SYM(r.r_info) == weak_tls_symbol) weak_dtprel = &r;
      }
    }
  }
  assert(reloc0 && reloc1 && dtprel && weak_dtprel);

  const auto open_copy = [&](const char* tag) {
    const int fd = fixture_fd(directory, tag);
    assert(fd >= 0 && write(fd, data, bytes) == static_cast<ssize_t>(bytes));
    auto result = runtime.open_fd(fd);
    assert(close(fd) == 0);
    return result;
  };

  const auto check_unsupported_flags = [](const auto& result) {
    const auto& error = result.error.native.detail;
    assert(!result && error.code == YUKILINKER_C_UNSUPPORTED &&
           error.stage == YUKILINKER_C_METADATA && error.machine == EM_RISCV &&
           !error.execution_started);
  };
  const auto flags = header->e_flags;
  assert((flags & EF_RISCV_FLOAT_ABI_MASK) == EF_RISCV_FLOAT_ABI_DOUBLE);
  for (const auto abi :
       {EF_RISCV_FLOAT_ABI_SOFT, EF_RISCV_FLOAT_ABI_SINGLE, EF_RISCV_FLOAT_ABI_QUAD}) {
    header->e_flags = (flags & ~EF_RISCV_FLOAT_ABI_MASK) | abi;
    check_unsupported_flags(open_copy("riscv64-float-abi"));
  }
  header->e_flags = flags | EF_RISCV_RVE;
  check_unsupported_flags(open_copy("riscv64-rve"));
  header->e_flags = flags | 0x20;  // EF_RISCV_RV64ILP32
  check_unsupported_flags(open_copy("riscv64-ilp32"));
  header->e_flags = flags | 0x40;  // EF_RISCV_RVY (pure-capability ABI)
  check_unsupported_flags(open_copy("riscv64-rvy"));
  header->e_flags = flags | EF_RISCV_TSO;
  for (unsigned matching : {4u, 3u}) {
    ZtsoTopology topology{matching};
    ztso_topology = &topology;
    auto tso = open_copy("riscv64-tso");
    ztso_topology = nullptr;
    assert(topology.probed && topology.read_possible);
    if (matching == 4)
      assert(tso && tso.value.close().private_mapping_unmapped());
    else
      check_unsupported_flags(tso);
  }
  header->e_flags = flags;

  const Elf64_Rela saved0 = *reloc0;
  const Elf64_Rela saved1 = *reloc1;

  reloc0->r_info = ELF64_R_INFO(0, R_RISCV_IRELATIVE);
  reloc0->r_addend = static_cast<Elf64_Sxword>(resolver);
  // The second slot uses the same resolver and would overwrite the HWCAP recorded by IRELATIVE.
  reloc1->r_info = ELF64_R_INFO(0, R_RISCV_NONE);
  auto irel = open_copy("riscv64-irelative");
  assert(irel);
  auto image = irel.value.image();
  assert(image);
  RiscvIfunc resolved_slot;
  memcpy(&resolved_slot, reinterpret_cast<const void*>(image.value.load_bias + slots),
         sizeof(resolved_slot));
  assert(resolved_slot && resolved_slot() == getauxval(AT_HWCAP));
  auto fn = irel.value.symbol<RiscvIfunc>("module_riscv_ifunc");
  assert(fn && resolved_slot == fn.value);
  // Inspect both GD slots directly. A zero module ID bypasses the weak slot in __tls_get_addr.
  const auto check_dtprel = [&](const Elf64_Rela& rel, Elf64_Addr symbol_value) {
    Elf64_Addr stored_offset;
    memcpy(&stored_offset, reinterpret_cast<const void*>(image.value.load_bias + rel.r_offset),
           sizeof(stored_offset));
    assert(stored_offset == symbol_value + rel.r_addend - 0x800);
  };
  check_dtprel(*dtprel, tls_value);
  check_dtprel(*weak_dtprel, 0);
  assert(irel.value.close().private_mapping_unmapped());

  *reloc0 = saved0;
  reloc1->r_info = ELF64_R_INFO(ELF64_R_SYM(saved1.r_info), R_RISCV_32);
  auto bad_reloc = open_copy("riscv64-bad-reloc");
  assert(!bad_reloc && bad_reloc.error.native.detail.code == YUKILINKER_C_UNSUPPORTED &&
         bad_reloc.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
         bad_reloc.error.native.detail.machine == EM_RISCV &&
         bad_reloc.error.native.detail.relocation_type == R_RISCV_32 &&
         bad_reloc.error.native.detail.offset == slots + word &&
         !bad_reloc.error.native.detail.execution_started);

  *reloc1 = saved1;
  bool patched_note = false;
  for (unsigned i = 0; i < header->e_phnum; ++i) {
    auto& ph = programs[i];
    if (ph.p_type != PT_NOTE || ph.p_filesz < 40) continue;
    const size_t bump = (8 - (ph.p_offset % 8)) % 8;
    if (ph.p_filesz - bump < 32) continue;
    ph.p_type = 0x6474e553;  // PT_GNU_PROPERTY
    ph.p_flags = PF_R;
    ph.p_offset += bump;
    ph.p_vaddr += bump;
    ph.p_paddr = ph.p_vaddr;
    ph.p_filesz = 32;
    ph.p_memsz = 32;
    ph.p_align = 8;
    uint32_t note[8] = {4, 16, 5, 0, 0xc0000000U, 4, 1, 0};
    memcpy(&note[3], "GNU", 4);
    memcpy(data + ph.p_offset, note, sizeof(note));
    patched_note = true;
    break;
  }
  assert(patched_note);
  auto bad_prop = open_copy("riscv64-bad-prop");
  assert(!bad_prop && bad_prop.error.native.detail.code == YUKILINKER_C_UNSUPPORTED &&
         bad_prop.error.native.detail.stage == YUKILINKER_C_PROTECTION &&
         bad_prop.error.native.detail.machine == EM_RISCV &&
         !bad_prop.error.native.detail.execution_started);

  assert(munmap(data, bytes) == 0);
  puts(
      "PASS riscv64 TLSDESC, trad TLS, RVV/FP preservation, hwprobe IFUNC, IRELATIVE and GNU "
      "property");
}

#endif
