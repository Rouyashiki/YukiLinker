// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "config.hpp"

namespace yukilinker::internal {

struct ImageState;

struct TlsReference {
  uintptr_t module_id = 0;
  uintptr_t byte_offset = 0;
  uintptr_t generation = 0;
  bool unresolved_weak = false;
};

struct TlsIndex {
  unsigned long module = 0;
  unsigned long offset = 0;
};

struct TlsTemplate {
  uintptr_t module_id = 0;
  uintptr_t generation = 0;
  const void* initial_bytes = nullptr;
  size_t file_bytes = 0;
  size_t memory_bytes = 0;
  size_t alignment = 1;
  bool active = false;
  ImageState* image = nullptr;
  TlsTemplate* next = nullptr;
};

// Only the full runtime defines this, but the reduced loader declares its accessors too.
struct ThreadTlsState;

#if YUKILINKER_FULL
// Clang's emulated TLS ABI is four target words. Compiler-rt owns the third word when its own
// accessor is bound. The Core keeps its keys outside the mapped control, including after reload.
struct EmutlsControl {
  uintptr_t size;
  uintptr_t alignment;
  uintptr_t index;
  const void* initial;
};
static_assert(sizeof(EmutlsControl) == 4 * sizeof(void*));
void* bound_emutls_accessor(const ImageState* image);
bool validate_emutls_controls(ImageState* image);

struct EmutlsBlock {
  const EmutlsControl* control = nullptr;
  ImageState* owner = nullptr;
  uint64_t generation = 0;
  void* storage = nullptr;
  EmutlsBlock* next = nullptr;
};

// An interrupted warm lookup can still be reading a previous table after a signal handler
// grows it. Keep all tables and blocks until thread exit. A forced detach clears the block's
// generation before releasing the image; readers never follow its owner.
struct EmutlsTable {
  size_t capacity;
  size_t used;
  EmutlsTable* retired;
  EmutlsBlock* blocks;
  EmutlsBlock** slots() { return reinterpret_cast<EmutlsBlock**>(this + 1); }
};

extern "C" void* yuki_emutls_get_address(const EmutlsControl* control);
constexpr char kEmutlsAccessor[] = "__emutls_get_address";

struct TlsDescriptorIndex {
  uintptr_t module;
  uintptr_t offset;
  uintptr_t generation;
};
// Only its own thread writes generation, storage and memory_bytes, with signals blocked; the
// lock-free path reads them with __atomic builtins, generation first. Other threads write only
// owner (detach), which that path never reads.
struct ThreadTlsBlock {
  uintptr_t generation = 0;
  void* storage = nullptr;
  // The template's size when the storage was made; the lock-free path bounds offsets with it.
  size_t memory_bytes = 0;
  ThreadTlsBlock* next = nullptr;
  uintptr_t module_id = 0;
  ImageState* owner = nullptr;
};
// A thread's blocks by module id, followed by `capacity` slots. Only its own thread reads it
// without a lock. A larger table replaces it and keeps it as `retired` until the state is freed:
// a handler may grow the table under a lookup it interrupted, which still reads the old one.
struct ThreadBlockTable {
  size_t capacity;
  ThreadBlockTable* retired;
  ThreadTlsBlock** slots() { return reinterpret_cast<ThreadTlsBlock**>(this + 1); }
};
struct ThreadExitRecord;
struct ThreadTlsState {
  pid_t tid = 0;
  uintptr_t identity = 0;
  ThreadBlockTable* blocks = nullptr;
  ThreadTlsBlock* first = nullptr;
  EmutlsTable* emutls = nullptr;
  bool emutls_deferred = false;
  ThreadExitRecord* destructors = nullptr;
  ThreadTlsState* next = nullptr;
};
struct ThreadExitRecord {
  void (*function)(void*);
  void* argument;
  ImageState* owner;
  ThreadTlsState* thread;
  ThreadExitRecord* next;
};
// Generations by module id, in chunks that never move once published, so the lock-free path can
// read them while a load adds one. Slot 0 is never used. Together the chunks stay within the same
// 4 MiB accounting limit, and the largest module id is unchanged.
constexpr size_t kTlsGenerationChunkSlots = 1024;
constexpr size_t kTlsModuleMemoryLimit = size_t{4} * 1024 * 1024;
constexpr size_t kTlsGenerationChunks =
    kTlsModuleMemoryLimit / (kTlsGenerationChunkSlots * sizeof(uintptr_t));
constexpr size_t kTlsModuleIdLimit = kTlsGenerationChunks * kTlsGenerationChunkSlots;
extern ThreadTlsState* g_thread_states;
extern TlsTemplate* g_tls_templates;
extern uintptr_t* g_tls_generation_chunks[kTlsGenerationChunks];
// Chunks published so far; written under g_tls_mutex.
extern size_t g_tls_generation_chunk_count;
extern uintptr_t g_next_tls_generation;
// Every holder also holds the operation lock and blocks signals, so it is never contended, no
// signal handler on the holder's thread finds it held, and it is free whenever a fork happens.
extern pthread_mutex_t g_tls_mutex;
extern pthread_key_t g_thread_tls_key;
extern bool g_thread_tls_key_valid;
extern bool g_tls_stopped;

// Blocks, for a TLS critical section, every signal a caller may block except the synchronous
// faults: a handler on this thread then runs only after the scope, so it never finds g_tls_mutex
// held or this thread's TLS state half changed. Leave Bionic's reserved signals alone.
// Faults stay deliverable because the kernel would force a blocked one to
// its default action, past every handler.
struct ScopedSignalBlocker {
  explicit ScopedSignalBlocker(bool enable = true) {
    if (enable) block();
  }
  void block() {
    if (active) return;
    // The kernel numbers signals from one. The first application RT signal is a
    // property of the running Bionic, which reserves some of the low RT signals.
    constexpr uint64_t ordinary = (uint64_t{1} << (__SIGRTMIN - 1)) - 1;
    const int rt_min = SIGRTMIN;
    const int rt_max = SIGRTMAX;
    const uint64_t realtime =
        rt_min >= 1 && rt_max <= 64 && rt_min <= rt_max
            ? (UINT64_MAX << (rt_min - 1)) & (UINT64_MAX >> (64 - rt_max))
            : 0;
    uint64_t bits = ordinary | realtime;
    constexpr int faults[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGSYS};
    for (int fault : faults) bits &= ~(uint64_t{1} << (fault - 1));
    sigset64_t set;
    static_assert(sizeof(set) == sizeof(bits));
    memcpy(&set, &bits, sizeof(set));
    change_mask(SIG_BLOCK, &set, &old);
    active = true;
  }
  void restore() {
    if (!active) return;
    change_mask(SIG_SETMASK, &old, nullptr);
    active = false;
  }
  ~ScopedSignalBlocker() { restore(); }
  ScopedSignalBlocker(const ScopedSignalBlocker&) = delete;
  ScopedSignalBlocker& operator=(const ScopedSignalBlocker&) = delete;
  ScopedSignalBlocker(ScopedSignalBlocker&&) = delete;
  ScopedSignalBlocker& operator=(ScopedSignalBlocker&&) = delete;

 private:
  bool active = false;
  sigset64_t old;
  static void change_mask(int how, const sigset64_t* set, sigset64_t* previous) {
    // The kernel accepts the full mask on both pointer widths. Oreo's 32-bit
    // pthread_sigmask truncates it, and newer libc wrappers can change the
    // reserved timer bit on restore. Restore exactly what this thread had.
    if (syscall(SYS_rt_sigprocmask, how, set, previous, sizeof(*set)) != 0) abort();
  }
};
#endif

bool activate_tls(ImageState* image);
void deactivate_tls(ImageState* image);
// Drops every thread's block for this image's slot, so nothing names it after it is freed.
// Callers hold the operation lock and must have deactivated the template first.
void detach_image_tls_blocks(ImageState* image);
// Frees a thread's TLS state, its records and its blocks without collecting (shutdown, the fork
// child, an empty state's release).
void destroy_thread_tls_state(void* opaque);
// Sets *created when this call made the state; only that call may free it again.
ThreadTlsState* thread_tls_state(bool* created = nullptr);
// Frees the calling thread's state while it holds no TLS block and no thread-destructor record, so
// its exit runs no runtime code for it. The caller holds the operation lock and passes a state its
// own call created, or shutdown's own.
void release_empty_thread_tls_state(ThreadTlsState* state);
void* current_thread_tls_data(uintptr_t module_id, uintptr_t generation);
extern "C" void* yuki_tls_get_addr(TlsIndex* index);
#if defined(__i386__)
// The i386 general-dynamic PLT call passes its TLS index in EAX.
extern "C" __attribute__((regparm(1))) void* yuki_tls_get_addr_i386(TlsIndex* index);
#endif
bool discover_tls_segment(ImageState* image);

#if defined(__aarch64__)
extern "C" uintptr_t yuki_tlsdesc_dynamic_entry(uintptr_t* descriptor);
extern "C" uintptr_t yuki_tlsdesc_weak_entry(uintptr_t* descriptor);
#endif

}  // namespace yukilinker::internal
