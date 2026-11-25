// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../internal/elf_arch.hpp"
#include "../internal/enumeration.hpp"
#if YUKILINKER_FULL
#include "../internal/private_pthread_keys.hpp"
#endif
#include "../internal/runtime_model.hpp"
#if YUKILINKER_FULL && defined(__riscv) && __riscv_xlen == 64
#include <linux/futex.h>
#include <linux/pidfd.h>
#include <poll.h>
#include <sys/pidfd.h>

#include <iterator>

#include "../arch/riscv64/tlsdesc_layout.h"
#endif

namespace yukilinker::internal {

#if YUKILINKER_FULL
// This libc ABI is available throughout the supported API range. Bind it with the Core
// so registering a destructor never needs a symbol lookup from an atfork handler.
extern "C" int __cxa_thread_atexit_impl(void (*)(void*), void*, void*);
namespace {
#if defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
uintptr_t current_thread_pointer() {
  return reinterpret_cast<uintptr_t>(__builtin_thread_pointer());
}
#endif

#if defined(__riscv) && __riscv_xlen == 64
bool reserve_thread_spill(ThreadTlsState* thread, size_t file_bytes = 0);
#endif

// Under the mask, or by the owning thread's lock-free path.
ThreadTlsBlock* table_block(ThreadBlockTable* table, uintptr_t module_id) {
  return table != nullptr && module_id < table->capacity
             ? __atomic_load_n(&table->slots()[module_id], __ATOMIC_RELAXED)
             : nullptr;
}

// Under g_tls_mutex, for an id below generation_slots().
uintptr_t* generation_slot(uintptr_t module_id) {
  return g_tls_generation_chunks[module_id / kTlsGenerationChunkSlots] +
         module_id % kTlsGenerationChunkSlots;
}
size_t generation_slots() { return g_tls_generation_chunk_count * kTlsGenerationChunkSlots; }

// Under g_tls_mutex. A published chunk stays where it is until shutdown.
bool add_generation_chunk() {
  if (g_tls_generation_chunk_count == kTlsGenerationChunks) return false;
  auto* chunk = static_cast<uintptr_t*>(calloc(kTlsGenerationChunkSlots, sizeof(uintptr_t)));
  if (chunk == nullptr) return false;
  __atomic_store_n(&g_tls_generation_chunks[g_tls_generation_chunk_count], chunk, __ATOMIC_RELEASE);
  ++g_tls_generation_chunk_count;
  return true;
}

// A state's current table and every table it replaced; every path that frees a state uses it.
void free_block_tables(ThreadTlsState* state) {
  for (ThreadBlockTable* table = state->blocks; table != nullptr;) {
    ThreadBlockTable* retired = table->retired;
    free(table);
    table = retired;
  }
  state->blocks = nullptr;
}

// This thread's address for (module_id, offset) when it already has the module's current block,
// found without a lock, an allocation or a runtime call, so a signal handler may use it whatever
// it interrupted. The thread's own block is found before the shared generations are read: a
// thread with a block has a state, and shutdown frees the chunks only once no thread has one.
// `matched` receives the generation the block was checked against. Null: take the slow path.
void* own_block_address(uintptr_t module_id, uintptr_t offset, uintptr_t* matched) {
  if (module_id == 0 || module_id >= kTlsModuleIdLimit) return nullptr;
  if (!__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE)) return nullptr;
  auto* thread = static_cast<ThreadTlsState*>(pthread_getspecific(g_thread_tls_key));
  if (thread == nullptr) return nullptr;
  // A handler on this thread may publish a table or a block between these loads; the signal
  // fences order the loads against it and emit no instruction.
  ThreadBlockTable* table = __atomic_load_n(&thread->blocks, __ATOMIC_RELAXED);
  __atomic_signal_fence(__ATOMIC_ACQUIRE);
  ThreadTlsBlock* block = table_block(table, module_id);
  __atomic_signal_fence(__ATOMIC_ACQUIRE);
  if (block == nullptr) return nullptr;
  const uintptr_t* chunk = __atomic_load_n(
      &g_tls_generation_chunks[module_id / kTlsGenerationChunkSlots], __ATOMIC_ACQUIRE);
  if (chunk == nullptr) return nullptr;
  const uintptr_t generation =
      __atomic_load_n(&chunk[module_id % kTlsGenerationChunkSlots], __ATOMIC_RELAXED);
  if (generation == 0 || __atomic_load_n(&block->generation, __ATOMIC_RELAXED) != generation)
    return nullptr;
  // Size and storage only after the generation matched: a handler that replaces a stale block's
  // storage frees the old one, and a lookup that read the old generation never uses it.
  __atomic_signal_fence(__ATOMIC_ACQUIRE);
  if (offset >= __atomic_load_n(&block->memory_bytes, __ATOMIC_RELAXED)) return nullptr;
  if (matched != nullptr) *matched = generation;
  return static_cast<uint8_t*>(__atomic_load_n(&block->storage, __ATOMIC_RELAXED)) + offset;
}

// Whether an image whose thread pin just went may be left for collection: no open, pin or
// callback names it, and its load root is not open either (an open root marks its whole group).
bool unpinned_image(const ImageState* image) {
  return !image->references && !image_is_pinned(image) && !image->load_root->references;
}

// Collects what a dropped thread pin left, as Bionic unloads a library on the exiting thread once
// its last thread_local destructor has run. Only outside every operation and callback of this
// thread: a frame below would hold pointers into the images, or another thread's state.
void collect_unpinned() {
  if (!g_operation_depth_valid || operation_depth() != 1 || callback_frame_open() || g_tls_stopped)
    return;
  (void)collect_images();
}

// With signals blocked. A callback can register another destructor before returning,
// so the completed record need not still be at the head.
void release_registered_destructor(ThreadExitRecord* record) {
  auto** link = &record->thread->destructors;
  while (*link != record) link = &(*link)->next;
  *link = record->next;
  --record->owner->thread_destructors;
  free_object(record);
}

#if defined(__riscv) && __riscv_xlen == 64
void release_thread_spill_tag(ThreadTlsState* state) {
  if (state->spill_tag) {
    __atomic_store_n(state->spill_tag, uintptr_t{0}, __ATOMIC_RELEASE);
    state->spill_tag = nullptr;
  }
}
#endif

bool release_native_thread_storage(ThreadTlsState* state) {
#if defined(__riscv) && __riscv_xlen == 64
  release_thread_spill_tag(state);
#endif
  bool unpinned = false;
  ThreadTlsBlock* block = state->first;
  while (block != nullptr) {
    ThreadTlsBlock* next = block->next;
    ImageState* owner = block->owner;
    if (owner && owner->tls_users) {
      --owner->tls_users;
      unpinned |= unpinned_image(owner);
    }
    free(block->storage);
    free_object(block);
    block = next;
  }
  state->first = nullptr;
  free_block_tables(state);
  return unpinned;
}

// Called under the operation lock with signals blocked, including when discarding a vanished
// thread after fork. No key or destructor of the vanished thread is invoked.
bool release_thread_tls_state(ThreadTlsState* state) {
  if (state == nullptr) return false;
  bool unpinned = release_native_thread_storage(state);
  // A live thread releases each record after its Bionic callback returns. An exited thread
  // or one lost at fork can leave pending records, including a callback interrupted by fork.
  while (auto* record = state->destructors) {
    auto* owner = record->owner;
    release_registered_destructor(record);
    unpinned |= unpinned_image(owner);
  }
  if (auto* table = state->emutls) {
    while (auto* block = table->blocks) {
      table->blocks = block->next;
      if (block->owner) {
        --block->owner->tls_users;
        unpinned |= unpinned_image(block->owner);
      }
      free(block->storage);
      free_object(block);
    }
    while (table) {
      auto* retired = table->retired;
      free(table);
      table = retired;
    }
  }
  auto** link = &g_thread_states;
  while (*link && *link != state) link = &(*link)->next;
  if (*link) *link = state->next;
  free_object(state);
  return unpinned;
}

// Collections one thread exit runs at most. Each one that leaves a fresh state behind ran a
// finalizer, and a finalizer may load a new library each time, so nothing else bounds them.
constexpr size_t kThreadExitCollections = 64;

// The TLS key's destructor. Bionic runs it in pthread_key_clean_all, after the thread's
// thread_local destructors, with the key cleared. A finalizer that a collection runs here and
// that touches TLS makes a fresh state. Pending C++ or managed key callbacks keep their storage.
// Otherwise drain native blocks and give new emutls blocks one turn of Bionic's other destructors.
// A state left after the last round can be reaped once the thread exits.
void thread_tls_key_destructor(void* opaque) {
  OperationGuard operation;
  auto* state = static_cast<ThreadTlsState*>(opaque);
  for (size_t collections = 0;; ++collections) {
    bool unpinned;
    bool deferred;
    {
      // Bionic frees a thread's TLS with signals blocked; the lock is waited for with the
      // thread's own mask, as every operation waits.
      ScopedSignalBlocker signals;
      if (!__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE)) return;
      auto* armed = static_cast<ThreadTlsState*>(pthread_getspecific(g_thread_tls_key));
      if (collections != 0) state = armed;
      if (state == nullptr) return;
      // Late C++ cleanup can run from exit(). A managed key destructor can also pass existing
      // TLS to a key due in a later round, without allocating a block or extending its grace.
      const bool callbacks = state->destructors || current_thread_has_private_key_callbacks();
      deferred = callbacks || (state->emutls && !state->emutls_deferred);
      if (deferred) {
        // A finalizer's fresh state is already armed. For the state Bionic passed in, restore
        // its key if possible. Even if that fails, its storage stays live until thread exit.
        if (!armed) (void)pthread_setspecific(g_thread_tls_key, state);
        if (callbacks) return;
        state->emutls_deferred = true;
        unpinned = release_native_thread_storage(state);
      } else {
        if (armed == state && pthread_setspecific(g_thread_tls_key, nullptr) != 0) return;
        unpinned = release_thread_tls_state(state);
      }
    }
    if (!unpinned) return;
    if (collections == kThreadExitCollections) {
      // Any image just unpinned waits for the next collection, on any thread.
      host_log_error("yukilinker: thread exit left images for a later collection");
      return;
    }
    // Finalizers run with the thread's own signal mask and may create a fresh state.
    collect_unpinned();
    if (deferred) return;
  }
}

}  // namespace

// Shutdown, fork recovery, exited-thread reaping and an empty state's release free it here.
void destroy_thread_tls_state(void* opaque) {
  auto* state = static_cast<ThreadTlsState*>(opaque);
  if (state == nullptr) return;
  OperationGuard operation;
  ScopedSignalBlocker signals;
  (void)release_thread_tls_state(state);
}

bool ensure_thread_tls_key() {
  if (__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE)) return true;
  pthread_mutex_lock(&g_key_mutex);
  if (!g_thread_tls_key_valid && !g_keys_retired) {
    const int error = pthread_key_create(&g_thread_tls_key, thread_tls_key_destructor);
    if (error != 0) {
      errno = error;
    } else if (ensure_thread_identity_key()) {
      __atomic_store_n(&g_thread_tls_key_valid, true, __ATOMIC_RELEASE);
    } else {
      pthread_key_delete(g_thread_tls_key);
    }
  }
  const bool valid = g_thread_tls_key_valid;
  pthread_mutex_unlock(&g_key_mutex);
  return valid;
}

ThreadTlsState* thread_tls_state(bool* created) {
  if (created != nullptr) *created = false;
  if (g_tls_stopped) return nullptr;
  if (!ensure_thread_tls_key()) return nullptr;
  auto* state = static_cast<ThreadTlsState*>(pthread_getspecific(g_thread_tls_key));
  if (state != nullptr) return state;
  // A handler on this thread must not make a second state between setspecific and the link.
  ScopedSignalBlocker signals;
  state = static_cast<ThreadTlsState*>(pthread_getspecific(g_thread_tls_key));
  if (state != nullptr) return state;
  // Bionic clears a key before calling its destructor. A signal in that interval must still
  // see this thread's original blocks. The upcoming destructor owns the state until it releases
  // it or rearms the key. Its identity key has no destructor and remains readable in that gap.
  uintptr_t identity = current_thread_identity(false);
  if (identity) {
    for (state = g_thread_states; state; state = state->next)
      if (state->identity == identity) return state;
  } else {
    identity = current_thread_identity(true);
    if (!identity) return nullptr;
  }
  state = allocate_object<ThreadTlsState>();
  if (state == nullptr) return nullptr;
  state->tid = gettid();
  state->identity = identity;
#if defined(__riscv) && __riscv_xlen == 64
  state->thread_pointer = current_thread_pointer();
#endif
  if (pthread_setspecific(g_thread_tls_key, state) != 0) {
    free_object(state);
    return nullptr;
  }
  state->next = g_thread_states;
  g_thread_states = state;
  if (created != nullptr) *created = true;
  return state;
}

void release_empty_thread_tls_state(ThreadTlsState* state) {
  // A handler on this thread must not add a block between the test and the free.
  ScopedSignalBlocker signals;
  if (state == nullptr || state->first != nullptr || state->emutls ||
      state->destructors != nullptr ||
      !__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE) ||
      pthread_getspecific(g_thread_tls_key) != state)
    return;
  (void)pthread_setspecific(g_thread_tls_key, nullptr);
  destroy_thread_tls_state(state);
}

TlsTemplate* find_tls_template(uintptr_t module_id) {
  for (TlsTemplate* candidate = g_tls_templates; candidate != nullptr; candidate = candidate->next)
    if (candidate->active && candidate->module_id == module_id) return candidate;
  return nullptr;
}

ThreadTlsBlock* find_thread_block(ThreadTlsState* thread, uintptr_t module_id) {
  return table_block(thread->blocks, module_id);
}

// Under g_tls_mutex with signals blocked. See ThreadBlockTable for why the old table stays.
bool ensure_thread_block_capacity(ThreadTlsState* thread, uintptr_t module_id) {
  ThreadBlockTable* current = thread->blocks;
  const size_t old_capacity = current != nullptr ? current->capacity : 0;
  if (module_id < old_capacity) return true;
  if (module_id == UINTPTR_MAX) return false;

  size_t required = static_cast<size_t>(module_id + 1);
  size_t capacity = old_capacity == 0 ? 8 : old_capacity;
  while (capacity < required) {
    if (capacity > SIZE_MAX / 2) {
      capacity = required;
      break;
    }
    capacity *= 2;
  }

  size_t bytes;
  if (multiply_overflow(capacity, sizeof(ThreadTlsBlock*), &bytes) ||
      add_overflow(bytes, sizeof(ThreadBlockTable), &bytes))
    return false;
  auto* table = static_cast<ThreadBlockTable*>(calloc(1, bytes));
  if (table == nullptr) return false;
  table->capacity = capacity;
  table->retired = current;
  ThreadTlsBlock** slots = table->slots();
  for (size_t i = 0; i < old_capacity; ++i) slots[i] = current->slots()[i];
  __atomic_store_n(&thread->blocks, table, __ATOMIC_RELEASE);
  return true;
}

void* allocate_thread_storage(const TlsTemplate& tls) {
  void* storage = nullptr;
  size_t alignment = tls.alignment < sizeof(void*) ? sizeof(void*) : tls.alignment;
  if (posix_memalign(&storage, alignment, tls.memory_bytes) != 0) return nullptr;
  memset(storage, 0, tls.memory_bytes);
  if (tls.file_bytes != 0) memcpy(storage, tls.initial_bytes, tls.file_bytes);
  return storage;
}

ThreadTlsBlock* create_thread_block(const TlsTemplate& tls) {
  auto* block = allocate_object<ThreadTlsBlock>();
  if (block == nullptr) return nullptr;
  block->storage = allocate_thread_storage(tls);
  if (block->storage == nullptr) {
    free_object(block);
    return nullptr;
  }
  block->generation = tls.generation;
  block->memory_bytes = tls.memory_bytes;
  block->module_id = tls.module_id;
  block->owner = tls.image;
  ++block->owner->tls_users;
  retain_tls_dependencies(block->owner);
  return block;
}

bool reset_thread_block(ThreadTlsBlock* block, const TlsTemplate& tls) {
  void* storage = allocate_thread_storage(tls);
  if (storage == nullptr) return false;
  if (block->owner && block->owner->tls_users) --block->owner->tls_users;
  block->owner = tls.image;
  ++block->owner->tls_users;
  retain_tls_dependencies(block->owner);
  // Only a stale block is reset, so a lookup this interrupts fails its generation compare and
  // never uses the old storage, which goes last.
  void* old_storage = block->storage;
  __atomic_store_n(&block->storage, storage, __ATOMIC_RELAXED);
  __atomic_store_n(&block->memory_bytes, tls.memory_bytes, __ATOMIC_RELAXED);
  __atomic_store_n(&block->generation, tls.generation, __ATOMIC_RELAXED);
  block->module_id = tls.module_id;
  free(old_storage);
  return true;
}

bool activate_tls(ImageState* image) {
  TlsTemplate& tls = image->tls;
  // An initial emutls access may run inside prepare_fork, while its thread holds g_key_mutex.
  if (image->managed_emutls && !ensure_thread_tls_key())
    return fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA);
  if (tls.memory_bytes == 0) return true;
  if (tls.file_bytes > tls.memory_bytes || !is_power_of_two(tls.alignment == 0 ? 1 : tls.alignment))
    return false;
  if (tls.alignment == 0) tls.alignment = 1;
  // The segment itself was checked above: what can fail from here on is the key or a generation
  // chunk, a resource and not the image.
  if (!ensure_thread_tls_key()) return fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA);

  ScopedSignalBlocker signals;
  pthread_mutex_lock(&g_tls_mutex);
  if (g_tls_stopped) {
    pthread_mutex_unlock(&g_tls_mutex);
    return false;
  }
  uintptr_t module_id = 1;
  while (module_id < generation_slots() &&
         __atomic_load_n(generation_slot(module_id), __ATOMIC_RELAXED) != 0)
    ++module_id;
  if (module_id >= generation_slots() && !add_generation_chunk()) {
    pthread_mutex_unlock(&g_tls_mutex);
    // The calloc's ENOMEM, or the module-id cap.
    errno = ENOMEM;
    return fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA);
  }
  uintptr_t generation = g_next_tls_generation++;
  if (generation == 0) generation = g_next_tls_generation++;
  tls.module_id = module_id;
  tls.generation = generation;
  tls.image = image;
  tls.active = true;
  tls.next = g_tls_templates;
  g_tls_templates = &tls;
  __atomic_store_n(generation_slot(module_id), generation, __ATOMIC_RELEASE);
  pthread_mutex_unlock(&g_tls_mutex);
  return true;
}

void deactivate_tls(ImageState* image) {
  if (image == nullptr || !image->tls.active) return;
  ScopedSignalBlocker signals;
  pthread_mutex_lock(&g_tls_mutex);
  TlsTemplate** link = &g_tls_templates;
  while (*link != nullptr && *link != &image->tls) link = &(*link)->next;
  if (*link == &image->tls) *link = image->tls.next;
  uintptr_t module_id = image->tls.module_id;
  if (module_id != 0 && module_id < generation_slots())
    __atomic_store_n(generation_slot(module_id), uintptr_t{0}, __ATOMIC_RELEASE);
  image->tls.active = false;
  image->tls.next = nullptr;
  image->tls.module_id = 0;
  image->tls.generation = 0;
  pthread_mutex_unlock(&g_tls_mutex);
}

// A failed image is freed without waiting for its users, so every block that names it is
// detached first: the block itself belongs to its thread and stays until that thread exits, but
// it must not keep a pointer to the image, and the slot can be handed to another image.
void detach_image_tls_blocks(ImageState* image) {
  if (image == nullptr) return;
  ScopedSignalBlocker signals;
  pthread_mutex_lock(&g_tls_mutex);
  for (ThreadTlsState* thread = g_thread_states; thread != nullptr; thread = thread->next) {
    if (auto* table = thread->emutls) {
      for (auto* block = table->blocks; block; block = block->next) {
        if (block->owner != image) continue;
        __atomic_store_n(&block->generation, uint64_t{0}, __ATOMIC_RELEASE);
        block->owner = nullptr;
        --image->tls_users;
      }
    }
    for (ThreadTlsBlock* block = thread->first; block != nullptr; block = block->next) {
      if (block->owner != image) continue;
      block->owner = nullptr;
      --image->tls_users;
    }
  }
  pthread_mutex_unlock(&g_tls_mutex);
}

namespace {

// Under g_tls_mutex with signals blocked: this thread's block for the template, made or replaced
// as needed. Only this thread writes its table and blocks.
void* thread_block_address(ThreadTlsState* thread, const TlsTemplate& tls, uintptr_t offset,
                           [[maybe_unused]] int* allocation_error) {
#if defined(__riscv) && __riscv_xlen == 64
  if (!thread->spill_tag && !reserve_thread_spill(thread)) {
    if (allocation_error) *allocation_error = errno;
    return nullptr;
  }
#endif
  ThreadTlsBlock* block = find_thread_block(thread, tls.module_id);
  if (block == nullptr) {
    if (!ensure_thread_block_capacity(thread, tls.module_id)) return nullptr;
    block = create_thread_block(tls);
    if (block == nullptr) return nullptr;
    block->next = thread->first;
    thread->first = block;
    __atomic_store_n(&thread->blocks->slots()[tls.module_id], block, __ATOMIC_RELEASE);
  } else if (block->generation != tls.generation && !reset_thread_block(block, tls)) {
    return nullptr;
  }
  return static_cast<uint8_t*>(block->storage) + offset;
}

// Bionic's tls_get_addr_slow_path, except that the operation lock is waited for with the
// caller's signal mask (a load may hold it for long). Everything after it runs with signals
// blocked, and g_tls_mutex is then never contended: every holder also holds the operation lock.
__attribute__((noinline)) void* tls_get_addr_slow(const TlsIndex& index, int* allocation_error) {
  OperationGuard operation;
  // activate_tls creates the key before any template, so without it nothing is active. This
  // path therefore never takes g_key_mutex, which explicit prepare_fork holds.
  if (!__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE)) return nullptr;
  ScopedSignalBlocker signals;
  ThreadTlsState* thread = nullptr;
  bool created = false;
  void* address = nullptr;
  pthread_mutex_lock(&g_tls_mutex);
  // Template and offset first: an access that fails there leaves no state behind.
  TlsTemplate* tls = find_tls_template(index.module);
  if (tls != nullptr && index.offset < tls->memory_bytes) {
    thread = thread_tls_state(&created);
    if (thread != nullptr)
      address = thread_block_address(thread, *tls, index.offset, allocation_error);
  }
  pthread_mutex_unlock(&g_tls_mutex);
  // A failed allocation keeps no state this call made: an empty one would hold shutdown off.
  if (address == nullptr && created) release_empty_thread_tls_state(thread);
  return address;
}

}  // namespace

void* tls_block_address(uintptr_t module_id, uintptr_t byte_offset, int* allocation_error) {
  // Module 0 (an unresolved weak TLS symbol) has no block: null, with no side effect.
  if (module_id == 0) return nullptr;
  // Lock-free for a block this thread already has, as Bionic's TLS_GET_ADDR.
  void* address = own_block_address(module_id, byte_offset, nullptr);
  if (address != nullptr) return address;
  const TlsIndex index{static_cast<unsigned long>(module_id),
                       static_cast<unsigned long>(byte_offset)};
  return tls_get_addr_slow(index, allocation_error);
}

extern "C" void* yuki_tls_get_addr(TlsIndex* index) {
  if (index == nullptr || index->module == 0) return nullptr;
  return tls_block_address(index->module, index->offset + arch::kTlsDtvOffset);
}

namespace {
bool emutls_template(ImageState* owner, const EmutlsControl* control, TlsTemplate* object) {
  const auto offset =
      reinterpret_cast<uintptr_t>(control) - reinterpret_cast<uintptr_t>(owner->memory.bias);
  if (!runtime_pointer<EmutlsControl>(owner, offset) ||
      __atomic_load_n(&control->index, __ATOMIC_ACQUIRE) != 0 ||
      (control->alignment && !is_power_of_two(control->alignment)))
    return false;
  object->memory_bytes = std::max(uintptr_t{1}, control->size);
  object->alignment = control->alignment;
  if (control->initial && control->size) {
    auto* source = caller_image(const_cast<void*>(control->initial));
    if (!source || source->releasing ||
        !runtime_pointer<uint8_t>(source,
                                  reinterpret_cast<uintptr_t>(control->initial) -
                                      reinterpret_cast<uintptr_t>(source->memory.bias),
                                  control->size))
      return false;
    object->initial_bytes = control->initial;
    object->file_bytes = control->size;
  }
  return true;
}
}  // namespace

void* bound_emutls_accessor(const ImageState* image) {
  if (!image || image->mixed_emutls_accessors || image->deferred_emutls_accessor) return nullptr;
  return image->managed_emutls ? reinterpret_cast<void*>(yuki_emutls_get_address)
                               : image->emutls_accessor_provider;
}

// Exported controls are known after relocation and can be checked before any private code runs.
// A local control has no dynamic symbol in a stripped DSO and receives the same check on use.
bool validate_emutls_controls(ImageState* image) {
  // A directly callable name or version of the native accessor would keep using compiler-rt
  // even if another relocation in the same image bound to Core.
  if (image->binds_core_emutls &&
      (image->has_local_emutls_accessor || image->mixed_emutls_accessors ||
       image->deferred_emutls_accessor))
    return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_RELOCATIONS, kEmutlsAccessor);
  if (!image->host && !image->has_emutls_controls) return true;
  const auto refuse_control = [image](uint32_t index) {
    const auto& symbol = image->symbols.entries[index];
    return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_RELOCATIONS,
                string_at(image, symbol.st_name),
                symbol_version(image, index, symbol.st_shndx == SHN_UNDEF));
  };
  void* accessor = bound_emutls_accessor(image);
  const bool may_use_core = image->binds_core_emutls || image->deferred_emutls_accessor;
  if (image->native_emutls_controls && (may_use_core || image->mixed_emutls_accessors))
    return refuse_control(image->native_emutls_controls->symbol);
  for (auto* edge = image->dependencies; edge; edge = edge->next) {
    if (!edge->emutls_control) continue;
    auto* provider = edge->image;
    // A fully native trusted group keeps its native bindings. A mixed group must agree
    // on a known accessor in either import direction before any private IFUNC runs.
    if (image->host && provider && provider->host && !image->mixed_emutls_accessors &&
        !provider->mixed_emutls_accessors && !may_use_core && !provider->binds_core_emutls &&
        !provider->deferred_emutls_accessor)
      continue;
    if (!accessor || accessor != bound_emutls_accessor(provider))
      return refuse_control(edge->emutls_control);
  }
  if (accessor != reinterpret_cast<void*>(yuki_emutls_get_address)) return true;
  if (image->host && !ensure_thread_tls_key())
    return fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA);
  for (size_t i = 0; i < image->symbols.count; ++i) {
    const auto& symbol = image->symbols.entries[i];
    const char* name = string_at(image, symbol.st_name);
    if (symbol.st_shndx == SHN_UNDEF || !name || strncmp(name, "__emutls_v.", 11) != 0) continue;
    auto* control = runtime_pointer<EmutlsControl>(image, symbol.st_value);
    TlsTemplate object;
    if (symbol.st_shndx == SHN_ABS || ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT ||
        symbol.st_size < sizeof(EmutlsControl) || !control ||
        !emutls_template(image, control, &object))
      return fail(YUKILINKER_C_INVALID_ELF, YUKILINKER_C_RELOCATIONS, name);
  }
  return true;
}

namespace {
size_t emutls_hash(const EmutlsControl* control) {
  const auto word = reinterpret_cast<uintptr_t>(control) / alignof(EmutlsControl);
  return word ^ (word >> 5) ^ (word >> 11);
}

// Half-full at most. Return the block and, for insertion, the matching or first unused slot.
EmutlsBlock* find_emutls_block(EmutlsTable* table, const EmutlsControl* control, size_t* slot) {
  if (!table) return nullptr;
  const size_t mask = table->capacity - 1;
  for (size_t i = emutls_hash(control) & mask;; i = (i + 1) & mask) {
    auto* block = __atomic_load_n(&table->slots()[i], __ATOMIC_ACQUIRE);
    if (!block || block->control == control) {
      if (slot) *slot = i;
      return block;
    }
  }
}

EmutlsTable* grow_emutls_table(EmutlsTable* old) {
  size_t capacity = 8;
  if (old) {
    size_t live = 0;
    for (size_t i = 0; i < old->capacity; ++i) {
      auto* block = old->slots()[i];
      if (block && block->generation) ++live;
    }
    // Rehash without doubling when detached dead blocks pushed occupancy to the threshold.
    capacity = live >= old->capacity / 4 ? old->capacity * 2 : old->capacity;
  }
  size_t bytes;
  if (multiply_overflow(capacity, sizeof(EmutlsBlock*), &bytes) ||
      add_overflow(bytes, sizeof(EmutlsTable), &bytes))
    abort();
  auto* table = static_cast<EmutlsTable*>(calloc(1, bytes));
  if (!table) abort();
  table->capacity = capacity;
  table->retired = old;
  if (old) {
    table->blocks = old->blocks;
    for (size_t i = 0; i < old->capacity; ++i) {
      auto* block = old->slots()[i];
      if (!block || !block->generation) continue;
      size_t slot;
      find_emutls_block(table, block->control, &slot);
      table->slots()[slot] = block;
      ++table->used;
    }
  }
  return table;
}

// The control identifies its defining image after ELF interposition. Compiler-generated callers
// have no allocation failure return. The Core never publishes an index in the control.
__attribute__((noinline)) void* emutls_address_slow(const EmutlsControl* control) {
  OperationGuard operation;
  ScopedSignalBlocker signals;
  ThreadTlsState* thread = thread_tls_state();
  if (!thread) abort();
  // A signal handler may have published this control since the first lookup.
  auto* table = thread->emutls;
  size_t slot;
  auto* previous = find_emutls_block(table, control, &slot);
  if (previous && previous->generation) return previous->storage;
  auto* owner = caller_image(const_cast<EmutlsControl*>(control));
  TlsTemplate object;
  if (bound_emutls_accessor(owner) != reinterpret_cast<void*>(yuki_emutls_get_address) ||
      !admits_private_tls(owner) || !emutls_template(owner, control, &object))
    abort();
  if (!table || (!previous && table->used >= table->capacity / 2)) {
    table = grow_emutls_table(table);
    __atomic_store_n(&thread->emutls, table, __ATOMIC_RELEASE);
    find_emutls_block(table, control, &slot);
  }
  auto* block = allocate_object<EmutlsBlock>();
  if (!block) abort();
  void* storage = allocate_thread_storage(object);
  if (!storage) abort();
  *block = {control, owner, owner->generation, storage, table->blocks};
  table->blocks = block;
  // Another key destructor can publish this address after our first cleanup pass. Give all
  // blocks in the table a full pass after the most recent allocation.
  thread->emutls_deferred = false;
  if (!previous) ++table->used;
  ++owner->tls_users;
  retain_tls_dependencies(owner);
  __atomic_store_n(&table->slots()[slot], block, __ATOMIC_RELEASE);
  return storage;
}
}  // namespace

extern "C" void* yuki_emutls_get_address(const EmutlsControl* control) {
  if (__atomic_load_n(&g_thread_tls_key_valid, __ATOMIC_ACQUIRE)) {
    auto* thread = static_cast<ThreadTlsState*>(pthread_getspecific(g_thread_tls_key));
    if (thread) {
      auto* table = __atomic_load_n(&thread->emutls, __ATOMIC_ACQUIRE);
      auto* block = find_emutls_block(table, control, nullptr);
      if (block && __atomic_load_n(&block->generation, __ATOMIC_ACQUIRE)) return block->storage;
    }
  }
  return emutls_address_slow(control);
}

#if defined(__i386__)
extern "C" __attribute__((regparm(1))) void* yuki_tls_get_addr_i386(TlsIndex* index) {
  return yuki_tls_get_addr(index);
}
#endif

void run_thread_destructor(void* opaque) {
  OperationGuard operation;
  auto* record = static_cast<ThreadExitRecord*>(opaque);
  ImageState* owner = record->owner;
  // Keep the record linked across the unlocked callback. A fork on another thread must
  // be able to drop this pin in the child, even though the callback there will never return.
  {
    CallbackGuard callback_scope(owner, CallbackGuard::Code::TlsDestructor);
    call_module(record->function, record->argument);
  }
  // Bionic's __cxa_thread_finalize runs this as the thread exits, before the key destructors and
  // with no loader lock held. Check the owner before a signal can collect the unpinned image.
  bool unpinned;
  {
    ScopedSignalBlocker signals;
    release_registered_destructor(record);
    unpinned = unpinned_image(owner);
  }
  if (unpinned) collect_unpinned();
}

int module_thread_atexit(void (*function)(void*), void* argument, void* dso) {
  OperationGuard operation;
  // An earlier host atfork prepare can initialize a C++ TLS object. Owner lookup needs the
  // registry mutex, and Bionic registration can reenter Core with the operation lock dropped.
  ScopedForkUnlock fork_locks;
  auto* owner = find_exit_owner(dso);
  if (!owner || !function || !admits_private_tls(owner)) return -1;
  bool created = false;
  auto* thread = thread_tls_state(&created);
  if (!thread) return -1;
  auto* record = allocate_object<ThreadExitRecord>();
  if (!record) {
    if (created) release_empty_thread_tls_state(thread);
    return -1;
  }
  // Pinned and linked before the lock drops, so a collection or a fork child accounts for it.
  {
    ScopedSignalBlocker signals;
    *record = {function, argument, owner, thread, thread->destructors};
    ++owner->thread_destructors;
    retain_tls_dependencies(owner);
    thread->destructors = record;
  }
  int status = -1;
  {
    // Bionic versions that pin the anchor take the linker mutex. A linker callback can
    // reenter Core, so release the operation lock across registration.
    CallbackGuard host_scope(nullptr);
    status = __cxa_thread_atexit_impl(run_thread_destructor, record,
                                      reinterpret_cast<void*>(&pthread_self));
  }
  if (status == 0) return 0;
  ScopedSignalBlocker signals;
  release_registered_destructor(record);
  // Only a state this call made: an older one may be in use by a read a handler interrupted.
  if (created) release_empty_thread_tls_state(thread);
  return -1;
}

// Lock-free, like the access path: this thread's block when it holds `generation`.
void* current_thread_tls_data(uintptr_t module_id, uintptr_t generation) {
  uintptr_t matched = 0;
  void* storage = generation != 0 ? own_block_address(module_id, 0, &matched) : nullptr;
  return matched == generation ? storage : nullptr;
}

#if defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
extern "C" __attribute__((visibility("hidden"))) uintptr_t
yuki_tlsdesc_dynamic_body(uintptr_t* descriptor) {
  uintptr_t raw = 0;
  memcpy(&raw, reinterpret_cast<const uint8_t*>(descriptor) + sizeof(raw), sizeof(raw));
  const auto* cookie = reinterpret_cast<const TlsDescriptorIndex*>(raw);
  void* address = tls_block_address(cookie->module, cookie->offset);
  return reinterpret_cast<uintptr_t>(address) - current_thread_pointer();
}
#endif  // #if defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
#if defined(__riscv) && __riscv_xlen == 64
// The resolver links banks in a single Core-owned mapping, preserving the scan order so
// later bursts reuse the same files. Only the first header stores the register file size.
struct RiscvSpillBank {
  RiscvSpillBank* next;
  size_t file_bytes;
  uintptr_t owners[YUKI_RVV_TOTAL_SLOTS];
  uintptr_t frames[YUKI_RVV_TOTAL_SLOTS];
};
struct RiscvThreadSpills {
  RiscvThreadSpills* next;
  size_t file_bytes;
  uintptr_t owners[YUKI_RVV_NESTED_SLOTS];
  uintptr_t thread;
  uintptr_t frames[YUKI_RVV_NESTED_SLOTS];
};
static_assert(offsetof(RiscvSpillBank, file_bytes) == 8 &&
              offsetof(RiscvSpillBank, owners) == YUKI_RVV_OWNERS &&
              offsetof(RiscvSpillBank, frames) == YUKI_RVV_FRAMES &&
              sizeof(RiscvSpillBank) == YUKI_RVV_FILES);
static_assert(offsetof(RiscvThreadSpills, file_bytes) == 8 &&
              offsetof(RiscvThreadSpills, owners) == YUKI_RVV_OWNERS &&
              offsetof(RiscvThreadSpills, thread) == YUKI_RVV_THREAD_TAG &&
              offsetof(RiscvThreadSpills, frames) == YUKI_RVV_THREAD_FRAMES &&
              sizeof(RiscvThreadSpills) == YUKI_RVV_THREAD_FILES);
constexpr size_t kTidsPerPinChunk = size_t{1} << YUKI_RVV_PIN_CHUNK_SHIFT;
constexpr size_t kPinChunkWords = kTidsPerPinChunk / YUKI_RVV_PIN_GROUP;
constexpr size_t kSpillPinWords = (1u << YUKI_RISCV_TID_BITS) / YUKI_RVV_PIN_GROUP;
constexpr size_t kPinDirectoryWords = kSpillPinWords / kPinChunkWords / 64;
extern "C" {
__attribute__((visibility("hidden"))) RiscvSpillBank* yuki_riscv_spill_banks = nullptr;
__attribute__((visibility("hidden"))) RiscvThreadSpills* yuki_riscv_thread_spills = nullptr;
__attribute__((visibility("hidden"))) size_t yuki_riscv_spill_stride = 0;
__attribute__((visibility("hidden"))) uintptr_t yuki_riscv_spill_end = 0;
__attribute__((visibility("hidden"))) uintptr_t yuki_riscv_spill_fork_thread = 0;
// Bionic LP64 non-PI recursive mutexes keep the owner TID in the second 32-bit
// word. Validate it before publishing any descriptor that can read it.
extern __attribute__((visibility("hidden"))) const int32_t* const yuki_riscv_operation_owner_tid =
    &g_operation_mutex.__private[1];
// Offset and sequence of our own Bionic pthread key. Neither word changes
// while a descriptor can execute. One bit per possible Linux TID pins its
// destructor before the first borrow, including an interrupted first visit.
__attribute__((visibility("hidden"))) uintptr_t yuki_riscv_spill_key[2]{};
__attribute__((visibility("hidden"))) uintptr_t* yuki_riscv_spill_pins = nullptr;
__attribute__((visibility("hidden"))) uintptr_t yuki_riscv_spill_pin_chunks[kPinDirectoryWords]{};
// Indexed by kernel TID. A borrower publishes its TP before claiming a file.
// The low bit tags an exit watch, which a new enrollment replaces with its TP.
__attribute__((visibility("hidden"))) uintptr_t* yuki_riscv_spill_threads = nullptr;
}
static_assert(YUKI_RVV_PIN_GROUP == sizeof(uintptr_t));  // assembly indexes words by aligned TID
static pthread_key_t spill_exit_key;
static bool spill_exit_key_valid;
static bool spill_reservation_committed;

template <class Bank>
static size_t spill_bank_bytes(size_t file_bytes) {
  return sizeof(Bank) + sizeof(Bank::owners) / sizeof(uintptr_t) * file_bytes;
}

static size_t mapped_spill_bytes(size_t bytes) {
  const size_t page = system_page_size();
  return (bytes + page - 1) & ~(page - 1);
}

static size_t spill_reservation_bytes() {
  return yuki_riscv_spill_end - reinterpret_cast<uintptr_t>(yuki_riscv_spill_banks);
}

static bool reserve_spill_banks(size_t file_bytes) {
  const size_t stride = mapped_spill_bytes(spill_bank_bytes<RiscvSpillBank>(file_bytes));
  constexpr size_t tids = size_t{1} << YUKI_RISCV_TID_BITS;
  // Reserve ordinary capacity for every possible Linux task. RLIMIT_NPROC can fall
  // below the live thread count or rise after binding, and privileged callers are exempt.
  size_t banks = (tids + YUKI_RVV_SLOTS - 1) / YUKI_RVV_SLOTS;
  const int saved_errno = errno;
  size_t bytes;
  void* memory;
  for (;;) {
    bytes = banks * stride;
    memory = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory != MAP_FAILED) break;
    if (banks == 1 || errno != ENOMEM) return false;
    // Smaller address spaces and finite RLIMIT_AS can limit the available capacity.
    banks = std::max<size_t>(1, banks / 4);
  }
  errno = saved_errno;
  auto* first = new (memory) RiscvSpillBank{};
  first->file_bytes = file_bytes;
  yuki_riscv_spill_stride = stride;
  yuki_riscv_spill_end = reinterpret_cast<uintptr_t>(memory) + bytes;
  __atomic_store_n(&yuki_riscv_spill_banks, first, __ATOMIC_RELEASE);
  return true;
}

static bool release_spill_reservation() {
  if (!yuki_riscv_spill_banks) return true;
  if (munmap(yuki_riscv_spill_banks, spill_reservation_bytes()) != 0) {
    report_cleanup_failure();
    record_event(nullptr, YUKILINKER_C_EVENT_CLEANUP_FAILURE, YUKILINKER_C_IO_ERROR);
    return false;
  }
  yuki_riscv_spill_banks = nullptr;
  yuki_riscv_spill_end = 0;
  yuki_riscv_spill_stride = 0;
  return true;
}

static RiscvThreadSpills* allocate_thread_spills(size_t file_bytes) {
  const auto bytes = spill_bank_bytes<RiscvThreadSpills>(file_bytes);
  void* memory = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED) return nullptr;
  auto* bank = new (memory) RiscvThreadSpills{};
  bank->file_bytes = file_bytes;
  return bank;
}

static bool release_thread_spills(RiscvThreadSpills*& head) {
  while (auto* bank = head) {
    auto* next = bank->next;
    const size_t bytes = spill_bank_bytes<RiscvThreadSpills>(bank->file_bytes);
    if (munmap(bank, bytes) != 0) {
      report_cleanup_failure();
      record_event(nullptr, YUKILINKER_C_EVENT_CLEANUP_FAILURE, YUKILINKER_C_IO_ERROR);
      return false;
    }
    head = next;
  }
  return true;
}

namespace {
struct SpillExitWatch {
  SpillExitWatch* next;
  uintptr_t thread;
  pid_t tid;
  int fd;
};
SpillExitWatch* spill_exit_watches;

uintptr_t watch_tag(const SpillExitWatch* watch) {
  return reinterpret_cast<uintptr_t>(watch) | 1;
}

uintptr_t spill_thread_pointer(uintptr_t value) {
  return (value & 1) ? reinterpret_cast<const SpillExitWatch*>(value & ~uintptr_t{1})->thread
                     : (value & ~uintptr_t{2});
}

void reap_spill_exit_watches(bool discard = false) {
  auto** link = &spill_exit_watches;
  while (auto* watch = *link) {
    const auto tid = static_cast<unsigned>(watch->tid);
    auto* group = &yuki_riscv_spill_pins[tid / YUKI_RVV_PIN_GROUP];
    auto* thread = &yuki_riscv_spill_threads[tid];
    // The group is read first. A new borrower publishes its TP before advancing that epoch.
    auto word = __atomic_load_n(group, __ATOMIC_ACQUIRE);
    auto tag = watch_tag(watch);
    if (__atomic_load_n(thread, __ATOMIC_ACQUIRE) == tag) {
      const auto bit = uintptr_t{1} << (tid % YUKI_RVV_PIN_GROUP);
      if (!discard && (word & bit)) {
        pollfd event{watch->fd, POLLIN, 0};
        if ((word | uintptr_t{YUKI_RVV_PIN_MASK}) == UINTPTR_MAX || poll(&event, 1, 0) != 1 ||
            !(event.revents & (POLLIN | POLLHUP)) ||
            !__atomic_compare_exchange_n(group, &word, word & ~bit, false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE)) {
          link = &watch->next;
          continue;
        }
      }
      __atomic_compare_exchange_n(thread, &tag, uintptr_t{0}, false, __ATOMIC_ACQ_REL,
                                  __ATOMIC_ACQUIRE);
    }
    *link = watch->next;
    close(watch->fd);
    free_object(watch);
  }
}

void watch_spill_thread_exit(uintptr_t thread) {
  const pid_t tid = gettid();
  if (tid <= 0 || static_cast<unsigned>(tid) >= (1u << YUKI_RISCV_TID_BITS)) return;
  auto& slot = yuki_riscv_spill_threads[tid];
  // Synthetic/manual key values do not represent a borrower, and a repeated callback can
  // keep an existing watch so long as no descriptor has enrolled again.
  if (__atomic_load_n(&slot, __ATOMIC_ACQUIRE) != thread) return;
  const int fd = pidfd_open(tid, PIDFD_THREAD);
  auto* watch = fd != -1 ? allocate_object<SpillExitWatch>() : nullptr;
  if (!watch) {
    if (fd != -1) close(fd);
    // Tag an exited thread without a pidfd so a reusing thread knows it does not hold the pin.
    __atomic_store_n(&slot, thread | uintptr_t{2}, __ATOMIC_RELEASE);
    return;
  }
  *watch = {spill_exit_watches, thread, tid, fd};
  spill_exit_watches = watch;
  __atomic_store_n(&slot, watch_tag(watch), __ATOMIC_RELEASE);
}

template <class Bank>
void clear_spill_owners(Bank* bank, uintptr_t thread, bool vanished) {
  for (; bank; bank = __atomic_load_n(&bank->next, __ATOMIC_ACQUIRE)) {
    for (size_t i = 0; i < sizeof(bank->owners) / sizeof(uintptr_t); ++i) {
      const auto owner = __atomic_load_n(&bank->owners[i], __ATOMIC_RELAXED);
      if (!owner) continue;
      const bool mine = (owner & ~uintptr_t{1}) == thread;
      if (vanished && mine && owner != thread)
        __atomic_store_n(&bank->owners[i], thread, __ATOMIC_RELEASE);
      if (mine == vanished) continue;
      __atomic_store_n(&bank->frames[i], uintptr_t{0}, __ATOMIC_RELAXED);
      __atomic_store_n(&bank->owners[i], uintptr_t{0}, __ATOMIC_RELEASE);
    }
  }
}

void abandoned_spills(void*) {
  OperationGuard operation;
  ScopedSignalBlocker signals;
  const int saved_errno = errno;
  const auto self = current_thread_pointer();
  clear_spill_owners(yuki_riscv_spill_banks, self, false);
  clear_spill_owners(yuki_riscv_thread_spills, self, false);
  // Keep the TID pinned through Bionic's return from this callback. Shutdown
  // can reap it once the kernel confirms that this generation has exited.
  reap_spill_exit_watches();
  watch_spill_thread_exit(self);
  errno = saved_errno;
}

// Compare through the kernel before trusting Bionic's candidate key-data pointer.
// A zero-length requeue compares the word without modifying it or waiting on it.
bool probe_key_word(uintptr_t address, uint32_t expected, bool require_match) {
  uint32_t other = 0;
  const long result =
      syscall(SYS_futex, address, FUTEX_CMP_REQUEUE_PRIVATE, 0, 0, &other, expected);
  return result == 0 || (!require_match && result == -1 && errno == EAGAIN);
}

bool prepare_spill_key() {
  if (spill_exit_key_valid) return true;
  const int err = pthread_key_create(&spill_exit_key, abandoned_spills);
  if (err) return fail_errno(YUKILINKER_C_RELOCATIONS, err);
  const auto tp = current_thread_pointer();
  const int saved_probe_errno = errno;
  uintptr_t thread = 0, keys = 0;
  bool compatible =
      tp % alignof(uintptr_t) == 0 &&
      probe_key_word(tp + YUKI_BIONIC_PTHREAD_FROM_TP, 0, false) &&
      probe_key_word(tp + YUKI_BIONIC_PTHREAD_FROM_TP + 4, 0, false) &&
      probe_key_word(tp + YUKI_BIONIC_KEY_DATA_FROM_TP, 0, false) &&
      probe_key_word(tp + YUKI_BIONIC_KEY_DATA_FROM_TP + 4, 0, false);
  errno = saved_probe_errno;
  if (compatible) {
    memcpy(&thread, reinterpret_cast<void*>(tp + YUKI_BIONIC_PTHREAD_FROM_TP), sizeof(thread));
    memcpy(&keys, reinterpret_cast<void*>(tp + YUKI_BIONIC_KEY_DATA_FROM_TP), sizeof(keys));
  }
  const unsigned index = static_cast<unsigned>(spill_exit_key) ^ (1u << 31);
  uintptr_t cookie;
  compatible = compatible && thread && thread % alignof(uintptr_t) == 0 &&
               thread == static_cast<uintptr_t>(pthread_self()) && keys && index < 256 &&
               thread <= UINTPTR_MAX - YUKI_BIONIC_TID_FROM_PTHREAD - sizeof(pid_t);
  if (compatible) {
    const int saved_tid_errno = errno;
    compatible = probe_key_word(thread + YUKI_BIONIC_TID_FROM_PTHREAD, 0, false);
    errno = saved_tid_errno;
  }
  if (compatible) {
    pid_t tid;
    memcpy(&tid, reinterpret_cast<void*>(thread + YUKI_BIONIC_TID_FROM_PTHREAD), sizeof(tid));
    // The relocation owns the operation mutex, even if its pthread depth-key store failed.
    compatible = tid > 0 && tid == gettid() &&
                 __atomic_load_n(yuki_riscv_operation_owner_tid, __ATOMIC_RELAXED) == tid &&
                 pthread_setspecific(spill_exit_key, &cookie) == 0;
  }
  if (compatible) {
    const size_t offset = index * 2 * sizeof(uintptr_t);
    const uintptr_t entry = keys + offset;
    const uintptr_t marker = reinterpret_cast<uintptr_t>(&cookie);
    const int saved = errno;
    compatible = keys <= UINTPTR_MAX - offset - 15 && entry % alignof(uintptr_t) == 0 &&
                 probe_key_word(entry + 8, static_cast<uint32_t>(marker), true) &&
                 probe_key_word(entry + 12, static_cast<uint32_t>(marker >> 32), true);
    // Observe a second public write to the same cell before reading its adjacent sequence.
    const uintptr_t second = reinterpret_cast<uintptr_t>(&spill_exit_key);
    compatible = compatible && pthread_setspecific(spill_exit_key, &spill_exit_key) == 0 &&
                 probe_key_word(entry + 8, static_cast<uint32_t>(second), true) &&
                 probe_key_word(entry + 12, static_cast<uint32_t>(second >> 32), true) &&
                 probe_key_word(entry, 0, false) && probe_key_word(entry + 4, 0, false);
    if (compatible) {
      uintptr_t sequence;
      memcpy(&sequence, reinterpret_cast<void*>(entry), sizeof(sequence));
      compatible = (sequence & 1) != 0;
      if (compatible) {
        yuki_riscv_spill_key[0] = offset;
        yuki_riscv_spill_key[1] = sequence;
      }
    }
    compatible = pthread_setspecific(spill_exit_key, nullptr) == 0 && compatible;
    errno = saved;
  }
  if (!compatible) {
    pthread_key_delete(spill_exit_key);
    return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_RELOCATIONS);
  }
  // Only a Core which binds a wide descriptor needs lifetime pins.
  // The TID arrays are demand-zero. Only pages reached by this Core's borrowers are written.
  constexpr size_t tids = 1u << YUKI_RISCV_TID_BITS;
  auto* pins = static_cast<uintptr_t*>(calloc(kSpillPinWords + tids, sizeof(uintptr_t)));
  if (!pins) {
    pthread_key_delete(spill_exit_key);
    return fail_errno(YUKILINKER_C_RELOCATIONS, ENOMEM);
  }
  yuki_riscv_spill_pins = pins;
  yuki_riscv_spill_threads = pins + kSpillPinWords;
  spill_exit_key_valid = true;
  return true;
}

void release_spill_key() {
  if (!spill_exit_key_valid) return;
  pthread_key_delete(spill_exit_key);
  spill_exit_key_valid = false;
  reap_spill_exit_watches(true);
  free(yuki_riscv_spill_pins);
  yuki_riscv_spill_pins = nullptr;
  yuki_riscv_spill_threads = nullptr;
  memset(yuki_riscv_spill_pin_chunks, 0, sizeof(yuki_riscv_spill_pin_chunks));
}

bool fail_initial_spill_mapping(int error) {
  // No wide descriptor has been published. Detach the provisional thread tags before
  // unmapping their storage. A failed unmap stays on the list for accounting and retry.
  fail_errno(YUKILINKER_C_RELOCATIONS, error);
  for (auto* thread = g_thread_states; thread; thread = thread->next)
    release_thread_spill_tag(thread);
  (void)release_thread_spills(yuki_riscv_thread_spills);
  release_spill_key();
  return false;
}

// The operation lock serializes assignments. The tag grants access to scratch space only.
// The TLS lookup still reads the calling thread's pthread key and verifies the generation.
bool reserve_thread_spill(ThreadTlsState* thread, size_t file_bytes) {
  if (!file_bytes) {
    if (!yuki_riscv_spill_banks) return true;
    file_bytes = yuki_riscv_spill_banks->file_bytes;
  }
  auto** link = &yuki_riscv_thread_spills;
  for (;;) {
    auto* bank = *link;
    if (!bank) {
      bank = allocate_thread_spills(file_bytes);
      if (!bank) return false;
      __atomic_store_n(link, bank, __ATOMIC_RELEASE);
    }
    // The native TLS key can release the tag before the spill key reclaims frames
    // abandoned by pthread_exit. Let that destructor finish before reassigning the bank.
    if (!__atomic_load_n(&bank->thread, __ATOMIC_ACQUIRE) &&
        std::none_of(std::begin(bank->owners), std::end(bank->owners), [](const auto& owner) {
          return __atomic_load_n(&owner, __ATOMIC_ACQUIRE) != 0;
        })) {
      thread->spill_tag = &bank->thread;
      __atomic_store_n(&bank->thread, thread->thread_pointer, __ATOMIC_RELEASE);
      return true;
    }
    link = &bank->next;
  }
}
}  // namespace

bool prepare_riscv_tlsdesc_spills(ImageState* image) {
  if (image->uses_riscv_tlsdesc_spills) return true;
  size_t vlenb;
  asm("csrr %0, vlenb" : "=r"(vlenb));
  if (vlenb <= YUKI_RVV_INLINE_VLENB) return true;
  // The relocation owns the operation lock. Publish the first mapping before a signal can fork.
  ScopedSignalBlocker signals;
  if (!yuki_riscv_spill_banks) {
    if (!prepare_spill_key()) return false;
    // Traditional TLS and symbol lookups can warm a thread before the first TLSDESC is loaded.
    for (auto* thread = g_thread_states; thread; thread = thread->next)
      if (thread->first && !thread->spill_tag && !reserve_thread_spill(thread, 32 * vlenb))
        return fail_initial_spill_mapping(errno);
    if (!reserve_spill_banks(32 * vlenb)) return fail_initial_spill_mapping(errno);
  }
  image->uses_riscv_tlsdesc_spills = true;
  return true;
}

void commit_riscv_tlsdesc_spills(uint64_t first_generation) {
  if (spill_reservation_committed || !yuki_riscv_spill_banks) return;
  for (const auto* image = g_first_image; image; image = image->next) {
    if (image->load_root->generation != first_generation || !image->uses_riscv_tlsdesc_spills)
      continue;
    spill_reservation_committed = true;
    return;
  }
}

bool rollback_riscv_tlsdesc_spills() {
  if (spill_reservation_committed || (!yuki_riscv_spill_banks && !yuki_riscv_thread_spills))
    return true;
  ScopedSignalBlocker signals;
  if (spill_reservation_committed) return true;
  // A relocation pass may have dropped the operation lock. Another open can still own a
  // descriptor, and failed execution can leave a live image in the registry.
  for (const auto* image = g_first_image; image; image = image->next)
    if (image->uses_riscv_tlsdesc_spills) return true;
  if (riscv_tlsdesc_spills_busy()) return true;
  const int saved_errno = errno;
  const int key_error = spill_exit_key_valid ? pthread_setspecific(spill_exit_key, nullptr) : 0;
  if (key_error != 0) {
    errno = key_error;
    report_cleanup_failure();
    record_event(nullptr, YUKILINKER_C_EVENT_CLEANUP_FAILURE, YUKILINKER_C_IO_ERROR);
    errno = saved_errno;
    return false;
  }
  // Keep all thread reserves usable if the shared mapping could not be returned. Once it
  // is gone, a failed thread unmap leaves only an untagged mapping for cleanup or reuse.
  bool released = release_spill_reservation();
  if (released) {
    for (auto* thread = g_thread_states; thread; thread = thread->next)
      release_thread_spill_tag(thread);
    released = release_thread_spills(yuki_riscv_thread_spills);
    release_spill_key();
  }
  errno = saved_errno;
  return released;
}

void prepare_riscv_tlsdesc_spills_for_fork() {
  if (spill_exit_watches) {
    ScopedSignalBlocker signals;
    const int saved_errno = errno;
    reap_spill_exit_watches();
    errno = saved_errno;
  }
  // Keep descriptor calls by the forker independent of peer borrows, including
  // child handlers that run before Core can discard the vanished peers' slots.
  __atomic_store_n(&yuki_riscv_spill_fork_thread, current_thread_pointer(), __ATOMIC_SEQ_CST);
}

// Only a previously enrolled thread can leave a pin in a chunk. Enrollment
// publishes the directory bit before claiming a slot. A full Core shutdown
// is the only point at which a directory bit can be forgotten.
template <class Visit>
static bool visit_spill_pin_chunks(Visit visit) {
  for (size_t i = 0; i < kPinDirectoryWords; ++i) {
    auto bits = __atomic_load_n(&yuki_riscv_spill_pin_chunks[i], __ATOMIC_ACQUIRE);
    while (bits) {
      const size_t begin = (i * 64 + __builtin_ctzl(bits)) * kPinChunkWords;
      if (visit(begin, begin + kPinChunkWords)) return true;
      bits &= bits - 1;
    }
  }
  return false;
}

void unlock_riscv_tlsdesc_spills_after_fork(bool child, pid_t parent_tid) {
  ScopedSignalBlocker signals;
  if (child) {
    const int saved_errno = errno;
    const auto survivor = current_thread_pointer();
    clear_spill_owners(yuki_riscv_spill_banks, survivor, true);
    clear_spill_owners(yuki_riscv_thread_spills, survivor, true);
    // The survivor keeps its thread pointer and receives a new kernel TID.
    // Earlier child handlers may already have pinned the new TID as well.
    if (spill_exit_key_valid) {
      const unsigned old_tid = static_cast<unsigned>(parent_tid);
      const unsigned tid = static_cast<unsigned>(gettid());
      constexpr unsigned tid_limit = 1u << YUKI_RISCV_TID_BITS;
      const auto mask = uintptr_t{1} << (tid % YUKI_RVV_PIN_GROUP);
      const auto has_pin = [survivor, tid_limit](unsigned id) {
        if (id >= tid_limit) return false;
        const auto chunk = id / kTidsPerPinChunk;
        return (yuki_riscv_spill_pin_chunks[chunk / 64] & (uintptr_t{1} << (chunk % 64))) &&
               (yuki_riscv_spill_pins[id / YUKI_RVV_PIN_GROUP] &
                (uintptr_t{1} << (id % YUKI_RVV_PIN_GROUP))) &&
               spill_thread_pointer(yuki_riscv_spill_threads[id]) == survivor;
      };
      const bool pinned = tid < tid_limit && (has_pin(old_tid) || has_pin(tid));
      if (pinned) {
        yuki_riscv_spill_threads[tid] = survivor;
        const auto chunk = tid / kTidsPerPinChunk;
        yuki_riscv_spill_pin_chunks[chunk / 64] |= uintptr_t{1} << (chunk % 64);
      }
      visit_spill_pin_chunks([&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
          const uintptr_t current = yuki_riscv_spill_pins[i];
          uintptr_t keep = (current & ~uintptr_t{YUKI_RVV_PIN_MASK}) |
                           (pinned && i == tid / YUKI_RVV_PIN_GROUP ? mask : 0);
          if (current != keep) {
            if ((keep | uintptr_t{YUKI_RVV_PIN_MASK}) != UINTPTR_MAX)
              keep += YUKI_RVV_PIN_EPOCH;
            __atomic_store_n(&yuki_riscv_spill_pins[i], keep, __ATOMIC_RELEASE);
          }
        }
        return false;
      });
      reap_spill_exit_watches(true);
    }
    errno = saved_errno;
  }
  __atomic_store_n(&yuki_riscv_spill_fork_thread, uintptr_t{0}, __ATOMIC_RELEASE);
}

static size_t thread_spill_bytes() {
  size_t sum = 0;
  for (auto* bank = yuki_riscv_thread_spills; bank; bank = bank->next)
    sum += mapped_spill_bytes(spill_bank_bytes<RiscvThreadSpills>(bank->file_bytes));
  return sum;
}

// A nonzero TP asks about a particular owner, including the caller. Zero asks about peers.
// Only erase an exited TID if the whole word still has the enrollment epoch we probed.
static bool spill_pin_live(uintptr_t owner, pid_t self, pid_t pid) {
  return visit_spill_pin_chunks([&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto* group = &yuki_riscv_spill_pins[i];
      auto word = __atomic_load_n(group, __ATOMIC_ACQUIRE);
      auto bits = word & YUKI_RVV_PIN_MASK;
      unsigned retries = 0;
      while (bits) {
        const auto bit = bits & -bits;
        const auto tid = static_cast<pid_t>(YUKI_RVV_PIN_GROUP * i + __builtin_ctzl(bit));
        bits &= ~bit;
        if (owner ? spill_thread_pointer(__atomic_load_n(&yuki_riscv_spill_threads[tid],
                                                        __ATOMIC_ACQUIRE)) != owner
                  : tid == self)
          continue;
        if (tid == self || syscall(SYS_tgkill, pid, tid, 0) != -1 || errno != ESRCH) return true;
        if ((word | uintptr_t{YUKI_RVV_PIN_MASK}) != UINTPTR_MAX) {
          const auto remaining = word & ~bit;
          if (__atomic_compare_exchange_n(group, &word, remaining, false, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE)) {
            word = remaining;
          } else {
            if (++retries == 8) return true;
            bits = word & YUKI_RVV_PIN_MASK;
          }
        }
      }
    }
    return false;
  });
}

// A later application key can abandon a file after Bionic's final visit to our key.
// Tag the owner before rechecking: a thread reusing its TP must publish its own pin
// and claim an untagged slot. Only the operation-lock holder can install this tag.
static void reap_spill_owner(uintptr_t* slot, uintptr_t* frame, pid_t self, pid_t pid) {
  auto value = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
  const auto owner = value & ~uintptr_t{1};
  if (!owner) return;
  if (value != UINTPTR_MAX) {
    auto marked = owner | 1;
    if (value == owner && (spill_pin_live(owner, self, pid) ||
                           !__atomic_compare_exchange_n(slot, &value, marked, false,
                                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)))
      return;
    if (spill_pin_live(owner, self, pid)) {
      __atomic_compare_exchange_n(slot, &marked, owner, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
      return;
    }
    // An interrupted collection can resume either the liveness check or this final release.
    if (!__atomic_compare_exchange_n(slot, &marked, UINTPTR_MAX, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED))
      return;
  }
  __atomic_store_n(frame, uintptr_t{0}, __ATOMIC_RELAXED);
  __atomic_store_n(slot, uintptr_t{0}, __ATOMIC_RELEASE);
}

template <class Bank>
static void reap_spill_list(Bank* bank, pid_t self, pid_t pid) {
  for (; bank; bank = __atomic_load_n(&bank->next, __ATOMIC_ACQUIRE))
    for (size_t i = 0; i < sizeof(bank->owners) / sizeof(uintptr_t); ++i)
      reap_spill_owner(&bank->owners[i], &bank->frames[i], self, pid);
}

void reap_riscv_tlsdesc_spills() {
  if (!spill_exit_key_valid) return;
  ScopedSignalBlocker signals;
  const int saved = errno;
  const pid_t self = gettid(), pid = getpid();
  reap_spill_exit_watches();
  reap_spill_list(yuki_riscv_spill_banks, self, pid);
  reap_spill_list(yuki_riscv_thread_spills, self, pid);
  errno = saved;
}

size_t riscv_tlsdesc_mapped_bytes() {
  reap_riscv_tlsdesc_spills();
  return spill_reservation_bytes() + thread_spill_bytes();
}

bool riscv_tlsdesc_spills_busy() {
  if (!spill_exit_key_valid) return false;
  reap_riscv_tlsdesc_spills();
  const int saved = errno;
  const bool active = spill_pin_live(0, gettid(), getpid());
  errno = saved;
  return active;
}

bool release_riscv_tlsdesc_spills() {
  // Fork recovery traverses both lists even after the last image has been retired.
  ScopedSignalBlocker signals;
  if (riscv_tlsdesc_spills_busy()) return false;
  const int key_error = spill_exit_key_valid ? pthread_setspecific(spill_exit_key, nullptr) : 0;
  if (key_error != 0) {
    errno = key_error;
    report_cleanup_failure();
    record_event(nullptr, YUKILINKER_C_EVENT_CLEANUP_FAILURE, YUKILINKER_C_IO_ERROR);
    return false;
  }
  if (!release_thread_spills(yuki_riscv_thread_spills) || !release_spill_reservation())
    return false;
  release_spill_key();
  return true;
}
#endif
#else
bool activate_tls(ImageState* image) { return image->tls.memory_bytes == 0; }
int module_thread_atexit(void (*)(void*), void*, void*) { return -1; }
void deactivate_tls(ImageState*) {}
void detach_image_tls_blocks(ImageState*) {}
void* tls_block_address(uintptr_t, uintptr_t, int*) { return nullptr; }
extern "C" void* yuki_tls_get_addr(TlsIndex*) { return nullptr; }
void* current_thread_tls_data(uintptr_t, uintptr_t) { return nullptr; }
#endif  // #if YUKILINKER_FULL

bool discover_tls_segment(ImageState* image) {
  bool found = false;
  for (size_t i = 0; i < image->memory.program_header_count; ++i) {
    const ElfW(Phdr) & ph = image->memory.program_headers[i];
    if (ph.p_type != PT_TLS) continue;
    if (found || ph.p_filesz > ph.p_memsz || (ph.p_align > 1 && !is_power_of_two(ph.p_align)))
      return false;
    found = true;
    image->tls.initial_bytes = runtime_pointer<uint8_t>(image, ph.p_vaddr, ph.p_filesz);
    if (ph.p_filesz != 0 && image->tls.initial_bytes == nullptr) return false;
    image->tls.file_bytes = ph.p_filesz;
    image->tls.memory_bytes = ph.p_memsz;
    image->tls.alignment = ph.p_align == 0 ? 1 : ph.p_align;
  }
  return true;
}

}  // namespace yukilinker::internal
