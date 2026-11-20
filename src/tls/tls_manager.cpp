// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../internal/enumeration.hpp"
#if YUKILINKER_FULL
#include "../internal/private_pthread_keys.hpp"
#endif
#include "../internal/runtime_model.hpp"

namespace yukilinker::internal {

#if YUKILINKER_FULL
// This libc ABI is available throughout the supported API range. Bind it with the Core
// so registering a destructor never needs a symbol lookup from an atfork handler.
extern "C" int __cxa_thread_atexit_impl(void (*)(void*), void*, void*);
namespace {

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

bool release_native_thread_storage(ThreadTlsState* state) {
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
void* thread_block_address(ThreadTlsState* thread, const TlsTemplate& tls, uintptr_t offset) {
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
__attribute__((noinline)) void* tls_get_addr_slow(const TlsIndex& index) {
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
    if (thread != nullptr) address = thread_block_address(thread, *tls, index.offset);
  }
  pthread_mutex_unlock(&g_tls_mutex);
  // A failed allocation keeps no state this call made: an empty one would hold shutdown off.
  if (address == nullptr && created) release_empty_thread_tls_state(thread);
  return address;
}

}  // namespace

extern "C" void* yuki_tls_get_addr(TlsIndex* index) {
  // Module 0 (an unresolved weak TLS symbol) has no block: null, with no side effect.
  if (index == nullptr || index->module == 0) return nullptr;
  // Lock-free for a block this thread already has, as Bionic's TLS_GET_ADDR.
  void* address = own_block_address(index->module, index->offset, nullptr);
  return address != nullptr ? address : tls_get_addr_slow(*index);
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

uintptr_t current_thread_pointer() {
  return reinterpret_cast<uintptr_t>(__builtin_thread_pointer());
}

#if defined(__aarch64__)
extern "C" __attribute__((visibility("hidden"))) uintptr_t
yuki_tlsdesc_dynamic_body(uintptr_t* descriptor) {
  auto* index = reinterpret_cast<TlsIndex*>(descriptor[1]);
  void* address = yuki_tls_get_addr(index);
  return reinterpret_cast<uintptr_t>(address) - current_thread_pointer();
}
#endif  // #if defined(__aarch64__)
#else
bool activate_tls(ImageState* image) { return image->tls.memory_bytes == 0; }
int module_thread_atexit(void (*)(void*), void*, void*) { return -1; }
void deactivate_tls(ImageState*) {}
void detach_image_tls_blocks(ImageState*) {}
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
