// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../internal/private_pthread_keys.hpp"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#include "../internal/enumeration.hpp"
#include "../internal/runtime_model.hpp"

namespace yukilinker::internal {
namespace {

// These are address-only references to Bionic's versioned symbols. The Core's final link can
// wrap its ordinary pthread calls or add CFI jump tables without changing the provider match.
extern "C" {
extern char bionic_key_create[] __asm__("pthread_key_create@LIBC");
extern char bionic_key_delete[] __asm__("pthread_key_delete@LIBC");
extern char bionic_setspecific[] __asm__("pthread_setspecific@LIBC");
extern char bionic_once[] __asm__("pthread_once@LIBC");
}

// Bionic owns the key number, sequence and raw value. Its destructor for the public key is null.
// One additional Bionic key per Core dispatches callbacks whose code a private unload could
// otherwise unmap. In particular this covers a compiler-rt built into a stripped DSO that calls
// its emutls accessor directly. All registry mutations are under the operation lock.
struct PrivateKey {
  pthread_key_t number;
  void (*destructor)(void*);
  ImageState* owner;
  PrivateKey* next;
};

struct KeyValue {
  PrivateKey* key;
  unsigned due;
  KeyValue* next;
};

struct KeyThread {
  pid_t tid;
  uintptr_t identity;
  KeyValue* values;
  ImageState* pending;
  unsigned round;
  bool dispatching;
  KeyThread* next;
};

PrivateKey* keys;
KeyThread* threads;
pthread_key_t dispatch_key;
bool dispatch_key_valid;
// Bionic keeps a key without a destructor readable throughout thread cleanup. A numeric token
// distinguishes the original thread even when its destructor key is already cleared and its
// kernel TID has since been reused. It retains no storage or code after Core shuts down.
pthread_key_t identity_key;
bool identity_key_valid;
uintptr_t last_identity;

// Bionic uses these three int states and a private futex on every supported ABI. Keep the
// public control interoperable with libc while recording who can finish a PRIVATE initializer.
constexpr int kOnceRunning = 1;
constexpr int kOnceDone = 2;
static_assert(PTHREAD_ONCE_INIT == 0 && sizeof(pthread_once_t) == sizeof(int));
struct PrivateOnce {
  pthread_once_t* control;
  pthread_t owner;
  ImageState* control_image;
  PrivateOnce* next;
};
PrivateOnce* initializers;
// Sequential first touches reuse this Core-owned record without allocating.
PrivateOnce first_initializer;

void remove_once(PrivateOnce** link) {
  auto* entry = *link;
  *link = entry->next;
  if (entry == &first_initializer)
    first_initializer = {};
  else
    free_object(entry);
}

void finish_once(PrivateOnce* entry) {
  if (!entry) return;
  auto** link = &initializers;
  while (*link != entry) link = &(*link)->next;
  remove_once(link);
}

void wake_once(pthread_once_t* control) {
  const int saved = errno;
  syscall(__NR_futex, control, FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
  errno = saved;
}

struct OnceCall {
  pthread_once_t* control;
  PrivateOnce* entry;
};

void abandon_once_call(void* opaque) {
  OperationGuard operation;
  ScopedSignalBlocker signals;
  auto* call = static_cast<OnceCall*>(opaque);
  int running = kOnceRunning;
  (void)__atomic_compare_exchange_n(call->control, &running, PTHREAD_ONCE_INIT, false,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
  // A signal can exit the thread between publishing completion and waking its waiters.
  wake_once(call->control);
  finish_once(call->entry);
}

void dispatch(void* opaque);

PrivateKey** find_key(pthread_key_t number) {
  auto** link = &keys;
  while (*link && (*link)->number != number) link = &(*link)->next;
  return link;
}

KeyValue** find_value(KeyThread* thread, PrivateKey* key) {
  auto** link = &thread->values;
  while (*link && (*link)->key != key) link = &(*link)->next;
  return link;
}

void drop_value(KeyValue** link) {
  auto* value = *link;
  *link = value->next;
  --value->key->owner->tls_users;
  free_object(value);
}

void drop_thread(KeyThread** link) {
  auto* thread = *link;
  *link = thread->next;
  if (thread->pending) --thread->pending->thread_destructors;
  while (thread->values) drop_value(&thread->values);
  free_object(thread);
}

// A foreign thread's dispatch key cannot be cleared here. Its empty record stays until that
// thread exits or uses the wrappers again. Its existence then protects only Core.
void release_empty(KeyThread* thread) {
  if (thread->values || thread->dispatching || pthread_getspecific(dispatch_key) != thread) return;
  if (pthread_setspecific(dispatch_key, nullptr) != 0) return;
  auto** link = &threads;
  while (*link != thread) link = &(*link)->next;
  drop_thread(link);
}

void clear_key_values(PrivateKey* key) {
  for (auto* thread = threads; thread;) {
    auto* next = thread->next;
    auto** value = find_value(thread, key);
    if (*value) drop_value(value);
    release_empty(thread);
    thread = next;
  }
}

void erase_key(PrivateKey** link) {
  auto* key = *link;
  // The setspecific fast path can observe the head without the operation lock.
  __atomic_store_n(link, key->next, __ATOMIC_RELEASE);
  if (key->owner) clear_key_values(key);
  free_object(key);
}

KeyThread* find_current_thread() {
  auto* thread = static_cast<KeyThread*>(pthread_getspecific(dispatch_key));
  if (thread) return thread;
  const uintptr_t id = current_thread_identity(false);
  if (id)
    for (thread = threads; thread; thread = thread->next)
      if (thread->identity == id) return thread;
  return nullptr;
}

KeyThread* create_thread_record() {
  const uintptr_t id = current_thread_identity(true);
  if (!id) return nullptr;
  auto* thread = allocate_object<KeyThread>();
  if (!thread) return nullptr;
  *thread = {gettid(), id, nullptr, nullptr, 0, false, threads};
  if (pthread_setspecific(dispatch_key, thread) != 0) {
    free_object(thread);
    return nullptr;
  }
  threads = thread;
  return thread;
}

struct KeyCallback {
  void (*function)(void*);
  void* argument;
};

// The selected callback stays pinned in the thread record until a published frame takes over.
// A fork child can drop a vanished thread's pending pin even if frame publication failed.
bool next_callback(KeyThread* thread, KeyCallback* call) {
  ScopedSignalBlocker signals;
  for (;;) {
    auto** link = &thread->values;
    while (*link && (*link)->due > thread->round) link = &(*link)->next;
    if (!*link) return false;
    auto* key = (*link)->key;
    void* argument = pthread_getspecific(key->number);
    (void)pthread_setspecific(key->number, nullptr);
    if (argument) {
      *call = {key->destructor, argument};
      thread->pending = key->owner;
      ++thread->pending->thread_destructors;
    }
    drop_value(link);
    if (argument) return true;
  }
}

void take_callback_pin(ImageState* owner, void* opaque) {
  auto* thread = static_cast<KeyThread*>(opaque);
  thread->pending = nullptr;
  --owner->thread_destructors;
}

void dispatch(void* opaque) {
  OperationGuard operation;
  auto* thread = static_cast<KeyThread*>(opaque);
  {
    ScopedSignalBlocker signals;
    // Bionic cleared our key before this call. Keep the record visible to a destructor rearming
    // its key, to fork from that destructor, and to Bionic's next destructor pass.
    thread->dispatching = true;
    ++thread->round;
    (void)pthread_setspecific(dispatch_key, thread);
  }
  KeyCallback call{};
  while (next_callback(thread, &call)) {
    auto* owner = thread->pending;
    CallbackGuard frame(owner, CallbackGuard::Code::TlsDestructor, false, take_callback_pin,
                        thread);
    call_module(call.function, call.argument);
    if (!frame.saved_state) {
      // The callback ran under the lock. Its pending record also survives a fork in that call.
      ScopedSignalBlocker signals;
      take_callback_pin(owner, thread);
    }
  }
  // On Bionic's last pass, a rearmed public key is still readable by later destructors.
  // Its value keeps the owner live until an explicit clear/delete or confirmed thread exit.
  if (operation_depth() == 1 && !callback_frame_open() && !g_tls_stopped) (void)collect_images();
  ScopedSignalBlocker signals;
  thread->dispatching = false;
  release_empty(thread);
}

}  // namespace

bool ensure_thread_identity_key() {
  if (identity_key_valid) return true;
  ScopedSignalBlocker signals;
  if (identity_key_valid) return true;
  const int error = g_keys_retired ? EAGAIN : pthread_key_create(&identity_key, nullptr);
  if (error) {
    errno = error;
    return false;
  }
  identity_key_valid = true;
  return true;
}

uintptr_t current_thread_identity(bool create) {
  if (!identity_key_valid && (!create || !ensure_thread_identity_key())) return 0;
  const auto read = [] { return reinterpret_cast<uintptr_t>(pthread_getspecific(identity_key)); };
  uintptr_t id = read();
  if (id || !create) return id;
  ScopedSignalBlocker signals;
  id = read();
  if (id != 0) return id;
  if (last_identity == UINTPTR_MAX) return 0;
  id = last_identity + 1;
  // pthread keys store void*, even for an opaque numeric cookie that is never dereferenced.
  // NOLINTNEXTLINE(performance-no-int-to-ptr)
  if (pthread_setspecific(identity_key, reinterpret_cast<void*>(id)) != 0) return 0;
  last_identity = id;
  return id;
}

namespace {
int module_pthread_once(pthread_once_t* once, void (*initialize)()) {
  if (__atomic_load_n(&g_fork_locked, __ATOMIC_ACQUIRE)) recover_early_fork_child();
  if (__atomic_load_n(once, __ATOMIC_ACQUIRE) == kOnceDone) return 0;
  OperationGuard operation;
  // A signal can fork on this thread. Publish the caller, initializer and callback frames
  // atomically with their pins, then restore the application mask for the actual wait or call.
  ScopedSignalBlocker signals;
  CallerCall caller(caller_image(__builtin_return_address(0)));
  auto* owner = caller_image(reinterpret_cast<void*>(initialize));
  // An earlier prepare handler may be the one that lets another thread's initializer finish.
  ScopedForkUnlock fork_locks;
  auto* control_image = caller_image(once);
  bool collect_control = false;
  {
    // Pin a distinct control image across the unlocked wait and initializer so another thread
    // cannot unmap *once before the completion store or futex wake.
    ImageState* pinned_control = control_image && control_image != owner ? control_image : nullptr;
    SnapshotGuard control_pin(&pinned_control, pinned_control ? 1 : 0, false, false);
    PrivateOnce* entry = nullptr;
    bool run = true;
    for (;;) {
      // The mapping can outlive a control object's lifetime. Reuse its abandoned record
      // even when the caller has constructed a fresh PTHREAD_ONCE_INIT at that address.
      for (entry = initializers; entry; entry = entry->next)
        if (!entry->owner && entry->control == once) break;
      int state = PTHREAD_ONCE_INIT;
      if (__atomic_compare_exchange_n(once, &state, kOnceRunning, false, __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE)) {
        if (!control_image) break;
        if (!entry) {
          entry = first_initializer.control ? allocate_object<PrivateOnce>() : &first_initializer;
          // Compiler-rt assumes the initializer ran whenever pthread_once returns.
          if (!entry) abort();
          *entry = {once, {}, control_image, initializers};
          initializers = entry;
        }
        break;
      }
      if (state == kOnceDone) {
        run = false;
        break;
      }
      // Only an actual caller may retry an inherited PRIVATE control. Leave its running
      // word in place so Bionic waiters still wait for the new initializer to publish done.
      if (entry) break;
      CallbackGuard wait(owner, CallbackGuard::Code::Image);
      signals.restore();
      const int saved = errno;
      syscall(__NR_futex, once, FUTEX_WAIT_PRIVATE, kOnceRunning, nullptr, nullptr, 0);
      errno = saved;
      signals.block();
    }
    if (run) {
      if (entry) entry->owner = pthread_self();
      {
        CallbackGuard callback(owner, CallbackGuard::Code::Image);
        // Only this thread's pthread_exit touches the public control. Fork recovery never
        // walks cleanup records on other threads' stacks, which may themselves be DONTFORK.
        OnceCall call{once, entry};
        pthread_cleanup_push(abandon_once_call, &call);
        signals.restore();
        call_module(initialize);
        // A concurrent fork may hold the operation lock when the initializer returns. Publish
        // completion before reacquiring it so the child inherits the initialized state.
        __atomic_store_n(once, kOnceDone, __ATOMIC_RELEASE);
        wake_once(once);
        signals.block();
        pthread_cleanup_pop(0);
      }
      finish_once(entry);
    }
    collect_control = pinned_control && !control_pin.previous && control_pin.collect_after;
  }
  if (collect_control) {
    signals.restore();
    (void)collect_images();
    signals.block();
  }
  return 0;
}

int module_pthread_key_create(pthread_key_t* number, void (*destructor)(void*)) {
  if (!destructor) return pthread_key_create(number, nullptr);
  OperationGuard operation;
  ScopedSignalBlocker signals;
  auto* owner = caller_image(reinterpret_cast<void*>(destructor));
  if (!owner) return pthread_key_create(number, destructor);
  if (g_keys_retired || !admits_private_tls(owner)) return EAGAIN;
  auto* key = allocate_object<PrivateKey>();
  if (!key) return ENOMEM;
  pthread_key_t fresh;
  int error = pthread_key_create(&fresh, nullptr);
  if (error) {
    free_object(key);
    return error;
  }
  if (!dispatch_key_valid) {
    error = pthread_key_create(&dispatch_key, dispatch);
    if (!error && !ensure_thread_identity_key()) {
      error = errno;
      (void)pthread_key_delete(dispatch_key);
    }
    if (error) {
      (void)pthread_key_delete(fresh);
      free_object(key);
      return error;
    }
    dispatch_key_valid = true;
  }
  *key = {fresh, destructor, owner, keys};
  __atomic_store_n(&keys, key, __ATOMIC_RELEASE);
  *number = fresh;
  return 0;
}

int module_pthread_setspecific(pthread_key_t number, const void* data) {
  // A managed key is in the list before its creator can publish the number. Only test for
  // emptiness here; both traversal and admission of a destructor still need the operation lock.
  if (!__atomic_load_n(&keys, __ATOMIC_ACQUIRE)) return pthread_setspecific(number, data);
  OperationGuard operation;
  ScopedSignalBlocker signals;
  auto* key = *find_key(number);
  if (!key) return pthread_setspecific(number, data);
  auto* thread = find_current_thread();
  if (!data) {
    const int error = pthread_setspecific(number, nullptr);
    if (!error && thread) {
      auto** link = find_value(thread, key);
      if (*link) drop_value(link);
      release_empty(thread);
    }
    return error;
  }
  if (!key->owner || !admits_private_tls(key->owner)) return EINVAL;
  if (!thread) thread = create_thread_record();
  if (!thread) return ENOMEM;
  auto** link = find_value(thread, key);
  if (*link) return pthread_setspecific(number, data);
  auto* entry = allocate_object<KeyValue>();
  if (!entry) {
    release_empty(thread);
    return ENOMEM;
  }
  const int error = pthread_setspecific(number, data);
  if (error) {
    free_object(entry);
    release_empty(thread);
    return error;
  }
  *entry = {key, thread->round + 1, nullptr};
  *link = entry;
  ++key->owner->tls_users;
  retain_tls_dependencies(key->owner);
  return 0;
}

int module_pthread_key_delete(pthread_key_t number) {
  OperationGuard operation;
  ScopedSignalBlocker signals;
  auto** link = find_key(number);
  const int error = pthread_key_delete(number);
  if (!error && *link) erase_key(link);
  return error;
}
}  // namespace

void* private_pthread_address(const ImageState* caller, const char* name, void* resolved) {
  if (!resolved || !name || strncmp(name, "pthread_", 8) != 0) return resolved;
  struct PthreadFunction {
    const char* suffix;
    void* bionic;
    void* wrapper;
    bool changes_existing_key;
  };
  static const PthreadFunction functions[] = {
      {"key_create", bionic_key_create, reinterpret_cast<void*>(module_pthread_key_create), false},
      {"key_delete", bionic_key_delete, reinterpret_cast<void*>(module_pthread_key_delete), true},
      {"setspecific", bionic_setspecific, reinterpret_cast<void*>(module_pthread_setspecific),
       true},
      {"once", bionic_once, reinterpret_cast<void*>(module_pthread_once), false},
  };
  for (const auto& function : functions) {
    // A trusted module can receive a managed key even if all keys it creates are native.
    if (resolved == function.bionic && strcmp(name + 8, function.suffix) == 0 &&
        (!caller->host || function.changes_existing_key))
      return function.wrapper;
  }
  return resolved;
}

bool private_key_threads_active() { return threads != nullptr; }

bool current_thread_has_private_key_callbacks() {
  const auto* thread = threads ? find_current_thread() : nullptr;
  return thread && (thread->values || thread->dispatching);
}

bool has_private_key_destructor(const ImageState* image) {
  for (auto* key = keys; key; key = key->next)
    if (key->owner == image) return true;
  return false;
}

// A destructor can first set a private key after dispatch's turn in Bionic's final pass. There
// is then no further callback. A collection can discard its pins once the kernel confirms that
// the thread is gone. A reused TID or a denied probe only delays collection. Never inspect a
// dead pthread_t. No per-thread fd or procfs access is needed.
void reap_exited_threads() {
  if (!threads && !g_thread_states) return;
  ScopedSignalBlocker signals;
  const int saved = errno;
  // A different thread may have deleted the last key from our record. Only this thread can
  // disarm its dispatch key. If Bionic already cleared it, the pending callback owns the record.
  if (threads) {
    auto* own = static_cast<KeyThread*>(pthread_getspecific(dispatch_key));
    if (own) release_empty(own);
  }
  const pid_t self = gettid();
  const pid_t process = getpid();
  const uintptr_t identity = current_thread_identity(false);
  const auto exited = [=](pid_t tid, uintptr_t id) {
    if (tid == self) return id != identity;
    return syscall(__NR_tgkill, process, tid, 0) < 0 && errno == ESRCH;
  };
  auto** link = &threads;
  while (*link) {
    auto* thread = *link;
    if (exited(thread->tid, thread->identity))
      drop_thread(link);
    else
      link = &thread->next;
  }
  // The final pthread key round can leave any Core state armed. With a local compiler-rt
  // the storage belongs to the DSO, and only its C++ destructor record lives here.
  for (auto* state = g_thread_states; state;) {
    auto* next = state->next;
    if (exited(state->tid, state->identity)) destroy_thread_tls_state(state);
    state = next;
  }
  errno = saved;
}

void private_keys_after_fork() {
  ScopedSignalBlocker signals;
  // Only the forking thread's nested initializers can return. Mark the others using
  // Core memory alone, even when the control's page was excluded from fork.
  for (auto** link = &initializers; *link;) {
    auto* entry = *link;
    const bool survivor = entry->owner && pthread_equal(entry->owner, pthread_self());
    if (!survivor && !entry->control_image) {
      remove_once(link);
    } else {
      if (!survivor) entry->owner = {};
      link = &entry->next;
    }
  }
  const uintptr_t id = current_thread_identity(false);
  auto** link = &threads;
  while (*link) {
    auto* thread = *link;
    // A signal may have forked after Bionic cleared the key to invoke dispatch, before the
    // callback reinstalled its dispatch record.
    if (thread->identity == id) {
      thread->tid = gettid();
      link = &(*link)->next;
    } else {
      drop_thread(link);
    }
  }
}

void retire_private_keys(ImageState* image) {
  if (!keys && !initializers) return;
  ScopedSignalBlocker signals;
  // An inherited control may never be called. Its address stops identifying this
  // control when the image goes away, even if the next mapping uses the same address.
  for (auto** link = &initializers; *link;) {
    auto* entry = *link;
    if (entry->control_image == image) {
      if (!entry->owner) {
        remove_once(link);
        continue;
      }
      entry->control_image = nullptr;
    }
    link = &entry->next;
  }
  for (auto* key = keys; key; key = key->next) {
    if (key->owner != image) continue;
    // The public key belongs to its creator and may have been passed to other modules.
    // Keep its Bionic number reserved until explicit deletion, with no callable destructor.
    clear_key_values(key);
    key->owner = nullptr;
    key->destructor = nullptr;
  }
}

void shutdown_private_keys() {
  // The surviving public keys have null Bionic destructors and do not call into Core.
  while (keys) erase_key(&keys);
  if (dispatch_key_valid) (void)pthread_key_delete(dispatch_key);
  dispatch_key_valid = false;
  if (identity_key_valid) (void)pthread_key_delete(identity_key);
  identity_key_valid = false;
  last_identity = 0;
}

}  // namespace yukilinker::internal
