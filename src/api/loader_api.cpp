// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <type_traits>

#include "../internal/elf_arch.hpp"
#include "../internal/enumeration.hpp"
#if defined(YUKILINKER_RUNTIME)
#include "../internal/caller_stubs.hpp"
#include "../internal/host_imports.hpp"
#endif
#include "../internal/android_fork_mutex.hpp"
#include "../internal/private_pthread_keys.hpp"
#include "../internal/registry.hpp"
#include "../internal/runtime_model.hpp"

extern "C" int __register_atfork(void (*prepare)(), void (*parent)(), void (*child)(), void* dso);

namespace yukilinker::internal {

namespace {

// The dlopen flags every private open path accepts; Bionic rejects all others too.
constexpr uint32_t kSupportedOpenFlags =
    RTLD_NOW | RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD | RTLD_NODELETE;

#if YUKILINKER_FULL
void publish_refusal(const yukilinker_c_error_detail& error, const OperationRefusal& refusal);

// A missing unversioned import may have been supplied by Core itself during relocation.
void supply_missing_emutls(SymbolTarget& target, const ImageState* image, const char* name,
                           const char* version) {
  if (!target.found && !target.failed && image->managed_emutls && !version && name &&
      strcmp(name, kEmutlsAccessor) == 0 &&
      image->emutls_accessor_provider == reinterpret_cast<void*>(yuki_emutls_get_address))
    target = {nullptr, nullptr, image->emutls_accessor_provider, true};
}
#endif

// One operation's error record, and the refusal that decided it. A nested operation (a callback's,
// or one call inside another) has its own of both, so it never overwrites the outer one's. A frame
// of a public call (publish) that is the thread's outermost operation hands the refusal to the
// thread's record when the operation ends: kept when it failed with that refusal, cleared
// otherwise. Inside a private dl* call it records into the call's slot instead, and the call
// publishes.
struct ErrorScope {
  yukilinker_c_error_detail* previous;
  OperationRefusal* previous_refusal;
  OperationRefusal* previous_call_slot;
  const LoadOptions* options;
  OperationRefusal refusal;
  bool publish;
  ErrorScope(yukilinker_c_error_detail* error, const LoadOptions* next = nullptr,
             bool outermost = false)
      : previous(g_operation_error),
        previous_refusal(g_operation_refusal),
        previous_call_slot(g_private_call_slot),
        options(g_open_options),
        publish(outermost && g_operation_refusal == nullptr) {
    g_operation_error = error;
    // The private call's own frame: its first operation frame shares the call's slot.
    const bool in_call = g_private_call_slot && g_operation_refusal == g_private_call_slot;
    g_operation_refusal = in_call ? g_private_call_slot : &refusal;
    // Anything deeper (a callback's operation) is no longer the private call's.
    g_private_call_slot = nullptr;
    g_open_options = next;
    if (error) *error = {};
  }
  ErrorScope(const ErrorScope&) = delete;
  ErrorScope& operator=(const ErrorScope&) = delete;
  ErrorScope(ErrorScope&&) = delete;
  ErrorScope& operator=(ErrorScope&&) = delete;
  ~ErrorScope() {
    if (previous && g_operation_error) {
      previous->execution_started |= g_operation_error->execution_started;
      previous->cleanup_incomplete |= g_operation_error->cleanup_incomplete;
    }
#if YUKILINKER_FULL
    if (publish && g_operation_error) publish_refusal(*g_operation_error, refusal);
#endif
    g_operation_error = previous;
    g_operation_refusal = previous_refusal;
    g_private_call_slot = previous_call_slot;
    g_open_options = options;
  }
};

void* loader_create_context_impl(const char* path, yukilinker_c_dependency_provider provider,
                                 void* user) {
  OperationGuard operation;
  if (path && strlen(path) >= sizeof(Context::search_path)) return nullptr;
#if YUKILINKER_FULL
  // A shutdown past its boundary admits nothing new.
  if (shutdown_begun()) return nullptr;
#endif
  auto* context = allocate_object<Context>();
  if (!context) return nullptr;
  if (path) (void)snprintf(context->search_path, sizeof(context->search_path), "%s", path);
  context->provider = provider;
  context->user = user;
  link_context(context);
  return context;
}

int loader_destroy_context_impl(void* opaque) {
  OperationGuard operation;
  if (!opaque || opaque == &g_default_context) return 0;
  // What another context left behind (a dead copy) does not hold this one.
  (void)collect_images();
  // A standalone context, not a namespace's: those are destroyed through their token.
  const auto explicit_context = [](void* candidate) -> Context* {
    for (auto* context = g_contexts; context; context = context->next)
      if (context == candidate && !context->namespace_id) return context;
    return nullptr;
  };
  Context* context = explicit_context(opaque);
  if (!context || context->snapshot_refs || context->namespace_refs || context->waiting_opens)
    return 0;
  for (auto* token = g_namespaces; token; token = token->next)
    if (token->context == opaque) return 0;
#if YUKILINKER_FULL
  // Its images go with it, RTLD_GLOBAL ones included. A refusal changed nothing; once the context
  // is sealed, a 0 means part of it is retired and the next call resumes.
  if (retire_scope_images(context) != YUKILINKER_C_OK) return 0;
  // Retirement drops the lock for finalizers; look the context up again.
  context = explicit_context(opaque);
  if (!context || context->snapshot_refs || context->namespace_refs || context->waiting_opens)
    return 0;
#endif
  if (context->images != 0) return 0;
  unlink_context(context);
  free_object(context);
  return 1;
}

void* api_open_fd_offset(int fd, const LoadOptions* options, uint64_t source_offset,
                         yukilinker_c_error_detail* output,
                         const LoadPlacement* placement = nullptr,
                         const RelroOptions* relro = nullptr, bool by_path = false) {
  OperationGuard operation;
  yukilinker_c_error_detail error{};
  ErrorScope scope(&error, options, true);
  if (options && (options->size != sizeof(*options) || (options->flags & ~kSupportedOpenFlags))) {
    fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_SOURCE);
    if (output) *output = error;
    return nullptr;
  }
  if (options && !valid_context(options->context)) {
    fail(YUKILINKER_C_INVALID_HANDLE, YUKILINKER_C_SOURCE);
    if (output) *output = error;
    return nullptr;
  }
  if (options && options->origin)
    (void)snprintf(error.object, sizeof(error.object), "%s", options->origin);
  auto* handle =
      dlopen_memfd_offset(fd, options ? options->origin : nullptr, options && options->file_backed,
                          source_offset, placement, relro, by_path);
  if (!handle && error.code == YUKILINKER_C_OK) fail(YUKILINKER_C_INVALID_ELF, YUKILINKER_C_SOURCE);
  if (output) *output = error;
  return handle ? public_token(image_of(handle)) : nullptr;
}

void* loader_open_fd_impl(int fd, const LoadOptions* options, yukilinker_c_error_detail* output) {
  return api_open_fd_offset(fd, options, 0, output);
}

void* loader_open_path_impl(const char* path, const LoadOptions* options,
                            yukilinker_c_error_detail* error) {
  OperationGuard operation;
  // Every argument check precedes open(), which is a side effect of its own.
  uint32_t code = YUKILINKER_C_OK;
  if (!path || strnlen(path, sizeof(ImageState::origin)) == sizeof(ImageState::origin) ||
      (options && (options->size != sizeof(*options) || (options->flags & ~kSupportedOpenFlags))))
    code = YUKILINKER_C_UNSUPPORTED;
  else if (options && !valid_context(options->context))
    code = YUKILINKER_C_INVALID_HANDLE;
  if (code != YUKILINKER_C_OK) {
    yukilinker_c_error_detail rejected{};
    ErrorScope scope(&rejected, nullptr, true);
    fail(code, YUKILINKER_C_SOURCE);
    if (error) *error = rejected;
    return nullptr;
  }
  // A FIFO must not block with the operation lock held; load_image refuses it.
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) {
    const int open_errno = errno;
    // Recorded through the operation's scope, so a refusal an earlier operation kept is cleared.
    yukilinker_c_error_detail failed{};
    {
      ErrorScope scope(&failed, nullptr, true);
      errno = open_errno;
      fail(open_errno == EACCES ? YUKILINKER_C_PERMISSION_DENIED : YUKILINKER_C_IO_ERROR,
           YUKILINKER_C_SOURCE);
    }
    failed.system_errno = open_errno;
    (void)snprintf(failed.object, sizeof(failed.object), "%s", path);
    if (error) *error = failed;
    return nullptr;
  }
  LoadOptions request = options ? *options : LoadOptions{};
  request.size = sizeof(request);
  request.origin = path;
  void* handle = api_open_fd_offset(fd, &request, 0, error, nullptr, nullptr, true);
  host_close_fd(fd);
  return handle;
}

#if defined(YUKILINKER_RUNTIME)
namespace {

// The host imports a relocation in the handle's scope bound through: the images a lookup through it
// searches (walk_handle_scope, as search_scope walks them), not its load root's other dependencies.
// A namespace link's target is another context's, whose imports are its own. False when the walk
// ran out of memory.
bool closure_import_mask(ImageState* image, uint32_t* mask) {
  struct Closure {
    Context* context;
    uint32_t mask;
  } closure{image->context, 0};
  *mask = 0;
  if (!image->context->host_imports) return true;
  const bool walked = walk_handle_scope(
      image,
      [](ImageState* visited, void* user) {
        auto* walk = static_cast<Closure*>(user);
        if (visited->context == walk->context) walk->mask |= visited->host_import_mask;
        return true;
      },
      &closure);
  *mask = closure.mask;
  return walked;
}

// A miss of a private dlsym through a handle, retried through the host imports that its closure
// bound through: the address a relocation would have bound.
SymbolTarget lookup_closure_import(ImageState* image, const char* name, const char* version) {
  SymbolTarget failure;
  failure.failed = true;
  uint32_t mask = 0;
  if (!closure_import_mask(image, &mask)) {
    // Never the whole context instead: a handle sees only what its scope bound.
    fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA, name, version);
    return failure;
  }
  if (mask == 0) return {};
  const HostImportResult imported = lookup_host_import(image->context, image, mask, name, version);
  // NO_MEMORY is recorded already.
  if (imported.failed) return failure;
  if (imported.refused) {
    fail_refused(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, imported.reason, imported.library,
                 name, version);
    return failure;
  }
  return {nullptr, nullptr, imported.address, imported.found};
}

}  // namespace
#endif  // #if defined(YUKILINKER_RUNTIME)

namespace {
SymbolTarget handle_target(ImageState* image, const char* name, const char* version) {
  auto target = search_scope(image, name, version, GlobalLookup::None);
#if defined(YUKILINKER_RUNTIME)
  if (!target.found && !target.failed) target = lookup_closure_import(image, name, version);
#endif
#if YUKILINKER_FULL
  supply_missing_emutls(target, image, name, version);
#endif
  return target;
}

SymbolResolution handle_address(ImageState* image, const SymbolTarget& target, const char* name) {
#if YUKILINKER_FULL
  // A private IFUNC can reenter close while materializing its address.
  void* provider = strcmp(name, kEmutlsAccessor) == 0 && image->managed_emutls
                       ? image->emutls_accessor_provider
                       : nullptr;
#endif
  auto value = materialize_target(target);
#if YUKILINKER_FULL
  if (provider && value.address == reinterpret_cast<uintptr_t>(provider))
    value.address = reinterpret_cast<uintptr_t>(yuki_emutls_get_address);
#else
  (void)image;
  (void)name;
#endif
  return value;
}

#if YUKILINKER_FULL
// On LP32 RTLD_NEXT has the private-token tag. Test the pseudo-handles before decoding tokens.
bool pseudo_handle(const void* handle) { return handle == RTLD_DEFAULT || handle == RTLD_NEXT; }

SymbolTarget pseudo_target(ImageState* caller, void* handle, const char* name,
                           const char* version) {
  auto target = search_scope(caller->load_root, name, version, GlobalLookup::Dynamic,
                             handle == RTLD_NEXT ? caller : nullptr);
  // The system load order around a PRIVATE caller is unknown. Only RTLD_DEFAULT falls back.
  if (target.found || target.failed || handle == RTLD_NEXT) return target;
  if (caller->namespace_id == 0) {
    CallbackGuard callback(caller);
    void* address = nullptr;
    if (host_dlsym(RTLD_DEFAULT, name, version, &address)) return {nullptr, nullptr, address, true};
  }
#if defined(YUKILINKER_RUNTIME)
  const auto imported = lookup_host_import(caller->context, caller, UINT32_MAX, name, version);
  if (imported.refused)
    fail_refused(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, imported.reason, imported.library,
                 name, version);
  target = {nullptr, nullptr, imported.address, imported.found,
            imported.failed || imported.refused};
#endif
  supply_missing_emutls(target, caller, name, version);
  return target;
}

bool lookup_control_compatible(ImageState* image, void* handle, const SymbolTarget& control,
                               const char* name, const char* version) {
  auto* owner = control.image;
  if (owner && (ELF64_ST_TYPE(control.symbol->st_info) != STT_OBJECT ||
                owner->mixed_emutls_accessors || owner->deferred_emutls_accessor))
    return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
  const bool native_import = !owner || (owner != image && owner->host && owner->passive_emutls);
  if (native_import) {
    // A passive trusted provider has no accessor to compare. As with a system control,
    // use the reader's actual relocation and compare its native accessor in this scope.
    const auto value = materialize_target(control);
    if (!value.valid) return fail(YUKILINKER_C_INVALID_ELF, YUKILINKER_C_METADATA, name, version);
    auto* binding = image->native_emutls_controls;
    while (binding && (binding->provider != owner || binding->address != value.address))
      binding = binding->next;
    if (!binding || !bound_emutls_accessor(image) || image->binds_core_emutls)
      return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
  }
  // System lookups and IFUNCs can reenter close. Check generations before using the original
  // scope or control again, even if a new copy has taken the same address.
  const uint64_t scope_generation = image->generation;
  const uint64_t control_generation = owner ? owner->generation : 0;
  const auto accessor = pseudo_handle(handle)
                            ? pseudo_target(image, handle, kEmutlsAccessor, nullptr)
                            : handle_target(image, kEmutlsAccessor, nullptr);
  if (accessor.failed) return false;
  image = image_by_generation(scope_generation);
  if (!image) return fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA, name, version);
  void* address = nullptr;
  if (accessor.found) {
    if (accessor.image && accessor.image->phase == Phase::Preparing)
      return fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA, name, version);
    if (accessor.image && ELF64_ST_TYPE(accessor.symbol->st_info) != STT_FUNC &&
        ELF64_ST_TYPE(accessor.symbol->st_info) != STT_GNU_IFUNC)
      return fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
    const auto value = handle_address(image, accessor, kEmutlsAccessor);
    if (!value.valid) return fail(YUKILINKER_C_INVALID_ELF, YUKILINKER_C_METADATA, kEmutlsAccessor);
    address = reinterpret_cast<void*>(value.address);
  }
  image = image_by_generation(scope_generation);
  if (!image || (!accessible_image(image) && !retiring_here(image)))
    return fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA, name, version);
  if (control_generation) {
    owner = image_by_generation(control_generation);
    if (!owner || (!accessible_image(owner) && !retiring_here(owner)))
      return fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA, name, version);
  }
  if (native_import)
    return (address && address == bound_emutls_accessor(image)) ||
           fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
  // A hidden local accessor can still use its own control.
  if (!accessor.found)
    return shares_emutls_accessor(image, owner) ||
           fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
  void* expected = bound_emutls_accessor(owner);
  const bool compatible = expected ? address == expected : caller_image(address) == owner;
  return compatible || fail(YUKILINKER_C_UNSUPPORTED, YUKILINKER_C_METADATA, name, version);
}
#endif
}  // namespace

LookupValue lookup_locked(void* handle, const char* name, const char* version, ImageState* caller) {
  LookupValue result{};
  ErrorScope scope(&result.error, nullptr, true);
  if (!name) {
    fail(YUKILINKER_C_INVALID_HANDLE, YUKILINKER_C_METADATA);
    return result;
  }
  auto* image = caller;
  SymbolTarget target;
#if YUKILINKER_FULL
  if (caller && pseudo_handle(handle)) {
    if (strcmp(name, arch::kTlsGetAddr) == 0) {
      // The module IDs in a PRIVATE caller belong to this Core.
      if (caller->releasing) {
        fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT, name, version);
        return result;
      }
      caller->binds_core_wrapper = true;
      result.address = module_api_symbol(name);
      result.found = 1;
      return result;
    }
    target = pseudo_target(caller, handle, name, version);
    if (target.image && accessible_image(target.image) && exit_cleanup_uncertain()) {
      fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT);
      return result;
    }
  } else
#endif
  {
    if (exit_cleanup_uncertain()) {
      fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT);
      return result;
    }
    image = state_of(static_cast<SoHandle*>(handle));
    if (!image || !accessible_image(image) || (private_token(handle) && !image->references)) {
      fail(YUKILINKER_C_INVALID_HANDLE, YUKILINKER_C_METADATA);
      return result;
    }
    if (image->phase == Phase::Preparing) {
      fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA);
      return result;
    }
    target = handle_target(image, name, version);
  }
#if defined(YUKILINKER_RUNTIME)
  // Modules using a PRIVATE handle share the registry used by their relocations. A host lookup
  // receives the provider's address, as does a module looking through an explicit system handle.
  if (caller && target.found && !target.image) {
    void* address = private_pthread_address(caller, name, target.address);
    if (address != target.address) {
      if (caller->releasing) {
        fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT, name, version);
        return result;
      }
      caller->binds_core_wrapper = true;
      target.address = address;
    }
  }
#endif
  if (target.failed) return result;
  if (!target.found) {
    fail(YUKILINKER_C_SYMBOL_MISSING, YUKILINKER_C_METADATA, name, version);
    return result;
  }
  // A cycle's dependency can still be preparing while the image that needs it is relocated.
  if (target.image && target.image->phase == Phase::Preparing) {
    fail(YUKILINKER_C_BUSY, YUKILINKER_C_METADATA);
    return result;
  }
#if YUKILINKER_FULL
  if ((target.image || target.address) && !strncmp(name, "__emutls_v.", 11) &&
      !lookup_control_compatible(image, handle, target, name, version))
    return result;
  if (target.image && ELF64_ST_TYPE(target.symbol->st_info) == STT_TLS) {
    TlsIndex index{target.image->tls.module_id, target.symbol->st_value};
    result.address = yuki_tls_get_addr(&index);
    result.found = result.address != nullptr;
    // An accessible image's template is active, so inside the segment only this thread's block
    // can be missing: one of its allocations failed (posix_memalign leaves errno alone).
    if (!result.found && index.offset < target.image->tls.memory_bytes) {
      errno = ENOMEM;
      fail(YUKILINKER_C_NO_MEMORY, YUKILINKER_C_METADATA, name, version);
    } else if (!result.found) {
      fail(YUKILINKER_C_INVALID_ELF, YUKILINKER_C_METADATA, name, version);
    }
    return result;
  }
#endif
  auto materialized = handle_address(image, target, name);
#if YUKILINKER_FULL
  if (caller && materialized.valid &&
      materialized.address == reinterpret_cast<uintptr_t>(yuki_emutls_get_address)) {
    if (caller->releasing) {
      fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT, name, version);
      return result;
    }
    caller->binds_core_wrapper = true;
  }
#endif
  result.address = reinterpret_cast<void*>(materialized.address);
  result.found = materialized.valid;
  return result;
}

CloseStatus close_locked(void* handle, yukilinker_c_error_detail* output) {
  yukilinker_c_error_detail error{};
  ErrorScope scope(&error, nullptr, true);
  if (exit_cleanup_uncertain()) {
    fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT);
    error.cleanup_incomplete = 1;
    if (output) *output = error;
    return YUKILINKER_C_CLOSE_ERROR;
  }
  auto* image = state_of(static_cast<SoHandle*>(handle));
  // A handle with no reference left is refused, unless it names a dead copy: Closing, still
  // registered (state_of found it by its full token). A close of
  // that retries its retirement, releasing no reference (it has none): the recovery path for an
  // unmap that failed. A token is matched in full and never names two registered images.
  const bool retry = image && !image->references && image->phase == Phase::Closing;
  // A reference an open still under way holds is not the caller's to give back.
  if (!image || (!committed_references(image) && !retry)) {
    fail(YUKILINKER_C_INVALID_HANDLE, YUKILINKER_C_RETIREMENT);
    if (output) *output = error;
    return YUKILINKER_C_CLOSE_ERROR;
  }
  // The reference goes first, before the collection below can drop the lock to wait for another
  // thread's collection: module_dlclose decides its SELF_CLOSE pin right before this call, as of
  // this decrement.
  if (committed_references(image)) --image->references;
  bool collected = collect_after_close(image);
  collected &= !error.cleanup_incomplete;
  if (output) *output = error;
  return !collected                                 ? YUKILINKER_C_CLOSE_ERROR
         : state_of(static_cast<SoHandle*>(handle)) ? YUKILINKER_C_RETAINED
                                                    : YUKILINKER_C_CLOSED;
}

CloseStatus loader_close_impl(void* handle, yukilinker_c_error_detail* output) {
  OperationGuard operation;
  return close_locked(handle, output);
}

#if YUKILINKER_FULL
struct DlErrorState {
  bool pending = false;
  char text[256]{};
  // The refusal that decided this thread's last failed operation (publish_refusal).
  OperationRefusal refusal;
};
// The key's destructor is libc free, which runs no destructor of its own.
static_assert(std::is_trivially_destructible_v<DlErrorState>);

// Each thread's private dlerror record, apart from ThreadTlsState. The key's destructor is libc
// free, so a thread that only saw a failure runs no runtime code when it exits.
pthread_key_t g_dl_error_key;
bool g_dl_error_key_valid = false;

// A failure whose thread has no record and cannot get one is kept in a spare slot, for that thread
// only, under the operation lock. Once its dlerror returns the text, the slot is lent to that
// thread until its next failing private dl* call, where Bionic overwrites its buffer. A failure
// takes its thread's own slot, else a free one. A slot lent to another thread or holding its unread
// failure is never taken: when all are held, the new failure is dropped and logged. An exited
// thread keeps its slot until a fork, or until a thread given its id takes it, unread text and all.
struct SpareDlError {
  DlErrorState state;
  pthread_t thread{};
  bool lent = false;
};
constexpr size_t kSpareDlErrors = 8;
SpareDlError g_spare_dl_errors[kSpareDlErrors];
#endif  // #if YUKILINKER_FULL

#if YUKILINKER_FULL
// The thread holding the fork locks, and whether the runtime's atfork handler took them rather
// than an explicit prepare_fork. Written under the locks: a thread reads itself as the owner only
// if it took them.
pthread_t g_fork_owner;
// The owner's tid in the parent: the child's gettid() differs, and its load_waits slots carry this.
int32_t g_fork_tid;
bool g_fork_by_handler;
// Explicit prepare_fork calls the owner made while it held the locks; each after_fork gives one
// back.
unsigned g_fork_brackets;
// Whether this fork's prepare handler took the locks. libc's atfork lock serializes forks from the
// prepare handlers to the parent handlers, and a child has only the forking thread.
bool g_fork_handler_took;
// The runtime's atfork handlers are registered under this dso, which nothing else uses, so only
// __cxa_finalize(&g_fork_cookie) removes them.
char g_fork_cookie;
bool g_fork_handlers;

bool fork_locks_mine() {
  return __atomic_load_n(&g_fork_locked, __ATOMIC_ACQUIRE) &&
         pthread_equal(__atomic_load_n(&g_fork_owner, __ATOMIC_RELAXED), pthread_self());
}

// Takes every lock a fork must not split; false once shutdown has retired the keys.
bool lock_for_fork(bool handler) {
  operation_lock();
  if (!g_operation_depth_valid) {
    operation_unlock();
    return false;
  }
  // g_tls_mutex is not taken: every holder also holds the operation lock with signals blocked,
  // so it is free at fork, and a first TLS touch on this thread (a signal handler, a
  // pthread_atfork handler) can still make its block.
  pthread_mutex_lock(&g_exit_mutex);
  pthread_mutex_lock(&g_registry_mutex);
  pthread_mutex_lock(&g_metadata_mutex);
  pthread_mutex_lock(&g_key_mutex);
  g_fork_by_handler = handler;
  g_fork_brackets = 0;
  __atomic_store_n(&g_fork_owner, pthread_self(), __ATOMIC_RELAXED);
  g_fork_tid = gettid();
  __atomic_store_n(&g_fork_locked, true, __ATOMIC_RELEASE);
  return true;
}

void unlock_after_fork(int child);

// The runtime's own atfork handlers. libc runs the prepare handlers in reverse registration order
// with its atfork lock held, so the lock order is libc's atfork lock, then the runtime's.
void fork_prepare() {
  g_fork_handler_took = false;
  // An explicit bracket of this thread may hold the locks already; its after_fork gives them back.
  if (!__atomic_load_n(&g_operation_depth_valid, __ATOMIC_ACQUIRE) || fork_locks_mine()) return;
  g_fork_handler_took = lock_for_fork(true);
}

void fork_parent() {
  if (!g_fork_handler_took) return;
  g_fork_handler_took = false;
  unlock_after_fork(0);
}

void fork_child() {
  if (g_fork_handler_took) unlock_after_fork(1);
}
#endif  // #if YUKILINKER_FULL

void loader_prepare_fork_impl() {
#if YUKILINKER_FULL
  // Before the keys exist or after shutdown there is nothing for a fork to protect.
  if (!__atomic_load_n(&g_operation_depth_valid, __ATOMIC_ACQUIRE)) return;
  // Called again by the thread that holds the locks, from a handler inside the fork it bracketed:
  // the matching after_fork gives this call back.
  if (fork_locks_mine()) {
    if (!g_fork_by_handler) ++g_fork_brackets;
    return;
  }
  // The runtime's atfork handlers lock inside fork(); locking here would invert their order.
  if (__atomic_load_n(&g_fork_handlers, __ATOMIC_ACQUIRE)) return;
  (void)lock_for_fork(false);
#endif
}

void loader_after_fork_impl(int child) {
#if YUKILINKER_FULL
  // Only a bracket gives back what a bracket took; the atfork handler releases its own.
  if (!fork_locks_mine() || g_fork_by_handler) return;
  if (g_fork_brackets != 0) {
    --g_fork_brackets;
    return;
  }
  unlock_after_fork(child);
#else
  (void)child;
#endif
}

#if YUKILINKER_FULL
// A vanished thread's TLS destructor will never return in the child. Its TLS is discarded below.
// All other in-flight calls must belong to the surviving thread for a parked close to resume.
bool resumable_close_after_fork(const ImageState* image, const CallbackGuard* frame,
                                const SnapshotGuard* snapshot) {
  if (image->phase != Phase::Closing || image->closing_pass || !image->lifecycle.initialized ||
      image->lifecycle.fini_thread || image->releasing)
    return false;
  if (!image->non_tls_calls && !image->caller_calls) return true;
  size_t active = 0, callers = 0;
  for (; frame; frame = frame->previous) {
    if (frame->image != image) continue;
    if (frame->caller_call)
      ++callers;
    else if (frame->code != CallbackGuard::Code::TlsDestructor)
      ++active;
  }
  for (; snapshot; snapshot = snapshot->previous)
    for (size_t i = 0; i < snapshot->count; ++i) active += snapshot->images[i] == image;
  return active == image->non_tls_calls && callers == image->caller_calls;
}

void unlock_after_fork(int child) {
  ScopedSignalBlocker signals(child != 0);
  if (child) {
    // An earlier child handler or signal may already have recovered this fork.
    if (!fork_locks_mine()) return;
    g_fork_handler_took = false;
  }
  __atomic_store_n(&g_fork_locked, false, __ATOMIC_RELEASE);
  __atomic_store_n(&g_fork_owner, pthread_t{}, __ATOMIC_RELAXED);
  // These normal mutexes were acquired by prepare on this very thread. Bionic's
  // normal unlock does not compare the old TID. Preserve their real lifetime and
  // release order in both libc and the detector; the TLS lock was never acquired.
  pthread_mutex_unlock(&g_key_mutex);
  pthread_mutex_unlock(&g_metadata_mutex);
  pthread_mutex_unlock(&g_registry_mutex);
  pthread_mutex_unlock(&g_exit_mutex);
  if (child) {
    abandon_exit_cleanup(pthread_self(), true);
    const uintptr_t depth = operation_depth();
    const auto recovered = recover_android_fork_mutex(&g_operation_mutex, depth);
    // Every waiting open was another thread's, and the child has none of them.
    pthread_cond_t idle = PTHREAD_COND_INITIALIZER_MONOTONIC_NP;
    memcpy(&g_load_wait_cond, &idle, sizeof(idle));
    for (auto* waiter = g_load_waiters; waiter; waiter = waiter->next)
      if (waiter->context) --waiter->context->waiting_opens;
    g_load_waiters = nullptr;
    wait_slots_keep_forker(g_fork_tid);
    // Only the forking thread is left to read a private failure or to hold a spare's text.
    for (auto& slot : g_spare_dl_errors) {
      if (pthread_equal(slot.thread, pthread_self())) continue;
      slot.state.pending = false;
      slot.lent = false;
    }
#if defined(YUKILINKER_RUNTIME)
    modules_after_fork();
#endif
    size_t admissions = recovered.restored_depth;
    auto* frames = static_cast<CallbackGuard*>(pthread_getspecific(g_callback_key));
    auto* snapshots = static_cast<SnapshotGuard*>(pthread_getspecific(g_snapshot_key));
    for (auto* image = g_first_image; image; image = image->next) {
      const bool paused_close = resumable_close_after_fork(image, frames, snapshots);
      // A finalization another thread was running has nobody left here: the next run resumes it.
      if (image->lifecycle.fini_thread &&
          !pthread_equal(image->lifecycle.fini_thread, pthread_self()))
        image->lifecycle.fini_thread = {};
      image->non_tls_calls = 0;
      image->tls_destructor_calls = 0;
      // The other threads' calls are gone with them; this thread's are counted again below.
      image->caller_calls = 0;
      // A paused close or a sealed context resumes only the finalizers that had not begun.
      if (image->phase == Phase::Closing && (paused_close || context_sealed(image->context)))
        continue;
      if (image->phase != Phase::Ready && !pthread_equal(image->loading_thread, pthread_self())) {
        image->phase = Phase::Retired;
        image->flags |= RTLD_NODELETE;
        image->nodelete_reasons |= YUKILINKER_C_NODELETE_FORK;
      }
    }
    for (auto* frame = frames; frame; frame = frame->previous) {
      // A call marker holds no admission, only its call's count (none once its call is over).
      if (frame->caller_call) {
        if (frame->image) ++frame->image->caller_calls;
        continue;
      }
      admissions += frame->depth;
      if (frame->image) ++frame->active_counter();
    }
    // Only this thread's iterations are left, and only they stay active.
    g_active_snapshots = nullptr;
    for (auto* snapshot = snapshots; snapshot; snapshot = snapshot->previous) {
      for (size_t i = 0; i < snapshot->count; ++i) ++snapshot->images[i]->non_tls_calls;
      if (!snapshot->waitable) continue;
      snapshot->next_active = g_active_snapshots;
      g_active_snapshots = snapshot;
    }
    if (g_collecting && !pthread_equal(g_collecting_thread, pthread_self())) g_collecting = false;
    // A create another thread had in progress has no thread left here to finish it.
    if (g_runtime_creating && !pthread_equal(g_runtime_creating_thread, pthread_self()))
      g_runtime_creating = false;
    // A shutdown another thread was resuming has nobody left to finish it: the next shutdown here
    // resumes it.
    if (g_shutdown_running && !pthread_equal(g_shutdown_thread, pthread_self()))
      g_shutdown_running = false;
    __atomic_store_n(&g_active_operations, admissions, __ATOMIC_RELEASE);
    // The threads that waited for the lock are not in the child.
    __atomic_store_n(&g_lock_waiters, size_t{0}, __ATOMIC_RELEASE);
    private_keys_after_fork();
    const uintptr_t child_identity = current_thread_identity(false);
    const pid_t child_tid = gettid();
    auto* thread = g_thread_states;
    while (thread) {
      auto* next = thread->next;
      // Bionic may already have cleared the key before entering its destructor on the forking
      // thread. Its callback still owns that state, even if a signal has created another one.
      if (thread->identity == child_identity)
        thread->tid = child_tid;
      else
        destroy_thread_tls_state(thread);
      thread = next;
    }
  }
  operation_unlock();
}
#endif  // #if YUKILINKER_FULL

LoaderStats loader_query_stats_impl() {
  OperationGuard operation;
  LoaderStats result{};
  result.arena_bytes = g_metadata_bytes;
  result.peak_arena_bytes = g_peak_metadata_bytes;
  for (auto* image = g_first_image; image; image = image->next) {
    ++result.images;
    result.mapped_bytes += image->memory.span;
    result.tls_blocks += image->tls_users;
    result.thread_destructors += image->thread_destructors;
  }
  for (auto* source = g_retained_sources; source; source = source->next)
    result.mapped_bytes += source->bytes;
#if defined(YUKILINKER_RUNTIME)
  // Caller stub pages stay mapped until runtime_destroy (a successful try_shutdown keeps them),
  // also those of retired images.
  size_t pages = 0;
  size_t bytes = 0;
  caller_stub_stats(&pages, &bytes);
  result.mapped_bytes += bytes;
#endif
  return result;
}

int loader_release_host_impl(void* handle) {
  OperationGuard operation;
  auto* image = state_of(static_cast<SoHandle*>(handle));
  {
#if YUKILINKER_FULL
    ScopedSignalBlocker signals;
#endif
    if (g_collecting || !image || !image->host || image->active_calls() || image->snapshot_refs ||
        image->lease_refs || image->tls.active || image->tls_users || image->thread_destructors ||
        image->references != 1)
      return 0;
#if YUKILINKER_FULL
    // A callback can reenter from an open that still holds this image. Core-owned callback
    // registrations, storage and control providers must also outlive their users.
    if (!sole_operation() || image->phase != Phase::Ready || has_private_key_destructor(image) ||
        image->binds_core_emutls || image->binds_core_wrapper)
      return 0;
    for (auto* dep = image->dependencies; dep; dep = dep->next)
      if (dep->emutls_control && (!dep->image || !dep->image->host)) return 0;
#endif
    for (auto* other = g_first_image; other; other = other->next) {
      if (other == image) continue;
      if (other->load_root == image) return 0;
      for (auto* dep = other->dependencies; dep; dep = dep->next)
        if (dep->image == image) return 0;
    }
    // A dependency close calls the host with the lock dropped. Seal registration before
    // signals or a host callback can acquire this image during handoff.
    image->releasing = true;
  }
  if (!close_dependencies(image)) {
    image->releasing = false;
    return 0;
  }
  unregister_image(image);
  discard_exit_callbacks(image);
  // The handoff is done, so a metadata page left mapped does not undo it: the page stays counted
  // in arena_bytes, and try_shutdown retries it and reports a failure.
  (void)free_image_state(image);
  return 1;
}

}  // namespace

ImageState* caller_image(void* address) {
  for (auto* image = g_first_image; image; image = image->next)
    if (image_contains(image, address)) return image;
  return nullptr;
}

#if YUKILINKER_FULL
void recover_early_fork_child() {
  // pthread_self survives fork, but Bionic's recursive mutex still names the parent's TID.
  // Complete the ordinary child recovery once, before even trying to acquire that mutex.
  if (fork_locks_mine() && g_fork_tid != gettid()) unlock_after_fork(1);
}

ScopedForkUnlock::ScopedForkUnlock() : suspended(fork_locks_mine()) {
  if (suspended) {
    ScopedSignalBlocker signals;
    by_handler = g_fork_by_handler;
    brackets = g_fork_brackets;
    unlock_after_fork(0);
  }
}

ScopedForkUnlock::~ScopedForkUnlock() {
  if (suspended) {
    ScopedSignalBlocker signals;
    // The enclosing operation keeps the runtime live.
    (void)lock_for_fork(by_handler);
    g_fork_brackets = brackets;
  }
}

// The runtime's handlers stay with libc until the runtime is terminal or unloaded.
void remove_fork_handlers() {
  if (!__atomic_exchange_n(&g_fork_handlers, false, __ATOMIC_SEQ_CST)) return;
  // Removes every entry under the cookie: the runtime's handlers and nothing else.
  __cxa_finalize(&g_fork_cookie);
}

void register_fork_handlers() {
  if (__register_atfork(fork_prepare, fork_parent, fork_child, &g_fork_cookie) != 0) return;
  __atomic_store_n(&g_fork_handlers, true, __ATOMIC_SEQ_CST);
  // A shutdown that finished meanwhile found nothing to remove.
  if (__atomic_load_n(&g_keys_retired, __ATOMIC_SEQ_CST)) remove_fork_handlers();
}

void retire_fork_handlers() {
  if (!__atomic_load_n(&g_keys_retired, __ATOMIC_SEQ_CST)) return;
  remove_fork_handlers();
  remove_process_exit_entries();
}

#if defined(YUKILINKER_RUNTIME)
// A system dlclose that skipped shutdown, or the bootstrap unloading an image it could not use,
// unmaps the handlers' code.
[[gnu::destructor]] void remove_fork_handlers_at_unload() {
  remove_fork_handlers();
  remove_process_exit_entries();
  // Stubs of a runtime no owner destroyed: their entries go with the runtime's text.
  (void)release_caller_stub_pages();
}
#endif  // #if defined(YUKILINKER_RUNTIME)

void retire_dl_error_key() {
  if (!__atomic_load_n(&g_dl_error_key_valid, __ATOMIC_ACQUIRE)) return;
  // Only this thread's record is freed: another thread may be exiting and freeing its own through
  // the key, and a live thread's record stays its memory once the key is gone.
  auto* own = static_cast<DlErrorState*>(pthread_getspecific(g_dl_error_key));
  (void)pthread_setspecific(g_dl_error_key, nullptr);
  __atomic_store_n(&g_dl_error_key_valid, false, __ATOMIC_RELEASE);
  pthread_key_delete(g_dl_error_key);
  free_object(own);
}
#endif  // #if YUKILINKER_FULL

namespace {

#if YUKILINKER_FULL
bool ensure_dl_error_key() {
  if (__atomic_load_n(&g_dl_error_key_valid, __ATOMIC_ACQUIRE)) return true;
  // A fork holds g_key_mutex while its atfork handlers run: such a failure takes the spare.
  if (g_fork_locked) return false;
  pthread_mutex_lock(&g_key_mutex);
  // libc free, never runtime code: a thread may exit after the runtime is unmapped.
  if (!g_dl_error_key_valid && !g_keys_retired && pthread_key_create(&g_dl_error_key, free) == 0)
    __atomic_store_n(&g_dl_error_key_valid, true, __ATOMIC_RELEASE);
  const bool valid = g_dl_error_key_valid;
  pthread_mutex_unlock(&g_key_mutex);
  return valid;
}

DlErrorState* dl_error_state() {
  if (!ensure_dl_error_key()) return nullptr;
  auto* state = static_cast<DlErrorState*>(pthread_getspecific(g_dl_error_key));
  if (state) return state;
  state = allocate_object<DlErrorState>();
  if (state && pthread_setspecific(g_dl_error_key, state) != 0) {
    free_object(state);
    state = nullptr;
  }
  return state;
}

// Clearing needs no record, so it never allocates one.
DlErrorState* existing_dl_error_state() {
  if (!__atomic_load_n(&g_dl_error_key_valid, __ATOMIC_ACQUIRE)) return nullptr;
  return static_cast<DlErrorState*>(pthread_getspecific(g_dl_error_key));
}

bool spare_in_use(const SpareDlError& slot) { return slot.state.pending || slot.lent; }

// Ends an operation for host_import_refusal: a failure decided by a refusal is kept, anything else
// clears what an earlier one kept. Clearing allocates nothing; a refusal this thread has no record
// for (no key, no memory) is dropped, and the query then reports none.
void publish_refusal(const yukilinker_c_error_detail& error, const OperationRefusal& refusal) {
  if (error.code != YUKILINKER_C_OK && refusal.set) {
    if (auto* state = dl_error_state()) state->refusal = refusal;
    return;
  }
  if (auto* state = existing_dl_error_state()) state->refusal.set = false;
}

}  // namespace

// A private dl* call (dlopen, android_dlopen_ext, dlsym, dlvsym) ends the thread's last operation
// as a public call does: its refusal slot is shared by every operation frame inside it, and when it
// returns, a failure keeps the refusal that decided it and anything else clears an older one. Each
// path reports through set_dl_error with a record of its own, so the outcome is passed to end().
// A call nested in another operation (a constructor's dlopen inside an open) leaves that to the
// outer one, which then decides from its own outcome.
class PrivateCall {
 public:
  PrivateCall()
      : previous_(g_operation_refusal),
        previous_call_(g_private_call_slot),
        outermost_(g_operation_refusal == nullptr) {
    if (!outermost_) return;
    g_operation_refusal = &refusal_;
    g_private_call_slot = &refusal_;
  }
  ~PrivateCall() {
    if (!outermost_) return;
    g_operation_refusal = previous_;
    g_private_call_slot = previous_call_;
  }
  PrivateCall(const PrivateCall&) = delete;
  PrivateCall& operator=(const PrivateCall&) = delete;
  PrivateCall(PrivateCall&&) = delete;
  PrivateCall& operator=(PrivateCall&&) = delete;

  template <typename T>
  T end(T result) {
    if (outermost_) {
      yukilinker_c_error_detail outcome{};
      outcome.code = result ? YUKILINKER_C_OK : YUKILINKER_C_UNSUPPORTED;
      publish_refusal(outcome, refusal_);
    }
    return result;
  }

 private:
  OperationRefusal refusal_;
  OperationRefusal* previous_;
  OperationRefusal* previous_call_;
  bool outermost_;
};

uint32_t api_host_import_refusal(yukilinker_c_host_import_refusal* refusal) {
  if (!refusal) return YUKILINKER_C_INVALID_HANDLE;
  if (refusal->size != sizeof(*refusal)) return YUKILINKER_C_UNSUPPORTED;
  const auto* state = existing_dl_error_state();
  if (!state || !state->refusal.set) return YUKILINKER_C_DEPENDENCY_MISSING;
  refusal->reason = state->refusal.reason;
  memcpy(refusal->library, state->refusal.library, sizeof(refusal->library));
  memcpy(refusal->symbol, state->refusal.symbol, sizeof(refusal->symbol));
  memcpy(refusal->version, state->refusal.version, sizeof(refusal->version));
  return YUKILINKER_C_OK;
}

namespace {

// This thread's spare slot: at most one holds an unread failure of it or is lent to it.
SpareDlError* own_spare_dl_error() {
  for (auto& slot : g_spare_dl_errors)
    if (spare_in_use(slot) && pthread_equal(slot.thread, pthread_self())) return &slot;
  return nullptr;
}

// A slot no thread holds, or null: a lent slot's reader may still read its text, and an unread
// failure is kept, so neither is ever taken from its thread.
SpareDlError* free_spare_dl_error() {
  for (auto& slot : g_spare_dl_errors)
    if (!spare_in_use(slot)) return &slot;
  return nullptr;
}

void set_dl_error(const yukilinker_c_error_detail& error) {
  // As in Bionic, a success changes nothing: an unread failure stays pending, and a pointer dlerror
  // returned stays valid.
  if (error.code == YUKILINKER_C_OK) return;
  // This failure is the thread's newest, so an unread host one is stale: Bionic's buffer would hold
  // only this. Read here, it leaves module_dlerror's host fallback empty. This drops the lock.
  (void)host_dlerror();
  SpareDlError* own = own_spare_dl_error();
  auto* state = dl_error_state();
  if (state) {
    // The record takes the newest failure. Bionic overwrites the buffer, so a loan ends too.
    if (own) {
      own->state.pending = false;
      own->lent = false;
    }
  } else {
    SpareDlError* slot = own ? own : free_spare_dl_error();
    if (!slot) {
      host_log_error("yukilinker: dlerror spare slots are full");
      return;
    }
    // Bionic overwrites the thread's buffer here, so this thread's loan of its slot ends.
    slot->thread = pthread_self();
    slot->lent = false;
    state = &slot->state;
  }
  state->pending = true;
  (void)snprintf(state->text, sizeof(state->text),
                 "YukiLinker: error=%u stage=%u symbol=%.128s%s%.64s", error.code, error.stage,
                 error.symbol, error.version[0] ? " version=" : "", error.version);
}

// A failed host call left its failure in the host's dlerror, this thread's newest one, so an older
// private one must not shadow it. A successful one leaves that pending, as in Bionic.
void yield_dl_error_to_host() {
  if (auto* state = existing_dl_error_state()) state->pending = false;
  if (SpareDlError* own = own_spare_dl_error()) own->state.pending = false;
}

char* module_dlerror() {
  // No lock and no operation, so shutdown does not wait for this and may delete the key meanwhile.
  // Bionic's pthread_getspecific then returns null (it checks the key's sequence), so this reads
  // this thread's own record or nothing: only this thread writes its record, and shutdown frees
  // only the record of the thread that runs it. Reading allocates nothing.
  if (auto* state = existing_dl_error_state(); state && state->pending) {
    state->pending = false;
    return state->text;
  }
  // A thread without a record has no private failure but a spare one; the slots are shared.
  OperationGuard operation;
  SpareDlError* slot = own_spare_dl_error();
  if (!slot || !slot->state.pending) return host_dlerror();
  slot->state.pending = false;
  // Read without the lock: no other thread takes a lent slot, so only this thread's next failing
  // private call writes it.
  slot->lent = true;
  return slot->state.text;
}

// Unknown flags fail before any lookup, provider call, open or host call, as in Bionic.
bool reject_open_flags(int flags) {
  if ((static_cast<uint32_t>(flags) & ~kSupportedOpenFlags) == 0) return false;
  yukilinker_c_error_detail error{};
  error.code = YUKILINKER_C_UNSUPPORTED;
  set_dl_error(error);
  return true;
}

// The first image of the caller's context named name, by origin or soname, that this thread may
// use, or one the failure sweep of this thread's own open is releasing (the open refuses that one).
// *loading is set to the first one an open waits for: another thread is still loading it, or
// another thread's collection is retiring it.
ImageState* named_image(const ImageState* caller, const char* name, ImageState** loading) {
  *loading = nullptr;
  for (auto* image = g_first_image; image; image = image->next) {
    if (image->context != caller->context ||
        (strcmp(image->origin, name) != 0 && (!image->soname || strcmp(image->soname, name) != 0)))
      continue;
    if (accessible_image(image) || released_here(image)) return image;
    if (!*loading && awaited_image(image)) *loading = image;
  }
  return nullptr;
}

void* module_open_body(ImageState* caller, const char* name, int flags);

void* module_open_for(ImageState* caller, const char* name, int flags) {
  PrivateCall call;
  return call.end(module_open_body(caller, name, flags));
}

void* module_open_body(ImageState* caller, const char* name, int flags) {
  if (reject_open_flags(flags)) return nullptr;
  if (!caller || !name) {
    void* handle;
    {
      CallbackGuard callback_scope(caller);
      handle = host_dlopen(name, flags, nullptr, caller);
    }
    if (!handle) yield_dl_error_to_host();
    return handle;
  }
  ImageState* loading = nullptr;
  // A context under retirement admits no open, not even one that only takes a reference.
  if (context_sealed(caller->context)) {
    yukilinker_c_error_detail sealed{};
    sealed.code = YUKILINKER_C_BUSY;
    sealed.stage = YUKILINKER_C_RETIREMENT;
    set_dl_error(sealed);
    return nullptr;
  }
  ImageState* image = named_image(caller, name, &loading);
#if YUKILINKER_FULL
  uint64_t waited_since = 0;
  while (!image && loading && wait_for_load(loading, caller->context, caller, &waited_since))
    image = named_image(caller, name, &loading);
#endif  // #if YUKILINKER_FULL
  if (image) {
    // As for a root open that deduplicates to it, an image still preparing is not handed out, and
    // neither is one a failure sweep is releasing. One past relocation is: Bionic lets a
    // constructor open its own library, and runs the constructors of one that has not run them.
    // A wait above dropped the lock, and the context may have been sealed meanwhile.
    if (image->phase == Phase::Preparing || image->releasing || context_sealed(image->context)) {
      yukilinker_c_error_detail busy{};
      busy.code = YUKILINKER_C_BUSY;
      busy.stage =
          context_sealed(image->context) ? YUKILINKER_C_RETIREMENT : YUKILINKER_C_INITIALIZATION;
      set_dl_error(busy);
      return nullptr;
    }
    ++image->references;
    ++image->pending_references;
    const AddedOpenFlags added = add_open_flags(image, static_cast<uint32_t>(flags));
    // As Bionic's dlopen, the open runs the constructors of the image it returns. A relocated
    // image belongs to an open of this thread that has not run them yet; a failure there revokes
    // the reference and takes back the flags this open added.
    yukilinker_c_error_detail error{};
    if (image->phase == Phase::Relocated) {
      ErrorScope scope(&error);
      if (!initialize_reused(image)) {
        remove_open_flags(image, added);
        image = nullptr;
      }
    }
    // Committed, and the token taken, before set_dl_error, which can drop the lock.
    if (image) --image->pending_references;
    void* token = image ? public_token(image) : nullptr;
    set_dl_error(error);
    return token;
  }
  char path[4096]{};
  const char* origin = nullptr;
  bool by_path = false;
  int fd = open_private_dependency(caller, name, path, sizeof(path), &origin, &by_path);
  if (fd < 0) {
#if YUKILINKER_FULL
    const LinkResolution linked = resolve_through_links(caller, name, flags);
    yukilinker_c_error_detail refused{};
    switch (linked.outcome) {
      case LinkOutcome::kImage:
        // Only a reference: the open's flags stay with the namespace that loaded the image.
        ++linked.image->references;
        return public_token(linked.image);
      case LinkOutcome::kSystem:
        return linked.system_handle;
      case LinkOutcome::kBusy:
        refused.code = YUKILINKER_C_BUSY;
        break;
      case LinkOutcome::kDenied:
        refused.code = YUKILINKER_C_PERMISSION_DENIED;
        break;
      case LinkOutcome::kMissing:
        refused.code = YUKILINKER_C_DEPENDENCY_MISSING;
        break;
      case LinkOutcome::kUnlinked:
        break;
    }
    if (refused.code != YUKILINKER_C_OK) {
      refused.stage = YUKILINKER_C_DEPENDENCIES;
      set_dl_error(refused);
      return nullptr;
    }
#endif  // #if YUKILINKER_FULL
    if (caller->namespace_id != 0) {
      void* handle;
      {
        CallbackGuard callback_scope(caller);
        handle = host_dlopen_reported(name, flags | RTLD_NOLOAD, caller);
      }
      yukilinker_c_error_detail error{};
      if (!handle) {
        error.code = YUKILINKER_C_DEPENDENCY_MISSING;
        error.stage = YUKILINKER_C_DEPENDENCIES;
      }
      set_dl_error(error);
      return handle;
    }
    void* handle;
    {
      CallbackGuard callback_scope(caller);
      handle = host_dlopen(name, flags, nullptr, caller);
    }
    if (!handle) yield_dl_error_to_host();
    return handle;
  }
  LoadOptions options{
      sizeof(options), static_cast<uint32_t>(flags), caller->memory.file_backed, 0, origin,
      caller->context};
  yukilinker_c_error_detail error{};
  void* handle = api_open_fd_offset(fd, &options, 0, &error, nullptr, nullptr, by_path);
  host_close_fd(fd);
  set_dl_error(error);
  return handle;
}

pid_t module_fork() {
  OperationGuard operation;
  // The caller's code runs on in both processes once fork returns: counted as one of its own calls
  // into the runtime, so a close on another thread meanwhile keeps it (a return-address hold).
  ImageState* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  pid_t result;
  int saved_errno;
  {
    // No runtime lock across the host's hooks and fork(): the hooks may call back in, and the
    // runtime's atfork handlers take the lock inside fork() in libc's order. A host-call frame, so
    // nothing this thread does inside it waits for another thread.
    CallbackGuard host_scope(nullptr);
    host_fork_hook(YUKILINKER_C_HOST_FORK_PREPARE);
    // The runtime's atfork handlers lock inside fork(); the brackets lock only if they could not
    // be registered.
    loader_prepare_fork_impl();
    result = ::fork();
    saved_errno = errno;
    loader_after_fork_impl(result == 0);
    host_fork_hook(result == 0 ? YUKILINKER_C_HOST_FORK_CHILD : YUKILINKER_C_HOST_FORK_PARENT);
  }
  errno = saved_errno;
  return result;
}

void* module_dlopen(const char* name, int flags) {
  OperationGuard operation;
  ImageState* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  return module_open_for(caller, name, flags);
}

void* android_dlopen_ext_for(ImageState* caller, const char* name, int flags,
                             const android_dlextinfo* ext);

void* module_android_dlopen_ext(const char* name, int flags, const android_dlextinfo* ext) {
  OperationGuard operation;
  ImageState* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  return android_dlopen_ext_for(caller, name, flags, ext);
}

void* android_dlopen_ext_body(ImageState* caller, const char* name, int flags,
                              const android_dlextinfo* ext);

void* android_dlopen_ext_for(ImageState* caller, const char* name, int flags,
                             const android_dlextinfo* ext) {
  PrivateCall call;
  return call.end(android_dlopen_ext_body(caller, name, flags, ext));
}

void* android_dlopen_ext_body(ImageState* caller, const char* name, int flags,
                              const android_dlextinfo* ext) {
  if (reject_open_flags(flags)) return nullptr;
  if (!ext || !ext->flags) return module_open_body(caller, name, flags);
  auto* namespace_token = (ext && (ext->flags & ANDROID_DLEXT_USE_NAMESPACE))
                              ? find_namespace(ext->library_namespace)
                              : nullptr;
  constexpr uint64_t placement_flags =
      ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_RESERVED_ADDRESS_HINT;
  constexpr uint64_t relro_flags = ANDROID_DLEXT_WRITE_RELRO | ANDROID_DLEXT_USE_RELRO;
  const bool has_placement = (ext->flags & placement_flags) != 0;
  if (!caller || !(ext->flags & ANDROID_DLEXT_USE_LIBRARY_FD) ||
      (ext->flags & ~(ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD |
                      ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET | ANDROID_DLEXT_USE_NAMESPACE |
                      placement_flags | relro_flags)) ||
      ((ext->flags & placement_flags) == placement_flags) ||
      (has_placement &&
       ((reinterpret_cast<uintptr_t>(ext->reserved_addr) % loader_page_size()) ||
        (ext->reserved_size % loader_page_size()) ||
        ext->reserved_size > UINTPTR_MAX - reinterpret_cast<uintptr_t>(ext->reserved_addr) ||
        (ext->reserved_size && !ext->reserved_addr))) ||
      ((ext->flags & ANDROID_DLEXT_USE_NAMESPACE) && !namespace_token) ||
      (!(ext->flags & ANDROID_DLEXT_USE_NAMESPACE) && ext->library_namespace) ||
      ((ext->flags & relro_flags) && ext->relro_fd < 0) ||
      ((ext->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) &&
       (ext->library_fd_offset < 0 ||
        (static_cast<uint64_t>(ext->library_fd_offset) % loader_page_size()) != 0))) {
    yukilinker_c_error_detail error{};
    error.code = YUKILINKER_C_UNSUPPORTED;
    set_dl_error(error);
    return nullptr;
  }
  int relro_fd = -1;
  if (ext->flags & relro_flags) {
    struct stat source_status{}, relro_status{};
    const int access = fcntl(ext->relro_fd, F_GETFL);
    const bool write_relro = (ext->flags & ANDROID_DLEXT_WRITE_RELRO) != 0;
    const bool invalid_fd =
        fstat(ext->library_fd, &source_status) != 0 || fstat(ext->relro_fd, &relro_status) != 0 ||
        access < 0 || !S_ISREG(relro_status.st_mode) ||
        (source_status.st_dev == relro_status.st_dev &&
         source_status.st_ino == relro_status.st_ino) ||
        (access & O_APPEND) ||
        (write_relro ? (access & O_ACCMODE) != O_RDWR : (access & O_ACCMODE) == O_WRONLY);
    if (!invalid_fd) relro_fd = fcntl(ext->relro_fd, F_DUPFD_CLOEXEC, 0);
    if (invalid_fd || relro_fd < 0) {
      yukilinker_c_error_detail error{};
      error.code = invalid_fd ? YUKILINKER_C_UNSUPPORTED : YUKILINKER_C_IO_ERROR;
      set_dl_error(error);
      return nullptr;
    }
  }
  LoadOptions options{sizeof(options),
                      static_cast<uint32_t>(flags),
                      caller->memory.file_backed,
                      0,
                      name,
                      namespace_token ? namespace_token->context : caller->context};
  yukilinker_c_error_detail error{};
  options.force_load = (ext->flags & ANDROID_DLEXT_FORCE_LOAD) != 0;
  const uint64_t source_offset = (ext->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET)
                                     ? static_cast<uint64_t>(ext->library_fd_offset)
                                     : 0;
  const LoadPlacement placement{ext->reserved_addr, ext->reserved_size,
                                (ext->flags & ANDROID_DLEXT_RESERVED_ADDRESS_HINT) != 0};
  const RelroOptions relro{relro_fd, (ext->flags & ANDROID_DLEXT_WRITE_RELRO) != 0,
                           (ext->flags & relro_flags) != 0};
  void* handle =
      api_open_fd_offset(ext->library_fd, &options, source_offset, &error,
                         has_placement ? &placement : nullptr, relro_fd >= 0 ? &relro : nullptr);
  if (relro_fd >= 0) (void)host_close_fd(relro_fd);
  set_dl_error(error);
  return handle;
}

void* module_lookup_body(ImageState* caller, void* handle, const char* name, const char* version,
                         bool* failed);

// A lookup that found a symbol of value 0 still succeeded; only a reported failure counts.
void* module_lookup_for(ImageState* caller, void* handle, const char* name, const char* version) {
  PrivateCall call;
  bool failed = false;
  void* address = module_lookup_body(caller, handle, name, version, &failed);
  call.end(!failed);
  return address;
}

void* module_lookup_body(ImageState* caller, void* handle, const char* name, const char* version,
                         bool* failed) {
  const bool pseudo = pseudo_handle(handle);
  if ((pseudo && caller) ||
      (!pseudo && (private_token(handle) || state_of(static_cast<SoHandle*>(handle))))) {
    auto result = lookup_locked(handle, name, version, caller);
    set_dl_error(result.error);
    *failed = result.error.code != YUKILINKER_C_OK;
    return result.address;
  }
  void* address = nullptr;
  bool found;
  {
    CallbackGuard callback_scope(caller);
    found = host_dlsym(handle, name, version, &address);
  }
  yukilinker_c_error_detail error{};
  if (!found) {
    error.code = YUKILINKER_C_SYMBOL_MISSING;
    (void)snprintf(error.symbol, sizeof(error.symbol), "%s", name ? name : "");
    if (version) (void)snprintf(error.version, sizeof(error.version), "%s", version);
  }
  set_dl_error(error);
  *failed = !found;
  return address;
}

#if defined(YUKILINKER_RUNTIME)

// The image a caller stub names, by its generation: any registered one, as caller_image takes any
// registered image the return address lies in (a destructor of a Closing image is a caller too;
// the open or lookup then applies its own rules). Once the image is unregistered, null with a
// dlerror saying the caller is gone. Never the host's path: a stub's caller is a namespace image,
// which must not reach the system's global group by a fallback.
ImageState* stub_caller(uintptr_t binding) {
  ImageState* image = image_by_generation(caller_stub_generation(binding));
  if (image) return image;
  yukilinker_c_error_detail retired{};
  retired.code = YUKILINKER_C_INVALID_HANDLE;
  retired.stage = YUKILINKER_C_RETIREMENT;
  (void)snprintf(retired.symbol, sizeof(retired.symbol), "%s", "caller image retired");
  set_dl_error(retired);
  return nullptr;
}

}  // namespace
}  // namespace yukilinker::internal

using namespace yukilinker::internal;  // NOLINT(google-build-using-namespace)

extern "C" void* yuki_caller_dlopen_from(const char* name, int flags, uintptr_t binding) {
  OperationGuard operation;
  ImageState* caller = stub_caller(binding);
  CallerCall call(caller);
  return caller ? module_open_for(caller, name, flags) : nullptr;
}

extern "C" void* yuki_caller_android_dlopen_ext_from(const char* name, int flags,
                                                     const android_dlextinfo* ext,
                                                     uintptr_t binding) {
  OperationGuard operation;
  ImageState* caller = stub_caller(binding);
  CallerCall call(caller);
  return caller ? android_dlopen_ext_for(caller, name, flags, ext) : nullptr;
}

extern "C" void* yuki_caller_dlsym_from(void* handle, const char* name, uintptr_t binding) {
  OperationGuard operation;
  ImageState* caller = stub_caller(binding);
  CallerCall call(caller);
  return caller ? module_lookup_for(caller, handle, name, nullptr) : nullptr;
}

extern "C" void* yuki_caller_dlvsym_from(void* handle, const char* name, const char* version,
                                         uintptr_t binding) {
  OperationGuard operation;
  ImageState* caller = stub_caller(binding);
  CallerCall call(caller);
  return caller ? module_lookup_for(caller, handle, name, version) : nullptr;
}

extern "C" int yuki_caller_dl_iterate_phdr_from(PrivateDlIterateCallback callback, void* user,
                                                uintptr_t binding) {
  OperationGuard operation;
  ImageState* caller = stub_caller(binding);
  return caller ? module_dl_iterate_phdr_for(caller, callback, user) : 0;
}

namespace yukilinker::internal {
namespace {
#endif  // #if defined(YUKILINKER_RUNTIME)

void* module_dlsym(void* handle, const char* name) {
  OperationGuard operation;
  ImageState* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  return module_lookup_for(caller, handle, name, nullptr);
}

void* module_dlvsym(void* handle, const char* name, const char* version) {
  OperationGuard operation;
  ImageState* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  return module_lookup_for(caller, handle, name, version);
}

// A private dlclose can drop the last open that keeps its caller mapped while the caller's code
// still runs after the call returns; Bionic unloads before dlclose returns and has no such case.
// The caller's load root is then pinned (RTLD_NODELETE, YUKILINKER_C_NODELETE_SELF_CLOSE): a leak
// instead of an unmap under running code. A caller counts as kept while a durable holder reaches it
// over mark_image's edges through durable steps. Active calls, snapshots, leases, TLS blocks and
// thread destructors go on their own and never count.

// An image whose edges last as long as what holds it. Collection frees a Closing one once its pins
// go, NODELETE or not (CALLBACK_REENTRY is only ever set on a Closing image), and another open's
// failure sweep can release an image that open is loading or has failed, with its edges, before
// any of its code ran. The caller's own group ran code, so its failure keeps it (FAILED_EXECUTION).
bool durable_step(const ImageState* image, const ImageState* group) {
  return image->phase == Phase::Ready || image->phase == Phase::Retired ||
         (image->load_root == group && image->phase != Phase::Closing);
}

// Holds what it reaches until someone closes or unloads it: RTLD_NODELETE or RTLD_GLOBAL (which
// only an explicit retirement unloads), the caller's own open in progress, or an open of a Ready
// image. The close under test takes one of dropped's opens. A holder has to be a durable step as
// well (reaches_caller checks it first): another open's failure sweep releases even a NODELETE
// image of that open.
bool durable_holder(const ImageState* image, const ImageState* group, const ImageState* dropped) {
  if (image->flags & (RTLD_NODELETE | RTLD_GLOBAL)) return true;
  if (image->load_root == group && image_loading(image)) return true;
  return image->phase == Phase::Ready && image->references > (image == dropped ? 1U : 0U);
}

// Whether image reaches caller over mark_image's edges, only through durable steps if asked.
bool reaches_caller(ImageState* image, const ImageState* caller, uint64_t visit, bool durable) {
  if (!image) return false;
  if (image == caller) return true;
  if (image->graph_visit == visit) return false;
  image->graph_visit = visit;
  if (durable && !durable_step(image, caller->load_root)) return false;
  if (image->load_root != image && reaches_caller(image->load_root, caller, visit, durable))
    return true;
  for (auto* dep = image->dependencies; dep; dep = dep->next)
    if (reaches_caller(dep->image, caller, visit, durable)) return true;
  return false;
}

// One walk for all holders: a step one holder reached without finding the caller leads nowhere
// from another holder either.
bool durably_kept(const ImageState* caller, const ImageState* dropped) {
  const uint64_t visit = ++g_graph_visit;
  for (auto* image = g_first_image; image; image = image->next)
    if (durable_holder(image, caller->load_root, dropped) &&
        reaches_caller(image, caller, visit, true))
      return true;
  return false;
}

int module_dlclose_body(void* handle, ImageState* caller);

// A private dlclose ends the thread's last operation as the other private dl* calls do: it keeps
// no refusal, so an older one is cleared whichever path it takes (a pseudo-handle, the host's, a
// private image).
int module_dlclose(void* handle) {
  OperationGuard operation;
  auto* caller = caller_image(__builtin_return_address(0));
  CallerCall call(caller);
  PrivateCall private_call;
  const int result = module_dlclose_body(handle, caller);
  return private_call.end(result == 0) ? 0 : -1;
}

int module_dlclose_body(void* handle, ImageState* caller) {
  yukilinker_c_error_detail error{};
  // A pseudo-handle names no image. Bionic would take LP32's RTLD_NEXT for a soinfo pointer, so
  // neither goes to the host.
  if (pseudo_handle(handle)) {
    error.code = YUKILINKER_C_INVALID_HANDLE;
    error.stage = YUKILINKER_C_RETIREMENT;
    set_dl_error(error);
    return -1;
  }
  if (!private_token(handle) && !state_of(static_cast<SoHandle*>(handle))) {
    int result;
    {
      CallbackGuard callback_scope(caller);
      result = host_dlclose(handle);
    }
    if (result != 0) yield_dl_error_to_host();
    return result;
  }
  // A Closing caller, a finalizer's dlclose, retires anyway.
  const bool guarded = caller && caller->phase != Phase::Closing;
  // loader_close_impl takes a reference only from an image that has one; any other close drops
  // nothing.
  auto* target = state_of(static_cast<SoHandle*>(handle));
  const bool takes = target && committed_references(target) > 0;
  // Decided in the lock hold in which loader_close_impl takes that reference: it reaches its
  // decrement without dropping the lock, so nothing can take the target's place in between. A wait
  // added to loader_close_impl has to come after the decrement.
  const bool kept = guarded && durably_kept(caller, takes ? target : nullptr);
  bool pin = guarded && !kept && takes && reaches_caller(target, caller, ++g_graph_visit, false);
  if (caller) ++caller->non_tls_calls;
  auto result = loader_close_impl(handle, &error);
  if (caller) {
    // The finalizers this close ran, or another thread while it dropped the lock, can have let
    // the last holder go too. The pin stands whatever loader_close_impl reports.
    pin = pin || (kept && !durably_kept(caller, nullptr));
    if (pin) {
      caller->load_root->flags |= RTLD_NODELETE;
      caller->load_root->nodelete_reasons |= YUKILINKER_C_NODELETE_SELF_CLOSE;
    }
    --caller->non_tls_calls;
  }
  set_dl_error(error);
  return result == YUKILINKER_C_CLOSE_ERROR ? -1 : 0;
}

int module_dladdr(const void* address, Dl_info* info) {
  OperationGuard operation;
  auto* image = caller_image(const_cast<void*>(address));
  if (!image) return host_dladdr(address, info);
  if (!info) return 0;
  *info = {};
  info->dli_fname = image->origin;
  info->dli_fbase = image->memory.reservation;
  // As Bionic's find_symbol_by_address: the first symbol that contains the address. With a GNU
  // table only the hashed symbols count; linkers sort them by bucket, so index order is Bionic's.
  const auto bias = reinterpret_cast<uintptr_t>(image->memory.bias);
  const uintptr_t offset = reinterpret_cast<uintptr_t>(address) - bias;
  const auto& symbols = image->symbols;
  for (size_t i = symbols.gnu_hash ? symbols.gnu_hash[1] : 0; i < symbols.count; ++i) {
    const auto& symbol = symbols.entries[i];
    if (symbol.st_shndx == SHN_UNDEF || ELF64_ST_TYPE(symbol.st_info) == STT_TLS ||
        offset < symbol.st_value || offset - symbol.st_value >= symbol.st_size)
      continue;
    info->dli_sname = symbols.strings + symbol.st_name;
    info->dli_saddr = reinterpret_cast<void*>(bias + symbol.st_value);
    break;
  }
  return 1;
}
#endif

void* module_api_symbol_impl(const char* name) {
  if (strcmp(name, "__cxa_atexit") == 0) return reinterpret_cast<void*>(module_cxa_atexit);
  if (strcmp(name, "__cxa_finalize") == 0) return reinterpret_cast<void*>(module_cxa_finalize);
  if (strcmp(name, "__cxa_thread_atexit_impl") == 0 || strcmp(name, "__cxa_thread_atexit") == 0)
    return reinterpret_cast<void*>(module_thread_atexit);
#if YUKILINKER_FULL
  if (strcmp(name, arch::kTlsGetAddr) == 0) {
#if defined(__i386__)
    return reinterpret_cast<void*>(yuki_tls_get_addr_i386);
#else
    return reinterpret_cast<void*>(yuki_tls_get_addr);
#endif
  }
  if (strcmp(name, "fork") == 0) return reinterpret_cast<void*>(module_fork);
  if (strcmp(name, "dlopen") == 0) return reinterpret_cast<void*>(module_dlopen);
  if (strcmp(name, "android_dlopen_ext") == 0)
    return reinterpret_cast<void*>(module_android_dlopen_ext);
  if (strcmp(name, "dlsym") == 0) return reinterpret_cast<void*>(module_dlsym);
  if (strcmp(name, "dlvsym") == 0) return reinterpret_cast<void*>(module_dlvsym);
  if (strcmp(name, "dlclose") == 0) return reinterpret_cast<void*>(module_dlclose);
  if (strcmp(name, "dlerror") == 0) return reinterpret_cast<void*>(module_dlerror);
  if (strcmp(name, "dladdr") == 0) return reinterpret_cast<void*>(module_dladdr);
  if (strcmp(name, "dl_iterate_phdr") == 0) return reinterpret_cast<void*>(module_dl_iterate_phdr);
#if defined(__arm__)
  if (strcmp(name, "dl_unwind_find_exidx") == 0)
    return reinterpret_cast<void*>(module_dl_unwind_find_exidx);
#endif
#endif
  return nullptr;
}

}  // namespace

void* module_api_symbol(const char* name) { return module_api_symbol_impl(name); }

int runtime_try_shutdown(yukilinker_c_error_detail* error) {
  OperationGuard operation;
  yukilinker_c_error_detail result{};
  ErrorScope scope(&result);
#if YUKILINKER_FULL
  // Before the boundary a refusal is YUKILINKER_C_BUSY and changes nothing, or
  // YUKILINKER_C_IO_ERROR when only an earlier leak could not be unmapped again. Past it a 0 never
  // means BUSY: YUKILINKER_C_RETRY (another call in flight, or one resuming), YUKILINKER_C_IO_ERROR
  // with cleanup_incomplete (an unmap failed), or YUKILINKER_C_UNSUPPORTED when what is left can
  // never be retired. The next call resumes.
  if (g_shutdown_phase == ShutdownPhase::kShutDown) {
    if (error) {
      *error = {};
      error->cleanup_incomplete = host_close_leaked() ? 1 : 0;
    }
    return 1;
  }
  bool done = false;
  if (!g_shutdown_running) {
    if (!shutdown_begun()) {
      // No collection before the boundary: a refusal changes nothing. finish_shutdown retires
      // what nothing keeps, past it.
      const uint32_t begun = begin_shutdown();
      if (begun != YUKILINKER_C_OK) {
        fail(begun, YUKILINKER_C_RETIREMENT);
        if (error) *error = result;
        return 0;
      }
    }
    done = finish_shutdown();
  }
  if (done) {
    // A failure an earlier collection reported was resolved since: the shutdown succeeded. A host
    // import the system failed to close is still reported: the runtime may be unmapped, but that
    // library stays loaded.
    result = {};
    result.cleanup_incomplete = host_close_leaked() ? 1 : 0;
    if (error) *error = result;
    return 1;
  }
  if (shutdown_unfinishable()) {
    result.code = YUKILINKER_C_UNSUPPORTED;
    result.stage = YUKILINKER_C_RETIREMENT;
  } else {
    fail(YUKILINKER_C_RETRY, YUKILINKER_C_RETIREMENT);
  }
  if (error) *error = result;
  return 0;
#else
  collect_images();
  if (shutdown()) {
    result = {};
    if (error) *error = result;
    return 1;
  }
  fail(YUKILINKER_C_BUSY, YUKILINKER_C_RETIREMENT);
  if (error) *error = result;
  return 0;
#endif
}

CloseStatus api_close_locked(void* handle, yukilinker_c_error_detail* output) {
  return close_locked(handle, output);
}

void* loader_create_context(const char* path, yukilinker_c_dependency_provider provider,
                            void* user) {
  return loader_create_context_impl(path, provider, user);
}
int loader_destroy_context(void* opaque) { return loader_destroy_context_impl(opaque); }
void* loader_open_fd(int fd, const LoadOptions* options, yukilinker_c_error_detail* output) {
  return loader_open_fd_impl(fd, options, output);
}
void* loader_open_path(const char* path, const LoadOptions* options,
                       yukilinker_c_error_detail* error) {
  return loader_open_path_impl(path, options, error);
}
LookupValue loader_lookup(void* handle, const char* name, const char* version) {
  OperationGuard operation;
  return lookup_locked(handle, name, version, nullptr);
}
CloseStatus loader_close(void* handle, yukilinker_c_error_detail* output) {
  return loader_close_impl(handle, output);
}
void loader_prepare_fork() { loader_prepare_fork_impl(); }
void loader_after_fork(int child) { loader_after_fork_impl(child); }
LoaderStats loader_query_stats() { return loader_query_stats_impl(); }
int loader_release_host(void* handle) { return loader_release_host_impl(handle); }

}  // namespace yukilinker::internal
