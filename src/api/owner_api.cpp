// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../internal/caller_stubs.hpp"
#include "../internal/host_imports.hpp"
#include "../internal/registry.hpp"
#include "../internal/runtime_model.hpp"

namespace yukilinker::internal {

// Matches the current owner whether or not it still admits calls.
Runtime* owner_from(void* opaque) {
  if (opaque == nullptr || opaque != g_runtime_owner) return nullptr;
  auto* runtime = static_cast<Runtime*>(opaque);
  return runtime->magic == Runtime::kMagic ? runtime : nullptr;
}

// Callers hold an OperationGuard, so the owner cannot retire between this check and the call.
Runtime* runtime_from(void* opaque) {
  auto* runtime = owner_from(opaque);
  return runtime != nullptr && runtime->active ? runtime : nullptr;
}

// A stale owner overwrites the caller's error record instead of leaving old contents behind.
void report_stale(yukilinker_c_error_detail* error, uint32_t stage) {
  if (error == nullptr) return;
  *error = {};
  error->code = YUKILINKER_C_STALE_TOKEN;
  error->stage = stage;
}

// Shared by try_shutdown and runtime_destroy. On success the default host table is back in
// place and the owner admits nothing but runtime_destroy. The owner goes inactive at the
// shutdown's boundary (begin_shutdown), not before: a refusal leaves it as it was.
bool retire_runtime(Runtime* owner, yukilinker_c_error_detail* error) {
  if (!runtime_try_shutdown(error)) return false;
  owner->active = false;
  owner->shut_down = true;
  publish_host_services(nullptr);
  return true;
}

void* owner_runtime_create(const void* host_services) {
  const auto* services = static_cast<const yukilinker_c_host_services*>(host_services);
  if (!validate_host_services(services)) return nullptr;
  if (!ensure_operation_keys()) return nullptr;
  // The table belongs to the caller, so it is copied out before the owner keeps it.
  yukilinker_c_host_services copied = *services;
  copied.size = sizeof(yukilinker_c_host_services);

  // The copy is taken first, the lock second: nothing is latched until the call has been admitted.
  OperationGuard operation;
  // A second owner is refused before the page size hook runs for it, and a create issued from
  // that hook is refused for the same reason: this span has no owner yet.
  // Nor once a shutdown has passed its boundary: the runtime admits nothing new.
  if (g_runtime_owner != nullptr || g_runtime_creating || shutdown_begun()) return nullptr;
  if (!sole_operation()) return nullptr;
  CreateScope creating;
  // The hook runs in a callback frame, so an owner-changing call it makes is refused.
  size_t requested = 0;
  bool has_page_size = false;
  if (!query_host_page_size(copied, &requested, &has_page_size)) return nullptr;
  // The hook ran with the lock released and only creates were refused meanwhile, so another
  // thread's operation may have been admitted; the table must not change under it.
  if (!sole_operation()) return nullptr;
  auto* owner = static_cast<Runtime*>(calloc(1, sizeof(Runtime)));
  if (owner == nullptr) return nullptr;
  // Latched last, so a create that fails leaves no sticky page size behind.
  if (!adopt_host_page_size(requested, has_page_size)) {
    free(owner);
    return nullptr;
  }
  owner->magic = Runtime::kMagic;
  owner->active = true;
  owner->host_services = copied;
  __atomic_store_n(&g_runtime_owner, owner, __ATOMIC_RELEASE);
  publish_host_services(&owner->host_services);
  return owner;
}

uint32_t destroy_owner(void* opaque) {
  OperationGuard operation;
  auto* owner = owner_from(opaque);
  if (owner == nullptr) return 0;
  // A callback deeper in this same thread must not retire the owner under the call it is
  // reporting: the operation that entered it would then finish against a published default table.
  // An owner that already shut down has no table left to tear down, so it stays destroyable.
  if (!owner->shut_down && !sole_holder()) return 0;
  // An inactive owner that has not shut down is past the shutdown's boundary: this call resumes.
  if (!owner->shut_down && !retire_runtime(owner, nullptr)) return 0;
  // Only now: a pointer an image handed out stays callable, reporting its image retired, until
  // the owner is destroyed, try_shutdown included (yukilinker.h, namespace_create). A page that
  // cannot be unmapped stays owned so the host can retry before unmapping the runtime itself.
  if (!release_caller_stub_pages()) {
    host_log_error("yukilinker: a caller stub page could not be unmapped");
    return 0;
  }
  // The storage stays behind as a tombstone; no later handle can match it.
  modules_free_state();
  __atomic_store_n(&g_runtime_owner, static_cast<Runtime*>(nullptr), __ATOMIC_RELEASE);
  return 1;
}

// The runtime's atfork handlers go once the lock is released, before the host can unmap it.
uint32_t owner_runtime_destroy(void* opaque) {
  const uint32_t destroyed = destroy_owner(opaque);
  if (destroyed) retire_fork_handlers();
  return destroyed;
}

uint32_t shut_down_owner(void* opaque, yukilinker_c_error_detail* error) {
  OperationGuard operation;
  // A retired owner outranks the busy check: after shutdown it is stale from any depth. One past
  // the boundary, inactive, is still accepted here: this call resumes its shutdown.
  auto* owner = owner_from(opaque);
  if (owner == nullptr || owner->shut_down) {
    report_stale(error, YUKILINKER_C_RETIREMENT);
    return 0;
  }
  // Refused for the same reason as runtime_destroy: BUSY before the boundary (nothing changed),
  // RETRY past it (the shutdown has begun and the next call resumes).
  if (!sole_holder()) {
    if (error) {
      *error = {};
      error->code = shutdown_begun() ? YUKILINKER_C_RETRY : YUKILINKER_C_BUSY;
      error->stage = YUKILINKER_C_RETIREMENT;
    }
    return 0;
  }
  return retire_runtime(owner, error) ? 1 : 0;
}

uint32_t owner_try_shutdown(void* opaque, yukilinker_c_error_detail* error) {
  const uint32_t retired = shut_down_owner(opaque, error);
  if (retired) retire_fork_handlers();
  return retired;
}

uint32_t owner_context_destroy(void* opaque, void* context) {
  OperationGuard operation;
  if (runtime_from(opaque) == nullptr) return 0;
  return loader_destroy_context(context) != 0;
}

}  // namespace yukilinker::internal
