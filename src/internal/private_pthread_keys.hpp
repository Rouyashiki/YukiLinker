// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#include <pthread.h>
#include <stdint.h>

namespace yukilinker::internal {

struct ImageState;

// After normal scope and version resolution, route Bionic's TLS-related pthread calls through Core.
// Preserve any other provider's address, including a successful null result.
void* private_pthread_address(const ImageState* caller, const char* name, void* resolved);

// These calls hold the operation lock. A thread with an outstanding Bionic callback keeps Core
// callable even after another thread deletes the last private key it used.
bool private_key_threads_active();
bool current_thread_has_private_key_callbacks();
bool has_private_key_destructor(const ImageState* image);
bool ensure_thread_identity_key();
uintptr_t current_thread_identity(bool create);
void reap_exited_threads();
void private_keys_after_fork();
void retire_private_keys(ImageState* image);
void shutdown_private_keys();

}  // namespace yukilinker::internal
