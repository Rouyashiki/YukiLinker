// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

// Shared by the register-preserving entry and the Core that owns its spill banks.
#define YUKI_RVV_INLINE_VLENB 32
#define YUKI_RVV_SLOTS 64
#define YUKI_RVV_FORK_SLOTS 8
#define YUKI_RVV_NESTED_SLOTS 8
#define YUKI_RVV_LOCK_SLOTS 8
#define YUKI_RVV_TOTAL_SLOTS \
  (YUKI_RVV_SLOTS + YUKI_RVV_FORK_SLOTS + YUKI_RVV_NESTED_SLOTS + YUKI_RVV_LOCK_SLOTS)
#define YUKI_RVV_OWNERS 16
#define YUKI_RVV_FORK_OWNERS (YUKI_RVV_OWNERS + 8 * YUKI_RVV_SLOTS)
#define YUKI_RVV_NESTED_OWNERS (YUKI_RVV_FORK_OWNERS + 8 * YUKI_RVV_FORK_SLOTS)
#define YUKI_RVV_LOCK_OWNERS (YUKI_RVV_NESTED_OWNERS + 8 * YUKI_RVV_NESTED_SLOTS)
#define YUKI_RVV_FRAMES (YUKI_RVV_LOCK_OWNERS + 8 * YUKI_RVV_LOCK_SLOTS)
#define YUKI_RVV_FILES (YUKI_RVV_FRAMES + 8 * YUKI_RVV_TOTAL_SLOTS)

#define YUKI_RVV_THREAD_TAG (YUKI_RVV_OWNERS + 8 * YUKI_RVV_NESTED_SLOTS)
#define YUKI_RVV_THREAD_FRAMES (YUKI_RVV_THREAD_TAG + 8)
#define YUKI_RVV_THREAD_FILES (YUKI_RVV_THREAD_FRAMES + 8 * YUKI_RVV_NESTED_SLOTS)

// Android riscv64 Bionic. Verify the key-data location and sequence against
// pthread_setspecific before publishing the first wide descriptor.
#define YUKI_BIONIC_KEY_DATA_FROM_TP -72
#define YUKI_BIONIC_PTHREAD_FROM_TP -56
#define YUKI_BIONIC_TID_FROM_PTHREAD 16
#define YUKI_RISCV_TID_BITS 22
// A directory bit covers 4096 TIDs (512 pin words).
#define YUKI_RVV_PIN_CHUNK_SHIFT 12
// Low byte tracks eight TIDs. The upper bits change on every enrollment.
#define YUKI_RVV_PIN_GROUP 8
#define YUKI_RVV_PIN_EPOCH (1 << YUKI_RVV_PIN_GROUP)
#define YUKI_RVV_PIN_MASK (YUKI_RVV_PIN_EPOCH - 1)
