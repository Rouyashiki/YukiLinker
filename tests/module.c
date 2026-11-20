// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

static int value;
__attribute__((constructor)) static void initialize(void) {
  const char* address = getenv("YUKILINKER_TEST_WAIT_BARRIER");
  if (address) {
    pthread_barrier_t* barrier = (pthread_barrier_t*)(uintptr_t)strtoull(address, NULL, 16);
    for (unsigned i = 0; i < 2; ++i) {
      int status = pthread_barrier_wait(barrier);
      if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) abort();
    }
  }
  value = 42;
}
__attribute__((visibility("default"))) int module_answer(void) { return value; }
