// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#if defined(__riscv) && __riscv_xlen == 64 && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <string.h>

#if defined(__riscv) && __riscv_xlen == 64
#include <riscv_vector.h>
#include <stdatomic.h>
#include <sys/hwprobe.h>
#endif

// This fixture always exercises native ELF TLS in PRIVATE. Older libc stubs
// omit this import, which the runtime supplies when it relocates the fixture.
#if __ANDROID_API__ < 29 && defined(__i386__)
__asm__(".weak ___tls_get_addr");
#elif __ANDROID_API__ < 29 && (defined(__arm__) || defined(__x86_64__))
__asm__(".weak __tls_get_addr");
#endif

int __cxa_atexit(void (*callback)(void*), void* data, void* owner);
void __cxa_finalize(void* owner);
int __cxa_thread_atexit_impl(void (*callback)(void*), void* data, void* owner);
extern void* __dso_handle;

__thread int module_value = 42;
static int* fork_calls;
static void (*close_step)(int);
static void count(void* value) { ++*(int*)value; }
static void child(void) {
  if (fork_calls) ++*fork_calls;
}

int* module_slot(void) { return &module_value; }
static void finish_cookie(void* unused) {
  (void)unused;
  close_step(2);
}
int module_watch_close(void (*step)(int)) {
  close_step = step;
  return __cxa_atexit(finish_cookie, NULL, &close_step);
}
__attribute__((destructor(201))) static void start_close(void) {
  if (close_step) {
    ++module_value;
    // The TLS hold parks this cookie before the host starts process exit.
    __cxa_finalize(&close_step);
    close_step(1);
  }
}
__attribute__((destructor(200))) static void finish_close(void) {
  if (close_step) close_step(3);
}
int module_lookup_emutls(const char* path, int expected) {
  void* handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
  if (!handle) return 0;
  dlerror();
  void* address = dlsym(handle, "__emutls_get_address");
  void* control = dlsym(handle, "__emutls_v.fixture_shared");
  const char* error = dlerror();
  void* (*access)(void*);
  memcpy(&access, &address, sizeof(access));
  int matched = expected ? access && control && !error && *(int*)access(control) == expected
                         : access && !control && error;
  return dlclose(handle) == 0 && matched;
}
int module_iterate(int (*visit)(struct dl_phdr_info*, size_t, void*), void* data) {
  return dl_iterate_phdr(visit, data);
}
int module_thread_exit(int* calls) { return __cxa_thread_atexit_impl(count, calls, &__dso_handle); }
int module_exit(int* calls) { return __cxa_atexit(count, calls, &__dso_handle); }
int module_fork(int* calls) {
  fork_calls = calls;
  return pthread_atfork(0, 0, child);
}

#if defined(__i386__) || defined(__x86_64__)
typedef int (*probe_function)(void);
static int probe_answer(void) { return 73; }
probe_function module_x86_resolver(void) { return probe_answer; }
int module_x86_ifunc(void) __attribute__((ifunc("module_x86_resolver")));
extern int module_x86_weak(void) __attribute__((weak));
// The host rewrites these five ordinary address relocations in a copy of this DSO. Android lld
// does not emit x86_64's narrow dynamic relocations from PIC input.
probe_function module_x86_slots[] = {module_x86_ifunc, module_x86_ifunc, module_x86_weak,
                                     module_x86_ifunc, module_x86_ifunc};
#elif defined(__riscv) && __riscv_xlen == 64
typedef uint64_t (*probe_function)(void);
// Bionic can resolve the address slots before the PLT and invoke the resolver again for dlsym.
static _Atomic uint64_t resolver_hwcap;
static uint64_t read_hwcap(void) {
  return atomic_load_explicit(&resolver_hwcap, memory_order_relaxed);
}
probe_function module_riscv_resolver(uint64_t hwcap, __riscv_hwprobe_t hwprobe, void* reserved) {
  struct riscv_hwprobe pair = {RISCV_HWPROBE_KEY_IMA_EXT_0, 0};
  if (!hwprobe || reserved != NULL || hwprobe(&pair, 1, 0, NULL, 0) != 0) return NULL;
  atomic_store_explicit(&resolver_hwcap, hwcap, memory_order_relaxed);
  return read_hwcap;
}
uint64_t module_riscv_ifunc(void) __attribute__((ifunc("module_riscv_resolver")));
extern __thread int module_riscv_weak_tls __attribute__((weak));
int* module_riscv_weak_tls_addr(void) { return &module_riscv_weak_tls; }
// Keep RVV vectors and double FPRs live across a cold TLSDESC access to module_value.
__attribute__((target("arch=+v"))) int module_riscv_tls_clobber_check(const int32_t* buf, size_t n,
                                                                      double a, double b) {
  size_t vl = __riscv_vsetvl_e32m1(n);
  vint32m1_t v0 = __riscv_vle32_v_i32m1(buf, vl);
  vint32m1_t v1 = __riscv_vle32_v_i32m1(buf + n, vl);
  double fp_sum = a + b;
  __asm__ volatile("" : "+vr"(v0), "+vr"(v1), "+f"(fp_sum) :: "memory");
  int tls_val = module_value;
  __asm__ volatile("" : "+vr"(v0), "+vr"(v1), "+f"(fp_sum), "+r"(tls_val) :: "memory");
  vint32m1_t sum = __riscv_vadd_vv_i32m1(v0, v1, vl);
  vint32m1_t red = __riscv_vredsum_vs_i32m1_i32m1(sum, __riscv_vmv_s_x_i32m1(0, vl), vl);
  int vec_total = __riscv_vmv_x_s_i32m1_i32(red);
  return vec_total + tls_val + (int)fp_sum;
}

__attribute__((target("arch=+v"), noinline)) int module_riscv_tls_vstart_check(void) {
  static const uint8_t pattern[16] = {
      0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
      0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
  };
  uint8_t out[16];
  size_t vl = __riscv_vsetvl_e8m1(16);
  vuint8m1_t v = __riscv_vle8_v_u8m1(pattern, vl);
  size_t got_vstart = 0;
  int cond = 0;
  int tls_val = 0;
  __asm__ volatile("csrw vstart, %2\n\tli %0, 1"
                   : "=r"(cond), "+vr"(v)
                   : "r"(3)
                   : "memory");
  if (cond) tls_val = module_value;
  __asm__ volatile("csrr %0, vstart\n\tcsrwi vstart, 0"
                   : "=r"(got_vstart), "+vr"(v)
                   : "r"(tls_val)
                   : "memory");
  __riscv_vse8_v_u8m1(out, v, vl);
  if (got_vstart != 3) return -1;
  for (size_t i = 0; i < vl; ++i) {
    if (out[i] != 0x5a) return -2;
  }
  return tls_val;
}
probe_function module_riscv_slots[] = {module_riscv_ifunc, module_riscv_ifunc};
#endif
