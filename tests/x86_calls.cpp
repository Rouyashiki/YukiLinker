// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <android/dlext.h>
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unwind.h>

#include <exception>

#include "../src/internal/call_barrier.hpp"
#include "control.hpp"
#include "host_services.h"
#include "yukilinker.hpp"

namespace {

template <typename Pointer>
Pointer imported(const yukilinker::Module& module, const char* symbol) {
  const auto getter = module.symbol<Pointer (*)()>(symbol);
  assert(getter && getter.value);
  const auto result = getter.value();
  assert(result);
  return result;
}

struct StackWalk {
  uintptr_t expected_pc;
  bool found;
};

_Unwind_Reason_Code visit_frame(_Unwind_Context* frame, void* opaque) {
  auto* walk = static_cast<StackWalk*>(opaque);
  if (_Unwind_GetIP(frame) != walk->expected_pc) return _URC_NO_REASON;
  walk->found = true;
  return _URC_END_OF_STACK;
}

uintptr_t backtrace_callback(uintptr_t first, uintptr_t second, uintptr_t user) {
  assert(first == 11 && second == 19 && user);
  _Unwind_Backtrace(visit_frame, reinterpret_cast<void*>(user));
  return 71;
}

[[gnu::noinline, clang::disable_tail_calls]] void check_stack_walk() {
  // The walk must reach the call site in exercise_x86_calls above the barrier.
  StackWalk walk{reinterpret_cast<uintptr_t>(__builtin_return_address(0)), false};
  assert(yuki_call_barrier(reinterpret_cast<const void*>(backtrace_callback), 11, 19,
                           reinterpret_cast<uintptr_t>(&walk)) == 71 &&
         walk.found);
}

uintptr_t throw_from_callback(uintptr_t, uintptr_t, uintptr_t) { throw 1; }

void check_exception_barrier() {
  const pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    std::set_terminate([] { _exit(73); });
    try {
      yuki_call_barrier(reinterpret_cast<const void*>(throw_from_callback), 0, 0, 0);
    } catch (...) {
      _exit(1);
    }
    _exit(2);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 73);
}
}  // namespace

void exercise_x86_calls(yukilinker::Runtime& runtime, const char* directory) {
  auto context = runtime.context(directory);
  assert(context);
  auto scope = runtime.namespace_create(&context);
  assert(scope && scope.link(nullptr, YUKILINKER_C_NAMESPACE_LINK_SYSTEM |
                                          YUKILINKER_C_NAMESPACE_LINK_ALL) == yukilinker::Code::Ok);
  yukilinker::OpenOptions options;
  options.native.namespace_scope = scope.native_handle();
  char caller_path[4096], target_path[4096];
  snprintf(caller_path, sizeof(caller_path), "%s/liblinker_x86_calls.so", directory);
  snprintf(target_path, sizeof(target_path), "%s/liblinker_module.so", directory);
  auto caller = runtime.open_path(caller_path, options);
  auto target = runtime.open_path(target_path, options);
  assert(caller && target);
  const auto open_from = imported<decltype(&dlopen)>(caller.value, "module_dlopen");
  const auto ext_from =
      imported<decltype(&android_dlopen_ext)>(caller.value, "module_android_dlopen_ext");
  const auto sym_from = imported<decltype(&dlsym)>(caller.value, "module_dlsym");
  const auto vsym_from = imported<decltype(&dlvsym)>(caller.value, "module_dlvsym");
  const auto iterate_from =
      imported<decltype(&dl_iterate_phdr)>(caller.value, "module_dl_iterate_phdr");
  const auto close_from = imported<decltype(&dlclose)>(caller.value, "module_dlclose");
  const auto tail = caller.value.symbol<decltype(&dlsym)>("module_tail_lookup");
  const auto tls_lookup = caller.value.symbol<int (*)()>("module_tls_lookup_matches");
  const auto answer = target.value.symbol<void*>("module_answer", "MODULE_API");
  assert(tail && tls_lookup && tls_lookup.value() && answer);
  void* opened = open_from("liblinker_module.so", RTLD_NOW | RTLD_NOLOAD);
  assert(opened && sym_from(opened, "module_answer") == answer.value);
  assert(vsym_from(opened, "module_answer", "MODULE_API") == answer.value);
  assert(!vsym_from(opened, "module_answer", "NO_VERSION"));
  assert(tail.value(opened, "module_answer") == answer.value);
  android_dlextinfo ext{};
  ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  ext.library_fd = open(target_path, O_RDONLY | O_CLOEXEC);
  assert(ext.library_fd >= 0);
  void* extended = ext_from("liblinker_module.so", RTLD_NOW, &ext);
  assert(extended && close(ext.library_fd) == 0);
  assert(sym_from(extended, "module_answer") == answer.value);
  assert(close_from(extended) == 0 && close_from(opened) == 0);
  if (test_loader_page_size() == 16384) {
    constexpr size_t kPage16k = 16384;
    constexpr size_t kReserveBytes = 256 * 1024;
    const int src_fd = open(target_path, O_RDONLY | O_CLOEXEC);
    struct stat src_st{};
    assert(src_fd >= 0 && fstat(src_fd, &src_st) == 0 && src_st.st_size > 0);
    const size_t src_bytes = static_cast<size_t>(src_st.st_size);
    void* source = mmap(nullptr, src_bytes, PROT_READ, MAP_PRIVATE, src_fd, 0);
    assert(source != MAP_FAILED);
    // Both offsets contain the same valid ELF so that only their alignment differs.
    const auto open_at_offset = [&](off64_t offset) {
      const int fd = fixture_fd(directory, "16k-offset");
      assert(fd >= 0 && pwrite64(fd, source, src_bytes, offset) == static_cast<ssize_t>(src_bytes));
      android_dlextinfo info{};
      info.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET |
                   ANDROID_DLEXT_FORCE_LOAD;
      info.library_fd = fd;
      info.library_fd_offset = offset;
      void* handle = ext_from("offset.so", RTLD_NOW, &info);
      assert(close(fd) == 0);
      return handle;
    };
    assert(!open_at_offset(4096));
    void* from_off = open_at_offset(kPage16k);
    assert(from_off);
    assert(munmap(source, src_bytes) == 0);
    auto off_answer = reinterpret_cast<int (*)()>(sym_from(from_off, "module_answer"));
    assert(off_answer && off_answer() == 42 && close_from(from_off) == 0);

    void* raw =
        mmap(nullptr, kReserveBytes + kPage16k, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(raw != MAP_FAILED);
    const uintptr_t raw_addr = reinterpret_cast<uintptr_t>(raw);
    const uintptr_t aligned_addr = (raw_addr + kPage16k - 1) & ~(kPage16k - 1);
    const size_t prefix = aligned_addr - raw_addr;
    const size_t suffix = kPage16k - prefix;
    if (prefix) assert(munmap(raw, prefix) == 0);
    if (suffix) assert(munmap(reinterpret_cast<void*>(aligned_addr + kReserveBytes), suffix) == 0);
    void* base = reinterpret_cast<void*>(aligned_addr);

    android_dlextinfo bad_res{};
    bad_res.flags =
        ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD | ANDROID_DLEXT_RESERVED_ADDRESS;
    bad_res.library_fd = src_fd;
    bad_res.reserved_addr = static_cast<char*>(base) + 4096;
    bad_res.reserved_size = kReserveBytes - kPage16k;
    assert(!ext_from("res-unaligned-addr.so", RTLD_NOW, &bad_res));
    bad_res.reserved_addr = base;
    bad_res.reserved_size = kReserveBytes - 4096;
    assert(!ext_from("res-unaligned-size.so", RTLD_NOW, &bad_res));

    const int relro_fd = fixture_fd(directory, "16k-relro");
    assert(relro_fd >= 0);
    android_dlextinfo writer_ext{};
    writer_ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD |
                       ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_WRITE_RELRO;
    writer_ext.library_fd = src_fd;
    writer_ext.reserved_addr = base;
    writer_ext.reserved_size = kReserveBytes;
    writer_ext.relro_fd = relro_fd;
    void* writer = ext_from("relro-writer-16k.so", RTLD_NOW, &writer_ext);
    assert(writer);
    auto w_answer = reinterpret_cast<int (*)()>(sym_from(writer, "module_answer"));
    assert(w_answer && w_answer() == 42);
    struct stat relro_st{};
    assert(fstat(relro_fd, &relro_st) == 0 && relro_st.st_size >= static_cast<off_t>(kPage16k) &&
           (relro_st.st_size % static_cast<off_t>(kPage16k)) == 0);

    // Reuse the reservation so the reader's relocated pointers match the saved page.
    assert(close_from(writer) == 0);
    android_dlextinfo reader_ext = writer_ext;
    reader_ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD |
                       ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_USE_RELRO;
    void* reader = ext_from("relro-reader-16k.so", RTLD_NOW, &reader_ext);
    assert(reader);
    auto r_answer = reinterpret_cast<int (*)()>(sym_from(reader, "module_answer"));
    assert(r_answer && r_answer() == 42);
    auto snapshot = runtime.snapshot();
    assert(snapshot);
    uint64_t shared_bytes = 0;
    for (size_t i = 0; i < snapshot.value.size(); ++i) {
      const auto image = snapshot.value.image(i);
      assert(image);
      if (image.value.mapping_start != aligned_addr) continue;
      const auto mapping = snapshot.value.mapping(i);
      assert(mapping);
      shared_bytes = mapping.value.relro_shared_bytes;
      break;
    }
    assert(shared_bytes >= kPage16k);
    assert(snapshot.value.release() == yukilinker::Code::Ok);
    assert(close_from(reader) == 0);
    assert(close(relro_fd) == 0 && close(src_fd) == 0);
    assert(munmap(base, kReserveBytes) == 0);
    puts("PASS 16 KiB android_dlopen_ext placement, fd offset and RELRO sharing");
  }
  int visited = 0;
  const auto visit = [](dl_phdr_info* info, size_t size, void* user) {
    assert(info && size && user);
    ++*static_cast<int*>(user);
    return 79;
  };
  assert(iterate_from(visit, &visited) == 79 && visited == 1);
  check_stack_walk();
  check_exception_barrier();

  assert(caller.value.close().private_mapping_unmapped());
  auto replacement = runtime.open_path(caller_path, options);
  assert(replacement);
  const auto fresh = imported<decltype(&dlopen)>(replacement.value, "module_dlopen");
  assert(fresh != open_from);
  opened = fresh("liblinker_module.so", RTLD_NOW | RTLD_NOLOAD);
  assert(opened);
  assert(!open_from("liblinker_module.so", RTLD_NOW));
  assert(!ext_from("liblinker_module.so", RTLD_NOW, nullptr));
  assert(!sym_from(opened, "module_answer") && !vsym_from(opened, "module_answer", "MODULE_API"));
  assert(iterate_from([](dl_phdr_info*, size_t, void*) { return 71; }, nullptr) == 0);
  assert(close_from(opened) == 0);
  assert(replacement.value.close().private_mapping_unmapped());
  assert(target.value.close().private_mapping_unmapped());
  assert(scope.destroy() == yukilinker::Code::Ok && context.destroy());
  puts("PASS caller bindings, tail call, stale generation and DWARF call barrier");
}
