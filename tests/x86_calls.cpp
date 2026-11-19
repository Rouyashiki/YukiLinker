// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <android/dlext.h>
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unwind.h>

#include <exception>

#include "../src/internal/call_barrier.hpp"
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
  puts("PASS x86 caller bindings, tail call, stale generation and DWARF call barrier");
}
