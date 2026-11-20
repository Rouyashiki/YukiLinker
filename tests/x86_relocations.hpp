// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#if (defined(__i386__) || defined(__x86_64__)) && !defined(YUKILINKER_TEST_CFI)

#include <assert.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yukilinker.hpp>

inline void exercise_x86_relocations(yukilinker::Runtime& runtime, const char* directory) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/liblinker_lifecycle.so", directory);
  const int source = open(path, O_RDONLY | O_CLOEXEC);
  struct stat status{};
  assert(source >= 0 && fstat(source, &status) == 0 && status.st_size > 0);
  const size_t bytes = status.st_size;
  auto* data =
      static_cast<uint8_t*>(mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, source, 0));
  assert(data != MAP_FAILED && close(source) == 0);
  const auto* header = reinterpret_cast<ElfW(Ehdr)*>(data);
  const auto* sections = reinterpret_cast<ElfW(Shdr)*>(data + header->e_shoff);
  auto* programs = reinterpret_cast<ElfW(Phdr)*>(data + header->e_phoff);
  ElfW(Addr) slots = 0, resolver = 0;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    const auto& section = sections[i];
    if (section.sh_type != SHT_DYNSYM) continue;
    const auto* symbols = reinterpret_cast<const ElfW(Sym)*>(data + section.sh_offset);
    const char* names = reinterpret_cast<char*>(data + sections[section.sh_link].sh_offset);
    for (size_t j = 0; j < section.sh_size / sizeof(*symbols); ++j) {
      if (strcmp(names + symbols[j].st_name, "module_x86_slots") == 0) slots = symbols[j].st_value;
      if (strcmp(names + symbols[j].st_name, "module_x86_resolver") == 0)
        resolver = symbols[j].st_value;
    }
  }
  assert(slots && resolver);
  constexpr size_t word = sizeof(ElfW(Addr));
  uint8_t* initial = nullptr;
  ElfW(Addr) last = 0;
  for (unsigned i = 0; i < header->e_phnum; ++i) {
    auto& p = programs[i];
    if (p.p_type != PT_LOAD || !(p.p_flags & PF_W) || slots < p.p_vaddr ||
        slots + 5 * word > p.p_vaddr + p.p_filesz)
      continue;
    initial = data + p.p_offset + (slots - p.p_vaddr);
    // One narrow write ends exactly at the end of the writable segment, including during
    // deferred IFUNC replay. Its implicit addend on i386 comes from zero-initialized BSS.
    last = p.p_vaddr + p.p_memsz;
    p.p_memsz += sizeof(uint32_t);
  }
  assert(initial && last);
  memset(initial, 0xa5, 5 * word);
#if defined(__x86_64__)
  using Rel = Elf64_Rela;
  constexpr uint32_t section_type = SHT_RELA, abs32 = R_X86_64_32, pc32 = R_X86_64_PC32;
  constexpr uint32_t irelative = R_X86_64_IRELATIVE, unsupported = R_X86_64_32S;
#else
  using Rel = Elf32_Rel;
  constexpr uint32_t section_type = SHT_REL, abs32 = R_386_32, pc32 = R_386_PC32;
  constexpr uint32_t irelative = R_386_IRELATIVE, unsupported = R_386_16;
#endif
  const ElfW(Addr) offsets[] = {slots + 1, slots + 5, slots + 9, last, slots + 4 * word};
  const uint32_t types[] = {abs32, pc32, pc32, pc32, irelative};
  const ElfW(Addr) addends[] = {3, 7, 11, 0, resolver};
  Rel* weak = nullptr;
  Rel* at_end = nullptr;
  unsigned seen = 0;
  for (unsigned i = 0; i < header->e_shnum; ++i) {
    if (sections[i].sh_type != section_type) continue;
    auto* entries = reinterpret_cast<Rel*>(data + sections[i].sh_offset);
    for (size_t j = 0; j < sections[i].sh_size / sizeof(Rel); ++j) {
      auto& r = entries[j];
      if (r.r_offset < slots || r.r_offset >= slots + 5 * word) continue;
      const size_t index = (r.r_offset - slots) / word;
      assert(r.r_offset == slots + index * word && !(seen & (1u << index)));
      seen |= 1u << index;
      r.r_offset = offsets[index];
#if defined(__x86_64__)
      r.r_info = ELF64_R_INFO(index == 4 ? 0 : ELF64_R_SYM(r.r_info), types[index]);
      r.r_addend = addends[index];
#else
      r.r_info = ELF32_R_INFO(index == 4 ? 0 : ELF32_R_SYM(r.r_info), types[index]);
      if (r.r_offset != last)
        memcpy(initial + (r.r_offset - slots), &addends[index], sizeof(Elf32_Addr));
#endif
      if (index == 2) weak = &r;
      if (index == 3) at_end = &r;
    }
  }
  assert(seen == 31 && weak && at_end);
  const auto open_copy = [&] {
    const int fd = fixture_fd(directory, "x86-relocations");
    assert(fd >= 0 && write(fd, data, bytes) == static_cast<ssize_t>(bytes));
    auto result = runtime.open_fd(fd);
    assert(close(fd) == 0);
    return result;
  };
  auto loaded = open_copy();
  assert(loaded);
  auto function = loaded.value.symbol<int (*)()>("module_x86_ifunc");
  assert(function && function.value() == 73);
  const auto image = loaded.value.image();
  assert(image);
  const uintptr_t target = reinterpret_cast<uintptr_t>(function.value);
  const uintptr_t bias = image.value.load_bias;
  const auto narrow = [bias](ElfW(Addr) offset) {
    uint32_t value;
    memcpy(&value, reinterpret_cast<const void*>(bias + offset), sizeof(value));
    return value;
  };
  assert(narrow(offsets[0]) == static_cast<uint32_t>(target + 3));
  assert(narrow(offsets[1]) == static_cast<uint32_t>(target + 7 - (bias + offsets[1])));
  assert(narrow(offsets[2]) == 11);  // unresolved weak PC32
  assert(narrow(last) == static_cast<uint32_t>(target - (bias + last)));
  uintptr_t indirect;
  memcpy(&indirect, reinterpret_cast<const void*>(bias + offsets[4]), sizeof(indirect));
  assert(indirect == target);
  const auto* live = reinterpret_cast<const uint8_t*>(bias + slots);
  assert(live[0] == 0xa5 && live[13] == 0xa5);
  assert(loaded.value.close().private_mapping_unmapped());

  // Overlap the end of the second narrow write by one byte.
  weak->r_offset = offsets[1] + 3;
  auto refused = open_copy();
  assert(!refused && refused.error.native.detail.code == YUKILINKER_C_INVALID_ELF &&
         refused.error.native.detail.stage == YUKILINKER_C_RELOCATIONS &&
         !refused.error.native.detail.execution_started);

  // The last four bytes hold the operand. An unsupported encoding reports its
  // own type and offset even when a native pointer would cross the boundary.
  weak->r_offset = offsets[2];
#if defined(__x86_64__)
  at_end->r_info = ELF64_R_INFO(ELF64_R_SYM(at_end->r_info), unsupported);
#else
  at_end->r_info = ELF32_R_INFO(ELF32_R_SYM(at_end->r_info), unsupported);
#endif
  auto unknown = open_copy();
  const auto& error = unknown.error.native.detail;
  assert(!unknown && error.code == YUKILINKER_C_UNSUPPORTED &&
         error.stage == YUKILINKER_C_RELOCATIONS && error.machine == header->e_machine &&
         error.relocation_type == unsupported && error.offset == last && !error.execution_started);
  assert(munmap(data, bytes) == 0);
  puts("PASS x86 narrow relocations, weak PC32, IFUNC and IRELATIVE");
}

#endif
