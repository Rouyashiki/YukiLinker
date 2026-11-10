// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#include <assert.h>

#include <initializer_list>

#include "../src/internal/elf_reader.hpp"

template <typename Ehdr, typename Phdr>
void exercise_relro_layout(size_t page) {
  struct Fixture {
    Ehdr header;
    Phdr segments[5];
  } valid{};
  auto& header = valid.header;
  memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = sizeof(Ehdr) == sizeof(Elf64_Ehdr) ? ELFCLASS64 : ELFCLASS32;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_ident[EI_VERSION] = EV_CURRENT;
  header.e_version = EV_CURRENT;
  header.e_type = ET_DYN;
  header.e_machine = sizeof(Ehdr) == sizeof(Elf64_Ehdr) ? EM_AARCH64 : EM_ARM;
  header.e_ehsize = sizeof(Ehdr);
  header.e_phoff = offsetof(Fixture, segments);
  header.e_phentsize = sizeof(Phdr);
  header.e_phnum = 5;
  auto& readable = valid.segments[0];
  readable.p_type = PT_LOAD;
  readable.p_flags = PF_R;
  readable.p_filesz = sizeof(valid);
  readable.p_memsz = page / 2;
  readable.p_align = page;
  auto& writable = valid.segments[1];
  writable.p_type = PT_LOAD;
  writable.p_flags = PF_R | PF_W;
  writable.p_offset = 0x40;
  writable.p_vaddr = 2 * page + 0x40;
  writable.p_memsz = 0x500;
  writable.p_align = page;
  valid.segments[2].p_type = PT_DYNAMIC;
  valid.segments[2].p_vaddr = 0x80;
  valid.segments[2].p_memsz = 0x20;
  auto& relro = valid.segments[3];
  relro.p_type = PT_GNU_RELRO;
  relro.p_vaddr = writable.p_vaddr;
  relro.p_memsz = page - 0x40;
  valid.segments[4] = writable;
  valid.segments[4].p_vaddr = 5 * page + 0x40;
  const auto check = [&](const Fixture& fixture, bool expected) {
    yukilinker::elf::Layout<Ehdr, Phdr> layout;
    assert(yukilinker::elf::inspect(&fixture, sizeof(fixture), page, header.e_machine, &layout) ==
           expected);
    assert(!layout.unsupported);
  };
  check(valid, true);
  auto test = valid;
  test.segments[3].p_memsz = writable.p_memsz;
  check(test, true);
  ++test.segments[3].p_memsz;
  check(test, true);
  test = valid;
  ++test.segments[3].p_memsz;
  check(test, false);
  test = valid;
  test.segments[3].p_vaddr = writable.p_vaddr + writable.p_memsz;
  test.segments[3].p_memsz = 1;
  check(test, false);
  test = valid;
  test.segments[3].p_vaddr = 4 * page;
  test.segments[3].p_memsz = 1;
  check(test, false);
  test = valid;
  test.segments[3].p_memsz = 3 * page + 1;
  check(test, false);
  for (const auto flags : {PF_R, PF_W, PF_R | PF_X}) {
    test = valid;
    test.segments[1].p_flags = flags;
    check(test, false);
  }
  test = valid;
  test.segments[1].p_memsz = 0;
  check(test, false);
  constexpr auto limit = std::numeric_limits<decltype(Phdr::p_vaddr)>::max();
  test = valid;
  test.segments[3].p_memsz = limit;
  check(test, false);
  test = valid;
  test.segments[3].p_vaddr = limit - 7;
  test.segments[3].p_memsz = 16;
  check(test, false);
  test = valid;
  test.segments[1].p_memsz = limit - writable.p_vaddr;
  check(test, false);
  test = valid;
  test.segments[2].p_vaddr = readable.p_memsz - 1;
  check(test, false);
  test = valid;
  test.segments[1] = valid.segments[4];
  test.segments[4] = writable;
  check(test, true);
}

inline void exercise_relro_layouts() {
  for (const size_t page : {4096U, 16384U}) {
    exercise_relro_layout<Elf32_Ehdr, Elf32_Phdr>(page);
    exercise_relro_layout<Elf64_Ehdr, Elf64_Phdr>(page);
  }
}
