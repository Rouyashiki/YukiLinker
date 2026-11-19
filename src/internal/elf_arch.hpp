// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once

#include <elf.h>

#include <cstdint>

namespace yukilinker::internal::arch {

// These dynamic relocations implement the same operations under different ABI numbers.
#if defined(__aarch64__)
inline constexpr uint16_t kMachine = EM_AARCH64;
inline constexpr uint32_t kAbsolute = R_AARCH64_ABS64;
inline constexpr uint32_t kGlobDat = R_AARCH64_GLOB_DAT;
inline constexpr uint32_t kJumpSlot = R_AARCH64_JUMP_SLOT;
inline constexpr uint32_t kRelative = R_AARCH64_RELATIVE;
inline constexpr uint32_t kIRelative = R_AARCH64_IRELATIVE;
inline constexpr uint32_t kDtpMod = R_AARCH64_TLS_DTPMOD64;
inline constexpr uint32_t kDtpOff = R_AARCH64_TLS_DTPREL64;
inline constexpr uint32_t kTpOff = R_AARCH64_TLS_TPREL64;
#elif defined(__arm__)
inline constexpr uint16_t kMachine = EM_ARM;
inline constexpr uint32_t kAbsolute = R_ARM_ABS32;
inline constexpr uint32_t kGlobDat = R_ARM_GLOB_DAT;
inline constexpr uint32_t kJumpSlot = R_ARM_JUMP_SLOT;
inline constexpr uint32_t kRelative = R_ARM_RELATIVE;
inline constexpr uint32_t kIRelative = R_ARM_IRELATIVE;
inline constexpr uint32_t kDtpMod = R_ARM_TLS_DTPMOD32;
inline constexpr uint32_t kDtpOff = R_ARM_TLS_DTPOFF32;
inline constexpr uint32_t kTpOff = R_ARM_TLS_TPOFF32;
#elif defined(__i386__)
inline constexpr uint16_t kMachine = EM_386;
inline constexpr uint32_t kAbsolute = R_386_32;
inline constexpr uint32_t kGlobDat = R_386_GLOB_DAT;
inline constexpr uint32_t kJumpSlot = R_386_JMP_SLOT;
inline constexpr uint32_t kRelative = R_386_RELATIVE;
inline constexpr uint32_t kIRelative = R_386_IRELATIVE;
inline constexpr uint32_t kDtpMod = R_386_TLS_DTPMOD32;
inline constexpr uint32_t kDtpOff = R_386_TLS_DTPOFF32;
inline constexpr uint32_t kTpOff = R_386_TLS_TPOFF;
#elif defined(__x86_64__)
inline constexpr uint16_t kMachine = EM_X86_64;
inline constexpr uint32_t kAbsolute = R_X86_64_64;
inline constexpr uint32_t kGlobDat = R_X86_64_GLOB_DAT;
inline constexpr uint32_t kJumpSlot = R_X86_64_JUMP_SLOT;
inline constexpr uint32_t kRelative = R_X86_64_RELATIVE;
inline constexpr uint32_t kIRelative = R_X86_64_IRELATIVE;
inline constexpr uint32_t kDtpMod = R_X86_64_DTPMOD64;
inline constexpr uint32_t kDtpOff = R_X86_64_DTPOFF64;
inline constexpr uint32_t kTpOff = R_X86_64_TPOFF64;
#else
#error Unsupported Android ELF machine
#endif

#if defined(__i386__)
inline constexpr char kTlsGetAddr[] = "___tls_get_addr";
#else
inline constexpr char kTlsGetAddr[] = "__tls_get_addr";
#endif

}  // namespace yukilinker::internal::arch
