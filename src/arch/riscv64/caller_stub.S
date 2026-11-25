// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKILINKER_FULL
#define YUKILINKER_FULL 0
#endif

#if !defined(__riscv) || __riscv_xlen != 64
#error "caller_stub.S is the riscv64 caller stub"
#endif

#if YUKILINKER_FULL

/*
 * The caller-dependent imports of an image in a managed namespace bind to a slab of per-image
 * stubs (caller_stubs.cpp). Each 32-byte stub is the template below with its two literals patched:
 * it loads the binding-cell address into t1 and tail-jumps to one of the entries, which pass it on
 * as the last argument of the C++ function that reads the generation under the operation lock.
 * .option norvc guarantees fixed 4-byte instructions so the two literals sit at +16 and +24.
 * t0, t1, t2 are caller-saved temporaries; ra and a0..a7 stay untouched.
 */
.text
.p2align 3
.hidden yuki_caller_stub_template
.global yuki_caller_stub_template
.type yuki_caller_stub_template, %object
yuki_caller_stub_template:
    .option push
    .option norvc
    auipc t0, 0
    ld    t1, 16(t0)
    ld    t2, 24(t0)
    jr    t2
    .option pop
    .quad 0
    .quad 0
.size yuki_caller_stub_template, . - yuki_caller_stub_template

.macro caller_entry name, target, arg_reg
.hidden \name
.global \name
.type \name, %function
.p2align 2
\name:
.cfi_startproc
    mv \arg_reg, t1
    tail \target
.cfi_endproc
.size \name, . - \name
.endm

caller_entry yuki_caller_dlopen, yuki_caller_dlopen_from, a2
caller_entry yuki_caller_android_dlopen_ext, yuki_caller_android_dlopen_ext_from, a3
caller_entry yuki_caller_dlsym, yuki_caller_dlsym_from, a2
caller_entry yuki_caller_dlvsym, yuki_caller_dlvsym_from, a3
caller_entry yuki_caller_dl_iterate_phdr, yuki_caller_dl_iterate_phdr_from, a2

#endif  // YUKILINKER_FULL

.section .note.GNU-stack, "", @progbits
