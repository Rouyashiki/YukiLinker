// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "asm.h"

// caller_stubs.cpp copies this template into the code page, fills the binding
// and entry addresses, then makes the page executable before publishing it.
.text
.p2align 4
.hidden yuki_caller_stub_template
.globl yuki_caller_stub_template
.type yuki_caller_stub_template, @object
yuki_caller_stub_template:
    YUKI_ENDBR
#if defined(__x86_64__)
    leaq .Lbinding(%rip), %r11
    jmp *8(%r11)
    .org yuki_caller_stub_template + 16, 0x90
.Lbinding:
    .quad 0, 0
#else
    // No PC-relative data operands on i386. The immediates at offsets 5 and
    // 10 are patched before publication. Both registers are caller-saved.
    movl $0, %eax
    movl $0, %ecx
    jmp *%ecx
#endif
.size yuki_caller_stub_template, . - yuki_caller_stub_template

.macro caller_entry name, target, argc
.p2align 4
.hidden \name
.globl \name
.type \name, @function
\name:
.cfi_startproc
    YUKI_ENDBR
#if defined(__x86_64__)
    // The extra binding argument follows the two or three original arguments.
    .if \argc == 3
    movq (%r11), %rcx
    .else
    movq (%r11), %rdx
    .endif
    jmp \target
#else
    // The importer owns its cdecl arguments. Copy them into an aligned call
    // frame that also has room for the binding and leave the original intact.
    movl %esp, %ecx
    .if \argc == 3
    subl $12, %esp
    .cfi_adjust_cfa_offset 12
    .endif
    pushl %eax
    .cfi_adjust_cfa_offset 4
    .if \argc == 3
    pushl 12(%ecx)
    .cfi_adjust_cfa_offset 4
    .endif
    pushl 8(%ecx)
    .cfi_adjust_cfa_offset 4
    pushl 4(%ecx)
    .cfi_adjust_cfa_offset 4
    call \target
    .if \argc == 3
    addl $28, %esp
    .cfi_adjust_cfa_offset -28
    .else
    addl $12, %esp
    .cfi_adjust_cfa_offset -12
    .endif
    ret
#endif
.cfi_endproc
.size \name, . - \name
.endm

caller_entry yuki_caller_dlopen, yuki_caller_dlopen_from, 2
caller_entry yuki_caller_android_dlopen_ext, yuki_caller_android_dlopen_ext_from, 3
caller_entry yuki_caller_dlsym, yuki_caller_dlsym_from, 2
caller_entry yuki_caller_dlvsym, yuki_caller_dlvsym_from, 3
caller_entry yuki_caller_dl_iterate_phdr, yuki_caller_dl_iterate_phdr_from, 2
