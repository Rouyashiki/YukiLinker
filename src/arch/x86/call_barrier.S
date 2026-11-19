// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "asm.h"

// Call the module with three native words and return its result. DWARF can
// walk this frame, but an exception must terminate before entering the runtime.
.text
.p2align 4
.hidden yuki_call_barrier
.globl yuki_call_barrier
.type yuki_call_barrier, @function
yuki_call_barrier:
.cfi_startproc
.cfi_personality 0x1b, yuki_barrier_personality
    YUKI_ENDBR
#if defined(__x86_64__)
    movq %rdi, %rax
    movq %rsi, %rdi
    movq %rdx, %rsi
    movq %rcx, %rdx
    subq $8, %rsp
    .cfi_adjust_cfa_offset 8
    call *%rax
    addq $8, %rsp
    .cfi_adjust_cfa_offset -8
#else
    movl 4(%esp), %eax
    // Successive pushes put a2, a1 and a0 at the same displacement.
    .rept 3
    pushl 16(%esp)
    .cfi_adjust_cfa_offset 4
    .endr
    call *%eax
    addl $12, %esp
    .cfi_adjust_cfa_offset -12
#endif
    ret
.cfi_endproc
.size yuki_call_barrier, . - yuki_call_barrier

.p2align 4
.hidden yuki_barrier_personality
.globl yuki_barrier_personality
.type yuki_barrier_personality, @function
yuki_barrier_personality:
.cfi_startproc
    YUKI_ENDBR
#if defined(__x86_64__)
    movl %esi, %eax
#else
    movl 8(%esp), %eax
#endif
    // SEARCH_PHASE (bit 0) gets _URC_FATAL_PHASE1_ERROR (3), other phases
    // get _URC_FATAL_PHASE2_ERROR (2).
    andl $1, %eax
    addl $2, %eax
    ret
.cfi_endproc
.size yuki_barrier_personality, . - yuki_barrier_personality
