// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#if !defined(__riscv) || __riscv_xlen != 64
#error "call_barrier.S is the riscv64 barrier"
#endif

/*
 * uintptr_t yuki_call_barrier(const void* function, uintptr_t a0, uintptr_t a1, uintptr_t a2)
 * calls function(a0, a1, a2). Its frame names a personality that fails the search phase, so an
 * exception escaping module code ends in std::terminate here instead of unwinding through runtime
 * frames, which have no cleanups. A backtrace still walks through it: _Unwind_Backtrace never calls
 * the personality.
 */
.text
.p2align 2
.hidden yuki_call_barrier
.global yuki_call_barrier
.type yuki_call_barrier, %function
yuki_call_barrier:
.cfi_startproc
.cfi_personality 0x1b, yuki_barrier_personality
    addi sp, sp, -16
    .cfi_def_cfa_offset 16
    sd   ra, 8(sp)
    sd   s0, 0(sp)
    .cfi_offset ra, -8
    .cfi_offset s0, -16
    addi s0, sp, 16
    mv   t0, a0
    mv   a0, a1
    mv   a1, a2
    mv   a2, a3
    jalr ra, 0(t0)
    ld   ra, 8(sp)
    ld   s0, 0(sp)
    addi sp, sp, 16
    .cfi_restore ra
    .cfi_restore s0
    .cfi_def_cfa_offset 0
    ret
.cfi_endproc
.size yuki_call_barrier, . - yuki_call_barrier

/* (version, actions, ...): the search phase (_UA_SEARCH_PHASE, bit 0) gets _URC_FATAL_PHASE1_ERROR
 * (3), so _Unwind_RaiseException returns and the thrower terminates; a cleanup or forced phase
 * gets _URC_FATAL_PHASE2_ERROR (2). */
.p2align 2
.hidden yuki_barrier_personality
.global yuki_barrier_personality
.type yuki_barrier_personality, %function
yuki_barrier_personality:
.cfi_startproc
    andi a0, a1, 1
    addi a0, a0, 2
    ret
.cfi_endproc
.size yuki_barrier_personality, . - yuki_barrier_personality

.section .note.GNU-stack, "", @progbits
