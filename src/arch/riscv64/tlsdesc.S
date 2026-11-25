// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKILINKER_FULL
#define YUKILINKER_FULL 0
#endif

#if !defined(__riscv) || __riscv_xlen != 64
#error "tlsdesc.S is the riscv64 TLSDESC resolver"
#endif

#if YUKILINKER_FULL
#include "tlsdesc_layout.h"

/*
 * RISC-V TLSDESC entry and return convention:
 *   Entry: a0 = descriptor address, t0 (x5) = return address.
 *   Exit:  a0 = target address - tp.
 * Preserve the other GPRs and floating-point state. Android's Clang can also keep RVV registers
 * live across a TLSDESC call, so preserve the vector file and configuration even when the Core
 * selects a narrower -march.
 */
.attribute arch, "rv64imafdcv"
.equ .Lwide_frame_bytes, 400
.text
.p2align 2
.hidden yuki_tlsdesc_dynamic_entry
.global yuki_tlsdesc_dynamic_entry
.type yuki_tlsdesc_dynamic_entry, %function
yuki_tlsdesc_dynamic_entry:
.cfi_startproc
.cfi_return_column 5
    addi sp, sp, -336
    .cfi_def_cfa_offset 336

    // The frame chain records the previous s0 and the TLSDESC return PC in t0.
    sd   s0, 320(sp)
    .cfi_offset s0, -16
    sd   t0, 328(sp)
    .cfi_offset t0, -8
    sd   ra, 16(sp)
    .cfi_offset ra, -320
    sd   t1, 24(sp)
    .cfi_offset t1, -312
    sd   t2, 32(sp)
    .cfi_offset t2, -304
    sd   t3, 40(sp)
    .cfi_offset t3, -296
    sd   t4, 48(sp)
    .cfi_offset t4, -288
    sd   t5, 56(sp)
    .cfi_offset t5, -280
    sd   t6, 64(sp)
    .cfi_offset t6, -272
    sd   a1, 72(sp)
    .cfi_offset a1, -264
    sd   a2, 80(sp)
    .cfi_offset a2, -256
    sd   a3, 88(sp)
    .cfi_offset a3, -248
    sd   a4, 96(sp)
    .cfi_offset a4, -240
    sd   a5, 104(sp)
    .cfi_offset a5, -232
    sd   a6, 112(sp)
    .cfi_offset a6, -224
    sd   a7, 120(sp)
    .cfi_offset a7, -216

    addi s0, sp, 336
    .cfi_def_cfa s0, 0

    fsd  ft0,  128(sp)
    .cfi_offset ft0, -208
    fsd  ft1,  136(sp)
    .cfi_offset ft1, -200
    fsd  ft2,  144(sp)
    .cfi_offset ft2, -192
    fsd  ft3,  152(sp)
    .cfi_offset ft3, -184
    fsd  ft4,  160(sp)
    .cfi_offset ft4, -176
    fsd  ft5,  168(sp)
    .cfi_offset ft5, -168
    fsd  ft6,  176(sp)
    .cfi_offset ft6, -160
    fsd  ft7,  184(sp)
    .cfi_offset ft7, -152
    fsd  ft8,  192(sp)
    .cfi_offset ft8, -144
    fsd  ft9,  200(sp)
    .cfi_offset ft9, -136
    fsd  ft10, 208(sp)
    .cfi_offset ft10, -128
    fsd  ft11, 216(sp)
    .cfi_offset ft11, -120
    fsd  fa0,  224(sp)
    .cfi_offset fa0, -112
    fsd  fa1,  232(sp)
    .cfi_offset fa1, -104
    fsd  fa2,  240(sp)
    .cfi_offset fa2, -96
    fsd  fa3,  248(sp)
    .cfi_offset fa3, -88
    fsd  fa4,  256(sp)
    .cfi_offset fa4, -80
    fsd  fa5,  264(sp)
    .cfi_offset fa5, -72
    fsd  fa6,  272(sp)
    .cfi_offset fa6, -64
    fsd  fa7,  280(sp)
    .cfi_offset fa7, -56
    frcsr t1
    sd   t1,   288(sp)

    csrr t2, vl
    sd   t2, 296(sp)
    csrr t3, vtype
    sd   t3, 0(sp)
    csrr t4, vcsr
    sd   t4, 8(sp)
    csrr t5, vstart
    sd   t5, 304(sp)

    // Small vector files stay inline. Acquire any wider save area with integer
    // instructions: both libc calls and Linux syscalls may clobber live vectors.
    addi sp, sp, -16
    csrr t1, vlenb
    li   t2, YUKI_RVV_INLINE_VLENB
    bgtu t1, t2, .Larm_spill
    sd   zero, -344(s0)
    slli t2, t1, 5
    sub  sp, sp, t2
    mv   t4, sp
    j    .Lspill
.Larm_spill:
    // The exit key records a numeric frame address. Neither libc nor its destructor
    // dereferences it after siglongjmp. Save the prior tag and pin state on this frame.
    addi sp, s0, -.Lwide_frame_bytes
    sd   zero, -344(s0)
.Lpin_thread:
    li   a7, 0
    ld   a6, YUKI_BIONIC_PTHREAD_FROM_TP(tp)
    lw   t2, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    srli t3, t2, YUKI_RISCV_TID_BITS
    bnez t3, .Linvalid_tid
    lla  t3, yuki_riscv_spill_threads
    ld   t3, 0(t3)
    slli t4, t2, 3
    add  t3, t3, t4
.Lregister_thread:
    ld   t6, 0(t3)
    beq  t6, tp, .Lpin_registered
    lw   a5, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    bne  a5, t2, .Lpin_thread
    lr.d.aq a4, (t3)
    bne  a4, t6, .Lregister_thread
    sc.d.rl a4, tp, (t3)
    bnez a4, .Lregister_thread
    li   a7, 1
.Lpin_registered:
    // Publish the chunk before the pin. Bits remain set through fork so an
    // enrollment interrupted between these stores can finish in either process.
    srli t3, t2, YUKI_RVV_PIN_CHUNK_SHIFT
    li   t4, 1
    sll  t4, t4, t3
    srli t3, t3, 6
    slli t3, t3, 3
    lla  t6, yuki_riscv_spill_pin_chunks
    add  t3, t3, t6
    ld   t6, (t3)
    and  t6, t6, t4
    bnez t6, .Lchunk_known
    amoor.d zero, t4, (t3)
.Lchunk_known:
    // Pin before arming the key. An interrupted acquisition which has not
    // armed it yet holds no files. Only the outermost pin clears its bit.
    lla  t3, yuki_riscv_spill_pins
    ld   t3, 0(t3)
    andi t4, t2, -YUKI_RVV_PIN_GROUP   // eight TIDs share one eight-byte word
    add  t3, t3, t4
    andi t4, t2, YUKI_RVV_PIN_GROUP-1
    li   t6, 1
    sll  t4, t6, t4
.Lmark_pin:
    ld   t6, (t3)
    lw   a4, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    bne  a4, t2, .Lpin_thread
    addi a5, t6, YUKI_RVV_PIN_EPOCH
    bgeu a5, t6, .Lpin_set
    mv   a5, t6                        // keep this group conservatively pinned on overflow
.Lpin_set:
    or   a5, a5, t4
    lr.d.aq a4, (t3)
    bne  a4, t6, .Lmark_pin
    sc.d.rl a4, a5, (t3)
    bnez a4, .Lmark_pin
    not  t6, t6
    and  t6, t6, t4
    or   a7, a7, t6
    // A signal handler can fork between reading the TID and claiming its bit.
    lw   a4, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    beq  a4, t2, .Lpin_done
    beqz t6, .Lpin_thread
    not  t4, t4
    and  t6, a5, t4
.Lundo_phantom_pin:
    lr.d.aq a4, (t3)
    bne  a4, a5, .Lpin_thread
    sc.d.rl a4, t6, (t3)
    bnez a4, .Lundo_phantom_pin
    j    .Lpin_thread
.Lpin_done:
    sd   a7, 16(sp)
    sd   t2, 24(sp)
    sd   a5, 40(sp)
    ld   t2, YUKI_BIONIC_KEY_DATA_FROM_TP(tp)
    lla  t3, yuki_riscv_spill_key
    ld   t4, 0(t3)
    add  t2, t2, t4
    sd   t2, 0(sp)
    ld   t4, 8(t3)                    // sequence from a real pthread_setspecific
    amoswap.d t3, t4, (t2)
    addi t2, t2, 8
    amoswap.d t6, s0, (t2)           // numeric frame tag, never dereferenced
    beq  t3, t4, .Lkey_current
    li   t6, 0                        // this index previously belonged to another key
.Lkey_current:
    sd   t6, 8(sp)
    // The fork owner's slots are available even to child handlers registered before Core.
    // Their TLS lookup can then reach the ordinary early-child recovery path.
    li   a4, YUKI_RVV_OWNERS
    li   a5, YUKI_RVV_FORK_OWNERS
    lla  t2, yuki_riscv_spill_fork_thread
    ld   t2, 0(t2)
    bne  t2, tp, .Lfirst_bank
    li   a4, YUKI_RVV_FORK_OWNERS
    li   a5, YUKI_RVV_NESTED_OWNERS
.Lfirst_bank:
    lla  a2, yuki_riscv_spill_banks
    ld   t5, 0(a2)
    fence r, rw
    beqz t5, .Lstack_fallback
.Lbank:
    add  t2, t5, a4
    add  t6, t5, a5
.Lslot:
    ld   t3, 0(t2)
    bne  t3, tp, .Lordinary_new
    ld   t3, (YUKI_RVV_FRAMES-YUKI_RVV_OWNERS)(t2)
    bne  t3, s0, .Lnext_slot         // the same frame address cannot be active twice
    mv   a1, tp
    j    .Ltry_slot
.Lordinary_new:
    bnez t3, .Lnext_slot
    li   a1, 0
.Ltry_slot:
    lr.d.aq t3, (t2)
    bne  t3, a1, .Lnext_slot
    sc.d.rl t3, tp, (t2)             // publish the pin even on same-frame reuse
    bnez t3, .Ltry_slot
    addi t3, t2, (YUKI_RVV_FRAMES-YUKI_RVV_OWNERS)
    addi t4, t5, YUKI_RVV_FILES
.Lclaimed:
    sd   s0, 0(t3)
    sd   t3, 32(sp)
    sd   t2, -344(s0)
    addi t3, t5, YUKI_RVV_OWNERS
    sub  t3, t2, t3
    srli t3, t3, 3
    slli a3, t1, 5                    // a register file is 32 vlenb at every bank
    mul  t3, t3, a3
    add  t4, t4, t3
    j    .Lspill
.Lnext_slot:
    addi t2, t2, 8
    bltu t2, t6, .Lslot
    // A signal can interrupt the final normal borrower while fork holds both locks.
    // Only that borrower can enter this bank's nested range, and it retains the normal
    // slot until all its signal frames return. The fork owner's range stays independent.
    addi t3, t5, YUKI_RVV_FORK_OWNERS
    bne  t6, t3, .Lnext_bank
    ld   t3, -8(t6)
    andi t3, t3, -2
    bne  t3, tp, .Lnext_bank
    addi t2, t5, YUKI_RVV_NESTED_OWNERS
    addi t6, t5, YUKI_RVV_LOCK_OWNERS
    j    .Lslot
.Lnext_bank:
    mv   t4, t5
    ld   t5, 0(t4)
    fence r, rw
    bnez t5, .Lbank
    li   t2, YUKI_RVV_OWNERS
    bne  a4, t2, .Lgrow_bank
    // Cold lookups, including one nested inside the last ordinary borrower, can all
    // wait for the fork owner. A thread with native TLS has its own reserve.
    lla  t2, yuki_riscv_thread_spills
    ld   t5, 0(t2)
.Lthread_bank:
    fence r, rw
    beqz t5, .Lthread_end
    ld   a3, YUKI_RVV_THREAD_TAG(t5)
    beq  a3, tp, .Lthread_file
.Lnext_thread_bank:
    ld   t5, 0(t5)
    j    .Lthread_bank
.Lthread_file:
    addi t2, t5, YUKI_RVV_OWNERS
    addi t3, t5, YUKI_RVV_THREAD_TAG
.Lclaim_thread:
    ld   a3, 0(t2)
    bne  a3, tp, .Lthread_new
    ld   a3, (YUKI_RVV_THREAD_FRAMES-YUKI_RVV_OWNERS)(t2)
    bne  a3, s0, .Lnext_thread_file
    mv   a1, tp
    j    .Ltry_thread_file
.Lthread_new:
    bnez a3, .Lnext_thread_file
    li   a1, 0
.Ltry_thread_file:
    lr.d.aq a3, (t2)
    bne  a3, a1, .Lnext_thread_file
    sc.d.rl a3, tp, (t2)
    bnez a3, .Ltry_thread_file
    bnez a1, .Lthread_claimed
    ld   a3, YUKI_RVV_THREAD_TAG(t5)
    beq  a3, tp, .Lthread_claimed
    fence rw, w
    sd   zero, 0(t2)
    j    .Lnext_thread_bank
.Lthread_claimed:
    addi t3, t2, (YUKI_RVV_THREAD_FRAMES-YUKI_RVV_OWNERS)
    addi t4, t5, YUKI_RVV_THREAD_FILES
    j    .Lclaimed
.Lnext_thread_file:
    addi t2, t2, 8
    bltu t2, t3, .Lclaim_thread
    // A retired pthread's state can await collection after libc reuses its tp.
    j    .Lnext_thread_bank
.Lthread_end:
    // Ordinary borrowers may all be waiting for our recursive operation mutex.
    // Use its reserve before growing, including when the reservation fits one bank.
    lla  t2, yuki_riscv_operation_owner_tid
    ld   t2, 0(t2)
    lw   t2, 0(t2)
    ld   t3, YUKI_BIONIC_PTHREAD_FROM_TP(tp)
    lw   t3, YUKI_BIONIC_TID_FROM_PTHREAD(t3)
    bne  t2, t3, .Lgrow_bank
    li   a4, YUKI_RVV_LOCK_OWNERS
    li   a5, YUKI_RVV_FRAMES
    j    .Lfirst_bank
.Lgrow_bank:
    // Every borrower computes the same successor in the existing mapping.
    // Preemption, fork or a nonlocal exit before publication leaves it available.
    lla  t2, yuki_riscv_spill_stride
    ld   t2, (t2)
    add  t5, t4, t2
    lla  t3, yuki_riscv_spill_end
    ld   t3, (t3)
    bgeu t5, t3, .Lstack_fallback
    amoswap.d.rl zero, t5, (t4)
    j    .Lbank
.Lstack_fallback:
    // The descriptor must still return the TLS address under pressure. Waiting for a
    // shared file could deadlock with an interrupted borrower or the operation mutex.
    // Probe each minimum-sized Android page before moving farther down the stack.
    slli t2, t1, 5
    li   t4, 4096
.Lprobe_stack:
    bleu t2, t4, .Lfinish_stack
    sub  sp, sp, t4
    sd   zero, 0(sp)
    sub  t2, t2, t4
    j    .Lprobe_stack
.Lfinish_stack:
    sub  sp, sp, t2
    mv   t4, sp
.Lspill:
    sd   t4, -352(s0)
    slli t3, t1, 3
    csrwi vstart, 0
    vs8r.v v0,  (t4)
    add  t4, t4, t3
    vs8r.v v8,  (t4)
    add  t4, t4, t3
    vs8r.v v16, (t4)
    add  t4, t4, t3
    vs8r.v v24, (t4)

    call yuki_tlsdesc_dynamic_body

    csrr t1, vlenb
    slli t3, t1, 3
    ld   t4, -352(s0)
    csrwi vstart, 0
    vl8r.v v0,  (t4)
    add  t4, t4, t3
    vl8r.v v8,  (t4)
    add  t4, t4, t3
    vl8r.v v16, (t4)
    add  t4, t4, t3
    vl8r.v v24, (t4)

    ld   t2, -344(s0)
    beqz t2, .Lrestore_stack_spill
    ld   t3, 32(sp)
    sd   zero, 0(t3)
    fence rw, w
    sd   zero, 0(t2)
.Lpop_spill:
    ld   a3, 0(sp)
    addi a3, a3, 8
    ld   a4, 8(sp)
    bnez a4, .Lpop_key
    // A nested entry can run during first-use initialization of a recycled
    // Bionic key. Inspect actual borrows if the enrollment sequence changed.
    ld   a6, YUKI_BIONIC_PTHREAD_FROM_TP(tp)
    lw   t2, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    ld   t3, 24(sp)
    bne  t2, t3, .Lscan_owner_list
    srli t3, t2, YUKI_RISCV_TID_BITS
    bnez t3, .Lscan_owner_list
    lla  t3, yuki_riscv_spill_pins
    ld   t3, 0(t3)
    andi t4, t2, -YUKI_RVV_PIN_GROUP   // eight TIDs share one eight-byte word
    add  t3, t3, t4
    ld   t4, (t3)
    li   t6, -YUKI_RVV_PIN_EPOCH
    bgeu t4, t6, .Lrestore             // retain the exit key if the sequence has saturated
    ld   t6, 40(sp)
    beq  t4, t6, .Lpop_key
.Lscan_owner_list:
    li   a7, YUKI_RVV_TOTAL_SLOTS
    lla  t2, yuki_riscv_spill_banks
.Lcheck_owner_list:
    ld   t2, (t2)
    fence r, rw
    beqz t2, .Lowner_list_end
    addi t3, t2, YUKI_RVV_OWNERS
    mv   t4, a7
.Lcheck_owner:
    ld   t6, (t3)
    andi t6, t6, -2
    beq  t6, tp, .Lrestore
    addi t3, t3, 8
    addi t4, t4, -1
    bnez t4, .Lcheck_owner
    j    .Lcheck_owner_list
.Lowner_list_end:
    li   t4, YUKI_RVV_NESTED_SLOTS
    beq  a7, t4, .Lpop_key
    mv   a7, t4
    lla  t2, yuki_riscv_thread_spills
    j    .Lcheck_owner_list
.Lpop_key:
    // An inner lookup discarded by siglongjmp retains its tag and exit key.
    lr.d t3, (a3)
    bne  t3, s0, .Lrestore
    sc.d t3, a4, (a3)
    bnez t3, .Lpop_key
    bnez a4, .Lrestore
    ld   t3, 16(sp)
    beqz t3, .Lrestore
    ld   a6, YUKI_BIONIC_PTHREAD_FROM_TP(tp)
.Lunpin_thread:
    lw   t2, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    srli t3, t2, YUKI_RISCV_TID_BITS
    bnez t3, .Lrestore
    lla  t3, yuki_riscv_spill_pins
    ld   t3, 0(t3)
    andi t4, t2, -YUKI_RVV_PIN_GROUP   // eight TIDs share one eight-byte word
    add  t3, t3, t4
    andi t4, t2, YUKI_RVV_PIN_GROUP-1
    li   t6, 1
    sll  t4, t6, t4
    not  t4, t4
.Lunpin_snapshot:
    ld   t6, (t3)
    li   a5, -YUKI_RVV_PIN_EPOCH
    bgeu t6, a5, .Lrestore
    lw   a5, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    bne  a5, t2, .Lunpin_thread
    ld   a5, (a3)
    bnez a5, .Lrestore
    and  a5, t6, t4
.Lunpin_cas:
    lr.d.aq a7, (t3)
    bne  a7, t6, .Lunpin_snapshot
    sc.d.rl a7, a5, (t3)
    bnez a7, .Lunpin_cas
    lw   t6, YUKI_BIONIC_TID_FROM_PTHREAD(a6)
    bne  t6, t2, .Lunpin_thread
    j    .Lrestore
.Lrestore_stack_spill:
    li   t3, YUKI_RVV_INLINE_VLENB
    bleu t1, t3, .Lrestore
    addi sp, s0, -.Lwide_frame_bytes  // discard the file and keep the wide path's key state
    j    .Lpop_spill
.Linvalid_tid:
    neg  a0, tp
.Lrestore:
    addi sp, s0, -336
    .cfi_def_cfa sp, 336
    ld   t2, 296(sp)
    ld   t3, 0(sp)
    ld   t4, 8(sp)
    csrw vcsr, t4
    vsetvl zero, t2, t3
    ld   t5, 304(sp)
    csrw vstart, t5

    ld   t1, 288(sp)
    fscsr t1
    fld  fa7,  280(sp)
    fld  fa6,  272(sp)
    fld  fa5,  264(sp)
    fld  fa4,  256(sp)
    fld  fa3,  248(sp)
    fld  fa2,  240(sp)
    fld  fa1,  232(sp)
    fld  fa0,  224(sp)
    fld  ft11, 216(sp)
    fld  ft10, 208(sp)
    fld  ft9,  200(sp)
    fld  ft8,  192(sp)
    fld  ft7,  184(sp)
    fld  ft6,  176(sp)
    fld  ft5,  168(sp)
    fld  ft4,  160(sp)
    fld  ft3,  152(sp)
    fld  ft2,  144(sp)
    fld  ft1,  136(sp)
    fld  ft0,  128(sp)

    ld   a7, 120(sp)
    ld   a6, 112(sp)
    ld   a5, 104(sp)
    ld   a4, 96(sp)
    ld   a3, 88(sp)
    ld   a2, 80(sp)
    ld   a1, 72(sp)
    ld   t6, 64(sp)
    ld   t5, 56(sp)
    ld   t4, 48(sp)
    ld   t3, 40(sp)
    ld   t2, 32(sp)
    ld   t1, 24(sp)
    ld   ra, 16(sp)
    ld   t0, 328(sp)
    ld   s0, 320(sp)
    .cfi_restore s0
    addi sp, sp, 336
    .cfi_def_cfa_offset 0
    .cfi_restore t0
    .cfi_restore ra
    .cfi_restore t1
    .cfi_restore t2
    .cfi_restore t3
    .cfi_restore t4
    .cfi_restore t5
    .cfi_restore t6
    .cfi_restore a1
    .cfi_restore a2
    .cfi_restore a3
    .cfi_restore a4
    .cfi_restore a5
    .cfi_restore a6
    .cfi_restore a7
    .cfi_restore ft0
    .cfi_restore ft1
    .cfi_restore ft2
    .cfi_restore ft3
    .cfi_restore ft4
    .cfi_restore ft5
    .cfi_restore ft6
    .cfi_restore ft7
    .cfi_restore ft8
    .cfi_restore ft9
    .cfi_restore ft10
    .cfi_restore ft11
    .cfi_restore fa0
    .cfi_restore fa1
    .cfi_restore fa2
    .cfi_restore fa3
    .cfi_restore fa4
    .cfi_restore fa5
    .cfi_restore fa6
    .cfi_restore fa7
    jr   t0
.cfi_endproc
.size yuki_tlsdesc_dynamic_entry, . - yuki_tlsdesc_dynamic_entry

.p2align 2
.hidden yuki_tlsdesc_weak_entry
.global yuki_tlsdesc_weak_entry
.type yuki_tlsdesc_weak_entry, %function
yuki_tlsdesc_weak_entry:
.cfi_startproc
.cfi_return_column 5
    ld   a0, 8(a0)
    sub  a0, a0, tp
    jr   t0
.cfi_endproc
.size yuki_tlsdesc_weak_entry, . - yuki_tlsdesc_weak_entry

#endif  // YUKILINKER_FULL

.section .note.GNU-stack, "", @progbits
