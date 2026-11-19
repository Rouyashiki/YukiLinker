// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#if defined(__x86_64__)
#define YUKI_ENDBR endbr64
#define YUKI_PROPERTY_ALIGN 8
#elif defined(__i386__)
#define YUKI_ENDBR endbr32
#define YUKI_PROPERTY_ALIGN 4
#else
#error "Expected an Android x86 target"
#endif

.section .note.GNU-stack, "", @progbits

// LLD intersects the input IBT/SHSTK properties. Match the consuming build's
// compiler flags; every indirect entry has a landing pad and returns normally.
#if defined(__CET__) && (__CET__ & 3)
.section .note.gnu.property, "a", @note
.balign YUKI_PROPERTY_ALIGN
.long 4
.long .Lproperty_end - .Lproperty
.long 5
.asciz "GNU"
.Lproperty:
.long 0xc0000002 // GNU_PROPERTY_X86_FEATURE_1_AND
.long 4
.long __CET__ & 3
.balign YUKI_PROPERTY_ALIGN
.Lproperty_end:
#endif
