/* SPDX-License-Identifier: Apache-2.0 */
/* Closed instruction profiles, ordinary CPU memory accesses, no delayed fault grant. */
.section .text,"ax"
.code16
.global _start
_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    /* Enable ordinary SSE without enabling interrupts or a host-dependent boot. */
    movl %cr0, %eax
    andl $0xfffffffb, %eax
    orl $2, %eax
    movl %eax, %cr0
    movl %cr4, %eax
    orl $0x600, %eax
    movl %eax, %cr4

    /* Unrolled stores make the startup retired-instruction count unambiguous. */
.set arena_word, 0x7000
.rept 2048
    movl $0x35353535, arena_word
.set arena_word, arena_word + 4
.endr
    movl $0x51f15eed, %esi
    xorl %ebp, %ebp

.global writer_loop
writer_loop:
    roll $13, %esi
    xorl $0x9e3779b9, %esi
    addl $0x6d2b79f5, %esi
    movl %esi, %eax

/* Operation targets touch page two; ordinary counter/witness stores stay in page one. */
.global operation_begin
operation_begin:
.ifdef OMIT_OPERATION
.if CASE == 10
.rept 5
    nop
.endr
.elseif CASE == 11
.rept 6
    nop
.endr
.elseif CASE == 25 || CASE == 26
.rept 5
    nop
.endr
.elseif CASE >= 23 && CASE <= 24 || CASE == 27
.rept 3
    nop
.endr
.elseif CASE >= 12 && CASE <= 14
.rept 3
    nop
.endr
.else
    nop
.endif
.else
.if CASE == 0
    movb %al, 0x8040
.elseif CASE == 1
    movw %ax, 0x8040
.elseif CASE == 2
    movl %eax, 0x8040
.elseif CASE == 3
    movl %eax, 0x8043
.elseif CASE == 4
    movl %eax, 0x7ffd
.elseif CASE == 5
    xchgb %al, 0x8040
.elseif CASE == 6
    xchgw %ax, 0x8040
.elseif CASE == 7
    xchgl %eax, 0x8040
.elseif CASE == 8
    xchgl %eax, 0x8043
.elseif CASE == 9
    xchgl %eax, 0x7ffd
.elseif CASE == 10
    movl 0x8080, %eax
    movl 0x8084, %edx
    movl %esi, %ebx
    movl %esi, %ecx
    lock cmpxchg8b 0x8080
.elseif CASE == 11
    movl %esi, %ecx
.ifdef FORCE_FAILED_CAS_SUCCESS
    movl $0x35353535, %eax
.else
    xorl %eax, %eax
.endif
    lock cmpxchgl %ecx, 0x8080
    movl %eax, 0x7100
    sete %dl
    movb %dl, 0x7104
.elseif CASE >= 12 && CASE <= 14
    movd %esi, %xmm0
    pshufd $0, %xmm0, %xmm0
.if CASE == 12
    movdqa %xmm0, 0x8080
.elseif CASE == 13
    movdqu %xmm0, 0x8083
.else
    movdqu %xmm0, 0x7ff9
.endif
.elseif CASE == 15
    lock addb %al, 0x8040
.elseif CASE == 16
    lock addw %ax, 0x8040
.elseif CASE == 17
    lock addl %eax, 0x8040
.elseif CASE == 18
    lock addl %eax, 0x8043
.elseif CASE == 19
    lock addl %eax, 0x7ffd
.elseif CASE == 20
    lock xaddl %eax, 0x8040
.elseif CASE == 21
    lock xaddl %eax, 0x8043
.elseif CASE == 22
    lock xaddl %eax, 0x7ffd
.elseif CASE == 23 || CASE == 24
.if CASE == 23
    movl 0x8080, %eax
    movl %esi, %ecx
    lock cmpxchgl %ecx, 0x8080
.else
    movl 0x7ffd, %eax
    movl %esi, %ecx
    lock cmpxchgl %ecx, 0x7ffd
.endif
.elseif CASE == 25 || CASE == 26
.if CASE == 25
.set cas_target, 0x8083
.else
.set cas_target, 0x7ffd
.endif
    movl cas_target, %eax
    movl cas_target + 4, %edx
    movl %esi, %ebx
    movl %esi, %ecx
    lock cmpxchg8b cas_target
.elseif CASE == 27
    /* Two ordinary writes have distinct partial cuts, not an atomic group. */
    movl %eax, 0x7ff8
    notl %eax
    movl %eax, 0x8008
.else
.error "closed CASE required"
.endif
.endif
.global operation_end
operation_end:
    incl %ebp
.if CASE == 11
    /* Failed CAS makes no target-byte claim; this ordinary store witnesses progress. */
    movl %ebp, 0x7010
.else
    /* EBP witnesses progress without masking either half of a cross-page write. */
    nop
.endif
    jmp writer_loop

.section .identity,"a"
    .ascii "CRUCWRT1"
    .long CASE

.section .reset,"ax"
.code16
    ljmp $0xf000, $0x0000
