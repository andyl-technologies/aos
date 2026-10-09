/* SPDX-License-Identifier: MIT */
/* The x86 workload's memory operations expressed with AArch64 Linux syscalls. */
.section .bss
.balign 4096
arena:
    .skip 262144
answer:
    .skip 8

.section .text
.global _start
_start:
    adrp x1, arena
    add x1, x1, :lo12:arena
    mov w2, #20000
    mov w8, #3
    mov x11, #0
    mov w12, #0x660d
    movk w12, #0x19, lsl #16
    mov w13, #0xf35f
    movk w13, #0x3c6e, lsl #16
    mov w9, #0xfff8
    movk w9, #3, lsl #16

memory_loop:
    mul w8, w8, w12
    add w8, w8, w13
    and w0, w8, w9
    ldr x10, [x1, x0]
    eor x10, x10, x8
    str x10, [x1, x0]
    add x11, x11, x10
    tbz w8, #0, even_value
    add x11, x11, #19

even_value:
    subs w2, w2, #1
    b.ne memory_loop

    adrp x1, answer
    add x1, x1, :lo12:answer
    str x11, [x1]
    mov x0, #1
    mov x2, #8
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

.section .note.GNU-stack,"",@progbits
