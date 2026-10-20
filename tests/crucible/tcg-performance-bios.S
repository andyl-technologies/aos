/* SPDX-License-Identifier: GPL-2.0-or-later */

/* A firmware-free, register and RAM workload with no host-dependent inputs. */
.section .text,"ax"
.code16
.global _start
_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movl $0x51f15eed, %eax
    xorl %ecx, %ecx

workload:
    roll $13, %eax
    xorl $0x9e3779b9, %eax
    addl $0x6d2b79f5, %eax
    movl %eax, 0x7000
    incl %ecx
    movl %ecx, 0x7004

.ifdef IO_POST
    /* POST writes force I/O exits without introducing host-dependent inputs. */
    outb %al, $0x80
.endif
    jmp workload

.section .reset,"ax"
.code16
    ljmp $0xf000, $0x0000
