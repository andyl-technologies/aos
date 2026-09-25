/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Enter the 32-bit LAPIC fixture without executing platform firmware. The
 * generic loader places guest.elf in RAM before this reset ROM runs.
 */

.code16
.section .text.boot, "ax"
.global boot
boot:
    cli
    movw $0xf000, %ax
    movw %ax, %ds
    lgdt gdt_descriptor

    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $(0x000f0000 + protected_entry)

.code32
protected_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorl %eax, %eax
    movw %ax, %fs
    movw %ax, %gs

    movl $0x00090000, %esp
    movl $0x00100034, %eax
    jmp *%eax

.align 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:

gdt_descriptor:
    .word gdt_end - gdt - 1
    .long 0x000f0000 + gdt

.section .reset, "ax"
.code16
    ljmp $0xf000, $boot
    .fill 11, 1, 0
