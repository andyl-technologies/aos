/* SPDX-License-Identifier: Apache-2.0 */

/* Enter the loaded fault guest directly instead of spending the gate in BIOS. */
.code16
.section .text.boot, "ax"
.global boot
boot:
    cli
    movw %cs, %ax
    movw %ax, %ds
    lgdt gdt_descriptor
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $protected_mode + 0x000f0000

.code32
protected_mode:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $0x00090000, %esp
    movl $0x2badb002, %eax
    xorl %ebx, %ebx
    ljmp $0x08, $GUEST_ENTRY

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
