/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Enter the AOS Linux setup image without executing platform firmware. QEMU's
 * generic loaders place the prepared image and initramfs before this ROM runs.
 */

.code16
.section .text.boot, "ax"
.global boot
boot:
    cli
    xorl %eax, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $0x00009000, %esp

    /* Fail unsupported firmware calls instead of jumping through an empty IVT. */
    xorl %edi, %edi
    movw $256, %cx
1:
    movw $bios_unsupported, (%di)
    movw $0xf000, 2(%di)
    addw $4, %di
    loop 1b

    movw $bios_int15, (0x15 * 4)
    movw $0xf000, (0x15 * 4 + 2)

    movw $0x1000, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $0x0000fff0, %esp
    xorl %ebx, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    xorl %edi, %edi
    xorl %ebp, %ebp
    ljmp $0x1020, $0x0000

bios_unsupported:
    pushw %bp
    movw %sp, %bp
    orw $1, 6(%bp)
    popw %bp
    iret

bios_int15:
    cmpl $0x0000e820, %eax
    je bios_e820
    cmpw $0xe801, %ax
    je bios_e801
    cmpb $0x88, %ah
    je bios_88
    jmp bios_unsupported

bios_88:
    movw $0xfc00, %ax
    pushw %bp
    movw %sp, %bp
    andw $0xfffe, 6(%bp)
    popw %bp
    iret

bios_e801:
    movw $0x3c00, %ax
    movw $0x0f00, %bx
    movw %ax, %cx
    movw %bx, %dx
    pushw %bp
    movw %sp, %bp
    andw $0xfffe, 6(%bp)
    popw %bp
    iret

bios_e820:
    cmpl $0x534d4150, %edx
    jne bios_unsupported
    cmpl $20, %ecx
    jb bios_unsupported
    cmpl $2, %ebx
    ja bios_unsupported

    pushl %esi
    pushw %ds
    pushw %cs
    popw %ds
    movl %ebx, %esi
    shll $2, %ebx
    addl %esi, %ebx
    shll $2, %ebx
    addl $e820_entries, %ebx

    movl 0(%ebx), %eax
    movl %eax, %es:0(%di)
    movl 4(%ebx), %eax
    movl %eax, %es:4(%di)
    movl 8(%ebx), %eax
    movl %eax, %es:8(%di)
    movl 12(%ebx), %eax
    movl %eax, %es:12(%di)
    movl 16(%ebx), %eax
    movl %eax, %es:16(%di)

    popw %ds
    movl %esi, %ebx
    incl %ebx
    cmpl $3, %ebx
    jne 2f
    xorl %ebx, %ebx
2:
    popl %esi
    movl $0x534d4150, %eax
    movl $20, %ecx
    pushw %bp
    movw %sp, %bp
    andw $0xfffe, 6(%bp)
    popw %bp
    iret

.align 4
e820_entries:
    /* Conventional memory, firmware hole, and RAM through 256 MiB. */
    .quad 0x0000000000000000
    .quad 0x000000000009fc00
    .long 1
    .quad 0x000000000009fc00
    .quad 0x0000000000060400
    .long 2
    .quad 0x0000000000100000
    .quad 0x000000000ff00000
    .long 1

.section .reset, "ax"
    ljmp $0xf000, $boot
    .fill 11, 1, 0
