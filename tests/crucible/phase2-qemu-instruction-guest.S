/* SPDX-License-Identifier: Apache-2.0 */

.section .multiboot, "a"
.align 4
.long 0x1badb002
.long 0x00000003
.long -(0x1badb002 + 0x00000003)

.section .text
.code32
.global _start
_start:
    cli
    lgdt gdt_descriptor
    ljmp $0x08, $1f
1:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    mov $stack_top, %esp

    mov %cr4, %eax
    or $0x620, %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr
    mov $page_map_level_4, %eax
    mov %eax, %cr3
    mov %cr0, %eax
    or $0x80010000, %eax
    and $~(1 << 2), %eax
    or $(1 << 1), %eax
    mov %eax, %cr0
    ljmp $0x18, $long_mode_start

.code64
long_mode_start:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    lea stack_top(%rip), %rsp

    lea instruction_exception_handler(%rip), %rax
    movw %ax, instruction_idt + 6 * 16(%rip)
    shr $16, %rax
    movw %ax, instruction_idt + 6 * 16 + 6(%rip)
    movl $0, instruction_idt + 6 * 16 + 8(%rip)
    lea instruction_page_fault_handler(%rip), %rax
    movw %ax, instruction_idt + 14 * 16(%rip)
    shr $16, %rax
    movw %ax, instruction_idt + 14 * 16 + 6(%rip)
    movl $0, instruction_idt + 14 * 16 + 8(%rip)
    lidt idt_descriptor(%rip)

instruction_loop:
    incl instruction_iterations(%rip)

.global instruction_result
instruction_result:
    mov $0x40, %rax
    cmp $0x41, %eax
    je 7f
    cmp $0x43, %eax
    jne 8f
7:
    mov %eax, instruction_result_value(%rip)
8:

    mov instruction_skip_count(%rip), %ebx
.global instruction_skip
instruction_skip:
    add $1, %rbx
    mov %ebx, instruction_skip_count(%rip)

    mov instruction_replay_count(%rip), %ecx
.global instruction_replay
instruction_replay:
    add $1, %rcx
    mov %ecx, instruction_replay_count(%rip)

.global instruction_exception_probe
instruction_exception_probe:
    nop

    mov $0x12345679, %edx
    call instruction_load
    cmpl $1, instruction_store_count(%rip)
    jne 11f
    movl $0, instruction_store_count(%rip)
    call instruction_store
11:
    cmpl $1, instruction_atomic_count(%rip)
    jne 12f
    movl $0, instruction_atomic_count(%rip)
    mov $1, %eax
    call instruction_atomic
12:
    movaps instruction_fp_one(%rip), %xmm1
    xorps %xmm0, %xmm0
    call instruction_fp_simd
    cmpl $1, instruction_control_count(%rip)
    jne 13f
    movl $0, instruction_control_count(%rip)
    call instruction_control_case
13:
    cmpl $1, instruction_natural_exception_count(%rip)
    jne 14f
    movl $0, instruction_natural_exception_count(%rip)
    call instruction_natural_exception
14:
    cmpl $1, instruction_result_fault_count(%rip)
    jne 15f
    movl $0, instruction_result_fault_count(%rip)
    call instruction_result_fault
15:
    mov $0x5a, %eax
    call instruction_device_io
    call instruction_self_modify
    jmp instruction_loop

.global instruction_control_case
instruction_control_case:
.global instruction_control
instruction_control:
    jmp 2f
    jmp 3f
2:
    incl instruction_control_count(%rip)
3:
    ret

.global instruction_atomic
instruction_atomic:
.global instruction_atomic_instruction
instruction_atomic_instruction:
    lock addl $1, instruction_atomic_count(%rip)
    ret

.global instruction_load
instruction_load:
.global instruction_load_instruction
instruction_load_instruction:
    mov instruction_load_source(%rip), %edx
    cmp $0x12345679, %edx
    sete %al
    movzbl %al, %eax
    add $0x40, %eax
    cmp $0x41, %eax
    je 9f
    cmpl $0x41, instruction_load_result(%rip)
    je 10f
9:
    mov %eax, instruction_load_result(%rip)
10:
    ret

.global instruction_store
instruction_store:
.global instruction_store_instruction
instruction_store_instruction:
    incl instruction_store_count(%rip)
    ret

.global instruction_fp_simd
instruction_fp_simd:
    addps %xmm1, %xmm0
    movd %xmm0, %eax
    test %eax, %eax
    je 5f
    cmp $0x3f800001, %eax
    je 5f
    cmp $0x40400000, %eax
    jne 6f
5:
    mov $0x41, %eax
    jmp 7f
6:
    mov $0x40, %eax
7:
    cmp $0x41, %eax
    je 9f
    cmpl $0x41, instruction_fp_result(%rip)
    je 10f
9:
    mov %eax, instruction_fp_result(%rip)
10:
    ret

.global instruction_natural_exception
instruction_natural_exception:
.global instruction_exception_instruction
instruction_exception_instruction:
    ud2
    ret

.global instruction_device_io
instruction_device_io:
.global instruction_device_instruction
instruction_device_instruction:
    outb %al, $0x40
    ret

.global instruction_self_modify
instruction_self_modify:
    lea instruction_self_modify_byte(%rip), %rdi
.global instruction_self_modify_instruction
instruction_self_modify_instruction:
    incb (%rdi)
    ret
instruction_self_modify_byte:
    .byte 0

instruction_exception_handler:
    lea instruction_exception_instruction(%rip), %rax
    cmp %rax, (%rsp)
    jne 4f
    addq $2, (%rsp)
    incl instruction_natural_exception_count(%rip)
    iretq

.global instruction_result_fault
instruction_result_fault:
    movabs $0xffff800000000000, %rdi
.global instruction_result_fault_instruction
instruction_result_fault_instruction:
    mov (%rdi), %eax
    and $1, %eax
    add $0x40, %eax
    mov %eax, instruction_result_fault_value(%rip)
    ret

instruction_page_fault_handler:
    lea instruction_result_fault_instruction(%rip), %rax
    cmp %rax, 8(%rsp)
    jne 16f
    lea instruction_result_fault_source(%rip), %rdi
    incl instruction_result_fault_count(%rip)
    add $8, %rsp
    iretq
16:
    hlt
4:
    incl instruction_exception_count(%rip)
    iretq

.section .data, "aw"
.align 8
.global instruction_iterations
instruction_iterations:
    .long 0
.global instruction_result_value
instruction_result_value:
    .long 0
.global instruction_skip_count
instruction_skip_count:
    .long 0
.global instruction_replay_count
instruction_replay_count:
    .long 0
.global instruction_exception_count
instruction_exception_count:
    .long 0
.global instruction_natural_exception_count
instruction_natural_exception_count:
    .long 1
.global instruction_result_fault_count
instruction_result_fault_count:
    .long 1
.global instruction_result_fault_value
instruction_result_fault_value:
    .long 0
instruction_result_fault_source:
    .long 0
.global instruction_control_count
instruction_control_count:
    .long 1
.global instruction_store_count
instruction_store_count:
    .long 1
.global instruction_atomic_count
instruction_atomic_count:
    .long 1
instruction_load_source:
    .long 0x12345678
.global instruction_load_result
instruction_load_result:
    .long 0
.global instruction_fp_result
instruction_fp_result:
    .long 0
.align 16
instruction_fp_one:
    .long 0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000

.align 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
gdt_end:
gdt_descriptor:
    .word gdt_end - gdt - 1
    .long gdt

.section .data, "aw"
.align 8
instruction_idt:
    .rept 6
    .quad 0
    .quad 0
    .endr
    .word 0
    .word 0x18
    .byte 0
    .byte 0x8e
    .word 0
    .long 0
    .long 0
    .rept 249
    .quad 0
    .quad 0
    .endr
instruction_idt_end:

.section .data, "aw"
idt_descriptor:
    .word instruction_idt_end - instruction_idt - 1
    .long instruction_idt
    .long 0

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:

.section .page_tables, "aw"
.align 4096
page_map_level_4:
    .long page_directory_pointer + 0x3
    .long 0
    .fill 511, 8, 0
.align 4096
page_directory_pointer:
    .long page_directory + 0x3
    .long 0
    .fill 511, 8, 0
.align 4096
page_directory:
.set huge_page_address, 0
.rept 512
    .quad huge_page_address + 0x83
    .set huge_page_address, huge_page_address + 0x200000
.endr

.section .note.GNU-stack, "", @progbits
