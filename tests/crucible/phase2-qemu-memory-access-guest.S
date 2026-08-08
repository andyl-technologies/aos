/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The live gate assembles this guest once per TEST_MODE.  Each image performs
 * exactly one production memory operation after a deterministic setup delay,
 * publishes its complete result vector, and then spins without touching the
 * target again.  The delay lets the plugin commit its rule before the tested
 * operation without adding a test-only synchronization path to QEMU.
 */

.ifndef TEST_MODE
.set TEST_MODE, 1
.endif

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
    mov $page_map_level4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr
    mov %cr0, %eax
    or $0x80010000, %eax
    mov %eax, %cr0
    lgdt gdt_descriptor
    ljmp $0x08, $long_mode

.code64
long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $stack_top, %rsp
    lea exception_handler(%rip), %rax
    movw %ax, idt + 14 * 16
    movw $0x08, idt + 14 * 16 + 2
    movb $0, idt + 14 * 16 + 4
    movb $0x8e, idt + 14 * 16 + 5
    shr $16, %rax
    movw %ax, idt + 14 * 16 + 6
    shr $16, %rax
    movl %eax, idt + 14 * 16 + 8
    movl $0, idt + 14 * 16 + 12
    lea idt(%rip), %rax
    movq %rax, idt_descriptor + 2
    lidt idt_descriptor
.if TEST_MODE >= 14
    movb $0x7e, scenario_result
0:
    cmpb $0x7f, scenario_result
    jne 0b
.endif
    mov $20000, %ecx
1:
    pause
    loop 1b

.if TEST_MODE == 1
    movb aligned_target, %al
    movb %al, aligned_result
.elseif TEST_MODE == 2
    movl unaligned_target, %eax
    movl %eax, unaligned_result
.elseif TEST_MODE == 3
    movq cross_page_target, %rax
    movq %rax, cross_page_result
.elseif TEST_MODE == 4
    mov $0xa5a5a5a5, %eax
    movl %eax, aligned_target
    movl aligned_target, %eax
    movl %eax, aligned_result
.elseif TEST_MODE == 5
    mov $0xa5a5a5a5, %eax
    movl %eax, unaligned_target
    movl unaligned_target, %eax
    movl %eax, unaligned_result
.elseif TEST_MODE == 6
    movabs $0xa5a5a5a5a5a5a5a5, %rax
    movq %rax, cross_page_target
    movq cross_page_target, %rax
    movq %rax, cross_page_result
.elseif TEST_MODE == 7
    call fault_fetch
.elseif TEST_MODE == 8
    mov $0xa5, %al
    xchgb %al, atomic_target
    movb atomic_target, %al
    movb %al, atomic_result
.elseif TEST_MODE == 9
    mov $0xa5a5, %ax
    xchgw %ax, atomic_target
    movw atomic_target, %ax
    movw %ax, atomic_result
.elseif TEST_MODE == 10
    mov $0xa5a5a5a5, %eax
    xchgl %eax, atomic_target
    movl atomic_target, %eax
    movl %eax, atomic_result
.elseif TEST_MODE == 11
    movabs $0xa5a5a5a5a5a5a5a5, %rax
    xchgq %rax, atomic_target
    movq atomic_target, %rax
    movq %rax, atomic_result
.elseif TEST_MODE == 12
    movabs $0x5a5a5a5a5a5a5a5a, %rax
    mov %rax, %rdx
    movabs $0xa5a5a5a5a5a5a5a5, %rbx
    mov %rbx, %rcx
    lock cmpxchg16b atomic_target
    movq atomic_target, %rax
    movq atomic_target + 8, %rdx
    movq %rax, atomic_result
    movq %rdx, atomic_result + 8
.elseif TEST_MODE == 13
    xor %eax, %eax
    xor %edx, %edx
    movabs $0xa5a5a5a5a5a5a5a5, %rbx
    mov %rbx, %rcx
    lock cmpxchg16b atomic_target
    movq %rax, atomic_result
    movq %rdx, atomic_result + 8
.elseif TEST_MODE == 14
    movb aligned_target, %al
    movb $0, scenario_result
.elseif TEST_MODE == 15
    movb aligned_target, %al
    mov $20000, %ecx
3:
    pause
    loop 3b
    movb aligned_target, %al
    movb %al, scenario_result
.elseif TEST_MODE == 16
    movb cross_page_target + 4, %al
    movb aligned_target, %al
    movb %al, scenario_result
.elseif TEST_MODE == 17
    movb aligned_target, %al
    movb %al, scenario_result
.elseif TEST_MODE == 18
retrying_load:
    movb aligned_target, %al
    movb %al, scenario_result
.else
    .error "unknown TEST_MODE"
.endif
2:
    pause
    jmp 2b

exception_handler:
.if TEST_MODE == 18
    movb scenario_scratch, %dl
    incb %dl
    movb %dl, scenario_scratch
    addq $8, %rsp
    iretq
.else
    movb $0xe1, scenario_result
4:
    pause
    jmp 4b
.endif

.section .fault_text, "ax"
.global fault_fetch
fault_fetch:
    .byte 0xb8
.global fetch_immediate
fetch_immediate:
    .long 0x5a
    movb %al, fetch_result
    ret

.section .fault_data, "aw"
.global aligned_target
aligned_target:
    .fill 16, 1, 0x5a
.org 0x100
.global aligned_result
aligned_result:
    .fill 16, 1, 0
.org 0x201
.global unaligned_target
unaligned_target:
    .fill 16, 1, 0x5a
.org 0x300
.global unaligned_result
unaligned_result:
    .fill 16, 1, 0
.org 0xffc
.global cross_page_target
cross_page_target:
    .fill 16, 1, 0x5a
.org 0x1100
.global cross_page_result
cross_page_result:
    .fill 16, 1, 0
.org 0x1200
.global atomic_target
.align 16
atomic_target:
    .fill 16, 1, 0x5a
.org 0x1300
.global atomic_result
atomic_result:
    .fill 16, 1, 0
.org 0x1400
.global fetch_result
fetch_result:
    .byte 0

.section .scenario_data, "aw"
.global scenario_result
scenario_result:
    .fill 16, 1, 0
.global scenario_scratch
scenario_scratch:
    .byte 0

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:

.section .idt, "aw", @progbits
.align 16
idt:
    .skip 16 * 256
idt_end:
idt_descriptor:
    .word idt_end - idt - 1
    .skip 8

.section .page_tables, "aw"
.align 4096
page_map_level4:
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
    .quad 0x0000000000000083
    .fill 511, 8, 0

.section .gdt, "a"
.align 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:
gdt_descriptor:
    .word gdt_end - gdt - 1
    .long gdt

.section .note.GNU-stack, "", @progbits
