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
    mov $page_directory, %eax
    mov %eax, %cr3
.ifdef CRUCIBLE_ENABLE_MCA
    /* Enable architectural machine-check delivery and bank zero. */
    mov %cr4, %eax
    or $0x40, %eax
    mov %eax, %cr4
    mov $0x17b, %ecx
    mov $-1, %eax
    mov $-1, %edx
    wrmsr
    mov $0x400, %ecx
    wrmsr
    lea machine_check_handler, %eax
    movw %ax, machine_check_idt + 18 * 8
    shr $16, %eax
    movw %ax, machine_check_idt + 18 * 8 + 6
    mov %cs, %ax
    movw %ax, machine_check_idt + 18 * 8 + 2
    movb $0, machine_check_idt + 18 * 8 + 4
    movb $0x8e, machine_check_idt + 18 * 8 + 5
    lidt machine_check_idtr
.endif
    mov %cr0, %eax
    or $0x80010000, %eax
    mov %eax, %cr0
    movb $0x5a, paging_ready
    mov $stack_top, %esp
1:
    xor %edi, %edi
    movl %edi, persistent_register_result
    call mutation_code
    movb %al, mutation_execution_result
    add $1, %eax
    jmp 1b

.section .data
.global mutation_byte
mutation_byte:
    .byte 0x5a
.global paging_ready
paging_ready:
    .byte 0x00
.global mutation_execution_result
mutation_execution_result:
    .byte 0x00
.global persistent_register_result
persistent_register_result:
    .long 0x00000000
.ifdef CRUCIBLE_ENABLE_MCA
machine_check_idtr:
    .word 256 * 8 - 1
    .long machine_check_idt
.endif

.section .cross, "aw"
.global mutation_cross_page
mutation_cross_page:
    .byte 0x5a, 0x5a

.section .mutation_code, "ax"
.global mutation_code
mutation_code:
    mov $0x5a, %eax
    ret

.ifdef CRUCIBLE_ENABLE_MCA
machine_check_handler:
    push %eax
    push %ecx
    push %edx
    mov $0x17a, %ecx
    xor %eax, %eax
    xor %edx, %edx
    wrmsr
    pop %edx
    pop %ecx
    pop %eax
    iret
.endif

.section .readonly_data, "a"
.global mutation_readonly_byte
mutation_readonly_byte:
    .byte 0x5a

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:
.ifdef CRUCIBLE_ENABLE_MCA
.align 16
machine_check_idt:
    .skip 256 * 8
.endif

.section .page_tables, "aw"
.align 4096
page_directory:
    .long page_table + 0x3
    .fill 1023, 4, 0
.align 4096
page_table:
.set page_address, 0
.rept 261
    .long page_address + 0x3
    .set page_address, page_address + 0x1000
.endr
    /* 0x00105000 is present but read-only under CR0.WP. */
    .long page_address + 0x1
    .set page_address, page_address + 0x1000
.rept 762
    .long page_address + 0x3
    .set page_address, page_address + 0x1000
.endr

.section .note.GNU-stack, "", @progbits
