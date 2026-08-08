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
    mov %cr0, %eax
    or $0x80010000, %eax
    mov %eax, %cr0
    mov $stack_top, %esp
1:
    movb fault_target, %al
    movb %al, fault_result
    jmp 1b

.section .fault_data, "aw"
.global fault_target
fault_target:
    .byte 0x5a
.global fault_result
fault_result:
    .byte 0x00

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:

.section .page_tables, "aw"
.align 4096
page_directory:
    .long page_table + 0x3
    .fill 1023, 4, 0
.align 4096
page_table:
.set page_address, 0
.rept 1024
    .long page_address + 0x3
    .set page_address, page_address + 0x1000
.endr

.section .note.GNU-stack, "", @progbits
