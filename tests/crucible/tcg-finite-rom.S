/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed work, independent of timers and of the emulator's instruction clock. */
.section .text,"ax"
.code16
.global _start, workload, workload_end
_start:
    cli
    movw %cs, %ax
    movw %ax, %ds
    lgdt gdt_pointer - _start
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $8, $protected_entry

.code32
protected_entry:
    movw $16, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $0x6000, %esp

    /* No firmware initializes COM1. Configure the same UART in every row. */
    movw $0x3fb, %dx
    movb $3, %al
    outb %al, %dx
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx

    movl $registration, %eax
    movl $81, %ecx
    outb %al, $0xe7
    movl $setup_complete, %eax
    movl $14, %ecx
    outb %al, $0xe7
    movl $start_token, %esi
    call emit_string

    movl $0x51f15eed, %eax
    movl $ITERATIONS, %ecx
workload:
    roll $13, %eax
    xorl $0x9e3779b9, %eax
    addl $0x6d2b79f5, %eax
    movl %eax, 0x7000
    decl %ecx
    movl %ecx, 0x7004
    jnz workload
workload_end:
    movl $ITERATIONS, 0x7008
    movl $0x524f4d31, 0x700c

    /* UART and protocol operands must not replace the arithmetic witness. */
    pushal
    movl $end_prefix, %esi
    call emit_string
    movl 0x7000, %ebx
    call emit_hex
    movb $':', %al
    call emit_byte
    movl $ITERATIONS, %ebx
    call emit_hex
    movb $10, %al
    call emit_byte
    popal

    /* Sim authenticates seq2 after the common endpoint; stock ignores it. */
    pushl %eax
    pushl %ecx
    movl $request, %eax
    movl $128, %ecx
    outb %al, $0xe7
    popl %ecx
    popl %eax
halted:
    cli
    hlt
    jmp halted

emit_string:
    lodsb
    testb %al, %al
    jz string_done
    call emit_byte
    jmp emit_string
string_done:
    ret

emit_hex:
    movl $8, %edi
hex_digit:
    roll $4, %ebx
    movb %bl, %al
    andb $15, %al
    addb $'0', %al
    cmpb $'9', %al
    jbe digit_ready
    addb $7, %al
digit_ready:
    call emit_byte
    decl %edi
    jnz hex_digit
    ret

emit_byte:
    pushl %eax
    pushl %ecx
    pushl %edx
    movl $1048576, %ecx
    movw $0x3fd, %dx
uart_poll:
    inb %dx, %al
    testb $0x20, %al
    jnz uart_ready
    loop uart_poll
    /* A missing token is a bounded guest failure, never successful work. */
uart_failed:
    cli
    hlt
    jmp uart_failed
uart_ready:
    popl %edx
    popl %ecx
    popl %eax
    pushl %edx
    movw $0x3f8, %dx
    outb %al, %dx
    popl %edx
    ret

.balign 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
gdt_pointer:
    .word 23
    .long gdt
start_token:
    .asciz "\nCRUCIBLE_ROM_START_V1\n"
end_prefix:
    .asciz "\nCRUCIBLE_ROM_DONE_V1:"

/* Public whitebox ABI records, identical to the stock Linux guest's schema. */
registration:
    .short 1, 1, 56, 0
    .long 81
    .quad 1
    .long 56, 12, 68, 1, 69, 1, 70, 11
    .short 1, 0
    .ascii "flight.ready"
    .byte 1, 1
    .short 9
    .ascii "readiness"
setup_complete:
    .byte 0x43, 0x52, 0x42, 0x4c, 3, 0, 2, 0, 2, 0, 0, 0, 1, 0
request:
    .short 1, 2, 48, 0
    .long 128
    .quad 2
    .long 48, 12, 60, 4
    .quad 0
    .long 64
    .ascii "flight.readyboot"
    .zero 64

.section .reset,"ax"
.code16
    ljmp $0xf000, $0
