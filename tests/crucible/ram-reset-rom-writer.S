/* SPDX-License-Identifier: Apache-2.0 */
/* The generic loader seeds RAM; a real machine reset must restore that seed. */
.section .text.boot,"ax"
.code16
.global boot, seed_checked, payload_written, writer_wait
boot:
    cli
    cld
    movw $0xf000, %ax
    movw %ax, %ds
    lgdt gdt_descriptor
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $8, $(0xf0000 + protected_entry)

.code32
protected_entry:
    movw $16, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $0x6000, %esp

    /* This fixture is the firmware and owns the UART's initial configuration. */
    movw $0x3fb, %dx
    movb $3, %al
    outb %al, %dx
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx

    movl $0x100000, %edi
    movl $32, %ecx
    movb $0x3d, %al
verify_seed:
    cmpb %al, (%edi)
    jne seed_failed
    addb $17, %al
    incl %edi
    loop verify_seed
seed_checked:
    movl $(0xf0000 + ready_marker), %esi
    call emit_string

    movl $0x1000000, %ecx
    movw $0x3fd, %dx
writer_wait:
    inb %dx, %al
    testb $1, %al
    jnz writer_command
    loop writer_wait
    jmp command_failed
writer_command:
    movw $0x3f8, %dx
    inb %dx, %al
    cmpb $'W', %al
    jne command_failed

    movl $0x100000, %edi
    movl $32, %ecx
    movb $0xc2, %al
write_payload:
    movb %al, (%edi)
    subb $17, %al
    incl %edi
    loop write_payload
payload_written:
    movl $(0xf0000 + written_marker), %esi
    call emit_string
    jmp halted

seed_failed:
    movl $(0xf0000 + bad_seed_marker), %esi
    call emit_string
    jmp halted
command_failed:
    movl $(0xf0000 + bad_command_marker), %esi
    call emit_string
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

emit_byte:
    pushl %eax
    pushl %ecx
    pushl %edx
    movl $0x100000, %ecx
    movw $0x3fd, %dx
uart_poll:
    inb %dx, %al
    testb $0x20, %al
    jnz uart_ready
    loop uart_poll
    jmp halted
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
gdt_descriptor:
    .word 23
    .long 0xf0000 + gdt
ready_marker:
    .asciz "\nRESET_ROM_READY_V1\n"
written_marker:
    .asciz "\nRESET_ROM_WRITTEN_V1\n"
bad_seed_marker:
    .asciz "\nRESET_ROM_BAD_SEED_V1\n"
bad_command_marker:
    .asciz "\nRESET_ROM_BAD_COMMAND_V1\n"

.section .reset,"ax"
.code16
    ljmp $0xf000, $boot
    .fill 11, 1, 0
