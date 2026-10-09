/* SPDX-License-Identifier: Apache-2.0 */
/* The generic loader seeds RAM; a real machine reset must restore that seed. */
.section .text.boot,"ax"
.code16
.global boot, seed_checked, payload_written, validate_reply
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

    /* Warm reset is exercised only after the completed-write boundary. The
     * guest latch survives that reset, while the generic loader rewrites seed
     * RAM. It is guest state, not host authority or proof of physical reset. */
    cmpl $0, 0x7100
    je cold_boot
    cmpl $0x524d0001, 0x7100
    jne command_failed
    movl $(0xf0000 + reseeded_marker), %esi
    call emit_string
    jmp halted
cold_boot:
    movl $(0xf0000 + registration_template), %esi
    movl $81, %ecx
    call copy_message
    outb %al, $0xe7
    movl $(0xf0000 + setup_template), %esi
    movl $14, %ecx
    call copy_message
    outb %al, $0xe7

    movl $(0xf0000 + request_template), %esi
    movl $128, %ecx
    call copy_message
baseline_boundary:
    outb %al, $0xe7
    pushl $2
    pushl $0x7000
baseline_reply_call:
    call validate_reply
    addl $8, %esp
    testl %eax, %eax
    jz command_failed
    movl $0x524d0001, 0x7100

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
    movl $(0xf0000 + request_template), %esi
    movl $128, %ecx
    call copy_message
    movl $3, 0x700c
    movl $0x31303077, 0x703c /* "w001", the existing selectable instance key. */
written_boundary:
    outb %al, $0xe7
    pushl $3
    pushl $0x7000
    call validate_reply
    addl $8, %esp
    testl %eax, %eax
    jz command_failed
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

/* Copy public v1 protocol bytes to writable guest RAM. EAX carries the guest
 * virtual address and ECX the length through the established port doorbell. */
copy_message:
    pushl %ecx
    movl $0x7000, %edi
    rep movsb
    popl %ecx
    movl $0x7000, %eax
    ret

.section .text.reply,"ax"

/* cdecl: reply[128], expected sequence. The real host must resume this CPU with
 * an exact Selected Unit reply before stores; an unchanged request refuses.
 * This routine is also called verbatim by the freestanding local ELF32 test. */
validate_reply:
    movl 4(%esp), %ecx
    cmpl $0x00030001, 0(%ecx)
reply_first_guard:
    jne reply_refused
    cmpl $96, 4(%ecx)
    jne reply_refused
    cmpl $97, 8(%ecx)
    jne reply_refused
    movl 8(%esp), %edx
    cmpl %edx, 12(%ecx)
    jne reply_refused
    cmpl $0, 16(%ecx)
    jne reply_refused
    cmpl $0, 20(%ecx)
    jne reply_refused
    cmpl $96, 88(%ecx)
    jne reply_refused
    cmpl $1, 92(%ecx)
    jne reply_refused
    cmpb $1, 96(%ecx)
    jne reply_refused
    movl $97, %edx
reply_padding:
    cmpb $0, (%ecx,%edx)
    jne reply_refused
    incl %edx
    cmpl $128, %edx
    jne reply_padding
    movl $1, %eax
    ret
reply_refused:
    xorl %eax, %eax
    ret

.section .note.GNU-stack,"",@progbits
.section .text.boot,"ax"

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
reseeded_marker:
    .asciz "\nRESET_ROM_RESEEDED_V1\n"
bad_seed_marker:
    .asciz "\nRESET_ROM_BAD_SEED_V1\n"
bad_command_marker:
    .asciz "\nRESET_ROM_BAD_COMMAND_V1\n"

/* Exact existing flight.ready registration/default Unit/readiness tag. */
.global registration_template, setup_template, request_template
registration_template:
    .short 1, 1, 56, 0
    .long 81
    .quad 1
    .long 56, 12, 68, 1, 69, 1, 70, 11
    .short 1, 0
    .ascii "flight.ready"
    .byte 1, 1
    .short 9
    .ascii "readiness"
    .if (. - registration_template) != 81
    .error "registration length"
    .endif
setup_template:
    .byte 0x43, 0x52, 0x42, 0x4c, 3, 0, 2, 0, 2, 0, 0, 0, 1, 0
request_template:
    .short 1, 2, 48, 0
    .long 128
    .quad 2
    .long 48, 12, 60, 4, 0, 0, 64
    .ascii "flight.readyboot"
    .zero 64
    .if (. - request_template) != 128
    .error "request length"
    .endif

.section .reset,"ax"
.code16
    ljmp $0xf000, $boot
    .fill 11, 1, 0
