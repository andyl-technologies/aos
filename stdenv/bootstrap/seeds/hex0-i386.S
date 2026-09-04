/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Readable assembly cross-check for the AOS i386 hex0 bootstrap seed.
 *
 * The canonical byte source is hex0-i386.hex0. This file intentionally
 * contains only the code region: README.md documents how its .text bytes are
 * compared with the code bytes in the canonical source and committed ELF.
 */

.code32
.section .text
.global _start

.equ SYS_exit,    1
.equ SYS_read,    3
.equ SYS_write,   4
.equ SYS_open,    5
.equ SYS_close,   6
.equ SYS_unlink, 10
.equ SYS_fchmod, 94
.equ SYS_fsync, 118

.equ EINTR,        4
.equ O_WRONLY,     1
.equ O_CREAT,     64
.equ O_EXCL,     128
.equ OUTPUT_FLAGS, O_WRONLY | O_CREAT | O_EXCL
.equ OUTPUT_MODE,  0700

_start:
    popl %eax
    cmpl $3, %eax
    jne fail_without_output

    popl %eax
    popl %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $SYS_open, %eax
    int $0x80
    testl %eax, %eax
    js fail_without_output
    movl %eax, %esi

    popl %ebx
    pushl %ebx
    movl $OUTPUT_FLAGS, %ecx
    movl $OUTPUT_MODE, %edx
    movl $SYS_open, %eax
    int $0x80
    testl %eax, %eax
    js fail_without_output
    movl %eax, %edi

    subl $4, %esp
    movl %edi, %ebx
    movl $OUTPUT_MODE, %ecx
    movl $SYS_fchmod, %eax
    int $0x80
    testl %eax, %eax
    js fail_with_output

    movl $-1, %ebp

read_next:
    call read_byte
    cmpl $1, %eax
    je classify_byte
    testl %eax, %eax
    je end_of_input
    jmp fail_with_output

classify_byte:
    movzbl (%esp), %eax
    cmpb $'#', %al
    je skip_comment
    cmpb $';', %al
    je skip_comment

    cmpb $'0', %al
    jb classify_separator
    cmpb $'9', %al
    jbe decimal_digit
    cmpb $'A', %al
    jb fail_with_output
    cmpb $'F', %al
    jbe uppercase_digit
    cmpb $'a', %al
    jb fail_with_output
    cmpb $'f', %al
    ja fail_with_output
    subb $('a' - 10), %al
    jmp accept_nibble

uppercase_digit:
    subb $('A' - 10), %al
    jmp accept_nibble

decimal_digit:
    subb $'0', %al

accept_nibble:
    cmpl $-1, %ebp
    jne emit_byte
    movl %eax, %ebp
    jmp read_next

emit_byte:
    shll $4, %ebp
    orl %ebp, %eax
    movb %al, (%esp)
    call write_byte
    cmpl $1, %eax
    jne fail_with_output
    movl $-1, %ebp
    jmp read_next

classify_separator:
    cmpb $' ', %al
    je read_next
    cmpb $'\t', %al
    je read_next
    cmpb $'\n', %al
    je read_next
    cmpb $'\r', %al
    je read_next
    jmp fail_with_output

skip_comment:
    call read_byte
    cmpl $1, %eax
    jne comment_read_ended
    cmpb $'\n', (%esp)
    jne skip_comment
    jmp read_next

comment_read_ended:
    testl %eax, %eax
    je end_of_input
    jmp fail_with_output

end_of_input:
    cmpl $-1, %ebp
    jne fail_with_output

sync_output:
    movl $SYS_fsync, %eax
    movl %edi, %ebx
    int $0x80
    cmpl $-EINTR, %eax
    je sync_output
    testl %eax, %eax
    js fail_with_output

    movl $SYS_close, %eax
    movl %edi, %ebx
    int $0x80
    testl %eax, %eax
    js fail_with_output

    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80

read_byte:
    movl $SYS_read, %eax
    movl %esi, %ebx
    leal 4(%esp), %ecx
    movl $1, %edx
    int $0x80
    cmpl $-EINTR, %eax
    je read_byte
    ret

write_byte:
    movl $SYS_write, %eax
    movl %edi, %ebx
    leal 4(%esp), %ecx
    movl $1, %edx
    int $0x80
    cmpl $-EINTR, %eax
    je write_byte
    ret

fail_with_output:
    movl $SYS_unlink, %eax
    movl 4(%esp), %ebx
    int $0x80
    cmpl $-EINTR, %eax
    je fail_with_output

fail_without_output:
    movl $1, %ebx
    movl $SYS_exit, %eax
    int $0x80
