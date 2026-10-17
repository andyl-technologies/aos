/* SPDX-License-Identifier: MIT */
/* A freestanding x86-64 Linux syscall workload; no guest libc or host input. */
.section .bss
.balign 4096
arena:
    .skip 262144
answer:
    .skip 8

.section .text
.global _start
_start:
    lea arena(%rip), %rdi
    mov $20000, %ecx
    mov $3, %r8d
    xor %r9, %r9

memory_loop:
    imul $1664525, %r8d, %r8d
    add $1013904223, %r8d
    mov %r8d, %eax
    and $262136, %eax
    xor %r8, (%rdi,%rax)
    add (%rdi,%rax), %r9
    test $1, %r8d
    jz even_value
    add $19, %r9

even_value:
    dec %ecx
    jnz memory_loop

    mov %r9, answer(%rip)
    mov $1, %eax
    mov $1, %edi
    lea answer(%rip), %rsi
    mov $8, %edx
    syscall

    mov $60, %eax
    xor %edi, %edi
    syscall

.section .note.GNU-stack,"",@progbits
