/* SPDX-License-Identifier: MIT */
/* Returns exact configured CPUID rows and unsupported-index results. */
.section .text
.global _start
.type _start, @function
_start:
    lea results(%rip), %r15

    mov $0x0d, %eax
    xor %ecx, %ecx
    call record_cpuid

    mov $0x0d, %eax
    mov $1, %ecx
    call record_cpuid

    mov $0x0d, %eax
    mov $2, %ecx
    call record_cpuid

    mov $0x0d, %eax
    mov $63, %ecx
    call record_cpuid

    /* This index used to wrap the signed offset calculation to zero. */
    mov $0x0d, %eax
    mov $0x40000000, %ecx
    call record_cpuid

    mov $0x0d, %eax
    mov $0xffffffff, %ecx
    call record_cpuid

    /* A non-indexed leaf must ignore ECX instead of applying the bound. */
    mov $1, %eax
    xor %ecx, %ecx
    call record_cpuid

    mov $1, %eax
    mov $0xffffffff, %ecx
    call record_cpuid

    mov $1, %eax
    mov $1, %edi
    lea results(%rip), %rsi
    mov $128, %edx
    syscall
    cmp $128, %rax
    jne failed_write

    xor %edi, %edi
    jmp exit_guest

failed_write:
    mov $42, %edi

exit_guest:
    mov $60, %eax
    syscall
    ud2
.size _start, .-_start

.type record_cpuid, @function
record_cpuid:
    cpuid
    mov %eax, 0(%r15)
    mov %ebx, 4(%r15)
    mov %ecx, 8(%r15)
    mov %edx, 12(%r15)
    add $16, %r15
    ret
.size record_cpuid, .-record_cpuid

.section .bss
.balign 16
results:
    .skip 128

.section .note.GNU-stack,"",@progbits
