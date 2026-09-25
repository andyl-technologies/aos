/* SPDX-License-Identifier: Apache-2.0 */

.set LAPIC_BASE, 0xfee00000
.set LAPIC_EOI, 0x0b0
.set LAPIC_SPURIOUS, 0x0f0
.set LAPIC_LVT_TIMER, 0x320
.set LAPIC_INITIAL_COUNT, 0x380
.set LAPIC_DIVIDE, 0x3e0
.set LAPIC_TIMER_VECTOR, 0x30
.set LAPIC_TIMER_PERIODIC, 0x20000
.set LAPIC_TIMER_COUNT, 1000
.set EXPECTED_INTERRUPTS, 4

.section .multiboot, "a"
.align 4
.long 0x1badb002
.long 0x00000003
.long -(0x1badb002 + 0x00000003)

.section .text, "ax"
.code32
.global _start
_start:
    cli
    movl $stack_top, %esp

    movl $timer_handler, %eax
    movw %ax, interrupt_table + LAPIC_TIMER_VECTOR * 8
    shrl $16, %eax
    movw %ax, interrupt_table + LAPIC_TIMER_VECTOR * 8 + 6
    movw %cs, %ax
    movw %ax, interrupt_table + LAPIC_TIMER_VECTOR * 8 + 2
    movb $0x8e, interrupt_table + LAPIC_TIMER_VECTOR * 8 + 5
    lidt interrupt_table_descriptor

    movl $(LAPIC_BASE + LAPIC_SPURIOUS), %edi
    movl $0x1ff, (%edi)
    movl $(LAPIC_BASE + LAPIC_DIVIDE), %edi
    movl $0x0b, (%edi)
    movl $(LAPIC_BASE + LAPIC_LVT_TIMER), %edi
    movl $(LAPIC_TIMER_PERIODIC + LAPIC_TIMER_VECTOR), (%edi)
    movl $(LAPIC_BASE + LAPIC_INITIAL_COUNT), %edi
    movl $LAPIC_TIMER_COUNT, (%edi)
    sti

wait_for_timer:
    hlt
    cmpl $EXPECTED_INTERRUPTS, interrupt_count
    jb wait_for_timer

    cli
    movl $(LAPIC_BASE + LAPIC_INITIAL_COUNT), %edi
    movl $0, (%edi)
    movw $0xf4, %dx
    movl $0x10, %eax
    outl %eax, %dx
halt_forever:
    hlt
    jmp halt_forever

timer_handler:
    pushl %eax
    incl interrupt_count
    movl $0, LAPIC_BASE + LAPIC_EOI
    popl %eax
    iret

.section .data, "aw"
.align 8
interrupt_table_descriptor:
    .word 256 * 8 - 1
    .long interrupt_table

.section .bss, "aw", @nobits
.align 16
interrupt_count:
    .long 0
interrupt_table:
    .skip 256 * 8
stack_bottom:
    .skip 16384
stack_top:

.section .note.GNU-stack, "", @progbits
