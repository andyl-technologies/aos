/* SPDX-License-Identifier: Apache-2.0 */

.section .text
.global _start
_start:
    mov x0, #0xff
    msr mair_el1, x0
    ldr x0, =0x803519
    msr tcr_el1, x0
    adrp x0, level1_table
    add x0, x0, :lo12:level1_table
    msr ttbr0_el1, x0
    dsb sy
    isb
    mrs x0, sctlr_el1
    orr x0, x0, #1
    msr sctlr_el1, x0
    isb
    adrp x0, instruction_vectors
    add x0, x0, :lo12:instruction_vectors
    msr vbar_el1, x0
    isb
    mrs x0, cpacr_el1
    orr x0, x0, #(3 << 20)
    msr cpacr_el1, x0
    isb

    adrp x20, instruction_iterations
    add x20, x20, :lo12:instruction_iterations
    adrp x21, instruction_result_value
    add x21, x21, :lo12:instruction_result_value
    adrp x22, instruction_skip_count
    add x22, x22, :lo12:instruction_skip_count
    adrp x23, instruction_replay_count
    add x23, x23, :lo12:instruction_replay_count

instruction_loop:
.global instruction_result
instruction_result:
    mov w0, #0x40
    cmp w0, #0x41
    b.eq 7f
    cmp w0, #0x43
    b.ne 8f
7:
    str w0, [x21]
8:

    ldr w4, [x22]
.global instruction_skip
instruction_skip:
    add w4, w4, #1
    str w4, [x22]

    ldr w5, [x23]
.global instruction_replay
instruction_replay:
    add w5, w5, #1
    str w5, [x23]

.global instruction_exception_probe
instruction_exception_probe:
    nop

    mov w9, #0x5679
    movk w9, #0x1234, lsl #16
    bl instruction_load
    adrp x6, instruction_store_count
    add x6, x6, :lo12:instruction_store_count
    ldr w8, [x6]
    cmp w8, #4
    b.ne 11f
    str wzr, [x6]
    bl instruction_store
11:
    adrp x6, instruction_atomic_count
    add x6, x6, :lo12:instruction_atomic_count
    ldr w8, [x6]
    cmp w8, #1
    b.ne 12f
    str wzr, [x6]
    mov w7, #1
    bl instruction_atomic
12:
    adrp x6, instruction_fp_one
    add x6, x6, :lo12:instruction_fp_one
    ldr q1, [x6]
    eor v0.16b, v0.16b, v0.16b
    bl instruction_fp_simd
    adrp x6, instruction_control_count
    add x6, x6, :lo12:instruction_control_count
    ldr w8, [x6]
    cmp w8, #1
    b.ne 13f
    str wzr, [x6]
    bl instruction_control_case
13:
    adrp x6, instruction_natural_exception_count
    add x6, x6, :lo12:instruction_natural_exception_count
    ldr w8, [x6]
    cmp w8, #1
    b.ne 14f
    str wzr, [x6]
    bl instruction_natural_exception
14:
    adrp x6, instruction_result_fault_count
    add x6, x6, :lo12:instruction_result_fault_count
    ldr w8, [x6]
    cmp w8, #1
    b.eq 141f
    cbnz w8, 15f
    adrp x6, instruction_result_fault_source
    add x6, x6, :lo12:instruction_result_fault_source
    bl instruction_result_fault_instruction
    b 15f
141:
    str wzr, [x6]
    bl instruction_result_fault
15:
    mov w7, #0x5a
    bl instruction_device_io
    bl instruction_self_modify
    bl instruction_replay_exception
    ldr w3, [x20]
    add w3, w3, #1
    str w3, [x20]
    b instruction_loop

.global instruction_control_case
instruction_control_case:
.global instruction_control
instruction_control:
    b 1f
    b 2f
1:
    adrp x6, instruction_control_count
    add x6, x6, :lo12:instruction_control_count
    ldr w7, [x6]
    add w7, w7, #1
    str w7, [x6]
2:
    ret

.global instruction_atomic
instruction_atomic:
    adrp x6, instruction_atomic_count
    add x6, x6, :lo12:instruction_atomic_count
    mov w7, #1
.global instruction_atomic_instruction
instruction_atomic_instruction:
    ldadd w7, w8, [x6]
    ret

.global instruction_load
instruction_load:
    adrp x6, instruction_load_source
    add x6, x6, :lo12:instruction_load_source
.global instruction_load_instruction
instruction_load_instruction:
    ldr w9, [x6]
    mov w10, #0x5679
    movk w10, #0x1234, lsl #16
    cmp w9, w10
    cset w10, eq
    add w10, w10, #0x40
    adrp x6, instruction_load_result
    add x6, x6, :lo12:instruction_load_result
    cmp w10, #0x41
    b.eq 9f
    ldr w11, [x6]
    cmp w11, #0x41
    b.eq 10f
9:
    str w10, [x6]
10:
    ret

.global instruction_store
instruction_store:
    adrp x6, instruction_store_slots
    add x6, x6, :lo12:instruction_store_slots
    ldr w9, [x20]
.global instruction_store_instruction
instruction_store_instruction:
    str w9, [x6], #4
    adrp x7, instruction_store_count
    add x7, x7, :lo12:instruction_store_count
    adrp x8, instruction_store_slots
    add x8, x8, :lo12:instruction_store_slots
    sub x6, x6, x8
    str w6, [x7]
    ret

.global instruction_fp_simd
instruction_fp_simd:
    fadd v0.4s, v0.4s, v1.4s
    fmov w10, s0
    cbz w10, 5f
    mov w11, #1
    movk w11, #0x3f80, lsl #16
    cmp w10, w11
    b.eq 5f
    mov w11, #0
    movk w11, #0x4040, lsl #16
    cmp w10, w11
    cset w10, eq
    add w10, w10, #0x40
    b 6f
5:
    mov w10, #0x41
6:
    adrp x6, instruction_fp_result
    add x6, x6, :lo12:instruction_fp_result
    cmp w10, #0x41
    b.eq 9f
    ldr w11, [x6]
    cmp w11, #0x41
    b.eq 10f
9:
    str w10, [x6]
10:
    ret

.global instruction_natural_exception
instruction_natural_exception:
.global instruction_exception_instruction
instruction_exception_instruction:
    udf #0
    ret

.global instruction_device_io
instruction_device_io:
    ldr x6, =0x09010004
.global instruction_device_instruction
instruction_device_instruction:
    str w7, [x6]
    ret

.global instruction_self_modify
instruction_self_modify:
    adrp x6, instruction_self_modify_instruction
    add x6, x6, :lo12:instruction_self_modify_instruction
    ldr w8, [x6]
    eor w7, w8, #1
.global instruction_self_modify_instruction
instruction_self_modify_instruction:
    str w7, [x6]
    str w8, [x6]
    ret

.global instruction_replay_exception
instruction_replay_exception:
    adrp x6, instruction_replay_exception_pointer
    add x6, x6, :lo12:instruction_replay_exception_pointer
.global instruction_replay_exception_instruction
instruction_replay_exception_instruction:
    ldr x6, [x6]
    ret

.align 11
instruction_vectors:
.rept 16
    b instruction_exception_handler
    .space 124
.endr

instruction_exception_handler:
    mrs x2, elr_el1
    adrp x3, instruction_result_fault_instruction
    add x3, x3, :lo12:instruction_result_fault_instruction
    cmp x2, x3
    b.ne 2f
    adrp x6, instruction_result_fault_source
    add x6, x6, :lo12:instruction_result_fault_source
    adrp x0, instruction_result_fault_count
    add x0, x0, :lo12:instruction_result_fault_count
    b 4f
2:
    adrp x3, instruction_exception_instruction
    add x3, x3, :lo12:instruction_exception_instruction
    cmp x2, x3
    b.ne 3f
    add x2, x2, #4
    msr elr_el1, x2
    adrp x0, instruction_natural_exception_count
    add x0, x0, :lo12:instruction_natural_exception_count
    b 4f
3:
    adrp x0, instruction_exception_count
    add x0, x0, :lo12:instruction_exception_count
4:
    ldr w1, [x0]
    add w1, w1, #1
    str w1, [x0]
    eret

.global instruction_result_fault
instruction_result_fault:
    mov x6, #-1
.global instruction_result_fault_instruction
instruction_result_fault_instruction:
    ldr w9, [x6]
    and w9, w9, #1
    add w9, w9, #0x40
    adrp x6, instruction_result_fault_value
    add x6, x6, :lo12:instruction_result_fault_value
    str w9, [x6]
    ret

.section .data, "aw"
.align 8
.global instruction_iterations
instruction_iterations:
    .word 0
.global instruction_result_value
instruction_result_value:
    .word 0
.global instruction_skip_count
instruction_skip_count:
    .word 0
.global instruction_replay_count
instruction_replay_count:
    .word 0
.global instruction_exception_count
instruction_exception_count:
    .word 0
.global instruction_natural_exception_count
instruction_natural_exception_count:
    .word 1
.global instruction_result_fault_count
instruction_result_fault_count:
    .word 2
.global instruction_result_fault_value
instruction_result_fault_value:
    .word 0
instruction_result_fault_source:
    .word 0
.global instruction_control_count
instruction_control_count:
    .word 1
.global instruction_store_count
instruction_store_count:
    .word 4
.align 16
instruction_store_slots:
    .fill 4, 4, 0
.global instruction_load_source
instruction_load_source:
    .word 0x12345678
.global instruction_load_result
instruction_load_result:
    .word 0
.global instruction_fp_result
instruction_fp_result:
    .word 0
.global instruction_atomic_count
instruction_atomic_count:
    .word 1
.align 4
instruction_fp_one:
    .word 0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000
.align 3
instruction_replay_exception_pointer:
    .quad 0xffff000000000000

.section .page_tables, "aw"
.align 12
level1_table:
    /* Map the virt machine's low MMIO window as Device-nGnRnE memory. */
    .quad 0x405
    .quad level2_table + 0x3
    .fill 510, 8, 0
.align 12
level2_table:
    .quad 0
    .quad level3_table + 0x3
    .fill 510, 8, 0
.align 12
level3_table:
.set page_address, 0x40200000
.rept 512
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
