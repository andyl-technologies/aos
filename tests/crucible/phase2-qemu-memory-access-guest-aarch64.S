/* SPDX-License-Identifier: Apache-2.0 */

.arch armv8.1-a+lse

.ifndef TEST_MODE
.set TEST_MODE, 1
.endif

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
    adrp x0, exception_vectors
    add x0, x0, :lo12:exception_vectors
    msr vbar_el1, x0
    isb
.if TEST_MODE == 19
    adrp x0, fetch_result
    add x0, x0, :lo12:fetch_result
    mov w1, #0x7e
    strb w1, [x0]
0:
    ldrb w1, [x0]
    cmp w1, #0x7f
    b.ne 0b
.elseif TEST_MODE >= 14
    adrp x0, scenario_result
    add x0, x0, :lo12:scenario_result
    mov w1, #0x7e
    strb w1, [x0]
0:
    ldrb w1, [x0]
    cmp w1, #0x7f
    b.ne 0b
.endif
    mov x0, #20000
1:
    subs x0, x0, #1
    b.ne 1b

.if TEST_MODE == 1
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    adrp x2, aligned_result
    add x2, x2, :lo12:aligned_result
    ldrb w0, [x1]
    strb w0, [x2]
.elseif TEST_MODE == 2
    adrp x1, unaligned_target
    add x1, x1, :lo12:unaligned_target
    adrp x2, unaligned_result
    add x2, x2, :lo12:unaligned_result
    ldr w0, [x1]
    str w0, [x2]
.elseif TEST_MODE == 3
    adrp x1, cross_page_target
    add x1, x1, :lo12:cross_page_target
    adrp x2, cross_page_result
    add x2, x2, :lo12:cross_page_result
    ldr x0, [x1]
    str x0, [x2]
.elseif TEST_MODE == 4
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    adrp x2, aligned_result
    add x2, x2, :lo12:aligned_result
    mov w0, #0xa5a5
    movk w0, #0xa5a5, lsl #16
    str w0, [x1]
    ldr w0, [x1]
    str w0, [x2]
.elseif TEST_MODE == 5
    adrp x1, unaligned_target
    add x1, x1, :lo12:unaligned_target
    adrp x2, unaligned_result
    add x2, x2, :lo12:unaligned_result
    mov w0, #0xa5a5
    movk w0, #0xa5a5, lsl #16
    str w0, [x1]
    ldr w0, [x1]
    str w0, [x2]
.elseif TEST_MODE == 6
    adrp x1, cross_page_target
    add x1, x1, :lo12:cross_page_target
    adrp x2, cross_page_result
    add x2, x2, :lo12:cross_page_result
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    str x0, [x1]
    ldr x0, [x1]
    str x0, [x2]
.elseif TEST_MODE == 7 || TEST_MODE == 19
    bl fault_fetch
.elseif TEST_MODE >= 8 && TEST_MODE <= 13
    adrp x4, atomic_target
    add x4, x4, :lo12:atomic_target
    adrp x5, atomic_result
    add x5, x5, :lo12:atomic_result
.if TEST_MODE == 8
    mov w0, #0xa5
    swpb w0, w1, [x4]
    ldrb w0, [x4]
    strb w0, [x5]
.elseif TEST_MODE == 9
    mov w0, #0xa5a5
    swph w0, w1, [x4]
    ldrh w0, [x4]
    strh w0, [x5]
.elseif TEST_MODE == 10
    mov w0, #0xa5a5
    movk w0, #0xa5a5, lsl #16
    swp w0, w1, [x4]
    ldr w0, [x4]
    str w0, [x5]
.elseif TEST_MODE == 11
    mov x0, #0xa5a5
    movk x0, #0xa5a5, lsl #16
    movk x0, #0xa5a5, lsl #32
    movk x0, #0xa5a5, lsl #48
    swp x0, x1, [x4]
    ldr x0, [x4]
    str x0, [x5]
.elseif TEST_MODE == 12
    mov x0, #0x5a5a
    movk x0, #0x5a5a, lsl #16
    movk x0, #0x5a5a, lsl #32
    movk x0, #0x5a5a, lsl #48
    mov x1, x0
    mov x2, #0xa5a5
    movk x2, #0xa5a5, lsl #16
    movk x2, #0xa5a5, lsl #32
    movk x2, #0xa5a5, lsl #48
    mov x3, x2
    casp x0, x1, x2, x3, [x4]
    ldp x0, x1, [x4]
    stp x0, x1, [x5]
.elseif TEST_MODE == 13
    mov x0, #0
    mov x1, #0
    mov x2, #0xa5a5
    movk x2, #0xa5a5, lsl #16
    movk x2, #0xa5a5, lsl #32
    movk x2, #0xa5a5, lsl #48
    mov x3, x2
    casp x0, x1, x2, x3, [x4]
    stp x0, x1, [x5]
.endif
.elseif TEST_MODE == 14
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb wzr, [x2]
.elseif TEST_MODE == 15
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    ldrb w0, [x1]
    mov x3, #20000
3:
    yield
    subs x3, x3, #1
    b.ne 3b
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb w0, [x2]
.elseif TEST_MODE == 16
    adrp x1, cross_page_target
    add x1, x1, :lo12:cross_page_target
    ldrb w0, [x1, #4]
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb w0, [x2]
.elseif TEST_MODE == 17
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb w0, [x2]
.elseif TEST_MODE == 18
retrying_load:
    adrp x1, aligned_target
    add x1, x1, :lo12:aligned_target
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb w0, [x2]
.elseif TEST_MODE == 20 || TEST_MODE == 21 || TEST_MODE == 22
    ldr x1, =0x40600000
    ldrb w0, [x1]
    adrp x2, scenario_result
    add x2, x2, :lo12:scenario_result
    strb w0, [x2]
.else
    .error "unknown TEST_MODE"
.endif
2:
    wfe
    b 2b

.align 11
exception_vectors:
.rept 16
    b exception_handler
    .space 124
.endr

exception_handler:
.if TEST_MODE == 18 || TEST_MODE == 21
    adrp x10, scenario_scratch
    add x10, x10, :lo12:scenario_scratch
    ldrb w11, [x10]
    add w11, w11, #1
    strb w11, [x10]
    eret
.else
    adrp x1, scenario_result
    add x1, x1, :lo12:scenario_result
    mov w0, #0xe1
    strb w0, [x1]
4:
    wfe
    b 4b
.endif

.section .fault_text, "ax"
.global fault_fetch
.global fetch_instruction
fault_fetch:
fetch_instruction:
    .word 0x52800b40
    adrp x1, fetch_result
    add x1, x1, :lo12:fetch_result
    strb w0, [x1]
    ret

.section .fault_data, "aw"
.global aligned_target
aligned_target:
    .fill 16, 1, 0x5a
.org 0x100
.global aligned_result
aligned_result:
    .fill 16, 1, 0
.org 0x201
.global unaligned_target
unaligned_target:
    .fill 16, 1, 0x5a
.org 0x300
.global unaligned_result
unaligned_result:
    .fill 16, 1, 0
.org 0xffc
.global cross_page_target
cross_page_target:
    .fill 16, 1, 0x5a
.org 0x1100
.global cross_page_result
cross_page_result:
    .fill 16, 1, 0
.org 0x1200
.global atomic_target
.balign 16
atomic_target:
    .fill 16, 1, 0x5a
.org 0x1300
.global atomic_result
atomic_result:
    .fill 16, 1, 0
.org 0x1400
.global fetch_result
fetch_result:
    .byte 0

.section .scenario_data, "aw"
.global scenario_result
scenario_result:
    .fill 16, 1, 0
.global scenario_scratch
scenario_scratch:
    .byte 0

.section .page_tables, "aw"
.align 12
level1_table:
    .quad 0
    .quad level2_table + 0x3
    .fill 510, 8, 0
.align 12
level2_table:
    .quad 0
    .quad level3_table + 0x3
    .quad 0
    .quad fault_level3_table + 0x3
    .fill 508, 8, 0
.align 12
level3_table:
.set page_address, 0x40200000
.rept 512
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
.align 12
fault_level3_table:
    .quad aligned_target + 0x703
    .fill 511, 8, 0
