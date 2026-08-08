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
    adrp x1, fault_target
    add x1, x1, :lo12:fault_target
    adrp x2, fault_result
    add x2, x2, :lo12:fault_result
1:
    ldrb w0, [x1]
    strb w0, [x2]
    b 1b

.section .fault_data, "aw"
.global fault_target
fault_target:
    .byte 0x5a
.global fault_result
fault_result:
    .byte 0x00

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
    .fill 510, 8, 0
.align 12
level3_table:
.set page_address, 0x40200000
.rept 512
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
