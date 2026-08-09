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
    adrp x1, paging_ready
    add x1, x1, :lo12:paging_ready
    mov w0, #0x5a
    strb w0, [x1]
    adrp x2, mutation_execution_result
    add x2, x2, :lo12:mutation_execution_result
    adrp x3, persistent_register_result
    add x3, x3, :lo12:persistent_register_result
1:
    mov x28, #0
    str x28, [x3]
    bl mutation_code
    strb w0, [x2]
    add w0, w0, #1
    b 1b

.section .mutation_code, "ax"
.global mutation_code
mutation_code:
    mov w0, #0x5a
    ret

.section .data, "aw"
.global mutation_byte
mutation_byte:
    .byte 0x5a
.global paging_ready
paging_ready:
    .byte 0x00
.global mutation_execution_result
mutation_execution_result:
    .byte 0x00
.balign 8
.global persistent_register_result
persistent_register_result:
    .quad 0x0000000000000000

.section .cross, "aw"
.global mutation_cross_page
mutation_cross_page:
    .byte 0x5a, 0x5a

.section .readonly_data, "a"
.global mutation_readonly_byte
mutation_readonly_byte:
    .byte 0x5a

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
    .fill 29, 8, 0
    .quad last_level3_table + 0x3
    .fill 480, 8, 0
.align 12
level3_table:
.set page_address, 0x40200000
.rept 258
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
    /* 0x40302000 is present but read-only at EL1. */
    .quad page_address + 0x783
    .set page_address, page_address + 0x1000
.rept 253
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
.align 12
last_level3_table:
.set page_address, 0x43e00000
.rept 512
    .quad page_address + 0x703
    .set page_address, page_address + 0x1000
.endr
