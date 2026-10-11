/* SPDX-License-Identifier: MIT */
/* Execute real lower/upper 64-bit and byte PMULL, including source aliasing. */
.arch armv8-a+crypto
.text
.global _start
_start:
    adrp x20, input
    add x20, x20, :lo12:input
    adrp x21, output
    add x21, x21, :lo12:output
1:
    mov x0, #0
    mov x1, x20
    mov x2, #32
    mov x8, #63
    svc #0
    cbz x0, 2f
    cmp x0, #32
    b.ne 3f
    ldr q0, [x20]
    ldr q1, [x20, #16]
    pmull v2.1q, v0.1d, v1.1d
    pmull2 v3.1q, v0.2d, v1.2d
    pmull v4.8h, v0.8b, v1.8b
    pmull2 v5.8h, v0.16b, v1.16b
    str q2, [x21]
    str q3, [x21, #16]
    str q4, [x21, #32]
    str q5, [x21, #48]
    pmull v0.1q, v0.1d, v1.1d
    str q0, [x21, #64]
    ldr q0, [x20]
    pmull2 v1.1q, v0.2d, v1.2d
    str q1, [x21, #80]
    mov x0, #1
    mov x1, x21
    mov x2, #96
    mov x8, #64
    svc #0
    cmp x0, #96
    b.ne 3f
    b 1b
2:
    mov x0, #0
    b 4f
3:
    mov x0, #1
4:
    mov x8, #93
    svc #0
.bss
.balign 16
input:
    .skip 32
output:
    .skip 96
