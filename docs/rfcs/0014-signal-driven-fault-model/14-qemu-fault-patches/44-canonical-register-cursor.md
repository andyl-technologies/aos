# 0093 - Canonical after-instruction register cursor

## Purpose

Patch `0093` makes register mutation evidence use the same canonical RR
coordinate as durable scheduler state. QEMU plugin callbacks observe the
retired prefix before the current callback instruction. Evidence for the
after-instruction phase therefore advances that prefix by the current
instruction before hashing or serialization.

If the advancement reaches the pinned quantum, the evidence reports the next
CPU in deterministic RR order at position zero. It never serializes the
transient current-owner, position-equal-quantum coordinate.

## Canonicality contract

Before-instruction mutations continue to use the ordinary formal RR cursor
API. After-instruction mutations require the serialized owner to match the
applying vCPU, require a nonzero pinned quantum, and reject positions beyond
the terminal. They then advance exactly once and project an exact terminal
without mutating scheduler state.

The applying vCPU remains explicit in register evidence independently of the
post-instruction scheduler coordinate. A terminal single-vCPU run therefore
records the same vCPU at position zero; a multi-vCPU run records the next RR
vCPU at position zero.

## Files and license scope

The patch modifies GPL-side `plugins/crucible-fault-register.c` and its QEMU
live plugin test. It changes no shared-memory or control wire format and adds
no QEMU file.

## Required gates

1. The complete live register mutation matrix must pass both mutation phases,
   including its exact terminal case.
2. The terminal case must reject the legacy position-equal-quantum evidence.
3. Patch-prefix provenance, attribution, regeneration, drop-one, ABI, and
   license-boundary gates must pass.

- **[QFP-REG-CURSOR-1]** After-instruction register evidence MUST identify the
  semantic coordinate after the current instruction.
- **[QFP-REG-CURSOR-2]** A terminal register coordinate MUST use the canonical
  next-owner, position-zero handoff and MUST NOT serialize a terminal cursor.
