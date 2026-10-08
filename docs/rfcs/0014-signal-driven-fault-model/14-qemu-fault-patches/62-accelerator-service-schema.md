# Capability task 0111 — Correct the accelerator service schema

The atomic patch `crucible-qemu-11.1.1.patch` makes the
closed QEMU node-fault parser agree with the versioned accelerator service
payload.

## Problem

The typed host encoder represents accelerator capacity as a ratio in payload
field P1. QEMU's accelerator validator likewise requires P1 to be a ratio, but
the command was routed through the generic service schema, which required an
unsigned integer in that position. Every otherwise valid accelerator service
command therefore failed schema parsing before PREPARE and could never reach
the production device policy.

## Contract

Accelerator service commands use their own closed schema: capacity is a ratio,
compute and memory-rate enable flags are booleans, their service limits are
unsigned integers, and the optional thermal/power policy remains the versioned
byte payload. No other service command changes schema.

PREPARE continues to validate without changing device state. APPLY atomically
installs the keyed accelerator service rule, and the accelerator device remains
the sole owner of job-service accounting and occurrence evidence.

## Evidence

The live hardware gate submits the typed state-machine effect through the
production signal runtime and real patched QEMU. It requires one authenticated
service action, three exact job-service occurrences, and guest-visible GPU,
TPU, and FPGA completion under the half-capacity thermal/power policy. The
atomic-patch capability test also requires the dedicated ratio schema, rejects
the incorrect generic mapping, and proves the capability is absent from
pristine QEMU.
