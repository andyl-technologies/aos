# 0102 - BQL-held exact register capture

## Purpose

Patch `0102` admits architectural register observation from an exact callback
that holds QEMU's big lock even when post-snapshot RR reselection temporarily
leaves the serialized owner invalid. At that boundary, `current_cpu` may retain
the preceding vCPU, but the BQL proves every vCPU register file is quiescent.

Idle-time advance completions are also explicitly scoped as exact callbacks so
their register capture uses the same authority as other deterministic control
boundaries.

## Admission contract

A running VM may expose registers only when deterministic single-threaded RR is
active, the callback is exact, and either its current vCPU is the serialized
owner or the callback holds the BQL. A stopped VM retains the existing
BQL-held admission. Concurrent, stale, and unowned non-BQL contexts fail
closed and emit diagnostics.

## Files and license scope

The patch modifies GPL-side `plugins/api-system.c` and `plugins/api.c`. It
changes no shared-memory or control wire format and adds no QEMU file.

## Required gates

1. Source continuation and two fresh-process restores must capture identical
   registers after an exact snapshot.
2. Register reads outside an exact BQL-held or serialized-owner boundary must
   remain rejected.
3. Patch-prefix provenance, regeneration, ABI, and license-boundary gates must
   pass.

- **[QFP-BQL-REG-1]** A BQL-held exact callback MAY read all quiescent vCPU
  registers while serialized RR owner reselection is pending.
- **[QFP-BQL-REG-2]** BQL ownership MUST NOT admit register reads from a
  non-exact callback while the VM is running.
