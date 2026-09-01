# 0103 - Checkpoint control-wake isolation

## Purpose

Patch `0103` lets an exact checkpoint hand its already-queued native VM stop to
QEMU's main loop without admitting new device work. The host must wake the
main loop after the plugin publishes the frozen coordinate, but the block
backend shares that eventfd and ordinarily resumes one parked request on every
drained wake.

## Isolation contract

When a Crucible native VM stop is pending, a drained shared-memory wake remains
a control notification only. The block backend consumes the notification but
does not advance its wake generation or resume a parked coroutine. Ordinary
response and reset notifications retain their existing request-progress
semantics.

This ordering applies only after QEMU has accepted the exact stop handoff. It
therefore cannot hide device work during checkpoint admission: the host must
first prove an idle, inactive, deadline-free boundary before ringing the
control wake.

## Files and license scope

The patch modifies GPL-side `block/crucible-shmem.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The pending-block exact snapshot scenario must publish an exact pause, enter
   native stopped state, and restore durably without a post-pause completion.
2. Production block requests must continue to advance on ordinary response and
   reset notifications.
3. Patch-prefix provenance, regeneration, ABI, and license-boundary gates must
   pass.

- **[QFP-CHECKPOINT-WAKE-1]** A control wake after exact pause publication MUST
  return the BQL to QEMU's main loop without resuming a parked block request.
- **[QFP-CHECKPOINT-WAKE-2]** The isolation MUST apply only while native VM stop
  is pending and MUST NOT suppress ordinary device progress.
