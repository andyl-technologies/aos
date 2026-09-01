# Patch 0078: guest-state fingerprint domains

## Responsibility

`0078-crucible-fingerprint-guest-state-domains.patch` makes the black-box
fingerprint describe the guest continuation that must survive an exact restore,
not process-local control machinery used to perform that restore. It serializes
only QEMU VMState sections classified as volatile guest state or device state.
The separately authenticated Apache continuation remains responsible for host
queues, fault sequences, scheduler decisions, and other cross-process control
state.

The raw terminal VMState export is unchanged. It continues to serialize the
complete state required by terminal lifecycle evidence; the narrower domain
selection applies only to the black-box equality oracle.

## Transient interrupt notifications

`CPUState.interrupt_request` contains both guest-relevant interrupt state and
QEMU control notifications. `CPU_INTERRUPT_EXITTB` asks translated execution to
return to the main loop. On x86, `CPU_INTERRUPT_POLL` asks QEMU to poll and
convert a virtual event before the next guest instruction. Their presence can
differ after `loadvm` even when the restored guest continuation is exact, and
neither bit is guest-observable architectural state at a stopped boundary.

The common fingerprint serializer therefore masks:

- the target-independent `CPU_INTERRUPT_EXITTB` bit; and
- bits declared by the concrete CPU class in
  `crucible_fingerprint_transient_interrupt_mask`.

The x86 CPU class declares `CPU_INTERRUPT_POLL`. Other targets default to an
empty target-specific mask until their implementation identifies an equivalent
control-only notification. Common plugin code does not include target headers
or test poisoned `TARGET_*` macros.

The serializer holds the big QEMU lock, saves every original
`interrupt_request`, applies the masks, serializes the fingerprint domains, and
restores every original value before releasing the lock. Thus fingerprinting is
side-effect-free even when serialization fails. Architectural interrupt
controller state and all unmasked CPU interrupt bits remain authenticated.

## Verification

The live exact-snapshot gate checkpoints a running two-vCPU guest at a nonzero
RR position, force-kills the old process, restores into a fresh process, and
requires exact equality of:

- aggregate icount and the full RR cursor;
- every vCPU register digest and retired-instruction count;
- writable RAM digest and byte count;
- guest/device VMState digest and byte count; and
- VMState schema digest.

It then runs an independently launched replay suffix to the same horizon. A
negative control changes only the captured RR position, recomputes the canonical
black-box fingerprint, and requires production fault-runtime admission to reject
the altered value. Patch microtests also require the guest-state domain call,
generic transient mask, target-specific declaration, and x86 poll mask to remain
present.

## Boundary and licensing

VMState classification, CPU-class masks, and QEMU serialization live entirely
inside the applicable GPL scope. The Apache host sees only fixed-width digests,
byte counts, vCPU records, and RR cursor values through the versioned shared
memory protocol. The signed patch commit and its exact source tree are retained
in the corresponding-source bundle.
