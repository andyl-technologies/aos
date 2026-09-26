# Capability task 0070 — `crucible-fault-vmstate`

## Purpose

Completes VMState, process identity, capability/evidence export, snapshot
barriers, and aggregate conformance for every fault capability. The atomic
patch ships only when this closure is complete.

## Capability and dependencies

- Provides `qemu.fault-vmstate.v1` and the final
  `qemu.fault-system.complete.v1` marker.
- Requires the capabilities specified by capability tasks 0047–0069 and the
  existing native QMP checkpoint VMState,
  process attestation, and fingerprint projection facilities.

## VMState sections

The atomic patch registers one versioned subsection for each state domain:

| Section | State |
| --- | --- |
| command ABI | pending command/result slots, sequences, copied payloads, registry hash |
| safe boundary | armed/reached states, order keys, boundary generation, publication state |
| memory impulse/access | persistent rule generations, sparse region state, retention/rowhammer counters, service and delayed access state |
| register/instruction | persistent rules, occurrence/replay counters, metadata generations and pending hooks |
| interrupt | rules, event source sequences, delayed/storm queues and associated controller fault state |
| hardware error | bank/platform records, pending delivery, platform device queue and linked memory command state |
| vCPU service | shares/caps, credits, remainder, windows, eligibility/stall/offline/recovery state |
| lifecycle | nonterminal transition, hang/boot/retry/reset policy and process-generation metadata |
| clock | transforms, anchors, source/sync/wander/clamp state and transformed timer generations |
| accelerator | lifecycle, queues/jobs, service remainder, device memory/rules and completions |

Sections use explicit version/length, canonical field order, bounds, reserved
zeros, and `needed` predicates. A section is present whenever its state could
affect future behavior, even if no fault is currently active. Unknown major
version fails restore; no compatibility shim is included.

## Snapshot barrier

Before QMP save:

1. scheduler authorizes an exact node boundary;
2. plugin stops new command consumption and QEMU reaches all-vCPU/device
   quiescence;
3. handlers finish or roll back any `applying` command;
4. dirty tracking, delayed events, service, timers, device queues, and results are
   committed through the boundary;
5. QEMU publishes a pre-save fault-state digest;
6. VMState serialization occurs;
7. plugin resumes only after QMP confirms completion.

Restore validates atomic-patch identity, machine/CPU/device manifests, fault ABI,
capability set, every subsection version/bound, and pre-save digest before guest
execution. It rebuilds indexes deterministically from serialized sorted rules and
verifies their digest. No host pointer/index cache is serialized.

## Thin/fat checkpoint relationship

The QEMU VMState is the live backend portion of a fat checkpoint. The Apache host
checkpoint separately stores signal/binding/adapter state and hashes the QEMU
VMState artifact. A thin checkpoint reconstructs both from ancestor plus schedule
and verifies the same host state ID, QEMU fault-state digest, and execution
fingerprint.

## Capability/system marker

The final marker hashes the pinned QEMU tag, complete atomic-patch bytes, QEMU
configuration/machine/CPU manifests, fault ABI, registered capabilities and
bounds, plugin identity, shmem ABI, VMState section versions, and license/source
artifact identity. Discovery rejects any missing required capability or extra
unrecognized mutation handler.

The marker is emitted in package metadata and queried live through the existing
GPL-side discovery surface. Host admission compares both and fails on mismatch.

## Evidence closure

Every applied command result references content-addressed full evidence when it
cannot fit inline. The reproduction artifact retains QEMU VMState, command/result
streams, manifests, atomic-patch/system marker, aggregate fingerprints, and corresponding
source identity as declared dependencies. GC cannot remove them while a
savepoint/reproduction artifact is retained.

## Aggregate live gates

1. **Per-capability resume matrix:** snapshot before arm, armed, immediately
   before opportunity, immediately after apply, delayed/pending, and recovered
   states for every capability; compare uninterrupted and resumed runs.
2. **Cross-capability overlap:** combine register/instruction/memory/interrupt/error/
   clock/service/lifecycle/accelerator effects at one boundary and prove declared
   total order, evidence, and replay.
3. **Multi-vCPU:** apply commands across all vCPUs near RR switches/IPIs and
   prove identical trajectories under adversarial host scheduling.
4. **Both architectures:** every architecture-neutral effect runs on x86-64 and
   AArch64; architecture-specific manifests cover their complete corresponding
   error/register/clock/interrupt contracts.
5. **Locked replay corruption:** independently corrupt command target, phase,
   opportunity, precondition, capability, atomic-patch identity, VMState subsection,
   result, and fingerprint; fail at the first mismatch.
6. **Inertness:** run the full pristine-QEMU and atomic-patch non-sim corpus, including
   machine enumeration, boot, device I/O, migration, snapshot, QMP schema, and
   instruction traces.
7. **Performance:** disabled, enabled-empty, sparse non-match, and active-match
   benchmarks for every hook class meet the
   [resource contract](../13-resource-and-performance-bounds.md).
8. **License/release:** build matching complete corresponding source, notices,
   new-file inventory, DCO audit, license-boundary dependency scan, and binary/
   source identity binding.

## Failure behavior

Snapshot/restore mismatch is fatal before resume. An unknown/missing state section
cannot default empty. A command in impossible `applying` state, partial result,
bad index digest, capability drift, or over-limit state rejects the checkpoint.
The system never drops pending faults to make an old checkpoint load.

## Licensing checklist

VMState and QEMU discovery changes remain in applicable GPL scope. Public
capability/evidence/identity formats remain in dual-licensed boundary crates.
Release packaging includes the atomic patch, plugin/generated build sources, and
notices. The DCO-signed commit updates the integration manifest, capability
catalog and count, `LICENSES.md`,
ABI vectors, source closure, and release gates.

- **[QFP-STATE-1]** `qemu.fault-system.complete.v1` MUST NOT be emitted unless
  every 0047–0070 capability and VMState subsection passes its live gate.
- **[QFP-STATE-2]** Restore MUST never omit, default, or translate fault state
  from another semantic version.
- **[QFP-STATE-3]** The implementation PR cannot leave draft until the aggregate
  capability matrix, inertness, license, and corresponding-source gates all pass.
