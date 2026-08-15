# Patch 0067 — `crucible-core-fault-vmstate`

## Purpose

Adds the single aggregate QEMU VMState transaction and complete save/restore
implementations for every fault domain carried through patch 0066. This patch
does not advertise the final fault-system capability: patches 0068 and 0069 add
their own required `clock` and `accelerator` sections, and patch 0070 proves the
closed registry and emits the aggregate marker. A fault-enabled run fails save
admission while any required section is absent; it never writes a checkpoint
that silently omits state.

## Scope and dependencies

- Depends on patches 0047 through 0066 and QEMU's live migration framework.
- Creates `plugins/crucible-fault-vmstate.c` under
  `GPL-2.0-or-later` with an explicit SPDX identifier.
- Provides versioned big-endian codecs and section registration only inside the
  GPL-side QEMU process. No QEMU type crosses the shared-memory boundary.
- Serializes the `command`, `memory`, `node-rules`, `cpu`, `interrupt`,
  `hardware-error`, `vcpu-service`, and `lifecycle` sections. The closed final
  registry additionally requires `clock` and `accelerator`.

## Aggregate envelope

The envelope begins with `CRUCFVM1`, version `1`, and an exact section count.
Sections are sorted lexicographically and encode a nonempty name of at most 32
bytes, zero reserved flags, an exact version, a 64-bit length, and canonical
payload bytes. Each section is limited to 64 MiB, the complete envelope to
256 MiB, and the complete envelope is followed by its SHA-256 digest.

Save admission requires the exact closed section-name registry. Duplicate,
missing, unknown, out-of-order, oversized, truncated, trailing, wrong-version,
nonzero-reserved, or digest-mismatched input fails restore before live state is
changed.

## Transactional restore

Restore is a prepare/commit transaction:

1. parse and authenticate the complete aggregate envelope;
2. prepare `node-rules` first so every later section can resolve rule identity;
3. prepare every other section into bounded private allocations without
   changing live state;
4. require exact agreement between restored event reservations and references,
   and between restored deferred-command totals and the command section;
5. commit node rules, then domain state, then the command queue; and
6. free every staged object on any prepare failure.

No section may allocate, validate, resolve a reference, or return a recoverable
error after its commit begins. Cross-section references use stable rule IDs and
validated lookup, never pointers or serialized container internals. Restore
rebuilds indexes from canonical ordered records.

## Section contracts

| Section | Required state and validation |
| --- | --- |
| `command` | Pending commands in total order, completed results, copied payloads, deferred total, bounded seen-sequence window, maximum sequence, registry digest, ABI/version/phase/capability validation, and re-arming through the registered handler. |
| `node-rules` | Canonically ordered typed rules, generations, binding/action/schema identities, decoded command parameters, event reservations, and the stable rule index used by all later sections. |
| `memory` | Persistent memory-region rule state, sparse retention/rowhammer/service data, delayed operations, occurrence counters, and referenced rule identities within declared maxima. |
| `cpu` | Register and instruction rules, architectural occurrence/replay state, active instruction work, and target identity compatible with the restored CPU manifest. |
| `interrupt` | Source generations, delayed and storm events, controller delivery state, occurrence counters, event reservations, and valid rule references. |
| `hardware-error` | Machine-check/RAS/platform records, linked memory error state, pending delivery, acknowledgement state, and exact rule references. |
| `vcpu-service` | Per-vCPU shares, capacity credits and remainders, window/eligibility state, stall/offline/recovery state, and topology-compatible vCPU IDs. |
| `lifecycle` | Process generation, nonterminal transition state, hang/boot/reset/retry policy, terminal authorization/evidence digests, pending decisions, and immutable process binding. |

Every section has its own magic, version, reserved-zero checks, count and byte
ceilings, canonical order, full-consumption check, and consistency validation.
Empty active-domain state is encoded explicitly where needed to distinguish it
from an absent implementation.

## Activation and inertness

The aggregate VMState handler is active only for single-threaded deterministic
RR with a bound Crucible lifecycle process. Ordinary QEMU and non-simulation
machines do not register fault process state, do not change migration bytes, and
retain upstream behavior. Repeated enablement is rejected rather than creating
duplicate save handlers.

## Required live gates

1. Save and restore each section empty, at its maximum legal count, and with
   pending, delayed, active, completed, recovered, and terminal state.
2. Compare uninterrupted execution with restore at every rule phase on x86-64
   and AArch64, including multi-vCPU RR boundaries.
3. Corrupt every envelope and section field class independently; each mutation
   must fail before any live-state commit.
4. Delete, duplicate, reorder, truncate, extend, or version-skew each section;
   restore must reject it.
5. Break every cross-section rule, reservation, deferred-count, CPU, and process
   reference; restore must reject it transactionally.
6. Force allocation failure during every prepare stage and verify unchanged
   pre-restore state and no leak; commit stages must have no fallible path.
7. Remove patch 0067 and prove the core VMState gate and final aggregate marker
   fail. Remove a domain registration and prove save admission fails closed.
8. Run the unpatched-versus-patched non-simulation migration corpus and prove
   identical enumeration, migration bytes, and guest behavior.

## Licensing and completion

The patch must be a separate DCO-signed QEMU commit, update the patch manifest,
bundle, new-file license inventory, corresponding-source closure, and live-gate
catalog, and pass `gate:abi-conformance` and `gate:license-boundary`.

- **[QFP-CORE-STATE-1]** A save MUST include all registered fault state or fail
  before producing a usable checkpoint.
- **[QFP-CORE-STATE-2]** Restore MUST validate and prepare the complete state
  graph before committing any section.
- **[QFP-CORE-STATE-3]** The final system marker MUST remain unavailable until
  patches 0068 through 0070 close the complete registry and all live gates.
