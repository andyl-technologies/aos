# Patch 0051 — `crucible-register-mutate`

## Purpose

Adds architecture-typed register impulse and persistent read/write transforms at
safe boundaries. It extends existing register introspection with validated
mutation; it does not expose a generic host pointer or debugger interface.

## Capability and dependencies

- Provides `qemu.register.mutate.x86_64.v1` and
  `qemu.register.mutate.aarch64.v1`.
- Depends on 0047–0048 and existing per-vCPU register/RR introspection.
- Persistent access transforms also depend on the architecture hook portion of
  this patch and are VMState-complete under 0059.

## Architecture register manifests

QEMU exports a canonical manifest for the exact pinned CPU model. Each row has
numeric register ID, stable name, width, writable mask, reserved/ignored mask,
register group, safe phases, side-effect class, and save/restore coverage.

x86-64 must cover GPRs, RIP, RFLAGS, segment selectors/bases/limits/attributes,
control registers, EFER and modeled system registers, debug registers, x87,
MMX, SIMD/vector registers, and other guest-visible registers of the pinned CPU
model. AArch64 must cover X0–X30, SP, PC, PSTATE, ELR/SPSR by exception level,
guest-visible system registers, FP status/control, and SIMD/vector registers.
Read-only or implementation-private fields are present as non-writable and
cannot be targeted.

### Public target-manifest process protocol

The manifest crosses the Apache/GPL process boundary only as explicitly
encoded little-endian bytes. The normative constants and independent C view
are generated in `crates/crucible-shmem/include/crucible_shmem_abi.h`; the
canonical Rust codec and rejection rules are implemented in
`crates/crucible-shmem/src/shmem/fault_target_manifest.rs`. Neither view
contains a native pointer, QEMU structure, callback, or host-language enum
layout.

The 16-byte `CRUCFTQ1` query is exactly:

| Offset | Width | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `CRUCFTQ1` |
| 8 | 2 | codec version | `1` |
| 10 | 2 | manifest kind | `1` (`register`) |
| 12 | 4 | reserved | all zero |

Version 1 registers only kind `1`. Unknown kinds are rejected; a kind is not
reserved or advertised until its complete response codec, provider, consumer,
golden vector, and live gate exist.

The register response starts with this 56-byte header:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `CRUCRGM1` |
| 8 | 2 | codec version | `1` |
| 10 | 2 | architecture | capability scope `x86_64` or `aarch64` |
| 12 | 2 | CPU-model byte length | `1..=96` |
| 14 | 2 | reserved | zero |
| 16 | 4 | row count | `1..=4096` |
| 20 | 4 | body byte length | exact remaining length |
| 24 | 32 | body digest | BLAKE3 of bytes beginning at offset 56 |

The body is the exact printable, non-space ASCII CPU-model identity followed
by `row_count` variable rows. Each row begins with this 42-byte header, then
contains `name`, `writable`, `reserved`, `ignored`, and `read_only` bytes in
that order:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | nonzero numeric ID |
| 4 | 2 | closed register-group tag |
| 6 | 2 | reserved, zero |
| 8 | 4 | width in bits |
| 12 | 8 | safe model-phase mask |
| 20 | 4 | required side-effect flags |
| 24 | 4 | impulse/persistent/VMState flags |
| 28 | 2 | name length |
| 30 | 2 | writable-mask length |
| 32 | 2 | reserved-mask length |
| 34 | 2 | ignored-mask length |
| 36 | 2 | read-only-mask length |
| 38 | 4 | complete row length |

Every mask length equals `ceil(width_bits / 8)`. For every in-range bit,
exactly one of the four masks contains that bit; padding bits are zero. Numeric
IDs strictly increase, names are unique canonical lowercase identifiers, and
the total header plus body cannot exceed the shared fault-payload hard limit.
Decoders reproduce the canonical encoding byte for byte or reject it. The
frozen cross-language vector is
`crates/crucible-shmem/tests/fixtures/fault_register_manifest_v1.hex`.

QEMU first copies its process-private row structure into the GPL plugin. The
plugin validates width against the redundant mask length before dereferencing
any mask pointer, converts the rows to the public byte codec, and seals a
one-to-one mapping from the public name hash to the private numeric ID. Duplicate
names, duplicate IDs, registry changes during the two-call copy, or a manifest
that cannot fit the result arena fail launch before guest execution.

Manifest hashes enter QEMU capabilities and scenario admission. CPU model or
QEMU changes that alter the manifest require a semantic version/golden update.
Production launch construction accepts only
`QemuFaultCapabilityRequirement::current_v1_for_node`; the requirement binds
the World node hash, architecture, realized QOM CPU type, complete canonical
register manifest, and derived capability digest before process spawn. The VM
node ID and plugin `fault_node_hash` must both equal that bound node hash.
Generic row constructors and ABI-boundary constructors are not public launch
paths. Loaded-backend gates have a crate-private discovery path because their
purpose is to interrogate the real QEMU implementation; it cannot be called by
production consumers.

## Command payload

The common typed payload carries the target vCPU, architecture/register
manifest identities, target and effect bit ranges, phase, rule generation,
`bit_flip/stuck/replace` mutation, exact mask/value bytes, and closed occurrence
policy. The command envelope carries the expected precondition digest. Ranges
must fit the register and writable mask; reserved bits are always preserved and
there is no policy that permits writing them.

`replace` replaces the complete selected bit range. Bit flips XOR the mask.
`stuck` uses equal-width mask and value bytes to force only selected bits.
Persistent stuck rules transform reads/writes at the declared register
access/commit hook;
if QEMU has no semantically complete hook for a manifest row, that row cannot
advertise persistent capability even though impulse mutation may exist.

## Side effects and validation

Registers affecting translation, privilege, interrupt state, FP/vector mode,
timers, or execution flow use QEMU's architecture setter and trigger required
TLB/TB invalidation, hflags recomputation, interrupt reevaluation, timer rearm,
or CPU synchronization. Direct struct writes are forbidden unless the upstream
architecture contract explicitly designates them and the microtest proves all
derived state.

Reserved bits are preserved. Modeling an illegal architectural state uses patch
0052 exception injection, not writing a QEMU-invalid reserved combination.
Mutation of PC/RIP changes the next instruction and is evidenced as a control-
flow mutation; target translation must be valid or the resulting guest
architecture exception must be deterministic.

## Composition and evidence

Same register/phase commands apply in canonical order with intermediate values.
Persistent rules are an ordered transform set. Evidence includes manifest/CPU
model, vCPU/RR cursor, register/field, before/after complete register value,
derived-state actions, phase, icount, and fingerprint.

The GPL-side `CRUCQRW1` record has a fixed 128-byte little-endian header,
followed by `before`, `after`, `mask`, and `value` byte strings in that order:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | magic `CRUCQRW1` |
| 8 | 2 | codec version `1` |
| 10 | 2 | architecture scope |
| 12 | 2 | model phase |
| 14 | 2 | reserved, zero |
| 16 | 4 | vCPU index |
| 20 | 4 | private numeric manifest row ID |
| 24 | 4 | closed mutation-kind tag |
| 28 | 4 | declared side-effect mask |
| 32 | 4 | performed side-effect mask |
| 36 | 4 | first bit |
| 40 | 4 | bit count |
| 44 | 4 | `before` byte length |
| 48 | 4 | `after` byte length |
| 52 | 4 | `mask` byte length |
| 56 | 8 | observed node icount |
| 64 | 8 | RR current vCPU |
| 72 | 8 | RR cursor position |
| 80 | 8 | RR switch quantum |
| 88 | 32 | execution fingerprint SHA-256 |
| 120 | 4 | `value` byte length |
| 124 | 4 | reserved, zero |

`RR cursor position` is normally strictly less than `RR switch quantum`.
After-instruction evidence may carry the terminal position equal to the
quantum: QEMU captures that boundary after the final instruction retires and
before the RR scheduler rotates to its next slice. No other model phase may
use the terminal position, and values greater than the quantum are invalid.

The Apache bridge does not trust this private row ID in isolation. It resolves
the submitted public register-name hash through the exact admitted manifest,
then requires the returned architecture, row ID, phase, range, mutation kind,
mask, value, widths, and side-effect declaration to match that command and row.
It independently recomputes the selected-bit transform and both value hashes.
Only then does it emit the canonical 256-byte-header public evidence record,
which carries the architecture/CPU/manifest digests and the same four byte
strings. A mismatch is a terminal bridge error, never a partially accepted
event.

## VMState

Architectural values already participate in CPU VMState; persistent rule tables
and pending commands are added by 0059. Save/load validates identical register
manifest hash and CPU model.

## Live microtests

1. For every writable manifest group on both architectures, mutate a selected
   field and prove guest/QEMU observation plus fingerprint change.
2. Cover PC, flags/PSTATE, control/system, FP/SIMD, translation-affecting, and
   interrupt-affecting side effects explicitly.
3. Verify reserved/out-of-range/read-only/wrong-manifest/wrong-vCPU/wrong-before
   failures leave state unchanged.
4. Exercise persistent stuck read/write rules where advertised.
5. Save/restore after each group and compare uninterrupted execution.
6. Revert patch and fail live mutation gate; prove non-sim inertness.

## Licensing checklist

Architecture/QEMU CPU changes and plugin calls remain GPL-side. The host sees
only the public numeric manifest and values. No QEMU CPU struct/layout crosses
the boundary. Preserve notices, inventory new files, DCO-sign, and include full
source/microtests.

- **[QFP-REG-1]** Capability coverage is manifest-row and phase specific; a
  generic “register write supported” bit is insufficient.
- **[QFP-REG-2]** Derived architectural/QEMU state MUST be recomputed through
  approved setters before acknowledging application.
