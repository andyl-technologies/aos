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

Manifest hashes enter QEMU capabilities and scenario admission. CPU model or
QEMU changes that alter the manifest require a semantic version/golden update.

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
