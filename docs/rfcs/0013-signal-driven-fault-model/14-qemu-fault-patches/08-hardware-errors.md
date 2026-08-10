# Patch 0054 — `crucible-hardware-error-inject`

## Purpose

Adds architecture/platform-correct CPU and memory hardware-error injection:
x86 machine checks, AArch64 synchronous/asynchronous hardware errors, corrected
and uncorrectable memory/ECC records, and deterministic reset/fatal outcomes.
Generic exceptions remain in 0052; memory access poison remains in 0050.

## Capability and dependencies

- Uses the `qemu.cpu.exception.v1` command capability for CPU records and
  `qemu.memory.ecc-event.v1` for memory records. Each capability manifest has
  a closed `hardware_error_classes` member. CPU entries are exactly
  `x86_machine_check.v1` and/or `aarch64_ras.v1`; memory entries enumerate the
  realized platform record mechanisms and corrected/uncorrectable classes.
  Admission requires the requested record kind and all of its exact field masks
  to be present. An empty member advertises only ordinary exception entry and
  cannot admit a hardware-error record.
- Depends on 0047–0053 and machine firmware/platform error-reporting realization.

## Error manifest

The realized machine reports a closed architecture/platform manifest:

| Architecture | Required classes |
| --- | --- |
| x86-64 | recoverable/fatal machine check, corrected machine-check record, memory hierarchy/bus error banks, optional CMCI where realized |
| AArch64 | synchronous external abort where architecturally valid, asynchronous SError, corrected platform record, fatal hardware error |
| Both | corrected/uncorrectable memory ECC record tied to GPA and optional channel/rank/bank/syndrome |

This manifest member is part of the capability digest exchanged by 0047; it is
not a separately negotiated command or an unversioned extension string. Rows
specify exact status/syndrome field masks, bank/record IDs, delivery phase,
maskability, guest firmware/table/device prerequisite, supported privilege level,
and resulting QEMU/guest state. Unsupported firmware/machine configurations fail
admission rather than logging a host-only fake error.

## Platform reporting device

When upstream machine support is insufficient, the patch adds a sim-only
`crucible-hw-error` platform component realized only under `-accel sim` with the
matched plugin. It publishes architecture-standard error records through the
pinned machine's supported mechanism, such as ACPI APEI/GHES for compatible
machines, and asserts the corresponding architecture interrupt/error path. It
does not require an AOS-specific guest driver. A guest may ignore a standard
corrected record; QEMU still records successful platform publication.

The device and its firmware/table contribution are part of machine identity and
VMState. Non-sim machine enumeration is unchanged.

## Command payload

CPU hardware errors use the common `NodeException` payload: architecture,
vector/class, syndrome, optional fault address, before/after timing, maskability,
and exactly one `architecture_default`, `x86_machine_check`, or `aarch64_ras`
record. The x86 record carries bank, MCi status/address/misc, MCG status, and
corrected state. The AArch64 record carries ESR/FAR/DISR, synchronous versus
asynchronous delivery, and corrected state. The target supplies the vCPU and
the command envelope supplies phase and expected record digest.

Memory hardware errors use the common ECC payload: corrected/uncorrectable,
address, syndrome, bank/channel/rank identities, and closed telemetry,
corrected-interrupt, or complete exception visibility. A separate same-boundary
memory poison/mutation and lifecycle command expresses linked data corruption
or fatal reset; canonical binding order and evidence bind the commands rather
than an optional opaque command-sequence field.

## Semantics

- Corrected error publishes a standard corrected record/event and does not
  corrupt returned data unless a separate memory transform does so.
- Uncorrectable recoverable error publishes record and injects the declared
  architecture exception; poisoned access may be the triggering opportunity.
- Fatal error follows architecture/platform fatal delivery, then the declared
  deterministic node lifecycle outcome from patch 0056.
- x86 machine-check fields and bank state are written through architecture
  helpers before injection; invalid combinations reject.
- AArch64 ESR/FAR/SError state and target exception level follow the manifest;
  impossible synchronous/asynchronous combinations reject.

Repeated errors update bank/record overflow/valid bits by the documented
architecture rule. Same-boundary errors order by severity, target, record/bank,
and command order key.

## Evidence and VMState

Evidence includes manifest and machine/firmware identity, target, raw typed
record fields, prior/new bank/platform record state, linked memory state,
architecture injection acknowledgement, guest-visible entry where observable,
fatal lifecycle transition, and fingerprints. Patch 0059 serializes platform
device queues, bank/record state, pending delivery, and links to memory commands.

## Live microtests

1. Boot unmodified x86-64 and AArch64 fixture guests with the standard platform
   reporting surface and inject every advertised corrected/recoverable/fatal
   class.
2. Verify QEMU architecture state and guest-visible record/exception where the
   guest supports it; guest ignorance of corrected telemetry remains a recorded
   successful platform delivery, not a simulated test-double result.
3. Link ECC errors to real GPA poison/mutation and verify before/precondition.
4. Exercise masking, repeated/overflowed records, simultaneous banks/records,
   wrong firmware/machine, invalid fields, and unsupported privilege states.
5. Save/restore pending and delivered records.
6. Revert patch and fail capability/live gates; prove non-sim device enumeration
   and behavior equal unpatched QEMU.

## Licensing checklist

Architecture CPU, ACPI/platform device, firmware-table integration, and plugin
code are QEMU/GPL-side. New device files receive explicit applicable notices and
enter `LICENSES.md`. The Apache host exchanges only public typed error records.
DCO, microtests, source catalog, notices, and corresponding source are required.

- **[QFP-HWERR-1]** A corrected error requires real platform/QEMU record state;
  an event-log-only implementation is forbidden.
- **[QFP-HWERR-2]** Architecture-specific fields MUST be manifest-validated and
  live-tested on their architecture before capability advertisement.
