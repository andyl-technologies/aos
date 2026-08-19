# 0086 - Genesis observation boundary

## Purpose

The independent definition process must capture complete architectural state
for every realized vCPU before guest execution. Patch `0085` correctly rejects
ordinary unowned plugin callbacks, including plugin exit, so definition capture
needs an explicit stopped-state boundary rather than an exception to register
ownership.

Patch `0086` extends the existing BQL-held pause callback with one additional
admitted state: `RUN_STATE_PRELAUNCH` while the raw retired-instruction count is
exactly zero. It does not add a second register reader or relax live execution
ownership.

## Admission contract

`qemu_plugin_crucible_request_terminal_pause` invokes its callback with status
zero only when the caller is under the Big QEMU Lock and one of these conditions
holds:

1. QEMU is in `RUN_STATE_PAUSED`; or
2. QEMU is in `RUN_STATE_PRELAUNCH` and `icount_get_raw_observed()` is exactly
   zero.

A running VM first follows the existing asynchronous stop path. Prelaunch with
a negative observation fails with `EPERM`; prelaunch after any retired
instruction fails with `ERANGE`; every other non-running state fails with
`ECANCELED`. A nonzero callback status never authorizes raw export.

## Definition capture lifecycle

The trace plugin initializes each configured vCPU register manifest from the
realized machine. When all configured manifests are complete in
`definition_only` mode, it submits exactly one pause request. The BQL-held
callback records its request, completion, and zero status in the definition
record, then samples all vCPU register files, RAM, VMState, RR genesis state,
and process identity through production QEMU APIs.

The QMP harness waits boundedly for exactly one complete definition record
before requesting process exit. Plugin exit may report a missing record, but it
must never sample or synthesize one. Request failure, callback failure, an
incomplete manifest, a nonzero register-read failure count, or a zero component
digest fails the run loudly.

## Files and license scope

The patch modifies `include/qemu/qemu-plugin.h` and `plugins/api.c`. Both retain
their existing upstream licenses. It creates no QEMU source file, so
`LICENSES.md` does not gain a row. The trace plugin remains GPL-2.0-only and
communicates only serialized evidence across the established process boundary.

## Required gates

1. Launch a four-vCPU definition process with `-S` and prove QMP reports
   `prelaunch` with CPU indexes `0..3`.
2. Prove exactly one callback-authorized definition record is visible before
   QMP quit, with raw icount and retired count zero.
3. Prove every register count, register byte count, register digest, RAM digest,
   and device-state digest is complete and nonzero.
4. Prove plugin exit contains no definition sampling fallback.
5. Rebuild every QEMU patch prefix, regenerate the deterministic patch stack,
   and pass ABI, license-boundary, and source-retention gates.

- **[QFP-GENESIS-1]** All-vCPU prelaunch observation MUST occur under the BQL at
  exact raw icount zero.
- **[QFP-GENESIS-2]** Definition evidence MUST be complete before process-exit
  control begins and MUST NOT be synthesized from an exit callback.
