# Crucible gate evidence scope

Some Crucible gates deliberately exercise fake runners, `SimDouble`, or a
performance cost model. Those component tests remain useful regression tests;
their success is not evidence that the corresponding scenario ran in QEMU.

## Fingerprint authority

`checks.crucible.phase2.gates.singleVmFingerprint` directly instantiates
`phase1-production-fingerprint-sample.nix`. Its raw derivation imports the
production Rust-plugin flight and the QEMU fingerprint projection manifest, so
consumers of `.rawGate` cannot bypass either authority. The gate orders after
`qemuInert.rawGate`; its outer wrapper retains the canonical Phase 2 ordering
and projection-manifest dependency.

The production flight executes two QEMU runs, perturbs host scheduling,
compares fingerprint samples, and exercises an instruction-adjacent mismatch
window. Generic fingerprint-runner tests still use fake streams to cover
comparator and error-handling behavior, but they do not certify the production
gate.

## Phase-7 component reports

The following raw checks now report `status=component-only`, an explicit
`evidence_scope`, and `live_qemu_acceptance=not-established-by-this-check`:

| Raw gate | Evidence exercised by its test target | Separate production evidence |
| --- | --- | --- |
| `phase7.gates.perfBench` | Deterministic performance cost model | `checks.fleet.crucible-perf` and focused live performance checks |
| `phase7.gates.fleetEquivalence` | SimDouble search/fleet finding and artifact equivalence | Live fingerprint dependency plus separate distributed exploration checks |

The Phase 7 e2e derivation now emits a native-evidence contract instead of a
component-only completion result. Its `canonical_gate_status` remains
`release-blocked` until authenticated transcripts from two distinct physical
hosts are supplied, and becomes `satisfied` only after it verifies that
evidence.

These component checks still pass when their own assertions pass. Naming a
production check in a result file does not execute that check, and importing a
single-VM live fingerprint result does not prove live distributed search
equivalence. The current live CLI verification path uses the production QEMU
control plane and lifecycle loop. Run the separate fleet checks to obtain their production
evidence and inspect their actual scenario coverage; this wiring audit did not
execute those fleet workloads. The phase-7 CI wiring check rejects
unqualified completion metadata on these component reports.

This correction does not replace the cost model with measurements, convert the
mock e2e target into a live scenario runner, or establish live fleet equivalence
for the SimDouble matrix. Those coverage boundaries remain explicit; neither
component reports nor a single live dependency certify the entire matrix.
