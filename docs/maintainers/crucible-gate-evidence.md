# Crucible gate evidence scope

Some Crucible gates deliberately exercise fake runners, `SimDouble`, or a
performance cost model. Those component tests remain useful regression tests;
their success is not evidence that the corresponding scenario ran in QEMU.

## Fingerprint dependency correction

`checks.crucible.phase2.gates.singleVmFingerprint` previously required the live
production-plugin fingerprint check only through its outer ordering wrapper.
Consumers using `.rawGate`, including phase-7 fleet equivalence, could bypass
that authority and still obtain a passing dependency. The raw gate now also
requires both `phase2.qemuSingleVmFingerprint` (the diagnostic C-trace importer)
and `phase2.qemuLivePluginFingerprint` (the production Rust-plugin authority).
The wiring checks require these dependencies on both paths.

The live plugin authority executes two QEMU runs, perturbs host scheduling,
compares fingerprint samples, and exercises a changed-frame negative control
with live divergence bisection. The generic fingerprint-runner tests still use
fake streams to cover comparator and error-handling behavior. The diagnostic
importer separately records its partial scope; it does not replace the live
plugin authority.

## Phase-7 component reports

The following raw checks now report `status=component-only`, an explicit
`evidence_scope`, and `live_qemu_acceptance=not-established-by-this-check`:

| Raw gate | Evidence exercised by its test target | Separate production evidence |
| --- | --- | --- |
| `phase7.gates.perfBench` | Deterministic performance cost model | `checks.fleet.crucible-perf` and focused live performance checks |
| `phase7.gates.e2eDeterminism` | Shared mock artifact under host profiles | `checks.fleet.crucible-e2e-determinism` |
| `phase7.gates.fleetEquivalence` | SimDouble search/fleet finding and artifact equivalence | Live fingerprint dependency plus separate distributed exploration checks |

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
