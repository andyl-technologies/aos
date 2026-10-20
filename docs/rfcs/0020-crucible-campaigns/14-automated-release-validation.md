# 14. Automated release validation

Crucible Campaigns release acceptance is executable and fail closed. It combines
the Phase 9 required-gate aggregate with a live packaged-QEMU determinism flight.
Release does not depend on operator sign-off, a destructive-recovery drill, a
long-running dogfood flight, a signer quorum, or evidence from another physical
host.

The prior manual release workflow and its evidence formats have been removed.
Contribution authorization and QEMU licensing checks remain independent release
requirements under repository policy.

## 14.1 Executable acceptance inputs

`gate:campaign-release-acceptance` accepts only authenticated PASS results for:

- `gate:campaign-gate-matrix`;
- `gate:campaign-operational-continuity`;
- `gate:campaign-replay`;
- `gate:hot-fork-scaling`;
- `gate:campaign-required-gates`; and
- `gate:e2e-determinism`.

The required-gates aggregate binds every release claim to the exact result bytes
that established it. This includes the automated five-VM Envoy product gate
retained by CAM-13. The release manifest binds the Crucible package, patched
QEMU, plugin, guest kernel, root image, ABI, and license-boundary identities.
Missing inputs, changed digests, extra or missing claim gates, symlinked evidence,
and incompatible schemas block acceptance.

## 14.2 Local deterministic QEMU flight

`gate:e2e-determinism` runs the packaged Crucible CLI, patched QEMU, and plugin
under TCG on the build machine. The gate runs the same representative multi-VM
fault scenario under each of these host profiles:

1. a quiet single-core profile;
2. randomized worker scheduling on two available cores; and
3. CPU pressure, synchronous I/O pressure, wall-clock launch jitter, and bounded
   scheduler preemption on four available cores.

The gate requires nonempty live event and execution-fingerprint streams. Their
canonical bytes must agree across all profiles. Each profile must produce the
same reproduction artifact bytes. The artifact from the quiet profile is then
replayed locally under the hostile four-core profile, and that replay must
reproduce the recorded outcome, event stream, and fingerprint stream exactly.

This profile change is the host-profile independence test. It deliberately
perturbs host scheduling, core availability, wall-clock launch timing, and I/O
service without making a second physical host part of the release contract.

## 14.3 Retained evidence

The fleet derivation retains:

- raw JSONL and store-population output for every profile;
- the canonical result comparison and per-profile artifact digests;
- host-pressure worker status and bounded-preemption evidence;
- the locally replayed artifact and replay transcript;
- a manifest that hashes the exact scenario, QEMU binary and build identity,
  plugin, kernel, root image, canonical results, command journal, and
  reproduction artifact; and
- a result that binds the manifest, canonical results, and reproduction
  artifact by SHA-256.

Phase 9 verifies those files directly from the executable fleet derivation. It
does not accept an injected evidence path or an operator-authored substitute.
The accepted release bundle copies the validated evidence and records its result
and manifest digests alongside all other executable gate results.

## 14.4 Negative controls

The release-contract check constructs a valid local evidence bundle, verifies
it, and then proves fail-closed behavior for missing evidence, altered canonical
results, and a changed closure-manifest digest. The native gate separately fails
when a profile diverges, a fingerprint stream is empty, the artifact changes,
the replay does not apply bounded scheduler preemption, or the live QEMU result
cannot be reproduced.
