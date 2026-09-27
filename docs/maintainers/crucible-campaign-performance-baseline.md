# Crucible campaign performance baseline

RFC-0020 §10.4 requires a measured baseline and a regression ratchet on the
pinned reference host. `gate:campaign-performance` deliberately returns
`BLOCKED` while `campaign-performance-reference-baseline-v1.env` is absent or
its reviewed SHA-256 is unset. Do not fill either value from an estimate or a
synthetic result. The first accepted sample must come from the production QEMU
scaling gate on the host named in
`tests/crucible/fixtures/campaign-performance-reference-host-v1.env`.

## Collect the reference evidence

1. Freeze the source commit and coordinate an exclusive quiet window for host
   CPU 0. Stop other CPU-isolated benchmark and correctness VMs, and record the
   source commit, UTC time, and any host load that could affect timing. The
   scaling flight pins Firecracker to CPU 0; its guest test also requires CPU 0
   affinity. Keep the host profile's kernel, CPU model, stepping, and microcode
   unchanged during the measurement.
2. From that source checkout, run the ordinary release derivations without
   shared development caches:

   ```sh
   scaling_out=$(bash ./aos-dev --release build check crucible.phase7.gates.hotForkScaling.rawGate --no-out-link)
   metadata_out=$(bash ./aos-dev --release build check crucible.phase9.gates.campaignMetadataMillion --no-out-link)
   ```

   These are long production flights: the scaling gate includes 10,000 child
   lifecycles, and the metadata gate admits one million real attempts. Do not
   replace either with a unit-test result or a modeled benchmark.
3. Retain the exact `${scaling_out}/serial.log`,
   `${scaling_out}/host-reference.env`, `${scaling_out}/result`,
   `${metadata_out}/evidence/profile.env`,
   `${metadata_out}/evidence/million-admissions.log`, and
   `${metadata_out}/result`
   outside the source checkout. Record their store paths and SHA-256 digests
   with the source commit for review. Both results must begin with `PASS`.

The scaling serial log must contain exactly one positive value for each
`corpus_0..2_campaign_planner_queue_ns` and
`corpus_0..2_hot_guest_continuation_ns`, plus their matching reported totals.
The current gate checks these totals, the identical short-branch boundary, the
packaged planner, the SQLite store graph, and the host's CPU 0 affinity. The
observed totals must satisfy `planner_ns * 100 < guest_ns * 5`. The metadata
result must authenticate one million admissions and the bounded object, index,
physical-store, and peak-memory evidence.

## Review and pin the baseline

Create `tests/crucible/fixtures/campaign-performance-reference-baseline-v1.env`
from the retained raw scaling result. Its exact fields are:

```text
schema=crucible.campaign-performance.baseline.v1
reference_host_profile_sha256=<SHA-256 of campaign-performance-reference-host-v1.env>
baseline_planner_queue_ns=<measured campaign_planner_queue_total_ns>
baseline_guest_continuation_ns=<measured hot_guest_continuation_total_ns>
max_planner_queue_ratio_ppm=<reviewed integer ceiling>
```

The gate requires `0 < ceiling < 50,000` and
`baseline_planner_queue_ns * 1,000,000 <= baseline_guest_continuation_ns * ceiling`.
Choose and explain a bounded margin for measurement noise; do not raise the
ceiling simply to make a later regression pass. Preserve the raw per-corpus
samples and the host-reference file so a reviewer can recompute both totals
and confirm the host profile. The current gate requires the baseline itself to
pass the strict 5% limit and applies the same ceiling to every later measurement.

Set `approvedSha256` beside the baseline path in
`tests/crucible/phase9-campaign-performance.nix` to the exact SHA-256 of the
reviewed fixture. Review the fixture, hash change, raw evidence, source commit,
and ceiling rationale together. A future baseline revision needs a new measured
sample and the same review; changing the hash without evidence is not a
performance qualification.

After pinning, run the performance gate:

```sh
bash ./aos-dev --release build check crucible.phase9.gates.campaignPerformance --no-out-link
```

Inspect its `result`
and retained `evidence/` files. When their other producer gates are green, run
`crucible.phase9.gates.campaignRequiredGates` and
`crucible.phase9.gates.campaignReleaseAcceptance` through the same
`aos-dev --release build check` command. `PASS` from the performance gate is necessary
but does not replace the independent hot-fork, metadata, Envoy, determinism,
ABI, and license gates.
