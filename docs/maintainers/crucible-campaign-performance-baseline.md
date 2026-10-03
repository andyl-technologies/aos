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
2. From that source checkout, run the scaling release derivation without shared
   development caches:

   ```sh
   scaling_out=$(bash ./aos-dev --release build check crucible.phase7.gates.hotForkScaling.rawGate --no-out-link)
   ```

   This production flight includes 10,000 child lifecycles. Do not replace it
   with a unit-test result or a modeled benchmark. Confirm its `result` begins
   with `PASS` before considering the measurement.
3. Retain the exact `${scaling_out}/serial.log`,
   `${scaling_out}/host-reference.env`, `${scaling_out}/result`,
   and their store path outside the source checkout. Record the source commit,
   UTC time, and SHA-256 digests for review.
4. Run the independent million-admission release derivation. It may run while
   the scaling baseline is under review, but its `PASS` result is required
   before `gate:campaign-performance` can pass:

   ```sh
   metadata_out=$(bash ./aos-dev --release build check crucible.phase9.gates.campaignMetadataMillion --no-out-link)
   ```

   Retain `${metadata_out}/evidence/profile.env`,
   `${metadata_out}/evidence/million-admissions.log`, and
   `${metadata_out}/result` with their SHA-256 digests. The result must begin
   with `PASS` and authenticate one million real admissions.

The scaling serial log must contain exactly one positive value for each
`corpus_0..2_campaign_planner_queue_ns` and
`corpus_0..2_hot_guest_continuation_ns`, plus their matching reported totals.
The current gate checks these totals, the identical short-branch boundary, the
packaged planner, the SQLite store graph, and the host's CPU 0 affinity. The
observed totals must satisfy `planner_ns * 100 < guest_ns * 5`. The metadata
result must authenticate one million admissions and the bounded object, index,
physical-store, and peak-memory evidence.

## Review and pin the baseline

Choose a reviewed integer ratio ceiling from the measured ratio and a justified
noise margin. Extract the candidate fixture with the AOS-built Python package:

```sh
python_out=$(bash ./aos-dev --release build package python3 --no-out-link)
"$python_out/bin/python3" tests/crucible/campaign-performance-baseline.py \
  "$scaling_out" --ratio-ceiling-ppm "$reviewed_ceiling_ppm" \
  > campaign-performance-reference-baseline-v1.env
```

The extractor requires a `PASS` scaling result, the exact pinned host profile,
CPU 0 guest affinity, the packaged planner and SQLite backend, three positive
per-corpus measurements, matching totals, and the strict 5% limit. It emits
the SHA-256 of the raw scaling result, serial log, and observed host profile.
Review those raw files before copying the candidate to
`tests/crucible/fixtures/campaign-performance-reference-baseline-v1.env`.
The fixture has these exact fields:

```text
schema=crucible.campaign-performance.baseline.v1
reference_host_profile_sha256=<SHA-256 of campaign-performance-reference-host-v1.env>
reference_scaling_result_sha256=<SHA-256 of retained scaling result>
reference_scaling_serial_sha256=<SHA-256 of retained scaling serial.log>
reference_scaling_host_sha256=<SHA-256 of retained scaling host-reference.env>
baseline_planner_queue_ns=<measured campaign_planner_queue_total_ns>
baseline_guest_continuation_ns=<measured hot_guest_continuation_total_ns>
max_planner_queue_ratio_ppm=<reviewed integer ceiling>
```

The gate requires `0 < ceiling < 50,000` and
`baseline_planner_queue_ns * 1,000,000 <= baseline_guest_continuation_ns * ceiling`.
Do not raise the ceiling simply to make a later regression pass. Preserve the
raw per-corpus samples and the host-reference file so a reviewer can recompute
both totals and confirm the host profile. The gate requires the baseline itself
to pass the strict 5% limit and applies the same ceiling to every later
measurement. Its PASS record retains the reference evidence digests.

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
