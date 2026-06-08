# Registry VM Validation Runbook

> **Status:** VM validation PR runbook. These checks run inside the Nix-based
> headless Firecracker VM test harness and require a KVM-capable builder. Do not
> run them on developer laptops without KVM access. The current builder target is
> `dylan@builder-hil1-c13958ef`.

The VM checks live in
[`../../../tests/vm/apm/registry_validation.nix`](../../../tests/vm/apm/registry_validation.nix)
and are exposed through
[`../../../tests/vm/apm/default.nix`](../../../tests/vm/apm/default.nix).
Run them from a Linux/KVM checkout synced to the builder:

```sh
nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array
nix-build -A checks.vm.apm.registry-validation-origin-cdn-layout
nix-build -A checks.vm.apm.registry-validation-stock-git-matrix
nix-build -A checks.vm.apm.registry-validation-pack-delta-perf
```

## Builder Evidence: 2026-06-08

The focused registry validation checks passed on
`dylan@builder-hil1-c13958ef` from the synced checkout
`/tmp/aos-vm-fleet-validation-20260606` with:

```sh
nix-build /tmp/aos-vm-fleet-validation-20260606 --argstr system x86_64-linux -A checks.vm.apm.registry-validation-stock-nix-backend-array --no-out-link
nix-build /tmp/aos-vm-fleet-validation-20260606 --argstr system x86_64-linux -A checks.vm.apm.registry-validation-origin-cdn-layout --no-out-link
nix-build /tmp/aos-vm-fleet-validation-20260606 --argstr system x86_64-linux -A checks.vm.apm.registry-validation-stock-git-matrix --no-out-link
nix-build /tmp/aos-vm-fleet-validation-20260606 --argstr system x86_64-linux -A checks.vm.apm.registry-validation-pack-delta-perf --no-out-link
```

Passing outputs:

- `stock-nix-backend-array`:
  `/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`
- `origin-cdn-layout`:
  `/nix/store/xfzd1yim7sx5cq9gsg6nx8kvh1hi551s-aos-vm-test-apm-registry-validation-origin-cdn-layout-0`
- `stock-git-matrix`:
  `/nix/store/yx7wm7m63l6smij5k57dbjlz22y3ql74-aos-vm-test-apm-registry-validation-stock-git-matrix-0`
- `pack-delta-perf`:
  `/nix/store/c6lg01w5ks8f2h4ginav0wfdhlf12az9-aos-vm-test-apm-registry-validation-pack-delta-perf-0`

The detailed guest evidence is in each output's `serial.log`.

## 1. Stock Nix, Signatures, And Backend Array

Check:

```sh
nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array
```

This VM creates a tiny fixed-output store path, generates signed static
Nix-cache files with `apr cache generate`, uploads the same generated cache to a
mixed destination array, and serves the generated cache to stock Nix with
`require-sigs = true`.

Evidence required:

- generated `.narinfo` contains `Sig:`;
- stock `nix path-info --store http://127.0.0.1:18080 <store-path>` succeeds
  with `require-sigs` and the generated trusted public key;
- `file://`, S3-compatible, and SFTP destinations receive byte-identical
  `nix-cache-info`, `<storehash>.narinfo`, and `nar/*` outputs;
- an invalid fourth destination is reported as one partial failure only after
  all valid destinations have been attempted.

Primary files:

- [`../../registry/nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
- [`../../registry/publishing.md`](../../registry/publishing.md)
- [`../../../tests/vm/apm/registry_validation.nix`](../../../tests/vm/apm/registry_validation.nix)
- [`../../../crates/aos-package/src/registry/nixcache.rs`](../../../crates/aos-package/src/registry/nixcache.rs)
- [`../../../crates/aos-cache/src/backend/s3.rs`](../../../crates/aos-cache/src/backend/s3.rs)
- [`../../../crates/aos-cache/src/backend/sftp.rs`](../../../crates/aos-cache/src/backend/sftp.rs)

Passing builder evidence: output
`/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`.
Its `serial.log` records the expected aggregate invalid-destination diagnostic
for `not-a-url`, then
`registry stock Nix + backend array validation passed`.

## 2. CDN / Mirror Layout

Check:

```sh
nix-build -A checks.vm.apm.registry-validation-origin-cdn-layout
```

This VM uploads a git-native registry origin plus generated static-cache files to
an S3-compatible endpoint and inspects the recorded upload metadata.

Evidence required:

- immutable uploads happen before mutable pointer/index uploads;
- immutable `objects/**`, `nar/**`, and `*.narinfo` get long immutable
  `Cache-Control`;
- mutable `HEAD`, `info/refs`, `objects/info/**`, `channels/**`, and
  `nix-cache-info` get low-TTL / must-revalidate `Cache-Control`;
- content types match the reference layout;
- `objects/info/alternates`, when present, contains only relative paths.

Primary files:

- [`../../registry/http-layout.md`](../../registry/http-layout.md)
- [`../../registry/publishing.md`](../../registry/publishing.md)
- [`../../../tests/vm/apm/registry_validation.nix`](../../../tests/vm/apm/registry_validation.nix)
- [`../../../crates/aos-package/src/registry/static_upload.rs`](../../../crates/aos-package/src/registry/static_upload.rs)
- [`../../../crates/aos-package/src/registry/objectstore.rs`](../../../crates/aos-package/src/registry/objectstore.rs)

Passing builder evidence: output
`/nix/store/xfzd1yim7sx5cq9gsg6nx8kvh1hi551s-aos-vm-test-apm-registry-validation-origin-cdn-layout-0`.
Its `serial.log` records
`registry origin CDN layout validation passed`.

## 3. Stock Git Matrix

Check:

```sh
nix-build -A checks.vm.apm.registry-validation-stock-git-matrix
```

This VM serves a sha256 bare registry over dumb HTTP and clones it with the
pinned minimum Git floor and the repo's current Git package.

Evidence required:

- `pkgs."git-2_42"` reports Git 2.42.x;
- `pkgs.git` reports a supported newer version;
- both binaries clone the dumb-HTTP origin;
- both clones report `rev-parse --show-object-format` as `sha256`.

Primary files:

- [`../../registry/http-layout.md`](../../registry/http-layout.md)
- [`../../../pkgs/tools/git-2_42.nix`](../../../pkgs/tools/git-2_42.nix)
- [`../../../pkgs/tools/git.nix`](../../../pkgs/tools/git.nix)
- [`../../../tests/vm/apm/registry_validation.nix`](../../../tests/vm/apm/registry_validation.nix)
- [`../../../crates/aos-package/src/registry/git.rs`](../../../crates/aos-package/src/registry/git.rs)

Passing builder evidence: output
`/nix/store/yx7wm7m63l6smij5k57dbjlz22y3ql74-aos-vm-test-apm-registry-validation-stock-git-matrix-0`.
Its `serial.log` records `validating stock Git 2.42.0`,
`validating stock Git 2.48.1`, and
`registry stock Git matrix validation passed`.

## 4. Pack/Delta Performance

Check:

```sh
nix-build -A checks.vm.apm.registry-validation-pack-delta-perf
```

This VM builds a synthetic sha256 registry, measures full-pack generation,
thin-delta generation, zstd compression, and consumer reconstruction, and prints
`REGISTRY_PERF_METRIC` lines.

Evidence required:

- `REGISTRY_PERF_METRIC full_pack_bytes=...`;
- `REGISTRY_PERF_METRIC full_pack_ns=...`;
- `REGISTRY_PERF_METRIC thin_delta_bytes=...`;
- `REGISTRY_PERF_METRIC thin_delta_ns=...`;
- `REGISTRY_PERF_METRIC zstd_delta_bytes=...`;
- `REGISTRY_PERF_METRIC zstd_ns=...`;
- `REGISTRY_PERF_METRIC reconstruct_ns=...`;
- reconstructed consumer repo contains the target commit.

Primary files:

- [`../../registry/packs-and-deltas.md`](../../registry/packs-and-deltas.md)
- [`../../../tests/vm/apm/registry_validation.nix`](../../../tests/vm/apm/registry_validation.nix)
- [`../../../crates/aos-package/src/registry/pack.rs`](../../../crates/aos-package/src/registry/pack.rs)
- [`../../../crates/aos-package/src/registry/fetch.rs`](../../../crates/aos-package/src/registry/fetch.rs)
- [`../../../crates/aos-package/tests/registry_perf.rs`](../../../crates/aos-package/tests/registry_perf.rs)

Passing builder evidence: output
`/nix/store/c6lg01w5ks8f2h4ginav0wfdhlf12az9-aos-vm-test-apm-registry-validation-pack-delta-perf-0`.
Its `serial.log` records:

```text
REGISTRY_PERF_METRIC full_pack_bytes=11276
REGISTRY_PERF_METRIC full_pack_ns=86438382
REGISTRY_PERF_METRIC thin_delta_bytes=11295
REGISTRY_PERF_METRIC thin_delta_ns=49235341
REGISTRY_PERF_METRIC zstd_delta_bytes=7191
REGISTRY_PERF_METRIC zstd_ns=1748206
REGISTRY_PERF_METRIC reconstruct_ns=2568679
```

## 5. Max-Staleness Boundary

`max_staleness_seconds` default tuning is not a VM-testable implementation
property because it depends on production update cadence, quiet-channel duration,
and CDN incident behavior. Repository behavior is covered by Rust unit/e2e tests
in [`../../../crates/aos-package/src/registry/git.rs`](../../../crates/aos-package/src/registry/git.rs)
and
[`../../../crates/aos-package/tests/registry_e2e.rs`](../../../crates/aos-package/tests/registry_e2e.rs);
the VM CDN-layout check covers the mutable-path TTL side. Fleet default tuning
belongs in deployment rollout notes.
