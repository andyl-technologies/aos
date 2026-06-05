# Registry External Validation Runbook

> **Status:** Handoff runbook for the remaining external validation gates in
> [`TODO.md`](./TODO.md). This file does not replace the reference docs in
> [`../../registry`](../../registry); it collects the commands and evidence needed
> before the remaining unchecked TODOs can be marked complete.

## 1. Stock Nix `require-sigs`

Run only on a controlled/containerized Nix host. The test creates a tiny
fixed-output store path and the stock-Nix probe uses `nix path-info --store` with
`require-sigs = true`.

```sh
AOS_PACKAGE_TEST_REAL_NIX_CACHE=1 \
AOS_PACKAGE_TEST_STOCK_NIX_CACHE=1 \
  cargo test --manifest-path crates/Cargo.toml -p aos-package \
  static_nix_cache_e2e_generates_serves_and_downloads_real_store_path -- --nocapture
```

Evidence needed:

- command output showing the stock-Nix probe ran instead of skipped;
- generated narinfo includes `Sig:`;
- `nix path-info --store <cache-url> <store-path>` succeeds with signatures
  required.

Primary files:

- [`../../registry/nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
- [`../../../crates/aos-package/tests/registry_cache_e2e.rs`](../../../crates/aos-package/tests/registry_cache_e2e.rs)
- [`../../../crates/aos-package/src/registry/nixcache.rs`](../../../crates/aos-package/src/registry/nixcache.rs)

## 2. Service-Backed Upload Matrix

First run the backend-level S3/SFTP round trips:

```sh
AOS_CACHE_TEST_S3_URL=s3://bucket/prefix \
  cargo test --manifest-path crates/Cargo.toml -p aos-cache \
  s3_backend_round_trips_against_env_url -- --ignored --nocapture

AOS_CACHE_TEST_SFTP_URL=sftp://user@host/path \
  cargo test --manifest-path crates/Cargo.toml -p aos-cache \
  sftp_backend_round_trips_against_env_url -- --ignored --nocapture
```

Then run the generated static-cache matrix against a mixed destination array. The
test automatically prepends a local `file://` destination, so the env var should
list the service-backed destinations:

```sh
AOS_PACKAGE_TEST_REAL_NIX_CACHE=1 \
AOS_PACKAGE_TEST_GENERATED_CACHE_UPLOAD_URLS='s3://bucket/prefix sftp://user@host/path' \
  cargo test --manifest-path crates/Cargo.toml -p aos-package \
  static_nix_cache_e2e_generates_serves_and_downloads_real_store_path -- --nocapture
```

Evidence needed:

- backend-level S3 and SFTP write/read round trips pass;
- generated cache upload writes `nix-cache-info`, `<storehash>.narinfo`, and
  `nar/*` to S3, local file, and SFTP destinations;
- readback uses the `aos-cache` backend trait for each destination;
- partial destination failures are reported only after all destinations are
  attempted.

Primary files:

- [`../../../crates/aos-cache/tests/backend_matrix.rs`](../../../crates/aos-cache/tests/backend_matrix.rs)
- [`../../../crates/aos-package/tests/registry_cache_e2e.rs`](../../../crates/aos-package/tests/registry_cache_e2e.rs)
- [`../../../crates/aos-cache/src/backend/s3.rs`](../../../crates/aos-cache/src/backend/s3.rs)
- [`../../../crates/aos-cache/src/backend/sftp.rs`](../../../crates/aos-cache/src/backend/sftp.rs)

## 3. Stock Git Matrix

Use pinned/containerized Git binaries for the documented floor and newer
supported clients. The matrix test is ignored because it temporarily changes
`PATH`; run it single-threaded.

```sh
AOS_PACKAGE_TEST_GIT_MATRIX=/path/to/git-2.42/bin/git:/path/to/git-current/bin/git \
  cargo test --manifest-path crates/Cargo.toml -p aos-package \
  stock_git_configured_version_matrix_syncs_sha256_dumb_http_registry -- \
  --ignored --nocapture --test-threads=1
```

Evidence needed:

- each listed binary reports `git version >= 2.42.0`;
- each binary syncs the sha256 dumb-HTTP fixture through
  `registry::git::sync_git`;
- failures force either a documented floor change or a compatibility fix.

Primary files:

- [`../../registry/http-layout.md`](../../registry/http-layout.md)
- [`../../../crates/aos-package/tests/registry_e2e.rs`](../../../crates/aos-package/tests/registry_e2e.rs)
- [`../../../crates/aos-package/src/registry/git.rs`](../../../crates/aos-package/src/registry/git.rs)

## 4. Pack/Delta Performance

Run on representative producer hardware and on the smallest supported consumer
host. Increase package count until it resembles the production registry size.

```sh
AOS_PACKAGE_TEST_REGISTRY_PERF=1 \
AOS_PACKAGE_TEST_REGISTRY_PERF_PACKAGES=500 \
  cargo test --manifest-path crates/Cargo.toml -p aos-package \
  registry_pack_delta_perf_harness_reports_metrics -- --ignored --nocapture
```

Evidence needed:

- full-pack generation time and bytes;
- thin-delta generation time and bytes;
- zstd compression time and bytes;
- full-pack and compressed-delta reconstruction times;
- decision on `pack-objects` window/depth/compression, zstd level/window, and
  whether dictionary training is worth shipping.

Primary files:

- [`../../registry/packs-and-deltas.md`](../../registry/packs-and-deltas.md)
- [`../../../crates/aos-package/tests/registry_perf.rs`](../../../crates/aos-package/tests/registry_perf.rs)
- [`../../../crates/aos-package/src/registry/pack.rs`](../../../crates/aos-package/src/registry/pack.rs)
- [`../../../crates/aos-package/src/registry/fetch.rs`](../../../crates/aos-package/src/registry/fetch.rs)

## 5. CDN / Mirror Validation

Run against the actual CDN/mirror stack used for production origins.

Evidence needed:

- immutable files (`objects/<xx>/<62>`, `releases/**`, `nar/**`,
  `*.narinfo`) receive long immutable caching;
- mutable files (`HEAD`, `info/refs`, `objects/info/**`, `channels/**`,
  `nix-cache-info`) receive low TTL / must-revalidate behavior;
- `objects/info/alternates` remains byte-identical after mirroring and contains
  only relative paths;
- a frontier/pointer update is not visible before its referenced immutable
  objects are readable from the edge;
- mirror freshness diagnostics are understandable when a channel pointer is
  stale or frozen.

Primary files:

- [`../../registry/http-layout.md`](../../registry/http-layout.md)
- [`../../registry/publishing.md`](../../registry/publishing.md)
- [`../../../crates/aos-package/src/registry/static_upload.rs`](../../../crates/aos-package/src/registry/static_upload.rs)
- [`../../../crates/aos-package/src/registry/fetch.rs`](../../../crates/aos-package/src/registry/fetch.rs)

## 6. Max-Staleness Tuning

Use real fleet update cadence and CDN behavior before changing the default.

Evidence needed:

- distribution of successful channel refresh intervals across production hosts;
- expected quiet-channel durations;
- CDN/mirror stale-edge behavior and incident recovery expectations;
- chosen `max_staleness_seconds` default plus operator override guidance.

Primary files:

- [`../../registry/versioning-and-channels.md`](../../registry/versioning-and-channels.md)
- [`../../registry/signing-and-trust.md`](../../registry/signing-and-trust.md)
- [`open-questions.md`](./open-questions.md)
- [`../../../crates/aos-package/src/registry/git.rs`](../../../crates/aos-package/src/registry/git.rs)

## 7. Final Operator Docs Gate

After the external gates above pass, update the operator-facing docs with the
validated commands, required environment/auth setup, supported versions, and
production defaults.

Primary files:

- [`../../registry/publishing.md`](../../registry/publishing.md)
- [`../../registry/nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md)
- [`../../registry/signing-and-trust.md`](../../registry/signing-and-trust.md)
- [`../../registry/repo-layout.md`](../../registry/repo-layout.md)
- [`../../registry/README.md`](../../registry/README.md)
