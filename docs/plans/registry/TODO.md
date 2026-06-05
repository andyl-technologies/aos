# Registry Implementation TODO

This checklist tracks the implementation branch for the git-native registry
target described in `docs/registry/` and planned in `docs/plans/registry/`.
Keep this file current as work lands.

## Branch Setup

- [x] Fetch latest `origin/master`.
- [x] Create implementation branch from `origin/master`.
- [x] Open PR.

## WS-01 Object Store

- [x] Add `registry::objectstore` module.
- [x] Implement bare sha256 repo initialization and object-format guard.
- [x] Implement semver release object-dir mapping.
- [x] Implement sha256 loose-object path validation and 2/62 split.
- [x] Implement relative root `objects/info/alternates` writer.
- [x] Implement `git update-server-info` wrapper.
- [x] Add focused object-store unit tests.
- [x] Wire producer create path to sha256 object-store helpers.
- [x] Wire publish path to object-store refresh/alternates helpers.
- [x] Add dumb-HTTP clone integration coverage.

## WS-02 Packs And Deltas

- [x] Add `registry::pack` module.
- [x] Implement release-kind and guaranteed delta-base scheme.
- [x] Implement full-pack and thin-delta `git pack-objects` wrappers.
- [x] Implement zstd compress/decompress wrappers.
- [x] Implement `git index-pack` and `--fix-thin` wrappers.
- [x] Add focused pack/delta unit tests.
- [x] Retire bundle producer/consumer path.

## WS-03 Channels And Rollouts

- [x] Add `registry::channel` module.
- [x] Add `channel` config field and `TrackingMode::Channel`.
- [x] Add semver floor, bucket, and retained release fields to registry state.
- [x] Remove legacy creation-token state when the bundle path is retired.
- [x] Implement bucket selection, bucket hex rendering, and probe-forward order.
- [x] Implement semver floor anti-rollback check.
- [x] Implement partition map/frontier helpers.
- [x] Add focused channel/state unit tests.
- [x] Add `apr channel init/advance/status` command surface.

## WS-04 Signing And Trust

- [x] Add `registry::keys` module for committed `keys.toml`.
- [x] Remove in-repo `registry.toml` signing public-key field.
- [x] Add `git verify-tag` helper.
- [x] Add tag-object parser and name-binding checks.
- [x] Add tag-chain verification helper.
- [x] Rewrite producer tag/sign paths to create signed tag objects.
- [x] Add rotation/revocation helpers and tests.

## WS-05 Consumer Cutover

- [x] Resolve channel bucket to verified semver tag and commit.
- [x] Run floor check before object fetch.
- [x] Implement delta/full/loose object fetch resolution.
- [x] Persist retained release set and prune obsolete objects.
- [x] Resolve committed `registry.toml` `[[caches]]` from verified tree.
- [x] Remove `bundle-list.toml` selection from `apm update`.

## WS-06 Nix Cache Generation

- [x] Extract narinfo format/sign/cache-info helpers for producer reuse.
- [x] Add AOT static cache generator for narinfo, NAR, and `nix-cache-info`.
- [x] Add publish-time completeness check for registry-listed store paths.
- [x] Add upload integration for static cache files.
- [x] Add stock-Nix/static-cache smoke coverage.

## Docs Cleanup

- [x] Clear completed current-state sections from `docs/registry/*` as old behavior
      is removed from code.
- [x] Keep `docs/registry/current-state.md` only for remaining as-is behavior and
      historical reference.

## Production Readiness Backlog

These items are still open after the git-native registry implementation work.
Keep them unchecked until the referenced target docs are implemented and backed
by Rust integration/e2e tests where the item calls for tests.
Each open item includes the full context files an implementation agent should
read before editing code or docs.

### Current Rust Test Surface

- [x] Inventory the registry-adjacent Rust test surface before assigning the
      remaining e2e work. Current coverage is mostly focused unit/module tests
      embedded in source files; there is no `crates/aos-package/tests/` or
      `crates/aos-cache/tests/` integration harness yet. Treat every
      `crates/aos-package/tests/*.rs` and `crates/aos-cache/tests/*.rs` file
      named below as a new file to create. Existing context:
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/keys.rs`,
      `crates/aos-package/src/registry/verify.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-package/src/registry/parse.rs`,
      `crates/aos-package/src/registry/state.rs`,
      `crates/aos-package/src/registry/mod.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-package/src/config.rs`,
      `crates/aos-package/src/types.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-core/src/nar/info.rs`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/resolve.rs`, and the only existing crate-level tests
      directory currently found, `crates/aos-systemd/tests/`.
- [ ] Create shared integration-test fixture utilities for git-native registry
      tests: temporary sha256 bare origins, signed tag/key material, static HTTP
      serving, cache directory construction, command invocation helpers, and
      assertions for persisted `registries.d` state. Keep the helpers in a new
      test support module and use them across the e2e items below. Context:
      `docs/registry/current-state.md`, `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/publishing.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/verify.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and new files such as
      `crates/aos-package/tests/common/mod.rs`,
      `crates/aos-package/tests/registry_e2e.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.

### Cross-Cutting Rust Integration / E2E Tests

- [ ] Add a full producer-to-consumer HTTP e2e test for the git-native registry:
      create a sha256 registry, publish multiple releases, sign tags, advance a
      channel partition, serve the static tree over HTTP, and run the consumer
      sync path through bucket selection, tag-chain verification, object fetch,
      package extraction, and persisted state updates. Context:
      `docs/registry/architecture.md`, `docs/registry/current-state.md`,
      `docs/registry/http-layout.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/signing-and-trust.md`, `docs/registry/publishing.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/verify.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and a new integration file
      such as `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add committed-tree layout integration coverage: verify the signed
      tag->commit->tree path authenticates and extracts the root `registry.toml`,
      committed `keys.toml`, `packages/<letter>/<name>.toml`, `closures/<hash>`,
      and `.gitattributes`; verify client-side `registries.d` cache overrides
      and committed `registry.toml` `[[caches]]` priority ordering are applied
      after sync. Context: `docs/registry/repo-layout.md`,
      `docs/registry/current-state.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/signing-and-trust.md`,
      `crates/aos-package/src/registry/parse.rs`,
      `crates/aos-package/src/registry/closures.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/verify.rs`,
      `crates/aos-package/src/config.rs`,
      `crates/aos-package/src/types.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-package/src/registry_ops.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add channel rollout e2e coverage for all trust and safety gates: signed
      partition tag -> signed semver tag -> commit, embedded tag-name
      name-binding failures, probe-forward order, retained-release persistence,
      semver precedence including prerelease/build metadata, anti-rollback floor
      rejection, fix-forward behavior, and stale/missing partition surfaces.
      Context:
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/types.rs`,
      `crates/aos-package/src/config.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/verify.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add executable pack/delta e2e coverage for full packs, thin deltas,
      zstd-compressed pack artifacts, `git index-pack --fix-thin`, fallback from
      missing/corrupt delta to full pack, fallback from missing/corrupt full pack
      to loose-object git fetch, and pruning behavior after retained releases
      change. Context: `docs/registry/packs-and-deltas.md`,
      `docs/registry/http-layout.md`, `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add a static Nix-cache e2e test that uses real Nix-store fixtures when
      available: run `apr cache generate`, serve `nix-cache-info`,
      `<storehash>.narinfo`, and `nar/*.nar.zst` over static HTTP, download
      through the `apm` narinfo path, and verify with stock `nix` substituter
      behavior under `require-sigs` where the host has Nix installed. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/current-state.md`, `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-core/src/nar/info.rs`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-cache/src/backend/mod.rs`, and a new integration file such as
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [ ] Add one-key projection coverage for git tag signatures and Nix narinfo
      signatures: prove the same Ed25519 key material can produce the
      `registry:Ed25519:<base64>` AOS trust form and the `<name>:<base64>` Nix
      `trusted-public-keys` form, and that generated narinfo `Sig:` lines verify
      under stock-Nix-compatible rules. Context:
      `docs/registry/signing-and-trust.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/repo-layout.md`,
      `crates/aos-package/src/security.rs`,
      `crates/aos-package/src/registry/keys.rs`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [x] Add cache URL-key compatibility coverage for generated narinfo `URL:`
      fields and uploaded object paths. Prove the colon-free
      `nar/{store_hash}-sha256-{hex}` path generated by `nar_url` is exactly the
      path `apr cache generate` writes, uploads, serves, and `apm` downloads.
      The coverage now verifies `upload_static_cache` preserves the generated
      narinfo `URL:` object path through a filesystem upload and `download_nars`
      follows the narinfo-supplied colon-free path through a static `file://`
      cache. If a future colon-retained option is reintroduced, gate it behind
      explicit config and cover both forms. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [ ] Add backend matrix integration tests for cache generation/upload and cache
      reads: local filesystem `file://`, mocked/static HTTP, S3-compatible
      storage, and SFTP. Prove repeatable `--upload-url` destination arrays can
      include mixed `(s3, local filesystem path, SFTP)` targets, that partial
      failures are reported after all destinations are attempted, and that each
      backend can read the generated `nix-cache-info`, `.narinfo`, and `nar/`
      objects it writes. Use hermetic fakes where possible and gate container or
      external-service variants behind ignored tests or feature flags. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/publishing.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and a new integration file
      such as `crates/aos-cache/tests/backend_matrix.rs`.
- [ ] Add stock git compatibility tests for the pinned minimum git version and
      sha256 dumb-HTTP behavior. The current local-git smoke test is not enough
      to prove production compatibility across supported client versions.
      Context: `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/security.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/git.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.

### Producer / Publishing Target State

- [ ] Implement the single production publish orchestrator, tentatively
      `apr release` or `apr publish --release`, that performs the ordered
      pipeline end to end: commit metadata, create/sign release tag, generate
      full packs and thin deltas, compress artifacts, refresh dumb-HTTP indexes,
      generate the static Nix cache, upload immutable artifacts first, advance
      channel partitions, and publish low-TTL mutable surfaces last. Include
      dry-run, resume/idempotency, clear error reporting, and a publisher
      concurrency guard. Context: `docs/registry/architecture.md`,
      `docs/registry/publishing.md`, `docs/registry/http-layout.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/channel.rs`, and
      `crates/aos-package/src/registry/nixcache.rs`.
- [ ] Add upload support for the full git-native static origin, not only the
      generated static Nix cache files. The publish path must upload `HEAD`,
      `info/refs`, `objects/**`, `objects/info/**`, `channels/**`,
      `releases/**`, and any cache files in the required immutable-first /
      mutable-last order, with per-path cache-control/TTL metadata where the
      selected backend can express it. Context: `docs/registry/http-layout.md`,
      `docs/registry/publishing.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-cache/src/backend/mod.rs`.
- [x] Replace the single optional cache `--upload-url` with repeatable or
      array-style upload destinations, and define partial-failure semantics for
      a destination set such as `(s3, local filesystem path, SFTP)`. The CLI now
      accepts repeatable `--upload-url` values and the upload helper reports
      partial destination failures after attempting all destinations. The backend
      factory still supports one URL per backend instance for `file://`,
      `http(s)://`, `s3://`, and `sftp://`/`ssh://`.
      Context: `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`, and
      `crates/aos-cache/src/backend/sftp.rs`.
- [ ] Expose production auth/config flags for upload backends in the registry
      command surface: S3 region/profile/endpoint, SFTP key/password/agent
      behavior, HTTP token/basic/header credentials, and config-file/env
      precedence. Context: `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`, and
      `crates/aos-cache/src/backend/mod.rs`.
- [ ] Add tests for torn-publish and concurrent-publisher failure modes:
      intentionally expose low-TTL refs or channel partitions before immutable
      objects, interleave two partition advances, and prove consumers either
      keep the old floor or fail closed with actionable errors. Context:
      `docs/registry/publishing.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.

### Consumer Production Hardening

- [x] Pin and enforce the minimum supported git version for sha256 dumb-HTTP
      registries. Add a runtime capability check that produces a clear
      "requires sha256 git" error before a low-level fetch or object panic. The
      AOS consumer floor is Git 2.42.0, enforced with `git --version` parsing and
      a local `git init --bare --object-format=sha256` capability probe.
      Context: `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Revisit bucket selection so rollout assignment uses a registry-local salt,
      survives cloned images and missing `/etc/machine-id`, and does not flap
      after the first sync. Add migration tests for existing persisted buckets.
      First assignment now hashes `registry_name || "\0" || generated_salt`,
      persists only the resulting bucket index, and leaves existing persisted
      buckets untouched. Probe-forward still uses `(bucket+i) mod 256` without
      re-pinning. Tests cover registry+salt selection, salt shape, persisted
      bucket migration, and probe order.
      Context: `docs/registry/versioning-and-channels.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/channel.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Implement and test consumer max-staleness/freshness policy for frozen but
      validly signed mirrors. Cover first-sync, offline, quiet-channel, stale
      mutable-surface, frozen-but-reachable mirror behavior, and anti-rollback
      interactions. Do not close this until the target is either implemented or
      explicitly documented as an accepted limitation when a mirror keeps serving
      an old but still validly signed pointer. Partial implementation landed:
      channel refresh failures are evaluated
      against `[registry.state].last_update`, with a 14-day default and a
      per-registry `max_staleness_seconds` override. Unit tests cover first-sync
      failure, fresh failed refresh, stale failed refresh, timestamp parsing, and
      clock-skew/future timestamp tolerance. Remaining work is broader policy
      validation for successful refreshes that return stale-but-valid data, e2e
      validation for offline/quiet-channel/stale-mutable-surface/anti-rollback
      interactions, and production default tuning. Context:
      `docs/registry/signing-and-trust.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/apt-comparison.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/verify.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add an explicit trust-management CLI for registry keys, including pin,
      re-pin, rotation, revocation, and compromised-key workflows. The lower
      level keystore and committed `keys.toml` helpers exist, but operators need
      a supported command surface and e2e tests. Context:
      `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/security.rs`,
      `crates/aos-package/src/registry/keys.rs`, and
      `crates/aos-package/src/registry/verify.rs`.
- [x] Emit the initial committed `keys.toml` trust roster from `apr create`.
      `apr create` now writes a schema-1 roster, optionally with an active
      `--trust-key registry:Ed25519:<base64>` and optional `--trust-key-id`
      (default `initial`), before the initial commit. Context:
      `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/architecture.md`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry/keys.rs`, and
      `crates/aos-package/src/security.rs`.
- [ ] Maintain the committed `keys.toml` trust roster through producer key
      rotation and revocation operations. The parser/writer helpers and
      create-time emission exist, but operators still need supported rotation
      and revocation command workflows. Context: `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/architecture.md`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry/keys.rs`, and
      `crates/aos-package/src/security.rs`.
- [ ] Add migration/capability tests for clean-break behavior: old bundle-mode
      clients against a git-native origin, new git-native clients against an old
      origin, first git-native sync floor seeding, and clear user-facing errors
      during any temporary dual-detect window. Also ratify the EOL/model-detect
      policy in docs before marking this complete. Context:
      `docs/registry/current-state.md`,
      `docs/registry/http-layout.md`,
      `docs/plans/registry/open-questions.md`,
      `docs/plans/registry/gap-analysis.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.

### Performance / Compatibility Validation

- [ ] Benchmark and tune producer pack settings and consumer reconstruct cost:
      `git pack-objects --window`, `--depth`, `--compression=0`, zstd level,
      zstd `--long` window, optional dictionary training, and memory limits on
      the smallest supported host. Context:
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and a new benchmark or
      integration harness such as `crates/aos-package/tests/registry_perf.rs`.
- [ ] Validate CDN and mirror behavior against the target HTTP layout: byte
      stable relative `objects/info/alternates`, cache-control policy for
      immutable and mutable surfaces, missing-object recovery, and mirror
      freshness diagnostics. Context: `docs/registry/http-layout.md`,
      `docs/registry/publishing.md`,
      `docs/registry/signing-and-trust.md`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.

### Documentation Re-Grounding

- [ ] Reconcile `docs/registry/README.md` and `docs/registry/current-state.md`
      with the production-readiness status after the backlog above lands. In
      particular, keep the as-built/current-state language separate from target
      language and remove "remaining producer gaps" claims once the unified
      release/upload pipeline is implemented. Context:
      `docs/registry/README.md`, `docs/registry/current-state.md`,
      `docs/registry/publishing.md`, and `docs/registry/nix-cache-compatibility.md`.
- [ ] Resolve remaining registry-reference doc inconsistencies as implementation
      lands, especially stale statements about Nix narinfo `Sig:` wiring,
      static-cache producer status, max-staleness behavior, and backend support
      levels. Context: `docs/registry/signing-and-trust.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/current-state.md`,
      `docs/registry/publishing.md`,
      `docs/registry/apt-comparison.md`, and `docs/plans/registry/TODO.md`.
- [ ] Re-ground stale plan/open-question text that still describes old
      producer/cache gaps or pre-cutover implementation details. Context:
      `docs/plans/registry/open-questions.md`,
      `docs/plans/registry/design-brief.md`,
      `docs/plans/registry/gap-analysis.md`,
      `docs/plans/registry/workstream-01-object-store.md`,
      `docs/plans/registry/workstream-02-pack-delta-pipeline.md`,
      `docs/plans/registry/workstream-03-channels-rollouts.md`,
      `docs/plans/registry/workstream-04-signing-trust.md`,
      `docs/plans/registry/workstream-05-consumer.md`, and
      `docs/plans/registry/workstream-06-nix-cache.md`.
- [x] Close or re-ground `docs/plans/registry/open-questions.md` Q8 against the
      implemented colon-free static NAR `URL:` key. `docs/registry/`
      currently says `nar_url` writes `nar/{store_hash}-sha256-{hex}` and
      `aos-core` tests cover that form; Q8 now records the colon-free key as
      resolved and cites the producer/upload/consumer coverage. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-package/src/download.rs`.
- [ ] Update operator docs once backend arrays, auth flags, `apr release`, trust
      management, and stock-Nix verification are implemented and tested.
      Context: `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/repo-layout.md`, and
      `docs/registry/README.md`.
