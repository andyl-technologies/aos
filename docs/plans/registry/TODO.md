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
- [ ] Add channel rollout e2e coverage for all trust and safety gates: signed
      partition tag -> signed semver tag -> commit, embedded tag-name
      name-binding failures, probe-forward order, retained-release persistence,
      anti-rollback floor rejection, fix-forward behavior, and stale/missing
      partition surfaces. Context:
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
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
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-cache/src/backend/mod.rs`, and a new integration file such as
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [ ] Add backend matrix integration tests for cache generation/upload and cache
      reads: local filesystem `file://`, mocked/static HTTP, S3-compatible
      storage, and SFTP. Use hermetic fakes where possible and gate container or
      external-service variants behind ignored tests or feature flags. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/publishing.md`,
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
      `crates/aos-package/src/registry/objectstore.rs`,
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
      mutable-last order. Context: `docs/registry/http-layout.md`,
      `docs/registry/publishing.md`,
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

- [ ] Pin and enforce the minimum supported git version for sha256 dumb-HTTP
      registries. Add a runtime capability check that produces a clear
      "requires sha256 git" error before a low-level fetch or object panic.
      Context: `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Revisit bucket selection so rollout assignment uses a registry-local salt,
      survives cloned images and missing `/etc/machine-id`, and does not flap
      after the first sync. Add migration tests for existing persisted buckets.
      Context: `docs/registry/versioning-and-channels.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/channel.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Implement and test consumer max-staleness/freshness policy for frozen but
      validly signed mirrors. Cover first-sync, offline, quiet-channel, stale
      mutable-surface, and anti-rollback interactions. Context:
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
- [ ] Emit and maintain the committed `keys.toml` trust roster from producer
      commands, starting with `apr create` and continuing through key rotation
      and revocation operations. The parser/writer helpers exist, but
      `docs/registry/repo-layout.md` still calls out that `keys.toml` is not
      emitted by create yet. Context: `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/architecture.md`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry/keys.rs`, and
      `crates/aos-package/src/security.rs`.
- [ ] Add migration/capability tests for clean-break behavior: old bundle-mode
      clients against a git-native origin, new git-native clients against an old
      origin, and clear user-facing errors during any temporary dual-detect
      window. Context: `docs/registry/current-state.md`,
      `docs/registry/http-layout.md`,
      `docs/plans/registry/open-questions.md`,
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
- [ ] Update operator docs once backend arrays, auth flags, `apr release`, trust
      management, and stock-Nix verification are implemented and tested.
      Context: `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/repo-layout.md`, and
      `docs/registry/README.md`.
