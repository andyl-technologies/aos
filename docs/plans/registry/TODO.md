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
      embedded in source files. `crates/aos-cache/tests/backend_matrix.rs` now
      starts the cache backend matrix; `crates/aos-package/tests/common/mod.rs`
      and `crates/aos-package/tests/registry_e2e.rs` now start the
      git-native registry integration harness. Existing context:
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
      `crates/aos-cache/tests/backend_matrix.rs`,
      `crates/aos-cache/src/resolve.rs`, and the only existing crate-level tests
      directory currently found, `crates/aos-systemd/tests/`.
- [x] Create shared integration-test fixture utilities for git-native registry
      tests: temporary sha256 source repos and bare origins, signed tag/key
      material, static HTTP serving, cache directory construction, git command
      invocation helpers, and assertions for persisted `registries.d` state.
      The first smoke test proves the fixture can sign a release tag, publish a
      sha256 dumb-HTTP origin, sync it through `registry::git::sync_git`,
      extract packages/root `registry.toml`, load the package registry, and
      round-trip persisted state. Context:
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
      `crates/aos-package/tests/registry_e2e.rs`, and future
      `crates/aos-package/tests/registry_cache_e2e.rs`.

### Cross-Cutting Rust Integration / E2E Tests

- [x] Add a full producer-to-consumer HTTP e2e test for the git-native registry:
      create a sha256 registry, publish multiple releases, sign tags, advance a
      channel partition, serve the static tree over HTTP, and run the consumer
      sync path through bucket selection, tag-chain verification, object fetch,
      package extraction, and persisted state updates. The coverage now lives in
      `crates/aos-package/tests/registry_e2e.rs`:
      `signed_channel_http_e2e_advances_persisted_bucket` publishes 1.0.0 and
      1.1.0, serves a dumb-HTTP origin plus mutable `channels/stable/<bucket>`
      files, verifies signed channel-tag -> signed semver-tag -> commit
      resolution, persists bucket/floor/retained state, and confirms the loaded
      package metadata advances to 1.1.0. Context:
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
- [x] Add committed-tree layout integration coverage: verify the signed
      tag->commit->tree path authenticates and extracts the root `registry.toml`,
      committed `keys.toml`, `packages/<letter>/<name>.toml`, `closures/<hash>`,
      and `.gitattributes`; verify client-side `registries.d` cache overrides
      and committed `registry.toml` `[[caches]]` priority ordering are applied
      after sync. The consumer now materializes `closures/` into the registry
      metadata cache and root `registry.toml`, `keys.toml`, and `.gitattributes`
      into the local registry tree, removing stale root-file copies when
      upstream deletes them. `RegistryConfig` now carries client-side `caches`
      from `registries.d`, and `resolve_mirrors_for_registry` merges those with
      committed caches before sorting by priority. The signed-channel HTTP e2e
      asserts closure loading, keys-roster parsing, root-file extraction, and
      merged cache order. Context: `docs/registry/repo-layout.md`,
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
- [x] Add channel rollout e2e coverage for all trust and safety gates: signed
      partition tag -> signed semver tag -> commit, embedded tag-name
      name-binding failures, probe-forward order, retained-release persistence,
      semver precedence including prerelease/build metadata, anti-rollback floor
      rejection, fix-forward behavior, and stale/missing partition surfaces. The
      coverage now lives in `crates/aos-package/tests/registry_e2e.rs`:
      `signed_channel_http_e2e_advances_persisted_bucket` covers the successful
      signed chain, bucket/floor/retained persistence, and package extraction;
      `channel_rollout_e2e_enforces_safety_gates_and_fix_forward` covers
      embedded-name rejection, probe-forward recovery, anti-rollback refusal,
      fix-forward, and a prerelease/build semver target; and
      `channel_first_sync_fails_closed_when_no_partition_is_usable` covers
      missing first-sync partition diagnostics. Context:
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
- [x] Add executable pack/delta e2e coverage for full packs, thin deltas,
      zstd-compressed pack artifacts, `git index-pack --fix-thin`, fallback from
      missing/corrupt delta to full pack, fallback from missing/corrupt full pack
      to loose-object git fetch, and pruning behavior after retained releases
      change. The coverage now lives in
      `crates/aos-package/tests/registry_e2e.rs`:
      `pack_delta_e2e_fetches_full_pack_and_compressed_thin_delta` builds a real
      full pack, publishes a zstd-compressed thin delta, resolves both over
      static HTTP, and verifies the target commit exists after
      `index-pack --fix-thin`; `pack_delta_e2e_falls_back_from_corrupt_artifacts`
      proves corrupt deltas fall through to the full-pack anchor plus git-fetch
      loose fallback, and corrupt full packs fall directly to git-fetch fallback;
      `signed_channel_http_e2e_advances_persisted_bucket` asserts retained
      release pruning keeps retained release dirs and removes stale ones. The
      implementation now streams thin packs through `git index-pack --fix-thin
      --stdin` and verifies copied full-pack indexes before accepting them.
      Context: `docs/registry/packs-and-deltas.md`,
      `docs/registry/http-layout.md`, `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Add a static Nix-cache e2e test that uses real Nix-store fixtures:
      generate static cache files, serve `nix-cache-info`,
      `<storehash>.narinfo`, and `nar/*.nar.zst` over static HTTP, download
      through the `apm` narinfo path, and compare the downloaded/decompressed
      NAR bytes with `nix-store --dump`. This coverage now lives in
      `crates/aos-package/tests/registry_cache_e2e.rs`:
      `static_nix_cache_e2e_generates_serves_and_downloads_real_store_path`.
      Because the fixture uses `nix-store --add-fixed` and mutates the host Nix
      store, normal Rust test runs skip it unless
      `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` is set. When enabled, it calls
      `nixcache::generate_static_cache`, validates signed narinfo output, serves
      the generated static tree through `StaticHttpServer`, and verifies the AOS
      narinfo download path reconstructs the exact NAR bytes. Stock
      `nix path-info --store <cache>` verification is present as an additional
      opt-in behind `AOS_PACKAGE_TEST_STOCK_NIX_CACHE=1` and bounded with an
      exact-child timeout because the local host probe hung during development.
      Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/current-state.md`, `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-core/src/nar/info.rs`,
      `crates/aos-core/src/nar/cache.rs`,
      `crates/aos-package/src/download.rs`,
      `crates/aos-cache/src/backend/mod.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [x] Add CLI-level static-cache compatibility coverage that actually drives
      `apr cache generate` end to end. `crates/aos/tests/apr_cache_cli.rs`
      creates a temporary user APM config/registry, runs the real Cargo-built
      `apr` binary against a real Nix-store fixture when
      `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` is set, verifies generated
      `nix-cache-info` priority, and verifies the `file://`
      `--upload-url` destination receives matching cache-info, narinfo, and NAR
      files. Context: `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/publishing.md`,
      `docs/plans/registry/workstream-06-nix-cache.md`,
      `crates/aos/Cargo.toml`,
      `crates/aos/src/main.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos/tests/apr_cache_cli.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [ ] Run and stabilize stock Nix substituter verification under `require-sigs`
      in a controlled/containerized Nix environment. The opt-in code path exists
      in `crates/aos-package/tests/registry_cache_e2e.rs` behind
      `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` plus
      `AOS_PACKAGE_TEST_STOCK_NIX_CACHE=1` with an exact-child timeout, but it is
      not default CI evidence because the local host probe hung during
      development and should run only in controlled Nix hosts. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/workstream-06-nix-cache.md`,
      `crates/aos-package/tests/registry_cache_e2e.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-package/src/download.rs`.
- [x] Add one-key projection coverage for git tag signatures and Nix narinfo
      signatures: prove the same Ed25519 key material can produce the
      `registry:Ed25519:<base64>` AOS trust form and the `<name>:<base64>` Nix
      `trusted-public-keys` form, and that generated narinfo `Sig:` lines verify
      under stock-Nix-compatible rules. The coverage now signs a real git tag
      with an OpenSSH Ed25519 private key generated from the same seed used by
      `NarInfoSigner`, verifies the tag through the AOS `allowed_signers` path,
      and verifies the narinfo `Sig:` with the raw Nix public-key projection.
      Context:
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
- [x] Add the first `aos-cache` backend integration harness. The new
      `crates/aos-cache/tests/backend_matrix.rs` covers a hermetic local
      filesystem write/read round trip and a static HTTP read round trip for
      `nix-cache-info`, `<storehash>.narinfo`, and `nar/` objects, including
      exact `nix-cache-info` body upload with a non-default priority for
      writable backends. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`, and
      `crates/aos-cache/tests/backend_matrix.rs`.
- [x] Add ignored, env-gated backend matrix hooks for external S3-compatible and
      SFTP write/read validation. They are not production evidence until run
      against real or containerized services, but they define the same round-trip
      contract as the hermetic filesystem test. Context:
      `crates/aos-cache/tests/backend_matrix.rs`,
      `crates/aos-cache/src/backend/s3.rs`, and
      `crates/aos-cache/src/backend/sftp.rs`.
- [x] Preserve generated `nix-cache-info` metadata during static-cache uploads
      and cover generated cache upload/readback through a repeatable filesystem
      destination array. `upload_static_cache` now uploads the exact generated
      `nix-cache-info` body instead of asking each backend to synthesize a
      default-priority stub. `crates/aos-package/tests/registry_cache_e2e.rs`
      uploads the generated real-store fixture cache to two `file://`
      destinations through `upload_static_cache_to_all`, reads the uploaded
      narinfo/NAR back through the `aos-cache` backend trait, and verifies the
      uploaded `nix-cache-info` body matches the generated output. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/publishing.md`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-cache/tests/backend_matrix.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [ ] Complete service-backed backend matrix integration tests for generated
      static-cache upload/readback across S3-compatible storage and SFTP, then
      prove one repeatable `--upload-url` array can mix `(s3, local filesystem
      path, SFTP)` targets and still report partial failures only after all
      destinations are attempted. Local `file://` generated upload/readback and
      static HTTP readback are covered; promote the ignored S3/SFTP hooks to
      container-backed or CI-run coverage before checking this off. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/publishing.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-cache/tests/backend_matrix.rs`,
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [x] Add current-stock-git compatibility coverage for the pinned minimum git
      version and sha256 dumb-HTTP behavior. `crates/aos-package/tests/
      registry_e2e.rs` now includes
      `stock_git_current_version_syncs_sha256_dumb_http_registry`, which asserts
      the host `git --version` is at least 2.42.0, verifies the fixture origin is
      a sha256 repository, serves it over static HTTP, and runs the actual
      `registry::git::sync_git` consumer path. Context:
      `docs/registry/http-layout.md`, `docs/registry/signing-and-trust.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Add a supported-version stock Git compatibility matrix for the pinned
      minimum Git version and newer clients. The current-stock-git e2e proves
      this host's Git, but production compatibility across the documented floor
      and newer supported clients still needs containerized or pinned-binary
      coverage before this is fully proven. Context:
      `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/security.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/git.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.

### Producer / Publishing Target State

- [x] Implement the single production publish orchestrator as `apr release`.
      It supports committed-tree releases and optional `--store-path` releases
      that delegate to `apr publish`, commits `--cache-url` into
      `registry.toml` before signing, creates/reuses the signed semver tag,
      generates self-contained full packs at `X.Y.0` anchors and compressed
      guaranteed thin deltas, refreshes dumb-HTTP indexes, optionally generates
      static Nix-cache files via `--cache-output`, initializes/advances channel
      partitions, and uploads immutable payloads before low-TTL mutable
      refs/channels to repeatable `--upload-url` backends. It includes
      `--dry-run`, `--resume`, clear existing-artifact errors, and a local
      publisher lock in the git dir. Coverage includes
      `release_orchestrator_e2e_uploads_channel_origin_and_syncs_consumer` in
      `crates/aos-package/tests/registry_e2e.rs`, which releases a committed
      sha256 registry tree, uploads it to `file://`, serves that uploaded
      origin, and syncs a channel consumer from it. Real-Nix cache generation,
      stock-Nix substituter validation, service-backed S3/SFTP upload tests,
      and CDN/mirror behavior remain tracked by their separate TODOs. Context:
      `docs/registry/architecture.md`, `docs/registry/publishing.md`,
      `docs/registry/http-layout.md`, `docs/registry/packs-and-deltas.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/open-questions.md`, `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/channel.rs`, and
      `crates/aos-package/src/registry/nixcache.rs`.
- [x] Add upload support for the full git-native static origin, not only the
      generated static Nix cache files. `apr origin upload --upload-url ...`
      now refreshes the local static git view and uploads `HEAD`, `info/refs`,
      `objects/**`, `objects/info/**`, `channels/**`, `releases/**`, and
      optional generated static-cache files from `--cache-dir` in
      immutable-first / mutable-last order. Backend upload support now has a
      generic static-file method for `file://`, generic `http(s)://`, `s3://`,
      and `sftp://`/`ssh://`; S3 and HTTP receive per-path `Content-Type` and
      `Cache-Control` metadata. Coverage includes
      `registry::static_upload` unit tests for ordering and filesystem upload,
      plus `static_origin_upload_e2e_syncs_uploaded_filesystem_destination` in
      `crates/aos-package/tests/registry_e2e.rs`, which uploads a real
      sha256 dumb-HTTP origin to `file://`, serves that uploaded tree, and syncs
      a consumer from it. Service-backed S3/SFTP validation remains tracked by
      the separate backend-matrix TODO. Context:
      `docs/registry/http-layout.md`,
      `docs/registry/publishing.md`,
      `docs/registry/current-state.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/static_upload.rs`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-package/tests/registry_e2e.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`,
      `crates/aos-net/src/types.rs`, and
      `crates/aos-net/src/protocol/s3.rs`.
- [x] Replace the single optional cache `--upload-url` with repeatable or
      array-style upload destinations, and define partial-failure semantics for
      a destination set such as `(s3, local filesystem path, SFTP)`. The CLI now
      accepts repeatable `--upload-url` values and the upload helper reports
      partial destination failures after attempting all destinations. Regression
      coverage now proves both cache uploads and full static-origin uploads
      continue past a failed middle destination and write later filesystem
      destinations before returning the aggregate error. The backend factory
      still supports one URL per backend instance for `file://`, `http(s)://`,
      `s3://`, and `sftp://`/`ssh://`.
      Context: `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/static_upload.rs`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/http.rs`,
      `crates/aos-cache/src/backend/s3.rs`, and
      `crates/aos-cache/src/backend/sftp.rs`.
- [x] Expose production auth/env flags for upload backends in the registry
      command surface: S3 region/profile/endpoint, SFTP key/password/agent
      behavior, and HTTP token/basic/header credentials. `apr cache generate`
      now flattens backend upload auth flags into the `Generate` command,
      maps them into `aos_cache::AuthOptions`, and threads those options through
      `upload_static_cache_to_all`. Coverage includes
      `cache_upload_auth_args_map_to_backend_options` plus
      `crates/aos/tests/apr_cache_cli.rs`, which exercises the flags on the real
      `apr` binary while uploading to a safe `file://` destination. Context:
      `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos/tests/apr_cache_cli.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/nixcache.rs`, and
      `crates/aos-cache/src/backend/mod.rs`.
- [x] Add persistent config-file precedence for registry upload backend auth.
      `registries.d/<name>.toml` now accepts an optional
      `[registry.upload_auth]` table with the same auth shape as
      `apr cache generate` flags: token/view, HTTP basic/header, S3
      region/profile/endpoint, and SFTP key/password/ask-pass settings. The
      merge rule is config defaults first, then env/CLI values from Clap override
      those defaults, with final view fallback to `"default"`.
      Coverage includes config-file parsing, selected-registry lookup, and
      `CacheUploadAuthArgs::auth_options_with_config` precedence tests. Context:
      `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/current-state.md`,
      `crates/aos-package/src/types.rs`,
      `crates/aos-package/src/config.rs`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`, and
      `crates/aos-cache/src/backend/mod.rs`.
- [x] Add tests for torn-publish and concurrent-publisher failure modes:
      `crates/aos-package/tests/registry_e2e.rs` now includes
      `channel_torn_publish_keeps_old_floor_when_partition_leads_objects`,
      which exposes an updated channel partition before its immutable release
      tag/object graph is published and proves the consumer probes forward to
      the old usable release/floor, and
      `channel_interleaved_partition_advances_reject_stale_publisher_rollback`,
      which interleaves v2/v3 partition updates and proves a stale publisher's
      later v2 overwrite fails closed with a rollback/freshness diagnostic while
      preserving the v3 floor. Context:
      `docs/registry/publishing.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/current-state.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/tests/common/mod.rs`, and
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
- [x] Implement and test consumer max-staleness/freshness policy for frozen but
      validly signed mirrors. Channel refresh failures are evaluated against
      `[registry.state].last_update`, with a 14-day default and a per-registry
      `max_staleness_seconds` override. Successful channel refreshes now refresh
      `last_update` only on first sync or semver advancement; unchanged but
      valid signed channel targets are accepted only while the previous
      freshness timestamp is within the max-staleness window, and they do not
      refresh that clock. Unit tests cover first-sync failure, fresh failed
      refresh, stale failed refresh, timestamp parsing, first-sync/advance
      freshness recording, quiet unchanged channels within the window, and stale
      unchanged pointers. E2e coverage now includes first-sync failure with no
      usable partition, a reachable but stale unchanged signed partition that
      fails closed, and anti-rollback/fix-forward rollout behavior. Context:
      `docs/registry/signing-and-trust.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/apt-comparison.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/channel.rs`,
      `crates/aos-package/src/registry/verify.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [ ] Validate and tune the production `max_staleness_seconds` default for real
      fleets and CDN behavior. The implementation deliberately uses the local
      freshness clock because signed channel tags have no in-band expiry; this
      can reject genuinely quiet channels if operators choose too short a
      window, and a host with no recent freshness observation still cannot prove
      a reachable unchanged pointer is malicious. Context:
      `docs/plans/registry/open-questions.md`,
      `docs/registry/versioning-and-channels.md`,
      `docs/registry/http-layout.md`,
      `crates/aos-package/src/registry/git.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Add an explicit trust-management CLI for local registry trust keys,
      including pin, re-pin, rotation overlap, unpin, and compromised-key
      recovery workflows. `apr trust pin <registry> <registry:Ed25519:base64>`
      pins a local trust anchor, a second pin appends a rotation-overlap key,
      `--replace` performs explicit re-pin/recovery, `apr trust list` reports
      pinned keys, and `apr trust remove` / `apr trust unpin` removes local
      pins. `crates/aos/tests/apr_trust_cli.rs` covers the real CLI flow and
      rejects registry/key name mismatches. Producer-side committed `keys.toml`
      lifecycle remains tracked separately below. Context:
      `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos/tests/apr_trust_cli.rs`,
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
- [x] Maintain the committed `keys.toml` trust roster through producer key
      add/list/retire operations. `apr keys list`, `apr keys add <id> <key>`,
      and `apr keys retire <id>` now operate on the committed schema-1 roster,
      validate key ids and `registry:Ed25519:<base64>` registry binding, reject
      duplicate or already-revoked ids, require an active survivor for planned
      retirement, require/derive the survivor `--vouched-by` id, and commit +
      refresh dumb-HTTP metadata unless `--no-commit` is passed.
      `crates/aos/tests/apr_keys_cli.rs` drives the real `apr` binary against a
      temporary sha256 git registry and verifies commits plus `keys.toml`
      content. Context: `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/architecture.md`,
      `docs/registry/publishing.md`, `docs/registry/current-state.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/keys.rs`,
      `crates/aos-package/src/security.rs`, and
      `crates/aos/tests/apr_keys_cli.rs`.
- [x] Add producer signing-key-id selection for release and channel signing.
      `apr tag`, `apr sign`, `apr channel init`, and `apr channel advance`
      now accept `--key-id <id>` as a mutually exclusive alternative to direct
      `--key <private-key-path>`. The id is validated against the committed
      `keys.toml` active roster, rejected if revoked or registry-mismatched,
      and resolved through the selected local `registries.d/<name>.toml`
      `[registry.signing_keys]` private-key map. Unit coverage in
      `crates/aos-package/src/registry_ops.rs` checks direct-key bypass,
      ambiguous source rejection, key-id resolution, missing local mapping,
      revoked-key rejection, and a real git SSH signed tag verified through
      `verify_tag_signature`. Config coverage in
      `crates/aos-package/src/config.rs` checks `signing_keys` parsing, and the
      shared fixture serializer in `crates/aos-package/tests/common/mod.rs`
      preserves the table for future integration/e2e fixtures. Context:
      `docs/registry/repo-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/publishing.md`,
      `docs/registry/current-state.md`,
      `crates/aos-package/src/lib.rs`,
      `crates/aos-package/src/types.rs`,
      `crates/aos-package/src/config.rs`,
      `crates/aos-package/src/registry_ops.rs`,
      `crates/aos-package/src/registry/keys.rs`,
      `crates/aos-package/src/security.rs`,
      `crates/aos-package/tests/common/mod.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Add migration/capability tests for clean-break behavior. The policy is now
      ratified as a clean break: plain `http(s)://` origins must expose the
      git-native dumb-HTTP `HEAD` + `info/refs` surface; legacy-only
      `bundle-list.toml` origins fail with a clear clean-break error; if both
      surfaces exist, the git-native surface wins; git-native producers do not
      emit `bundle-list.toml`, so bundle-mode clients are EOL at registry
      cutover. Coverage in `crates/aos-package/tests/registry_e2e.rs` includes
      `legacy_bundle_only_http_origin_fails_with_clean_break_error`,
      `dual_surface_http_origin_prefers_git_native_over_legacy_manifest`, the
      existing git-native fixture assertion that no `bundle-list.toml` is
      emitted, and `signed_channel_http_e2e_advances_persisted_bucket` for first
      git-native channel sync floor seeding. Context:
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

- [x] Reconcile `docs/registry/README.md` and `docs/registry/current-state.md`
      with the production-readiness status after the local implementation
      backlog landed. The README now lists release orchestration and static
      origin/cache upload in the as-built summary, `current-state.md` describes
      `apr release`, and stale "remaining producer gaps" claims were removed
      from the reference docs. External production-readiness validation remains
      tracked by the stock-Nix, backend-matrix, CDN, Git-version, staleness, and
      benchmarking TODOs. Context: `docs/registry/README.md`,
      `docs/registry/current-state.md`, `docs/registry/publishing.md`,
      `docs/registry/packs-and-deltas.md`, and
      `docs/registry/nix-cache-compatibility.md`.
- [x] Resolve remaining registry-reference doc inconsistencies as implementation
      landed. `docs/registry/README.md`, `docs/registry/current-state.md`,
      `docs/registry/publishing.md`, `docs/registry/packs-and-deltas.md`,
      `docs/registry/apt-comparison.md`, `docs/registry/architecture.md`,
      `docs/registry/repo-layout.md`, and
      `docs/registry/nix-cache-compatibility.md` now describe the implemented
      `apr release`, static-cache producer, signing-key-id, trust-roster, and
      backend-upload surfaces without stale "producer gap" wording. Remaining
      stock-Nix, S3/SFTP, CDN, max-staleness, Git-version, and benchmark caveats
      are represented as explicit validation TODOs rather than stale reference
      claims.
- [x] Re-ground stale plan/open-question text that still describes old
      producer/cache gaps or pre-cutover implementation details. The plan README,
      design brief, gap analysis, validation report, and workstream docs now
      identify pre-cutover `CURRENT` citations and old producer/cache language as
      archival planning context, and direct agents to the as-built docs plus this
      TODO file for live status. Context:
      `docs/plans/registry/README.md`,
      `docs/plans/registry/open-questions.md`,
      `docs/plans/registry/design-brief.md`,
      `docs/plans/registry/gap-analysis.md`,
      `docs/plans/registry/workstream-01-object-store.md`,
      `docs/plans/registry/workstream-02-pack-delta-pipeline.md`,
      `docs/plans/registry/workstream-03-channels-rollouts.md`,
      `docs/plans/registry/workstream-04-signing-trust.md`,
      `docs/plans/registry/workstream-05-consumer.md`,
      `docs/plans/registry/workstream-06-nix-cache.md`,
      `docs/plans/registry/validation-report.md`,
      and `docs/registry/current-state.md`.
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
