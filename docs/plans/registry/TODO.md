# Registry Implementation TODO

This checklist tracks the implementation branch for the git-native registry
target described in `docs/registry/` and planned in `docs/plans/registry/`.
Keep this file current as work lands.

> **VM validation PR status:** local implementation and reference-doc updates
> landed in the prior PR. This PR turns the external stock-Nix, backend-array,
> stock-Git, CDN-layout, and pack/delta validation gates into Nix VM checks under
> `tests/vm/apm/registry_validation.nix`. The focused registry VM checks passed
> on a remote KVM builder on 2026-06-08;
> fleet-specific `max_staleness_seconds` tuning remains operator rollout policy
> rather than a repository implementation item. Additional builder validation
> on 2026-06-08 passed the full `checks.fleet` aggregate after the fleet
> `apm-e2e` registry fixture was corrected to initialize a sha256 bare origin.
> APM-specific validation on 2026-06-08 passed the full `checks.vm.apm`
> aggregate after adding the command-surface VM check and build activity
> Rust coverage.
> A full `checks.integration` aggregate was also attempted, but it failed in the
> unrelated `cross-cutting-archive-chain` libarchive check before completing;
> the registry-requested Go CGO GCC/LLVM integration gate passed separately.
> Context for that non-registry failure: `pkgs/libs/libarchive.nix`.

## Branch Setup

- [x] Fetch latest `origin/master`.
- [x] Create VM validation branch from `origin/master`.
- [x] Open VM validation PR: https://github.com/andyl-technologies/aos/pull/24.

## VM Validation PR

- [x] Add `tests/vm/apm/registry_validation.nix` and wire it from
      `tests/vm/apm/default.nix`. The VM file carries the external validation
      checks that were left after the Rust implementation PR:
      `registry-validation-stock-nix-backend-array`,
      `registry-validation-origin-cdn-layout`,
      `registry-validation-stock-git-matrix`, and
      `registry-validation-pack-delta-perf`. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/http-layout.md`, `docs/registry/publishing.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/versioning-and-channels.md`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-package/src/registry/static_upload.rs`,
      `crates/aos-package/src/registry/fetch.rs`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`,
      `crates/aos-net/src/protocol/s3.rs`,
      `crates/aos-net/src/protocol/sftp.rs`,
      `tests/vm/apm/default.nix`, and
      `tests/vm/apm/registry_validation.nix`.
- [x] Add a pinned minimum Git package for the stock-Git floor matrix. Context:
      `pkgs/tools/git-2_42.nix`, `pkgs/tools/git.nix`,
      `docs/registry/http-layout.md`, and
      `tests/vm/apm/registry_validation.nix`.
- [x] Run all registry validation VM checks on a remote KVM builder:
      `nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array`,
      `nix-build -A checks.vm.apm.registry-validation-origin-cdn-layout`,
      `nix-build -A checks.vm.apm.registry-validation-stock-git-matrix`, and
      `nix-build -A checks.vm.apm.registry-validation-pack-delta-perf`.
      Builder evidence from 2026-06-08:
      `apm-registry-validation-stock-nix-backend-array` passed at
      `/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`;
      `apm-registry-validation-origin-cdn-layout` passed at
      `/nix/store/xfzd1yim7sx5cq9gsg6nx8kvh1hi551s-aos-vm-test-apm-registry-validation-origin-cdn-layout-0`;
      `apm-registry-validation-stock-git-matrix` passed at
      `/nix/store/yx7wm7m63l6smij5k57dbjlz22y3ql74-aos-vm-test-apm-registry-validation-stock-git-matrix-0`;
      and `apm-registry-validation-pack-delta-perf` passed at
      `/nix/store/c6lg01w5ks8f2h4ginav0wfdhlf12az9-aos-vm-test-apm-registry-validation-pack-delta-perf-0`.
      Context: `tests/vm/apm/registry_validation.nix`,
      `lib/testing/vm.nix`, `lib/testing/firecracker.nix`, and
      `docs/plans/registry/validation-runbook.md`.
- [x] Update `docs/registry/*` and `docs/plans/registry/validation-runbook.md`
      with the VM check commands and evidence once the builder run passes.
      Context: `docs/registry/current-state.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/http-layout.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/publishing.md`, and
      `docs/plans/registry/validation-runbook.md`.

## Cross-Cutting VM Integration

- [x] Run the Go CGO GCC/LLVM integration VM check on a remote KVM builder:
      `nix-build -A checks.integration.go-cgo-gcc-and-clang`.
      Builder evidence from 2026-06-08:
      `cross-cutting-go-cgo-gcc-clang` passed at
      `/nix/store/3h0lvv0npqba00jfvgb3qv5jfqprwsqa-aos-vm-test-cross-cutting-go-cgo-gcc-clang-0`;
      its serial log reports `go-cgo-compiler-ok` for both compiler paths and
      `Go CGO GCC/LLVM integration: PASS`. Context:
      `pkgs/toolchain/go/go.nix`, `lib/testing/vm.nix`, and
      `lib/testing/firecracker.nix`.
- [x] Run the full fleet VM aggregate on a remote KVM builder after
      adding the external registry validation checks. Builder evidence from
      2026-06-08: `checks.fleet` passed with outputs for
      `apm-e2e`, `apm-system-activation-fail`, `apm-system-upgrade`,
      `apm-systemd-client`, `k3s-combined-worker`,
      `k3s-control-plane-worker`, and `test-http-server-pair`. The final
      `apm-e2e` run passed at
      `/nix/store/vkxg2pj9y4szwr0s72hhgkcf5ix41gp9-aos-fleet-test-apm-e2e-0`.
      Context: `tests/fleet/apm-e2e.nix`, `lib/testing/fleet.nix`,
      `lib/testing/vm.nix`, and `docs/plans/registry/validation-runbook.md`.

## APM Command And Activity Coverage

- [x] Add exhaustive Rust coverage for build activity event types across both
      active transports. `crates/aos-server/src/build.rs` now covers every
      internal SSE event emitted by `BuildEventKind`: `status`, `log`,
      `complete`, `error`, `daemon-unavailable`, and `drain`.
      `crates/aos-server/src/services/build.rs` covers every ConnectRPC
      `BuildEvent.event_type` mapping and the `BuildClosure` derivation
      override behavior. `crates/aos-server/src/routes.rs` covers the legacy
      SSE `build-closure` wrapper event, and
      `crates/aos-proto/src/proto/aos/build/v1/build.proto` now documents that
      `build-closure` is an outer SSE wrapper rather than an internal
      ConnectRPC activity kind. Local evidence from 2026-06-08:
      `cargo test --manifest-path crates/Cargo.toml -p aos-server` passed with
      10 tests. Context: `crates/aos-server/src/build.rs`,
      `crates/aos-server/src/services/build.rs`,
      `crates/aos-server/src/routes.rs`,
      `crates/aos-proto/src/proto/aos/build/v1/build.proto`,
      `crates/aos/src/commands/build.rs`, and `crates/aos-remote/src/client.rs`.
- [x] Add APM package command-surface VM coverage for commands that were not
      already strongly covered by install/remove/update/system flows.
      `checks.vm.apm.command-surface` creates a real local registry cache and
      profile metadata, then exercises `search`, `show`, `list`, `depends`,
      `rdepends`, `policy`, `files`, `source`, `verify`, `clean`, `reinstall`,
      `full-upgrade`, and side-effect-free `gc --help` coverage. It also covers
      filters and flags such as `search --names-only`, `search --installed`,
      `list --installed`, `list --upgradable`, `list --held`,
      `source --show-drv`, `source --fetch`, and `clean --generations --keep`.
      `apm gc` itself is intentionally not executed in the headless VM because
      a real `nix-store --gc` can collect rootfs dependencies; the command
      parser/surface is covered without mutating the VM store. Builder evidence
      from 2026-06-08:
      `checks.vm.apm.command-surface` passed at
      `/nix/store/4sq0pa2na132r2ibap89mgfk9wf4sqyr-aos-vm-test-apm-command-surface-0`.
      Context: `tests/vm/apm/packages.nix`,
      `tests/vm/apm/fixtures.nix`, `tests/vm/apm/default.nix`,
      `crates/aos-package/src/lib.rs`, `crates/aos-package/src/query.rs`,
      `crates/aos-package/src/deps.rs`, `crates/aos-package/src/source.rs`,
      `crates/aos-package/src/clean.rs`,
      `crates/aos-package/src/install.rs`,
      `crates/aos-package/src/upgrade.rs`,
      `crates/aos-package/src/remove.rs`,
      `crates/aos-package/src/rollback.rs`, and
      `crates/aos-package/src/hold.rs`.
- [x] Inventory the remaining APM/APR production command coverage by file so
      future agents can trace every command family. Package install/remove,
      upgrade, rollback, hold/unhold, query, source/verify, clean, and command
      parser coverage lives in `tests/vm/apm/packages.nix` and the Rust files
      listed above. `apm update` and real producer/consumer registry sync are
      covered in `tests/fleet/apm-e2e.nix`. System install/upgrade/rollback,
      image pulls, kernel mode flags, drain behavior, activation failure, and
      systemd-client behavior are covered in `tests/vm/apm/system.nix`,
      `tests/vm/apm/kernel.nix`, `tests/vm/apm/image.nix`,
      `tests/fleet/apm-system-upgrade.nix`,
      `tests/fleet/apm-system-activation-fail.nix`, and
      `tests/fleet/apm-systemd-client.nix`. APR registry producer,
      tracking/channel, cache/backend, multi-registry, RPC, and e2e lifecycle
      coverage lives in `tests/vm/apm/registry.nix`,
      `tests/vm/apm/tracking.nix`, `tests/vm/apm/cache.nix`,
      `tests/vm/apm/multi_registry.nix`, `tests/vm/apm/rpc.nix`,
      `tests/vm/apm/e2e.nix`, `tests/vm/apm/registry_validation.nix`,
      `crates/aos/tests/apr_cache_cli.rs`,
      `crates/aos/tests/apr_keys_cli.rs`,
      `crates/aos/tests/apr_trust_cli.rs`,
      `crates/aos-package/tests/registry_e2e.rs`,
      `crates/aos-package/tests/registry_cache_e2e.rs`,
      `crates/aos-package/tests/registry_perf.rs`, and
      `crates/aos-cache/tests/backend_matrix.rs`.
- [x] Run the full `checks.vm.apm` aggregate on a remote KVM builder
      after adding `checks.vm.apm.command-surface`. Builder evidence from
      2026-06-08: the aggregate command
      `nix-build --no-out-link --expr 'let aos = import . { system = "x86_64-linux"; }; in builtins.attrValues aos.checks.vm.apm'`
      returned 0. The output set included the new command-surface test at
      `/nix/store/ngqcnmlcyz4k0j3v9mn7jlw35jkvc5yq-aos-vm-test-apm-command-surface-0`
      along with the registry, tracking, package, sysroot-lock, system, kernel,
      image, cache, multi-registry, RPC, and e2e APM VM tests. Context:
      `tests/vm/apm/default.nix`,
      `tests/vm/apm/packages.nix`, `lib/testing/vm.nix`, and
      `lib/testing/firecracker.nix`.

## Non-Registry Integration Observation

- [x] Attempt the full `checks.integration` aggregate on a remote KVM builder
      for extra confidence. The aggregate did not
      complete: `cross-cutting-archive-chain` failed with a fortified
      buffer-overflow abort while running the libarchive tar.gz extraction test,
      and Nix also reported unrelated package-build failures from the same broad
      aggregate. This is not a remaining `docs/registry` implementation item;
      the targeted registry-adjacent integration gate above passed. Context:
      `pkgs/libs/libarchive.nix`, `pkgs/toolchain/go/go.nix`,
      `lib/testing/firecracker.nix`, and
      `docs/plans/registry/TODO.md`.

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
- [x] Implement libgit2 full-pack generation/indexing and Rust thin-delta generation.
- [x] Implement zstd compress/decompress wrappers.
- [x] Implement libgit2 pack indexing for full packs and completed thin packs.
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
      zstd-compressed thin-delta artifacts, libgit2 pack indexing, fallback from
      missing/corrupt delta to full pack, fallback from missing/corrupt full pack
      to loose-object git fetch, and pruning behavior after retained releases
      change. The coverage now lives in
      `crates/aos-package/tests/registry_e2e.rs`:
      `pack_delta_e2e_fetches_full_pack_and_compressed_thin_delta` builds a real
      full pack, publishes a zstd-compressed thin delta, resolves both over
      static HTTP, and verifies the target commit exists after local pack
      indexing; `pack_delta_e2e_falls_back_from_corrupt_artifacts`
      proves corrupt deltas fall through to the full-pack anchor plus git-fetch
      loose fallback, and corrupt full packs fall directly to git-fetch fallback;
      `signed_channel_http_e2e_advances_persisted_bucket` asserts retained
      release pruning keeps retained release dirs and removes stale ones. The
      implementation now streams full and thin packs through libgit2 pack
      indexing and publishes producer-generated full-pack indexes for stock Git.
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
- [x] Validate stock Nix substituter behavior under `require-sigs` in the VM
      test-suite PR. `registry-validation-stock-nix-backend-array` creates a
      fixed-output store path inside the VM, generates signed static cache
      files with `apr cache generate`, serves those files over dumb HTTP, and
      runs stock `nix path-info --store http://...` with
      `require-sigs = true` and the generated trusted public key. The opt-in
      Rust path remains in `crates/aos-package/tests/registry_cache_e2e.rs`
      behind `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` plus
      `AOS_PACKAGE_TEST_STOCK_NIX_CACHE=1`, but the VM check is the controlled
      external validation gate. Builder evidence from 2026-06-08:
      `/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0/serial.log`
      reports `registry stock Nix + backend array validation passed`.
      Context:
      `docs/registry/nix-cache-compatibility.md`,
      `docs/plans/registry/workstream-06-nix-cache.md`,
      `docs/plans/registry/validation-runbook.md`,
      `tests/vm/apm/registry_validation.nix`,
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
- [x] Add an env-gated generated static-cache upload/readback matrix hook for
      service-backed destinations. When
      `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` and
      `AOS_PACKAGE_TEST_GENERATED_CACHE_UPLOAD_URLS` are set,
      `crates/aos-package/tests/registry_cache_e2e.rs` uploads the actual
      generated Nix-cache output to a mixed destination array containing a local
      `file://` target plus the supplied URLs, then reads back narinfo and NAR
      payloads through the `aos-cache` backend trait. Context:
      `docs/registry/nix-cache-compatibility.md`,
      `crates/aos-package/src/registry/nixcache.rs`,
      `crates/aos-cache/src/backend/mod.rs`,
      `crates/aos-cache/src/backend/fs.rs`,
      `crates/aos-cache/src/backend/s3.rs`,
      `crates/aos-cache/src/backend/sftp.rs`, and
      `crates/aos-package/tests/registry_cache_e2e.rs`.
- [x] Validate service-backed generated static-cache upload/readback for an
      array of `file://`, `s3://`, and `sftp://` destinations in the VM test
      suite. `registry-validation-stock-nix-backend-array` starts a local
      S3-compatible HTTP endpoint and an OpenSSH SFTP endpoint inside the VM,
      runs `apr cache generate` with repeatable `--upload-url` values for S3,
      local filesystem, SFTP, and one invalid URL, verifies all successful
      destinations receive byte-identical cache outputs, and verifies the
      aggregate partial-failure error is reported only after all destinations
      are attempted. Builder evidence from 2026-06-08:
      `/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0/serial.log`
      reports `static cache upload failed for 1/4 destination(s)` for
      `not-a-url`, followed by
      `registry stock Nix + backend array validation passed`.
      Context:
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
      `crates/aos-package/tests/registry_cache_e2e.rs`,
      `crates/aos-net/src/protocol/s3.rs`,
      `crates/aos-net/src/protocol/sftp.rs`, and
      `tests/vm/apm/registry_validation.nix`.
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
- [x] Add an env-gated supported-version stock Git compatibility matrix harness
      for the pinned minimum Git version and newer clients.
      `stock_git_configured_version_matrix_syncs_sha256_dumb_http_registry`
      reads `AOS_PACKAGE_TEST_GIT_MATRIX` as a PATH-style list of git binaries or
      bin directories, then reruns the same sha256 dumb-HTTP sync e2e with each
      pinned Git selected through a temporary PATH shim. The test is ignored
      because PATH is process-global; run it explicitly with `--ignored` and
      `--test-threads=1`. Context:
      `docs/registry/http-layout.md`,
      `docs/plans/registry/open-questions.md`,
      `crates/aos-package/src/registry/git.rs`,
      `crates/aos-package/src/registry/objectstore.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Run and publish the supported-version stock Git compatibility matrix for
      the pinned minimum Git version and newer clients in the VM test-suite PR.
      `registry-validation-stock-git-matrix` includes the pinned
      `pkgs."git-2_42"` floor package and the repo's current `pkgs.git`, serves
      a sha256 bare registry over dumb HTTP inside the VM, and requires both
      binaries to clone it as sha256. The host-current e2e and env-gated Rust
      matrix remain useful lower-level coverage, but the VM check is the
      production floor evidence. Builder evidence from 2026-06-08:
      `/nix/store/yx7wm7m63l6smij5k57dbjlz22y3ql74-aos-vm-test-apm-registry-validation-stock-git-matrix-0/serial.log`
      reports `validating stock Git 2.42.0`, `validating stock Git 2.48.1`,
      and `registry stock Git matrix validation passed`.
      Context:
      `docs/registry/http-layout.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/plans/registry/open-questions.md`,
      `pkgs/tools/git-2_42.nix`,
      `tests/vm/apm/registry_validation.nix`,
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
      origin, and syncs a channel consumer from it. The VM validation PR items
      above cover stock-Nix substituter behavior, service-backed S3/SFTP upload
      arrays, CDN-layout metadata, stock-Git compatibility, and pack/delta
      metrics. Context:
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
      a consumer from it. The VM validation PR item above covers service-backed
      S3/SFTP execution against in-VM endpoints. Context:
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
- [x] Keep production `max_staleness_seconds` default tuning as an operator
      rollout policy, not a repository implementation blocker. The
      implementation deliberately uses the local freshness clock because signed
      channel tags have no in-band expiry; this can reject genuinely quiet
      channels if operators choose too short a window, and a host with no recent
      freshness observation still cannot prove a reachable unchanged pointer is
      malicious. Rust unit/e2e coverage now proves first-sync failure, refresh
      failure, and reachable unchanged signed partitions fail closed when the
      freshness clock is stale. The VM validation PR covers the CDN-facing
      mutable-path TTL contract; real fleet interval distributions still belong
      in deployment rollout notes. Context:
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

- [x] Add an opt-in producer/consumer performance harness for registry pack and
      delta metrics. `crates/aos-package/tests/registry_perf.rs` builds a
      multi-package fixture, measures full-pack generation, thin-delta
      generation, zstd compression, full-pack reconstruction, and compressed
      delta reconstruction, then prints byte/time metrics. It is ignored by
      default; run it with `AOS_PACKAGE_TEST_REGISTRY_PERF=1` and optionally set
      `AOS_PACKAGE_TEST_REGISTRY_PERF_PACKAGES=<n>`. Context:
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/publishing.md`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_perf.rs`.
- [x] Run the registry performance harness in the VM validation PR. The Rust
      harness exists in the implementation PR, and
      `registry-validation-pack-delta-perf` now records VM-side
      `REGISTRY_PERF_METRIC` values for full-pack bytes/time, thin-delta
      bytes/time, zstd bytes/time, and consumer reconstruction time. Target-host
      evidence should still inform producer pack settings and consumer
      reconstruct cost: Rust thinpack strategy selection, zstd level, zstd
      `--long` window, optional dictionary training, and memory limits. Builder
      evidence from 2026-06-08:
      `/nix/store/c6lg01w5ks8f2h4ginav0wfdhlf12az9-aos-vm-test-apm-registry-validation-pack-delta-perf-0/serial.log`
      reported `full_pack_bytes=11276`, `full_pack_ns=86438382`,
      `thin_delta_bytes=11295`, `thin_delta_ns=49235341`,
      `zstd_delta_bytes=7191`, `zstd_ns=1748206`, and
      `reconstruct_ns=2568679`.
      Context:
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/publishing.md`,
      `docs/plans/registry/open-questions.md`,
      `tests/vm/apm/registry_validation.nix`,
      `crates/aos-package/src/registry/pack.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_perf.rs`.
- [x] Add hermetic CDN/mirror layout regression coverage for the pieces we can
      prove without external infrastructure: byte-stable relative
      `objects/info/alternates`, immutable-vs-mutable static-origin
      cache-control/content-type metadata, loose-object fallback planning, and
      corrupt-pack fallback to Git's dumb-HTTP fetch. Context:
      `docs/registry/http-layout.md`,
      `crates/aos-package/src/registry/objectstore.rs`,
      `crates/aos-package/src/registry/static_upload.rs`,
      `crates/aos-package/src/registry/fetch.rs`, and
      `crates/aos-package/tests/registry_e2e.rs`.
- [x] Validate the CDN/mirror HTTP layout against a service-like object backend
      in the VM validation PR. `registry-validation-origin-cdn-layout` uploads a
      git-native origin plus generated static-cache files to an S3-compatible
      endpoint inside the VM, checks immutable objects/NARs/narinfos receive
      long immutable cache-control metadata, checks mutable `HEAD`,
      `info/refs`, `channels/**`, `objects/info/**`, and `nix-cache-info`
      receive low-TTL metadata, verifies immutable uploads happen before mutable
      pointers, and verifies `objects/info/alternates` remains relative.
      Deployed CDN edge behavior and incident diagnostics remain production
      rollout validation. Builder evidence from 2026-06-08:
      `/nix/store/xfzd1yim7sx5cq9gsg6nx8kvh1hi551s-aos-vm-test-apm-registry-validation-origin-cdn-layout-0/serial.log`
      reports `registry origin CDN layout validation passed`.
      Context: `docs/registry/http-layout.md`,
      `docs/registry/publishing.md`,
      `docs/registry/signing-and-trust.md`,
      `tests/vm/apm/registry_validation.nix`,
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
- [x] Update the external-validation runbook so agents/operators have one place
      to run the stock-Nix, S3/SFTP, stock-Git, performance, CDN/mirror, and
      max-staleness policy gates before claiming production validation.
      The runbook now records the builder commands, output paths, serial-log
      locations, and 2026-06-08 VM evidence for the focused registry checks.
      Context: `docs/plans/registry/validation-runbook.md`,
      `docs/plans/registry/TODO.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/http-layout.md`,
      `docs/registry/packs-and-deltas.md`,
      `docs/registry/publishing.md`,
      `docs/registry/versioning-and-channels.md`, and
      `docs/registry/signing-and-trust.md`.
- [x] Close VM-validation operator docs. `docs/registry/*` documents backend
      arrays, auth flags, `apr release`, trust management, and stock-Nix
      verification hooks; this PR should replace the remaining follow-up
      validation caveats with the VM check commands and the fleet-only
      `max_staleness_seconds` tuning boundary. The reference docs now point at
      the completed VM checks and keep max-staleness tuning as an operator
      rollout policy. Context:
      `docs/registry/publishing.md`,
      `docs/registry/nix-cache-compatibility.md`,
      `docs/registry/signing-and-trust.md`,
      `docs/registry/repo-layout.md`, and
      `docs/registry/README.md`.
