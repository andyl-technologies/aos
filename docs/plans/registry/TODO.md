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
- [ ] Retire bundle producer/consumer path.

## WS-03 Channels And Rollouts

- [x] Add `registry::channel` module.
- [x] Add `channel` config field and `TrackingMode::Channel`.
- [x] Add semver floor, bucket, and retained release fields to registry state.
- [ ] Remove legacy creation-token state when the bundle path is retired.
- [x] Implement bucket selection, bucket hex rendering, and probe-forward order.
- [x] Implement semver floor anti-rollback check.
- [x] Implement partition map/frontier helpers.
- [x] Add focused channel/state unit tests.
- [ ] Add `apr channel init/advance/status` command surface.

## WS-04 Signing And Trust

- [x] Add `registry::keys` module for committed `keys.toml`.
- [x] Remove in-repo `registry.toml` signing public-key field.
- [x] Add `git verify-tag` helper.
- [x] Add tag-object parser and name-binding checks.
- [x] Add tag-chain verification helper.
- [x] Rewrite producer tag/sign paths to create signed tag objects.
- [x] Add rotation/revocation helpers and tests.

## WS-05 Consumer Cutover

- [ ] Resolve channel bucket to verified semver tag and commit.
- [ ] Run floor check before object fetch.
- [ ] Implement delta/full/loose object fetch resolution.
- [ ] Persist retained release set and prune obsolete objects.
- [ ] Resolve committed `registry.toml` `[[caches]]` from verified tree.
- [ ] Remove `bundle-list.toml` selection from `apm update`.

## WS-06 Nix Cache Generation

- [ ] Extract narinfo format/sign/cache-info helpers for producer reuse.
- [ ] Add AOT static cache generator for narinfo, NAR, and `nix-cache-info`.
- [ ] Add publish-time completeness check for registry-listed store paths.
- [ ] Add upload integration for static cache files.
- [ ] Add stock-Nix/static-cache smoke coverage.

## Docs Cleanup

- [x] Clear completed current-state sections from `docs/registry/*` as old behavior
      is removed from code.
- [ ] Keep `docs/registry/current-state.md` only for remaining as-is behavior and
      historical reference.
