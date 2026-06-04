# Registry Implementation TODO

This checklist tracks the implementation branch for the git-native registry
target described in `docs/registry/` and planned in `docs/plans/registry/`.
Keep this file current as work lands.

## Branch Setup

- [x] Fetch latest `origin/master`.
- [x] Create implementation branch from `origin/master`.
- [ ] Open PR.

## WS-01 Object Store

- [ ] Add `registry::objectstore` module.
- [ ] Implement bare sha256 repo initialization and object-format guard.
- [ ] Implement semver release object-dir mapping.
- [ ] Implement sha256 loose-object path validation and 2/62 split.
- [ ] Implement relative root `objects/info/alternates` writer.
- [ ] Implement `git update-server-info` wrapper.
- [ ] Add focused object-store unit tests.
- [ ] Wire producer create/publish paths to sha256 object-store helpers.
- [ ] Add dumb-HTTP clone integration coverage.

## WS-02 Packs And Deltas

- [ ] Add `registry::pack` module.
- [ ] Implement release-kind and guaranteed delta-base scheme.
- [ ] Implement full-pack and thin-delta `git pack-objects` wrappers.
- [ ] Implement zstd compress/decompress wrappers.
- [ ] Implement `git index-pack` and `--fix-thin` wrappers.
- [ ] Add focused pack/delta unit tests.
- [ ] Retire bundle producer/consumer path.

## WS-03 Channels And Rollouts

- [ ] Add `registry::channel` module.
- [ ] Add `channel` config field and `TrackingMode::Channel`.
- [ ] Replace creation-token state with semver floor, bucket, and retained releases.
- [ ] Implement bucket selection, bucket hex rendering, and probe-forward order.
- [ ] Implement semver floor anti-rollback check.
- [ ] Implement partition map/frontier helpers.
- [ ] Add focused channel/state unit tests.
- [ ] Add `apr channel init/advance/status` command surface.

## WS-04 Signing And Trust

- [ ] Add `registry::keys` module for committed `keys.toml`.
- [ ] Remove in-repo `registry.toml` signing public-key field.
- [ ] Add `git verify-tag` helper.
- [ ] Add tag-object parser and name-binding checks.
- [ ] Add tag-chain verification helper.
- [ ] Rewrite producer tag/sign paths to create signed tag objects.
- [ ] Add rotation/revocation helpers and tests.

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

- [ ] Clear completed current-state sections from `docs/registry/*` as old behavior
      is removed from code.
- [ ] Keep `docs/registry/current-state.md` only for remaining as-is behavior and
      historical reference.
