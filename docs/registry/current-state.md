# AOS Registry — Current State

> **Status:** Reference / as-built. This document describes the registry
> behavior implemented in `crates/aos-package` after the git-native registry
> cutover work. For target intent, see
> [`architecture.md`](architecture.md), [`http-layout.md`](http-layout.md),
> [`versioning-and-channels.md`](versioning-and-channels.md),
> [`packs-and-deltas.md`](packs-and-deltas.md), and
> [`nix-cache-compatibility.md`](nix-cache-compatibility.md).

All paths below are relative to the repo root unless noted.

---

## 1. What the registry is today

An AOS registry is a git repository of package metadata:

- `registry.toml` at the repo root contains `[registry]` metadata and `[[caches]]`
  NAR cache pointers.
- `keys.toml` is the committed registry trust roster for rotation and
  revocation.
- `packages/<letter>/<name>.toml` stores package metadata in the nested
  `[package]` / `[[versions]]` / `[versions.platforms.<platform>]` shape parsed
  by `registry/parse.rs`.
- `closures/<hash>` stores precomputed dependency adjacency lists.

The producer creates sha256 git repositories and refreshes the static object
indexes needed by dumb HTTP. The consumer uses native git sync for both `git://`
/ `git+*://` origins and plain `http(s)://` origins.

---

## 2. CLI dispatch

One binary serves three entry points:

| Invocation | Effective command |
|---|---|
| `apr ...` | `aos package registry ...` |
| `apm ...` | `aos package ...` |
| `aos package ...` | literal |

The dispatch lives in `crates/aos/src/main.rs`. Registry producer commands are in
`crates/aos-package/src/registry_ops.rs`.

---

## 3. Producer state

Implemented producer behavior:

- `apr create` initializes a sha256 git repository, sets `HEAD` to
  `refs/heads/stable`, writes the committed root `registry.toml`, and refreshes
  static git indexes.
- `apr publish`, `apr unpublish`, and `apr tag` update package metadata and then
  refresh the object-store view with `objects/info/alternates` and
  `git update-server-info`.
- `apr tag --key` creates signed release tag objects. `apr sign <tag> --key`
  re-signs an existing release tag.
- `apr channel init`, `apr channel advance`, and `apr channel status` manage the
  256 signed partition tag files under `channels/<name>/00..ff` and update the
  frontier branch.
- `registry::objectstore` owns sha256 object-format checks, release object-dir
  paths, loose-object path validation, relative alternates, and
  `update-server-info`.
- `registry::pack` owns the release delta scheme and wrappers around
  `git pack-objects`, zstd, and `git index-pack --fix-thin`.

Remaining producer gaps:

- Publish-time static Nix-cache generation is not implemented yet:
  `nix-cache-info`, `*.narinfo`, `nar/` files, completeness checks, and upload
  integration are still WS-06 work.
- The pack helpers exist, but the end-to-end producer upload flow for generated
  pack artifacts is not complete.

---

## 4. Consumer state

`apm update` routes both HTTP and native git transports through
`registry::git::sync_git`:

1. Normalize the origin URL.
2. Ensure the local bare repo exists with sha256 object format.
3. Fetch branch/tag refs with git.
4. Resolve the target commit from the requested tracking mode.
5. Verify trust:
   - branch/tag/version/commit modes use the configured commit-signature path
     when required;
   - channel mode verifies the signed partition tag, signed semver tag, and
     commit chain with name-binding.
6. Enforce fast-forward from the last synced commit.
7. Extract `packages/` to the remote metadata cache.
8. Extract committed root `registry.toml` so `[[caches]]` are available to NAR
   mirror resolution.
9. Persist registry state.

Channel tracking now resolves a deterministic persisted bucket through
`/channels/<name>/<bucket>`, probes forward when needed, verifies that partition
tag object, maps it to a signed semver release tag, checks the anti-rollback
floor, and records the selected release in `retained`.

The consumer currently delegates object transfer to git's fetch machinery. The
target AOS-specific delta-pack walk and retention policy are represented in the
pack/channel/object-store helpers but are not yet a complete custom fetch path.

---

## 5. Registry config and state

Per-registry config files live under `registries.d/<name>.toml`. The mutable
`[registry.state]` section now writes:

```toml
[registry.state]
last_commit = "<sha256 commit>"
floor = "1.4.2"
bucket = 183
retained = ["1.4.2"]
last_update = "2026-02-16T12:00:00Z"
```

`last_commit` supports fast-forward checks. `floor` is the semver anti-rollback
floor. `bucket` persists deterministic rollout assignment. `retained` records
release object directories that should survive pruning.

---

## 6. Signing and trust

Implemented trust pieces:

- `security.rs` parses `registry:Ed25519:<base64>` keys, stores trusted keys, and
  verifies git signatures through SSH-format signing.
- `registry::keys` parses committed `keys.toml`, supports rotation overlap,
  active-key lookup, revocation gating, and tests the survivor-vouched revocation
  rules.
- `registry::verify` parses tag objects, enforces name-binding, verifies
  `tag -> tag -> commit` release chains, and rejects non-semver release names
  where semver is required.
- `apr tag --key`, `apr sign <tag> --key`, and channel partition commands create
  signed tag objects rather than signing commits.

---

## 7. NAR downloads and Nix-cache compatibility

The `apm` NAR downloader is narinfo-driven today:

- It fetches `<store-hash>.narinfo` from the selected cache base.
- It downloads the NAR path named by the narinfo `URL:` field.
- It verifies the compressed file against `FileHash` when present, falling back
  to `NarHash` for uncompressed NARs.

Reusable formatting and signing logic already exists in `aos-core` and
`aos-server`: `NarInfo`, narinfo formatting, `NarInfoSigner`, and compressed
file hash/size calculation. What remains is an ahead-of-time producer that emits
static Nix-cache files for registry store paths and uploads them to the selected
origin.

---

## 8. Current gaps

The git-native registry path is active, but these items remain incomplete:

- A full custom AOS object fetch path over the release pack graph.
- Static Nix-cache file generation and upload.
- Publish-time completeness checks for every store path listed by the registry.
- Stock-Nix smoke coverage against the generated static cache.

These are tracked in [`docs/plans/registry/TODO.md`](../plans/registry/TODO.md).
