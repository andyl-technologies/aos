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
/ `git+*://` origins and plain `http(s)://` origins. Consumer sync requires
Git 2.42.0 or newer and preflights both `git --version` and local
`git init --bare --object-format=sha256` support before fetching a registry.
For plain `http(s)://` origins it also preflights the git-native dumb-HTTP
surface (`HEAD` and `info/refs`). Legacy bundle-only origins that expose
`bundle-list.toml` are rejected with a clean-break error; there is no
bundle/`creation_token` fallback in the active update path.

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
  `refs/heads/stable`, writes the committed root `registry.toml`, writes a
  schema-1 `keys.toml` trust roster (optionally seeded by `--trust-key` and
  `--trust-key-id`), and refreshes static git indexes.
- `apr keys list/add/retire` maintains the committed `keys.toml` trust roster.
  `add` validates key ids and registry-bound `registry:Ed25519:<base64>` keys;
  `retire` moves an active id to `[[revoked]]`, requires an active survivor
  key, and records/derives the survivor `--vouched-by` id for the planned
  retirement workflow. These commands commit and refresh static git indexes
  unless `--no-commit` is passed.
- `apr publish`, `apr unpublish`, and release signing commands update package
  metadata/tag state and then refresh the object-store view with
  `objects/info/alternates` and `git update-server-info`.
- `apr tag` creates signed release tag objects. `apr sign <tag>` re-signs an
  existing release tag. Both accept either `--key <private-key-path>` for
  direct one-off signing or `--key-id <keys.toml-id>` to resolve a local private
  key path from `[registry.signing_keys]` in the selected
  `registries.d/<name>.toml`. `--key-id` validates the committed `keys.toml`
  active id, rejects revoked ids, checks registry binding, and requires the
  configured local private-key path to exist.
- `apr channel init`, `apr channel advance`, and `apr channel status` manage the
  256 signed partition tag files under `channels/<name>/00..ff` and update the
  frontier branch. Channel signing uses the same `--key` / `--key-id` selection
  rules as release signing.
- `registry::objectstore` owns sha256 object-format checks, release object-dir
  paths, loose-object path validation, relative alternates, and
  `update-server-info`.
- `registry::pack` owns the release delta scheme and wrappers around
  `git pack-objects`, zstd, and `git index-pack --fix-thin`.
- `apr cache generate` emits static Nix-cache files for every registry-listed
  store path: `nix-cache-info`, `<storehash>.narinfo`, and `nar/*.nar.zst`.
  It fails closed when a listed store path is absent from the local Nix store,
  can upload the generated files to one or more repeatable `--upload-url`
  destinations through `aos-cache` backends while preserving the generated
  `nix-cache-info` body, can read producer upload-auth defaults from
  `[registry.upload_auth]` in the selected `registries.d/<name>.toml` with
  env/CLI overrides, and can update the committed root `registry.toml`
  `[[caches]]` pointer.
- `apr origin upload` uploads the full dumb-HTTP git origin surface to one or
  more repeatable backend URLs after refreshing static git indexes. It uploads
  immutable payloads (`objects/**`, `releases/**`, and optional static-cache
  NAR/narinfo files from `--cache-dir`) before mutable surfaces (`HEAD`,
  `info/refs`, `objects/info/**`, `channels/**`, and `nix-cache-info`) and
  applies per-path cache-control/content-type metadata where the backend
  supports it.
- `apr release <semver>` is the guarded producer orchestrator. It can release an
  already committed registry tree or optionally publish a real Nix store path
  first, commits a `[[caches]]` pointer before signing when `--cache-url` is
  supplied, creates/reuses the signed semver tag, generates full packs at
  `X.Y.0` anchors and compressed guaranteed thin deltas, refreshes static git
  indexes, optionally generates static Nix-cache files with `--cache-output`,
  initializes or advances channel partitions, and uploads the static origin to
  repeatable backend URLs in immutable-first / mutable-last order. It has a
  local publisher lock, `--dry-run`, and `--resume` for interrupted immutable
  artifact generation.

---

## 4. Consumer state

`apm update` routes both HTTP and native git transports through
`registry::git::sync_git`:

1. Normalize the origin URL.
2. Preflight sha256-capable Git and, for plain `http(s)://`, the git-native
   dumb-HTTP origin shape.
3. Ensure the local bare repo exists with sha256 object format.
4. Fetch branch/tag refs with git.
5. Resolve the target commit from the requested tracking mode.
6. Verify trust:
   - branch/tag/version/commit modes use the configured commit-signature path
     when required;
   - channel mode verifies the signed partition tag, signed semver tag, and
     commit chain with name-binding.
7. Enforce fast-forward from the last synced commit.
8. Extract `packages/` and `closures/` to the remote metadata cache.
9. Extract committed root `registry.toml`, `keys.toml`, and `.gitattributes`
   so `[[caches]]` are available to NAR mirror resolution and trust-roster
   helpers can read the authenticated tree after sync.
10. Persist registry state.

Channel tracking resolves a deterministic persisted bucket through
`/channels/<name>/<bucket>`, probes forward when needed, verifies that partition
tag object, maps it to a signed semver release tag, checks the anti-rollback
floor, then invokes `registry::fetch` to resolve objects. That resolver prefers
an AOS thin delta from a retained base, falls back to the target `X.Y.0`
full-pack anchor plus a forward delta, and finally delegates to `git fetch` for
the dumb-HTTP loose-object correctness floor.

Channel e2e coverage includes torn-publish safety: an early mutable partition
that names an unpublished release is skipped in favor of the old usable
partition/floor, and an interleaved stale-publisher overwrite is rejected as a
rollback while preserving the newer floor.

---

## 5. Registry config and state

Per-registry config files live under `registries.d/<name>.toml`. The mutable
`[registry.state]` section now writes:

```toml
[registry.state]
last_commit = "<sha256 commit>"
floor = "1.4.2"
bucket = 183
retained = ["1.0.0", "1.4.0", "1.4.2"]
last_update = "2026-02-16T12:00:00Z"
```

`last_commit` supports fast-forward checks. `floor` is the semver anti-rollback
floor. `bucket` persists deterministic rollout assignment. `retained` records
release object directories that should survive pruning. For a patch release this
is the minimum `{X.0.0, X.Y.0, X.Y.Z}` set. For channel tracking, `last_update`
is the local freshness clock: first sync and semver advancement refresh it;
unchanged but valid signed channel targets are accepted only while this timestamp
is within `max_staleness_seconds`, and they do not refresh it.

---

## 6. Signing and trust

Implemented trust pieces:

- `security.rs` parses `registry:Ed25519:<base64>` keys, stores trusted keys, and
  verifies git signatures through SSH-format signing.
- `apr trust pin/list/remove` manages local `trusted-keys.d/<registry>.pub`
  anchors. Re-running `pin` appends an overlap key for rotation; `pin --replace`
  is the explicit out-of-band re-pin path for compromised-key recovery.
- `registry::keys` parses committed `keys.toml`, supports rotation overlap,
  active-key lookup, revocation gating, and tests the survivor-vouched revocation
  rules.
- `apr keys list/add/retire` is the producer-side command surface for committed
  roster maintenance. Release/channel signing can select a committed active key
  id via `--key-id`, with the local private key path stored outside the registry
  in `[registry.signing_keys]`.
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

Shared formatting and signing logic now lives in `aos-core::nar::cache`:
`render_static_narinfo`, `nix_cache_info`, `nar_url`, and `NarInfoSigner`.
`aos-server` calls that shared library for its live cache responses, while
`apr cache generate` calls the same library offline to write the static cache.

The generated narinfo layout is covered by round-trip tests and a stock-Nix
fingerprint signature verification test; the producer-side path is covered by
store-path collection and committed-cache-pointer tests. Production validation
for the stock-Nix substituter path and mixed cache upload destinations is covered
by the VM check
`checks.vm.apm.registry-validation-stock-nix-backend-array`, which creates a
tiny fixed-output path inside the VM, generates signed static cache files, serves
them to stock Nix with `require-sigs = true`, and uploads the same cache to
`file://`, S3-compatible, and SFTP destinations. That check passed on
`dylan@builder-hil1-c13958ef` on 2026-06-06. The lower-level Rust real-Nix e2e
remains opt-in behind `AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` for local debugging
because it mutates the host Nix store.
