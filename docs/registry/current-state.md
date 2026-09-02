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
- `store/<2-char>/<ia>` stores the realisation graph: blessed NAR bytes, dependency edges, and content addresses per store path (RFC-0005).

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

## 2. CLI boundaries

Independent `apm` and `apr` parsers call shared library implementations.
Consumer registry configuration is available below `apm registry`; producer
operations are available only through `apr`. `aos` has no package subcommand,
and private on-host lifecycle operations run through `aos-package-runtime`.
Registry producer implementations are in
`crates/aos-package/src/registry_ops.rs`.

---

## 3. Producer state

Implemented producer behavior:

- `apr create` initializes a sha256 git repository, sets `HEAD` to
  `refs/heads/stable`, writes the committed root `registry.toml`, writes a
  schema-1 `keys.toml` trust roster (optionally seeded by `--trust-key` and
  `--trust-key-id`), and refreshes static git indexes.
- `apr keys generate/list/add/retire` maintains the committed `keys.toml` trust
  roster. `generate <id>` mints an Ed25519 keypair in-process (the hermetic
  `sshkey` module, no `ssh-keygen`), writes the OpenSSH private key to
  `apm/keys/<registry>-<id>.key` (mode `0600`, refusing to overwrite), records
  its path in `[registry.signing_keys]`, prints the public key + fingerprint,
  and with `--add` appends it to the roster. `add` validates key ids and
  registry-bound `registry:Ed25519:<base64>` keys; `retire` moves an active id
  to `[[revoked]]`, requires an active survivor key, records/derives the
  survivor `--vouched-by` id, and **re-signs** the channel partition tags and
  release tags whose only valid signer was the retired key using the vouching
  key (`--no-resign` skips and lists the affected tags). Because they modify
  `keys.toml`, `add` and `retire` require `--key`/`--key-id` and produce a
  **signed** commit (an empty roster seeded by `apr create --trust-key` is the
  only unsigned exception). These commands commit and refresh static git indexes
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
- `registry::pack` owns the release delta scheme, libgit2 full-pack generation,
  pure-Rust thin-pack generation, zstd transport compression for thin deltas, and
  libgit2 pack indexing for both full packs and completed thin deltas.
- `apr cache generate` emits static Nix-cache files for every registry-listed
  store path: `nix-cache-info`, `<storehash>.narinfo`, and `nar/*.nar.zst`.
  It fails closed when a listed store path is absent from the local Nix store,
  can upload the generated files to one or more repeatable `--upload-url`
  destinations through `aos-cache` backends while preserving the generated
  `nix-cache-info` body, can read producer upload defaults (destinations and
  auth, persisted by `apr origin config`) from `[registry.upload_auth]` in the
  selected `registries.d/<name>.toml` with env/CLI overrides, and can update
  the committed root `registry.toml` `[[caches]]` pointer.
- `apr origin upload` uploads the full dumb-HTTP git origin surface to one or
  more repeatable backend URLs (or the `upload_urls` persisted by
  `apr origin config` when no `--upload-url` is given) after refreshing static
  git indexes. It uploads
  immutable payloads (`objects/**`, `releases/**`, and optional static-cache
  NAR/narinfo files from `--cache-dir`) before mutable surfaces (`HEAD`,
  `info/refs`, `objects/info/**`, `channels/**`, and `nix-cache-info`) and
  applies per-path cache-control/content-type metadata where the backend
  supports it.
- `apr release <semver>` is the guarded producer orchestrator. It can release an
  already committed registry tree or optionally publish a real Nix store path
  first, stages static Nix-cache files internally when publishing store roots,
  commits the `[[caches]]` pointer before signing, creates/reuses the signed
  semver tag, generates full packs plus `.idx` files at `X.Y.0` anchors and
  compressed guaranteed thin deltas, refreshes static git indexes, initializes or advances
  channel partitions without partition decrements, and uploads cache payloads
  plus the static origin to repeatable backend URLs in producer-safe order. It
  has a local publisher lock,
  `--dry-run`, `--no-skip`, and `--resume` for interrupted immutable artifact
  generation.

---

## 4. Consumer state

`apm update` routes both HTTP and native git transports through
`registry::git::sync_git`:

1. Normalize the origin URL.
2. **Assemble the trusted key set** for the registry: every key in
   `trusted-keys.d` (`KeyStore::lookup_all`, with `# revoked:` exclusions
   applied), falling back to the `[registry.signing] public_key` config anchor
   **only when that set is empty**. Signing is enforced unless
   `[registry.signing] required = false`; if it is enforced and the set is
   empty, sync **fails closed** with an instruction to pin a key — there is no
   silent trust-on-first-use.
3. Preflight sha256-capable Git and, for plain `http(s)://`, the git-native
   dumb-HTTP origin shape.
4. Ensure the local bare repo exists with sha256 object format.
5. Fetch branch/tag refs with git.
6. Resolve the target commit from the requested tracking mode.
7. **Verify the new head commit** against the trusted set (any key in the set
   satisfies the signature) before trusting any tree content.
8. Enforce fast-forward from the last synced commit.
9. **Load, validate, and pin the `keys.toml` roster** committed at the verified
   head: write its active keys into the writable `trusted-keys.d`, drop pins no
   longer active, and mask any revoked key still present in a read-only anchor
   with a `# revoked:` line. A missing or empty roster under enforcement is a
   hard error.
10. Verify trust for the resolved target against the **post-pin** trusted set:
    - branch/tag/version/commit modes verify the commit signature when required;
    - channel mode verifies the signed partition tag, signed semver tag, and
      commit chain with name-binding.
11. Extract `packages/` and `store/` to the remote metadata cache.
12. Extract committed root `registry.toml`, `keys.toml`, and `.gitattributes`
    so `[[caches]]` are available to NAR mirror resolution and trust-roster
    helpers can read the authenticated tree after sync.
13. Persist registry state.

Continuity is enforced by steps 7–8 together: a roster change is accepted only
when the introducing commit fast-forwards the prior head **and** is signed by a
key the client already trusted, even if the new active set is disjoint from the
old one. This makes multi-maintainer rotation and revocation reach machines
in-band on their next sync. First contact is verified out of the box when the
trust anchor is baked into the image (§6).

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
  verifies git signatures against a **set** of trusted keys
  (`verify_commit_signature`/`verify_tag_signature` take `trusted_keys: &[String]`
  and write one allowed-signers line per key; an empty set is an error). A
  signature is valid iff it matches **any** currently-trusted key, which is what
  lets overlapping maintainer keys both verify.
- The trusted-key store is a search path whose first directory is **writable**
  (roster pins, `apr trust pin`) and the rest **read-only** (the image-baked
  anchor). `KeyStore::lookup_all` returns every key with `# revoked:` exclusions
  applied; a revoked key still present in a read-only anchor is masked by a
  `# revoked:` line in the writable store. Both scopes are rooted at
  `APM_SYSTEM_CONFIG_DIR` (default `/etc/apm`), so a non-empty absolute override
  redirects `registries.d` and `trusted-keys.d` for development on non-AOS hosts.
- Bootstrap trust is delivered **out-of-band**, never by silent TOFU: the
  `aos.apm.registries` module (`modules/base/apm-registries.nix`) bakes
  `/etc/apm/registries.d/<name>.toml` and `/etc/apm/trusted-keys.d/<name>.pub`
  into the image; alternatively an operator runs `apr trust pin`, or sets
  `[registry.signing] public_key` (consulted only when the store is empty).
- `registry::keys` parses committed `keys.toml`, and `pin_rotated_keys` writes a
  verified roster's active set into the writable store during sync (rotation
  overlap, stale-pin removal, revocation masking).
- `apr trust pin/list/remove` manages local `trusted-keys.d/<registry>.pub`
  anchors. Re-running `pin` appends an overlap key; `pin --replace` is the
  explicit out-of-band re-pin path for compromised-key recovery.
- `apr keys generate/list/add/retire` is the producer-side roster surface (§3).
  Roster-modifying commands sign their commits; retirement re-signs affected
  tags. Release/channel signing can select a committed active key id via
  `--key-id`, with the local private key path stored outside the registry in
  `[registry.signing_keys]`.
- `registry::verify` parses tag objects, enforces name-binding, verifies
  `tag -> tag -> commit` release chains against the trusted set, and rejects
  non-semver release names where semver is required.
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
store-path collection and committed-cache-pointer tests. The VM check
`checks.vm.apm.registry-validation-stock-nix-backend-array` validates the
stock-Nix substituter path and mixed cache upload destinations by creating a
tiny fixed-output path inside the VM, generating signed static cache files,
cache to `file://`, S3-compatible, and SFTP destinations. This passed on a
remote KVM builder on 2026-06-08 with output
`/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`.
The lower-level Rust real-Nix e2e remains opt-in behind
`AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` for local debugging because it mutates the
host Nix store.
