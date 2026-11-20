# Registry implementation

This page maps the registry design onto the code: the producer in
`crates/registry/aos-registry-authoring` (`apr`), the consumer in
`crates/registry/aos-registry-client` with installation in
`crates/packages/aos-package-manager` (`apm`), and the shared, wasm-clean wire
reader in `crates/registry/aos-registry-format`. The design itself is described
in [`architecture.md`](architecture.md), [`http-layout.md`](http-layout.md),
[`versioning-and-channels.md`](versioning-and-channels.md),
[`packs-and-deltas.md`](packs-and-deltas.md), and [`nix-cache.md`](nix-cache.md).

All paths below are relative to the repo root unless noted.

---

## 1. Registry contents

An AOS registry is a git repository of package metadata:

- `registry.toml` at the repo root contains `[registry]` metadata and the
  `[caches]` stack of Nix archive (NAR) cache pointers.
- `keys.toml` is the committed registry trust roster for rotation and
  revocation.
- `packages/<letter>/<name>.toml` stores package metadata in the nested
  `[package]` / `[[versions]]` / `[versions.platforms.<platform>]` shape parsed
  by `registry/parse.rs`.
- `store/<2-char>/<ia>` stores the realisation graph: blessed NAR bytes,
  dependency edges, and content addresses per store path.

The producer creates sha256 git repositories and refreshes the static object
indexes needed by dumb HTTP. Neither tool runs a `git` binary: repository
access goes through libgit2 (`registry::repo` for the consumer,
`registry::porcelain` for the producer), and the `gitcmd` modules that build
`git` command lines are compiled only for tests.

The consumer syncs `git://` / `git+*://` origins with libgit2's smart
transport and plain `http(s)://` origins with the pure-Rust static reader in
`registry::dumb_http`, since libgit2 does not speak dumb HTTP. For plain
`http(s)://` origins it first checks for the git-native dumb-HTTP files
(`HEAD` and `info/refs`). Bundle-only origins that expose
`bundle-list.toml` are rejected; there is no bundle/`creation_token` fallback.

---

## 2. CLI boundaries

Independent `apm` and `apr` parsers call shared library implementations.
Consumer registry configuration is available below `apm registry`; producer
operations are available only through `apr`. `aos` has no package subcommand,
and private on-host lifecycle operations run through `aos-package-runtime`.

| Piece | Location |
|---|---|
| `apm` and `apr` top-level parsers (`ApmCli`, `AprCli`) | `crates/cli/aos-cli/src/cli/mod.rs` |
| `apr` subcommands (`RegistryCommand`) | `crates/registry/aos-registry-authoring/src/commands.rs` |
| `apm` subcommands (`PackageCommand`, `ApmRegistryCommand`) | `crates/packages/aos-package-manager/src/lib.rs` |
| `apr` command handlers | `crates/registry/aos-registry-authoring/src/registry_ops/`, re-exported by `registry_ops.rs` |

AOS-specific release planning and qualification run through
`aos maintain release`, using shared libraries; there is no `aos release`
command.

---

## 3. Producer

What each `apr` command does is described once, in the command table of
[`publishing.md`](publishing.md) §2; roster maintenance and key selection
(`--key` / `--key-id`) are specified in
[`signing-and-trust.md`](signing-and-trust.md) §2.2 and §2.5. This section maps
the commands onto modules.

Command handlers, under
`crates/registry/aos-registry-authoring/src/registry_ops/`:

| Commands | Module |
|---|---|
| `apr create` | `lifecycle.rs` |
| `apr keys ...`, `apr trust ...` | `trust.rs` |
| `apr publish` | `publish.rs` |
| `apr commit`, `apr push` | `workflow.rs` |
| `apr store ...` | `store_commands.rs` |
| `apr tag`, `apr sign` | `tags.rs` |
| `apr channel ...` | `channels.rs` |
| `apr cache ...`, `apr origin ...` | `distribution.rs` |
| `apr release` | `release.rs` |

Libraries the handlers call:

- `registry::objectstore` (in `aos-registry-client`) owns sha256 object-format
  checks, release object-dir paths, loose-object path validation, relative
  alternates, and the `info/refs` / `objects/info/packs` writer. Every command
  that adds commits or moves refs refreshes these files afterward.
- `registry::pack` owns the release delta scheme, libgit2 full-pack generation,
  zstd transport compression for thin deltas, and libgit2 pack indexing for
  both full packs and completed thin deltas; `registry::thinpack` is the
  pure-Rust thin-pack writer.
- `registry::nixcache` generates the static Nix cache for `apr cache generate`
  and updates the committed `[caches]` pointer; uploads go through
  `aos-nix-cache` backends.
- `registry::static_upload` collects and uploads the static git origin for
  `apr origin upload`: immutable payloads first, replaceable pointers last,
  with per-path cache-control and content-type metadata where the backend
  supports it.
- `apr release <semver>` is the guarded orchestrator over all of the above. It
  holds a local publisher lock and supports `--dry-run`, `--no-skip`, and
  `--resume` for interrupted immutable artifact generation.

---

### Unpublished release candidates

`apr release <version> --stage <id>` retains an isolated candidate with an exact
inventory. `apr stage list` and `apr stage show <id>` report it;
`apr stage discard <id> --stage-revision N` checks the observed revision before
discard. Candidate update, resume, and finalization name `--stage-revision`;
`--from-stage <id>` selects the reviewed revision for release.

An unfinished stage does not move published default catalogs or channel
partitions. Maintainer branches are workspaces; configured channel branch
names reserve the frontier schema. Direct refs/digests/cache URLs may expose
candidate bytes. Stages work without a Hub, and Hub permissioned views use the
same inventory and revision contract. See [release stages](release-stages.md).

## 4. Consumer

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
3. For plain `http(s)://`, check the git-native dumb-HTTP origin shape.
4. Ensure the local bare repo exists with sha256 object format.
5. Resolve the tracking mode; with no tracking field set, discover the
   origin's default channel from its symbolic `HEAD` and track that channel.
6. Fetch the refs the tracking mode needs.
7. **Verify the roster head commit** against the trusted set (any key in the
   set satisfies the signature) before trusting any tree content.
8. Enforce fast-forward of the roster head from the last verified roster
   commit.
9. **Load and validate the `keys.toml` roster** committed at the verified
   head. Its active keys become the **post-pin** trusted set. A missing or
   empty roster under enforcement is a hard error.
10. Resolve and verify the selected release against the post-pin trusted set:
    - every mode verifies the selected commit's signature and fast-forward
      from the previously selected commit;
    - channel mode verifies the signed partition tag, signed semver tag, and
      commit chain with name-binding, then fetches the release's objects;
    - AOS-TUF (The Update Framework) metadata is verified, with timestamp
      expiry enforced unless the tracking mode is an immutable pin.
11. Extract `packages/`, `store/`, and declared provenance to the remote
    metadata cache.
12. Extract committed root `registry.toml`, `keys.toml`, and `.gitattributes`
    so the `[caches]` stack is available to NAR mirror resolution and
    trust-roster helpers can read the authenticated tree after sync.
13. **Pin the roster**: write its active keys into the writable
    `trusted-keys.d`, drop pins no longer active, and mask any revoked key
    still present in a read-only anchor with a `# revoked:` line.
14. Persist registry state.

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
full-pack anchor plus a forward delta, and finally falls back to a plain fetch
of the release tag, the dumb-HTTP loose-object correctness floor
([`packs-and-deltas.md`](packs-and-deltas.md) §4).

Channel e2e coverage includes torn-publish safety: an early mutable partition
that names an unpublished release is skipped in favor of the old usable
partition/floor, and an interleaved stale-publisher overwrite is rejected as a
rollback while preserving the newer floor.

---

## 5. Registry config and state

Per-registry config files live under `registries.d/<name>.toml`, read from
every configuration layer (`/etc/apm`, `/var/lib/apm/config`, and for user
scope `~/.config/apm`) and merged per file stem. The mutable
`[registry.state]` section (`RegistryState`,
`crates/registry/aos-registry-format/src/consumer.rs`) records:

```toml
[registry.state]
last_commit = "<sha256 commit>"
selected_channel = "stable"
default_channel = "stable"
last_roster_commit = "<sha256 commit>"
floor = "1.4.2"
bucket = 183
retained = ["1.0.0", "1.4.0", "1.4.2"]
last_update = "2026-02-16T12:00:00Z"
tuf_root_version = 3
tuf_targets_version = 41
tuf_snapshot_version = 41
tuf_timestamp_version = 977
```

| Field | Meaning |
|---|---|
| `last_commit` | Selected commit of the last sync; the base for the selected-release fast-forward check. |
| `selected_channel` | The channel being tracked, whether named in config or discovered from `HEAD`. |
| `default_channel` | Set only when no tracking field is configured: the discovered default channel, kept so a later `HEAD` change does not silently move the host. |
| `last_roster_commit` | Last verified trust-roster commit, advanced independently of the selected release. |
| `floor` | The semver anti-rollback floor. |
| `bucket` | The persisted rollout partition (0-255). |
| `retained` | Release versions kept locally as delta bases; for a patch release, the minimum `{X.0.0, X.Y.0, X.Y.Z}` set. Other release object directories are pruned. |
| `last_update` | The local freshness clock. For channel tracking, first sync and semver advancement refresh it; an unchanged but valid signed channel target is accepted only while this timestamp is within `max_staleness_seconds`, and does not refresh it. |
| `tuf_*_version` | Highest accepted version of each AOS-TUF role's metadata, the floor for the next sync. |

---

## 6. Signing and trust

- `security.rs` parses `registry:Ed25519:<base64>` keys, stores trusted keys,
  and verifies git signatures against a **set** of trusted keys
  (`verify_commit_signature`/`verify_tag_signature` take `trusted_keys:
  &[String]` and check the object's SSHSIG (OpenSSH signature) in-process
  against each key; an empty set is an error). A signature is valid when it
  matches **any** currently-trusted key, which is what lets overlapping
  maintainer keys both verify.
- The trusted-key store is a search path whose first directory is **writable**
  (roster pins, `apr trust pin`) and the rest **read-only** (the image-baked
  anchor). `KeyStore::lookup_all` returns every key with `# revoked:` exclusions
  applied; a revoked key still present in a read-only anchor is masked by a
  `# revoked:` line in the writable store. The read-only anchor is rooted at
  `APM_SYSTEM_CONFIG_DIR` (default `/etc/apm`), so a non-empty absolute override
  redirects its `registries.d` and `trusted-keys.d` for development on non-AOS
  hosts.
- Bootstrap trust is delivered **out-of-band**, never by silent
  trust-on-first-use (TOFU): the `aos.apm.registries` module
  (`modules/base/apm-registries.nix`) bakes `/etc/apm/registries.d/<name>.toml`
  and `/etc/apm/trusted-keys.d/<name>.pub` into the image; alternatively an
  operator runs `apr trust pin`, or sets `[registry.signing] public_key`
  (consulted only when the store is empty).
- `registry::keys` parses committed `keys.toml`, and `pin_rotated_keys` writes a
  verified roster's active set into the writable store during sync (rotation
  overlap, stale-pin removal, revocation masking).
- `apr trust pin/list/remove` manages local `trusted-keys.d/<registry>.pub`
  anchors. Re-running `pin` appends an overlap key; `pin --replace` is the
  explicit out-of-band re-pin path for compromised-key recovery.
- `apr keys generate/list/add/retire` is the producer-side roster command set.
  Roster-modifying commands sign their commits; retirement preserves release
  identities and rejects lost active-key release trust by default. Release/channel signing can select a committed active key id via
  `--key-id`, with the local private key path stored outside the registry in
  `[registry.signing_keys]`.
- `registry::verify` parses tag objects, enforces name-binding, verifies
  `tag -> tag -> commit` release chains against the trusted set, and rejects
  non-semver release names where semver is required.
- `apr tag --key` and channel partition commands create signed tag objects.
  `apr sign <tag> --key` is restricted to nonrelease maintenance tags.

---

## 7. NAR downloads and Nix-cache compatibility

The `apm` NAR downloader is narinfo-driven:

- It fetches `<store-hash>.narinfo` from the selected cache base.
- It downloads the NAR path named by the narinfo `URL:` field.
- It verifies the compressed file against `FileHash` when present, falling back
  to `NarHash` for uncompressed NARs.

Shared formatting and signing logic lives in `aos_nar::cache`:
`render_static_narinfo`, `nix_cache_info`, `nar_url`, and `NarInfoSigner`.
`aos-build-server` calls that shared library for its live cache responses, while
`apr cache generate` calls the same library offline to write the static cache.

The generated narinfo layout is covered by round-trip tests and a stock-Nix
fingerprint signature verification test; the producer-side path is covered by
store-path collection and committed-cache-pointer tests. The VM check
`checks.vm.apm.registry-validation-stock-nix-backend-array` validates the
stock-Nix substituter path and mixed cache upload destinations by creating a
tiny fixed-output path inside the VM, generating signed static cache files,
and uploading them to `file://`, S3-compatible, and SFTP destinations.
The lower-level Rust real-Nix e2e remains opt-in behind
`AOS_PACKAGE_TEST_REAL_NIX_CACHE=1` for local debugging because it mutates the
host Nix store.
