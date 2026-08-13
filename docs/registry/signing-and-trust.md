# Signing & Trust

> **Status:** Reference. Grounded in
> [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md) §11 and §5
> and the **Registry PKI v1** work (multi-maintainer signing keys, the baked image
> trust anchor, and in-band roster distribution), which is now **implemented** — see
> §2.5–§2.7 and the §9 status table. Where this doc cites current code, the code wins
> for *current state*; the brief wins for *target intent*.
>
> **Audience:** implementers, architects, engineers.

This document defines how the AOS registry establishes trust: what is signed, what is
not, the verification chain a consumer walks, and the anti-rollback discipline that
keeps a fleet moving forward. The registry is a **bare git repository (sha256 object
format) served over dumb HTTP**; trust is rooted entirely in **signed git tag
objects**. See [`architecture.md`](architecture.md) for the broader picture and
[`http-layout.md`](http-layout.md) for the byte-level object layout.

Related siblings:
[`versioning-and-channels.md`](versioning-and-channels.md) (the 256-partition rollout
and bucket selection), [`publishing.md`](publishing.md) (how the producer signs and
advances partitions), and
[`nix-cache-compatibility.md`](nix-cache-compatibility.md) (the NAR cache that reuses
the same key).

---

## 1. What is signed (and what is not)

The registry has three ref layers. Only the **tag objects** are signed; branch refs
are unsigned convenience pointers and are **never** part of the trust chain.

| Path / ref | What | Signed? | In trust chain? | Consumer |
|---|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` (e.g. `stable`) | no | no | stock git + AOS |
| `refs/heads/<channel>` | channels are **branches**; head = **frontier** | no (ref pointer) | **no** | stock git convenience |
| `refs/tags/<semver>` | release: signed annotated tag → commit | **yes** | **yes** | stock (`verify-tag`) + AOS |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (tag name == channel name) → semver tag | **yes** | **yes** | AOS rollout only |

Key consequences:

- **Branch refs carry no authority.** `refs/heads/<channel>` is just a 64-hex pointer
  at the rollout **frontier** (the newest release any partition targets). A stock
  `git pull <channel>` follows it without rollout protection — acceptable, because
  rollout is an AOS-fleet concept, not a git-clone concept. Trust derives from the
  signed tags only.
- **Releases are independently verifiable by stock git.** Because the release tag
  `refs/tags/<semver>` is itself the signed object, any third party can run
  `git verify-tag <semver>` against the trusted key without any AOS tooling.
- **Channel partition tags are AOS-only.** They live *outside* the ref namespace at
  `/channels/<name>/<00..ff>` (256 files), so they never appear in `info/refs` and a
  stock dumb clone never sees them.
- **The tree binds content, not just names.** The signed commit's tree carries the
  `store/` realisation graph (blessed bytes + dependency edges + content
  addresses for every published closure member, [`repo-layout.md`](repo-layout.md) §5, RFC-0005), so the signature vouches for the
  exact NAR bytes of the whole dependency graph - input-addressed store-path names
  alone would only bind the graph's *shape*. Cache-served narinfos are advisory
  transport metadata, never a trust source.

---

## 2. Signing primitives

The cryptographic primitive is **kept unchanged** by the registry design. The
implemented registry model signs tag objects chained `tag → tag → commit`
instead of relying on signed commits for release authority.

### 2.1 Key format — `name:Ed25519:<base64>`

A signing key is a single line, `registry:algorithm:base64key`, parsed by
`parse_signing_key` in
[`crates/aos-package/src/security.rs:575`](../../crates/aos-package/src/security.rs).
The parser is strict:

- splits on `:` into exactly three fields;
- rejects an empty registry name or empty key;
- **rejects any algorithm other than `Ed25519`** — the only supported algorithm.

```
aos-core:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAI...base64...
└──┬───┘ └──┬──┘ └────────────────┬──────────────────┘
registry  algo            base64 public key
```

The short display **fingerprint** is the first 8 hex chars of the SHA-256 of the
decoded key bytes (`key_fingerprint`, `security.rs:603`).

Maintainers generate keys with **`apr keys generate <id>`** rather than calling
`ssh-keygen`: it builds an Ed25519 keypair in-process via the hermetic `sshkey`
module ([`crates/aos-package/src/sshkey.rs`](../../crates/aos-package/src/sshkey.rs),
`Ed25519Keypair::generate`), writes the OpenSSH private key to
`$XDG_CONFIG_HOME/apm/keys/<registry>-<id>.key` (mode `0600`, dir `0700`, refusing
to overwrite), records the path in `[registry.signing_keys]` so `--key-id <id>`
resolves it, and prints the public key in `registry:Ed25519:<base64>` form plus its
fingerprint. The private key never leaves the maintainer's machine. See §7.1 of
the PKI design and [`publishing.md`](publishing.md).

### 2.2 SSH-format Ed25519 git signatures

Git is configured for SSH signing (`gpg.format = ssh`). Signature production now
uses **signed annotated tag objects** (`git tag -s <name>`, with an optional
freeform `-m <message>`), not signed commits. `apr tag <name> --key <key>` creates
a signed release tag; `apr sign <tag> --key <key>` re-signs an existing release
tag object. Both commands also accept `--key-id <id>`, which resolves `<id>`
through the committed active `keys.toml` roster and the producer's local
`registries.d/<name>.toml` `[registry.signing_keys]` private-key map. Channel
partition signing uses the same `--key` / `--key-id` rules for
`apr channel init` and `apr channel advance`. `--key` and `--key-id` are
mutually exclusive.

```toml
[registry.signing_keys]
initial = "/run/secrets/aos-core-initial"
next = "/run/secrets/aos-core-next"
```

A signed tag carries **no structured payload** — it is a pure signed pointer
(standard git tag fields: `object`, `type`, the tag **name**, `tagger`) plus the
Ed25519 signature and an optional human-readable message. The signature
algorithm, key format, and trust store are unchanged.

Because registry repositories use Git's sha256 object format, clients need
**Git 2.42.0 or newer**. `apm update` enforces this before fetching by checking
`git --version` and probing `git init --bare --object-format=sha256`; stock
`git verify-tag` / `git clone` users need the same floor.

### 2.3 Verification — `git verify-*` against a **key set**

Verification takes a **non-empty set of trusted keys**, not a single key — this is
what lets any of several overlapping maintainer keys (the `keys.toml` roster, §2.5)
satisfy the chain. Both
`verify_commit_signature`
([`security.rs:455`](../../crates/aos-package/src/security.rs)) and
`verify_tag_signature` ([`security.rs:490`](../../crates/aos-package/src/security.rs))
take `trusted_keys: &[String]` (each in `registry:Ed25519:<base64>` form). They:

1. write a temporary allowed-signers file with **one line per trusted key**
   (`write_allowed_signers`, `security.rs:424`), each of the form
   `registry ssh-ed25519 <base64>`;
2. run `git -c gpg.ssh.allowedSignersFile=<tmp> verify-commit <commit>` /
   `verify-tag <tag>` and return `Ok(true)` iff the process exits zero — i.e. the
   signature matches **any** listed key.

An **empty key set is a hard error, never a pass** (`write_allowed_signers`,
`security.rs:424`). A signature is therefore valid iff it was made by a key the
caller currently trusts; because the caller supplies only the post-pin trusted set
(§2.6), signatures by a revoked key **fail closed**. The principal in each
allowed-signers line is the literal token `registry`, not the registry's name.
Stock git users run `git verify-tag` themselves with the trusted key in their own
allowed-signers file.

### 2.4 Trust store — `trusted-keys.d` (writable pins + read-only anchor)

Trusted keys live on disk as `<registry>.pub` files inside a **search path** of
directories, managed by `KeyStore`
([`security.rs:74`](../../crates/aos-package/src/security.rs)). The **first**
directory in the path is the **writable** store (where roster pins and `apr trust`
land); the rest are **read-only**, including the image-baked anchor (§2.6). The
path depends on the profile scope (`ProfileScope::trusted_keys_dirs`,
[`types.rs:665`](../../crates/aos-package/src/types.rs)):

- **User scope:** `$XDG_CONFIG_HOME/apm/trusted-keys.d` (writable), then
  `/etc/apm/trusted-keys.d` (read-only anchor).
- **System scope:** `/etc/apm/trusted-keys.d` (writable), then
  `/var/lib/apm/trusted-keys.d` (read-only).

The `/etc/apm` root is the value of `APM_SYSTEM_CONFIG_DIR` (§2.7), so both scopes
can be redirected for development on non-AOS hosts.

`KeyStore` reads keys with:

- `lookup_all` ([`security.rs:103`](../../crates/aos-package/src/security.rs)) —
  returns **every** key for a registry across **all** directories (the multi-line
  rotation-overlap format), applying the `# revoked:` exclusions described below.
- `lookup` (`security.rs:88`) — the first key only.
- `store` (`security.rs:159`) — persists a key to the writable directory, writing
  the canonical `registry:Ed25519:<base64>` line.
- `sync_registry_keys` (`security.rs:225`) — rewrites the writable store to match a
  freshly-verified roster (used by roster pinning, §2.6).

`apr trust` is the supported manual trust-store CLI:

- `apr trust pin <registry> <registry:Ed25519:<base64>>` writes the key to the
  writable `trusted-keys.d` directory. Re-running `pin` with a distinct key
  appends it, which supports overlap during key rotation.
- `apr trust pin <registry> <key> --replace` removes existing local pins first,
  the explicit out-of-band re-pin path for compromised-key recovery.
- `apr trust list [registry]` prints pinned keys and fingerprints.
- `apr trust remove <registry>` (alias: `unpin`) removes local pinned keys.

**Masking read-only anchor keys (`# revoked:`).** Keys in read-only directories
(notably the image-baked `/etc/apm/trusted-keys.d` anchor) are **never modified**
by sync. To stop trusting a key that still appears in a read-only anchor file, the
writable store records a `# revoked: <key>` comment line; `lookup_all`
(`security.rs:103`) filters any key matching such a line out of its result
(`parse_revoked_line`, `security.rs:350`; `REVOKED_LINE_PREFIX`, `security.rs:59`).
Files with no such comment are parsed exactly as before, so the format is
backward-compatible.

**No silent Trust-On-First-Use during sync.** A `tofu_check`
([`security.rs:382`](../../crates/aos-package/src/security.rs)) primitive still
exists (and is exercised by tests), but the registry **sync path no longer accepts
a key on first use**: if signing is enforced and the assembled trusted set is empty,
`sync_git` **aborts** with an instruction to pin a key or configure an anchor
(§2.6). Bootstrap trust must arrive out-of-band — the image-baked anchor (§2.6), an
explicit `apr trust pin`, or the `[registry.signing] public_key` config anchor —
never from blindly trusting whatever the first sync returns.

### 2.5 The trust roster — `keys.toml` (consumed by clients)

The committed **`keys.toml` trust roster** is the **authoritative trusted-key set**.
It is a committed tree file listing the **active signing key(s)** and a **revoked
list**, authenticated like every other tree file by the signed tag
(tag → commit → tree → file). Clients now **read it during sync** and pin its active
set (§2.6) — a release or channel tag is valid when signed by **any active roster
key** (§2.3). The signing pubkey is **removed** from the committed `registry.toml` —
a key stored inside a file that is authenticated *by* that key is circular for
bootstrap. The on-disk shape and fields live in
[`repo-layout.md`](repo-layout.md) §3.

```
  baked anchor (out of band, §2.6)       keys.toml (in the committed tree)
  ┌──────────────────────────┐           ┌─────────────────────────────────┐
  │ /etc/apm/trusted-keys.d   │           │ active keys + revoked list      │
  │ (image) or `apr trust pin`│ ──verify──▶ authenticated by the signed tag │
  │ THE bootstrap root        │  the tag  │ (tag → commit → tree → file)    │
  └──────────────────────────┘           └─────────────────────────────────┘
        trust starts here                  trust EVOLVES here (rotate/revoke)
```

**The trust model: signed git lineage plus AOS-TUF release metadata.** The
out-of-band anchor and signed git lineage (signed tag → commit → parent chain),
plus the continuity rule of §2.6, authenticate the first accepted registry
commit and the `keys.toml` roster. Moving-ref release commits must also carry
AOS-TUF metadata under `tuf/`; `root.json` names role keys and thresholds,
`targets.json` hashes the non-`tuf/` catalog, `snapshot.json` binds root/targets
metadata, and `timestamp.json` gives the signed expiry/freshness pointer.

**Rotation (overlap window).** To roll a signing key forward, publish a `keys.toml`
that lists **both** the old and the new key, in a commit **signed by a currently-
trusted key**. A client that already trusts the old key verifies that commit, reads
`keys.toml`, and **pins the new key** (§2.6). A later release can then drop the old
key from the roster and sign with the new key alone. The overlap window makes the
handoff seamless: no client is ever asked to trust a key it cannot reach through a
key it already trusts.

**Planned retirement.** `apr keys retire <id> [--vouched-by <survivor-id>]` moves a
key to `[[revoked]]` in a commit **signed by one of the *other* overlapping active
keys** — a key cannot credibly revoke itself, so retirement always rides on a second
still-trusted active key. Because signatures by a revoked key are invalid (§2.3),
`retire` also **re-signs** the channel partition tags and the release tags they
reference whose only valid signer was the retired key, using the vouching key
(§2.6); `--no-resign` skips this and prints the affected tag list instead. The
revocation propagates to clients on their **next sync**, not a package upgrade.

**Compromise.** Revocation is the same `apr keys retire` operation with `--reason`.
For local recovery — e.g. if a client must drop a key that still appears in a
**read-only** baked anchor — the operator **re-pins** the writable store with
`apr trust pin --replace`, and the `# revoked:` masking (§2.4) excludes the bad key
even though the read-only anchor file is untouched.

Producer maintenance for the committed roster is `apr keys`:
`apr keys generate <id>` mints a keypair (§2.2), `apr keys add <id> <key>` appends an
active overlap key, `apr keys retire <id> …` revokes one, and `apr keys list` reports
active/revoked ids. `add` and `retire` modify `keys.toml`, so they require
`--key-id`/`--key` and produce a **signed** commit (an unsigned roster commit is
rejected by clients at §2.6); the only exception is the very first key of an empty
roster, seeded by `apr registry create --trust-key`. The commands validate key ids and
registry binding, reject duplicate/revoked ids, keep an active survivor during
retirement, and commit + refresh the git-static indexes unless `--no-commit` is
passed. Release and channel signing select a committed active roster id with
`--key-id <id>` (must exist, not be revoked, belong to the registry, and have a local
private-key path in `[registry.signing_keys]`); direct `--key <private-key-path>`
remains available for one-off signing.

This is **decided** — see [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md)
§14 (and that the roster is a standalone `keys.toml`, not a `[keys]` block in
`registry.toml`).

> **NAR safety (defence in depth).** An authenticated-but-wrong `[[caches]]` pointer
> cannot serve bad bytes: NARs are **content-addressed and SHA-256-verified** on
> download. The trust that actually matters is the **tag/commit chain governed by
> `keys.toml`**, not the cache list — a mis-signed or mis-pointed cache yields a hash
> mismatch and a rejected fetch, not a compromised closure. See
> [`repo-layout.md`](repo-layout.md) §3 and
> [`nix-cache-compatibility.md`](nix-cache-compatibility.md).

### 2.6 Roster consumption during sync — continuity enforcement + the baked anchor

`sync_git` ([`registry/git.rs:85`](../../crates/aos-package/src/registry/git.rs))
consumes the roster on every sync. Signing is **enforced by default**: an absent
`[registry.signing]` section verifies (`signing_enforced`, `git.rs:299`); only
`required = false` opts out. The steps, in order:

1. **Assemble the prior trusted set `T`** (`assemble_trusted_set`, `git.rs:314`):
   every key from `KeyStore::lookup_all(registry)` (all dirs, `# revoked:`
   exclusions applied). Only when that is **empty** is the `[registry.signing]
   public_key` config entry consulted as a **bootstrap anchor**. (Unioning it
   unconditionally would keep a revoked config key trusted forever.)
2. **Fail closed on no anchor.** If signing is enforced and `T` is empty, abort with
   an instruction to `apr trust pin` or configure an anchor — there is no silent TOFU.
3. **Fetch** refs and resolve the new head commit.
4. **Verify the new head commit** against `T` (any-active-key, §2.3;
   `verify_head_commit`, `git.rs:329`). Failure aborts; the previously synced state
   stays in use.
5. **Enforce fast-forward** from the recorded previous head (existing anti-rollback).
6. **Load + validate the roster** at the verified head (`apply_roster`, `git.rs:358`):
   schema is 1, `active` is non-empty, keys parse and their embedded registry name
   matches. A missing/empty roster under enforcement is a misconfigured registry, not
   a pass.
7. **Pin the roster** (`pin_rotated_keys`,
   [`registry/keys.rs:134`](../../crates/aos-package/src/registry/keys.rs)): write all
   active keys into the **writable** `trusted-keys.d`, drop pins absent from the new
   active set, and mask any now-revoked key still present in a **read-only** anchor via
   a `# revoked:` line (§2.4).
8. **Re-verify the channel/release tag chain** (§3) against the **post-pin** trusted
   set, so a roster change takes effect within the same sync.

**Continuity** is the conjunction of steps 4 and 5: a roster change is accepted only
when it extends the history the client already verified **and** is signed by a key the
client already trusted — even if the new active set is entirely disjoint from `T`,
because the *introducing* commit was signed by a key in `T`. A replayed older history
fails step 5; a forged roster fails step 4.

**The baked image anchor.** First contact is verified out of the box because the
out-of-band anchor is **baked into the AOS image**. The module
[`modules/base/apm-registries.nix`](../../modules/base/apm-registries.nix) defines
`aos.apm.registries.<name>` with `url`, a non-empty `trustKeys` list, `required`
(default `true`), and `priority`. For each entry it emits two `environment.etc`
files:

- `/etc/apm/registries.d/<name>.toml` — the registry config, with
  `[registry.signing]` `required` and `public_key` set to the **first** `trustKeys`
  entry (the bootstrap anchor of step 1);
- `/etc/apm/trusted-keys.d/<name>.pub` — **all** `trustKeys`, one per line (the
  read-only anchor file `lookup_all` reads, supporting rotation overlap).

An eval-time assertion requires every `trustKeys` entry to parse as
`<name>:Ed25519:<base64>` with the prefix equal to the attribute name. Updating the
baked anchor is an ordinary image rebuild; **day-to-day rotation reaches deployed
machines in-band (steps 1–8) without an image change**. `apm registry add --no-verify`
is the inverse for local development: it writes `[registry.signing] required = false`
so an unsigned/dev registry syncs without an anchor.

### 2.7 `APM_SYSTEM_CONFIG_DIR`

The system config root defaults to `/etc/apm` but honors the
`APM_SYSTEM_CONFIG_DIR` environment variable when it is set to a **non-empty
absolute path** (`resolve_system_config_dir`,
[`types.rs:31`](../../crates/aos-package/src/types.rs); resolved once per process and
cached, `apm_system_config_dir`, `types.rs:52`). Relative or empty values are
ignored so a stray `APM_SYSTEM_CONFIG_DIR=` cannot redirect trust to an unexpected
place. It affects **every** derived system path — `registries.d`, `trusted-keys.d`,
and the rest — in **both** profile scopes, and is the supported way to point
`apm`/`apr` at a writable fixture tree when developing on NixOS or macOS. User-scope
paths continue to honor `XDG_CONFIG_HOME`. The variable is documented in the
`apm`/`apr` `--help` output.

---

## 3. The trust chain — `tag → tag → commit` with name-binding

AOS verification is a **two-hop signed-tag chain** anchored at the consumer's
deterministically-selected channel partition (see
[`versioning-and-channels.md`](versioning-and-channels.md) for bucket selection):

```
  /channels/<name>/<bucket>          refs/tags/<semver>            commit
  ┌────────────────────────┐        ┌────────────────────┐       ┌──────────┐
  │ SIGNED partition tag    │ ────▶ │ SIGNED release tag  │ ────▶ │  commit  │
  │ object                  │ refs  │ object              │ refs  │  (tree)  │
  │ tag-name == <name>      │       │ tag-name == <semver>│       │          │
  │ (pure signed pointer)   │       │ (pure signed ptr)   │       │          │
  │ Ed25519 SSH signature   │       │ Ed25519 SSH sig     │       │          │
  └────────────────────────┘        └────────────────────┘       └──────────┘
        hop 1: verify sig                hop 2: verify sig
        + name == channel name           + name == semver
```

Each hop performs **two** checks; both must pass:

1. **Signature check** — the tag object's SSH-format Ed25519 signature verifies
   against **any key in the trusted set** (the post-pin roster set, §2.6) via the
   `git verify-tag` / `allowed_signers` mechanism of §2.3.
2. **Name-binding check** — the **embedded tag-name field** inside the tag object
   equals the **expected name for its serving path**:
   - under `/channels/<name>/<00..ff>`, every one of the 256 partition tags must have an
     embedded tag name **== `<name>`** (the channel name);
   - under `/releases/<major>/<minor>/<patch…>/` (i.e. `refs/tags/<semver>`), the
     embedded tag name **== `<semver>`**.

### 3.1 Why name-binding matters

A bare signature check answers "did the registry owner sign *some* tag?" but **not**
"is this the tag that *belongs at this path*?" Without name-binding, an attacker (or a
buggy mirror) who can rearrange static files could serve a validly-signed tag at the
wrong path — e.g. place the signed `1.0.0` release tag under
`/channels/stable/3f`, or serve the `testing` channel tag where `stable` is expected.
Both substitutions carry a genuine signature and would pass a naive verifier.

Binding the **embedded tag-name == expected path name** closes this: the tag object
itself states what it is, the signature covers that statement, and the consumer
refuses any tag whose self-declared name does not match where it was fetched from.
This prevents **cross-serving** of one signed object as another.

### 3.2 Verification pseudocode

```
fn verify_channel(registry, channel, bucket) -> Result<Semver> {
    keys  = assemble_trusted_set(registry)?        // post-pin roster set  (§2.6)

    # hop 1: the channel partition tag
    ptag  = fetch("/channels/{channel}/{bucket}")   # signed tag object
    require verify_tag_signature(ptag, keys)       # §2.3 (any active key)
    require ptag.embedded_tag_name == channel      # NAME-BINDING (channel)
    semver = ptag.target_semver                    # tag → tag

    # hop 2: the release (semver) tag
    rtag  = fetch_tag("refs/tags/{semver}")        # signed tag object
    require verify_tag_signature(rtag, keys)       # §2.3 (any active key)
    require rtag.embedded_tag_name == semver       # NAME-BINDING (semver)
    commit = rtag.target_commit                    # tag → commit

    # anti-rollback floor (§5) — never move below the persisted floor
    require semver_ge(semver, monotonic_floor())

    Ok(semver)                                     # commit is now trusted
}
```

Only after **both** hops pass (signature + name-binding) and the anti-rollback floor
(§5) is cleared does the consumer trust the underlying commit and begin fetching its
object store (packs/deltas/loose objects — see
[`packs-and-deltas.md`](packs-and-deltas.md)).

### 3.3 Branch refs are not consulted for trust

Note the chain **never** reads `refs/heads/<channel>`. The branch head is the
**frontier** (the rollout target), a convenience pointer for stock `git pull`. The
AOS consumer's authoritative target is the **partition tag for its bucket**, which may
deliberately lag the frontier during a staged rollout. See
[`versioning-and-channels.md`](versioning-and-channels.md) for the
branch-head-equals-frontier model.

---

## 4. Freshness

Signed tags carry no expiry field; a tag is a pure signed pointer (§2.2).
Moving-ref syncs require AOS-TUF metadata and enforce freshness in band by
checking `tuf/timestamp.json`, whose signed payload binds the accepted snapshot
hash and expires after the publisher's timestamp window. Explicit commit, tag,
and version pins verify TUF signatures, hashes, and metadata version floors when
TUF exists, but can reproduce old immutable pre-TUF snapshots without failing
solely on missing or expired timestamp metadata. Channel tracking also keeps the
existing pointer-level defenses:

| Mechanism | Where | What it bounds |
|---|---|---|
| **Low CDN TTL** on `/channels` (and `info/refs`, `objects/info`) | edge / CDN policy ([`http-layout.md`](http-layout.md)) | how long a stale rollout pointer can be served before the edge re-fetches the origin |
| **Consumer max-staleness policy** | client-side registry config | how long *this consumer* will trust a previously-fetched channel pointer before it MUST re-fetch and re-validate |
| **Monotonic anti-rollback floor** | consumer (§5) | the lower bound on the accepted release, regardless of pointer age |

For channel-tracked registries, `apm` records its local freshness timestamp in
`[registry.state].last_update`. The local registry config may set
`max_staleness_seconds`; when omitted, channel sync uses a 14-day default. First
sync and semver advancement refresh this timestamp. If a later channel refresh
cannot fetch refs, cannot resolve a usable signed partition, or resolves an
unchanged-but-valid signed target, `apm` compares `last_update` to that bound and
fails closed with a staleness-oriented error once the bound is exceeded.
Unchanged targets do not refresh the timestamp. A first sync has no prior
freshness observation, so a failed first refresh is also a hard failure.

The CDN policy ([`http-layout.md`](http-layout.md)) **MUST** keep `/channels` (and
`info/refs`, `objects/info`) at low TTL so a consumer re-fetches and sees rollout
advances quickly; releases under `/releases/**` are immutable and may be cached with a
long TTL. A consumer that cannot reach the origin to refresh a stale channel pointer
falls back to its anti-rollback floor (§5) and its own max-staleness policy rather than
trusting a stale pointer indefinitely.

> **Split authority:** release metadata now has signed expiry in
> `tuf/timestamp.json`, enforced when a moving ref selects a release; channel
> partition tags remain pure git tag objects, so pointer freshness is still
> bounded by CDN TTL, max-staleness, and the floor. A frozen mirror serving an
> old release commit through a moving ref is caught by TUF expiry once the
> accepted timestamp ages out. An explicit immutable pin is operator-chosen and
> remains reproducible, verifying signed metadata and catalog hashes when they
> exist without expiring old pre-cutover snapshots.

---

## 5. Anti-rollback — monotonic floor + fix-forward

A consumer must never be talked *backwards* onto an older, possibly-vulnerable
release. Two mechanisms enforce this.

### 5.1 Monotonic floor (consumer side)

Each consumer persists a **monotonic floor**: the semver of the highest release it has
ever accepted. The verification chain (§3.2) refuses any target `semver` that is
**less than** the floor — even if that older tag is perfectly signed and
name-bound. The floor advances when a newer release is accepted and **never**
retreats.

```
  floor = max(floor, accepted_release)        # only ever increases
  on each update:
      target = verify_channel(...)            # §3.2 (signature + name-binding pass)
      if semver_lt(target, floor): REJECT     # signed-but-older ⇒ refuse
      else: accept; floor = max(floor, target)
```

This makes a downgrade attack inert: serving a stale (but validly signed) partition
tag pointing at an older release is rejected by the floor.

> The current code already models the *git-ancestry* analogue of this idea:
> `check_downgrade` ([`security.rs:256`](../../crates/aos-package/src/security.rs))
> classifies a transition as `FastForward`, `SameCommit`, `Downgrade`, or `Diverged`
> via `git merge-base --is-ancestor`, and a `Downgrade` (`security.rs:291`) is the
> reject case. **TARGET:** the consumer's floor is expressed in **semver** precedence
> (semver ordering, no `v` prefix — see
> [`versioning-and-channels.md`](versioning-and-channels.md)); git ancestry remains a
> secondary sanity check where commit history is available.

### 5.2 Fix-forward (publisher side)

Because consumers enforce a floor, the publisher **cannot** abort a bad rollout by
pointing partitions back at the prior release — the floor would block consumers that
already advanced from accepting the older target anyway. Aborting a bad rollout is
therefore **fix-forward**:

```
  Bad rollout detected at 1.4.0
        │
        ├─ DO NOT decrement partitions back to 1.3.x   ✗ (floor blocks it)
        │
        └─ Publish a NEW release 1.4.1 (the fix) and
           point the affected partitions at 1.4.1       ✓ fix-forward
```

The un-advanced partitions in a staged rollout still name the **prior** release, so a
half-rolled-out bad release is naturally contained: only the buckets already advanced
need a fix-forward, the rest were never moved. See
[`versioning-and-channels.md`](versioning-and-channels.md) for the publisher's
partition-advancement model and [`publishing.md`](publishing.md) for the pipeline.

---

## 6. One key, two surfaces — git signing + Nix narinfo

A single Ed25519 key per registry covers **both** trust surfaces:

1. **Git tag signatures** — the `tag → tag → commit` chain above (the primary use).
2. **Nix narinfo `Sig:`** — if the origin *also* serves a NAR binary cache, the
   `<storehash>.narinfo` `Sig:` field can reuse the **same** Ed25519 key. The cache
   location is **not** carried in any signed tag (tags are pure pointers): it lives in
   the committed `registry.toml` `[[caches]]` (authenticated via the tag —
   [`repo-layout.md`](repo-layout.md) §2), with the consumer's client-side
   `registries.d/<name>.toml` as an optional override/supplement (higher priority
   wins). The origin MAY serve the stock-nix superset (`nix-cache-info`,
   `<storehash>.narinfo`, `nar/…`) — see
   [`nix-cache-compatibility.md`](nix-cache-compatibility.md).

These are **separate signature objects** (a git SSH-format tag signature vs. a Nix
narinfo `Sig:` line) produced by the **same** key material. A consumer that already
trusts `<registry>.pub` for git tag verification can verify NAR substitution from the
same origin without provisioning a second key. The key-management surface
(`trusted-keys.d` anchoring/pinning, the `keys.toml` roster, fingerprinting) is
shared; only the verification *call site* differs (git tag vs. narinfo).

The public-key encodings are format-specific projections of that same key: git
verification stores an SSH `ssh-ed25519` public-key blob in the
`registry:Ed25519:<base64>` AOS trust form, while stock Nix
`trusted-public-keys` uses `<name>:<base64>` with the raw Ed25519 verifying key
bytes.

---

## 7. Trust boundaries — summary table

| Concern | Mechanism | Authority? |
|---|---|---|
| Is this the registry's bootstrap key? | image-baked anchor in `/etc/apm/trusted-keys.d` (`aos.apm.registries`) or `apr trust pin` / `[registry.signing] public_key` — no silent TOFU (§2.4, §2.6) | root of trust |
| How do keys rotate / get revoked? | committed `keys.toml` trust roster (§2.5), consumed in-band under continuity enforcement (§2.6) | yes — evolves an anchored trust |
| Is this tag genuinely signed? | `git verify-tag` + temp `allowed_signers` against the **trusted set** (any active key, §2.3) | yes |
| Is this tag at the *right* path? | embedded tag-name == expected path name (channel / semver) | yes — closes cross-serving |
| Which release does my bucket get? | signed `/channels/<name>/<bucket>` partition tag (hop 1) | yes |
| Which commit is that release? | signed `refs/tags/<semver>` release tag (hop 2) | yes |
| Is the frontier branch trustworthy? | `refs/heads/<channel>` — **unsigned pointer** | **no** (convenience only) |
| Is this pointer fresh? | AOS-TUF `timestamp.json` for release metadata; low CDN TTL on `/channels` + consumer max-staleness policy + monotonic floor for rollout pointers | freshness, not forgery |
| Could I be downgraded? | consumer **monotonic floor** (semver); abort = **fix-forward** | yes |
| Are these NAR bytes the published bytes? | `store/` realisation graph in the signed tree: decompressed SHA-256 + size must match a blessed NAR; unmapped path = hard failure when the graph is published (RFC-0005) | yes - roots content at the tag signature |
| NAR substitution from same origin? | `store/` realisation graph (above); narinfo `Sig:` reusing the **one** Ed25519 key remains for stock-Nix consumers | yes |

---

## 8. Object format note — sha256

All git operations use the **sha256 object format**
(`git init --object-format=sha256`); loose object paths are the 2/62 split of the
64-hex sha256 (see [`http-layout.md`](http-layout.md)). This affects trust in two
ways:

- **Stronger content addressing.** Tag, commit, and tree object identities are
  sha256, so the signed tag's reference to its target commit (and the commit's tree)
  is bound by a modern hash.
- **No capability negotiation over dumb HTTP.** Because dumb HTTP has no capability
  exchange, the client git must natively support sha256. This is a compatibility
  edge, not a trust weakness — it is tracked as an open question
  ([`../plans/registry/open-questions.md`](../plans/registry/open-questions.md), brief
  §16.1) for tested client git versions.

---

## 9. Implementation status

| Capability | Status (code today) |
|---|---|
| Key format `name:Ed25519:<base64>` | `parse_signing_key` (`security.rs:575`) |
| Key generation | `apr keys generate` mints OpenSSH Ed25519 keys via the hermetic `sshkey` module — no `ssh-keygen` shellout (`registry_ops.rs:2922`, `sshkey.rs`) |
| Trust store | `KeyStore` writable-pin + read-only-anchor search path with `# revoked:` masking (`security.rs:74`, `lookup_all` `:103`), plus `apr trust pin/list/remove` |
| Bootstrap anchor | image-baked `aos.apm.registries` → `/etc/apm/{registries.d,trusted-keys.d}` (`modules/base/apm-registries.nix`); or `apr trust pin`; or `[registry.signing] public_key` when the store is empty. **No silent TOFU during sync** |
| Any-active-key verification | `verify_commit_signature`/`verify_tag_signature` take `trusted_keys: &[String]`; empty set is an error. CLI tests call this production verifier directly, while the focused security, Hub, and change-request interoperability tests generate stock-Git signatures to preserve the independent parser check. Nix checks route every stock-Git/OpenSSH signing fixture command through test helpers that supply the otherwise passwd-less builder identity from a repository-owned build-only preload fixture; production artifacts retain no OpenSSH or identity-shim runtime path. |
| Roster consumption (client) | `sync_git` assembles `T`, verifies the head commit, fast-forwards, validates + pins the roster, masks revoked anchor keys, re-verifies the chain post-pin (`registry/git.rs:85`,`:314`,`:329`,`:358`; `pin_rotated_keys` `registry/keys.rs:134`) |
| Strict-by-default signing | absent `[registry.signing]` enforces verification; `required = false` (or `apm registry add --no-verify`) is the only opt-out (`signing_enforced` `git.rs:299`) |
| Key rotation / revocation | `apr keys add/retire` with survivor + vouching checks; retirement re-signs affected channel/release tags via the vouching key (`--no-resign` to skip) (`registry_ops.rs:2551`,`2742`,`2815`) |
| Signed roster commits | `apr keys add/retire` require `--key`/`--key-id` and produce signed `keys.toml` commits (`resolve_roster_commit_key` `registry_ops.rs:3059`) |
| Signature *production* | `apr tag` / `apr sign <tag>` create signed release tag objects; `apr channel init/advance` writes signed partition tag files; all accept `--key` or roster-backed `--key-id` |
| What is signed | **`tag → tag → commit`** chain (partition + release tags), plus signed `keys.toml` commits |
| Name-binding | embedded tag-name == expected path name (channel / semver) |
| Anti-rollback | semver monotonic floor + fix-forward |
| Dev config root | `APM_SYSTEM_CONFIG_DIR` redirects `/etc/apm` for both scopes (`types.rs:31`,`:52`) |
| Nix narinfo `Sig:` | `NarInfoSigner` signs static narinfos during cache generation; the same Ed25519 key projects from git SSH tag signing to Nix narinfo signing |

The full implementation plan for this surface is
[`../plans/registry/workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md).
Historical removed concepts are listed in design-brief §15.

---

## See also

- [`README.md`](README.md) — registry doc index and glossary.
- [`architecture.md`](architecture.md) — git-over-dumb-HTTP, the three ref layers.
- [`repo-layout.md`](repo-layout.md) - the committed git tree: `registry.toml` (pubkey removed) + `keys.toml` trust roster + `packages/` + `store/` realisation graph.
- [`http-layout.md`](http-layout.md) — HTTP/object layout, CDN TTLs, sha256 object store.
- [`versioning-and-channels.md`](versioning-and-channels.md) — semver, channels-as-branches, 256-partition rollout, bucket selection, anti-rollback.
- [`packs-and-deltas.md`](packs-and-deltas.md) — what the verified commit's object store contains.
- [`publishing.md`](publishing.md) — producer pipeline: commit → sign → pack → advance partitions.
- [`nix-cache-compatibility.md`](nix-cache-compatibility.md) — NAR cache reusing the one Ed25519 key.
- [`current-state.md`](current-state.md) — current git-native implementation status.
- Plan: [`../plans/registry/workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md), [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md), [`../plans/registry/open-questions.md`](../plans/registry/open-questions.md).
