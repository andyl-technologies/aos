# Signing & Trust

> **Status:** TARGET reference. Grounded in
> [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md) §11 and §5
> (the authoritative target intent). Where this doc cites current code, the code wins
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

---

## 2. Signing primitives (CURRENT → TARGET)

The cryptographic primitive is **already in the codebase** and is **kept unchanged**
by this redesign. Only *what gets signed* changes: from a signed commit (current) to
signed tag objects chained `tag → tag → commit` (target).

### 2.1 Key format — `name:Ed25519:<base64>`

A signing key is a single line, `registry:algorithm:base64key`, parsed by
`parse_signing_key` in
[`crates/aos-package/src/security.rs:306`](../../crates/aos-package/src/security.rs).
The parser is strict:

- splits on `:` into exactly three fields (`security.rs:307`);
- rejects an empty registry name (`security.rs:318`) or empty key (`security.rs:321`);
- **rejects any algorithm other than `Ed25519`** (`security.rs:324`) — the only
  supported algorithm today and in the target.

```
aos-core:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAI...base64...
└──┬───┘ └──┬──┘ └────────────────┬──────────────────┘
registry  algo            base64 public key
```

The short display **fingerprint** is the first 8 hex chars of the SHA-256 of the
decoded key bytes (`key_fingerprint`, `security.rs:338`).

### 2.2 SSH-format Ed25519 git signatures

Git is configured for SSH signing (`gpg.format = ssh`). Signature *production* is
`apr sign`, which today amends the HEAD commit with `git commit --amend --no-edit -S`
in [`crates/aos-package/src/registry_ops.rs:1770`](../../crates/aos-package/src/registry_ops.rs).
Tag creation today is `apr tag`
([`registry_ops.rs:1706-1710`](../../crates/aos-package/src/registry_ops.rs)): when a
`--message` is given it runs `git tag -a <name> -m <msg>` (annotated), otherwise it
runs `git tag <name>` (lightweight). Either way it is **not yet signed** (`-s`).

**TARGET delta:** `apr sign` / the publish pipeline produces **signed annotated tag
objects** (`git tag -s <name>`, with an optional freeform `-m <message>`), not signed
commits. A signed tag carries **no structured payload** — it is a pure signed pointer
(standard git tag fields: `object`, `type`, the tag **name**, `tagger`) plus the
Ed25519 signature and an optional human-readable message. Both channel partition tags
and release tags are signed. The signature algorithm, key format, and trust store are
unchanged.

### 2.3 Verification — `git verify-*` + a temporary `allowed_signers`

Signature *verification* is `verify_commit_signature` in
[`security.rs:199`](../../crates/aos-package/src/security.rs). It:

1. parses the expected key (`security.rs:204`);
2. writes a temporary allowed-signers file of the form
   `registry ssh-ed25519 <base64>` (`security.rs:208`);
3. runs `git -c gpg.ssh.allowedSignersFile=<tmp> verify-commit <commit>`
   (`security.rs:217`) and returns `Ok(true)` iff the process exits zero
   (`security.rs:232`).

**TARGET delta:** the target verifies **tag** objects, so the equivalent helper runs
`git -c gpg.ssh.allowedSignersFile=<tmp> verify-tag <tag>` — the same allowed-signers
mechanism, the same Ed25519 key, the same temp-file pattern. The principal in the
allowed-signers line is the literal token `registry` (`security.rs:208`), not the
registry's name. (Stock git users run `git verify-tag`
themselves with the trusted key in their own allowed-signers file.)

### 2.4 Trust store — TOFU + `trusted-keys.d`

Trusted keys live on disk as `<registry>.pub` files inside a search path of
directories, managed by `KeyStore` ([`security.rs:52`](../../crates/aos-package/src/security.rs)):

- `lookup` reads `<dir>/<registry>.pub`, parses the `name:Ed25519:<base64>` line, and
  tags the first directory as the writable TOFU store, the rest as
  `PreInstalled` (`security.rs:70`).
- `store` persists a TOFU-accepted key to the first (writable) directory
  (`security.rs:97`), writing the canonical `registry:algorithm:public_key` line
  (`security.rs:107`).
- Pre-installed keys ship in `/etc/apm/trusted-keys.d/` (`KeySource::PreInstalled`,
  `security.rs:22`).

**Trust-On-First-Use** is `tofu_check` ([`security.rs:159`](../../crates/aos-package/src/security.rs)),
which returns one of three decisions:

| Decision | Meaning | Action |
|---|---|---|
| `AlreadyTrusted` | received key == stored key (`security.rs:179`) | proceed |
| `NewKey { needs_confirmation }` | no key on file (`security.rs:175`) | prompt the user, then `store` |
| `KeyMismatch { stored, received }` | a *different* key is already trusted (`security.rs:182`) | **reject** — possible key substitution |

This store and TOFU flow is **unchanged** in the target. The same `<registry>.pub`
key that anchors release/channels tag verification is the key used everywhere below.

### 2.5 The trust roster — `keys.toml` (TARGET)

Bootstrap trust is **client-side**: the `<registry>.pub` pinned in `trusted-keys.d`
via TOFU (§2.4) is the anchor and the **only** thing that is true before any object is
fetched. The signing pubkey is therefore **removed** from the committed
`registry.toml` — a key stored inside a file that is authenticated *by* that key is
circular for bootstrap (it can attest to nothing the consumer doesn't already have to
trust out of band). See [`repo-layout.md`](repo-layout.md) §2 for the
`registry.toml` shape (which now carries only `[registry]` + `[[caches]]`).

Instead the registry publishes a **`keys.toml` trust roster** — a committed tree file
listing the **active signing key(s)** and a **revoked list**, authenticated like every
other tree file by the signed tag (tag → commit → tree → file). It does **not**
bootstrap trust; it *evolves* a trust the consumer already holds. The on-disk shape and
fields live in [`repo-layout.md`](repo-layout.md) §3.

```
  trusted-keys.d/<registry>.pub          keys.toml (in the committed tree)
  ┌──────────────────────────┐           ┌─────────────────────────────────┐
  │ TOFU-pinned ANCHOR (§2.4) │           │ active keys + revoked list      │
  │ client-side, out of band  │ ──verify──▶ authenticated by the signed tag │
  │ THE bootstrap root        │  the tag  │ (tag → commit → tree → file)    │
  └──────────────────────────┘           └─────────────────────────────────┘
        trust starts here                  trust EVOLVES here (rotate/revoke)
```

**Rotation (overlap window).** To roll the signing key forward, publish a `keys.toml`
that lists **both** the old and the new key in a tag **signed by the currently-trusted
key**. A consumer that already trusts the old key verifies that tag, reads `keys.toml`,
and **pins the new key** (updating its TOFU store). A later release can then drop the
old key from the roster and sign with the new key alone. The overlap window is what
makes the handoff seamless: no consumer is ever asked to trust a key it cannot reach
through a key it already trusts.

**Revocation (compromise).** To retire a compromised key, list it under the roster's
revoked entries — but the `keys.toml` carrying that revocation **must be signed by a
key the consumer trusts that is *not* the revoked one.** A single key cannot credibly
revoke itself. Two structures satisfy this:

- **TUF-style root/operational split** — a dedicated **offline root (anchor) key**
  (the one TOFU-pinned in `trusted-keys.d`) signs `keys.toml`, while a separate
  **operational key** signs day-to-day release and channel tags. Compromise of the
  hot operational key is recoverable: the offline root signs a `keys.toml` revoking it
  and naming a fresh operational key.
- **≥2 overlapping active keys** — keep two active signing keys so a `keys.toml`
  revoking one can still be signed by the other.

Whether to adopt the dedicated-root model or a single-key-with-overlap model is an
**open choice** — see [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md)
§16 (and whether the roster is a standalone `keys.toml` or a `[keys]` block in
`registry.toml`).

> **NAR safety (defence in depth).** An authenticated-but-wrong `[[caches]]` pointer
> cannot serve bad bytes: NARs are **content-addressed and SHA-256-verified** on
> download. The trust that actually matters is the **tag/commit chain governed by
> `keys.toml`**, not the cache list — a mis-signed or mis-pointed cache yields a hash
> mismatch and a rejected fetch, not a compromised closure. See
> [`repo-layout.md`](repo-layout.md) §3 and
> [`nix-cache-compatibility.md`](nix-cache-compatibility.md).

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
   against the trusted `<registry>.pub` key (the `git verify-tag` /
   `allowed_signers` mechanism of §2.3).
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
    key   = key_store.lookup(registry)?            // trusted <registry>.pub  (§2.4)

    # hop 1: the channel partition tag
    ptag  = fetch("/channels/{channel}/{bucket}")   # signed tag object
    require verify_tag_signature(ptag, key)        # §2.3
    require ptag.embedded_tag_name == channel      # NAME-BINDING (channel)
    semver = ptag.target_semver                    # tag → tag

    # hop 2: the release (semver) tag
    rtag  = fetch_tag("refs/tags/{semver}")        # signed tag object
    require verify_tag_signature(rtag, key)        # §2.3
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

## 4. Freshness — no in-band expiry

Signed tags carry **no in-band expiry field**. There is no `valid_until` (nor any other
structured payload) inside a tag object — a tag is a pure signed pointer (§2.2).
Freshness is therefore enforced **out of band**, by three cooperating mechanisms:

| Mechanism | Where | What it bounds |
|---|---|---|
| **Low CDN TTL** on `/channels` (and `info/refs`, `objects/info`) | edge / CDN policy ([`http-layout.md`](http-layout.md)) | how long a stale rollout pointer can be served before the edge re-fetches the origin |
| **Consumer max-staleness policy** | client-side registry config | how long *this consumer* will trust a previously-fetched pointer before it MUST re-fetch and re-validate |
| **Monotonic anti-rollback floor** | consumer (§5) | the lower bound on the accepted release, regardless of pointer age |

The CDN policy ([`http-layout.md`](http-layout.md)) **MUST** keep `/channels` (and
`info/refs`, `objects/info`) at low TTL so a consumer re-fetches and sees rollout
advances quickly; releases under `/releases/**` are immutable and may be cached with a
long TTL. A consumer that cannot reach the origin to refresh a stale channel pointer
falls back to its anti-rollback floor (§5) and its own max-staleness policy rather than
trusting a stale pointer indefinitely.

> **Trade-off:** because there is no in-band signed expiry, this freshness model is
> **weaker** than a signed `valid_until` against a **frozen-but-validly-signed mirror**.
> A mirror that keeps serving an old, correctly-signed channel pointer cannot be caught
> by the pointer's own contents; it is bounded only by the consumer's max-staleness
> policy and the floor. An in-band expiry would let the producer assert "this pointer is
> stale after T" inside the signed object itself. This is an accepted trade for keeping
> tags as pure signed pointers; see
> [`../plans/registry/open-questions.md`](../plans/registry/open-questions.md).

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
(TOFU, `trusted-keys.d`, fingerprinting) is shared; only the verification *call site*
differs (git tag vs. narinfo).

---

## 7. Trust boundaries — summary table

| Concern | Mechanism | Authority? |
|---|---|---|
| Is this the registry's key? | TOFU + `trusted-keys.d/<registry>.pub` (`security.rs` `KeyStore`/`tofu_check`) | root of trust |
| How do keys rotate / get revoked? | committed `keys.toml` trust roster (§2.5), signed by an already-trusted (non-revoked) key | yes — evolves an anchored trust |
| Is this tag genuinely signed? | `git verify-tag` + temp `allowed_signers` (Ed25519) | yes |
| Is this tag at the *right* path? | embedded tag-name == expected path name (channel / semver) | yes — closes cross-serving |
| Which release does my bucket get? | signed `/channels/<name>/<bucket>` partition tag (hop 1) | yes |
| Which commit is that release? | signed `refs/tags/<semver>` release tag (hop 2) | yes |
| Is the frontier branch trustworthy? | `refs/heads/<channel>` — **unsigned pointer** | **no** (convenience only) |
| Is this pointer fresh? | low CDN TTL on `/channels` + consumer max-staleness policy + monotonic floor (no in-band expiry) | freshness, not forgery |
| Could I be downgraded? | consumer **monotonic floor** (semver); abort = **fix-forward** | yes |
| NAR substitution from same origin? | narinfo `Sig:` reusing the **one** Ed25519 key | yes |

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

## 9. Implementation status (CURRENT vs TARGET)

| Capability | CURRENT (code today) | TARGET |
|---|---|---|
| Key format `name:Ed25519:<base64>` | `parse_signing_key` (`security.rs:306`) | unchanged |
| Trust store TOFU + `trusted-keys.d` | `KeyStore` / `tofu_check` (`security.rs:52`,`:159`) | unchanged (the bootstrap anchor) |
| Signing pubkey location | `[registry.signing].public_key` inside `registry.toml` (`RegistryRootConfig`) | **removed** from `registry.toml`; trust = `keys.toml` roster + TOFU |
| Key rotation / revocation | — (single pinned key, no roster) | committed `keys.toml` roster: overlap-window rotation, root/operational (or ≥2-key) revocation (§2.5) |
| Signature *production* | `apr sign` = `git commit --amend -S` (`registry_ops.rs:1770`) | `git tag -s` on **tag objects** |
| Tag creation | `apr tag` = `git tag -a` with `--message`, else lightweight `git tag` (both **unsigned**) (`registry_ops.rs:1706-1710`) | `git tag -s` (signed) for channel + release tags |
| Signature *verification* | `verify_commit_signature` = `git verify-commit` (`security.rs:199`) | `git verify-tag` (same allowed-signers mechanism) |
| What is signed | the HEAD **commit** | **`tag → tag → commit`** chain (partition + release tags) |
| Name-binding | none | embedded tag-name == expected path name (channel / semver) |
| Anti-rollback | `check_downgrade` git-ancestry (`security.rs:256`) | semver **monotonic floor** + **fix-forward** |
| Nix narinfo `Sig:` | not wired | reuse the one Ed25519 key |

The full implementation plan for this surface is
[`../plans/registry/workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md).
Superseded concepts live only in current-state.md (today's code) and design-brief §15.

---

## See also

- [`README.md`](README.md) — registry doc index and glossary.
- [`architecture.md`](architecture.md) — git-over-dumb-HTTP, the three ref layers.
- [`repo-layout.md`](repo-layout.md) — the committed git tree: `registry.toml` (pubkey removed) + `keys.toml` trust roster + `packages/` + `closures/`.
- [`http-layout.md`](http-layout.md) — HTTP/object layout, CDN TTLs, sha256 object store.
- [`versioning-and-channels.md`](versioning-and-channels.md) — semver, channels-as-branches, 256-partition rollout, bucket selection, anti-rollback.
- [`packs-and-deltas.md`](packs-and-deltas.md) — what the verified commit's object store contains.
- [`publishing.md`](publishing.md) — producer pipeline: commit → sign → pack → advance partitions.
- [`nix-cache-compatibility.md`](nix-cache-compatibility.md) — NAR cache reusing the one Ed25519 key.
- [`current-state.md`](current-state.md) — the as-is bundle/`creation_token` implementation.
- Plan: [`../plans/registry/workstream-04-signing-trust.md`](../plans/registry/workstream-04-signing-trust.md), [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md), [`../plans/registry/open-questions.md`](../plans/registry/open-questions.md).
