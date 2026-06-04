# Signing & Trust

> **Scope:** how the AOS package registry authenticates its contents — one
> Ed25519 keypair serving two protocols, SSH-format git commit signatures plus
> Nix narinfo `Sig:` lines, Trust-On-First-Use (TOFU) + admin-provisioned
> trusted keys, the *transitive* authentication of NAR blobs through the signed
> git commit, and the full threat model (tamper / MITM / rollback / freeze /
> omission).
>
> **Audience:** users who must trust a registry, implementers wiring the
> verification path, and architects evaluating the security model.
>
> **CURRENT vs TARGET:** sections labeled **CURRENT** describe code that exists
> today, cited as `path:line`. Sections labeled **TARGET** describe the design in
> [`design-brief.md`](../plans/registry/design-brief.md) §4.2 / §4.5 that is not
> yet implemented. Where they diverge, both are shown side by side.

**Related reference docs:** [README](./README.md) ·
[architecture](./architecture.md) · [current-state](./current-state.md) ·
[http-layout](./http-layout.md) · [registry-toml](./registry-toml.md) ·
[bundles-and-deltas](./bundles-and-deltas.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[publishing](./publishing.md) ·
[versioning-and-channels](./versioning-and-channels.md) ·
[apt-comparison](./apt-comparison.md)

**Related plan docs:** [design-brief](../plans/registry/design-brief.md) ·
[gap-analysis](../plans/registry/gap-analysis.md) ·
[workstream-01-registry-root](../plans/registry/workstream-01-registry-root.md) ·
[workstream-03-nix-cache](../plans/registry/workstream-03-nix-cache.md) ·
[workstream-05-consumer](../plans/registry/workstream-05-consumer.md) ·
[open-questions](../plans/registry/open-questions.md)

---

## 1. The trust chain at a glance

The registry is a **git repository of TOML metadata**, not a blob store
(see [architecture](./architecture.md)). NAR build artifacts live on a separate
cache/mirror. The entire trust model is built around a single observation: **git
is a Merkle DAG**, so signing one commit cryptographically authenticates the
whole tree reachable from it. Every package TOML records the SHA-256 of its NAR,
so the signature on the commit transitively pins the bytes of every artifact —
without any per-NAR signature.

```
            Ed25519 secret key (one key, held by the maintainer)
                              │
                ┌─────────────┴─────────────┐
        signs git commit              signs each narinfo  (TARGET — see §5)
        (SSH-format sig)              (Nix fingerprint)
                │                             │
                ▼                             ▼
   ┌────────────────────────┐     ┌──────────────────────────┐
   │  git commit  (Merkle    │     │  <storehash>.narinfo      │
   │  root of the registry)  │     │  Sig: <name>:<base64sig>  │
   └───────────┬─────────────┘     └────────────┬─────────────┘
               │ tree object hash               │ authenticates ONE narinfo
               ▼                                 ▼
   packages/<x>/<name>.toml            consumed by stock `nix`
               │  records nar_hash                (require-sigs path)
               ▼
   closures/<hash>  (adjacency list of dependency hashes)
               │  each line names dep hashes
               ▼
   NAR blob  ← verified by SHA-256 content hash on download
   (nar/<sha256:hex>.nar.zst on the cache/mirror)
```

- **`apm` (AOS consumer)** roots its trust in the **signed commit**. It never
  needs a per-NAR signature: the commit → TOML → `nar_hash` → SHA-256 chain is
  sufficient. NARs are verified by content hash only
  (`download.rs`; design-brief §2.8, §3).
- **stock `nix` (dev-shell substituter, TARGET)** cannot read git commits. To let
  it consume the same NARs without `require-sigs = false`, the **same key** also
  signs each `narinfo` in the Nix-native form. See
  [nix-cache-compatibility](./nix-cache-compatibility.md).

---

## 2. One Ed25519 key, two protocols

**TARGET** (design-brief §4.2). A single Ed25519 keypair is the root of trust.
The *secret* is shared — one key to generate, store, rotate, and protect — but it
produces **two different signatures over two different signed messages**, and the
*public* key is published in **two encodings** for the two verifier ecosystems.

| Aspect | git commit signature | Nix narinfo `Sig:` |
|---|---|---|
| Algorithm | Ed25519 | Ed25519 |
| Signature format | SSH signature (`gpg.format=ssh`) | Nix's own `<name>:<base64sig>` |
| Signed message | the git commit object | the narinfo *fingerprint* string |
| Fingerprint inputs | (git's commit serialization) | `(StorePath, NarHash, NarSize, References)` |
| Verified by | `git verify-commit` | `nix` / `nix-store --verify` |
| Consumed by | `apm` (transitively authenticates the tree) | stock `nix` substituter |
| Status | **CURRENT** (commit signing exists, see §4) | **TARGET** (no narinfo emission yet) |

Because the two signatures cover **different bytes**, possessing one does not let
an attacker forge the other; both are only producible by the holder of the one
secret key.

### 2.1 Two public-key encodings

From the one public key, two textual encodings are published:

| Encoding | Form | Consumer | Where it lives |
|---|---|---|---|
| AOS / TOFU | `registry:Ed25519:<base64>` (`name:algo:key`) | `apm` | registry's `signing.public_key`; pinned to `trusted-keys.d/{registry}.pub` |
| Nix | `<name>:<base64>` | stock `nix` | a host's `nix.conf` `trusted-public-keys` |

> **CURRENT shape of the AOS encoding.** `parse_signing_key`
> (`crates/aos-package/src/security.rs:306`) requires exactly
> `registry:algorithm:base64key` (three colon-separated parts) and **rejects any
> algorithm but `Ed25519`** (`security.rs:324`). Example:
> `aos-core:Ed25519:Xk9m2base64Qp4=`. The `RegistrySigningConfig.public_key`
> field (`types.rs:597`) and the embedded `SigningConfig.public_key`
> (`types.rs:246`) both carry a string in this format.

The Nix encoding (`<name>:<base64>`) is not yet emitted by any AOS tool; it is
part of the narinfo work in
[workstream-03-nix-cache](../plans/registry/workstream-03-nix-cache.md).

---

## 3. Transitive authentication of NARs

The design rests on three facts (design-brief §3):

1. **The Ed25519-signed git commit authenticates the whole tree.** Git is a
   Merkle DAG: the commit object names a tree hash, which names every blob and
   subtree. Tamper with any TOML and the tree hash changes, which invalidates the
   commit signature.
2. **Each TOML records its NAR's SHA-256.** A package's
   `[versions.platforms.<platform>]` table carries `nar_hash` (and
   `download_hash` for the compressed `.nar.zst`); the `closures/<hash>` files
   record the dependency adjacency (design-brief §2.3).
3. **NARs are content-addressed and verified on download by SHA-256.**
   `download.rs` builds `nar_url(mirror_url, nar_hash)` →
   `{mirror_url}/{nar_hash}.nar.zst` and checks the content hash (design-brief
   §2.8). There is **no per-NAR signature** in the AOS path, and the AOS client
   does not need one.

So for `apm`, the chain is:

```
signed commit  ──►  tree hash  ──►  TOML  ──►  nar_hash  ──►  NAR bytes
   (Ed25519)        (git Merkle)   (in-tree)   (SHA-256)     (content check)
```

A mirror that serves NAR blobs is fully untrusted: it can only return bytes whose
SHA-256 already matches a hash committed under the signed root. Any substitution
fails the content check.

> **Why stock `nix` still needs a per-narinfo signature (TARGET).** `nix` does
> not consume the git commit and has no notion of "the tree that committed this
> hash." Its only authentication hook is the narinfo `Sig:` line. The per-narinfo
> Ed25519 signature exists **solely** to satisfy `nix` without
> `require-sigs = false` (design-brief §4.2); it is redundant for `apm`.

---

## 4. CURRENT signing & verification implementation

This section documents what the code does **today**. Several pieces of the §1
trust chain are present; some are partial. Discrepancies are flagged and recorded
in the open-questions summary.

### 4.1 Producer: `apr sign` and `apr push`

| Operation | Behavior | Citation |
|---|---|---|
| `apr sign [COMMIT]` | `git commit --amend --no-edit -S` — re-commits HEAD with an SSH/GPG signature using git's ambient signing config. | `registry_ops.rs:1759` (fn), `registry_ops.rs:1770` (the git call) |
| `apr tag` | `git tag -a <name> -m <msg>` (or lightweight `git tag <name>`). | `registry_ops.rs:1707` |
| `apr push` | `git push [-u origin] [<branch>] [--force]`. The fast-forward-only ref update is the only concurrency guard (design-brief §4.4). | `registry_ops.rs:1410`–`1442` |

> **Discrepancy (sign target argument).** `apr sign` accepts an optional
> `commit` argument and reports `Signed commit {target}`, but the underlying
> command is always `git commit --amend --no-edit -S`, which only re-signs
> **HEAD** — the `commit`/`target` value is used only in the success message
> (`registry_ops.rs:1767`–`1771`). Signing an arbitrary historical commit is not
> implemented.

> **Discrepancy (`--key` is ignored).** Both `apr sign` and `apr tag` take a
> `_key: Option<&str>` parameter that is **unused** (`registry_ops.rs:1700`,
> `registry_ops.rs:1762`). Signing always uses git's configured signing key
> (`user.signingkey` / `gpg.format`); there is no per-invocation key selection.

The signature produced is SSH-format Ed25519 only if the maintainer has
configured `git config gpg.format ssh` and pointed `user.signingkey` at an
Ed25519 key. The registry tooling does not configure this for you.

### 4.2 Consumer: trusted-key storage & TOFU primitives

`crates/aos-package/src/security.rs` provides the trust building blocks:

- **`KeyStore`** (`security.rs:52`) reads/writes `{registry}.pub` files across an
  ordered list of directories. Index `0` is the writable TOFU store; later
  directories are read-only pre-installed keys (`security.rs:62`–`92`). The
  directory list comes from `ProfileScope::trusted_keys_dirs`
  (`types.rs:502`):

  | Scope | Search order (`trusted_keys_dirs()`) |
  |---|---|
  | user | `~/.config/apm/trusted-keys.d/` (writable, TOFU), then `/etc/apm/trusted-keys.d/` (read-only) |
  | system | `/etc/apm/trusted-keys.d/` (writable), then `/var/lib/apm/trusted-keys.d/` |

  A key found in dir `0` is tagged `KeySource::Tofu`; one found later is
  `KeySource::PreInstalled` (`security.rs:76`–`80`). The on-disk line format is
  `{registry}:{algorithm}:{public_key}\n` (`security.rs:107`).

- **`tofu_check`** (`security.rs:159`) parses a received
  `registry:algorithm:base64key`, looks up any pinned key, and returns a
  `TofuDecision`:

  | `TofuDecision` | Meaning | Action |
  |---|---|---|
  | `AlreadyTrusted(key)` | pinned key matches received key | proceed |
  | `NewKey { key, needs_confirmation: true }` | nothing pinned yet | prompt user, then `store()` to pin |
  | `KeyMismatch { stored, received }` | a *different* key is already pinned | **reject** (possible key-substitution attack) |

  This is classic TOFU: the first key is accepted (optionally with a prompt) and
  pinned; any later mismatch is a hard failure.

- **`verify_commit_signature`** (`security.rs:199`) builds a temporary
  `allowed_signers` file containing `registry ssh-ed25519 <pubkey>` and runs
  `git -c gpg.ssh.allowedSignersFile=<tmp> verify-commit <commit>` — i.e. it
  verifies an **SSH-format Ed25519** signature against the *pinned* key, not
  against ambient git config.

- **`parse_signing_key`** (`security.rs:306`) / **`key_fingerprint`**
  (`security.rs:338`, first 8 hex chars of the SHA-256 of the decoded key) round
  out the API.

### 4.3 Consumer: the live git-sync verification path

The actually-wired verification during `apm update` over a `git*` transport lives
in `crates/aos-package/src/registry/git.rs`:

1. Fetch refs, resolve the new HEAD commit (`git.rs:60`–`63`).
2. **If `signing.required`**, call `verify_commit_signature`
   (`git.rs:66`–`70`).
3. **Enforce fast-forward**: `enforce_fast_forward` runs
   `git merge-base --is-ancestor old new`; a non-FF transition is rejected as a
   downgrade/force-push (`git.rs:73`–`75`, `git.rs:412`).

> **Discrepancy (two `verify_commit_signature` functions; the wired one ignores
> the pinned key).** The function actually called by the sync path is a *second,
> private* `verify_commit_signature` in `git.rs:384`, **not** the one in
> `security.rs`. The `git.rs` version runs a bare `git verify-commit <commit>`
> and **ignores its `_signing` argument** (`git.rs:387`–`394`) — it relies on
> git's ambient `gpg.ssh.allowedSignersFile`, not on the pinned
> `trusted-keys.d/{registry}.pub`. The `security.rs::verify_commit_signature`,
> which *does* pin to the trusted key via a temporary allowed-signers file, is
> **not** called from the sync path.

> **Discrepancy (TOFU is not wired into sync).** Of the `security` module, only
> `KeyStore::remove` is invoked from `lib.rs:1344`–`1345` (to clean up a key when
> a registry is removed). `tofu_check`, `KeyStore::lookup`/`store`, and
> `TofuDecision` are **not** called from the update/sync path in the current
> tree. The TOFU acceptance-and-pin flow described in design-brief §2.10 is
> implemented as reusable primitives but **not yet wired** into `apm update`.

### 4.4 Consumer: rollback / downgrade defenses (CURRENT)

Two independent monotonicity checks exist:

| Check | Mechanism | Citation |
|---|---|---|
| **Commit ancestry** | `git merge-base --is-ancestor`: the new commit must be a descendant of the last verified commit. Distinguishes `FastForward` / `SameCommit` / `Downgrade` / `Diverged`. | `security.rs:256` (`check_downgrade`); `git.rs:412` (`enforce_fast_forward`, the wired one) |
| **Token monotonicity** | `check_monotonic(old, new)` rejects `new_token <= old_token`, where the token is `year*1_000_000 + month*10_000 + patch` derived from the calendar tag. | `state.rs:104`; called from `update.rs:265` |

The token check defends the **HTTP bundle** transport (which has no git ancestry
to compare against during selection); the ancestry check defends the **git**
transport. See [bundles-and-deltas](./bundles-and-deltas.md) and
[versioning-and-channels](./versioning-and-channels.md) for the
`creation_token` encoding.

> **Note (HTTP bundle path & signatures).** The bundle transport
> (`registry/bundle.rs`) verifies each bundle by **SHA-256 + `git bundle
> verify`** (design-brief §2.4), and applies `check_monotonic` on the token. It
> does **not** itself run commit-signature verification today; commit-signature
> checking is implemented on the `git*` transport path (`git.rs`). Closing this
> for the bundle path is part of the consumer workstream — see
> [workstream-05-consumer](../plans/registry/workstream-05-consumer.md).

---

## 5. TARGET signing & verification

The target (design-brief §4.2–§4.5) adds the Nix-cache half of the key's job and
hardens freshness, without changing the AOS trust root.

### 5.1 Per-narinfo Ed25519 `Sig:` (the new artifact)

Each generated `<storehash>.narinfo` gets a `Sig:` line signed by the **same**
Ed25519 key, over Nix's standard fingerprint
`(StorePath, NarHash, NarSize, References)`:

```
StorePath: /nix/store/<storehash>-<name>-<version>
URL: nar/<download_hash>.nar.zst
Compression: zstd
FileHash: sha256:<download_hash>
FileSize: <download_size>
NarHash: sha256:<nar_hash>
NarSize: <nar_size>
References: <hash>-<name> <hash>-<name> ...
Deriver: <source_drv>
Sig: <name>:<base64-ed25519-signature>
```

Notes (design-brief §4.1):
- `References:` must **expand bare dependency hashes → `<hash>-<name>`
  basenames** (the package TOML stores bare hashes; narinfo wants basenames).
- This `Sig:` exists **only** for stock `nix`. `apm` ignores it and continues to
  trust the signed commit transitively (§3).

See [nix-cache-compatibility](./nix-cache-compatibility.md) for the full narinfo
field mapping and the dev-shell substituter wiring; the emitter is
[workstream-03-nix-cache](../plans/registry/workstream-03-nix-cache.md).

### 5.2 The signed root `registry.toml` (freshness anchor)

The target collapses the registry root to a **single inline-signed**
`registry.toml` (killing `bundle-list.toml`), like APT's `InRelease`
(design-brief §4.3). For trust, the load-bearing additions are:

- **`pubkey`** — the Ed25519 public key (both encodings derivable from it).
- **`[latest]`** — a *signed* pointer (`tag`, `token`, `head` = authentic git
  commit SHA). This is the freshness / anti-rollback anchor a dumb-HTTP directory
  listing cannot provide.
- **`valid_until`** — APT-style signed expiry: the freeze defense (§6).
- **inline signature line(s)** — root + signature fetched as one atomic object,
  so a client never races a torn root+sig pair.
- **by-hash references** — bundles/indices referenced by hash, so a client that
  read `root@T` resolves a consistent set even after `root@T+1`.

See [registry-toml](./registry-toml.md) for the full annotated schema and
[publishing](./publishing.md) for the atomic root-flip ordering.

---

## 6. Threat model

The table maps each threat to the defense and its status. **TARGET** rows depend
on the signed `registry.toml` root (§5.2) that does not exist yet.

| Threat | What the attacker does | Defense | Status |
|---|---|---|---|
| **Tamper** | mirror/CDN alters a TOML or NAR | signed commit pins the tree (Merkle); every NAR pinned by in-tree SHA-256 (§3) | **CURRENT** for content hashes; commit-sig wired only on `git*` transport (§4.3) |
| **MITM** | active network attacker substitutes bytes in flight | same as tamper — bytes are pinned by signature + content hash; a substituted byte fails verification | **CURRENT** (content), **partial** (commit-sig on git transport only) |
| **Rollback** | serve an older, validly-signed state | git ancestry (`merge-base --is-ancestor`) + monotonic `[latest].token` / `check_monotonic` | **CURRENT** (`check_downgrade`/`enforce_fast_forward`/`check_monotonic`); `[latest]` token is TARGET |
| **Freeze** | mirror stuck on a *validly-signed-but-old* root indefinitely | APT-style **`valid_until`** expiry in the signed root; client rejects an expired root | **TARGET** (§5.2) — sequence-based `[latest]` alone cannot detect this |
| **Omission** | listing hides newer bundles to keep a client stale | signed **`[latest].head`** target the client must reach; if unreachable, the client **fails closed** (freeze degrades to DoS, not silent rollback) | **TARGET** (§5.2) |
| **Key substitution** | swap in the attacker's key as "the" registry key | TOFU pin: `KeyMismatch` is a hard reject; admin pre-provisioning in `trusted-keys.d/` overrides TOFU | primitives **CURRENT** (`tofu_check`), but **not wired** into sync (§4.3) |

### 6.1 Why each TARGET defense is necessary

- **`valid_until` (freeze defense).** A purely sequence-based anti-rollback
  (`[latest].token` monotonicity) cannot tell "this is genuinely the latest" from
  "a mirror has frozen at a once-valid state." Time-bounded expiry forces the
  producer to re-sign on a cadence; a client that sees an expired root refuses it
  (design-brief §4.5, §6 Tier 1). This is cheap: re-sign each publish with
  `valid_until = publish_time + N`.
- **Signed `[latest].head` (omission / fail-closed).** With an authentic target
  commit SHA in the signed root, a listing that hides newer bundles makes the
  signed target *unreachable* — the client errors out rather than silently using
  stale data. The attack collapses from "silent rollback" to "denial of service"
  (design-brief §4.5).
- **by-hash references (torn-publish safety).** Referencing bundles by their
  hashed key means a client mid-publish never assembles an inconsistent
  `root@T` + `bundle@T+1` mix (design-brief §4.3, §6 Tier 1).

### 6.2 Residual / out-of-scope

- **Compromise of the one secret key** defeats both protocols at once — that is
  the cost of the single-key design. Mitigation is operational (key storage,
  rotation cadence), not cryptographic. Rotation cadence and `valid_until` window
  length are open (design-brief §7.5).
- **First-contact TOFU** trusts the first key seen for a registry; an attacker who
  is in the path on *first* sync can pin their own key. Admin pre-provisioning in
  `trusted-keys.d/` (read-only dirs, `KeySource::PreInstalled`) eliminates this
  window for managed fleets.

---

## 7. Operational notes & examples

### 7.1 Pinning a registry key out-of-band (admin pre-provisioning)

Drop a `{registry}.pub` file into a read-only trusted-keys directory so the key
is `PreInstalled` (never subject to first-use acceptance):

```
# /etc/apm/trusted-keys.d/aos-core.pub
aos-core:Ed25519:Xk9m2base64Qp4=
```

Search order is defined by `trusted_keys_dirs()` (`types.rs:502`): for a user
scope, `~/.config/apm/trusted-keys.d/` (writable TOFU store) is searched first,
then `/etc/apm/trusted-keys.d/`. A key in the second directory is treated as
admin-installed.

### 7.2 Requiring signed commits

The git-transport sync verifies signatures only when the registry's
`signing.required` is true (`git.rs:67`; `SigningConfig.required` defaults to
`true`, `types.rs:247`). In the per-registry config:

```toml
[registry]
name = "aos-core"
url = "git+https://example.com/aos-core.git"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:Xk9m2base64Qp4="
```

> See §4.3 discrepancies: with the current wiring, the sig check uses git's
> **ambient** allowed-signers config rather than this pinned `public_key`. To
> verify against the pinned key today, the maintainer must also configure git's
> `gpg.ssh.allowedSignersFile`. Wiring `security.rs::verify_commit_signature`
> (which pins automatically) into the sync path is tracked in
> [workstream-05-consumer](../plans/registry/workstream-05-consumer.md).

### 7.3 Using the registry as a Nix substituter (TARGET)

Once narinfo emission lands (§5.1), a non-AOS dev-shell host trusts the **Nix
encoding** of the same key:

```conf
# nix.conf
substituters = https://cache.example.com/aos-core
trusted-public-keys = aos-core:<base64-of-the-same-ed25519-public-key>
```

No `require-sigs = false` is needed: the per-narinfo `Sig:` is valid under this
key. See [nix-cache-compatibility](./nix-cache-compatibility.md).

---

## 8. Summary

- **One Ed25519 key, two protocols, two signatures, two public-key encodings.**
  The secret is shared; the signed messages differ (§2).
- **`apm` trusts the signed git commit and authenticates NARs transitively**
  through in-tree SHA-256 hashes — no per-NAR signature needed (§3).
- **CURRENT:** commit signing via `apr sign` (`registry_ops.rs:1770`); FF-only
  `apr push`; TOFU/`KeyStore`/pinning primitives in `security.rs`; rollback
  defenses via ancestry + token monotonicity. Gaps: TOFU and the pinned-key
  commit verifier are **not yet wired into sync**; the wired git verifier ignores
  the pinned key; the bundle transport does not run commit-sig verification (§4).
- **TARGET:** per-narinfo Ed25519 `Sig:` for stock `nix`; an inline-signed
  `registry.toml` carrying `pubkey`, `[latest]` (`tag`/`token`/`head`),
  `valid_until`, and by-hash references — closing the **freeze** and **omission**
  threats and making clients fail closed (§5, §6).
