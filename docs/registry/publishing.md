# Publishing & Concurrency

> **Audience:** registry maintainers (producers), implementers of the `apr`
> tooling, and architects reasoning about the registry's safety properties.
>
> **Scope:** the producer-side workflow — how a new package version gets from a
> local Nix store path into a published, signed, fetchable registry — and the
> concurrency model that makes concurrent publishes safe. This is the
> counterpart to the consumer-side flow in
> [bundles-and-deltas.md](./bundles-and-deltas.md).

This document labels every claim as **CURRENT** (verified against the code, cited
as `path:line`) or **TARGET** (the design intent from the
[design brief](../plans/registry/design-brief.md), §2.11 and §4.4). The gap
between them is the subject of
[workstream-02-publish-pipeline.md](../plans/registry/workstream-02-publish-pipeline.md).

---

## 1. Mental model

A registry is a **git repository of TOML metadata** plus a set of **immutable,
content-addressed artifacts** (NARs, narinfos, git bundles) served over dumb
HTTP. Publishing has two halves that must not be confused:

1. **Land metadata in git.** Edit `packages/<x>/<name>.toml` + `closures/<hash>`,
   commit, sign, and push. The git push is the *serialization point*: the remote
   ref update is an atomic compare-and-swap (CAS) that linearizes all publishers.
2. **Materialize and publish artifacts.** From the *landed* commit, generate the
   bundles, narinfos, and `nix-cache-info`, upload the immutable objects, and
   then flip the signed root (`registry.toml`) atomically as the final step.

```
                       PRODUCER                                CONSUMER
   ┌─────────────────────────────────────────┐
   │ apr publish  → edit TOML + closures      │
   │ (git commit) → land metadata in history  │
   │ apr sign     → SSH-Ed25519 sign the HEAD │
   │ apr push     → CAS: FF-only ref update   │──┐  git push (atomic ref CAS)
   └─────────────────────────────────────────┘  │
                                                 ▼
                                          ┌──────────────┐
                                          │  remote git  │  ← the lock
                                          │  registry    │
                                          └──────┬───────┘
   ┌─────────────────────────────────────────┐  │
   │ generate bundles / narinfos / cache-info │  │  (winner only)
   │ upload immutable content-addressed objs  │──┼──► nar/, *.narinfo, *.bundle
   │ flip registry.toml LAST (conditional PUT)│──┼──► registry.toml  (atomic)
   └─────────────────────────────────────────┘  │
                                                 ▼
                                          apm update / nix substitute
```

The asymmetry between these two halves is the central fact of the current
codebase: half (1) is implemented; half (2) is mostly absent.

---

## 2. The `apr` command surface (CURRENT)

`apr` is the same binary as `aos`/`apm`, dispatched on `argv[0]`; `apr …` expands
to `package registry …` (design brief §1, §2.1). All producer logic lives in
`crates/aos-package/src/registry_ops.rs`. The command enum is
`RegistryCommand` (`crates/aos-package/src/lib.rs:272`).

The commands relevant to a publish, in workflow order:

| Command | Function | What it actually does (CURRENT) |
|---|---|---|
| `apr create <name> [--remote URL]` | `create` (`registry_ops.rs:421`) | `git init`, make `packages/`, write a default `registry.toml`, initial commit, optional `git remote add origin`. |
| `apr publish <store-path> [...]` | `publish` (`registry_ops.rs:476`) | Introspect the path, write `packages/<x>/<name>.toml`, compute + write `closures/<hash>`, then (unless `--no-commit`) `git add -A && git commit`. |
| `apr unpublish <pkg> [version] [--platform]` | `unpublish` (`registry_ops.rs:785`) | Remove a TOML / version / platform entry and commit. |
| `apr status` / `apr log` / `apr diff` | `status`/`log`/`diff` (`registry_ops.rs:1333`, `1345`, `1176`) | Thin `git status` / `git log --oneline` / `git diff` wrappers. |
| `apr branch …` | `run_branch` (`registry_ops.rs:1376`) | `git branch`/`checkout` wrappers. |
| `apr pull [--rebase]` | `pull` (`registry_ops.rs:1445`) | `git pull [--rebase]` — the retry primitive for a lost CAS race (§5). |
| `apr tag <name> [--message] [--key]` | `tag` (`registry_ops.rs:1696`) | `git tag [-a -m …]`. **`--key` is accepted but ignored** (`_key`, `registry_ops.rs:1700`). |
| `apr sign [commit] [--key]` | `sign` (`registry_ops.rs:1759`) | `git commit --amend --no-edit -S` — SSH-Ed25519 sign HEAD. **`--key` is ignored** (`_key`, `registry_ops.rs:1764`); see §3. |
| `apr bundle [--output] [--tag] [--delta-from] [--update-manifest]` | `bundle` (`registry_ops.rs:1718`) | `git bundle create` into a local dir. **`--update-manifest` is ignored** (`_update_manifest`, `registry_ops.rs:1723`); see §4. |
| `apr push [--branch] [--set-upstream] [--force]` | `push` (`registry_ops.rs:1410`) | `git push [-u origin] [branch] [--force]`. This is the CAS point (§5). |
| `apr verify` / `apr validate` | `verify`/`validate` (`registry_ops.rs:1020`, `1210`) | Local consistency check; `validate` does `HEAD` probes against `[[caches]]` mirrors. |

There is no `apr publish-bundles`, `apr release`, or any upload command today —
the design brief §2.11 enumerates this as the producer-side gap, and §7 lists the
proposed `apr release` end-to-end orchestrator as an open question.

---

## 3. `apr sign` — signing the metadata (CURRENT)

`apr sign` runs exactly:

```
git commit --amend --no-edit -S      # registry_ops.rs:1770
```

Key facts:

- It **amends `HEAD`** and re-signs in place. The `commit` positional argument is
  only used for the success message (`target`, `registry_ops.rs:1767`); it does
  **not** sign an arbitrary historical commit.
- `--key` is **accepted and ignored** (`_key`, `registry_ops.rs:1764`). The key is
  whatever git resolves from `user.signingkey` + `gpg.format = ssh`; the registry
  does not select a key for you.
- Verification (consumer side) expects an **SSH-format Ed25519** signature:
  `verify_commit_signature` (`security.rs:199`) builds a temporary
  `allowed_signers` file and runs
  `git -c gpg.ssh.allowedSignersFile=… verify-commit <commit>`
  (`security.rs:221`). `parse_signing_key` (`security.rs:306`) rejects any
  algorithm other than `Ed25519` (`security.rs:324`).

This is why the **commit** is the trust root: git is a Merkle DAG, so signing the
HEAD commit transitively authenticates every TOML and every NAR hash recorded in
those TOMLs (design brief §3). There is no per-artifact signature today.

> **TARGET (§4.2):** the *same* Ed25519 keypair will additionally sign each
> narinfo with the Nix `(StorePath, NarHash, NarSize, References)` fingerprint, so
> stock `nix` can substitute without `require-sigs = false`. The key is shared;
> the signed messages differ. See
> [signing-and-trust.md](./signing-and-trust.md).

---

## 4. `apr bundle` — materializing transport (CURRENT)

`apr bundle` (`registry_ops.rs:1718`) runs `git bundle create` into a local
output directory (default `bundles/`):

- **Snapshot:** `git bundle create <dir>/<reg>-<tag>.bundle <tag>`
  (`registry_ops.rs:1748`).
- **Delta:** with `--delta-from <from>`, `git bundle create
  <dir>/<reg>-<from>..<tag>.bundle <from>..<tag>` (`registry_ops.rs:1739`).

What it does **not** do (design brief §2.11, gap table):

- It does **not** write or update `bundle-list.toml`. The `--update-manifest`
  flag is declared (`lib.rs:553`) but the handler parameter is dead code
  (`_update_manifest`, `registry_ops.rs:1723`). The manifest types in
  `registry/bundle.rs` are `Deserialize`-only — **there is no serializer
  anywhere** (design brief §2.4, §2.11).
- It does **not** compute a `creation_token`. The encode function
  (`registry/state.rs` `version_to_token`) exists but is only called consumer-side
  (design brief §2.5, §2.11).
- It does **not** classify snapshot vs sequential vs skip delta. The producer
  passes `--tag`/`--delta-from` by hand; classification (`classify_delta`) is a
  read-time, consumer-side concern (design brief §2.4, §2.6).
- It does **not** upload anything. The only upload code in the tree is in
  `aos-cache`, and that is for NARs, not bundles (design brief §2.11).
- It does **not** emit narinfo or `nix-cache-info` (design brief §2.11).

| Capability | Status (CURRENT) | Cite |
|---|---|---|
| `git bundle create` snapshot/delta | ✅ | `registry_ops.rs:1739`, `:1748` |
| Write `bundle-list.toml` | ❌ (manifest is `Deserialize`-only) | design brief §2.4, §2.11 |
| `creation_token` compute | ❌ (encode fn unused producer-side) | design brief §2.5, §2.11 |
| Classify snapshot/sequential/skip | ❌ (read-time only) | design brief §2.4 |
| Upload bundles | ❌ | design brief §2.11 |
| narinfo / `nix-cache-info` | ❌ | design brief §2.11 |

> **TARGET (§4.3):** `bundle-list.toml` is **removed** entirely; its enumeration
> moves **into** the single signed root `registry.toml`, referenced by hash
> (by-hash discipline). See [registry-toml.md](./registry-toml.md) and
> [http-layout.md](./http-layout.md).

---

## 5. Concurrency model — git ref CAS is the lock

### 5.1 CURRENT: `apr push` = `git push`, FF-rejection is the only guard

`apr push` (`registry_ops.rs:1410`) assembles a plain `git push` argument vector
and runs it (`registry_ops.rs:1435`). There is **no separate lock service, no
lease, no advisory lock file** — the design brief §2.11 states plainly: "No
locks/atomicity beyond git's own FF-rejection on push."

The safety property is borrowed wholesale from git's ref-update semantics:

- A `git push` of a branch ref is an **atomic compare-and-swap** on the remote:
  the update succeeds only if the remote ref still points at the commit the
  pusher's local ref descends from (a fast-forward).
- Two publishers who both branched from commit `C` and pushed: the **first** wins
  the CAS; the **second** gets a **non-fast-forward rejection** and must
  reconcile.

```
   pusher A          remote ref          pusher B
   ────────          ──────────          ────────
   HEAD = A1
                     origin = C
   git push  ─────►  CAS(C → A1) ✓
                     origin = A1
                                         HEAD = B1  (also from C)
                     CAS(C → B1) ✗  ◄──  git push   → "non-fast-forward" reject
                                         apr pull --rebase   (replay B1 onto A1)
                                         HEAD = B1'
                     CAS(A1 → B1') ✓ ◄──  git push  retry  ✓
```

The loser's recovery primitive is `apr pull --rebase` (`registry_ops.rs:1445`,
`git pull --rebase`), which replays the local commit on top of the winner's, then
retries the push. This rebase-and-retry loop is **manual today** — `apr` does not
auto-retry.

> **`--force` escape hatch (CURRENT).** `apr push --force` (`registry_ops.rs:1425`)
> bypasses the FF check entirely — it is a non-CAS overwrite that can clobber a
> concurrent publish and create a history the consumer's downgrade defenses
> (`check_downgrade` / `merge-base --is-ancestor`, `security.rs`) will flag as
> `Diverged`. Reserve it for single-publisher recovery, never for routine
> publishing.

### 5.2 TARGET: the strict atomic publish ordering (§4.4)

The git CAS guarantees *metadata* linearizability. The remaining problem is the
*artifacts* (bundles, narinfos, root) on the HTTP origin, which is not git and has
no CAS — unless we impose one. The design brief §4.4 fixes the only safe ordering:

1. **Land + sign + push.** `apr publish` → commit → `apr sign` (SSH-Ed25519) →
   `apr push`. The CAS winner alone proceeds; losers `pull --rebase` + retry.
2. **Winner generates from the landed commit.** Only the CAS winner materializes
   the artifacts — bundles, narinfos, `nix-cache-info` — from the exact commit
   that landed, so the artifacts correspond to authentic, signed metadata.
3. **Upload immutable, content-addressed objects first.** NARs, `*.narinfo`, and
   `*.bundle` are content-addressed and therefore **idempotent**: they may be
   uploaded in any order, retried freely, and a concurrent publisher uploading the
   same object writes identical bytes. No coordination needed.
4. **Flip the root last, atomically.** `registry.toml` is the *only* mutable
   object. It is replaced via a **conditional PUT** — S3 `If-Match` /
   `If-None-Match` ETag CAS — so a lost update (two flips racing) is rejected
   rather than silently overwritten. Because step 3 already uploaded everything
   the new root references, a reader sees **either** the old root **or** the new
   root, never a torn state pointing at a missing object.

```
  ORDER     OBJECT                         MUTABILITY        CAS MECHANISM
  ─────     ──────                         ──────────        ─────────────
   1        git commit (metadata)          append-only       git ref FF CAS
   2        (winner generates artifacts)   —                 —
   3a       nar/<h>.nar.zst                immutable (CA)    none needed (idempotent)
   3b       <storehash>.narinfo            immutable (CA)    none needed
   3c       bundles/<...>.bundle           immutable (CA)    none needed
   4        registry.toml  (the ROOT)      MUTABLE           conditional PUT (If-Match ETag)
```

**Invariant:** everything the new root references must already exist before the
root flips. The flip is the single linearization point on the HTTP origin; the
git push is the single linearization point on the metadata.

### 5.3 TARGET: "latest" is an explicit signed field, not derived

CURRENT: there is no "latest" pointer at all; consumers derive freshness by
scanning the manifest for the maximum `creation_token` (design brief §2.11).

TARGET (§4.3, §4.4): `registry.toml` carries an explicit, signed `[latest]` block
— `tag`, `token`, and `head` (the authentic git commit SHA) — flipped atomically
as the final publish step. This is the anti-rollback / freshness anchor that a
dumb-HTTP directory listing cannot provide. See
[registry-toml.md](./registry-toml.md) and
[versioning-and-channels.md](./versioning-and-channels.md).

---

## 6. Why conditional-PUT + by-hash defeats the torn read

The combination of three disciplines makes a mid-publish reader always see a
consistent registry:

1. **Content-addressed artifacts** (already true for NARs; TARGET for bundles +
   narinfos): the *name* of an object is a hash of its bytes, so an object can
   never change meaning. Re-uploading is a no-op.
2. **By-hash references in the root** (TARGET, §4.3 / APT `by-hash` discipline):
   `registry.toml` references each bundle/index *by its hashed key*. A client that
   read `root@T` resolves a fully consistent object set even if `root@T+1` lands
   mid-fetch, because the objects `root@T` named are immutable and still present.
3. **Atomic root flip via conditional PUT** (TARGET, §4.4): the root is the only
   mutable object and is swapped with an ETag CAS, so readers observe exactly one
   of `{root@T, root@T+1}`, never a half-written root.

The threat-model payoff (design brief §4.5):

| Threat | Defense | CURRENT / TARGET |
|---|---|---|
| Tamper / MITM | signed commit + signed root + content hashes pin the bytes | commit-sign CURRENT; root-sign TARGET |
| Torn publish (reader mid-flip) | by-hash refs + atomic conditional-PUT root flip | TARGET (§4.3, §4.4) |
| Lost update (two flips race) | conditional PUT `If-Match` rejects the stale writer | TARGET (§4.4) |
| Rollback / stale mirror | `check_monotonic` on `[latest].token` + `merge-base --is-ancestor` | `check_monotonic` exists consumer-side (design brief §2.5); `[latest]` TARGET |
| Freeze (valid-but-old root) | `valid_until` expiry in the signed root → client rejects expired | TARGET (§4.5, §6 Tier 1) |
| Omission (listing hides newer bundles) | signed `[latest].head` → client fails closed, can't reach signed target | TARGET (§4.5) |

---

## 7. End-to-end producer walkthrough

### 7.1 CURRENT (what works today)

```sh
# One-time
apr create acme --remote git@github.com:acme/registry.git

# Per release
apr publish /nix/store/<hash>-curl-8.5.0 \
    --description "URL transfer tool" --license MIT --maintainer acme
# → writes packages/c/curl.toml + closures/<hash>, then commits

apr tag v2026.06.0 --message "June release"   # plain git tag (--key ignored)
apr sign                                      # git commit --amend -S on HEAD
apr push --set-upstream --branch main         # FF-only CAS; the lock

# Manual, local-only transport materialization (no manifest, no upload):
apr bundle --tag v2026.06.0                              # snapshot bundle
apr bundle --delta-from v2026.05.0 --tag v2026.06.0      # delta bundle
# → files land in ./bundles/ ; publishing them to a mirror is out of scope
```

Everything after `apr push` is incomplete: the operator must hand-copy bundles to
a mirror, hand-author `bundle-list.toml`, and there is no NAR/narinfo upload from
this tool (NAR upload lives in `aos-cache`).

### 7.2 TARGET (the §4.4 pipeline, e.g. a future `apr release`)

```
apr publish … && apr sign && apr push        # land + sign + CAS-win
        │
        ▼  (winner only, from the landed commit)
generate: bundles + creation_token + delta classification
          narinfos (Ed25519 Sig) + nix-cache-info
        │
        ▼
upload immutable CA objects: nar/, *.narinfo, *.bundle   (idempotent, any order)
        │
        ▼
flip registry.toml via conditional PUT (If-Match ETag)   (atomic, last)
        └─ updates [latest] {tag, token, head}, by-hash bundle index, valid_until
```

Open design questions for this pipeline (design brief §7): whether `apr` gains a
real `apr release` orchestrator, whether upload backends are pluggable (S3 /
rsync / plain PUT), the `valid_until` window + re-sign cadence, and the
`bundle-list.toml` → `registry.toml` migration (compat shim vs clean schema-version
break). See [open-questions.md](../plans/registry/open-questions.md) and
[workstream-02-publish-pipeline.md](../plans/registry/workstream-02-publish-pipeline.md).

---

## 8. Cross-references

- [README.md](./README.md) — registry doc index and overview.
- [architecture.md](./architecture.md) — the layered trust/metadata/blob model.
- [current-state.md](./current-state.md) — full as-is grounding (design brief §2).
- [http-layout.md](./http-layout.md) — object/namespace layout, by-hash, S3 vs dumb HTTP.
- [registry-toml.md](./registry-toml.md) — the single signed root schema and `[latest]`.
- [bundles-and-deltas.md](./bundles-and-deltas.md) — consumer-side bundle selection.
- [nix-cache-compatibility.md](./nix-cache-compatibility.md) — narinfo / `nix-cache-info` emission.
- [signing-and-trust.md](./signing-and-trust.md) — one Ed25519 key, two protocols; threat model.
- [versioning-and-channels.md](./versioning-and-channels.md) — channels, rollouts, `creation_token`.
- [apt-comparison.md](./apt-comparison.md) — APT `InRelease` / `by-hash` / `Valid-Until` precedent.
- Plan: [design-brief.md](../plans/registry/design-brief.md) (§2.11, §4.4 are authoritative for this doc),
  [gap-analysis.md](../plans/registry/gap-analysis.md),
  [workstream-02-publish-pipeline.md](../plans/registry/workstream-02-publish-pipeline.md).
