# AOS Registry — Open Questions, Risks & Migration Strategy

> **Status:** Plan document. Derived from the
> [design brief](./design-brief.md) §7, with risk and migration detail expanded
> for implementers. Where this doc describes **CURRENT** behavior it cites code
> as `path:line` (paths relative to the repo root; the registry crate is
> `crates/aos-package/`). Where it describes **TARGET** behavior it draws from
> the brief's §4–§6 decisions.
>
> **Audience:** implementers, architects, engineers, and reviewers who must sign
> off before the `registry.toml` root and the publish pipeline land.

This is the living register of *unresolved* decisions for the AOS registry
redesign. Everything here is deliberately **not** settled in the reference docs;
each item names the owning workstream, the options on the table, a
recommendation where the brief implies one, and the blast radius if we get it
wrong. The single largest cross-cutting decision — **migration: compat shim vs.
clean break with a schema bump** — gets its own section (§3) because it gates the
sequencing of every other workstream.

---

## 0. How to read this document

| Column / marker | Meaning |
|---|---|
| **CURRENT** | As-is behavior, grounded in code (`path:line`). |
| **TARGET** | The decided end-state from the [design brief](./design-brief.md) §4. |
| **OPEN** | A genuinely unresolved choice. Must be closed before the owning workstream merges. |
| **Owner WS** | The workstream that must resolve and implement the decision. |

Workstream references:

- [WS-01 — registry root](./workstream-01-registry-root.md)
- [WS-02 — publish pipeline](./workstream-02-publish-pipeline.md)
- [WS-03 — nix cache](./workstream-03-nix-cache.md)
- [WS-04 — channels & rollouts](./workstream-04-channels-rollouts.md)
- [WS-05 — consumer](./workstream-05-consumer.md)

See also the [gap analysis](./gap-analysis.md) for the full producer/consumer
gap enumeration and the [plan README](./README.md) for milestone sequencing.

---

## 1. The open questions (brief §7, expanded)

The numbering follows the design brief §7 exactly so the two documents stay in
lockstep. Each entry adds the owning workstream, the decision options, a default
recommendation, and the failure mode.

### Q1 — Exact `packages/*.toml` field names and shape

| | |
|---|---|
| **Brief §7** | "Exact `packages/*.toml` field names/shape — confirm against `types.rs` before enshrining in the reference schema doc." |
| **Owner WS** | [WS-01](./workstream-01-registry-root.md) (schema), informs [WS-03](./workstream-03-nix-cache.md) (narinfo mapping) |
| **Status** | OPEN — verification task, not a design choice. |

**Why it is open.** The [current-state](../../registry/current-state.md) and
[registry-toml](../../registry/registry-toml.md) reference docs describe the
package-TOML fields (`store_path`, `nar_hash`, `nar_size`, `download_hash`,
`download_size`, `closure_size`, `source_drv`, `source_nar_hash`, `references`,
plus `[[…images]]` for sysroot images) **from the design conversation**, not
from a field-by-field read of the serde structs. The brief itself flags this:
package-TOML fields were "Established fields from the conversation (implementers
MUST confirm exact names against `types.rs`)" (design brief §2.3).

**What must happen.** Before the narinfo generator (WS-03) and the
`registry.toml` serializer (WS-01) hard-code field names, an implementer must
read the `#[derive(Deserialize)]` structs in `crates/aos-package/src/types.rs`
and reconcile every name, optionality, and default against the reference schema.
Any mismatch is a documentation bug to be fixed in
[registry-toml.md](../../registry/registry-toml.md), not a silent code change.

**Failure mode.** Low blast radius but high friction: a wrong field name in the
narinfo `References:` expansion (see Q-refs below) produces narinfos that stock
`nix` rejects, and the failure surfaces only at substitution time on a
dev-shell host, far from the producer.

> **Recorded discrepancy (see Open Questions output).** This authoring pass did
> not re-read `types.rs`. The field list in the reference docs is therefore
> *brief-grounded, not code-verified*. Q1 must be closed by direct code reading.

### Q2 — NAR co-location vs. separate cache origin

| | |
|---|---|
| **Brief §7** | "Serve NARs under `{base}/nar/` on the registry origin, or keep them on a separate cache and only point narinfo `URL:` at it? (Both work; pick per deployment.)" |
| **Owner WS** | [WS-03](./workstream-03-nix-cache.md) (narinfo `URL:`), [WS-02](./workstream-02-publish-pipeline.md) (upload backends) |
| **Status** | OPEN — explicitly a per-deployment choice, not a single global decision. |

**The two layouts.**

```
Option A — co-located (single origin)
  https://registry.example/
    ├── registry.toml            (signed root)
    ├── nix-cache-info
    ├── <storehash>.narinfo       URL: nar/<download_hash>.nar.zst   (relative)
    ├── nar/<download_hash>.nar.zst
    └── bundles/<name>/...

Option B — split origin (registry separate from blob store)
  https://registry.example/        https://cache.example/
    ├── registry.toml                └── nar/<download_hash>.nar.zst
    ├── nix-cache-info
    ├── <storehash>.narinfo
    │     URL: https://cache.example/nar/<download_hash>.nar.zst  (absolute)
    └── bundles/<name>/...
```

**What the code does today (CURRENT).** The consumer already separates the two:
`download.rs` builds `nar_url(mirror_url, nar_hash)` →
`{mirror_url}/{nar_hash}.nar.zst`, and `resolve_mirror` reads `[[caches]]` from
the local registry clone (sorted by priority), falling back to
`{registry.url}/nar` (design brief §2.8). So the *consumer* is already
co-location-agnostic; the open question is which the *narinfo `URL:`* points at
for **stock `nix`** consumers, which cannot read `[[caches]]`.

**Recommendation.** Make it a publish-time configuration knob: emit **relative**
narinfo `URL:` (Option A) by default so a single-origin deployment "just works",
and allow an absolute-URL override (Option B) for deployments with a dedicated
CDN/blob origin. The brief deliberately leaves this open — the design must
support both, not pick one.

**Interaction with Q3.** Whichever layout is chosen, the NAR filename grammar
(Q3) must survive the chosen edge.

### Q3 — narinfo `URL:` colon-in-filename through the CDN/edge

| | |
|---|---|
| **Brief §7** | "narinfo `URL:` colon-in-filename (`sha256:<hex>.nar.zst`) — confirm acceptable through the chosen CDN/edge (S3 allows colons; some edges re-encode)." |
| **Owner WS** | [WS-03](./workstream-03-nix-cache.md), [WS-02](./workstream-02-publish-pipeline.md) (upload) |
| **Status** | OPEN — environment-dependent; needs an empirical check per edge. |

**The hazard.** AOS names NAR blobs by the full `sha256:<hex>` string — the
filename **literally contains a colon** (design brief §2.8;
`download.rs nar_url`). Object stores and CDNs disagree on colon handling: S3
permits `:` in keys, but some HTTP edges/proxies percent-encode `:` → `%3A` on
the way through, which silently breaks the content-address match on the client.

**Options.**

1. **Keep the colon.** Verify per-edge that `:` passes through unmodified
   end-to-end (request, cache key, and stored object key). Cheapest; matches the
   existing consumer code with no change.
2. **Switch the on-disk NAR filename to `download_hash`** (the compressed-file
   hash, already a colon-free-able hex) for the narinfo `URL:`, while keeping the
   `nar_hash` colon form only inside TOML metadata. The
   [nix-cache-compatibility](../../registry/nix-cache-compatibility.md) reference
   already notes `URL: nar/<download_hash>.nar.zst` as the derived narinfo field
   (design brief §4.1 table), which is colon-free if `download_hash` is rendered
   as bare hex.
3. **Encode defensively** — produce both forms and 301-redirect, only if an edge
   forces it. Adds origin complexity; avoid unless required.

**Recommendation.** Prefer Option 2 for the narinfo `URL:` path (colon-free,
robust across edges) and keep the colon form only where it is already
load-bearing in TOML. Confirm against the actual `download.rs` filename
convention during WS-03 before committing — this overlaps Q1's verification.

**Failure mode.** Silent: a re-encoding edge yields HTTP 403/404 on NAR fetch,
or worse, a 200 on a differently-keyed object whose hash then fails
verification. Either way the failure is at the consumer, hard to attribute back
to the edge.

### Q4 — Rollout gating function (phased updates)

| | |
|---|---|
| **Brief §7** | "Rollout gating function — exact deterministic hash (machine-id + channel/tag) and how clients learn their percentage bucket." |
| **Owner WS** | [WS-04](./workstream-04-channels-rollouts.md) (producer side), [WS-05](./workstream-05-consumer.md) (client gating) |
| **Status** | OPEN — both the hash construction and the bucket-discovery mechanism are undecided. |

**What is decided (TARGET).** `[channels]` in `registry.toml` carry an optional
`rollout = N` percentage; clients gate on a deterministic hash of the machine-id
so a given machine deterministically lands in-or-out of the rollout, mirroring
APT's `Phased-Update-Percentage` (design brief §4.3, §6 Tier-1 item 4). The
percentage lives in the signed root, so the producer controls blast radius with
a single atomic flip.

**What is open.**

1. **Hash inputs.** The brief says "machine-id + channel/tag". The exact
   pre-image matters for stability: if the channel *name* is hashed, a machine's
   in/out decision is stable across promotions within the same channel; if the
   target *tag* is hashed, every new tag re-shuffles the cohort (a different set
   of machines is canaried each release). These have opposite operational
   properties; the design must pick deliberately.
2. **Hash function.** Needs to be a stable, well-specified digest (e.g. a
   truncated SHA-256 of `"{machine-id}:{channel}"` taken mod 100). Must be
   pinned in the spec so client and any server-side analytics agree.
3. **Bucket discovery.** "How clients learn their percentage bucket" — the
   client computes its own bucket locally from `machine-id` and compares to the
   signed `rollout = N`; no server round-trip should be required (offline-safe,
   no fingerprinting leak). Confirm there is no need for the server to *know* a
   client's bucket.
4. **Machine-id source on AOS.** Which identifier (`/etc/machine-id`,
   systemd's, a registry-local salt?) and what happens on machines without one.

**Recommendation.** Hash `"{channel}:{machine-id}"` (channel name, not tag) so
cohorts are stable across promotions; truncated SHA-256 mod 100; purely
client-local computation. Spell the exact pre-image and digest in WS-04 so it is
reproducible and testable. This is operational, not a correctness gate — a wrong
choice degrades to "rollouts shuffle oddly", not "machines get bad bytes".

### Q5 — `valid_until` window length and re-sign cadence

| | |
|---|---|
| **Brief §7** | "`valid_until` window length and re-sign cadence/automation." |
| **Owner WS** | [WS-04](./workstream-04-channels-rollouts.md), [WS-02](./workstream-02-publish-pipeline.md) (re-sign automation) |
| **Status** | OPEN — policy + automation, no single right number. |

**What is decided (TARGET).** The signed root carries an APT-style `valid_until`
expiry; a client **rejects an expired root** (design brief §4.5 Freeze, §6
Tier-1 item 1). This is the freeze defense that the sequence-based `[latest]`
alone cannot provide — a mirror stuck on a validly-signed-but-old root.

**The tension.** The window length trades two failure modes:

- **Too long** (e.g. 90 days): a freeze attack / stalled mirror can serve stale
  bytes for up to the window before clients fail closed.
- **Too short** (e.g. 1 day): every consumer in a low-velocity deployment breaks
  the moment publishing pauses (holidays, incidents, a quiet package), turning a
  security feature into an availability footgun. Requires reliable re-sign
  automation that itself becomes a single point of failure.

**Open sub-questions.**

1. **Default window** and whether it is configurable per registry / per channel.
2. **Re-sign cadence** — re-sign on every publish with `valid_until = now + N`
   (brief §6 Tier-1 item 1: "Re-sign each publish with expiry = publish + N"),
   *plus* a heartbeat re-sign for registries that publish less often than `N`.
3. **Automation owner.** A heartbeat re-signer needs the signing key online or a
   short-lived delegation — which reopens key-handling questions (see §2 Risk R4).
4. **Clock-skew tolerance** on the client when comparing `now` to `valid_until`.

**Recommendation.** Start with a generous default (suggest ~30 days),
configurable; re-sign on every publish; add a scheduled heartbeat re-sign as a
WS-04 follow-on, not a launch blocker. Document the chosen number in
[versioning-and-channels.md](../../registry/versioning-and-channels.md).

### Q6 — A real `apr release` / `apr publish-bundles` command

| | |
|---|---|
| **Brief §7** | "Whether `apr` gains a real `apr publish-bundles`/`apr release` command that performs the §4.4 ordering end-to-end (generate → upload → flip), and whether upload backends are pluggable (S3, rsync, plain PUT)." |
| **Owner WS** | [WS-02](./workstream-02-publish-pipeline.md) |
| **Status** | OPEN — this is the central producer-side build decision. |

**Why it is the crux.** The producer is the [asymmetry](./gap-analysis.md): the
consumer is rich, the producer is a thin wrapper over `git` + `git bundle
create`. The design brief §2.11 enumerates the missing producer machinery — no
`bundle-list.toml` writer (manifest types are `Deserialize`-only,
`registry/bundle.rs`), `apr bundle`'s `_update_manifest` parameter is **unused
dead code** (`registry_ops.rs:1718`), no producer-side `creation_token`
computation, no delta classification, no upload, no narinfo emission, no atomic
root flip. The brief's §4.4 publishing model only becomes real when one command
performs the whole ordered sequence:

```
apr release  (TARGET — performs §4.4 ordering atomically):
  1. apr publish → commit → apr sign (SSH-Ed25519) → git push   [CAS winner]
  2. winner generates from landed commit: bundles, narinfos, nix-cache-info
  3. upload immutable content-addressed objects first (idempotent, any order)
  4. flip registry.toml LAST via conditional PUT (If-Match / If-None-Match)
```

**Open sub-questions.**

1. **Command surface.** One `apr release` that does everything, or composable
   verbs (`apr bundle` → `apr upload` → `apr flip-root`) that a release script
   chains? The latter is more testable and lets CI own ordering; the former is a
   safer default for humans (the ordering in §4.4 is the *only* safe order).
2. **Pluggable upload backends.** S3 (with `If-Match`/`If-None-Match` ETag CAS
   for the root flip), rsync, and plain HTTP PUT are all named. Conditional PUT
   semantics differ across backends — rsync has no native CAS, so the atomic
   root-flip guarantee (brief §4.4 step 4) is **backend-dependent**. Define what
   "atomic flip" degrades to on a backend lacking conditional PUT.
3. **Where bundle/narinfo generation runs.** On the publishing host from the
   landed commit, or as a separate CI job that re-derives from the signed `head`?
4. **Idempotency / resume.** A `release` that fails after step 3 but before step
   4 must be safely re-runnable (immutable objects already uploaded).

**Recommendation.** Build composable verbs underneath a single `apr release`
convenience wrapper; make upload a trait with S3/rsync/PUT impls; require the S3
backend to use ETag CAS for the root and document that rsync/PUT flips are
last-writer-wins (acceptable only for single-publisher registries). This is the
heart of WS-02 and gates the whole target design becoming operable.

### Q7 — Migration: compat shim vs. clean break with schema bump

| | |
|---|---|
| **Brief §7** | "Migration: do existing `bundle-list.toml` mirrors get a compatibility shim, or is this a clean break with a schema-version bump?" |
| **Owner WS** | [WS-01](./workstream-01-registry-root.md) (schema/version), [WS-05](./workstream-05-consumer.md) (consumer dual-read) |
| **Status** | OPEN — the highest-leverage open question. Owns its own section below. |

This is large enough that it gets [§3](#3-migration-strategy-the-central-decision).

---

## 2. Risk register

Risks that are not phrased as a single "which option" question but that the
implementation must actively manage. Each names the mitigation and the owning
workstream.

| ID | Risk | Likelihood × Impact | Mitigation | Owner WS |
|---|---|---|---|---|
| **R1** | **Brief-grounded fields drift from code.** Reference schema docs were written from the design conversation, not a `types.rs` read (Q1). | Med × Med | Close Q1 by direct code read before WS-01/WS-03 hard-code names; add a schema round-trip test. | WS-01, WS-03 |
| **R2** | **Torn publish.** A reader fetches `registry.toml@T+1` whose referenced bundle/narinfo isn't uploaded yet. | Low × High | Strict §4.4 ordering: immutable objects first, root flip last; by-hash references so root@T stays resolvable after root@T+1 (brief §4.3, §6 Tier-1 item 2). | WS-02 |
| **R3** | **Atomic-flip guarantee is backend-dependent.** rsync/plain-PUT lack conditional PUT; concurrent publishers can lose updates (Q6.2). | Med × High | Restrict non-CAS backends to single-publisher registries; require S3 `If-Match` for multi-publisher; document the degradation. | WS-02 |
| **R4** | **Online signing key for heartbeat re-sign.** `valid_until` heartbeat (Q5) wants the key available off the publish path. | Med × High | Prefer publish-time re-sign only at launch; if heartbeat is needed, use a short-lived delegated key, never the long-term commit/narinfo key online. | WS-04 |
| **R5** | **Colon-in-filename breakage on an edge** (Q3). Silent NAR-fetch failures far from the producer. | Med × Med | Prefer colon-free `download_hash` narinfo `URL:`; add an integration test that fetches a NAR end-to-end through the real edge. | WS-03 |
| **R6** | **Rollout cohort instability** (Q4). Hashing the tag instead of the channel re-shuffles canaries every release. | Med × Low | Hash the channel name; spec and test the exact pre-image. | WS-04 |
| **R7** | **Stock-`nix` rejects generated narinfos.** Missing/incorrect `Sig:`, bad `References:` basename expansion, or `nix-cache-info` mismatch (brief §4.1). | Med × Med | Golden-file narinfo tests against a real `nix` substituter in CI before WS-03 ships; references must expand bare hashes → `<hash>-<name>` basenames. | WS-03 |
| **R8** | **Migration straddle bugs** (Q7). A half-migrated mirror serves neither format cleanly; old clients hit a `registry.toml`-only mirror, or new clients hit a `bundle-list.toml`-only mirror. | Med × High | A bounded dual-read/dual-publish window with a hard EOL; never an indefinite straddle (see §3). | WS-01, WS-02, WS-05 |
| **R9** | **`creation_token` overflow / encoding mismatch** between the new producer writer and the existing consumer decode. Consumer enforces month 1–12, patch ≤ 9999 (`registry/state.rs version_to_token`, brief §2.5). | Low × Med | The producer's new encoder MUST reuse the *same* `version_to_token` function, not a re-implementation; add a producer/consumer round-trip test. | WS-02 |
| **R10** | **Freeze window vs. availability** (Q5). `valid_until` too short breaks quiet registries; too long weakens the freeze defense. | Med × Med | Generous default + per-registry override + heartbeat re-sign; document the trade-off prominently. | WS-04 |

---

## 3. Migration strategy — the central decision

> This section is the expanded answer to **Q7** and the migration half of this
> document's mandate. It does not *decide* the question (the brief leaves it
> open) but it frames the two paths, their consequences, and a recommended
> sequence so the decision can be made with eyes open.

### 3.1 What is actually changing on the wire

The redesign replaces the **root index file** and adds two new namespaces. The
*bundle* objects and the *NAR* objects do not change shape.

| Layer | CURRENT | TARGET | Breaking? |
|---|---|---|---|
| Root index | `bundles/{name}/bundle-list.toml`, `Deserialize`-only `BundleManifest` (`registry/bundle.rs`) | single signed `registry.toml` at `{base}/registry.toml` (brief §4.3) | **Yes** — new file, new location, inline signature, `[latest]`/`[channels]`/`valid_until` fields |
| Bundle blobs | `bundles/{name}/{uri}` git bundles | unchanged (still git bundles, referenced by-hash from the root) | No |
| NAR blobs | `{mirror}/{nar_hash}.nar.zst` (`download.rs`) | unchanged, possibly co-located + colon question (Q2/Q3) | Mostly no |
| Nix protocol | absent | new: `nix-cache-info`, `<storehash>.narinfo`, `nar/` (brief §4.1) | Additive (strict superset) — never breaks existing AOS clients |
| Signing | signed git commit only (`security.rs`) | signed commit **+** inline-signed root **+** per-narinfo `Sig:` (brief §4.2) | Additive at the trust root; the inline root signature is new to verify |

The Nix-cache layer (WS-03) is a **strict superset** in disjoint URL namespaces
(brief §4.1, §3 clarification 1) — it can never break an existing `apm` client,
so it is *not* part of the migration tension. The migration question is entirely
about the **root file** swap: `bundle-list.toml` → `registry.toml`.

### 3.2 Option A — compatibility shim (dual-publish, dual-read)

The producer emits **both** roots for a transition window; consumers prefer
`registry.toml` and fall back to `bundle-list.toml`.

```
Mirror during the shim window:
  {base}/registry.toml              ← new clients (preferred)
  {base}/bundles/{name}/bundle-list.toml   ← old clients (fallback)
  {base}/bundles/{name}/*.bundle    ← shared, unchanged
```

- **Producer:** the new `apr release` writes `registry.toml` *and* regenerates
  `bundle-list.toml` from the same landed commit. Note this requires building the
  `bundle-list.toml` **writer that does not exist today** (brief §2.11; the
  manifest types are `Deserialize`-only) — so the shim is *not* free; it forces
  implementing a serializer for a format we intend to retire.
- **Consumer:** `apm update` tries `registry.toml`; on 404 (old mirror) falls
  back to the existing `BundleManifest::fetch` path
  (`{base}/bundles/{name}/bundle-list.toml`, brief §2.4).

| Pros | Cons |
|---|---|
| Old clients keep working with zero coordination. | Must build a throwaway `bundle-list.toml` **writer** (new code for a dying format). |
| Mirrors can be migrated lazily, one at a time. | Two roots to keep consistent — a torn/skewed pair is a new failure mode (R8). |
| No flag day; safe for fleets with mixed client versions. | The new security properties (`valid_until` freeze defense, signed `[latest]`, by-hash) are **absent** for clients still on the old root — the shim *weakens the security story* for the duration. |
| | Indefinite straddle risk if the EOL is never enforced. |

### 3.3 Option B — clean break with a schema-version bump

`bundle-list.toml` is removed; `registry.toml` carries `[meta] schema/version`
(brief §4.3); old clients are explicitly cut over.

- **Producer:** `apr release` writes only `registry.toml`. No `bundle-list.toml`
  writer is ever built (the dead `_update_manifest` parameter at
  `registry_ops.rs:1718` is simply deleted).
- **Consumer:** clients are upgraded to read `registry.toml` *before* any mirror
  drops `bundle-list.toml`. The `[meta]` `schema`/`version` field lets a client
  refuse a root it is too old to understand (forward-compat, brief §4.3, §6
  Tier-2 capability flags).

| Pros | Cons |
|---|---|
| No throwaway serializer; the dead `_update_manifest` path is deleted, not revived. | Requires coordinated client rollout *before* mirror cutover (a flag day per mirror). |
| Full target security model (`valid_until`, signed `[latest]`, by-hash) from day one for every client. | Old `apm` binaries break the moment a mirror cuts over — bad for fleets that pin old clients. |
| One root file; no dual-write consistency hazard (closes R8). | Needs a "minimum client version" gate communicated and enforced. |
| Simpler producer; fewer moving parts in the highest-risk new pipeline (WS-02). | |

### 3.4 Recommended path: bounded shim → schema-gated clean break

The brief does not decide this, but its design pressure points one way. The
clean break (Option B) is where we want to *land* — it is the only path that
delivers the full §4.5 threat model (freeze defense, signed `[latest]`,
fail-closed omission) to *all* clients and avoids building a serializer for a
format we are killing. But a hard flag day is hostile to fleets running pinned
`apm` binaries.

The synthesis the design implies:

1. **Ship `[meta] schema`/`version` first (WS-01).** Land the `registry.toml`
   root with an explicit schema version and capability flags *before* anything
   depends on it. This is the forward-compat lever the clean break needs.
2. **Ship the consumer dual-read first (WS-05), then wait.** Teach `apm` to
   prefer `registry.toml` and fall back to `bundle-list.toml`. This is a *thin*
   shim — it does **not** require a `bundle-list.toml` writer, only the existing
   reader as a fallback. Roll this client out and let it propagate.
3. **Producer writes only `registry.toml` (WS-02).** Do **not** build the
   `bundle-list.toml` writer. New mirrors are `registry.toml`-only; old mirrors
   keep their existing static `bundle-list.toml` files (already published, never
   regenerated). A dual-read client handles both populations during the window.
4. **Announce a minimum-client version and an EOL date.** Once telemetry/policy
   shows old clients are drained, drop the consumer fallback in a later release.

This gives the safety of a shim (no flag day; mixed clients coexist) **without**
the cost of a throwaway serializer, and converges on the clean break's
single-root simplicity and full security model. The one residual is that
*already-published* `bundle-list.toml` files served by old static mirrors lack
the new freeze/`[latest]` protections — acceptable because those mirrors are
end-of-life by construction and the EOL date bounds the exposure.

> **Decision still required.** The above is a *recommendation derived from the
> brief's pressure*, not a ratified decision. WS-01/WS-02/WS-05 owners must
> confirm: (a) the minimum-client-version mechanism, (b) the EOL date/policy,
> and (c) whether step 2's fallback is worth its complexity vs. a coordinated
> hard cutover for a small, controlled fleet.

### 3.5 Migration invariants (whatever path is chosen)

These must hold regardless of shim vs. clean break:

1. **Bundle and NAR objects never change format or location** during migration —
   only the root index moves. A migrating mirror keeps serving the same
   `*.bundle` and `*.nar.zst` bytes (§3.1).
2. **No indefinite straddle.** Any dual-read/dual-publish window has a published
   EOL; the registry must not carry two root formats forever (R8).
3. **`creation_token` encoding is shared.** The producer's new writer reuses the
   consumer's `version_to_token` (brief §2.5; `registry/state.rs`), never a
   re-implementation, so old and new tooling agree on ordering (R9).
4. **Monotonicity survives the cutover.** `check_monotonic` (brief §2.5) must see
   a non-decreasing `[latest].token` across the `bundle-list.toml` →
   `registry.toml` boundary, or clients will read the swap as a rollback.
5. **The signed commit remains the trust root throughout.** Both roots are
   downstream of the same Ed25519-signed git history; migration never introduces
   an unsigned intermediary (brief §3 clarification 3, §4.2).

---

## 4. Decision tracking

A compact index for reviewers. "Blocks" = which workstream cannot merge until the
item is closed.

| # | Question / Risk | Owner WS | Blocks merge of | Default recommendation |
|---|---|---|---|---|
| Q1 | Package-TOML field names | WS-01 | WS-01 schema, WS-03 narinfo | Read `types.rs`; reconcile docs |
| Q2 | NAR co-location vs. split origin | WS-03 / WS-02 | WS-03 narinfo `URL:` | Relative URL default, absolute override |
| Q3 | Colon-in-NAR-filename through edge | WS-03 | WS-03, WS-02 upload | Colon-free `download_hash` URL |
| Q4 | Rollout gating hash + bucket discovery | WS-04 / WS-05 | WS-04 rollouts | Hash `channel:machine-id`, client-local |
| Q5 | `valid_until` window + re-sign cadence | WS-04 / WS-02 | WS-04 freshness | ~30d default, re-sign per publish + heartbeat |
| Q6 | `apr release` shape + pluggable upload | WS-02 | WS-02 (the pipeline) | Composable verbs under one wrapper; S3 ETag CAS |
| Q7 | Migration: shim vs. clean break | WS-01 / WS-05 | WS-01, WS-02, WS-05 | Bounded thin-shim dual-read → schema-gated clean break (§3.4) |
| R2/R3 | Torn / non-atomic publish | WS-02 | WS-02 | Strict §4.4 ordering; restrict non-CAS backends |
| R7 | Stock-`nix` narinfo acceptance | WS-03 | WS-03 | Golden-file tests vs. real `nix` |

---

## 5. Related documents

**Plan set ([docs/plans/registry/](./README.md)):**

- [README](./README.md) — plan overview, milestones, sequencing.
- [design-brief.md](./design-brief.md) — authoritative intent; §7 is the source of this doc.
- [gap-analysis.md](./gap-analysis.md) — producer/consumer gap enumeration.
- [workstream-01-registry-root.md](./workstream-01-registry-root.md) — schema, serializer, inline signing (Q1, Q7).
- [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md) — `apr release`, upload, CAS (Q6, R2, R3, R9).
- [workstream-03-nix-cache.md](./workstream-03-nix-cache.md) — narinfo / `nix-cache-info` (Q2, Q3, R5, R7).
- [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md) — channels, rollouts, `valid_until` (Q4, Q5, R4, R6, R10).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — root read, channel tracking, fail-closed (Q7, R8).

**Reference set ([docs/registry/](../../registry/README.md)) — target state:**

- [README](../../registry/README.md) ·
  [architecture.md](../../registry/architecture.md) ·
  [current-state.md](../../registry/current-state.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [registry-toml.md](../../registry/registry-toml.md) ·
  [bundles-and-deltas.md](../../registry/bundles-and-deltas.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [signing-and-trust.md](../../registry/signing-and-trust.md) ·
  [publishing.md](../../registry/publishing.md) ·
  [versioning-and-channels.md](../../registry/versioning-and-channels.md) ·
  [apt-comparison.md](../../registry/apt-comparison.md)
