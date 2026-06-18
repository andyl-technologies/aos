> **Scope note.** This file covers caches the hub *observes* — the
> advertised-endpoint stack a registry points consumers at, and the
> always-on consistency validation over it. **Hosting and managing** caches
> (GC, size limits, search, GC roots, NAR explorer) is
> [11-caches.md](11-caches.md): the "CacheStore" below is realized by a managed
> `caches` row, and the advertised-endpoint table (`caches(registry_id, url,
> priority)`) is renamed `advertised_caches` there to free the `caches` name
> for the managed object.

### Cache stores, stacks, and consistency validation

**Shared NAR storage (no duplication).** Verified against the code:
narinfo and NAR files contain nothing registry-specific — no registry
id, content-hash-named files, signatures over content
(`crates/aos-core/src/nar/info.rs`) — so multiple registries pointing
`[[caches]]` at the same cache URL is already fully supported with
natural deduplication. The hub models this as a shareable
**CacheStore** (a binding + prefix that several registries advertise):
an org with twenty team registries stores each NAR once. No
`registry.toml` change required.

**Cache stacks.** Today the `[[caches]]` list is a *preference* list,
not a failover chain: `apm` resolves the highest-priority cache and
uses only it (`resolve_mirror` in
`crates/aos-package/src/download.rs` takes
`mirrors.first()`). The stack model generalizes this into a small,
nestable expression:

```text
StackNode =
  | endpoint(url)            # one cache endpoint
  | try [node, node, …]      # ordered fall-through: hit each member
                             # top-to-bottom, first hit wins
                             # (availability = UNION of members)
  | mirror [node, node, …]   # declared replicas: every member is
                             # expected to hold the full set
                             # (validation invariant: INTERSECTION
                             # must equal union; client may use any
                             # member — first, or latency-based)
```

`try` is the user-visible "stack": top-to-bottom fall-through, union
semantics. `mirror` is a replication contract: it doesn't change what
a client may fetch, it changes what the validator *enforces* (every
member individually complete) and what the hub's replication jobs
maintain. Nodes nest — e.g. `try [ mirror [r2-eu, r2-us],
upstream-cdn, s3-backup ]` — internal fast replicas first, falling
through to the upstream public cache, then cold backup.

Encoding, in two backwards-compatible layers:

1. **Flattened `[[caches]]`** — every stack flattens to today's
   priority list (depth-first order → descending priorities), so
   existing clients keep working with no schema change. The parser
   ignores unknown fields (`RegistryRootConfig` has no
   `deny_unknown_fields`), making layer 2 additive-safe.
2. **A committed `[cache_stack]` expression** in `registry.toml` for
   stack-aware clients, carrying the full nested structure.

Required `apm` enhancement (small, and valuable independent of stacks):
**miss-fallthrough** — on narinfo/NAR 404 from the selected cache, fall
to the next entry instead of failing. Phase one of the stack feature is
exactly this (making the flattened list behave as a `try` stack);
nested semantics ride on the `[cache_stack]` expression afterward.

**Consistency validation.** The hub continuously proves that *every
package the registry lists actually resolves in the caches it
advertises* — the server-side, always-on generalization of
`apr validate`:

- **What is checked**: for each package version × platform in the
  verified index, the full closure set (store path + transitive
  references, walked via `closures/` and narinfo `References`) against
  each advertised cache endpoint.
- **Depths**: `presence` (HEAD each `.narinfo`), `integrity` (HEAD the
  NAR; `FileSize`/`Compression` consistency), `deep` (sampled download
  + `FileHash` verification). Presence runs on every index refresh and
  after every managed publish; integrity on schedule; deep on a sampled
  rotation.
- **Coverage requirements derive from stack semantics**: for a `try`
  node, the *union* of members must cover the closure set (and the hub
  reports which member serves what fraction — a top member at 60%
  coverage means 40% of fetches fall through); for a `mirror` node,
  *each member individually* must cover it — any shortfall is a
  replication failure, with a one-click repair job that copies the
  missing objects from a member that has them (content-addressed, so
  always safe).
- **Surfacing**: a per-registry health page with a cache × coverage
  matrix, missing-path drill-down, and history; failures are
  first-class health states on the registry home (consumers deserve to
  see "mirror X is missing 3 NARs" before pointing a fleet at it).
- **Gating**: on hub-managed publishes, the pointer flip can optionally
  be gated on `presence` validation of required caches — a release is
  not announced until its closures are fetchable. Wire semantics, so
  the unchanged-CLI contract holds: with the gate enabled, the facade
  accepts the client's mutable-pointer PUTs into a **staging area** and
  returns `202 Accepted` with a status URL; validation runs; on pass
  the hub flips the pointers server-side (under the publish lease,
  conditional-PUT), on fail the release stays staged and visible in the
  publish pipeline view with the missing-path report. `apr` treats
  `202` on mutable uploads as success-pending and can poll (`apr
  release --wait`); a staged release that is never repaired is
  garbage-collected after a configurable window (default 7 days) and
  audited as abandoned. With the gate disabled (the default), pointer
  PUTs apply immediately and validation runs after the fact.

### Mirroring other registries

Headline property, worth stating prominently: **a mirror cannot alter
content without breaking verification.** Releases are signed tag
objects, partitions are signed name-bound tags, objects are sha256
content-addressed, narinfos are Ed25519-signed — a mirror is a byte
courier, not a trust party. The only attacks left are staleness/freeze
and withholding, both already bounded by the consumer's
`max_staleness_seconds` and monotonic anti-rollback floor.

Three named modes, to prevent concept confusion:

1. **Full mirror** — the "internal mirror of the public andyl
   registry" case. A registry of `kind: mirror` with a `MirrorSource
   { upstream_url, schedule, verify: true }`: a scheduled job fetches
   the upstream surface exactly as `apm` would (the same `surface/`
   reader), **verifies tags against the upstream roster before
   accepting anything**, writes byte-identical files into the local
   binding immutable-first, and refuses to flip local pointers on
   verification failure — a poisoned upstream never propagates.
   Consumers keep **upstream trust anchors**; only the URL in their
   `registries.d` changes. The UI labels it "mirror of
   https://cdn.aos.andyl.org — trust anchors are upstream's" and shows
   sync lag.
2. **Derived registry** — re-signed under the org's own roster;
   may subset, extend, or re-publish. Different commit hashes,
   different trust anchors — genuinely a different registry. This is a
   publish-pipeline feature (an eventual `apr import-from`), named here
   to keep it distinct, deferred past v1.
3. **Pull-through cache** — a *proxied* frontend that fetches from
   upstream on miss, verifies, persists to the local binding, and
   serves. Content-addressed payloads (objects, packs, NARs) are
   verified by hash and trivially safe to persist; pointers
   (`info/refs`, partition tags) are self-verifying but are persisted
   with upstream-equivalent low TTL and re-fetched on expiry — never
   frozen. The proxy falls through to upstream on any local miss, so
   ordering hazards don't exist: fall-through *is* the completeness
   guarantee. A natural fit for the Workers target with R2 as the
   persistent cache; the same logic runs over the local binding
   natively. (A pull-through frontend composes with cache stacks: it
   is an `endpoint` whose backing happens to be lazy.)

