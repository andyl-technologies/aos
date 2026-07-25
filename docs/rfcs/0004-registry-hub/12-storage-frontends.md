# Storage-binding frontends — direct-from-bucket serving by inheritance

- **Status:** Implemented (2026-06-24). Schema (migrations v29–v30), the
  cache + registry bucket-direct resolvers, the instance-default and org
  custom-binding WebUI, and the security gate are all in and green; see the
  implementation checklist at the bottom for the per-item state and the small
  remaining polish.
- **Builds on:** [`01-architecture.md`](01-architecture.md) (a control plane
  over a *static data plane*), [`03-api-storage-frontends.md`](03-api-storage-frontends.md)
  (`StorageBinding`, shared buckets, direct/proxied frontends), and
  [`11-caches.md`](11-caches.md) (managed caches share the same storage +
  frontend machinery as registries).

> **Follow-up (migration v33) — `public_base_url` renamed to `endpoint`.**
> The body below (history) calls the bucket-origin column `public_base_url` and
> describes it as "the origin a Direct frontend rewrites/reads from." That
> framing was wrong and a footgun: the column is *only* the **S3/R2 API
> endpoint** the hub writes objects through and presigns reads against
> (`s3surface`); nothing ever read it as a consumer-facing read origin. The
> consumer-facing read URL is, and always was, a **frontend** (`direct_consumer_url`
> builds from `frontend.domain`, never this column). Yet two forms wrote the
> same column under two labels — the create form's "endpoint" and the serving
> page's "public base URL" (placeholder `cdn.example.com`) — so an operator who
> "corrected" the serving-page value to their CDN domain silently broke the
> write/presign path. v33 renames the column to `endpoint`, both forms now label
> it "endpoint" with the API-endpoint help/placeholder, the misleading
> `binding.public_base_url` help is removed, and the CLI flag is `--endpoint`.
> The model: **`endpoint` = the bucket's origin (hub I/O); frontends = where
> consumers read.** Wherever the history says `public_base_url`, read `endpoint`.

## The problem

The hub is read-heavy, and the read path's *bulk* — Nix `nar/**` and the git
wire surface (`objects/**`, packs, `info/refs`) — currently streams through the
Worker: `R2 → wasm → client`. That is the wrong layer for throughput. It bills
Worker duration on every byte, doubles the hop, and forgoes R2's CDN. The
architecture already names the right shape — *control plane over a static data
plane* — and the data model already has the pieces to realize it:

- `storage_bindings.access` is `public` or `private`, and a `public` binding
  carries a `public_base_url` described (v23) as "the origin a **Direct**
  frontend rewrites to." A `direct` frontend "CNAMEs straight to the origin and
  never reaches the hub" — i.e. bytes served straight from the bucket/CDN.
- `frontends` already model `domain`, `base_path`, `mode` (`direct`/`proxied`),
  `serves_git/cache/web`, `advertised`, `is_primary`, `consumer_priority`.

What is missing is the **binding** between those two halves:

1. **`frontends` cannot attach to a storage binding.** Its target is
   `registry_id` (v16) or `cache_id` (v24), enforced by
   `CHECK ((registry_id IS NULL) <> (cache_id IS NULL))`. A domain that serves a
   *bucket* — and that every registry/cache stored in that bucket should inherit
   — has nowhere to live. Today an operator would hand-create a near-identical
   `direct` frontend per registry, each pointing at the same bucket domain.
2. **The instance default storage is not a real row.** A registry/cache with
   `storage_binding_id IS NULL` uses "the deployment's default storage," which
   is passed through the `SurfaceProvider` port and rendered as a *synthetic*
   row in the UI (`binding.rs`). It therefore cannot carry a `public_base_url`
   or a frontend, and cannot be edited through the same form as custom bindings.
3. **No inheritance / path inference.** Nothing derives a consumer's public URL
   from its upload location — `{storage frontend domain}/{base_path}/{prefix}`.

## The model

A **storage binding owns its frontends.** A frontend on a public binding says:
*"this bucket is reachable at `domain[/base_path]`; the object at key `K` is at
`domain/base_path/K`."* Every registry and cache stored in that binding
**inherits** that frontend, with its own object paths derived from its `prefix`
(its upload location within the bucket). Each consumer can **toggle whether to
advertise** the inherited frontend, in its own config — so a registry opts its
bucket-domain substituter URL in or out without ever creating a frontend row.

The instance default storage becomes a **real, editable `storage_bindings`
row** so it carries a `public_base_url`/frontend and is edited through the exact
same form as a custom binding.

### Why this is mostly additive (no byte-path rewriting)

A crucial property keeps the facade out of the hot path entirely for the direct
case: **the hub does not generate the narinfo `URL:` field.** It is
uploader-provided and, by Nix convention, relative (`URL: nar/<hash>.nar.zst`),
resolved by the client against whatever substituter base URL it was configured
with. So "serve direct from the bucket" is **not** facade rewriting — it is
*advertising the bucket's frontend domain as the substituter URL*. A `direct`
frontend CNAMEs to the bucket, so a client configured with
`https://cdn.example.com/acme/prod` fetches both `…/<hash>.narinfo` and the
relative `…/nar/<hash>.nar.zst` straight from R2's CDN; the hub is never in the
byte path. The hub keeps serving the small, dynamic control plane (browse, RPC,
index, freshness probes) where the D1 read-replica and edge cache already help.

For a `proxied` frontend (or a `private` binding) nothing changes: the existing
hub facade — now fronted by the edge-cache read-through — serves it, with
private origins presigned (`302`) or streamed as today.

## Schema deltas

**A. Frontends become polymorphic over their target.** Add a nullable
`storage_binding_id` and widen the one-of constraint to three:

```sql
ALTER TABLE frontends ADD COLUMN storage_binding_id INTEGER
    REFERENCES storage_bindings(id) ON DELETE CASCADE;
-- replaces the 2-way CHECK with: exactly one of the three targets is set
-- CHECK ( (registry_id IS NOT NULL) + (cache_id IS NOT NULL)
--         + (storage_binding_id IS NOT NULL) = 1 )
```

(SQLite cannot alter a `CHECK` in place; the table is rebuilt exactly as the
v24 cache-frontend migration did.) `FrontendRecord` gains
`storage_binding_id: Option<i64>`; `list_frontends` grows a
`list_storage_frontends(binding_id)` sibling and `frontends_by_domain` is
unchanged (it already keys on `domain`/`base_path`).

**B. The default storage becomes a real singleton row.** A migration seeds one
instance-scoped `storage_bindings` row (e.g. `org_id IS NULL` + an
`is_instance_default` flag, `kind` = the deployment's `r2`/`local_fs`, `access`
defaulting to `private` until an operator sets `public` + `public_base_url`).
`storage_binding_id IS NULL` on registries/caches continues to mean "default,"
resolving to that row. The synthetic-row rendering in `binding.rs` is replaced
by reading the real row, so the default is editable through the normal form.

**C. The advertise toggle.** A per-consumer field controls whether the
inherited storage frontend is advertised. Two viable encodings (open question
below): a registry-config boolean in `registry.toml` (consistent with how
`[[caches]]` advertisement already lives in the committed config), or a column
on `registries`/`caches`. Default follows the binding frontend's own
`advertised`.

## Inheritance and URL derivation

A consumer *C* (registry or cache) stored in binding *S* inherits each frontend
*F* of *S*. The **effective frontend** for *C* is:

```text
scheme://F.domain/{F.base_path}/{C.prefix}        (segments joined, empties dropped)
```

- *serves_* gating, `mode`, `consumer_priority`, and `is_primary` come from *F*.
- A consumer-level frontend (a row with `registry_id`/`cache_id`) still wins
  over an inherited one for the same surface, so an operator can override.
- The advertised substituter/registry URL for *C* becomes the effective
  frontend URL instead of `{hub external_url}/{C.slug}` (today's
  `cache_advertise_url`). When advertised, it is written into the registry's
  committed `[[caches]]` (the existing write-through), so the existing
  `advertised_caches` index and freshness probes pick it up unchanged.

## Security boundary (the load-bearing invariant)

A public bucket domain makes **every object at its key publicly fetchable**.
The v23 `access` gate is the boundary and must be enforced end to end:

- **Only `public` bindings may carry a `direct`/advertised frontend.** A
  `private` binding stays proxied/presigned; it must never get a direct frontend
  or have its domain advertised.
- A **private registry/cache must not become publicly fetchable** by inheriting
  a public binding's frontend. Inheritance + advertise is gated on the
  consumer's `visibility` being public *and* the binding being public. (Mixing a
  private registry into a public bucket is itself a misconfiguration the
  provisioning path should refuse, or isolate by prefix with the bucket's own
  ACLs.)
- Content-addressed `nar/**` and git objects are safe-once-published (you need
  the hash), but registry/cache *visibility* is the access-control point, so the
  gate is on visibility, not on content-addressability.

## Unified storage-binding form

The storage-binding editor (create + edit) gains a **frontends sub-form**
identical to the registry/cache frontend editor — `domain`, `base_path`,
`mode`, `serves_git/cache/web`, `advertised`, `is_primary`. Because the default
storage is now a real row, the **same form edits the default and custom
bindings**, satisfying the "same interface/form" requirement. The
`StorageService` (per [`03`](03-api-storage-frontends.md)) gains
frontend-on-binding CRUD mirroring the registry/cache frontend RPCs.

## Migration and sequencing

This change is additive but lands squarely in the storage-binding /
instance-settings / config-form surface that is **under active development** in
parallel. To avoid colliding on migrations and forms:

1. **Land B first** (default storage as a real row) as its own migration +
   `binding.rs`/settings change — it is the prerequisite the in-flight
   settings UI also wants, so it should be coordinated, not duplicated.
2. **Then A** (storage-binding frontends: migration, `FrontendRecord`,
   `StorageService` CRUD, the frontends sub-form).
3. **Then C + advertise wiring** (inheritance in the effective-frontend
   resolver, the advertise toggle, repoint `cache_advertise_url`/registry
   advertisement at the derived URL).
4. **Then deploy** (`aos-hub worker deploy` provisions/records the default
   bucket's `public_base_url` + a default `direct` frontend when the operator
   has a CDN domain for the bucket).

No byte-path/facade rewrite is required for the direct case (see above); the
proxied/private path is unchanged.

## Open questions

- **Advertise encoding** — registry-config boolean (committed, audited,
  consistent with `[[caches]]`) vs a DB column. The committed-config option is
  preferred for the same provenance reasons `[[caches]]` is committed.
- **Default-storage public domain provisioning** — does `worker deploy` set the
  bucket's `public_base_url` + seed the default `direct` frontend, or is it an
  operator action in settings? Likely both: deploy seeds, settings edits.
- **Git direct serving** — dumb-HTTP git from a bucket domain works for the
  static object/pack/`info/refs` layout, but `apr`/clients must be pointed at
  the bucket domain; confirm the git client UX for an advertised git frontend.
- **Per-consumer override granularity** — one advertise toggle for all inherited
  frontends of a binding, or per-frontend? Start with one; revisit if needed.

## Implementation checklist

- [x] Migration v29: `frontends.storage_binding_id` + 3-way one-of CHECK (table
      rebuild); `FrontendRecord` field; `create_storage_frontend`
      (Direct-over-private gate); `list_storage_frontends`; shared SELECT/row map.
- [x] Effective-frontend resolver (cache path): `RpcService::cache_consumer_url`
      inherits binding frontends, derives URL from `prefix`, applies own-frontend
      precedence + the public-binding gate; `advertise_cache_change` repointed at
      the derived URL. Pure helpers unit-tested.
- [x] Migration v30: the instance default storage is a real, editable
      `storage_bindings` row (`org_id` nullable + `is_instance_default`, seeded
      singleton); `instance_default_binding()` + `set_binding_public()`.
      Surface-root resolution is intentionally unchanged — `storage_binding_id IS
      NULL` still resolves via the runtime port; the row only anchors the
      default's frontends + public settings, which the resolver inherits.
- [x] Resolver inherits the **instance-default** binding for binding-less caches
      (`cache_consumer_url`), so default-bucket caches advertise bucket-direct too.
- [x] WebUI: the instance default storage page (`/-/instance/storage`) edits the
      default binding's public access (`set-public`) and frontends
      (`add-frontend`/`delete-frontend`) via the shared
      `storage_binding_serving_section` — the same form custom bindings will use.
- [x] WebUI: org **custom** storage bindings share the same interface — a
      per-binding page (`GET`/`POST /-/org/{org}/bindings/{id}`) edits public
      access + frontends via the same `storage_binding_serving_section`, gated by
      `StorageManage` and scoped to the owning org; the org storage tab links
      each binding to it.
- [x] Registry-side resolver: `registry_consumer_url` (a shared
      `direct_consumer_url` over a `FrontendSurface` git/cache) resolves a
      registry's git surface to a bucket-direct URL when a direct frontend (own
      or inherited) exists; wired into the browse setup snippets.
- [x] Security test: `storage_frontends_reject_direct_over_private_binding`
      asserts the boundary at the data layer (private rejects Direct, publish
      permits it, frontends scope to the binding, the seeded default is org-less
      and private). The create-time gate + resolve-time public re-check are in;
      pure selection/URL logic is unit-tested.
- [x] Per-consumer advertise toggle (migration v31 `advertise_storage_frontend`,
      default on): a registry/cache can opt out of advertising its *inherited*
      storage frontend (its own frontends still apply). The resolver
      (`direct_consumer_url`) gates only the inherited path on it; getter/setter
      + a default/update test; a "Bucket-direct serving" checkbox on **both** the
      registry storage tab (`POST /{slug}/-/settings/advertise-frontend`) and the
      cache page (`POST /-/org/{org}/caches/{slug}/advertise-frontend`). A DB
      column, not committed config, so caches (no `registry.toml`) share the
      mechanism.
- [~] `worker deploy` default-bucket `public_base_url` seeding — **not built;
      unnecessary.** The migration seeds the row and operators set
      `public_base_url` in the WebUI; the deploy has no operator CDN domain to
      auto-seed, so there is nothing to pre-populate.

**Status: implemented.** All §12 work landed and is green (348 core tests +
wasm). The advertise checkbox is on **both** the registry storage tab and the
cache page. The only follow-up is pointing `apr`/git clients at an advertised
git frontend — an `apr`-CLI change in a separate crate; the server side is
complete (the browse setup snippets already show the bucket-direct URL).
