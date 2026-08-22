### API: `aos.registry.v1` over ConnectRPC

Buf-compliant protos in `crates/aos-proto`, served via Connect
(JSON + binary, HTTP/1.1 and h2) so the browser, the CLIs, and
third-party tooling share one schema:

| Service | Responsibility |
| --- | --- |
| `OrgService` | orgs, membership, invitations |
| `ProjectService` | project tree CRUD, role grants |
| `RegistryService` | create/import/configure registries, visibility, trust-anchor display, freshness/health, mirror sources |
| `StorageService` | bindings, bucket provisioning, frontend domains, cache stores |
| `PackageService` | search, package/version/platform metadata, closures, narinfo lookups, reverse-deps |
| `ChannelService` | channel list, 256-partition state, floor history; reviewed advance/init against an exact signing-key generation |
| `PublishService` | the write path: stage release, mint upload credentials (`MintUploadCredentials`), finalize, status stream, publish leases |
| `ValidationService` | consistency-validation runs, per-cache coverage reports, repair jobs |
| `KeyService` | roster mirror, signing-key generations, typed usages, rotation and retirement workflows |
| `TokenService` | provisioning-token CRUD — same semantics as `aos token` |
| `AuditService` | audit log queries |
| `GitService` | log/diff/branch/refs read API for the UI and remote `apr` |
| `ConfigService` | change-sets: draft, review-diff, apply, revert |

**Publish concurrency.** `apr` serializes publishers with an exclusive
on-disk lock (`ReleaseLock`, `.git/apr-release.lock` in
`registry_ops.rs`) — but that lock is per-clone, invisible across
maintainers' machines. The hub closes the gap server-side: the facade
holds a **per-registry publish lease** (acquired implicitly by the
first mutable-pointer write of a pipeline or explicitly via
`PublishService.Stage`; expires on a deadline, renewable while uploads
progress), concurrent finalize attempts get `409 Conflict`, and every
mutable-pointer write goes through conditional PUT / compare-and-swap
where the binding supports it (the `capabilities.conditional_put` field
exists for exactly this) so a lost-update on `info/refs`, partitions,
or `nix-cache-info` is structurally impossible on the managed path.
Direct-to-bucket publishers bypass the lease by definition — for them
the hub can only detect and flag races after the fact, which the
registry page surfaces as a health warning.

### Storage: `Binding` and shared buckets

A registry never owns a bucket directly; it references a
**Binding** plus a sub-prefix:

```text
Binding {
  id, org_id,
  kind:        HubManagedR2 | ExternalS3 | ExternalR2 | LocalFs,
  endpoint, region, bucket, root_prefix,
  credentials: CredentialRef { purpose: write | admin | mint },
  worker_binding: Option<String>,   # static R2 binding name when this
                                    # is a hub-owned bucket (Workers)
  capabilities: { mint_scoped_creds, conditional_put,
                  public_base_url: Option<Url> },
  health
}
Registry { …, binding_id, prefix: "{org}/{proj…}/{reg}/" }
```

Credential purposes are kept distinct because their blast radii
differ: `write` lets the hub's upload facade write under the binding;
`admin` is bucket lifecycle (create, custom domains, CORS) and exists
only on hub-managed bindings; `mint` is a parent credential for
deriving short-lived prefix-scoped credentials for direct producer
upload.

**Provisioning modes:**

1. **Hub-managed (default; R2 flagship).** A Workers-hosted hub *can*
   create R2 buckets — the Cloudflare REST API is plain HTTPS, callable
   from a Worker with an account-scoped API token held as a Worker
   secret. However, Workers **R2 bindings are static at deploy time**,
   so the default shape is *one (or a few) hub-owned shared buckets
   bound at deploy time, with registries as prefixes* — keeping the
   zero-egress fast path. Dedicated bucket-per-registry is an opt-in
   (large tenants, clean export/exit), accessed via R2's S3-compatible
   endpoint with SigV4 (the same `aos-net` engine; SigV4-over-fetch on
   Workers) — latency cost only, R2 has no egress fees.
2. **BYO bucket**, in three tiers by what the operator hands over:
   `write` credentials (hub hosts the upload facade and pointer
   flips), `mint` (hub brokers direct uploads), or **nothing** —
   registration-only: the hub indexes the registry through its public
   URL exactly like an `apm` client. Registration-only is phase 1's
   mode for `cdn.aos.andyl.org`.
3. **BYO prefix** on a hub bucket — mode 1 with a tenant-supplied
   prefix.

**Shared buckets work cleanly** because everything that matters is
per-object: `Cache-Control`/`Content-Type` are set per uploaded file
(`crates/aos-package/src/registry/static_upload.rs`), and consumption
is pure GETs — `apm`, stock git, and Nix never call a listing API.
Credential scoping per prefix: STS session policies on AWS S3; on R2,
**permanent API tokens are bucket-scoped only, but the temporary-
credentials API mints short-lived SigV4 credentials scoped to bucket +
prefixes** — exactly the `mint` purpose. Default write path on shared
buckets is the hub facade (the producer's token is hub-scoped; the hub
enforces the prefix structurally on any backend); direct-to-bucket
scoped credentials are an optimization via
`PublishService.MintUploadCredentials`. Bucket-wide permanent keys are
never handed out for shared buckets. One constraint surfaced as a
`Frontend` validation rule rather than a footgun: a *direct* custom
domain serving a shared-bucket prefix at its domain root needs an
origin-path rewrite (native on CloudFront; a one-line rule in front of
R2).

### Frontends: direct and proxied domains

> **Extended for caches in [11-caches.md](11-caches.md).** Frontends serve
> *caches* too (a nullable `frontends.cache_id`); that file also adds what this
> sketch omitted and the thin shipped schema lacks — explicit proxy settings
> (timeouts, streaming, retry/failover, range passthrough), a
> `bindings.access = public | private` mode with `public_base_url`,
> hub-proxy-to-authenticated-origin (SigV4 / native R2 binding) with presigned
> GET (`302`) reads, LRU access-signal handling under direct mode, and the
> cross-visibility pointing matrix (public registry → private cache rejected;
> private registry → public cache flagged).

A **Frontend** is a domain serving some subset of a registry's
surfaces, in a mode — **mode is a property of the frontend, not the
registry**, and a registry can have many frontends:

```text
Frontend {
  id, registry_id, domain, base_path,
  mode:     Direct | Proxied,
  surfaces: { git, cache, web },
  direct:   { cdn_kind: R2CustomDomain | CloudFront | GenericCdn
              | PlainS3, origin_path },
  proxied:  { visibility_enforced, render_html },
  consumer_priority,                  # → [[caches]] priority
  advertised: { in_caches, primary_origin },   # exactly one primary
  health: { last_probe_at, status, observed_frontier, lag_releases }
}
```

`Direct` = hub not in the serving path (CNAME → R2 custom domain,
CloudFront → S3); the hub only probes it. `Proxied` = the hub's facade
(redirect, or zero-egress R2 proxy on Workers) — which is what enables
bearer-token enforcement on private registries and HTML at the same
URL. A typical registry: proxied
`hub.example.com/acme/infra/prod` (primary origin + HTML) plus direct
`cdn.acme.com` (high-priority cache mirror) plus a low-priority S3
backup.

**Mapping to consumer configuration requires zero schema change for
the cache surface**: the committed `registry.toml` already carries
`[[caches]]` entries with `url` + `priority`, and the client merges
them with client-side entries and sorts by priority descending
(`resolve_mirrors_for_registry` in
`crates/aos-package/src/registry_ops.rs`; `RegistryRootConfig` /
`CacheEntry` in `types.rs`). Each frontend with
`surfaces.cache && advertised.in_caches` becomes one `[[caches]]` row.
Because `registry.toml` is signed tree content, the hub cannot silently
edit the mirror list — updating it is a normal signed publish through a
reviewed external or provider-custodied signing operation. That is correct and
desirable: *the mirror list is part of what consumers verify*. When a
probe finds a mirror stale or dead, the hub alerts and offers a
one-click "demote mirror" change request.

The **git origin** is the one genuinely singular thing today
(`RegistryConfig.url` is a single string in `types.rs`). A stale
git origin is *safe* by construction (signed tags + anti-rollback floor
→ old-but-valid state); it is an availability gap only. Deferred
follow-ons: a client-side `urls = [..]` ordered fallback list in
`registries.d`, and later a committed `[[origins]]` table mirroring the
`[[caches]]` shape.

**Mirror replication and ordering.** `apr origin upload` already
accepts multiple `--upload-url` destinations with independent
per-destination failure — but the current loop is *destination-major*
(one mirror receives everything including mutable pointers before the
next starts), so cross-mirror pointer/payload skew is possible. A
small `apr` change is specified regardless of the hub: restructure to
**phase-major** order — all `Immutable` files to *all* destinations,
then all `Mutable` pointers to all destinations; a mirror that fails
phase 1 skips phase 2 and stays stale-but-consistent. New invariant:
*any pointer visible on any mirror only references objects present on
every mirror that completed phase 1.* The hub's **`ReplicationJob`**
(replicate primary → secondary bindings server-side, immutable-first,
idempotent because content-addressed) follows the same rule, and
per-frontend **`FrontendProbe`** jobs record observed frontier + lag
(the `frontend_probes` table), rendered as a freshness table on the
registry page. Naming note: replication jobs copy *this* registry
across its own frontends; `MirrorSource` (next section) tracks an
*upstream* registry — two unrelated features that both colloquially
read as "mirroring".
