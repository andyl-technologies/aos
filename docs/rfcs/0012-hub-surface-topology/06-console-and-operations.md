# Console and operations

This file defines the information architecture and operational views. The
normative page/action mapping shared with the CLI and API is in
[`09-interface-contracts.md`](09-interface-contracts.md). The complete shared
settings shell, navbar hierarchy, page-ownership rules, and responsive layout
are in
[`10-settings-information-architecture.md`](10-settings-information-architecture.md).

## Information architecture

The console should expose the topology from the resource where an operator is
making a decision, without requiring them to follow numeric binding links.

### Registry

**Overview** shows canonical Git, Nix-cache, and web endpoints plus health.

**Storage & replicas** shows every placement's kind, derived role, binding,
prefix, desired lifecycle/read posture, observed completeness/health,
generation lag, and replication state. A separate Write authority panel shows
desired and observed placement, topology and binding-write revisions,
generations, reconciliation, and effective Enabled or Blocked state.

**Delivery** shows every simultaneous route:

| URL | Mode | Access | Capabilities | Placement policy | Canonical | Health |
| --- | --- | --- | --- | --- | --- | --- |

**Binary caches** shows the consumer stack and operational integrations
without calling either one a generic link:

| Binary cache | Used by clients | Retention | Population | Coverage |
| --- | --- | --- | --- | --- |

The committed stack has Applied/Pending/Drifted state tied to a registry
change request. Managed identities survive route URL changes.

### Binary cache

**Overview / Use this cache** shows the stable canonical substituter URL,
trusted public key, visibility, coverage summary, and setup snippets.

**Storage & replicas** uses the same placement and Write authority components
as registries and adds object-presence completeness.

**Delivery** uses the same route table as registries.

**Objects & closures** shows objects, closure graph, NAR details, and presence
by placement.

**Retention** shows subscriptions and manual/leased roots with counts,
selectors, last refresh, and exposure warnings.

**Garbage collection** shows logical policy, safety gates, immutable plans,
quota contributors, and links to dedicated run/deletion-job detail. Placement
eviction remains a separate workflow reached from Storage & replicas.

**Integrations** distinguishes registries that consume, retain, or populate the
cache. A registry can appear in one, two, or all three columns.

### Binding

The binding page owns infrastructure facts:

- API origin, bucket/root, region, and read capabilities;
- immutable write-capability/credential revisions, validation, and current
  default;
- credential purposes and last validation;
- placements using the binding;
- desired/observed authorities pinned to each write revision and rotation
  fan-out progress;
- gateways;
- capacity and health; and
- possible physical equivalence requiring confirmation.

It does not decide which cache a registry publishes to clients.

The Write authority panel never folds authority into placement edit controls.
When no authority exists it says **Writes blocked — no write authority** and
offers Promote on an eligible complete placement. During promotion it shows
the old observed authority first, the desired candidate second, and **Writes
blocked pending generation N** until reconciliation completes. A degraded or
externally invalidated observed authority remains identified as Primary while
its separate effective-write state says Blocked and links to the failing
placement or binding revision.

### Domains

Add an organization/instance-level Domains page:

| Hostname | Ownership | DNS | Certificate | Endpoints |
| --- | --- | --- | --- | --- |

Domain lifecycle includes DNS-name ownership verification, DNS target, and
certificate issuance. It does not pretend an IP literal is a domain or own
listeners, access providers, and routes.

### Endpoints

Add the sibling client-origin inventory:

| Origin | Host kind | Ingress/network | Listener/TLS | Consumer scopes | Routes | Probe |
| --- | --- | --- | --- | --- | --- | --- |

Endpoint state distinguishes **desired** listener/TLS configuration from
**observed** deployment. Origins are rendered from typed scheme, DNS/IPv4/IPv6
host, effective port, and network policy rather than stored URL text.
Provider adapters reconcile what they can; an externally managed or in-VPN
endpoint remains **declared**, not healthy, until an authorized probe confirms
it. Cleartext posture is always visible. Worker deployment uses the complete
managed Hub-endpoint set, while direct endpoints resolve to their declared
CDN/gateway instead of the Worker.

### Network policies

Add a sibling inventory for network realms and trusted ingress:

| Boundary | Kind | Default revision | Active/retiring | Consumers | Last probe |
| --- | --- | --- | --- | --- | --- |

Boundary detail separates stable identity from immutable protection revisions.
It owns trusted mTLS/assertion posture, protected-transport requirements,
consumer grants, per-revision verification, overlap/coordinated activation,
consumer move plans, and retirement. Endpoint forms select an
verified revision; they cannot assert protection themselves. Unknown,
mismatched, or degraded observations display the concrete fail-closed effects.

## Route editor

The route editor proceeds in explicit stages:

1. Select or create a typed endpoint from the full client origin.
2. Choose a Hub-route base path and target surface; direct mode instead shows
   the path derived from gateway client base plus placement prefix.
3. Choose delivery mode.
4. Choose client access policy.
5. Select a complete placement, immutable placement-policy revision, or—for
   direct mode—complete placement plus reconciled gateway revision.
6. Select protocol capabilities.
7. Probe and preview exact URLs/path rewrites.
8. Enable and optionally make canonical.

The form changes its defaults based on known facts:

- private surface -> Hub proxy + Hub auth;
- public complete placement with a configured CDN gateway -> direct public;
- shard -> Hub proxy + hash-partition policy;
- external/VPN access -> direct with declared provider/network.

Invalid combinations are not offered. In particular, a private surface does
not get a default “direct and advertised” form.

## Explainability

Every surface has an “Explain request path” control. Given a URL and optional
object path, it renders:

```text
https://hub.example/acme/cache/abc.narinfo
  endpoint: https://hub.example:443 (DNS; Hub listener/TLS active)
  endpoint grant: instance default -> org:acme
  route: /acme/cache -> cache acme/cache
  mode: Hub proxy
  client access: AOS bearer token required
  placement policy: ordered failover
    1. r2-us/acme/cache (primary derived from observed authority; ready, complete)
    2. s3-eu/acme/cache (replica derived from complete kind; ready, complete)
  origin access: scoped read credential
  result: eligible
```

Rejected paths show the exact invariant: visibility mismatch, incomplete
placement, desired read/lifecycle exclusion, policy or shard mismatch, missing
object presence, stale mutable-publication watermark, missing capability, stale
generation, failed TLS, unsupported client authentication, or unavailable
origin credentials. This request-relative explanation is the authoritative
effective-read result; a placement's Read selected label is only desired
posture.

## Cache integration workflow

“Integrate binary cache” offers three independently reviewable actions:

- **Use for clients**: choose stack location and draft signed config change.
- **Protect artifacts**: choose retention selectors and grace.
- **Upload releases**: choose required/best-effort population and placements.

The review screen states which operations are immediate SQL changes and which
await registry signature/merge. Removing an integration uses the same explicit
verbs.

Empty states are factual:

- “No binary caches are in the signed consumer stack.”
- “No retention subscriptions protect this registry's artifacts.”
- “No population target uploads releases to a binary cache.”

Avoid vacuous text such as “every linked cache is advertised” when there are
no caches.

## GC operations

The GC plan shows:

- objects and bytes logically retained;
- root counts by subscription/release/channel/manual source;
- the root, object-graph, inventory, policy, and topology versions captured;
- logically collectable objects after subscription and unreferenced grace;
- per-placement narinfo actions followed by dependent NAR actions;
- objects blocked by incomplete inventory or unknown presence;
- projected post-run quotas; and
- blocking coverage failures for missing release snapshots, missing closure
  metadata, stale selectors, or in-flight population/copy work.

Operators can inspect “why retained?” for any object and “what would break?”
for any subscription removal.

Apply accepts the reviewed plan id and confirmation hash. It never recomputes a
larger candidate set. If roots, leases, objects, inventories, policy, placements,
or conflicting work changed, the entire apply is stale and creates no
tombstones. The first destructive sweep after migration also requires explicit
acknowledgement. Subsequent scheduled runs create and apply their own immutable
plans under the approved policy and remain audited.

A run detail page separates logical state from physical progress:

```text
Logical apply       1,204 tombstones · complete
Narinfo deletion    2,401 / 2,408 placement actions
NAR deletion        1,881 / 1,889 placement actions
Confirmed reclaimed 84.2 GiB
Failed              6 retrying · 2 awaiting review
Abandoned/leaked    0 B
```

Each failed action shows placement, phase, expected object version, attempt and
next retry. Retry is idempotent. Abandon is a separate destructive review that
keeps leaked-presence evidence and never increases reclaimed-byte totals.

## Setup snippets

Snippets are generated per route and client compatibility:

- public stock Nix;
- stock Nix with netrc/Basic where supported;
- AOS clients with bearer auth;
- Git with credential-helper auth; and
- private-network instructions.

The console never emits a stock-Nix snippet for an access policy stock Nix
cannot satisfy.

## Operational status

Route, placement, write authority, binding capability, replication, coverage,
retention, and GC health are separate states. A single green “cache” badge is
insufficient.

Recommended surface summary:

```text
Delivery          3/3 routes healthy
Write authority   primary r2-us · writes enabled · generation 8
Storage & replicas 2 complete placements · 1 replica 12s behind
Coverage      99.98% (2 missing paths)
Retention     current, 14,202 roots
Population    last release complete
GC            healthy, next run in 4h
```

Audit events use the explicit nouns and verbs: `route.enabled`,
`placement.drained`, `retention.refreshed`, `population.completed`,
`cache.gc.completed`, and `placement.eviction.completed`.

GC audit additionally records subscription/policy plans and applies, refresh
source revisions and failures, manual-root lifecycle, lease issue/renew/revoke/
expiry, plan creation/staleness/apply, first-sweep acknowledgement, logical
tombstones, job retry, and administrative abandonment. Records contain stable
resource and operation ids, actor, scope, input versions, and outcome, never
origin credentials or secret values.

Operational metrics use bounded organization/cache/placement/backend/state
labels, never store hashes. They cover active reasons by kind, refresh lag and
failures, mark duration/objects/edges/coverage errors, unreferenced-age buckets,
plan candidates and stale reasons, live-closure quota breach, tombstones,
deletion backlog/retries/age/error class, and estimated, confirmed, and leaked
bytes separately.
