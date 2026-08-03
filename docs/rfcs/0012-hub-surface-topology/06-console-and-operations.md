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

**Storage & replicas** shows every placement, role, binding, prefix,
completeness, generation lag, and replication state.

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

**Storage & replicas** shows placements and object-presence completeness.

**Delivery** uses the same route table as registries.

**Objects & closures** shows objects, closure graph, NAR details, and presence
by placement.

**Retention** shows subscriptions and manual/leased roots with counts,
selectors, last refresh, and exposure warnings.

**Garbage collection** shows logical policy, placement policies, dry-run plan,
quota contributors, run history, and deletion backlog.

**Integrations** distinguishes registries that consume, retain, or populate the
cache. A registry can appear in one, two, or all three columns.

### Storage binding

The binding page owns infrastructure facts:

- API origin, bucket/root, region, and capabilities;
- credential purposes and last validation;
- placements using the binding;
- storage gateways;
- capacity and health; and
- possible physical equivalence requiring confirmation.

It does not decide which cache a registry publishes to clients.

### Domains

Add an organization/instance-level Domains page:

| Hostname | DNS | TLS | Access provider | Routes | Probe state |
| --- | --- | --- | --- | --- | --- |

Domain lifecycle includes ownership verification, DNS target, certificate
state, Worker/native deployment state, external provider declaration, and all
base-path routes. This makes globally unique domain/path ownership visible
before collisions occur.

Domain state distinguishes **desired** configuration from **observed**
deployment. Adding a route does not by itself prove that DNS, TLS, a Worker
custom-domain binding, a native reverse-proxy mapping, or a CDN origin rewrite
exists. Provider adapters reconcile what they can; externally managed domains
remain pending until probes confirm the declared route. Worker deployment uses
the complete managed Hub-domain set, while direct domains resolve to their
declared CDN/gateway instead of the Worker.

## Route editor

The route editor proceeds in explicit stages:

1. Select or verify a domain.
2. Choose base path and target surface.
3. Choose delivery mode.
4. Choose client access policy.
5. Select a placement or placement policy.
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
  domain: hub.example (TLS active)
  route: /acme/cache -> cache acme/cache
  mode: Hub proxy
  client access: AOS bearer token required
  placement policy: ordered failover
    1. r2-primary/acme/cache (ready, complete)
    2. s3-replica/acme/cache (ready, complete)
  origin access: scoped read credential
  result: eligible
```

Rejected paths show the exact invariant: visibility mismatch, incomplete
placement, missing capability, stale generation, failed TLS, unsupported
client authentication, or unavailable origin credentials.

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
- logically collectable objects after grace;
- per-placement physical deletions;
- objects blocked by incomplete inventory or unknown presence;
- projected post-run quotas; and
- warnings for missing release snapshots or stale selectors.

Operators can inspect “why retained?” for any object and “what would break?”
for any subscription removal.

The first destructive sweep after migration requires explicit confirmation.
Subsequent scheduled runs use the approved policy and remain audited.

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

Route, placement, replication, coverage, retention, and GC health are separate
states. A single green “cache” badge is insufficient.

Recommended surface summary:

```text
Delivery          3/3 routes healthy
Storage & replicas primary ready, 1 replica 12s behind
Coverage      99.98% (2 missing paths)
Retention     current, 14,202 roots
Population    last release complete
GC            healthy, next run in 4h
```

Audit events use the explicit nouns and verbs: `route.enabled`,
`placement.drained`, `retention.refreshed`, `population.completed`,
`cache.gc.completed`, and `placement.eviction.completed`.
