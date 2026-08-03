# RFC-0012: AOS Hub surface topology

- **Status:** Proposed.
- **Date:** 2026-08-03.
- **Audience:** anyone working on AOS Hub registries, binary caches, storage
  bindings, frontends, domains, publication, replication, or cache garbage
  collection.
- **Supersedes:** the topology portions of RFC-0004
  [`03-api-storage-frontends.md`](../0004-registry-hub/03-api-storage-frontends.md),
  [`04-caching-and-mirroring.md`](../0004-registry-hub/04-caching-and-mirroring.md),
  [`05-url-cli-and-config.md`](../0004-registry-hub/05-url-cli-and-config.md),
  [`11-caches.md`](../0004-registry-hub/11-caches.md), and
  [`12-storage-frontends.md`](../0004-registry-hub/12-storage-frontends.md).
  Those documents remain the historical record for the shipped implementation.
  RFC-0004's tenancy, IAM, signed registry format, shared native/Worker runtime,
  and control-plane architecture remain in force.

## Summary

AOS Hub manages two independently useful HTTP surfaces:

- a **registry**, which publishes a signed Git-backed catalog and is also
  Nix-cache compatible; and
- a **binary cache**, which publishes `nix-cache-info`, narinfos, and NARs and
  need not be associated with a registry.

This RFC separates five concerns that the current schema and console partly
conflate:

1. A **surface** is the stable logical identity and protocol namespace.
2. A **placement** stores some or all of a surface on one storage binding and
   prefix. A surface may have several placements from the start.
3. A **delivery route** maps a domain and base path to a surface, either
   directly, through AOS Hub, or through an externally protected network or
   gateway. Every valid route implements the same machine-path protocol.
4. Registry/cache integrations are separate **consumer publication**,
   **retention**, and **population** relationships. None implies another.
5. Cache garbage collection is driven by provenance-bearing root reasons
   derived from immutable registry release artifact sets, not by an ambiguous
   registry/cache link.

The resulting topology is:

```text
                                signed consumer cache stack
                    Registry --------------------------------> Delivery route
                       |                                              |
                       | release artifact sets                        v
                       |                                      Binary cache
                       |                                       logical surface
                       |                                              |
                       +---- retention subscription ------------------+
                       |                                              |
                       +---- population target -----------------------+

 Registry or binary-cache logical surface
                 |
                 +---- placement A ---- storage binding A + prefix
                 +---- placement B ---- storage binding B + prefix
                 +---- placement C ---- storage binding C + prefix
                 |
                 +---- route 1: cdn.example/path       -> placement A (direct)
                 +---- route 2: hub.example/path       -> placement policy (Hub proxy)
                 +---- route 3: cache.corp/path        -> placement B (external/VPN auth)
```

## Topic files

| File | Contents |
| --- | --- |
| [`00-goals-and-invariants.md`](00-goals-and-invariants.md) | Scope, terminology, and load-bearing invariants |
| [`01-domain-model.md`](01-domain-model.md) | Surfaces, placements, bindings, domains, routes, and object presence |
| [`02-delivery-and-auth.md`](02-delivery-and-auth.md) | Simultaneous HTTP paths, direct/CDN/Hub modes, routing, and private access |
| [`03-registry-cache-relations.md`](03-registry-cache-relations.md) | Standalone/shared caches, signed consumer stacks, retention, population, and coverage |
| [`04-retention-and-gc.md`](04-retention-and-gc.md) | Release artifact snapshots, selectors, root provenance, and multi-placement GC |
| [`05-data-model-and-api.md`](05-data-model-and-api.md) | Normative records, constraints, API verbs, and complete-cutover strategy |
| [`06-console-and-operations.md`](06-console-and-operations.md) | Information architecture, names, status views, domain lifecycle, and operations |
| [`07-implementation-plan.md`](07-implementation-plan.md) | Sequencing, migration, acceptance criteria, and test matrix |
| [`08-decisions-and-open-questions.md`](08-decisions-and-open-questions.md) | Locked choices, rejected conflations, and remaining bounded questions |
| [`09-interface-contracts.md`](09-interface-contracts.md) | Normative Web UI navigation/actions, clean-break CLI commands, and Connect-JSON services |
| [`10-settings-information-architecture.md`](10-settings-information-architecture.md) | Uniform instance/organization/registry/cache settings shell, navbar hierarchy, page ownership, and responsive layout |
| [`11-web-route-cutover-ledger.md`](11-web-route-cutover-ledger.md) | Exhaustive method+path replacement/deletion ledger for the hard Web UI cutover |

## Relationship to current behavior

The current implementation has the right raw concepts but gives several rows
more than one meaning:

- `registries.storage_binding_id` and `caches.storage_binding_id` permit only
  one placement.
- `frontends` can target a registry, cache, or storage binding; binding rows are
  inherited through a per-resource advertise toggle.
- `cache_registry_links` combines retention with a legacy `advertised` bit,
  while the signed registry configuration is the actual consumer cache stack.
- effective frontend URLs are compared to committed string URLs to infer a
  managed-cache relationship.
- current GC safely roots all artifacts in the registry's current indexed
  catalog, while release-count and channel-frontier policy fields are not yet
  evaluated against release-specific artifact snapshots.

RFC-0012 preserves the registry and Nix HTTP wire protocols and the shared
native/Worker serving implementation. The control-plane schema, Web UI, CLI,
and API make a complete cutover with no legacy topology paths or compatibility
code in the finished system.
