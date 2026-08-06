# RFC-0012: AOS Hub surface topology

- **Status:** Proposed. First-class signed system-image distribution is
  implemented and native/Worker end-to-end tested; the complete production
  topology cutover remains pending.
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

A registry may also publish a signed AOS sysroot catalog whose release entries
resolve directly to end-user disk encodings. Raw, QCOW2, VMDK, and VHD are
representations of one logical release, delivered as exact image bytes through
the same placement and route topology.

This RFC separates five concerns that the current schema and console partly
conflate:

1. A **surface** is the stable logical identity and protocol namespace.
2. A **placement** stores some or all of a surface on one storage binding and
   prefix. A surface may have several placements from the start; a separate
   per-surface authority record selects and reconciles its single writer.
3. A **network boundary** carries revisioned, observed transport/trusted-ingress
   posture. A **delivery endpoint** is an immutable-identity typed DNS/IP
   client origin pinned to one boundary, and a **delivery route** maps one
   endpoint generation and base path to a surface, either
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
                 +---- write authority ---- desired/observed placement generation
                 |
                 +---- placement A ---- storage binding A + prefix
                 +---- placement B ---- storage binding B + prefix
                 +---- placement C ---- storage binding C + prefix
                 |
                 +---- route 1: cdn.example/path       -> gateway rev -> placement A (direct)
                 +---- route 2: hub.example/path       -> placement policy (Hub proxy)
                 +---- route 3: cache.corp/path        -> gateway rev -> placement B (VPN)
```

## Topic files

| File | Contents |
| --- | --- |
| [`00-goals-and-invariants.md`](00-goals-and-invariants.md) | Scope, terminology, and load-bearing invariants |
| [`01-domain-model.md`](01-domain-model.md) | Surfaces, placements, write authority, bindings, domains, routes, and object presence |
| [`02-delivery-and-auth.md`](02-delivery-and-auth.md) | Simultaneous HTTP paths, direct/CDN/Hub modes, routing, private access, and atomic image publication |
| [`03-registry-cache-relations.md`](03-registry-cache-relations.md) | Standalone/shared caches, signed consumer stacks, retention, population, and coverage |
| [`04-retention-and-gc.md`](04-retention-and-gc.md) | Release artifact snapshots, selectors, root provenance, and multi-placement GC |
| [`05-data-model-and-api.md`](05-data-model-and-api.md) | Normative records, constraints, API verbs, and complete-cutover strategy |
| [`06-console-and-operations.md`](06-console-and-operations.md) | Information architecture, names, status views, domain/endpoint lifecycle, and operations |
| [`07-implementation-plan.md`](07-implementation-plan.md) | Sequencing, migration, system-image delivery, acceptance criteria, and test matrix |
| [`08-decisions-and-open-questions.md`](08-decisions-and-open-questions.md) | Locked choices, rejected conflations, and remaining bounded questions |
| [`09-interface-contracts.md`](09-interface-contracts.md) | Normative Web UI navigation/actions, system-image discovery/downloads, clean-break CLI commands, and Connect-JSON services |
| [`10-settings-information-architecture.md`](10-settings-information-architecture.md) | Uniform instance/organization/registry/cache settings shell, navbar hierarchy, page ownership, and responsive layout |
| [`11-web-route-cutover-ledger.md`](11-web-route-cutover-ledger.md) | Exhaustive method+path replacement/deletion ledger for the hard Web UI cutover |
| [`12-topology-cutover-operator-runbook.md`](12-topology-cutover-operator-runbook.md) | Signed one-shot plan, quiescence, backup/restore proof, switch, rollback, and post-cutover GC procedure |
| [`hub-api-manifest-v1.json`](hub-api-manifest-v1.json) | Versioned topology CLI/service family and mutation-protocol manifest |
| [`hub-cli-json-schema-v1.json`](hub-cli-json-schema-v1.json) | JSON Schema for the stable `aos hub --json` success envelope |
| [`hub-topology-cutover-plan-v1.schema.json`](hub-topology-cutover-plan-v1.schema.json) | Closed schema for the secret-free signed cutover plan |
| [`hub-topology-cutover-report-v1.schema.json`](hub-topology-cutover-report-v1.schema.json) | Closed schema for success, rollback, and failed-closed execution evidence |

The cutover artifacts use the closed `aos-cutover-schema/v1` dialect defined by
the checked metaschema and implemented by the offline verifier. Acceptance
requires root authentication of the complete bundle, byte identity between
the bundled and running verifier, exact schema validation, signer-role checks,
all semantic cross-set and reference checks, and the complete adversarial
fixture matrix described by the operator runbook.

## Relationship to current behavior

The current implementation has the right raw concepts but gives several rows
more than one meaning:

- `registries.storage_binding_id` and `binary_caches.storage_binding_id` permit only
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
