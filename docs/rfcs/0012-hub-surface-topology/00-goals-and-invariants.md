# Goals and invariants

## Goals

1. Registries and binary caches are independently useful logical resources.
2. Either surface kind may have several simultaneous storage placements.
3. Either surface kind may be reachable at several simultaneous HTTP URLs.
4. Static CDN, direct origin, private-network, native-Hub, and Worker-Hub paths
   implement the same machine-path contract wherever their declared
   capabilities overlap.
5. A registry may use several caches; several registries may share one cache;
   and those caches and registries may occupy unrelated storage bindings.
6. Client publication, artifact upload, retention, replication, and serving
   are explicit relationships with one effect each.
7. Private surfaces remain private regardless of placement or delivery mode.
8. Cache GC retains every live closure selected by every retention source and
   explains why each object remains rooted.
9. Operators can understand the effective topology without reconstructing it
   from storage, serving, cache, and config pages.

## Non-goals

- Changing the signed registry Git/tag/channel formats.
- Making AOS Hub a trust party for registries that use maintainer-held keys.
- Requiring Hub-managed storage or domains. External storage, CDNs, VPNs, and
  authentication gateways remain supported.
- Pretending a direct route has the same observability or access telemetry as a
  proxied route. Protocol equivalence does not imply operational equivalence.
- Treating a storage binding as a consumer-facing URL.

## Terminology

| Term | Meaning |
| --- | --- |
| **Surface** | Stable logical HTTP namespace: a registry or binary cache |
| **Registry** | Signed catalog/Git surface, also Nix-cache compatible |
| **Binary cache** | Standalone Nix substituter namespace |
| **Storage binding** | Credentials and capabilities for an object-store origin |
| **Placement** | A surface's data at one binding and prefix |
| **Domain** | Verified hostname and TLS/access-provider lifecycle |
| **Delivery route** | Domain + base path mapped to a surface and delivery mode |
| **Endpoint** | The concrete URL produced by a delivery route |
| **Storage gateway** | Reusable direct mapping from a domain/base path to a binding |
| **Consumer cache stack** | Signed registry policy telling clients which substituters to try |
| **Retention subscription** | Policy selecting registry artifacts that root a cache's GC graph |
| **Population target** | Policy causing a producer/release workflow to upload to a cache |
| **Root reason** | Provenance-bearing reason one cache store hash cannot be collected |

Use **route** for the configured mapping and **endpoint** for its resulting
URL. Avoid the unqualified words “link,” “frontend,” and “advertise” in new
interfaces; they each hide more than one effect in the current model.

## Load-bearing invariants

### Identity is not location

A surface id and canonical Hub URL survive changes to storage bindings,
prefixes, domains, CDNs, and active placements. No consumer relationship is
identified by comparing its current URL string.

### Placement is not publication

Storing a registry or cache on a public binding does not publish it to clients.
Adding a delivery route does not add a cache to a registry's signed cache
stack. Adding a cache to a signed stack does not upload content or protect it
from GC.

### One relationship, one effect

- Consumer cache entry: affects signed client configuration only.
- Retention subscription: affects GC roots only.
- Population target: affects uploads only.
- Replication policy: affects placement copies only.
- Delivery route: affects HTTP reachability only.

A console wizard may create several of these in one reviewed operation, but
the stored records and audit events remain separate.

### Every route has an explicit access posture

A route is one of:

- public;
- authenticated by AOS Hub;
- authenticated by a declared external provider; or
- restricted to a declared private network.

“Direct” never means “implicitly safe.” A private surface cannot have an
anonymous public route, even if its origin prefix is difficult to guess.

### Machine paths are protocol-equivalent

Every healthy route declaring a surface capability returns equivalent bytes
and HTTP semantics for that capability. Registry routes support the declared
subset of Git, Nix-cache, and web paths. Binary-cache routes support the
declared subset of Nix-cache and web paths.

Dynamic HTML and control-plane RPC do not have to exist on a static direct
route. Machine-path equivalence is mandatory; control-plane equivalence is not.

### Route selection never invents authority

A Hub proxy may authenticate a client and then use private origin credentials.
A direct route relies on its CDN, gateway, or network to enforce the declared
access posture. The Hub does not label an external route private without a
configured and probed enforcement mechanism.

### Complete endpoints never expose partial data silently

A route advertised as a complete registry/cache endpoint may select only a
complete placement or a placement policy with transparent failover. A shard is
never directly advertised as the whole surface.

### Signed publication remains signed

The committed registry consumer cache stack remains the source of truth for
what clients use. Operational SQL settings may draft a change request but may
not silently rewrite signed registry configuration.

### GC is monotone over root reasons

An object is live when at least one unexpired root reason reaches it. Removing
one registry, release selector, or manual pin removes only its reason. GC may
delete an object only after all reasons disappear and the applicable grace
period expires.

### Failed indexing fails safe

Failure to index a registry release, refresh a retention subscription, read a
placement, or ingest access logs preserves the previous successful state. A
transient control-plane error cannot manufacture a mass-deletion event.

### Native and Worker behavior is one contract

Native Hub and Worker Hub use the same route matcher, authorization decision,
placement selector, range behavior, conditional request behavior, and error
mapping. Runtime-specific storage adapters may differ; application semantics
may not.

### The cutover leaves no compatibility topology

After cutover, the schema, source, Web UI, CLI, generated API, native binary,
and Worker contain only the new model. Old external URLs survive only as
ordinary validated delivery routes. Rollback restores the complete old
deployment and database backup; it is not a branch in the new runtime.
