# Effective settings and coordinated workflows

## User-facing contract

Settings begin with the effective configuration and the actions needed to
change it. The instance, organization, registry, and cache shells retain a
persistent resource kind, identity, owner, and link back to the relevant
surface or inventory. Navigation within a scope preserves that context.

| Scope | Overview answers | Configuration areas |
| --- | --- | --- |
| Instance | Which infrastructure is shared, who consumes it, and what needs attention? | Infrastructure, identity/signup, resource defaults, access, appearance, activity |
| Organization | Which resources belong here, which infrastructure is available, and which grants are missing? | Resources, infrastructure, members/SSO, automation, activity |
| Registry | Which URLs do clients use, where are bytes stored, and are publication and indexing healthy? | Delivery, storage/replicas, consumer caches, access/trust, publishing policy |
| Cache | Which Nix URL and signing identity are effective, where are objects stored, and who consumes them? | Delivery, storage/replicas, integrations, access/trust, retention/GC |

Overview pages summarize state. Focused editors own mutable settings. Delivery
shows audience, effective URL, readiness, storage target, and access policy
together. Storage/replicas shows current read and write locations before
offering replication, policy, or authority changes. Configuration history is
identified as history, distinct from editing current settings.

Canonical settings paths remain explicit in the closed route registry.
Superseded paths and deprecated APIs can be removed in an immediate cutover.
Development databases are disposable; incompatible schema changes document
their reset requirements instead of retaining compatibility-only machinery.

## Guided and advanced access

Primary actions express an outcome: add a delivery destination, connect a
cache, add a replica, or retire infrastructure. Resource inventories remain
directly accessible. Advanced inspection follows actual resource edges and
shows ownership, grants, exact generations, configuration digests, and
controller evidence. It never substitutes category links for live topology.

Guided workflows and advanced editors use the same resources, validation,
authorization, and plan/apply protocol. An advanced edit is immediately part of
the effective configuration and can invalidate a workflow's reviewed inputs.
Permission checks apply to each resource's actual owner; access to a consuming
organization does not confer administration of an instance-owned dependency.

Read-only users see effective state and permitted diagnostics. Mutation
controls require their specific capabilities. An inventory remains readable
when editor prerequisites are unavailable or fail to load.

## Delivery destination workflow

The initial workflow connects an existing provider attachment and storage
placement to a direct delivery destination. It can use existing endpoint
infrastructure or create explicit resources within the caller's authority.
Provider setup that requires a separate interface remains an explicit
prerequisite with concrete instructions and observed verification.

The workflow retains immutable reviewed intent and durable progress. The
browser sends typed requests and displays state; the shared core owns step
ordering, resource selection, child operations, and replay. Native, Worker,
CLI, and browser callers invoke that same implementation.

```text
select surface and storage
  -> select or describe hostname/endpoint
  -> select access and audiences
  -> review exact resources, owners, and effects
  -> create or reuse explicit resources
  -> verify current configuration
  -> review activation against current versions
  -> activate requested audiences
```

Creation and verification do not replace existing advertised destinations.
Activation proves the exact selected resource generations, current grants,
readiness, and expected audience versions. A stale observation or intervening
edit blocks activation. Changing several audiences must not leave a partial
selection when a later audience fails validation.

Each accepted step records sufficient identity before effects to replay after
an interrupted response. Retry never turns a same-named foreign resource into
the selected resource and never silently replans different intent. A page
reload can recover the workflow from the authorized surface inventory.

External operations cannot share a transaction with SQLite. Their durable
state distinguishes pending prerequisites, work in progress, verified work,
and failures requiring action. An HTTP success alone is not permission,
ownership, or configuration evidence.

## Subsequent workflows

The interaction and operation model also applies to:

- creating a working registry or cache, including placement and delivery;
- connecting a cache to a registry, with independent consumer publication,
  population, and retention choices;
- adding storage or a replica, followed by optional authority transition;
- changing a destination through a verified successor;
- retiring infrastructure through explicit dependency resolution; and
- rotating credentials or signing generations with observed overlap and
  retirement.

Each workflow keeps domain-specific safety rules. Consumer-cache publication
continues through the signed configuration protocol; population and retention
do not become implicit consequences of publishing a consumer entry.

## Read models and validation

Page-sized inventory and selector reads bound database work before expanding
related records. Available infrastructure is queried by immutable consumer
scope, with owner identity retained. A page shares its topology response and
loads advanced details on demand.

Validation measures browser requests, internal SQL calls, rows read, and
latency on representative fixtures. Tests exercise shared ownership, viewers,
same-named resources, expired or replaced plans, interrupted effects, failed
verification, and concurrent activation. Native and Worker checks preserve
the same behavior, including transaction and authorization failures.
