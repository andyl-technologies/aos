# Decisions and considerations

## Alternatives considered

| Alternative | Assessment |
| --- | --- |
| Keep every hosted Hub function in Cloudflare Workers and move relational rows into many Durable Objects | This may improve parallelism, but would require redefining cross-owner transactions, global identity and route reservations, publication floors, and the current shared SQL query model. Request sharding today spreads execution while all rows remain in one HubDb object. It is not the first hybrid implementation. Workers-only remains supported. |
| Put the entire Hub on GCP and have Native fetch all R2/S3 bytes | Application-to-database latency would improve, but indexing, uploads, downloads, mirroring, and GC would move large bytes through GCP. It misses the egress and horizontal storage-compute goals. Native-only still remains useful for self-hosting. |
| Use Firestore as the hybrid system of record | The present `Database` layer and Hub schema are relational SQL, with joins, migrations, uniqueness rules, and multi-row transactions. Firestore would be a new persistence model and application redesign, not a driver addition. PostgreSQL is the concrete first hybrid backend because the SQL abstraction already includes it. Firestore can be reconsidered with a separate evidence-backed design. |
| Run PostgreSQL beside a public Native origin without a Worker | This is simpler, but it removes the storage-work tier and requires another way to keep large object paths off GCP. It also lacks the specified edge cache and shielding behavior. |
| Use Durable Objects as the cache for the entire Hub catalog | A shared object would recreate a serialization point and remote hop. Per-object, reconstructable parse caches have a narrower identity and lifecycle that fit the storage-work path. |
| Require a seamless live migration before hybrid can run | Staging can be reset and initialized explicitly. An online migration protocol would delay the runtime work without improving its architecture. Portable snapshot/import is retained as a later, reusable capability. |

## Cost and placement considerations

Cloudflare Worker execution is not automatically colocated with every R2 or
S3 object. S3 may charge for bytes sent to a Worker and may be distant from
the Worker colo chosen for a request. The storage executor must record object
store region, Worker location where observable, transferred bytes, request
count, and latency. Scheduler policy may choose a different executor deployment
or a provider-native transfer path for a binding when measurements show that
to be cheaper or faster. These choices must preserve the same signed/fenced
work-plan contract and keep bulk bytes outside the Native Hub.

Caching can lower origin traffic but cannot hide an overloaded SQL primary on
authenticated requests. The database connection budget, slow queries,
transaction duration, and background-job concurrency must be measured and
bounded. Read replicas are an optimization only for queries whose consistency
contract permits them; publication, authorization, and freshness checks stay
on the authoritative primary until separately specified.

A public or private object download through the Worker can still incur
provider egress or Worker cost. This RFC primarily removes the avoidable
GCP-facing object transfer and puts horizontally scalable compute near the
storage path. Cost reports compare all providers rather than treating Cloudflare
or S3 bandwidth as free.

## Security and correctness considerations

- Worker storage results are evidence, not policy decisions. Native verifies
  canonical signed payloads or cryptographically bound projections when a
  trust decision depends on the source bytes; a Worker parser cannot mint a
  release, bypass anti-rollback floors, or broaden a binding grant.
- A storage plan names one deployment, audience, operation, exact object or
  bounded selection, binding/placement revisions, parser version, expiry,
  result-size limit, and idempotency key. A stolen plan has limited scope and
  lifetime. Worker and Native have separate service identities; neither
  accepts browser-provided internal headers as authority.
- Public edge cache invalidation follows committed route and publication
  changes. Private data is never shared across users through a generic cache.
  When the edge lacks current authorization evidence, it asks Native or fails.
- A parse cache hit is valid only for the exact object content/version and
  parser/schema version. Cache removal is best effort; correctness cannot
  depend on an alarm firing or a Durable Object being collected promptly.
- Failed storage work cannot become a successful database commit. Ambiguous
  responses retain an idempotency key and are reconciled against physical
  object evidence before retry or finalization.

## Bounded open decisions

These decisions do not change the ownership split above, but must be settled
and tested before their affected phase ships:

1. **Worker packaging.** Whether public proxy and storage executor begin in
   one Worker deployment or two, based on measured placement, limits, and
   failure isolation. The protocol and credentials must permit separation.
2. **Transport identity.** The exact GCP ingress mechanism and Worker-to-Native
   authentication method, including key rotation and origin reachability. The
   authenticated request-envelope and direct-origin rejection invariants are
   fixed.
3. **Inspection catalogue.** The first closed set of registry, package-doc,
   image, and OCI projections, their version negotiation, parser reuse, and
   per-operation byte/CPU/result ceilings. A generic query language is not
   assumed.
4. **Per-object cache threshold.** Which expensive inspections merit a Durable
   Object, versus direct Worker computation or ordinary edge cache, after
   measuring object sizes, parse cost, reuse, and cache invalidation cost.
5. **Deployment capacity.** Native replica count, PostgreSQL pool limits,
   Worker concurrency, and S3 placement policy from staging load tests.
6. **Portable snapshot UX.** The logical format and CLI come first. An admin
   wizard may follow, using the same verified import/export operation rather
   than inventing a second data path.

The first hybrid staging launch does not depend on the portable snapshot phase.
It does depend on tested initialization, explicit reset controls, a recovery
plan appropriate to the environment, and the runtime and storage-work gates
in this RFC.
