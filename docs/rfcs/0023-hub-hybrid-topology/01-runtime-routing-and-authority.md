# Runtime routing and authority

## The hybrid request path

```text
                  public Hub, registry, and cache authorities
                                      |
                                      v
                             Cloudflare Worker
                     ingress policy, route classification
                      /          |                \
             static/cache   object delivery       control request
                  |              |                       |
                  v              v                       v
              edge cache   R2/S3 adapter        Native Hub service on GCP
                                                 shared Hub router and jobs
                                                          |
                                                          v
                                               Cloud SQL PostgreSQL

             Native Hub -- bounded storage work plans --> Worker executor
             Native Hub <-- bounded derived results ---- Worker executor
```

The Worker is the first AOS-controlled hop for **every public Hub authority**,
including management pages, Connect-JSON APIs, registry and cache routes, and
OCI routes. The Native service is the application origin for authenticated
HTML, the canonical API, policy decisions, and transactional work. The Worker
may also serve static assets, eligible public cache entries, and object bytes
without involving Native on each transfer.

The ingress and storage executor form one logical Worker tier. They may be
separate Worker deployments when route isolation, storage bindings, or
independent scaling warrant it; their protocol and service identities remain
explicit. Splitting them does not create a second Hub control plane.

“Public Worker API” in this design means an Internet-reachable Worker route
with a defined authorization policy. The storage-work endpoint used by Native
is reachable over HTTPS but accepts only service-authenticated, scoped work
plans. It is never an anonymous object-query API. It is handled before the
general origin proxy route so Native-to-Worker requests cannot loop back to
Native.

## Request ownership

| Request class | Worker responsibility | Native responsibility |
| --- | --- | --- |
| Static site assets | Serve versioned immutable assets; cache at edge | Publish the asset version used by rendered pages |
| Anonymous public HTML and safe reads | Cache only explicitly eligible responses with bounded freshness and the correct authority/key | Render on misses; define cacheability and invalidation from committed state |
| Authenticated HTML, sessions, and Connect-JSON control APIs | Apply ingress limits and proxy without shared caching | Authenticate, authorize, render, execute and commit |
| Public immutable object delivery | Resolve an approved route and stream from the placement or cache | Publish route/object authority and any policy needed to create a delivery grant |
| Private object delivery | Validate an exact-object, short-lived delivery grant, then stream without shared caching | Authenticate user and mint or validate the scoped grant |
| Upload bytes | Accept/stream or issue scoped direct-storage upload access; enforce size and content constraints | Create write intent, choose placement, finalize after verifying storage evidence |
| Internal storage work | Authenticate plan, execute bounded operation near storage, return a projection | Create plan, verify result, decide whether to persist it |

The Worker must not build a second Hub control-plane router for hybrid mode.
Current Native and Worker-only implementations already mount the shared
`aos_hub_core` router, but hybrid's Worker dispatches control requests to the
Native instance of that router. This keeps IAM, session, topology, and
publication behavior in one authoritative execution path. Worker-only keeps
its existing local execution path as a separate deployment mode.

### Routing decision

The Worker classifies a request from a versioned routing table and explicit
method/path rules. Classification happens before any origin fetch or cache
lookup. The principal classes are static asset, cacheable public response,
object delivery, storage-work API, and Native control request. A missing,
stale, or ambiguous route cannot become an unauthenticated object read; it
goes to Native for an authoritative decision or fails closed when the target
requires a binding the Worker cannot safely resolve.

RFC-0012 endpoint identity and route generations remain authoritative. The
Worker receives a signed or authenticated projection of committed routing
state, with generation numbers and expiration. It cannot use a slug alone to
guess a placement or silently keep serving a deleted private endpoint. An
origin-proxy fallback is available for ordinary control reads and pages, but
not as a generic fallback for large object bytes.

Public route changes and publication commits trigger targeted cache
invalidation or a version change in the cache key. Bounded TTLs cap stale
exposure if invalidation is delayed. A privacy or authorization change must
invalidate affected public entries before the new policy is considered
effective, or route those entries to Native until the edge projection catches
up.

## Origin shielding and cache policy

The Worker serves the console's hashed static assets and other immutable
assets at the edge. It may cache anonymous, public `GET`/`HEAD` responses
only when Native or a versioned route policy explicitly marks them cacheable.
The cache key includes public authority, full relevant path/query, encoding,
response version or publication generation, and every variant that affects
content. It never includes a bearer token or session identifier as a way to
make a shared cache safe.

Requests with an `Authorization` header, session cookie, private route, write
method, or `Set-Cookie` response bypass the shared edge cache. So do identity
ceremonies, administrative routes, and responses marked `private` or
`no-store`. The Worker preserves Native's `Vary` and cache directives; it
must not turn an uncacheable origin response into a public one. Public object
delivery may use long-lived immutable caching only when its object identity
and access class are immutable. Private object responses do not become shared
cache entries even when their bytes are content addressed.

Shielding includes rate limits, request-body limits for control APIs,
concurrency/admission limits, and coalescing or short caching of eligible
public misses. Limits for bulk uploads and downloads are enforced in the
storage path without buffering their bodies at Native. Worker caches are
performance aids; they do not store authoritative sessions, SQL rows, or
publication decisions.

## Trusted edge-to-Native proxy

The Native origin is reachable only from an authenticated Worker ingress or
an explicit operator channel. The ingress uses a dedicated service identity
and encrypted transport. Native checks that identity before accepting any
edge-supplied transport evidence. A direct request to the origin cannot claim
to have passed through the Worker.

At the public boundary the Worker removes client-supplied forwarding and AOS
transport-evidence headers. It then supplies a signed, short-lived envelope
containing the original public authority and scheme, verified client address,
method and path/query, request ID, timestamp, and edge deployment identity.
The envelope is bound to this origin request, so an attacker cannot replay
transport evidence for another URL or host. Native validates the envelope
and reconstructs the public request context before its existing host-bound
route, cookie, CSRF, redirect, and absolute-URL logic runs. The upstream TLS
host used to reach GCP is not substituted for the client's public authority.
The existing `DeliveryTransportEvidence` boundary is the starting point for
that verified request context, not an unrelated second source of authority.

Raw browser `Forwarded`, `X-Forwarded-*`, `X-AOS-*`, and `Host` values are not
trust evidence on their own. The Native service rejects inconsistent or
expired evidence and never enables `trusted_proxy` just because a header is
present. The origin also applies its own request-body and timeout limits;
edge limits are defense in depth, not its sole protection.

The Worker streams request and response bodies for proxied control traffic
within the control-plane size cap. It passes cookies and end-user
authorization through to Native; it does not validate a login independently
or mint a second session. Native's response status, security headers,
redirect target, and cache policy remain authoritative. The edge may add
request IDs, `Server-Timing`, and its own cache result for observability.

## Native service and PostgreSQL

Hybrid runs the Native Hub's shared service against Cloud SQL PostgreSQL in
the same GCP region. A pooled connection is local to that region; a request
does not send each SQL statement through a remote Durable Object. The Hub's
SQL `Backend` and PostgreSQL dialect provide the foundation, but the native
`serve` bootstrap must accept a PostgreSQL URL and configure pooling,
migrations, health checks, and transactional job coordination. Current native
bootstrap still opens its local SQLite file, so supporting PostgreSQL in
the server is implementation work rather than a configuration-only change.

Several request replicas may share the service identity and database.
Per-process memory, local filesystem, and in-process leases cannot be the
sole authority for sessions, routing, background job ownership, publication
locks, or upload completion. Hybrid moves those coordination points into
PostgreSQL or another explicit shared coordinator with fenced leases. Native
keeps the final database commit and anti-rollback checks even when many
Workers perform storage work concurrently.

Worker-only request execution shards are not carried into hybrid's control
path. They currently spread application execution but still issue short SQL
calls to a single HubDb object. Hybrid reduces repeated network latency by
placing application execution and PostgreSQL together. An object-scoped
Durable Object may still cache parse results or coordinate work for one
immutable store object; its lifecycle and correctness rules are specified in
the storage-compute chapter.

The main implementation seams in the current tree are:

- `crates/aos-hub-worker/src/lib.rs`: split the Worker entry into explicit
  Worker-only and hybrid dispatch. Reuse its route classification and safe
  public-cache rules where they apply; hybrid control requests go to Native
  instead of a request-execution Durable Object.
- `crates/aos-hub/src/server.rs`: keep the shared service/router and add a
  verified hybrid ingress context. Configure hybrid storage and coordination
  ports without weakening native-only operation.
- `crates/aos-hub/src/main.rs`: add an explicit hybrid serving configuration.
  The present `serve` bootstrap opens local SQLite and assumes local instance
  files and in-process coordination.
- `crates/aos-hub-core/src/backend/sqlx.rs`: use its PostgreSQL backend as
  the SQL starting point, then qualify migrations and transaction semantics
  against PostgreSQL in the complete Hub service.

## Failure behavior

If Native or PostgreSQL is unavailable, authenticated pages and control APIs
fail with an explicit unavailable response. The Worker may continue to serve
only static assets and public, immutable or still-fresh cached responses whose
policy permits origin-independent delivery. It may not authorize new private
downloads from stale session state. If the storage executor is unavailable,
Native retains the queued work and retries with idempotent plans; it does not
fall back to downloading whole objects through GCP without an explicit,
bounded operator-approved path.

A rollout carries an edge/Native protocol compatibility check and deployment
identity. An edge deployment with an incompatible Native or storage-work
protocol fails the affected route closed and reports the mismatch. Operator
diagnostics distinguish edge rejection, origin failure, SQL delay, cache
behavior, and storage-executor delay.
