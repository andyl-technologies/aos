# Delivery and authentication

## One Hub route pipeline

Every Hub-proxy or Hub-redirect request reaches the same pipeline:

```text
endpoint authority + path
  -> endpoint listener/TLS termination
  -> longest-prefix route match
  -> capability classification
  -> route access policy
  -> surface visibility authorization
  -> placement or placement-policy selection
  -> exact presence/publication eligibility
  -> protocol path handler
  -> origin read
```

Control-plane paths are classified before delivery routes. The shared
native/Worker router implements this complete per-request pipeline for
Hub-served routes and uses the same host/path normalization, typed resolution
result, selectors, and eligibility predicates. Direct routes use the weaker but
safe external publication invariant defined below because they cannot query Hub
presence state per request. A route is not healthy merely because DNS resolves:
verified route health requires representative Git and/or Nix-cache machine-path
probes. Routes that cannot be probed from an authorized network are explicitly
`declared`, not reported healthy.

## Delivery endpoint transport

Routes select a typed delivery endpoint, never an opaque origin string. The
endpoint fixes scheme, DNS/IPv4/IPv6 host, effective port, and ingress/network
boundary. It is an inbound client URL and is distinct from the outbound storage
origin, which remains an independently credentialed SSRF boundary.

Plain HTTP requires explicit cleartext acknowledgement and is valid only for
anonymous public machine data or inside a named network boundary whose
protected-transport assertion is observed. Hub session cookies, bearer/Basic
credentials, presigned capabilities, and origin secrets never cross
unauthenticated cleartext. Hub redirect is HTTPS-only. Generated snippets label
HTTP posture and never silently downgrade an HTTPS endpoint.

## Delivery modes

### Hub proxy

The request terminates at native AOS Hub or AOS Hub Worker. The Hub:

1. authenticates and authorizes the client;
2. selects a placement;
3. authenticates to the origin with its placement-scoped credential;
4. streams the response; and
5. records request and cache-access telemetry.

The proxy must preserve `HEAD`, `GET`, conditional requests, byte ranges,
`ETag`, `Last-Modified`, `Content-Length`, `Content-Type`, and the immutable
versus mutable `Cache-Control` policy. Bodies are streamed and never buffered
as a whole.

The portable HTTP conformance contract includes `Accept-Ranges`,
`Content-Range`, `If-Match`, `If-None-Match`, `If-Modified-Since`,
`If-Unmodified-Since`, and `If-Range`, including correct `206`, `304`, `412`,
and `416` outcomes. Native Hub and Worker strip hop-by-hop headers and any
origin authentication or `Set-Cookie`; they never forward an origin `Location`.
Unexpected origin redirects and non-retriable origin failures become a
sanitized `502`. Cache and content headers are derived from verified metadata,
not trusted blindly from a mutable backend.

Selection and origin open may retry another eligible placement only for the
typed policy failure contract: connect failure, timeout before response
headers, origin `429`/`502`/`503`/`504`, exact-presence mismatch, or verified
corruption. A `404` with an exact presence record is a presence mismatch; an
ordinary absent object remains `404`. Once response headers or body bytes have
been sent, the selected origin is fixed: the Hub never splices two objects into
one response. A missing exact presence record is ineligible, not an invitation
to probe arbitrary storage. Authentication, authorization, malformed range,
and other client errors never fail over.

This is the most capable mode and the default for private surfaces.

### Hub-authorized redirect

The request terminates at the Hub for authentication and authorization. After
selection, the Hub returns a short-lived, path-specific presigned origin URL.

The redirect is a temporary bearer capability. Its TTL is bounded, it is never
written into a registry configuration or setup snippet, and responses carrying
it are private/no-store. Use this mode only where URL disclosure for the TTL is
an acceptable policy. Fall back to streaming proxy when the origin cannot
presign, the client cannot follow the redirect safely, or stricter confinement
is required.

Presigning occurs only after the same authorization, policy selection, exact
presence, publication-watermark, and origin-condition checks as proxy mode.
The URL is scoped to one method and object path, has the shortest practical
TTL, never more than 300 seconds, and uses a binding capability pinned by the
selected placement. Hub evaluates request preconditions and `If-Range` against
the selected verified metadata. It returns final `304`, `412`, or `416`
responses itself where applicable. Otherwise it returns `307 Temporary
Redirect` and signs a request whose origin re-evaluates the client's unchanged
conditional and range headers against identical ETag/size metadata; Hub never
rewrites a client's `Range` header across a redirect.
Redirect responses set private, no-store caching and a no-referrer policy. A
transient origin-open or presign failure may select another eligible placement
before a redirect is returned; a returned capability is never silently
replaced.

### Direct

The client reaches a static CDN, object-store custom domain, reverse proxy, or
private gateway without passing through AOS Hub. The route pins one complete
placement through one immutable, reconciled storage-gateway revision.

Direct routes provide the lowest Hub cost and preserve the static-data-plane
architecture. They also mean:

- the external component, not Hub, enforces the declared access policy;
- Hub request logs and exact LRU access signals are unavailable unless logs are
  imported;
- backend redundancy inside the pinned gateway is external to AOS placement
  selection; alternate AOS placements require client cache-stack fallback; and
- dynamic Hub HTML and RPC are not implied.

Direct routes over public origins can be anonymous. Direct routes for private
surfaces require an explicit external authentication or private-network
policy.

A direct route pins exactly one complete placement through a reconciled storage
gateway. Placement-policy failover and shards require Hub proxy or an
explicit external implementation modeled by a future gateway capability; they
are not implied by a direct URL. If a request for a direct route reaches the
Hub data plane, the Hub returns `421 Misdirected Request` and never falls back
to proxying with its origin credentials.

Direct publication writes immutable objects and verifies their external
readability before atomically advancing a gateway-visible publication manifest
or mutable pointer. Route health pins that manifest and the reconciled gateway
generation. The origin returns ordinary `404` for absence; it never consults a
partial placement or silently fails over. This complete-placement publication
ordering is the external substitute for Hub's per-request presence check.

An endpoint origin/listener that carries both direct and Hub-served route
prefixes requires a verified layer-7 ingress capable of applying the same
normalized longest-path dispatch before either backend. A DNS record or IP
listener alone cannot distinguish those backends, so the console rejects an
otherwise ambiguous mixed-mode endpoint.

## Access policies

Access policy and delivery mode are orthogonal but not every pairing is valid.

| Access policy | Hub proxy | Hub redirect | Direct |
| --- | --- | --- | --- |
| Public | Yes | Usually unnecessary | Yes |
| AOS Hub auth | Yes | Yes, as a temporary capability | No |
| External identity provider/gateway | Yes, through trusted ingress assertions | No | Yes |
| Private network/VPN/IP allowlist | Yes | Only if the presigned origin enforces the same boundary | Yes |

### Public

Anonymous reads are permitted. Public routes remain subject to integrity,
capability, and placement-completeness checks.

### AOS Hub authentication

Hub routes accept the credentials appropriate to each client:

- browser session cookies for the console and browse UI;
- bearer tokens for `apm`, `apr`, and AOS-aware cache clients;
- HTTP Basic/netrc bridging for stock Nix where supported; and
- normal Git credential-helper HTTP authentication for Git clients.

Authentication identifies the principal. Surface visibility and IAM authorize
the read. Origin credentials are never exposed to the client.

### External authentication

A direct route may rely on a named provider such as a corporate reverse proxy,
Cloudflare Access, mTLS gateway, signed-cookie CDN, or HTTP Basic gateway. The
route's closed `external_provider` access policy records:

- provider kind, stable resource identity, and exact observed revision;
- expected credential mechanism;
- which client classes can use it;
- probe credentials or a network probe location, if available; and
- last verified policy state.

The console must not claim that stock Nix can use a route whose authentication
scheme Nix cannot express. Setup snippets are generated per compatible client.

When such a provider fronts a Hub-proxy route, Hub accepts identity only from a
configured trusted ingress and verifies a signed assertion or mutually
authenticated channel bound to that provider. Client-supplied forwarding or
identity headers are stripped and never establish an access class or
principal. Direct routes rely on the provider itself and cannot claim Hub
authentication.

### Private network

A route may be restricted by VPN, VPC, tunnel, or source IP. Network location
is the enforcement mechanism; obscurity of the hostname or path is not. The
route's closed `private_network` access policy pins the named network boundary
and exact immutable revision and uses its configured in-boundary health probe.

A redirect is valid only when the presigned origin independently enforces that
same named boundary revision for the capability's lifetime and the exact
revision is currently observed `verified`. Unknown, stale, mismatched, or
degraded boundary observation makes the redirect ineligible. Merely authenticating the
initial Hub request does not confine a bearer URL to the network.

## Surface visibility constraints

A route's effective audience must be no broader than its surface visibility.

- A public surface may use any route posture.
- An internal surface may use Hub auth, an internal external provider, or a
  private-network route.
- A private surface may use Hub auth or an explicitly scoped external/private
  route.
- An anonymous direct route for an internal/private surface is invalid.

The same constraints are checked at route creation, route enablement, surface
visibility changes, placement moves, endpoint changes, and route
access-provider changes.

A public binding does not force every surface on it to be public. It does mean
that a private prefix cannot rely on the binding itself for isolation; any
route or leaked origin URL could bypass Hub authorization. The console should
therefore warn or reject private placements on origins whose object ACLs cannot
enforce prefix isolation.

## Origin authentication

Origin access is independent of client access:

```text
client --client auth--> route --surface authz--> Hub/CDN
Hub/CDN --origin credential--> storage placement
```

A Hub route may serve a public or private origin. A direct CDN route may serve
a private origin if the CDN holds a scoped origin-access credential and does
not expose the origin. A direct backend route is possible only when the backend
itself enforces the declared client policy.

Credentials are recorded by purpose:

- read;
- write;
- temporary-credential minting; and
- binding administration.

No permanent bucket-wide credential is handed to a client for a shared
binding.

## Multiple simultaneous URLs

A surface may have routes such as:

```text
Registry acme/prod
  https://hub.example/acme/prod       Hub proxy, public, Git+cache+web, canonical
  https://cdn.example/acme/prod       Direct CDN, public, Git+cache
  https://registry.corp/acme/prod     Direct private gateway, Git+cache

Binary cache acme/shared
  https://cache.example/acme/shared   Direct CDN, public, cache, canonical
  https://hub.example/-/cache/acme/shared
                                      Hub proxy, AOS auth, cache+web
  https://cache.corp/shared           Direct VPN route, cache
  http://[fd00:acme::20]:8080/shared  Direct protected-VPN endpoint, cache
```

All routes remain live. “Canonical” selects setup-snippet and stable-reference
behavior; it does not disable alternatives.

Canonical URLs should normally be stable Hub-owned endpoints. A canonical Hub
route may proxy or redirect to an efficient direct placement. Registries then
commit stable endpoints in signed consumer cache stacks while operators may
change storage/CDN topology without rewriting every registry.

## Capabilities and path behavior

Routes declare capabilities rather than assuming every path can be served by
every mode:

| Surface | Capability | Representative paths |
| --- | --- | --- |
| Registry | Git | `info/refs`, `HEAD`, `objects/**`, `releases/**`, `channels/**` |
| Registry | Nix cache | `nix-cache-info`, `*.narinfo`, `nar/**` |
| Registry | Web | browse HTML and static assets |
| Binary cache | Nix cache | `nix-cache-info`, `*.narinfo`, `nar/**`, mass query |
| Binary cache | Web | object search, closure/NAR browse UI |

Direct static routes normally implement machine paths only. Hub routes may
content-negotiate HTML at the root while keeping known machine paths
unambiguous. A route that declares a capability is probed for that capability
and is removed from canonical/advertised selection when it becomes invalid.

## Placement failover

Hub routes may select among placements. Reads fail over only on transport,
origin, missing-presence, or verified-corruption conditions defined by the
placement policy. Authentication failures and client errors never trigger a
fallback that could broaden access.

For immutable objects, failover is request-local. For mutable registry
pointer requests, route resolution first snapshots the surface's committed
publication-head id; only complete placements with that exact watermark are
eligible for the lifetime of the request. The route exposes generation lag in
health and must not serve a newer pointer whose referenced immutable objects
are absent from the selected placement set.
Mutable pointers are never read from shard placements.

`ordered_failover` uses its stored order. `local_then_remote` first filters by
the request access class and then uses stored order. The class is `local` only
when the request arrives through an endpoint pinning the policy's exact
boundary revision, that revision is currently observed `verified`, and its
configured mutually authenticated ingress or local network listener asserts
the boundary; every direct, untrusted, or unclassified
request is `remote`. Remote requests use only remote members. Local requests
use local members first and may use remote members only when the immutable
policy revision sets `allow_remote_fallback`. `hash_partition` computes
`hash_range_v1`, selects the exact range's replica group, and uses its stored
order; complete fallbacks are consulted only for absence or a declared
transient failure. Partial range overlap and uncovered ranges without a
complete fallback make a policy invalid.

The origin abstraction used by native Hub and Worker exposes streaming reads,
conditional metadata, and optional path-scoped presigning with the same typed
error classes. Backends do not choose failover or weaken route authorization.

## Writes

Consumer delivery routes do not imply write authority. Producers upload
through a separately authorized Hub upload facade or receive short-lived
placement-scoped upload credentials.

For replicated surfaces, publishing is phase-major:

1. write immutable objects to every required placement;
2. verify required presence;
3. update mutable pointers on placements that completed phase 1; and
4. mark lagging placements degraded and repair them asynchronously.

No placement exposes a pointer to objects it has not received.
