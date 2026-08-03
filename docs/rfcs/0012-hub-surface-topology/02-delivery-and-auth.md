# Delivery and authentication

## One route pipeline

Every request reaches the same conceptual pipeline, even when some stages are
implemented by a CDN or private gateway instead of AOS Hub:

```text
hostname + path
  -> domain/TLS termination
  -> longest-prefix route match
  -> route access policy
  -> surface visibility authorization
  -> placement or placement-policy selection
  -> protocol path handler
  -> origin read
```

The shared native/Worker router implements this pipeline for Hub-served routes.
Direct routes declare equivalent external behavior and are continuously
probed. A route is not healthy merely because DNS resolves: capability probes
exercise representative Git and/or Nix-cache machine paths.

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

### Direct

The client reaches a static CDN, object-store custom domain, reverse proxy, or
private gateway without passing through AOS Hub. The route pins a complete
placement or maps through a storage gateway.

Direct routes provide the lowest Hub cost and preserve the static-data-plane
architecture. They also mean:

- the external component, not Hub, enforces the declared access policy;
- Hub request logs and exact LRU access signals are unavailable unless logs are
  imported;
- route failover must be supplied by the CDN/gateway or by client cache-stack
  fallback; and
- dynamic Hub HTML and RPC are not implied.

Direct routes over public origins can be anonymous. Direct routes for private
surfaces require an explicit external authentication or private-network
policy.

## Access policies

Access policy and delivery mode are orthogonal but not every pairing is valid.

| Access policy | Hub proxy | Hub redirect | Direct |
| --- | --- | --- | --- |
| Public | Yes | Usually unnecessary | Yes |
| AOS Hub auth | Yes | Yes, as a temporary capability | No |
| External identity provider/gateway | Optional defense in depth | No | Yes |
| Private network/VPN/IP allowlist | Yes | Yes if origin is reachable | Yes |

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
route records:

- provider kind and owner;
- expected credential mechanism;
- which client classes can use it;
- probe credentials or a network probe location, if available; and
- last verified policy state.

The console must not claim that stock Nix can use a route whose authentication
scheme Nix cannot express. Setup snippets are generated per compatible client.

### Private network

A route may be restricted by VPN, VPC, tunnel, or source IP. Network location
is the enforcement mechanism; obscurity of the hostname or path is not. The
route records the named network boundary and uses an in-boundary health probe
where possible.

## Surface visibility constraints

A route's effective audience must be no broader than its surface visibility.

- A public surface may use any route posture.
- An internal surface may use Hub auth, an internal external provider, or a
  private-network route.
- A private surface may use Hub auth or an explicitly scoped external/private
  route.
- An anonymous direct route for an internal/private surface is invalid.

The same constraints are checked at route creation, route enablement, surface
visibility changes, placement moves, and domain/access-provider changes.

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
pointers, only placements at the same published generation are eligible. The
route exposes generation lag in health and must not serve a newer pointer whose
referenced immutable objects are absent from the selected placement set.

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
