# Hub control plane and console

This page defines the relationship between the AOS Hub API, the `aos hub` CLI,
and the authenticated settings web application, and the checked manifests that
keep them in parity. The topology records and invariants are described in
[topology.md](topology.md) and [domain-model.md](domain-model.md).

## Parity boundary

The public remote control plane consists of every end-user operation that can
inspect or manage a running Hub without direct database, process, or deployment
access. Every capability in that boundary has:

- an `aos.hub.v1` Connect-JSON contract;
- an `aos hub` command with stable JSON output;
- an authenticated Web workflow when the capability is meaningful to a human;
- one permission and scope interpretation across all clients; and
- equivalent native and Cloudflare Worker behavior.

Public registry browsing, package installation, system-image discovery, and
downloads use their own end-user interfaces. They are API- and CLI-backed
where applicable, but are not part of settings merely to satisfy parity.

The following are not end-user control-plane capabilities:

- starting or configuring the native Hub process or Worker deployment;
- schema migration, backup restoration, root recovery, or recovery of the
  key that seals secrets at rest;
- controller reconciliation reports and storage-provider callbacks;
- direct database inspection or repair; and
- offline topology-cutover artifact generation and verification.

The checked capability manifest classifies these exclusions explicitly. A
missing interface is never treated as an implicit exclusion.

## One API, three clients

The Connect API is the sole management authority:

```text
browser session --CSRF exchange--> five-minute access JWT --+
                                                            |
aos hub login --> access JWT + refresh credential ----------+--> aos.hub.v1
                                                            |
service account --> access token --> access JWT ------------+
```

The credential terms (access token, access JWT, refresh credential) are
defined in [tenancy-and-auth.md](tenancy-and-auth.md#credentials).

The Web application does not submit management forms to bespoke HTTP handlers.
The CLI does not inspect Hub storage or invoke hidden operator endpoints. Both
clients serialize the generated ProtoJSON request types and consume the same
response and error contracts.

Every browser and CLI unary request sends the shared
`connect-protocol-version: 1` contract exported by `aos-hub-api`; the
native and Worker dispatchers reject a missing, repeated, or different value.
This is one protocol constant used by all clients and servers, not parallel
client-specific spellings.

The authenticated organization inventory is also the tenant-bootstrap entry
point.
A user with no memberships can open it and the dedicated organization-creation
page. The API remains the sole authority for live invite-only and signup-domain
policy when the user plans creation; route visibility does not duplicate or
bypass that policy.

A Web route's organization slug is only a locator. Before an organization page
lists or creates scoped infrastructure, the client calls `GetOrganization` and
uses the returned immutable `authorization_scope_key`. It carries the slug
separately only for API references whose declared identity is a human-facing
organization name. Constructing `org:{slug}` or parsing a stable scope back
into a slug is forbidden.

Web inventory is complete rather than viewport-sized: every paginated list
follows opaque `next_page_token` values to exhaustion. The shared browser
transport rejects a repeated non-empty token, so a server pagination cycle
fails visibly instead of spinning or silently truncating the resource graph.
Malformed tokens are rejected even when the selected inventory is empty.

The browser exchanges its short-lived management session when client-side
history crosses a canonical settings-scope root. Sibling pages under one
instance, organization, registry, or cache root share the same permission set
and retain the mounted shell during navigation. Route permissions therefore
always describe the exact current scope; a permission union obtained for a
global inventory is never reused to render an organization, registry, or cache
editor. When a scope crossing does require a new session, the application
retains the previous shell through the transition instead of replacing the
viewport with a loading page. Destination workflows own localized loading
states for their panels.

Every durable desired-state mutation follows one interaction:

1. Read the resource and exact resource version.
2. Submit a plan request with an idempotency key and expected version.
3. Present the semantic diff, effect manifest, warnings, and confirmation hash.
4. Apply the returned immutable plan and confirmation hash.
5. Follow any returned operation to a terminal state.
6. Reload canonical resource state.

Stale plans are never silently recomputed during apply. A client may preserve
the user's draft while requesting a new plan, but it must present the new
effects for confirmation.

Resource versions are opaque compare-and-swap tokens. For resources that can
be deleted and recreated under the same logical key, the token binds both the
monotonic row revision and an immutable incarnation. Numeric equality alone is
not sufficient: a plan for revision one of a deleted incarnation must fail
against revision one of its replacement. Plan-request idempotency is checked
before reading mutable target state, so retrying the exact request returns the
original plan even after that plan has changed or deleted the resource. The
service and its atomic apply transaction are the only production mutation
path; direct table seed helpers are compiled only into test fixtures.

## Capability manifest

[`hub-control-plane-capabilities-v1.json`](../../../crates/hub/aos-hub-api/contracts/hub-control-plane-capabilities-v1.json)
is the closed, versioned parity contract. Its HTTP entries identify
non-Connect authentication endpoints. Its service entries identify the
audience, owning API methods, CLI command families, and Web workflows for one
protobuf service. Native and Worker are the only supported runtimes.

The `aos-hub-api` `contract_inventory` integration tests compare this manifest
with the generated protobuf descriptor. API generation itself reads only the
canonical protobuf sources under `api/proto/`, independent of browser code.
Every API method appears exactly once. Every method owned by an `end-user` or
`public` service must also be referenced by the browser client.
An exact method may instead have a non-empty `web_method_exceptions` reason
when another browser call returns the same complete model or the action is an
explicit retained authentication ceremony. Unknown, duplicate, and stale
exceptions fail the integration gate. The service authorization
implementation is the authority for each method's permission and scope; the
manifest does not duplicate that security policy.

Browser method coverage recognizes generated path identifiers only as Rust
code, excluding comments and string literals, so prose cannot satisfy the
gate. The native console integration suite exercises a zero-membership session
exchange. The real-workerd deployment fixture exchanges a browser session and
completes an authenticated read plus one reviewed plan/apply mutation through
the production Worker route stack.

## Browser application boundary

The management application (`crates/hub/aos-hub-console`) is a Rust/Leptos
workspace member rendered entirely in the browser (client-side rendering). It
imports
the wasm-clean messages and generated Connect paths from `aos-hub-api` and
uses a typed transport over browser `fetch`. It does not maintain handwritten
wire structs or method URLs.

The bundle is compiled with the repository Rust toolchain for
`wasm32-unknown-unknown`, processed by the version-matched `wasm-bindgen`, and
installed as content-addressed JavaScript, WebAssembly, and CSS. Native and
Worker packages consume that same derivation. The application shell is not
cached; content-addressed assets are immutable. The generated module exports
the application mount entry point, and both runtime bootstrap modules call it
explicitly after WebAssembly initialization. Packaging and Worker E2E gates
reject a bootstrap that initializes the library without mounting the console.

The server shell loads the Hub's established `style.css` and `app.js` before
the content-addressed console assets. The client renders the same masthead,
session links, settings navigation, page measure, controls, forms, tables,
badges, attached-help behavior, focus behavior, responsive disclosure, and
version statline with configured legal links used by the server-rendered
pages. The management shell does not expose transport implementation labels.
Console CSS is strictly additive: packaging fails if it declares a root theme,
forces a color scheme, selects a replacement font, or introduces
dashboard-style elevation, so public, login, account, and other
server-rendered pages keep their appearance.

The client owns:

- scoped navigation and deep-link routing;
- API reads, pagination, and permission-aware rendering;
- typed editors and semantic plan review;
- operation status, cancellation, and retry;
- direct/proxy and multipart cache-object and publication uploads.

Bearer credentials, secret values, and upload authorization material are never
persisted by the application. Secret inputs are one-way fields or references,
and a newly issued secret is shown exactly once.

## Browser authentication

`POST /-/auth/session-token` is the only bridge from a browser session to the
Connect API. It requires:

- a valid HttpOnly session cookie;
- an allowed same-origin request;
- the session's CSRF proof; and
- an unexpired user and membership state.

The request names the current canonical deep link in `x-aos-console-route`.
The Hub resolves that route to its immutable authorization scope and evaluates
permissions from live grants; an unknown or mismatched route produces an empty
permission set. The `no-store` response contains a five-minute access JWT,
principal summary, effective grants, and the evaluated route permissions. The
application holds it only in memory and filters navigation from those
server-evaluated capabilities. After one API `401`, the application may
exchange once and retry once. A second failure navigates to
`/login?next=<current-deep-link>`.

Login, account password and passkey management, session revocation, OIDC
callbacks, invitation redemption, and device approval are server-rendered.
They establish or alter authentication state and are not management API
shortcuts. The sign-in methods themselves are described in
[tenancy-and-auth.md](tenancy-and-auth.md#credentials).

## CLI authentication and profiles

`aos hub login --hub URL` implements the OAuth 2.0 device authorization grant:

1. Request a device and user code.
2. Display the verification URI and code and optionally open a browser.
3. Poll the token endpoint at the server-provided interval.
4. Handle pending, slow-down, denial, and expiry responses.
5. Store the resulting access JWT and refresh credential for that normalized
   Hub origin in a mode-0600 user configuration file.

The CLI refreshes an expired access JWT with its refresh credential, which
rotates on every refresh; their shapes and lifetimes are in
[tenancy-and-auth.md](tenancy-and-auth.md#credentials). `aos hub logout`
revokes the refresh-credential family and removes the local profile.

Command connection resolution is, in order: explicit `--hub`/`--token`,
`AOS_HUB`/`AOS_TOKEN`, then the active stored Hub profile. `aos hub whoami`
shows the resolved origin, principal, credential expiry, memberships, and
effective grants.

Automation that holds an access token exchanges it for an access JWT through
an explicit token grant: it presents the `aos_` secret as the
`Authorization: Bearer` value of a
`urn:aos:params:oauth:grant-type:provisioning-token` request. That grant
returns no refresh credential.

The three runtime-identical endpoints are:

- `POST /oauth2/device_authorization` with `client_id=aos-cli`, a canonical
  stable resource `scope`, and an optional space-separated `permission` set;
- `POST /oauth2/token` with an explicit RFC 8628 device-code,
  `refresh_token`, or
  `urn:aos:params:oauth:grant-type:provisioning-token` grant; and
- `POST /oauth2/revoke` with `client_id=aos-cli`, the refresh credential, and
  `token_type_hint=refresh_token`.

Every response from these credential endpoints is non-cacheable. Unknown,
expired, denied, replayed, and rate-limited grants use structured OAuth error
responses; a consumed device code never remains usable as an opaque bearer.

## Service accounts and access tokens

Service accounts are organization-owned principals with list, get, create,
rename, and delete operations. Memberships grant users or service accounts a
role at an instance, organization, or resource scope.

An access token is the long-lived `aos_` secret defined in
[tenancy-and-auth.md](tenancy-and-auth.md#credentials). It is issued at any
authorization scope, not as a registry-specific resource. Issuance records:

- owner principal;
- canonical scope;
- requested permissions;
- comment;
- issue, expiry, last-use, rotation, and retirement times; and
- token generation.

The secret is returned once and only its hash is stored. Effective permissions
are the intersection of token permissions and the owner's current effective
grants. Disabling a service account or removing its membership therefore takes
effect without enumerating every issued token. Tokens default to 30 days and
cannot exceed 90 days.

Organization IAM parity also includes membership inventory and replacement,
invitations, OIDC configuration, and captured email-domain claim, verification,
and release.

### Invitations

An invitation is a durable pending grant proposal, never a membership alias.
Creation never pre-creates a user.

- **Create and cancel.** Administrator creation and cancellation use ordinary
  immutable plan/apply pairs. A durable live-invitation key enforces at most
  one pending invitation for an organization, email, and scope.
- **Acceptance secret.** Creation generates a high-entropy `aosi_` acceptance
  secret, stores its SHA-256 verifier, and retains only an AES-GCM-sealed
  recovery copy under the Hub's durable at-rest key. An exact idempotent apply
  retry unseals that same secret, closing the mutation-to-response crash
  window without persisting plaintext credential material or coupling
  invitations to ephemeral JWT keys.
- **Recovery-copy erasure.** Acceptance and cancellation erase the recovery
  copy. Bounded native maintenance and Worker Cron passes erase expired
  recovery copies and release their live keys atomically.
- **Acceptance.** The invited user presents the secret through the
  `AcceptInvitation` identity ceremony after authenticating with the exact
  canonical email. That ceremony is the narrow exception to administrator
  review: the secret and matching live identity are its preconditions, and one
  checked transaction both marks the invitation accepted and creates the exact
  direct membership. A conflict rolls both changes back.
- **States and audit.** Pending, accepted, cancelled, and time-derived expired
  states remain inspectable. Each transition emits a secret-redacted IAM audit
  event in the same checked transaction as its state and membership effects.

Native and Worker deployments use the same service and schema migrations
([runtime.md](runtime.md#database-backend)).

## Settings hierarchy

The settings navigation is data. Each settings scope has a `PageSpec` table
in `crates/hub/aos-hub-ui/src/lib.rs` (`INSTANCE_PAGES`,
`ORGANIZATION_PAGES`, `REGISTRY_PAGES`, and `CACHE_PAGES`) whose entries are in
final navigation order and name each page's key, label, navigation group,
canonical route suffix, and capability-manifest workflow. Those tables are
the source of truth; the summary below follows them.

Every scope root is its first navigation entry, is labeled **Overview**, and
belongs to no group. Creation pages such as "Create registry" also carry no
group. The remaining pages are grouped as follows:

| Scope | Group | Pages |
| --- | --- | --- |
| Organization | Resources | Projects, Registries, Binary caches |
| Organization | Infrastructure | Bindings, Domains, Network policies, Endpoints, Gateways, Topology defaults |
| Organization | Access & trust | Identity & access, Members, SSO, Signing keys, Access tokens |
| Organization | Automation | Webhooks |
| Organization | Activity | Operations, Audit log |
| Organization | Danger zone | Danger zone |
| Registry | Topology | Storage & replicas, Delivery, Binary caches |
| Registry | Access & trust | Identity & access, Signing keys, Access tokens |
| Registry | Publishing | Staged releases, Containers, Upstream mirror |
| Registry | Activity | Configuration history, Change requests, Publications, Operations & health |
| Registry | Danger zone | Danger zone |
| Binary cache | Topology | Storage & replicas, Delivery |
| Binary cache | Content | Objects & closures, Integrations |
| Binary cache | Access & trust | Identity & access, Signing keys, Access tokens |
| Binary cache | Policy | Retention, Garbage collection |
| Binary cache | Activity | Operations & health |
| Binary cache | Danger zone | Danger zone |

Registry and cache scopes share the Topology, Access & trust, Activity, and
Danger zone groups. Routes are edited on a surface's Delivery page.

Pages have one primary mutation domain. Topological context appears as links
and backlinks instead of duplicated editors: a placement page edits storage
intent, not delivery, and a route page edits one client path, not storage
identity. The registry/cache relationship pages follow the same rule; the
single effect of each record is listed in
[topology.md](topology.md#one-relationship-one-effect).

## Publication uploads

Connect requests are bounded control messages. Large NAR (Nix archive), blob,
and disk image bytes use upload tickets and direct or multipart object
transfers. The publication and upload protocols are specified in
[delivery.md](delivery.md#writes).
The Web application begins a publication, uploads immutable objects, and
commits only after every required object and placement verifies. Cache-object
uploads use `CreateCacheObjectUploads`; a direct-origin capability receives no
Hub bearer, while a typed same-origin proxy receives the in-memory access
JWT. When a single-request upload ticket carries no URL, the browser uses the
typed begin, part, complete, and abort multipart protocol. A partial or failed
registry publication is not discoverable.

The browser does not persist upload state or authorization material. Durable
publication sessions are discoverable from the Hub, so a user can reopen an
exact publication and upload its remaining declared objects. An interrupted
cache-object multipart transfer is aborted and restarted from a newly reviewed
upload ticket.

## Server-rendered routes

Canonical management GET URLs are application deep links that return the
console shell. Management has no server-rendered POST routes, redirects,
aliases, dual-write paths, or feature flags; every management mutation is an
`aos.hub.v1` call. The server-rendered route classes are limited to:

- login, logout, OIDC, magic-link, and passkey authentication;
- account password, passkey, and session management;
- invitation and device-code activation; and
- public registry, package, release, channel, image, and byte-delivery pages.

The exact route classes and rejection rules are recorded in the
[web route ledger](../../../crates/cli/aos-cli/hub-topology-cutover/web-route-ledger-v1.md).
Repository guards in `crates/cli/aos-cli/tests/hub_topology_cutover.rs` and
`crates/hub/aos-hub-api/tests/contract_inventory.rs` fail if a management
handler outside these classes, a direct database mutation, or a management
POST route appears.
