# Control-plane parity and client console

This chapter defines the final relationship between the AOS Hub API, CLI, and
authenticated settings Web application. It is normative for the control-plane
cutover. The topology records and invariants remain owned by the preceding
chapters.

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
downloads use their existing end-user surfaces. They remain API- and CLI-backed
where applicable, but do not move inside settings merely to satisfy parity.

The following are not end-user control-plane capabilities:

- starting or configuring the native Hub process or Worker deployment;
- schema migration, backup restoration, root recovery, or seal-key recovery;
- controller reconciliation reports and storage-provider callbacks;
- direct database inspection or repair; and
- offline topology-cutover artifact generation and verification.

The checked capability manifest classifies these exclusions explicitly. A
missing interface is never treated as an implicit exclusion.

## One API, three clients

The Connect API is the sole management authority:

```text
browser session --CSRF exchange--> five-minute bearer --+
                                                        |
aos hub device login --> access/refresh credential -----+--> aos.hub.v1
                                                        |
service account --> scoped access token ----------------+
```

The Web application does not submit management forms to bespoke HTTP handlers.
The CLI does not inspect Hub storage or invoke hidden operator endpoints. Both
clients serialize the generated ProtoJSON request types and consume the same
response and error contracts.

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

## Capability manifest

`hub-control-plane-capabilities-v1.json` is the closed, versioned parity
contract. A capability entry contains:

- stable capability id, resource family, scope, action, and permission;
- audience: `end-user`, `public`, `operator`, or `controller`;
- interaction: `read`, `plan-apply`, `operation`, `upload`, `download`, or
  `authentication`;
- every owning API method;
- CLI command paths, if applicable;
- Web route and workflow ids, if applicable;
- native and Worker availability; and
- an exclusion reason for non-end-user entries.

Checks compare the manifest with the protobuf descriptor, Clap command tree,
and Web route/workflow registry. Each API method appears exactly once. A
plan/apply entry names both methods. A final production build rejects the
states `planned`, `partial`, and `legacy`.

## Browser application boundary

The management application is a Rust/Leptos CSR workspace member. It imports
the wasm-clean messages and generated Connect paths from `aos-proto-types` and
uses a typed transport over browser `fetch`. It does not maintain handwritten
wire structs or method URLs.

The bundle is compiled with the repository Rust toolchain for
`wasm32-unknown-unknown`, processed by the version-matched `wasm-bindgen`, and
installed as content-addressed JavaScript, WebAssembly, and CSS. Native and
Worker packages consume that same derivation. The application shell is not
cached; content-addressed assets are immutable.

The client owns:

- scoped navigation and deep-link routing;
- API reads, pagination, and permission-aware rendering;
- typed editors and semantic plan review;
- operation status, cancellation, and retry;
- resumable direct and multipart publication uploads; and
- non-secret interrupted-upload metadata in IndexedDB.

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

The response is `no-store` and contains a five-minute bearer, principal
summary, and effective grants. The application holds it only in memory. After
one API `401`, the application may exchange once and retry once. A second
failure navigates to `/login?next=<current-deep-link>`.

Login, account password and passkey management, session revocation, OIDC
callbacks, invitation redemption, and device approval remain server-rendered.
They establish or alter authentication state and are not management API
shortcuts.

## CLI authentication and profiles

`aos hub login --hub URL` implements the OAuth 2.0 device authorization grant:

1. Request a device and user code.
2. Display the verification URI and code and optionally open a browser.
3. Poll the token endpoint at the server-provided interval.
4. Handle pending, slow-down, denial, and expiry responses.
5. Store the resulting access and refresh credentials for that normalized Hub
   origin in a mode-0600 user configuration file.

Access JWTs last one hour. Opaque refresh credentials have a 30-day idle and
90-day absolute lifetime, are hashed at rest, rotate on every refresh, and are
bound into a family. Reuse of a consumed refresh credential revokes the family.
`aos hub logout` revokes the family and removes the local profile.

Command connection resolution is, in order: explicit `--hub`/`--token`,
`AOS_HUB`/`AOS_TOKEN`, then the active stored Hub profile. `aos hub whoami`
shows the resolved origin, principal, credential expiry, memberships, and
effective grants.

The provisioning-secret bootstrap is an explicit token grant for initial
automation. The old untyped exchange and provisioning-secret-only login syntax
are not retained.

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

Access tokens replace registry-specific token resources. Issuance records:

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

An invitation is a durable pending grant proposal, never a membership alias.
Administrator creation and cancellation use ordinary immutable plan/apply
pairs. Creation generates a high-entropy `aosi_` acceptance secret, stores its
SHA-256 verifier, and retains only an AES-GCM-sealed recovery copy under the
Hub's durable at-rest key. An exact idempotent apply retry unseals that same
secret, closing the mutation-to-response crash window without persisting
plaintext credential material or coupling invitations to ephemeral JWT keys.
Acceptance and cancellation erase the recovery copy. Bounded native maintenance
and Worker Cron passes erase expired recovery copies and release their live keys
atomically. A durable live-invitation key enforces at most one pending invitation
for an organization, email, and scope. The invited user presents the secret
through the `AcceptInvitation` identity ceremony after authenticating with the
exact canonical email. That ceremony is the narrow exception to administrator review:
the secret and matching live identity are its preconditions, and one checked
transaction both marks the invitation accepted and creates the exact direct
membership. A conflict rolls both changes back. Pending, accepted, cancelled,
and time-derived expired states remain inspectable; creation never pre-creates
a user. Each transition emits a secret-redacted IAM audit event in the same
checked transaction as its state and membership effects. Native and
Worker deployments use the same service and migration, and Worker schema DDL
advances its migration ledger in the same Durable Object transaction. Native
PostgreSQL and SQLite migrate transactionally; MySQL uses a keyed singleton
ledger plus replay-safe DDL and exact index-catalog checks because MySQL DDL
implicitly commits.

## Settings hierarchy

Every scope root is its first navigation entry and is labeled **Overview**.
The organization group order is:

1. Overview
2. Projects
3. Registries
4. Binary caches
5. Storage
6. Networking
7. Identity & access
8. Signing
9. Webhooks
10. Operations
11. Audit
12. Danger

Networking contains domains, network boundaries, delivery endpoints, storage
gateways, and routes. Registry and cache pages reuse the same Overview,
Delivery, Placements, Integrations, Security, Operations, Activity, and Danger
grammar. Registry content owns packages, releases, channels, images,
publication, mirror, and configuration. Cache content owns objects, closures,
retention, population, coverage, and garbage collection.

Pages have one primary mutation domain. Topological context appears as links
and backlinks instead of duplicated editors. In particular:

- a placement edits storage intent, not delivery;
- a delivery route edits one simultaneous client path, not storage identity;
- a registry cache stack edits signed consumer configuration;
- a retention subscription edits GC roots; and
- a population target edits desired byte presence.

## Publication uploads

Connect requests remain bounded control messages. Large NAR, blob, and disk
image bytes use upload admissions and direct or multipart object transfers.
The Web application computes SHA-256, begins a publication, uploads immutable
objects, reconciles interrupted upload state, and commits only after every
required object and placement verifies. A partial or failed publication is not
discoverable.

IndexedDB may retain publication ids, upload ids, local file identity, offsets,
and checksums so a user can resume. It must not retain API bearers or signed
upload credentials.

## Hard management cutover

Canonical management GET URLs remain stable and become application deep links.
All management POST routes, inventory-only templates, management renderers,
and private bridge dispatch are deleted. There are no redirects, aliases,
dual-write paths, or feature flags after cutover.

The retained server-rendered route classes are limited to:

- login, logout, OIDC, magic-link, and passkey authentication;
- account password, passkey, and session management;
- invitation and device-code activation; and
- public registry, package, release, channel, image, and byte-delivery pages.

The exact route classes and rejection rules are recorded in
`11-web-route-cutover-ledger.md`.

## Acceptance

The cutover is complete only when:

- capability checks report no incomplete end-user entry;
- native and Worker API/authentication fixtures are equivalent;
- every durable mutation passes plan/apply, stale-version, expired-plan,
  confirmation, permission, idempotency, and audit tests;
- registry and cache scenarios cover standalone caches, shared caches, ordered
  cache stacks, multiple placements, and simultaneous delivery routes;
- publication and image fixtures cover resumable uploads, exact bytes,
  checksums, range requests, and public/private access;
- repository guards find no removed management handler or POST route;
- the exact candidate commit passes hosted staging acceptance; and
- end-user documentation describes only tested, shipped workflows.
