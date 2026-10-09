# Use the AOS Hub API

AOS Hub exposes unary, Connect-compatible JSON routes over HTTP. Requests use
JSON bodies and responses use JSON; clients do not need a gRPC runtime.

## Endpoint shape

Methods are mounted at:

```text
POST /aos.hub.v1.<Service>/<Method>
```

For example:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme/cdn"}' \
  https://hub.example.com/aos.hub.v1.RegistryService/GetRegistry
```

An empty request may be sent as `{}`. API errors use a JSON envelope with a
machine-readable `code` and a human-readable `message`.

The service families cover registries, organizations, projects, storage,
packages, channels, audits, instance settings, identity and access, webhooks,
publishing, Git surfaces, and binary caches. The complete request and response
schema is in
[`hub.proto`](../../../crates/aos-proto/src/proto/aos/hub/v1/hub.proto).

## Authentication

Public registry reads do not require authentication. Private reads and changes
require a bearer access token with the necessary permission:

```text
Authorization: Bearer <access-token>
```

The simple `/<flat-slug>/-/api/...` routes documented in the web guide are
always public-only: they do not use a browser session or bearer token, and the
current router accepts only single-segment slugs. Use the unary service routes
for canonical organization/registry paths and authenticated visibility.

Interactive clients start an RFC 8628 device grant with
`POST /oauth2/device_authorization`, show the returned verification URL and
user code, and poll `POST /oauth2/token` at the advertised interval. A
successful poll returns a one-hour access token and a rotating refresh
credential. `aos hub login` implements this flow:

```sh
aos hub login --hub https://hub.example.com
```

The device request uses `client_id=aos-cli`, an optional canonical stable
resource `scope`, and an optional space-separated `permission` value. Polling
uses grant type `urn:ietf:params:oauth:grant-type:device_code`. Refresh uses
grant type `refresh_token`; every successful refresh returns a replacement
refresh credential. Reusing a consumed credential revokes the complete family.
`POST /oauth2/revoke` accepts the refresh credential,
`client_id=aos-cli`, and `token_type_hint=refresh_token`.

Publishing automation may instead start with a provisioning token whose secret
begins with `aos_`. The Hub stores only its hash. Exchange it with the explicit
grant type `urn:aos:params:oauth:grant-type:provisioning-token` and the secret
as an `Authorization: Bearer` credential. A native operator can mint scoped
provisioning tokens with `aos-hub token mint`.

All OAuth credential responses carry `Cache-Control: no-store`. Native and
Cloudflare Worker deployments mount the same handlers and return the same
structured pending, slow-down, denial, expiry, and invalid-grant errors.

The CLI obtains user credentials through `aos hub login`; the browser console
obtains a short-lived bearer from its signed-in session without exposing it to
the user. Bootstrap administration through the local `aos-hub` command on
native deployments or the web console on either runtime. Non-browser API
clients still need a suitably scoped device-flow or provisioning credential.

Browser authentication uses an opaque session cookie and is intentionally
separate from API bearer tokens.

Inspect a bearer without exposing its secret through
`IdentityService/WhoAmI`:

```sh
curl -fsS \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access-token>' \
  -d '{}' \
  https://hub.example.com/aos.hub.v1.IdentityService/WhoAmI
```

The response identifies the live user or service account, lists current role
grants, and separately reports this token's scope, permissions, and expiry.

`IdentityService` manages generic access tokens with
`ListAccessTokens`, `PlanIssueAccessToken`/`IssueAccessToken`, and
`PlanRetireAccessToken`/`RetireAccessToken`. Requests use canonical stable
authorization scopes and native permission verbs such as `read`, `publish`,
`binding.manage`, or `cache.gc.plan`. There are no registry-token RPC
aliases. Token metadata includes its non-secret comment, creation, expiry,
last-use, rotation, retirement, and lifecycle state; the plaintext secret is
returned once by the issuance apply response.

Service accounts use `ListServiceAccounts`, `GetServiceAccount`, and reviewed
create, update, and delete pairs. A rename changes only the human-facing
`<org>/<name>` reference; the numeric principal identity remains stable. Delete
removes direct memberships atomically, while retained token metadata becomes
unusable immediately because its owner is no longer live. The former
`AutomationPrincipal` API names are not served.

Organization invitations use `ListInvitations`, `GetInvitation`, reviewed
`PlanCreateInvitation`/`CreateInvitation` and
`PlanCancelInvitation`/`CancelInvitation` pairs, plus the authenticated
`AcceptInvitation` identity ceremony. Creation returns a 256-bit `aosi_`
acceptance secret; only its SHA-256 verifier and AES-GCM-sealed recovery copy
are stored. Retrying the exact same apply idempotency key returns the same
unsealed secret, while a different apply is rejected. Acceptance or
cancellation erases the recovery copy immediately; bounded maintenance erases
expired copies. A pending invitation is not a user or membership. Acceptance
succeeds only for a live user whose
canonical email and organization match the invitation, and atomically consumes
the secret while creating the exact direct membership. History remains visible
as `pending`, `accepted`, `cancelled`, or time-derived `expired` metadata.
Connect responses carry `Cache-Control: no-store`, `Pragma: no-cache`, and
`Referrer-Policy: no-referrer`, so secret-bearing mutation results are not
retained by shared caches or leaked as referrers.

Organization SSO uses two explicit `IdentityService` resources. The
identity-provider surface consists of `GetIdentityProvider`, reviewed
`PlanSetIdentityProvider`/`SetIdentityProvider`, and reviewed
`PlanRemoveIdentityProvider`/`RemoveIdentityProvider`. Reads report only
whether a client secret is configured. A plaintext replacement is accepted at
the request edge, sealed before plan persistence, and never returned.

Email-domain ownership uses `ListOrganizationDomains`,
`GetOrganizationDomain`, and reviewed claim, verify, and release pairs. A new
claim requires `expectedResourceVersion: "absent"`; subsequent operations use
the exact returned resource version. Verification performs DNS resolution in
both native and Worker deployments and commits only when the exact reviewed
TXT challenge is present. Claim, audit, and plan completion are one atomic
database transaction, including on MySQL.

## Topology and cache bytes

`TopologyService/ExplainSurfaceRequest` explains how one absolute HTTP request
selects a live simultaneous route. `TopologyService/ListObjectPresence`
returns physical evidence for one logical object across all placements.
Placements are addressed by their stable surface-local names. Cache placement
eviction uses the reviewed
`BinaryCacheService/PlanRunPlacementEviction`/`RunPlacementEviction` pair and
is separate from logical GC.

Cache producers call `BinaryCacheService/CreateCacheObjectUploads` with one
canonical machine path and declared byte size, or parallel `paths`/`sizes`
arrays containing at most 256 unique objects. The batch response preserves
input order and exact retries return the same live tickets. A non-empty
`uploadUrl` accepts the exact bytes with `PUT`; direct-origin URLs are
capabilities and must not receive the Hub bearer, while
`/BinaryCacheService/UploadObject/...` is a typed authenticated Hub proxy. An
empty URL requires
`BeginCacheMultipartUpload`, numbered `PUT` requests to the returned
`partUploadUrl`, and `CompleteCacheMultipartUpload`; clients abort failed
uploads with `AbortCacheMultipartUpload`.

## Scripting

The remote client covers common calls and provides stable JSON output:

```sh
aos --json hub registry list --hub https://hub.example.com
aos --json hub registry get acme/cdn --hub https://hub.example.com
```

Pass `--token '<access-token>'` to commands that require authentication. Use
the schema when building a client or integration.

## Read native release documentation

`aos.hub.v1.DocumentationService` uses the registry's normal read authorization.
Native references are retained with completed signed releases. Hub checks the
publication's documentation directory and exact `options.json` byte identity
before returning or rendering the `aos.module.documentation` document.
Packages without a native documentation artifact return not found. The
`/{registry}/-/api/v1/` documentation, ability, and option reads accept the same
registry read bearer as their RPC counterparts; a browser session cookie alone
does not authenticate these JSON routes. Credentialed responses use private,
no-store caching even when the document digest identifies immutable bytes.

| Method | Native behavior |
| --- | --- |
| `GetPackageDocumentation` | Selects registry/package/version/platform, with an optional exact `release` pin. |
| `SearchPackageDocumentation` | Searches generated `package`, `option`, or `operation` rows; each result carries release, registry commit, and document digest. |
| `ListPackageOptions` | Lists typed native options with prefix, owner, portable type JSON, and extensibility filters. |
| `GetPackageOption` | Selects an option by exact nonempty literal path segments. |
| `ComparePackageDocumentation` | Compares two package versions on the same platform and returns `aos.module.documentation.comparison`. |
| `GetDocumentationArtifact` | Retrieves the exact native reference matching a document digest. |
| `GetPackageDocumentationSchema` | Returns the selected native reference bytes and documentation identity. |

For a pinned document read:

```sh
curl -fsS -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access-token>' \
  -d '{"registry":"acme/packages","package":"sample","version":"1.0","platform":"x86_64-linux","release":"1.0.0"}' \
  https://hub.example.com/aos.hub.v1.DocumentationService/GetPackageDocumentation
```

Empty version/platform selectors use Hub's deterministic default selection.
An explicit release never falls back to another release. The HTTP package
options list also honors its `release` query; the options RPC uses
version/platform selection. The response identity includes the verified commit,
tag object, completed snapshot, exact document
digest and size, and artifact store path/NAR identity. The `canonicalJson`
transport field carries the exact signed JSON bytes as protobuf JSON base64.
Decode those bytes before checking their digest; do not parse and reserialize
the document first. `etag` is the document digest.
A search-to-read client should send the result's release with its exact package,
version, and platform, then check the returned commit and digest against the
result.

The schema-named method returns the package's native reference; it does not
return an independently authored schema. Interface metadata identifies each
interface's release owner: package interfaces use the owning package release,
and OS/base interfaces use the OS release. `moduleRequirements` entries
preserve `owner`, `package`, and `packageVersion`; `osRequirements` entries
preserve `owner` and `osVersion` for the selected host OS. Plain dependencies inherit the recipe's generated
`package.versionRequirement`; explicit source pins remain exact. These fields are generated from the same module
declarations; they do not report a resolver decision. The generic reference
schema is available through local documentation tooling. Native comparison output keeps
option path segments and `[ability, operation]` pairs separate, and compares
option type/mutability/extension policy and operation input/result types,
handler availability, and configured instances. It also reports interface release
owner changes and module requirement changes by exact `[owner, package]` pairs. Prose changes and observed runtime state are outside
that comparison.

## Read native release declarations and reporter assertions

`GetPackageAbilityReference` returns the exact native reference bytes with the
completed release, commit, tag, snapshot, and document digest. The retired
manifest/provider-plan identity fields are reserved. `GetReleaseAbilityGraph`
returns `aos.module.release-graph`: an authenticated release and platform pin
with exact package references. It aggregates declarations; it does not infer
executed effects or handler edges.

`ReportPackageAbilityDeployment` accepts `aos.module.deployment-report`, binding
one enrolled deployment slot and strictly increasing sequence to an exact native
package reference. Hub checks the desired transaction graph, declaration input
and result contracts, and any reported result values. The active enrolled
principal and current enrollment resource version must match. Reports expire
within 300 seconds; reads require `audit.read` and recheck enrollment liveness.
Exact identities and checked values establish the report's scope, not proof of
live runtime state. The graph is desired state and outputs are reporter
assertions. Migrating from retired report formats clears their assertion bytes
while preserving enrollment and the sequence replay fence.

## Inspect a native runtime document

This stateless endpoint is available when the browse UI is mounted:

```text
POST /-/api/runtime-documentation
POST /-/api/runtime-documentation?format=html
```

Send raw JSON with schema `aos.module.documentation` or
`aos.package.transaction`. The shared native reader validates the document;
transaction input includes checked graph identities, dependencies, and ordering.
The default response is parsed JSON; `format=html` returns an HTML fragment with
package/operation links or the ordered execution path. Invalid documents or
formats return HTTP 400. Requests share the Hub's 8 MiB body ceiling.

```sh
curl --data-binary @options.json -H 'Content-Type: application/json' \
  'https://hub.example/-/api/runtime-documentation?format=html'
```

The endpoint does not retain uploads, evaluate Nix, execute handlers, authenticate
release provenance, or add documents to a release index. Successful inspection
responses use `Cache-Control: no-store`. This read-only browser support endpoint
is separate from the release documentation Connect service. See the
[runtime abilities guide](../aos/runtime-abilities.md) for native declaration
and transaction examples.

## Unpublished registry release candidates

`aos.hub.v1.PublishService` exposes these Connect methods. Every operation,
including inventory reads, requires the registry's Publish permission.

| Method | Purpose |
| --- | --- |
| `UpsertStagedRelease` | Save or attach one portable candidate revision with compare-and-swap |
| `GetStagedRelease` | Read its exact signed commit, withheld pointer bytes, and inventory |
| `ListStagedReleases` | List permissioned candidates with `page_size`, `page_token`, and `next_page_token` |
| `FinalizeStagedRelease` | Publish the frozen revision and reserved signed release identity |
| `DiscardStagedRelease` | Relinquish a candidate after an exact revision check |

Each method is a POST to `/aos.hub.v1.PublishService/<method>`.
`UpsertStagedRelease` takes `registry`, exactly one of canonical `revision_json`
or gzip `revision_gzip` bytes in the shared `aos.registry-stage/v1` schema,
`expected_revision` (`0` for creation; the observed revision for an edit or
attachment), and an optional `publication_id` that may initially be empty.
The Connect envelope is capped at 8 MiB, decoded revision JSON at 32 MiB, and
compressed bytes at 6 MiB minus 4 KiB. A revision has at most 50,000 objects.
Protobuf JSON encodes gzip bytes as base64; pointer bytes within the revision
also use base64 strings. Detail reads return `revision_gzip`; list summaries
leave both payload fields empty. These limits cover metadata, not artifacts;
bulk object admission uses the existing chunked publication-manifest protocol.

`FinalizeStagedRelease` takes `registry`, `stage_id`, `expected_revision`, and
`release_id` matching the version declared by that revision. Releasing freezes
the revision; retries continue the exact signed tag, commit, and release/OCI
bindings after public verification. Discarded or superseded candidate roots
retain a 24-hour grace period, while released and shared roots remain retained.
Default public catalogs and channel pointers never discover unfinished stages.

For an AOS distribution timestamp, admission binds the exact prepared envelope
to its immutable metadata inventory and applies the existing publication and
monotonic timestamp rules. Registry tag verification and consumer verification
of distribution TUF signatures against pinned roots are distinct checks. Hub
admission does not infer root trust from a candidate-supplied root.

See [the console workflow](web.md#review-unpublished-release-candidates) and
[the common stage contract](../../registry/release-stages.md) for candidate
inspection, resume, and the distinction between staged bytes and publication.
