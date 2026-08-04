# Web UI, CLI, and API contracts

The Web UI, `aos hub` CLI, and Connect-JSON API are three presentations of the
same resources and operations. They must not invent separate meanings for
“frontend,” “link,” “advertise,” or “change storage.”

## Shared interaction rules

1. Every mutation has one primary effect: placement, route, consumer
   publication, retention, population, replication, or GC.
2. Cross-resource workflows first produce a semantic plan. Apply uses the
   versions observed by that plan and rejects stale state.
3. Signed registry changes remain change requests. An API success means the
   proposal was created, not that consumers already see it.
4. Long operations return an operation id and observable status instead of
   holding an HTTP request open.
5. Human interfaces show names and URLs. Numeric ids remain API/storage
   identifiers and are not the principal navigation model.
6. Every read command and list endpoint has stable machine-readable output.
7. Destructive operations require an explicit plan/apply or confirmation
   token; `--yes` is valid only after the plan is printed or supplied by id.
8. Placement mutation inputs use kind, lifecycle, and read selection. Primary
   role and effective write eligibility are derived responses; only promotion
   changes desired write authority.
9. Desired and observed authority, placement state, and generations are shown
   separately. Interfaces never present a pending promotion as two primaries
   or silently elect a writer from health.

## Resource references

The CLI uses qualified surface references so registries and binary caches may
share names without ambiguous flags:

```text
registry:andyl/main
cache:andyl/shared
```

The API uses a typed `SurfaceRef` oneof. The Web UI derives it from its scoped
resource route. Neither accepts a bare integer as the normal user-facing
reference.

## Cross-interface ownership

| Settings owner | CLI family | API owner |
| --- | --- | --- |
| Storage bindings and defaults | `storage-binding`, `{org,instance} topology-defaults` | `StorageBindingService` |
| Storage, replicas, and write authority | `placement`, `placement-policy`, `placement-equivalence` | `TopologyService` |
| Domains | `domain` | `DomainService` domain methods |
| Storage gateways | `gateway` | `DomainService` gateway methods |
| Delivery | `route` | `RouteService` |
| Consumer cache stack | `registry cache-stack` | `CacheIntegrationService` consumer methods |
| Retention subscriptions | `cache retention` | `CacheIntegrationService` retention methods |
| Manual roots and leases | `cache root`, `cache lease` | `BinaryCacheService` retention-root methods |
| Population and coverage | `cache population`, `cache coverage` | `CacheIntegrationService` population/coverage methods |
| Logical GC and placement eviction | `cache gc`, `placement eviction` | `BinaryCacheService` |
| Long-running work | `operation` | `OperationsService` |

An interface may link to another owner's editor, but it does not reimplement
or proxy that mutation under a second resource path.

Retained settings features make the same namespace/name cutover; they are not
left as undocumented Web-only operations:

| Settings owner | Final CLI family | Final `aos.hub.v1` API owner |
| --- | --- | --- |
| Organizations and projects | `org`, `project` | `OrganizationService`, `ProjectService` CRUD |
| Members, invitations, roles, SSO | `org member`, `org sso` | `IdentityService` member and SSO methods |
| Hosted and surface signing keys | `signing-key` | `SigningKeyService` list/enroll/rotate/retire methods |
| Webhooks | `org webhook` | `WebhookService` list plus plan/apply create/delete methods |
| Audit | `audit` | `AuditService` |
| Registry CRUD and identity/access | `registry`, `registry identity` | `RegistryService` get/list plus plan/apply create/update/delete methods |
| Registry tokens | `registry token` | `IdentityService` list plus plan/apply mint/rotate/revoke methods |
| Upstream registry mirror | `registry mirror` | `RegistryMirrorService` |
| Signed configuration | `registry configuration` | `RegistryConfigurationService` |
| Change requests | `registry change-request` | `ChangeRequestService` comment/review/close/reopen/apply methods |
| Channels | `registry channel` | `ChannelService` list/get plus plan/apply update/advance methods |
| Publish history and credentials | `registry publish` | `PublishService` |
| Binary-cache CRUD and identity/access | `cache`, `cache identity` | `BinaryCacheService` plan/apply CRUD/update methods |
| Instance identity, resource defaults, branding | `instance identity`, `instance resource-defaults`, `instance branding` | `InstanceService` get plus separate plan/apply update methods |

The old ambiguous `OrgService`, `StorageService`, `ConfigService`, `IamService`,
and registry-package `CacheService` descriptors are replaced by the final names
above. Exact request types preserve the one-effect and plan/apply rules; tests
map every final Web form action to its CLI command and API method.

## Web UI contract

The settings-shell hierarchy, exact grouped navbars, page ownership, ordering,
and layout behavior are normative in
[`10-settings-information-architecture.md`](10-settings-information-architecture.md).
The exhaustive old method+path deletion and replacement list is normative in
[`11-web-route-cutover-ledger.md`](11-web-route-cutover-ledger.md).

### Navigation and canonical paths

The exact grouped labels and ordering are specified in
`10-settings-information-architecture.md`. The canonical path trees are:

```text
/-/orgs/new

/-/org/{org}
/-/org/{org}/projects
/-/org/{org}/projects/new
/-/org/{org}/registries
/-/org/{org}/registries/new
/-/org/{org}/caches
/-/org/{org}/caches/new
/-/org/{org}/storage-bindings
/-/org/{org}/storage-bindings/new
/-/org/{org}/domains
/-/org/{org}/domains/new
/-/org/{org}/storage-gateways
/-/org/{org}/storage-gateways/new
/-/org/{org}/topology-defaults
/-/org/{org}/members
/-/org/{org}/members/invitations/new
/-/org/{org}/sso
/-/org/{org}/hosted-keys
/-/org/{org}/hosted-keys/new
/-/org/{org}/webhooks
/-/org/{org}/webhooks/new
/-/org/{org}/operations
/-/org/{org}/audit-log
/-/org/{org}/danger

/{registry}/-/settings
/{registry}/-/settings/placements
/{registry}/-/settings/delivery
/{registry}/-/settings/caches
/{registry}/-/settings/caches/consumer-stack
/{registry}/-/settings/access
/{registry}/-/settings/signing-keys
/{registry}/-/settings/tokens
/{registry}/-/settings/upstream-mirror
/{registry}/-/settings/configuration
/{registry}/-/settings/channels
/{registry}/-/settings/change-requests
/{registry}/-/settings/publish-history
/{registry}/-/settings/operations
/{registry}/-/settings/danger

/-/org/{org}/caches/{cache}
/-/org/{org}/caches/{cache}/placements
/-/org/{org}/caches/{cache}/delivery
/-/org/{org}/caches/{cache}/objects
/-/org/{org}/caches/{cache}/retention
/-/org/{org}/caches/{cache}/retention/subscriptions/{registry}
/-/org/{org}/caches/{cache}/retention/manual-roots/new
/-/org/{org}/caches/{cache}/integrations
/-/org/{org}/caches/{cache}/integrations/{registry}/population
/-/org/{org}/caches/{cache}/garbage-collection
/-/org/{org}/caches/{cache}/garbage-collection/plans/{plan}
/-/org/{org}/caches/{cache}/garbage-collection/runs/{operation}
/-/org/{org}/caches/{cache}/garbage-collection/runs/{operation}/jobs/{job}
/-/org/{org}/caches/{cache}/access
/-/org/{org}/caches/{cache}/signing-key
/-/org/{org}/caches/{cache}/operations
/-/org/{org}/caches/{cache}/danger

/-/instance
/-/instance/identity-and-signup
/-/instance/resource-defaults
/-/instance/branding
/-/instance/storage-bindings
/-/instance/domains
/-/instance/storage-gateways
/-/instance/topology-defaults
/-/instance/operations
```

Placement and delivery creation use `/new` below their owning collection;
detail, edit, plan, and operation URLs use stable resource ids below the same
collection. Registry placeholders retain the current nested
`{org}/{project...}/{registry}` shape.

The hard-cutover route mapping is:

| Removed UI location | Canonical replacement |
| --- | --- |
| organization root rendering Registries | organization Overview; registry inventory at `/registries` |
| organization `/storage` | `/storage-bindings` |
| organization `/keys` | `/hosted-keys` |
| organization `/audit` | `/audit-log` |
| organization `/settings` redirect | deleted; use the organization root Overview |
| organization `/bindings/{id}` | `/storage-bindings/{id}` |
| organization binding frontend section | `/storage-gateways` and materialized surface delivery routes |
| registry `/settings` General page | registry `/settings` Overview and `/settings/access` |
| registry `/settings/storage` | `/settings/placements` |
| registry `/settings/serving` | `/settings/delivery` and `/settings/upstream-mirror` |
| registry `/-/keys` | `/settings/signing-keys` |
| registry `/settings/config` | `/settings/configuration` |
| registry `/-/changes` | `/settings/change-requests` |
| registry `/-/publishes` | `/settings/publish-history` |
| cache `/storage` | `/placements` |
| cache `/serving` | `/delivery` |
| cache `/links` | `/integrations` |
| cache `/pins` | `/retention` and `/garbage-collection` |
| instance root General form | instance Overview and `/identity-and-signup` |
| instance `/serving` | `/resource-defaults` |
| instance `/storage` | `/storage-bindings` |

Semantically final paths such as registry `/settings/caches` remain canonical;
they are not compatibility aliases. All removed handlers and paths disappear
at cutover and are not retained as redirects or read-only pages. Release notes
and the preflight report provide this mapping before deployment.

Form POST paths live below the page that owns the resource; successful
mutations redirect to a stable operation or resource URL.

### Storage & replicas

The page shows placement cards/table, placement-policy order, and a separate
Write authority panel. That panel names the desired and observed placement,
their generations, reconciliation state/error, and whether writes currently
fail closed. The observed authority sorts first; a different desired candidate
is labeled Promotion pending rather than Primary. Placement forms never expose
editable primary, write-enabled, or write-order controls.

Supported actions are:

- add a placement;
- scan or rescan presence;
- seed/replicate from an existing placement;
- repair missing/corrupt objects;
- change read-policy order;
- review and promote a ready complete placement through the Write authority
  panel;
- retry or review cancellation of a pending/failed promotion;
- begin drain;
- cancel drain; and
- remove a fully drained placement.

“Move storage” becomes a guided workflow:

1. create destination placement;
2. copy and verify;
3. update applicable placement policies;
4. optionally promote write authority to the destination;
5. drain the source; and
6. remove the source later.

The workflow never presents a binding change as an instantaneous pointer swap
when bytes or routes still depend on the old placement. Promotion apply uses
the authority, current-writer, and candidate versions captured by its impact
plan. A pending promotion links to its operation/reconciliation state and
cannot be bypassed by editing either placement.

### Delivery

The route table and editor specified in
[`06-console-and-operations.md`](06-console-and-operations.md) are normative.
Actions are add, edit, probe, explain, enable, disable, make canonical, and
remove. Direct gateway-derived routes display their gateway and placement;
they are not hidden as inherited state.

Changing domain, access provider, surface visibility, placement policy, or
canonical status opens an impact review showing affected setup snippets,
signed cache entries, routes, and client compatibility.

### Binary-cache integrations

The Registry “Binary caches” page is a read-only aggregation with two views:

- **Consumer cache stack:** the signed `try`/`mirror` expression, external and
  managed endpoints, pending change requests, coverage, and evaluation order.
- **Operational integrations:** retention subscriptions and population
  targets.

“Integrate binary cache” is a preview-only review of three independent forms.
Each section has its own plan id, permission check, resource version, and link
to the canonical workflow that can apply it:

```text
Consumer publication: plan plan_pub_... -> continue in consumer cache stack
Retention: plan plan_ret_... -> continue in cache retention
Population: skipped
```

The review has no apply-all action. Applying or retrying one plan in its owner
never applies another. A partial result is the normal composition of independent
states, not a failed cross-resource transaction. Removing an integration asks
which dedicated workflow to open; there is no one-click ambiguous “unlink.”

Each effect has exactly one settings owner and canonical editor: consumer
publication under the registry consumer stack, retention under the cache's
registry subscription, and population under the cache's registry integration.
Inverse-scope views link to these editors and do not mount duplicate forms.

### Retention and GC

Retention editing uses typed selectors rather than a global “keep versions”
box. The page previews selected releases, channel partition targets, artifact
counts, closure size, and exposure consequences before apply.

GC is always plan-first in the Web UI. Logical cache GC and placement eviction
have different buttons, reports, permissions, and confirmations.
The policy page links to dedicated immutable plan and run resources rather than
submitting a synchronous sweep. Plan review shows captured versions, coverage
gates, `unreferenced_since`, per-placement narinfo-before-NAR actions, and
estimated versus shared bytes. Run detail shows confirmed deletion, retry, and
abandonment without treating leaked bytes as reclaimed.

### No-JS behavior

All reads and mutations work through normal forms, POST/redirect/GET, and
operation-status pages. JavaScript may enhance reordering, polling, and route
explanation but may not be the only way to perform or review an operation.

## CLI contract

### Command ownership

`aos hub` is the user/operator remote porcelain and calls the public
Connect-JSON API. `aos-hub` remains the server/deployment/recovery binary:

```text
aos-hub serve
aos-hub init / schema / worker deploy
```

Ordinary topology CRUD is not independently reimplemented as direct database
logic in both binaries. Local recovery commands call the same core service
methods or are explicitly labeled offline recovery operations.

The cutover uses a one-shot preflight/transformer artifact. That artifact is
removed after all managed deployments migrate; it is not a permanent
`aos-hub` subcommand or runtime compatibility layer.

### Common flags and output

Every desired-state, policy, or destructive `aos hub` mutation accepts the
existing Hub URL/token configuration and:

```text
--json                 stable versioned JSON output
--plan                 print effects without applying
--plan-id <id>         apply a previously reviewed plan
--if-version <value>   optimistic-concurrency precondition
--yes                  non-interactive confirmation after a plan
```

List commands support pagination and `--json`. Long-running commands print the
operation id and support `--wait`, `--timeout`, and `operation watch`.
Read-only probes and idempotent reconcile/refresh/scan triggers do not invent a
no-op semantic plan; they return observed state or an operation id.

### Surface inspection

```text
aos hub surface show <surface-ref>
aos hub surface topology <surface-ref>
aos hub surface explain <surface-ref> --url <url> [--path <machine-path>]
```

`topology` prints placements, placement policies, routes, canonical endpoints,
and current health as a tree. `explain` mirrors the Web UI request-path
explanation and has identical JSON fields.

### Placements

```text
aos hub placement list <surface-ref>
aos hub placement show <surface-ref> <placement>
aos hub placement add <surface-ref> --binding <name> --prefix <prefix>
  [--kind complete|shard|archive]
  [--desired-state active|offline] [--read enabled|disabled]
  [--read-order <ordinal>] [--partition-rule <json>]
aos hub placement update <surface-ref> <placement>
  [--desired-state active|offline] [--read enabled|disabled]
  [--read-order <ordinal>] --if-version <version>
aos hub placement scan <surface-ref> <placement>
aos hub placement replicate <surface-ref> --from <placement> --to <placement>
aos hub placement repair <surface-ref> <placement> [--from <placement>]
aos hub placement promote <surface-ref> <placement>
aos hub placement promotion cancel <surface-ref>
aos hub placement drain <surface-ref> <placement>
aos hub placement drain cancel <surface-ref> <placement>
aos hub placement remove <surface-ref> <placement>

aos hub placement-equivalence list <surface-ref>
aos hub placement-equivalence confirm <placement-a> <placement-b>
aos hub placement-equivalence remove <equivalence>

aos hub placement-policy show <surface-ref>
aos hub placement-policy set <surface-ref>
  --kind ordered-failover --member <placement> ...
aos hub placement-policy test <surface-ref> --path <machine-path>
```

`placement add` never grants write authority or changes canonical routes by
itself. A newly created surface may remain safely read-only until initial
authority is created from a ready complete placement. `promote` returns an
impact plan covering writes, fencing/reconciliation, and mutable pointers. Its
plan records the authority version, expected current placement, and candidate
write-spec and binding-write revisions; apply rejects if any is stale or no
longer valid. Replicate/scan/repair/drain return operation ids. When the surface
has no authority, the same command plans guarded initial authority creation
rather than requiring an unrelated placement mutation.

Create defaults are `--kind complete`, `--desired-state active`,
`--read enabled`, and `--read-order 0`; archive defaults to read disabled and
rejects explicit read enablement. `--partition-rule` is required for `shard`
and rejected otherwise. `draining` is owned by `placement drain`, not generic
create/update. Binding, prefix, kind, and partition rule are immutable in
`placement update`; changing them uses add/replicate/promote/drain. Web forms
and API messages use the same defaults and update field set.

`placement promotion cancel` is plan/apply, not deletion of pending metadata.
It restores desired and observed authority to the previously observed writer
only after reconciliation proves the candidate is fenced and the old writer
is eligible. It advances the authority generation and rejects stale plans.

`placement list`, `placement show`, and `surface topology` report placement
kind and desired/observed state, plus derived role and effective read/write
eligibility. They report desired/observed authority placements and generations
and pinned binding-write revisions explicitly. Placement-level read posture is
not a claim about an arbitrary object: `surface explain --path` evaluates the
normative policy/shard/presence/publication predicate. No CLI flag sets role,
write enablement, or write order.

### Storage bindings, defaults, domains, gateways, and delivery routes

```text
aos hub storage-binding list [--org <org>]
aos hub storage-binding show <binding-ref>
aos hub storage-binding create --org <org> ...
aos hub storage-binding update <binding-ref> ...
aos hub storage-binding credential set <binding-ref> --purpose <purpose> ...
aos hub storage-binding credential rotate <binding-ref> --purpose <purpose>
aos hub storage-binding credential validate <binding-ref> [--purpose <purpose>]
aos hub storage-binding write-revision list <binding-ref>
aos hub storage-binding write-revision show <binding-ref> <revision>
aos hub storage-binding write-revision reconcile <binding-ref> <revision>
aos hub storage-binding delete <binding-ref>

aos hub org topology-defaults show <org>
aos hub org topology-defaults set <org>
  [--storage-binding <binding>] [--domain <domain>] [--gateway <gateway>]
aos hub org topology-defaults clear <org>
  [--storage-binding] [--domain] [--gateway]
aos hub instance topology-defaults show
aos hub instance topology-defaults set
  [--domain <domain>] [--gateway <gateway>]
aos hub instance topology-defaults clear [--domain] [--gateway]

aos hub domain list [--org <org>]
aos hub domain show <hostname>
aos hub domain add <hostname> [--org <org>]
aos hub domain update <hostname> ...
aos hub domain dns configure <hostname> ...
aos hub domain tls configure <hostname> ...
aos hub domain access configure <hostname> ...
aos hub domain verify <hostname>
aos hub domain status <hostname>
aos hub domain reconcile <hostname>
aos hub domain remove <hostname>

aos hub gateway list --binding <binding>
aos hub gateway show <gateway>
aos hub gateway add --binding <binding> --domain <hostname>
  [--base-path <path>] [--origin-path <path>] --access <policy>
aos hub gateway update <gateway> ...
aos hub gateway preview <gateway>
aos hub gateway reconcile <gateway>
aos hub gateway enable|disable <gateway>
aos hub gateway remove <gateway>

aos hub route list <surface-ref>
aos hub route add <surface-ref> --domain <hostname> [--base-path <path>]
  --mode hub-proxy|hub-redirect|direct --access <policy>
  (--placement <name> | --placement-policy <name>)
  [--serves git] [--serves cache] [--serves web]
aos hub route update <route> ...
aos hub route probe <route>
aos hub route explain <route> [--path <machine-path>]
aos hub route enable|disable|remove <route>
aos hub route canonical <route> --audience git|cache|web
```

`storage-binding create` is organization-only. The deployment-provisioned
binding is addressed as `instance:default`; supported endpoint/credential
maintenance uses update/credential commands, while create/delete/replacement is
rejected.

Repeated `--serves` flags build a capability set. Access-provider-specific
options use namespaced forms rather than a generic secret JSON argument. Secret
values are read from files/stdin or credential stores and are never echoed.

### Upstream registry mirror

```text
aos hub registry mirror show <registry>
aos hub registry mirror set <registry> --source <url> ...
aos hub registry mirror remove <registry>
aos hub registry mirror sync <registry>
```

Set/remove are plan/apply desired-state changes. Sync is an idempotent operation
trigger and returns an operation id.

### Consumer cache stack

```text
aos hub registry cache-stack show <registry>
aos hub registry cache-stack add <registry>
  (--cache <managed-cache> | --url <external-url>)
  [--before <entry>] [--mirror-with <entry>]
aos hub registry cache-stack move <registry> <entry> --before <entry>
aos hub registry cache-stack remove <registry> <entry>
aos hub registry cache-stack validate <registry>
```

Every mutating command drafts or updates a signed registry change request and
prints its `change_id`. It does not claim “advertised” until that change is
merged and re-indexed.

### Retention

```text
aos hub cache retention list <cache>
aos hub cache retention set <cache> --registry <registry>
  [--current-catalog]
  [--channel <name> ... | --all-channel-targets]
  [--recent-releases <count>]
  [--release <tag> ...]
  [--semver <requirement>]
  [--all-releases]
  [--removal-grace <duration>]
aos hub cache retention remove <cache> --registry <registry>
aos hub cache retention refresh <cache> [--registry <registry>]
aos hub cache retention explain <cache> <store-hash>
aos hub cache retention roots <cache> [--registry <registry>]
aos hub cache root create <cache> <store-hash> --reason <text>
  [--lease-until <time>]
aos hub cache root delete <cache> <root-id>
aos hub cache lease renew <cache> <root-id> --expires <time>
aos hub cache lease revoke <cache> <lease-id>
```

`set` replaces the named subscription after showing the selector diff and
estimated artifact/closure impact. It does not change cache-global TTL or
capacity settings.

Manual roots use stable ids for renewal/removal. `roots` and `explain` report
provenance alongside subscription-derived reasons. Lease renewal creates a new
history record; it does not rewrite the prior lease in place.

### Population and coverage

```text
aos hub cache population list <cache>
aos hub cache population set <cache> --registry <registry>
  --trigger release|manual|continuous
  --required|--best-effort
  [--placement-policy <policy>] [--validation-gate presence|integrity|none]
aos hub cache population run <cache> --registry <registry> [--release <tag>]
aos hub cache population remove <cache> --registry <registry>

aos hub cache coverage show <cache> [--registry <registry>]
aos hub cache coverage validate <cache> [--registry <registry>]
aos hub cache coverage repair <cache> [--registry <registry>]
```

### Garbage collection and eviction

```text
aos hub cache gc policy show|set <cache> ...
aos hub cache gc plan create <cache>
aos hub cache gc plan show <cache> <plan-id>
aos hub cache gc first-sweep plan-acknowledgement <cache> --gc-plan-id <id>
aos hub cache gc first-sweep acknowledge <cache>
  --ack-plan-id <id> --confirm-hash <hash> [--yes]
aos hub cache gc run <cache> --plan-id <id> --confirm-hash <hash> [--yes]
aos hub cache gc runs list <cache>
aos hub cache gc runs show <cache> <operation-id>
aos hub cache gc runs watch <cache> <operation-id>
aos hub cache gc jobs list <cache> <operation-id>
aos hub cache gc jobs show <cache> <job-id>
aos hub cache gc jobs retry <cache> <job-id>
aos hub cache gc jobs abandon <cache> <job-id> [--yes]

aos hub placement eviction plan <surface-ref> <placement>
aos hub placement eviction run <surface-ref> <placement> --plan-id <id> [--yes]
```

`gc run` is the logical namespace operation. Placement eviction is never
synonymous with it. `gc run` never recalculates candidates: input-version or
candidate drift rejects the whole apply. Retry is idempotent; abandon records
the expected leaked presence and requires its own reviewed confirmation.

First-sweep acknowledgement is a separate durable, audited plan/apply. Its
plan requires a currently valid immutable GC plan and binds that plan's
candidate/action manifest hash, safety gates, cache epoch, and policy version.
Apply records actor, GC plan, confirmation hash, and acknowledgement time and
advances the epoch, deliberately making the reviewed GC plan stale; the first
destructive run therefore requires a new plan. `--yes` suppresses only the
interactive prompt and never creates acknowledgement implicitly.

### Convenience porcelain

```text
aos hub cache integration list <cache> [--registry <registry>]
aos hub cache integration show <cache> --registry <registry>
aos hub cache integrate <cache> --registry <registry>
  [--use-for-clients]
  [--retain-current-catalog] [--retain-channel <name> ...]
  [--retain-recent-releases <count>] [--retain-release <tag> ...]
  [--retain-semver <requirement>] [--retain-all-releases]
  [--populate required|best-effort]
  [--population-trigger release|manual|continuous]
```

This command is preview-only porcelain. It produces up to three separately
labeled plan ids and prints the exact dedicated apply commands; it calls no
mutation API. This prevents a convenience command from inventing a
cross-resource transaction or ambiguous partial failure. Omitting all three
flags is an error.

### Breaking command replacement

The cutover removes the old variants; the final parser and help output contain
only the new model:

| Removed command | Replacement |
| --- | --- |
| `cache link --roots-packages` | `cache retention set --current-catalog` |
| `cache link --advertise` | `registry cache-stack add` |
| `cache unlink` | explicit cache-stack, retention, and/or population removal |
| `frontend ...` | `route ...` and `gateway ...` |
| `registry/cache change-storage` | placement add/replicate/promote/drain workflow |
| `cache gc-policy --keep-versions` | per-registry `cache retention set --recent-releases` |
| `cache pin` / `cache unpin` | stable `cache root` and immutable `cache lease` resources |
| `cache gc --dry-run` / immediate `cache gc` | `cache gc plan create` then `cache gc run --plan-id` |

There are no deprecated clap variants, translation branches, compatibility
warnings, or old JSON shapes in the final CLI. The preflight tool scans known
automation/configuration under operator-supplied paths and reports commands
that must be rewritten before cutover.

## Connect-JSON API contract

The cutover renames the complete public package from `aos.registry.v1` to
`aos.hub.v1`. Registries are no longer the only Hub resource, and doing the
namespace rename now avoids carrying that historical mismatch indefinitely.
All existing retained services and the new topology services move together;
native and Worker mount no `aos.registry.v1` routes after cutover. Generated
clients, fixtures, documentation, and `RegistryHubClient`-style names are
renamed to Hub terminology in the same change.

Services use typed messages; SQL JSON encodings described elsewhere in this
RFC are not exposed as opaque API JSON.

### Common messages

```text
SurfaceRef = oneof { registry_slug, cache_slug }
ResourceVersion = opaque monotonic/version token
PlanRef = { plan_id, expires_at, input_versions, effects, warnings }
OperationRef = { operation_id, kind, state, created_at }
```

Every mutating request accepts an idempotency key and optional expected
resource version. Conflicts return `ABORTED`/HTTP 409 with the current version.
Validation errors return typed field violations. Authorization uses the
existing IAM scopes and returns `PERMISSION_DENIED` without leaking private
resource existence outside the caller's scope.

List methods use cursor pagination and deterministic ordering. Responses carry
resource versions and stable ids. Secret-bearing write fields are write-only.

The public contract defines typed `Placement`, `PlacementObservation`,
`SurfaceWriteAuthority`, `PlacementAuthorityStatus`, `PlacementPolicy`,
`PlacementEquivalence`, `ObjectPresence`, `PlacementImpact`, `StorageBinding`,
`StorageBindingCapabilities`, `StorageBindingHealth`, `Domain`,
`DomainDesiredState`, `DomainObservedState`, `DnsConfiguration`,
`TlsConfiguration`, `DomainAccessConfiguration`, `StorageGateway`,
`GatewayRoutePreview`, `InstanceTopologyDefaults`,
`OrganizationTopologyDefaults`, `ManualRetentionRoot`, `RetentionLease`,
`RootReason`, `RetentionImpact`, `CacheGcGeneration`, `CacheGcPlan`,
`CacheGcCandidate`, `CacheGcPlacementAction`, and `CacheGcDeletionJob`
messages. Provider and storage credentials
are represented by purpose-scoped credential references, not opaque public JSON
or readable secret values.

GC operational state is not implied by public cache visibility. Authorized
cache readers may inspect summaries and retention explanations; actor identity
in root provenance requires `audit.read`. Retention configuration uses
`cache.retention.manage`; plan creation uses `cache.gc.plan`; logical apply,
retry, and abandonment use `cache.gc.execute`. A scoped service account may
hold `cache.lease.self` to create, renew, or revoke only its own lease without
receiving retention-policy or GC authority. Cross-organization subscriptions
require approval on both the registry source and cache destination. Instance
caches retain root `iam.admin` administration. Owner and Admin roles receive
the three cache-management verbs by default; lower roles receive no destructive
GC verb, and service-account lease authority is granted explicitly rather than
inferred from cache read access.

### TopologyService

```text
GetSurfaceTopology
ExplainSurfaceRequest
GetWriteAuthority
ReconcileWriteAuthority

ListPlacements
GetPlacement
PlanCreatePlacement / CreatePlacement
PlanUpdatePlacement / UpdatePlacement
PlanPromotePlacement / PromotePlacement
PlanCancelPlacementPromotion / CancelPlacementPromotion
PlanDrainPlacement / DrainPlacement
PlanCancelPlacementDrain / CancelPlacementDrain
PlanDeletePlacement / DeletePlacement
ScanPlacement
ReplicatePlacement
RepairPlacement
ListObjectPresence

GetPlacementPolicy
PlanSetPlacementPolicy / SetPlacementPolicy
TestPlacementPolicy

ListPlacementEquivalences
PlanConfirmPlacementEquivalence / ConfirmPlacementEquivalence
PlanDeletePlacementEquivalence / DeletePlacementEquivalence
```

Scan, replicate, repair, and drain return `OperationRef`. Placement plan
effects use `PlacementImpact` to include route eligibility, desired/observed
write-authority generations, replication bytes, fencing/reconciliation, and
signed-config impact without mutating any of those resources implicitly.

`CreatePlacement` contains binding, prefix, kind, initial desired state, desired
read selection/order, and a shard rule where required, with the CLI defaults
above applied by every interface. `UpdatePlacement` contains only desired
state, read selection/order, and expected resource version; binding, prefix,
kind, shard rule, authority, and observation are not generic update fields.
Response messages additionally contain observed state/completeness, coarse
desired read posture, and derived role/effective selection. Request-relative
effective reads use the complete predicate in `05-data-model-and-api.md`.
`SurfaceWriteAuthority` contains desired and observed placement references,
write-spec and binding-write revisions, generations, reconciliation
state/error, mode, and resource version. No request message accepts primary
role, `write_enabled`, or write order.

`PlanPromotePlacement` resolves and returns the expected authority version,
current observed placement, candidate write-spec and binding-write revisions,
candidate eligibility, and semantic effects. `PromotePlacement` requires the
plan id and those exact preconditions. Its core apply is one authority-row CAS
on every backend. If external reconciliation is required, it returns `OperationRef` and
`ReconcileWriteAuthority` may advance only the matching desired generation;
the method is idempotent and never rewrites a newer promotion.
`CancelPlacementPromotion` follows the same authority-row CAS and generation
rules after its fencing preconditions have reconciled; an operator can also
retry the associated operation without creating a new desired generation.

### StorageBindingService

```text
ListStorageBindings
GetStorageBinding
PlanCreateStorageBinding / CreateStorageBinding
PlanUpdateStorageBinding / UpdateStorageBinding
PlanSetStorageBindingCredential / SetStorageBindingCredential
PlanRotateStorageBindingCredential / RotateStorageBindingCredential
ValidateStorageBindingCredential
ListStorageBindingWriteRevisions
GetStorageBindingWriteRevision
ReconcileStorageBindingWriteRevision
PlanDeleteStorageBinding / DeleteStorageBinding

GetInstanceDefaultStorageBinding
GetInstanceTopologyDefaults
PlanSetInstanceTopologyDefaults / SetInstanceTopologyDefaults
GetOrganizationTopologyDefaults
PlanSetOrganizationTopologyDefaults / SetOrganizationTopologyDefaults
```

`StorageBindingRef` is a oneof of the instance default or an organization
binding reference. Capability and health records contain no credentials.
Changing defaults does not mutate existing placements, routes, or gateways.
A write-credential/capability rotation creates and validates an immutable
revision, returns an authority fan-out plan, and keeps the old revision usable
until all pins move. Revision responses expose credential references and
revision/capability fingerprints, never secret material. Equal capability
fingerprints do not suppress a revision whose credential-version reference
changed. Provider invalidation is observed separately and makes affected
authorities write-blocked.

### DomainService

```text
ListDomains
GetDomain
PlanCreateDomain / CreateDomain
PlanUpdateDomain / UpdateDomain
PlanConfigureDomainDns / ConfigureDomainDns
PlanConfigureDomainTls / ConfigureDomainTls
PlanConfigureDomainAccess / ConfigureDomainAccess
GetDomainVerification
GetDomainStatus
VerifyDomain
ReconcileDomain
PlanDeleteDomain / DeleteDomain

ListStorageGateways
GetStorageGateway
PlanCreateStorageGateway / CreateStorageGateway
PlanUpdateStorageGateway / UpdateStorageGateway
PreviewGatewayRoutes
ReconcileStorageGateway
PlanEnableStorageGateway / EnableStorageGateway
PlanDisableStorageGateway / DisableStorageGateway
PlanDeleteStorageGateway / DeleteStorageGateway
```

Domain responses separately report desired DNS/TLS/access configuration and
observed provider/probe state.

### RouteService

```text
ListRoutes
GetRoute
PlanCreateRoute / CreateRoute
PlanUpdateRoute / UpdateRoute
PlanEnableRoute / EnableRoute
PlanDisableRoute / DisableRoute
PlanDeleteRoute / DeleteRoute
PlanSetCanonicalRoute / SetCanonicalRoute
ProbeRoute
ExplainRoute
```

Route messages use typed `DeliveryMode`, `AccessPolicy`, `RouteCapabilities`,
and `RouteTarget` fields. `ExplainRoute` includes authorization and selection
decisions but redacts credentials and private-resource details unavailable to
the caller.

### RegistryMirrorService

```text
GetRegistryMirror
PlanSetRegistryMirror / SetRegistryMirror
PlanDeleteRegistryMirror / DeleteRegistryMirror
SyncRegistryMirror
```

The mirror source is registry content acquisition, not a delivery route.
`SyncRegistryMirror` returns `OperationRef`.

### CacheIntegrationService

```text
ListRegistryCacheIntegrations
ListCacheRegistryIntegrations
GetCacheRegistryIntegration
PreviewCacheIntegration

GetConsumerCacheStack
ValidateConsumerCacheStack
PlanConsumerCacheChange
CreateConsumerCacheChangeset

GetRetentionSubscription
ListRetentionSubscriptions
PlanSetRetentionSubscription / SetRetentionSubscription
PlanDeleteRetentionSubscription / DeleteRetentionSubscription
RefreshRetentionSubscription
ExplainRetention

GetPopulationTarget
ListPopulationTargets
PlanSetPopulationTarget / SetPopulationTarget
PlanDeletePopulationTarget / DeletePopulationTarget
RunPopulation

GetCoverage
RunCoverageValidation
RunCoverageRepair
```

Consumer publication responses return `change_id` and change-set state.
Retention selectors are a typed union. Publication, retention, and population
methods never call one another implicitly. `PreviewCacheIntegration` returns
up to three independent `PlanRef` values and has no combined apply method.

### BinaryCacheService

```text
GetCacheGcPolicy
PlanSetCacheGcPolicy / SetCacheGcPolicy
PlanCacheGc
RunCacheGc(plan_id)
PlanAcknowledgeCacheGcFirstSweep / AcknowledgeCacheGcFirstSweep
GetCacheGcPlan
GetCacheGcRun
ListCacheGcRuns
GetCacheGcDeletionJob
ListCacheGcDeletionJobs
RetryCacheGcDeletionJob
PlanAbandonCacheGcDeletionJob / AbandonCacheGcDeletionJob
ListRootReasons
GetRetentionRoot
ListRetentionRoots
PlanCreateManualRetentionRoot / CreateManualRetentionRoot
PlanRenewRetentionLease / RenewRetentionLease
PlanRevokeRetentionLease / RevokeRetentionLease
PlanDeleteManualRetentionRoot / DeleteManualRetentionRoot
RefreshAllRetention

PlanPlacementEviction
RunPlacementEviction(plan_id)
```

The service also owns binary-cache CRUD and object inspection under explicit
`BinaryCache` message names. Bare `Cache` protobuf records from the old package
are not carried into `aos.hub.v1`.

Plans are immutable snapshots with expiry and input versions. `RunCacheGc`
rejects a stale or mismatched plan rather than recomputing a more destructive
set at apply time. The plan contains a complete mark-generation reference,
root/object/inventory/policy/topology versions, coverage failures, and typed
candidate and placement-action manifests. Apply returns `OperationRef` after
one guarded logical-tombstone transition; physical workers consume only the
recorded actions.

### OperationsService

```text
GetOperation
ListOperations
WatchOperation
CancelOperation
RetryOperation
```

Operations expose progress, item/byte counts, current phase, warnings, and
terminal error details. Cancellation is best-effort and leaves topology in a
documented resumable state.

### Events and audit

Long operations and state transitions emit existing audit/webhook records with
stable resource ids:

```text
placement.scan.completed
placement.replication.completed
placement.promotion.requested
placement.promotion.completed
placement.promotion.failed
placement.drained
route.probe.changed
route.canonical.changed
retention.subscription.plan.created
retention.subscription.applied
retention.subscription.deleted
retention.refresh.started
retention.refresh.failed
retention.refresh.completed
retention.root.plan.created
retention.root.created
retention.root.deleted
retention.lease.issued
retention.lease.renewed
retention.lease.revoked
retention.lease.expired
population.completed
coverage.changed
cache.gc.policy.plan.created
cache.gc.policy.updated
cache.gc.mark.started
cache.gc.mark.completed
cache.gc.mark.failed
cache.gc.plan.created
cache.gc.plan.stale
cache.gc.plan.applied
cache.gc.first_sweep.acknowledged
cache.gc.started
cache.gc.logical_tombstones.created
cache.gc.job.started
cache.gc.job.succeeded
cache.gc.job.failed
cache.gc.job.blocked
cache.gc.job.retried
cache.gc.job.abandoned
cache.gc.completed
cache.gc.failed
placement.eviction.completed
```

Web UI and CLI operation views consume the same event/status model. Events
distinguish estimated, confirmed reclaimed, and administratively leaked bytes.
Audit payloads include actor, scope, plan/operation ids, source/input versions,
and result but exclude credentials and high-cardinality object data.

## Interface acceptance criteria

- Every Web UI mutation maps to one documented API plan/apply pair or one
  documented immediate method.
- Every new `aos hub` command is a thin client of that API and has a `--json`
  golden test.
- Web UI, CLI, and API use the same names for placements, routes, consumer
  cache stacks, retention subscriptions, population targets, and root reasons.
- Web UI, CLI, API, native routing, and Worker routing derive the same primary,
  promotion-pending, and effective-write state from one authority projection;
  mutation inputs contain none of those derived fields.
- Native and Worker API fixtures produce identical status codes and response
  bodies for authorization and validation cases.
- Old commands, Web UI paths, protobuf descriptors, and Connect-JSON routes are
  absent from the final binaries and routing tables.
- Repository-wide checks reject `aos.registry.v1`, `LinkCache`, legacy
  frontend handlers, old ambiguous service names, and the removed combined CLI
  variants outside historical RFC text and the ephemeral cutover artifact.
- CLI help examples, Web UI help text, and API docs are generated or checked
  against the same typed enums wherever practical.
