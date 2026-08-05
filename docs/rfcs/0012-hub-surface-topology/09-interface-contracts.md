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
   token; `--yes` is valid only while applying a plan supplied by id.
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
| DNS domains | `domain` | `DomainService` |
| Network boundaries | `network-boundary` | `NetworkBoundaryService` |
| Delivery endpoints | `endpoint` | `DeliveryService` endpoint methods |
| Storage gateways | `gateway` | `DeliveryService` gateway methods |
| Delivery | `route` | `RouteService` |
| Consumer cache stack | `registry cache-stack` | `CacheIntegrationService` consumer methods |
| Retention subscriptions | `cache retention` | `CacheIntegrationService` retention methods |
| Manual roots and leases | `cache root`, `cache lease` | `BinaryCacheService` retention-root methods |
| Population and coverage | `cache population`, `cache coverage` | `CacheIntegrationService` population/coverage methods |
| Logical GC and placement eviction | `cache gc`, `placement eviction` | `BinaryCacheService` |
| Long-running work | `operation` | `OperationService` |

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
| Registry tokens | `registry token` | `IdentityService` list plus plan/apply issue/retire methods; rotation is explicit issue-then-retire |
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
/-/org/{org}/identity-and-access
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
/-/org/{org}/network-boundaries
/-/org/{org}/network-boundaries/new
/-/org/{org}/delivery-endpoints
/-/org/{org}/delivery-endpoints/new
/-/org/{org}/storage-gateways
/-/org/{org}/storage-gateways/new
/-/org/{org}/topology-defaults
/-/org/{org}/members
/-/org/{org}/members/invitations/new
/-/org/{org}/sso
/-/org/{org}/signing-keys
/-/org/{org}/signing-keys/new
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
/-/instance/domains/new
/-/instance/network-boundaries
/-/instance/network-boundaries/new
/-/instance/delivery-endpoints
/-/instance/delivery-endpoints/new
/-/instance/storage-gateways
/-/instance/storage-gateways/new
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
| organization `/keys` | `/signing-keys` |
| organization `/audit` | `/audit-log` |
| organization `/settings` redirect | deleted; use the organization root Overview |
| organization `/bindings/{id}` | `/storage-bindings/{id}` |
| organization binding frontend section | `/storage-gateways` and explicit surface delivery routes |
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
Actions are add, edit, replace, probe, explain, enable, disable, make canonical,
and remove. Direct gateway-backed routes display their gateway and placement.
They are user-owned resources: gateway reconciliation never creates or edits
them, and gateway preview only drafts explicit RouteService plans.

Changing endpoint, route access provider, surface visibility, placement
policy, or canonical status opens an impact review showing affected setup
snippets, signed cache entries, routes, and client compatibility.

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

The cutover CLI is resource-scoped. Organization-owned project, audit,
identity, and webhook commands live below `aos hub org`; registry-owned
package, channel, publication, configuration, mirror, and consumer-cache-stack
commands live below `aos hub registry`. The former top-level spellings are
removed rather than retained as aliases. Cross-cutting topology resources such
as placements, routes, domains, and storage bindings remain top-level families
because their typed references can span more than one owner or surface.

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
--idempotency-key <k>  stable key reused for every retry of plan or apply
--if-version <value>   optimistic-concurrency precondition
--yes                  non-interactive confirmation for a supplied plan id
```

List commands support pagination and `--json`. Long-running commands print the
operation id and support `--wait`, `--timeout`, and `operation watch`.
External probes and reconcile/refresh/scan triggers are effects: callers first
create an immutable plan, then apply it to receive an operation id. Controller
observations use separate authenticated and generation-fenced controller RPCs.

Every successful `--json` response is wrapped as
`{"schema_version":"aos.hub.cli/v1","kind":"...","data":...}`. The
stable, snake-case `kind` discriminator identifies the command result. The committed
[`hub-cli-json-schema-v1.json`](hub-cli-json-schema-v1.json) defines the stable
envelope, while [`hub-api-manifest-v1.json`](hub-api-manifest-v1.json) records
the cutover command families, service ownership, pagination convention, and
plan/apply fields. Command-specific data preserves the public API response
shape with recursively normalized `snake_case` keys. Version 1 is closed:
unknown envelope and command-specific `data` fields are rejected. Any field
addition or incompatible shape change requires a new schema version and an
explicit client upgrade.

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
aos hub placement add <surface-ref> <placement> --binding <name> --prefix <prefix>
  [--kind complete|shard|archive]
  [--desired-state active|offline] [--read enabled|disabled]
  [--read-order <ordinal>] [--hash-range <start>-<end>]
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
aos hub placement-equivalence confirm <surface-ref> <placement-a> <placement-b>
aos hub placement-equivalence remove <equivalence>

aos hub placement-policy list <surface-ref>
aos hub placement-policy show <surface-ref> <policy> [--revision <revision>]
aos hub placement-policy create <surface-ref> <policy>
  --kind ordered-failover --member <placement> ...
aos hub placement-policy revise <surface-ref> <policy>
  --kind local-then-remote --local-boundary <boundary>@<revision>
  --local <placement> ... --remote <placement> ...
  [--allow-remote-fallback]
aos hub placement-policy revise <surface-ref> <policy>
  --kind hash-partition
  --range <start>-<end>=<placement>[,<replica>...] ...
  [--complete-fallback <placement> ...]
aos hub placement-policy test <surface-ref> <policy> --revision <revision>
  --object <canonical-object-ref> [--access-class local|remote]
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
rejects explicit read enablement. `--hash-range` is required for `shard` and
rejected otherwise; its bounds are the typed half-open `HashRangeV1` bucket
interval `[start, end)` with `0 <= start < end <= 65536`, not JSON. Bounds use
unsigned 32-bit integers. `draining` is owned by `placement drain`, not generic
create/update. Binding, prefix, kind, and hash range are immutable in
`placement update`; changing them uses add/replicate/promote/drain. Web forms
and API messages use the same defaults and update field set.

Local-then-remote policy messages pin a typed `NetworkBoundaryRevisionRef`.
Plans display the stable boundary identity, exact revision, verification state,
and digest input; apply rejects a stale or unverified revision. Published
policy meaning never follows a boundary's moving desired pointer.

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

Placement-policy create/revise always produces a new immutable revision and
prints its content digest. Existing routes and population targets remain pinned
until separately planned updates move them. Test resolves a canonical logical
object to its stored partition key and prints the normative digest, bucket,
replica group, fallback decisions, and typed failure contract.

### Storage bindings, defaults, domains, endpoints, gateways, and routes

```text
aos hub org update <org> --display-name <name>
aos hub org webhook list <org>
aos hub org webhook create <org> --url <https-url>
  [--event <event> ...] --secret-version-ref <provider-ref>
  --credential-fingerprint <sha256-hex>
aos hub org webhook delete <id> --if-version <resource-version>

aos hub storage-binding list [--org <org>]
aos hub storage-binding show <binding-ref>
aos hub storage-binding create --org <org> --name <name>
  --kind local-fs --root <absolute-path>
aos hub storage-binding create --org <org> --name <name>
  --kind s3|r2 --bucket <bucket> [--prefix <object-prefix>]
  --endpoint <https-origin> --region <signing-region>
  --access public|private
aos hub storage-binding credential set <binding-ref>
  --purpose read|write|delete|list|presign --secret-version-ref <provider-ref>
  --credential-fingerprint <sha256-hex>
aos hub storage-binding credential rotate <binding-ref>
  --purpose read|write|delete|list|presign
  --from-generation <generation> --secret-version-ref <provider-ref>
  --credential-fingerprint <sha256-hex>
aos hub storage-binding credential validate <binding-ref>
  [--purpose read|write|delete|list|presign]
aos hub storage-binding write-revision list <binding-ref>
  [--page-size <count>] [--page-token <token>]
aos hub storage-binding write-revision show <binding-ref> <revision>
aos hub storage-binding write-revision reconcile <binding-ref> <revision>
aos hub storage-binding grant <binding-ref> --consumer-scope <scope>
aos hub storage-binding revoke <binding-ref> --consumer-scope <scope>
aos hub storage-binding delete <binding-ref>

aos hub org topology-defaults show <org>
aos hub org topology-defaults set <org>
  [--storage-binding <binding>] [--domain <domain>]
  [--endpoint <endpoint>] [--gateway <gateway>]
aos hub org topology-defaults clear <org>
  [--storage-binding] [--domain] [--endpoint] [--gateway]
aos hub instance topology-defaults show
aos hub instance topology-defaults set
  [--domain <domain>] [--endpoint <endpoint>] [--gateway <gateway>]
aos hub instance topology-defaults clear
  [--domain] [--endpoint] [--gateway]

aos hub domain list [--org <org>]
aos hub domain show <hostname>
aos hub domain add <hostname> [--org <org>]
aos hub domain dns configure <hostname>
  --mode hub-managed --provider <provider> --zone-id <provider-zone-id>
  [--record-ttl <seconds>]
aos hub domain dns configure <hostname>
  --mode external --expected-target <canonical-dns-name>
aos hub domain certificate configure <hostname> --mode hub-managed
aos hub domain certificate configure <hostname>
  --mode external --certificate-ref <secret-ref>
aos hub domain verify <hostname>
aos hub domain status <hostname>
aos hub domain reconcile <hostname>
aos hub domain remove <hostname>

aos hub network-boundary list [--org <org>]
aos hub network-boundary show <boundary>
aos hub network-boundary add <name> --kind vpn|vpc|tunnel [--org <org>]
  --provider <provider> --provider-account <account-or-tenant>
  --resource-id <globally-qualified-provider-resource-id>
aos hub network-boundary add <name> --kind source-allowlist [--org <org>]
  --allowlist-id <stable-owner-scoped-logical-id>
aos hub network-boundary add <name> --kind trusted-ingress [--org <org>]
  --provider <provider> --provider-account <account-or-tenant>
  --listener-id <globally-qualified-provider-listener-id>
aos hub network-boundary revise <boundary>
  [--protected-transport required|not-required]
  [--trusted-ingress none]
  [--trusted-ingress mtls --ca-secret-ref <ref> [--client-san <name> ...]]
  [--trusted-ingress signed-assertion --issuer <issuer> --audience <audience>
    --verification-key-secret-ref <ref>]
  [--cidr <canonical-cidr> [--cidr <canonical-cidr> ...] | --clear-cidrs]
  [--probe-location <location-ref> | --clear-probe-location]
aos hub network-boundary grant <boundary> --consumer-scope <scope>
aos hub network-boundary revoke <boundary> --consumer-scope <scope>
  [--pin-resolution-file <json-file>]
aos hub network-boundary revision list <boundary>
  [--page-size <count>] [--page-token <token>]
aos hub network-boundary revision show <boundary>@<revision>
aos hub network-boundary revision probe <boundary>@<revision>
aos hub network-boundary revision reconcile <boundary>@<revision>
aos hub network-boundary revision activate <boundary>@<revision>
  --mode overlap|coordinated --default-for-new-plans yes|no
  [--pin-resolution-file <json-file>]
aos hub network-boundary revision retire <boundary>@<revision>
aos hub network-boundary status <boundary>
aos hub network-boundary remove <boundary>

aos hub endpoint list [--org <org>]
aos hub endpoint show <endpoint>
aos hub endpoint add <https://host[:port]> [--org <org>]
  --network-boundary <boundary> --ingress hub|external|layer7
aos hub endpoint add <http://host[:port]> [--org <org>]
  --acknowledge-cleartext --network-boundary <boundary>
  --ingress hub|external|layer7
aos hub endpoint update <endpoint>
  [--ingress hub|external|layer7]
  [--boundary-revision <revision>]
  [--listener-provider hub-native|hub-worker|external|layer7]
  [--listener-resource-id <stable-provider-id>]
  [--tls-provider hub-managed|external --certificate-ref <ref>]
  [--probe-location <location-ref> | --clear-probe-location]
aos hub endpoint grant <endpoint> --consumer-scope <scope>
aos hub endpoint revoke <endpoint> --consumer-scope <scope>
aos hub endpoint status|probe|reconcile <endpoint>
aos hub endpoint remove <endpoint>

aos hub gateway list --binding <binding>
aos hub gateway show <gateway>
aos hub gateway add --binding <binding> --endpoint <endpoint>
  [--client-base-path <path>] [--origin-prefix <path>]
  --access public|external-provider|private-network
  [<access-policy-options>]
aos hub gateway update <gateway>
  [--endpoint-generation <generation>]
  [--client-base-path <path>] [--origin-prefix <path>]
  [--access public|external-provider|private-network
    [<access-policy-options>]]
aos hub gateway grant <gateway>@<generation> --consumer-scope <scope>
aos hub gateway revoke <gateway>@<generation> --consumer-scope <scope>
aos hub gateway preview <gateway>
aos hub gateway reconcile <gateway>
aos hub gateway enable|disable <gateway>
aos hub gateway remove <gateway>

aos hub route list <surface-ref>
aos hub route add <surface-ref> --endpoint <endpoint> [--base-path <path>]
  --mode hub-proxy|hub-redirect
  --access public|hub-auth|external-provider|private-network
  [<access-policy-options>]
  (--placement <complete> | --placement-policy <name>@<revision>)
  [--serves git] [--serves cache] [--serves web]
aos hub route add <surface-ref> --endpoint <endpoint>
  --mode direct --placement <complete>
  --gateway <gateway>@<generation>
  [--serves git] [--serves cache] [--serves web]
aos hub route update <route>
  [--mode hub-proxy|hub-redirect|direct]
  [--endpoint-generation <generation>]
  [--placement <complete> | --placement-policy <name>@<revision>]
  [--gateway <gateway>@<generation>]
  [--access public|hub-auth|external-provider|private-network
    [<access-policy-options>]]
  [--serves git] [--serves cache] [--serves web]
aos hub route replace <route> --endpoint <endpoint> [--base-path <path>]
  --mode hub-proxy|hub-redirect
  --access public|hub-auth|external-provider|private-network
  [<access-policy-options>]
  (--placement <complete> | --placement-policy <name>@<revision>)
  [--serves git] [--serves cache] [--serves web]
aos hub route replace <route> --endpoint <endpoint>
  --mode direct --placement <complete>
  --gateway <gateway>@<generation>
  [--serves git] [--serves cache] [--serves web]
aos hub route probe <route>
aos hub route explain <route> [--path <machine-path>]
aos hub route enable|disable|remove <route>
aos hub route canonical <route> --audience git|cache|web
```

Endpoint and gateway refs resolve to exact immutable generations in every
plan; apply rejects a changed desired generation. A direct route has no
independent base-path option: its path is derived as
`join_segments(gateway.client_base_path, placement.prefix)` and shown in the
plan. Endpoint origin/realm fields are absent from `endpoint update`; replacing
them uses create plus the affected route/gateway move plan.

Omitted Hub-route `--base-path`, gateway `--client-base-path`, and gateway
`--origin-prefix` each default to canonical `/` in CLI, API, and Web forms.
Plans always print the resolved values before collision checks or direct-route
composition; omission and explicit `/` are byte-for-byte equivalent fixtures.
Topology-default endpoint and gateway refs similarly resolve to exact granted
desired generations in the plan. Apply rejects pointer or grant changes, and a
later endpoint/gateway revision does not silently retarget the default.

Boundary create accepts exactly one typed identity variant. `public` has no
identity options and is the deployment-provisioned, instance-owned,
non-deletable `instance:public` singleton; create/remove reject that kind.
Update also rejects it; probe/reconcile refresh only its fixed revision-1
observation. Endpoint plans show and pin `instance:public@1` explicitly.
VPN/VPC/tunnel and trusted-ingress identities use provider, provider
account/tenant, plus a globally qualified resource/listener id; source
allowlists use an owner-scoped stable logical id. Sorted canonical CIDR membership is revisioned
configuration. The service derives the immutable identity fingerprint from
that typed value and never accepts a digest. Trusted verification material is
passed by secret reference and responses expose only redacted references.
Every endpoint create requires an exact boundary reference and owner-scope
grant and an explicit ingress kind; there is no implicit public-boundary or
ingress selection in CLI, API, or Web.

Revision/update commands use patch semantics for scalar fields: omission keeps
the current value, and at least one field must be supplied. Repeated collection
flags replace the complete normalized collection; their paired `--clear-*`
flag is the only way to select an empty/null value and is mutually exclusive
with the repeated setter. In particular, boundary `--cidr` replaces all CIDRs,
`--client-san` replaces all SANs, route `--serves` replaces the complete
non-empty capability set, and probe-location clear is explicit. A trusted
ingress kind change supplies its complete required kind-specific fields.

`<access-policy-options>` is the kind-specific suffix in the following closed,
kind-discriminated grammar (the command's displayed `--access` flag is not
repeated):

```text
--access public
--access hub-auth
  [--hub-principal <principal-kind>:<principal-name> ...]
  [--hub-client-class <client-class> ...]
--access external-provider
  --external-provider-kind <provider-kind>
  --external-provider-resource-id <stable-provider-resource-id>
  --external-provider-revision <observed-provider-revision>
  --external-client-mechanism <mechanism>=<verification-secret-ref> ...
  [--external-client-class <client-class> ...]
--access private-network
  --access-boundary <boundary>@<revision>
```

`mechanism` is one of `bearer-token`, `signed-cookie`, `signed-header`, or
`mtls`. Repeating principal, client-class, and mechanism flags forms a sorted,
deduplicated set; an empty `hub-auth` set means any authenticated principal.
`public` rejects every kind-specific field. `hub-auth` rejects external and
boundary fields. `external-provider` requires at least one mechanism and
rejects Hub and boundary fields. `private-network` rejects Hub and external
fields. Gateways reject `hub-auth`. A direct route accepts no access-policy
input: it copies the selected immutable gateway generation's complete policy
and digest and displays both in the plan. Updating a direct route to a different
gateway generation derives the replacement policy the same way. Hub-route
access flags are rejected whenever the final mode is direct.

`storage-binding create` is organization-only. The deployment-provisioned
binding is addressed as `instance:default`; supported endpoint/credential
maintenance uses update/credential commands, while create/delete/replacement is
rejected.

Repeated `--serves` flags build a capability set. Access-provider-specific
options use namespaced forms rather than a generic secret JSON argument. Secret
values are read from files/stdin or credential stores and are never echoed.

Endpoint input is parsed into typed scheme, DNS/IPv4/IPv6 host, effective port,
and network boundary; the URL string is never stored. IPv6 zone ids, userinfo,
query, and fragment are rejected. Route and gateway commands reference an
existing endpoint and never create one implicitly. Default ports are omitted
only when rendering the canonical origin.

### Binary cache definition

```text
aos hub cache list [--org <org>]
aos hub cache show <cache>
aos hub cache create <cache> --name <name>
  --visibility public|internal|private
  [--nix-priority <priority>] [--compression zstd|xz|none]
  [--mass-query enabled|disabled]
aos hub cache update <cache>
  [--name <name>] [--visibility public|internal|private]
  [--nix-priority <priority>] [--compression zstd|xz|none]
  [--mass-query enabled|disabled]
aos hub cache delete <cache>
```

Create, update, and delete use the same plan/apply contract as every other
control-plane mutation. The cache definition owns stable identity, access
posture, and the Nix protocol defaults `nix_priority`, `compression`, and
`want_mass_query`; placements, delivery, consumer publication, retention,
population, and garbage collection remain separate command families below.
List and show render `BinaryCache` resources even though the user-facing CLI
noun remains the concise `cache`.

### Upstream registry mirror

```text
aos hub registry mirror show <registry>
aos hub registry mirror set <registry> --source <https-url>
  [--refspec <git-refspec>] [--auth-secret-ref <secret-ref>]
  [--interval <duration>]
  [--signature-policy required|optional|disabled]
aos hub registry mirror remove <registry>
aos hub registry mirror sync <registry> [--if-version <version>]
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
  [--recent-releases <count> [--recent-include-prereleases]]
  [--release <tag> ...]
  [--semver <requirement> [--semver-include-prereleases]]
  [--all-releases]
  [--removal-grace <duration>]
aos hub cache retention remove <cache> --registry <registry>
aos hub cache retention refresh <cache> [--registry <registry>]
  [--if-version <version>]
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
aos hub cache gc policy show <cache>
aos hub cache gc policy set <cache>
  --unreferenced-grace <duration>
  [--soft-max-bytes <bytes> | --clear-soft-max-bytes]
  [--soft-max-objects <count> | --clear-soft-max-objects]
  --schedule <cron-expression> --deletion-concurrency <count>
  --retry-initial <duration> --retry-max <duration>
  --retry-max-attempts <count> --tombstone-retention <duration>
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
aos hub cache gc jobs retry <cache> <job-id> [--if-version <version>]
aos hub cache gc jobs abandon <cache> <job-id>
  [--if-version <version>]
aos hub cache gc jobs abandon <cache> <job-id>
  --plan-id <id> --confirm-hash <hash> [--yes]

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
  [--retain-recent-releases <count> [--recent-include-prereleases]]
  [--retain-release <tag> ...]
  [--retain-semver <requirement> [--semver-include-prereleases]]
  [--retain-all-releases]
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
`PlacementPolicyRevision`, `PlacementPolicyReplicaGroup`, `HashRangeV1`,
`AccessClass`, `PolicyFailureContract`, `PlacementEquivalence`,
`ObjectPresence`, `PlacementImpact`, `StorageBinding`,
`StorageBindingCapabilities`, `StorageBindingHealth`, `Domain`,
`DomainDesiredState`, `DomainObservedState`, `DnsConfiguration`,
`CertificateConfiguration`, `DeliveryEndpoint`, `EndpointHost`,
`EndpointDesiredState`, `EndpointObservedState`, `NetworkBoundary`,
`NetworkBoundaryIdentity`, `NetworkBoundaryRevision`,
`NetworkBoundaryRevisionRef`, `NetworkBoundaryRevisionLifecycle`,
`NetworkBoundaryObservation`, `TrustedIngressConfiguration`,
`DeliveryAccessPolicy`, `ExternalProviderPolicy`, `TlsConfiguration`,
`ConsumerScopeGrant`, `StorageGateway`, `PlacementDeliveryManifest`,
`DeliveryRoute`, `DeliveryRouteTarget`, `RouteCapabilities`, `CanonicalRoute`,
`DeliveryRouteObservation`, `DirectDeliveryRouteEvidence`,
`DeliveryRouteAccessObservation`,
`GatewayRoutePreview`, `InstanceTopologyDefaults`,
`OrganizationTopologyDefaults`, `ManualRetentionRoot`, `RetentionLease`,
`RootReason`, `RetentionImpact`, `CacheGcGeneration`, `CacheGcPlan`,
`CacheGcCandidate`, `CacheGcPlacementAction`, and `CacheGcDeletionJob`
messages. Provider and storage credentials
are represented by purpose-scoped credential references, not opaque public JSON
or readable secret values.

`ConsumerScopeGrant` is the one shared grant wire type: resource kind and
stable id, optional exact generation (required for endpoint/gateway and absent
for binding/boundary), consumer scope, grant generation/kind, `active|revoked`
state, grant and optional revoke actor/timestamps, live-pin count/impact
summary, and resource version. Closed validation rejects a resource generation
on stable-grant resources or its omission on revision-grant resources. JSON
goldens cover initial active, blocked revoke with pins, revoked tombstone, and
later active regrant with an incremented grant generation.

Every coordinated boundary activation and every revocation of a consumable
grant carries `repeated PinResolution pin_resolutions`. A plan accepts exactly
one resolution for every live pin id and rejects missing, duplicate, or extra
entries. The source pin tuple and source target resource version are sealed by
the plan. `move_endpoint` names another immutable generation of the same
endpoint on the target boundary revision; `replace_route` names an enabled
replacement route plus its exact current generation, configuration digest, and
resource version; `release` names the exact source resource version to disable
or delete. A route replacement uses a different stable route id: one route has
only one current configuration head, so the old pinned generation and a newer
replacement generation cannot both be current under the same stable id.

Apply creates a parent operation and one durable child job per pin atomically.
The target boundary remains `activating` and therefore non-servable while jobs
run. Each child executes its source/target CAS and records success only after
the exact source pin is absent and the target postcondition still matches.
Only the final checked transaction may activate the target revision, move the
default, fence old revisions, complete the operation, and emit the activation
event. Grant revocation follows the same acknowledgement rule: it cannot
transition the grant tombstone to `revoked` before every sealed pin-resolution
job succeeds. A late unplanned pin fails finalization and requires a new plan.

The CLI consumes a strict, versioned document rather than a raw protobuf
array. Unknown top-level fields, unsupported versions, empty pin ids, duplicate
pin ids, missing actions, and malformed nested protobuf JSON fail locally;
source/target staleness still fails authoritatively during server planning.

```json
{
  "schemaVersion": "aos.hub.pin-resolutions.v1",
  "resolutions": [
    {
      "pinId": "boundary-pin:example",
      "release": { "expectedSourceResourceVersion": "12" }
    }
  ]
}
```

Plan responses that discover live pins include the same schema version and a
resolution-document scaffold containing every exact source pin with an empty
action. Web and CLI edit or export that scaffold; neither reconstructs pin ids
from human-readable effect strings.

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

### OrganizationService

```text
ListOrganizations
GetOrganization
PlanCreateOrganization / CreateOrganization
PlanUpdateOrganization / UpdateOrganization
PlanDeleteOrganization / DeleteOrganization
```

Organization slug, stable id, and owner scope are immutable after creation.
Update owns display name and other non-identity profile metadata only; member,
SSO, infrastructure, and deletion mutations remain on their dedicated owners.
The stable id is also the canonical `org:<incarnation-id>` consumer scope. It
is generated once, never derived from the mutable human-facing namespace, and
is never reused after hard deletion. Grant APIs reject organization scopes
that do not identify a live organization. Hard purge atomically releases every
binding, boundary, endpoint, and gateway pin, appends revocation events for
every active grant, removes all grant rows for the old incarnation, and only
then completes. Recreating the same slug therefore creates unrelated authority.

### TopologyService

```text
GetSurfaceTopology
ExplainSurfaceRequest
GetWriteAuthority

ListPlacements
GetPlacement
PlanCreatePlacement / CreatePlacement
PlanUpdatePlacement / UpdatePlacement
PlanPromotePlacement / PromotePlacement
PlanCancelPlacementPromotion / CancelPlacementPromotion
PlanDrainPlacement / DrainPlacement
PlanCancelPlacementDrain / CancelPlacementDrain
PlanDeletePlacement / DeletePlacement
PlanScanPlacement / ScanPlacement
PlanReplicatePlacement / ReplicatePlacement
PlanRepairPlacement / RepairPlacement
ListObjectPresence

ListPlacementPolicies
GetPlacementPolicy
ListPlacementPolicyRevisions
GetPlacementPolicyRevision
PlanCreatePlacementPolicy / CreatePlacementPolicy
PlanRevisePlacementPolicy / RevisePlacementPolicy
TestPlacementPolicyRevision

ListPlacementEquivalences
PlanConfirmPlacementEquivalence / ConfirmPlacementEquivalence
PlanDeletePlacementEquivalence / DeletePlacementEquivalence
```

Scan, replicate, repair, and drain return `OperationRef`. Placement plan
effects use `PlacementImpact` to include route eligibility, desired/observed
write-authority generations, replication bytes, fencing/reconciliation, and
signed-config impact without mutating any of those resources implicitly.

Placement-policy create/revise accepts typed ordered groups,
local-boundary/access-class groups, or `HashRangeV1` ranges and complete
fallbacks. Revisions are immutable and return a content digest plus fixed
selector-vector results. Routes and population targets reference a revision id,
not the mutable current-revision pointer. There is no Set method that edits
members beneath a live route.

`HashRangeV1` conformance repeats the normative selector vectors used by every
generated client and runtime:

| 32-byte `partition_key` | selector digest | bucket |
| --- | --- | ---: |
| all `00` | `c84df95b5544ccded87876f4a24fc63445f48af7dcddac6af26f2a7a7742abda` | 51277 |
| bytes `00` through `1f` | `5266775ea5f5297e717cfd66abe696828282822c7793ad0d5c5ab0b0fc5f0cbc` | 21094 |
| all `ff` | `5de6f7beb4067b866bc9835b476fd57f583f208dd247679ef8098bfd65aa4b01` | 24038 |

`CreatePlacement` contains binding, prefix, kind, initial desired state, desired
read selection/order, and a typed shard hash range where required, with the CLI
defaults above applied by every interface. `UpdatePlacement` contains only
desired state, read selection/order, and expected resource version; binding,
prefix, kind, shard hash range, authority, and observation are not generic
update fields.
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
controller-only `TopologyControllerService.ReportWriteAuthority` may advance
only the matching desired generation;
the method is idempotent and never rewrites a newer promotion.
`CancelPlacementPromotion` follows the same authority-row CAS and generation
rules after its fencing preconditions have reconciled; an operator can also
retry the associated operation without creating a new desired generation.

Controller observations are not public operator mutations. They live only on
`StorageBindingControllerService`, `NetworkBoundaryControllerService`,
`DeliveryControllerService`, `RouteControllerService`,
`TopologyControllerService`, and `BinaryCacheUploadControllerService`. Every
`Report*` or `Complete*` request carries `controller_lease_id`,
`controller_generation`, and `expected_observation_version`; the Hub requires
a service-account token and rejects a missing, expired, wrong-generation, or
stale observation fence. Upload completion uses `ReportCacheUpload` and
`ReportCacheNarinfos` on that same internal surface, never a public durable
mutation exception.

### StorageBindingService

```text
ListStorageBindings
GetStorageBinding
PlanCreateStorageBinding / CreateStorageBinding
PlanSetStorageBindingCredential / SetStorageBindingCredential
PlanRotateStorageBindingCredential / RotateStorageBindingCredential
PlanValidateStorageBindingCredential / ValidateStorageBindingCredential -> OperationRef
PlanGrantStorageBindingScope / GrantStorageBindingScope
PlanRevokeStorageBindingScope / RevokeStorageBindingScope
ListStorageBindingWriteRevisions
GetStorageBindingWriteRevision
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
The provider identity carried by `StorageBindingSpec` is immutable after
creation; endpoint, bucket, prefix, root, region, access-mode, and provider
changes use replacement plus explicit placement migration rather than update.
Binding grant/revoke is dual-scope plan/apply. Stable binding refs resolve to
one exact binding; apply rejects changed dependencies and cannot revoke while a
placement, gateway, or topology default holds an exact active grant pin. Revoke
leaves the durable grant tombstone and appends its lifecycle event.
A write-credential/capability rotation creates and validates an immutable
revision, returns an authority fan-out plan, and keeps the old revision usable
until all pins move. Revision responses expose credential references and
revision/capability fingerprints, never secret material. Equal capability
fingerprints do not suppress a revision whose credential-version reference
changed. Provider invalidation is observed separately and makes affected
authorities write-blocked.

`ValidateStorageBindingCredential` accepts only the binding, closed purpose,
exact credential generation, expected credential-head version, and idempotency
key. It never accepts a validation state or error supplied by a client. The
returned operation is executed by a controller-owned adapter that resolves the
immutable secret reference and exercises the declared `read`, `write`,
`delete`, `list`, or `presign` capability against the configured origin. Write
validation separately records whether create-if-absent semantics were observed.
Sanitized status evidence is retained on the operation; secret material and
signed probe URLs are never persisted. The credential-head observation and its
named audit/outbox event are committed under the exact head-version CAS.

The `write` probe uses an operation-derived deterministic key and the minimal
multipart capability set: list incomplete multipart uploads for that exact key,
abort every exact-key remainder, create one fresh upload, and abort it. Listing
is capped at 1000 results; truncation, a foreign key, malformed identity, or an
unabortable upload fails closed. The probe token is durable before external I/O,
so retries recover crashes before the create response, after the upload id, and
after abort without requiring object-delete or bucket-wide list authority.
`conditionalWritesSupported` remains false unless a separate adapter can
produce equally recoverable provider evidence; a successful ordinary write
probe never infers conditional semantics.

### DomainService

```text
ListDomains
GetDomain
PlanCreateDomain / CreateDomain
PlanConfigureDomainDns / ConfigureDomainDns
PlanConfigureDomainCertificate / ConfigureDomainCertificate
VerifyDomain
PlanDeleteDomain / DeleteDomain
```

`GetDomain` is the single read projection for both desired and observed domain
state; there are no overloaded verification/status aliases. Domain responses
report DNS-name ownership, DNS state, and certificate
issuance. They do not represent an IP address, listener, route access policy,
or full client origin. Hostname and owner scope are immutable, and there is no
generic update: DNS and certificate posture use their dedicated methods. A
hostname change uses replacement domain and endpoint plans. `VerifyDomain`
creates a durable, generically targeted operation and queues external I/O; it
requires the exact current resource version plus an idempotency key, and a
retry resolves to the same operation instead of scheduling duplicate work. It
never changes observations inline. There is no public reconciliation RPC: the
native and Worker controllers claim the operation and record evidence directly
in one lease-version-fenced database transaction.

The controller queries typed A, AAAA, and CNAME records and canonicalizes IP
addresses and IDNA hostnames before comparison. Outbound resolution rejects
non-global addresses at connection time, does not follow redirects, and repeats
the same checks on every durable retry. Each retry sends its own
controller-keyed, operation-, generation-, and attempt-bound nonce to
`/.well-known/aos-domain-probe`. The version-2 response is canonical JSON in a
canonically base64url-encoded Ed25519 envelope. Its signed statement binds the
nonce, a maximum-30-second issuance window, hostname, exact endpoint id and
generation, and pinned public-key identity. It does not carry certificate
fingerprints, provider mode, configuration digests, SANs, or validity dates:
those would be self-attested because neither portable reqwest nor Worker Fetch
exposes the live TLS leaf. The successful HTTPS connection independently proves
public trust, hostname coverage, and current validity for that request.

The controller creates each challenge from cryptographically secure random
bytes and commits only its digest, operation id, endpoint generation, attempt,
and expiry to the durable database in the same transaction that creates the
attempt. A retry always receives a fresh challenge; accepting a response
atomically consumes that challenge, so concurrent and replayed responses fail
closed. There is no configured nonce-derivation key and no process-local nonce
table. Trust comes from the public key pinned in each immutable endpoint
generation's `probeConfiguration`. Native deployments load exact
endpoint-generation seeds from
`HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE`; Worker deployments use the
`HUB_DOMAIN_PROBE_SIGNER_MANIFEST` secret. Both runtimes mount the well-known
route, reject cleartext/non-443 requests, consume a nonce once, and return 503
when the exact secret reference is absent or owned by another provider.
Cloudflare deploy installs an empty manifest when none exists, keeping the
responder explicitly unready until endpoint-generation material is deployed.
External/CDN terminators must implement this responder contract themselves and
remain unready until their provider reports the exact generation installed.
The verified TLS connection and signed responder identity are both required;
the manifest is readiness configuration, not certificate evidence.

### NetworkBoundaryService

```text
ListNetworkBoundaries
GetNetworkBoundary
PlanCreateNetworkBoundary / CreateNetworkBoundary
ListNetworkBoundaryRevisions
GetNetworkBoundaryRevision
PlanReviseNetworkBoundary / ReviseNetworkBoundary
PlanActivateNetworkBoundaryRevision / ActivateNetworkBoundaryRevision
PlanRetireNetworkBoundaryRevision / RetireNetworkBoundaryRevision
PlanGrantNetworkBoundaryScope / GrantNetworkBoundaryScope
PlanRevokeNetworkBoundaryScope / RevokeNetworkBoundaryScope
PlanDeleteNetworkBoundary / DeleteNetworkBoundary
```

Boundary responses expose stable realm identity, the desired default immutable
revision, all per-revision verification/enforcement observations and lifecycle
states, probe provenance, consumer counts/versions, and authorized consumer
scopes. They never expose
private keys or assertion secrets. Unknown or mismatched observation is not a
protected boundary. Read uses `network_boundary.read`; revision, probe, and
reconcile actions use `network_boundary.manage`; cross-scope grants
additionally require `network_boundary.grant` in both owner and consumer
scopes. Instance administrators hold these permissions for instance
boundaries.

Topology authorization uses closed, resource-specific verbs rather than a
generic storage-management surrogate: `storage_binding.read/manage/grant`,
`placement.read/manage`, `placement_policy.read/manage`, `domain.read/manage`,
`network_boundary.read/manage/grant`, `delivery_endpoint.read/manage/grant`,
`storage_gateway.read/manage/grant`, and `route.read/manage`. Every durable
operation persists the exact controlling verb at creation; cancel and retry
re-authorize that stored verb, so adding a secondary target cannot silently
change who controls existing work.

The deployment-provisioned public singleton is returned by list/get but create,
identity update, transfer, and delete reject it. Its instance-default grant is
eagerly projected to exact organization scope rows.
`ReviseNetworkBoundary` creates `staged` revision content and does not move the
default pointer, activate, or invalidate any older revision. Probe/reconcile
targets `<boundary>@<revision>`. Activate's required
`default_for_new_plans` choice controls a versioned default-pointer CAS.
Activate and
retire are plan/apply; overlap mode verifies and activates alongside older
revisions, while coordinated mode returns the complete consumer move and
acknowledged fail-closed window. Retire CASes the lifecycle
`consumer_version` and zero serving-pin count. IAM and audit distinguish revise,
verify, activate, coordinated move, and retire.
The first retire apply transitions `active -> retiring`, increments the version,
and rejects new serving-pin acquisition while existing verified pins remain eligible. A
later apply completes `retiring -> retired` only at zero serving pins; CLI and Web show
the remaining consumers and offer their move plans.

### DeliveryService

```text
ListDeliveryEndpoints
GetDeliveryEndpoint
PlanCreateDeliveryEndpoint / CreateDeliveryEndpoint
ListDeliveryEndpointGenerations
GetDeliveryEndpointGeneration
PlanStageDeliveryEndpointGeneration / StageDeliveryEndpointGeneration
PlanActivateDeliveryEndpointGeneration / ActivateDeliveryEndpointGeneration
PlanGrantDeliveryEndpointScope / GrantDeliveryEndpointScope
PlanRevokeDeliveryEndpointScope / RevokeDeliveryEndpointScope
PlanDeleteDeliveryEndpoint / DeleteDeliveryEndpoint

ListStorageGateways
GetStorageGateway
PlanCreateStorageGateway / CreateStorageGateway
PlanUpdateStorageGateway / UpdateStorageGateway
PlanGrantStorageGatewayScope / GrantStorageGatewayScope
PlanRevokeStorageGatewayScope / RevokeStorageGatewayScope
PreviewGatewayRoutes
PlanEnableStorageGateway / EnableStorageGateway
PlanDisableStorageGateway / DisableStorageGateway
PlanDeleteStorageGateway / DeleteStorageGateway
```

Endpoint responses report the typed origin, ingress/network realm, desired
listener/TLS posture, observed listener/TLS/probe state, and authorized consumer
scopes. Update creates a new endpoint generation and cannot change scheme,
host, port, or boundary identity; those changes require a replacement endpoint
and an impact-planned route/gateway move. Gateway responses pin immutable
endpoint and gateway revisions.
Endpoint grant/revoke resolves the stable endpoint ref to its exact desired
generation in the plan; apply rejects a generation change. Endpoint update
lists affected routes and grants, and carries forward only explicitly confirmed
exact active grant generations/pins before route movement. These operations require
`delivery_endpoint.grant` in both owner and consumer scopes; no old-generation
grant acts as a wildcard.
`endpoint update --boundary-revision` may select only an immutable revision of
the endpoint's existing boundary. Its plan pins the old/new boundary and
endpoint generations and enumerates grants, routes, gateway revisions, and
topology defaults. Apply rejects changed per-revision observation/lifecycle,
consumer version, or any input version; it never follows the boundary default
pointer implicitly.
Gateway grants pin the exact immutable generation. A gateway update plan lists
all existing grants and affected routes; apply creates explicitly confirmed
replacement-generation grants before moving routes. It never treats an old
generation grant as a wildcard. Revoke preserves the durable tombstone and
requires zero live pins. Grant/revoke requires `storage_gateway.grant`
in both owner and consumer scopes; instance administrators hold it for
instance gateways.

### RouteService

```text
ListRoutes
GetRoute
PlanCreateRoute / CreateRoute
PlanUpdateRoute / UpdateRoute
PlanReplaceRoute / ReplaceRoute
PlanEnableRoute / EnableRoute
PlanDisableRoute / DisableRoute
PlanDeleteRoute / DeleteRoute
PlanSetCanonicalRoute / SetCanonicalRoute
ExplainRoute
```

Route messages use typed `DeliveryEndpointRef`, `DeliveryMode`, `DeliveryAccessPolicy`,
`RouteCapabilities`, and `RouteTarget` fields. `RouteTarget` is a closed union:
`HubPlacement`, `HubPolicyRevision`, or
`DirectGatewayPlacement { placement_id, gateway_id, gateway_generation }`.
The API cannot express direct-plus-policy or Hub-plus-gateway combinations.
Both pinned-placement variants require a complete placement; shards are
reachable only through a validated policy revision. `ExplainRoute` includes
normalized authority and path, capability, authorization, publication-head
snapshot, selector vector, presence decision, and sanitized failover
classification, but redacts credentials and private-resource details
unavailable to the caller.

`ReplaceRoute` accepts the same closed route specification as `CreateRoute`
plus the old route id. It creates a distinct route/configuration in disabled,
non-canonical state with a new immutable URL reservation and appends the
old/new relation to the audit log; it never mutates the old route. Its impact
plan returns the required probe, enable, signed-stack change/re-index, canonical
move, disable, and delete sequence. `UpdateRoute`
rejects a changed endpoint identity, base path, or direct derived path; a mode
or target change is an update only when the final rendered URL is byte-identical.
`DisableRoute` and `DeleteRoute` reject every current signed-stack reference;
`DeleteRoute` physically deletes the unreferenced live route/configuration rows
while retaining its privacy-minimized URL reservation and append-only audit
event. The signed registry commit remains signed history.

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
PlanCreateConsumerCacheChangeset
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
PlanRunCacheGc
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

PlanRunPlacementEviction
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

### OperationService

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

`ListOperations` takes the same closed typed resource oneof returned in each
operation's immutable target list; it does not accept a free-form
`targetKind`/`targetId` pair. The CLI expresses this as one required qualified
argument such as `registry:andyl/main`, `cache:andyl/shared`,
`domain:<stable-id>`, or `route:<stable-id>`. Only the operation's `primary`
target participates in resource listing and authorization; source,
destination, policy, and generation targets remain visible in the operation
detail without making the operation appear in several unrelated inventories.

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
storage_binding.scope.granted
storage_binding.scope.revoked
network_boundary.revision.reconciled
network_boundary.revision.probe.changed
network_boundary.revision.created
network_boundary.revision.activated
network_boundary.revision.retiring
network_boundary.revision.retired
network_boundary.coordinated_move.started
network_boundary.coordinated_move.completed
network_boundary.scope.granted
network_boundary.scope.revoked
delivery_endpoint.reconciled
delivery_endpoint.probe.changed
delivery_endpoint.scope.granted
delivery_endpoint.scope.revoked
delivery_endpoint.grants.carried_forward
storage_gateway.scope.granted
storage_gateway.scope.revoked
storage_gateway.grants.carried_forward
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
- Web UI, CLI, and API use the same names for DNS domains, network boundaries,
  delivery endpoints,
  placements, routes, consumer cache stacks, retention subscriptions,
  population targets, and root reasons.
- DNS, IPv4, IPv6, default/custom-port, and protected-HTTP endpoint fixtures
  round-trip to one typed origin in Web UI, CLI, API, native, and Worker; no
  interface persists an opaque URL.
- Route target and endpoint/gateway grant fixtures prove that shared instance
  infrastructure is usable by granted organizations while cross-surface and
  ungranted cross-organization targets are structurally rejected.
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
