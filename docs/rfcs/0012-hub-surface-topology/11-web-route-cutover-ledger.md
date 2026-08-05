# Web route cutover ledger

This ledger is normative for the one-shot Web UI cutover. It inventories every
current management route affected by RFC-0012, including form methods. A row
marked **remove** is absent from both native and Worker routing after cutover;
it is not a redirect, alias, or compatibility handler.

For registry rows, `{registry}` means both a flat slug and the existing nested
`{org}/{project...}/{registry}` shape. The flat router and nested registry
classifier/dispatcher must change atomically.

## Global and organization routes

| Current method and path | Final disposition |
| --- | --- |
| `GET/POST /new` | remove; use `GET/POST /-/orgs/new` |
| `GET /-/orgs` | retain as the global organization inventory |
| `GET /-/caches` | retain as the global cache inventory outside settings |
| `GET /-/org/{org}` | retain with new Overview semantics |
| `GET /-/org/{org}/identity-and-access` | add as the owner of organization profile fields |
| `POST /-/org/{org}/identity-and-access/plan-update` / `POST /-/org/{org}/identity-and-access/update` | add organization profile plan/apply; slug and stable id are not mutable |
| `GET /-/org/{org}/settings` | remove redirect; use the organization root |
| `GET /-/org/{org}/audit` | move to `GET /-/org/{org}/audit-log` |
| `GET /-/org/{org}/members` | retain |
| `POST /-/org/{org}/members` | remove; use `POST /-/org/{org}/members/invitations` from `GET .../invitations/new` |
| `POST /-/org/{org}/members/remove` | remove; use `POST .../members/{principal}/remove` |
| `POST /-/org/{org}/members/role` | remove; use `POST .../members/{principal}/role` |
| `GET /-/org/{org}/projects` | retain as inventory only |
| `POST /-/org/{org}/projects` | retain as collection create from `GET .../projects/new` |
| `POST /-/org/{org}/projects/delete` | remove; use `POST .../projects/{project}/delete` |
| `GET /-/org/{org}/storage` | move to `GET .../storage-bindings` |
| `POST /-/org/{org}/bindings` | move to `POST .../storage-bindings` from `GET .../storage-bindings/new` |
| `POST /-/org/{org}/bindings/delete` | remove; use `POST .../storage-bindings/{binding}/delete` |
| `GET /-/org/{org}/bindings/{id}` | move to `GET .../storage-bindings/{binding}` |
| `POST /-/org/{org}/bindings/{id}` | remove overloaded dispatcher; split access, credential, and storage-gateway actions by owner |
| `GET /-/org/{org}/caches` | retain as inventory only |
| `POST /-/org/{org}/caches` | retain as collection create from `GET .../caches/new` |
| `GET /-/org/{org}/registries/new` | retain |
| `GET /-/org/{org}/registries` | add as the registry inventory moved from the root |
| `POST /-/org/{org}/registries` | retain as collection create |
| `GET /-/org/{org}/danger` | retain |
| `POST /-/org/{org}/delete` | remove; use `POST .../danger/delete` |
| `GET /-/org/{org}/keys` | move to `GET .../signing-keys` |
| `POST /-/org/{org}/keys` | move to `POST .../signing-keys` from `GET .../signing-keys/new` |
| `GET /-/org/{org}/webhooks` | retain as inventory only |
| `POST /-/org/{org}/webhooks` | retain as collection create from `GET .../webhooks/new`; move deletion to `POST .../webhooks/{webhook}/delete` |
| `GET/POST /-/org/{org}/sso` | retain as the SSO configuration resource |

The removed binding-detail POST operations map as follows:

- access/origin settings -> `POST .../storage-bindings/{binding}/access`;
- credentials -> purpose-specific set/rotate/validate workflows below the
  binding;
- frontend creation -> `POST .../storage-gateways` from
  `GET .../storage-gateways/new`; and
- frontend edit/delete -> resource-specific storage-gateway actions.

## Binary-cache routes

Let `B = /-/org/{org}/caches/{cache}`.

| Current method and path | Final disposition |
| --- | --- |
| `GET B` | retain with new Overview semantics |
| `POST B` | remove; use purpose-specific forms below `B/access` |
| `GET B/links` | move to read-only `GET B/integrations` |
| `GET B/pins` | remove; split between `GET B/retention` and `GET B/garbage-collection` |
| `GET B/danger` | retain |
| `POST B/link` | remove; use independent consumer-publication, retention, and population workflows |
| `POST B/unlink` | remove; use the same independent workflows |
| `GET B/storage` | move to `GET B/placements` |
| `POST B/storage` | remove pointer swap; use placement add, replicate, promote, drain, and delete workflows |
| `GET B/serving` | move to `GET B/delivery` |
| `POST B/advertise-frontend` | remove; create an explicit gateway-backed delivery route |
| `POST B/gc` | remove overloaded action; split into policy, immutable plan, and run resources below `B/garbage-collection` |
| `POST B/pin/add` | move to `POST B/retention/manual-roots` |
| `POST B/pin/remove` | remove; use `POST B/retention/manual-roots/{root}/delete` |
| `POST B/delete` | remove; use `POST B/danger/delete` |

Consumer-publication mutations reached from this cache remain owned by the
selected registry's signed cache-stack workflow. Retention and population use
their cache/registry subresource ids. The Integrations matrix itself has no
generic mutation action.

The final cache retention and GC route families are resource-specific:

| Final method and path | Owner |
| --- | --- |
| `GET B/retention` | subscriptions, manual roots, leases, and root reasons inventory |
| `GET B/retention/subscriptions/{registry}` | one subscription and refresh-generation history |
| `POST B/retention/subscriptions/{registry}/plan-set` / `POST B/retention/subscriptions/{registry}/set` | subscription plan/apply |
| `POST B/retention/subscriptions/{registry}/plan-delete` / `POST B/retention/subscriptions/{registry}/delete` | subscription removal plan/apply |
| `POST B/retention/subscriptions/{registry}/refresh` | idempotent refresh operation |
| `GET B/retention/manual-roots/new` | manual-root creation form |
| `POST B/retention/manual-roots/plan` / `POST B/retention/manual-roots` | manual-root plan/apply |
| `POST B/retention/manual-roots/{root}/delete/plan` / `POST B/retention/manual-roots/{root}/delete` | manual-root removal plan/apply |
| `POST B/retention/manual-roots/{root}/leases/plan` / `POST B/retention/manual-roots/{root}/leases` | immutable lease renewal plan/apply |
| `POST B/retention/leases/{lease}/revoke/plan` / `POST B/retention/leases/{lease}/revoke` | lease revocation plan/apply |
| `GET B/garbage-collection` | policy, safety gates, and plan creation |
| `POST B/garbage-collection/policy/plan-set` / `POST B/garbage-collection/policy/set` | GC-policy plan/apply |
| `POST B/garbage-collection/plans` | create immutable mark and GC plan |
| `GET B/garbage-collection/plans/{plan}` | semantic candidate/action review |
| `POST B/garbage-collection/first-sweep/plan-acknowledgement` | plan a durable acknowledgement against one valid GC plan |
| `POST B/garbage-collection/first-sweep/acknowledge` | apply the confirmation-bound acknowledgement; stales the reviewed GC plan |
| `POST B/garbage-collection/plans/{plan}/run` | guarded logical apply; returns operation |
| `GET B/garbage-collection/runs/{operation}` | logical and per-placement progress |
| `GET B/garbage-collection/runs/{operation}/jobs/{job}` | one deletion action and retry history |
| `POST B/garbage-collection/runs/{operation}/jobs/{job}/retry` | idempotent retry |
| `POST B/garbage-collection/runs/{operation}/jobs/{job}/plan-abandon` / `POST B/garbage-collection/runs/{operation}/jobs/{job}/abandon` | reviewed leaked-presence abandonment |

There is no final POST that means both plan and run, no `dry_run` compatibility
parameter, and no form that recomputes candidates when applying a plan.

## Registry routes

Let `R = /{registry}/-/settings`.

| Current method and path | Final disposition |
| --- | --- |
| `GET R` | retain with new Overview semantics |
| `POST R/visibility` | move to `POST R/access/visibility` |
| `POST R/crawl` | move to `POST R/access/crawl-policy` |
| `GET R/storage` | move to `GET R/placements` |
| `POST R/storage` | remove pointer swap; use placement workflows |
| `POST R/advertise-frontend` | remove; use an explicit delivery route |
| `GET R/caches` | retain as read-only cache topology/entry point |
| `POST R/cache-link` | remove; use independent consumer-stack, retention, and population workflows |
| `POST R/cache-unlink` | remove; use the same independent workflows |
| `GET R/danger` | retain |
| `POST R/delete` | remove; use `POST R/danger/delete` |
| `GET R/serving` | split into `GET R/delivery` and `GET R/upstream-mirror` |
| `POST R/serving` | remove overloaded dispatcher; split route CRUD below `R/delivery/routes` and mirror configuration below `R/upstream-mirror` |
| `GET R/tokens` | retain as inventory only |
| `POST R/tokens` | retain as collection create from `GET R/tokens/new` |
| `POST R/tokens/revoke` | remove; use `POST R/tokens/{token}/revoke` |
| `POST R/tokens/rotate` | remove; use `POST R/tokens/{token}/rotate` |
| `GET/POST R/config` | move to `GET/POST R/configuration` |
| `GET /{registry}/-/keys` | move to `GET R/signing-keys` |
| `GET /{registry}/-/keys/rotate` | move to `GET R/signing-keys/rotate` |
| `GET /{registry}/-/publishes` | move to `GET R/publish-history` |
| `GET /{registry}/-/changes` | move to `GET R/change-requests` |
| `GET /{registry}/-/changes/{id}` | move to `GET R/change-requests/{id}` |
| `POST /{registry}/-/changes/{id}/{comment,review,close,reopen}` | move to the same action below `R/change-requests/{id}` |
| `GET/POST /{registry}/-/channels/{name}/console` | move to `GET/POST R/channels/{name}` |
| `POST /{registry}/-/channels/{name}/advance` | move to `POST R/channels/{name}/advance` |

## Instance routes

| Current method and path | Final disposition |
| --- | --- |
| `GET /-/instance` | retain with new Overview semantics |
| `POST /-/instance` | remove; split signup/password/session fields to `POST /-/instance/identity-and-signup` and anonymous cache discovery to `POST /-/instance/resource-defaults` |
| `GET/POST /-/instance/storage` | remove overloaded page; use storage bindings and storage gateways below their canonical collections |
| `GET/POST /-/instance/branding` | retain |
| `GET/POST /-/instance/serving` | move to `GET/POST /-/instance/resource-defaults` |

## Enforcement

The implementation generates a method+path manifest for native and Worker
routing plus the nested registry dispatcher. Tests compare it to the final
manifest and assert every removed method/path pair above is absent. Reused URLs
are final handlers with the new semantics, never compatibility aliases.

Rendered-HTML tests also reject every removed form action. A repository guard
rejects old route fragments and active keys outside historical RFC prose and
the ephemeral cutover artifact. Any route discovered during implementation but
missing from this ledger blocks cutover until its explicit final disposition is
added.

The route manifest additionally rejects legacy cache GC/link handlers and
actions named `link`, `unlink`, `pins`, `pin/add`, `pin/remove`, or the
overloaded `gc` POST. Native and Worker manifests must expose the same final
retention, plan, run, job, retry, and abandonment method/path pairs.
