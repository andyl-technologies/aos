# Implementation plan and acceptance criteria

The implementation may be built and tested in phases, but production performs
one complete cutover. The new runtime never dual-reads old and new topology,
and RFC-0012 is not complete while legacy schema, handlers, commands, API
methods, or compatibility branches remain in the repository.

## Phase 0: characterization and safety barriers

- [ ] Snapshot current URL resolution for registry/cache own frontends,
      binding frontends, default binding, visibility combinations, and native
      versus Worker runtimes.
- [ ] Add characterization tests for current cache GC roots, manual expiry,
      shared registry/cache links, and dry runs.
- [ ] Inventory every deployed binding, prefix, frontend, domain, and committed
      cache URL; flag probable physical equivalence without merging it.
- [ ] Add a runtime kill switch that disables destructive cache GC while
      placement/presence migration is incomplete.
- [ ] Capture golden `--help`, JSON output, Web UI form/action, and Connect-JSON
      fixtures for every legacy frontend, storage-change, cache-link, and GC
      operation affected by the rewrite.

**Done when:** the one-shot cutover can compare old and new effective URLs and
GC plans for every existing surface before it mutates production state.

## Phase 1: placements

- [ ] Finalize typed storage-binding capabilities, purpose-scoped credentials,
      instance-singleton behavior, and organization/instance topology defaults.
- [ ] Ship `StorageBindingService`, `aos hub storage-binding`, topology-default
      CLI families, and organization/instance Web editors before placement
      creation depends on them.
- [ ] Add `surface_placements`, placement state, and placement policies.
- [ ] Make the cutover transform each registry/cache binding+prefix into a
      primary placement and reject incomplete or ambiguous rows.
- [ ] Add object-presence indexing per placement.
- [ ] Implement placement scan, replicate, repair, drain, and explain APIs.
- [ ] Implement ordered failover in shared core for native and Worker.

**Done when:** one registry and one binary cache can each serve through a Hub
route from two bindings, survive primary read failure, and report which
placement served the object.

## Phase 2: domains and delivery routes

- [ ] Normalize hostname lifecycle into `domains`.
- [ ] Add delivery routes, canonical routes, and storage gateways.
- [ ] Migrate registry/cache frontends to routes and binding frontends to
      gateways plus materialized derived routes.
- [ ] Implement one longest-prefix route matcher in shared core.
- [ ] Implement Hub proxy, Hub-authorized redirect, and direct route records.
- [ ] Implement route access policies and visibility revalidation.
- [ ] Add capability probes for Git and Nix-cache semantics.
- [ ] Import every still-supported URL as an ordinary route and require signed
      config migration for every URL that will not exist after cutover.
- [ ] Ship the Delivery Web UI, `aos hub route/domain/gateway` commands, and
      `TopologyService`/`DomainService`/`RouteService` methods together.

**Done when:** a public registry and cache are simultaneously usable through a
Hub URL, direct CDN URL, and alternate direct origin/gateway URL; byte/range/
conditional semantics pass the same conformance suite on every route.

## Phase 3: private route authentication

- [ ] Unify session, bearer, Basic/netrc, and Git credential authentication at
      the shared route authorization boundary.
- [ ] Add scoped origin-read credentials and secret-free route explanations.
- [ ] Add external-provider and private-network access-policy records.
- [ ] Validate client compatibility before producing setup snippets.
- [ ] Test presigned redirect TTL, no-store behavior, path confinement, and
      revocation boundaries.

**Done when:** a private surface works through native Hub and Worker Hub with
identical authorization results; an anonymous direct route is structurally
impossible; and a declared VPN/external gateway route is represented without
claiming Hub enforcement.

## Phase 4: split registry/cache integrations

- [ ] Add retention subscriptions and population targets.
- [ ] Migrate `cache_registry_links.roots_packages` to the default retention
      selector.
- [ ] Delete `LinkCache` and the old combined request/response messages.
- [ ] Index signed consumer entries with stable cache/route identity.
- [ ] Add the three-choice integration workflow and accurate empty states.
- [ ] Enforce cross-visibility and cross-organization approval per operation.
- [ ] Ship the Binary caches Web UI, `cache-stack`/`retention`/`population`
      commands, and `CacheIntegrationService` methods together.

**Done when:** publication, retention, and population can be independently
created and removed, with no operation changing either of the other two.

## Phase 5: release artifact snapshots and GC provenance

- [ ] Index artifact sets from every verified release tag commit.
- [ ] Resolve every channel partition to a release artifact set.
- [ ] Add selector evaluation and transactional root-reason refresh.
- [ ] Preserve old successful reasons on index/refresh failure.
- [ ] Move release-count/channel policy from cache-global state to each
      retention subscription.
- [ ] Add logical GC tombstones and per-placement deletion jobs.
- [ ] Split logical GC from placement eviction.
- [ ] Add explain/dry-run/quota-contributor UI and APIs.
- [ ] Delete ambiguous CLI GC/link commands and ship only the plan-first
      commands specified by `09-interface-contracts.md`.

**Done when:** tests prove that current catalog artifacts, every active channel
partition target, and the configured number of recent releases remain present
across GC; removing one shared-cache subscription cannot collect another
registry's closure.

## Phase 6: replication, shards, and population

- [ ] Implement immutable-first replication and pointer-last registry
      publication across required placements.
- [ ] Implement NAR-first/narinfo-last cache replication.
- [ ] Implement complete-replica health and repair.
- [ ] Implement one stable hash-partition rule and proxy-only shard routing.
- [ ] Implement release population targets and required/best-effort gates.
- [ ] Integrate coverage validation with population and mirror-stack health.

**Done when:** complete replicas may serve directly; a missing replica object
is repaired; shards are never exposed as complete endpoints; and a required
population target can gate release announcement without exposing partial
state.

## Phase 7: unify the settings Web UI

- [ ] Replace the flat `SettingsTab` list with one grouped settings-navigation
      model shared by instance, organization, registry, and binary-cache
      scopes.
- [ ] Make each scope root render Overview and make Overview the first active
      item; move organization Registries to its explicit inventory path.
- [ ] Build shared scope-header, summary-strip, placement, delivery-route,
      cache-integration, operation, impact-review, and danger components.
- [ ] Render registry and binary-cache placement/delivery pages from the same
      component and column definitions, parameterized by `SurfaceRef`.
- [ ] Split storage inventory from credentials, gateways, placements, and
      delivery; split cache retention from logical GC and placement eviction.
- [ ] Replace combined “Serving & mirror,” “Linked registries,” and “GC & pins”
      pages with the single-responsibility pages defined by
      `10-settings-information-architecture.md`.
- [ ] Move resource creation, credential rotation, migration, and destructive
      operations to dedicated workflows; remove full create forms from list
      pages.
- [ ] Implement the wide settings workspace and responsive context rail while
      preserving the existing visual language and complete no-JS operation.
- [ ] Add role-aware grouped-nav snapshots, root-route/active-item tests,
      canonical-row ordering tests, shared-component parity tests, and wide,
      medium, and narrow layout snapshots.
- [ ] Generate the final method+path route manifest and an exhaustive old-route
      deletion manifest; assert no removed GET/POST form action is mounted by
      the flat router, nested-registry dispatcher, native runtime, or Worker.
- [ ] Remove old settings route names, handlers, templates, nav labels, and
      duplicated registry/cache rendering code rather than retaining aliases.

**Done when:** instance, organization, registry, and binary-cache settings use one
deterministic hierarchy; each root selects the first Overview item; every page
has one primary mutation domain; registry/cache topology views cannot drift;
and the final route table contains only the canonical paths in
`09-interface-contracts.md`.

## Phase 8: cut over and delete the old topology

- [ ] Quiesce Hub writes and destructive GC; take and verify a full control
      database backup.
- [ ] Run the preflight inventory, route/config coverage check, placement
      presence scan, and GC comparison. Abort on any unexplained difference.
- [ ] Merge every required signed consumer-cache URL change before switching
      off an old URL.
- [ ] Stop old native and Worker deployments.
- [ ] Run the one-shot cutover that creates all new records and drops old
      topology tables/columns in one maintenance operation.
- [ ] Deploy native and Worker binaries that understand only the new schema and
      mount only `aos.hub.v1`.
- [ ] Delete old frontend/link/storage-switch code, old Web UI handlers/paths,
      old CLI variants, old `aos.registry.v1` routes/messages, URL-string
      identity, compatibility tests, and feature flags.
- [ ] Squash the Hub database schema for fresh installations so it creates only
      the new topology. Do not retain the cutover transformer in steady-state
      runtime code.
- [ ] Update canonical operator documentation to describe only the new model.
- [ ] Mark RFC-0012 implemented and RFC-0004 topology chapters superseded.

**Done when:** repository search, schema inspection, generated API descriptors,
CLI `--help`, route inventory, and Web UI routing prove the old topology is
absent. Any retained external URL is a normal delivery route, not a legacy
alias or special-case handler.

## Required rename and deletion ledger

The cutover is incomplete until these concepts disappear from steady-state
source and generated artifacts:

| Current name/shape | Final name/shape |
| --- | --- |
| `caches` system-of-record table / generic managed `Cache` messages | `binary_caches` / `BinaryCache` |
| `frontends` / `FrontendRecord` | `delivery_routes` / `DeliveryRoute` |
| binding-targeted frontend | `StorageGateway` plus explicit materialized routes |
| resource `advertise_storage_frontend` toggle | removed |
| `cache_registry_links` / `CacheRegistryLink` | separate retention and population records; signed stack remains registry content |
| `advertised_caches` and URL-string reconciliation | `registry_cache_stack_entries` with stable managed ids |
| generic `consumer_priority` | stack order, placement member order, or Nix priority as distinct fields |
| `change_storage` pointer swap | placement add/replicate/promote/drain workflow |
| `frontends_by_domain`-style dispatch | domain + longest-prefix delivery-route dispatch |
| `direct_consumer_url`/inheritance resolver | canonical delivery-route and placement-policy resolution |
| `aos.registry.v1` | `aos.hub.v1` |
| `RegistryHubClient` and registry-only generated names | `HubClient` and Hub resource names |
| `OrgService`, `StorageService`, `ConfigService`, `IamService`, registry-package `CacheService` | `OrganizationService`, `StorageBindingService`, `RegistryConfigurationService`, `IdentityService`, `BinaryCacheService` |
| old storage/serving/cache settings handlers | new placements/delivery/cache-integration handlers only |

Historical RFC prose may retain old names to explain provenance. Runtime code,
active schema, canonical operator docs, generated API descriptors, CLI help,
and Web UI templates may not.

## Test matrix

Every relevant case runs against native sqlite/local-fs, native S3-compatible
storage, and Worker D1/R2 where the runtime supports the binding.

### Placement cases

- one primary;
- primary plus complete replica;
- degraded primary failover;
- archive excluded from reads;
- deterministic two-shard routing;
- drain while requests are active;
- duplicate-prefix rejection and explicit placement equivalence.

### Route cases

- Hub proxy, Hub redirect, public direct CDN, direct backend;
- external-auth and private-network declarations;
- several base paths on one domain and longest-prefix match;
- Git/Nix-cache path and header conformance;
- range requests and conditional requests;
- canonical change without disabling old route;
- domain change requires an explicit new route and impact plan;
- native/Worker authorization parity.

### Interface cases

- every Web UI action maps to the documented API method;
- every desired-state, policy, or destructive CLI mutation supports plan/apply
  and optimistic concurrency; idempotent observation/reconcile triggers return
  state or operation ids;
- stable `--json` golden output for every new command family;
- long operations have CLI watch and Web UI status parity;
- signed consumer changes report pending versus applied accurately;
- each instance, organization, registry, and cache scope root renders Overview
  and activates the first navbar item;
- grouped navbar order is stable for every scope and permission class;
- canonical routes, primary placements, and defaults sort before alternates;
- organization resource inventories and all creation workflows have distinct
  paths, with no full create form appended to a list page;
- registry and binary-cache placement/delivery views share component and
  column-definition snapshots;
- wide, medium, and narrow snapshots cover long values, degraded state, empty
  state, and permission-restricted state;
- removed commands, Web paths, and API routes are not mounted;
- removed form actions do not occur in rendered HTML or route manifests;
- no-JS Web UI completion for every topology and integration mutation;
- native and Worker Connect-JSON fixture parity.

### Security cases

- every visibility/access-policy/mode combination;
- private origin behind public Hub route with client auth;
- public-read/authenticated-write cache;
- presigned URL cannot escape placement prefix;
- auth failure never falls back to a broader route/placement;
- external route never mislabeled as Hub-authenticated;
- public registry cannot publish an unreadable cache route.

### GC cases

- all current catalog versions, not only newest;
- current and partially rolled-out channel targets;
- latest-N verified release snapshots;
- exact and semver selectors;
- multiple root reasons for one store hash;
- several registries sharing one cache;
- root-refresh failure preserves previous roots;
- logical deletion across partial backend failure;
- rooted closure over cap remains intact;
- direct-route missing access telemetry changes only eviction order.

## Cutover and rollback

The cutover is maintenance-mode replace, not expand/dual-read/contract:

1. build and validate the complete new implementation off production;
2. pre-create and merge required signed URL changes;
3. quiesce writes and take a verified backup;
4. stop old processes;
5. transform and validate all topology records;
6. drop old schema objects;
7. deploy the new native/Worker/API/CLI/Web UI together; and
8. re-enable writes only after route, placement, auth, coverage, and GC-plan
   smoke tests pass.

Rollback is full restoration of the verified pre-cutover database backup and
old deployment artifacts while writes remain quiesced. The new runtime does
not contain a legacy read mode. Destructive GC stays disabled until the new
root and presence models pass their post-cutover safety gates.
