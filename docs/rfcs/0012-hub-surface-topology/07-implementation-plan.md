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
      immutable write revisions and validation observations,
      instance-singleton behavior, and organization/instance topology defaults.
- [ ] Ship `StorageBindingService`, `aos hub storage-binding`, topology-default
      CLI families, and organization/instance Web editors before placement
      creation depends on them.
- [ ] Add placement specification, separately writable observations, placement
      policies, and one versioned write-authority resource per writable
      surface. Do not store primary role, write enablement, or write order on
      placement rows.
- [ ] Make the cutover transform each registry/cache binding+prefix into a
      complete placement plus observation. Create ready authority only for a
      proven writable, validated, unambiguous legacy destination; leave
      explicitly read-only surfaces authority-free and abort on unproven
      declared writability, ambiguity, or collisions.
- [ ] Implement initial authority creation and promotion as guarded
      single-row statements shared by native SQL and Worker Durable Object SQLite.
- [ ] Implement retry and reviewed cancellation for pending/failed promotions;
      cancellation restores the observed writer only after fencing checks and
      is itself generation guarded.
- [ ] Pin writer-critical placement revisions through same-surface composite
      foreign keys so promotion cannot race drain, delete, or incompatible
      placement changes on PostgreSQL or MySQL.
- [ ] Map placement write-spec versions to immutable binding-write revisions;
      pin both in authority and implement resumable revision-rotation fan-out
      before revoking an old credential.
- [ ] Derive primary role, promotion-pending status, and effective read/write
      eligibility in one shared projection used by API, Web, CLI, and routing.
- [ ] Add object-presence indexing per placement.
- [ ] Implement placement scan, replicate, repair, drain, and explain APIs.
- [ ] Implement ordered failover in shared core for native and Worker.

**Done when:** one registry and one binary cache can each serve through a Hub
route from two bindings; each has several complete placements but one
generation-checked writer; promotion cannot produce two Hub writers; a read
failure on the observed-authority placement is visible without silently moving
authority; and the runtime reports which placement served the object.

## Phase 2: domains, endpoints, and delivery routes

- [ ] Normalize DNS lifecycle into `domains`; model revisioned, observed
      `network_boundaries`; and migrate every client URL into a typed
      immutable-identity `delivery_endpoint` with explicit scheme,
      DNS/IPv4/IPv6 host, effective port, and pinned endpoint/boundary
      revisions.
- [ ] Provision the non-deletable instance public-boundary singleton and
      eagerly materialize its exact instance-default organization grants.
- [ ] Add delivery routes, permanent privacy-minimized URL reservations,
      canonical routes, storage gateways, and append-only route audit events.
- [ ] Migrate registry/cache frontends to routes and binding frontends to
      gateways plus explicit reviewed direct routes for supported old URLs.
- [ ] Implement one raw-request-target parser and segment-boundary
      longest-prefix matcher in shared core, with fixed native/Worker vectors
      for scheme/authority/port, DNS and IP normalization, IDNA, percent
      encoding, Unicode, realms, and reserved control namespaces.
- [ ] Implement Hub proxy, Hub-authorized redirect, and direct route records.
- [ ] Implement immutable placement-policy and gateway revisions with
      same-surface/scope composite foreign keys and closed route-target unions.
- [ ] Run proxy and redirect through one exact-presence/publication-head
      selector; implement the typed failure taxonomy and forbid mid-response
      failover.
- [ ] Conform native and Worker HTTP handling for ranges, conditions, cache
      headers, sanitized origin failures, `307`, and `421` direct-route misses.
- [ ] Implement route access policies and visibility revalidation.
- [ ] Implement the durable route-replacement workflow: create/probe/enable the
      successor, commit and re-index signed-stack changes, move canonical
      audiences, then disable/delete the predecessor; resume idempotently after
      a crash at every boundary.
- [ ] Add capability probes for Git and Nix-cache semantics.
- [ ] Import every still-supported URL as an ordinary route and require signed
      config migration for every URL that will not exist after cutover.
- [ ] Ship the Delivery Web UI, `aos hub
      {domain,network-boundary,endpoint,gateway,route}` commands, and
      `DomainService`/`NetworkBoundaryService`/`DeliveryService`/
      `RouteService` methods together.

**Done when:** a public registry and cache are simultaneously usable through a
Hub URL, direct CDN URL, and alternate direct origin/gateway URL; byte/range/
conditional semantics pass the same conformance suite on every route; direct
requests that reach Hub return `421`; and no cross-surface/scope or invalid
mode/target tuple is representable. DNS, IPv4, IPv6, default/custom-port, and
explicit protected-HTTP fixtures round-trip to one canonical endpoint origin.
Public and private boundary fixtures round-trip stable typed identity, desired
default plus per-revision verification/lifecycle, trusted-ingress configuration, grants, and
fail-closed degraded state through Web, CLI, API, native, and Worker paths.

## Phase 3: private route authentication

- [ ] Unify session, bearer, Basic/netrc, and Git credential authentication at
      the shared route authorization boundary.
- [ ] Add scoped origin-read credentials and secret-free route explanations.
- [ ] Add external-provider and private-network access-policy records.
- [x] Accept ingress identity/access class only from mutually authenticated,
      configured ingress and strip client-supplied forwarding assertions.
- [ ] Permit private-network redirects only when the presigned origin enforces
      the same named boundary.
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
- [ ] Persist an immutable release-artifact snapshot header and manifest digest
      atomically with its artifact rows; distinguish a complete empty set from
      an unindexed or failed release and preserve every prior complete snapshot.
- [ ] Resolve every channel partition to a release artifact set.
- [ ] Add selector evaluation and transactional root-reason refresh.
- [ ] Preserve old successful reasons on index/refresh failure.
- [ ] Move release-count/channel policy from cache-global state to each
      retention subscription.
- [ ] Add logical GC tombstones and per-placement deletion jobs.
- [ ] Normalize cache-object reference edges and the store-hash -> narinfo ->
      shared-NAR mapping; remove cache-global physical refcounts.
- [ ] Add immutable root/mark generations, first-unreferenced time, complete
      coverage gates, and versioned relational GC candidate/action manifests.
- [ ] Apply a reviewed GC plan with one portable CAS over root, graph,
      inventory, policy, topology, candidate, and conflicting-work inputs.
- [ ] Delete narinfo before a placement-scoped zero-refcount NAR; implement
      idempotent retry/backoff, version/ETag checks, and audited abandonment
      without false reclaimed-byte accounting.
- [ ] Split logical GC from placement eviction.
- [ ] Add explain/immutable-plan/quota-contributor UI and APIs.
- [ ] Delete ambiguous CLI GC/link commands and ship only the plan-first
      commands specified by `09-interface-contracts.md`.

**Done when:** tests prove that current catalog artifacts, every active channel
partition target, and the configured number of recent releases remain present
across GC; removing one shared-cache subscription cannot collect another
registry's closure; concurrent root/population/inventory change stales the old
plan; and partial placement deletion never loses presence evidence or reports
unconfirmed bytes as reclaimed.

## Phase 5a: first-class AOS system-image distribution

- [x] Extend each signed sysroot catalog entry with a direct-delivery contract:
      platform and architecture, encoding format, logical image identity,
      deterministic object key and useful filename, media type, compression,
      encoded byte size, SHA-256, compatible targets, release/channel identity,
      and a complete integrity-bound `image-info.json` reference.
- [x] Model raw, QCOW2, VMDK, and VHD as encodings of one logical release and
      expose target selection for bare metal, QEMU/KVM, OpenStack, VMware, and
      Hyper-V without exposing Nix store paths or NARs.
- [x] Emit or attach canonical image metadata for every published encoding;
      converted outputs no longer depend on an implicit sibling
      `image-info.json` during publication.
- [x] Add the registry **Images** navbar entry and browse page with release,
      channel, architecture, format, target, size, checksum, release and boot
      verification state, filters, and direct download actions.
- [x] Ship `ImageService.ListImages`, `GetImage`, and `ResolveImage` in
      `aos.hub.v1`, returning immutable byte URLs and complete integrity and
      image-info metadata.
- [x] Ship `aos image list`, `show`, and `download` with release/channel,
      architecture, format, target, package, output, JSON, authenticated
      private-registry access, resumable range downloads, useful filenames,
      exact-size enforcement, and mandatory SHA-256 verification.
- [x] Preserve package-oriented `apm install ... --image` behavior while
      making `aos image` the direct end-user image-discovery workflow.
- [x] Serve the exact disk file in native and Worker deployments with public
      and private authorization, `HEAD`, ranges, `Content-Disposition`,
      integrity headers, and immutable caching.
- [x] Publish disk bytes and signed catalog metadata before advancing release
      and channel discovery. Treat disk files and image-info documents as
      publication and GC roots, and fail closed on partial publication.
- [x] Add a hermetic producer fixture with fake raw and QCOW2 images and run it
      end to end through native and live Worker Durable Object deployments,
      covering API, Web UI, CLI, exact bytes, checksum verification, range
      requests, and public and authenticated access.

**Done when:** one signed release is discoverable as raw and QCOW2 through the
Web UI and API; the CLI downloads and verifies exact disk bytes; native and
Worker pass the same public/private, `HEAD`, and range matrix; incomplete
publication is invisible; and the image and metadata objects remain release
roots. This phase is complete.

## Phase 6: replication, shards, and population

- [ ] Implement immutable-first replication and pointer-last registry
      publication across required placements.
- [ ] Implement NAR-first/narinfo-last cache replication.
- [ ] Implement complete-replica health and repair.
- [ ] Implement normative `hash_range_v1` vectors and proxy-only shard routing.
- [ ] Implement release population targets and required/best-effort gates.
- [ ] Integrate coverage validation with population and mirror-stack health.

**Done when:** complete replicas may serve directly; a missing replica object
is repaired; native/Worker fixed vectors choose the same two-shard bucket and
replica order; overlap/uncovered-range validation fails closed; mutable
pointers never select shards; shards are never exposed as complete endpoints;
and a required population target can gate release announcement without
exposing partial state.

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
- [ ] Give Storage & replicas a separate Write authority panel showing desired
      and observed placement/generation, pending or failed reconciliation, and
      the sole Promote action. Placement editors expose kind, lifecycle, read
      selection, and order but never editable primary/write fields.
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
- [ ] Rewrite any unreleased additive topology migration in place instead of
      adding a compatibility migration from its provisional role/write shape;
      reset branch-local databases that ran it.
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
| binding-targeted frontend | `StorageGateway` plus explicit user-owned routes |
| resource `advertise_storage_frontend` toggle | removed |
| `cache_registry_links` / `CacheRegistryLink` | separate retention and population records; signed stack remains registry content |
| `cache_gc_roots`, `CacheGcRoot`, pin/unpin root RPC shapes | manual retention roots, lease history, and provenance-bearing root reasons |
| synchronous `RunCacheGc { dry_run }` / DB-first `sweep_cache` | immutable `PlanRunCacheGc` plus guarded asynchronous `RunCacheGc(plan_id)` |
| cache-global binding/prefix `nar_refcount` and single cache writer | explicit narinfo/NAR surface objects and placement-scoped deletion actions |
| `cache_gc_runs` aggregate-only rows | topology operation plus versioned GC plan, object, action, and job records |
| `cache_gc_policy.keep_release_versions` / `keep_channel_frontier` | typed per-subscription retention selectors |
| authoritative `cache_objects.refs` JSON | normalized `cache_object_references` edges |
| `cache_usage.used_bytes` / `object_count` authority | derived logical and per-placement inventory/accounting projections |
| `cache_objects.uploaded_at` as GC age | informational `published_at`; eligibility begins at `unreferenced_since` |
| cache-row `last_accessed_at` authority | advisory access observations with source/freshness; eviction ordering only |
| RPCs `LinkCache`, `UnlinkCache`, `ListCacheLinks` | signed consumer-stack and independent retention/population services |
| messages `LinkCacheRequest`, `LinkCacheResponse`, `UnlinkCacheRequest`, `UnlinkCacheResponse`, `ListCacheLinksRequest`, `ListCacheLinksResponse`, `CacheLink` | removed with no compatibility messages |
| RPCs `PinCachePath`, `UnpinCachePath`, `ListCacheRoots` | manual-root/lease plan methods and provenance-bearing root reads |
| messages `PinCachePathRequest`, `PinCachePathResponse`, `UnpinCachePathRequest`, `UnpinCachePathResponse`, `ListCacheRootsRequest`, `ListCacheRootsResponse`, `CacheRoot` | removed with no compatibility messages |
| old `RunCacheGcRequest`, `RunCacheGcResponse`, `CacheGcPolicyMsg`, and aggregate `CacheGcRun` shapes | typed immutable GC plan, operation, candidate, placement-action, and deletion-job messages |
| `HubCacheCmd::{ChangeStorage,Link,Unlink}` | placement workflow, consumer cache stack, and independent retention/population commands |
| server `CacheCommand::{Link,Unlink,Links,GcPolicy,Pin,Renew,Unpin,Roots,Gc,GcRuns}` | final plan-first cache integration, root/lease, GC plan/run/job command families |
| `advertised_caches` and URL-string reconciliation | `registry_cache_stack_entries` with stable managed ids |
| generic `consumer_priority` | stack order, placement member order, or Nix priority as distinct fields |
| placement `role`, `write_enabled`, `write_order`, and primary-discriminator columns | placement `kind` plus per-surface desired/observed write authority; role and effective write state are derived |
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
storage, and Worker Durable Object SQLite/R2 where the runtime supports the binding.

### Placement cases

- an authority-free surface is read-only and initial authority creation is
  idempotent;
- cutover leaves explicitly read-only legacy surfaces authority-free, creates
  ready authority only from validated unambiguous writable evidence, and
  aborts on unproven declared writability or multiple writer candidates;
- several complete placements coexist without stored primary/write fields;
- one observed primary plus complete replicas is derived consistently;
- simultaneous promotions from one authority version have exactly one winner;
- stale authority, current-writer, and candidate write-spec versions each
  reject;
- stale, invalid, or capability-insufficient binding-write revisions reject;
- binding rotation may reconcile the same placement to a new revision,
  survives partial fan-out, and cannot delete/revoke the old Hub-managed
  revision while any desired/observed authority pins it;
- a same-capability/new-credential rotation produces a distinct revision
  fingerprint, retains the equal capability fingerprint, and completes the
  normal authority fan-out instead of colliding with uniqueness;
- promotion racing binding-revision deletion has one FK-serialized winner;
  provider-side invalidation immediately blocks effective writes without
  moving authority;
- a cross-surface, shard, archive, partial, provisioning, degraded, draining,
  or write-incapable candidate rejects;
- promotion racing drain, delete, or a writer-critical placement change cannot
  commit both outcomes;
- crash after desired promotion leaves explicit pending reconciliation and no
  effective Hub writer; retry, cancellation, or completion is generation
  guarded;
- cancellation cannot restore writes until the candidate is fenced and the
  observed writer is ready, and stale cancellation cannot rewrite a newer
  promotion;
- stale reconciliation completion cannot overwrite a newer desired generation;
- desired and observed authority placements cannot drain or delete, including
  both sides of a pending promotion;
- degraded/offline observation makes effective writes false without silently
  moving authority, while observations remain writable;
- derived primary/replica/shard/archive roles and effective write fields match
  in database, API, CLI, Web UI, native routing, and Worker routing;
- archive excluded from reads;
- deterministic two-shard routing;
- drain while requests are active;
- duplicate-prefix rejection and explicit placement equivalence;
- direct SQL rejects duplicate per-surface authority, cross-surface authority,
  deletion of an authority placement or pinned binding revision, a cache
  publication watermark, and a cross-registry publication watermark;
- placement deletion cascades generic observations and same-registry
  publication watermarks only after authority references are removed;
- request-relative effective reads cover desired lifecycle/read selection,
  ready/degraded observation, complete versus shard policy, object presence,
  mutable publication watermark, and native/Worker parity;
- MySQL affected-row classification rereads authoritative state rather than
  relying on no-change row counts; and
- SQLite, Durable Object SQLite, PostgreSQL, and MySQL pass the same single-statement CAS and
  fault-injection fixtures.
- placement-policy builder mutations and publication CAS `build_version` on
  native transactions and Durable Object atomic batches; the shared stale-builder fixture
  proves no mutation can land after publication.

### Route cases

- Hub proxy, Hub redirect, public direct CDN, direct backend;
- external-auth and private-network declarations;
- several base paths on one delivery endpoint and longest-prefix match;
- omitted and explicit `/` route/gateway path defaults produce identical plans
  and derived URLs;
- Git/Nix-cache path and header conformance;
- range requests and conditional requests;
- canonical change without disabling old route;
- any route endpoint/target/access/capability update increments the
  configuration generation, invalidates old probe/access/direct evidence, and
  withholds healthy/canonical advertisement until exact-generation reprobe;
- endpoint origin or network-realm change requires a replacement endpoint and
  an impact-planned route/gateway move;
- explicit same-boundary revision movement creates a new endpoint generation,
  enumerates grants/routes/gateways/defaults, and rejects stale apply;
- gateway-generation grant/revoke and explicitly confirmed grant carry-forward
  preserve exact consumer-scope authorization;
- endpoint-generation grant/revoke and explicitly confirmed grant
  carry-forward preserve exact consumer-scope authorization and stale apply
  fails;
- storage-binding exact grant/revoke gates placements, gateways, and defaults;
  cross-scope and nonexistent bindings fail structurally on every backend;
- binding, boundary, endpoint-generation, and gateway-generation grant-pin
  acquisition versus revoke CAS has one winner on native databases and Durable Object SQLite;
  revoke rejects nonzero pins, preserves history, and regrant increments the
  grant generation so an old pin can never revive;
- stale/mismatched boundary revisions, degraded protection, trusted-ingress
  spoofing and verification, public versus protected cleartext, exact boundary
  grant/revoke, endpoint-generation moves, and local `AccessClass` fail closed
  identically in native/Worker and every database fixture;
- overlap rollout keeps old and new exact consumers eligible; `retiring`
  rejects new serving-pin acquisition while preserving verified old pins;
  serving-pin acquisition and retire CAS yield one winner on native databases
  and Durable Object SQLite; nonzero serving pins block
  final retirement; coordinated mode persists its acknowledged fail-closed
  window and crash-resumes without accepting the wrong revision;
- native/Worker authorization parity.

### Interface cases

- every Web UI action maps to the documented API method;
- every desired-state, policy, or destructive CLI mutation supports plan/apply
  and optimistic concurrency; idempotent observation/reconcile triggers return
  state or operation ids;
- stable `--json` golden output for every new command family;
- long operations have CLI watch and Web UI status parity;
- signed consumer changes report pending versus applied accurately;
- managed signed-stack projections reject dangling/cross-cache/partial
  cache-route pairs and configuration digest mismatches;
- a rendered-URL change creates, probes, and enables a replacement before its
  signed-stack commit/re-index, then moves canonical selection and disables and
  deletes the predecessor; crash-resume works after every transition, both URLs
  serve during overlap, disable/delete is blocked while the old route remains
  signed, and deletion leaves only the URL reservation plus redacted audit;
- URL reservation creation versus key rotation has one winner, recomputes the
  candidate under every retained key version, rejects reuse across rotations,
  and fails closed on key loss until backup restore on native databases and Durable Object SQLite;
- URL reservation vectors allow the same private IP/path in two distinct
  NetworkBoundary identity fingerprints but deny reuse of that IP/path in one
  boundary; deleting/recreating an identical typed boundary spec still denies
  reuse because its stable fingerprint is unchanged;
- each instance, organization, registry, and cache scope root renders Overview
  and activates the first navbar item;
- grouped navbar order is stable for every scope and permission class;
- canonical routes, the observed write-authority placement, and defaults sort
  before alternates; a desired pending candidate is visibly distinct;
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
- credential-bearing HTTP, private redirect, and local classification reject
  unknown, stale, mismatched, or degraded boundary observation;
- client-supplied trusted-ingress assertions never establish identity or local
  access, while the exact configured mTLS/assertion revision does;

### GC cases

- all current catalog versions, not only newest;
- current and partially rolled-out channel targets;
- latest-N verified release snapshots;
- immutable release-commit artifact sets despite later catalog change;
- complete zero-artifact snapshots versus missing/failed snapshots;
- release snapshot source/tag verification, exact row count, canonical metadata
  digest, one-time complete pointer, and terminal header/child immutability;
- exact and semver selectors;
- recent-release stable ordering/tie vectors, count bounds, prerelease flags,
  and canonical RFC-owned SemVer requirement grammar match native/Worker;
- multiple root reasons for one store hash;
- several registries sharing one cache;
- one registry contributing independently to several caches;
- a standalone cache with no registry-derived roots;
- root-refresh failure preserves previous roots;
- refresh retirement grace preserves parent generations;
- refresh staging is unreachable; stale parent pointer, selector/source
  revision, reason count, provenance, subscription version, or cache epoch
  cannot advance `current_refresh_id`;
- only the current unsuperseded/unrevoked lease head is active; renewal,
  revocation, expiry cutoff, and root deletion have deterministic races;
- cycles, diamond closures, shared NARs, and missing root/reference metadata;
- first absent mark starts `unreferenced_since`, repeated absence preserves it,
  and a new root or lease clears it;
- root refresh, manual pin/unpin, lease renewal/revocation near expiry,
  registry source advance, upload, population, reference replacement, scan,
  placement change, and
  concurrent double-apply each stale an older incompatible plan;
- every competing root/graph/inventory/topology/fence mutation and GC apply
  claims the same epoch row; native transactions and Durable Object atomic batches choose
  the same single winner and roll back partial tombstone/job creation;
- logical deletion across partial backend failure;
- complete replicas, shards, archives, partial tiers, and off-policy observed
  copies receive the correct logical-deletion action set;
- narinfo deletion precedes NAR deletion at every placement, with differing
  per-placement shared-NAR refcounts;
- abandoned narinfo leaves dependent NAR blocked; global active-job uniqueness,
  exact-match reuse, and success/abandon byte sums cannot double count;
- backend timeout/5xx, credential revocation, ETag mismatch, not-found after a
  worker crash, DB failure after backend delete, retry exhaustion, and audited
  abandonment are idempotent and account bytes correctly;
- rooted closure over cap remains intact;
- direct-route missing access telemetry changes only eviction order;
- plan actor/scope/expiry/confirmation mismatch rejects; public anonymous
  readers cannot inspect root actors or deletion jobs; and
- native/Worker plus SQLite, Durable Object SQLite, PostgreSQL, and MySQL fixtures produce the
  same guarded-apply and job-transition outcomes.

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

The steady-state repository also contains no legacy cache-link/root tables,
single-placement cache writer, binding/prefix NAR refcount, DB-first sweep,
synchronous dry-run branch, old GC protobuf/messages/routes, old CLI variants,
or `/links`, `/pins`, `/gc`, pin, link, or unlink Web handlers. The preflight
transformer may read those inputs only before the maintenance cutover and is
then removed.
