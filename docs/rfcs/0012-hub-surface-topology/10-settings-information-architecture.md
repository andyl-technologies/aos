# Settings Web UI information architecture

This document defines one settings system for instance administration,
organizations, registries, and binary caches. It preserves the current visual
language—paper-like content, thin rules, compact chips, plain forms, dense
legible tables, and no-JS operation—but replaces inconsistent navigation,
overloaded panels, and hidden topology relationships.

## Problems in the current UI

The current implementation already shares a sidebar renderer across scopes,
but the content hierarchy is not actually uniform:

- the organization default route renders Registries while Projects is the
  first navbar item;
- “General” means different things for registries and caches;
- registry “Serving & mirror” combines delivery routes with upstream registry
  mirroring;
- cache “Linked registries” combines relationships whose publication,
  retention, and population effects differ;
- cache “GC & pins” combines sweep mechanics, registry retention policy,
  manual root management, and run history;
- storage pages combine inventory, creation, origin credentials, delivery
  configuration, migration, and deletion;
- list pages frequently append large creation forms below the inventory;
- the organization nav mixes resources, people, infrastructure, automation,
  and audit without visible grouping;
- default/canonical resources are not consistently sorted first; and
- the same concept is called Storage, Serving, Frontend, or binding inheritance
  depending on the page where it appears.

The redesign changes information architecture and page ownership, not the
established visual identity.

## Shared settings shell

Every scope uses the same structural shell:

```text
breadcrumb

scope header
  type · name                         primary action / status
  concise purpose or canonical URL

settings workspace
  sectioned left nav | page header + summary strip     | optional context rail
                       primary content
                       secondary/advanced sections
```

### Scope header

The header's identity and chrome remain stable while navigating within a scope.
It contains:

- resource kind: Organization, Registry, or Binary cache;
- display name and stable slug;
- visibility/status chips where applicable;
- canonical endpoint or organization identity summary;
- one action slot whose page-appropriate action may change with the selected
  section, never a row of unrelated controls; and
- a View surface / Exit settings link for registries and caches.

The header does not repeat the selected navigation label. The page body begins
with the selected page's `<h1>` and one sentence explaining its responsibility.

### Three-column behavior

The default wide layout is:

```text
220px navigation | minmax(0, 1fr) primary content | 260px context rail
```

The context rail is optional. It holds topology context, health, documentation,
or impact summaries—not essential form fields. Pages without rail content let
the primary column use the available width.

At medium widths the rail moves below the primary content. At narrow widths the
navigation becomes a horizontally scrollable section bar followed by the page
content. Navigation order and labels do not change responsively.

Tables and topology diagrams may use a full-width breakout within the content
column. Forms retain a readable measure rather than stretching every input to
the viewport width.

## Navigation rules

### Default-first invariant

The first selectable navbar item is always the route reached by the scope's
settings/management root. Its key is `overview` and its label is **Overview**.
Exactly one item is active on every settings page.

This fixes the current organization mismatch rather than special-casing it:

```text
/-/org/{org}                 -> Overview, first item
/{registry}/-/settings       -> Overview, first item
/-/org/{org}/caches/{cache}  -> Overview, first item
/-/instance                  -> Overview, first item
```

### Stable group order

Scopes draw from the same superset group order:

1. Overview
2. Resources
3. Infrastructure or Topology
4. Content
5. Access & trust
6. Policy or Publishing
7. Appearance
8. Automation
9. Activity
10. Danger zone

Groups with no applicable items are omitted. Items never reorder based on
health, counts, permission, or recent use. Status belongs in a badge, not in
navigation position.

### Labels

Use concrete nouns:

- Overview, not General;
- Storage & replicas, not Storage when placements are meant;
- Delivery, not Serving or Frontends;
- Binary caches, not Caches in a registry context;
- Integrations, not Linked registries;
- Retention and Garbage collection as separate pages;
- Publish history, not Publishes; and
- Identity & access, not Settings.

### Permission behavior

A user who can read a section sees its navbar item. Write controls are omitted
or replaced with a concise permission notice. A section is hidden only when
the user cannot read its contents at all.

The nav does not produce dead links, and it never shows an item that will
respond with a generic forbidden page for the current principal.

#### Normative read-only role contract

The topology cutover defines the two read-only roles exactly:

- **Viewer** grants `read`, `storage_binding.read`, `placement.read`,
  `placement_policy.read`, `domain.read`, `network_boundary.read`,
  `delivery_endpoint.read`, `storage_gateway.read`, and `route.read`.
- **Developer** grants that exact Viewer set plus `tokens.self`.

Neither role grants a topology mutation, audit, credential, configuration, or
IAM verb. `storage_binding.read` exposes only binding identity, provider kind,
stable owner scope, resource version, and redacted health/backlinks. Its SQL and
API projections MUST NOT contain local root paths, object endpoints, buckets,
prefixes, signing regions, access modes, secret-version references, credential
fingerprints, or write-credential version references. Those values may be
queried and rendered only after `storage_binding.manage` succeeds.

### Nav metadata

Use restrained metadata only when actionable:

- count badges for pending operations or change requests;
- a warning dot for degraded delivery/placement health;
- no badge for ordinary inventory counts; and
- no success badges on every healthy item.

The active state remains the current accent rule/weight treatment. Group labels
are muted text, not additional clickable tabs.

## Common page anatomy

Every page follows the same vertical order:

1. Page title and one-sentence responsibility.
2. Optional notice or pending-operation banner.
3. Compact summary strip with two to five relevant facts.
4. Primary inventory, configuration, topology, or workflow.
5. Secondary details.
6. Advanced options in a native `<details>` section where appropriate.
7. Related links and audit provenance.

### One page, one primary job

A page may show related read-only context, but it owns one primary job. Avoid:

- inventory plus full creation form plus credential editor plus delete controls;
- current topology plus storage migration plus delivery configuration;
- GC policy plus retention selectors plus manual pins plus destructive run;
- consumer cache-stack editing plus cache creation; or
- identity settings plus resource deletion.

Creation and destructive workflows use dedicated pages:

```text
.../placements/new
.../delivery/new
.../domains/new
.../storage-bindings/new
.../integrations/new
.../danger
```

List pages use a `+ Add ...` primary link. Small inline operations such as
probe, refresh, retry, or reordering may stay near the affected row.

### Summary strips

Summary strips are read-only and use consistent fact order:

```text
identity/status -> canonical/default -> health -> usage -> pending work
```

They replace repeated explanatory prose and should link to the page that owns
each fact.

### Tables and cards

Use tables for comparable rows and stacked cards for long origins, credentials,
or topology nodes. Preserve the current compact table/card styling.

Row actions follow:

```text
row identity link | status/metadata | primary row action | overflow/secondary actions
```

Delete is never the default row action. When JavaScript is absent, secondary
actions appear as explicit text links rather than an inaccessible menu.

## Ordering rules inside pages

Default and canonical objects are always first:

- canonical route before alternate routes;
- observed authority placement before a different desired pending candidate,
  then other complete placements, shards, and archives;
- default storage binding before custom bindings;
- default gateway before alternates;
- current/active policy before historical revisions;
- pending or failed operations before completed history; and
- consumer cache-stack entries in actual signed evaluation order.

Within the same class, configured order wins where semantics exist; otherwise
sort by stable display name. Do not sort priorities lexically or reverse their
protocol meaning.

Each default/canonical row carries a text chip and a short reason:

```text
canonical · used in setup snippets
primary · observed write authority
writes blocked · authority or binding revision is not effectively writable
default · used when no binding is selected
```

## Organization settings

The organization is the ownership and infrastructure boundary. It owns
resources, reusable storage/network primitives, identities, trust, automation,
and audit. It does not edit a child registry's cache stack or a child cache's
retention policy directly.

### Navbar

```text
Overview

Resources
  Projects
  Registries
  Binary caches

Infrastructure
  Storage bindings
  Domains
  Network boundaries
  Delivery endpoints
  Storage gateways
  Topology defaults

Access & trust
  Identity & access
  Members
  SSO
  Signing keys
  Access tokens

Automation
  Webhooks

Activity
  Operations
  Audit log

Danger zone
```

### Overview

The organization root is no longer a Registry inventory masquerading as the
landing page. It shows:

- organization identity and member/owner status;
- resource counts and health exceptions;
- default storage binding and default domain/endpoint/gateway, if configured;
- pending operations/change requests;
- recent audit activity; and
- direct links to create a project, registry, or binary cache.

The Overview uses compact summary cards and exception lists. Complete resource
inventories live on their own pages.

### Projects, Registries, and Binary caches

Each resource list has the same shape:

- title, concise description, `+ Create` action;
- search/filter where inventory warrants it;
- identity, visibility, topology health, and relevant usage columns;
- row link to the resource's Overview; and
- no appended full creation form.

Creation uses dedicated `/new` pages with the same review/confirmation pattern.

### Storage bindings

The list shows the instance/deployment default first, followed by organization
bindings. It owns origin/API capability and credentials—not delivery routes.

Binding detail contains:

- origin/API endpoint, bucket/root, region, and credential purposes;
- exact consumer-scope grant generation/state, live-pin counts, revoked
  history, and affected topology;
- read capabilities and observed health;
- immutable binding-write revisions, credential-version references,
  validation, current default, and affected authority fan-out;
- placements using the binding, grouped by registry/cache;
- storage gateways using it; and
- capacity/usage.

Create, edit credentials, rotate credentials, and delete are separate
workflows. Rotation shows old/new revisions and per-authority reconciliation;
the old revision cannot be retired while any desired/observed authority pins
it. Delete first presents affected placements and cannot proceed while live
placements remain.
Grant/revoke is dual-scope plan/apply and cannot CAS an exact grant generation
to Revoked while a placement, gateway, or topology default holds its active
pin. Revoked tombstones and lifecycle events remain visible.

### Domains

The domain inventory shows DNS ownership, desired/observed DNS state,
certificate issuance, endpoint count, and affected runtime. Domain detail owns
verification, DNS, and certificate-provider reconciliation. It links to its
delivery endpoints but does not own listeners, route access, or placement
policy.

### Network boundaries

The boundary inventory shows stable realm identity, kind, desired default
revision, active/retiring revision count, authorized consumer scopes, endpoint
count, and last probe. Boundary detail has a per-revision table ordered Staged,
Active, Retiring, then Retired, with exact protection/trusted-ingress
verification, activation mode, active/revoked grant generation, serving-pin
count/version, probe provenance, and
impact links. It owns revision creation, probe/reconcile, overlap or coordinated
activation review/apply, consumer move plans, two-phase retirement, and grants.
Unknown, stale, or mismatched
observations are visibly ineligible for credential-bearing HTTP, trusted local
classification, and private redirects.
Retiring fences new consumers while listing and preserving eligible existing
verified pins until their explicit move plans complete.
The `instance:public` row is system managed: the UI exposes its observation,
fixed revision 1, and exact grants but no create, revise, transfer, rename, or
delete action. Probe/reconcile is observation-only.

### Delivery endpoints

The endpoint inventory shows exact rendered origin, DNS/IPv4/IPv6 host type,
effective port, ingress/network boundary, desired/observed listener and TLS
state, exact boundary revision, probe posture, active/revoked exact-generation
consumer grants with live-pin counts, and route count. Endpoint detail owns listener reconciliation, cleartext
acknowledgement, scope grants, and probes. Origin identity is immutable;
changing scheme, host, port, or realm starts a replacement-and-move workflow.
It never stores an opaque URL or storage origin. DNS endpoints link
back to their domain; IP endpoints explicitly show that DNS lifecycle does not
apply.
Endpoint generation plans show every exact grant and affected route; operators
confirm which grants are materialized for the replacement generation before
routes move.
Moving to another revision of the same boundary is an explicit endpoint
generation plan that also lists affected gateways and defaults; changing the
boundary identity still requires endpoint replacement.

### Storage gateways

The gateway list shows endpoint/client base path, binding, access posture,
origin prefix, exact-generation active/revoked grants with live-pin counts, and number of materialized
routes. Gateway detail owns a grant inventory/editor, previews the routes it
would materialize, and offers an explicit reconcile operation. Revision plans
show which grants carry forward and which routes move; a grant never silently
applies to a later generation.

### Topology defaults

Owns the organization's optional default storage binding, DNS domain, delivery
endpoint, and storage gateway used by creation workflows. Changing a default
has an impact plan but never retargets an existing placement or route. Overview
and infrastructure inventories display these values and link here; they do not
edit them inline.

### Identity & access

Owns the organization's editable display name and other non-identity profile
metadata. Stable organization id, slug, and owner scope are immutable after
creation. Member roles, SSO, signing keys, infrastructure, and deletion remain
on their dedicated pages; Overview only summarizes and links here.

### Members, SSO, and signing keys

These remain distinct because their permissions and risk differ. Member
invitation gets a dedicated workflow rather than a large form below the member
table. Signing-key usage shows which registries, caches, and channel purposes
pin each immutable generation before rotation or retirement.

SSO is itself split into two related resources. The organization owns one
redacted OIDC identity-provider configuration and any number of globally unique
email-domain claims. Provider credentials are sealed before immutable plan
persistence. Domain verification resolves the exact reviewed TXT challenge;
there is no operator-only database stamp or alternate verification path. Both
resources use exact revision plan/apply mutations in the Web UI, CLI, and API.

### Operations and audit

Operations is live/asynchronous work with progress and retry. Audit log is the
immutable record of completed and attempted control-plane changes. They are
adjacent but not combined.

The Operations page is one uniform scope-closure view at instance,
organization, registry, and cache levels. It resolves the page locator to an
immutable authorization scope, lists all descendant-owned operations, and
filters by the closed operation-state vocabulary. Expanded rows expose every
typed target snapshot, generation/digest evidence, progress, terminal error,
and exact resource version. Retry and cancellation are version-fenced explicit
confirmations. Organization Audit remains the durable event history and is not
folded into this live-work inventory.

## Registry settings

The registry owns its signed catalog, placements, delivery routes, consumer
cache stack, trust/access policy, and publishing workflow.

The public registry browse navbar is separate from settings navigation and is
ordered Overview, Packages, Releases, Channels, Images, Keys, then Settings
when authorized. **Images** is always discoverable for a readable registry and
opens `/{registry}/-/images`; private-registry authorization follows the same
visibility rules as other browse inventory.

### Navbar

```text
Overview

Topology
  Storage & replicas
  Delivery
  Binary caches

Access & trust
  Identity & access
  Signing keys
  Access tokens

Publishing
  Images
  Packages
  Upstream mirror
  Configuration
  Channels
  Change requests
  Publish history

Activity
  Operations & health

Danger zone
```

### Overview

Registry Overview answers:

- What is this registry and who can read it?
- What canonical Git, Nix-cache, and web endpoints should clients use?
- Are all required placements/routes healthy and current?
- Which binary caches do clients use?
- Is publication, coverage, or replication blocked?
- What operation or change request needs attention?

It contains a compact topology summary:

```text
signed registry
  -> canonical delivery route
  -> placement policy
  -> observed write authority + complete replicas

consumer cache stack
  -> managed/external endpoints
```

All nodes link to their owning settings pages. Overview has no full edit form.

### Storage & replicas

Owns placement inventory, presence/completeness, replication, promotion, drain,
and migration. Binding credentials remain on the organization binding page.

Above the inventory, a separate Write authority panel shows desired and
observed placement, topology/binding revisions, generations, reconciliation,
and effective Enabled or Blocked state. The observed authority is first; a
different desired candidate follows with Promotion pending. Other complete
placements, shards, and archives follow. Placement forms never edit primary or
write-enabled state. The page shows route impact of changing a placement, but
route editing remains on Delivery.

Add placement owns binding, prefix, kind (complete by default), initial active
or offline state, desired read selection/order, and a shard rule only for
shards. Archive defaults to read disabled. Edit placement owns only desired
active/offline state and read selection/order; Drain owns the draining
transition. Binding, prefix, kind, shard rule, observed fields, and authority
are not editable there.

### Delivery

Owns all simultaneous routes and canonical selection. Routes are grouped by
audience only when necessary; the default table shows one row per URL with Git,
cache, and web capability chips.

Canonical Git/cache/web routes appear first. “Serving & mirror” is removed:
upstream registry mirroring is not delivery and belongs on the separate
Upstream mirror page.

Route detail separates immutable URL identity from mutable target, access,
capability, observation, and canonical state. Editing fields whose normalized
result keeps the rendered URL opens the ordinary update impact plan. Editing
endpoint identity or base path opens **Replace route**, which creates a disabled
successor and presents a resumable progress rail: create, probe, enable, update
and re-index every signed cache-stack reference, move canonical audiences,
disable old, delete old. The old and new URLs are both shown throughout the
overlap, with blocking references and the next safe action. Closing/reopening
the page resumes the durable operation rather than drafting another successor.

For a direct route, access is displayed as read-only inherited gateway policy;
changing it links to creation of a new gateway revision and then a route update
or replacement. Delete is unavailable until the route is disabled,
non-canonical, absent from signed stacks, and free of live pins. Route history
links to the signed registry commit and redacted audit event after live
configuration rows are deleted.

### Upstream mirror

Owns the existing upstream registry source, synchronization posture, and source
health. It does not own client delivery routes. Moving this shipped feature out
of the combined page is a relocation, not a feature removal.

### Binary caches

Provides a read-only topology of the signed consumer cache stack and operational
cache integrations, using the two-view structure in
`09-interface-contracts.md`. Consumer publication, retention, and population
changes open their dedicated subresource workflows and produce independent
plans. This page does not create organization caches inline; `Select existing`
and `Create binary cache` link to the appropriate organization workflows and
return to the integration review.

### Identity & access

Owns name/description where SQL-backed, visibility, crawl policy, and access
impact. Signed registry metadata still changes through Configuration. The UI
distinguishes the two and never offers competing edits for the same field.

### Signing keys and access tokens

Signing keys own consumer trust and provider-custodied operations. Access
tokens own Hub API and upload credentials on the registry's immutable
authorization scope. They remain separate pages with cross-links where a
publishing operation needs both.

### Configuration, channels, change requests, and publish history

- Configuration edits signed registry content and creates/reviews changes.
- Channels operates rollout targets and partitions.
- Change requests shows pending/reviewed/applied configuration work.
- Publish history shows every durable release pipeline execution and its
  artifacts newest first. Operators select an incomplete exact session from
  this inventory to resume it; they do not need to preserve a publication id
  outside the Hub.

These pages share publication context but do not combine their forms or audit
histories into one overloaded panel.

### Operations & health

Combines live operational status only where it is useful to correlate route,
placement, coverage, and publication failures. It links to durable Audit at the
organization scope instead of duplicating a second audit system.

The page is backed by the registry's immutable authorization-scope closure,
not a slug-derived filter or a list of only registry-primary operations.

## Binary-cache settings

The binary cache owns its Nix namespace, placements, routes, content,
retention, GC, integrations, signing, and access posture.

### Navbar

```text
Overview

Topology
  Storage & replicas
  Delivery

Content
  Objects & closures
  Integrations

Access & trust
  Identity & access
  Signing keys
  Access tokens

Policy
  Retention
  Garbage collection

Activity
  Operations & health

Danger zone
```

### Overview

Cache Overview shows:

- stable canonical substituter URL and public key;
- visibility and compatible client setup snippets;
- object/byte usage;
- derived observed-authority/replica health, effective write state, and route
  health;
- registry coverage and retention freshness;
- last/next GC; and
- pending population, replication, or repair operations.

No storage, serving, GC-policy, and identity forms are stacked together.

### Storage & replicas and Delivery

These are structurally identical to the registry pages and use the same shared
components, columns, ordering, forms, and help text. Surface-specific
capabilities differ, but the interface grammar does not.

### Objects & closures

Owns search, narinfo/NAR inspection, closure graph, and per-placement presence.
Manual pin/unpin is an object action that opens a retention-impact review; the
pin inventory itself appears on Retention.

### Integrations

Replaces Linked registries. Its top-level matrix is read-only and has
independent columns for:

- used by registry consumers;
- retention source;
- population source; and
- measured coverage.

The same registry may participate in any combination. No generic linked state
is displayed. Each cell links to the consumer-publication, retention, or
population workflow that owns that mutation; coverage links to inspection and
repair. An integration review may preview several independent plans but never
applies them as one transaction.

### Retention

Owns registry subscriptions, selectors, root reasons, manual pins/leases,
refresh health, source revision, removal-grace lineage, and “why retained?”
explanation. Release selectors show snapshot completeness and channel
partition provenance. Manual roots and immutable lease history use stable ids.
It does not configure cache capacity or run deletion.

### Garbage collection

Owns logical TTL/capacity/schedule, GC plans, run history, quota breaches, and
placement-eviction links. A destructive run always follows a reviewed immutable
plan. Retention selectors are read-only context with a link back to Retention.

The collection page owns policy and plan creation. A plan detail page owns
review and guarded apply; a run detail page owns progress; and a deletion-job
detail owns retry or reviewed abandonment. The plan summary shows root,
object-graph, inventory, policy, and topology versions, coverage blockers,
`unreferenced_since`, and ordered per-placement narinfo/NAR actions. The run
summary distinguishes logical tombstones, confirmed reclaimed bytes, retrying
work, and administratively leaked bytes.

Before the first destructive sweep, the collection page offers a separate
plan/acknowledge flow bound to one valid reviewed GC plan. It shows that the
acknowledgement intentionally stales that plan and that a new plan is required
to run collection. Ordinary run confirmation and no-JS `--yes` equivalents do
not create this durable acknowledgement implicitly.

Placement eviction is linked from this page but edited under Storage &
replicas. A local tier quota never appears as permission to collect a logically
live object from the cache namespace.

### Identity & access, signing keys, and access tokens

Identity & access owns display name, visibility, Nix priority, compression,
mass-query behavior, and client-compatibility impact. Signing keys own narinfo
signing trust, rotation, and setup-snippet consequences. Access tokens own Hub
API credentials issued on the cache's immutable authorization scope. None of
these pages duplicates client-facing HTTP authorization, which remains an
independent property of every simultaneous delivery route.

## Instance settings

Instance administration shares the shell because it owns defaults and
infrastructure reused by organizations and surfaces. Its navbar is:

```text
Overview

Infrastructure
  Storage bindings
  Domains
  Network boundaries
  Delivery endpoints
  Storage gateways
  Topology defaults

Access & trust
  Identity & signup
  Access tokens

Policy
  Resource defaults

Appearance
  Branding

Activity
  Operations
```

The instance root is an operational Overview, not the current Signup & identity
form. Identity & signup owns signup policy, allowed domains, authentication
methods, and session lifetime. Access tokens owns deployment-scoped Hub API
credentials. Resource defaults owns new-surface crawl policy, upload limits,
and anonymous cache discovery defaults. Branding remains its own page. Instance
infrastructure pages use the same organization components and show which
organization resources inherit each default, including boundary protection
revisions, trusted-ingress verification, grants, and endpoint usage.
The instance Storage
bindings page represents the one deployment-provisioned default binding: it may
support origin/credential maintenance, but it cannot create, delete, or swap
the deployment binding. Instance Topology defaults selects optional domain and
endpoint/gateway defaults; its storage binding is the deployment singleton.

## Topological context and cross-links

Every topology page includes a small context rail with edge-labeled **Owns**,
**Uses**, and **Used by** sections. It never implies containment where the
domain model has a reference:

```text
Registry or binary cache
  owns -> Placement
  owns -> Delivery route

Placement
  uses -> Storage binding
  used by -> Placement policy

Delivery route
  uses -> Delivery endpoint
  uses -> Placement or placement policy
  direct mode uses -> Storage-gateway revision

Domain
  used by -> Delivery endpoint

Network boundary
  used by -> Delivery endpoint

Delivery endpoint
  used by -> Delivery route and storage-gateway revision

Storage gateway revision
  uses -> Delivery endpoint and Storage binding
  used by -> Direct delivery route

Storage binding
  used by -> Placement and Storage-gateway revision

Registry
  owns -> Consumer cache-stack entry
  entry uses -> Binary-cache delivery route

Binary cache
  owns -> Retention subscription
  subscription uses -> Registry release artifact sets
```

Each node has one primary settings owner. Cross-links never embed a second full
editor for the related resource.

## Shared components

Implement one component/data model for each repeated concept:

- settings shell, group heading, and nav item;
- scope header and summary strip;
- placement table/card and placement health;
- write-authority panel with desired/observed generations and binding revision;
- route table, route capability chips, and canonical marker;
- DNS-domain/certificate status and delivery-endpoint listener/TLS/probe status;
- cache integration matrix;
- operation status/progress;
- GC mark/plan review, placement-action progress, and deletion-job detail;
- impact-plan review;
- danger confirmation; and
- empty/error/permission states.

Registry and cache pages parameterize these components by `SurfaceRef`; they do
not fork HTML strings and drift in labels/order.

## Forms and progressive disclosure

Forms use the existing visual style. Improve hierarchy through structure:

- required/basic fields first;
- advanced backend/provider fields in `<details>`;
- credentials grouped by purpose;
- live computed URL/path preview after the relevant fields;
- validation adjacent to the affected field;
- one primary submit button with a precise verb; and
- impact review before high-consequence apply.

JavaScript may update previews and conditional fields. The server renders the
same valid defaults and validates the full state without JavaScript.

## Empty, loading, and degraded states

Every page names the absent object and next action:

```text
No delivery routes. Add a route to make this cache reachable.
No retention subscriptions. Only manual pins currently protect objects.
No complete GC mark. Run a retention refresh and full placement scan before
planning collection.
GC plan stale. Roots, object metadata, inventory, policy, or topology changed;
create a new plan.
No write authority. This surface is read-only until an eligible complete
placement is promoted.
Promotion pending. Writes are blocked until desired and observed generations
match; retry or review cancellation.
No replicas. The observed authority placement is the only current copy.
```

Do not use universal claims for empty sets. Degraded states keep the inventory
visible and place remediation beside the failing row.

## Accessibility

- Group labels use semantic headings/list structure inside the settings nav.
- The active item uses `aria-current="page"`.
- Status never relies on color alone.
- Keyboard focus order follows visible layout.
- Horizontally scrollable narrow navigation receives a label and visible focus.
- Tables have real headers and an alternate stacked presentation when needed.
- Operation progress has text state in addition to any visual bar.
- `<details>` summaries describe what is hidden.

## Acceptance criteria

- The root route for instance, organization, registry settings, and cache
  settings selects the first **Overview** navbar item.
- Navbar group and item order is deterministic and snapshot-tested for every
  scope and permission class.
- Canonical/default rows and the derived observed-authority placement are first
  and labeled in every inventory.
- Registry and cache placement/delivery pages render through the same shared
  components and column definitions.
- No list page contains a full create form; creation uses a dedicated page.
- No page owns more than one of placement, route, retention, GC, population,
  identity/access, or destructive deletion mutation domains.
- GC policy, immutable-plan review, operation progress, and job retry/abandon
  use distinct canonical resources even though they share the Garbage
  collection navbar owner.
- Organization Overview is a real overview rather than an alias for Registries.
- “General,” “Serving & mirror,” “Linked registries,” “GC & pins,” and
  “Frontend” do not appear in final canonical nav/help text.
- Wide, medium, and narrow layout snapshots cover long domains, endpoints,
  nested registry slugs, warning banners, and empty states.
- Every page works without JavaScript and exposes the same operations as the
  CLI/API permission model.
- Page titles, breadcrumb labels, nav labels, CLI nouns, and API resources use
  the same terminology.
