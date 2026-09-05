# Hub settings and delivery workflows

## Outcome

Operators can understand the effective configuration of an instance,
organization, registry, or cache and complete delivery setup without manually
coordinating unrelated resource editors. Advanced resource inspection and
editing remain available through the same authorized APIs.

The first complete workflow connects an existing CDN attachment to existing
storage. It owns reviewed intent, prerequisite checks, resumable progress,
verification, and activation. Provider-side actions that Hub cannot perform
are explicit prerequisites, with observed completion rather than optimistic
success. Existing working delivery remains selected until activation succeeds.

## Invariants

- Resource ownership and consumer grants remain explicit. Workflows never
  acquire authority unavailable to the caller.
- Routes, endpoints, gateways, policies, and storage retain their identities,
  immutable generations, version checks, and individual inspection surfaces.
- Every durable mutation uses reviewed plan/apply semantics. A browser draft
  change invalidates its reviewed plan.
- Provider operations are resumable and idempotent; they do not pretend to
  share a database transaction. Activation checks current verification and
  resource versions.
- Worker and native deployments share orchestration and authorization logic.
- Inventory reads are independent of optional editor prerequisites and bound
  their database work before expanding detail.
- Settings and advanced views read the same authoritative configuration.
  Superseded paths may be removed in a direct cutover; development databases
  may be reset instead of requiring compatibility migrations.

## Implementation sequence

1. Reproduce and fix shared-binding lookup, inventory scope, stale plan, and
   route-advertisement selection errors. Establish focused validation.
2. Define effective configuration and workflow contracts, reusing existing
   plans, operations, controller observations, and outbox machinery.
3. Implement the delivery workflow and effective Delivery page together,
   including interruption, retry, missing-grant, and verification failures.
4. Apply consistent scope headers, effective overviews, focused editors, and
   advanced inspection across instance, organization, registry, and cache.
5. Extend established workflow patterns to resource creation, cache
   integration, replicas, delivery changes, and infrastructure retirement.
6. Independently review, run appropriate hermetic checks, publish incremental
   commits, and open a pull request with precise validation evidence.

## Acceptance scenarios

- An organization consumes an explicitly granted instance-owned binding.
- Same-named bindings in different owners cannot select each other's storage.
- A viewer can inspect configuration without being offered unusable mutation
  controls.
- A changed draft or failed replacement plan cannot apply an older review.
- Audience selectors initially reflect the currently advertised route.
- An operator can leave and resume delivery setup with durable progress.
- Missing grants and external provider prerequisites identify the exact
  blocking action without widening authority.
- Failed verification cannot activate or advertise a replacement destination.
- Advanced resource edits appear in effective views and invalidate stale
  workflow assumptions.
- Settings inventories and selectors avoid repeated topology expansion and
  demonstrate bounded query behavior on representative fixtures.

## Progress

- Initial source review completed at `37a423e9e`.
- Implementation checkout: `dplecki/hub-settings-workflows`.
- Console correctness/presentation and backend read models were implemented
  and independently reviewed in isolated checkouts.
- Effective scope headers and instance, organization, registry, and cache
  overviews separate current configuration from editing.
- Delivery setup persists reviewed intent, child plans, verification
  operations, replay keys, and prerequisite versions. Activation checks
  current evidence and grants while switching all audiences atomically.
- Delivery shows selected URLs and their endpoint/storage relationships.
  Advanced editors remain available; their prerequisite reads are deferred
  until opened and shared within the page.
- Storage groups location creation and replica copying with guidance for
  authority changes and drain/deletion. Cache integrations distinguish client
  use, population, and retention.
- Shared-resource selectors retain exact owner identities and current
  grants. Route and scoped gateway inventories paginate in SQL before
  expanding details. Worker workflow requests use stable execution affinity.
- Changed drafts invalidate pending and in-flight reviews in delivery,
  storage, organization profile, instance settings, and cache policy editors.

## Validation record

Checks use the AOS development toolchain. The console and Worker pass
WebAssembly compilation. Focused native tests pass for delivery workflow
replay and activation (10), scoped SQL route pagination (1), Worker request
affinity (2), CLI argument boundaries (3), the complete retained-control API
foundation (21), console contracts (27), native console HTTP integration
(6), and shared-infrastructure HTTP authorization (1): 71 tests in total.

Changed code passes formatting checks. A workspace-wide format check also
reports existing differences in `crates/aos-hub-core/src/db/oci_gc/plan.rs` and
`crates/aos/src/commands/build.rs`; those unrelated files were left unchanged.

Follow-up local verification uses `tests/native/hub-settings.py` to launch a
real native Hub process with fresh state and compiled console assets. Its 29
checks pass over TCP, including reviewed setup, incorrect confirmation,
explicit credentials with stale profiles, replay, process restart, concurrent
resume, blocked activation, and wrong-kind activation-plan rejection without
fabricated controller observations.
The same test is registered as `checks.vm.hub-settings`. At `dc731de33`,
the Firecracker/KVM VM passed all 29 checks with `TEST_RESULT:PASS` and exit 0.
Its hermetic package prerequisite passed 3,709 tests, with 5 skipped. Later
production changes affect console callback lifetime, refresh, and narrow-layout
CSS, covered separately
by the final browser run.

The real Chrome driver in `tests/native/hub-settings-browser.py` exercises
rendered login and settings pages, guided delivery review, stale-draft
invalidation, advanced controls, repeated workflow resume/remount, browser
history, and response completion after navigating away. It records
desktop/narrow screenshots,
JavaScript errors, and nonsecret request timings. The final run at
`3b9801a90` passed all 76 checks with no skips, JavaScript exceptions, console
errors, or failed requests. All six narrow captures stayed at 390px; the
12 desktop/narrow screenshots were visually reviewed. The final console
distribution matches the assets embedded in the tested native executable.

This verification found and corrected an unconsumed endpoint probe operation,
unnecessary refresh of unrelated CLI credentials, and initially expanded
mobile navigation. Domain verification now uses the consumed controller path;
its failure/retry regression passes with the full delivery suite (11 tests).
The updated console contract suite passes all 28 tests. Provider probe editors
are multiline, and the registry overview links directly to Containers. Disabled
container GC diagnostics load only when their advanced section is opened.
Browser resume exposed disposed reactive state during same-page replacement;
workflow refresh now remounts keyed content within the persistent settings
shell, while application-owned navigation state survives. Different settings
routes also use keyed shells to avoid reusing disposed page state. Refresh
defers disposal until mutation callbacks and queued reactive updates settle.
Changed settings callbacks use an owner-free cancellation registry that closes
when their page is disposed; the selected container editor has its own scope.
Mutation navigation also defers unmount until callback cleanup finishes.
Main workflow steps show status and blockers, with resource IDs kept in
advanced inspection.
Console asset staging also preserves rebuildability when inputs are read-only
Nix store files. The full package gate caught stale migration-count assertions
and missing CLI coverage registration. The packaged source filter now includes
the executable native harness required by that coverage check.

Delivery topology now selects active operations through scoped SQL primary
and secondary target matching, eliminating per-operation remote reads for
unrelated tenants and correcting placement identity matching.

The read/query changes are structural improvements, not deployed Worker
latency benchmarks. Full topology still expands each route and placement.
The local fixture measured six topology reads at about 12 ms each; this is
not representative of deployed Worker state. Its remaining read cost should
be measured with authenticated Worker request and SQL diagnostics against
representative state. Unauthenticated staging
requests measure the login redirect, not authenticated delivery loading;
existing staging credentials were rejected, so no authenticated latency claim is made.

The schema additions use the existing migration ledger and require no reset.
The route-list continuation token is now a stable route-ID cursor; callers
must start a fresh listing after the cutover. Provider accounts and CDN
attachments remain external prerequisites. Local verification did not exercise
successful external CDN activation; staging deployment evidence follows.

Staging deployment verification (2026-09-05 UTC):

- Deployed source `f1a411c1d915163fca10d6eb41fffe3d5c101412` using immutable
  installer `/nix/store/ii0bqqhh53pa9drwzkif58mnczyc32gd-aos-hub-cloudflare-0.1.0`.
  The hosted deployment identity matches `staging-` plus that full commit.
- Cloudflare OAuth identified the ANDYL account. Live provider settings showed
  database instance `hub`, contrary to the earlier runbook's `hub-v2`. The old
  deployed source already used schema identity `aos-hub/topology-hard-cutover/2`;
  the update retained `hub`, existing domains, storage bindings, and secrets.
- Public registry and registry health return HTTP 200. Containers now redirects
  anonymous users to login instead of returning 404; Delivery also reaches login.
  Served console JavaScript, WebAssembly, and CSS match the packaged bytes.
- The old recovery endpoint returned 404, so no predeployment bookmark was
  captured. The new endpoint successfully captured a postdeployment bookmark
  for database `hub` and the verified deployment identity. No database reset or
  secret rotation was performed.
- Authenticated hosted workflow checks and Delivery latency remain pending:
  the separate Hub profile refresh still returns `invalid_grant`. Cloudflare
  authentication does not renew a Hub session. Local native/VM/browser evidence
  above remains the completed workflow verification.
