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

Runtime latency on a deployed Worker and authenticated browser rendering have
not been measured. No browser automation harness is available in this
workspace; HTTP console tests and WebAssembly compilation do not establish
visual behavior. The read/query changes are structural improvements, not
production latency benchmarks.

The schema additions use the existing migration ledger and require no reset.
The route-list continuation token is now a stable route-ID cursor; callers
must start a fresh listing after the cutover. Provider accounts and CDN
attachments remain external prerequisites, and no live deployment or database
reset was performed.
