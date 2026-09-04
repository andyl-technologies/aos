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
- Existing canonical deep links remain usable. Settings and advanced views
  read the same authoritative configuration.

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
- Console correctness/presentation, backend read models, and independent
  validation are being developed in isolated checkouts.

## Validation record

Pending baseline and implementation checks. Runtime latency and authenticated
browser behavior have not yet been measured; source-level findings are not
production benchmarks.
