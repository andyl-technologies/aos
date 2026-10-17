//! Observes covered service/binder controls under their original credit.
//!
//! The test-only lower allocator owns the raw boundary; this module borrows
//! private original accounting without exposing a production ownership getter.

use super::*;
use crucible_linux_resource::test_support::TestAllocationObserver;

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

fn exact_config(publication: BinderPublication) -> Config {
    let mut authored = config();
    let projects = usize::try_from(authored.resources.file_descriptors / 2)
        .unwrap_or_else(|error| panic!("fixture project capacity: {error}"));
    authored.resources.metadata_bytes = quota_bootstrap_bytes(publication)
        .unwrap_or_else(|error| panic!("original structure: {error}"))
        + quota_constructor_bytes(projects)
            .unwrap_or_else(|error| panic!("original constructor: {error}"));
    authored
}

#[test]
fn last_private_service_control_closes_before_its_original_constructor_credit() {
    let (binder, control) = TestAllocationObserver::capture(
        arc_allocation_bytes::<QuotaService>()
            .unwrap_or_else(|error| panic!("service control layout: {error}")),
        || {
            exact_config(BinderPublication::Value)
                .build()
                .unwrap_or_else(|error| panic!("original service admission: {error}"))
        },
    );
    let metadata = binder.service.metadata.clone();
    let last = binder.clone();
    drop(binder);
    let (_, retained) = TestAllocationObserver::observe(
        &metadata,
        control.unwrap_or_else(|| panic!("service control must be observed")),
        || drop(last),
    );

    assert_eq!(retained, Some(metadata.maximum_resident_bytes()));
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}

#[test]
fn opaque_graph_control_closes_before_its_original_binder_and_service_credit() {
    let authored = exact_config(BinderPublication::Graph);
    let binder = LinuxProjectQuotaBinder::construct(
        authored.budgets,
        authored.outer,
        authored.resources,
        BinderPublication::Graph,
    )
    .unwrap_or_else(|error| panic!("original graph service: {error}"));
    let metadata = binder.service.metadata.clone();
    let (handle, control) = TestAllocationObserver::capture(
        StorePhysicalQuotaBinderHandle::allocation_bytes::<LinuxProjectQuotaBinder>()
            .unwrap_or_else(|error| panic!("graph control layout: {error}")),
        || StorePhysicalQuotaBinderHandle::new(binder),
    );
    let last = handle.clone();
    drop(handle);
    let (_, retained) = TestAllocationObserver::observe(
        &metadata,
        control.unwrap_or_else(|| panic!("graph control must be observed")),
        || drop(last),
    );

    assert_eq!(retained, Some(metadata.maximum_resident_bytes()));
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}

#[test]
fn ordinary_graph_arc_is_a_causal_counterexample_for_original_body_credit() {
    let authored = exact_config(BinderPublication::Graph);
    let binder = LinuxProjectQuotaBinder::construct(
        authored.budgets,
        authored.outer,
        authored.resources,
        BinderPublication::Graph,
    )
    .unwrap_or_else(|error| panic!("original graph service: {error}"));
    let metadata = binder.service.metadata.clone();
    let (old, control) = TestAllocationObserver::capture(
        arc_allocation_bytes::<LinuxProjectQuotaBinder>()
            .unwrap_or_else(|error| panic!("old graph control layout: {error}")),
        || Arc::new(binder),
    );
    let (_, retained) = TestAllocationObserver::observe(
        &metadata,
        control.unwrap_or_else(|| panic!("old control must be observed")),
        || drop(old),
    );

    assert_eq!(
        retained,
        Some(
            quota_bootstrap_bytes(BinderPublication::Graph)
                .unwrap_or_else(|error| panic!("original structure: {error}"))
        )
    );
    assert!(retained.is_some_and(|bytes| bytes < metadata.maximum_resident_bytes()));
}

#[test]
fn valid_borrower_unwind_closes_private_service_control_before_refund() {
    let (binder, control) = TestAllocationObserver::capture(
        arc_allocation_bytes::<QuotaService>()
            .unwrap_or_else(|error| panic!("service control layout: {error}")),
        || {
            exact_config(BinderPublication::Value)
                .build()
                .unwrap_or_else(|error| panic!("original service admission: {error}"))
        },
    );
    let metadata = binder.service.metadata.clone();
    let (result, retained) = TestAllocationObserver::observe(
        &metadata,
        control.unwrap_or_else(|| panic!("service control must be observed")),
        || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _borrower = binder;
                panic!("intentional borrower unwind after completed publication");
            }))
        },
    );

    assert!(result.is_err());
    assert_eq!(retained, Some(metadata.maximum_resident_bytes()));
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}
