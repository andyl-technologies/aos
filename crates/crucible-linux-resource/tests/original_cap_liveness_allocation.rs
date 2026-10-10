//! Observes healthy original-cap checks without operation or heap publication.
//!
//! Original supervisor construction and the model observer controls are outside
//! this component check; the actual liveness call is measured independently.

// crucible-lint: allow panic-shortcut -- fixture admission, healthy liveness and status-query errors deliberately fail this zero-allocation invariant.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_linux_resource::test_support::TestAllocationObserver;

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

#[test]
fn healthy_checks_add_no_allocation_or_operation() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(60)),
    )
    .unwrap();
    let child = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    assert!(root.operation_statuses().unwrap().is_empty());
    assert!(child.operation_statuses().unwrap().is_empty());

    let (result, counts) = TestAllocationObserver::count(|| {
        for _ in 0..64 {
            root.verify_original_live()?;
            child.verify_original_live()?;
        }
        Ok::<_, crucible_linux_resource::host_supervision::HostSupervisionError>(())
    });

    result.unwrap();
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(root.operation_statuses().unwrap().is_empty());
    assert!(child.operation_statuses().unwrap().is_empty());
}
