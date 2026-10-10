//! Measures actual bootstrap allocations and original unpublished coordinates.
//!
//! The shared safe observer records exact ordered allocator requests in a fixed
//! thread-local buffer. Tests reject overflow and any native reallocation.

use super::*;
use crate::host_services::{HostServiceBootstrap, HostServiceError};
use crate::test_support::{AllocationEvents, TestAllocationObserver};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

fn observe<T>(action: impl FnOnce() -> T) -> (T, AllocationEvents) {
    let (value, events) = TestAllocationObserver::capture_allocation_events(action)
        .unwrap_or_else(|error| panic!("original native event capture: {error}"));

    assert!(!events.overflow, "every original event must be captured");
    assert_eq!(
        events.reallocations, 0,
        "original requests do not reallocate"
    );

    (value, events)
}

fn budgets() -> HostOperationBudgets {
    HostOperationBudgets {
        classes: [HostOperationBudget::finite(Duration::from_secs(60)); HOST_OPERATION_CLASS_COUNT],
    }
}

fn charged_accounts() -> AdmittedHostServiceBootstrap {
    HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
        .unwrap_or_else(|error| panic!("original capacities: {error}"))
        .reserve_structure(
            HostSupervisionBootstrap::structure_bytes()
                .unwrap_or_else(|error| panic!("supervision geometry: {error}"))
                + HostServiceBootstrap::control_bytes()
                    .unwrap_or_else(|error| panic!("capacity geometry: {error}")),
        )
        .unwrap_or_else(|error| panic!("original structural charge: {error}"))
}

#[test]
fn both_original_counter_refusals_allocate_nothing() {
    for (resident, metadata) in [(143, 256), (512, 143)] {
        let (result, observation) = observe(|| {
            HostServiceBootstrap::new(1, 1, resident, metadata)
                .and_then(|original| original.reserve_structure(144))
        });

        assert!(matches!(result, Err(HostServiceError::CapacityExhausted)));
        assert_eq!(observation.count, 0);
    }
}

#[test]
fn original_supervisor_and_preparation_remain_unallocated_until_publication() {
    let ((original, slice), observation) = observe(|| {
        let mut original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
            .unwrap_or_else(|error| panic!("original supervisor: {error}"));
        let slice = original
            .wait_slice()
            .unwrap_or_else(|error| panic!("original preparation: {error}"));
        (original, slice)
    });

    assert_eq!(observation.count, 0);
    assert_eq!(slice, Duration::from_millis(10));
    assert_eq!(original.state.next_operation, 1);
    assert_eq!(original.preparation.completed, 0);
    assert_eq!(original.preparation.required, 1);
}

#[test]
fn publication_preserves_origin_identity_progress_and_operation_coordinates() {
    let mut original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
        .unwrap_or_else(|error| panic!("original supervisor: {error}"));
    original
        .wait_slice()
        .unwrap_or_else(|error| panic!("original preparation: {error}"));
    let started = original.started;
    let kernel_origin = original.original_monotonic_ns;
    let cap_id = original.state.cap_id;
    let operation_started = original.preparation.started;
    let progress = original.preparation.last_progress;
    let accounts = charged_accounts();
    let (supervisor, preparation) = original
        .publish(&accounts)
        .unwrap_or_else(|error| panic!("paid supervisor publication: {error}"));

    assert_eq!(supervisor.shared.started, started);
    assert_eq!(supervisor.shared.original_monotonic_ns, kernel_origin);
    assert_eq!(supervisor.shared.cap_id, cap_id);
    assert_eq!(preparation.id, 1);
    let state = supervisor
        .shared
        .state
        .lock()
        .unwrap_or_else(|error| panic!("original operation: {error}"));
    let operation = state
        .operations
        .get(&1)
        .unwrap_or_else(|| panic!("published original operation"));
    assert_eq!(state.next_operation, 1);
    assert_eq!(operation.started, operation_started);
    assert_eq!(operation.last_progress, progress);
    assert_eq!(operation.completed, 0);
    assert_eq!(operation.required, 1);
    assert_eq!(operation.state, HostOperationState::Running);
}

#[test]
fn exact_startup_requests_match_the_pinned_tree_and_control_geometry() {
    let original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
        .unwrap_or_else(|error| panic!("original supervisor: {error}"));
    let accounts = charged_accounts();
    let ((supervisor, preparation, resources, metadata), observation) = observe(|| {
        let (supervisor, preparation) = original
            .publish(&accounts)
            .unwrap_or_else(|error| panic!("paid supervisor publication: {error}"));
        let (resources, metadata) = accounts.publish();
        (supervisor, preparation, resources, metadata)
    });
    let expected = [
        arc_bytes::<Condvar>().unwrap_or_else(|error| panic!("condition control: {error}")),
        std::mem::size_of::<TreeLeaf<u64, (HostOperationBudgets, Option<Weak<Shared>>)>>(),
        arc_bytes::<Mutex<OuterAuthority>>()
            .unwrap_or_else(|error| panic!("outer control: {error}")),
        arc_bytes::<Shared>().unwrap_or_else(|error| panic!("supervisor control: {error}")),
        std::mem::size_of::<TreeLeaf<u64, Operation>>(),
        usize::try_from(
            HostServiceBootstrap::control_bytes()
                .unwrap_or_else(|error| panic!("account controls: {error}"))
                / 2,
        )
        .unwrap_or_else(|error| panic!("account extent: {error}")),
        usize::try_from(
            HostServiceBootstrap::control_bytes()
                .unwrap_or_else(|error| panic!("account controls: {error}"))
                / 2,
        )
        .unwrap_or_else(|error| panic!("account extent: {error}")),
    ];

    assert_eq!(observation.count, expected.len());
    for (event, bytes) in observation.entries().zip(expected) {
        assert!(event.allocated);
        assert_eq!(event.bytes, bytes);
        assert_eq!(event.alignment, 8);
    }
    eprintln!(
        "actual startup extents={expected:?}; fresh_token={} operation={} state={} source={} operation_leaf={} operation_internal={} roster_leaf={} roster_internal={} supervision_peak={}",
        std::mem::size_of::<HostSupervisionBootstrap>(),
        std::mem::size_of::<Operation>(),
        std::mem::size_of::<SupervisionState>(),
        std::mem::size_of::<HostDeadlineSource>(),
        std::mem::size_of::<TreeLeaf<u64, Operation>>(),
        std::mem::size_of::<TreeInternal<u64, Operation>>(),
        std::mem::size_of::<TreeLeaf<u64, (HostOperationBudgets, Option<Weak<Shared>>)>>(),
        std::mem::size_of::<TreeInternal<u64, (HostOperationBudgets, Option<Weak<Shared>>)>>(),
        HostSupervisionBootstrap::structure_bytes()
            .unwrap_or_else(|error| panic!("supervision peak: {error}"))
    );

    drop(preparation);
    drop(supervisor);
    drop(resources);
    drop(metadata);
}

#[test]
fn twelve_record_split_peak_matches_actual_leaf_and_root_requests() {
    let mut operations = BTreeMap::new();
    let ((), observation) = observe(|| {
        for id in 0..MAX_HOST_OPERATIONS {
            operations.insert(
                id as u64,
                Operation {
                    class: HostOperationClass::Preparation,
                    control: false,
                    started: Duration::ZERO,
                    last_progress: Duration::ZERO,
                    started_revision: 0,
                    completed: 0,
                    required: 1,
                    state: HostOperationState::Running,
                    startup_cancellation: None,
                },
            );
        }
    });

    let expected = [
        std::mem::size_of::<TreeLeaf<u64, Operation>>(),
        std::mem::size_of::<TreeLeaf<u64, Operation>>(),
        std::mem::size_of::<TreeInternal<u64, Operation>>(),
    ];
    assert_eq!(observation.count, expected.len());
    for (event, bytes) in observation.entries().zip(expected) {
        assert!(event.allocated);
        assert_eq!(event.bytes, bytes);
    }
}

#[test]
fn original_roster_refusal_precedes_invalid_outer_without_allocation() {
    let mut roster = budgets();
    roster.classes[HostOperationClass::Setup as usize] = HostOperationBudget::unlimited_quantum();
    let (result, observation) =
        observe(|| HostSupervisionBootstrap::new(roster, Some(Duration::ZERO)));

    assert!(matches!(
        result,
        Err(HostSupervisionError::UnboundedInfrastructure {
            class: HostOperationClass::Setup
        })
    ));
    assert_eq!(observation.count, 0);
}

#[test]
fn original_sticky_operation_failure_wins_expired_outer_during_unpublished_poll() {
    let mut original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
        .unwrap_or_else(|error| panic!("original supervisor: {error}"));
    original.preparation.state = HostOperationState::Canceled;
    original.state.cap_state = HostOperationState::Expired;
    let (result, observation) = observe(|| original.wait_slice());

    assert!(matches!(
        result,
        Err(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled
        })
    ));
    assert_eq!(original.preparation.state, HostOperationState::Canceled);
    assert_eq!(observation.count, 0);
}

#[test]
fn original_expired_preparation_keeps_its_identity_without_allocation() {
    let mut original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
        .unwrap_or_else(|error| panic!("original supervisor: {error}"));
    original.preparation.state = HostOperationState::Expired;
    let (result, observation) = observe(|| original.wait_slice());

    assert!(matches!(
        result,
        Err(HostSupervisionError::DeadlineExpired {
            operation_id: 1,
            class: HostOperationClass::Preparation
        })
    ));
    assert_eq!(observation.count, 0);
}

#[test]
fn publication_refuses_an_insufficient_admitted_original_token_before_any_control() {
    let original = HostSupervisionBootstrap::new(budgets(), Some(Duration::from_secs(60)))
        .unwrap_or_else(|error| panic!("original supervisor: {error}"));
    let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
        .unwrap_or_else(|error| panic!("original capacities: {error}"))
        .reserve_structure(
            HostServiceBootstrap::control_bytes()
                .unwrap_or_else(|error| panic!("original control geometry: {error}")),
        )
        .unwrap_or_else(|error| panic!("original structural charge: {error}"));
    let (result, observation) = observe(|| original.publish(&accounts));

    assert!(matches!(
        result,
        Err(HostSupervisionError::CapacityExhausted)
    ));
    assert_eq!(observation.count, 0);
}
