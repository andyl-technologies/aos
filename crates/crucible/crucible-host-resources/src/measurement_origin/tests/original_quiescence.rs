//! Exercises real paired guards using the existing controlled origin fixture.
//!
//! The fixture does not authenticate PID1 or grant a native role. These controls
//! execute the published supervisor, actual eventfd and same-account custody.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use crate::host_services::{HostServiceAllocator, HostServiceBootstrap};
use crate::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationState, HostOperationSupervisor,
    HostSupervisionBootstrap, HostSupervisionError,
};

fn original() -> (
    HostServiceAllocator,
    HostServiceAllocator,
    HostOperationSupervisor,
    Arc<HostOperationGuard>,
) {
    let origin = super::mechanism_origin(Duration::ZERO, Duration::from_secs(60));
    let mut budgets = super::finite_budgets(Duration::from_secs(30));
    budgets.classes[HostOperationClass::Preparation as usize].total_timeout =
        Some(Duration::from_millis(100));
    budgets.classes[HostOperationClass::Preparation as usize].poll_interval =
        Duration::from_millis(1);
    budgets.classes[HostOperationClass::Quiescence as usize].poll_interval =
        Duration::from_millis(10);
    let bootstrap = HostSupervisionBootstrap::from_measurement_origin(origin, budgets).unwrap();
    let accounts = HostServiceBootstrap::new(1, 4, 1 << 20, 1 << 20)
        .unwrap()
        .reserve_structure(
            HostSupervisionBootstrap::structure_bytes().unwrap()
                + HostServiceBootstrap::control_bytes().unwrap(),
        )
        .unwrap();
    let (supervisor, preparation) = bootstrap.publish(&accounts).unwrap();
    let (resident, metadata) = accounts.publish();
    (resident, metadata, supervisor, Arc::new(preparation))
}

fn subscribe(pause: &HostOperationGuard, account: &HostServiceAllocator) -> OwnedFd {
    let event = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .unwrap();
    let credit = account
        .reserve_resources(
            0,
            1,
            HostOperationGuard::original_quiescence_cancellation_bytes(),
        )
        .unwrap();
    let duplicate = rustix::io::fcntl_dupfd_cloexec(&event, 3).unwrap();
    pause
        .retain_original_quiescence_cancellation(duplicate, credit)
        .unwrap();
    event
}

#[test]
fn later_pause_retains_exact_preparation_and_its_earlier_deadline() {
    let (account, _metadata, supervisor, preparation) = original();
    let retained = Arc::downgrade(&preparation);
    let pause = preparation.begin_original_quiescence().unwrap();
    assert!(pause.wait_slice().is_err());
    let _event = subscribe(&pause, &account);
    let parent_id = preparation.status().unwrap().operation_id;
    let parent_binding = supervisor.outer_cap_binding().unwrap();

    let basis = pause.serialize_original_quiescence_basis().unwrap();

    assert_eq!(&basis[16..48], &parent_binding.cap_id);
    assert_eq!(
        u64::from_be_bytes(basis[72..80].try_into().unwrap()),
        1_000_000
    );
    assert!(pause.wait_slice().unwrap() <= Duration::from_millis(1));
    let end = u64::from_be_bytes(basis[64..72].try_into().unwrap());
    // Quiescence allows thirty seconds, but the retained Preparation allows
    // only one tenth of a second. Its exported end cannot become thirty seconds.
    assert!(end < parent_binding.original_monotonic_ns + 1_000_000_000);
    assert_ne!(
        u64::from_be_bytes(basis[48..56].try_into().unwrap()),
        parent_id
    );
    drop(preparation);
    assert!(retained.upgrade().is_some());
    while pause.wait_for_change().is_ok() {}
    assert!(matches!(
        pause.wait_slice(),
        Err(HostSupervisionError::DeadlineExpired {
            operation_id: 1,
            class: HostOperationClass::Preparation,
        })
    ));
    assert!(pause.serialize_original_quiescence_basis().is_err());
    assert!(account.reserve_resources(0, 4, 1).is_err());
    drop(pause);
    assert!(retained.upgrade().is_none());
    assert!(account.reserve_resources(0, 4, 1).is_ok());
}

#[test]
fn actual_process_event_refuses_wait_progress_and_completion_without_consuming_it() {
    let (account, _metadata, _supervisor, preparation) = original();
    let pause = preparation.begin_original_quiescence().unwrap();
    let event = subscribe(&pause, &account);

    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();

    for outcome in [
        pause.wait_slice().map(|_| ()),
        pause.wait_for_change(),
        pause.progress(1),
        pause.complete().map(|_| ()),
    ] {
        assert!(matches!(
            outcome,
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            })
        ));
    }
    let mut bytes = [0; 8];
    assert_eq!(rustix::io::read(&event, &mut bytes).unwrap(), 8);
    assert_eq!(u64::from_ne_bytes(bytes), 1);
}

#[test]
fn ordinary_and_derived_preparations_cannot_issue_the_fixed_original_pause() {
    let ordinary =
        HostOperationSupervisor::new(super::finite_budgets(Duration::from_secs(1)), None).unwrap();
    let ordinary = Arc::new(ordinary.begin(HostOperationClass::Preparation).unwrap());
    assert!(ordinary.begin_original_quiescence().is_err());

    let (_account, _metadata, supervisor, preparation) = original();
    let child = supervisor
        .new_budget_owner(super::finite_budgets(Duration::from_secs(1)))
        .unwrap();
    let derived = Arc::new(child.begin(HostOperationClass::Preparation).unwrap());
    assert!(derived.begin_original_quiescence().is_err());
    let replacement = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    assert!(replacement.begin_original_quiescence().is_err());
    assert_eq!(preparation.status().unwrap().operation_id, 1);
}
