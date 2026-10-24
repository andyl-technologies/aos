//! Exercises real bounded mutex admission without a Main or native provider.
//!
//! These components use actual supervision and mutex ownership. They issue no
//! Source, World, Target or prepared-native token and cannot qualify native birth.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
};

fn supervisor() -> HostOperationSupervisor {
    HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )
    .expect("finite mechanism supervision")
}

#[test]
fn held_host_refuses_the_same_canceled_preparation_and_observes_post() {
    let host = Mutex::new(73_u64);
    let held = host.lock().unwrap();
    let allocation = std::ptr::from_ref(&*held);
    let supervisor = supervisor();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let identity = original.status().unwrap().operation_id;
    supervisor.cancel().unwrap();

    let observed = acquire_host(&host, &original);

    assert!(observed.host.is_err());
    let Some(AdmissionFirst::Original(first)) = observed.first else {
        panic!("the same canceled Original must refuse before host entry");
    };
    assert_eq!(observed.post, Err(first));
    assert_eq!(original.status().unwrap().operation_id, identity);
    assert_eq!(std::ptr::from_ref(&*held), allocation);
    assert_eq!(*held, 73);
    drop(held);

    // Reobserving the terminal operation cannot enter another Preparation or
    // make the now-available host usable under a replacement clock.
    let again = acquire_host(&host, &original);
    assert!(again.host.is_err());
    assert_eq!(again.post, Err(first));
    assert_eq!(original.status().unwrap().operation_id, identity);
    assert_eq!(*host.try_lock().unwrap(), 73);
}

#[test]
fn successful_acquisition_retains_the_same_host_and_original_operation() {
    let host = Mutex::new(81_u64);
    let allocation = std::ptr::from_ref(&*host.lock().unwrap());
    let supervisor = supervisor();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let before = original.status().unwrap();

    let observed = acquire_host(&host, &original);

    assert!(observed.first.is_none());
    assert_eq!(observed.post, Ok(()));
    let held = observed.host.unwrap();
    assert_eq!(std::ptr::from_ref(&*held), allocation);
    assert_eq!(*held, 81);
    assert!(host.try_lock().is_err());
    let after = original.status().unwrap();
    assert_eq!(after.operation_id, before.operation_id);
    assert_eq!(after.class, HostOperationClass::Preparation);
    assert_eq!(after.state, HostOperationState::Running);
    drop(held);
    original.complete().unwrap();
}

#[test]
fn negative_post_releases_only_the_acquired_mutex_before_entry() {
    let host = Mutex::new(97_u64);
    let supervisor = supervisor();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let held = host.try_lock().unwrap();
    let allocation = std::ptr::from_ref(&*held);
    supervisor.cancel().unwrap();

    // This is the genuine acquisition-post helper, with the actual guard that
    // was acquired before cancellation. No constructor has been invoked.
    let observed = observe_acquisition(Ok(held), None, &original);

    assert!(observed.host.is_err());
    assert!(observed.first.is_none());
    assert!(observed.post.is_err());
    let held = host
        .try_lock()
        .expect("refused pre-entry post returned its mutex");
    assert_eq!(std::ptr::from_ref(&*held), allocation);
    assert_eq!(*held, 97);
}

#[test]
fn initiating_custody_failure_and_actual_post_remain_independent() {
    let host = Mutex::new(101_u64);
    let supervisor = supervisor();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let first = QemuVmRealizationError::ExecutorUnavailable {
        operation: "mechanism acquisition refusal",
        message: String::from("same retained initiating allocation"),
    };
    let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &first else {
        unreachable!();
    };
    let allocation = message.as_ptr();
    supervisor.cancel().unwrap();

    let observed = observe_acquisition::<u64>(Err(first), Some(AdmissionFirst::Custody), &original);

    let QemuVmRealizationError::ExecutorUnavailable { message, .. } = observed.host.unwrap_err()
    else {
        panic!("the actual initiating refusal was replaced by the post");
    };
    assert_eq!(message.as_ptr(), allocation);
    assert!(matches!(observed.first, Some(AdmissionFirst::Custody)));
    assert!(observed.post.is_err());
    assert_eq!(*host.try_lock().unwrap(), 101);
}

#[test]
fn contended_host_waits_under_the_same_original_then_acquires_the_same_allocation() {
    let host = Arc::new(Mutex::new(109_u64));
    let held = host.lock().unwrap();
    let original = Arc::new(supervisor().begin(HostOperationClass::Preparation).unwrap());
    let identity = original.status().unwrap().operation_id;
    let (waiting, entered_wait) = std::sync::mpsc::sync_channel(0);
    let worker_host = Arc::clone(&host);
    let worker_original = Arc::clone(&original);
    let worker = std::thread::spawn(move || {
        let mut signal = Some(waiting);
        let observed = acquire_host_with_wait(&worker_host, &worker_original, || {
            if let Some(signal) = signal.take() {
                signal.send(()).unwrap();
            }
            worker_original.wait_for_change()
        });
        assert!(observed.first.is_none());
        assert!(observed.post.is_ok());
        let acquired = observed.host.unwrap();
        assert_eq!(*acquired, 109);
        assert_eq!(worker_original.status().unwrap().operation_id, identity);
        assert_eq!(
            worker_original.status().unwrap().state,
            HostOperationState::Running
        );
    });

    // The real try-lock has refused before this handshake, while its SAME
    // Preparation stays Running. Returning the actual guard enables progress.
    entered_wait.recv().unwrap();
    assert_eq!(original.status().unwrap().operation_id, identity);
    assert_eq!(*held, 109);
    drop(held);
    worker.join().unwrap();
    assert_eq!(*host.lock().unwrap(), 109);
    original.complete().unwrap();
}
