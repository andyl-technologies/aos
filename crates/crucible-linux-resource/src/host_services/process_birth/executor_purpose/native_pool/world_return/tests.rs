//! Checks shared return cuts with actual ledgers, local guards and kernel writes.
//!
//! These component fixtures cannot construct an authenticated Main or pool.
//! They exercise the same internal journal and postcut used by genuine loans
//! and canonical claims; public issuer-to-return qualification remains separate.

use super::super::{HostResourceVector, NativeNodeReservation, NativeWorldIdentity};
use super::*;
use crate::host_services::{HostServiceAllocator, HostServiceLease};
use crate::host_supervision::{HostOperationBudgets, HostOperationSupervisor};

fn selected(
    original: &Arc<HostOperationGuard>,
    window: HostServiceLease,
) -> (ledger::PoolLedger, u64) {
    let ceiling = HostResourceVector {
        resident_peak_bytes: 1024,
        metadata_bytes: 256,
        backing_peak_bytes: 1024,
        cpu_slots: 2,
        task_slots: 4,
        file_descriptors: 64,
        ..HostResourceVector::default()
    };
    let mut ledger = ledger::PoolLedger::new(ceiling, 2, 0, 0).unwrap();
    let (epoch, peak, tables) = ledger
        .assign(
            NativeWorldIdentity {
                owner: [1; 32],
                selection: [2; 32],
            },
            &[NativeNodeReservation {
                node: [3; 32],
                source_host_descriptors: 4,
                target_host_descriptors: 4,
                resources: HostResourceVector {
                    resident_peak_bytes: 128,
                    metadata_bytes: 32,
                    backing_peak_bytes: 128,
                    cpu_slots: 1,
                    task_slots: 2,
                    file_descriptors: 48,
                    ..HostResourceVector::default()
                },
            }],
            16,
            original,
        )
        .unwrap();
    assert_eq!((peak, tables), (8, 48));
    ledger.bind_window(epoch, window).unwrap();
    ledger.take_consumer(epoch).unwrap();
    (ledger, epoch)
}

fn fixture() -> (
    ledger::PoolLedger,
    u64,
    HostOperationSupervisor,
    Arc<HostOperationGuard>,
) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let window = HostServiceAllocator::new(1, 56, 1)
        .unwrap()
        .reserve_resources(0, 56, 0)
        .unwrap();
    let (ledger, epoch) = selected(&original, window);
    (ledger, epoch, supervisor, original)
}

#[test]
fn pending_body_preserves_original_identity_and_enters_no_cleanup() {
    let (ledger, epoch, supervisor, original) = fixture();
    let debt = ledger.charged_resources();
    assert!(matches!(
        prepare_return(&ledger, epoch, Some(&original)).unwrap(),
        ReturnStart::Observed(NativeWorldReturn::PendingBody)
    ));
    assert!(matches!(
        prepare_return(&ledger, epoch, None).unwrap(),
        ReturnStart::Observed(NativeWorldReturn::PendingBody)
    ));
    assert_eq!(ledger.charged_resources(), debt);
    assert!(ledger.saved_cleanup(epoch).is_err());
    assert!(Arc::ptr_eq(
        ledger.world_original(epoch).unwrap(),
        &original
    ));

    let foreign = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    assert!(prepare_return(&ledger, epoch, Some(&foreign)).is_err());
    assert!(ledger.saved_cleanup(epoch).is_err());
    assert!(ledger.world_original(epoch + 1).is_err());
    assert_eq!(ledger.charged_resources(), debt);
}

#[test]
fn shared_return_start_uses_the_retained_original_and_same_cleanup() {
    let (mut ledger, epoch, supervisor, original) = fixture();
    ledger.close_consumer(epoch).unwrap();
    let ReturnStart::Ready {
        original: retained,
        cleanup,
    } = prepare_return(&ledger, epoch, None).unwrap()
    else {
        panic!("ready exact World");
    };
    assert!(Arc::ptr_eq(&retained, &original));
    assert!(Arc::ptr_eq(&cleanup, &ledger.saved_cleanup(epoch).unwrap()));
    let foreign = Arc::new(
        supervisor
            .begin_control(HostOperationClass::Cleanup)
            .unwrap(),
    );
    assert!(ledger.verify_cleanup(epoch, &foreign).is_err());

    supervisor.cancel().unwrap();
    let ReturnStart::Ready {
        original: repeated,
        cleanup: saved,
    } = prepare_return(&ledger, epoch, Some(&original)).unwrap()
    else {
        panic!("same ready World");
    };
    assert!(Arc::ptr_eq(&repeated, &retained));
    assert!(Arc::ptr_eq(&saved, &cleanup));
    ledger.verify_cleanup(epoch, &saved).unwrap();
    assert!(
        original
            .verify_operation_class(HostOperationClass::Preparation)
            .is_err()
    );
}

#[test]
fn observation_refuses_contention_and_unissued_epochs() {
    let (ledger, epoch, _, _) = fixture();
    let ledger = Mutex::new(ledger);
    let borrowed = ledger.lock().unwrap();
    assert!(observe_returned(&ledger, epoch).is_err());
    assert!(borrow_unreturned_world(&ledger, epoch).is_err());
    let mut canonical = false;
    assert!(!observe_claim_returned(&ledger, epoch, &mut canonical));
    assert!(!canonical);
    drop(borrowed);
    assert!(!observe_returned(&ledger, epoch).unwrap());
    assert!(!observe_claim_returned(&ledger, epoch, &mut canonical));
    assert!(!observe_claim_returned(&ledger, 0, &mut canonical));
    assert!(!observe_claim_returned(&ledger, epoch + 1, &mut canonical));
    assert!(!canonical);
    assert!(observe_returned(&ledger, 0).is_err());
    assert!(observe_returned(&ledger, epoch + 1).is_err());
    assert!(borrow_unreturned_world(&ledger, 0).is_err());
    assert!(borrow_unreturned_world(&ledger, epoch + 1).is_err());
    let open = borrow_unreturned_world(&ledger, epoch).unwrap();
    assert!(open.saved_cleanup(epoch).is_err());
}

/// Runs inside the existing isolated descriptor helper after genuine setrlimit.
/// No synthetic Main, family witness, claim or cleanup loan is constructed.
pub(in super::super::super) fn check_real_kernel_world_return(
    original: Arc<HostOperationGuard>,
    window: HostServiceLease,
    close: impl FnOnce(&Arc<HostOperationGuard>) -> (Result<(), ServiceBirthError>, bool),
    expect_work_failure: bool,
    expect_consumed: bool,
) {
    let (mut ledger, epoch) = selected(&original, window);
    let charged = ledger.charged_resources();
    assert!(matches!(
        prepare_return(&ledger, epoch, Some(&original)).unwrap(),
        ReturnStart::Observed(NativeWorldReturn::PendingBody)
    ));
    assert!(ledger.saved_cleanup(epoch).is_err());
    ledger.close_consumer(epoch).unwrap();
    let ReturnStart::Ready {
        original: retained,
        cleanup,
    } = prepare_return(&ledger, epoch, None).unwrap()
    else {
        panic!("closed body is ready");
    };
    assert!(Arc::ptr_eq(&retained, &original));
    let ledger::WorldReturnPreparation::Ready {
        index,
        used,
        peak,
        tables,
    } = ledger.prepare_world_return(epoch).unwrap()
    else {
        panic!("exact return geometry");
    };
    assert_eq!((peak, tables), (8, 48));

    // The caller executes the real kernel return and may perturb only its own
    // readback/guard after the write. This is not a replacement success result.
    let (work, consumed) = close(&cleanup);
    assert_eq!(consumed, expect_consumed);
    assert_eq!(work.is_err(), expect_work_failure);
    let first = match &work {
        Err(ServiceBirthError::Policy(message)) => Some(message.as_ptr()),
        _ => None,
    };
    let mut returned = false;
    record_return(&mut ledger, epoch, index, used, consumed, &mut returned);
    assert_eq!(returned, expect_consumed);
    if consumed {
        assert_eq!(ledger.charged_resources(), used);
        assert_ne!(ledger.charged_resources(), charged);
    } else {
        assert_eq!(ledger.charged_resources(), charged);
    }
    let result = work.map(|()| NativeWorldReturn::Returned);
    let report = finish_return(result, &cleanup, returned).unwrap_err();
    assert_eq!(report.first_error().is_some(), expect_work_failure);
    assert!(report.post_error().is_some());
    if let Some(first) = first {
        assert!(
            matches!(report.first_error(), Some(ServiceBirthError::Policy(message))
            if message.as_ptr() == first)
        );
    }

    if !consumed {
        assert!(!ledger.observe_world_returned(epoch).unwrap());
        assert_eq!(ledger.charged_resources(), charged);
        assert!(Arc::ptr_eq(&cleanup, &ledger.saved_cleanup(epoch).unwrap()));
        assert!(ledger.verify_cleanup(epoch, &cleanup).is_err());
        let ledger = Mutex::new(ledger);
        let mut canonical = false;
        assert!(!observe_claim_returned(&ledger, epoch, &mut canonical));
        assert!(!canonical);
        return;
    }

    // This is the same observation used by the canonical claim and its Drop;
    // historical/post refusal does not justify another descriptor write.
    assert!(ledger.observe_world_returned(epoch).unwrap());
    assert!(matches!(
        prepare_return(&ledger, epoch, Some(&original)).unwrap(),
        ReturnStart::Observed(NativeWorldReturn::Returned)
    ));
    assert!(ledger.saved_cleanup(epoch).is_err());
    assert_eq!(ledger.charged_resources(), used);
    let ledger = Mutex::new(ledger);
    assert!(observe_returned(&ledger, epoch).unwrap());
    assert!(observe_returned(&ledger, epoch).unwrap());
    let mut canonical = false;
    // Actual consumption is known in the ledger while the canonical local
    // receipt is still false. A new loan must refuse before cloning its Arc.
    assert!(!canonical);
    assert!(borrow_unreturned_world(&ledger, epoch).is_err());
    assert!(observe_claim_returned(&ledger, epoch, &mut canonical));
    assert!(canonical);
    let borrowed = ledger.lock().unwrap();
    // The canonical observation latches actual return before later Drop. This
    // same predicate now needs no lock even while the real ledger is borrowed.
    assert!(observe_claim_returned(&ledger, epoch, &mut canonical));
    assert_eq!(borrowed.charged_resources(), used);
}
