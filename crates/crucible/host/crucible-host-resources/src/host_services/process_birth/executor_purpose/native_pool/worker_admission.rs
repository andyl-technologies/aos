//! Admits permanent worker debt without waiting on another pool operation.
//!
//! Both retained-Main observations run outside the ledger lock. A failed post
//! retains any standing debit in the same canonical ledger, without renewing
//! its original or creating a replacement bank or failure owner.

use super::*;

pub(super) fn admit_worker_controls(
    ledger: &Mutex<PoolLedger>,
    bytes: u64,
    check: impl Fn() -> Result<(), ServiceBirthError>,
) -> Result<(), NativePoolRefusal> {
    check().map_err(|cause| NativePoolRefusal {
        cause,
        after: None,
        _retained: None,
        world_assignment_refused: false,
    })?;

    let result = ledger
        .try_lock()
        .map_err(|_| ServiceBirthError::policy("Main worker control ledger is busy or uncertain"))
        .and_then(|mut ledger| ledger.reserve_worker_controls(bytes));
    let after = check().err();
    match (result, after) {
        (Ok(()), None) => Ok(()),
        (Err(cause), after) => Err(NativePoolRefusal {
            cause,
            after,
            _retained: None,
            world_assignment_refused: false,
        }),
        (Ok(()), Some(after)) => Err(NativePoolRefusal {
            cause: ServiceBirthError::policy("Main worker control postcut refused"),
            after: Some(after),
            _retained: None,
            world_assignment_refused: false,
        }),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- pure ledger debt and real mechanism-Original controls issue no authenticated Main, native bank or Source.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::host_supervision::{HostOperationBudgets, HostOperationClass, HostOperationSupervisor};
    use std::cell::Cell;

    fn ledger() -> Mutex<PoolLedger> {
        Mutex::new(
            PoolLedger::new(
                HostResourceVector {
                    resident_peak_bytes: 1000,
                    backing_peak_bytes: 1000,
                    metadata_bytes: 200,
                    staging_bytes: 100,
                    cpu_slots: 4,
                    task_slots: 20,
                    file_descriptors: 64,
                    paging_io_slots: 10,
                },
                2,
                8,
                3,
            )
            .unwrap(),
        )
    }

    #[test]
    fn contended_debit_preserves_same_ledger_and_independent_original_post() {
        let ledger = ledger();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let calls = Cell::new(0);
        let held = ledger.lock().unwrap();
        let initial = held.charged_resources();
        let report = admit_worker_controls(&ledger, 112, || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                supervisor.cancel().unwrap();
            }
            original
                .try_verify_unlent_preparation()
                .map_err(ServiceBirthError::from)
        })
        .unwrap_err();

        assert_eq!(calls.get(), 2);
        assert!(matches!(&report.cause, ServiceBirthError::Policy(message)
            if message == "Main worker control ledger is busy or uncertain"));
        assert!(
            matches!(&report.after, Some(ServiceBirthError::Supervision(actual))
            if *actual == original.wait_slice().unwrap_err())
        );
        assert_eq!(held.charged_resources(), initial);
        assert!(!report.world_assignment_was_refused());
        drop(held);
        assert!(ledger.try_lock().is_ok());
    }

    #[test]
    fn refused_post_keeps_the_actual_once_only_permanent_debit() {
        let ledger = ledger();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let calls = Cell::new(0);
        let report = admit_worker_controls(&ledger, 112, || {
            // Acquiring this exact lock proves neither boundary runs under it.
            assert!(ledger.try_lock().is_ok());
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                supervisor.cancel().unwrap();
            }
            original
                .try_verify_unlent_preparation()
                .map_err(ServiceBirthError::from)
        })
        .unwrap_err();

        assert_eq!(calls.get(), 2);
        let charged = ledger.lock().unwrap().charged_resources();
        assert_eq!(charged.metadata_bytes, 120);
        assert_eq!(charged.resident_peak_bytes, 120);
        assert!(matches!(
            report.after.as_ref(),
            Some(ServiceBirthError::Supervision(_))
        ));
        assert!(ledger.lock().unwrap().reserve_worker_controls(1).is_err());
        assert_eq!(ledger.lock().unwrap().charged_resources(), charged);
        assert!(!report.world_assignment_was_refused());
    }

    #[test]
    fn refused_prefix_has_no_debit_and_success_uses_the_same_original_twice() {
        let ledger = ledger();
        let initial = ledger.lock().unwrap().charged_resources();
        let first = String::from("actual retained Main prefix refused");
        let pointer = first.as_ptr();
        let first = std::cell::RefCell::new(Some(first));
        let report = admit_worker_controls(&ledger, 112, || {
            Err(ServiceBirthError::Policy(
                first.borrow_mut().take().unwrap().into(),
            ))
        })
        .unwrap_err();
        let ServiceBirthError::Policy(first) = &report.cause else {
            panic!("same first");
        };
        assert_eq!(first.as_ptr(), pointer);
        assert!(report.after.is_none());
        assert_eq!(ledger.lock().unwrap().charged_resources(), initial);

        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let calls = Cell::new(0);
        admit_worker_controls(&ledger, 112, || {
            assert!(ledger.try_lock().is_ok());
            calls.set(calls.get() + 1);
            original
                .try_verify_unlent_preparation()
                .map_err(ServiceBirthError::from)
        })
        .unwrap();
        assert_eq!(calls.get(), 2);
        original.wait_slice().unwrap();
        assert!(ledger.lock().unwrap().reserve_worker_controls(1).is_err());
    }
}
