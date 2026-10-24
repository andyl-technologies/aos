//! Binds Source assignment publication to its real private ledger primitive.
//!
//! These controls mutate inert accounting using a real mechanism Original;
//! they create no authenticated Main, Source, native claim or cleanup holder.

use super::*;
use std::cell::Cell;

fn original() -> Arc<HostOperationGuard> {
    let supervisor = crate::host_supervision::HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets::default(),
        None,
    )
    .unwrap();
    Arc::new(
        supervisor
            .begin(crate::host_supervision::HostOperationClass::Preparation)
            .unwrap(),
    )
}

fn identity() -> NativeWorldIdentity {
    NativeWorldIdentity {
        owner: [11; 32],
        selection: [13; 32],
    }
}

fn assert_unpublished(ledger: &PoolLedger, initial: HostResourceVector) {
    assert_eq!(ledger.used, initial);
    assert_eq!(ledger.next_world, 0);
    assert_eq!(ledger.next_assignment, 0);
    assert!(ledger.worlds.iter().all(Option::is_none));
    assert!(ledger.nodes.iter().all(Option::is_none));
}

#[test]
fn source_zero_controls_and_invalid_geometry_preserve_the_same_nominal_slot() {
    let original = original();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    let original_nominal = Box::new(29_u64);
    let pointer = std::ptr::from_ref(&*original_nominal);
    let mut nominal = Some(original_nominal);
    let mut callbacks = 0;

    assert!(
        ledger
            .assign_source(identity(), &requests(), 0, &original, || {
                callbacks += 1;
                drop(nominal.take());
            })
            .is_err()
    );
    assert_eq!(callbacks, 0);
    assert_eq!(std::ptr::from_ref(&**nominal.as_ref().unwrap()), pointer);
    assert_unpublished(&ledger, initial);

    let mut invalid = requests();
    invalid[1].node = invalid[0].node;
    assert!(
        ledger
            .assign_source(identity(), &invalid, 16, &original, || {
                callbacks += 1;
                drop(nominal.take());
            })
            .is_err()
    );
    assert_eq!(callbacks, 0);
    assert_eq!(std::ptr::from_ref(&**nominal.as_ref().unwrap()), pointer);
    assert_unpublished(&ledger, initial);
}

#[test]
fn publication_callback_precedes_every_debit_epoch_and_row_write() {
    let original = original();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    let callbacks = Cell::new(0);

    // Panic injection probes the infallible publication boundary in inert local
    // accounting. Production uses only the actual nonpanicking proof transfer.
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = ledger.assign_source(identity(), &requests(), 16, &original, || {
            callbacks.set(callbacks.get() + 1);
            panic!("stop immediately before publication");
        });
    }));

    assert!(stopped.is_err());
    assert_eq!(callbacks.get(), 1);
    assert_unpublished(&ledger, initial);
}

#[test]
fn source_birth_marks_body_issued_once_and_preserves_the_actual_original() {
    let original = original();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    let mut nominal = Some(Box::new(31_u64));
    let mut callbacks = 0;

    let (epoch, peak, tables) = ledger
        .assign_source(identity(), &requests(), 16, &original, || {
            callbacks += 1;
            drop(nominal.take());
        })
        .unwrap();

    assert_eq!(callbacks, 1);
    assert!(nominal.is_none());
    assert_eq!((epoch, peak, tables), (1, 26, 20));
    assert_eq!(ledger.next_world, epoch);
    assert_eq!(ledger.next_assignment, 2);
    let row = ledger
        .worlds
        .iter()
        .flatten()
        .find(|row| row.epoch == epoch)
        .unwrap();
    assert!(row.consumer_issued);
    assert!(!row.consumer_closed);
    assert!(!row.node_constructor_entered);
    assert!(Arc::ptr_eq(&row._original, &original));
    assert_eq!(ledger.used.metadata_bytes, initial.metadata_bytes + 80 + 16);
    assert!(ledger.take_consumer(epoch).is_err());
    let charged = ledger.used;
    assert!(
        ledger
            .assign_source(identity(), &requests(), 16, &original, || callbacks += 1)
            .is_err()
    );
    assert_eq!(callbacks, 1);
    assert_eq!(ledger.used, charged);
}

#[test]
fn inert_zero_body_primitive_keeps_its_original_closed_body_semantics() {
    let original = original();
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let (epoch, _, _) = ledger
        .assign(identity(), &requests(), 0, &original)
        .unwrap();
    let row = ledger
        .worlds
        .iter()
        .flatten()
        .find(|row| row.epoch == epoch)
        .unwrap();

    assert!(!row.consumer_issued);
    assert!(row.consumer_closed);
    assert!(ledger.take_consumer(epoch).is_err());
    assert!(ledger.close_consumer(epoch).is_err());
}

#[test]
fn actual_held_assignment_ledger_refuses_without_consuming_nominal_or_debit() {
    let ledger = std::sync::Mutex::new(PoolLedger::new(ceiling(), 2, 8, 3).unwrap());
    let held = ledger.lock().unwrap();
    let initial = held.used;
    let supervisor = crate::host_supervision::HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets::default(),
        None,
    )
    .unwrap();
    let original = Arc::new(
        supervisor
            .begin(crate::host_supervision::HostOperationClass::Preparation)
            .unwrap(),
    );
    let operation = original.status().unwrap().operation_id;
    let checks = Cell::new(0);
    let mut nominal = Some(Box::new(37_u64));
    let pointer = std::ptr::from_ref(&**nominal.as_ref().unwrap());

    let (result, after) = observe_world_attempt(
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                supervisor.cancel().unwrap();
            }
            original
                .wait_slice()
                .map(|_| ())
                .map_err(ServiceBirthError::from)
        },
        || {
            let mut ledger = borrow_world_control(&ledger, "actual held assignment ledger")?;
            ledger
                .assign_source(identity(), &requests(), 16, &original, || {
                    drop(nominal.take())
                })
                .map(|_| ())
        },
    );

    assert!(matches!(result, Err(ServiceBirthError::Policy(ref message))
        if message == "actual held assignment ledger"));
    assert_eq!(checks.get(), 2);
    assert!(matches!(after, Some(ServiceBirthError::Supervision(actual))
        if actual == original.wait_slice().unwrap_err()));
    assert_eq!(std::ptr::from_ref(&**nominal.as_ref().unwrap()), pointer);
    assert_unpublished(&held, initial);
    assert_eq!(original.status().unwrap().operation_id, operation);
    drop(held);
    assert!(ledger.try_lock().is_ok());
}
