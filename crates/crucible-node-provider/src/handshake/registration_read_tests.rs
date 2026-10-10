//! Exercises original gate identity, contention and actual epoch revocation.

use super::*;

#[test]
fn original_epoch_revocation_and_foreign_gate_refuse() -> Result<(), ProviderError> {
    let gate = Arc::new(Mutex::new(()));
    let current = Arc::new(AtomicU64::new(7));
    let original = RegistrationRead {
        gate: Arc::clone(&gate),
        current: Arc::clone(&current),
        original: 7,
    };
    let same = RegistrationRead {
        gate: Arc::clone(&gate),
        current: Arc::clone(&current),
        original: 7,
    };
    let foreign = RegistrationRead {
        gate: Arc::new(Mutex::new(())),
        current: Arc::clone(&current),
        original: 7,
    };

    original.ensure_current()?;
    assert!(original.same_original(&same));
    assert!(!original.same_original(&foreign));

    current.store(8, Ordering::Release);
    assert!(original.ensure_current().is_err());
    assert!(same.ensure_current().is_err());
    Ok(())
}

#[test]
fn held_original_registration_gate_refuses_without_waiting() -> Result<(), ProviderError> {
    let gate = Arc::new(Mutex::new(()));
    let original = RegistrationRead {
        gate: Arc::clone(&gate),
        current: Arc::new(AtomicU64::new(7)),
        original: 7,
    };
    let held = gate
        .lock()
        .map_err(|_| ProviderError::Correlation("synthetic original gate setup poisoned"))?;

    assert!(original.ensure_current().is_err());
    drop(held);
    original.ensure_current()
}
