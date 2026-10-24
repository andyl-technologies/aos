//! Exercises retained capability admission and its original account lifetime.

use super::SessionLifetimeRetention;
use crucible_control_api::admitted_output::test_support::tracked_fixture_budget;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Capability {
    used: Arc<AtomicU64>,
    minimum_credit: u64,
    destroyed_with_credit: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Capability {
    fn drop(&mut self) {
        self.destroyed_with_credit.store(
            self.used.load(Ordering::SeqCst) >= self.minimum_credit,
            Ordering::SeqCst,
        );
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn admitted_retention_requires_current_account_and_refuses_exhausted_credit()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(SessionLifetimeRetention::try_new_admitted([0_u8; 64]).is_err());

    let (budget, used) = tracked_fixture_budget(4096)?;
    let scope = budget.enter();
    let before = used.load(Ordering::SeqCst);
    assert!(SessionLifetimeRetention::try_new_admitted([0_u8; 8192]).is_err());
    assert_eq!(used.load(Ordering::SeqCst), before);
    drop(scope);
    drop(budget);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn admitted_retention_keeps_original_credit_through_capability_destruction()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = tracked_fixture_budget(4096)?;
    let destroyed_with_credit = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let scope = budget.enter();
    let minimum_credit = used.load(Ordering::SeqCst) + std::mem::size_of::<Capability>() as u64;
    let retention = SessionLifetimeRetention::try_new_admitted(Capability {
        used: used.clone(),
        minimum_credit,
        destroyed_with_credit: destroyed_with_credit.clone(),
        dropped: dropped.clone(),
    })?;
    assert!(used.load(Ordering::SeqCst) >= minimum_credit);

    drop(scope);
    drop(budget);
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(used.load(Ordering::SeqCst) > 0);
    drop(retention);

    assert!(dropped.load(Ordering::SeqCst));
    assert!(destroyed_with_credit.load(Ordering::SeqCst));
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}
