//! Exact-account alias checks and independent original first-refusal ordering.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
#[error("the captured original account closed")]
struct OriginalClosed;

struct Authority {
    resources: Arc<FixtureResourceBudget>,
    events: Arc<AtomicU64>,
    event: u64,
    allowed: AtomicBool,
    refusal: DecodeAdmissionError,
}

impl Authority {
    fn new(resources: Arc<FixtureResourceBudget>, events: Arc<AtomicU64>, event: u64) -> Arc<Self> {
        Arc::new(Self {
            resources,
            events,
            event,
            allowed: AtomicBool::new(true),
            refusal: DecodeAdmissionError::new(OriginalClosed),
        })
    }
}

fn record(events: &AtomicU64, event: u64) {
    events
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |before| {
            before.checked_mul(10)?.checked_add(event)
        })
        .unwrap();
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        record(&self.events, self.event);
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(self.refusal.clone())
        }
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.resources
            .reserve(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

fn original(authority: Arc<Authority>) -> DecodeBudget {
    DecodeBudget::new(authority, 1024 * 1024).unwrap()
}

fn pair() -> (Arc<Authority>, Arc<Authority>, DecodeBudget, DecodeBudget) {
    let resources = Arc::new(FixtureResourceBudget::new(0, 1024 * 1024));
    let events = Arc::new(AtomicU64::new(0));
    let caller = Authority::new(resources.clone(), events.clone(), 1);
    let source = Authority::new(resources, events.clone(), 2);
    let caller_account = original(caller.clone());
    let source_account = original(source.clone());
    events.store(0, Ordering::SeqCst);
    (caller, source, caller_account, source_account)
}

fn assert_original(error: StoreError, original: &DecodeAdmissionError) {
    let StoreError::DecodeAdmission { source, .. } = error else {
        panic!("expected the actual original admission failure")
    };
    assert_eq!(&source, original);
}

#[test]
fn pure_clones_share_one_check_before_and_after_the_same_callback() {
    let (authority, _, caller, _) = pair();
    let source = caller.clone();
    assert!(caller.same_account(&source));
    check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        Ok(())
    })
    .unwrap();
    assert_eq!(authority.events.load(Ordering::SeqCst), 131);
}

#[test]
fn shared_bank_distinct_accounts_keep_independent_checks_and_sticky_failures() {
    let (authority, source_authority, caller, source) = pair();
    assert!(Arc::ptr_eq(
        &authority.resources,
        &source_authority.resources
    ));
    assert!(!caller.same_account(&source));
    check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        Ok(())
    })
    .unwrap();
    assert_eq!(authority.events.load(Ordering::SeqCst), 12312);

    let child = caller.child().unwrap();
    assert!(!caller.same_account(&child));
    child.record_failure(source_authority.refusal.clone());
    authority.events.store(0, Ordering::SeqCst);
    let error = check_pair(&caller, &child, &mut || {
        record(&authority.events, 3);
        Ok(())
    })
    .unwrap_err();
    assert_original(error, &source_authority.refusal);
    assert_eq!(authority.events.load(Ordering::SeqCst), 1);
    caller.verify_live().unwrap();
}

#[test]
fn distinct_source_closure_refuses_before_callback_after_caller_preflight() {
    let (authority, source_authority, caller, source) = pair();
    source_authority.allowed.store(false, Ordering::SeqCst);
    let error = check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        Ok(())
    })
    .unwrap_err();
    assert_original(error, &source_authority.refusal);
    assert_eq!(authority.events.load(Ordering::SeqCst), 12);
}

#[test]
fn closed_clone_refuses_before_callback_and_callback_revocation_is_rechecked() {
    let (authority, _, caller, _) = pair();
    let source = caller.clone();
    authority.allowed.store(false, Ordering::SeqCst);
    let error = check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        Ok(())
    })
    .unwrap_err();
    assert_original(error, &authority.refusal);
    assert_eq!(authority.events.load(Ordering::SeqCst), 1);

    authority.allowed.store(true, Ordering::SeqCst);
    authority.events.store(0, Ordering::SeqCst);
    let error = check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        authority.allowed.store(false, Ordering::SeqCst);
        Ok(())
    })
    .unwrap_err();
    assert_original(error, &authority.refusal);
    assert_eq!(authority.events.load(Ordering::SeqCst), 131);
}

#[test]
fn callback_error_remains_first_when_callback_also_revokes_the_original() {
    let (authority, _, caller, _) = pair();
    let source = caller.clone();
    let error = check_pair(&caller, &source, &mut || {
        record(&authority.events, 3);
        authority.allowed.store(false, Ordering::SeqCst);
        Err(StoreError::Unauthorized)
    })
    .unwrap_err();
    assert!(matches!(error, StoreError::Unauthorized));
    assert_eq!(authority.events.load(Ordering::SeqCst), 13);
}
