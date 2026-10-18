//! Checks local candidate custody across real mutex refusal and owner exclusion.
//!
//! These controls issue no native Source, return journal or cleanup grant.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

struct Candidate {
    contents: String,
    dropped: Arc<AtomicUsize>,
}

impl Drop for Candidate {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn contended_cleanup_owner_preserves_the_same_candidate() {
    let owner = Mutex::new(42);
    let held = owner.lock().unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let contents = String::from("original candidate allocation");
    let allocation = contents.as_ptr();
    let mut candidate = Some(Candidate {
        contents,
        dropped: dropped.clone(),
    });

    let result = abort_inactive_candidate(
        &mut candidate,
        || {
            owner
                .try_lock()
                .map_err(|_| RamError::Invariant("cleanup owner busy"))
        },
        |_| panic!("refused cleanup cannot consume the candidate"),
    );

    assert!(matches!(
        result,
        Err(RamError::Invariant("cleanup owner busy"))
    ));
    assert_eq!(candidate.as_ref().unwrap().contents.as_ptr(), allocation);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(*held, 42);
    drop(candidate);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn candidate_abort_keeps_the_validated_owner_exclusive_through_publication() {
    let owner = Mutex::new(42);
    let dropped = Arc::new(AtomicUsize::new(0));
    let contents = String::from("original candidate allocation");
    let allocation = contents.as_ptr();
    let mut candidate = Some(Candidate {
        contents,
        dropped: dropped.clone(),
    });

    let mut retained_owner = abort_inactive_candidate(
        &mut candidate,
        || {
            owner
                .try_lock()
                .map_err(|_| RamError::Invariant("cleanup owner busy"))
        },
        |candidate| {
            assert!(matches!(owner.try_lock(), Err(TryLockError::WouldBlock)));
            assert_eq!(candidate.contents.as_ptr(), allocation);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            drop(candidate);
            Ok(())
        },
    )
    .unwrap();

    assert!(candidate.is_none());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(matches!(owner.try_lock(), Err(TryLockError::WouldBlock)));
    assert_eq!(*retained_owner, 42);
    *retained_owner = 43;
    drop(retained_owner);
    assert_eq!(*owner.lock().unwrap(), 43);
}

#[test]
fn refused_candidate_abort_restores_original_custody_and_leaves_owner_unchanged() {
    let owner = Mutex::new(42);
    let dropped = Arc::new(AtomicUsize::new(0));
    let contents = String::from("original candidate allocation");
    let allocation = contents.as_ptr();
    let mut candidate = Some(Candidate {
        contents,
        dropped: dropped.clone(),
    });

    let result = abort_inactive_candidate(
        &mut candidate,
        || {
            owner
                .try_lock()
                .map_err(|_| RamError::Invariant("cleanup owner busy"))
        },
        |candidate| {
            assert!(matches!(owner.try_lock(), Err(TryLockError::WouldBlock)));
            Err(candidate)
        },
    );

    assert!(matches!(
        result,
        Err(RamError::Invariant(
            "arena identity rollback authority uncertain"
        ))
    ));
    assert_eq!(candidate.as_ref().unwrap().contents.as_ptr(), allocation);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(*owner.try_lock().unwrap(), 42);
    drop(candidate);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_candidate_refuses_before_cleanup_or_publication() {
    let mut candidate: Option<Candidate> = None;

    let result: Result<(), RamError> = abort_inactive_candidate(
        &mut candidate,
        || panic!("missing custody cannot start cleanup"),
        |_| panic!("missing custody cannot publish a successful abort"),
    );

    assert_eq!(
        result,
        Err(RamError::Invariant("arena identity receipt absent"))
    );
}
