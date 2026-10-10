//! Checks typed and erased observers sharing one concrete failure identity.

// crucible-lint: allow panic-shortcut -- fixtures panic to localize typed original-cause and layout failures.
#![allow(clippy::unwrap_used)]

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::SharedOperationalCause;

#[derive(Debug)]
struct OriginalCause {
    drops: Arc<AtomicUsize>,
}

impl fmt::Display for OriginalCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original concrete failure")
    }
}

impl Error for OriginalCause {}

impl Drop for OriginalCause {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn typed_and_erased_observers_share_identity_and_original_downcast() {
    let drops = Arc::new(AtomicUsize::new(0));
    let typed = SharedOperationalCause::new(OriginalCause {
        drops: drops.clone(),
    });
    let typed_clone = typed.clone();
    let erased = typed.backend_cause();
    let transferred = typed_clone.into_backend_cause();
    let erased_clone = erased.clone();

    assert_eq!(erased, transferred);
    assert_eq!(erased, erased_clone);
    assert!(std::ptr::eq(
        typed.source_ref(),
        erased
            .source()
            .unwrap()
            .downcast_ref::<OriginalCause>()
            .unwrap(),
    ));
    assert_eq!(erased.to_string(), "original concrete failure");
    assert_eq!(
        format!("{erased:?}"),
        format!("BackendOperationalCause({:?})", typed.source_ref())
    );

    drop(typed);
    drop(erased);
    drop(transferred);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(erased_clone);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn mixed_concurrent_observers_destroy_the_original_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let typed = SharedOperationalCause::new(OriginalCause {
        drops: drops.clone(),
    });
    let erased = typed.backend_cause();
    let barrier = std::sync::Barrier::new(8);
    let typed_observers: Vec<_> = (0..4).map(|_| typed.clone()).collect();
    let erased_observers: Vec<_> = (0..4).map(|_| erased.clone()).collect();
    drop(typed);
    drop(erased);

    std::thread::scope(|scope| {
        for observer in typed_observers {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(observer);
            });
        }
        for observer in erased_observers {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(observer);
            });
        }
    });

    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_owner_has_one_pointer_and_erasure_adds_no_body() {
    assert_eq!(
        std::mem::size_of::<SharedOperationalCause<OriginalCause>>(),
        8
    );
    assert_eq!(
        std::mem::align_of::<SharedOperationalCause<OriginalCause>>(),
        8
    );
    assert_eq!(std::mem::size_of::<OriginalCause>(), 8);
    assert_eq!(
        SharedOperationalCause::<OriginalCause>::allocation_bytes().unwrap(),
        24
    );
}
