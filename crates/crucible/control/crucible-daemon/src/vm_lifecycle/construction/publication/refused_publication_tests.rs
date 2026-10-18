//! Preserves the actual returned token/body across unavailable publication.
//!
//! This negative-only component uses the canonical reservation implementation
//! with no queue. Its local file and diagnostic carry no execution authority.

#![cfg(test)]

use super::*;
use crucible_control_api::ProductionVmCleanupOwner;
use std::error::Error;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type CleanupFailure = <ProductionVmConstructionCustody as ProductionVmCleanupOwner>::Failure;

struct FileOwner {
    _file: File,
    cleanup_calls: Arc<AtomicUsize>,
    destroyed: Arc<AtomicBool>,
}

impl ProductionVmCleanupOwner for FileOwner {
    type Failure = CleanupFailure;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        panic!("refused publication never transfers the retained owner's obligations");
    }

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
        panic!("publication must never execute the retained owner's cleanup");
    }
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        self.destroyed.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("component constructor refusal {marker}")]
struct ConstructorRefusal {
    marker: u64,
}

fn first_cause(first: &LifecycleApiError) -> &ConstructorRefusal {
    let LifecycleApiError::ConfigurationCopy(first) = first else {
        panic!("the original typed constructor error was replaced");
    };
    first
        .source()
        .expect("retained typed source")
        .downcast_ref::<ConstructorRefusal>()
        .expect("same concrete first error")
}

struct ExpectedCustody {
    token: *const (),
    body: *const (),
    first: *const ConstructorRefusal,
    descriptor: i32,
    file_identity: (u64, u64),
    cleanup_calls: Arc<AtomicUsize>,
    destroyed: Arc<AtomicBool>,
}

impl ExpectedCustody {
    fn assert_retained(&self, failure: &ProductionVmConstructionFailure) {
        let FailureStorage::Rejected { first, returned } = &failure.storage else {
            panic!("the actual rejected pair left its owning failure");
        };
        let returned = returned.lock().expect("component returned slot");
        let (token, body) = returned.as_ref().expect("same token and body remain owned");
        assert_eq!(std::ptr::from_ref(token.as_ref()).cast::<()>(), self.token);
        assert_eq!(std::ptr::from_ref(body.as_ref()).cast::<()>(), self.body);
        let cause = first_cause(first);
        assert!(std::ptr::eq(cause, self.first));
        assert_eq!(cause.marker, 73);
        assert!(failure.additional.is_none());
        assert_eq!(self.cleanup_calls.load(Ordering::SeqCst), 0);
        assert!(!self.destroyed.load(Ordering::SeqCst));
        let retained = fs::metadata(format!("/proc/self/fd/{}", self.descriptor))
            .expect("the same local file must remain open");
        assert_eq!((retained.dev(), retained.ino()), self.file_identity);
    }
}

#[test]
fn unavailable_canonical_handoff_keeps_same_pair_and_first_cause_twice() {
    let file = tempfile::tempfile().expect("real component file");
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata().expect("component file identity");
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let destroyed = Arc::new(AtomicBool::new(false));
    let owner: Box<
        dyn ProductionVmCleanupOwner<
                Failure = CleanupFailure,
                PostBody = crate::ProductionVmConstructionPostBody,
            >,
    > = Box::new(FileOwner {
        _file: file,
        cleanup_calls: Arc::clone(&cleanup_calls),
        destroyed: Arc::clone(&destroyed),
    });
    let reservation =
        crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_reservation_for_test();
    let first = LifecycleApiError::ConfigurationCopy(
        crucible_engine::owned_decode::DecodeAdmissionError::new(ConstructorRefusal { marker: 73 }),
    );
    let expected = ExpectedCustody {
        token: std::ptr::from_ref(reservation.as_ref()).cast::<()>(),
        body: std::ptr::from_ref(owner.as_ref()).cast::<()>(),
        first: std::ptr::from_ref(first_cause(&first)),
        descriptor,
        file_identity: (metadata.dev(), metadata.ino()),
        cleanup_calls,
        destroyed,
    };
    let mut failure = ProductionVmConstructionFailure {
        storage: FailureStorage::Rejected {
            first,
            returned: std::sync::Mutex::new(Some((reservation, owner))),
        },
        additional: None,
    };
    expected.assert_retained(&failure);

    assert!(failure.retry_reserved_publication().is_err());
    expected.assert_retained(&failure);

    assert!(failure.retry_reserved_publication().is_err());
    expected.assert_retained(&failure);

    failure = failure
        .into_published_error()
        .expect_err("a diagnostic cannot consume an unpublished owner/token pair");
    expected.assert_retained(&failure);

    // Only this unissued token and local file exist. Dispose them explicitly
    // after the custody assertions; no Main/World charge or role is returned.
    let FailureStorage::Rejected { returned, .. } = &mut failure.storage else {
        panic!("component still owns its rejected pair");
    };
    let (reservation, owner) = returned
        .get_mut()
        .expect("component slot")
        .take()
        .expect("same pair for explicit component disposal");
    drop(owner);
    drop(reservation);
    assert!(expected.destroyed.load(Ordering::SeqCst));
    assert_eq!(expected.cleanup_calls.load(Ordering::SeqCst), 0);
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |current| (
            current.dev(),
            current.ino()
        ) != expected
            .file_identity)
    );
}
