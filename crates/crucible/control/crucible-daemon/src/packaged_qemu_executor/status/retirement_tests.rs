//! Checks status invalidation around automatic and consuming lifecycle return.

use super::*;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};

struct StatusObservedBody {
    file: File,
    tracker: PackagedWorldLifecycleTracker,
    dropped: Arc<AtomicBool>,
    expected_valid: bool,
}

impl Drop for StatusObservedBody {
    fn drop(&mut self) {
        assert_eq!(self.tracker.snapshot().is_some(), self.expected_valid);
        self.dropped.store(true, Ordering::Release);
    }
}

fn retained_body(
    tracker: &PackagedWorldLifecycleTracker,
    expected_valid: bool,
) -> (StatusObservedBody, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    (
        StatusObservedBody {
            file: tempfile::tempfile().expect("retained lifecycle descriptor"),
            tracker: tracker.clone(),
            dropped: Arc::clone(&dropped),
            expected_valid,
        },
        dropped,
    )
}

#[test]
fn unfinished_status_invalidates_before_automatic_body_destruction() {
    let tracker = PackagedWorldLifecycleTracker::new();
    let (inner, dropped) = retained_body(&tracker, false);
    let lifecycle = PackagedStatusLifecycle {
        status: LifecycleStatusOnDrop {
            lifecycles: tracker.clone(),
            execution: None,
            shutdown_finished: false,
        },
        inner,
    };
    assert!(tracker.snapshot().is_some());

    drop(lifecycle);

    assert!(dropped.load(Ordering::Acquire));
    assert!(tracker.snapshot().is_none());
}

#[test]
fn consuming_status_return_moves_the_same_body_without_dropping_it() {
    for shutdown_finished in [false, true] {
        let tracker = PackagedWorldLifecycleTracker::new();
        let (inner, dropped) = retained_body(&tracker, shutdown_finished);
        let identity = |body: &StatusObservedBody| {
            let metadata = body.file.metadata().expect("same open file");
            (body.file.as_raw_fd(), metadata.dev(), metadata.ino())
        };
        let original_identity = identity(&inner);
        let lifecycle = PackagedStatusLifecycle {
            status: LifecycleStatusOnDrop {
                lifecycles: tracker.clone(),
                execution: None,
                shutdown_finished,
            },
            inner,
        };

        let PackagedStatusLifecycle { status, inner } = lifecycle;
        drop(status);

        assert!(!dropped.load(Ordering::Acquire));
        assert_eq!(identity(&inner), original_identity);
        assert_eq!(tracker.snapshot().is_some(), shutdown_finished);

        drop(inner);

        assert!(dropped.load(Ordering::Acquire));
    }
}
