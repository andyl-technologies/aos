//! Checks actual queued receipt retention through completion and publication.

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[derive(Default)]
struct Counts {
    completed: AtomicUsize,
    dropped: AtomicUsize,
}

struct Operation {
    counts: Arc<Counts>,
    refuse: bool,
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.counts.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl SourceOperation for Operation {
    fn wait_slice(&self) -> io::Result<Duration> {
        Ok(Duration::from_millis(1))
    }

    fn complete(&self) -> io::Result<()> {
        if self.refuse {
            return Err(io::Error::from_raw_os_error(libc::ECANCELED));
        }
        self.counts.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        Ok(Duration::from_millis(1))
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.complete().map_err(Into::into)
    }
}

fn receipt(refuse: bool) -> (Option<QueuedPlacement>, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let queued = QueuedPlacement {
        operation: Arc::new(Operation {
            counts: counts.clone(),
            refuse,
        }),
        generation: 7,
        completed_work: Arc::new(AtomicU64::new(0)),
    };
    (Some(queued), counts)
}

#[test]
fn original_completion_refusal_retains_the_same_queued_receipt() {
    let (mut queued, counts) = receipt(true);
    let operation = Arc::downgrade(&queued.as_ref().unwrap().operation);

    assert!(
        finish_queued_receipt(&mut queued, None, || {
            panic!("failed original must not publish settlement")
        })
        .is_err()
    );
    assert!(Arc::ptr_eq(
        &operation.upgrade().unwrap(),
        &queued.as_ref().unwrap().operation
    ));
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn publication_refusal_retains_a_completed_operation_for_containment() {
    let (mut queued, counts) = receipt(false);

    assert!(
        finish_queued_receipt(&mut queued, Some(7), || {
            Err(RamError::Invariant("placement receipt unavailable"))
        })
        .is_err()
    );
    assert_eq!(queued.as_ref().unwrap().generation, 7);
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn superseded_generation_cannot_finish_or_drop_current_receipt() {
    let (mut queued, counts) = receipt(false);

    assert!(
        finish_queued_receipt(&mut queued, Some(6), || {
            panic!("stale generation must not publish")
        })
        .is_ok()
    );
    assert_eq!(queued.as_ref().unwrap().generation, 7);
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn completion_and_publication_precede_actual_receipt_release() {
    let (mut queued, counts) = receipt(false);

    finish_queued_receipt(&mut queued, Some(7), || {
        assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .unwrap();
    assert!(queued.is_none());
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
}
