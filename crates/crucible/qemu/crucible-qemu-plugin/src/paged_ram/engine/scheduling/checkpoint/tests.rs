//! Exercises real queue retention without treating modeled native evidence as authority.

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::sync::atomic::{AtomicI32, AtomicUsize};
use std::time::Duration;

// This test helper probes the actual queue mutex; it never issues native proof.
fn try_checkpoint_queue<T>(
    queue: &Mutex<PlacementQueue>,
    action: impl FnOnce(&mut PlacementQueue) -> Result<T, RamError>,
) -> Result<T, RamError> {
    let mut queue = queue
        .try_lock()
        .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
    action(&mut queue)
}

#[derive(Default)]
struct Counts {
    completed: AtomicUsize,
    completion_errno: AtomicI32,
    dropped: AtomicUsize,
}

struct Operation(Arc<Counts>);

impl SourceOperation for Operation {
    fn wait_slice(&self) -> io::Result<Duration> {
        Ok(Duration::from_millis(1))
    }

    fn complete(&self) -> io::Result<()> {
        self.0.completed.fetch_add(1, Ordering::SeqCst);
        let error = self.0.completion_errno.load(Ordering::SeqCst);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(())
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        Ok(Duration::from_millis(1))
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.complete().map_err(Into::into)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn queue() -> (PlacementQueue, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let queue = PlacementQueue {
        receipt: Some(QueuedPlacement {
            operation: Arc::new(Operation(counts.clone())),
            generation: 9,
            completed_work: Arc::new(AtomicU64::new(4)),
        }),
        capture: PlacementCapture::default(),
        dispatching: false,
    };
    (queue, counts)
}

#[test]
fn requested_hold_retains_actual_work_and_cannot_acknowledge_detachment() {
    let (mut queue, counts) = queue();
    let operation = Arc::downgrade(&queue.receipt.as_ref().unwrap().operation);

    queue.request_checkpoint(1).unwrap();

    assert!(queue.capture.require_open().is_err());
    assert!(queue.check_detached(1).is_err());
    assert_eq!(queue.receipt.as_ref().unwrap().generation, 9);
    assert_eq!(
        queue
            .receipt
            .as_ref()
            .unwrap()
            .completed_work
            .load(Ordering::SeqCst),
        4
    );
    assert!(Arc::ptr_eq(
        &operation.upgrade().unwrap(),
        &queue.receipt.as_ref().unwrap().operation
    ));
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_receipt_still_closes_admission_and_requires_native_detachment() {
    let mut queue = PlacementQueue::default();

    queue.request_checkpoint(1).unwrap();

    assert!(queue.capture.is_held());
    assert!(queue.capture.require_open().is_err());
    assert!(queue.check_detached(1).is_err());
}

#[test]
fn busy_actual_queue_refuses_before_it_can_replace_a_hold() {
    let queue = Mutex::new(PlacementQueue::default());
    let owner = queue.lock().unwrap();

    assert!(try_checkpoint_queue(&queue, |queue| queue.request_checkpoint(1)).is_err());

    assert!(!owner.capture.is_held());
    assert_eq!(owner.capture.issued_transaction, 0);
}

#[test]
fn another_transaction_or_stale_disposition_never_reopens_work() {
    let (mut queue, counts) = queue();
    queue.request_checkpoint(3).unwrap();

    assert!(queue.request_checkpoint(4).is_err());
    assert!(
        queue
            .record_detached(&DetachedCheckpointMailbox { transaction: 2 })
            .is_err()
    );
    assert!(
        queue
            .release_checkpoint(2, || panic!("stale release must not restore"))
            .is_err()
    );

    assert!(queue.capture.is_held());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_accepted_policy_cannot_match_old_mailbox_evidence() {
    let (mut queue, _) = queue();
    queue.request_checkpoint(1).unwrap();
    queue.receipt.as_mut().unwrap().generation = 10;

    assert!(
        queue
            .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
            .is_err()
    );

    assert!(queue.capture.is_held());
}

#[test]
fn failed_restore_keeps_detached_gate_and_same_pending_operation() {
    let (mut queue, counts) = queue();
    queue.request_checkpoint(1).unwrap();
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();

    assert!(
        queue
            .release_checkpoint(1, || Err(RamError::Invariant("modeled mailbox busy")))
            .is_err()
    );

    assert!(queue.check_detached(1).is_err());
    assert!(
        queue
            .release_checkpoint(1, || panic!("uncertain restore must not retry"))
            .is_err()
    );
    assert!(queue.capture.require_open().is_err());
    assert!(queue.receipt.is_some());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn successful_restore_reopens_only_after_same_work_is_reenqueued() {
    let (mut queue, counts) = queue();
    queue.request_checkpoint(1).unwrap();
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();

    queue
        .release_checkpoint(1, || {
            assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
            assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
            Ok(())
        })
        .unwrap();

    assert!(queue.capture.require_open().is_ok());
    assert!(queue.receipt.is_some());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert!(queue.request_checkpoint(1).is_err());
    assert!(queue.request_checkpoint(2).is_ok());
}

#[test]
fn empty_detached_hold_releases_without_fabricating_new_placement_work() {
    let mut queue = PlacementQueue::default();
    queue.request_checkpoint(1).unwrap();
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();

    queue
        .release_checkpoint(1, || panic!("empty work must not schedule a callback"))
        .unwrap();

    assert!(queue.capture.require_open().is_ok());
    assert!(queue.receipt.is_none());
}

#[test]
fn callback_admitted_before_request_can_finish_but_its_receipt_stays_owned() {
    let (mut queue, counts) = queue();
    queue.request_checkpoint(1).unwrap();

    queue.finish_receipt(9, || Ok(())).unwrap();

    assert!(queue.receipt.is_none());
    assert!(queue.capture.completed_receipt.is_some());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();
    queue
        .release_checkpoint(1, || panic!("completed work must not be re-enqueued"))
        .unwrap();
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn completion_publication_refusal_keeps_the_original_receipt_under_the_hold() {
    let (mut queue, counts) = queue();
    queue.request_checkpoint(1).unwrap();

    assert!(
        queue
            .finish_receipt(9, || Err(RamError::Invariant(
                "modeled publication refusal"
            )))
            .is_err()
    );

    assert!(queue.receipt.is_some());
    assert!(queue.capture.completed_receipt.is_none());
    assert!(queue.capture.is_held());
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();
    assert!(queue.check_detached(1).is_err());
    assert!(
        queue
            .release_checkpoint(1, || panic!("uncertain work must remain held"))
            .is_err()
    );
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_dispatch_census_refuses_detachment_until_the_same_work_returns() {
    let (mut queue, counts) = queue();
    queue.dispatching = true;
    queue.request_checkpoint(1).unwrap();

    assert!(
        queue
            .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
            .is_err()
    );
    assert!(queue.check_detached(1).is_err());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);

    queue.finish_receipt(9, || Ok(())).unwrap();
    queue.dispatching = false;
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();
    assert!(queue.check_detached(1).is_ok());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn initiating_failure_survives_poisoned_final_dispatch_custody() {
    let (mut owned, _) = queue();
    owned.dispatching = true;
    let queue = Mutex::new(owned);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _owner = queue.lock().unwrap();
        panic!("modeled final owner failure");
    }));
    assert!(poisoned.is_err());

    let refusal = finish_placement_dispatch(
        &queue,
        Err(RamError::Native {
            operation: "actual initiating work refusal",
            status: -libc::ECANCELED,
        }),
    );

    assert!(matches!(refusal, Err(RamError::Native {
        operation: "actual initiating work refusal", status,
    }) if status == -libc::ECANCELED));
    let owner = match queue.lock() {
        Ok(_) => panic!("final owner must stay poisoned"),
        Err(owner) => owner,
    };
    assert!(owner.get_ref().dispatching);
    drop(owner);
    assert!(finish_placement_dispatch(&queue, Ok(())).is_err());
}

#[test]
fn negative_completion_after_its_effect_retains_the_receipt_without_retry() {
    let (mut queue, counts) = queue();
    counts
        .completion_errno
        .store(libc::ECANCELED, Ordering::SeqCst);
    let operation = Arc::downgrade(&queue.receipt.as_ref().unwrap().operation);
    queue.request_checkpoint(1).unwrap();

    let result = queue.finish_receipt(9, || panic!("failed completion must not publish"));
    assert!(
        matches!(result, Err(RamError::Io(error)) if error.raw_os_error() == Some(libc::ECANCELED))
    );
    assert!(
        queue
            .finish_receipt(9, || panic!("uncertain completion must not retry"))
            .is_err()
    );
    queue
        .record_detached(&DetachedCheckpointMailbox { transaction: 1 })
        .unwrap();
    assert!(
        queue
            .release_checkpoint(1, || panic!("uncertain receipt must remain held"))
            .is_err()
    );

    assert!(Arc::ptr_eq(
        &operation.upgrade().unwrap(),
        &queue.receipt.as_ref().unwrap().operation
    ));
    assert!(queue.capture.disposition_uncertain);
    assert!(queue.capture.completed_receipt.is_none());
    assert!(queue.capture.require_open().is_err());
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}
