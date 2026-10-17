//! Exercises actual request/operation/body custody at settlement and refusal.

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Counts {
    admitted: AtomicUsize,
    completed: AtomicUsize,
    dropped: AtomicUsize,
}

struct Operations {
    counts: Arc<Counts>,
    refuse_admission: bool,
    refuse_completion: bool,
}

struct Operation {
    counts: Arc<Counts>,
    refuse_completion: bool,
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
        if self.refuse_completion {
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

impl SourceOperationFactory for Operations {
    fn begin(&self, class: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        assert_eq!(class, SourceOperationClass::PageIn);
        if self.refuse_admission {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        self.counts.admitted.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Operation {
            counts: self.counts.clone(),
            refuse_completion: self.refuse_completion,
        }))
    }
}

fn event(address: u64) -> FaultEvent {
    FaultEvent {
        address,
        thread_id: 17,
        write: false,
        write_protected: false,
    }
}

fn fixture() -> (MetadataBudget, FaultWorkOwner, Operations) {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent);
    let owner = FaultWorkOwner::prepare(&budget).unwrap();
    let operations = Operations {
        counts: Arc::new(Counts::default()),
        refuse_admission: false,
        refuse_completion: false,
    };
    (budget, owner, operations)
}

#[test]
fn insufficient_metadata_refuses_before_operation_birth() {
    let extent = FaultWorkOwner::required_metadata_bytes().unwrap();
    let budget = MetadataBudget::new(extent - 1);

    assert!(FaultWorkOwner::prepare(&budget).is_err());
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn completion_releases_actual_operation_then_body_and_same_credit() {
    let (budget, owner, operations) = fixture();
    let extent = budget.used_bytes();
    {
        let mut work = owner.try_lock().unwrap();
        work.claim(event(0x1000), &operations).unwrap();
        let (request, _, scratch) = work.request().unwrap();
        assert_eq!(request, event(0x1000));
        scratch[7] = 23;
        work.settled().unwrap();
        assert!(work.claimed.is_none());
        assert_eq!(work.scratch[7], 0);
    }

    assert_eq!(operations.counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(operations.counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(budget.used_bytes(), extent);
    drop(owner);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn completion_refusal_keeps_request_buffer_operation_and_credit() {
    let (budget, owner, mut operations) = fixture();
    operations.refuse_completion = true;
    let extent = budget.used_bytes();
    {
        let mut work = owner.try_lock().unwrap();
        work.claim(event(0x2000), &operations).unwrap();
        work.request().unwrap().2[31] = 79;
        assert!(work.settled().is_err());
        assert_eq!(work.request().unwrap().0, event(0x2000));
        assert_eq!(work.scratch[31], 79);
        assert!(work.failed);
    }

    drop(owner);
    assert_eq!(operations.counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(operations.counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn consumed_event_survives_admission_refusal_with_no_live_operation() {
    let (budget, owner, mut operations) = fixture();
    operations.refuse_admission = true;
    let extent = budget.used_bytes();
    {
        let mut work = owner.try_lock().unwrap();
        assert!(work.claim(event(0x3000), &operations).is_err());
        assert_eq!(work.claimed.as_ref().unwrap().event, event(0x3000));
        assert!(work.claimed.as_ref().unwrap().operation.is_none());
        assert!(work.settled().is_err());
    }

    assert_eq!(operations.counts.admitted.load(Ordering::SeqCst), 0);
    drop(owner);
    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn later_claim_cannot_replace_unsettled_event_or_original_operation() {
    let (_, owner, operations) = fixture();
    let mut work = owner.try_lock().unwrap();
    work.claim(event(0x4000), &operations).unwrap();

    assert!(work.claim(event(0x5000), &operations).is_err());
    assert_eq!(work.request().unwrap().0, event(0x4000));
    assert_eq!(operations.counts.admitted.load(Ordering::SeqCst), 1);
    work.settled().unwrap();
}

#[test]
fn resolver_uncertainty_never_refunds_a_live_request() {
    let (budget, owner, operations) = fixture();
    let extent = budget.used_bytes();
    {
        let mut work = owner.try_lock().unwrap();
        work.claim(event(0x6000), &operations).unwrap();
        work.request().unwrap().2[63] = 127;
        work.fail();
        assert!(work.settled().is_err());
        assert_eq!(work.scratch[63], 127);
    }

    drop(owner);
    assert_eq!(operations.counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn pause_request_does_not_acknowledge_a_claimed_request() {
    let (_, owner, operations) = fixture();
    let mut work = owner.try_lock().unwrap();
    work.claim(event(0x7000), &operations).unwrap();
    // Admission remains responsive while the actual request/body lock is held.
    owner.request_pause(7).unwrap();
    assert!(!owner.pause_acknowledged(7));
    assert!(owner.acknowledge_pause_at_boundary(&work).is_err());
    work.settled().unwrap();
    assert!(owner.acknowledge_pause_at_boundary(&work).unwrap());
    assert!(owner.pause_acknowledged(7));
    owner.release_pause(7).unwrap();
}

#[test]
fn undisposed_pause_retains_an_empty_body_and_same_credit() {
    let (budget, owner, _) = fixture();
    let extent = budget.used_bytes();
    owner.request_pause(8).unwrap();
    {
        let work = owner.try_lock().unwrap();
        assert!(owner.acknowledge_pause_at_boundary(&work).unwrap());
    }
    drop(owner);
    assert_eq!(budget.used_bytes(), extent);
}

#[test]
fn matching_disposition_frees_empty_body_before_credit_refund() {
    let (budget, owner, _) = fixture();
    owner.request_pause(9).unwrap();
    {
        let work = owner.try_lock().unwrap();
        assert!(owner.acknowledge_pause_at_boundary(&work).unwrap());
    }
    assert!(owner.release_pause(8).is_err());
    assert!(owner.pause_acknowledged(9));
    owner.release_pause(9).unwrap();
    drop(owner);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn concurrent_pause_waits_for_the_claimed_operation_boundary() {
    let (budget, owner, operations) = fixture();
    let owner = Arc::new(owner);
    let worker_owner = owner.clone();
    let (claimed_tx, claimed_rx) = std::sync::mpsc::sync_channel(0);
    let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        let mut work = worker_owner.try_lock().unwrap();
        work.claim(event(0x8000), &operations).unwrap();
        work.request().unwrap().2[11] = 43;
        claimed_tx.send(()).unwrap();
        finish_rx.recv().unwrap();
        assert!(!worker_owner.pause_acknowledged(10));
        assert_eq!(work.scratch[11], 43);
        work.settled().unwrap();
        assert!(worker_owner.acknowledge_pause_at_boundary(&work).unwrap());
    });
    claimed_rx.recv().unwrap();

    owner.request_pause(10).unwrap();
    assert!(!owner.pause_acknowledged(10));
    assert!(owner.try_lock().is_err());
    assert!(owner.release_pause(10).is_err());
    finish_tx.send(()).unwrap();
    worker.join().unwrap();

    assert!(owner.pause_acknowledged(10));
    owner.release_pause(10).unwrap();
    drop(owner);
    assert_eq!(budget.used_bytes(), 0);
}

fn read_message(
    work: &mut FaultWork,
    count: usize,
    kind: u8,
    flags: u64,
) -> io::Result<Option<FaultEvent>> {
    work.receipt.read_with(|message| {
        message[0] = kind;
        message[8..16].copy_from_slice(&flags.to_ne_bytes());
        message[16..24].copy_from_slice(&0x9000_u64.to_ne_bytes());
        message[24..28].copy_from_slice(&17_u32.to_ne_bytes());
        Ok(count)
    })
}

#[test]
fn consumed_malformed_bytes_block_replacement_and_retain_prepaid_body() {
    for (count, kind, flags) in [(7, 0x12, 0), (32, 0x13, 0), (32, 0x12, 4)] {
        let (budget, owner, operations) = fixture();
        let extent = budget.used_bytes();
        owner.request_pause(23).unwrap();
        {
            let mut work = owner.try_lock().unwrap();
            assert!(read_message(&mut work, count, kind, flags).is_err());
            assert!(work.receipt.retained());
            assert!(work.unresolved());
            assert!(
                work.receipt
                    .read_with(|_| panic!("consumed bytes must not be overwritten"))
                    .is_err()
            );
            assert!(owner.acknowledge_pause_at_boundary(&work).is_err());
            assert!(work.settled().is_err());
        }

        assert_eq!(operations.counts.admitted.load(Ordering::SeqCst), 0);
        drop(owner);
        assert_eq!(budget.used_bytes(), extent);
    }
}

#[test]
fn valid_kernel_receipt_follows_same_operation_completion_disposition() {
    for refuse_completion in [false, true] {
        let (budget, owner, mut operations) = fixture();
        operations.refuse_completion = refuse_completion;
        let extent = budget.used_bytes();
        {
            let mut work = owner.try_lock().unwrap();
            let event = read_message(&mut work, 32, 0x12, 0).unwrap().unwrap();
            work.claim(event, &operations).unwrap();
            work.request().unwrap().2[9] = 41;

            assert_eq!(work.settled().is_err(), refuse_completion);
            assert_eq!(work.receipt.retained(), refuse_completion);
            assert_eq!(work.unresolved(), refuse_completion);
            assert_eq!(work.scratch[9], if refuse_completion { 41 } else { 0 });
        }

        drop(owner);
        assert_eq!(
            budget.used_bytes(),
            if refuse_completion { extent } else { 0 }
        );
        assert_eq!(
            operations.counts.completed.load(Ordering::SeqCst),
            usize::from(!refuse_completion)
        );
        assert_eq!(
            operations.counts.dropped.load(Ordering::SeqCst),
            usize::from(!refuse_completion)
        );
    }
}

#[test]
fn interrupted_or_empty_kernel_read_never_admits_an_operation() {
    let (_, owner, operations) = fixture();
    let mut work = owner.try_lock().unwrap();
    for errno in [libc::EAGAIN, libc::EINTR] {
        assert!(
            work.receipt
                .read_with(|_| Err(io::Error::from_raw_os_error(errno)))
                .unwrap()
                .is_none()
        );
        assert!(!work.receipt.retained());
        assert!(!work.unresolved());
    }

    assert!(work.receipt.read_with(|_| Ok(0)).is_err());
    assert!(!work.receipt.retained());
    assert!(work.claimed.is_none());
    assert_eq!(operations.counts.admitted.load(Ordering::SeqCst), 0);
}
