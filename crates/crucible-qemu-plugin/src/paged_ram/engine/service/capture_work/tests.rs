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

    fn with_fingerprint_operation(
        &self,
        _exchange: &mut dyn FnMut(&dyn SourceOperation),
    ) -> Result<(), ObservationOperationError> {
        Err(io::Error::from_raw_os_error(libc::ENOTSUP).into())
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
