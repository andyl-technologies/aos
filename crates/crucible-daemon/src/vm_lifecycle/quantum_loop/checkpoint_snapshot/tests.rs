//! Preserves owned capture-reader causes in the original prepaid scheduler body.
//!
//! The finite fixture scope models an original allowance. Incoming IO payload
//! allocation and enclosing production controls remain outside this proof.

use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::exact_checkpoint::CaptureReadError;
use crucible_cas::content_store::StoreError;
use crucible_cas::ram::{PreparedRamFailure, RamOperationFailure, RamStoreError};

use super::{SchedulerError, ram_capture_read_failure, ram_checkpoint_failure};

#[derive(Debug)]
struct OriginalPayload {
    drops: Arc<AtomicUsize>,
}

impl fmt::Display for OriginalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original capture IO payload")
    }
}

impl Error for OriginalPayload {}

impl Drop for OriginalPayload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

fn retained_io(error: &SchedulerError) -> &io::Error {
    let SchedulerError::RamFailure { source, .. } = error else {
        panic!("expected typed retained scheduler cause");
    };
    let RamStoreError::Store(StoreError::StreamIo { source, .. }) = source.storage_failure() else {
        panic!("expected the original owned stream IO cause");
    };
    source
}

#[test]
fn owned_io_payload_survives_mapping_clone_and_final_unwind() {
    let _scope = crucible::test_support::fixture_decode_scope(64 * 1024)
        .unwrap_or_else(|error| panic!("finite original fixture scope: {error}"));
    let original = crucible::owned_decode::current_budget()
        .unwrap_or_else(|| panic!("saved original fixture account"));
    let drops = Arc::new(AtomicUsize::new(0));
    let incoming = io::Error::other(OriginalPayload {
        drops: drops.clone(),
    });
    let identity = incoming
        .get_ref()
        .and_then(|source| source.downcast_ref::<OriginalPayload>())
        .map(|source| source as *const OriginalPayload)
        .unwrap_or_else(|| panic!("original payload identity"));
    let prepared = PreparedRamFailure::<SchedulerError>::new(&original)
        .unwrap_or_else(|error| panic!("prepay before reader effects: {error}"));

    let failure = prepared
        .run(&mut || Ok(()), |_| {
            Err::<(), _>(ram_capture_read_failure(CaptureReadError::Io(incoming)))
        })
        .err()
        .unwrap_or_else(|| panic!("expected original typed failure"));
    assert!(matches!(failure, RamOperationFailure::Retained(_)));
    let error = ram_checkpoint_failure(failure, &original);
    let cloned = error.clone();
    drop(error);

    let actual = retained_io(&cloned)
        .get_ref()
        .and_then(|source| source.downcast_ref::<OriginalPayload>())
        .map(|source| source as *const OriginalPayload);
    assert_eq!(actual, Some(identity));
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert!(cloned.source().is_some());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _last = cloned;
        panic!("intentional final owned reader cause unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn errno_static_validation_and_allocation_remain_typed() {
    let errno = ram_capture_read_failure(CaptureReadError::Io(io::Error::from_raw_os_error(
        rustix::io::Errno::BADF.raw_os_error(),
    )));
    let RamStoreError::Store(StoreError::StreamIo { source, .. }) = errno else {
        panic!("IO must remain owned stream IO");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::BADF.raw_os_error())
    );

    assert!(matches!(
        ram_capture_read_failure(CaptureReadError::Malformed("trailing page capture bytes")),
        RamStoreError::Invalid("trailing page capture bytes")
    ));
    let validation = ram_capture_read_failure(CaptureReadError::Validation(
        crucible_ram::RamError::OutOfRange,
    ));
    assert!(matches!(
        validation,
        RamStoreError::LogicalValidation(crucible_ram::RamError::OutOfRange)
    ));
    assert!(
        validation
            .source()
            .is_some_and(|source| source.downcast_ref::<crucible_ram::RamError>().is_some())
    );

    let allocation = Vec::<u8>::new()
        .try_reserve_exact(usize::MAX)
        .err()
        .unwrap_or_else(|| panic!("expected original typed failure"));
    let failure = ram_capture_read_failure(CaptureReadError::Allocation(allocation));
    assert!(matches!(
        failure,
        RamStoreError::Store(StoreError::Allocation { custody: None, .. })
    ));
    eprintln!(
        "scheduler={} RAM error={} owned reader={} original shared carrier={}",
        std::mem::size_of::<SchedulerError>(),
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<CaptureReadError>(),
        PreparedRamFailure::<SchedulerError>::allocation_bytes()
            .unwrap_or_else(|error| panic!("actual carrier layout: {error}"))
    );
}

#[test]
fn first_cancellation_and_owned_reader_failure_survive_together() {
    let _scope = crucible::test_support::fixture_decode_scope(64 * 1024)
        .unwrap_or_else(|error| panic!("finite original fixture scope: {error}"));
    let original = crucible::owned_decode::current_budget()
        .unwrap_or_else(|| panic!("saved original fixture account"));
    let prepared = PreparedRamFailure::<SchedulerError>::new(&original)
        .unwrap_or_else(|error| panic!("prepay before reader effects: {error}"));
    let mut calls = 0;
    let failure = prepared
        .run(
            &mut || {
                calls += 1;
                Err(SchedulerError::OperationalBoundary {
                    class: crucible::SchedulerOperationalFailureClass::Canceled,
                    message: String::from("original checkpoint cancellation"),
                })
            },
            |boundary| {
                assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
                assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
                Err::<(), _>(ram_capture_read_failure(CaptureReadError::Io(
                    io::Error::from_raw_os_error(rustix::io::Errno::BADF.raw_os_error()),
                )))
            },
        )
        .err()
        .unwrap_or_else(|| panic!("expected original reader failure with first cancellation"));
    let error = ram_checkpoint_failure(failure, &original);

    assert_eq!(calls, 1);
    assert_eq!(
        error.operational_failure_class(),
        Some(crucible::SchedulerOperationalFailureClass::Canceled)
    );
    assert_eq!(
        retained_io(&error.clone()).raw_os_error(),
        Some(rustix::io::Errno::BADF.raw_os_error())
    );
}
