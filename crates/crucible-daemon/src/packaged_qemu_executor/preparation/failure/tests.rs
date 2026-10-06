//! Exercises typed expiry diagnostics and their original finite storage custody.

use super::*;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAXIMUM_BYTES: u64 = 64 * 1024;

struct Authority {
    outstanding: Arc<AtomicU64>,
}

struct Lease {
    outstanding: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.outstanding
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= MAXIMUM_BYTES)
            })
            .map_err(|_| DecodeAdmissionError::new(std::io::Error::other("fixture exhausted")))?;

        Ok(Arc::new(Lease {
            outstanding: Arc::clone(&self.outstanding),
            bytes,
        }))
    }
}

fn budget(outstanding: &Arc<AtomicU64>) -> DecodeBudget {
    DecodeBudget::new(
        Arc::new(Authority {
            outstanding: Arc::clone(outstanding),
        }),
        MAXIMUM_BYTES,
    )
    .unwrap_or_else(|error| panic!("finite fixture admission: {error}"))
}

#[derive(Debug)]
struct NativeSetupFailure {
    outstanding: Arc<AtomicU64>,
    minimum_live_bytes: u64,
    dropped: Arc<AtomicBool>,
}

impl fmt::Display for NativeSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RAM controller Setup expired")
    }
}

impl Error for NativeSetupFailure {}

impl Drop for NativeSetupFailure {
    fn drop(&mut self) {
        assert!(self.outstanding.load(Ordering::SeqCst) >= self.minimum_live_bytes);
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn expired_failure_retains_original_source_and_credit_until_final_drop() {
    let outstanding = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let budget = budget(&outstanding);
    let resources = budget
        .reserve_scratch_array::<PackagedQemuExecutorError>(1)
        .unwrap_or_else(|error| panic!("expiry storage admission: {error}"));
    let retained_bytes = outstanding.load(Ordering::SeqCst);
    let failure = NativeSetupFailure {
        outstanding: Arc::clone(&outstanding),
        minimum_live_bytes: retained_bytes,
        dropped: Arc::clone(&dropped),
    };
    let cause = PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(failure));

    let error = match finish_capture::<()>(Err(cause), true, resources) {
        Err(error) => error,
        Ok(()) => panic!("expired capture cannot succeed"),
    };
    // The source remains authoritative after the lexical account owner closes.
    drop(budget);

    let PackagedQemuExecutorError::PreparationExpired {
        source: Some(source),
    } = &error
    else {
        panic!("expiration must preserve its original capture failure");
    };
    let PackagedQemuExecutorError::PreparationSupervisor(io) = source.cause() else {
        panic!("the typed native failure must remain unchanged");
    };
    assert!(
        io.get_ref()
            .is_some_and(|error| error.is::<NativeSetupFailure>())
    );
    assert!(
        error
            .source()
            .is_some_and(|error| error.is::<PreparationExpiredCause>())
    );
    assert!(
        source
            .source()
            .is_some_and(|error| error.is::<PackagedQemuExecutorError>())
    );
    assert_eq!(
        source.to_string(),
        "packaged preparation supervision failed: RAM controller Setup expired"
    );
    assert_eq!(outstanding.load(Ordering::SeqCst), retained_bytes);
    assert!(!dropped.load(Ordering::SeqCst));

    drop(error);

    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}

#[test]
fn unexpired_failure_keeps_its_classification_and_releases_unused_storage() {
    let outstanding = Arc::new(AtomicU64::new(0));
    let budget = budget(&outstanding);
    let baseline = outstanding.load(Ordering::SeqCst);
    let resources = budget
        .reserve_scratch_array::<PackagedQemuExecutorError>(1)
        .unwrap_or_else(|error| panic!("expiry storage admission: {error}"));

    let error = match finish_capture::<()>(
        Err(PackagedQemuExecutorError::NoCampaigns),
        false,
        resources,
    ) {
        Err(error) => error,
        Ok(()) => panic!("failed capture cannot succeed"),
    };

    assert!(matches!(error, PackagedQemuExecutorError::NoCampaigns));
    assert_eq!(outstanding.load(Ordering::SeqCst), baseline);
    drop(budget);
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}

struct Candidate(Arc<AtomicBool>);

impl Drop for Candidate {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn expired_success_discards_candidate_without_inventing_a_source() {
    let outstanding = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let budget = budget(&outstanding);
    let baseline = outstanding.load(Ordering::SeqCst);
    let resources = budget
        .reserve_scratch_array::<PackagedQemuExecutorError>(1)
        .unwrap_or_else(|error| panic!("expiry storage admission: {error}"));

    let result = finish_capture(Ok(Candidate(Arc::clone(&dropped))), true, resources);

    assert!(matches!(
        result,
        Err(PackagedQemuExecutorError::PreparationExpired { source: None })
    ));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(outstanding.load(Ordering::SeqCst), baseline);
    drop(budget);
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}
