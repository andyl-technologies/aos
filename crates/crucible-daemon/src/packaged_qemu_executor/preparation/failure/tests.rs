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
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.outstanding.load(Ordering::SeqCst) > MAXIMUM_BYTES {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.outstanding
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= MAXIMUM_BYTES)
            })
            .map_err(|_| DecodeAdmissionError::new(std::io::Error::other("fixture exhausted")))?;

        Ok(crucible_cas::owned_decode::ResourceLoan::new(Lease {
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

#[cfg(feature = "private-measurement-domain")]
#[test]
fn private_typed_finish_preserves_capture_completion_cleanup_and_live_credit() {
    use crate::private_original_capture::{
        OriginalCaptureCompletion, OriginalCaptureWatcherRefusal,
    };
    use crucible_api::host_operational::HostOperationalError;
    use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};

    // This exercises the real owning diagnostic and admitted Box, not an
    // actual watchdog expiry, original PID1 or physical native retirement.
    let outstanding = Arc::new(AtomicU64::new(0));
    let decoding = budget(&outstanding);
    let resources = decoding
        .reserve_scratch_array::<OriginalCaptureFailureBody>(1)
        .unwrap();
    let admitted = outstanding.load(Ordering::SeqCst);
    assert!(admitted > 0);
    eprintln!(
        "original_capture_failure_body={} owning_error={} packaged_error={} scratch={}",
        std::mem::size_of::<OriginalCaptureFailureBody>(),
        std::mem::size_of::<OriginalCaptureFailure>(),
        std::mem::size_of::<PackagedQemuExecutorError>(),
        std::mem::size_of::<DecodeScratch>()
    );
    let dropped = Arc::new(AtomicBool::new(false));
    let capture = PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(
        NativeSetupFailure {
            outstanding: Arc::clone(&outstanding),
            minimum_live_bytes: admitted,
            dropped: Arc::clone(&dropped),
        },
    ));
    let refusal = OriginalCaptureWatcherRefusal::CaptureWait {
        source: HostSupervisionError::DeadlineExpired {
            operation_id: 41,
            class: HostOperationClass::Setup,
        },
        original_after: None,
    };
    let completion = OriginalCaptureCompletion {
        original_before: None,
        original_after: None,
        child: None,
        watcher: Some(refusal),
        join_panicked: false,
    };
    let result = finish_original_capture::<()>(
        Err(capture),
        completion,
        Some(HostOperationalError::Unavailable),
        None,
        resources,
    );
    let Err(PackagedQemuExecutorError::OriginalPreparationCapture(source)) = result else {
        panic!("typed original capture expected")
    };

    assert_eq!(source.completion(), Some(completion));
    assert_eq!(source.watcher(), Some(refusal));
    assert!(matches!(
        source.cleanup(),
        Some(HostOperationalError::Unavailable)
    ));
    assert!(source.start().is_none());
    let Some(PackagedQemuExecutorError::PreparationSupervisor(capture)) = source.capture() else {
        panic!("real IO cause expected")
    };
    assert!(capture.get_ref().unwrap().is::<NativeSetupFailure>());
    assert_eq!(outstanding.load(Ordering::SeqCst), admitted);
    assert!(!dropped.load(Ordering::SeqCst));

    drop(source);
    assert!(dropped.load(Ordering::SeqCst));
    drop(decoding);
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn private_accepted_finish_keeps_success_and_returns_unused_original_credit() {
    use crate::private_original_capture::OriginalCaptureCompletion;
    let outstanding = Arc::new(AtomicU64::new(0));
    let decoding = budget(&outstanding);
    let resources = decoding
        .reserve_scratch_array::<OriginalCaptureFailureBody>(1)
        .unwrap();
    assert!(outstanding.load(Ordering::SeqCst) > 0);
    let completion = OriginalCaptureCompletion {
        original_before: None,
        original_after: None,
        child: None,
        watcher: None,
        join_panicked: false,
    };
    assert_eq!(
        finish_original_capture(
            Ok::<_, PackagedQemuExecutorError>(7),
            completion,
            None,
            None,
            resources
        )
        .unwrap(),
        7
    );
    drop(decoding);
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "private-measurement-domain")]
#[test]
fn earlier_retained_supervision_cuts_remain_in_the_standard_error_chain() {
    use crate::private_original_capture::OriginalCaptureCompletion;
    use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};

    // Error-carrier projection controls preserve exact stored IDs/classes;
    // real clock/expiry scheduling is covered by the joined watcher controls.
    let early = HostSupervisionError::DeadlineExpired {
        operation_id: 73,
        class: HostOperationClass::Setup,
    };
    let later = HostSupervisionError::Unavailable;
    let outstanding = Arc::new(AtomicU64::new(0));
    let decoding = budget(&outstanding);
    for cut in 0..4 {
        let resources = decoding
            .reserve_scratch_array::<OriginalCaptureFailureBody>(1)
            .unwrap();
        let completion = OriginalCaptureCompletion {
            original_before: (cut == 1).then_some(early),
            child: (cut == 2).then_some(early),
            original_after: (cut == 3).then_some(early),
            watcher: None,
            join_panicked: false,
        };
        let error = original_failure(
            OriginalCaptureFailureBody {
                capture: None,
                start: None,
                completion: (cut != 0).then_some(completion),
                watcher: None,
                cleanup: Some(crucible_api::host_operational::HostOperationalError::Unavailable),
                configuration_original: (cut == 0).then_some(early),
                release_original: Some(later),
            },
            resources,
        );
        let PackagedQemuExecutorError::OriginalPreparationCapture(error) = error else {
            panic!("expected retained original failure")
        };
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<HostSupervisionError>(),
            Some(&early)
        );
        assert_eq!(error.release_original(), Some(later));
    }

    let direct = PackagedQemuExecutorError::OriginalPreparationBoundary(early);
    assert_eq!(
        direct
            .source()
            .unwrap()
            .downcast_ref::<HostSupervisionError>(),
        Some(&early)
    );
    drop(decoding);
    assert_eq!(outstanding.load(Ordering::SeqCst), 0);
}
