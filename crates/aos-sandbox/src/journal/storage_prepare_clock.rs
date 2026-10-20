//! Retains the actual kernel clock at the ordinary Storage Prepare append.
//!
//! This adds one fixed restriction immediately before append_exact. It never
//! skips an ordinary semantic guard or supplies missing Storage payment/custody.

use aos_sandbox_broker::{BrokerAdmissionError, StoragePrepareNativeClockLoanV1};
use aos_sandbox_core::RawPairedClockSample;

use super::semantic_append::AppendScope;
use super::{CacheMutationGateV1, CommitResult, Journal, JournalError};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

#[derive(Default)]
struct RetainedClockResultsV1 {
    kernel: Option<Box<crate::policy_compiler::RetainedKernelPairedClockAttemptV1>>,
    sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    validation: Option<Result<(), BrokerAdmissionError>>,
}

/// Owns the once-only raw clock result and its independent admission check.
///
/// Vacant custody allocates nothing and grants no authority. The original
/// Storage attempt parks this capture before entering Native, then retains it
/// beside the actual commit result through all later response/Session posts.
#[derive(Default)]
pub struct StoragePrepareNativeClockCaptureV1 {
    retained: RetainedClockResultsV1,
    #[cfg(any(test, feature = "test-fixtures"))]
    fixture_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    #[cfg(any(test, feature = "test-fixtures"))]
    fail_after_append: bool,
}

impl StoragePrepareNativeClockCaptureV1 {
    /// Creates vacant nonauthorizing custody without observing the kernel.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            retained: RetainedClockResultsV1 {
                kernel: None,
                sample: None,
                validation: None,
            },
            #[cfg(any(test, feature = "test-fixtures"))]
            fixture_sample: None,
            #[cfg(any(test, feature = "test-fixtures"))]
            fail_after_append: false,
        }
    }

    /// Reports the complete production inline capture width for supplier checks.
    ///
    /// Explicit fixture-only injection slots are excluded. This measured layout
    /// value is DATA and cannot establish payment or permit an operation.
    #[must_use]
    pub const fn retained_layout_bytes() -> usize {
        std::mem::size_of::<RetainedClockResultsV1>()
    }

    pub(crate) fn retaining_native_demand_v1()
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use crate::policy_compiler::RetainedKernelPairedClockAttemptV1 as Clock;
        let bytes = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, Clock::MAXIMUM_RETAINED_FILES_V1 as u64))
    }

    pub(crate) fn retain_native_source_v1(&mut self) {
        // Only the same once-entered actual Native attempt selects this inert
        // destination after its real caller has prepaid the fixed shape.
        self.retained.kernel = Some(Box::new(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::default()));
    }

    /// Borrows the exact kernel result without moving its original cause.
    #[must_use]
    pub fn sample_result(&self) -> Option<&Result<RawPairedClockSample, SourceGenesisErrorV1>> {
        self.retained.sample.as_ref()
    }

    /// Borrows the independent original authority-clock comparison result.
    #[must_use]
    pub fn validation_result(&self) -> Option<&Result<(), BrokerAdmissionError>> {
        self.retained.validation.as_ref()
    }

    /// Reports that the once-only capture has already crossed or refused entry.
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.retained.sample.is_some() || self.retained.validation.is_some()
    }

    /// Borrows the earliest retained clock producer or validation failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.retained.kernel.as_ref().and_then(|original| original.failure())
            .or_else(|| self.retained.sample.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| {
                self.retained
                    .validation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &(dyn std::error::Error + 'static))
            })
    }

    /// Seeds only the clock DATA used by explicit Native guard fixtures.
    ///
    /// This fixture supplies no signature, protected writer or paid original.
    /// All ordinary journal and exact admitted-effect checks remain active.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn with_untrusted_sample_for_fixture(
        sample: Result<RawPairedClockSample, SourceGenesisErrorV1>,
    ) -> Self {
        Self {
            fixture_sample: Some(sample),
            ..Self::new()
        }
    }

    /// Selects a fixed error after real durable append for explicit fixtures.
    ///
    /// This neither skips admission nor fabricates a commit. Native appends
    /// and synchronizes the actual frames, then poisons the same owner before
    /// returning the injected error instead of publishing its cached view.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn with_durable_append_failure_for_fixture(sample: RawPairedClockSample) -> Self {
        Self {
            fail_after_append: true,
            ..Self::with_untrusted_sample_for_fixture(Ok(sample))
        }
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn take_durable_append_failure(&mut self) -> bool {
        std::mem::take(&mut self.fail_after_append)
    }

    fn reject_loan(&mut self, error: BrokerAdmissionError) -> Result<CommitResult, JournalError> {
        if !self.attempted() {
            self.retained.validation = Some(Err(error));
        }
        Err(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_final_clock(
        &mut self,
        loan: &StoragePrepareNativeClockLoanV1<'_>,
    ) -> Result<(), JournalError> {
        if self.attempted() {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        let fixture = self.fixture_sample.take();
        #[cfg(not(any(test, feature = "test-fixtures")))]
        let fixture: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>> = None;
        let sample = match fixture {
            Some(sample) => sample,
            None => match self.retained.kernel.as_mut() {
                Some(original) => original.observe_once(None),
                None => crate::policy_compiler::observe_root_first_source_successor_clock_v2(None),
            },
        };
        self.retained.sample = Some(sample);
        let current = match self.retained.sample.as_ref() {
            Some(Ok(current)) => *current,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.retained.validation = Some(loan.require_native_clock(current));
        match self.retained.validation {
            Some(Ok(())) => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

impl Journal {
    /// Adds the exact original Storage Prepare clock restriction to ordinary commit.
    ///
    /// This entrypoint grants no exception to ordinary semantic, capacity,
    /// owner, Q04 or protected-name checks. The one fixed kernel observation
    /// occurs after those checks and frame construction, immediately before
    /// the unchanged native append. Its whole result stays in `capture`.
    ///
    /// # Errors
    /// Preserves ordinary commit failures. Returns `ProtectedBoundary` when
    /// the exact loan or final clock fails, retaining the original clock cause
    /// in the caller-owned capture. Native append uncertainty remains poison.
    pub fn commit_storage_prepare_with_clock_v1(
        &mut self,
        loan: Result<StoragePrepareNativeClockLoanV1<'_>, BrokerAdmissionError>,
        capture: &mut StoragePrepareNativeClockCaptureV1,
    ) -> Result<CommitResult, JournalError> {
        if capture.attempted() {
            return Err(JournalError::ProtectedBoundary);
        }
        let loan = match loan {
            Ok(loan) => loan,
            Err(error) => return capture.reject_loan(error),
        };
        self.commit_with_native_scope_and_storage_clock(
            loan.transaction(),
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            None,
            None,
            None,
            Some((&loan, capture)),
            None,
        )
    }
}
