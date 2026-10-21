//! Owns the one production Capture create issuance and its actual commit.
//!
//! The full signed admission, fresh authenticated Host readback, protected
//! output and original policy are joined before the sole424 attempt append.
//! A fresh noncopyable commit can be taken only after retained clock bookends
//! and exact MAC/readback. Historical queries cannot construct that token.
//! Actual same-F prepayment, privileged worker and physical completion remain
//! separate required owners; neither a receipt nor a parsed source grants them.

use super::*;
use aos_sandbox_broker::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3;
use crate::execution_capture_policy::CaptureAllocationV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureIssuanceClockErrorV3 {
    #[error("Capture issuance clock changed or its original entry expired")]
    Stale,
    #[error(transparent)]
    Native(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for CaptureIssuanceClockErrorV3 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self { Self::Native(cause) }
}

#[derive(Debug, thiserror::Error)]
#[error("Capture create issuance is closed with its original retained")]
struct CaptureIssuanceClosedV3;

static CLOSED: CaptureIssuanceClosedV3 = CaptureIssuanceClosedV3;

type Clock = RetainedKernelPairedClockAttemptV1<CaptureIssuanceClockErrorV3>;

#[derive(Default)]
pub(super) struct CaptureAttemptCommitOriginalV3 {
    pub(super) canonical_encoded: Option<Result<Vec<u8>, ExecutionOutputLedgerErrorV1>>,
    pub(super) encoded: Option<Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1>>,
    pub(super) transaction: Option<Result<JournalTransaction, aos_sandbox_controller_domain::JournalError>>,
    pub(super) commit: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    pub(super) readback: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    pub(super) returned: Option<Result<ProtectedCaptureCreateAttemptReceiptV1, ExecutionOutputLedgerErrorV1>>,
}

impl CaptureAttemptCommitOriginalV3 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        error(&self.canonical_encoded).or_else(|| error(&self.encoded)).or_else(|| error(&self.transaction))
            .or_else(|| error(&self.commit)).or_else(|| error(&self.readback))
            .or_else(|| error(&self.returned))
    }

    #[cfg(test)]
    pub(super) fn into_result_v3(mut self)
        -> Result<ProtectedCaptureCreateAttemptReceiptV1, ExecutionOutputLedgerErrorV1>
    {
        if let Some(Err(error)) = self.canonical_encoded.take() { return Err(error); }
        if let Some(Err(error)) = self.encoded.take() { return Err(error); }
        if let Some(Err(error)) = self.transaction.take() { return Err(error.into()); }
        if let Some(Err(error)) = self.commit.take() { return Err(error.into()); }
        if let Some(Err(error)) = self.readback.take() { return Err(error); }
        self.returned.take().ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?
    }
}

#[derive(Clone, Copy)]
enum Failure { BeforeClock, Entry, Sources, IssueTime, Retained, Commit, AfterClock, After, Closed }

/// Retains the actual signed admission and all reached native/durable results.
///
/// The genuine fixed F caller must prepay its whole demand before constructing
/// the admission/Host/source models. This inert destination creates no loan.
pub(crate) struct CaptureCreateIssuanceOriginalV3 {
    admitted: Option<VerifiedCaptureReserveOngoingAdmissionV3>,
    requirement: Option<CaptureDatasetRequirementV1>,
    policy: Option<CaptureAllocationV1>,
    clocks: [Clock; 2],
    pairs: [Option<Result<RawPairedClockSample, CaptureIssuanceClockErrorV3>>; 2],
    entry: Option<Result<(), aos_sandbox_broker::BrokerAdmissionError>>,
    issue_time: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    sources: Option<Result<VerifiedCaptureAttemptSourcesV1, CaptureSourceAdmissionErrorV2>>,
    retained: Option<Result<ProtectedRetainedCaptureV1, ExecutionOutputLedgerErrorV1>>,
    commit: CaptureAttemptCommitOriginalV3,
    after: Option<Result<(), aos_sandbox_broker::BrokerAdmissionError>>,
    native: Option<crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl CaptureCreateIssuanceOriginalV3 {
    pub(crate) fn new() -> Self {
        Self { admitted: None, requirement: None, policy: None,
            clocks: std::array::from_fn(|_| Clock::default()),
            pairs: std::array::from_fn(|_| None), entry: None, issue_time: None, sources: None,
            retained: None, commit: CaptureAttemptCommitOriginalV3::default(),
            after: None, native: None, first: None, entered: false, taken: false }
    }

    /// Prices the fixed carrier, native pair reservoirs and sole actual append.
    pub(crate) fn receiving_demand_v3(ledger: &ExecutionOutputLedgerV1)
        -> Result<ResourceVector, aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1>
    {
        // The sole canonical encoder returns an owned424-byte Vec. Its
        // buffer remains on the original while the checked array and later
        // native Fresh record coexist; conversion also has one array scratch.
        let canonical_planes = RECORD_BYTES.checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>()))
            .ok_or(aos_sandbox_controller_domain::JournalError::JournalTooLarge)?;
        let native_bytes = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(canonical_planes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(aos_sandbox_controller_domain::JournalError::JournalTooLarge)?;
        let native = ResourceVector::ZERO.with(D::MemoryBytes, native_bytes)
            .with(D::OpenFiles, 2 * Clock::MAXIMUM_RETAINED_FILES_V1 as u64);
        Ok(ledger.capture_ongoing_attempt_receiving_demand_v3()?.checked_add(native)?)
    }

    fn fail(&mut self, site: Failure) -> Result<(), ExecutionOutputLedgerErrorV1> {
        self.first.get_or_insert(site);
        Err(ExecutionOutputLedgerErrorV1::NotCurrent)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        if self.first.is_none() {
            return self.native.as_ref().and_then(|native| native.failure());
        }
        match self.first? {
            Failure::BeforeClock => self.clocks[0].failure().or_else(|| error(&self.pairs[0])),
            Failure::Entry => error(&self.entry),
            Failure::Sources => error(&self.sources),
            Failure::IssueTime => error(&self.issue_time),
            Failure::Retained => error(&self.retained),
            Failure::Commit => self.commit.failure(),
            Failure::AfterClock => self.clocks[1].failure().or_else(|| error(&self.pairs[1])),
            Failure::After => error(&self.after),
            Failure::Closed => Some(&CLOSED),
        }
    }

    pub(crate) fn postcheck_debt_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.clocks[1].failure().or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Parks the only native constructor behind this actual fresh commit.
    ///
    /// The factory consumes a noncopyable fresh owner; no receipt or query can
    /// call it. Even a rejected preflight retains the same signed admission.
    pub(crate) fn prepare_native_once_v3(&mut self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if self.native.is_some() { return self.fail(Failure::Closed); }
        let Some(fresh) = self.take_fresh_once_v3() else { return self.fail(Failure::Closed); };
        self.native = Some(crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3::from_fresh_v3(fresh));
        if self.native.as_ref().is_some_and(|native| native.failure().is_none()) { Ok(()) }
        else { Err(ExecutionOutputLedgerErrorV1::NotCurrent) }
    }

    pub(crate) fn take_native_once_v3(&mut self)
        -> Option<crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3>
    {
        if self.native.as_ref().is_none_or(|native| native.failure().is_some()) { return None; }
        self.native.take()
    }

    fn take_fresh_once_v3(&mut self) -> Option<FreshCaptureCreateCommitV3> {
        if !self.entered || self.taken || self.first.is_some()
            || !matches!(self.after, Some(Ok(())))
            || self.admitted.is_none() || self.requirement.is_none() || self.policy.is_none()
            || !matches!(self.sources, Some(Ok(_))) || !matches!(self.retained, Some(Ok(_)))
            || !matches!(self.commit.returned, Some(Ok(_)))
            || !matches!(self.commit.encoded, Some(Ok(_)))
        { return None; }
        // Every field is checked before the first move. A partial move cannot
        // discard an admitted/native prefix if another destination is absent.
        let Some(admitted) = self.admitted.take() else { std::process::abort() };
        let Some(requirement) = self.requirement.take() else { std::process::abort() };
        let Some(policy) = self.policy.take() else { std::process::abort() };
        let Some(Ok(sources)) = self.sources.take() else { std::process::abort() };
        let Some(Ok(retained)) = self.retained.take() else { std::process::abort() };
        let Some(Ok(receipt)) = self.commit.returned.as_ref() else { std::process::abort() };
        self.taken = true;
        let Some(Ok(record)) = self.commit.encoded.as_ref() else { std::process::abort(); };
        Some(FreshCaptureCreateCommitV3 { admitted, requirement, policy, sources, retained,
            receipt: *receipt, record: *record })
    }

}

/// Owns one noncopyable newly committed effect fence, never a historical query.
pub(crate) struct FreshCaptureCreateCommitV3 {
    admitted: VerifiedCaptureReserveOngoingAdmissionV3,
    requirement: CaptureDatasetRequirementV1,
    policy: CaptureAllocationV1,
    sources: VerifiedCaptureAttemptSourcesV1,
    retained: ProtectedRetainedCaptureV1,
    receipt: ProtectedCaptureCreateAttemptReceiptV1,
    record: [u8; RECORD_BYTES],
}

impl FreshCaptureCreateCommitV3 {
    // Borrowed facts retain their original noncopyable issuer beside the
    // native constructor. They cannot be used to construct another fresh token.
    pub(crate) fn native_parts_v3(&self)
        -> ([u8; 16], ObjectDigest, ObjectDigest, ObjectDigest, [u8; 16], u64,
            &ProtectedRetainedCaptureV1, &CaptureDatasetRequirementV1, CaptureAllocationV1)
    {
        (self.receipt.attempt, self.receipt.controller_grant_digest,
            self.receipt.host_receipt_digest, self.receipt.durable_attempt_digest,
            self.sources.kernel_boot_id, self.admitted.lifetime_v3().ongoing_deadline_v3(),
            &self.retained, &self.requirement, self.policy)
    }

    pub(crate) fn record_bytes_v3(&self) -> &[u8; RECORD_BYTES] { &self.record }

    pub(crate) fn admitted_v3(&self) -> &VerifiedCaptureReserveOngoingAdmissionV3 { &self.admitted }
}

impl ExecutionOutputLedgerV1 {
    /// Joins actual native inputs before the sole committed create attempt.
    pub(crate) fn issue_capture_create_ongoing_v3(
        &mut self,
        admitted: VerifiedCaptureReserveOngoingAdmissionV3,
        host: &AuthenticatedBrokerMethodOutcomeV1,
        requirement: CaptureDatasetRequirementV1,
        policy: CaptureAllocationV1,
        original: &mut CaptureCreateIssuanceOriginalV3,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if original.entered { return original.fail(Failure::Closed); }
        original.entered = true;
        original.admitted = Some(admitted);
        original.requirement = Some(requirement);
        original.policy = Some(policy);
        let body = (|| {
            original.pairs[0] = Some(original.clocks[0].observe_once(None));
            let Some(current) = original.pairs[0].as_ref().and_then(|pair| pair.as_ref().ok()).copied()
            else { return original.fail(Failure::BeforeClock); };
            let admitted = original.admitted.as_ref().ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            original.entry = Some(admitted.lifetime_v3().require_ongoing_clock_v3(&current));
            if !matches!(original.entry, Some(Ok(()))) { return original.fail(Failure::Entry); }
            let requirement = original.requirement.as_ref().ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            original.sources = Some(self.prepare_admitted_capture_ongoing_sources_v3(
                admitted, host, requirement, policy, current.boottime_nanoseconds(),
            ));
            let Some(sources) = original.sources.as_ref().and_then(|value| value.as_ref().ok())
            else { return original.fail(Failure::Sources); };
            original.issue_time = Some(sources.require_issue_time_v3(
                current.host_boot_id(), current.boottime_nanoseconds(),
            ));
            if !matches!(original.issue_time, Some(Ok(()))) { return original.fail(Failure::IssueTime); }
            original.retained = Some(self.read_protected_retained_capture(
                sources.execution, sources.create, sources.record_digest,
            ));
            let Some(retained) = original.retained.as_ref().and_then(|value| value.as_ref().ok())
            else { return original.fail(Failure::Retained); };
            original.commit.returned = Some(self.commit_capture_attempt_inner_v3(
                sources, retained, requirement, policy.metadata_headroom_bytes(),
                policy.minimum_remaining_bytes(), &mut original.commit,
            ));
            if !matches!(original.commit.returned, Some(Ok(_))) { return original.fail(Failure::Commit); }
            Ok(())
        })();
        // Both fixed clock reservoirs were paid before entry. This second
        // observation is owed even after source, encoder or native refusal.
        let first = original.pairs[0].as_ref().and_then(|pair| pair.as_ref().ok()).copied();
        original.pairs[1] = Some(original.clocks[1].observe_once(first));
        if let Some(current) = original.pairs[1].as_ref().and_then(|pair| pair.as_ref().ok()) {
            original.after = Some(match original.admitted.as_ref() {
                Some(admitted) => admitted.lifetime_v3().require_ongoing_clock_v3(current),
                None => Err(aos_sandbox_broker::BrokerAdmissionError::FenceRejected),
            });
            if !matches!(original.after, Some(Ok(()))) { original.first.get_or_insert(Failure::After); }
        } else { original.first.get_or_insert(Failure::AfterClock); }
        body?;
        if original.first.is_some() { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        Ok(())
    }
}

impl Drop for CaptureCreateIssuanceOriginalV3 {
    fn drop(&mut self) {
        // Every entered negative/ambiguous issuer remains on the genuine F
        // owner. Only the actual successful native transfer can dispose its
        // completed source/clock/commit scratch at this boundary.
        if self.entered && (!self.taken || self.first.is_some()) {
            std::process::abort();
        }
    }
}
