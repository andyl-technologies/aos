//! Retains the fifth fixed Host opening before the sole Guest nonce engine.
//!
//! This destination uses the same captured writer, native replay, namespace
//! claim and entropy step as the original consuming opener. Its caller owns
//! genuine prepaid Host receiving; no constructor here supplies authority.

use std::error::Error;

use aos_sandbox::journal::{CapturedJournalOpenModeV1, HostArgumentCapturedJournalOpenV2,
    ProtectedJournalPreopenReplayExtentV1, RecoveryReport};
use aos_sandbox::{Journal, JournalError};
use aos_sandbox_core::ResourceVector;

use super::{HostArgumentAttemptErrorV1, HostArgumentAttemptJournalV1,
    argument_journal_instance, journal_limits};

pub(super) struct HostArgumentNativeIoV2 {
    pub(super) response_mode: Option<Result<(), crate::live_agent::HostAgentLiveErrorV1>>,
    pub(super) sent: Option<Result<(), crate::live_agent::HostAgentLiveErrorV1>>,
    pub(super) received: Option<Result<Option<Vec<u8>>, crate::live_agent::HostAgentLiveErrorV1>>,
    pub(super) record: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    pub(super) failure: Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>,
    pub(super) completed: Option<super::CompletedHostArgumentOriginalV2>,
}

impl HostArgumentNativeIoV2 {
    fn new() -> Self { Self { response_mode: None, sent: None, received: None, record: None, failure: None, completed: None } }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.response_mode.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.sent.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &(dyn Error + 'static)))
            .or_else(|| self.failure.as_ref().map(|error| error as &(dyn Error + 'static)))
            .or_else(|| self.received.as_ref()?.as_ref().err().map(|error| error as &(dyn Error + 'static)))
    }
}

/// Parks the original argument journal and its final constructor outcome.
///
/// There is no public factory or independent receiving grant. Only the real
/// Host operation owner constructs and prices this fixed destination.
#[doc(hidden)]
#[must_use = "retain the fifth native prefix through the actual Host posts"]
pub struct HostArgumentAttemptOpeningV2 {
    native: HostArgumentCapturedJournalOpenV2,
    io: HostArgumentNativeIoV2,
    opened: Option<(Journal, RecoveryReport)>,
    construction: Option<Result<[u8; 16], HostArgumentAttemptErrorV1>>,
    future_append: Option<Result<ResourceVector, aos_sandbox::journal::JournalAppendReceivingDemandErrorV1>>,
    journal: Option<HostArgumentAttemptJournalV1>,
    prepared: bool,
    replayed: bool,
    borrowed: bool,
    closed: bool,
}

impl HostArgumentAttemptOpeningV2 {
    pub(crate) fn new() -> Self {
        Self { native: HostArgumentCapturedJournalOpenV2::new(), io: HostArgumentNativeIoV2::new(), opened: None,
            construction: None, future_append: None, journal: None, prepared: false, replayed: false,
            borrowed: false, closed: false }
    }

    pub(crate) fn fixed_preparation_demand_v2() -> Option<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;
        // Actual selected Launch parent mode prevents rights before queueing;
        // the same authenticated80 parser retains all reached native prefixes.
        // Native mode is required before the real pending append/Guest59 send.
        let (native_bytes, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::closed_zero_rights_receive_obligations_v1(super::MAXIMUM_PACKET_BYTES)?;
        let native = HostArgumentCapturedJournalOpenV2::fixed_preparation_demand().ok()?;
        let reply = u64::try_from(files.checked_add(1)?).ok()?;
        // Guest59 starts only after native take_opened retired every positive
        // traversal/bookend. The same three writer files remain alongside it.
        let file_peak = native.get(D::OpenFiles).max(3_u64.checked_add(reply)?);
        native.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from((2 * std::mem::size_of::<Self>()).checked_add(native_bytes)?
                    // The live proof retains the original decoded challenge,
                    // verified Guest evidence and complete bounded receipt.
                    .checked_add(2 * std::mem::size_of::<super::CompletedHostArgumentOriginalV2>())?
                    .checked_add(2 * (super::MAXIMUM_REQUEST_BYTES + super::MAXIMUM_PACKET_BYTES))?).ok()?)
                .with(D::OpenFiles, 0),
        ).ok().map(|demand| demand.with(D::OpenFiles, file_peak))
    }

    // The three actual journal files and successful raw59 record subject stay
    // held; no positive record/native-source disposal is assumed here.
    pub(crate) const fn positive_resident_files_v6() -> u64 { 3 + 1 }

    pub(crate) fn require_positive_residency_v6(&self) -> Result<(), HostArgumentAttemptErrorV1> {
        if self.closed || !self.borrowed || !self.native.was_taken_positive_v1()
            || self.opened.is_some() || self.journal.is_none()
            || self.io.completed.is_none() || self.io.record.is_none()
            || !matches!(self.io.sent, Some(Ok(())))
            || !matches!(self.io.received, Some(Ok(Some(_))))
            || self.failure().is_some()
        { return Err(HostArgumentAttemptErrorV1::Binding); }
        Ok(())
    }

    pub(crate) fn prepare_once(&mut self) -> Result<(), HostArgumentAttemptErrorV1> {
        if self.closed || self.prepared {
            self.closed = true;
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        self.prepared = true;
        self.native.prepare_once(journal_limits(), CapturedJournalOpenModeV1::CreateAndRepair);
        if self.native.captured_extent().is_none() {
            self.closed = true;
            return Err(HostArgumentAttemptErrorV1::Journal(JournalError::ProtectedBoundary));
        }
        Ok(())
    }

    pub(crate) fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.closed || !self.prepared || self.replayed { return None; }
        self.native.captured_extent()
    }

    pub(crate) fn replay_once(&mut self) -> Result<(), HostArgumentAttemptErrorV1> {
        if self.captured_extent().is_none() {
            self.closed = true;
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        self.replayed = true;
        self.native.replay_once();
        self.opened = self.native.take_opened();
        let Some((journal, _)) = self.opened.as_mut() else {
            self.closed = true;
            return Err(HostArgumentAttemptErrorV1::Journal(JournalError::ProtectedBoundary));
        };
        // Park the SAME positive Journal before namespace/entropy can fail.
        self.construction = Some(argument_journal_instance(journal));
        let instance = match self.construction.as_ref() {
            Some(Ok(instance)) => *instance,
            _ => {
                self.closed = true;
                return Err(HostArgumentAttemptErrorV1::Binding);
            }
        };
        let Some((journal, _)) = self.opened.take() else {
            std::process::abort();
        };
        self.journal = Some(HostArgumentAttemptJournalV1 { journal, instance });
        Ok(())
    }

    pub(crate) fn future_append_demand_v2(&mut self) -> Result<ResourceVector, HostArgumentAttemptErrorV1> {
        if self.future_append.is_some() { return Err(HostArgumentAttemptErrorV1::Binding); }
        let journal = &self.journal.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?.journal;
        let limits = journal.configured_limits_data_v1();
        let value = limits.maximum_record_bytes.checked_sub(7)
            .and_then(|bytes| bytes.checked_sub(limits.maximum_key_bytes))
            .ok_or(HostArgumentAttemptErrorV1::Binding)?;
        let record = aos_sandbox_journal::geometry::RecordShape {
            key_bytes: limits.maximum_key_bytes, value_bytes: Some(value),
        };
        self.future_append = Some(journal.append_sequence_receiving_demand_v1(
            [0, 1].into_iter().map(|_| Ok(std::iter::once(record)))));
        self.future_append.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(HostArgumentAttemptErrorV1::Binding)
    }

    pub(super) fn parts_once_v2(&mut self) -> Result<(&mut HostArgumentAttemptJournalV1, &mut HostArgumentNativeIoV2), HostArgumentAttemptErrorV1> {
        if self.closed || !self.replayed || self.borrowed || self.journal.is_none() {
            self.closed = true;
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        self.borrowed = true;
        let journal = self.journal.as_mut().ok_or(HostArgumentAttemptErrorV1::Binding)?;
        Ok((journal, &mut self.io))
    }

    pub(crate) fn require_specification_v2(
        &self,
        claim: &aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
        agent: &crate::live_agent::HostAgentLiveSessionV1,
        fields: &aos_sandbox_protocol::execution_spec_attempt::ExecutionSpecAttemptFieldsV1<'_>,
        controller_session: [u8; 32],
        now: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), HostArgumentAttemptErrorV1> {
        self.io.completed.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?
            .require_specification_v2(
                self.journal.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?,
                claim, agent, fields, controller_session, now,
            )
    }

    pub(crate) fn require_capture_preparation_v5(
        &self, claim: &aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
        agent: &crate::live_agent::HostAgentLiveSessionV1,
        content: &aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5<'_>,
        controller_session: [u8; 32], now: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), HostArgumentAttemptErrorV1> {
        self.io.completed.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?
            .require_capture_preparation_v5(
                self.journal.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?,
                claim, agent, content, controller_session, now,
            )
    }

    pub(crate) fn require_capture_specification_v5(
        &self, claim: &aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
        agent: &crate::live_agent::HostAgentLiveSessionV1,
        content: &aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5<'_>,
        pipes: &crate::storage_existing_output::capture::StorageCapturePipeLoanV2<'_>,
        controller_session: [u8; 32], now: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), HostArgumentAttemptErrorV1> {
        self.io.completed.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?
            .require_capture_specification_v5(
                self.journal.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?,
                claim, agent, content, pipes, controller_session, now,
            )
    }

    pub(crate) fn names_receiving_demand_v2() -> Option<ResourceVector> {
        aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(super::HOST_STATE_ROOT), super::JOURNAL_NAME,
        ).ok()
    }

    pub(crate) fn names_post_receiving_demand_v2() -> Option<ResourceVector> {
        aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
            super::JOURNAL_NAME,
        ).ok()
    }

    pub(crate) fn observe_names_before_v2(
        &self, original: &mut aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?.journal
            .validate_held_owned_at_for_uid_retaining(super::HOST_STATE_ROOT,
                super::JOURNAL_NAME, 0, original)
    }

    pub(crate) fn observe_names_before_with_directory_v6(&self,
        shared: &aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
        original: &mut aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?.journal
            .validate_held_owned_at_with_directory_retaining_v6(
                std::path::Path::new(super::HOST_STATE_ROOT), super::JOURNAL_NAME, 0,
                original, shared)
    }

    pub(crate) fn observe_names_post_v2(
        &self, original: &mut aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?.journal
            .observe_held_names_post_retaining_v1(original)
    }

    pub(crate) fn completed_original_cutoff_v2(&self) -> Result<u64, HostArgumentAttemptErrorV1> {
        self.io.completed.as_ref().ok_or(HostArgumentAttemptErrorV1::Binding)?.original_cutoff_v2()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure()
            .or_else(|| self.journal.as_ref()?.journal.retained_native_append_failure_v1())
            .or_else(|| self.opened.as_ref()?.0.retained_native_append_failure_v1())
            .or_else(|| self.future_append.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.io.failure())
            .or_else(|| self.construction.as_ref()?.as_ref().err().map(|error| error as _))
    }
}
