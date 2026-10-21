//! Retains exact fixed-role Session names, cookie and extent observations.
//!
//! The enclosing C18 lender pays the complete fixed shape before entry. These
//! originals establish the physical client association only; remote64/65
//! success and actual floor attachment remain separate mandatory transitions.

use aos_sandbox_api::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{RecordBindingError, SeqpacketSocket, StorageSeqpacketSessionOriginV1};

use crate::journal::{
    Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalPreopenReplayExtentV1, StorageNativeOpeningOwnerLinkV1,
};
use crate::ResourceReservationErrorV1;
use super::{Slot, error};
use std::error::Error;

pub(in crate::controller_execution_operation) struct ExecutionAvailabilitySessionNativeOriginalV2 {
    entered: bool,
    recipe: Slot<(), JournalError>,
    names: ProtectedJournalCurrentnessOriginalsV1,
    before: Slot<(), JournalError>,
    journal: Option<StorageNativeOpeningOwnerLinkV1>,
    binding: Option<([u8; 32], [u8; 32])>,
    socket: Slot<StorageSeqpacketSessionOriginV1, RecordBindingError>,
    kernel: Slot<u64, aos_linux_descriptors::Error>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Slot<ProtectedJournalPreopenReplayExtentV1, JournalError>,
    after_names: ProtectedJournalCurrentnessOriginalsV1,
    after: Slot<(), JournalError>,
}

/// Retains the actual DATA comparison and independently reached native cookie.
#[derive(Debug)]
pub struct ControllerExecutionAvailabilitySessionCurrentnessErrorV2 {
    data: Result<(), JournalError>,
    socket: Slot<(), RecordBindingError>,
    kernel: Slot<u64, aos_linux_descriptors::Error>,
}

impl Error for ControllerExecutionAvailabilitySessionCurrentnessErrorV2 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.data.as_ref().err().map(|cause| cause as _)
            .or_else(|| error(&self.kernel)).or_else(|| error(&self.socket))
    }
}

impl std::fmt::Display for ControllerExecutionAvailabilitySessionCurrentnessErrorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.source() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original execution availability Session changed"),
        }
    }
}

impl ExecutionAvailabilitySessionNativeOriginalV2 {
    pub(in crate::controller_execution_operation) fn require_journal_v2(&self, journal: &Journal) -> Result<(), ResourceReservationErrorV1> {
        if self.journal.as_ref().is_some_and(|link| link.matches_journal_v1(journal)) {
            Ok(())
        } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(in crate::controller_execution_operation) fn observe_same_v2(original: Option<&Self>, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ControllerExecutionAvailabilitySessionCurrentnessErrorV2> {
        let data = (|| {
            let original = original.ok_or(JournalError::ProtectedBoundary)?;
            original.require_journal_v2(journal).map_err(|_| JournalError::ProtectedBoundary)?;
            if original.binding != Some((transcript.session_binding(), transcript.protected_context_digest())) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })();
        let mut kernel = None;
        // This native comparison stays independent of financial/currentness
        // success, so an owed after observation cannot be suppressed.
        let observed = original.and_then(|original| original.socket.as_ref())
            .and_then(|value| value.as_ref().ok())
            .map(|origin| origin.require_same_socket_retaining_v4(socket, &mut kernel));
        if data.is_err() || !matches!(observed, Some(Ok(()))) {
            Err(ControllerExecutionAvailabilitySessionCurrentnessErrorV2 { data, socket: observed, kernel })
        } else { Ok(()) }
    }

    pub(in crate::controller_execution_operation) fn new() -> Self {
        Self {
            entered: false, recipe: None, names: ProtectedJournalCurrentnessOriginalsV1::new(),
            before: None, journal: None, binding: None, socket: None, kernel: None,
            metadata: None, extent: None,
            after_names: ProtectedJournalCurrentnessOriginalsV1::new(), after: None,
        }
    }

    pub(in crate::controller_execution_operation) fn fixed_demand_v2(host: bool) -> Result<ResourceVector, JournalError> {
        let names = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(directory(host)), "session.journal")?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        names.checked_add(names).and_then(|demand| demand.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, memory)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(in crate::controller_execution_operation) fn capture_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, host: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.capture_for_purpose_once_v2(journal, socket, transcript, host, false)
    }

    pub(in crate::controller_execution_operation) fn capture_cleanup_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.capture_for_purpose_once_v2(journal, socket, transcript, true, true)
    }

    fn capture_for_purpose_once_v2(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, host: bool, cleanup: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        let protocol = if host { BrokerSessionProtocolV1::Host } else { BrokerSessionProtocolV1::Storage };
        let method = if host { BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 }
            else { BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 };
        self.recipe = Some((|| {
            journal.ensure_protected_authority()?;
            if transcript.protocol() != protocol
                || transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER
                || if cleanup {
                    !host || !aos_sandbox_broker_session_protocol::profile::is_host_no_apply_cleanup_transcript_v1(transcript)
                } else { !transcript.negotiated_methods().contains(&method) }
                || !journal.has_captured_append_custody_v1()
                || journal.configured_limits() != crate::journal::broker_session_receiving::protected_session_journal_limits_v1()
            { return Err(JournalError::ProtectedBoundary); }
            Ok(())
        })());
        if !matches!(self.recipe, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }

        self.before = Some(journal.validate_held_owned_at_for_uid_retaining(
            directory(host), "session.journal", rustix::process::geteuid().as_raw(), &mut self.names));
        if matches!(self.before, Some(Ok(()))) {
            self.journal = Some(journal.held_session_owner_link_v1());
            self.binding = Some((transcript.session_binding(), transcript.protected_context_digest()));
            self.socket = Some(socket.capture_storage_session_origin_retaining_v4(&mut self.kernel));
            if matches!(self.socket, Some(Ok(_))) {
                self.extent = Some(journal.held_session_receiving_extent_v1(&mut self.metadata));
            }
        }
        // Entered names-before always owes this post, including a failed
        // native before, cookie or extent. No healthy financial gate intervenes.
        self.after = Some(journal.observe_held_names_post_retaining_v1(&mut self.after_names));
        if self.failure_v2().is_some() || !matches!(self.extent, Some(Ok(_))) {
            Err(ResourceReservationErrorV1::Conflict)
        } else { Ok(()) }
    }

    pub(in crate::controller_execution_operation) fn completed_session_binding_data_v2(&self)
        -> Result<[u8; 32], ResourceReservationErrorV1> {
        if self.failure_v2().is_some() || !matches!(self.before, Some(Ok(())))
            || !matches!(self.after, Some(Ok(()))) || !matches!(self.extent, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.binding.map(|binding| binding.0).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_execution_operation) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.recipe).or_else(|| self.names.failure()).or_else(|| error(&self.before))
            .or_else(|| error(&self.kernel)).or_else(|| error(&self.socket))
            .or_else(|| error(&self.metadata)).or_else(|| error(&self.extent))
            .or_else(|| self.after_names.failure()).or_else(|| error(&self.after))
    }
}

fn directory(host: bool) -> &'static str {
    if host { "/var/lib/aos/sandboxd/broker-session/host" }
    else { crate::journal::broker_session_receiving::CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1 }
}
