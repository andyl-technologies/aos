//! Keeps each actual Session IO phase on its same genuine C receiving original.
//!
//! Session witness checks remain in Security's shared retained flight. These
//! stages bind that flight to its already-completed role HELLO native owner;
//! they do not enter a new profile scope or replace the enclosing prearmed C,
//! Source and Root after destinations. Every entered phase owns a socket post
//! even when C's earlier debit has closed its financial original.

use super::*;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, StorageSeqpacketSendAttemptV1};
use crate::journal::broker_session_receiving::{
    outcome_demand, StorageSessionGeometryRefusalV1,
};

impl<'io, 'scope, 'source, 'original> NativeSessionIoMemberV2<'io, 'scope, 'source, 'original> {
    fn begin_io_v1(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, expected: IoPhaseV1, entered: IoPhaseV1,
    ) -> Result<(), ResourceReservationErrorV1> {

        let stage = self.stages_v2().active_mut()?;
        if stage.phase != expected || stage.before.is_some() || stage.failure().is_some()
            || (expected == IoPhaseV1::Prepared && stage.authenticated_request.is_none()) {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        stage.phase = entered;
        // Arm the independent destination before a healthy C check can fail.
        let current = self.require_current_v2();
        let association = self.require_session_v2(journal, socket, transcript);
        let stage = self.stages_v2().active_mut()?;
        stage.before = Some(current);
        stage.before_association = Some(association);
        if stage.failure().is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

    /// Starts the same admitted request's construction, retaining its entry.
    ///
    /// # Errors
    /// Refuses another phase, changed C or Session, and any earlier failure.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        self.begin_io_v1(journal, socket, transcript, IoPhaseV1::Fresh, IoPhaseV1::Preparing)
    }

    /// Starts the actual prepared packet's retained native send.
    ///
    /// # Errors
    /// Refuses an unfinished preparation, prior failure or changed original.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        self.begin_io_v1(journal, socket, transcript, IoPhaseV1::Prepared, IoPhaseV1::Sending)
    }

    /// Starts a retained receive only after the original packet was sent.
    ///
    /// # Errors
    /// Refuses a foreign phase, changed original or earlier failure.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        self.begin_io_v1(journal, socket, transcript, IoPhaseV1::Receiving, IoPhaseV1::Receiving)
    }

    /// Starts readiness observation for the same nonconsuming native attempt.
    ///
    /// # Errors
    /// Refuses an unrelated send/receive phase or any failed original.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        let (expected, entered) = if wants_write {
            (IoPhaseV1::Prepared, IoPhaseV1::WaitingSend)
        } else { (IoPhaseV1::Receiving, IoPhaseV1::WaitingReceive) };
        self.begin_io_v1(journal, socket, transcript, expected, entered)
    }

    /// Runs the entered phase's independently owed same-socket observation.
    ///
    /// This deliberately does not gate native observation on healthy C. The
    /// actual raw socket identity Result is retained even after financial refusal.
    ///
    /// # Errors
    /// Retains a changed native Session or refuses missing/repeated entry.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {

        let stage = self.stages_v2().active_mut()?;
        if stage.before.is_none() || stage.after_association.is_some() {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let association = self.require_session_v2(journal, socket, transcript);
        let stage = self.stages_v2().active_mut()?;
        stage.after_association = Some(association);
        if stage.failure().is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

    /// Borrows the immutable deadline from the exact persisted Apply attempt.
    ///
    /// # Errors
    /// Refuses a missing or failed original stage; this supplies no fresh deadline.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn original_cutoff_data_v1(&mut self) -> Result<u64, ResourceReservationErrorV1> {
        let stage = self.stages_v2().active_mut()?;
        if stage.failure().is_some() || stage.cutoff == 0 { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(stage.cutoff)
    }

    /// Disposes positive entry/post comparison DATA after the actual IO result.
    ///
    /// # Errors
    /// Refuses failed/incomplete posts or a phase without a consumed IO result.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn finish_positive_io_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        let stage = self.stages_v2().active_mut()?;
        if stage.failure().is_some() || !matches!(stage.after_association, Some(Ok(()))) {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let next = match stage.phase {
            IoPhaseV1::Preparing => IoPhaseV1::Prepared,
            IoPhaseV1::Sending => IoPhaseV1::Receiving,
            IoPhaseV1::Receiving => IoPhaseV1::Decode,
            _ => { stage.closed = true; return Err(ResourceReservationErrorV1::Conflict); }
        };
        reset_positive_turn(stage, next);
        Ok(())
    }

    /// Holds the same nonconsuming send through actual receipt disposal.
    ///
    /// # Errors
    /// Refuses consumed/partial sends, foreign sockets or incomplete posts.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn prepare_pending_send_disposal_once(self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<StorageProvisioningIoDisposalV1<'io>, ResourceReservationErrorV1> {
        let retain_native = matches!(&self, NativeSessionIoMemberV2::MaintenanceCatalog(_) | NativeSessionIoMemberV2::MaintenanceStorage(_));
        let stage = self.into_stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Sending || !receipt.is_nonconsuming() {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        stage.pending_binding = Some(if retain_native {
            receipt.require_same_socket_retaining_v4(socket, &mut stage.pending_native)
        } else {
            receipt.require_same_socket(socket)
        });
        pending_disposal(stage, IoPhaseV1::Prepared)
    }

    /// Holds the actual no-sample receive refusal through receipt disposal.
    ///
    /// # Errors
    /// Refuses consumed previews, malformed controls, fatal errors or failed posts.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn prepare_pending_receive_disposal_once(self,
        receipt: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<StorageProvisioningIoDisposalV1<'io>, ResourceReservationErrorV1> {
        let stage = self.into_stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Receiving
            || !(receipt.is_nonconsuming_would_block() || receipt.is_nonconsuming_interrupted()) {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        pending_disposal(stage, IoPhaseV1::Receiving)
    }

    /// Holds the successful readiness capsule until its actual native disposal.
    ///
    /// # Errors
    /// Refuses a nonwait phase or incomplete/failed independent posts.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn prepare_positive_wait_disposal_once(self)
        -> Result<StorageProvisioningIoDisposalV1<'io>, ResourceReservationErrorV1> {
        let stage = self.into_stages_v2().active_mut()?;
        let next = match stage.phase {
            IoPhaseV1::WaitingSend => IoPhaseV1::Prepared,
            IoPhaseV1::WaitingReceive => IoPhaseV1::Receiving,
            _ => { stage.closed = true; return Err(ResourceReservationErrorV1::Conflict); }
        };
        pending_disposal(stage, next)
    }

    /// Admits the actual retained hostile packet before either schema decoder.
    ///
    /// # Errors
    /// Retains actual geometry/refusal and never replaces a failed decoder entry.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), ResourceReservationErrorV1> {

        let inventory = self.stages_v2().active == Some(true);
        let stage = self.stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Decode || stage.decode.is_some() || stage.failure().is_some() {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        let geometry = self.response_decode_v2(packet.len(), inventory);
        let stage = self.stages_v2().active_mut()?;
        stage.decode_geometry = Some(geometry);
        let geometry = stage.decode_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        let canonical = packet.len().checked_mul(3).and_then(|n| u64::try_from(n).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let incoming = geometry.checked_add(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, canonical))?;
        let complete = self.complete_base_v2(incoming)?;

        let paid = self.require_complete_v2( complete);
        self.stages_v2().active_mut()?.decode = Some(paid);
        if self.stages_v2().active_mut()?.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let turn = self.native_turn_v2();
        self.stages_v2().retain_paid_v1(turn, incoming)?;
        Ok(())
    }

    /// Admits the exact existing outcome/history representation before its CAS.
    ///
    /// # Errors
    /// Retains actual preimage/request/body geometry and complete C23 refusal.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), ResourceReservationErrorV1> {
        let stage = self.stages_v2().active_mut()?;
        if stage.phase != IoPhaseV1::Decode || !matches!(stage.decode, Some(Ok(())))
            || stage.outcome.is_some() || stage.failure().is_some() {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        let extent = stage.extent.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        stage.outcome_geometry = Some(outcome_demand(extent, stored, request, body));
        let incoming = stage.outcome_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.complete_base_v2(incoming)?;

        let paid = self.require_complete_v2( complete);
        self.stages_v2().active_mut()?.outcome = Some(paid);
        if self.stages_v2().active_mut()?.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let turn = self.native_turn_v2();
        self.stages_v2().retain_paid_v1(turn, incoming)?;
        Ok(())
    }

    /// Records local disposition only after the retained terminal and all posts.
    ///
    /// Security alone checks the actual signed outcome/model and native posts;
    /// the phase keeps its full resident invoice and issues no semantic grant.
    ///
    /// # Errors
    /// Refuses incomplete outcome admission or any failed native stage.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn finish_terminal_data_once_v2(&mut self, expected_body: &[u8], journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {

        let journal_association = self.require_journal_v2(journal);
        let inventory = self.stages_v2().active == Some(true);
        let expected = self.method_v2(inventory);
        let protocol = self.protocol_v2();
        let stage = self.stages_v2().active_mut()?;
        stage.native_journal = Some(journal_association);
        if !matches!(stage.native_journal, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        if stage.phase != IoPhaseV1::Decode || !matches!(stage.outcome, Some(Ok(())))
            || !matches!(stage.terminal_association, Some(Ok(()))) || stage.failure().is_some()
            || outcome.method() != expected || outcome.request().method() != expected
            || outcome.request().session_binding() != stage.binding
            || stage.authenticated_request != Some(outcome.request().signed_request_digest())
            || (!inventory && outcome.request().exact_body() != expected_body)
            || !matches!(outcome.result(), aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { .. }) {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        stage.native_key = Some(aos_sandbox_protocol::authenticated_session::stored_history::canonical_protocol_key_v1(
            protocol));
        stage.native_position = Some((|| {
            let key = stage.native_key.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let raw = journal.get(crate::RecordNamespace::BrokerSessionTraffic, key).ok_or(ResourceReservationErrorV1::Conflict)?;
            aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryV1::decode_retaining(key, raw, &mut stage.native_row)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let stored = stage.native_row.stored().ok_or(ResourceReservationErrorV1::Conflict)?;
            aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1::decode_retaining(&stored.history, &mut stage.native_history)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let history = stage.native_history.history().ok_or(ResourceReservationErrorV1::Conflict)?;
            let head = history.head().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if stored.endpoint != aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client
                || head.phase() != aos_sandbox_broker_session_protocol::BrokerSessionDurablePhaseV1::Terminal
                || head.outcome_packet() != Some(outcome.canonical_packet())
                || head.request_packet() != outcome.request().canonical_packet()
                || stored.current_head != history.head_commitment() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(*blake3::hash(raw).as_bytes())
        })());
        if !matches!(stage.native_position, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        stage.terminal_identity = Some((outcome.request().signed_request_digest(),
            *blake3::hash(outcome.canonical_packet()).as_bytes()));
        stage.phase = IoPhaseV1::Complete;
        Ok(())
    }

    /// Runs the final same-Session native post independently of semantic success.
    ///
    /// # Errors
    /// Retains an actual changed socket/owner, including after a poisoned debit.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn observe_terminal_post_once_v2(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {

        let stage = self.stages_v2().active_mut()?;
        if stage.terminal_association.is_some() {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        let association = self.require_session_v2(journal, socket, transcript);
        let capture_position = matches!(self, NativeSessionIoMemberV2::StartResource(_) | NativeSessionIoMemberV2::HostCatalog(_)
            | NativeSessionIoMemberV2::DeletePreparation(_) | NativeSessionIoMemberV2::MaintenanceCatalog(_)
            | NativeSessionIoMemberV2::ExecutionNoApply(_) | NativeSessionIoMemberV2::ExecutionAvailability(_) | NativeSessionIoMemberV2::DeleteApply(_)
            | NativeSessionIoMemberV2::DeleteNetwork(_) | NativeSessionIoMemberV2::DeleteMount(_) | NativeSessionIoMemberV2::MaintenanceStorage(_));
        let stage = self.stages_v2().active_mut()?;
        stage.terminal_association = Some(association);
        if capture_position {
            // This independent prepaid names/witness post remains owed after
            // the preceding socket or financial failure. It cannot heal either.
            stage.terminal_native = Some(journal.observe_session_completion_position_retaining_v2(
                &mut stage.terminal_names, &mut stage.terminal_witness));
        }
        if stage.failure().is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

}

fn reset_positive_turn(stage: &mut IoStageV1, next: IoPhaseV1) {
    stage.before = None;
    stage.before_association = None;
    stage.after_association = None;
    stage.pending_binding = None;
    stage.pending_native = None;
    stage.phase = next;
}

fn pending_disposal(stage: &mut IoStageV1, next: IoPhaseV1)
    -> Result<StorageProvisioningIoDisposalV1<'_>, ResourceReservationErrorV1> {
    if stage.failure().is_some() || !matches!(stage.after_association, Some(Ok(()))) {
        stage.closed = true;
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(StorageProvisioningIoDisposalV1 { stage, next, completed: false })
}

/// Borrows the actual positive IO phase until its native receipt has dropped.
///
/// Only the shared Security kernel consumes this mechanical disposition after
/// dropping the same native receipt/readiness owner. Failure keeps it closed.
#[doc(hidden)]
#[must_use = "dispose the same successful native receipt before completing this phase"]
pub struct StorageProvisioningIoDisposalV1<'positive> {
    stage: &'positive mut IoStageV1,
    next: IoPhaseV1,
    completed: bool,
}

impl StorageProvisioningIoDisposalV1<'_> {
    /// Completes the same positively checked readiness capsule's real disposal.
    #[doc(hidden)]
    pub fn complete_after_wait_disposal(self) { self.complete_after_receipt_disposal(); }

    /// Completes the same nonconsuming native receipt's real disposal.
    #[doc(hidden)]
    pub fn complete_after_receipt_disposal(mut self) {
        reset_positive_turn(self.stage, self.next);
        self.completed = true;
    }
}

impl Drop for StorageProvisioningIoDisposalV1<'_> {
    fn drop(&mut self) {
        if !self.completed { self.stage.closed = true; }
    }
}

impl<'io, 'scope, 'source, 'original> NativeSessionIoMemberV2<'io, 'scope, 'source, 'original> {
    /// Admits the terminal predecessor replay from the actual held extent.
    ///
    /// # Errors
    /// Retains metadata, extent and geometry refusals before replay/map growth.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn admit_retained_predecessor_once(&mut self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        let stage = self.stages_v2().active_mut()?;
        if !matches!(stage.outcome, Some(Ok(()))) || stage.predecessor.is_some() || stage.failure().is_some() {
            stage.closed = true; return Err(ResourceReservationErrorV1::Conflict);
        }
        stage.predecessor_extent = Some(journal.held_session_receiving_extent_v1(&mut stage.predecessor_metadata));
        let geometry = stage.predecessor_extent.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(StorageSessionGeometryRefusalV1)
            .and_then(storage_retained_current_replay_demand_v1)
            .and_then(|demand| demand.checked_add(demand).map_err(|_| StorageSessionGeometryRefusalV1));
        let geometry = geometry.map(|demand| self.pure_model_demand_v2(demand));
        let stage = self.stages_v2().active_mut()?;
        stage.predecessor_geometry = Some(geometry);
        let incoming = stage.predecessor_geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.complete_base_v2(incoming)?;

        let paid = self.require_complete_v2( complete);
        self.stages_v2().active_mut()?.predecessor = Some(paid);
        if self.stages_v2().active_mut()?.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let turn = self.native_turn_v2();
        self.stages_v2().retain_paid_v1(turn, incoming)?;
        Ok(())
    }
}

impl<'io, 'scope, 'source, 'original> NativeSessionIoMemberV2<'io, 'scope, 'source, 'original> {
    /// Binds the actual signed request before the shared native sender can enter.
    ///
    /// # Errors
    /// Retains a different actual method/body/session/ceiling and refuses reentry.
    #[doc(hidden)]
    pub(in crate::controller_resource_reservation) fn bind_request_data_once_v2(&mut self, expected_body: &[u8],
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {

        let inventory = self.stages_v2().active == Some(true);
        let expected_method = self.method_v2(inventory);
        let stage = self.stages_v2().active_mut()?;
        if stage.request_binding.is_some() { stage.closed = true; return Err(ResourceReservationErrorV1::Conflict); }
        stage.request_binding = Some((|| {
            let shape = stage.shape.ok_or(ResourceReservationErrorV1::Conflict)?;
            let method = expected_method;
            if stage.phase != IoPhaseV1::Prepared || request.method() != method
                || request.session_binding() != stage.binding || request.canonical_packet().len() > shape.request_bytes
                || request.maximum_response_bytes() as usize > shape.response_bytes
                || request.deadline_boottime_nanoseconds() > stage.cutoff
                || (!inventory && request.exact_body() != expected_body) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(stage.request_binding, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        stage.authenticated_request = Some(request.signed_request_digest());
        stage.cutoff = stage.cutoff.min(request.deadline_boottime_nanoseconds());
        Ok(())
    }
}


macro_rules! delegate_common_io_turns_v2 {
    ($member:ident) => {
    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).begin_request_preparation_once(journal, socket, transcript)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).begin_send_once(journal, socket, transcript)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).begin_receive_once(journal, socket, transcript)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).begin_wait_once(journal, socket, transcript, wants_write)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).observe_io_post_once(journal, socket, transcript)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn original_cutoff_data_v1(&mut self) -> Result<u64, ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).original_cutoff_data_v1()
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn finish_positive_io_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).finish_positive_io_once()
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<StorageProvisioningIoDisposalV1<'positive>, ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).prepare_pending_send_disposal_once(receipt, socket)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn prepare_pending_receive_disposal_once<'positive>(&'positive mut self,
        receipt: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<StorageProvisioningIoDisposalV1<'positive>, ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).prepare_pending_receive_disposal_once(receipt)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<StorageProvisioningIoDisposalV1<'_>, ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).prepare_positive_wait_disposal_once()
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).admit_response_decode_once(packet)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).admit_outcome_once(stored, request, body)
    }

    /// Executes this finite phase on the same original C and native Session.
    ///
    /// # Errors
    /// Retains phase, receiving, original association and native refusal.
    #[doc(hidden)]
    pub fn admit_retained_predecessor_once(&mut self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::$member(self).admit_retained_predecessor_once(journal)
    }
    };
}

impl CreateProvisioningStorageIoLoanV1<'_> {
    delegate_common_io_turns_v2!(CreateStorage);

    /// Binds the actual signed Storage request to its original prepared effect.
    ///
    /// # Errors
    /// Retains changed contract, request, Session or native phase refusal.
    #[doc(hidden)]
    pub fn bind_storage_request_once_v1(&mut self, prepared: &PreparedAuthorityEffectV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v1(prepared, 1, None)?;
        NativeSessionIoMemberV2::CreateStorage(self)
            .bind_request_data_once_v2(prepared.attempt().body(), request)
    }

    /// Checks the same signed Storage terminal against its actual native row.
    ///
    /// # Errors
    /// Retains changed contract, complete outcome or actual native history.
    #[doc(hidden)]
    pub fn finish_storage_terminal_once_v1(&mut self, prepared: &PreparedAuthorityEffectV1,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v1(prepared, 2, None)?;
        NativeSessionIoMemberV2::CreateStorage(self)
            .finish_terminal_data_once_v2(prepared.attempt().body(), journal, outcome)
    }

    /// Runs the same Storage Session's independently owed terminal observation.
    ///
    /// # Errors
    /// Retains actual native refusal even after an earlier C or body failure.
    #[doc(hidden)]
    pub fn observe_storage_terminal_post_once_v1(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::CreateStorage(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}

impl crate::controller_execution_operation::ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    delegate_common_io_turns_v2!(ExecutionNoApply);
}

impl crate::OriginalDeleteStorageApplyLoanV3<'_> {
    delegate_common_io_turns_v2!(DeleteApply);
}

impl crate::OriginalDeleteNetworkApplyLoanV4<'_> {
    delegate_common_io_turns_v2!(DeleteNetwork);
}

impl crate::OriginalDeleteMountReapLoanV4<'_> {
    delegate_common_io_turns_v2!(DeleteMount);
}

impl crate::controller_execution_operation::ControllerExecutionAvailabilityClientLoanV2<'_> {
    delegate_common_io_turns_v2!(ExecutionAvailability);
}

impl crate::StartResourceProvisioningIoLoanV2<'_> {
    delegate_common_io_turns_v2!(StartResource);

    /// Binds the actual Network63/19 packet to its genuine Start preparation.
    ///
    /// # Errors
    /// Retains changed prepared/Root/Source/native association or request data.
    #[doc(hidden)]
    pub fn bind_resource_request_once_v2(&mut self, prepared: &crate::PreparedStartResourceRequestOriginalV2,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_contract_once_v2(prepared, 1, None)?;
        let body = prepared.request_body_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        NativeSessionIoMemberV2::StartResource(self).bind_request_data_once_v2(body, request)
    }

    /// Checks the actual signed Network outcome against its same native row.
    ///
    /// # Errors
    /// Retains changed Start preparation, complete outcome or native history.
    #[doc(hidden)]
    pub fn finish_resource_terminal_once_v2(&mut self, prepared: &crate::PreparedStartResourceRequestOriginalV2,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_contract_once_v2(prepared, 2, None)?;
        let body = prepared.request_body_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        NativeSessionIoMemberV2::StartResource(self).finish_terminal_data_once_v2(body, journal, outcome)
    }

    /// Runs the same Network Session's independently owed terminal observation.
    ///
    /// # Errors
    /// Retains actual native refusal even after an earlier C or body failure.
    #[doc(hidden)]
    pub fn observe_resource_terminal_post_once_v2(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::StartResource(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}

impl crate::StartHostCatalogIoLoanV2<'_> {
    delegate_common_io_turns_v2!(HostCatalog);

    /// Binds the actual sole-decoded method17 packet to this canonical source.
    ///
    /// # Errors
    /// Retains changed source/Header context, signed request or native phase.
    #[doc(hidden)]
    pub fn bind_catalog_request_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 1, None)?;
        self.require_publication_request_v2(request)?;
        // Header coordinates were produced from the SAME private Session and
        // source above; its canonical signed digest is retained by this common
        // binder and checked again against the actual protected terminal row.
        NativeSessionIoMemberV2::HostCatalog(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Joins the exact signed method17 outcome to the actual protected Session row.
    ///
    /// # Errors
    /// Retains changed source/request, incomplete native posts, or row mismatch.
    #[doc(hidden)]
    pub fn finish_catalog_terminal_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 2, None)?;
        self.require_publication_request_v2(outcome.request())?;
        NativeSessionIoMemberV2::HostCatalog(self)
            .finish_terminal_data_once_v2(outcome.request().exact_body(), journal, outcome)
    }

    /// Runs the same Host Session's independent native terminal post.
    ///
    /// # Errors
    /// Retains actual native refusal after primary financial/body failure too.
    #[doc(hidden)]
    pub fn observe_catalog_terminal_post_once_v2(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::HostCatalog(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}

impl crate::OriginalDeleteStoragePreparationLoanV3<'_> {
    delegate_common_io_turns_v2!(DeletePreparation);
}

impl crate::ControllerCatalogMaintenanceIoLoanV2<'_> {
    delegate_common_io_turns_v2!(MaintenanceCatalog);

    /// Binds the actual sole-decoded method17 packet to this canonical source.
    ///
    /// # Errors
    /// Retains changed source/Header context, signed request or native phase.
    #[doc(hidden)]
    pub fn bind_catalog_request_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 1, None)?;
        self.require_publication_request_v2(request)?;
        // Header coordinates were produced from the SAME private Session and
        // source above; its canonical signed digest is retained by this common
        // binder and checked again against the actual protected terminal row.
        NativeSessionIoMemberV2::MaintenanceCatalog(self)
            .bind_request_data_once_v2(request.exact_body(), request)
    }

    /// Joins the exact signed method17 outcome to the actual protected Session row.
    ///
    /// # Errors
    /// Retains changed source/request, incomplete native posts, or row mismatch.
    #[doc(hidden)]
    pub fn finish_catalog_terminal_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 2, None)?;
        self.require_publication_request_v2(outcome.request())?;
        NativeSessionIoMemberV2::MaintenanceCatalog(self)
            .finish_terminal_data_once_v2(outcome.request().exact_body(), journal, outcome)
    }

    /// Runs the same Host Session's independent native terminal post.
    ///
    /// # Errors
    /// Retains actual native refusal after primary financial/body failure too.
    #[doc(hidden)]
    pub fn observe_catalog_terminal_post_once_v2(&mut self, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::MaintenanceCatalog(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}

impl crate::ControllerMaintenanceStorageIoLoanV3<'_> {
    delegate_common_io_turns_v2!(MaintenanceStorage);

    /// Binds only the actual Root-transferred31 or retained fresh18 packet.
    ///
    /// # Errors
    /// Retains changed prepared/request/native phase or signed request refusal.
    #[doc(hidden)]
    pub fn bind_storage_request_once_v3(
        &mut self,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v3(prepared, 1, None)?;
        NativeSessionIoMemberV2::MaintenanceStorage(self)
            .bind_request_data_once_v2(prepared.request_data_v3().0, request)
    }

    /// Joins each actual signed outcome to its protected same-Session terminal.
    ///
    /// # Errors
    /// Retains changed prepared/request, terminal row, phase or native history.
    #[doc(hidden)]
    pub fn finish_storage_terminal_once_v3(
        &mut self,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v3(prepared, 2, None)?;
        NativeSessionIoMemberV2::MaintenanceStorage(self).finish_terminal_data_once_v2(
            prepared.request_data_v3().0,
            journal,
            outcome,
        )
    }

    /// Runs the independently owed native terminal after even after body refusal.
    ///
    /// # Errors
    /// Retains actual socket/names/witness failure without skipping either post.
    #[doc(hidden)]
    pub fn observe_storage_terminal_post_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::MaintenanceStorage(self)
            .observe_terminal_post_once_v2(journal, socket, transcript)
    }
}
