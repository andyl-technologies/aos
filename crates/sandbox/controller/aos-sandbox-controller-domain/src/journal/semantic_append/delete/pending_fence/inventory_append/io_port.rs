//! Lends one closed native IO turn to the existing Security transport.
//!
//! The enclosing original keeps C17 and Source exclusive throughout the whole
//! query. Each reached turn prepays its exact native/name traffic before entry;
//! its already-armed after never needs a new financial or healthy-C admission.

use super::*;
use super::io::{DeleteInventoryIoDisposalV1, Turn};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum IoPhase {
    Unprepared,
    Prepared,
    Sent,
    Decoded,
}

impl DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_> {
    /// Checks the exact Security layout paid by this original's constructor.
    ///
    /// # Errors
    /// Refuses an underdeclared layout, reentry or a failed query. Refusal is
    /// sticky and occurs before the upper owner or Session native IO enters.
    #[doc(hidden)]
    pub fn require_security_construction_once_v1(
        &mut self,
        actual: DeleteInventorySecurityShapeDataV1,
    ) -> Result<(), JournalError> {
        if self.security_admission.is_some() || self.first.is_some() {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        self.security_admission = Some(if self.phase == Phase::Fresh && actual == self.security_shape {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        });
        if self.security_admission.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::SecurityAdmission);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Starts request formation on the same captured Session.
    ///
    /// # Errors
    /// Retains phase, payment, identity, native or deadline refusal.
    #[doc(hidden)]
    pub fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>
    {
        self.begin_io(Turn::Preparation, IoPhase::Unprepared, journal, socket, transcript)
    }

    /// Starts one actual send of the fixed header-only Inventory request.
    ///
    /// # Errors
    /// Retains phase, payment, identity, native or deadline refusal.
    #[doc(hidden)]
    pub fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>
    {
        self.begin_io(Turn::Send, IoPhase::Prepared, journal, socket, transcript)
    }

    /// Starts one actual receive of the same already-sent request.
    ///
    /// # Errors
    /// Retains phase, payment, identity, native or deadline refusal.
    #[doc(hidden)]
    pub fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>
    {
        self.begin_io(Turn::Receive, IoPhase::Sent, journal, socket, transcript)
    }

    /// Starts readiness observation for the current pending turn.
    ///
    /// # Errors
    /// Refuses a foreign phase or retains payment/native/deadline failure.
    #[doc(hidden)]
    pub fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), JournalError> {
        let (turn, phase) = if wants_write {
            (Turn::WaitSend, IoPhase::Prepared)
        } else {
            (Turn::WaitReceive, IoPhase::Sent)
        };
        self.begin_io(turn, phase, journal, socket, transcript)
    }

    fn begin_io(&mut self, turn: Turn, expected: IoPhase, journal: &Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        if self.phase != Phase::Captured || self.first.is_some() || self.io_phase != expected
            || !self.io.is_idle() || !matches!(self.security_admission, Some(Ok(())))
        {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, cutoff) = self.source.coordinates()?;
        self.io_geometry = Some((|| {
            let network = match turn {
                Turn::Send => u64::try_from(
                    aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1(),
                ).map_err(|_| JournalError::ProtectedBoundary)?,
                Turn::Receive => u64::try_from(
                    aos_sandbox_broker_session_protocol::projection::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
                ).map_err(|_| JournalError::ProtectedBoundary)?,
                Turn::Preparation | Turn::WaitSend | Turn::WaitReceive => 0,
            };
            io::IoOriginals::traffic_demand(self.directory, network, 0)
        })());
        let demand = match self.io_geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first.get_or_insert(First::IoGeometry);
                if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
                self.phase = Phase::Failed;
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.io_admission = Some(self.source.reserve_additional(
            self.controller, self.launch, self.profile, demand,
        ));
        if self.io_admission.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::IoAdmission);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        let journal_owner = self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let socket_owner = self.socket.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.io.begin(turn, journal, socket, transcript, journal_owner, socket_owner,
            self.protocol, self.binding, self.method, self.directory, self.uid, cutoff).is_err()
        {
            self.first.get_or_insert(First::Io);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Runs the prepaid independent Session/deadline post for an entered turn.
    ///
    /// # Errors
    /// Retains the original primary or owed-post refusal without another debit.
    #[doc(hidden)]
    pub fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>
    {
        // No new before or financial check is allowed on this owed route.
        let (_, cutoff) = self.source.coordinates()?;
        let journal_owner = self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let socket_owner = self.socket.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let result = self.io.after(journal, socket, transcript, journal_owner, socket_owner,
            self.protocol, self.binding, cutoff);
        if result.is_err() {
            self.first.get_or_insert(First::Io);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
        }
        result
    }

    /// Returns only the original kernel/challenge-derived cutoff.
    ///
    /// # Errors
    /// Refuses an absent or failed actual query association.
    #[doc(hidden)]
    pub fn original_cutoff_data_v1(&self) -> Result<u64, JournalError> {
        self.source.coordinates().map(|(_, cutoff)| cutoff)
    }

    /// Completes one successful request, send or receive turn.
    ///
    /// # Errors
    /// Retains failed posts, late positive disposition or a foreign phase.
    #[doc(hidden)]
    pub fn finish_positive_io_once(&mut self) -> Result<(), JournalError> {
        let turn = match self.io.positive_turn_v1() {
            Ok(turn) => turn,
            Err(_) => {
                self.refuse();
                return Err(JournalError::ProtectedBoundary);
            }
        };
        if self.io.complete_consumed_turn_v1().is_err() {
            self.first.get_or_insert(First::Io);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        self.io_phase = match turn {
            Turn::Preparation => IoPhase::Prepared,
            Turn::Send => IoPhase::Sent,
            Turn::Receive => IoPhase::Decoded,
            Turn::WaitSend | Turn::WaitReceive => {
                self.refuse();
                return Err(JournalError::ProtectedBoundary);
            }
        };
        Ok(())
    }

    /// Keeps a genuine nonconsuming send through its positive raw disposal.
    ///
    /// # Errors
    /// Retains a foreign socket, consumed result or failed/late posts.
    #[doc(hidden)]
    pub fn prepare_pending_send_disposal_once(&mut self,
        native: &aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
        socket: &SeqpacketSocket,
    ) -> Result<DeleteInventoryIoDisposalV1<'_>, JournalError> {
        self.io.prepare_send_pending_v1(native, socket)
    }

    /// Keeps a genuine nonconsuming receive through its raw disposal.
    ///
    /// # Errors
    /// Retains consumed or failed/late observations.
    #[doc(hidden)]
    pub fn prepare_pending_receive_disposal_once(&mut self,
        native: &aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
    ) -> Result<DeleteInventoryIoDisposalV1<'_>, JournalError> {
        self.io.prepare_receive_pending_v1(native)
    }

    /// Keeps a successful readiness poll through its actual disposal.
    ///
    /// # Errors
    /// Retains a foreign phase or failed/late observations.
    #[doc(hidden)]
    pub fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<DeleteInventoryIoDisposalV1<'_>, JournalError>
    {
        self.io.prepare_wait_positive_v1()
    }

    /// Checks the same Session's prepaid full terminal replay lane.
    ///
    /// Its future prefix and sole shared replay/model suppliers were admitted
    /// before either append. The actual captured two-TX window enforces that
    /// prefix; this gate creates no new estimate, IO or replay authority.
    ///
    /// # Errors
    /// Refuses a foreign Session, failed outcome or repeated comparison entry.
    #[doc(hidden)]
    pub fn admit_retained_predecessor_once(&mut self, journal: &Journal)
        -> Result<(), JournalError>
    {
        if self.predecessor.is_some() {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        self.predecessor = Some(if self.phase == Phase::Captured && self.first.is_none()
            && self.io_phase == IoPhase::Decoded
            && matches!(self.outcome_admission, Some(Ok(())))
            && self.journal.as_ref().is_some_and(|owner| owner.matches_journal_v1(journal))
            && matches!(self.admission, Some(Ok(())))
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if self.predecessor.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Predecessor);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Admits the actual authenticated outcome before shared history/CAS growth.
    ///
    /// # Errors
    /// Retains a failed decoder, invalid real geometry or same-C17 exhaustion.
    #[doc(hidden)]
    pub fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), JournalError>
    {
        if self.phase != Phase::Captured || self.first.is_some() || self.io_phase != IoPhase::Decoded
            || !matches!(self.decode_admission, Some(Ok(()))) || self.outcome_geometry.is_some()
        {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        self.outcome_geometry = Some((|| {
            let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let complete = crate::journal::broker_session_receiving::outcome_demand(
                extent, stored, request, body,
            ).map_err(|_| JournalError::LimitExceeded("Delete Inventory outcome"))?;
            // The captured two-TX window already admitted these exact native
            // storage bytes. Keep the whole additional outcome model plane.
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, complete.get(D::MemoryBytes)))
        })());
        let demand = match self.outcome_geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first.get_or_insert(First::OutcomeGeometry);
                if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
                self.phase = Phase::Failed;
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.outcome_admission = Some(self.source.reserve_additional(
            self.controller, self.launch, self.profile, demand,
        ));
        if self.outcome_admission.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::OutcomeAdmission);
            if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}
