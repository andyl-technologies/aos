//! Resident zero-FD preparation on the same original pending Storage46 channel.
//!
//! Two fixed whole receive slots retain original record subjects and failures.
//! Endpoint-local heads are checked independently against the same held writer.
//! A failed, cancelled or unwinding loan closes permanently; neither EAGAIN nor
//! EINTR authorizes another attempted preparation action.

use aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1;
use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
use aos_sandbox_protocol::storage_output_reserve::continuation::{
    AUTHORIZATION_V1, MAXIMUM_PREPARATION_BYTES_V1, NOMINATION_V1,
    decode_preparation_v1, encode_preparation_v1, matches_original_request_v1,
};

use super::DormantAuthenticatedBrokerSessionV1;
use crate::BrokerSessionSecurityError;

#[derive(Clone, Copy)]
enum FailureSite {
    Witness,
    Protected,
    Encode(usize),
    Send(usize),
    Receive(usize),
    Decode(usize),
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OriginalOutputRequestIdentityV1 {
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
}

impl OriginalOutputRequestIdentityV1 {
    fn from_original(request: &AuthenticatedBrokerMethodRequestV1) -> Self {
        Self {
            request_id: request.request_id(),
            signed_request_digest: request.signed_request_digest(),
            session_binding: request.session_binding(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original output preparation is closed; its custody remains resident")]
pub(crate) struct OutputPreparationClosedV1;

#[derive(Debug, thiserror::Error)]
#[error("original output witness cause requires its resident Session loan")]
struct OutputWitnessUnavailableV1;

/// Owns original transport results separately from the Session it will borrow.
pub(crate) struct OutputPreparationCustodyV1 {
    original_request: Option<OriginalOutputRequestIdentityV1>,
    original_head: Option<[u8; 32]>,
    encoded: [Option<Result<Vec<u8>, ProtocolValidationError>>; 2],
    sent: [Option<Result<(), SeqpacketError>>; 2],
    packets: [OriginalOutputPacketV1; 2],
    decoded: [Option<Result<StorageOutputRegistrationPreparationV1, ProtocolValidationError>>; 2],
    protected_failure: Option<BrokerSessionSecurityError>,
    first_site: Option<FailureSite>,
    postcheck_debt: Option<BrokerSessionSecurityError>,
    witness_postcheck_debt: bool,
    closed: bool,
}

impl OutputPreparationCustodyV1 {
    pub(crate) fn empty() -> Self {
        Self {
            original_request: None,
            original_head: None,
            encoded: std::array::from_fn(|_| None),
            sent: std::array::from_fn(|_| None),
            packets: std::array::from_fn(|_| OriginalOutputPacketV1::empty()),
            decoded: std::array::from_fn(|_| None),
            protected_failure: None,
            first_site: None,
            postcheck_debt: None,
            witness_postcheck_debt: false,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_site? {
            FailureSite::Witness => Some(&OutputWitnessUnavailableV1),
            FailureSite::Protected => self.protected_failure.as_ref().map(|e| e as &dyn std::error::Error),
            FailureSite::Encode(i) => self.encoded.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            FailureSite::Send(i) => self.sent.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            FailureSite::Receive(i) => Some(self.packets.get(i)?.failure().unwrap_or(&OutputPreparationClosedV1)),
            FailureSite::Decode(i) => self.decoded.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            FailureSite::Closed if self.has_postcheck_debt() => None,
            FailureSite::Closed => Some(&OutputPreparationClosedV1),
        }
    }

    pub(crate) fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first_site? {
            FailureSite::Witness => Some(
                session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1),
            ),
            FailureSite::Receive(index) => Some(
                self.packets.get(index)?.failure_with_session(session)
                    .unwrap_or(&OutputPreparationClosedV1),
            ),
            _ => self.failure(),
        }
    }

    pub(crate) fn postcheck_debt_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_postcheck_debt {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        self.postcheck_debt.as_ref().map(|error| error as &dyn std::error::Error)
    }

    pub(crate) fn has_postcheck_debt(&self) -> bool {
        self.witness_postcheck_debt || self.postcheck_debt.is_some()
    }

    pub(crate) fn record(&self, stage: u32) -> Option<&StorageOutputRegistrationPreparationV1> {
        let index = stage_index(stage)?;
        self.decoded[index].as_ref()?.as_ref().ok()
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&BrokerSessionSecurityError> {
        self.postcheck_debt.as_ref()
    }

    fn close(&mut self, site: FailureSite) {
        self.closed = true;
        if self.first_site.is_none() {
            self.first_site = Some(site);
        }
    }
}

/// Borrows the real pending writer/socket; Drop never releases or replaces them.
pub(crate) struct HeldOutputPreparationV1<'session> {
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    state: &'session mut OutputPreparationCustodyV1,
    completed_turn: bool,
}

impl<'session> HeldOutputPreparationV1<'session> {
    pub(super) fn begin(
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        state: &'session mut OutputPreparationCustodyV1,
    ) -> Self {
        let identity = OriginalOutputRequestIdentityV1::from_original(request);
        if state.original_request.is_some_and(|original| original != identity) {
            state.close(FailureSite::Closed);
        } else {
            state.original_request = Some(identity);
        }
        Self {
            session,
            state,
            completed_turn: false,
        }
    }

    pub(crate) fn original_head(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<[u8; 32], OutputPreparationClosedV1> {
        self.recheck(request)?;
        self.state.original_head.ok_or(OutputPreparationClosedV1)
    }

    pub(crate) fn recheck(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.state.closed || self.state.original_request != Some(OriginalOutputRequestIdentityV1::from_original(request)) {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        if !self.session.revalidate_output_witnesses() {
            self.state.close(FailureSite::Witness);
            return Err(OutputPreparationClosedV1);
        }
        let result = self.session.owner.hold_output_registration_request(
            request, &self.session.transcript, self.session.socket.peer(),
        ).map(|cut| cut.head_commitment());
        match result {
            Ok(head) => {
                if self.state.original_head.is_some_and(|original| original != head) {
                    self.state.protected_failure = Some(BrokerSessionSecurityError::Currentness);
                    self.state.close(FailureSite::Protected);
                    if !self.session.revalidate_output_witnesses() {
                        self.state.witness_postcheck_debt = true;
                    }
                    return Err(OutputPreparationClosedV1);
                }
                self.state.original_head = Some(head);
                if !self.session.revalidate_output_witnesses() {
                    self.state.close(FailureSite::Witness);
                    return Err(OutputPreparationClosedV1);
                }
                Ok(())
            }
            Err(error) => {
                self.state.protected_failure = Some(error);
                self.state.close(FailureSite::Protected);
                if !self.session.revalidate_output_witnesses() {
                    self.state.witness_postcheck_debt = true;
                }
                Err(OutputPreparationClosedV1)
            }
        }
    }

    pub(crate) fn send(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        record: &StorageOutputRegistrationPreparationV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        let Some(index) = stage_index(record.stage) else {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        };
        if self.state.sent[index].is_some()
            || !matches_original_request_v1(record, request)
            || !matches!((request.direction(), record.stage),
                (AuthenticatedBrokerRequestDirectionV1::ServerReceive, NOMINATION_V1)
                | (AuthenticatedBrokerRequestDirectionV1::ClientSend, AUTHORIZATION_V1))
            || (record.stage == NOMINATION_V1
                && record.storage_pending_head != self.state.original_head.ok_or(OutputPreparationClosedV1)?)
            || (record.stage == AUTHORIZATION_V1
                && record.controller_pending_head != self.state.original_head.ok_or(OutputPreparationClosedV1)?)
        {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        self.state.encoded[index] = Some(encode_preparation_v1(record));
        if !matches!(&self.state.encoded[index], Some(Ok(_))) {
            self.state.close(FailureSite::Encode(index));
            return Err(OutputPreparationClosedV1);
        }
        self.recheck(request)?;
        let Some(Ok(packet)) = &self.state.encoded[index] else { return Err(OutputPreparationClosedV1); };
        self.state.sent[index] = Some(self.session.socket.send(packet));
        if self.state.sent[index].as_ref().is_some_and(Result::is_err) {
            self.state.close(FailureSite::Send(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        self.check_after_action(request);
        if self.state.closed {
            Err(OutputPreparationClosedV1)
        } else {
            Ok(())
        }
    }

    pub(crate) fn receive(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        stage: u32,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        let Some(index) = stage_index(stage) else {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        };
        if self.state.packets[index].received.is_some()
            || !matches!((request.direction(), stage),
                (AuthenticatedBrokerRequestDirectionV1::ClientSend, NOMINATION_V1)
                | (AuthenticatedBrokerRequestDirectionV1::ServerReceive, AUTHORIZATION_V1))
        {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        if !self.state.packets[index].receive_once(self.session, MAXIMUM_PREPARATION_BYTES_V1) {
            self.state.close(FailureSite::Receive(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        let Some(packet) = self.state.packets[index].payload() else { return Err(OutputPreparationClosedV1); };
        self.state.decoded[index] = Some(decode_preparation_v1(packet, stage));
        let Some(Ok(decoded)) = &self.state.decoded[index] else {
            self.state.close(FailureSite::Decode(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        };
        if !matches_original_request_v1(decoded, request) {
            self.state.close(FailureSite::Closed);
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        self.check_after_action(request);
        if self.state.closed {
            Err(OutputPreparationClosedV1)
        } else {
            Ok(())
        }
    }

    fn check_after_action(&mut self, request: &AuthenticatedBrokerMethodRequestV1) {
        if self.state.original_request != Some(OriginalOutputRequestIdentityV1::from_original(request)) {
            self.state.close(FailureSite::Closed);
            return;
        }
        if !self.session.revalidate_output_witnesses() {
            if self.state.postcheck_debt.is_none() {
                self.state.witness_postcheck_debt = true;
            }
            self.state.close(FailureSite::Closed);
        }
        // This independent check still runs after native or witness failure.
        let result = self.session.owner.hold_output_registration_request(
            request, &self.session.transcript, self.session.socket.peer(),
        ).map(|cut| cut.head_commitment());
        let error = match result {
            Ok(head) if self.state.original_head == Some(head) => None,
            Ok(_) => Some(BrokerSessionSecurityError::Currentness),
            Err(error) => Some(error),
        };
        if let Some(error) = error {
            if self.state.postcheck_debt.is_none() {
                self.state.postcheck_debt = Some(error);
            }
            self.state.close(FailureSite::Closed);
        }
        if !self.session.revalidate_output_witnesses() {
            if self.state.postcheck_debt.is_none() {
                self.state.witness_postcheck_debt = true;
            }
            self.state.close(FailureSite::Closed);
        }
    }

    /// Ends only this successful short loan; it does not retire the request.
    pub(crate) fn finish_turn(
        mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        self.completed_turn = true;
        Ok(())
    }

    /// Bookends an external domain action even when its resident result failed.
    /// A later currentness error is debt, not a replacement action cause.
    pub(crate) fn finish_action_turn(
        mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.check_after_action(request);
        if self.state.closed {
            return Err(OutputPreparationClosedV1);
        }
        self.completed_turn = true;
        Ok(())
    }
}

impl Drop for HeldOutputPreparationV1<'_> {
    fn drop(&mut self) {
        if !self.completed_turn {
            self.state.close(FailureSite::Closed);
        }
    }
}

fn stage_index(stage: u32) -> Option<usize> {
    match stage {
        NOMINATION_V1 => Some(0),
        AUTHORIZATION_V1 => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_postcheck_debt_does_not_replace_native_send_cause() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.sent = Some(Err(SeqpacketError::WouldBlock));
        flight.witness_postcheck_debt = true;

        let cause = flight.failure().unwrap();

        assert!(matches!(
            cause.downcast_ref::<SeqpacketError>(),
            Some(SeqpacketError::WouldBlock),
        ));
        assert!(flight.has_postcheck_debt());
    }

    #[test]
    fn later_witness_site_is_not_a_global_cause_priority() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.prepared = Some(Err(BrokerSessionSecurityError::Currentness));
        flight.witness_failure_site = Some(ClientWitnessSiteV1::Send);

        let cause = flight.failure().unwrap();

        assert!(matches!(
            cause.downcast_ref::<BrokerSessionSecurityError>(),
            Some(BrokerSessionSecurityError::Currentness),
        ));
    }

    #[test]
    fn witness_only_postcheck_is_debt_not_a_primary_marker() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.witness_postcheck_debt = true;
        flight.closed = true;

        assert!(flight.failure().is_none());
        assert!(flight.has_postcheck_debt());

        let mut preparation = OutputPreparationCustodyV1::empty();
        preparation.witness_postcheck_debt = true;
        preparation.close(FailureSite::Closed);

        assert!(preparation.failure().is_none());
        assert!(preparation.has_postcheck_debt());
    }

    #[test]
    fn preparation_has_exactly_two_fixed_slots_without_unknown_stage_aliases() {
        assert_eq!(stage_index(NOMINATION_V1), Some(0));
        assert_eq!(stage_index(AUTHORIZATION_V1), Some(1));
        assert_eq!(stage_index(0), None);
        assert_eq!(stage_index(3), None);
        assert_eq!(stage_index(u32::MAX), None);
    }
}

/// Owns the same authenticated client request across preparation and terminal CAS.
/// Protocol engines consume a gate/advancement once; they never take/reinsert a
/// Session or replace a failed request. Complete native records stay resident.
pub(crate) struct OriginalOutputClientFlightV1 {
    pub(crate) coordinates: Option<Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError>>,
    prepared: Option<Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError>>,
    initialization: Option<Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>>,
    successor: Option<Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError>>,
    sent: Option<Result<(), SeqpacketError>>,
    terminal_packet: OriginalOutputPacketV1,
    terminal: Option<Result<aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1, aos_sandbox_broker_session_protocol::BrokerSessionProjectionError>>,
    admission: Option<Result<crate::ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError>>,
    pub(crate) committed: Option<crate::ProtectedBrokerOutcomeCommitResultV1>,
    protected_failure: Option<BrokerSessionSecurityError>,
    pub(crate) postcheck_debt: Option<BrokerSessionSecurityError>,
    witness_failure_site: Option<ClientWitnessSiteV1>,
    witness_postcheck_debt: bool,
    closed: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientWitnessSiteV1 {
    Prepare,
    Initialize,
    Append,
    Send,
    Receive,
    Admission,
    Commit,
}

impl OriginalOutputClientFlightV1 {
    pub(crate) fn empty() -> Self {
        Self {
            coordinates: None,
            prepared: None,
            initialization: None,
            successor: None,
            sent: None,
            terminal_packet: OriginalOutputPacketV1::empty(),
            terminal: None,
            admission: None,
            committed: None,
            protected_failure: None,
            postcheck_debt: None,
            witness_failure_site: None,
            witness_postcheck_debt: false,
            closed: false,
        }
    }

    pub(crate) fn request(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        Some(&self.prepared.as_ref()?.as_ref().ok()?.0)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure_inner(None)
    }

    pub(crate) fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.failure_inner(Some(session))
    }

    fn failure_inner<'a>(
        &'a self,
        session: Option<&'a DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.coordinates { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Prepare, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.prepared { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Initialize, session) {
            return Some(error);
        }
        match &self.initialization {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Append, session) {
            return Some(error);
        }
        match &self.successor {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Send, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.sent { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Receive, session) {
            return Some(error);
        }
        let packet_failure = match session {
            Some(session) => self.terminal_packet.failure_with_session(session),
            None => self.terminal_packet.failure(),
        };
        if let Some(error) = packet_failure { return Some(error); }
        if let Some(Err(error)) = &self.terminal { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Admission, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.admission { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Commit, session) {
            return Some(error);
        }
        if let Some(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) = &self.committed { return Some(error); }
        self.protected_failure.as_ref().map(|error| error as &dyn std::error::Error)
    }

    fn witness_failure_at<'a>(
        &'a self,
        site: ClientWitnessSiteV1,
        session: Option<&'a DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_failure_site != Some(site) {
            return None;
        }
        Some(session.and_then(DormantAuthenticatedBrokerSessionV1::output_witness_failure)
            .unwrap_or(&OutputWitnessUnavailableV1))
    }

    pub(crate) fn postcheck_debt_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_postcheck_debt {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        self.postcheck_debt.as_ref().map(|error| error as &dyn std::error::Error)
    }

    pub(crate) fn has_postcheck_debt(&self) -> bool {
        self.witness_postcheck_debt || self.postcheck_debt.is_some()
    }

    fn check_witness(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        site: ClientWitnessSiteV1,
        post: bool,
    ) -> bool {
        if session.revalidate_output_witnesses() {
            return true;
        }
        if post {
            if self.postcheck_debt.is_none() {
                self.witness_postcheck_debt = true;
            }
        } else if self.witness_failure_site.is_none() {
            self.witness_failure_site = Some(site);
        }
        self.closed = true;
        false
    }

    /// Parks both independent postchecks even when the preceding action failed.
    fn check_after_transition(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        site: ClientWitnessSiteV1,
    ) -> bool {
        let witness_current = self.check_witness(session, site, true);
        let result = session.owner.revalidate_transport(&session.transcript, session.socket.peer());
        if let Err(error) = result {
            if self.postcheck_debt.is_none() {
                self.postcheck_debt = Some(error);
            }
            self.closed = true;
            self.check_witness(session, site, true);
            return false;
        }
        let after = self.check_witness(session, site, true);
        witness_current && after
    }

    pub(crate) fn prepare(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        envelope: BrokerRequestEnvelope,
    ) -> bool {
        if self.closed || self.prepared.is_some() { self.closed = true; return false; }
        let Some(Ok(coordinates)) = self.coordinates.as_ref() else { self.closed = true; return false; };
        let coordinates = *coordinates;
        if !matches!(envelope.method.as_known(), Some(BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE)) {
            self.closed = true;
            return false;
        }
        let Some(method) = envelope.method.as_known() else { self.closed = true; return false; };
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Prepare, false) {
            return false;
        }
        boundary.flight.prepared = Some(session.prepare_client_request(
            envelope, method, 0, coordinates.request_id(),
            coordinates.deadline_boottime_nanoseconds(), coordinates.maximum_response_bytes(),
        ));
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Prepare);
        if !after { return false; }
        let Some(Ok((_, initialize))) = &boundary.flight.prepared else { return false; };
        let initialize = *initialize;
        if initialize {
            if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Initialize, false) {
                return false;
            }
            let Some(Ok((request, _))) = &boundary.flight.prepared else { return false; };
            boundary.flight.initialization = Some(session.initialize_authenticated_request(request));
            let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Initialize);
            if !after { return false; }
            if !matches!(&boundary.flight.initialization, Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::Initialized))) { return false; }
        } else {
            if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Append, false) {
                return false;
            }
            let Some(Ok((request, _))) = &boundary.flight.prepared else { return false; };
            boundary.flight.successor = Some(session.append_authenticated_request(request));
            let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Append);
            if !after { return false; }
            if !matches!(&boundary.flight.successor, Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::Committed))) { return false; }
        }
        boundary.completed = true;
        true
    }

    pub(crate) fn send_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        if self.closed || self.sent.is_some() { self.closed = true; return false; }
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Send, false) {
            return false;
        }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        let Some(request) = boundary.flight.request() else { return false; };
        boundary.flight.sent = Some(session.socket.send(request.canonical_packet()));
        // The actual native send error wins over all later currentness debt.
        let after = boundary.flight.recheck_pending(session, true);
        if !matches!(&boundary.flight.sent, Some(Ok(()))) || !after { return false; }
        boundary.completed = true;
        true
    }

    pub(crate) fn receive_terminal_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        if self.closed || self.terminal_packet.received.is_some() { self.closed = true; return false; }
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Receive, false) {
            return false;
        }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        let Some(request) = boundary.flight.request() else { return false; };
        let Ok(maximum) = usize::try_from(request.maximum_response_bytes()) else { return false; };
        let received = boundary.flight.terminal_packet.receive_once(session, maximum);
        let after = boundary.flight.recheck_pending(session, true);
        if !received || !after { return false; }
        let Some(packet) = boundary.flight.terminal_packet.payload() else { return false; };
        boundary.flight.terminal = Some(aos_sandbox_broker_session_protocol::decode_canonical_response_v1(packet));
        if !matches!(&boundary.flight.terminal, Some(Ok(_))) { return false; }
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Admission, false) {
            return false;
        }
        let Some(Ok(terminal)) = &boundary.flight.terminal else { return false; };
        let Some(request) = boundary.flight.request() else { return false; };
        let (gate, _) = match session.reopen_broker_outcome(request) {
            Ok(gate) => gate,
            Err(error) => {
                boundary.flight.protected_failure = Some(error);
                boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Admission);
                return false;
            }
        };
        boundary.flight.admission = Some(gate.admit_outcome(terminal));
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Admission);
        if !after { return false; }
        if !matches!(&boundary.flight.admission, Some(Ok(crate::ProtectedBrokerOutcomeAdmissionV1::New { .. }))) { return false; }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Commit, false) {
            return false;
        }

        // One-way consumption into the sole outcome writer, not temporary
        // custody removal and reinsertion. Every canonical preimage remains.
        let Some(Ok(crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement })) = boundary.flight.admission.take() else { return false; };
        boundary.flight.committed = Some(session.commit_broker_outcome(advancement));
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Commit);
        if !after { return false; }
        if !matches!(&boundary.flight.committed, Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_))) { return false; }
        boundary.completed = true;
        true
    }

    fn recheck_pending(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, post: bool) -> bool {
        let site = if self.terminal.is_some() {
            ClientWitnessSiteV1::Commit
        } else if self.sent.is_some() {
            ClientWitnessSiteV1::Receive
        } else {
            ClientWitnessSiteV1::Send
        };
        let witness_current = self.check_witness(session, site, post);
        if !post && !witness_current { return false; }
        let Some(request) = self.request() else { return false; };
        let result = match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => session.owner.hold_capture_candidate_client_request(
                request, &session.transcript, session.socket.peer(),
            ),
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => session.owner.hold_output_registration_request(
                request, &session.transcript, session.socket.peer(),
            ),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => session.owner.hold_storage_output_host_readback(
                request, &session.transcript, session.socket.peer(),
            ),
            _ => return false,
        }.map(|_| ());
        if let Err(error) = result {
            if post {
                if self.postcheck_debt.is_none() { self.postcheck_debt = Some(error); }
            } else if self.protected_failure.is_none() { self.protected_failure = Some(error); }
            self.check_witness(session, site, true);
            return false;
        }
        let after = self.check_witness(session, site, post);
        witness_current && after
    }
}

struct OutputClientBoundaryV1<'flight> {
    flight: &'flight mut OriginalOutputClientFlightV1,
    completed: bool,
}

impl Drop for OutputClientBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed { self.flight.closed = true; }
    }
}

/// Retains the same writer's prepared, committed and transmitted terminal.
/// Successful local transmission never retires the original request.
pub(crate) struct OriginalOutputServerTerminalV1 {
    prepared: Option<Result<crate::ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError>>,
    pub(crate) committed: Option<crate::ProtectedBrokerOutcomeCommitResultV1>,
    before_commit: Option<Result<(), BrokerSessionSecurityError>>,
    before_send: Option<Result<(), BrokerSessionSecurityError>>,
    sent: Option<Result<(), SeqpacketError>>,
    after_send: Option<Result<(), BrokerSessionSecurityError>>,
    closed: bool,
}

impl OriginalOutputServerTerminalV1 {
    pub(crate) fn empty() -> Self {
        Self {
            prepared: None,
            committed: None,
            before_commit: None,
            before_send: None,
            sent: None,
            after_send: None,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.prepared { return Some(error); }
        if let Some(Err(error)) = &self.before_commit { return Some(error); }
        if let Some(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) = &self.committed { return Some(error); }
        if let Some(Err(error)) = &self.before_send { return Some(error); }
        if let Some(Err(error)) = &self.sent { return Some(error); }
        self.closed.then_some(&OutputPreparationClosedV1 as &dyn std::error::Error)
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&BrokerSessionSecurityError> {
        self.after_send.as_ref()?.as_ref().err()
    }

    pub(crate) fn locally_sent(&self) -> bool {
        !self.closed
            && matches!(&self.sent, Some(Ok(())))
            && matches!(&self.after_send, Some(Ok(())))
    }

    pub(crate) fn prepare_and_commit(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        body: &[u8],
    ) {
        if self.closed || self.prepared.is_some() {
            self.closed = true;
            return;
        }
        let mut boundary = OutputServerTerminalBoundaryV1 { terminal: self, completed: false };
        if !matches!(request.method(),
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT)
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || body.is_empty() || body.len() > 1024
        {
            return;
        }
        let message = aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope {
            request_id: request.request_id().to_vec(),
            method: request.method().into(),
            body: body.to_vec(),
            ..Default::default()
        };
        boundary.terminal.prepared = Some(session.prepare_broker_outcome(request, message));
        if !matches!(&boundary.terminal.prepared, Some(Ok(_))) { return; }

        // The same original pending writer is checked after canonical signing
        // and immediately before its existing durable commit engine.
        boundary.terminal.before_commit = Some(session.owner.hold_output_registration_request(
            request, &session.transcript, session.socket.peer(),
        ).map(|_| ()));
        if !matches!(&boundary.terminal.before_commit, Some(Ok(()))) { return; }
        let Some(Ok(pending)) = boundary.terminal.prepared.take() else { return; };
        boundary.terminal.committed = Some(session.commit_broker_outcome(pending));
        if !matches!(&boundary.terminal.committed, Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_))) { return; }
        boundary.completed = true;
    }

    pub(crate) fn send_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) {
        if self.closed || self.sent.is_some() { self.closed = true; return; }
        let mut boundary = OutputServerTerminalBoundaryV1 { terminal: self, completed: false };
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &boundary.terminal.committed else { return; };
        let currentness = match committed.storage_output_server_originals_v1() {
            Ok((_, currentness)) => currentness,
            Err(error) => {
                boundary.terminal.before_send = Some(Err(error));
                return;
            }
        };
        boundary.terminal.before_send = Some(session.owner.compare_storage_output_server_terminal_v1(
            currentness, session.socket.peer(),
        ));
        if !matches!(&boundary.terminal.before_send, Some(Ok(()))) { return; }

        boundary.terminal.sent = Some(session.socket.send(committed.exact_packet()));
        boundary.terminal.after_send = Some(session.owner.compare_storage_output_server_terminal_v1(
            currentness, session.socket.peer(),
        ));
        boundary.completed = matches!(&boundary.terminal.sent, Some(Ok(())))
            && matches!(&boundary.terminal.after_send, Some(Ok(())));
    }
}

struct OutputServerTerminalBoundaryV1<'terminal> {
    terminal: &'terminal mut OriginalOutputServerTerminalV1,
    completed: bool,
}

/// Keeps the actual initial native record and protected admission beside the
/// original Session. It uses the same parser and request CAS as ordinary receipt.
pub(crate) struct OriginalOutputServerReceiptV1 {
    packet: OriginalOutputPacketV1,
    profile: Option<Result<(), BrokerSessionSecurityError>>,
    clock: Option<Result<u64, BrokerSessionSecurityError>>,
    admission: Option<Result<crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError>>,
    initialization: Option<Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>>,
    successor: Option<Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError>>,
    before: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    after: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    completed: bool,
    closed: bool,
}

impl OriginalOutputServerReceiptV1 {
    pub(crate) fn empty() -> Self {
        Self {
            packet: OriginalOutputPacketV1::empty(),
            profile: None,
            clock: None,
            admission: None,
            initialization: None,
            successor: None,
            before: None,
            after: None,
            completed: false,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.before { return Some(error); }
        if let Some(Err(error)) = &self.profile { return Some(error); }
        if let Some(error) = self.packet.failure() { return Some(error); }
        if let Some(Err(error)) = &self.clock { return Some(error); }
        if let Some(Err(error)) = &self.admission { return Some(error); }
        match &self.initialization {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        match &self.successor {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        self.closed.then_some(&OutputPreparationClosedV1 as &dyn std::error::Error)
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&crate::DormantBrokerSessionHandshakeErrorV1> {
        self.after.as_ref()?.as_ref().err()
    }

    pub(crate) fn receive_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, deadline: u64) {
        if self.closed || self.before.is_some() { self.closed = true; return; }
        self.closed = true;
        self.before = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if !matches!(&self.before, Some(Ok(()))) { return; }
        self.receive_original(session);
        // Even an action error remains resident before this independent debt.
        self.after = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if matches!(&self.after, Some(Ok(()))) && self.actual_admission_complete() {
            self.closed = false;
            self.completed = true;
        }
    }

    fn receive_original(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) {
        self.profile = Some(session.owner.require_original_storage_output_server(
            &session.transcript, session.socket.peer(),
        ));
        if !matches!(&self.profile, Some(Ok(()))) { return; }
        let maximum = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(session.transcript.protocol());
        if !self.packet.receive_once(session, maximum) { return; }
        self.clock = Some(super::protected_boottime_nanoseconds());
        let Some(Ok(now)) = &self.clock else { return; };
        let Some(packet) = self.packet.payload() else { return; };
        self.admission = Some(session.owner.admit_received_request(
            packet, 0, &session.transcript, session.socket.peer(), *now,
        ));
        if let Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { request, requires_initialization })) = &self.admission {
            if *requires_initialization {
                self.initialization = Some(session.initialize_authenticated_request(request));
            } else {
                self.successor = Some(session.append_authenticated_request(request));
            }
        }
    }

    fn actual_admission_complete(&self) -> bool {
        match &self.admission {
            Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { requires_initialization: true, .. })) =>
                matches!(&self.initialization, Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::Initialized))),
            Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { requires_initialization: false, .. })) =>
                matches!(&self.successor, Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::Committed))),
            Some(Ok(_)) => true,
            _ => false,
        }
    }

    /// One-way handoff only after the actual resident CAS/postcheck results.
    pub(crate) fn into_admitted_original(&mut self) -> Option<crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1> {
        if !self.completed || self.closed { return None; }
        let Some(Ok(admission)) = self.admission.take() else { return None; };
        Some(admission)
    }
}

impl Drop for OutputServerTerminalBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.terminal.closed = true;
        }
    }
}

/// Retains a whole native zero-FD packet before binding and subject observations.
pub(crate) struct OriginalOutputPacketV1 {
    received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    subject_current: bool,
    witness_failure: bool,
}

impl OriginalOutputPacketV1 {
    pub(crate) fn empty() -> Self {
        Self {
            received: None,
            binding: None,
            alive: None,
            subject_current: false,
            witness_failure: false,
        }
    }

    pub(crate) fn receive_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
    ) -> bool {
        if self.received.is_some() { return false; }
        self.received = Some(session.socket.receive_retaining(maximum));
        let Some(Ok(record)) = &self.received else { return false; };
        self.binding = Some(session.socket.require_output_registration_received_original_v1(record));
        if !matches!(self.binding.as_ref(), Some(Ok(()))) { return false; }
        self.alive = Some(record.subject().is_alive());
        if !matches!(self.alive.as_ref(), Some(Ok(true))) { return false; }
        self.subject_current = session.require_output_subject(record.subject());
        self.witness_failure = !self.subject_current && session.output_witness_failure().is_some();
        self.subject_current
    }

    pub(crate) fn payload(&self) -> Option<&[u8]> {
        if !self.subject_current { return None; }
        Some(self.received.as_ref()?.as_ref().ok()?.payload())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.received { return Some(error); }
        if let Some(Err(error)) = &self.binding { return Some(error); }
        if let Some(Err(error)) = &self.alive { return Some(error); }
        if self.witness_failure { return Some(&OutputWitnessUnavailableV1); }
        None
    }

    fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.received { return Some(error); }
        if let Some(Err(error)) = &self.binding { return Some(error); }
        if let Some(Err(error)) = &self.alive { return Some(error); }
        if self.witness_failure {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        None
    }
}
