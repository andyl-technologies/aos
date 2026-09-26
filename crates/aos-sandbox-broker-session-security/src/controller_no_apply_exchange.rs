//! Controller-owned signed preliminary Host settlement and cold-query exchange.
//!
//! The original H archive, signed T outcome, and Controller argument source are
//! reauthenticated before either request is reserved. A signed Host response
//! remains historical evidence: no Controller prepare floor, CAS, ACK, or
//! public Create/Apply transition is issued here.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, HostNoApplySettlementPhaseV2 as WirePhaseV2,
    QueryHostExecutionNoApplySettlementRequestV2, SettleHostExecutionNoApplyRequestV2,
};
use aos_sandbox::controller_execution_argument_attempt::{
    ControllerExecutionArgumentAttemptV1, read_historical_controller_execution_argument_attempt_v1,
};
use aos_sandbox::controller_no_apply_settlement_cursor::{
    ControllerNoApplyCursorStateV1, ControllerNoApplySettlementCursorV1,
    observe_controller_no_apply_preliminary_v1, read_controller_no_apply_settlement_cursor_v1,
    reserve_controller_no_apply_settlement_cursor_v1,
};
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{EffectFailure, Journal};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1, HostNoApplySettlementHistoryV2, HostNoApplySettlementPhaseV2,
    ValidatedHostNoApplySettlementRequestV2, decode_host_no_apply_settlement_query_request_v2,
    decode_host_no_apply_settlement_request_v2, decode_host_no_apply_settlement_response_v2,
    match_archived_host_no_apply_outcome_v2, signed_host_no_apply_terminal_outcome_digest_v2,
    validate_host_no_apply_settlement_record_envelope_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::recovery::AuthenticatedOriginalHostNoApplyJoinV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1,
};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Host no-Apply settlement request custody is absent",
    retained: "Host no-Apply settlement retains protected session recovery",
    unusable: "Host no-Apply settlement session requires cold recovery",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettlementMethodV2 {
    Preliminary,
    Query,
}

impl SettlementMethodV2 {
    const fn broker_method(self) -> BrokerMethod {
        match self {
            Self::Preliminary => BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            Self::Query => BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct VerifiedControllerNoApplyArchiveV2 {
    source: ControllerExecutionArgumentAttemptV1,
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
    terminal_outcome: AuthenticatedBrokerMethodOutcomeV1,
    marker: HostExecutionNoApplyRecordV1,
}

impl VerifiedControllerNoApplyArchiveV2 {
    fn from_join(join: &AuthenticatedOriginalHostNoApplyJoinV1) -> Self {
        Self {
            source: join.original().source().clone(),
            original_session_binding: join.original().request().session_binding(),
            original_signed_request_digest: join.original().request().signed_request_digest(),
            archive_head: ObjectDigest::from_bytes(join.original().archive_head()),
            signed_terminal_outcome: signed_host_no_apply_terminal_outcome_digest_v2(
                join.no_apply_outcome(),
            ),
            terminal_outcome: join.no_apply_outcome().clone(),
            marker: join.no_apply_record(),
        }
    }

    fn preliminary_body(&self, coordinates: DormantBrokerRequestCoordinatesV1) -> Vec<u8> {
        SettleHostExecutionNoApplyRequestV2 {
            header: Some(coordinates.request_header()).into(),
            canonical_attempt: self.source.canonical_bytes().to_vec(),
            original_session_binding: self.original_session_binding.to_vec(),
            original_signed_request_digest: self.original_signed_request_digest.to_vec(),
            archive_head: self.archive_head.as_bytes().to_vec(),
            signed_terminal_outcome: self.signed_terminal_outcome.as_bytes().to_vec(),
            phase: WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY.into(),
            challenge: coordinates.request_id().to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn query_body(&self, coordinates: DormantBrokerRequestCoordinatesV1) -> Vec<u8> {
        QueryHostExecutionNoApplySettlementRequestV2 {
            header: Some(coordinates.request_header()).into(),
            canonical_attempt: self.source.canonical_bytes().to_vec(),
            original_session_binding: self.original_session_binding.to_vec(),
            original_signed_request_digest: self.original_signed_request_digest.to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn matches_preliminary(&self, record: &[u8]) -> bool {
        preliminary_matches_archive(
            record,
            self.marker,
            self.archive_head,
            self.signed_terminal_outcome,
        )
    }
}

fn preliminary_matches_archive(
    record: &[u8],
    marker: HostExecutionNoApplyRecordV1,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
) -> bool {
    let marker_digest: [u8; 32] = Sha256::digest(marker.encode_canonical()).into();
    validate_host_no_apply_settlement_record_envelope_v1(record) == Ok(1)
        && record.get(12..28) == Some(marker.fields().execution_id.as_slice())
        && record.get(28..44) == Some(marker.fields().create_operation_id.as_slice())
        && record.get(44..76) == Some(marker_digest.as_slice())
        && record.get(108..140) == Some(archive_head.as_bytes().as_slice())
        && record.get(140..172) == Some(signed_terminal_outcome.as_bytes().as_slice())
}

#[derive(Clone, Debug, PartialEq)]
struct SettlementExchangeContextV2 {
    method: SettlementMethodV2,
    archive: VerifiedControllerNoApplyArchiveV2,
    cursor: ControllerNoApplySettlementCursorV1,
    exact_body: Vec<u8>,
    validated_preliminary: Option<ValidatedHostNoApplySettlementRequestV2>,
}

/// Carries signed Host preliminary history without Controller CAS authority.
#[derive(Clone, Debug)]
pub(crate) struct ControllerHostNoApplyObservationV2 {
    archive: VerifiedControllerNoApplyArchiveV2,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    preliminary: Option<Vec<u8>>,
}

impl ControllerHostNoApplyObservationV2 {
    pub(crate) fn preliminary(&self) -> Option<&[u8]> {
        self.preliminary.as_deref()
    }

    pub(crate) const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }

    pub(crate) fn original_source(&self) -> &ControllerExecutionArgumentAttemptV1 {
        &self.archive.source
    }
}

/// Retains method 42 or 43 through protected send and outcome ambiguity.
#[derive(Default)]
pub(crate) struct ControllerHostNoApplyExchangeV2 {
    exchange: RetainedBrokerExchangeV1<SettlementExchangeContextV2>,
}

impl ControllerHostNoApplyExchangeV2 {
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Sends a signed preliminary request derived from current Controller H/T custody.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preliminary<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        source: &ControllerExecutionArgumentAttemptV1,
        clock: &mut T,
    ) -> Result<ControllerHostNoApplyObservationV2, EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.exchange.has_pending() {
            return Err(retryable("another Host settlement request retains custody"));
        }
        let archive = verify_archive(session, controller, assignment, source, clock)?;
        let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
        let mut issued = None;
        let mut validated_preliminary = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                SettlementMethodV2::Preliminary.broker_method(),
                |coordinates| {
                    require_coordinates(coordinates, &archive)?;
                    let body = archive.preliminary_body(coordinates);
                    issued = Some(body.clone());
                    Ok(BrokerRequestEnvelope {
                        method: SettlementMethodV2::Preliminary.broker_method().into(),
                        body,
                        ..Default::default()
                    })
                },
                |request| {
                    let decoded = decode_host_no_apply_settlement_request_v2(
                        request.exact_body(),
                        request.peer(),
                        request.peer_policy(),
                        sample.boottime_nanoseconds(),
                    );
                    match decoded {
                        Ok(stage)
                            if stage.phase() == HostNoApplySettlementPhaseV2::Preliminary
                                && *stage.header().request_id() == request.request_id()
                                && stage.challenge() == request.request_id()
                                && match_archived_host_no_apply_outcome_v2(
                                    &stage,
                                    archive.archive_head,
                                    &archive.terminal_outcome,
                                )
                                .is_ok_and(|marker| marker == archive.marker) =>
                        {
                            validated_preliminary = Some(stage);
                            true
                        }
                        _ => false,
                    }
                },
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("Host preliminary request needs protected recovery")
            })?;
        let exact_body = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host preliminary request was not issued")
        })?;
        let validated_preliminary = validated_preliminary.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host preliminary request was not validated")
        })?;
        let candidate = ControllerNoApplySettlementCursorV1::from_signed_preliminary_request(
            &archive.source,
            archive.marker,
            archive.archive_head,
            archive.signed_terminal_outcome,
            preparation.signed_request(),
            &validated_preliminary,
        )
        .map_err(|_| {
            self.exchange.mark_failed();
            retryable("signed Host preliminary cursor is invalid")
        })?;
        self.exchange.start(
            SettlementExchangeContextV2 {
                method: SettlementMethodV2::Preliminary,
                archive: archive.clone(),
                cursor: candidate,
                exact_body,
                validated_preliminary: Some(validated_preliminary),
            },
            preparation,
        );
        let current =
            verify_archive(session, controller, assignment, source, clock).map_err(|error| {
                self.exchange.mark_failed();
                error
            })?;
        if current != archive {
            self.exchange.mark_failed();
            return Err(retryable(
                "H/T archive changed before Controller cursor append",
            ));
        }
        let cursor = reserve_controller_no_apply_settlement_cursor_v1(
            controller,
            &archive.source,
            candidate,
        )
        .map_err(|_| {
            self.exchange.mark_failed();
            retryable("Controller preliminary cursor needs cold readback")
        })?;
        let Some(context) = self.exchange.context_mut() else {
            self.exchange.mark_failed();
            return Err(retryable("retained Host preliminary request is absent"));
        };
        context.cursor = cursor;
        let sealed =
            verify_archive(session, controller, assignment, source, clock).map_err(|error| {
                self.exchange.mark_failed();
                error
            })?;
        let readback = read_controller_no_apply_settlement_cursor_v1(
            controller,
            source,
            archive.marker,
            archive.archive_head,
            archive.signed_terminal_outcome,
        )
        .map_err(|_| {
            self.exchange.mark_failed();
            retryable("Controller preliminary cursor changed before Host send")
        })?;
        if sealed != archive || readback != Some(cursor) {
            self.exchange.mark_failed();
            return Err(retryable(
                "Controller and Host cut changed before Host send",
            ));
        }
        self.drain(session, controller, assignment, clock)?
            .ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Sends a distinct signed cold query for the same original H/T identity.
    pub(crate) fn query<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        source: &ControllerExecutionArgumentAttemptV1,
        clock: &mut T,
    ) -> Result<ControllerHostNoApplyObservationV2, EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.exchange.has_pending() {
            return Err(retryable("another Host settlement request retains custody"));
        }
        let archive = verify_archive(session, controller, assignment, source, clock)?;
        let cursor = read_controller_no_apply_settlement_cursor_v1(
            controller,
            source,
            archive.marker,
            archive.archive_head,
            archive.signed_terminal_outcome,
        )
        .map_err(|_| retryable("Controller preliminary cursor is not current"))?
        .ok_or_else(|| retryable("Controller preliminary cursor is absent"))?;
        if verify_archive(session, controller, assignment, source, clock)? != archive {
            return Err(retryable(
                "H/T archive changed around Controller cursor readback",
            ));
        }
        let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
        let mut issued = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                SettlementMethodV2::Query.broker_method(),
                |coordinates| {
                    require_coordinates(coordinates, &archive)?;
                    let body = archive.query_body(coordinates);
                    issued = Some(body.clone());
                    Ok(BrokerRequestEnvelope {
                        method: SettlementMethodV2::Query.broker_method().into(),
                        body,
                        ..Default::default()
                    })
                },
                |request| {
                    decode_host_no_apply_settlement_query_request_v2(
                        request.exact_body(),
                        request.peer(),
                        request.peer_policy(),
                        sample.boottime_nanoseconds(),
                    )
                    .is_ok_and(|query| {
                        *query.header().request_id() == request.request_id()
                            && *query.original().canonical_attempt()
                                == archive.source.canonical_bytes()
                            && query.original().original_session_binding()
                                == archive.original_session_binding
                            && query.original().original_signed_request_digest()
                                == archive.original_signed_request_digest
                    })
                },
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("Host settlement query needs protected recovery")
            })?;
        let exact_body = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host settlement query was not issued")
        })?;
        self.exchange.start(
            SettlementExchangeContextV2 {
                method: SettlementMethodV2::Query,
                archive,
                cursor,
                exact_body,
                validated_preliminary: None,
            },
            preparation,
        );
        self.drain(session, controller, assignment, clock)?
            .ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Resolves only the exact in-process request and rechecks Controller custody.
    pub(crate) fn drain<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<Option<ControllerHostNoApplyObservationV2>, EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.exchange.context().is_none() {
            return Ok(None);
        }
        let (context, outcome) = self.exchange.drive(session, &ERRORS)?;
        let current = verify_archive(
            session,
            controller,
            assignment,
            &context.archive.source,
            clock,
        )
        .map_err(|error| {
            self.exchange.mark_failed();
            error
        })?;
        if current != context.archive {
            self.exchange.mark_failed();
            return Err(retryable(
                "Controller no-Apply archive changed after Host response",
            ));
        }
        let observation = classify_outcome(&context, outcome).map_err(|error| {
            self.exchange.mark_failed();
            error
        })?;
        let current_cursor = read_controller_no_apply_settlement_cursor_v1(
            controller,
            &context.archive.source,
            context.archive.marker,
            context.archive.archive_head,
            context.archive.signed_terminal_outcome,
        )
        .map_err(|_| {
            self.exchange.mark_failed();
            retryable("Controller preliminary cursor changed after Host response")
        })?
        .ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Controller preliminary cursor disappeared")
        })?;
        if current_cursor != context.cursor {
            self.exchange.mark_failed();
            return Err(retryable("Controller preliminary cursor was replaced"));
        }
        let retained = if let Some(stage) = observation.preliminary() {
            observe_controller_no_apply_preliminary_v1(
                controller,
                &context.archive.source,
                context.cursor,
                observation.outcome(),
                stage,
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("signed Host preliminary needs Controller cursor readback")
            })?
        } else {
            if context.cursor.state() != ControllerNoApplyCursorStateV1::Requested {
                self.exchange.mark_failed();
                return Err(retryable(
                    "Host history rolled back below Controller cursor",
                ));
            }
            context.cursor
        };
        let final_archive = verify_archive(
            session,
            controller,
            assignment,
            &context.archive.source,
            clock,
        )
        .map_err(|error| {
            self.exchange.mark_failed();
            error
        })?;
        if final_archive != context.archive
            || read_controller_no_apply_settlement_cursor_v1(
                controller,
                &context.archive.source,
                context.archive.marker,
                context.archive.archive_head,
                context.archive.signed_terminal_outcome,
            )
            .ok()
            .flatten()
                != Some(retained)
        {
            self.exchange.mark_failed();
            return Err(retryable(
                "Controller and Host preliminary changed after cursor append",
            ));
        }
        Ok(Some(observation))
    }
}

fn verify_archive<T>(
    session: &mut DormantAuthenticatedBrokerSessionV1,
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    source: &ControllerExecutionArgumentAttemptV1,
    clock: &mut T,
) -> Result<VerifiedControllerNoApplyArchiveV2, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let current = read_historical_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        source.execution(),
        source.create_operation(),
        clock,
    )
    .map_err(|_| retryable("Controller argument source is not current"))?;
    if current.as_ref() != Some(source) {
        return Err(retryable("Controller argument source changed"));
    }
    let joined = session
        .historical_host_terminal_no_apply_archive(source)
        .map_err(|_| retryable("signed original Host H/T archive is unavailable"))?;
    let archive = VerifiedControllerNoApplyArchiveV2::from_join(&joined);
    let after = read_historical_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        source.execution(),
        source.create_operation(),
        clock,
    )
    .map_err(|_| retryable("Controller argument source changed after archive readback"))?;
    if after.as_ref() != Some(source) {
        return Err(retryable(
            "Controller argument source changed after archive readback",
        ));
    }
    Ok(archive)
}

fn require_coordinates(
    coordinates: DormantBrokerRequestCoordinatesV1,
    archive: &VerifiedControllerNoApplyArchiveV2,
) -> Result<(), BrokerSessionSecurityError> {
    if coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience()
            != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        || coordinates.request_id() == archive.source.request_id()
        || coordinates.request_id() == archive.marker.fields().terminal_request_id
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

fn classify_outcome(
    context: &SettlementExchangeContextV2,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ControllerHostNoApplyObservationV2, EffectFailure> {
    if outcome.method() != context.method.broker_method()
        || outcome.request().exact_body() != context.exact_body
    {
        return Err(retryable(
            "Host settlement outcome differs from signed request",
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(retryable("Host settlement request did not commit"));
    };
    let preliminary = match context.method {
        SettlementMethodV2::Preliminary => {
            let request = context
                .validated_preliminary
                .as_ref()
                .ok_or_else(|| retryable("validated Host preliminary request is absent"))?;
            let record = decode_host_no_apply_settlement_response_v2(
                exact_body,
                request,
                outcome.request().session_binding(),
            )
            .map_err(|_| retryable("signed Host preliminary response is invalid"))?;
            if !context.archive.matches_preliminary(&record) {
                return Err(retryable(
                    "Host preliminary record differs from H/T archive",
                ));
            }
            Some(record.to_vec())
        }
        SettlementMethodV2::Query => {
            let history = outcome
                .recorded_host_no_apply_settlement_history()
                .map_err(|_| retryable("signed Host settlement query is invalid"))?
                .ok_or_else(|| retryable("signed Host settlement query has no history"))?;
            checked_preliminary(&context.archive, &history)?
        }
    };
    Ok(ControllerHostNoApplyObservationV2 {
        archive: context.archive.clone(),
        outcome,
        preliminary,
    })
}

fn checked_preliminary(
    archive: &VerifiedControllerNoApplyArchiveV2,
    history: &HostNoApplySettlementHistoryV2,
) -> Result<Option<Vec<u8>>, EffectFailure> {
    let Some(preliminary) = history.stages()[0] else {
        return Ok(None);
    };
    if !archive.matches_preliminary(&preliminary) {
        return Err(retryable("cold Host preliminary differs from H/T archive"));
    }
    Ok(Some(preliminary.to_vec()))
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;

    use super::*;

    fn marker() -> HostExecutionNoApplyRecordV1 {
        HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [3; 16],
            terminal_request_id: [4; 16],
            host_boot_id: [5; 16],
            assignment_digest: [6; 32],
            source_record_digest: [7; 32],
            original_session_binding: [8; 32],
            original_signed_request_digest: [9; 32],
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 18,
        })
        .unwrap()
    }

    fn seal(record: &mut [u8; 396]) {
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.host-create-failure-lease.v1\0")
            .chain_update(&record[..364])
            .finalize();
        record[364..].copy_from_slice(&checksum);
    }

    fn preliminary(
        marker: HostExecutionNoApplyRecordV1,
        archive_head: ObjectDigest,
        terminal: ObjectDigest,
    ) -> [u8; 396] {
        let mut record = [0; 396];
        record[..8].copy_from_slice(b"AOSCHL01");
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[10] = 1;
        record[12..28].copy_from_slice(&marker.fields().execution_id);
        record[28..44].copy_from_slice(&marker.fields().create_operation_id);
        record[44..76].copy_from_slice(&Sha256::digest(marker.encode_canonical()));
        record[76..108].fill(14);
        record[108..140].copy_from_slice(archive_head.as_bytes());
        record[140..172].copy_from_slice(terminal.as_bytes());
        record[172..180].copy_from_slice(&19_u64.to_be_bytes());
        record[180..212].fill(15);
        record[212..244].fill(16);
        record[244..260].fill(17);
        record[260..268].copy_from_slice(&21_u64.to_be_bytes());
        seal(&mut record);
        record
    }

    #[test]
    fn cold_preliminary_rejects_changed_marker_h_head_terminal_and_stage() {
        let marker = marker();
        let archive_head = ObjectDigest::from_bytes([20; 32]);
        let terminal = ObjectDigest::from_bytes([21; 32]);
        let record = preliminary(marker, archive_head, terminal);

        assert!(preliminary_matches_archive(
            &record,
            marker,
            archive_head,
            terminal,
        ));
        assert!(!preliminary_matches_archive(
            &record,
            marker,
            ObjectDigest::from_bytes([22; 32]),
            terminal,
        ));
        assert!(!preliminary_matches_archive(
            &record,
            marker,
            archive_head,
            ObjectDigest::from_bytes([23; 32]),
        ));

        for offset in [12, 28, 44, 108, 140] {
            let mut changed = record;
            changed[offset] ^= 1;
            seal(&mut changed);
            assert!(!preliminary_matches_archive(
                &changed,
                marker,
                archive_head,
                terminal,
            ));
        }

        let mut bad_checksum = record;
        bad_checksum[364] ^= 1;
        assert!(!preliminary_matches_archive(
            &bad_checksum,
            marker,
            archive_head,
            terminal,
        ));

        let mut later_stage = record;
        later_stage[10] = 2;
        later_stage[268..300].fill(24);
        later_stage[300..332].fill(25);
        seal(&mut later_stage);
        assert!(!preliminary_matches_archive(
            &later_stage,
            marker,
            archive_head,
            terminal,
        ));
    }
}
