//! Retains a terminal's real replay and method admission through comparison.
//!
//! This private owner borrows the same authenticated request/history context.
//! It creates no Journal, native peer, writer, purpose or resource authority.

use super::*;
use super::current_replay::{ReplayValue, head_value, security_value};
use aos_sandbox_broker_session_protocol::durable::{
    HistoricalTrafficReplayCaptureV1, verify_historical_traffic_records_retaining_v1,
};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerResponseDecodeCaptureV1, decode_canonical_response_retaining_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    AuthenticatedBrokerMethodOutcomeCaptureV1,
    admit_client_received_outcome_retaining_v1,
    prepare_server_sent_outcome_retaining_v1,
};

#[derive(Default)]
pub(super) struct TerminalSemanticsOriginalsV1 {
    head_index: Option<Result<usize, BrokerSessionSecurityError>>,
    prior_traffic: HistoricalTrafficReplayCaptureV1,
    head: Option<Result<(), BrokerSessionDurableError>>,
    packet: Option<Result<(), BrokerSessionSecurityError>>,
    response: CanonicalBrokerResponseDecodeCaptureV1,
    response_disposed: bool,
    descriptor_count: Option<Result<usize, BrokerSessionSecurityError>>,
    admission: AuthenticatedBrokerMethodOutcomeCaptureV1,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    attempted: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl TerminalSemanticsOriginalsV1 {
    pub(super) fn observe_once(
        &mut self,
        history: &BrokerSessionDurableHistoryV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        final_traffic: &BrokerSessionTrafficStateV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.attempted {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.attempted = true;
        let returned = match reconstruct_terminal_semantics_engine(
            history, request, transcript, context, final_traffic, Some(self),
        ) {
            Ok(outcome) => {
                drop(outcome);
                Ok(())
            }
            Err(cause) => Err(cause),
        };
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    pub(super) fn value(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        match self.admission.value()? {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => Some(outcome),
            AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(value: &Option<Result<T, BrokerSessionSecurityError>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { value.as_ref()?.as_ref().err().map(|cause| cause as _) }
        cause(&self.head_index)
            .or_else(|| self.prior_traffic.cause())
            .or_else(|| self.head.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| cause(&self.packet))
            .or_else(|| self.response.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.descriptor_count))
            .or_else(|| self.admission.cause())
            .or_else(|| cause(&self.comparison))
            .or_else(|| cause(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<HistoricalTrafficReplayCaptureV1>())?
            .checked_add(std::mem::size_of::<CanonicalBrokerResponseDecodeCaptureV1>())?
            .checked_add(std::mem::size_of::<AuthenticatedBrokerMethodOutcomeCaptureV1>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, BrokerSessionTrafficStateV1>>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, AuthenticatedBrokerMethodOutcomeAdmissionV1>>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, AuthenticatedBrokerMethodOutcomeV1>>())?;
        // Seven optional controls, three embedded owner destinations and two
        // once/disposal flags coexist with the lower capsules after leaf disposal.
        let cells = 12_usize
            .checked_add(HistoricalTrafficReplayCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(CanonicalBrokerResponseDecodeCaptureV1::receiving_metadata_cells_v1()?)?;
        Some((bytes, cells))
    }
}

fn prior_traffic_value<'original>(
    records: &[BrokerSessionDurableRecordV1],
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    originals: Option<&'original mut HistoricalTrafficReplayCaptureV1>,
) -> Result<ReplayValue<'original, BrokerSessionTrafficStateV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return reconstruct_traffic_records(records, transcript, context).map(ReplayValue::Ordinary);
    };
    verify_historical_traffic_records_retaining_v1(records, transcript, context, originals)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    originals.traffic().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

fn descriptor_count(
    packet: &[u8],
    originals: Option<(&mut CanonicalBrokerResponseDecodeCaptureV1, &mut bool)>,
) -> Result<usize, BrokerSessionSecurityError> {
    let Some((originals, disposed)) = originals else {
        return decode_canonical_response_v1(packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
            .map(|response| response.message().descriptors.len());
    };
    decode_canonical_response_retaining_v1(packet, originals)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let model = originals.take_model_once().map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let count = model.message().descriptors.len();
    // This model's sole borrower is the completed descriptor-count projection.
    // Its ordinary temporary also ends before method admission begins.
    drop(model);
    *disposed = true;
    Ok(count)
}

fn admission_value<'original>(
    prior_traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    packet: &[u8],
    declared_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
    originals: Option<&'original mut AuthenticatedBrokerMethodOutcomeCaptureV1>,
) -> Result<ReplayValue<'original, AuthenticatedBrokerMethodOutcomeAdmissionV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return match request.direction() {
            AuthenticatedBrokerRequestDirectionV1::ClientSend => {
                admit_client_received_authenticated_broker_method_outcome_v1(
                    prior_traffic, request, packet, None, 0, context,
                )
            }
            AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
                prepare_server_sent_authenticated_broker_method_outcome_v1(
                    prior_traffic, request, packet, None, declared_descriptor_count, context,
                )
            }
        }.map(ReplayValue::Ordinary).map_err(|_| BrokerSessionSecurityError::Currentness);
    };
    match request.direction() {
        AuthenticatedBrokerRequestDirectionV1::ClientSend => {
            admit_client_received_outcome_retaining_v1(
                prior_traffic, request, packet, None, 0, context, originals,
            )
        }
        AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
            prepare_server_sent_outcome_retaining_v1(
                prior_traffic, request, packet, None, declared_descriptor_count, context, originals,
            )
        }
    }.map_err(|_| BrokerSessionSecurityError::Currentness)?;
    originals.value().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

pub(super) fn reconstruct_terminal_semantics_engine<'original>(
    history: &BrokerSessionDurableHistoryV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    final_traffic: &BrokerSessionTrafficStateV1,
    originals: Option<&'original mut TerminalSemanticsOriginalsV1>,
) -> Result<ReplayValue<'original, AuthenticatedBrokerMethodOutcomeV1>, BrokerSessionSecurityError> {
    let (index_slot, prior_slot, head_slot, packet_slot, response_slot, count_slot, admission_slot, comparison_slot) =
        match originals {
            Some(originals) => (Some(&mut originals.head_index), Some(&mut originals.prior_traffic),
                Some(&mut originals.head), Some(&mut originals.packet),
                Some((&mut originals.response, &mut originals.response_disposed)),
                Some(&mut originals.descriptor_count), Some(&mut originals.admission),
                Some(&mut originals.comparison)),
            None => (None, None, None, None, None, None, None, None),
        };
    let head_index = security_value(history.records().len().checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness), index_slot)?;
    let prior_traffic = prior_traffic_value(&history.records()[..*head_index], transcript, context, prior_slot)?;
    let head = head_value(history.head(), head_slot)?;
    security_value(head.outcome_packet().map(|_| ()).ok_or(BrokerSessionSecurityError::Currentness), packet_slot)?;
    let packet = head.outcome_packet().ok_or(BrokerSessionSecurityError::Currentness)?;
    let declared_descriptor_count = security_value(descriptor_count(packet, response_slot), count_slot)?;
    let admission = admission_value(&prior_traffic, request, packet, *declared_descriptor_count, context, admission_slot)?;
    security_value(match &*admission {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { next_traffic, .. }
            if next_traffic.as_ref() == final_traffic => Ok(()),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }, comparison_slot)?;
    match admission {
        ReplayValue::Ordinary(AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }) =>
            Ok(ReplayValue::Ordinary(outcome)),
        ReplayValue::Retained(AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }) =>
            Ok(ReplayValue::Retained(outcome)),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::journal::LifecycleTerminalFixture;

    #[test]
    fn actual_storage_terminal_matches_the_ordinary_semantics() {
        let mut fixture = LifecycleTerminalFixture::storage_client();
        let current = fixture.currentness.as_ref().unwrap();
        let snapshot = fixture.journal.read_current(BrokerSessionProtocolV1::Storage).unwrap();
        let history = BrokerSessionDurableHistoryV1::decode(snapshot.history.as_deref().unwrap()).unwrap();
        let traffic = reconstruct_traffic(&history, &current.transcript, &current.context).unwrap();
        let ordinary = reconstruct_terminal_semantics(
            &history, &current.request, &current.transcript, &current.context, &traffic,
        ).unwrap();
        let mut originals = TerminalSemanticsOriginalsV1::default();

        originals.observe_once(
            &history, &current.request, &current.transcript, &current.context, &traffic,
        ).unwrap();

        assert_eq!(originals.value().unwrap().canonical_packet(), ordinary.canonical_packet());
        assert!(originals.prior_traffic.traffic().unwrap().has_outstanding_request());
        assert!(originals.response_disposed);
        assert!(originals.failure().is_none());
    }

    #[test]
    fn actual_admission_survives_a_later_final_traffic_mismatch_and_reentry() {
        let mut fixture = LifecycleTerminalFixture::storage_client();
        let current = fixture.currentness.as_ref().unwrap();
        let snapshot = fixture.journal.read_current(BrokerSessionProtocolV1::Storage).unwrap();
        let history = BrokerSessionDurableHistoryV1::decode(snapshot.history.as_deref().unwrap()).unwrap();
        let unrelated_final = BrokerSessionTrafficStateV1::from_provisional_transcript(current.transcript.clone()).unwrap();
        let mut originals = TerminalSemanticsOriginalsV1::default();
        assert!(reconstruct_terminal_semantics(
            &history, &current.request, &current.transcript, &current.context, &unrelated_final,
        ).is_err());

        assert!(originals.observe_once(
            &history, &current.request, &current.transcript, &current.context, &unrelated_final,
        ).is_err());

        assert!(originals.value().is_none());
        let AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, next_traffic } = originals.admission.value().unwrap()
            else { panic!("the real terminal must retain its New admission"); };
        assert_eq!(outcome.canonical_packet(), history.head().unwrap().outcome_packet().unwrap());
        assert_ne!(next_traffic.as_ref(), &unrelated_final);
        let retained_packet = outcome.canonical_packet().as_ptr();
        let cause = originals.failure().unwrap().downcast_ref::<BrokerSessionSecurityError>().unwrap()
            as *const BrokerSessionSecurityError;
        assert!(originals.response_disposed);

        assert!(originals.observe_once(
            &history, &current.request, &current.transcript, &current.context, &unrelated_final,
        ).is_err());

        let AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } = originals.admission.value().unwrap()
            else { panic!("reentry must not replace the retained admission"); };
        assert_eq!(outcome.canonical_packet().as_ptr(), retained_packet);
        assert_eq!(originals.failure().unwrap().downcast_ref::<BrokerSessionSecurityError>().unwrap()
            as *const _, cause);
    }
}
