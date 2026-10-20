//! Actual historical Inventory/Prepare request prefixes through head comparison.
//!
//! This destination borrows the same completed history, transcript and context.
//! It is not a Session, native peer, receiving account or replay permission.

use super::*;
use crate::recovery::current_replay::{ReplayValue, security_value};
use aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerSemanticBindingsV1;
use aos_sandbox_broker_session_protocol::durable::{
    HistoricalTrafficReplayCaptureV1, verify_historical_traffic_records_retaining_v1,
};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerRequestEnvelopeV1,
    decode_canonical_request_retaining_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1;

#[derive(Default)]
pub(super) struct RetainedRequestOriginalsV1 {
    head_index: Option<Result<usize, BrokerSessionSecurityError>>,
    request_index: Option<Result<usize, BrokerSessionSecurityError>>,
    link: Option<Result<(), BrokerSessionSecurityError>>,
    prior: HistoricalTrafficReplayCaptureV1,
    canonical_decode: CanonicalBrokerRequestDecodeCaptureV1,
    canonical: Option<CanonicalBrokerRequestEnvelopeV1>,
    bindings: Option<Result<AuthenticatedBrokerSemanticBindingsV1, BrokerSessionSecurityError>>,
    verification_time: Option<Result<u64, BrokerSessionSecurityError>>,
    admission: AuthenticatedBrokerMethodRequestCaptureV1,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    entered: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl RetainedRequestOriginalsV1 {
    pub(super) fn observe_once(&mut self, history: &BrokerSessionDurableHistoryV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, context: &ProtectedBrokerSessionVerificationContextV1,
        peer: aos_sandbox_protocol::PeerCredentials, policy: aos_sandbox_protocol::PeerPolicy,
        direction: AuthenticatedBrokerRequestDirectionV1) -> Result<(), BrokerSessionSecurityError> {
        if self.entered {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.entered = true;
        let result = reconstruct_retained_request_engine(history, transcript, context, peer, policy, direction, Some(self));
        let returned = result.map(|value| { drop(value); });
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    pub(super) fn value(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        match self.admission.value()? {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => Some(request),
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(slot: &Option<Result<T, BrokerSessionSecurityError>>)
            -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.head_index).or_else(|| cause(&self.request_index)).or_else(|| cause(&self.link))
            .or_else(|| self.prior.cause())
            .or_else(|| self.canonical_decode.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.bindings)).or_else(|| cause(&self.verification_time))
            .or_else(|| self.admission.cause()).or_else(|| cause(&self.comparison))
            .or_else(|| cause(&self.returned)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<HistoricalTrafficReplayCaptureV1>())?
            .checked_add(std::mem::size_of::<CanonicalBrokerRequestDecodeCaptureV1>())?
            .checked_add(std::mem::size_of::<AuthenticatedBrokerMethodRequestCaptureV1>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, BrokerSessionTrafficStateV1>>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, CanonicalBrokerRequestEnvelopeV1>>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, AuthenticatedBrokerMethodRequestAdmissionV1>>())?
            .checked_add(std::mem::size_of::<ReplayValue<'static, AuthenticatedBrokerMethodRequestV1>>())?;
        // The method request's decoder/admission fields are already included
        // in the complete compiled bytes above, not additional namespace keys.
        let cells = 13usize.checked_add(HistoricalTrafficReplayCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(CanonicalBrokerRequestDecodeCaptureV1::receiving_metadata_cells_v1()?)?;
        Some((bytes, cells))
    }
}

fn prior_value<'original>(records: &[BrokerSessionDurableRecordV1], transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1, original: Option<&'original mut HistoricalTrafficReplayCaptureV1>)
    -> Result<ReplayValue<'original, BrokerSessionTrafficStateV1>, BrokerSessionSecurityError> {
    let Some(original) = original else {
        return reconstruct_traffic_records(records, transcript, context).map(ReplayValue::Ordinary);
    };
    verify_historical_traffic_records_retaining_v1(records, transcript, context, original)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    original.traffic().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

fn canonical_value<'original>(packet: &[u8], original: Option<(&mut CanonicalBrokerRequestDecodeCaptureV1,
    &'original mut Option<CanonicalBrokerRequestEnvelopeV1>)>)
    -> Result<ReplayValue<'original, CanonicalBrokerRequestEnvelopeV1>, BrokerSessionSecurityError> {
    let Some((decode, model)) = original else {
        return decode_canonical_request_v1(packet).map(ReplayValue::Ordinary)
            .map_err(|_| BrokerSessionSecurityError::Currentness);
    };
    decode_canonical_request_retaining_v1(packet, decode).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    *model = Some(decode.take_model_once().map_err(|_| BrokerSessionSecurityError::Currentness)?);
    model.as_ref().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

#[allow(clippy::too_many_arguments)]
fn admission_value<'original>(direction: AuthenticatedBrokerRequestDirectionV1,
    prior: &BrokerSessionTrafficStateV1, packet: &[u8], descriptor_count: usize,
    peer: aos_sandbox_protocol::PeerCredentials, policy: aos_sandbox_protocol::PeerPolicy,
    time: u64, bindings: AuthenticatedBrokerSemanticBindingsV1, context: &ProtectedBrokerSessionVerificationContextV1,
    original: Option<&'original mut AuthenticatedBrokerMethodRequestCaptureV1>)
    -> Result<ReplayValue<'original, AuthenticatedBrokerMethodRequestAdmissionV1>, BrokerSessionSecurityError> {
    let Some(original) = original else {
        let result = match direction {
            AuthenticatedBrokerRequestDirectionV1::ClientSend => prepare_client_sent_authenticated_broker_method_request_v1(
                prior, packet, None, descriptor_count, peer, policy, time, bindings, context),
            AuthenticatedBrokerRequestDirectionV1::ServerReceive => admit_server_received_authenticated_broker_method_request_v1(
                prior, packet, None, descriptor_count, peer, policy, time, bindings, context),
        };
        return result.map(ReplayValue::Ordinary).map_err(|_| BrokerSessionSecurityError::Currentness);
    };
    original.capture_once_v1(direction, prior, packet, None, descriptor_count, peer, policy, time, bindings, context)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    original.value().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

pub(super) fn reconstruct_retained_request_engine<'original>(history: &BrokerSessionDurableHistoryV1,
    transcript: &VerifiedBrokerSessionTranscriptV1, context: &ProtectedBrokerSessionVerificationContextV1,
    peer: aos_sandbox_protocol::PeerCredentials, policy: aos_sandbox_protocol::PeerPolicy,
    direction: AuthenticatedBrokerRequestDirectionV1, originals: Option<&'original mut RetainedRequestOriginalsV1>)
    -> Result<ReplayValue<'original, AuthenticatedBrokerMethodRequestV1>, BrokerSessionSecurityError> {
    let (head_slot, index_slot, link_slot, prior_slot, canonical_slot, bindings_slot, time_slot, admission_slot, comparison_slot) =
        match originals {
            Some(originals) => (Some(&mut originals.head_index), Some(&mut originals.request_index), Some(&mut originals.link),
                Some(&mut originals.prior), Some((&mut originals.canonical_decode, &mut originals.canonical)),
                Some(&mut originals.bindings), Some(&mut originals.verification_time), Some(&mut originals.admission),
                Some(&mut originals.comparison)),
            None => (None, None, None, None, None, None, None, None, None),
        };
    let head_index = security_value(history.records().len().checked_sub(1).ok_or(BrokerSessionSecurityError::Currentness), head_slot)?;
    let head = history.records().get(*head_index).ok_or(BrokerSessionSecurityError::Currentness)?;
    let request_index = security_value(match head.phase() {
        BrokerSessionDurablePhaseV1::RequestPrepared => Ok(*head_index),
        BrokerSessionDurablePhaseV1::Terminal => head_index.checked_sub(1).ok_or(BrokerSessionSecurityError::Currentness),
    }, index_slot)?;
    let request_record = history.records().get(*request_index).ok_or(BrokerSessionSecurityError::Currentness)?;
    security_value(if request_record.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || request_record.request_packet() != head.request_packet()
        || request_record.request_companion() != head.request_companion() {
        Err(BrokerSessionSecurityError::Currentness)
    } else { Ok(()) }, link_slot)?;
    let prior = prior_value(&history.records()[..*request_index], transcript, context, prior_slot)?;
    let canonical = canonical_value(head.request_packet(), canonical_slot)?;
    let method = canonical.signed_artifact().method();
    let bindings = security_value(authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
        .map_err(|_| BrokerSessionSecurityError::Currentness), bindings_slot)?;
    let descriptor_count = canonical.message().descriptors.len();
    let time = security_value(head.request_companion().deadline_boottime_nanoseconds().checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness), time_slot)?;
    let admission = admission_value(direction, &prior, head.request_packet(), descriptor_count,
        peer, policy, *time, *bindings, context, admission_slot)?;
    let request = match admission {
        ReplayValue::Ordinary(AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. }) => ReplayValue::Ordinary(request),
        ReplayValue::Retained(AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. }) => ReplayValue::Retained(request),
        _ => return Err(BrokerSessionSecurityError::Currentness),
    };
    security_value(if request_matches_head(&request, head, direction) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }, comparison_slot)?;
    Ok(request)
}
