//! Retains the sole client request engine's reached native and parser prefix.
//!
//! Ordinary callers immediately delegate with no destinations. C23 lends this
//! inert owner before signing or model growth; it cannot create a Session,
//! receiving purpose or protected append permission.

use super::*;
use super::super::current_replay::{ReplayValue, security_value};
use aos_sandbox_broker_session_protocol::durable::{HistoricalTrafficReplayCaptureV1, history::BrokerSessionDurableHistoryDecodeCaptureV1};
use aos_sandbox_broker_session_protocol::projection::{CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerRequestEnvelopeV1, decode_canonical_request_retaining_v1};
use aos_sandbox_protocol::authenticated_session::all_methods::{request_capture::AuthenticatedBrokerMethodRequestCaptureV1, AuthenticatedBrokerSemanticBindingsV1};

#[derive(Default)]
pub(crate) struct ClientRequestOriginalsV1 {
    context: CurrentContextOriginalsV1,
    first_peer: CurrentPeerOriginalsV1,
    stored: StoredReadOriginalsV1,
    publication: Option<Result<[u8; 32], BrokerSessionSecurityError>>,
    retired_history: BrokerSessionDurableHistoryDecodeCaptureV1,
    traffic_history: BrokerSessionDurableHistoryDecodeCaptureV1,
    traffic: HistoricalTrafficReplayCaptureV1,
    provisional: Option<Result<BrokerSessionTrafficStateV1, BrokerSessionSecurityError>>,
    packet: Option<Result<Vec<u8>, BrokerSessionSecurityError>>,
    canonical_decode: CanonicalBrokerRequestDecodeCaptureV1,
    canonical: Option<CanonicalBrokerRequestEnvelopeV1>,
    bindings: Option<Result<AuthenticatedBrokerSemanticBindingsV1, BrokerSessionSecurityError>>,
    admission: AuthenticatedBrokerMethodRequestCaptureV1,
    second_peer: CurrentPeerOriginalsV1,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    clock: Option<Result<u64, BrokerSessionSecurityError>>,
    entered: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl ClientRequestOriginalsV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(slot: &Option<Result<T, BrokerSessionSecurityError>>) -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
        }
        cause(&self.clock).or_else(|| self.context.failure()).or_else(|| self.first_peer.failure()).or_else(|| self.stored.failure())
            .or_else(|| cause(&self.publication)).or_else(|| self.retired_history.failure().map(|cause| cause as _))
            .or_else(|| self.traffic_history.failure().map(|cause| cause as _)).or_else(|| self.traffic.cause())
            .or_else(|| cause(&self.provisional)).or_else(|| cause(&self.packet))
            .or_else(|| self.canonical_decode.failure().map(|cause| cause as _)).or_else(|| cause(&self.bindings))
            .or_else(|| self.admission.cause()).or_else(|| self.second_peer.failure())
            .or_else(|| cause(&self.comparison)).or_else(|| cause(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn retained_endpoint_open_files_v1() -> Option<usize> {
        CurrentPeerOriginalsV1::retained_endpoint_open_files_v1()?.checked_mul(2)
    }

    pub(crate) fn receiving_backing_bytes_v1() -> Option<usize> {
        let (context, _) = CurrentContextOriginalsV1::receiving_footprint_v1()?;
        let (peer, _) = CurrentPeerOriginalsV1::receiving_footprint_v1()?;
        context.checked_add(peer.checked_mul(2)?)?
            .checked_add(StoredReadOriginalsV1::construction_bytes_v1()?)?
            .checked_add(StoredReadOriginalsV1::receiving_fixed_backing_bytes_v1()?)
    }
}

enum OptionalStored<'owner> { Ordinary(Option<StoredProtocolHistoryV1>), Retained(Option<&'owner StoredProtocolHistoryV1>) }
impl OptionalStored<'_> {
    fn as_ref(&self) -> Option<&StoredProtocolHistoryV1> {
        match self { Self::Ordinary(value) => value.as_ref(), Self::Retained(value) => *value }
    }
}

fn history_value<'owner>(stored: &StoredProtocolHistoryV1, capture: Option<&'owner mut BrokerSessionDurableHistoryDecodeCaptureV1>)
    -> Result<ReplayValue<'owner, BrokerSessionDurableHistoryV1>, BrokerSessionSecurityError> {
    let Some(capture) = capture else { return stored.history_model().map(ReplayValue::Ordinary); };
    BrokerSessionDurableHistoryV1::decode_retaining(&stored.history, capture).map_err(map_durable)?;
    capture.history().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

fn canonical_value<'owner>(packet: &[u8], capture: Option<(&mut CanonicalBrokerRequestDecodeCaptureV1,
    &'owner mut Option<CanonicalBrokerRequestEnvelopeV1>)>)
    -> Result<ReplayValue<'owner, CanonicalBrokerRequestEnvelopeV1>, BrokerSessionSecurityError> {
    let Some((capture, value)) = capture else {
        return decode_canonical_request_v1(packet).map(ReplayValue::Ordinary).map_err(|_| BrokerSessionSecurityError::Currentness);
    };
    decode_canonical_request_retaining_v1(packet, capture).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    *value = Some(capture.take_model_once().map_err(|_| BrokerSessionSecurityError::Currentness)?);
    value.as_ref().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

impl ProtectedBrokerSessionJournalV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_client_request_engine_v1(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
        actual_descriptor_count: usize,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
        originals: Option<&mut ClientRequestOriginalsV1>,
    ) -> Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        self.require_floor_method(method)?;
        let (context_slot, first_peer_slot, stored_slot, publication_slot, retired_history_slot, traffic_history_slot,
            traffic_slot, provisional_slot, packet_slot, canonical_slot, bindings_slot, admission_slot, second_peer_slot, comparison_slot) = match originals {
            Some(originals) => (Some(&mut originals.context), Some(&mut originals.first_peer), Some(&mut originals.stored),
                Some(&mut originals.publication), Some(&mut originals.retired_history), Some(&mut originals.traffic_history),
                Some(&mut originals.traffic), Some(&mut originals.provisional), Some(&mut originals.packet),
                Some((&mut originals.canonical_decode, &mut originals.canonical)), Some(&mut originals.bindings),
                Some(&mut originals.admission), Some(&mut originals.second_peer), Some(&mut originals.comparison)),
            None => (None, None, None, None, None, None, None, None, None, None, None, None, None, None),
        };
        let context = self.current_context_with_originals(transcript, context_slot)?;
        let first_peer = self.observe_peer_current_engine(transcript, connection_peer, None, first_peer_slot)?;
        let current = match stored_slot {
            Some(stored) => { stored.observe_optional_once(self)?; OptionalStored::Retained(stored.selected_optional_v1()) },
            None => OptionalStored::Ordinary(self.read_optional(transcript.protocol())?),
        };
        let current_publication = security_value(self.endpoint_publication(transcript.protocol()), publication_slot)?;
        let retired_rollover = match current.as_ref() {
            Some(current) if current.endpoint_publication == *current_publication
                && self.client_retired_transcript.as_ref().is_some_and(|retired|
                    retired.phase != RetiredStorageTranscriptPhaseV1::Consumed) =>
            {
                let history = history_value(current, retired_history_slot)?;
                self.require_retired_storage_rollover_v1(current, &history, transcript)?
            }
            _ => false,
        };
        let requires_initialization = retired_rollover || current.as_ref().is_none_or(|value| value.endpoint_publication != *current_publication);
        let traffic = match current.as_ref() {
            Some(current) if !requires_initialization => {
                super::super::current_replay::traffic_value(&*history_value(current, traffic_history_slot)?, transcript, &context, traffic_slot)?
            }
            _ => security_value(BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())
                .map_err(|_| BrokerSessionSecurityError::Currentness), provisional_slot)?,
        };
        let sequence = traffic.next_client_sequence();
        let packet = security_value(self.endpoint.finalize_client_request(message, method, transcript, sequence, request_id), packet_slot)?;
        let canonical = canonical_value(&packet, canonical_slot)?;
        let semantic_bindings = security_value(authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
            .map_err(|_| BrokerSessionSecurityError::Currentness), bindings_slot)?;
        let credentials = connection_peer.credentials();
        let peer = aos_sandbox_protocol::PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        let policy = aos_sandbox_protocol::PeerPolicy {
            uid: credentials.uid(),
            gid: Some(credentials.gid()),
            audience: context.audience(),
        };
        let request_owner = match admission_slot {
            Some(capture) => {
                capture.capture_once_v1(AuthenticatedBrokerRequestDirectionV1::ClientSend, &traffic, &packet, None,
                    actual_descriptor_count, peer, policy, now_boottime_nanoseconds, *semantic_bindings, &context)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                ClientRequestValueV1::Retained(capture)
            }
            None => match prepare_client_sent_authenticated_broker_method_request_v1(
                &traffic, &packet, None, actual_descriptor_count, peer, policy, now_boottime_nanoseconds,
                *semantic_bindings, &context,
            ).map_err(|_| BrokerSessionSecurityError::Currentness)? {
                AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => ClientRequestValueV1::Ordinary(request),
                _ => return Err(BrokerSessionSecurityError::Currentness),
            },
        };
        let request = request_owner.value()?;
        if request.method() != method
            || request.request_id() != request_id
            || request.client_sequence() != sequence
            || request.deadline_boottime_nanoseconds() != deadline_boottime_nanoseconds
            || request.maximum_response_bytes() != maximum_response_bytes
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let second_peer = self.observe_peer_current_engine(transcript, connection_peer, None, second_peer_slot)?;
        security_value(if first_peer.binding(self.endpoint.role(), transcript, &context)?
            != second_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            Err(BrokerSessionSecurityError::Currentness)
        } else { Ok(()) }, comparison_slot)?;
        if retired_rollover {
            // The actual paid first Client request, rather than HELLO DATA,
            // binds the same shared monotone initialization CAS/readback.
            self.bind_retired_storage_request_v1(&request)?;
        }
        Ok((request_owner.take_completed()?, requires_initialization))
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_client_request_retaining_v1(&mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod, actual_descriptor_count: usize,
        request_id: [u8; 16], deadline_boottime_nanoseconds: u64, maximum_response_bytes: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1, connection_peer: &ConnectionPeerIdentity,
        originals: &mut ClientRequestOriginalsV1,
    ) -> Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        if originals.entered {
            originals.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        originals.entered = true;
        originals.clock = Some(crate::handshake::protected_boottime_nanoseconds());
        let result = match originals.clock.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(now) => self.journal.prepare_client_request_engine_v1(message, method, actual_descriptor_count,
                request_id, deadline_boottime_nanoseconds, maximum_response_bytes, transcript,
                connection_peer, now, Some(originals)),
            None => Err(BrokerSessionSecurityError::Currentness),
        };
        match result {
            Ok(value) => { originals.returned = Some(Ok(())); Ok(value) }
            Err(cause) => { originals.returned = Some(Err(cause)); Err(BrokerSessionSecurityError::Currentness) }
        }
    }
}

enum ClientRequestValueV1<'original> {
    Ordinary(AuthenticatedBrokerMethodRequestV1),
    Retained(&'original mut AuthenticatedBrokerMethodRequestCaptureV1),
}

impl ClientRequestValueV1<'_> {
    fn value(&self) -> Result<&AuthenticatedBrokerMethodRequestV1, BrokerSessionSecurityError> {
        match self {
            Self::Ordinary(request) => Ok(request),
            Self::Retained(capture) => match capture.value() {
                Some(AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. }) => Ok(request),
                _ => Err(BrokerSessionSecurityError::Currentness),
            },
        }
    }

    fn take_completed(self) -> Result<AuthenticatedBrokerMethodRequestV1, BrokerSessionSecurityError> {
        match self {
            Self::Ordinary(request) => Ok(request),
            Self::Retained(capture) => match capture.take_admission_once_v1().map_err(|_| BrokerSessionSecurityError::Currentness)? {
                AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => Ok(request),
                _ => Err(BrokerSessionSecurityError::Currentness),
            },
        }
    }
}
