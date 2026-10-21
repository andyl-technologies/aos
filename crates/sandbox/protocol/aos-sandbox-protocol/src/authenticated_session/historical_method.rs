//! Reconstructs exact signed historical method DATA through the original engines.
//!
//! The caller separately supplies protected endpoint pins and live currentness.
//! These values never construct a Session, dispatch permit, floor or role owner.

mod retained;

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;

#[doc(hidden)]
pub use retained::{HistoricalStorageMethodCaptureV1, HistoricalStartResourceMethodCaptureV2, HistoricalStorageGuestRootMethodCaptureV2, HistoricalDeleteCleanupMethodCaptureV4};

use aos_sandbox_broker_session_protocol::{BrokerSessionDurableRecordV1,
    BrokerSessionDurablePhaseV1, BrokerSessionTrafficStateV1,
    VerifiedBrokerSessionTranscriptV1, decode_canonical_request_v1,
    decode_canonical_response_v1, complete_signed_request_digest_v1,
    verify_historical_traffic_records_v1};
use super::historical_checkpoint::HistoricalSessionCheckpointV1;
use super::all_methods::{AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodOutcomeAdmissionV1,
    AuthenticatedBrokerMethodResultV1, authenticated_semantic_bindings_from_envelope_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
    admit_client_received_authenticated_broker_method_outcome_v1};

/// Reports inconsistent, noncanonical or unauthentic historical method DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoricalMethodReplayErrorV1 {
    /// A recorded packet, semantic binding or exact historical predecessor differs.
    #[error("invalid historical authenticated broker method")]
    Invalid,
}

/// Selects a structural parse coordinate for an authenticated historical request.
///
/// Prepare has an independent catalog expiry that can precede its transport
/// deadline. Its historical parser checks both nonzero horizons from the boot
/// origin, rather than treating the transport deadline as an admission time.
/// This coordinate supplies neither a clock observation nor live currentness;
/// new requests still require their actual protected clock and authorization.
///
/// # Errors
///
/// Rejects a zero durable transport deadline.
pub fn historical_request_verification_time_v1(
    method: BrokerMethod,
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, HistoricalMethodReplayErrorV1> {
    let before_deadline = deadline_boottime_nanoseconds
        .checked_sub(1)
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;

    Ok(match method {
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => 0,
        _ => before_deadline,
    })
}

/// Reconstructs one successful historical terminal outcome and its exact request.
///
/// # Errors
/// Rejects invalid canonical packets, signatures, method semantics, predecessors,
/// request companions, result status or retained semantic commitments.
pub fn historical_terminal_outcome(
    records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
    terminal_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, HistoricalMethodReplayErrorV1> {
    historical_terminal_observation_impl_v2(records, terminal_index, checkpoint, transcript, true)
}

/// Reconstructs an authenticated terminal observation, including signed errors.
///
/// This preserves negative or uncertain historical evidence without granting
/// success, currentness, native custody or permission to retry an operation.
///
/// # Errors
/// Rejects invalid canonical packets, signatures, method semantics, exact
/// predecessors, companions or retained outcome semantic commitments.
pub fn historical_terminal_observation_v2(
    records: &[BrokerSessionDurableRecordV1],
    terminal_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, HistoricalMethodReplayErrorV1> {
    historical_terminal_observation_impl_v2(records, terminal_index, checkpoint, transcript, false)
}

fn historical_terminal_observation_impl_v2(
    records: &[BrokerSessionDurableRecordV1],
    terminal_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    require_success: bool,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, HistoricalMethodReplayErrorV1> {
    let (request_index, terminal) = terminal_request_v1(records, terminal_index)?;
    let (request, pending_traffic) =
        historical_client_request(records, request_index, checkpoint, transcript)?;
    let packet = terminal
        .outcome_packet()
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
    let canonical_outcome = decode_canonical_response_v1(packet)
        .map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?;
    let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
        &pending_traffic,
        &request,
        packet,
        None,
        canonical_outcome.message().descriptors.len(),
        checkpoint.context(),
    )
    .map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?
    {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
        AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => {
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
    };
    require_terminal_outcome_v1(&outcome, terminal, require_success)?;
    Ok(outcome)
}

/// Reconstructs one historical prepared request against its complete prior traffic.
///
/// # Errors
/// Rejects invalid framing, signatures, complete method semantics, transcript
/// linkage or any disagreement with the original durable request companion.
pub fn historical_client_request(
    records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
    request_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<
    (
        AuthenticatedBrokerMethodRequestV1,
        Box<BrokerSessionTrafficStateV1>,
    ),
    HistoricalMethodReplayErrorV1,
> {
    let prepared = records
        .get(request_index)
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
    if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared {
        return Err(HistoricalMethodReplayErrorV1::Invalid);
    }
    let prior =
        verify_historical_traffic_records_v1(&records[..request_index], transcript, checkpoint.context()).map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?;
    let canonical = decode_canonical_request_v1(prepared.request_packet())
        .map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?;
    let method = canonical.signed_artifact().method();
    let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
        .map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?;
    let peer = checkpoint.peer();
    let policy = crate::PeerPolicy {
        uid: peer.uid,
        gid: Some(peer.gid),
        audience: checkpoint.context().audience(),
    };
    let retained_time = historical_request_verification_time_v1(
        method, prepared.request_companion().deadline_boottime_nanoseconds(),
    )?;
    let (request, pending_traffic) =
        match prepare_client_sent_authenticated_broker_method_request_v1(
            &prior,
            prepared.request_packet(),
            None,
            canonical.message().descriptors.len(),
            peer,
            policy,
            retained_time,
            bindings,
            checkpoint.context(),
        )
        .map_err(|_| HistoricalMethodReplayErrorV1::Invalid)?
        {
            AuthenticatedBrokerMethodRequestAdmissionV1::New {
                request,
                next_traffic,
            } => (request, next_traffic),
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                return Err(HistoricalMethodReplayErrorV1::Invalid);
            }
        };
    if !request_matches_head(
        &request,
        prepared,
        AuthenticatedBrokerRequestDirectionV1::ClientSend,
    ) || request.semantic_commitment() != prepared.request_semantic_binding()
    {
        return Err(HistoricalMethodReplayErrorV1::Invalid);
    }
    Ok((request, pending_traffic))
}

/// Compares every historical request coordinate with its actual durable row.
///
/// This predicate supplies comparison DATA without reading or granting custody.
#[must_use]
pub fn request_matches_head(
    request: &AuthenticatedBrokerMethodRequestV1,
    head: &BrokerSessionDurableRecordV1,
    expected_direction: AuthenticatedBrokerRequestDirectionV1,
) -> bool {
    let signed = head.request_companion().signed_request();
    request.direction() == expected_direction
        && request.method() == head.method()
        && request.session_binding() == head.session_binding()
        && request.request_id() == head.request_id()
        && request.client_sequence() == head.client_sequence()
        && request.maximum_response_bytes() == head.maximum_response_bytes()
        && request.semantic_commitment() == head.request_semantic_binding()
        && request.signed_request_digest() == complete_signed_request_digest_v1(signed)
        && request.canonical_packet() == head.request_packet()
}

fn terminal_request_v1(
    records: &[BrokerSessionDurableRecordV1],
    terminal_index: usize,
) -> Result<(usize, &BrokerSessionDurableRecordV1), HistoricalMethodReplayErrorV1> {
    let request_index = terminal_index
        .checked_sub(1)
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
    let prepared = records
        .get(request_index)
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
    let terminal = records
        .get(terminal_index)
        .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
    if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || terminal.phase() != BrokerSessionDurablePhaseV1::Terminal
        || prepared.request_packet() != terminal.request_packet()
        || prepared.request_id() != terminal.request_id()
        || prepared.request_companion() != terminal.request_companion()
    {
        return Err(HistoricalMethodReplayErrorV1::Invalid);
    }
    Ok((request_index, terminal))
}

fn require_terminal_outcome_v1(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    terminal: &BrokerSessionDurableRecordV1,
    require_success: bool,
) -> Result<(), HistoricalMethodReplayErrorV1> {
    if outcome.semantic_commitment() != terminal.outcome_semantic_binding()
        || (require_success && !matches!(
            outcome.result(),
            AuthenticatedBrokerMethodResultV1::Success { .. }
        ))
    {
        return Err(HistoricalMethodReplayErrorV1::Invalid);
    }
    Ok(())
}
