//! Prices one Host Prepare/Accept using the existing Session representation engines.
//!
//! The extent comes from the same held writer. This is requirement DATA only;
//! the genuine Controller18 borrower must check it before signing or transport.

use super::*;

/// Bounds one actual Host58/59 request, outcome and enlarged native prefix.
///
/// This reuses the common request/outcome/schema and native replay recipes.
/// It prices a full hostile response at the actual negotiated receiver bound;
/// successful small responses do not justify a smaller raw receive permit.
/// Existing parser limits and service cgroup bounds remain unchanged.
///
/// # Errors
/// Rejects a different method/protocol, invalid negotiated response limit,
/// changed prefix geometry or unrepresentable checked demand.
pub fn host_execution_argument_client_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    method: BrokerMethod,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if !matches!(method, BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
        | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
        || transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host
    { return Err(invalid()); }
    execution_client_stage_demand_v1(extent, transcript, method).map(|(demand, _)| demand)
}

/// Bounds Authorize and first Observe on the same held Host Session.
///
/// The second Apply uses the first Apply's forecast appended prefix, so this
/// covers both request/outcome histories without treating the old prefix as
/// the second turn's final extent. It grants no request or effect authority.
///
/// # Errors
/// Rejects another protocol, invalid negotiated bounds or checked overflow.
pub fn host_execution_authorize_observe_client_demand_v2(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host {
        return Err(invalid());
    }
    let method = BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION;
    let (authorize, after_authorize) = execution_client_stage_demand_v1(extent, transcript, method)?;
    let (observe, _) = execution_client_stage_demand_v1(&after_authorize, transcript, method)?;
    authorize.checked_add(observe).map_err(|_| invalid())
}

/// Prices the existing closed output reservation/registration stages.
///
/// # Errors
/// Rejects other methods, protocol mismatches or checked representation overflow.
pub fn execution_output_client_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    method: BrokerMethod,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if !matches!(method, BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
        | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
        | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
    { return Err(invalid()); }
    execution_client_stage_demand_v1(extent, transcript, method).map(|(demand, _)| demand)
}

/// Prices one genuine Host Stop through the shared client Session recipe.
///
/// This is cost DATA, not a Runtime grant. The caller retains its actual Stop
/// admission and pays this whole same-writer forecast before request growth.
/// The hostile raw response keeps the actual negotiated receiver maximum;
/// a valid residual receipt's fixed width grants no smaller native envelope.
///
/// # Errors
/// Refuses another Session protocol, invalid negotiated limits or overflow.
pub fn host_stop_client_demand_v4(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host {
        return Err(invalid());
    }
    execution_client_stage_demand_v1(extent, transcript,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME).map(|(demand, _)| demand)
}

/// Prices the genuine adjacent Host Inventory on the same retained Session.
///
/// # Errors
/// Refuses another protocol, negotiated profile or checked geometry overflow.
pub fn host_stop_inventory_client_demand_v5(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host {
        return Err(invalid());
    }
    execution_client_stage_demand_v1(extent, transcript,
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME).map(|(demand, _)| demand)
}

fn execution_client_stage_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    method: BrokerMethod,
) -> Result<(ResourceVector, ProtectedJournalPreopenReplayExtentV1), StorageSessionGeometryRefusalV1> {
    let profile = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(method)
        .ok_or_else(invalid)?;
    if profile.protocol() != transcript.protocol()
        || !profile.success_response_descriptor_roles().is_empty()
    {
        return Err(invalid());
    }
    let request_bytes = profile.total_request_maximum_bytes();
    let response_bytes = usize::try_from(transcript.negotiated_maximum_response_bytes())
        .map_err(|_| invalid())?;
    if response_bytes == 0 || response_bytes > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(invalid());
    }
    let request = request_representation_demand_v1(extent, 0, 0, request_bytes, 1, 2)?;
    let prefix = usize::try_from(checked_prefix(extent)?).map_err(|_| invalid())?;
    let outcome = outcome_representation_demand_v1(extent, prefix, request_bytes, response_bytes)?;
    // Both common suppliers report append bytes, not an alternative lifetime
    // budget. Their sum bounds the reached request and outcome journal history.
    let append = request.get(D::StorageBytes).checked_add(outcome.get(D::StorageBytes))
        .ok_or_else(invalid)?;
    let future = extent.native_bytes.checked_add(append).ok_or_else(invalid)?;
    let future = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(extent.limits, future)
        .map_err(|_| invalid())?;
    let native = future.dominant_native_receiving_demand_v1().map_err(|_| invalid())?;
    let semantic = future.dominant_semantic_receiving_demand_v1().map_err(|_| invalid())?;
    let flight = ResourceVector::ZERO
        .with(D::NetworkBytes, as_u64(request_bytes.checked_add(response_bytes).ok_or_else(invalid)?)?)
        .with(D::OutputBytes, as_u64(request_bytes)?)
        .with(D::ConcurrentOperations, 1);
    let demand = schema_demand(extent)?.checked_add(request)
        .and_then(|v| v.checked_add(outcome))
        .and_then(|v| v.checked_add(native))
        .and_then(|v| v.checked_add(semantic))
        .and_then(|v| v.checked_add(flight)).map_err(|_| invalid())?;
    Ok((demand, future))
}
