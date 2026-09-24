//! Controller-signed operator Repair ingress on a separate fixed Storage socket.
//!
//! The ordinary Storage plan/lease verifier still authorizes every effect.
//! This boundary additionally verifies the live controller execution and
//! reserves its signed intent in the root-owned sidecar before worker dispatch.
//! A separate read-only query recovers the identical signed receipt after a
//! lost or expired effect response; it cannot authorize a new attempt.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_core::{ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::operator_storage_repair_transport::{
    MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V1, OperatorStorageRepairModeV1,
    OperatorStorageRepairRequestV1, OperatorStorageRepairResponseV1,
};
use aos_sandbox_protocol::{decode_request_envelope, validate_request_descriptor_roles};
use buffa::Message as _;

use crate::StorageAdmissionError;
use crate::operator_recovery::StorageOperatorRecoveryOwnerV1;
use crate::peer::ControllerPeerVerifier;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError, trusted_paired_clock_sample};
use crate::service::{StorageConnectionOutcome, StorageServiceError};
use crate::transport::{accept_connection, boottime, receive, send};

const RECEIVE_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_REQUEST_LIFETIME_NANOSECONDS: u64 = 60_000_000_000;
const STORAGE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Serves one operator Repair or receipt-recovery packet on its fixed socket.
///
/// # Errors
///
/// Returns an error for retired activation, invalid kernel time, or protected
/// Storage state requiring a process reopen. Peer and request rejections close
/// only the accepted child, without an authority-bearing response.
pub fn serve_operator_repair_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &ControllerPeerVerifier,
    owner: &mut StorageOperatorRecoveryOwnerV1,
) -> Result<StorageConnectionOutcome, StorageServiceError> {
    if runtime.requires_reopen() {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    verifier.validate_current()?;
    let Some(mut connection) = accept_connection(listener)? else {
        return Ok(StorageConnectionOutcome::TransportRejected);
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(StorageConnectionOutcome::PeerRejected),
    };
    let receive_deadline = boottime()?
        .checked_add(RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let record = match receive(
        &mut connection,
        MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V1,
        receive_deadline,
    ) {
        Ok(record) => record,
        Err(_) => return Ok(StorageConnectionOutcome::TransportRejected),
    };
    if verifier
        .verify_record(execution, connection.peer(), record.subject())
        .is_err()
    {
        return Ok(StorageConnectionOutcome::PeerRejected);
    }
    let request = match OperatorStorageRepairRequestV1::decode(record.payload()) {
        Ok(request) => request,
        Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
    };
    drop(record);

    let now = boottime()?;
    let latest = now
        .checked_add(MAXIMUM_REQUEST_LIFETIME_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    if request.deadline_boottime_nanoseconds() <= now
        || request.deadline_boottime_nanoseconds() > latest
        || verifier
            .recheck_connection(execution, connection.peer())
            .is_err()
    {
        return Ok(StorageConnectionOutcome::RequestRejected);
    }
    let effect_id = match owner.effect_id_for_intent(request.signed_intent()) {
        Ok(effect_id) => effect_id,
        Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
    };

    let signed_receipt = match request.mode() {
        OperatorStorageRepairModeV1::Effect => {
            let envelope = match decode_effect_envelope(request.authorized_envelope()) {
                Ok(envelope) => envelope,
                Err(()) => return Ok(StorageConnectionOutcome::RequestRejected),
            };
            if owner
                .effect_id_for_request(request.signed_intent(), envelope.body())
                .map_or(true, |bound_effect_id| bound_effect_id != effect_id)
            {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            if !runtime.is_repair_ready()
                || verifier
                    .recheck_connection(execution, connection.peer())
                    .is_err()
            {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            let Some(artifacts) = envelope.authorization() else {
                return Ok(StorageConnectionOutcome::RequestRejected);
            };
            let mut clock = || {
                trusted_paired_clock_sample().map_err(|_| StorageAdmissionError::VerificationFailed)
            };
            match runtime.repair_workspace_pin_for_operator(
                envelope.body(),
                artifacts,
                STORAGE_VERSION,
                execution.credentials(),
                verifier.policy(),
                request.signed_intent(),
                owner,
                &mut clock,
            ) {
                Ok(receipt) => receipt,
                Err(StorageRuntimeError::ReopenRequired) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
        }
        OperatorStorageRepairModeV1::RecoverReceipt => {
            if !runtime.is_inventory_ready() {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            if owner
                .require_reserved_intent(request.signed_intent())
                .is_err()
            {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            match runtime.recover_operator_workspace_pin_receipt(owner, effect_id) {
                Ok(receipt) => receipt,
                Err(StorageRuntimeError::ReopenRequired) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
        }
    };
    let response =
        OperatorStorageRepairResponseV1::new(request.request_id(), effect_id, signed_receipt)
            .map_err(|_| {
                StorageServiceError::Activation("operator Repair response was invalid".to_owned())
            })?;
    if verifier
        .recheck_connection(execution, connection.peer())
        .is_err()
        || send(
            &mut connection,
            &response.encode(),
            request.deadline_boottime_nanoseconds(),
        )
        .is_err()
    {
        return Ok(StorageConnectionOutcome::TransportRejected);
    }
    Ok(StorageConnectionOutcome::Served)
}

fn decode_effect_envelope(
    bytes: &[u8],
) -> Result<aos_sandbox_protocol::ValidatedBrokerRequestEnvelope, ()> {
    let raw = BrokerRequestEnvelope::decode_from_slice(bytes).map_err(|_| ())?;
    if raw.encode_to_vec() != bytes {
        return Err(());
    }
    let envelope = decode_request_envelope(bytes, ProtocolId::StorageBroker, 0).map_err(|_| ())?;
    if envelope.method() != BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
        || envelope.authorization().is_none()
        || validate_request_descriptor_roles(&envelope, &[]).is_err()
    {
        return Err(());
    }
    Ok(envelope)
}
