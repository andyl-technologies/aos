//! Controller-signed operator Repair ingress on a separate fixed Storage socket.
//!
//! The ordinary Storage plan/lease verifier still authorizes every effect.
//! This boundary additionally verifies the live controller execution. Prepare
//! retains and returns the owner-signed physical probe without dispatch; a
//! separate Execute reobserves that exact challenged probe before admission.
//! Read-only queries recover either the identical probe or a signed receipt
//! after a lost response, without authorizing another attempt.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_core::{ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::operator_storage_repair_transport_v3::{
    MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V3, OperatorStorageRepairModeV3,
    OperatorStorageRepairRequestV3, OperatorStorageRepairResponseV3, OperatorStorageRepairResultV3,
};
use aos_sandbox_protocol::{decode_request_envelope, validate_request_descriptor_roles};
use buffa::Message as _;

use crate::StorageAdmissionError;
use crate::operator_recovery::{StorageOperatorRecoveryErrorV1, StorageOperatorRecoveryOwnerV1};
use crate::peer::ControllerPeerVerifier;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError, trusted_paired_clock_sample};
use crate::service::{StorageConnectionOutcome, StorageServiceError};
use crate::transport::{accept_connection, boottime, receive, send};

const RECEIVE_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_REQUEST_LIFETIME_NANOSECONDS: u64 = 60_000_000_000;
const STORAGE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Serves one two-phase operator Repair or read-only recovery packet.
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
    guest_root_template: Option<&crate::guest_root_inventory::ProtectedGuestRootTemplateV1>,
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
        MAXIMUM_OPERATOR_STORAGE_REPAIR_PACKET_BYTES_V3.max(
            aos_sandbox_protocol::operator_storage_repair_terminal_v4::MAXIMUM_TERMINAL_REQUEST_BYTES_V4,
        ),
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
    if record.payload().starts_with(b"AOSORH04") {
        let request = match owner.verify_terminal_request_v4(record.payload()) {
            Ok(request) => request,
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        drop(record);
        let now = boottime()?;
        if request.deadline() <= now
            || request.deadline() > now.checked_add(MAXIMUM_REQUEST_LIFETIME_NANOSECONDS).ok_or(StorageServiceError::Clock)?
            || verifier.recheck_connection(execution, connection.peer()).is_err()
        {
            return Ok(StorageConnectionOutcome::RequestRejected);
        }
        // Original custody precedes exclusion. Failure after this point
        // leaves a cold-recoverable reservation and keeps dispatch closed.
        match owner.recover_terminal_settlement_v4(&request) {
            Ok(Some(readback)) => {
                if verifier.recheck_connection(execution, connection.peer()).is_err()
                    || send(&mut connection, &readback, request.deadline()).is_err()
                {
                    return Ok(StorageConnectionOutcome::TransportRejected);
                }
                return Ok(StorageConnectionOutcome::Served);
            }
            Ok(None) => {}
            Err(StorageOperatorRecoveryErrorV1::Journal(_)) => return Err(StorageRuntimeError::ReopenRequired.into()),
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        }
        match owner.reserve_terminal_hold_v4(&request) {
            Ok(()) => {}
            Err(StorageOperatorRecoveryErrorV1::Journal(_)) => return Err(StorageRuntimeError::ReopenRequired.into()),
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        }
        runtime.retain_operator_terminal_exclusion()?;
        let held = runtime.hold_operator_terminal_inventory_v4(
            request.inventory(), request.deadline(), guest_root_template, owner,
        )?;
        let witness = owner.finish_terminal_hold_v4(&request, held.state_cut(), held.live_cut())
            .map_err(|_| StorageRuntimeError::ReopenRequired)?;
        if verifier.recheck_connection(execution, connection.peer()).is_err()
            || send(&mut connection, witness.as_bytes(), request.deadline()).is_err()
        {
            return Ok(StorageConnectionOutcome::TransportRejected);
        }

        // Both actual owners stay on this same serial actor child. There is
        // no ordinary Inventory request while the hold is live.
        let ack = match receive(&mut connection,
            aos_sandbox_protocol::operator_storage_repair_terminal_v4::TERMINAL_SETTLEMENT_BYTES_V4,
            request.deadline())
        {
            Ok(ack) => ack,
            Err(_) => return Ok(StorageConnectionOutcome::TransportRejected),
        };
        if verifier.verify_record(execution, connection.peer(), ack.subject()).is_err()
            || verifier.recheck_connection(execution, connection.peer()).is_err()
        {
            return Ok(StorageConnectionOutcome::PeerRejected);
        }
        let settlement = match owner.settle_terminal_hold_v4(&request, &witness, ack.payload(), boottime()?) {
            Ok(settlement) => settlement,
            Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
        };
        drop(ack);
        let release = settlement.release().to_vec();
        held.release_after_settlement(settlement)?;
        if verifier.recheck_connection(execution, connection.peer()).is_err()
            || send(&mut connection, &release, request.deadline()).is_err()
        {
            return Ok(StorageConnectionOutcome::TransportRejected);
        }
        return Ok(StorageConnectionOutcome::Served);
    }
    let request = match OperatorStorageRepairRequestV3::decode(record.payload()) {
        Ok(request) => request,
        Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
    };
    drop(record);

    let now = boottime()?;
    let latest = now
        .checked_add(MAXIMUM_REQUEST_LIFETIME_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    if request.deadline() <= now
        || request.deadline() > latest
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

    let result = match request.mode() {
        OperatorStorageRepairModeV3::Prepare | OperatorStorageRepairModeV3::Execute => {
            let envelope = match decode_effect_envelope(request.envelope()) {
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
            let result = match request.mode() {
                OperatorStorageRepairModeV3::Prepare => runtime
                    .prepare_workspace_pin_repair_for_operator(
                        envelope.body(),
                        artifacts,
                        STORAGE_VERSION,
                        execution.credentials(),
                        verifier.policy(),
                        request.signed_intent(),
                        owner,
                        &mut clock,
                    )
                    .map(OperatorStorageRepairResultV3::Prepared),
                OperatorStorageRepairModeV3::Execute => runtime
                    .execute_prepared_workspace_pin_repair_for_operator(
                        envelope.body(),
                        artifacts,
                        STORAGE_VERSION,
                        execution.credentials(),
                        verifier.policy(),
                        request.signed_intent(),
                        request.expected_attestation_digest(),
                        owner,
                        &mut clock,
                    )
                    .map(completion_result),
                _ => return Ok(StorageConnectionOutcome::RequestRejected),
            };
            match result {
                Ok(result) => result,
                Err(StorageRuntimeError::ReopenRequired) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
        }
        OperatorStorageRepairModeV3::RecoverProbe => {
            if !runtime.is_inventory_ready() {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            match owner.recover_reserved_probe_attestation_v1(request.signed_intent()) {
                Ok(packet) => OperatorStorageRepairResultV3::Prepared(packet),
                Err(StorageOperatorRecoveryErrorV1::Journal(_)) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
        }
        OperatorStorageRepairModeV3::RecoverReceipt => {
            if !runtime.is_inventory_ready() {
                return Ok(StorageConnectionOutcome::RequestRejected);
            }
            match owner.require_reserved_intent(request.signed_intent()) {
                Ok(_) => {}
                Err(StorageOperatorRecoveryErrorV1::Journal(_)) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
            match runtime.recover_operator_workspace_pin_receipt(owner, effect_id) {
                Ok(receipt) => completion_result(receipt),
                Err(StorageRuntimeError::ReopenRequired) => {
                    return Err(StorageRuntimeError::ReopenRequired.into());
                }
                Err(_) => return Ok(StorageConnectionOutcome::RequestRejected),
            }
        }
    };
    let response = OperatorStorageRepairResponseV3::new(request.request_id(), effect_id, result)
        .map_err(|_| {
            StorageServiceError::Activation("operator Repair response was invalid".to_owned())
        })?;
    if verifier
        .recheck_connection(execution, connection.peer())
        .is_err()
        || send(&mut connection, &response.encode(), request.deadline()).is_err()
    {
        return Ok(StorageConnectionOutcome::TransportRejected);
    }
    Ok(StorageConnectionOutcome::Served)
}

fn completion_result(
    completion: Option<crate::operator_recovery::StorageOperatorRecoveryCompletionV2>,
) -> OperatorStorageRepairResultV3 {
    match completion {
        Some(completion) => OperatorStorageRepairResultV3::Complete(
            completion.signed_evidence,
            completion.signed_receipt,
        ),
        None => OperatorStorageRepairResultV3::Pending,
    }
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
