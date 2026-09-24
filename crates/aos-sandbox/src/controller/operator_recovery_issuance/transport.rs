//! Protected controller exchange with Storage's separate operator Repair socket.
//!
//! A successful exchange authenticates the exact Storage owner receipt, but
//! does not complete a public operation. Terminal completion additionally
//! requires independently admitted before/after and effect-commit evidence.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_core::operator_recovery_effect::{
    OPERATOR_RECOVERY_EFFECT_INTENT_BYTES, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};
use aos_sandbox_core::{OperationId, ProtocolId};
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::operator_storage_repair_transport_v2::{
    OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V2, OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V2,
    OperatorStorageRepairModeV2, OperatorStorageRepairRequestV2, OperatorStorageRepairResponseV2,
};
use aos_sandbox_protocol::{decode_request_envelope, validate_request_descriptor_roles};
use buffa::Message as _;
use rand::{TryRngCore as _, rngs::OsRng};
use rustix::event::{PollFd, PollFlags, poll};

use super::before;
use super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::{
    CURRENT_HEAD_DOMAIN_V2, OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1,
    REQUEST_DOMAIN, StorageRepairIssuanceV2, hash, issuance_key_v2,
};
use crate::controller::{
    ActivatedOperationCompiler, NodeController, SingleNodeEffectExecutor, recovery_current_key,
};
use crate::resource_inventory::ResourceInventoryServiceIdentity;
use crate::{Journal, RecordNamespace};

const EXCHANGE_NANOSECONDS: u64 = 60_000_000_000;

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Exchanges one durably issued intent with the live Storage sidecar.
    ///
    /// The caller must supply the exact authorized Storage envelope for an
    /// effect. Receipt recovery sends no envelope and cannot dispatch work.
    /// A signed result is only receipt custody, not public terminal evidence.
    ///
    /// # Errors
    ///
    /// Rejects changed issuance/current head, mismatched Storage body, unsafe
    /// service identity, failed transport, or a non-owner-signed response.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn exchange_storage_repair_v2(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        mode: OperatorStorageRepairModeV2,
        authorized_envelope: &[u8],
        expected_storage: &ResourceInventoryServiceIdentity,
    ) -> Result<
        Option<(
            [u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
            [u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
        )>,
        OperatorRecoveryIssuanceErrorV1,
    > {
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        let signed_intent = read_current_issuance(
            self.reconciler.journal_mut(),
            signer,
            operation_id,
            storage_request_body,
            mode,
        )?;
        validate_effect_envelope(mode, authorized_envelope, storage_request_body)?;

        let intent = verify_operator_recovery_effect_intent_v1(&signed_intent, signer.verifier())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let mut request_id = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut request_id)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let deadline = boottime()?
            .checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request = OperatorStorageRepairRequestV2::new(
            request_id,
            deadline,
            mode,
            signed_intent,
            authorized_envelope.to_vec(),
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let response = exchange(
            Path::new(OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V2),
            expected_storage,
            &request,
        )?;
        if response.request_id() != request_id || response.effect_id() != intent.effect_id {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let completion = response.completion().copied();
        if let Some((evidence, receipt)) = completion {
            owner.verify_wire_receipt(&intent, &evidence, &receipt)?;
        }

        let current = read_current_issuance(
            self.reconciler.journal_mut(),
            signer,
            operation_id,
            storage_request_body,
            mode,
        )?;
        if current != signed_intent {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        Ok(completion)
    }
}

fn read_current_issuance(
    journal: &mut Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    operation_id: OperationId,
    storage_request_body: &[u8],
    mode: OperatorStorageRepairModeV2,
) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES], OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = issuance_key_v2(*operation_id.as_bytes());
    let issued = StorageRepairIssuanceV2::decode(
        &key,
        journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
        signer.verifier(),
        signer.key_id(),
        signer.generation(),
    )?;
    let intent =
        verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let current = journal
        .get(
            RecordNamespace::OperatorRecovery,
            &recovery_current_key(intent.target_id),
        )
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest
        || hash(REQUEST_DOMAIN, &[storage_request_body]) != intent.effect_id
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    if mode == OperatorStorageRepairModeV2::Effect {
        before::read(journal, &issued, intent.effect_id)?;
    }
    Ok(issued.signed_intent)
}

fn validate_effect_envelope(
    mode: OperatorStorageRepairModeV2,
    bytes: &[u8],
    body: &[u8],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    if mode == OperatorStorageRepairModeV2::RecoverReceipt {
        return if bytes.is_empty() {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let raw = BrokerRequestEnvelope::decode_from_slice(bytes)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if raw.encode_to_vec() != bytes {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let envelope = decode_request_envelope(bytes, ProtocolId::StorageBroker, 0)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if envelope.method() != BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
        || envelope.body() != body
        || envelope.authorization().is_none()
        || validate_request_descriptor_roles(&envelope, &[]).is_err()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

fn exchange(
    socket_path: &Path,
    expected: &ResourceInventoryServiceIdentity,
    request: &OperatorStorageRepairRequestV2,
) -> Result<OperatorStorageRepairResponseV2, OperatorRecoveryIssuanceErrorV1> {
    let mut socket = DescriptorSubjectSocket::connect(socket_path)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    send(
        &mut socket,
        &request.encode(),
        request.deadline_boottime_nanoseconds(),
    )?;
    let record = receive(&mut socket, request.deadline_boottime_nanoseconds())?;
    if !record.descriptors().is_empty() {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let first = validate_service_subject(expected, record.subject())?;
    let response = OperatorStorageRepairResponseV2::decode(record.payload())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let second = validate_service_subject(expected, record.subject())?;
    if !same_process(first, second) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(response)
}

fn validate_service_subject(
    expected: &ResourceInventoryServiceIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo, OperatorRecoveryIssuanceErrorV1> {
    let credentials = subject.credentials();
    if credentials.uid() != expected.uid
        || credentials.gid() != expected.gid
        || !subject
            .is_alive()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    expected
        .cgroup
        .verify_exact_membership(subject.pidfd())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

fn boottime() -> Result<u64, OperatorRecoveryIssuanceErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(now.tv_sec).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    loop {
        if boottime()? >= deadline {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::OUT, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(_) => return Err(OperatorRecoveryIssuanceErrorV1::Binding),
        }
    }
}

fn receive(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
) -> Result<
    aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    OperatorRecoveryIssuanceErrorV1,
> {
    loop {
        if boottime()? >= deadline {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        match socket.receive(OPERATOR_STORAGE_REPAIR_RESPONSE_BYTES_V2, 0) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::IN, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(_) => return Err(OperatorRecoveryIssuanceErrorV1::Binding),
        }
    }
}

fn wait(
    socket: &DescriptorSubjectSocket,
    events: PollFlags,
    deadline: u64,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(
        socket
            .as_fd()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
        events,
    )];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(OperatorRecoveryIssuanceErrorV1::Binding),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(_) => Err(OperatorRecoveryIssuanceErrorV1::Binding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_recovery_never_carries_effect_authorization() {
        assert!(
            validate_effect_envelope(OperatorStorageRepairModeV2::RecoverReceipt, &[], &[]).is_ok()
        );
        assert!(
            validate_effect_envelope(OperatorStorageRepairModeV2::RecoverReceipt, &[1], &[])
                .is_err()
        );
        assert!(validate_effect_envelope(OperatorStorageRepairModeV2::Effect, &[], &[]).is_err());
    }
}
