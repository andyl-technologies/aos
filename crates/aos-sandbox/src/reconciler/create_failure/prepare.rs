//! Controller-owned prepare floor for one exact no-Apply Create settlement.
//!
//! ```text
//! AOSCFP01 | version:u16be | reserved:2 | operation:16 | AOSHNA01:384 |
//! H-head:32 | signed-terminal:32 | current-Host-cut:32 |
//! Host-lease-epoch:u64be | Host-lease-head:32 | wall-seconds:i64be |
//! three predecessor record digests:96 | three successor record digests:96 |
//! SHA256(domain || preceding):32
//! ```
//!
//! This is a Controller floor, not a Host lease or authorization to settle.
//! A prepared but uncommitted Create is a legitimate crash window that must
//! remain quarantined until fresh held Host proof permits the exact CAS.

use aos_proto::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox_core::{ObjectDigest, OperationId, ResourceKind};
use aos_sandbox_protocol::host_execution_no_apply::{
    HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1, HostExecutionNoApplyRecordV1,
};
use sha2::{Digest as _, Sha256};

use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::journal::{Journal, JournalRecord, RecordNamespace};
use crate::runtime_execution::no_apply_settlement::{
    HostSettlementRecordV1, HostSettlementStageV1, validate_history,
};

use super::{
    CreateFailureSettlementProofV1, EffectState, OperationState, ReconcilerError, decode_effect,
    decode_operation, effect_key, invalid_settlement, recovered_public_operation_admission_v1,
    validate_accepted_create_identity, validate_failed_create_operation,
};

const MAGIC: &[u8; 8] = b"AOSCFP01";
const DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare.v1\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare-head.v1\0";
const CAS_DOMAIN: &[u8] = b"aos.sandbox.create-failure-settlement-cas.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare-record.v1\0";
const VERSION: u16 = 1;
const BYTES: usize = 8
    + 2
    + 2
    + 16
    + HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1
    + 32 * 3
    + 8
    + 32
    + 8
    + 32 * 3
    + 32 * 3
    + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CreateFailurePrepareV1 {
    pub(super) operation_id: OperationId,
    pub(super) marker: HostExecutionNoApplyRecordV1,
    pub(super) archive_head: ObjectDigest,
    pub(super) signed_outcome: ObjectDigest,
    pub(super) current_host_cut: ObjectDigest,
    pub(super) host_lease_epoch: u64,
    pub(super) host_lease_head: ObjectDigest,
    pub(super) wall_seconds: i64,
    pub(super) predecessor: [ObjectDigest; 3],
    pub(super) successor: [ObjectDigest; 3],
}

impl CreateFailurePrepareV1 {
    pub(super) fn from_plan(
        operation_id: OperationId,
        proof: &CreateFailureSettlementProofV1,
        wall_seconds: i64,
        predecessor: [ObjectDigest; 3],
        successor: [ObjectDigest; 3],
    ) -> Result<Self, ReconcilerError> {
        if proof.host_lease_epoch == 0
            || proof.host_lease_head.as_bytes() == &[0; 32]
            || proof.archive_head.as_bytes() == &[0; 32]
            || proof.signed_outcome.as_bytes() == &[0; 32]
            || proof.current_host_cut.as_bytes() == &[0; 32]
            || predecessor
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
            || successor.iter().any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(invalid_settlement());
        }
        Ok(Self {
            operation_id,
            marker: proof.marker,
            archive_head: proof.archive_head,
            signed_outcome: proof.signed_outcome,
            current_host_cut: proof.current_host_cut,
            host_lease_epoch: proof.host_lease_epoch,
            host_lease_head: proof.host_lease_head,
            wall_seconds,
            predecessor,
            successor,
        })
    }

    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(&self.marker.encode_canonical());
        for digest in [
            self.archive_head,
            self.signed_outcome,
            self.current_host_cut,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.host_lease_epoch.to_be_bytes());
        bytes.extend_from_slice(self.host_lease_head.as_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        for digest in self.predecessor.into_iter().chain(self.successor) {
            bytes.extend_from_slice(digest.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub(super) fn digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(HEAD_DOMAIN)
                .chain_update(self.encode())
                .finalize()
                .into(),
        )
    }

    /// Commits the exact prepared floor and three successor record bytes.
    ///
    /// Callers may issue this coordinate only after durable CAS and replay
    /// validation have re-read those exact successor records.
    pub(super) fn settled_cas_digest(self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(CAS_DOMAIN)
            .chain_update(self.digest().as_bytes());
        for digest in self.successor {
            hasher.update(digest.as_bytes());
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    pub(super) fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, ReconcilerError> {
        if key.len() != 16
            || bytes.len() != BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..BYTES - 32])
                .finalize()
                .as_slice()
                != &bytes[BYTES - 32..]
        {
            return Err(invalid_settlement());
        }
        let mut reader = Reader { bytes, offset: 12 };
        let operation_id = OperationId::from_bytes(reader.take::<16>()?);
        let marker = HostExecutionNoApplyRecordV1::decode_canonical(
            &reader.take::<HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1>()?,
        )
        .map_err(|_| invalid_settlement())?;
        let digest = |reader: &mut Reader<'_>| -> Result<ObjectDigest, ReconcilerError> {
            let bytes = reader.take::<32>()?;
            if bytes == [0; 32] {
                return Err(invalid_settlement());
            }
            Ok(ObjectDigest::from_bytes(bytes))
        };
        let archive_head = digest(&mut reader)?;
        let signed_outcome = digest(&mut reader)?;
        let current_host_cut = digest(&mut reader)?;
        let host_lease_epoch = u64::from_be_bytes(reader.take::<8>()?);
        let host_lease_head = digest(&mut reader)?;
        let wall_seconds = i64::from_be_bytes(reader.take::<8>()?);
        let mut predecessor = [ObjectDigest::from_bytes([0; 32]); 3];
        let mut successor = predecessor;
        for value in &mut predecessor {
            *value = digest(&mut reader)?;
        }
        for value in &mut successor {
            *value = digest(&mut reader)?;
        }
        if operation_id.as_bytes() != key
            || marker.fields().create_operation_id != *operation_id.as_bytes()
            || host_lease_epoch == 0
            || reader.offset != BYTES - 32
        {
            return Err(invalid_settlement());
        }
        Ok(Self {
            operation_id,
            marker,
            archive_head,
            signed_outcome,
            current_host_cut,
            host_lease_epoch,
            host_lease_head,
            wall_seconds,
            predecessor,
            successor,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ReconcilerError> {
        let end = self.offset.checked_add(N).ok_or_else(invalid_settlement)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(invalid_settlement)?
            .try_into()
            .map_err(|_| invalid_settlement())?;
        self.offset = end;
        Ok(value)
    }
}

pub(super) fn record_digest(record: &JournalRecord) -> Result<ObjectDigest, ReconcilerError> {
    let value = record.value().ok_or_else(invalid_settlement)?;
    let key_len = u64::try_from(record.key().len()).map_err(|_| invalid_settlement())?;
    let value_len = u64::try_from(value.len()).map_err(|_| invalid_settlement())?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update([record.namespace() as u8])
            .chain_update(key_len.to_be_bytes())
            .chain_update(record.key())
            .chain_update(value_len.to_be_bytes())
            .chain_update(value)
            .finalize()
            .into(),
    ))
}

pub(super) fn load_floor(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<CreateFailurePrepareV1>, ReconcilerError> {
    journal
        .get(
            RecordNamespace::ControllerCreateFailurePrepare,
            operation_id.as_bytes(),
        )
        .map(|bytes| CreateFailurePrepareV1::decode(operation_id.as_bytes(), bytes))
        .transpose()
}

/// Checks historical coordinates only; it never produces a held Host proof.
#[allow(dead_code, reason = "live cross-owner lease transport remains closed")]
pub(super) fn validate_historical_host_floor_join(
    floor: CreateFailurePrepareV1,
    preliminary: HostSettlementRecordV1,
    sealed: HostSettlementRecordV1,
    protected_host_sequence: u64,
) -> Result<(), ReconcilerError> {
    if validate_history(
        floor.marker,
        Some(preliminary),
        Some(sealed),
        None,
        protected_host_sequence,
    )
    .map_err(|_| invalid_settlement())?
        != Some(HostSettlementStageV1::FloorSealed)
        || preliminary.execution.as_bytes() != &floor.marker.fields().execution_id
        || preliminary.operation != floor.operation_id
        || preliminary.archives.original_h_head != floor.archive_head
        || preliminary.archives.signed_terminal_outcome != floor.signed_outcome
        || preliminary.pre_lease_cut != floor.current_host_cut
        || preliminary.epoch != floor.host_lease_epoch
        || preliminary.digest() != floor.host_lease_head
        || sealed.controller_floor != Some(floor.digest())
    {
        return Err(invalid_settlement());
    }
    Ok(())
}

/// Rejoins a retained Host ACK with an already durable Controller successor.
///
/// A Host ACK alone is not evidence that Controller committed its CAS. The
/// Controller floor and its three successor records must still agree when
/// cold replay reconstructs this exact settlement.
#[allow(dead_code, reason = "signed cross-owner ACK transport remains closed")]
pub(super) fn validate_settled_host_floor_join(
    journal: &Journal,
    floor: CreateFailurePrepareV1,
    preliminary: HostSettlementRecordV1,
    sealed: HostSettlementRecordV1,
    retained: HostSettlementRecordV1,
    protected_host_sequence: u64,
) -> Result<(), ReconcilerError> {
    validate_historical_host_floor_join(floor, preliminary, sealed, protected_host_sequence)?;
    if validate_history(
        floor.marker,
        Some(preliminary),
        Some(sealed),
        Some(retained),
        protected_host_sequence,
    )
    .map_err(|_| invalid_settlement())?
        != Some(HostSettlementStageV1::AckRetained)
        || retained.controller_cas != Some(floor.settled_cas_digest())
    {
        return Err(invalid_settlement());
    }

    validate_all_floors(journal)?;
    let operation_bytes = journal
        .get(RecordNamespace::Operation, floor.operation_id.as_bytes())
        .ok_or_else(invalid_settlement)?;
    if decode_operation(operation_bytes)?.state != OperationState::FailedBeforeCommit {
        return Err(invalid_settlement());
    }
    Ok(())
}

pub(super) fn validate_all_floors(journal: &Journal) -> Result<(), ReconcilerError> {
    if journal
        .records(RecordNamespace::ControllerCreateFailurePrepare)
        .next()
        .is_none()
    {
        return Ok(());
    }

    // A recorded floor is authority-bearing; an empty legacy journal is not.
    journal.ensure_protected_authority()?;
    for (key, bytes) in journal.records(RecordNamespace::ControllerCreateFailurePrepare) {
        let floor = CreateFailurePrepareV1::decode(key, bytes)?;
        let operation_bytes = journal
            .get(RecordNamespace::Operation, key)
            .ok_or_else(invalid_settlement)?;
        let operation = decode_operation(operation_bytes)?;
        let effect_key = effect_key(floor.operation_id, 0);
        let effect_bytes = journal
            .get(RecordNamespace::Effect, &effect_key)
            .ok_or_else(invalid_settlement)?;
        let desired_key =
            super::desired_execution_key(journal, floor.marker.fields().execution_id)?;
        let desired_bytes = journal
            .get(RecordNamespace::DesiredState, &desired_key)
            .ok_or_else(invalid_settlement)?;
        let records = [
            JournalRecord::put(
                RecordNamespace::Effect,
                effect_key.to_vec(),
                effect_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                key.to_vec(),
                operation_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                desired_key,
                desired_bytes.to_vec(),
            ),
        ];
        let digests = records
            .iter()
            .map(record_digest)
            .collect::<Result<Vec<_>, _>>()?;
        let actual: [ObjectDigest; 3] = digests.try_into().map_err(|_| invalid_settlement())?;
        match operation.state {
            OperationState::Applying if actual == floor.predecessor => {
                let effect = decode_effect(effect_bytes)?;
                let projection = PublicProjectionStoreV1::new(journal)
                    .get(
                        PublicProjectionKindV1::Execution,
                        floor.marker.fields().execution_id,
                    )
                    .map_err(|_| invalid_settlement())?
                    .ok_or_else(invalid_settlement)?;
                let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
                    return Err(invalid_settlement());
                };
                let admission =
                    recovered_public_operation_admission_v1(journal, floor.operation_id)?
                        .ok_or_else(invalid_settlement)?;
                if operation.effect_count != 1
                    || operation.ownership_gated
                    || operation.runtime_intent_digest.is_some()
                    || operation.public_operation.map(|public| public.method())
                        != Some(PublicOperationMethodV1::CreateExecution)
                    || effect.plan.public_mutation_method()
                        != Some(PublicOperationMethodV1::CreateExecution)
                    || effect.dispatch.is_some()
                    || !matches!(effect.state, EffectState::Applying { .. })
                    || projection.operation() != floor.operation_id
                    || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
                    || execution.result.as_option().is_some()
                    || admission.authorization().project() != projection.project()
                    || admission.authorization().resource_kind() != ResourceKind::Execution
                {
                    return Err(invalid_settlement());
                }
                validate_accepted_create_identity(&effect, floor.operation_id, execution)?;
            }
            OperationState::FailedBeforeCommit if actual == floor.successor => {
                validate_failed_create_operation(journal, floor.operation_id, operation)?;
            }
            _ => return Err(invalid_settlement()),
        }
    }
    Ok(())
}
