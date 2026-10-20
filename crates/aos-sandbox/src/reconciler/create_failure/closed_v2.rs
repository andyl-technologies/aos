//! Encodes immutable closed-before-argument settlement rows and prepare DATA.
//!
//! The shared reducer keeps this relation separate from literal AOSCFB01 and
//! AOSCFP01. Root anchors exact row digests after planning; its actual floor
//! therefore belongs in Controller prepare, outside the immutable successor
//! receipt. Fresh cleanup currentness can rejoin the same six row bytes.
//!
//! ```text
//! AOSCFB02 | version:u16be | reserved:2 | terminal-archive:32 |
//! signed-terminal:32 | AOSHNB02:448 | predecessor-revision:32 |
//! successor-revision:32 | successor-operation:32 |
//! predecessor-sequence:u64be | effect-attempt:u32be | wall:i64be | checksum:32
//!
//! AOSCFP02 | version:u16be | reserved:2 | operation:16 | AOSHNB02:448 |
//! terminal-archive:32 | signed-terminal:32 | Root-floor:32 | Root-sequence:u64be |
//! wall:i64be | predecessor-record-digests:96 | successor-record-digests:96 | checksum:32
//! ```
//!
//! These private structs are comparison/row DATA. No constructor issues a
//! Host lease, independent Root floor or permission to commit a transaction.

use aos_sandbox_core::{ObjectDigest, OperationId, bounded_codec::BoundedReader};
use aos_sandbox_protocol::host_execution_no_apply::{
    BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2, ClosedBeforeArgumentNoApplyRecordV2,
};
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::{
    ClosedCreateFailureIdentityDataV2, ClosedCreateFailurePrepareDataV2,
};
use sha2::{Digest as _, Sha256};

use super::*;

mod planning;
pub(crate) use planning::{ClosedCreateFailurePlanDataV2, plan_closed_create_failure_rows_data_v2};

const RECEIPT_MAGIC: &[u8; 8] = b"AOSCFB02";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.create-failed-before-commit.closed.v2\0";
const RESOURCE_DOMAIN: &[u8] = b"aos.sandbox.failed-create-resource-version.closed.v2\0";
const RECEIPT_BYTES_V2: usize = 12 + 64 + BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2 + 96 + 8 + 4 + 8 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClosedCreateFailureReceiptV2 {
    pub(super) identity: ClosedCreateFailureIdentityDataV2,
    pub(super) predecessor_revision: ObjectDigest,
    pub(super) successor_revision: ObjectDigest,
    pub(super) successor_operation: ObjectDigest,
    pub(super) predecessor_sequence: u64,
    pub(super) effect_attempt: u32,
    pub(super) wall_seconds: i64,
}

impl ClosedCreateFailureReceiptV2 {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES_V2);
        bytes.extend_from_slice(RECEIPT_MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.identity.terminal_archive.as_bytes());
        bytes.extend_from_slice(self.identity.signed_terminal.as_bytes());
        bytes.extend_from_slice(&self.identity.marker.encode_canonical());
        for digest in [self.predecessor_revision, self.successor_revision, self.successor_operation] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.predecessor_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.effect_attempt.to_be_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        append_checksum(&mut bytes, RECEIPT_DOMAIN);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ()> {
        require_envelope(bytes, RECEIPT_MAGIC, RECEIPT_BYTES_V2, RECEIPT_DOMAIN)?;
        let mut reader = BoundedReader::new(&bytes[12..RECEIPT_BYTES_V2 - 32], |_| ());
        let terminal_archive = digest(&mut reader)?;
        let signed_terminal = digest(&mut reader)?;
        let marker = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(
            &reader.array::<BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2>()?,
        ).map_err(|_| ())?;
        let receipt = Self {
            identity: ClosedCreateFailureIdentityDataV2 { marker, terminal_archive, signed_terminal },
            predecessor_revision: digest(&mut reader)?,
            successor_revision: digest(&mut reader)?,
            successor_operation: digest(&mut reader)?,
            predecessor_sequence: u64::from_be_bytes(reader.array::<8>()?),
            effect_attempt: u32::from_be_bytes(reader.array::<4>()?),
            wall_seconds: i64::from_be_bytes(reader.array::<8>()?),
        };
        if reader.remaining() != 0 || receipt.predecessor_sequence == 0 || receipt.effect_attempt == 0
            || receipt.encode() != bytes { return Err(()); }
        Ok(receipt)
    }

    fn resource_version(self) -> [u8; 32] {
        Sha256::new().chain_update(RESOURCE_DOMAIN)
            .chain_update(self.identity.marker.encode_canonical())
            .chain_update(self.identity.terminal_archive.as_bytes())
            .chain_update(self.identity.signed_terminal.as_bytes())
            .chain_update(self.predecessor_revision.as_bytes()).finalize().into()
    }
}

/// Shares the sole three-row reducer without changing either literal encoding.
pub(super) enum CreateFailurePlanIdentityV2<'identity> {
    AfterArgument(&'identity CreateFailureSettlementProofV1),
    ClosedBeforeArgument(&'identity ClosedCreateFailureIdentityDataV2),
}

impl CreateFailurePlanIdentityV2<'_> {
    pub(super) fn require_current_journal_data_v2(&self, journal: &Journal) -> Result<(), ReconcilerError> {
        if let Self::ClosedBeforeArgument(identity) = self {
            planning::require_accepted_request_digest_data_v2(journal, identity.marker)
        } else { Ok(()) }
    }
    pub(super) fn require_identity_data_v2(&self) -> Result<(), ReconcilerError> {
        if let Self::ClosedBeforeArgument(identity) = self {
            if identity.terminal_archive.as_bytes() == &[0; 32]
                || identity.signed_terminal.as_bytes() == &[0; 32]
            { return Err(invalid_settlement()); }
        }
        Ok(())
    }

    pub(super) fn target_data_v2(&self) -> ([u8; 16], [u8; 16]) {
        match self {
            Self::AfterArgument(proof) => {
                let fields = proof.marker.fields();
                (fields.create_operation_id, fields.execution_id)
            }
            Self::ClosedBeforeArgument(identity) => {
                let fields = identity.marker.fields().source.fields();
                (fields.create_operation, fields.execution)
            }
        }
    }

    pub(super) fn receipt_data_v2(&self, predecessor_revision: ObjectDigest,
        successor_revision: ObjectDigest, successor_operation: ObjectDigest,
        predecessor_sequence: u64, effect_attempt: u32, wall_seconds: i64,
    ) -> CreateFailureReceiptDataV2 {
        match self {
            Self::AfterArgument(proof) => CreateFailureReceiptDataV2::AfterArgument((**proof).into_receipt(
                predecessor_revision, successor_revision, successor_operation,
                predecessor_sequence, effect_attempt, wall_seconds,
            )),
            Self::ClosedBeforeArgument(identity) => CreateFailureReceiptDataV2::ClosedBeforeArgument(
                ClosedCreateFailureReceiptV2 { identity: **identity, predecessor_revision,
                    successor_revision, successor_operation, predecessor_sequence, effect_attempt, wall_seconds },
            ),
        }
    }
}

pub(super) enum CreateFailureReceiptDataV2 {
    AfterArgument(CreateFailureReceiptV1),
    ClosedBeforeArgument(ClosedCreateFailureReceiptV2),
}

impl CreateFailureReceiptDataV2 {
    pub(super) fn decode(bytes: &[u8]) -> Result<Option<Self>, ()> {
        if bytes.starts_with(RECEIPT_MAGIC) {
            ClosedCreateFailureReceiptV2::decode(bytes).map(Self::ClosedBeforeArgument).map(Some)
        } else if bytes.starts_with(b"AOSCFB") && !bytes.starts_with(MAGIC) {
            Err(())
        } else {
            CreateFailureReceiptV1::decode(bytes).map(|value| value.map(Self::AfterArgument))
        }
    }

    pub(super) fn encode(self) -> Vec<u8> {
        match self {
            Self::AfterArgument(receipt) => receipt.encode(),
            Self::ClosedBeforeArgument(receipt) => receipt.encode(),
        }
    }

    pub(super) fn resource_version(&self) -> [u8; 32] {
        match self {
            Self::AfterArgument(receipt) => receipt.resource_version(),
            Self::ClosedBeforeArgument(receipt) => receipt.resource_version(),
        }
    }

    pub(super) fn with_successor_revision_v2(self, successor_revision: ObjectDigest) -> Self {
        match self {
            Self::AfterArgument(receipt) => Self::AfterArgument(CreateFailureReceiptV1 { successor_revision, ..receipt }),
            Self::ClosedBeforeArgument(receipt) => Self::ClosedBeforeArgument(ClosedCreateFailureReceiptV2 { successor_revision, ..receipt }),
        }
    }
}


fn append_checksum(bytes: &mut Vec<u8>, domain: &[u8]) {
    let checksum = Sha256::new().chain_update(domain).chain_update(&*bytes).finalize();
    bytes.extend_from_slice(&checksum);
}

fn require_envelope(bytes: &[u8], magic: &[u8; 8], width: usize, domain: &[u8]) -> Result<(), ()> {
    if bytes.len() != width || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10..12] != [0; 2]
        || Sha256::new().chain_update(domain).chain_update(&bytes[..width - 32]).finalize().as_slice()
            != &bytes[width - 32..] { return Err(()); }
    Ok(())
}

fn digest(reader: &mut BoundedReader<'_, ()>) -> Result<ObjectDigest, ()> {
    let bytes = reader.array::<32>()?;
    if bytes == [0; 32] { return Err(()); }
    Ok(ObjectDigest::from_bytes(bytes))
}

pub(super) fn validate_failed_operation_v2(
    journal: &Journal, operation_id: OperationId, operation: OperationRecord,
    effect: &aos_sandbox_protocol::domain_ledger::effect_history::EffectLedgerRecord,
    effect_attempt: u32, receipt: ClosedCreateFailureReceiptV2,
) -> Result<(), ReconcilerError> {
    journal.ensure_protected_authority()?;
    planning::require_accepted_request_digest_data_v2(journal, receipt.identity.marker)?;
    let floor = load_floor_v2(journal, operation_id)?;
    let source = receipt.identity.marker.fields().source.fields();
    if operation.state() != OperationState::FailedBeforeCommit || operation.effect_count() != 1
        || operation.ownership_gated() || operation.runtime_intent_digest().is_some()
        || operation.public_operation().map(|public| public.method()) != Some(PublicOperationMethodV1::CreateExecution)
        || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || effect.dispatch().is_some() || source.create_operation != operation_id.into_bytes()
        || receipt.successor_operation != operation_digest(operation)
        || receipt.effect_attempt != effect_attempt || floor.identity != receipt.identity
        || floor.wall_seconds != receipt.wall_seconds
    { return Err(invalid_settlement()); }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, source.execution)
        .map_err(|_| invalid_settlement())?.ok_or_else(invalid_settlement)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(invalid_settlement());
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?
        .ok_or_else(invalid_settlement)?;
    validate_accepted_create_identity(effect, operation_id, execution)?;
    if admission.authorization().project() != projection.project()
        || admission.authorization().resource_kind() != ResourceKind::Execution
        || projection.operation() != operation_id || projection.revision() != receipt.successor_revision
        || execution.sandbox_id.as_slice() != source.sandbox
        || execution.sandbox_incarnation_id.as_slice() != source.incarnation
        || execution.execution_id.as_slice() != source.execution
        || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_FAILED)
        || execution.observation_sequence != receipt.predecessor_sequence.checked_add(1).ok_or_else(invalid_settlement)?
        || execution.resource_version.as_slice() != receipt.resource_version()
        || execution.access.as_option().is_some() || execution.result.as_option().is_some()
        || execution.last_successful_reconciliation_time.as_option()
            .is_none_or(|time| time.seconds != receipt.wall_seconds || time.nanoseconds != 0)
    { return Err(invalid_settlement()); }
    if actual_record_digests_v2(journal, floor)? != floor.successor {
        return Err(invalid_settlement());
    }
    Ok(())
}

pub(super) fn validate_floor_v2(journal: &Journal, key: &[u8], bytes: &[u8]) -> Result<(), ReconcilerError> {
    journal.ensure_protected_authority()?;
    let floor = ClosedCreateFailurePrepareDataV2::decode_canonical(key, bytes).map_err(|_| invalid_settlement())?;
    planning::require_accepted_request_digest_data_v2(journal, floor.identity.marker)?;
    let operation_bytes = journal.get(RecordNamespace::Operation, key).ok_or_else(invalid_settlement)?;
    let operation = decode_operation(operation_bytes)?;
    let effect_bytes = journal.get(RecordNamespace::Effect, &effect_key(floor.operation, 0))
        .ok_or_else(invalid_settlement)?;
    let effect = decode_effect(effect_bytes).map_err(ReconcilerError::from)?;
    let actual = actual_record_digests_v2(journal, floor)?;
    match operation.state() {
        OperationState::FailedBeforeCommit if actual == floor.successor => {
            let EffectState::Applied { attempt, receipt } = effect.state() else {
                return Err(invalid_settlement());
            };
            let Some(CreateFailureReceiptDataV2::ClosedBeforeArgument(receipt)) =
                CreateFailureReceiptDataV2::decode(receipt.as_bytes()).map_err(|_| invalid_settlement())?
            else { return Err(invalid_settlement()); };
            validate_failed_operation_v2(journal, floor.operation, operation, &effect, *attempt, receipt)
        }
        OperationState::Applying if actual == floor.predecessor => {
            let source = floor.identity.marker.fields().source.fields();
            let projection = PublicProjectionStoreV1::new(journal)
                .get(PublicProjectionKindV1::Execution, source.execution)
                .map_err(|_| invalid_settlement())?.ok_or_else(invalid_settlement)?;
            let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
                return Err(invalid_settlement());
            };
            let admission = recovered_public_operation_admission_v1(journal, floor.operation)?
                .ok_or_else(invalid_settlement)?;
            if operation.effect_count() != 1 || operation.ownership_gated()
                || operation.runtime_intent_digest().is_some()
                || operation.public_operation().map(|public| public.method()) != Some(PublicOperationMethodV1::CreateExecution)
                || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
                || effect.dispatch().is_some() || !matches!(effect.state(), EffectState::Applying { .. })
                || projection.operation() != floor.operation || execution.execution_id.as_slice() != source.execution
                || execution.sandbox_id.as_slice() != source.sandbox
                || execution.sandbox_incarnation_id.as_slice() != source.incarnation
                || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
                || execution.result.as_option().is_some()
                || admission.authorization().project() != projection.project()
                || admission.authorization().resource_kind() != ResourceKind::Execution
            { return Err(invalid_settlement()); }
            validate_accepted_create_identity(&effect, floor.operation, execution)
        }
        _ => Err(invalid_settlement()),
    }
}

fn load_floor_v2(journal: &Journal, operation: OperationId) -> Result<ClosedCreateFailurePrepareDataV2, ReconcilerError> {
    let bytes = journal.get(RecordNamespace::ControllerCreateFailurePrepare, operation.as_bytes())
        .ok_or_else(invalid_settlement)?;
    ClosedCreateFailurePrepareDataV2::decode_canonical(operation.as_bytes(), bytes).map_err(|_| invalid_settlement())
}

fn actual_record_digests_v2(
    journal: &Journal,
    floor: ClosedCreateFailurePrepareDataV2,
) -> Result<[ObjectDigest; 3], ReconcilerError> {
    let records = actual_records_data_v2(journal, floor)?;
    Ok([
        record_digest(&records[0])?,
        record_digest(&records[1])?,
        record_digest(&records[2])?,
    ])
}

// Both validation and settled recovery borrow the same actual row identities.
// No predecessor bytes are reconstructed from a historical receipt.
fn actual_records_data_v2(
    journal: &Journal,
    floor: ClosedCreateFailurePrepareDataV2,
) -> Result<[JournalRecord; 3], ReconcilerError> {
    let effect_key = effect_key(floor.operation, 0);
    let desired_key = desired_execution_key(
        journal,
        floor.identity.marker.fields().source.fields().execution,
    )?;
    let effect = journal
        .get(RecordNamespace::Effect, &effect_key)
        .ok_or_else(invalid_settlement)?;
    let operation = journal
        .get(RecordNamespace::Operation, floor.operation.as_bytes())
        .ok_or_else(invalid_settlement)?;
    let desired = journal
        .get(RecordNamespace::DesiredState, &desired_key)
        .ok_or_else(invalid_settlement)?;
    Ok([
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key.to_vec(),
            effect.to_vec(),
        ),
        JournalRecord::put(
            RecordNamespace::Operation,
            floor.operation.into_bytes().to_vec(),
            operation.to_vec(),
        ),
        JournalRecord::put(RecordNamespace::DesiredState, desired_key, desired.to_vec()),
    ])
}
