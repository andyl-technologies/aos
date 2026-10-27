//! Owns immutable legacy prepare encoding and historical floor comparison.
//!
//! This DATA codec never creates the live Host proof retained by upper commit.

use super::*;

const MAGIC: &[u8; 8] = b"AOSCFP01";
const DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare.v1\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare-head.v1\0";
const CAS_DOMAIN: &[u8] = b"aos.sandbox.create-failure-settlement-cas.v1\0";
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
/// Retains immutable legacy floor DATA without a live Host lease.
pub struct CreateFailurePrepareV1 {
    /// Names the accepted Create operation.
    pub operation_id: OperationId,
    /// Retains the canonical historical Host marker.
    pub marker: HostExecutionNoApplyRecordV1,
    /// Commits the historical Host archive.
    pub archive_head: ObjectDigest,
    /// Commits the historical signed outcome.
    pub signed_outcome: ObjectDigest,
    /// Commits the historical Host cut.
    pub current_host_cut: ObjectDigest,
    /// Records the historical lease epoch as DATA.
    pub host_lease_epoch: u64,
    /// Commits the historical lease head as DATA.
    pub host_lease_head: ObjectDigest,
    /// Records the terminal wall coordinate.
    pub wall_seconds: i64,
    /// Commits the original three record encodings.
    pub predecessor: [ObjectDigest; 3],
    /// Commits the successor three record encodings.
    pub successor: [ObjectDigest; 3],
}

impl CreateFailurePrepareV1 {


    /// Encodes the exact historical grammar and checksum.
    pub fn encode(self) -> Vec<u8> {
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

    /// Computes the canonical floor commitment.
    pub fn digest(self) -> ObjectDigest {
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
    pub fn settled_cas_digest(self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(CAS_DOMAIN)
            .chain_update(self.digest().as_bytes());
        for digest in self.successor {
            hasher.update(digest.as_bytes());
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Decodes only the exact historical grammar.
    ///
    /// # Errors
    /// Refuses a malformed envelope, field, checksum or noncanonical encoding.
    pub fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, CreateFailureDataErrorV2> {
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
        let mut reader = BoundedReader::new(&bytes[12..], |_| invalid_settlement());
        let operation_id = OperationId::from_bytes(reader.array::<16>()?);
        let marker = HostExecutionNoApplyRecordV1::decode_canonical(
            &reader.array::<HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1>()?,
        )
        .map_err(|_| invalid_settlement())?;
        let digest = |reader: &mut BoundedReader<'_, CreateFailureDataErrorV2>| -> Result<
            ObjectDigest,
            CreateFailureDataErrorV2,
        > {
            let bytes = reader.array::<32>()?;
            if bytes == [0; 32] {
                return Err(invalid_settlement());
            }
            Ok(ObjectDigest::from_bytes(bytes))
        };
        let archive_head = digest(&mut reader)?;
        let signed_outcome = digest(&mut reader)?;
        let current_host_cut = digest(&mut reader)?;
        let host_lease_epoch = u64::from_be_bytes(reader.array::<8>()?);
        let host_lease_head = digest(&mut reader)?;
        let wall_seconds = i64::from_be_bytes(reader.array::<8>()?);
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
            || reader.remaining() != 32
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

/// Decodes a retained legacy floor, if present.
///
/// # Errors
/// Preserves the exact legacy floor decoder cause.
pub fn load_floor(
    journal: &CreateFailureHistoricalDataV2<'_>,
    operation_id: OperationId,
) -> Result<Option<CreateFailurePrepareV1>, CreateFailureDataErrorV2> {
    journal
        .get(
            RecordNamespace::ControllerCreateFailurePrepare,
            operation_id.as_bytes(),
        )
        .map(|bytes| CreateFailurePrepareV1::decode(operation_id.as_bytes(), bytes))
        .transpose()
}

/// Validates every recorded floor against its same-cut rows.
///
/// # Errors
/// Preserves ordered protection, row decoder and exact-relation failures.
pub fn validate_all_floors(journal: &CreateFailureHistoricalDataV2<'_>) -> Result<(), CreateFailureDataErrorV2> {
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
        if bytes.starts_with(crate::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2) {
            super::validate_floor_v2(journal, key, bytes)?;
            continue;
        }
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
        match operation.state() {
            OperationState::Applying if actual == floor.predecessor => {
                let effect = decode_effect(effect_bytes).map_err(CreateFailureDataErrorV2::from)?;
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
                if operation.effect_count() != 1
                    || operation.ownership_gated()
                    || operation.runtime_intent_digest().is_some()
                    || operation.public_operation().map(|public| public.method())
                        != Some(PublicOperationMethodV1::CreateExecution)
                    || effect.plan().public_mutation_method()
                        != Some(PublicOperationMethodV1::CreateExecution)
                    || effect.dispatch().is_some()
                    || !matches!(effect.state(), EffectState::Applying { .. })
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

#[cfg(test)]
mod tests {
    use crate::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;

    use super::*;

    #[test]
    fn encoded_floor_prefixes_checksum_tail_and_checksummed_invalid_fields() {
        let marker = HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [3; 16],
            terminal_request_id: [4; 16],
            host_boot_id: [5; 16],
            assignment_digest: [6; 32],
            source_record_digest: [7; 32],
            original_session_binding: [8; 32],
            original_signed_request_digest: [9; 32],
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 1,
        })
        .unwrap();
        // This is a historical DATA floor, not a held settlement proof.
        let floor = CreateFailurePrepareV1 {
            operation_id: OperationId::from_bytes([2; 16]),
            marker,
            archive_head: ObjectDigest::from_bytes([14; 32]),
            signed_outcome: ObjectDigest::from_bytes([15; 32]),
            current_host_cut: ObjectDigest::from_bytes([16; 32]),
            host_lease_epoch: 1,
            host_lease_head: ObjectDigest::from_bytes([17; 32]),
            wall_seconds: -1,
            predecessor: [ObjectDigest::from_bytes([18; 32]); 3],
            successor: [ObjectDigest::from_bytes([19; 32]); 3],
        };
        let encoded = floor.encode();
        let key = floor.operation_id.as_bytes();

        assert_eq!(encoded.len(), BYTES);
        assert_eq!(
            CreateFailurePrepareV1::decode(key, &encoded).unwrap(),
            floor
        );
        for length in 0..encoded.len() {
            assert!(CreateFailurePrepareV1::decode(key, &encoded[..length]).is_err());
        }
        assert!(CreateFailurePrepareV1::decode(&key[..15], &encoded).is_err());
        assert!(CreateFailurePrepareV1::decode(&[20; 16], &encoded).is_err());
        let mut longer = encoded.clone();
        longer.push(0);
        assert!(CreateFailurePrepareV1::decode(key, &longer).is_err());

        let marker_end = 28 + HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1;
        for (offset, width) in [
            (12, 16),
            (28, 1),
            (marker_end, 32),
            (marker_end + 32, 32),
            (marker_end + 64, 32),
            (marker_end + 96, 8),
            (marker_end + 104, 32),
            (marker_end + 144, 32),
            (BYTES - 64, 32),
        ] {
            let mut malformed = encoded.clone();
            malformed[offset..offset + width].fill(0);
            let checksum = Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&malformed[..BYTES - 32])
                .finalize();
            malformed[BYTES - 32..].copy_from_slice(&checksum);
            assert!(CreateFailurePrepareV1::decode(key, &malformed).is_err());
        }
        let mut malformed = encoded;
        malformed[BYTES - 1] ^= 1;
        assert!(CreateFailurePrepareV1::decode(key, &malformed).is_err());
    }
}
