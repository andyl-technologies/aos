//! Closed Host-side shape of the two-owner failed-Create settlement exchange.
//!
//! ```text
//! Effect key = 'l' | execution:16 | stage:u8
//! AOSCHL01 | version:u16be | stage:u8 | reserved:u8 |
//! execution:16 | Create-operation:16 |
//! Host marker digest:32 | Host handoff digest:32 |
//! Controller-asserted H-head:32 | Controller-asserted signed T-outcome:32 |
//! Host epoch:u64be | Host pre-lease cut:32 | session:32 | challenge:16 |
//! Host commit sequence:u64be | preceding-stage digest:32 |
//! Controller AOSCFP01 digest:32 | Controller CAS digest:32 |
//! SHA256(domain || preceding):32
//! ```
//!
//! These records are nonauthorizing protocol coordinates. In particular the
//! archive fields are Controller assertions, not Host observations. A future
//! writer must derive the Host fields under its runtime/HostState locks and
//! verify signed Controller currentness while that lock remains held. A
//! structural cold replay never revives a held lock, signer, or CAS permit.

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1, validate_host_no_apply_settlement_record_envelope_v1,
};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSCHL01";
const VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-create-failure-lease.v1\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.host-create-failure-lease-head.v1\0";
pub(crate) const RECORD_BYTES: usize = 396;
pub(crate) const KEY_PREFIX: u8 = b'l';

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum HostSettlementStageV1 {
    Preliminary = 1,
    FloorSealed = 2,
    AckRetained = 3,
}

impl HostSettlementStageV1 {
    fn from_byte(value: u8) -> Result<Self, HostSettlementRecordErrorV1> {
        match value {
            1 => Ok(Self::Preliminary),
            2 => Ok(Self::FloorSealed),
            3 => Ok(Self::AckRetained),
            _ => Err(HostSettlementRecordErrorV1),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Host failed-Create settlement coordinate is malformed or conflicting")]
pub(crate) struct HostSettlementRecordErrorV1;

/// Separates a Host marker/handoff claim from Controller archive assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostObservedSettlementIdentityV1 {
    marker_digest: ObjectDigest,
    handoff_digest: ObjectDigest,
    execution: ExecutionId,
    operation: OperationId,
    marker_sequence: u64,
}

impl HostObservedSettlementIdentityV1 {
    pub(crate) fn from_marker_and_handoff(
        marker: HostExecutionNoApplyRecordV1,
        handoff_digest: ObjectDigest,
    ) -> Result<Self, HostSettlementRecordErrorV1> {
        if handoff_digest.as_bytes() == &[0; 32] {
            return Err(HostSettlementRecordErrorV1);
        }
        let fields = marker.fields();
        Ok(Self {
            marker_digest: marker_digest(marker),
            handoff_digest,
            execution: ExecutionId::from_bytes(fields.execution_id),
            operation: OperationId::from_bytes(fields.create_operation_id),
            marker_sequence: fields.commit_sequence,
        })
    }
}

/// Names Controller-held H/T archive digests without granting Host authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerAssertedSettlementArchivesV1 {
    pub(crate) original_h_head: ObjectDigest,
    pub(crate) signed_terminal_outcome: ObjectDigest,
}

impl ControllerAssertedSettlementArchivesV1 {
    pub(crate) fn new(
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
    ) -> Result<Self, HostSettlementRecordErrorV1> {
        if original_h_head.as_bytes() == &[0; 32] || signed_terminal_outcome.as_bytes() == &[0; 32]
        {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(Self {
            original_h_head,
            signed_terminal_outcome,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostSettlementRecordV1 {
    pub(crate) stage: HostSettlementStageV1,
    pub(crate) execution: ExecutionId,
    pub(crate) operation: OperationId,
    pub(crate) marker_digest: ObjectDigest,
    pub(crate) handoff_digest: ObjectDigest,
    pub(crate) archives: ControllerAssertedSettlementArchivesV1,
    pub(crate) epoch: u64,
    pub(crate) pre_lease_cut: ObjectDigest,
    pub(crate) session_binding: [u8; 32],
    pub(crate) challenge: [u8; 16],
    pub(crate) commit_sequence: u64,
    pub(crate) predecessor: Option<ObjectDigest>,
    pub(crate) controller_floor: Option<ObjectDigest>,
    pub(crate) controller_cas: Option<ObjectDigest>,
}

impl HostSettlementRecordV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preliminary(
        observed: HostObservedSettlementIdentityV1,
        archives: ControllerAssertedSettlementArchivesV1,
        epoch: u64,
        pre_lease_cut: ObjectDigest,
        session_binding: [u8; 32],
        challenge: [u8; 16],
        commit_sequence: u64,
    ) -> Result<Self, HostSettlementRecordErrorV1> {
        let record = Self {
            stage: HostSettlementStageV1::Preliminary,
            execution: observed.execution,
            operation: observed.operation,
            marker_digest: observed.marker_digest,
            handoff_digest: observed.handoff_digest,
            archives,
            epoch,
            pre_lease_cut,
            session_binding,
            challenge,
            commit_sequence,
            predecessor: None,
            controller_floor: None,
            controller_cas: None,
        };
        if epoch < observed.marker_sequence
            || !preliminary_sequence_matches_epoch(epoch, commit_sequence)
            || !record.valid()
        {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(record)
    }

    pub(crate) fn seal_floor(
        self,
        controller_floor: ObjectDigest,
        commit_sequence: u64,
    ) -> Result<Self, HostSettlementRecordErrorV1> {
        if self.stage != HostSettlementStageV1::Preliminary
            || controller_floor.as_bytes() == &[0; 32]
            || commit_sequence <= self.commit_sequence
        {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(Self {
            stage: HostSettlementStageV1::FloorSealed,
            commit_sequence,
            predecessor: Some(self.digest()),
            controller_floor: Some(controller_floor),
            ..self
        })
    }

    pub(crate) fn retain_ack(
        self,
        controller_cas: ObjectDigest,
        commit_sequence: u64,
    ) -> Result<Self, HostSettlementRecordErrorV1> {
        if self.stage != HostSettlementStageV1::FloorSealed
            || controller_cas.as_bytes() == &[0; 32]
            || commit_sequence <= self.commit_sequence
        {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(Self {
            stage: HostSettlementStageV1::AckRetained,
            commit_sequence,
            predecessor: Some(self.digest()),
            controller_cas: Some(controller_cas),
            ..self
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_controller_floor(mut self, floor: ObjectDigest) -> Self {
        self.controller_floor = Some(floor);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_controller_cas(mut self, cas: ObjectDigest) -> Self {
        self.controller_cas = Some(cas);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_marker_digest(mut self, marker_digest: ObjectDigest) -> Self {
        self.marker_digest = marker_digest;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_archives(
        mut self,
        archives: ControllerAssertedSettlementArchivesV1,
    ) -> Self {
        self.archives = archives;
        self
    }

    pub(crate) fn digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(HEAD_DOMAIN)
                .chain_update(self.encode_canonical())
                .finalize()
                .into(),
        )
    }

    pub(crate) fn encode_canonical(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        let mut cursor = 0;
        for part in [
            MAGIC.as_slice(),
            &VERSION.to_be_bytes(),
            &[self.stage as u8],
            &[0],
            self.execution.as_bytes(),
            self.operation.as_bytes(),
            self.marker_digest.as_bytes(),
            self.handoff_digest.as_bytes(),
            self.archives.original_h_head.as_bytes(),
            self.archives.signed_terminal_outcome.as_bytes(),
            &self.epoch.to_be_bytes(),
            self.pre_lease_cut.as_bytes(),
            &self.session_binding,
            &self.challenge,
            &self.commit_sequence.to_be_bytes(),
            digest_bytes(self.predecessor).as_slice(),
            digest_bytes(self.controller_floor).as_slice(),
            digest_bytes(self.controller_cas).as_slice(),
        ] {
            bytes[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..cursor])
            .finalize();
        bytes[cursor..].copy_from_slice(&checksum);
        bytes
    }

    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, HostSettlementRecordErrorV1> {
        let stage = validate_host_no_apply_settlement_record_envelope_v1(bytes)
            .map_err(|_| HostSettlementRecordErrorV1)
            .and_then(HostSettlementStageV1::from_byte)?;
        let mut reader = Reader { bytes, offset: 12 };
        let execution = ExecutionId::from_bytes(reader.take::<16>()?);
        let operation = OperationId::from_bytes(reader.take::<16>()?);
        let marker_digest = reader.digest()?;
        let handoff_digest = reader.digest()?;
        let archives =
            ControllerAssertedSettlementArchivesV1::new(reader.digest()?, reader.digest()?)?;
        let epoch = u64::from_be_bytes(reader.take::<8>()?);
        let pre_lease_cut = reader.digest()?;
        let session_binding = reader.take::<32>()?;
        let challenge = reader.take::<16>()?;
        let commit_sequence = u64::from_be_bytes(reader.take::<8>()?);
        let predecessor = reader.optional_digest()?;
        let controller_floor = reader.optional_digest()?;
        let controller_cas = reader.optional_digest()?;
        let record = Self {
            stage,
            execution,
            operation,
            marker_digest,
            handoff_digest,
            archives,
            epoch,
            pre_lease_cut,
            session_binding,
            challenge,
            commit_sequence,
            predecessor,
            controller_floor,
            controller_cas,
        };
        if reader.offset != RECORD_BYTES - 32 || !record.valid() {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(record)
    }

    fn valid(self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.operation.as_bytes() != &[0; 16]
            && self.marker_digest.as_bytes() != &[0; 32]
            && self.handoff_digest.as_bytes() != &[0; 32]
            && self.archives.original_h_head.as_bytes() != &[0; 32]
            && self.archives.signed_terminal_outcome.as_bytes() != &[0; 32]
            && self.epoch != 0
            && self.pre_lease_cut.as_bytes() != &[0; 32]
            && self.session_binding != [0; 32]
            && self.challenge != [0; 16]
            && self.commit_sequence != 0
            && match self.stage {
                HostSettlementStageV1::Preliminary => {
                    self.predecessor.is_none()
                        && self.controller_floor.is_none()
                        && self.controller_cas.is_none()
                }
                HostSettlementStageV1::FloorSealed => {
                    self.predecessor.is_some()
                        && self.controller_floor.is_some()
                        && self.controller_cas.is_none()
                }
                HostSettlementStageV1::AckRetained => {
                    self.predecessor.is_some()
                        && self.controller_floor.is_some()
                        && self.controller_cas.is_some()
                }
            }
    }

    fn advances(self, predecessor: Self) -> bool {
        self.execution == predecessor.execution
            && self.operation == predecessor.operation
            && self.marker_digest == predecessor.marker_digest
            && self.handoff_digest == predecessor.handoff_digest
            && self.archives == predecessor.archives
            && self.epoch == predecessor.epoch
            && self.pre_lease_cut == predecessor.pre_lease_cut
            && self.session_binding == predecessor.session_binding
            && self.challenge == predecessor.challenge
            && self.commit_sequence > predecessor.commit_sequence
            && self.predecessor == Some(predecessor.digest())
    }
}

fn digest_bytes(digest: Option<ObjectDigest>) -> [u8; 32] {
    digest.map_or([0; 32], |value| *value.as_bytes())
}

fn marker_digest(marker: HostExecutionNoApplyRecordV1) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(marker.encode_canonical()).into())
}

fn preliminary_sequence_matches_epoch(epoch: u64, commit_sequence: u64) -> bool {
    // A one-record Journal transaction has a begin, record, and commit frame.
    // The snapshot epoch is the sequence of its next begin frame.
    epoch.checked_add(2) == Some(commit_sequence)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], HostSettlementRecordErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(HostSettlementRecordErrorV1)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HostSettlementRecordErrorV1)?
            .try_into()
            .map_err(|_| HostSettlementRecordErrorV1)?;
        self.offset = end;
        Ok(value)
    }

    fn digest(&mut self) -> Result<ObjectDigest, HostSettlementRecordErrorV1> {
        let bytes = self.take::<32>()?;
        if bytes == [0; 32] {
            return Err(HostSettlementRecordErrorV1);
        }
        Ok(ObjectDigest::from_bytes(bytes))
    }

    fn optional_digest(&mut self) -> Result<Option<ObjectDigest>, HostSettlementRecordErrorV1> {
        let bytes = self.take::<32>()?;
        Ok((bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes)))
    }
}

pub(crate) fn lease_key(execution: ExecutionId, stage: HostSettlementStageV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(18);
    key.push(KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key.push(stage as u8);
    key
}

/// Replays only structurally joined Host phases, never a held lock or signer.
pub(crate) fn validate_history(
    marker: HostExecutionNoApplyRecordV1,
    preliminary: Option<HostSettlementRecordV1>,
    floor: Option<HostSettlementRecordV1>,
    ack: Option<HostSettlementRecordV1>,
    protected_sequence: u64,
) -> Result<Option<HostSettlementStageV1>, HostSettlementRecordErrorV1> {
    let Some(preliminary) = preliminary else {
        return if floor.is_none() && ack.is_none() {
            Ok(None)
        } else {
            Err(HostSettlementRecordErrorV1)
        };
    };
    if preliminary.stage != HostSettlementStageV1::Preliminary
        || preliminary.execution.as_bytes() != &marker.fields().execution_id
        || preliminary.operation.as_bytes() != &marker.fields().create_operation_id
        || preliminary.marker_digest != marker_digest(marker)
        || preliminary.epoch < marker.fields().commit_sequence
        || !preliminary_sequence_matches_epoch(preliminary.epoch, preliminary.commit_sequence)
        || preliminary.commit_sequence > protected_sequence
    {
        return Err(HostSettlementRecordErrorV1);
    }
    let Some(floor) = floor else {
        return if ack.is_none() {
            Ok(Some(HostSettlementStageV1::Preliminary))
        } else {
            Err(HostSettlementRecordErrorV1)
        };
    };
    if floor.stage != HostSettlementStageV1::FloorSealed
        || !floor.advances(preliminary)
        || floor.commit_sequence > protected_sequence
    {
        return Err(HostSettlementRecordErrorV1);
    }
    let Some(ack) = ack else {
        return Ok(Some(HostSettlementStageV1::FloorSealed));
    };
    if ack.stage != HostSettlementStageV1::AckRetained
        || !ack.advances(floor)
        || ack.controller_floor != floor.controller_floor
        || ack.commit_sequence > protected_sequence
    {
        return Err(HostSettlementRecordErrorV1);
    }
    Ok(Some(HostSettlementStageV1::AckRetained))
}

#[cfg(test)]
mod tests {
    use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;

    use super::*;

    fn marker() -> HostExecutionNoApplyRecordV1 {
        HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
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
            commit_sequence: 10,
        })
        .expect("canonical marker")
    }

    #[test]
    fn canonical_phase_chain_rejects_reordered_and_equivocated_records() {
        let marker = marker();
        let observed = HostObservedSettlementIdentityV1::from_marker_and_handoff(
            marker,
            ObjectDigest::from_bytes([14; 32]),
        )
        .expect("marker coordinate");
        let archives = ControllerAssertedSettlementArchivesV1::new(
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .expect("archive coordinate");
        let preliminary = HostSettlementRecordV1::preliminary(
            observed,
            archives,
            11,
            ObjectDigest::from_bytes([17; 32]),
            [18; 32],
            [19; 16],
            13,
        )
        .expect("preliminary");
        let floor = preliminary
            .seal_floor(ObjectDigest::from_bytes([20; 32]), 16)
            .expect("floor");
        let ack = floor
            .retain_ack(ObjectDigest::from_bytes([21; 32]), 19)
            .expect("ack");

        for record in [preliminary, floor, ack] {
            assert_eq!(
                HostSettlementRecordV1::decode_canonical(&record.encode_canonical()),
                Ok(record)
            );
        }
        assert_eq!(
            validate_history(marker, Some(preliminary), Some(floor), Some(ack), 19),
            Ok(Some(HostSettlementStageV1::AckRetained))
        );
        assert!(validate_history(marker, Some(preliminary), None, Some(ack), 19).is_err());
        assert!(validate_history(marker, Some(preliminary), Some(floor), Some(ack), 18).is_err());
        assert!(
            validate_history(
                marker,
                Some(HostSettlementRecordV1 {
                    epoch: preliminary.epoch + 1,
                    ..preliminary
                }),
                None,
                None,
                19,
            )
            .is_err()
        );
        assert!(
            HostSettlementRecordV1::preliminary(
                observed,
                archives,
                marker.fields().commit_sequence - 1,
                ObjectDigest::from_bytes([17; 32]),
                [18; 32],
                [19; 16],
                marker.fields().commit_sequence + 1,
            )
            .is_err()
        );
        assert!(
            validate_history(
                marker,
                Some(preliminary),
                Some(floor.with_test_marker_digest(ObjectDigest::from_bytes([22; 32]))),
                None,
                19,
            )
            .is_err()
        );
        assert!(
            validate_history(
                marker,
                Some(preliminary.with_test_marker_digest(ObjectDigest::from_bytes([23; 32]))),
                None,
                None,
                19,
            )
            .is_err()
        );

        let mut corrupt = floor.encode_canonical();
        corrupt[10] = 4;
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&corrupt[..RECORD_BYTES - 32])
            .finalize();
        corrupt[RECORD_BYTES - 32..].copy_from_slice(&checksum);
        assert!(HostSettlementRecordV1::decode_canonical(&corrupt).is_err());
    }
}
