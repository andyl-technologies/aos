//! Encodes closed-before-argument Controller prepare and acknowledgement DATA.
//!
//! The prepare holds an independent Root reference outside the immutable three
//! successor rows. The acknowledgement commits the actual settled global cut.
//! Neither decoded value supplies a native prepared, floor or CAS owner.
//!
//! ```text
//! AOSCFP02 | version:2 | reserved:2 | operation:16 | marker:448 | H:32 | T:32 |
//! Root-floor:32 | Root-sequence:8 | wall:8 | predecessors:96 | successors:96 | checksum:32
//! AOSCFK02 | version:2 | reserved:2 | operation:16 | Root-floor:32 |
//! Root-sequence:8 | prepare:32 | settled-CAS:32 | phase:8 | global-C-cut:96 | checksum:32
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId, bounded_codec::BoundedReader};
use sha2::{Digest as _, Sha256};

use super::{BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2, ClosedBeforeArgumentNoApplyRecordV2};
use crate::domain_ledger::execution_no_apply_floor::{
    ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2, RootExecutionNoApplyControllerCutDataV2,
};

/// Identifies the sole closed-before-argument prepare grammar.
pub const CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2: &[u8; 8] = b"AOSCFP02";
/// Exact canonical prepare extent.
pub const CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2: usize =
    12 + 16 + BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2 + 64 + 32 + 8 + 8 + 192 + 32;
/// Exact canonical acknowledgement extent.
pub const CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2: usize =
    12 + 16 + 32 + 8 + 32 + 32 + 8 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2 + 32;

const PREPARE_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare.closed.v2\0";
const PREPARE_HEAD_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare-head.closed.v2\0";
const PREPARE_CAS_DOMAIN: &[u8] = b"aos.sandbox.create-failure-settlement-cas.closed.v2\0";
const ACK_DOMAIN: &[u8] = b"aos.sandbox.create-failure-ack.closed.v2\0";

/// Reports malformed closed Controller comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("closed Controller prepare or acknowledgement DATA is malformed")]
pub struct ClosedControllerDataErrorV2;

/// Carries exact terminal identities without creating terminal custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedCreateFailureIdentityDataV2 {
    /// Canonical durable Host terminal marker.
    pub marker: ClosedBeforeArgumentNoApplyRecordV2,
    /// Endpoint-independent literal signed terminal-group commitment H.
    pub terminal_archive: ObjectDigest,
    /// Exact canonical signed39 outcome packet commitment T.
    pub signed_terminal: ObjectDigest,
}

/// Retains a historical Root anchor beside exact prepared row DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedCreateFailurePrepareDataV2 {
    /// Accepted Create operation.
    pub operation: OperationId,
    /// Exact immutable Host terminal identity.
    pub identity: ClosedCreateFailureIdentityDataV2,
    /// Independently completed Root floor record commitment.
    pub root_floor: ObjectDigest,
    /// Per-operation Root floor revision.
    pub root_sequence: u64,
    /// Immutable successor wall second.
    pub wall_seconds: i64,
    /// Exact Effect, Operation and projection predecessor record digests.
    pub predecessor: [ObjectDigest; 3],
    /// Exact corresponding successor record digests.
    pub successor: [ObjectDigest; 3],
}

impl ClosedCreateFailurePrepareDataV2 {
    /// Derives the sole intended prepare from a canonical Root floor as DATA.
    ///
    /// This comparison does not establish that the floor or prepare reached
    /// disk. Native issuers independently prove their exact append and retain
    /// the Controller writer through prepare, CAS and acknowledgement.
    ///
    /// # Errors
    /// Rejects a legacy marker or any noncanonical closed prepare identity.
    pub fn from_root_floor_data_v2(
        floor: crate::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyFloorRecordDataV2,
    ) -> Result<Self, ClosedControllerDataErrorV2> {
        let fields = floor.fields();
        let lease = fields.host_lease.fields();
        let super::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) = lease.marker else {
            return Err(ClosedControllerDataErrorV2);
        };
        let prepare = Self {
            operation: OperationId::from_bytes(fields.operation),
            identity: ClosedCreateFailureIdentityDataV2 {
                marker,
                terminal_archive: ObjectDigest::from_bytes(lease.terminal_archive_head),
                signed_terminal: ObjectDigest::from_bytes(lease.signed_terminal_outcome),
            },
            root_floor: ObjectDigest::from_bytes(floor.digest()),
            root_sequence: fields.revision,
            wall_seconds: fields.terminal_wall_seconds,
            predecessor: fields.predecessor_rows.map(ObjectDigest::from_bytes),
            successor: fields.successor_rows.map(ObjectDigest::from_bytes),
        };
        Self::decode_canonical(prepare.operation.as_bytes(), &prepare.encode_canonical())
    }

    /// Encodes literal prepare DATA; native owners must authorize its append.
    #[must_use]
    pub fn encode_canonical(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2);
        bytes.extend_from_slice(CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.identity.marker.encode_canonical());
        bytes.extend_from_slice(self.identity.terminal_archive.as_bytes());
        bytes.extend_from_slice(self.identity.signed_terminal.as_bytes());
        bytes.extend_from_slice(self.root_floor.as_bytes());
        bytes.extend_from_slice(&self.root_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        for value in self.predecessor.into_iter().chain(self.successor) {
            bytes.extend_from_slice(value.as_bytes());
        }
        append_checksum(&mut bytes, PREPARE_DOMAIN);
        bytes
    }

    /// Decodes only the exact existing prepare grammar and operation key.
    ///
    /// # Errors
    /// Rejects wrong extents, checksums, reserved bytes, zero commitments or a
    /// disagreement between the key, operation and accepted Host source.
    pub fn decode_canonical(key: &[u8], bytes: &[u8]) -> Result<Self, ClosedControllerDataErrorV2> {
        require_envelope(
            bytes,
            CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2,
            CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2,
            PREPARE_DOMAIN,
        )?;
        let mut reader = BoundedReader::new(
            &bytes[12..CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2 - 32],
            |_| ClosedControllerDataErrorV2,
        );
        let operation = OperationId::from_bytes(reader.array::<16>()?);
        let marker = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(
            &reader.array::<BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2>()?,
        )
        .map_err(|_| ClosedControllerDataErrorV2)?;
        let identity = ClosedCreateFailureIdentityDataV2 {
            marker,
            terminal_archive: digest(&mut reader)?,
            signed_terminal: digest(&mut reader)?,
        };
        let value = Self {
            operation,
            identity,
            root_floor: digest(&mut reader)?,
            root_sequence: u64::from_be_bytes(reader.array::<8>()?),
            wall_seconds: i64::from_be_bytes(reader.array::<8>()?),
            predecessor: [
                digest(&mut reader)?,
                digest(&mut reader)?,
                digest(&mut reader)?,
            ],
            successor: [
                digest(&mut reader)?,
                digest(&mut reader)?,
                digest(&mut reader)?,
            ],
        };
        if operation.as_bytes() != key
            || *operation.as_bytes() != marker.fields().source.fields().create_operation
            || value.root_sequence == 0
            || reader.remaining() != 0
            || value.encode_canonical() != bytes
        {
            return Err(ClosedControllerDataErrorV2);
        }
        Ok(value)
    }

    /// Commits the exact canonical prepare, independently of its native custody.
    #[must_use]
    pub fn digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(PREPARE_HEAD_DOMAIN)
                .chain_update(self.encode_canonical())
                .finalize()
                .into(),
        )
    }

    /// Commits the intended exact three-row settlement relation.
    #[must_use]
    pub fn settled_cas_digest(self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(PREPARE_CAS_DOMAIN)
            .chain_update(self.digest().as_bytes());
        for value in self.successor {
            hasher.update(value.as_bytes());
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Names the finite native programme whose final Controller cut is compared.
///
/// These discriminators are DATA. Only the actual held Controller programme
/// may select a phase after independently validating its current rows/history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerCreateFailureAckPhaseV2 {
    /// Performs the original active one-row prepare and three-row terminal CAS.
    Active,
    /// Starts fresh cleanup from proven absence of this operation's floor.
    RecoveryBeforeFloor,
    /// Replaces a validated prepare before the actual three-row terminal CAS.
    RecoveryPrepared,
    /// Replaces prepare and validates unchanged terminal rows without rewriting them.
    RecoverySettled,
    /// Starts cleanup after durable Root floor but before Controller prepare.
    RecoveryFloorAnchored,
}

impl ControllerCreateFailureAckPhaseV2 {
    /// Returns the exact expected global sequence advance after the floor cut.
    ///
    /// A prepare transaction consumes three sequence positions. A terminal
    /// transaction consumes five more; settled replay appends no terminal rows.
    #[must_use]
    pub const fn controller_advance_data_v2(self) -> u64 {
        match self {
            Self::RecoverySettled => 3,
            Self::Active
            | Self::RecoveryBeforeFloor
            | Self::RecoveryPrepared
            | Self::RecoveryFloorAnchored => 8,
        }
    }

    const fn wire(self) -> u64 {
        match self {
            Self::Active => 1,
            Self::RecoveryBeforeFloor => 2,
            Self::RecoveryPrepared => 3,
            Self::RecoverySettled => 4,
            Self::RecoveryFloorAnchored => 5,
        }
    }

    fn decode(value: u64) -> Result<Self, ClosedControllerDataErrorV2> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::RecoveryBeforeFloor),
            3 => Ok(Self::RecoveryPrepared),
            4 => Ok(Self::RecoverySettled),
            5 => Ok(Self::RecoveryFloorAnchored),
            _ => Err(ClosedControllerDataErrorV2),
        }
    }
}

/// Compares a signed acknowledgement with an actual settled native C cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerCreateFailureAckDataV2 {
    /// Accepted Create operation.
    pub operation: OperationId,
    /// Root floor referenced by the durable Controller prepare.
    pub root_floor: ObjectDigest,
    /// Per-operation revision referenced by that prepare.
    pub root_sequence: u64,
    /// Exact durable prepare commitment.
    pub controller_prepare: ObjectDigest,
    /// Exact committed three-row CAS relation.
    pub settled_cas: ObjectDigest,
    /// Exact active or fresh cleanup native programme selected by the owner.
    pub phase: ControllerCreateFailureAckPhaseV2,
    /// Global Controller cut after the phase's actual writes and readback.
    pub controller_cut: RootExecutionNoApplyControllerCutDataV2,
}

impl ControllerCreateFailureAckDataV2 {
    /// Encodes acknowledgement DATA without producing an acknowledgement owner.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2] {
        let mut bytes = [0; CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2];
        bytes[..8].copy_from_slice(b"AOSCFK02");
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[12..28].copy_from_slice(self.operation.as_bytes());
        bytes[28..60].copy_from_slice(self.root_floor.as_bytes());
        bytes[60..68].copy_from_slice(&self.root_sequence.to_be_bytes());
        bytes[68..100].copy_from_slice(self.controller_prepare.as_bytes());
        bytes[100..132].copy_from_slice(self.settled_cas.as_bytes());
        bytes[132..140].copy_from_slice(&self.phase.wire().to_be_bytes());
        bytes[140..236].copy_from_slice(&self.controller_cut.encode_canonical());
        let checksum = Sha256::new()
            .chain_update(ACK_DOMAIN)
            .chain_update(&bytes[..236])
            .finalize();
        bytes[236..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes the exact closed acknowledgement comparison grammar.
    ///
    /// # Errors
    /// Rejects malformed extents, reserved bytes, checksums, identities or cuts.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ClosedControllerDataErrorV2> {
        require_envelope(
            bytes,
            b"AOSCFK02",
            CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
            ACK_DOMAIN,
        )?;
        let mut reader = BoundedReader::new(&bytes[12..236], |_| ClosedControllerDataErrorV2);
        let operation = OperationId::from_bytes(reader.array::<16>()?);
        let root_floor = digest(&mut reader)?;
        let root_sequence = u64::from_be_bytes(reader.array::<8>()?);
        let controller_prepare = digest(&mut reader)?;
        let settled_cas = digest(&mut reader)?;
        let phase =
            ControllerCreateFailureAckPhaseV2::decode(u64::from_be_bytes(reader.array::<8>()?))?;
        let controller_cut = RootExecutionNoApplyControllerCutDataV2::decode_canonical(
            &reader.array::<ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2>()?,
        )
        .map_err(|_| ClosedControllerDataErrorV2)?;
        let value = Self {
            operation,
            root_floor,
            root_sequence,
            controller_prepare,
            settled_cas,
            phase,
            controller_cut,
        };
        if operation.as_bytes() == &[0; 16]
            || root_sequence == 0
            || reader.remaining() != 0
            || value.encode_canonical().as_slice() != bytes
        {
            return Err(ClosedControllerDataErrorV2);
        }
        Ok(value)
    }
}

fn append_checksum(bytes: &mut Vec<u8>, domain: &[u8]) {
    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&*bytes)
        .finalize();
    bytes.extend_from_slice(&checksum);
}

fn require_envelope(
    bytes: &[u8],
    magic: &[u8; 8],
    width: usize,
    domain: &[u8],
) -> Result<(), ClosedControllerDataErrorV2> {
    if bytes.len() != width
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..10] != 2_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || Sha256::new()
            .chain_update(domain)
            .chain_update(&bytes[..width - 32])
            .finalize()
            .as_slice()
            != &bytes[width - 32..]
    {
        return Err(ClosedControllerDataErrorV2);
    }
    Ok(())
}

fn digest(
    reader: &mut BoundedReader<'_, ClosedControllerDataErrorV2>,
) -> Result<ObjectDigest, ClosedControllerDataErrorV2> {
    let bytes = reader.array::<32>()?;
    if bytes == [0; 32] {
        return Err(ClosedControllerDataErrorV2);
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_execution_no_apply::{
        BeforeArgumentNoApplySourceDataV2, BeforeArgumentNoApplySourceFieldsV2,
        ClosedBeforeArgumentNoApplyRecordFieldsV2,
    };

    fn prepare() -> ClosedCreateFailurePrepareDataV2 {
        let source = BeforeArgumentNoApplySourceDataV2::new(BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: [1; 16],
            execution: [2; 16],
            sandbox: [3; 16],
            incarnation: [4; 16],
            node: [5; 16],
            host_boot: [6; 16],
            assignment_epoch: 7,
            desired_generation: 8,
            accepted_request_digest: [9; 32],
            assignment_digest: [10; 32],
        })
        .unwrap();
        let marker =
            ClosedBeforeArgumentNoApplyRecordV2::new(ClosedBeforeArgumentNoApplyRecordFieldsV2 {
                source,
                terminal_request: [11; 16],
                terminal_session: [12; 32],
                signed_terminal_request: [13; 32],
                runtime_handle: [14; 32],
                execution_store: [15; 32],
                observed_preclose_cut: [16; 32],
                observed_epoch: 8,
                commit_sequence: 10,
            })
            .unwrap();
        ClosedCreateFailurePrepareDataV2 {
            operation: OperationId::from_bytes([1; 16]),
            identity: ClosedCreateFailureIdentityDataV2 {
                marker,
                terminal_archive: ObjectDigest::from_bytes([17; 32]),
                signed_terminal: ObjectDigest::from_bytes([18; 32]),
            },
            root_floor: ObjectDigest::from_bytes([19; 32]),
            root_sequence: 1,
            wall_seconds: 20,
            predecessor: [21, 22, 23].map(|v| ObjectDigest::from_bytes([v; 32])),
            successor: [24, 25, 26].map(|v| ObjectDigest::from_bytes([v; 32])),
        }
    }

    #[test]
    fn sole_prepare_preserves_812_bytes_and_rejects_foreign_operation_and_zero_reference() {
        let prepare = prepare();
        let bytes = prepare.encode_canonical();
        assert_eq!(bytes.len(), 812);
        assert_eq!(
            ClosedCreateFailurePrepareDataV2::decode_canonical(
                prepare.operation.as_bytes(),
                &bytes
            ),
            Ok(prepare)
        );
        assert!(ClosedCreateFailurePrepareDataV2::decode_canonical(&[2; 16], &bytes).is_err());
        let mut changed = prepare;
        changed.operation = OperationId::from_bytes([2; 16]);
        assert!(
            ClosedCreateFailurePrepareDataV2::decode_canonical(
                changed.operation.as_bytes(),
                &changed.encode_canonical()
            )
            .is_err()
        );
        changed = prepare;
        changed.root_floor = ObjectDigest::from_bytes([0; 32]);
        assert!(
            ClosedCreateFailurePrepareDataV2::decode_canonical(
                changed.operation.as_bytes(),
                &changed.encode_canonical()
            )
            .is_err()
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                ClosedCreateFailurePrepareDataV2::decode_canonical(
                    prepare.operation.as_bytes(),
                    &changed
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ack_binds_exact_phase_prepare_relation_and_global_cut_in_268_bytes() {
        use crate::domain_ledger::protected_names::ProtectedJournalNamesV1;
        let prepare = prepare();
        let controller_cut = RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
            ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
            108,
            4096,
            std::iter::empty(),
        )
        .unwrap();
        let ack = ControllerCreateFailureAckDataV2 {
            operation: prepare.operation,
            root_floor: prepare.root_floor,
            root_sequence: prepare.root_sequence,
            controller_prepare: prepare.digest(),
            settled_cas: prepare.settled_cas_digest(),
            phase: ControllerCreateFailureAckPhaseV2::Active,
            controller_cut,
        };
        let bytes = ack.encode_canonical();
        assert_eq!(bytes.len(), 268);
        assert_eq!(
            ControllerCreateFailureAckDataV2::decode_canonical(&bytes),
            Ok(ack)
        );
        assert!(ControllerCreateFailureAckDataV2::decode_canonical(&bytes[..267]).is_err());
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(ControllerCreateFailureAckDataV2::decode_canonical(&changed).is_err());
        }
        for phase in [
            ControllerCreateFailureAckPhaseV2::Active,
            ControllerCreateFailureAckPhaseV2::RecoveryBeforeFloor,
            ControllerCreateFailureAckPhaseV2::RecoveryPrepared,
            ControllerCreateFailureAckPhaseV2::RecoverySettled,
            ControllerCreateFailureAckPhaseV2::RecoveryFloorAnchored,
        ] {
            let selected = ControllerCreateFailureAckDataV2 { phase, ..ack };
            assert_eq!(
                ControllerCreateFailureAckDataV2::decode_canonical(&selected.encode_canonical()),
                Ok(selected)
            );
            assert_eq!(
                phase.controller_advance_data_v2(),
                if phase == ControllerCreateFailureAckPhaseV2::RecoverySettled {
                    3
                } else {
                    8
                }
            );
        }
        let mut unknown = bytes;
        unknown[132..140].copy_from_slice(&6_u64.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(ACK_DOMAIN)
            .chain_update(&unknown[..236])
            .finalize();
        unknown[236..].copy_from_slice(&checksum);
        assert!(ControllerCreateFailureAckDataV2::decode_canonical(&unknown).is_err());
    }
}
