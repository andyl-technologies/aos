//! Encodes the finite Root authorization for fresh cleanup-only Host reads.
//!
//! A genuine current Root issuer independently proves the exact history phase.
//! BeforeFloor permits actual39 before this operation's first floor, including
//! valid other-operation78 history. FloorAnchored covers an actual78 append
//! before Controller prepare durability; its intended812 remains DATA only.
//! Prepared and Settled require their actual
//! referenced floor and current head. DATA decoding supplies no native owner.
//!
//! ```text
//! AOSRAC02 | version:2 | reserved:2 | generation:8 | pin:32 |
//! Root-names:48 | next:8 | end:8 | policy:32 | policy-expiry:8 | C-cut:96 |
//! cleanup-nonce:32 | current-Host-node:16 | boot:16 | Session:32 |
//! first-clock:8 | cutoff:8 | historical-bound64:368 | accepted-source:216 |
//! durable39-marker:448 | H:32 | T:32 | phase:1 | instance-present:1 |
//! reserved:6 | optional-global-instance-slot:16 |
//! [current-floor:32 | current-revision:8 | referenced-prepare:812] |
//! signature:64 | packet-checksum:32
//! ```

use sha2::{Digest as _, Sha256};

use super::closed_controller::{
    CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, ClosedCreateFailurePrepareDataV2,
};
use super::{
    BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2, BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2,
    BeforeArgumentNoApplySourceDataV2, ClosedBeforeArgumentNoApplyRecordV2,
};
use crate::domain_ledger::{
    execution_no_apply_floor::{
        ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2, RootExecutionNoApplyControllerCutDataV2,
    },
    protected_names::ProtectedJournalNamesV1,
};
use crate::execution_availability::ExecutionAvailabilityPhaseV2;
use crate::host_execution_availability::observation::{
    HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2, HostExecutionAvailabilityObservationV2,
};

/// Dedicated signature domain for cleanup-read acquisition, never execution.
pub const ROOT_NO_APPLY_RECOVERY_ACQUISITION_SIGNING_DOMAIN_V2: &[u8] =
    b"aos.sandbox.root.execution-no-apply-recovery-acquisition.v2\0";
const PACKET_DOMAIN: &[u8] =
    b"aos.sandbox.root.execution-no-apply-recovery-acquisition-packet.v2\0";
const FIXED_PREFIX: usize = 12
    + 8
    + 32
    + 48
    + 8
    + 8
    + 32
    + 8
    + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2
    + 32
    + 16
    + 16
    + 32
    + 8
    + 8;
const FIXED_UNSIGNED: usize = FIXED_PREFIX
    + HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2
    + BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2
    + BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2
    + 64
    + 8
    + 16;
const HISTORY_BYTES: usize = 32 + 8 + CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2;
/// Largest canonical cleanup-read acquisition artifact, including its signature.
pub const MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2: usize =
    FIXED_UNSIGNED + HISTORY_BYTES + 64 + 32;

/// Reports malformed or differently bound cleanup-read acquisition DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Root NoApply recovery acquisition DATA is malformed or differently bound")]
pub struct RootNoApplyRecoveryAcquisitionDataErrorV2;

/// Names a native issuer's independently established protected history phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootNoApplyRecoveryPhaseV2 {
    /// Actual39 exists; this operation has no prepare,42Seal, terminal or floor.
    BeforeFloor,
    /// A real812 prepare references a floor in complete current78 history.
    Prepared,
    /// The same prepare and exact three terminal rows are independently read.
    Settled,
    /// Actual78 exists with exact intended812 DATA; C has no prepare or terminal.
    FloorAnchored,
}

impl RootNoApplyRecoveryPhaseV2 {
    fn tag(self) -> u8 {
        match self {
            Self::BeforeFloor => 1,
            Self::Prepared => 2,
            Self::Settled => 3,
            Self::FloorAnchored => 4,
        }
    }
}

/// Compares a referenced prepare with the current operation's Root head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNoApplyRecoveryHistoryDataV2 {
    /// Actual stored prepare for Prepared/Settled; its reference may name an ancestor.
    /// For FloorAnchored only, this is exact intended812 derived from the current
    /// actual Root floor, explicitly without any claim of Controller durability.
    pub prepare: ClosedCreateFailurePrepareDataV2,
    /// Actual current per-operation head's floor digest.
    pub current_floor: [u8; 32],
    /// Actual current per-operation head revision.
    pub current_revision: u64,
}

/// Carries comparison fields from a genuine fresh paid Root cleanup issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNoApplyRecoveryAcquisitionFieldsV2 {
    /// Dedicated signing credential generation.
    pub generation: u64,
    /// Exact matching generation-bound public credential commitment.
    pub key_commitment: [u8; 32],
    /// Current actual Root authority native names.
    pub authority_names: ProtectedJournalNamesV1,
    /// Current actual Root next position before any new floor append.
    pub authority_next: u64,
    /// Current actual Root native file end at that same cut.
    pub authority_end: u64,
    /// Current independently verified signed Root policy commitment.
    pub policy_commitment: [u8; 32],
    /// Exclusive actual signed policy wall expiry, never a financial timestamp.
    pub policy_expires_at: i64,
    /// Complete current Controller cut retained through this cleanup interval.
    pub controller_cut: RootExecutionNoApplyControllerCutDataV2,
    /// Actual fresh Controller cleanup original's native nonce.
    pub controller_nonce: [u8; 32],
    /// Actual target Host node from the current fixed native role.
    pub host_node: [u8; 16],
    /// Actual current Host boot, allowed to differ from historical execution.
    pub host_boot: [u8; 16],
    /// Actual new authenticated Controller-to-Host Session.
    pub host_session: [u8; 32],
    /// Fresh paid Controller cleanup first native paired clock.
    pub first_clock: u64,
    /// Immutable fresh cleanup deadline, bounded by real current authority.
    pub cutoff: u64,
    /// Original bound64 observation retained strictly as execution history.
    pub historical_availability: HostExecutionAvailabilityObservationV2,
    /// Exact protected accepted Create source retained as history.
    pub accepted_source: BeforeArgumentNoApplySourceDataV2,
    /// Actual durable39 future-Apply fence retained as immutable history.
    pub marker: ClosedBeforeArgumentNoApplyRecordV2,
    /// Exact original signed terminal group commitment H.
    pub terminal_archive: [u8; 32],
    /// Exact original signed39 packet commitment T.
    pub signed_terminal: [u8; 32],
    /// Actual persistent global instance when any legitimate78 history exists.
    pub root_instance: Option<[u8; 16]>,
    /// Independently classified protected history phase.
    pub phase: RootNoApplyRecoveryPhaseV2,
    /// Required prepare/current-head DATA for every phase except BeforeFloor.
    pub history: Option<RootNoApplyRecoveryHistoryDataV2>,
}

/// Borrows a canonical cleanup-read artifact without granting acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNoApplyRecoveryAcquisitionDataV2<'packet> {
    bytes: &'packet [u8],
    unsigned_len: usize,
    fields: RootNoApplyRecoveryAcquisitionFieldsV2,
}

impl<'packet> RootNoApplyRecoveryAcquisitionDataV2<'packet> {
    /// Decodes exact canonical cleanup-read comparison DATA.
    ///
    /// # Errors
    /// Rejects malformed extents/checksums, unknown phases, reserved fields,
    /// mismatched accepted/64/39 identities or missing required Root references.
    /// Dedicated signature verification and every native owner remain required.
    pub fn decode_canonical(
        bytes: &'packet [u8],
    ) -> Result<Self, RootNoApplyRecoveryAcquisitionDataErrorV2> {
        if bytes.len() < FIXED_UNSIGNED + 96
            || bytes.len() > MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2
            || bytes.get(..8) != Some(b"AOSRAC02")
            || bytes[8..10] != 2_u16.to_be_bytes()
            || bytes[10..12] != [0; 2]
            || hash(PACKET_DOMAIN, &bytes[..bytes.len() - 32])
                != field::<32>(bytes, bytes.len() - 32)?
        {
            return Err(RootNoApplyRecoveryAcquisitionDataErrorV2);
        }
        let mut cursor = FIXED_PREFIX;
        let historical_availability =
            HostExecutionAvailabilityObservationV2::decode_canonical(take(
                bytes,
                &mut cursor,
                HOST_EXECUTION_AVAILABILITY_OBSERVATION_BYTES_V2,
            )?)
            .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
        let accepted_source = BeforeArgumentNoApplySourceDataV2::decode_canonical(take(
            bytes,
            &mut cursor,
            BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2,
        )?)
        .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
        let marker = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(take(
            bytes,
            &mut cursor,
            BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2,
        )?)
        .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
        let terminal_archive = field(bytes, cursor)?;
        cursor += 32;
        let signed_terminal = field(bytes, cursor)?;
        cursor += 32;
        let phase = match field::<1>(bytes, cursor)?[0] {
            1 => RootNoApplyRecoveryPhaseV2::BeforeFloor,
            2 => RootNoApplyRecoveryPhaseV2::Prepared,
            3 => RootNoApplyRecoveryPhaseV2::Settled,
            4 => RootNoApplyRecoveryPhaseV2::FloorAnchored,
            _ => return Err(RootNoApplyRecoveryAcquisitionDataErrorV2),
        };
        let present = field::<1>(bytes, cursor + 1)?[0];
        if field::<6>(bytes, cursor + 2)? != [0; 6] {
            return Err(RootNoApplyRecoveryAcquisitionDataErrorV2);
        }
        cursor += 8;
        let instance = field::<16>(bytes, cursor)?;
        cursor += 16;
        let root_instance = match present {
            0 if instance == [0; 16] => None,
            1 if instance != [0; 16] => Some(instance),
            _ => return Err(RootNoApplyRecoveryAcquisitionDataErrorV2),
        };
        let history = if matches!(phase, RootNoApplyRecoveryPhaseV2::BeforeFloor) {
            None
        } else {
            let current_floor = field(bytes, cursor)?;
            cursor += 32;
            let current_revision = u64::from_be_bytes(field(bytes, cursor)?);
            cursor += 8;
            let prepare = ClosedCreateFailurePrepareDataV2::decode_canonical(
                &accepted_source.fields().create_operation,
                take(bytes, &mut cursor, CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2)?,
            )
            .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
            Some(RootNoApplyRecoveryHistoryDataV2 {
                prepare,
                current_floor,
                current_revision,
            })
        };
        if cursor.checked_add(96) != Some(bytes.len()) || field::<64>(bytes, cursor)? == [0; 64] {
            return Err(RootNoApplyRecoveryAcquisitionDataErrorV2);
        }
        let fields = RootNoApplyRecoveryAcquisitionFieldsV2 {
            generation: u64::from_be_bytes(field(bytes, 12)?),
            key_commitment: field(bytes, 20)?,
            authority_names: ProtectedJournalNamesV1::from_bytes(&bytes[52..100])
                .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?,
            authority_next: u64::from_be_bytes(field(bytes, 100)?),
            authority_end: u64::from_be_bytes(field(bytes, 108)?),
            policy_commitment: field(bytes, 116)?,
            policy_expires_at: i64::from_be_bytes(field(bytes, 148)?),
            controller_cut: RootExecutionNoApplyControllerCutDataV2::decode_canonical(
                &bytes[156..252],
            )
            .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?,
            controller_nonce: field(bytes, 252)?,
            host_node: field(bytes, 284)?,
            host_boot: field(bytes, 300)?,
            host_session: field(bytes, 316)?,
            first_clock: u64::from_be_bytes(field(bytes, 348)?),
            cutoff: u64::from_be_bytes(field(bytes, 356)?),
            historical_availability,
            accepted_source,
            marker,
            terminal_archive,
            signed_terminal,
            root_instance,
            phase,
            history,
        };
        require_fields(fields)?;
        Ok(Self {
            bytes,
            unsigned_len: cursor,
            fields,
        })
    }

    /// Returns exact nonauthorizing fields for actual native recipient checks.
    #[must_use]
    pub const fn fields_v2(self) -> RootNoApplyRecoveryAcquisitionFieldsV2 {
        self.fields
    }
    /// Returns the literal complete packet for the finite42 request.
    #[must_use]
    pub const fn canonical_bytes_v2(self) -> &'packet [u8] {
        self.bytes
    }
    /// Returns the literal unsigned prefix after the dedicated signature domain.
    #[must_use]
    pub fn unsigned_bytes_v2(self) -> &'packet [u8] {
        &self.bytes[..self.unsigned_len]
    }
    /// Returns unverified signature DATA without issuing a cleanup grant.
    #[must_use]
    pub fn signature_bytes_v2(self) -> [u8; 64] {
        let mut value = [0; 64];
        value.copy_from_slice(&self.bytes[self.unsigned_len..self.unsigned_len + 64]);
        value
    }
}

/// Encodes unsigned acquisition DATA; only the genuine native issuer may sign.
///
/// # Errors
/// Rejects malformed or inconsistent canonical phase/identity/history fields.
pub fn encode_root_no_apply_recovery_acquisition_unsigned_data_v2(
    fields: RootNoApplyRecoveryAcquisitionFieldsV2,
) -> Result<Vec<u8>, RootNoApplyRecoveryAcquisitionDataErrorV2> {
    require_fields(fields)?;
    let mut bytes = Vec::with_capacity(MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2 - 96);
    bytes.extend_from_slice(b"AOSRAC02");
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&fields.generation.to_be_bytes());
    bytes.extend_from_slice(&fields.key_commitment);
    bytes.extend_from_slice(&fields.authority_names.to_bytes());
    bytes.extend_from_slice(&fields.authority_next.to_be_bytes());
    bytes.extend_from_slice(&fields.authority_end.to_be_bytes());
    bytes.extend_from_slice(&fields.policy_commitment);
    bytes.extend_from_slice(&fields.policy_expires_at.to_be_bytes());
    bytes.extend_from_slice(&fields.controller_cut.encode_canonical());
    bytes.extend_from_slice(&fields.controller_nonce);
    bytes.extend_from_slice(&fields.host_node);
    bytes.extend_from_slice(&fields.host_boot);
    bytes.extend_from_slice(&fields.host_session);
    bytes.extend_from_slice(&fields.first_clock.to_be_bytes());
    bytes.extend_from_slice(&fields.cutoff.to_be_bytes());
    bytes.extend_from_slice(&fields.historical_availability.encode_canonical());
    bytes.extend_from_slice(&fields.accepted_source.encode_canonical());
    bytes.extend_from_slice(&fields.marker.encode_canonical());
    bytes.extend_from_slice(&fields.terminal_archive);
    bytes.extend_from_slice(&fields.signed_terminal);
    bytes.push(fields.phase.tag());
    bytes.push(u8::from(fields.root_instance.is_some()));
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&fields.root_instance.unwrap_or([0; 16]));
    if let Some(history) = fields.history {
        bytes.extend_from_slice(&history.current_floor);
        bytes.extend_from_slice(&history.current_revision.to_be_bytes());
        bytes.extend_from_slice(&history.prepare.encode_canonical());
    }
    Ok(bytes)
}

/// Frames a supplied signature as DATA, without exposing a native signer.
///
/// # Errors
/// Rejects malformed associations or the reserved zero signature.
pub fn encode_root_no_apply_recovery_acquisition_signed_data_v2(
    fields: RootNoApplyRecoveryAcquisitionFieldsV2,
    signature: [u8; 64],
) -> Result<Vec<u8>, RootNoApplyRecoveryAcquisitionDataErrorV2> {
    let mut bytes = encode_root_no_apply_recovery_acquisition_unsigned_data_v2(fields)?;
    bytes.extend_from_slice(&signature);
    let checksum = hash(PACKET_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum);
    RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(&bytes)?;
    Ok(bytes)
}

fn require_fields(
    fields: RootNoApplyRecoveryAcquisitionFieldsV2,
) -> Result<(), RootNoApplyRecoveryAcquisitionDataErrorV2> {
    let source = fields.accepted_source.fields();
    let marker = fields.marker.fields();
    let availability = fields.historical_availability.fields();
    ProtectedJournalNamesV1::from_bytes(&fields.authority_names.to_bytes())
        .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
    if fields.generation == 0
        || fields.key_commitment == [0; 32]
        || fields.authority_next == 0
        || fields.authority_end == 0
        || fields.policy_commitment == [0; 32]
        || fields.policy_expires_at <= 0
        || fields.controller_nonce == [0; 32]
        || fields.host_node == [0; 16]
        || fields.host_boot == [0; 16]
        || fields.host_session == [0; 32]
        || fields.cutoff <= fields.first_clock
        || fields.first_clock == 0
        || fields.terminal_archive == [0; 32]
        || fields.signed_terminal == [0; 32]
        || fields.host_node != source.node
        || marker.source != fields.accepted_source
        || availability.phase != ExecutionAvailabilityPhaseV2::AcceptedBind
        || availability.boot != source.host_boot
        || availability.bound_source_digest != *fields.accepted_source.digest().as_bytes()
        || availability.runtime_handle != marker.runtime_handle
        || availability.execution_store != marker.execution_store
        || fields.root_instance == Some([0; 16])
    {
        return Err(RootNoApplyRecoveryAcquisitionDataErrorV2);
    }
    match (fields.phase, fields.history) {
        (RootNoApplyRecoveryPhaseV2::BeforeFloor, None) => {}
        (
            RootNoApplyRecoveryPhaseV2::Prepared
            | RootNoApplyRecoveryPhaseV2::Settled
            | RootNoApplyRecoveryPhaseV2::FloorAnchored,
            Some(history),
        ) => {
            let p = history.prepare;
            if fields.root_instance.is_none()
                || history.current_floor == [0; 32]
                || history.current_revision < p.root_sequence
                || (history.current_revision == p.root_sequence)
                    != (history.current_floor == *p.root_floor.as_bytes())
                || matches!(fields.phase, RootNoApplyRecoveryPhaseV2::FloorAnchored)
                    && (history.current_revision != p.root_sequence
                        || history.current_floor != *p.root_floor.as_bytes())
                || p.operation.as_bytes() != &source.create_operation
                || p.identity.marker != fields.marker
                || p.identity.terminal_archive.as_bytes() != &fields.terminal_archive
                || p.identity.signed_terminal.as_bytes() != &fields.signed_terminal
            {
                return Err(RootNoApplyRecoveryAcquisitionDataErrorV2);
            }
            ClosedCreateFailurePrepareDataV2::decode_canonical(
                p.operation.as_bytes(),
                &p.encode_canonical(),
            )
            .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)?;
        }
        _ => return Err(RootNoApplyRecoveryAcquisitionDataErrorV2),
    }
    Ok(())
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn field<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], RootNoApplyRecoveryAcquisitionDataErrorV2> {
    let end = offset
        .checked_add(N)
        .ok_or(RootNoApplyRecoveryAcquisitionDataErrorV2)?;
    bytes
        .get(offset..end)
        .ok_or(RootNoApplyRecoveryAcquisitionDataErrorV2)?
        .try_into()
        .map_err(|_| RootNoApplyRecoveryAcquisitionDataErrorV2)
}

fn take<'bytes>(
    bytes: &'bytes [u8],
    cursor: &mut usize,
    width: usize,
) -> Result<&'bytes [u8], RootNoApplyRecoveryAcquisitionDataErrorV2> {
    let end = cursor
        .checked_add(width)
        .ok_or(RootNoApplyRecoveryAcquisitionDataErrorV2)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(RootNoApplyRecoveryAcquisitionDataErrorV2)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_execution_availability::observation::HostExecutionAvailabilityObservationFieldsV2;
    use crate::host_execution_no_apply::closed_controller::ClosedCreateFailureIdentityDataV2;
    use crate::host_execution_no_apply::{
        BeforeArgumentNoApplySourceFieldsV2, ClosedBeforeArgumentNoApplyRecordFieldsV2,
    };
    use aos_sandbox_model::{ObjectDigest, OperationId};
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

    fn fields() -> RootNoApplyRecoveryAcquisitionFieldsV2 {
        let prepare = prepare();
        let marker = prepare.identity.marker;
        let accepted_source = marker.fields().source;
        let historical_availability = HostExecutionAvailabilityObservationV2::new(
            HostExecutionAvailabilityObservationFieldsV2 {
                phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
                proposal_digest: [17; 32],
                request: [18; 16],
                session: [12; 32],
                signed_request: [19; 32],
                runtime_handle: marker.fields().runtime_handle,
                execution_store: marker.fields().execution_store,
                execution_cut: [20; 32],
                host_state_cut: [21; 32],
                boot: accepted_source.fields().host_boot,
                epoch: 8,
                first_clock: 100,
                cutoff: 1000,
                observed_clock: 200,
                bound_source_digest: *accepted_source.digest().as_bytes(),
            },
        )
        .unwrap();
        RootNoApplyRecoveryAcquisitionFieldsV2 {
            generation: 1,
            key_commitment: [31; 32],
            authority_names: ProtectedJournalNamesV1::from_historical_fields(
                (2, 3),
                (2, 4),
                (2, 5),
            ),
            authority_next: 50,
            authority_end: 8192,
            policy_commitment: [32; 32],
            policy_expires_at: 10000,
            controller_cut: RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
                100,
                4096,
                std::iter::empty(),
            )
            .unwrap(),
            controller_nonce: [33; 32],
            host_node: accepted_source.fields().node,
            host_boot: [34; 16],
            host_session: [35; 32],
            first_clock: 2000,
            cutoff: 3000,
            historical_availability,
            accepted_source,
            marker,
            terminal_archive: *prepare.identity.terminal_archive.as_bytes(),
            signed_terminal: *prepare.identity.signed_terminal.as_bytes(),
            root_instance: None,
            phase: RootNoApplyRecoveryPhaseV2::BeforeFloor,
            history: None,
        }
    }

    #[test]
    fn before_floor_is_explicit_and_does_not_renew_expired_execution_history() {
        let original = fields();
        let bytes =
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).unwrap();
        let decoded = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(&bytes).unwrap();
        assert_eq!(bytes.len(), 1580);
        assert_eq!(decoded.fields_v2(), original);
        assert_eq!(decoded.fields_v2().root_instance, None);
        assert_eq!(decoded.fields_v2().history, None);
        assert!(original.historical_availability.fields().cutoff < original.first_clock);
        assert_ne!(
            original.accepted_source.fields().host_boot,
            original.host_boot
        );
        let mut with_other_operations = original;
        with_other_operations.root_instance = Some([36; 16]);
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(
                with_other_operations,
                [1; 64]
            )
            .is_ok()
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(&changed).is_err());
        }
    }

    #[test]
    fn floor_anchored_requires_exact_current_intended_prepare_without_claiming_c_durability() {
        let mut original = fields();
        original.phase = RootNoApplyRecoveryPhaseV2::FloorAnchored;
        original.root_instance = Some([36; 16]);
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_err()
        );
        let prepare = prepare();
        original.history = Some(RootNoApplyRecoveryHistoryDataV2 {
            prepare,
            current_floor: *prepare.root_floor.as_bytes(),
            current_revision: prepare.root_sequence,
        });
        let bytes =
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).unwrap();
        assert_eq!(
            RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(&bytes)
                .unwrap()
                .fields_v2(),
            original
        );
        original.history.as_mut().unwrap().current_revision += 1;
        original.history.as_mut().unwrap().current_floor = [37; 32];
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_err()
        );
        original.phase = RootNoApplyRecoveryPhaseV2::Prepared;
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_ok()
        );
    }

    #[test]
    fn prepared_and_settled_require_actual_reference_data_and_allow_current_ancestor() {
        let mut original = fields();
        let prepare = prepare();
        original.phase = RootNoApplyRecoveryPhaseV2::Prepared;
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_err()
        );
        original.root_instance = Some([36; 16]);
        original.history = Some(RootNoApplyRecoveryHistoryDataV2 {
            prepare,
            current_floor: *prepare.root_floor.as_bytes(),
            current_revision: prepare.root_sequence,
        });
        let bytes =
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).unwrap();
        assert_eq!(
            bytes.len(),
            MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2
        );
        assert_eq!(bytes.len(), 2432);
        assert_eq!(
            RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(&bytes)
                .unwrap()
                .fields_v2(),
            original
        );
        original.history.as_mut().unwrap().current_revision += 1;
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_err()
        );
        original.history.as_mut().unwrap().current_floor = [37; 32];
        original.phase = RootNoApplyRecoveryPhaseV2::Settled;
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_ok()
        );
        original
            .history
            .as_mut()
            .unwrap()
            .prepare
            .identity
            .signed_terminal = ObjectDigest::from_bytes([99; 32]);
        assert!(
            encode_root_no_apply_recovery_acquisition_signed_data_v2(original, [1; 64]).is_err()
        );
    }
}
