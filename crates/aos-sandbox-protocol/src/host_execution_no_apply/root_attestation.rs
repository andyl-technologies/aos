//! Encodes dedicated Root floor public pins and finite signed attestation DATA.
//!
//! The signature attests a completed Root78 floor and exact *intended* prepare
//! bytes. It does not attest Controller prepare durability. Actual Controller
//! and Root owners retain their native barriers through prepare, CAS and ACK;
//! Host verifies the dedicated public pin and its own held challenge and cuts.
//!
//! ```text
//! AOSRNP02 | generation:u64be | Ed25519-public:32 | domain-checksum:32
//! AOSRNA02 | version:u16be | reserved:2 | generation:u64be | pin:32 |
//! Root-authority-names:48 | next:8 | end:8 | Root43-read-nonce:32 |
//! floor-width:u16be | reserved:6 | literal-floor:1836-or-1900 |
//! literal-head:104 | intended-prepare:812 | Ed25519-signature:64 | checksum:32
//! ```

use sha2::{Digest as _, Sha256};

use super::closed_controller::{
    CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, ClosedCreateFailurePrepareDataV2,
};
use crate::domain_ledger::{
    execution_no_apply_floor::{
        MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2, ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2,
        RootExecutionNoApplyFloorHeadDataV2, RootExecutionNoApplyFloorRecordDataV2,
    },
    protected_names::ProtectedJournalNamesV1,
};

/// Exact width of the generation-bound dedicated public credential.
pub const ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2: usize = 8 + 8 + 32 + 32;
/// Dedicated signature domain, prepended to the literal unsigned packet bytes.
pub const ROOT_NO_APPLY_ATTESTATION_SIGNING_DOMAIN_V2: &[u8] =
    b"aos.sandbox.root.execution-no-apply-attestation.v2\0";
/// Largest literal attestation accepted by the finite Host receiver.
pub const MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2: usize = 156
    + MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2
    + ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2
    + CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2
    + 64
    + 32;

const PIN_DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-public-pin.v2\0";
const PIN_COMMITMENT_DOMAIN: &[u8] =
    b"aos.sandbox.root.execution-no-apply-public-pin-commitment.v2\0";
const PACKET_DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-attestation-packet.v2\0";

/// Reports malformed dedicated public pin or attestation comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Root NoApply public pin or attestation DATA is malformed or differently bound")]
pub struct RootNoApplyAttestationDataErrorV2;

/// Retains a structurally canonical public pin without credential currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNoApplyPublicPinDataV2 {
    generation: u64,
    public_key: [u8; 32],
}

impl RootNoApplyPublicPinDataV2 {
    /// Constructs public provisioning DATA; native consumers validate the point.
    ///
    /// # Errors
    /// Rejects the reserved zero generation.
    pub fn new(
        generation: u64,
        public_key: [u8; 32],
    ) -> Result<Self, RootNoApplyAttestationDataErrorV2> {
        if generation == 0 {
            return Err(RootNoApplyAttestationDataErrorV2);
        }
        Ok(Self {
            generation,
            public_key,
        })
    }

    /// Encodes the sole fixed public credential grammar.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2] {
        let mut bytes = [0; ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2];
        bytes[..8].copy_from_slice(b"AOSRNP02");
        bytes[8..16].copy_from_slice(&self.generation.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.public_key);
        let checksum = hash(PIN_DOMAIN, &bytes[..48]);
        bytes[48..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes exact public credential bytes, separately from native custody.
    ///
    /// # Errors
    /// Rejects another extent, magic, generation or checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RootNoApplyAttestationDataErrorV2> {
        if bytes.len() != ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2
            || bytes.get(..8) != Some(b"AOSRNP02")
            || hash(PIN_DOMAIN, &bytes[..48]) != field::<32>(bytes, 48)?
        {
            return Err(RootNoApplyAttestationDataErrorV2);
        }
        Self::new(u64::from_be_bytes(field(bytes, 8)?), field(bytes, 16)?)
    }

    /// Returns the dedicated credential generation.
    #[must_use]
    pub const fn generation_v2(self) -> u64 {
        self.generation
    }

    /// Returns the exact public point encoding for strict Ed25519 validation.
    #[must_use]
    pub const fn public_key_v2(self) -> [u8; 32] {
        self.public_key
    }

    /// Commits the complete generation-bound canonical public credential.
    #[must_use]
    pub fn key_commitment_v2(self) -> [u8; 32] {
        hash(PIN_COMMITMENT_DOMAIN, &self.encode_canonical())
    }
}

/// Names intended attestation DATA without supplying a floor or signing owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyAttestationFieldsV2 {
    /// Actual native dedicated signing-key generation.
    pub generation: u64,
    /// Commitment to the matching complete public credential.
    pub key_commitment: [u8; 32],
    /// Actual protected Root authority journal names.
    pub authority_names: ProtectedJournalNamesV1,
    /// Actual native Root next position after the completed atomic78 append.
    pub authority_next: u64,
    /// Actual native Root file end at that same completed cut.
    pub authority_end: u64,
    /// Fresh paid Root opening nonce carried in the independently verified43.
    pub root_read_nonce: [u8; 32],
    /// Literal independently completed floor, including actual Host challenge.
    pub floor: RootExecutionNoApplyFloorRecordDataV2,
    /// Literal head read back from the same atomic transaction.
    pub head: RootExecutionNoApplyFloorHeadDataV2,
    /// Exact intended prepare; this field does not claim C already appended it.
    pub prepare: ClosedCreateFailurePrepareDataV2,
}

/// Borrows an exact signed packet without granting native floor currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyAttestationDataV2<'packet> {
    bytes: &'packet [u8],
    unsigned_len: usize,
    fields: RootExecutionNoApplyAttestationFieldsV2,
}

impl<'packet> RootExecutionNoApplyAttestationDataV2<'packet> {
    /// Decodes canonical literal bindings independently of signature authority.
    ///
    /// # Errors
    /// Rejects malformed extents/checksums or disagreement between the completed
    /// floor/head and exact intended prepare. Callers must verify the signature
    /// with an actually held native pin and retain both native writer barriers.
    pub fn decode_canonical(
        bytes: &'packet [u8],
    ) -> Result<Self, RootNoApplyAttestationDataErrorV2> {
        if bytes.len() > MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2
            || bytes.len() < 156 + 96
            || bytes.get(..8) != Some(b"AOSRNA02")
            || bytes[8..10] != 2_u16.to_be_bytes()
            || bytes[10..12] != [0; 2]
            || bytes[150..156] != [0; 6]
            || hash(PACKET_DOMAIN, &bytes[..bytes.len() - 32])
                != field::<32>(bytes, bytes.len() - 32)?
        {
            return Err(RootNoApplyAttestationDataErrorV2);
        }
        let floor_len = usize::from(u16::from_be_bytes(field(bytes, 148)?));
        let unsigned_len = 156_usize
            .checked_add(floor_len)
            .and_then(|n| n.checked_add(ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2))
            .and_then(|n| n.checked_add(CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2))
            .ok_or(RootNoApplyAttestationDataErrorV2)?;
        if unsigned_len.checked_add(96) != Some(bytes.len()) {
            return Err(RootNoApplyAttestationDataErrorV2);
        }
        let floor_bytes = bytes
            .get(156..156 + floor_len)
            .ok_or(RootNoApplyAttestationDataErrorV2)?;
        let operation = field::<16>(floor_bytes, 28)?;
        let revision = field::<8>(floor_bytes, 44)?;
        let mut key = [0; 24];
        key[..16].copy_from_slice(&operation);
        key[16..].copy_from_slice(&revision);
        let floor = RootExecutionNoApplyFloorRecordDataV2::decode_canonical(&key, floor_bytes)
            .map_err(|_| RootNoApplyAttestationDataErrorV2)?;
        let head_start = 156 + floor_len;
        let prepare_start = head_start + ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2;
        let head = RootExecutionNoApplyFloorHeadDataV2::decode_canonical(
            &operation,
            &bytes[head_start..prepare_start],
        )
        .map_err(|_| RootNoApplyAttestationDataErrorV2)?;
        let prepare = ClosedCreateFailurePrepareDataV2::decode_canonical(
            &operation,
            &bytes[prepare_start..unsigned_len],
        )
        .map_err(|_| RootNoApplyAttestationDataErrorV2)?;
        let fields = RootExecutionNoApplyAttestationFieldsV2 {
            generation: u64::from_be_bytes(field(bytes, 12)?),
            key_commitment: field(bytes, 20)?,
            authority_names: ProtectedJournalNamesV1::from_bytes(&bytes[52..100])
                .map_err(|_| RootNoApplyAttestationDataErrorV2)?,
            authority_next: u64::from_be_bytes(field(bytes, 100)?),
            authority_end: u64::from_be_bytes(field(bytes, 108)?),
            root_read_nonce: field(bytes, 116)?,
            floor,
            head,
            prepare,
        };
        require_fields(fields)?;
        if field::<64>(bytes, unsigned_len)? == [0; 64] {
            return Err(RootNoApplyAttestationDataErrorV2);
        }
        Ok(Self {
            bytes,
            unsigned_len,
            fields,
        })
    }

    /// Returns the literal complete packet for the authenticated42 body.
    #[must_use]
    pub const fn canonical_bytes_v2(self) -> &'packet [u8] {
        self.bytes
    }
    /// Returns the literal unsigned bytes following the dedicated signature domain.
    #[must_use]
    pub fn unsigned_bytes_v2(self) -> &'packet [u8] {
        &self.bytes[..self.unsigned_len]
    }
    /// Returns the exact signature bytes without treating them as verified.
    #[must_use]
    pub fn signature_bytes_v2(self) -> [u8; 64] {
        let mut signature = [0; 64];
        signature.copy_from_slice(&self.bytes[self.unsigned_len..self.unsigned_len + 64]);
        signature
    }
    /// Returns the exact dedicated signing-key generation.
    #[must_use]
    pub const fn generation_v2(self) -> u64 {
        self.fields.generation
    }
    /// Returns the exact generation-bound public-pin commitment.
    #[must_use]
    pub const fn key_commitment_v2(self) -> [u8; 32] {
        self.fields.key_commitment
    }
    /// Returns the completed floor as nonauthorizing comparison DATA.
    #[must_use]
    pub const fn floor_data_v2(self) -> RootExecutionNoApplyFloorRecordDataV2 {
        self.fields.floor
    }
    /// Returns the exact read-back Root floor head DATA.
    #[must_use]
    pub const fn head_data_v2(self) -> RootExecutionNoApplyFloorHeadDataV2 {
        self.fields.head
    }
    /// Returns the exact intended prepare DATA, without claiming C durability.
    #[must_use]
    pub const fn prepare_data_v2(self) -> ClosedCreateFailurePrepareDataV2 {
        self.fields.prepare
    }
    /// Returns Root's independent fresh43 opening nonce.
    #[must_use]
    pub const fn root_read_nonce_v2(self) -> [u8; 32] {
        self.fields.root_read_nonce
    }
    /// Returns the actual captured Root authority journal names as DATA.
    #[must_use]
    pub const fn authority_names_v2(self) -> ProtectedJournalNamesV1 {
        self.fields.authority_names
    }
    /// Returns the completed Root authority next position as DATA.
    #[must_use]
    pub const fn authority_next_v2(self) -> u64 {
        self.fields.authority_next
    }
    /// Returns the completed Root authority native file end as DATA.
    #[must_use]
    pub const fn authority_end_v2(self) -> u64 {
        self.fields.authority_end
    }
}

/// Encodes intended unsigned DATA for a privately held genuine signing owner.
///
/// # Errors
/// Rejects mismatched floor/head/intended-prepare or invalid native coordinates.
pub fn encode_root_no_apply_attestation_unsigned_data_v2(
    fields: RootExecutionNoApplyAttestationFieldsV2,
) -> Result<Vec<u8>, RootNoApplyAttestationDataErrorV2> {
    require_fields(fields)?;
    let floor = fields.floor.encode_canonical();
    let width = u16::try_from(floor.len()).map_err(|_| RootNoApplyAttestationDataErrorV2)?;
    let mut bytes = Vec::with_capacity(MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2 - 96);
    bytes.extend_from_slice(b"AOSRNA02");
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&fields.generation.to_be_bytes());
    bytes.extend_from_slice(&fields.key_commitment);
    bytes.extend_from_slice(&fields.authority_names.to_bytes());
    bytes.extend_from_slice(&fields.authority_next.to_be_bytes());
    bytes.extend_from_slice(&fields.authority_end.to_be_bytes());
    bytes.extend_from_slice(&fields.root_read_nonce);
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&floor);
    bytes.extend_from_slice(&fields.head.encode_canonical());
    bytes.extend_from_slice(&fields.prepare.encode_canonical());
    Ok(bytes)
}

/// Frames a supplied signature as DATA, separately from native issuance.
///
/// # Errors
/// Rejects invalid unsigned associations or the reserved all-zero signature.
pub fn encode_root_no_apply_attestation_signed_data_v2(
    fields: RootExecutionNoApplyAttestationFieldsV2,
    signature: [u8; 64],
) -> Result<Vec<u8>, RootNoApplyAttestationDataErrorV2> {
    let mut bytes = encode_root_no_apply_attestation_unsigned_data_v2(fields)?;
    bytes.extend_from_slice(&signature);
    let checksum = hash(PACKET_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum);
    RootExecutionNoApplyAttestationDataV2::decode_canonical(&bytes)?;
    Ok(bytes)
}

fn require_fields(
    fields: RootExecutionNoApplyAttestationFieldsV2,
) -> Result<(), RootNoApplyAttestationDataErrorV2> {
    ProtectedJournalNamesV1::from_bytes(&fields.authority_names.to_bytes())
        .map_err(|_| RootNoApplyAttestationDataErrorV2)?;
    let floor = fields.floor.fields();
    let lease = floor.host_lease.fields();
    let prepare = fields.prepare;
    // First initialization adds [instance,floor,head]; subsequent appends add
    // [floor,head]. Only the actual append owner proves which occurred.
    let next_delta = fields.authority_next.checked_sub(floor.authority_next);
    let super::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) = lease.marker else {
        return Err(RootNoApplyAttestationDataErrorV2);
    };
    if fields.generation == 0
        || fields.key_commitment == [0; 32]
        || fields.root_read_nonce == [0; 32]
        || fields.authority_end == 0
        || !matches!(next_delta, Some(4 | 5))
        || !fields.head.matches_floor_data_v2(fields.floor)
        || prepare.operation.as_bytes() != &floor.operation
        || prepare.root_floor.as_bytes() != &fields.floor.digest()
        || prepare.root_sequence != floor.revision
        || prepare.identity.marker != marker
        || prepare.identity.terminal_archive.as_bytes() != &lease.terminal_archive_head
        || prepare.identity.signed_terminal.as_bytes() != &lease.signed_terminal_outcome
        || prepare.wall_seconds != floor.terminal_wall_seconds
        || prepare.predecessor.map(|v| *v.as_bytes()) != floor.predecessor_rows
        || prepare.successor.map(|v| *v.as_bytes()) != floor.successor_rows
    {
        return Err(RootNoApplyAttestationDataErrorV2);
    }
    ClosedCreateFailurePrepareDataV2::decode_canonical(
        prepare.operation.as_bytes(),
        &prepare.encode_canonical(),
    )
    .map_err(|_| RootNoApplyAttestationDataErrorV2)?;
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
) -> Result<[u8; N], RootNoApplyAttestationDataErrorV2> {
    let end = offset
        .checked_add(N)
        .ok_or(RootNoApplyAttestationDataErrorV2)?;
    bytes
        .get(offset..end)
        .ok_or(RootNoApplyAttestationDataErrorV2)?
        .try_into()
        .map_err(|_| RootNoApplyAttestationDataErrorV2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::execution_no_apply_floor::{
        RootExecutionNoApplyControllerCutDataV2, RootExecutionNoApplyFloorFieldsV2,
    };
    use crate::execution_availability::ExecutionAvailabilityPhaseV2;
    use crate::host_execution_availability::observation::{
        HostExecutionAvailabilityObservationFieldsV2, HostExecutionAvailabilityObservationV2,
    };
    use crate::host_execution_no_apply::closed_controller::ClosedCreateFailureIdentityDataV2;
    use crate::host_execution_no_apply::current_lease::{
        CurrentHostNoApplyLeaseDataV2, CurrentHostNoApplyLeaseFieldsV2, HostNoApplyLeaseScopeV2,
    };
    use crate::host_execution_no_apply::{
        BeforeArgumentNoApplySourceDataV2, BeforeArgumentNoApplySourceFieldsV2,
        ClosedBeforeArgumentNoApplyRecordFieldsV2, ClosedBeforeArgumentNoApplyRecordV2,
        HostExecutionNoApplyRecordV2,
    };
    use aos_sandbox_core::{ObjectDigest, OperationId};

    fn floor_fields() -> RootExecutionNoApplyFloorFieldsV2 {
        // Canonical historical DATA only. These fixtures create no native
        // Host lease, Root original, physical writer or settlement permission.
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
        let availability = HostExecutionAvailabilityObservationV2::new(
            HostExecutionAvailabilityObservationFieldsV2 {
                phase: ExecutionAvailabilityPhaseV2::AcceptedBind,
                proposal_digest: [17; 32],
                request: [18; 16],
                session: [12; 32],
                signed_request: [19; 32],
                runtime_handle: [14; 32],
                execution_store: [15; 32],
                execution_cut: [20; 32],
                host_state_cut: [21; 32],
                boot: [6; 16],
                epoch: 8,
                first_clock: 100,
                cutoff: 1000,
                observed_clock: 200,
                bound_source_digest: *source.digest().as_bytes(),
            },
        )
        .unwrap();
        let host_lease = CurrentHostNoApplyLeaseDataV2::new(CurrentHostNoApplyLeaseFieldsV2 {
            scope: HostNoApplyLeaseScopeV2::Active,
            native_first_clock: 100,
            native_cutoff: 1000,
            native_boot: [6; 16],
            availability,
            accepted_source: source,
            marker: HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker),
            signed_terminal_outcome: [22; 32],
            terminal_archive_head: [23; 32],
            protected_host_state_cut: [24; 32],
            protected_execution_cut: [25; 32],
            lease_head: [26; 32],
            challenge: [27; 32],
            current_session: [28; 32],
            signed_current_request: [29; 32],
            lease_epoch: 10,
            observed_clock: 300,
            current_request: [30; 16],
        })
        .unwrap();
        RootExecutionNoApplyFloorFieldsV2 {
            root_instance: [31; 16],
            operation: [1; 16],
            revision: 1,
            authority_next: 32,
            predecessor_floor: [0; 32],
            policy_commitment: [33; 32],
            controller_cut: RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
                20,
                1024,
                [(
                    aos_sandbox_core::RecordNamespace::Operation,
                    b"operation".as_slice(),
                    b"requested".as_slice(),
                )],
            )
            .unwrap(),
            host_lease,
            signed_current_outcome: [34; 32],
            predecessor_rows: [[35; 32], [36; 32], [37; 32]],
            successor_rows: [[38; 32], [39; 32], [40; 32]],
            terminal_wall_seconds: 41,
        }
    }

    fn attestation_fields() -> RootExecutionNoApplyAttestationFieldsV2 {
        let floor = RootExecutionNoApplyFloorRecordDataV2::new(floor_fields()).unwrap();
        let f = floor.fields();
        let HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) =
            f.host_lease.fields().marker
        else {
            panic!("closed test marker")
        };
        let prepare = ClosedCreateFailurePrepareDataV2 {
            operation: OperationId::from_bytes(f.operation),
            identity: ClosedCreateFailureIdentityDataV2 {
                marker,
                terminal_archive: ObjectDigest::from_bytes(
                    f.host_lease.fields().terminal_archive_head,
                ),
                signed_terminal: ObjectDigest::from_bytes(
                    f.host_lease.fields().signed_terminal_outcome,
                ),
            },
            root_floor: ObjectDigest::from_bytes(floor.digest()),
            root_sequence: f.revision,
            wall_seconds: f.terminal_wall_seconds,
            predecessor: f.predecessor_rows.map(ObjectDigest::from_bytes),
            successor: f.successor_rows.map(ObjectDigest::from_bytes),
        };
        RootExecutionNoApplyAttestationFieldsV2 {
            generation: 1,
            key_commitment: RootNoApplyPublicPinDataV2::new(1, [7; 32])
                .unwrap()
                .key_commitment_v2(),
            authority_names: ProtectedJournalNamesV1::from_historical_fields(
                (2, 3),
                (2, 4),
                (2, 5),
            ),
            authority_next: f.authority_next + 5,
            authority_end: 4096,
            root_read_nonce: [42; 32],
            floor,
            head: RootExecutionNoApplyFloorHeadDataV2::from_floor_data_v2(floor),
            prepare,
        }
    }

    #[test]
    fn attestation_binds_literal_completed_floor_and_exact_intended_prepare() {
        let fields = attestation_fields();
        // A structural signature fixture deliberately creates no verified key,
        // native floor loan or native Controller prepared owner.
        let bytes = encode_root_no_apply_attestation_signed_data_v2(fields, [1; 64]).unwrap();
        let packet = RootExecutionNoApplyAttestationDataV2::decode_canonical(&bytes).unwrap();
        assert_eq!(bytes.len(), MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2);
        assert_eq!(packet.prepare_data_v2(), fields.prepare);
        assert_eq!(packet.floor_data_v2(), fields.floor);
        assert_eq!(
            packet.unsigned_bytes_v2(),
            encode_root_no_apply_attestation_unsigned_data_v2(fields).unwrap()
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(RootExecutionNoApplyAttestationDataV2::decode_canonical(&changed).is_err());
        }
        let mut changed = fields;
        changed.prepare.root_floor = ObjectDigest::from_bytes([9; 32]);
        assert!(encode_root_no_apply_attestation_unsigned_data_v2(changed).is_err());
        changed = fields;
        changed.prepare.successor[1] = ObjectDigest::from_bytes([9; 32]);
        assert!(encode_root_no_apply_attestation_unsigned_data_v2(changed).is_err());
        changed = fields;
        changed.authority_next += 1;
        assert!(encode_root_no_apply_attestation_unsigned_data_v2(changed).is_err());
    }

    #[test]
    fn public_pin_checks_every_literal_byte_and_generation() {
        let pin = RootNoApplyPublicPinDataV2::new(7, [9; 32]).unwrap();
        let bytes = pin.encode_canonical();
        assert_eq!(bytes.len(), 80);
        assert_eq!(
            RootNoApplyPublicPinDataV2::decode_canonical(&bytes),
            Ok(pin)
        );
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(RootNoApplyPublicPinDataV2::decode_canonical(&changed).is_err());
        }
        assert!(RootNoApplyPublicPinDataV2::new(0, [9; 32]).is_err());
        assert_ne!(
            pin.key_commitment_v2(),
            RootNoApplyPublicPinDataV2::new(8, [9; 32])
                .unwrap()
                .key_commitment_v2()
        );
        assert!(RootNoApplyPublicPinDataV2::decode_canonical(&bytes[..79]).is_err());
    }
}
