//! Encodes independent protected-local Root execution NoApply floor DATA.
//!
//! A genuine paid Root purpose anchors its independently checked current Host
//! lease and exact six Controller row digests here. The floor detects one-owner
//! rollback or split state under protected Root/kernel/PID1 trust; it claims no
//! whole-host disk rollback resistance. Decoding cannot produce a current floor.
//!
//! ```text
//! namespace78 revision key = operation:16 | revision:u64be
//! AOSRNF02 | version:u16be | reserved:2 | Root-instance:16 | operation:16 |
//! revision:u64be | Root-authority-next:u64be | predecessor-floor:32 |
//! policy:32 | final-global-Controller-cut:96 |
//! lease-bytes:u16be | reserved:6 | AOSHLV02:1344-or-1408 |
//! signed-current-outcome:32 | Controller-predecessors:96 |
//! Controller-successors:96 | terminal-wall:i64be | checksum:32
//!
//! namespace78 head key = operation:16
//! AOSRNH02 | operation:16 | revision:u64be | floor:32 |
//! Root-authority-next:u64be | checksum:32
//! ```

use crate::host_execution_no_apply::current_lease::{
    CurrentHostNoApplyLeaseDataV2, MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
};
use sha2::{Digest as _, Sha256};

mod controller_cut;
mod instance;

pub use controller_cut::{
    ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2, RootExecutionNoApplyControllerCutDataV2,
};
pub use instance::{
    ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2, ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2,
    RootExecutionNoApplyInstanceDataV2,
};

const FLOOR_MAGIC: &[u8; 8] = b"AOSRNF02";
const HEAD_MAGIC: &[u8; 8] = b"AOSRNH02";
const FLOOR_DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-floor.v2\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-head.v2\0";
const FIXED_FLOOR_BYTES: usize = 396 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2;
/// Largest canonical floor record, including the literal current Host lease.
pub const MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2: usize =
    FIXED_FLOOR_BYTES + MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2;
/// Exact canonical width of the current per-operation Root floor head.
pub const ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2: usize = 104;

/// Reports malformed independent Root floor comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Root execution NoApply floor DATA is malformed or differently bound")]
pub struct RootExecutionNoApplyFloorDataErrorV2;

/// Names one immutable per-operation floor revision without creating authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyFloorKeyDataV2 {
    operation: [u8; 16],
    revision: u64,
}

impl RootExecutionNoApplyFloorKeyDataV2 {
    /// Constructs a nonzero historical operation/revision key.
    ///
    /// # Errors
    /// Rejects a zero operation or revision.
    pub fn new(
        operation: [u8; 16],
        revision: u64,
    ) -> Result<Self, RootExecutionNoApplyFloorDataErrorV2> {
        if operation == [0; 16] || revision == 0 {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        Ok(Self {
            operation,
            revision,
        })
    }

    /// Encodes the exact revision key independently of the current-head key.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..16].copy_from_slice(&self.operation);
        bytes[16..].copy_from_slice(&self.revision.to_be_bytes());
        bytes
    }

    /// Decodes only one exact nonzero revision key.
    ///
    /// # Errors
    /// Rejects another width or reserved operation/revision.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RootExecutionNoApplyFloorDataErrorV2> {
        if bytes.len() != 24 {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        Self::new(field(bytes, 0)?, u64::from_be_bytes(field(bytes, 16)?))
    }

    /// Returns the historical operation as comparison DATA.
    #[must_use]
    pub const fn operation(self) -> [u8; 16] {
        self.operation
    }

    /// Returns the historical per-operation revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Derives the nonzero operation head key from this validated revision key.
    #[must_use]
    pub const fn head_key_data_v2(self) -> [u8; 16] {
        self.operation
    }
}

/// Carries the independently checked inputs saved by an actual Root issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyFloorFieldsV2 {
    /// Genuine protected Root instance, read by the native issuer.
    pub root_instance: [u8; 16],
    /// Exact accepted Create operation bound by the Host lease.
    pub operation: [u8; 16],
    /// Per-operation immutable floor revision, starting at one.
    pub revision: u64,
    /// Actual Root authority native next position before this append.
    pub authority_next: u64,
    /// Zero only for the first revision; otherwise the exact prior floor digest.
    pub predecessor_floor: [u8; 32],
    /// Current signed Root policy commitment, independently checked by the issuer.
    pub policy_commitment: [u8; 32],
    /// Final independently captured global Controller cut, beyond the six rows.
    pub controller_cut: RootExecutionNoApplyControllerCutDataV2,
    /// Actual active or recovery-cleanup lease verified through signed43.
    pub host_lease: CurrentHostNoApplyLeaseDataV2,
    /// Commitment of that actual independently authenticated current outcome.
    pub signed_current_outcome: [u8; 32],
    /// Exact Effect, Operation and Execution projection predecessor record digests.
    pub predecessor_rows: [[u8; 32]; 3],
    /// Exact Effect, Operation and Execution projection successor record digests.
    pub successor_rows: [[u8; 32]; 3],
    /// Immutable wall second used to plan the canonical failed successor.
    pub terminal_wall_seconds: i64,
}

/// Retains canonical historical Root floor DATA, without a native floor loan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyFloorRecordDataV2 {
    fields: RootExecutionNoApplyFloorFieldsV2,
}

impl RootExecutionNoApplyFloorRecordDataV2 {
    /// Constructs comparison DATA after structural cross-link validation.
    ///
    /// # Errors
    /// Rejects reserved identities, a mismatched accepted Create, missing row
    /// commitments or a first-revision/predecessor disagreement.
    pub fn new(
        fields: RootExecutionNoApplyFloorFieldsV2,
    ) -> Result<Self, RootExecutionNoApplyFloorDataErrorV2> {
        RootExecutionNoApplyFloorKeyDataV2::new(fields.operation, fields.revision)?;
        if fields.root_instance == [0; 16]
            || fields.authority_next == 0
            || fields.operation
                != fields
                    .host_lease
                    .fields()
                    .accepted_source
                    .fields()
                    .create_operation
            || fields.policy_commitment == [0; 32]
            || fields.signed_current_outcome == [0; 32]
            || (fields.revision == 1) != (fields.predecessor_floor == [0; 32])
            || fields
                .predecessor_rows
                .into_iter()
                .chain(fields.successor_rows)
                .any(|digest| digest == [0; 32])
        {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        Ok(Self { fields })
    }

    /// Returns historical coordinates for independently native comparisons.
    #[must_use]
    pub const fn fields(self) -> RootExecutionNoApplyFloorFieldsV2 {
        self.fields
    }

    /// Returns the exact immutable revision key.
    #[must_use]
    pub fn key(self) -> RootExecutionNoApplyFloorKeyDataV2 {
        RootExecutionNoApplyFloorKeyDataV2 {
            operation: self.fields.operation,
            revision: self.fields.revision,
        }
    }

    /// Encodes the sole canonical floor grammar with its literal Host lease.
    #[must_use]
    pub fn encode_canonical(self) -> Vec<u8> {
        let lease = self.fields.host_lease.encode_canonical();
        let mut bytes = Vec::with_capacity(FIXED_FLOOR_BYTES + lease.len());
        bytes.extend_from_slice(FLOOR_MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.fields.root_instance);
        bytes.extend_from_slice(&self.fields.operation);
        bytes.extend_from_slice(&self.fields.revision.to_be_bytes());
        bytes.extend_from_slice(&self.fields.authority_next.to_be_bytes());
        bytes.extend_from_slice(&self.fields.predecessor_floor);
        bytes.extend_from_slice(&self.fields.policy_commitment);
        bytes.extend_from_slice(&self.fields.controller_cut.encode_canonical());
        // The exact lower grammar has only these two fixed widths. This
        // conversion does not truncate a variable caller-controlled length.
        let width = if lease.len() == MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2 {
            MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2 as u16
        } else {
            (MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2 - 64) as u16
        };
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&lease);
        bytes.extend_from_slice(&self.fields.signed_current_outcome);
        for digest in self
            .fields
            .predecessor_rows
            .into_iter()
            .chain(self.fields.successor_rows)
        {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.fields.terminal_wall_seconds.to_be_bytes());
        let checksum = hash(FLOOR_DOMAIN, &bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Decodes one exact canonical revision and its independent literal lease.
    ///
    /// # Errors
    /// Rejects a wrong key/version/extent/checksum, reserved bytes or identities,
    /// malformed lease or any changed canonical cross-link.
    pub fn decode_canonical(
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Self, RootExecutionNoApplyFloorDataErrorV2> {
        if bytes.len() > MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2
            || bytes.len() < FIXED_FLOOR_BYTES
            || bytes.get(..8) != Some(FLOOR_MAGIC.as_slice())
            || field::<2>(bytes, 8)? != 2_u16.to_be_bytes()
            || field::<2>(bytes, 10)? != [0; 2]
            || field::<6>(bytes, 126 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2)? != [0; 6]
        {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        let width = usize::from(u16::from_be_bytes(field(
            bytes,
            124 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2,
        )?));
        if ![
            MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
            MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2 - 64,
        ]
        .contains(&width)
            || bytes.len() != FIXED_FLOOR_BYTES + width
            || hash(FLOOR_DOMAIN, &bytes[..bytes.len() - 32])
                != field::<32>(bytes, bytes.len() - 32)?
        {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        let lease_start = 132 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2;
        let host_lease = CurrentHostNoApplyLeaseDataV2::decode_canonical(
            &bytes[lease_start..lease_start + width],
        )
        .map_err(|_| RootExecutionNoApplyFloorDataErrorV2)?;
        let start = lease_start + width;
        let data = Self::new(RootExecutionNoApplyFloorFieldsV2 {
            root_instance: field(bytes, 12)?,
            operation: field(bytes, 28)?,
            revision: u64::from_be_bytes(field(bytes, 44)?),
            authority_next: u64::from_be_bytes(field(bytes, 52)?),
            predecessor_floor: field(bytes, 60)?,
            policy_commitment: field(bytes, 92)?,
            controller_cut: RootExecutionNoApplyControllerCutDataV2::decode_canonical(
                &bytes[124..124 + ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2],
            )?,
            host_lease,
            signed_current_outcome: field(bytes, start)?,
            predecessor_rows: [
                field(bytes, start + 32)?,
                field(bytes, start + 64)?,
                field(bytes, start + 96)?,
            ],
            successor_rows: [
                field(bytes, start + 128)?,
                field(bytes, start + 160)?,
                field(bytes, start + 192)?,
            ],
            terminal_wall_seconds: i64::from_be_bytes(field(bytes, start + 224)?),
        })?;
        if data.key().encode_canonical() != key || data.encode_canonical() != bytes {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        Ok(data)
    }

    /// Returns the domain-separated immutable floor commitment as DATA.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        hash(FLOOR_DOMAIN, &self.encode_canonical())
    }
}

/// Retains the exact historical current-head coordinates, without currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyFloorHeadDataV2 {
    operation: [u8; 16],
    revision: u64,
    floor: [u8; 32],
    authority_next: u64,
}

impl RootExecutionNoApplyFloorHeadDataV2 {
    /// Derives historical head DATA from one complete canonical floor record.
    #[must_use]
    pub fn from_floor_data_v2(floor: RootExecutionNoApplyFloorRecordDataV2) -> Self {
        let fields = floor.fields();
        Self {
            operation: fields.operation,
            revision: fields.revision,
            floor: floor.digest(),
            authority_next: fields.authority_next,
        }
    }

    /// Encodes the exact per-operation head grammar.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2] {
        let mut bytes = [0; ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2];
        bytes[..8].copy_from_slice(HEAD_MAGIC);
        bytes[8..24].copy_from_slice(&self.operation);
        bytes[24..32].copy_from_slice(&self.revision.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.floor);
        bytes[64..72].copy_from_slice(&self.authority_next.to_be_bytes());
        let checksum = hash(HEAD_DOMAIN, &bytes[..72]);
        bytes[72..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes a historical head under its exact operation key.
    ///
    /// # Errors
    /// Rejects another key/width/version, reserved coordinates or checksum.
    pub fn decode_canonical(
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Self, RootExecutionNoApplyFloorDataErrorV2> {
        if bytes.len() != ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2
            || bytes.get(..8) != Some(HEAD_MAGIC.as_slice())
            || hash(HEAD_DOMAIN, &bytes[..72]) != field::<32>(bytes, 72)?
        {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        let head = Self {
            operation: field(bytes, 8)?,
            revision: u64::from_be_bytes(field(bytes, 24)?),
            floor: field(bytes, 32)?,
            authority_next: u64::from_be_bytes(field(bytes, 64)?),
        };
        RootExecutionNoApplyFloorKeyDataV2::new(head.operation, head.revision)?;
        if head.operation != key || head.floor == [0; 32] || head.authority_next == 0 {
            return Err(RootExecutionNoApplyFloorDataErrorV2);
        }
        Ok(head)
    }

    /// Compares exact historical record/head association, without native proof.
    #[must_use]
    pub fn matches_floor_data_v2(self, floor: RootExecutionNoApplyFloorRecordDataV2) -> bool {
        self == Self::from_floor_data_v2(floor)
    }

    /// Returns the selected immutable revision key as comparison DATA.
    #[must_use]
    pub const fn revision_key_data_v2(self) -> RootExecutionNoApplyFloorKeyDataV2 {
        RootExecutionNoApplyFloorKeyDataV2 {
            operation: self.operation,
            revision: self.revision,
        }
    }

    /// Returns the head key through the same validated nonzero revision key.
    #[must_use]
    pub const fn key_data_v2(self) -> [u8; 16] {
        self.revision_key_data_v2().head_key_data_v2()
    }
}

fn field<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], RootExecutionNoApplyFloorDataErrorV2> {
    bytes
        .get(
            start
                ..start
                    .checked_add(N)
                    .ok_or(RootExecutionNoApplyFloorDataErrorV2)?,
        )
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RootExecutionNoApplyFloorDataErrorV2)
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_availability::ExecutionAvailabilityPhaseV2;
    use crate::host_execution_availability::observation::{
        HostExecutionAvailabilityObservationFieldsV2, HostExecutionAvailabilityObservationV2,
    };
    use crate::host_execution_no_apply::current_lease::{
        CurrentHostNoApplyLeaseFieldsV2, HostNoApplyLeaseScopeV2,
    };
    use crate::host_execution_no_apply::{
        BeforeArgumentNoApplySourceDataV2, BeforeArgumentNoApplySourceFieldsV2,
        ClosedBeforeArgumentNoApplyRecordFieldsV2, ClosedBeforeArgumentNoApplyRecordV2,
        HostExecutionNoApplyRecordV2,
    };

    pub(super) fn floor_fields() -> RootExecutionNoApplyFloorFieldsV2 {
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
                super::super::protected_names::ProtectedJournalNamesV1::from_historical_fields(
                    (1, 2),
                    (1, 3),
                    (1, 4),
                ),
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

    #[test]
    fn floor_and_head_require_exact_canonical_bytes_and_key() {
        let floor = RootExecutionNoApplyFloorRecordDataV2::new(floor_fields()).unwrap();
        let key = floor.key().encode_canonical();
        let bytes = floor.encode_canonical();
        assert_eq!(bytes.len(), MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2);
        assert_eq!(
            RootExecutionNoApplyFloorRecordDataV2::decode_canonical(&key, &bytes).unwrap(),
            floor
        );

        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                RootExecutionNoApplyFloorRecordDataV2::decode_canonical(&key, &changed).is_err(),
                "byte {index}"
            );
        }
        let foreign = RootExecutionNoApplyFloorKeyDataV2::new([42; 16], 1)
            .unwrap()
            .encode_canonical();
        assert!(RootExecutionNoApplyFloorRecordDataV2::decode_canonical(&foreign, &bytes).is_err());
        assert!(
            RootExecutionNoApplyFloorRecordDataV2::decode_canonical(
                &key,
                &bytes[..bytes.len() - 1]
            )
            .is_err()
        );

        let head = RootExecutionNoApplyFloorHeadDataV2::from_floor_data_v2(floor);
        let encoded = head.encode_canonical();
        assert_eq!(
            RootExecutionNoApplyFloorHeadDataV2::decode_canonical(&[1; 16], &encoded).unwrap(),
            head
        );
        assert!(head.matches_floor_data_v2(floor));
        for index in 0..encoded.len() {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert!(
                RootExecutionNoApplyFloorHeadDataV2::decode_canonical(&[1; 16], &changed).is_err(),
                "head byte {index}"
            );
        }
    }

    #[test]
    fn cleanup_renewal_reanchors_currentness_without_changing_six_row_plan() {
        let old = RootExecutionNoApplyFloorRecordDataV2::new(floor_fields()).unwrap();
        let mut fields = old.fields();
        let mut lease = fields.host_lease.fields();
        lease.scope = HostNoApplyLeaseScopeV2::RecoveryCleanup;
        lease.native_first_clock = 2000;
        lease.native_cutoff = 3000;
        lease.native_boot = [43; 16];
        lease.observed_clock = 2100;
        lease.current_request = [44; 16];
        lease.signed_current_request = [45; 32];
        fields.host_lease = CurrentHostNoApplyLeaseDataV2::new(lease).unwrap();
        fields.revision = 2;
        fields.authority_next += 1;
        fields.predecessor_floor = old.digest();
        fields.signed_current_outcome = [46; 32];
        let fresh = RootExecutionNoApplyFloorRecordDataV2::new(fields).unwrap();

        assert_ne!(fresh.digest(), old.digest());
        assert_eq!(
            fresh.fields().predecessor_rows,
            old.fields().predecessor_rows
        );
        assert_eq!(fresh.fields().successor_rows, old.fields().successor_rows);
        assert_eq!(
            fresh.fields().host_lease.fields().marker,
            old.fields().host_lease.fields().marker
        );
        assert!(
            !RootExecutionNoApplyFloorHeadDataV2::from_floor_data_v2(old)
                .matches_floor_data_v2(fresh)
        );
        fields.predecessor_floor = [0; 32];
        assert!(RootExecutionNoApplyFloorRecordDataV2::new(fields).is_err());
    }
}
