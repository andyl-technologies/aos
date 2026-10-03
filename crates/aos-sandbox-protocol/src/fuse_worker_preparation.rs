//! Closed preparation wire for the original Mount-owned worker session.
//!
//! These fixed-size comparison records carry no metadata, file bytes, Root
//! receipt or backing grant. The Mount producer must derive the plan from its
//! authentic held owners; decoding a plan or HELLO never proves that custody.
//!
//! ```text
//! AOSFWP01 | worker | boot | challenge | seven original-scope commitments |
//! ownership-lease identity | original expiry | preparation deadline
//! AOSFWH01 | worker | boot | original challenge | exact sealed-plan digest
//! ```

use sha2::{Digest as _, Sha256};

mod rendezvous;
pub use rendezvous::{WORKER_RENDEZVOUS_BYTES_V2, WorkerRendezvousChallengeV2};

mod kernel_init;
pub use kernel_init::{WORKER_KERNEL_PREPARATION_BYTES_V3, WorkerKernelPreparationPhaseV3};

/// Exact canonical byte count for the closed preparation plan.
pub const WORKER_PREPARATION_PLAN_BYTES_V1: usize = 328;
/// Exact canonical byte count for the nonauthorizing worker HELLO.
pub const WORKER_PREPARATION_HELLO_BYTES_V1: usize = 104;

/// Describes the original owner-held scope for comparison, not read authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerPreparationPlanV1 {
    /// Original durably reserved, nonzero worker-instance locator.
    pub worker_instance: [u8; 16],
    /// Original owner-observed kernel boot.
    pub kernel_boot: [u8; 16],
    /// Fresh original private-flight challenge, not a credential.
    pub challenge: [u8; 32],
    /// Exact authenticated original Controller broker request commitment.
    pub controller_request: [u8; 32],
    /// Exact durable original Mount reservation commitment.
    pub mount_reservation: [u8; 32],
    /// Exact current accepted assignment's original commitment.
    pub assignment: [u8; 32],
    /// Exact current original Attachment desired record commitment.
    pub attachment: [u8; 32],
    /// Exact retained original immutable View descriptor commitment.
    pub original_view_descriptor: [u8; 32],
    /// Exact assignment-selected resolved Policy descriptor commitment.
    pub resolved_policy_descriptor: [u8; 32],
    /// Exact original held Mount slot/namespace/allocation commitment.
    pub mount_slot: [u8; 32],
    /// Original authenticated assignment ownership-lease identity.
    pub ownership_lease: [u8; 16],
    /// Original attachment lifetime derived from accepted ownership custody.
    pub ownership_lease_expires_boottime_ns: u64,
    /// Preparation exchange deadline; it never extends or replaces the lease.
    pub preparation_deadline_boottime_ns: u64,
}

/// Reports a malformed closed comparison record.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error("malformed fixed worker preparation record")]
pub struct WorkerPreparationWireError;

impl WorkerPreparationPlanV1 {
    /// Encodes the exact closed plan without issuing consumer authority.
    ///
    /// # Errors
    ///
    /// Rejects zero commitments/identities or absent lease/deadline boundaries.
    pub fn encode(
        &self,
    ) -> Result<[u8; WORKER_PREPARATION_PLAN_BYTES_V1], WorkerPreparationWireError> {
        self.validate()?;
        let mut bytes = [0; WORKER_PREPARATION_PLAN_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSFWP01");
        bytes[8..24].copy_from_slice(&self.worker_instance);
        bytes[24..40].copy_from_slice(&self.kernel_boot);
        bytes[40..72].copy_from_slice(&self.challenge);
        for (offset, commitment) in self.commitments().into_iter().enumerate() {
            bytes[72 + offset * 32..104 + offset * 32].copy_from_slice(commitment);
        }
        bytes[296..312].copy_from_slice(&self.ownership_lease);
        bytes[312..320].copy_from_slice(&self.ownership_lease_expires_boottime_ns.to_le_bytes());
        bytes[320..328].copy_from_slice(&self.preparation_deadline_boottime_ns.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes only the exact version and byte count for structural comparison.
    ///
    /// # Errors
    ///
    /// Rejects another version, truncation, trailing bytes or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkerPreparationWireError> {
        if bytes.len() != WORKER_PREPARATION_PLAN_BYTES_V1 || bytes[..8] != *b"AOSFWP01" {
            return Err(WorkerPreparationWireError);
        }
        let plan = Self {
            worker_instance: array(bytes, 8)?,
            kernel_boot: array(bytes, 24)?,
            challenge: array(bytes, 40)?,
            controller_request: array(bytes, 72)?,
            mount_reservation: array(bytes, 104)?,
            assignment: array(bytes, 136)?,
            attachment: array(bytes, 168)?,
            original_view_descriptor: array(bytes, 200)?,
            resolved_policy_descriptor: array(bytes, 232)?,
            mount_slot: array(bytes, 264)?,
            ownership_lease: array(bytes, 296)?,
            ownership_lease_expires_boottime_ns: u64::from_le_bytes(array(bytes, 312)?),
            preparation_deadline_boottime_ns: u64::from_le_bytes(array(bytes, 320)?),
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Returns the exact canonical sealed-plan digest for carrier comparison.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed fields as [`Self::encode`].
    pub fn digest(&self) -> Result<[u8; 32], WorkerPreparationWireError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    /// Encodes a preparation-only HELLO bound to this exact original plan.
    ///
    /// # Errors
    ///
    /// Rejects the same malformed fields as [`Self::encode`]. The recipient
    /// must independently verify the actual record subject and held owners.
    pub fn hello(
        &self,
    ) -> Result<[u8; WORKER_PREPARATION_HELLO_BYTES_V1], WorkerPreparationWireError> {
        let mut bytes = [0; WORKER_PREPARATION_HELLO_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSFWH01");
        bytes[8..24].copy_from_slice(&self.worker_instance);
        bytes[24..40].copy_from_slice(&self.kernel_boot);
        bytes[40..72].copy_from_slice(&self.challenge);
        bytes[72..104].copy_from_slice(&self.digest()?);
        Ok(bytes)
    }

    /// Checks an exact HELLO's comparison bytes without authenticating its sender.
    ///
    /// # Errors
    ///
    /// Rejects a different version, plan, worker, boot, challenge or byte count.
    pub fn compare_hello(&self, bytes: &[u8]) -> Result<(), WorkerPreparationWireError> {
        if bytes != self.hello()? {
            return Err(WorkerPreparationWireError);
        }
        Ok(())
    }

    fn commitments(&self) -> [&[u8; 32]; 7] {
        [
            &self.controller_request,
            &self.mount_reservation,
            &self.assignment,
            &self.attachment,
            &self.original_view_descriptor,
            &self.resolved_policy_descriptor,
            &self.mount_slot,
        ]
    }

    fn validate(&self) -> Result<(), WorkerPreparationWireError> {
        if self.worker_instance == [0; 16]
            || self.kernel_boot == [0; 16]
            || self.challenge == [0; 32]
            || self.ownership_lease == [0; 16]
            || self
                .commitments()
                .into_iter()
                .any(|commitment| *commitment == [0; 32])
            || self.ownership_lease_expires_boottime_ns == 0
            || self.preparation_deadline_boottime_ns == 0
            || self.preparation_deadline_boottime_ns > self.ownership_lease_expires_boottime_ns
        {
            return Err(WorkerPreparationWireError);
        }
        Ok(())
    }
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], WorkerPreparationWireError> {
    bytes
        .get(offset..offset + N)
        .ok_or(WorkerPreparationWireError)?
        .try_into()
        .map_err(|_| WorkerPreparationWireError)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn plan() -> WorkerPreparationPlanV1 {
        WorkerPreparationPlanV1 {
            worker_instance: [1; 16],
            kernel_boot: [2; 16],
            challenge: [3; 32],
            controller_request: [4; 32],
            mount_reservation: [5; 32],
            assignment: [6; 32],
            attachment: [7; 32],
            original_view_descriptor: [8; 32],
            resolved_policy_descriptor: [9; 32],
            mount_slot: [10; 32],
            ownership_lease: [11; 16],
            ownership_lease_expires_boottime_ns: 300,
            preparation_deadline_boottime_ns: 100,
        }
    }

    #[test]
    fn canonical_original_scope_round_trips() {
        let original = plan();
        let bytes = original.encode().unwrap();
        assert_eq!(WorkerPreparationPlanV1::decode(&bytes).unwrap(), original);
        original.compare_hello(&original.hello().unwrap()).unwrap();
    }

    #[test]
    fn rejects_versions_sentinels_and_trailing_bytes() {
        let original = plan().encode().unwrap();
        for offset in [8, 24, 40, 72, 104, 136, 168, 200, 232, 264, 296] {
            let mut bytes = original;
            let length = if matches!(offset, 8 | 24 | 296) {
                16
            } else {
                32
            };
            bytes[offset..offset + length].fill(0);
            assert!(WorkerPreparationPlanV1::decode(&bytes).is_err());
        }
        assert!(WorkerPreparationPlanV1::decode(&original[..original.len() - 1]).is_err());
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(WorkerPreparationPlanV1::decode(&trailing).is_err());
        let mut version = original;
        version[7] = b'2';
        assert!(WorkerPreparationPlanV1::decode(&version).is_err());
    }

    #[test]
    fn preparation_cannot_extend_original_ownership_lease() {
        let mut original = plan();
        original.preparation_deadline_boottime_ns = 301;
        assert!(original.encode().is_err());
    }

    #[test]
    fn hello_is_bound_to_every_original_scope_commitment() {
        let original = plan();
        let hello = original.hello().unwrap();
        let mut changed = original.clone();
        changed.attachment[0] ^= 1;
        assert!(changed.compare_hello(&hello).is_err());
        changed = original;
        changed.ownership_lease_expires_boottime_ns += 1;
        assert!(changed.compare_hello(&hello).is_err());
    }
}
