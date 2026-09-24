//! Structural Controller source for a future signed Host output reservation.
//!
//! AOSCIR01 carries the Controller-derived AOSEOR02 claim verbatim. It is not
//! a signature or a Host reservation: an authenticated broker plan must bind
//! the exact carrier and request attempt, and Host must independently validate
//! its current assignment before committing the claim in its own journal.
//!
//! ```text
//! AOSCIR01 || AOSCIP01[184] || AOSEOR02[328] || accepted-request-digest[32]
//!          || sandbox[16] || incarnation[16] || node[16]
//!          || assignment-epoch:u64be || desired-generation:u64be
//!          || namespace-generation:u64be || assignment-manifest-digest[32]
//!          || SHA256("aos.sandbox.controller-execution-reserve-source.v1\0"
//!             || preceding)[32]
//! ```

use aos_sandbox_core::{IncarnationId, NodeId, ObjectDigest, RawPairedClockSample, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::environment::EnvironmentProtectedJournalOwnerV1;
use crate::execution_output_reservation::{
    CLAIM_BYTES, ExecutionOutputReservationErrorV1, accepted_claim, decode_claim,
};
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::reconciler::{ReconcilerError, accepted_create_execution_effect_from_journal_v1};
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};

use super::{
    ControllerExecutionPreissueErrorV1, ControllerExecutionPreissueV1, RECORD_BYTES,
    revalidate_accepted_execution_preissue_v1,
};

const MAGIC: &[u8; 8] = b"AOSCIR01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-execution-reserve-source.v1\0";
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.execution.accepted-create-request.v1\0";
#[cfg(test)]
const CLAIM_MAGIC: &[u8; 8] = b"AOSEOR02";
/// Returns the exact byte length of a version-one reserve source carrier.
pub const EXECUTION_RESERVE_SOURCE_BYTES_V1: usize =
    8 + RECORD_BYTES + CLAIM_BYTES + 32 + 16 + 16 + 16 + 8 + 8 + 8 + 32 + 32;
const SOURCE_BYTES: usize = EXECUTION_RESERVE_SOURCE_BYTES_V1;
const CLAIM_OFFSET: usize = 8 + RECORD_BYTES;
const REQUEST_OFFSET: usize = CLAIM_OFFSET + CLAIM_BYTES;

/// Reports absent or noncanonical Controller reserve-source evidence.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionReserveSourceErrorV1 {
    /// The structural carrier or one of its redundant bindings differs.
    #[error("execution reserve source is not canonical")]
    InvalidCarrier,
    /// The protected Controller preissue is absent or no longer current.
    #[error(transparent)]
    Preissue(#[from] ControllerExecutionPreissueErrorV1),
    /// The exact Controller-derived AOSEOR02 claim is unavailable.
    #[error(transparent)]
    Output(#[from] ExecutionOutputReservationErrorV1),
    /// The accepted Create effect cannot be replayed.
    #[error(transparent)]
    Operation(#[from] ReconcilerError),
    /// The signed current assignment or lease is unavailable.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
}

/// Holds a canonical but nonauthorizing provisional Host reserve source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionReserveSourceV1 {
    preissue: ControllerExecutionPreissueV1,
    claim: [u8; CLAIM_BYTES],
    accepted_request_digest: ObjectDigest,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    assignment_epoch: u64,
    desired_generation: u64,
    namespace_generation: u64,
    assignment_manifest_digest: ObjectDigest,
    carrier_digest: ObjectDigest,
}

impl ControllerExecutionReserveSourceV1 {
    /// Borrows the exact protected Controller preissue represented by the carrier.
    #[must_use]
    pub const fn preissue(&self) -> &ControllerExecutionPreissueV1 {
        &self.preissue
    }

    /// Borrows the exact AOSEOR02 claim that Host must independently validate.
    #[must_use]
    pub const fn canonical_output_claim(&self) -> &[u8; CLAIM_BYTES] {
        &self.claim
    }

    /// Returns the exact AOSEOR02 record digest for Host correlation.
    #[must_use]
    pub fn output_claim_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.claim).into())
    }

    /// Returns the domain-separated accepted public Create request commitment.
    #[must_use]
    pub const fn accepted_request_digest(&self) -> ObjectDigest {
        self.accepted_request_digest
    }

    /// Returns the exact assignment sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact assignment incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the exact assigned node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired-state generation.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the exact signed assignment-manifest commitment.
    #[must_use]
    pub const fn assignment_manifest_digest(&self) -> ObjectDigest {
        self.assignment_manifest_digest
    }

    /// Returns the digest a future signed broker grant must bind to its attempt.
    #[must_use]
    pub const fn carrier_digest(&self) -> ObjectDigest {
        self.carrier_digest
    }

    /// Returns the exact AOSCIR01 bytes for a future signed broker request.
    ///
    /// Structural integrity does not prove Controller provenance or authorize
    /// Host output reservation without a pinned signed grant.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; SOURCE_BYTES] {
        let mut bytes = [0_u8; SOURCE_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..CLAIM_OFFSET].copy_from_slice(&self.preissue.encode());
        bytes[CLAIM_OFFSET..REQUEST_OFFSET].copy_from_slice(&self.claim);
        bytes[REQUEST_OFFSET..REQUEST_OFFSET + 32]
            .copy_from_slice(self.accepted_request_digest.as_bytes());
        let mut offset = REQUEST_OFFSET + 32;
        for identity in [
            self.sandbox.as_bytes(),
            self.incarnation.as_bytes(),
            self.node.as_bytes(),
        ] {
            bytes[offset..offset + 16].copy_from_slice(identity);
            offset += 16;
        }
        for generation in [
            self.assignment_epoch,
            self.desired_generation,
            self.namespace_generation,
        ] {
            bytes[offset..offset + 8].copy_from_slice(&generation.to_be_bytes());
            offset += 8;
        }
        bytes[offset..offset + 32].copy_from_slice(self.assignment_manifest_digest.as_bytes());
        bytes[SOURCE_BYTES - 32..].copy_from_slice(self.carrier_digest.as_bytes());
        bytes
    }

    /// Parses structural carrier bytes without claiming signing authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed length, version, checksums, zero sentinels, or an
    /// AOSEOR02 claim that disagrees with the embedded AOSCIP01 identity and
    /// exact per-stream output ceilings.
    pub fn decode_structural(
        bytes: &[u8],
    ) -> Result<Self, ControllerExecutionReserveSourceErrorV1> {
        if bytes.len() != SOURCE_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ControllerExecutionReserveSourceErrorV1::InvalidCarrier);
        }
        let preissue = ControllerExecutionPreissueV1::decode(&bytes[8..CLAIM_OFFSET])?;
        let claim: [u8; CLAIM_BYTES] = bytes[CLAIM_OFFSET..REQUEST_OFFSET]
            .try_into()
            .map_err(|_| ControllerExecutionReserveSourceErrorV1::InvalidCarrier)?;
        let mut offset = REQUEST_OFFSET;
        let read_32 = |start: usize| -> Result<[u8; 32], ControllerExecutionReserveSourceErrorV1> {
            bytes[start..start + 32]
                .try_into()
                .map_err(|_| ControllerExecutionReserveSourceErrorV1::InvalidCarrier)
        };
        let read_16 = |start: usize| -> Result<[u8; 16], ControllerExecutionReserveSourceErrorV1> {
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| ControllerExecutionReserveSourceErrorV1::InvalidCarrier)
        };
        let accepted_request_digest = ObjectDigest::from_bytes(read_32(offset)?);
        offset += 32;
        let sandbox = SandboxId::from_bytes(read_16(offset)?);
        offset += 16;
        let incarnation = IncarnationId::from_bytes(read_16(offset)?);
        offset += 16;
        let node = NodeId::from_bytes(read_16(offset)?);
        offset += 16;
        let read_u64 = |start: usize| -> Result<u64, ControllerExecutionReserveSourceErrorV1> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .map_err(|_| ControllerExecutionReserveSourceErrorV1::InvalidCarrier)?,
            ))
        };
        let assignment_epoch = read_u64(offset)?;
        offset += 8;
        let desired_generation = read_u64(offset)?;
        offset += 8;
        let namespace_generation = read_u64(offset)?;
        offset += 8;
        let assignment_manifest_digest = ObjectDigest::from_bytes(read_32(offset)?);
        let recorded_carrier_digest = ObjectDigest::from_bytes(read_32(SOURCE_BYTES - 32)?);
        let source = Self {
            preissue,
            claim,
            accepted_request_digest,
            sandbox,
            incarnation,
            node,
            assignment_epoch,
            desired_generation,
            namespace_generation,
            assignment_manifest_digest,
            carrier_digest: recorded_carrier_digest,
        };
        if source.accepted_request_digest.as_bytes() == &[0; 32]
            || source.sandbox.as_bytes() == &[0; 16]
            || source.incarnation.as_bytes() == &[0; 16]
            || source.node.as_bytes() == &[0; 16]
            || source.assignment_epoch == 0
            || source.desired_generation == 0
            || source.namespace_generation == 0
            || source.assignment_manifest_digest.as_bytes() == &[0; 32]
            || source.carrier_digest != carrier_digest(&bytes[..SOURCE_BYTES - 32])
            || !claim_matches_preissue(
                &source.claim,
                &source.preissue,
                source.assignment_manifest_digest,
            )
        {
            return Err(ControllerExecutionReserveSourceErrorV1::InvalidCarrier);
        }
        Ok(source)
    }
}

/// Derives a nonauthorizing reserve carrier from current Controller owners.
///
/// The AOSEOR02 bytes are produced by the same accepted-Create code used by
/// the historical in-process Host ledger. Host still needs a pinned signed
/// method grant, independent assignment check, and durable owner commit.
///
/// # Errors
///
/// Rejects stale protected sources, an expired preissue, an incompatible exact
/// output claim, or absent accepted Create custody.
#[allow(clippy::too_many_arguments)]
pub fn prepare_execution_reserve_source_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    preissue: &ControllerExecutionPreissueV1,
    clock: &mut T,
) -> Result<ControllerExecutionReserveSourceV1, ControllerExecutionReserveSourceErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    revalidate_accepted_execution_preissue_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )?;
    let claim = accepted_claim(
        controller,
        preissue.create_operation(),
        preissue.execution(),
        parent,
    )?;
    let accepted =
        accepted_create_execution_effect_from_journal_v1(controller, preissue.create_operation())?
            .ok_or(ControllerExecutionReserveSourceErrorV1::InvalidCarrier)?;
    let request_digest = accepted_request_digest(
        accepted.caller().as_bytes(),
        accepted.project().as_bytes(),
        accepted.canonical_request(),
    );

    let manifest = parent.assignment().manifest();
    let mut source = ControllerExecutionReserveSourceV1 {
        preissue: preissue.clone(),
        claim: claim.bytes,
        accepted_request_digest: request_digest,
        sandbox: manifest.sandbox(),
        incarnation: manifest.incarnation(),
        node: manifest.node(),
        assignment_epoch: manifest.epoch().get(),
        desired_generation: manifest.desired_generation().get(),
        namespace_generation: manifest.namespace_generation().get(),
        assignment_manifest_digest: parent.assignment().digest(),
        carrier_digest: ObjectDigest::from_bytes([0; 32]),
    };
    if !claim_matches_preissue(
        &source.claim,
        &source.preissue,
        source.assignment_manifest_digest,
    ) {
        return Err(ControllerExecutionReserveSourceErrorV1::InvalidCarrier);
    }
    source.carrier_digest = carrier_digest(&source.canonical_bytes()[..SOURCE_BYTES - 32]);

    // The source is returned only after the same owners survive a final check.
    revalidate_accepted_execution_preissue_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )?;
    Ok(source)
}

fn claim_matches_preissue(
    claim: &[u8; CLAIM_BYTES],
    preissue: &ControllerExecutionPreissueV1,
    assignment_digest: ObjectDigest,
) -> bool {
    let Ok(decoded) = decode_claim(claim) else {
        return false;
    };
    decoded.execution == *preissue.execution().as_bytes()
        && decoded.create_operation == *preissue.create_operation().as_bytes()
        && decoded.assignment == assignment_digest
        && decoded.stream_limits
            == Some((
                preissue.maximum_stdout_bytes(),
                preissue.maximum_stderr_bytes(),
            ))
}

fn accepted_request_digest(caller: &[u8; 16], project: &[u8; 16], request: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(REQUEST_DOMAIN)
            .chain_update(caller)
            .chain_update(project)
            .chain_update((request.len() as u64).to_be_bytes())
            .chain_update(request)
            .finalize()
            .into(),
    )
}

fn carrier_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{ExecutionId, OperationId};

    use super::*;

    fn fixture() -> ControllerExecutionReserveSourceV1 {
        let mut preissue = ControllerExecutionPreissueV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            source_digest: ObjectDigest::from_bytes([3; 32]),
            maximum_stdout_bytes: 5,
            maximum_stderr_bytes: 7,
            controller_source_sequence: 9,
            host_boot_id: [4; 16],
            deadline_boottime_nanoseconds: 100,
            issuer_nonce: [5; 32],
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        preissue.record_digest = super::super::record_digest(&preissue.encode()[..152]);
        let mut claim = [0_u8; CLAIM_BYTES];
        claim[..8].copy_from_slice(CLAIM_MAGIC);
        claim[8..24].copy_from_slice(preissue.execution().as_bytes());
        claim[24..40].copy_from_slice(preissue.create_operation().as_bytes());
        for (offset, value) in [40, 72, 136, 168, 200, 264].into_iter().zip(1_u8..) {
            claim[offset..offset + 32].fill(value);
        }
        claim[104..136].fill(6);
        claim[232..240].copy_from_slice(&12_u64.to_be_bytes());
        claim[240..248].copy_from_slice(&20_u64.to_be_bytes());
        claim[248..256].copy_from_slice(&5_u64.to_be_bytes());
        claim[256..264].copy_from_slice(&7_u64.to_be_bytes());
        let checksum = Sha256::digest(&claim[..296]);
        claim[296..].copy_from_slice(&checksum);
        let mut source = ControllerExecutionReserveSourceV1 {
            preissue,
            claim,
            accepted_request_digest: ObjectDigest::from_bytes([7; 32]),
            sandbox: SandboxId::from_bytes([8; 16]),
            incarnation: IncarnationId::from_bytes([9; 16]),
            node: NodeId::from_bytes([10; 16]),
            assignment_epoch: 11,
            desired_generation: 12,
            namespace_generation: 13,
            assignment_manifest_digest: ObjectDigest::from_bytes([6; 32]),
            carrier_digest: ObjectDigest::from_bytes([0; 32]),
        };
        source.carrier_digest = carrier_digest(&source.canonical_bytes()[..SOURCE_BYTES - 32]);
        source
    }

    #[test]
    fn carrier_round_trip_and_tamper_rejection() {
        let source = fixture();
        let mut bytes = source.canonical_bytes();
        assert_eq!(
            ControllerExecutionReserveSourceV1::decode_structural(&bytes).unwrap(),
            source
        );

        bytes[CLAIM_OFFSET + 248] ^= 1;
        assert!(ControllerExecutionReserveSourceV1::decode_structural(&bytes).is_err());
        bytes = source.canonical_bytes();
        bytes[REQUEST_OFFSET] ^= 1;
        assert!(ControllerExecutionReserveSourceV1::decode_structural(&bytes).is_err());
    }

    #[test]
    fn claim_rejects_borrowed_assignment_and_over_parent_capacity() {
        let source = fixture();
        let mut claim = source.claim;
        claim[104..136].fill(99);
        let checksum = Sha256::digest(&claim[..296]);
        claim[296..].copy_from_slice(&checksum);
        assert!(!claim_matches_preissue(
            &claim,
            &source.preissue,
            source.assignment_manifest_digest,
        ));

        let mut claim = source.claim;
        claim[240..248].copy_from_slice(&11_u64.to_be_bytes());
        let checksum = Sha256::digest(&claim[..296]);
        claim[296..].copy_from_slice(&checksum);
        assert!(!claim_matches_preissue(
            &claim,
            &source.preissue,
            source.assignment_manifest_digest,
        ));
    }
}
