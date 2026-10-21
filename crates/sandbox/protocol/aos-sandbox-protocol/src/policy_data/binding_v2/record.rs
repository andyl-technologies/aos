//! Owns the sole canonical AOSPCB02 record and comparison-field DATA.
//!
//! ```text
//! AOSPCB02 | version2 | reserved6 | canonical fields616 | SHA25632
//! ```
//!
//! Fields, keys and commitments create no native custody or publication grant.

use super::{BINDING_V2_KEY_PREFIX, BindingDataErrorV1};
use aos_sandbox_model::{
    ObjectDigest, OperationId, ProjectId, SandboxId, bounded_codec::BoundedReader,
};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSPCB02";
/// Names the unchanged canonical binding checksum domain.
pub const BINDING_V2_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.protected-binding.v2\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-key.v2\0";
const RECORD_BYTES: usize = 664;
/// Bounds the unchanged canonical body before its checksum.
pub const BINDING_V2_BODY_BYTES: usize = RECORD_BYTES - 32;

/// Bounds one existing canonical closed-binding record.
pub const CLOSED_POLICY_BINDING_BYTES_V2: usize = RECORD_BYTES;

/// Retains canonical fields without asserting that their independent owners held a barrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedPolicyRootBindingV2 {
    pub issuer_owner: [u8; 16],
    pub project: ProjectId,
    pub sandbox: SandboxId,
    pub operation: OperationId,
    pub operation_revision: ObjectDigest,
    pub accepted_generation: u64,
    pub projection_revision: ObjectDigest,
    pub publisher_generation: u64,
    pub publisher_head: ObjectDigest,
    pub project_policy_head: ObjectDigest,
    pub project_policy_input: ObjectDigest,
    pub ancestry_head: ObjectDigest,
    pub compiler_head: ObjectDigest,
    pub cache_domain_head: ObjectDigest,
    pub revocation_head: ObjectDigest,
    pub physical_partition: ObjectDigest,
    pub physical_cache_head: ObjectDigest,
    pub normalized_input: ObjectDigest,
    pub candidate: ObjectDigest,
    pub project_signer_generation: u64,
    pub deployment_signer_generation: u64,
    pub barrier_epoch: u64,
    pub barrier_head: ObjectDigest,
    pub root_predecessor: ObjectDigest,
    pub root_generation: u64,
    pub effect_transaction: [u8; 16],
    pub handoff_epoch: u64,
}

impl ClosedPolicyRootBindingV2 {
    // This decoder projection is unbranded DATA. Q04's Root owner separately
    // verifies the pinned Controller packet and genuine same-flight gen1 cut
    // before these fields enter the shared compiler/proposal recipe.
    /// Decodes unbranded canonical comparison DATA.
    ///
    /// # Errors
    /// Rejects malformed or noncanonical binding bytes.
    pub fn q04_decode(bytes: &[u8]) -> Result<Self, BindingDataErrorV1> {
        Self::decode(bytes)
    }

    /// Returns the already encoded compiler commitments as DATA.
    pub fn q04_compilation_commitments(&self) -> (ObjectDigest, ObjectDigest) {
        (self.normalized_input, self.candidate)
    }

    /// Borrows the original comparison-field projection.
    pub fn q04_fields<'fields>(
        &'fields self,
        source_commitment: &'fields ObjectDigest,
    ) -> ClosedCreateProposalFieldViewV2<'fields> {
        ClosedCreateProposalFieldViewV2 {
            source_commitment,
            operation: &self.operation,
            operation_revision: &self.operation_revision,
            accepted_generation: &self.accepted_generation,
            sandbox: &self.sandbox,
            project: &self.project,
            projection_revision: &self.projection_revision,
            publisher_generation: &self.publisher_generation,
            publisher_head: &self.publisher_head,
            cache_domain_head: &self.cache_domain_head,
            revocation_head: &self.revocation_head,
            ancestry: &self.ancestry_head,
            physical_partition: &self.physical_partition,
            physical_cache: &self.physical_cache_head,
        }
    }

    fn canonical(&self) -> bool {
        self.issuer_owner != [0; 16]
            && self.project.as_bytes() != &[0; 16]
            && self.sandbox.as_bytes() != &[0; 16]
            && self.operation.as_bytes() != &[0; 16]
            && self.effect_transaction != [0; 16]
            && self.accepted_generation != 0
            && self.publisher_generation != 0
            && self.project_signer_generation != 0
            && self.deployment_signer_generation != 0
            && self.barrier_epoch != 0
            && self.root_generation != 0
            && self.handoff_epoch == self.barrier_epoch
            && (self.root_predecessor.as_bytes() == &[0; 32]) == (self.root_generation == 1)
            && [
                self.operation_revision,
                self.projection_revision,
                self.publisher_head,
                self.project_policy_head,
                self.project_policy_input,
                self.ancestry_head,
                self.compiler_head,
                self.cache_domain_head,
                self.revocation_head,
                self.physical_partition,
                self.physical_cache_head,
                self.normalized_input,
                self.candidate,
                self.barrier_head,
            ]
            .iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
    }

    /// Encodes the exact existing canonical record.
    ///
    /// # Errors
    /// Rejects zero or inconsistent canonical binding fields.
    pub fn encode(&self) -> Result<Vec<u8>, BindingDataErrorV1> {
        if !self.canonical() {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.issuer_owner);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(self.sandbox.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.operation_revision.as_bytes());
        bytes.extend_from_slice(&self.accepted_generation.to_be_bytes());
        bytes.extend_from_slice(self.projection_revision.as_bytes());
        bytes.extend_from_slice(&self.publisher_generation.to_be_bytes());
        bytes.extend_from_slice(self.publisher_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_input.as_bytes());
        bytes.extend_from_slice(self.ancestry_head.as_bytes());
        bytes.extend_from_slice(self.compiler_head.as_bytes());
        bytes.extend_from_slice(self.cache_domain_head.as_bytes());
        bytes.extend_from_slice(self.revocation_head.as_bytes());
        bytes.extend_from_slice(self.physical_partition.as_bytes());
        bytes.extend_from_slice(self.physical_cache_head.as_bytes());
        bytes.extend_from_slice(self.normalized_input.as_bytes());
        bytes.extend_from_slice(self.candidate.as_bytes());
        bytes.extend_from_slice(&self.project_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.deployment_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.barrier_epoch.to_be_bytes());
        bytes.extend_from_slice(self.barrier_head.as_bytes());
        bytes.extend_from_slice(self.root_predecessor.as_bytes());
        bytes.extend_from_slice(&self.root_generation.to_be_bytes());
        bytes.extend_from_slice(&self.effect_transaction);
        bytes.extend_from_slice(&self.handoff_epoch.to_be_bytes());
        if bytes.len() != BINDING_V2_BODY_BYTES {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let checksum = Sha256::new()
            .chain_update(BINDING_V2_CHECKSUM_DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes and compares the complete canonical record, including checksum.
    ///
    /// # Errors
    /// Rejects wrong framing, fields, size or canonical re-encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, BindingDataErrorV1> {
        if bytes.len() != RECORD_BYTES {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let mut reader =
            BoundedReader::new(bytes, |_| BindingDataErrorV1::UnauthenticatedCandidate);
        if reader.array::<8>()? != *MAGIC
            || reader.array::<2>()? != 2_u16.to_be_bytes()
            || reader.array::<6>()? != [0; 6]
        {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let binding = Self {
            issuer_owner: reader.array()?,
            project: ProjectId::from_bytes(reader.array()?),
            sandbox: SandboxId::from_bytes(reader.array()?),
            operation: OperationId::from_bytes(reader.array()?),
            operation_revision: reader.digest()?,
            accepted_generation: reader.u64()?,
            projection_revision: reader.digest()?,
            publisher_generation: reader.u64()?,
            publisher_head: reader.digest()?,
            project_policy_head: reader.digest()?,
            project_policy_input: reader.digest()?,
            ancestry_head: reader.digest()?,
            compiler_head: reader.digest()?,
            cache_domain_head: reader.digest()?,
            revocation_head: reader.digest()?,
            physical_partition: reader.digest()?,
            physical_cache_head: reader.digest()?,
            normalized_input: reader.digest()?,
            candidate: reader.digest()?,
            project_signer_generation: reader.u64()?,
            deployment_signer_generation: reader.u64()?,
            barrier_epoch: reader.u64()?,
            barrier_head: reader.digest()?,
            root_predecessor: reader.digest()?,
            root_generation: reader.u64()?,
            effect_transaction: reader.array()?,
            handoff_epoch: reader.u64()?,
        };
        // Leave the checksum unread; canonical re-encoding validates the whole record.
        if reader.remaining() != RECORD_BYTES - BINDING_V2_BODY_BYTES
            || binding.encode()?.as_slice() != bytes
        {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        Ok(binding)
    }

    /// Derives the existing content-addressed binding key.
    ///
    /// # Errors
    /// Rejects a record that cannot canonically encode.
    pub fn key(&self) -> Result<Vec<u8>, BindingDataErrorV1> {
        let encoded = self.encode()?;
        let digest = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(encoded)
            .finalize();
        let mut key = Vec::with_capacity(BINDING_V2_KEY_PREFIX.len() + 32);
        key.extend_from_slice(BINDING_V2_KEY_PREFIX);
        key.extend_from_slice(&digest);
        Ok(key)
    }
}

/// Decodes an exact root-journal key/value pair without granting publication authority.
///
/// # Errors
/// Rejects malformed binding bytes or a different content-addressed key.
pub fn decode_closed_policy_binding_v2(
    key: &[u8],
    value: &[u8],
) -> Result<ClosedPolicyRootBindingV2, BindingDataErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(value)?;
    if binding.key()?.as_slice() != key {
        return Err(BindingDataErrorV1::UnauthenticatedCandidate);
    }
    Ok(binding)
}

/// Validates one closed AOSPCB02 record and returns its content-addressed head.
///
/// The digest is framing evidence only; it cannot authorize publication or
/// an effect without the independent protected owner barrier.
///
/// # Errors
///
/// Rejects a malformed or noncanonical closed record.
pub fn closed_policy_binding_digest_v2(value: &[u8]) -> Result<ObjectDigest, BindingDataErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(value)?;
    let key = binding.key()?;
    let suffix: [u8; 32] = key[BINDING_V2_KEY_PREFIX.len()..]
        .try_into()
        .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?;
    Ok(ObjectDigest::from_bytes(suffix))
}

/// Borrows existing protected-cut comparison fields without adopting their authority.
pub struct ClosedCreateProposalFieldViewV2<'cut> {
    pub source_commitment: &'cut ObjectDigest,
    pub operation: &'cut aos_sandbox_model::OperationId,
    pub operation_revision: &'cut ObjectDigest,
    pub accepted_generation: &'cut u64,
    pub sandbox: &'cut aos_sandbox_model::SandboxId,
    pub project: &'cut aos_sandbox_model::ProjectId,
    pub projection_revision: &'cut ObjectDigest,
    pub publisher_generation: &'cut u64,
    pub publisher_head: &'cut ObjectDigest,
    pub cache_domain_head: &'cut ObjectDigest,
    pub revocation_head: &'cut ObjectDigest,
    pub ancestry: &'cut ObjectDigest,
    pub physical_partition: &'cut ObjectDigest,
    pub physical_cache: &'cut ObjectDigest,
}
