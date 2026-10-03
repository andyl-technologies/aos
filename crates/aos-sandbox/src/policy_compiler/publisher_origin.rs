//! Original compiler derivation retained in the publisher's revision record.
//!
//! Only the real compiler produces a [`CompiledPublisherPolicyRevisionV2`].
//! Cold decoding retains bytes and commitments, never authenticated model
//! constructors. Recompilation requires independently reconstructed typed
//! inputs with the original target; it cannot invert a resolved Policy.
//!
//! ```text
//! AOSPCO03 | project[16] | original-target[16] | normalized-input[32] |
//! candidate[32] | authority/namespace/hard/advisory/explanation[5][32] |
//! u32be-length + bytes, repeated for full-input/project/request/four-outputs
//! ```

use aos_sandbox_core::{
    DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    SandboxId, descriptor_for_bytes,
};
use sha2::{Digest as _, Sha256};

use crate::CommitResult;
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherPolicyError, PublisherPolicyStore,
};

use super::model::{CompiledPolicyCandidatePreimageV1, canonical_bytes};
use super::{
    CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1,
    normalized_policy_input_digest_v1,
};

const MAGIC: &[u8; 8] = b"AOSPCO03";
const INPUT_DOMAIN: &[u8] = b"aos.sandbox.publisher-original-compiler-input.v3";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.publisher-compiler-origin.v3\0";
const FIXED_BYTES: usize = 264;
// This is the existing publisher record ceiling, not extra journal capacity.
const MAXIMUM_BYTES: usize = 4 * 1024 * 1024;

/// Retains nonauthorizing original compiler bytes and output commitments.
///
/// Decoding proves bounded layout and byte cross-links, not genuine input
/// owners, compiler derivation, antirollback, or current publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPublisherCompilerOriginV3 {
    project: ProjectId,
    original_target: SandboxId,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    plans: [ObjectDigest; 5],
    fields: [Vec<u8>; 7],
}

impl RetainedPublisherCompilerOriginV3 {
    /// Returns the original project, not a signed authorization assertion.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the original target, never the later Create's random child.
    #[must_use]
    pub const fn original_target(&self) -> SandboxId {
        self.original_target
    }

    /// Returns the original normalized compiler-input commitment.
    #[must_use]
    pub const fn normalized_input(&self) -> ObjectDigest {
        self.normalized_input
    }

    /// Returns the exact existing compiled-candidate commitment.
    #[must_use]
    pub const fn candidate(&self) -> ObjectDigest {
        self.candidate
    }

    /// Returns the full original typed input serialization as data only.
    #[must_use]
    pub fn original_input_bytes(&self) -> &[u8] {
        &self.fields[0]
    }

    /// Returns the exact original project-layer bytes as data only.
    #[must_use]
    pub fn project_input_bytes(&self) -> &[u8] {
        &self.fields[1]
    }

    /// Returns the exact original request-layer bytes as data only.
    #[must_use]
    pub fn request_input_bytes(&self) -> &[u8] {
        &self.fields[2]
    }

    /// Returns Policy, Optimization, namespace, and advisory output bytes.
    #[must_use]
    pub fn output_bytes(&self) -> [&[u8]; 4] {
        [
            self.fields[3].as_slice(),
            self.fields[4].as_slice(),
            self.fields[5].as_slice(),
            self.fields[6].as_slice(),
        ]
    }

    /// Computes exact portable descriptors in the fixed four-output order.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable registered media type. No descriptor proves
    /// current input owners or enables a resource read.
    pub fn output_descriptors(&self) -> Result<[ObjectDescriptor; 4], PublisherPolicyError> {
        let media = [
            PortableMediaType::Policy,
            PortableMediaType::Optimization,
            PortableMediaType::Content,
            PortableMediaType::Content,
        ];
        let outputs = self.output_bytes();
        let [policy, optimization, namespace, advisory] =
            std::array::from_fn(|index| -> Result<_, PublisherPolicyError> {
                let kind = media[index];
                let bytes = outputs[index];
                let media = MediaType::new(kind.as_str())
                    .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
                Ok(descriptor_for_bytes(media, bytes))
            });
        Ok([policy?, optimization?, namespace?, advisory?])
    }

    /// Computes the complete retained origin digest, including original target.
    ///
    /// # Errors
    ///
    /// Rejects an oversized retained record or inconsistent output commitments.
    pub fn record_digest(&self) -> Result<ObjectDigest, PublisherPolicyError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(RECORD_DOMAIN)
                .chain_update(self.to_record_bytes()?)
                .finalize()
                .into(),
        ))
    }

    /// Checks derivation using the real compiler and independently typed inputs.
    ///
    /// This never decodes retained JSON into authenticated models. A caller
    /// must separately establish current/historical input owner custody. The
    /// original target is mandatory even when a later Create selects another
    /// child. Successful equality is derivation/provenance, not effect authority.
    ///
    /// # Errors
    ///
    /// Rejects substituted targets, any of the six layer fields, incomplete
    /// 16/22 resource profiles, input commitments, outputs, or failed compile.
    pub fn verify_original_derivation(
        &self,
        expected: &PolicyCompilerInputV1,
    ) -> Result<(), PublisherPolicyError> {
        if expected.project().project() != self.project
            || expected.sandbox() != self.original_target
            || !expected.ancestors().is_empty()
        {
            return Err(PublisherPolicyError::InvalidPolicyRevision);
        }
        let candidate = PolicyCompilerV1::compile_retained(expected)
            .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
        self.compare_compiled_derivation(expected, &candidate)
    }

    // Reuses an already freshly compiled candidate for compare-only consumers.
    // It does not authenticate model constructors or confer owner currentness.
    pub(crate) fn compare_compiled_derivation(
        &self,
        expected: &PolicyCompilerInputV1,
        candidate: &CompiledPolicyCandidateV1,
    ) -> Result<(), PublisherPolicyError> {
        let derived = retain_derivation(expected, candidate)?;
        if &derived != self {
            return Err(PublisherPolicyError::InvalidPolicyRevision);
        }
        Ok(())
    }

    pub(crate) fn to_record_bytes(&self) -> Result<Vec<u8>, PublisherPolicyError> {
        self.validate_links()?;
        let size = self.fields.iter().try_fold(FIXED_BYTES, |size, field| {
            size.checked_add(4)
                .and_then(|size| size.checked_add(field.len()))
                .filter(|size| *size <= MAXIMUM_BYTES)
                .ok_or(PublisherPolicyError::LimitExceeded("compiler origin bytes"))
        })?;
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(self.original_target.as_bytes());
        bytes.extend_from_slice(self.normalized_input.as_bytes());
        bytes.extend_from_slice(self.candidate.as_bytes());
        for plan in self.plans {
            bytes.extend_from_slice(plan.as_bytes());
        }
        for field in &self.fields {
            let length = u32::try_from(field.len())
                .map_err(|_| PublisherPolicyError::LimitExceeded("compiler origin bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    pub(crate) fn from_record_bytes(bytes: &[u8]) -> Result<Self, PublisherPolicyError> {
        if bytes.len() < FIXED_BYTES || bytes.len() > MAXIMUM_BYTES || bytes.get(..8) != Some(MAGIC)
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        let project = ProjectId::from_bytes(take(bytes, 8)?);
        let original_target = SandboxId::from_bytes(take(bytes, 24)?);
        let normalized_input = ObjectDigest::from_bytes(take(bytes, 40)?);
        let candidate = ObjectDigest::from_bytes(take(bytes, 72)?);
        let mut plans = [ObjectDigest::from_bytes([0; 32]); 5];
        for (index, plan) in plans.iter_mut().enumerate() {
            *plan = ObjectDigest::from_bytes(take(bytes, 104 + index * 32)?);
        }
        let mut fields = std::array::from_fn(|_| Vec::new());
        let mut offset = FIXED_BYTES;
        for field in &mut fields {
            let length = u32::from_be_bytes(take(bytes, offset)?) as usize;
            offset = offset
                .checked_add(4)
                .ok_or(PublisherPolicyError::CorruptState)?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(PublisherPolicyError::CorruptState)?;
            *field = bytes[offset..end].to_vec();
            offset = end;
        }
        if offset != bytes.len() {
            return Err(PublisherPolicyError::CorruptState);
        }
        let value = Self {
            project,
            original_target,
            normalized_input,
            candidate,
            plans,
            fields,
        };
        value.validate_links()?;
        Ok(value)
    }

    fn validate_links(&self) -> Result<(), PublisherPolicyError> {
        if self.project.as_bytes() == &[0; 16]
            || self.original_target.as_bytes() == &[0; 16]
            || self.normalized_input.as_bytes() == &[0; 32]
            || self
                .plans
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
            || self.fields.iter().any(Vec::is_empty)
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        let descriptors = self.output_descriptors()?;
        let candidate = CompiledPolicyCandidatePreimageV1::from_digests(self.plans)
            .commitment(descriptors.each_ref())
            .map_err(|_| PublisherPolicyError::CorruptState)?;
        let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            self.project,
            1,
            0,
            1,
            &self.fields[3],
            DecodeLimits::default(),
        )
        .map_err(|_| PublisherPolicyError::CorruptState)?;
        let input_media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| PublisherPolicyError::CorruptState)?;
        let project = descriptor_for_bytes(input_media.clone(), &self.fields[1]);
        let request = descriptor_for_bytes(input_media, &self.fields[2]);
        let inputs = policy.policy().input_commitments();
        if candidate.digest() != self.candidate
            || inputs.len() != 10
            || inputs.get(2) != Some(&project)
            || inputs.get(3) != Some(&request)
            || inputs.get(8) != Some(&descriptors[2])
            || inputs.get(9) != Some(&descriptors[3])
            || policy.policy().optimization_digest() != Some(&descriptors[1])
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        Ok(())
    }
}

/// Retains a prepared publisher revision produced only by real compilation.
pub struct CompiledPublisherPolicyRevisionV2 {
    revision: PreparedPublisherPolicyRevisionV1,
}

impl CompiledPublisherPolicyRevisionV2 {
    /// Returns the exact resolved policy revision and retained provenance data.
    #[must_use]
    pub const fn revision(&self) -> &PreparedPublisherPolicyRevisionV1 {
        &self.revision
    }
}

/// Compiles an explicit parentless original input and prepares its V2 revision.
///
/// No layer is inferred from resolved Policy or user data. Existing constructors
/// and the full compiler own normalization, six layer fields, complete resource
/// ceilings, and grant intersection. The result is still nonauthoritative until
/// genuine independent owners and the protected publication barrier qualify it.
///
/// # Errors
///
/// Rejects a nonparentless input, compile failure, invalid revision, or an
/// encoded revision exceeding the unchanged publisher record limit.
pub fn compile_publisher_policy_revision_v2(
    input: &PolicyCompilerInputV1,
    generation: u64,
    not_before: i64,
    expires_at: i64,
) -> Result<CompiledPublisherPolicyRevisionV2, PublisherPolicyError> {
    let origin = derive_origin(input)?;
    let origin_bytes = origin.to_record_bytes()?.len();
    let mut revision = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        origin.project,
        generation,
        not_before,
        expires_at,
        origin.output_bytes()[0],
        DecodeLimits::default(),
    )?;
    revision.retain_compiler_origin(origin)?;
    // Account for policy bytes, origin bytes, framing, and the existing header.
    let size = 88usize
        .checked_add(revision.canonical_policy().len())
        .and_then(|size| size.checked_add(origin_bytes))
        .ok_or(PublisherPolicyError::LimitExceeded("policy revision bytes"))?;
    if size > MAXIMUM_BYTES + 128 {
        return Err(PublisherPolicyError::LimitExceeded("policy revision bytes"));
    }
    Ok(CompiledPublisherPolicyRevisionV2 { revision })
}

impl PublisherPolicyStore<'_> {
    /// Publishes actual compiler provenance in the existing revision/head CAS.
    ///
    /// This retains the trusted Controller administration contract of the V1
    /// store. It adds no installed input-owner or public Create authority.
    ///
    /// # Errors
    ///
    /// Rejects CAS, resource cross-link, capacity, protection, or commit errors
    /// exactly as the existing publisher revision transaction does.
    pub fn publish_compiled_policy_from_trusted_controller_v2(
        &mut self,
        transaction_id: [u8; 16],
        expected_generation: Option<u64>,
        prepared: &CompiledPublisherPolicyRevisionV2,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.publish_policy_from_trusted_controller(
            transaction_id,
            expected_generation,
            prepared.revision(),
        )
    }
}

fn derive_origin(
    input: &PolicyCompilerInputV1,
) -> Result<RetainedPublisherCompilerOriginV3, PublisherPolicyError> {
    if !input.ancestors().is_empty() {
        return Err(PublisherPolicyError::InvalidPolicyRevision);
    }
    let candidate = PolicyCompilerV1::compile_retained(input)
        .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
    retain_derivation(input, &candidate)
}

fn retain_derivation(
    input: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
) -> Result<RetainedPublisherCompilerOriginV3, PublisherPolicyError> {
    if !input.ancestors().is_empty() {
        return Err(PublisherPolicyError::InvalidPolicyRevision);
    }
    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
    let full_input = canonical_bytes(INPUT_DOMAIN, input)
        .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)?;
    let output = candidate.portable();
    let origin = RetainedPublisherCompilerOriginV3 {
        project: input.project().project(),
        original_target: input.sandbox(),
        normalized_input,
        candidate: candidate.commitment().digest(),
        plans: candidate.commitment_preimage().digests(),
        fields: [
            full_input,
            input.project().canonical_bytes().to_vec(),
            input.request().canonical_bytes().to_vec(),
            output.policy_bytes().to_vec(),
            output.optimization_bytes().to_vec(),
            output.namespace_graph_bytes().to_vec(),
            output.advisory_program_bytes().to_vec(),
        ],
    };
    origin.to_record_bytes()?;
    Ok(origin)
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PublisherPolicyError> {
    let end = offset
        .checked_add(N)
        .ok_or(PublisherPolicyError::CorruptState)?;
    bytes
        .get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PublisherPolicyError::CorruptState)
}
