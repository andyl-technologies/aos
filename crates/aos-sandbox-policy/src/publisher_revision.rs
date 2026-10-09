//! Owns checked canonical publisher revisions and retained compiler provenance DATA.
//! It creates no native compiled revision, current admission, Journal loan or publication authority.

use aos_sandbox_core::format::{decode_policy, encode_policy};
use aos_sandbox_core::model::{CacheDomainKind, Policy};
use aos_sandbox_core::{DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest,
    PortableMediaType, ProjectId, SandboxId, descriptor_for_bytes, validate_required_features};
use sha2::{Digest as _, Sha256};
use crate::{canonical_bytes, compiled_policy_candidate_digest_v1,
    CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1};

const MAXIMUM_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_COLLECTION_ITEMS: usize = 1_024;
const MAXIMUM_TOTAL_ITEMS: usize = 65_536;
const MAXIMUM_STRING_BYTES: usize = 64 * 1024;
const MAXIMUM_DEPTH: usize = 64;

/// Reports invalid checked revision or retained provenance DATA.
#[derive(Debug, thiserror::Error)]
pub enum PublisherPolicyDataError {
    /// A bounded dimension was exceeded.
    #[error("publisher policy limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Canonical policy bytes or revision metadata are invalid.
    #[error("publisher policy revision is invalid")]
    InvalidPolicyRevision,
    /// Retained provenance framing or links are invalid.
    #[error("publisher policy namespace is corrupt")]
    CorruptState,
}

/// Reports sentinel identities/descriptors or unrepresentable normalized input.
#[derive(Debug, thiserror::Error)]
#[error("compiled policy publication is noncanonical")]
pub struct NormalizedPolicyInputErrorV1;

/// Freezes one bounded canonical resolved policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPublisherPolicyRevisionV1 {
    project: ProjectId,
    generation: u64,
    not_before: i64,
    expires_at: i64,
    policy: Policy,
    descriptor: ObjectDescriptor,
    canonical_policy: Vec<u8>,
    compiler_origin: Option<RetainedPublisherCompilerOriginV3>,
}

impl PreparedPublisherPolicyRevisionV1 {
    /// Decodes and freezes controller-resolved canonical policy bytes.
    ///
    /// Caller limits are clamped to publisher-policy hard ceilings before the
    /// core decoder allocates or performs normalized grant validation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyDataError`] for a zero project or generation, an
    /// invalid interval, oversized or malformed policy, non-project cache
    /// domain, or noncanonical bytes.
    pub fn from_canonical_bytes(
        project: ProjectId,
        generation: u64,
        not_before: i64,
        expires_at: i64,
        canonical_policy: &[u8],
        requested_limits: DecodeLimits,
    ) -> Result<Self, PublisherPolicyDataError> {
        if project.as_bytes() == &[0; 16] || generation == 0 || not_before >= expires_at {
            return Err(PublisherPolicyDataError::InvalidPolicyRevision);
        }
        if canonical_policy.len() > MAXIMUM_POLICY_BYTES {
            return Err(PublisherPolicyDataError::LimitExceeded("policy bytes"));
        }
        let policy = decode_policy(canonical_policy, bounded_decode_limits(requested_limits))
            .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
        validate_required_features(policy.required_features())
            .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
        for limit in policy.limits().limits() {
            validate_required_features(std::slice::from_ref(limit.enforcement()))
                .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
        }
        if policy.cache_domain().kind() != CacheDomainKind::Project
            || policy.cache_domain().domain_id().as_bytes() == &[0; 16]
            || encode_policy(&policy) != canonical_policy
        {
            return Err(PublisherPolicyDataError::InvalidPolicyRevision);
        }
        let canonical_policy = canonical_policy.to_vec();
        let descriptor = descriptor_for_bytes(policy_media_type()?, &canonical_policy);
        Ok(Self {
            project,
            generation,
            not_before,
            expires_at,
            policy,
            descriptor,
            canonical_policy,
            compiler_origin: None,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the contiguous policy generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the inclusive policy start time.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    /// Returns the exclusive policy expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the normalized policy.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Returns the exact canonical policy descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns exact canonical policy bytes.
    #[must_use]
    pub fn canonical_policy(&self) -> &[u8] {
        &self.canonical_policy
    }

    /// Returns retained compiler provenance data, when the revision is V2.
    ///
    /// The decoded value is not authenticated input or live publication
    /// authority. Legacy resolved-policy revisions intentionally return `None`.
    #[must_use]
    pub const fn compiler_origin(
        &self,
    ) -> Option<&RetainedPublisherCompilerOriginV3> {
        self.compiler_origin.as_ref()
    }

    pub fn retain_compiler_origin(
        &mut self,
        origin: RetainedPublisherCompilerOriginV3,
    ) -> Result<(), PublisherPolicyDataError> {
        if origin.project() != self.project
            || origin.output_bytes()[0] != self.canonical_policy.as_slice()
        {
            return Err(PublisherPolicyDataError::InvalidPolicyRevision);
        }
        self.compiler_origin = Some(origin);
        Ok(())
    }
}

fn bounded_decode_limits(requested: DecodeLimits) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: requested.maximum_bytes.min(MAXIMUM_POLICY_BYTES),
        maximum_collection_items: requested
            .maximum_collection_items
            .min(MAXIMUM_COLLECTION_ITEMS),
        maximum_total_items: requested.maximum_total_items.min(MAXIMUM_TOTAL_ITEMS),
        maximum_byte_string_bytes: requested
            .maximum_byte_string_bytes
            .min(MAXIMUM_STRING_BYTES),
        maximum_text_bytes: requested.maximum_text_bytes.min(MAXIMUM_STRING_BYTES),
        maximum_depth: requested.maximum_depth.min(MAXIMUM_DEPTH),
    }
}

fn policy_media_type() -> Result<MediaType, PublisherPolicyDataError> {
    MediaType::new(
        aos_sandbox_core::PortableMediaType::Policy
            .as_str()
            .to_owned(),
    )
    .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)
}

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
    pub fn output_descriptors(&self) -> Result<[ObjectDescriptor; 4], PublisherPolicyDataError> {
        let media = [
            PortableMediaType::Policy,
            PortableMediaType::Optimization,
            PortableMediaType::Content,
            PortableMediaType::Content,
        ];
        let outputs = self.output_bytes();
        let [policy, optimization, namespace, advisory] =
            std::array::from_fn(|index| -> Result<_, PublisherPolicyDataError> {
                let kind = media[index];
                let bytes = outputs[index];
                let media = MediaType::new(kind.as_str())
                    .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
                Ok(descriptor_for_bytes(media, bytes))
            });
        Ok([policy?, optimization?, namespace?, advisory?])
    }

    /// Computes the complete retained origin digest, including original target.
    ///
    /// # Errors
    ///
    /// Rejects an oversized retained record or inconsistent output commitments.
    pub fn record_digest(&self) -> Result<ObjectDigest, PublisherPolicyDataError> {
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
    ) -> Result<(), PublisherPolicyDataError> {
        if expected.project().project() != self.project
            || expected.sandbox() != self.original_target
            || !expected.ancestors().is_empty()
        {
            return Err(PublisherPolicyDataError::InvalidPolicyRevision);
        }
        let candidate = PolicyCompilerV1::compile_retained(expected)
            .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
        self.compare_compiled_derivation(expected, &candidate)
    }

    // Reuses an already freshly compiled candidate for compare-only consumers.
    // It does not authenticate model constructors or confer owner currentness.
    pub fn compare_compiled_derivation(
        &self,
        expected: &PolicyCompilerInputV1,
        candidate: &CompiledPolicyCandidateV1,
    ) -> Result<(), PublisherPolicyDataError> {
        let derived = retain_publisher_compiler_derivation_v3(expected, candidate)?;
        if &derived != self {
            return Err(PublisherPolicyDataError::InvalidPolicyRevision);
        }
        Ok(())
    }

    pub fn to_record_bytes(&self) -> Result<Vec<u8>, PublisherPolicyDataError> {
        self.validate_links()?;
        let size = self.fields.iter().try_fold(FIXED_BYTES, |size, field| {
            size.checked_add(4)
                .and_then(|size| size.checked_add(field.len()))
                .filter(|size| *size <= MAXIMUM_BYTES)
                .ok_or(PublisherPolicyDataError::LimitExceeded("compiler origin bytes"))
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
                .map_err(|_| PublisherPolicyDataError::LimitExceeded("compiler origin bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, PublisherPolicyDataError> {
        if bytes.len() < FIXED_BYTES || bytes.len() > MAXIMUM_BYTES || bytes.get(..8) != Some(MAGIC)
        {
            return Err(PublisherPolicyDataError::CorruptState);
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
                .ok_or(PublisherPolicyDataError::CorruptState)?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(PublisherPolicyDataError::CorruptState)?;
            *field = bytes[offset..end].to_vec();
            offset = end;
        }
        if offset != bytes.len() {
            return Err(PublisherPolicyDataError::CorruptState);
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

    fn validate_links(&self) -> Result<(), PublisherPolicyDataError> {
        if self.project.as_bytes() == &[0; 16]
            || self.original_target.as_bytes() == &[0; 16]
            || self.normalized_input.as_bytes() == &[0; 32]
            || self
                .plans
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
            || self.fields.iter().any(Vec::is_empty)
        {
            return Err(PublisherPolicyDataError::CorruptState);
        }
        let descriptors = self.output_descriptors()?;
        let candidate = compiled_policy_candidate_digest_v1(self.plans, descriptors.each_ref())
            .map_err(|_| PublisherPolicyDataError::CorruptState)?;
        let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            self.project,
            1,
            0,
            1,
            &self.fields[3],
            DecodeLimits::default(),
        )
        .map_err(|_| PublisherPolicyDataError::CorruptState)?;
        let input_media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| PublisherPolicyDataError::CorruptState)?;
        let project = descriptor_for_bytes(input_media.clone(), &self.fields[1]);
        let request = descriptor_for_bytes(input_media, &self.fields[2]);
        let inputs = policy.policy().input_commitments();
        if candidate != self.candidate
            || inputs.len() != 10
            || inputs.get(2) != Some(&project)
            || inputs.get(3) != Some(&request)
            || inputs.get(8) != Some(&descriptors[2])
            || inputs.get(9) != Some(&descriptors[3])
            || policy.policy().optimization_digest() != Some(&descriptors[1])
        {
            return Err(PublisherPolicyDataError::CorruptState);
        }
        Ok(())
    }
}

pub fn retain_publisher_compiler_derivation_v3(
    input: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
) -> Result<RetainedPublisherCompilerOriginV3, PublisherPolicyDataError> {
    if !input.ancestors().is_empty() {
        return Err(PublisherPolicyDataError::InvalidPolicyRevision);
    }
    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
    let full_input = canonical_bytes(INPUT_DOMAIN, input)
        .map_err(|_| PublisherPolicyDataError::InvalidPolicyRevision)?;
    let output = candidate.portable();
    let origin = RetainedPublisherCompilerOriginV3 {
        project: input.project().project(),
        original_target: input.sandbox(),
        normalized_input,
        candidate: candidate.commitment().digest(),
        plans: candidate.commitment_plan_digests(),
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

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PublisherPolicyDataError> {
    let end = offset
        .checked_add(N)
        .ok_or(PublisherPolicyDataError::CorruptState)?;
    bytes
        .get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PublisherPolicyDataError::CorruptState)
}

const NORMALIZED_INPUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.normalized-input.v1\0";

/// Computes the canonical normalized-input digest used by publication checks.
///
/// # Errors
///
/// Returns [`NormalizedPolicyInputErrorV1`] if an
/// input descriptor or target identity is sentinel-valued.
pub fn normalized_policy_input_digest_v1(
    input: &PolicyCompilerInputV1,
) -> Result<ObjectDigest, NormalizedPolicyInputErrorV1> {
    if input.sandbox().as_bytes() == &[0; 16] || input.project().project().as_bytes() == &[0; 16] {
        return Err(NormalizedPolicyInputErrorV1);
    }
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_INPUT_DOMAIN);
    hasher.update(input.sandbox().as_bytes());
    hasher.update(input.project().project().as_bytes());
    update_descriptor(&mut hasher, input.relation().descriptor())?;
    update_descriptor(&mut hasher, input.node().descriptor())?;
    update_descriptor(&mut hasher, input.site().descriptor())?;
    update_descriptor(&mut hasher, input.project().descriptor())?;
    for ancestor in input.ancestors() {
        update_descriptor(&mut hasher, ancestor.descriptor())?;
    }
    update_descriptor(&mut hasher, input.request().descriptor())?;
    update_descriptor(&mut hasher, input.endpoints().descriptor())?;
    update_descriptor(&mut hasher, input.destinations().descriptor())?;
    update_descriptor(&mut hasher, input.backend().descriptor())?;
    hasher.update(input.limits().work().to_be_bytes());
    hasher.update(input.limits().dag_depth().to_be_bytes());
    let rule_limit = u64::try_from(input.limits().rules())
        .map_err(|_| NormalizedPolicyInputErrorV1)?;
    hasher.update(rule_limit.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn update_descriptor(
    hasher: &mut Sha256,
    descriptor: &ObjectDescriptor,
) -> Result<(), NormalizedPolicyInputErrorV1> {
    if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() == 0 {
        return Err(NormalizedPolicyInputErrorV1);
    }
    hasher.update((descriptor.media_type().as_str().len() as u64).to_be_bytes());
    hasher.update(descriptor.media_type().as_str().as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    Ok(())
}
