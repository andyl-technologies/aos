//! Recompiles current parentless Create inputs at Root's independent cut.
//!
//! The same paid Controller reader and Root policy journal supply current
//! publisher/signed heads. Fresh Source17 and independent Cache verification
//! stay live around the pure compiler. B remains complete comparison input.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, DecodeLimits, MediaType, ObjectDescriptor,
    PortableMediaType, ProjectId, ResourceDimension as D, ResourceVector, SandboxId,
};
use aos_sandbox_model::format::{decode_policy, decode_sandbox_spec, descriptor_for_bytes, sandbox_spec_media_type};
use aos_sandbox_model::model::{Policy, SandboxSpec};
use aos_sandbox_policy::{
    AuthenticatedCacheDomainV1, AuthenticatedSandboxProjectRelationV1, CacheDomainBindingV1,
    CacheDomainVerifierV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1,
    SandboxProjectRelationVerifierV1,
};
use aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    ready::ReadyBundleDataV1,
    source_current::SourceCurrentReplyFieldsV1,
    cache_held::current_proof::CacheCurrentProofBodyDataV1,
};

use crate::journal::{Journal, JournalError};
use crate::policy_compiler::create_q04::{Q04CutIdentityV1, Q04PreviewV1};
use crate::policy_compiler::public_create_source::{
    CurrentCreateProjectPolicySourceV1, current_parentless_create_project_source_v1,
    parentless_create_input_from_authenticated_layers_v1,
};
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use super::super::policy_inputs::RootCurrentPolicyInputDataV1;

type Error = Box<dyn StdError>;

#[derive(Debug, thiserror::Error)]
#[error("the current Root Create compiler input or complete assignment changed")]
struct Changed;

#[derive(Default)]
pub(super) struct RootCurrentCompiledPolicyV1 {
    result: Option<Result<RootCurrentCompiledValuesV1, Error>>,
    entered: bool,
    closed: bool,
}

// These successful originals remain resident through the existing independent
// Root/Controller names, native-position, peer and paired-clock afterposts.
struct RootCurrentCompiledValuesV1 {
    source: CurrentCreateProjectPolicySourceV1,
    signed: RootSignedProjectSourcesV1,
    publisher: Policy,
    specification: SandboxSpec,
    input: PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
    origin: RetainedPublisherCompilerOriginV3,
    publisher_expires_at: i64,
}

impl RootCurrentCompiledPolicyV1 {
    pub(super) fn observe_once(
        &mut self,
        controller: &mut Journal,
        root_policy: &Journal,
        policy_data: &RootCurrentPolicyInputDataV1<'_>,
        source_current: SourceCurrentReplyFieldsV1,
        cache_current: &CacheCurrentProofBodyDataV1,
        bundle: ReadyBundleDataV1<'_>,
        parent: &Q04CutIdentityV1,
        assignment: &CanonicalAssignmentManifestV1,
        now: i64,
    ) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.result = Some(compile_current(
            controller, root_policy, policy_data, source_current, cache_current,
            bundle, parent, assignment, now,
        ));
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(_))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn require_live_at_v1(&self, sample: aos_sandbox_model::RawPairedClockSample)
        -> Result<(), JournalError>
    {
        self.require_complete()?;
        let values = self.result.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= values.signed.0.head().expires_at()
            || sample.wall_seconds() >= values.signed.1.expires_at()
            || sample.wall_seconds() >= values.publisher_expires_at
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(super) fn expires_at_v1(&self) -> Result<i64, JournalError> {
        self.require_complete()?;
        let values = self.result.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(values.publisher_expires_at.min(values.signed.0.head().expires_at())
            .min(values.signed.1.expires_at()))
    }

    pub(super) fn candidate_v1(&self) -> Result<&CompiledPolicyCandidateV1, JournalError> {
        self.require_complete()?;
        self.result.as_ref().and_then(|result| result.as_ref().ok())
            .map(|values| &values.candidate).ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error.as_ref())
    }

    pub(super) fn additional_receiving_demand_v1(actual_encoded_bytes: u64)
        -> Result<ResourceVector, JournalError>
    {
        let invalid = || JournalError::JournalTooLarge;
        // Four complete eight-MiB output objects may coexist with compiler
        // construction, full-origin comparison and retained derived output.
        // Existing schemas retain their original caps; no input supplies them.
        let output = (aos_sandbox_protocol::policy_data::MAXIMUM_CANONICAL_OBJECT_BYTES as u64)
            .checked_mul(4).and_then(|bytes| bytes.checked_mul(4)).ok_or_else(invalid)?;
        let bytes = actual_encoded_bytes.checked_mul(64)
            .and_then(|bytes| bytes.checked_add(output))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootCurrentCompiledValuesV1>() as u64))
            .and_then(|bytes| bytes.checked_add(4096)).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OutputBytes, output))
    }
}

fn compile_current(
    controller: &mut Journal,
    root_policy: &Journal,
    policy_data: &RootCurrentPolicyInputDataV1<'_>,
    source_current: SourceCurrentReplyFieldsV1,
    cache_current: &CacheCurrentProofBodyDataV1,
    bundle: ReadyBundleDataV1<'_>,
    parent: &Q04CutIdentityV1,
    assignment: &CanonicalAssignmentManifestV1,
    now: i64,
) -> Result<RootCurrentCompiledValuesV1, Error> {
    // These existing consuming readers validate full public authorization,
    // exact idempotency key/acceptance revision, Desired and publisher history.
    // They only read this actual already-replayed readonly Journal.
    let source = current_parentless_create_project_source_v1(controller,
        parent.operation(), parent.sandbox())?;
    let publisher_expires_at = {
        let store = crate::publisher_admin::policy::PublisherPolicyStore::load(controller,
            crate::publisher_admin::policy::PublisherPolicyLimits::default())?;
        store.current_policy(source.project())?.ok_or(Changed)?.expires_at()
    };
    let preview = Q04PreviewV1::decode(bundle.policy_sources, parent.nonce())?;
    policy_data.require_preview_data_v1(preview.fields())?;
    let signed = policy_data.verify_current_sources_v1(root_policy, now)?;
    let publisher = decode_policy(source.canonical_policy(), DecodeLimits::default())?;
    let (project, deployment_head, deployment) = &signed;
    let project_head = project.head();
    if source.operation_revision() != parent.operation_revision()
        || source.accepted_generation() != parent.accepted_generation()
        || source.projection_revision() != parent.desired_precondition()
        || source.project().as_bytes() != &source_current.project
        || source.sandbox().as_bytes() != &source_current.sandbox
        || source.commitment().as_bytes() != &source_current.controller_source
        || parent.ancestry().as_bytes() != &source_current.tree_head
        || project_head.project() != source.project()
        || project_head.publisher_generation() != source.policy_generation()
        || project_head.publisher_digest() != source.policy_digest()
        || project.cache_domain() != source.cache_domain()
        || project.revocation() != publisher.revocation()
        || project_head.prerequisite_claims() != [
            aos_sandbox_model::ObjectDigest::from_bytes(source_current.tree_head),
            deployment_head.packet_digest(), source.cache_domain_head(), source.revocation_head(),
        ]
        || now >= project_head.expires_at() || now >= deployment_head.expires_at()
        || !deployment.endpoints().entries().is_empty()
        || !deployment.destinations().entries().is_empty()
        || cache_current.snapshot.association.project != *source.project().as_bytes()
        || cache_current.snapshot.association.sandbox != *source.sandbox().as_bytes()
    {
        return Err(Changed.into());
    }

    let verifier = RootCurrentInputVerifierV1 {
        source: &source,
        fresh_source: source_current,
        cache: cache_current,
    };
    let domain = AuthenticatedCacheDomainV1::authenticate(
        project.cache_domain(),
        CacheDomainBindingV1::Project(source.project()),
        &verifier,
    )?;
    let layer = project
        .q04_layer_recipe()
        .materialize_with_authenticated_binding(domain)
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let relation = AuthenticatedSandboxProjectRelationV1::authenticate(
        source.sandbox(), source.project(), &verifier)?;
    let input = parentless_create_input_from_authenticated_layers_v1(relation, layer, deployment)?;
    let candidate = PolicyCompilerV1::compile_retained(&input)?;
    let origin = RetainedPublisherCompilerOriginV3::from_record_bytes(bundle.compiler_origin)?;
    aos_sandbox_policy::compare_publisher_compiler_derivation_v3(&origin, &input, &candidate)?;
    if origin.project() != parent.project() || origin.original_target() != parent.sandbox()
        || origin.candidate().as_bytes() != &parent.bytes()[488..520]
    { return Err(Changed.into()); }

    let specification = decode_sandbox_spec(bundle.specification, DecodeLimits::default())?;
    aos_sandbox_policy::require_specification_resource_profile_v1(
        specification.resource_profile(), candidate.hard_resources().core_profile(),
    )?;
    let media = MediaType::new(sandbox_spec_media_type(&specification).as_str())?;
    let spec_descriptor = descriptor_for_bytes(media, bundle.specification);
    let manifest = assignment.manifest();
    let policy = candidate.portable().policy();
    let mut commitments = policy.input_commitments().to_vec();
    commitments.sort();
    commitments.dedup();
    let features = aos_sandbox_model::model::assignment_required_features_v1(policy, &specification)?;
    if manifest.sandbox_spec() != &spec_descriptor || manifest.policy() != candidate.portable().policy_descriptor()
        || manifest.environment() != specification.environment()
        || manifest.root_view() != specification.root_view()
        || manifest.source_commitments() != commitments
        || manifest.required_features() != features
        || manifest.resource_commitment() != aos_sandbox_model::resource_profile_digest_v1(policy.limits())
        || manifest.reservations() != crate::policy_compiler::create_q04::candidate_capacity(&candidate)?
    { return Err(Changed.into()); }
    Ok(RootCurrentCompiledValuesV1 { source, signed, publisher, specification, input, candidate, origin,
        publisher_expires_at })
}

// This private view can be created only inside the complete joined consumer.
// It borrows the actual current Controller publisher observation and the fresh
// independently verified Source/Cache results. It exposes no factory or grant.
struct RootCurrentInputVerifierV1<'current> {
    source: &'current CurrentCreateProjectPolicySourceV1,
    fresh_source: SourceCurrentReplyFieldsV1,
    cache: &'current CacheCurrentProofBodyDataV1,
}

impl CacheDomainVerifierV1 for RootCurrentInputVerifierV1<'_> {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical: &[u8]) -> bool {
        let expected = aos_sandbox_protocol::policy_data::canonical_bytes(
            b"aos.sandbox.cache-domain-binding.v2",
            &(self.source.cache_domain(), CacheDomainBindingV1::Project(self.source.project())),
        )
        .map_err(aos_sandbox_policy::PolicyModelError::from);
        let Ok(expected) = expected else { return false; };
        let Ok(media) = MediaType::new(PortableMediaType::Content.as_str()) else { return false; };
        canonical == expected && descriptor_for_bytes(media, canonical) == *descriptor
            && self.cache.snapshot.association.project == *self.source.project().as_bytes()
            && self.cache.snapshot.association.sandbox == *self.source.sandbox().as_bytes()
    }
}

impl SandboxProjectRelationVerifierV1 for RootCurrentInputVerifierV1<'_> {
    fn verify(&self, sandbox: SandboxId, project: ProjectId,
        descriptor: &ObjectDescriptor, canonical: &[u8]) -> bool
    {
        let Ok(media) = MediaType::new(PortableMediaType::Content.as_str()) else { return false; };
        sandbox == self.source.sandbox() && project == self.source.project()
            && self.fresh_source.sandbox == *sandbox.as_bytes()
            && self.fresh_source.project == *project.as_bytes()
            && self.fresh_source.controller_source == *self.source.commitment().as_bytes()
            && descriptor_for_bytes(media, canonical) == *descriptor
    }
}
