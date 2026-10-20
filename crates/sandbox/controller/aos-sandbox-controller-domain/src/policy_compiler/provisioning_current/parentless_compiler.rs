//! Shares the sole selected inherited parentless layer/compiler recipe.
//!
//! Every caller independently joins actual native Controller/Source/Cache,
//! policy and enrollment owners and prepays typed work before this pure body.
//! Returned inputs/candidates are DATA, never currentness or issuance originals.

use std::error::Error;
use aos_sandbox_model::{CanonicalAssignmentManifestV1, ObjectDescriptor, ProjectId, SandboxId, MediaType};
use aos_sandbox_model::model::{CacheDomain, SandboxSpec};
use aos_sandbox_model::format::descriptor_for_bytes;
use aos_sandbox_policy::{AuthenticatedCacheDomainV1, AuthenticatedSandboxProjectRelationV1,
    CacheDomainBindingV1, CacheDomainVerifierV1, SandboxProjectRelationVerifierV1,
    PolicyCompilerInputV1, CompiledPolicyCandidateV1, PolicyCompilerV1};
use crate::journal::JournalError;
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use crate::policy_compiler::public_create_source::parentless_create_input_from_authenticated_layers_v1;

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
#[error("the freshly compiled parentless manifest differs")]
pub(super) struct RootParentlessComparisonChangedV1;

pub(crate) fn compile_parentless_current_v1(signed: &RootSignedProjectSourcesV1,
    project: ProjectId, sandbox: SandboxId, cache_domain: CacheDomain,
) -> Result<(PolicyCompilerInputV1, CompiledPolicyCandidateV1), Cause> {
    if signed.0.head().project() != project || signed.0.cache_domain() != cache_domain {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let verifier = FreshInputVerifierV1 {
        project,
        sandbox,
        cache_domain,
    };
    let domain = AuthenticatedCacheDomainV1::authenticate(
        cache_domain,
        CacheDomainBindingV1::Project(project),
        &verifier,
    )?;
    let layer = signed
        .0
        .q04_layer_recipe()
        .materialize_with_authenticated_binding(domain)
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let relation =
        AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)?;
    let input = parentless_create_input_from_authenticated_layers_v1(relation, layer, &signed.2)?;
    let candidate = PolicyCompilerV1::compile_retained(&input)?;
    Ok((input, candidate))
}

pub(in crate::policy_compiler) fn require_manifest_candidate_v1(assignment: &CanonicalAssignmentManifestV1,
    specification: &SandboxSpec, candidate: &CompiledPolicyCandidateV1,
) -> Result<(), Cause> {
    aos_sandbox_policy::require_specification_resource_profile_v1(
        specification.resource_profile(), candidate.hard_resources().core_profile())?;
    let manifest = assignment.manifest();
    let effective = candidate.portable().policy();
    let mut commitments = effective.input_commitments().to_vec();
    commitments.sort();
    commitments.dedup();
    let features = aos_sandbox_model::model::assignment_required_features_v1(effective, specification)?;
    if manifest.policy() != candidate.portable().policy_descriptor()
        || manifest.environment() != specification.environment()
        || manifest.root_view() != specification.root_view()
        || manifest.source_commitments() != commitments || manifest.required_features() != features
        || manifest.resource_commitment() != aos_sandbox_model::resource_profile_digest_v1(effective.limits())
        || manifest.reservations() != crate::policy_compiler::create_q04::candidate_capacity(candidate)?
    { return Err(RootParentlessComparisonChangedV1.into()); }
    Ok(())
}

struct FreshInputVerifierV1 { project: ProjectId, sandbox: SandboxId, cache_domain: CacheDomain }
impl CacheDomainVerifierV1 for FreshInputVerifierV1 {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical: &[u8]) -> bool {
        let expected = aos_sandbox_protocol::policy_data::canonical_bytes(
            b"aos.sandbox.cache-domain-binding.v2",
            &(self.cache_domain, CacheDomainBindingV1::Project(self.project)),
        )
        .map_err(aos_sandbox_policy::PolicyModelError::from);
        let Ok(expected) = expected else { return false; };
        let Ok(media) = MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str()) else { return false; };
        canonical == expected && descriptor_for_bytes(media, canonical) == *descriptor
    }
}
impl SandboxProjectRelationVerifierV1 for FreshInputVerifierV1 {
    fn verify(&self, sandbox: SandboxId, project: ProjectId,
        descriptor: &ObjectDescriptor, canonical: &[u8]) -> bool {
        let Ok(media) = MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str()) else { return false; };
        sandbox == self.sandbox && project == self.project
            && descriptor_for_bytes(media, canonical) == *descriptor
    }
}
