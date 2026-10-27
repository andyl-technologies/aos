//! Query-time canonical project-policy source for a parentless public Create.
//!
//! The controller journal already retains the exact canonical publisher
//! revision bytes. This join checks the live admitted operation, its current
//! sandbox projection, and the publisher's current revision in one protected
//! journal claim. It is a source observation, not a compiler layer or a
//! durable AOSPCB01 binding.
//!
//! The closed input precursor combines that observation with signed Root
//! sources as proposal DATA only; publication still requires its own join.

use aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldCodecV1;

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    VerifiedSignedProjectPolicySourceV2, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v2,
};

use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_model::model::CacheDomain;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use aos_sandbox_cache::{CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1, CurrentProjectPhysicalCacheHeadV1};
#[cfg(target_os = "linux")]
use aos_sandbox_cache::{CacheResidencyWriterReadbackV2, DormantCacheOwnerV1};
use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::public_projection::PublicProjectionStoreV1;
use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalOwnerV1,
};
#[cfg(target_os = "linux")]
use crate::journal::controller::production_journal_limits;
#[cfg(target_os = "linux")]
use crate::journal::{ControllerPolicyHoldV1, ControllerPolicyV8ReleaseEvidenceV1};
#[cfg(target_os = "linux")]
use crate::protected_domain_journal::ProtectedDomainJournalErrorV1;
use crate::publisher_admin::policy::{
    PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore,
};
use crate::reconciler::{
    ReconcilerError, checked_live_create_sandbox_admission_revision_v1,
    live_create_sandbox_admission_revision_v1, recovered_public_operation_admission_v1,
};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::{Journal, JournalError};
use aos_sandbox_protocol::domain_ledger::effect_history::EffectPlan;
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1,
};

#[cfg(target_os = "linux")]
use super::PolicyDeploymentHeadErrorV1;
use super::{
    AdmittedSignedProjectPolicySourceV2, PolicyPublicationPrerequisitesV1, RootV8ReleasedProofV1,
    normalized_policy_input_digest_v1,
};
#[cfg(target_os = "linux")]
use aos_sandbox_policy::{
    HardResourceModelError, PolicyModelError,
};
use aos_sandbox_policy::{
    CacheDomainInputV1, HardLimitValueV1, PolicyCompilerInputV1, RevocationInputV1,
};

/// Brands only the pair selected by the private current-Create producer.
fn relation_from_current_create_source(
    source: &CurrentCreateProjectPolicySourceV1,
) -> Result<
    aos_sandbox_policy::AuthenticatedSandboxProjectRelationV1,
    aos_sandbox_policy::PolicyModelError,
> {
    aos_sandbox_policy::AuthenticatedSandboxProjectRelationV1::authenticate(
        source.sandbox(),
        source.project(),
        &CurrentCreateRelationVerifierV1 { source },
    )
}

// Only the current-Create producer selects this verifier, after reading the
// actual protected Controller journal. The input remains nonauthoritative.
struct CurrentCreateRelationVerifierV1<'source> {
    source: &'source CurrentCreateProjectPolicySourceV1,
}

impl aos_sandbox_policy::SandboxProjectRelationVerifierV1 for CurrentCreateRelationVerifierV1<'_> {
    fn verify(
        &self,
        sandbox: SandboxId,
        project: ProjectId,
        descriptor: &aos_sandbox_model::ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> bool {
        let Ok(media) =
            aos_sandbox_model::MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str())
        else {
            return false;
        };

        sandbox == self.source.sandbox()
            && project == self.source.project()
            && !canonical_bytes.is_empty()
            && aos_sandbox_model::format::descriptor_for_bytes(media, canonical_bytes) == *descriptor
    }
}

pub(crate) use aos_sandbox_protocol::domain_ledger::project_source::{
    HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
};

mod current_publisher;
pub(in crate::policy_compiler) use current_publisher::{
    CurrentPublisherPolicyDataErrorV2, CurrentPublisherPolicyDataV2,
    current_publisher_policy_data_v2,
};


#[cfg(target_os = "linux")]
mod first_successor_ancestry;
#[cfg(target_os = "linux")]
mod gen1_ancestry;
#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) use first_successor_ancestry::consume_completed_first_successor_ancestry_v2;
pub(in crate::policy_compiler) use first_successor_ancestry::consume_completed_project_successor_ancestry_v3;
#[cfg(target_os = "linux")]
pub(crate) use gen1_ancestry::consume_completed_gen1_ancestry_v1;
pub(crate) use gen1_ancestry::consume_completed_project_genesis_ancestry_v3;

/// Reports a failed protected public-Create source join.
#[derive(Debug, thiserror::Error)]
pub enum CurrentCreatePolicySourceErrorV1 {
    /// The selected public operation or projection is absent or mismatched.
    #[error("public Create source is not current")]
    NotCurrent,
    /// The protected controller journal is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The public operation could not be validated.
    #[error(transparent)]
    Operation(#[from] ReconcilerError),
    /// The public projection could not be validated.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// The publisher policy namespace could not be validated.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
    /// The independent physical Cache owner could not establish currentness.
    #[error(transparent)]
    Cache(#[from] CacheResidencyProtectedJournalErrorV1),
    /// The held Controller or Source transaction rejected the upper barrier.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Protected(#[from] ProtectedDomainJournalErrorV1),
    /// The independent source-domain ancestry owner could not establish currentness.
    #[error(transparent)]
    Hierarchy(HierarchyProtectedJournalErrorV1),
}

/// Reports failure to construct nonauthorizing current-Create compiler input.
///
/// The original source, signed-layer and model causes remain typed. This error
/// does not classify Root stage issuance or release any owner custody.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum CurrentCreateCompilerInputErrorV1 {
    /// The original Controller source or fixed journal changed or is unavailable.
    #[error(transparent)]
    Source(#[from] CurrentCreatePolicySourceErrorV1),
    /// Signed project choices do not match protected current publisher state.
    #[error(transparent)]
    Project(#[from] PolicyDeploymentHeadErrorV1),
    /// The sole model constructor rejected input or canonical relation bytes.
    #[error(transparent)]
    Model(#[from] PolicyModelError),
    /// The complete inherited request profile could not be constructed.
    #[error(transparent)]
    Resources(#[from] HardResourceModelError),
}

#[cfg(target_os = "linux")]
impl From<aos_sandbox_policy::parentless_input::ParentlessPolicyInputDataErrorV1>
    for CurrentCreateCompilerInputErrorV1
{
    fn from(error: aos_sandbox_policy::parentless_input::ParentlessPolicyInputDataErrorV1) -> Self {
        use aos_sandbox_policy::parentless_input::ParentlessPolicyInputDataErrorV1;

        match error {
            ParentlessPolicyInputDataErrorV1::Model(error) => Self::Model(error),
            ParentlessPolicyInputDataErrorV1::Resources(error) => Self::Resources(error),
        }
    }
}

/// Carries a read-only snapshot of two independent heads at one held cut.
///
/// The value cannot authorize publication once the held writer callback ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentCreatePolicyBarrierHeadsV2 {
    ancestry: ObjectDigest,
    physical_partition: ObjectDigest,
    physical_cache: ObjectDigest,
}

impl CurrentCreatePolicyBarrierHeadsV2 {
    // The original completed flight and complete Cache Prepare replay are
    // borrowed here. The returned heads remain comparison DATA, not a new
    // currentness producer or a substitute for either held owner.
    #[cfg(target_os = "linux")]
    pub(super) fn from_original_q04_prepare(
        controller: &crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1<'_>,
        source: &crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1<'_>,
        inventory: &crate::hierarchy::protected_journal::RetainedTreeInventoryDataV1<'_>,
        root: &super::source_genesis_root::CompletedRootSourceGenesisFloorV1<'_, '_>,
        cache: &aos_sandbox_cache::Q04CachePrepareReadbackV1,
    ) -> Result<Self, super::create_q04::CreateQ04ErrorV1> {
        consume_completed_gen1_ancestry_v1(controller, source, inventory, root)?;
        let selected = cache.selected();
        if selected.project() != root.floor().project() {
            return Err(super::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        let result = Self {
            ancestry: root.floor().tree_head(),
            physical_partition: selected.partition().digest(),
            physical_cache: selected.head(),
        };
        consume_completed_gen1_ancestry_v1(controller, source, inventory, root)?;
        Ok(result)
    }

    /// Returns the current protected source-domain ancestry head.
    #[must_use]
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the selected complete physical Cache partition commitment.
    #[must_use]
    pub const fn physical_partition(self) -> ObjectDigest {
        self.physical_partition
    }

    /// Returns the current protected physical Cache replay head.
    #[must_use]
    pub const fn physical_cache(self) -> ObjectDigest {
        self.physical_cache
    }
}

aos_sandbox_protocol::define_current_create_project_source_model_v1!(CurrentCreateProjectPolicySourceV1, pub(crate));

impl CurrentCreateProjectPolicySourceV1 {
    #[cfg(target_os = "linux")]
    pub(super) fn q04_proposal_fields<'fields>(
        &'fields self,
        heads: &'fields CurrentCreatePolicyBarrierHeadsV2,
    ) -> super::binding_v2::ClosedCreateProposalFieldViewV2<'fields> {
        super::binding_v2::ClosedCreateProposalFieldViewV2 {
            source_commitment: &self.commitment,
            operation: &self.operation,
            operation_revision: &self.operation_revision,
            accepted_generation: &self.accepted_generation,
            sandbox: &self.sandbox,
            project: &self.project,
            projection_revision: &self.projection_revision,
            publisher_generation: &self.policy_generation,
            publisher_head: &self.policy_digest,
            cache_domain_head: &self.cache_domain_head,
            revocation_head: &self.revocation_head,
            ancestry: &heads.ancestry,
            physical_partition: &heads.physical_partition,
            physical_cache: &heads.physical_cache,
        }
    }
}


/// Checks a parentless Create draft against an admitted explicit V2 source.
///
/// This read-only draft is not a publication decision. The issuer must still
/// hold all independent owners through root CAS and recoverable effect handoff.
///
/// # Errors
///
/// Rejects a stale or substituted source, compiler input, prerequisite tuple,
/// or a request that supplies its own authority-bearing policy choices.
pub fn checked_parentless_create_policy_draft_v2(
    source: &CurrentCreateProjectPolicySourceV1,
    signed_project: &AdmittedSignedProjectPolicySourceV2,
    deployment: &PolicyDeploymentSourcesV1,
    input: &PolicyCompilerInputV1,
    prerequisites: &PolicyPublicationPrerequisitesV1,
    now_unix_seconds: i64,
) -> Result<ObjectDigest, CurrentCreatePolicySourceErrorV1> {
    let project_head = signed_project.head();
    let claimed_heads = project_head.prerequisite_claims();
    let current_domain = match signed_project.layer().cache_domain() {
        CacheDomainInputV1::Exact(binding) => binding.domain(),
        CacheDomainInputV1::Inherit => return Err(CurrentCreatePolicySourceErrorV1::NotCurrent),
    };
    if project_head.project() != source.project
        || project_head.publisher_generation() != source.policy_generation
        || project_head.publisher_digest() != source.policy_digest
        || now_unix_seconds >= project_head.expires_at()
        || current_domain != source.cache_domain
        || !matches!(
            signed_project.layer().revocation(),
            RevocationInputV1::Exact(_)
        )
        || claimed_heads
            != [
                prerequisites.ancestry_head(),
                prerequisites.compiler_authority_head(),
                prerequisites.cache_domain_head(),
                prerequisites.revocation_head(),
            ]
        || prerequisites.revocation_head() != source.revocation_head
        || prerequisites.cache_domain_head() != source.cache_domain_head
        || input.sandbox() != source.sandbox
        || input.project().project() != source.project
        || input.project().layer() != signed_project.layer()
        || input.node() != deployment.node()
        || input.site() != deployment.site()
        || input.backend() != deployment.backend()
        || !input.ancestors().is_empty()
        || !input.endpoints().entries().is_empty()
        || !input.destinations().entries().is_empty()
        || !request_is_inherited(input)
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    Ok(aos_sandbox_policy::parentless_input::parentless_explicit_draft_digest_v2(
        source.commitment,
        project_head.packet_digest(),
        project_head.input_digest(),
        prerequisites.digest(),
        normalized_input,
    ))
}

/// Checks an inert V2 draft from a signed but not independently admitted source.
///
/// This permits the controller to hand a root receipt into a closed proposal
/// while holding its local writers. The receipt is not protected project
/// admission, and neither this digest nor a closed root CAS grants publication.
///
/// # Errors
///
/// Rejects changed Create, signed prerequisite, or compiler-input choices.
pub fn checked_parentless_create_verified_policy_draft_v2(
    source: &CurrentCreateProjectPolicySourceV1,
    signed_project: &VerifiedSignedProjectPolicySourceV2,
    deployment: &PolicyDeploymentSourcesV1,
    input: &PolicyCompilerInputV1,
    prerequisites: &PolicyPublicationPrerequisitesV1,
    now_unix_seconds: i64,
) -> Result<ObjectDigest, CurrentCreatePolicySourceErrorV1> {
    let project_head = signed_project.head();
    if project_head.project() != source.project
        || project_head.publisher_generation() != source.policy_generation
        || project_head.publisher_digest() != source.policy_digest
        || now_unix_seconds >= project_head.expires_at()
        || signed_project.cache_domain() != source.cache_domain
        || project_head.prerequisite_claims()
            != [
                prerequisites.ancestry_head(),
                prerequisites.compiler_authority_head(),
                prerequisites.cache_domain_head(),
                prerequisites.revocation_head(),
            ]
        || prerequisites.cache_domain_head() != source.cache_domain_head
        || prerequisites.revocation_head() != source.revocation_head
        || input.sandbox() != source.sandbox
        || input.project().project() != source.project
        || !signed_project.matches_candidate_layer(input.project().layer())
        || input.node() != deployment.node()
        || input.site() != deployment.site()
        || input.backend() != deployment.backend()
        || !input.ancestors().is_empty()
        || !input.endpoints().entries().is_empty()
        || !input.destinations().entries().is_empty()
        || !request_is_inherited(input)
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    Ok(aos_sandbox_policy::parentless_input::parentless_explicit_draft_digest_v2(
        source.commitment,
        project_head.packet_digest(),
        project_head.input_digest(),
        prerequisites.digest(),
        normalized_input,
    ))
}

fn request_is_inherited(input: &PolicyCompilerInputV1) -> bool {
    let layer = input.request().layer();
    layer.grants().is_empty()
        && layer.namespace_rules().is_empty()
        && layer.advisory_actions().is_empty()
        && matches!(layer.cache_domain(), CacheDomainInputV1::Inherit)
        && matches!(layer.revocation(), RevocationInputV1::Inherit)
        && layer
            .resources()
            .portable()
            .iter()
            .chain(layer.resources().accounting())
            .all(|limit| limit.value() == HardLimitValueV1::Inherit)
}

/// Selects an admitted parentless Create by operation and project.
///
/// Exactly one durable Sandbox projection must name this operation. The
/// configured controller request scope and retained effect plan must match
/// the immutable admission digest. The selected identity is then rejoined to
/// current publisher policy under the same Controller writer. This is not a
/// held four-owner or Root decision.
///
/// # Errors
///
/// Returns an error for unsafe journal authority, mismatched scoped effect or
/// operation/projection/policy, missing project revocation binding, parented
/// Create, expired current policy, or noncanonical protected state.
pub fn current_parentless_create_project_source_for_operation_v1(
    journal: &mut Journal,
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
) -> Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1> {
    journal.ensure_protected_authority()?;
    let (revision, generation) =
        checked_live_create_sandbox_admission_revision_v1(journal, operation, scope, effect_plan)?
            .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let (sandbox, projection_revision) = PublicProjectionStoreV1::new(journal)
        .one_parentless_create_sandbox(operation, project)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let context = effect_plan
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(request) =
        context.validated_request().map_err(ReconcilerError::from)?
    else {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    };
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let PublicProjectionResourceV1::Sandbox(resource) = projection.resource() else {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    };
    let desired = resource
        .desired
        .as_option()
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if !request.parent_sandbox_id.is_empty()
        || request.project_id.as_slice() != project.as_bytes()
        || desired.specification.as_option() != request.specification.as_option()
        || desired.requested_policy.as_option() != request.requested_policy.as_option()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    let source = current_parentless_create_project_source_v1(journal, operation, sandbox)?;
    if source.project() != project
        || source.projection_revision() != projection_revision
        || source.operation_revision() != revision
        || source.accepted_generation() != generation
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(source)
}

/// Joins one parentless public Create to exact current canonical policy bytes.
///
/// The caller supplies an independently selected Sandbox identity. A production
/// effect should use [`current_parentless_create_project_source_for_operation_v1`]
/// to recover that identity from the admitted projection instead of guessing it.
/// The publisher policy is a resolved core policy, not a `PolicyLayerV1`;
/// this function cannot establish project/request/ancestor layer provenance.
///
/// # Errors
///
/// Returns an error for unsafe journal authority, missing or mismatched
/// operation/projection/policy, missing project revocation binding, parented
/// Create, expired current policy, or noncanonical protected state.
pub fn current_parentless_create_project_source_v1(
    journal: &mut Journal,
    operation: OperationId,
    sandbox: SandboxId,
) -> Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1> {
    current_parentless_create_project_source_with_observed_wall_v1(
        journal, operation, sandbox, None,
    )
}

pub(in crate::policy_compiler) fn current_parentless_create_project_source_with_observed_wall_v1(
    journal: &mut Journal,
    operation: OperationId,
    sandbox: SandboxId,
    observed_wall: Option<i64>,
) -> Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1> {
    aos_sandbox_protocol::current_parentless_create_project_source_recipe_v1!(
        rows = journal.historical_read_view_v1().rows_data_v2(),
        operation = operation, sandbox = sandbox, observed_wall = observed_wall,
        protected = { journal.ensure_protected_authority()?; },
        retained_protected = { journal.ensure_protected_authority().map_err(ReconcilerError::from)?; },
        projection_healthy = { journal.ensure_healthy().map_err(|_| aos_sandbox_protocol::public_api::projection::PublicProjectionError::CorruptRecord)?; },
        publisher_protected = { journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?; },
        outputs = (operation_revision, accepted_generation, project, projection_revision, policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, commitment)
    );
    Ok(CurrentCreateProjectPolicySourceV1 { operation, operation_revision, accepted_generation, sandbox, project, projection_revision, policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, commitment })
}

/// Selects current Create comparison inputs through their genuine read owner.
///
/// The same canonical recipe retains every original protected, projection and
/// Publisher check at its original frontier. This creates no Source owner,
/// current native permission or signed-input acceptance from historical DATA.
pub(in crate::policy_compiler) fn current_parentless_create_project_source_from_observation_v2(
    original: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    operation: OperationId,
    sandbox: SandboxId,
    observed_wall: Option<i64>,
) -> Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1> {
    aos_sandbox_protocol::current_parentless_create_project_source_recipe_v1!(
        rows = original.rows_data_v2(),
        operation = operation, sandbox = sandbox, observed_wall = observed_wall,
        protected = { original.ensure_protected_authority()?; },
        retained_protected = { original.ensure_protected_authority().map_err(ReconcilerError::from)?; },
        projection_healthy = { original.ensure_healthy().map_err(|_| aos_sandbox_protocol::public_api::projection::PublicProjectionError::CorruptRecord)?; },
        publisher_protected = { original.ensure_protected_authority().map_err(PublisherPolicyError::from)?; },
        outputs = (operation_revision, accepted_generation, project, projection_revision, policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, commitment)
    );
    Ok(CurrentCreateProjectPolicySourceV1 {
        operation, operation_revision, accepted_generation, sandbox, project,
        projection_revision, policy_generation, policy_digest, cache_domain,
        cache_domain_head, revocation_scope, revocation_generation, revocation_head,
        canonical_policy, commitment,
    })
}

/// Prices the new actual-owner interface without charging a Journal constructor.
pub(in crate::policy_compiler) fn current_parentless_observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    use crate::journal::historical_observation::HistoricalObservationV1;

    size_of::<(HistoricalObservationV1<'_>, OperationId, SandboxId, Option<i64>)>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<CurrentCreateProjectPolicySourceV1, CurrentCreatePolicySourceErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ReconcilerError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), PublisherPolicyError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), aos_sandbox_protocol::public_api::projection::PublicProjectionError>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

/// Rechecks the fixed Controller journal for the current-Create input precursor.
///
/// This uses the original writer's retained owner, fixed directory and names,
/// and exact production journal limits. It returns no owner identity, permit,
/// source snapshot or Root authority; accepted Create and publisher checks are
/// separate steps in the input producer.
///
/// # Errors
///
/// Rejects an unprotected or unhealthy writer, wrong production limits, or
/// changed fixed directory, journal or lock names and protected file metadata.
#[cfg(target_os = "linux")]
pub fn validate_current_create_controller_journal_v1(
    journal: &Journal,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let controller_uid = journal.protected_owner_uid()?;
    journal.require_protected_named_location(
        Path::new("/var/lib/aos/sandboxd"),
        "controller.journal",
        controller_uid,
        production_journal_limits(),
    )?;
    Ok(())
}

/// Constructs parentless compiler input against the actual Controller writer.
///
/// The caller supplies the typed sources from its exact signed Root stage
/// receipt. The complete request inherits every dimension; ancestors and both
/// catalogs are empty. Project choices reuse current protected publisher,
/// cache-domain and revocation replay, never the resolved public Policy.
///
/// The result is proposal DATA. Signed backend declarations do not establish
/// live enforcement, and no Source ancestry, physical Cache or live Root hold
/// is acquired here. Publication and effects still require their own genuine
/// held-owner/currentness join.
///
/// # Errors
///
/// Rejects an unsafe fixed Controller journal, changed accepted Create or
/// publisher/projection/revocation cut, expired or mismatched signed sources,
/// nonempty catalogs, or a failed canonical input/model constructor.
#[cfg(target_os = "linux")]
pub fn current_parentless_create_compiler_input_v1(
    journal: &mut Journal,
    operation: OperationId,
    sandbox: SandboxId,
    deployment_head: PolicyDeploymentHeadV1,
    deployment: &PolicyDeploymentSourcesV1,
    signed_project: &VerifiedSignedProjectPolicySourceV2,
) -> Result<PolicyCompilerInputV1, CurrentCreateCompilerInputErrorV1> {
    validate_current_create_controller_journal_v1(journal)?;
    let source = current_parentless_create_project_source_v1(journal, operation, sandbox)?;
    require_create_input_sources(&source, deployment_head, deployment, signed_project)?;

    let project_layer = super::project_source_v2::current_explicit_layer(
        journal,
        source.revocation_scope(),
        signed_project,
        current_create_input_time()?,
    )?;
    let relation = relation_from_current_create_source(&source)?;
    let input = aos_sandbox_policy::parentless_input::parentless_create_input_from_authenticated_layers_v1(
        relation, project_layer, deployment,
    ).map_err(CurrentCreateCompilerInputErrorV1::from)?;

    validate_current_create_controller_journal_v1(journal)?;
    let current = current_parentless_create_project_source_v1(journal, operation, sandbox)?;
    if current.commitment() != source.commitment() {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent.into());
    }
    require_create_input_sources(&current, deployment_head, deployment, signed_project)?;
    Ok(input)
}

#[cfg(target_os = "linux")]
fn require_create_input_sources(
    source: &CurrentCreateProjectPolicySourceV1,
    deployment_head: PolicyDeploymentHeadV1,
    deployment: &PolicyDeploymentSourcesV1,
    signed_project: &VerifiedSignedProjectPolicySourceV2,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let now = current_create_input_time()?;
    let project_head = signed_project.head();
    if now >= deployment_head.expires_at()
        || now >= project_head.expires_at()
        || project_head.project() != source.project()
        || project_head.publisher_generation() != source.policy_generation()
        || project_head.publisher_digest() != source.policy_digest()
        || signed_project.cache_domain() != source.cache_domain()
        || project_head.prerequisite_claims()[1] != deployment_head.packet_digest()
        || project_head.prerequisite_claims()[2] != source.cache_domain_head()
        || project_head.prerequisite_claims()[3] != source.revocation_head()
        || !deployment.endpoints().entries().is_empty()
        || !deployment.destinations().entries().is_empty()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_create_input_time() -> Result<i64, CurrentCreatePolicySourceErrorV1> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    i64::try_from(now.as_secs()).map_err(|_| CurrentCreatePolicySourceErrorV1::NotCurrent)
}

/// Holds the matching physical Cache partition inside an already-held source cut.
///
/// The caller must retain the controller and source-domain writers before the
/// Cache writer and recheck them after this callback. This helper grants no
/// publication or effect authority.
fn with_current_project_physical_cache_v1<R>(
    cache: &mut CacheResidencyProtectedOwnerV1,
    source: &CurrentCreateProjectPolicySourceV1,
    action: impl FnOnce(&CurrentCreateProjectPolicySourceV1, CurrentProjectPhysicalCacheHeadV1) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    let joined = cache.while_current_project_physical_cache(source.project(), |physical| {
        if physical.project() != source.project()
            || physical.partition().disclosure() != source.cache_domain()
            || physical.head().as_bytes() == &[0; 32]
        {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }

        Ok(action(source, physical))
    })?;
    joined
}

/// Holds one accepted Create and source-domain ancestry under their writers.
///
/// The caller must acquire the protected controller writer before the fixed
/// source-domain writer. The callback may acquire Cache and then root, but
/// must neither publish nor perform an effect. Both local heads are re-read
/// after the callback while the writer borrows remain held. The result is not
/// a transferable admission or a complete cross-owner cut.
///
/// # Errors
///
/// Rejects a non-current accepted Create, publisher/cache-domain/revocation
/// source, absent ancestry, or either head changing across the callback.
pub fn with_current_parentless_create_ancestry_v1<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(&CurrentCreateProjectPolicySourceV1, ObjectDigest) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    controller.ensure_protected_authority()?;
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(source_domains)
        .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?;

    with_rechecked_create_ancestry(
        || current_parentless_create_project_source_v1(controller, operation, sandbox),
        |project| {
            hierarchy
                .project_ancestry_head(project)
                .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?
                .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)
                .map(|current| current.evidence().head())
        },
        inspect,
    )
}

fn with_rechecked_create_ancestry<R>(
    mut read_create: impl FnMut() -> Result<
        CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicySourceErrorV1,
    >,
    mut read_ancestry: impl FnMut(ProjectId) -> Result<ObjectDigest, CurrentCreatePolicySourceErrorV1>,
    inspect: impl FnOnce(&CurrentCreateProjectPolicySourceV1, ObjectDigest) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    let source = read_create()?;
    let ancestry = read_ancestry(source.project())?;
    let result = inspect(&source, ancestry);

    let current_source = read_create()?;
    let current_ancestry = read_ancestry(source.project())?;
    if current_source.commitment() != source.commitment() || current_ancestry != ancestry {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(result)
}

/// Holds current Create, ancestry, and physical Cache sources for one inspection.
///
/// The caller must open and retain the controller writer, then source-domain
/// writer, then Cache writer; the callback may acquire the root policy writer
/// last. The callback must not perform an effect or publish AOSPCB02. It can
/// only prepare a candidate for a later root CAS and effect-handoff protocol.
/// Every local head is rechecked before the writer borrows are released.
///
/// # Errors
///
/// Rejects an absent, stale, or unhealthy owner head before or after the
/// callback. Errors from the callback remain its caller's responsibility.
pub fn with_current_create_policy_source_barrier_v2<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(&CurrentCreateProjectPolicySourceV1, CurrentCreatePolicyBarrierHeadsV2) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    with_current_create_policy_source_barrier_v3(
        controller,
        source_domains,
        cache,
        operation,
        sandbox,
        |_, source, heads| inspect(source, heads),
    )
}

/// Borrows the Controller writer inside a held Create/source/Cache cut.
///
/// This variant permits a caller to durably freeze the Controller journal
/// after computing an exact root proposal and before sending it. The callback
/// remains nonauthorizing; source-domain and Cache still need durable custody
/// before public Create can be enabled.
///
/// # Errors
///
/// Rejects stale or unhealthy Controller, ancestry, or physical Cache heads
/// before and after the callback.
pub fn with_current_create_policy_source_barrier_v3<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
    ) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    with_current_create_policy_source_barrier_v4(
        controller,
        source_domains,
        cache,
        operation,
        sandbox,
        |controller, _, source, heads| inspect(controller, source, heads),
    )
}

/// Borrows Controller and source-domain writers inside the held Cache cut.
///
/// The fixed source-domain journal stays writer-locked even while the typed
/// hierarchy claim is dropped to permit a durable hold append. Ancestry is
/// re-claimed and rechecked after the callback. This remains an inert local
/// cut until Cache and effect handoff join the same recovery protocol.
///
/// # Errors
///
/// Rejects stale or unhealthy Controller, ancestry, or physical Cache heads
/// before and after the callback.
pub fn with_current_create_policy_source_barrier_v4<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
    ) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    controller.ensure_protected_authority()?;
    let source = current_parentless_create_project_source_v1(controller, operation, sandbox)?;
    let ancestry = current_source_domain_ancestry(source_domains, source.project())?;

    let result = with_current_project_physical_cache_v1(cache, &source, |source, physical| {
        let heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry,
            physical_partition: physical.partition().digest(),
            physical_cache: physical.head(),
        };
        inspect(controller, source_domains, source, heads)
    })?;

    let current_source =
        current_parentless_create_project_source_v1(controller, operation, sandbox)?;
    let current_ancestry = current_source_domain_ancestry(source_domains, source.project())?;
    if current_source.commitment() != source.commitment() || current_ancestry != ancestry {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    Ok(result)
}

/// Retains Controller, Source, and all four Cache writers plus the physical flock.
///
/// The callback may perform an observational signer exchange. A later
/// authenticated Root RPC must acquire the Root writer last; this callback
/// does not join Root authority or issue an effect capability. It must not
/// publish, dispatch an effect, or treat the returned value as a transferable
/// cut. Cache's selected partition must
/// match the current Create project and disclosure; its held policy head must
/// match the same exact physical partition and replay head. All named writers
/// and source facts are rechecked even when the callback returns an error as
/// its value. Callers carry their own error inside `R` until all postflight
/// checks complete.
///
/// # Errors
///
/// Rejects changed Controller or Source names, accepted Create, publisher,
/// ancestry, Cache hold, selected partition, physical owner, or Cache writers.
#[cfg(target_os = "linux")]
pub fn with_current_create_cache_signer_barrier_v5<R>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
        &CacheResidencyWriterReadbackV2,
    ) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    let controller_uid = controller.protected_owner_uid()?;
    let require_controller_name = |journal: &Journal| {
        journal.require_protected_named_location(
            Path::new("/var/lib/aos/sandboxd"),
            "controller.journal",
            controller_uid,
            production_journal_limits(),
        )
    };
    require_controller_name(controller)?;
    source_domains.require_fixed_named_writer_v1()?;
    let source = current_parentless_create_project_source_v1(controller, operation, sandbox)?;
    let ancestry = current_source_domain_ancestry(source_domains, source.project())?;
    let controller_hold = controller
        .controller_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let source_hold = source_domains
        .closed_policy_source_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    if !matching_held_create_sources(&source, ancestry, controller_hold, source_hold) {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }

    let result = cache.with_held_cache_owner_readback_v2(physical, |held| {
        let selected = held.selected();
        if selected.project() != source.project()
            || selected.partition().disclosure() != source.cache_domain()
            || selected.head().as_bytes() == &[0; 32]
            || held.hold().project() != source.project()
            || held.hold().partition() != selected.partition().digest()
            || held.hold().cache_head() != selected.head()
            || held.hold().binding() != controller_hold.binding()
            || held.hold().epoch() != controller_hold.epoch()
        {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        let heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry,
            physical_partition: selected.partition().digest(),
            physical_cache: selected.head(),
        };
        Ok(inspect(controller, source_domains, &source, heads, held))
    });

    finish_held_create_source_cut(result.map_err(Into::into), || {
        let controller_name = require_controller_name(controller);
        let source_name = source_domains.require_fixed_named_writer_v1();
        let current_source =
            current_parentless_create_project_source_v1(controller, operation, sandbox);
        let current_ancestry = current_source_domain_ancestry(source_domains, source.project());
        let current_controller_hold = controller.controller_policy_hold_v1();
        let current_source_hold = source_domains.closed_policy_source_hold_v1();

        controller_name?;
        source_name?;
        if current_source?.commitment() != source.commitment() || current_ancestry? != ancestry {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }
        if current_controller_hold? != Some(controller_hold)
            || current_source_hold? != Some(source_hold)
        {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }
        Ok(())
    })
}

/// Runs a terminal observation after Cache postflight under every held writer.
///
/// Root may be acquired last during `inspect`. Cache validates its complete
/// replay, clock, four named writers, hold, and physical flock before
/// `terminal` runs. Controller and Source names, accepted Create, publisher,
/// ancestry, and held claims are then rechecked before that continuation.
/// The continuation may acknowledge an inert observation or commit a closed
/// Root CAS while all writers remain held. It cannot release an owner, publish
/// a binding, open Create, or dispatch an effect.
///
/// # Errors
///
/// Rejects stale owner custody or changed Source/Controller currentness.
/// Neither a failed Cache postflight nor a failed Controller/Source check
/// invokes the terminal continuation.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn with_current_create_cache_signer_terminal_barrier_v6<Prepared, Output>(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    cache: &mut CacheResidencyProtectedOwnerV1,
    physical: &DormantCacheOwnerV1,
    operation: OperationId,
    sandbox: SandboxId,
    inspect: impl FnOnce(
        &mut Journal,
        &mut ProtectedSourceDomainJournalOwnerV1,
        &CurrentCreateProjectPolicySourceV1,
        CurrentCreatePolicyBarrierHeadsV2,
        &CacheResidencyWriterReadbackV2,
    ) -> Prepared,
    terminal: impl FnOnce(&mut Journal, &mut ProtectedSourceDomainJournalOwnerV1, Prepared) -> Output,
) -> Result<Output, CurrentCreatePolicySourceErrorV1> {
    let cut = HeldCreateSourceCut::begin(controller, source_domains, operation, sandbox)?;

    cache
        .with_held_cache_owner_readback_after_postflight_v3(physical, |held| {
            let heads = cut.cache_heads(held)?;
            let prepared = inspect(controller, source_domains, &cut.source, heads, held);

            Ok((prepared, |prepared| {
                let result = (|| -> Result<Output, CurrentCreatePolicySourceErrorV1> {
                    cut.revalidate(controller, source_domains, operation, sandbox)?;
                    Ok(terminal(controller, source_domains, prepared))
                })();
                Ok(result)
            }))
        })
        .map_err(CurrentCreatePolicySourceErrorV1::from)?
}

#[cfg(target_os = "linux")]
mod v8_cache;
#[cfg(target_os = "linux")]
pub use v8_cache::{
    with_current_create_cache_signer_release_barrier_v7,
    with_current_create_cache_signer_released_barrier_v8,
    with_current_create_v8_owner_settlement_barrier_v9,
};

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn settle_released_v8_owner_rows(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    held_controller: ControllerPolicyHoldV1,
    receipt: super::RootV8EffectAckV1,
    proof: RootV8ReleasedProofV1,
    cache_held: CachePolicyHoldV1,
    cache_released: CachePolicyHoldV1,
    controller_uid: u32,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let floor = controller
        .controller_policy_v8_pre_release_floor_v1()?
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let current_source = source_domains
        .closed_policy_source_hold_v1()?
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    let source_held = if current_source.is_held() {
        current_source
    } else {
        let (held, released) = source_domains.closed_policy_source_v8_release_pair_v1()?;
        if released != current_source {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        held
    };
    if floor.root_release_marker_digest() != proof.release_marker_digest()
        || floor.cache_held_digest()
            != cache_held
                .record_digest()
                .map_err(crate::journal::JournalError::from)?
        || floor.source_held_digest()
            != source_held
                .record_digest()
                .map_err(crate::journal::JournalError::from)?
    {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }

    let current_controller = controller
        .controller_policy_hold_v1()?
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if current_controller.is_held() {
        if current_controller != held_controller
            || controller.controller_policy_v8_settlement_v1()?.is_some()
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
    } else {
        let settlement = controller
            .controller_policy_v8_settlement_v1()?
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if current_source.is_held()
            || settlement.controller_released_digest()
                != current_controller.record_digest().map_err(JournalError::from)?
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
    }

    // A durable Source release may have preceded a lost reply; its marker is
    // the only historical predecessor accepted on that replay path.
    source_domains.require_fixed_named_writer_v1()?;
    if current_source.is_held() {
        source_domains.retire_closed_policy_source_hold_v8(source_held)?;
    }
    let (prior_source, released_source) =
        source_domains.closed_policy_source_v8_release_pair_v1()?;
    if prior_source != source_held {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    let evidence = ControllerPolicyV8ReleaseEvidenceV1::new(
        held_controller,
        proof.release_marker_digest(),
        cache_held,
        cache_released,
        source_held,
        released_source,
    ).map_err(JournalError::from)?;
    HeldCreateSourceCut::require_controller_name(controller, controller_uid)?;
    source_domains.require_fixed_named_writer_v1()?;
    // The Controller journal checks exact typed S readback after its atomic commit.
    controller.retire_controller_policy_v8_hold_with_settlement_v1(
        held_controller,
        receipt,
        evidence,
    )?;
    if source_domains.closed_policy_source_v8_release_pair_v1()? != (source_held, released_source) {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    source_domains.require_fixed_named_writer_v1()?;
    HeldCreateSourceCut::require_controller_name(controller, controller_uid)?;
    Ok(())
}

#[cfg(target_os = "linux")]
struct HeldCreateSourceCut {
    source: CurrentCreateProjectPolicySourceV1,
    ancestry: ObjectDigest,
    controller_hold: ControllerPolicyHoldV1,
    source_hold: SourceDomainPolicyHoldV1,
    controller_uid: u32,
}

#[cfg(target_os = "linux")]
impl HeldCreateSourceCut {
    fn begin(
        controller: &mut Journal,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        operation: OperationId,
        sandbox: SandboxId,
    ) -> Result<Self, CurrentCreatePolicySourceErrorV1> {
        let controller_uid = controller.protected_owner_uid()?;
        Self::require_controller_name(controller, controller_uid)?;
        source_domains.require_fixed_named_writer_v1()?;
        let source = current_parentless_create_project_source_v1(controller, operation, sandbox)?;
        let ancestry = current_source_domain_ancestry(source_domains, source.project())?;
        let controller_hold = controller
            .controller_policy_hold_v1()?
            .filter(|hold| hold.is_held())
            .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
        let source_hold = source_domains
            .closed_policy_source_hold_v1()?
            .filter(|hold| hold.is_held())
            .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
        if !matching_held_create_sources(&source, ancestry, controller_hold, source_hold) {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }
        Ok(Self {
            source,
            ancestry,
            controller_hold,
            source_hold,
            controller_uid,
        })
    }

    fn require_controller_name(journal: &Journal, uid: u32) -> Result<(), JournalError> {
        journal.require_protected_named_location(
            Path::new("/var/lib/aos/sandboxd"),
            "controller.journal",
            uid,
            production_journal_limits(),
        )
    }

    fn cache_heads(
        &self,
        held: &CacheResidencyWriterReadbackV2,
    ) -> Result<CurrentCreatePolicyBarrierHeadsV2, CacheResidencyProtectedJournalErrorV1> {
        let selected = held.selected();
        if selected.project() != self.source.project()
            || selected.partition().disclosure() != self.source.cache_domain()
            || selected.head().as_bytes() == &[0; 32]
            || held.hold().project() != self.source.project()
            || held.hold().partition() != selected.partition().digest()
            || held.hold().cache_head() != selected.head()
            || held.hold().binding() != self.controller_hold.binding()
            || held.hold().epoch() != self.controller_hold.epoch()
        {
            return Err(CacheResidencyProtectedJournalErrorV1::StaleAuthority);
        }
        Ok(CurrentCreatePolicyBarrierHeadsV2 {
            ancestry: self.ancestry,
            physical_partition: selected.partition().digest(),
            physical_cache: selected.head(),
        })
    }

    fn revalidate(
        &self,
        controller: &mut Journal,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        operation: OperationId,
        sandbox: SandboxId,
    ) -> Result<(), CurrentCreatePolicySourceErrorV1> {
        Self::require_controller_name(controller, self.controller_uid)?;
        source_domains.require_fixed_named_writer_v1()?;
        let current_source =
            current_parentless_create_project_source_v1(controller, operation, sandbox)?;
        let current_ancestry =
            current_source_domain_ancestry(source_domains, self.source.project())?;
        if current_source.commitment() != self.source.commitment()
            || current_ancestry != self.ancestry
            || controller.controller_policy_hold_v1()? != Some(self.controller_hold)
            || source_domains.closed_policy_source_hold_v1()? != Some(self.source_hold)
        {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }
        Ok(())
    }

    fn validate_released_root_proof(
        &self,
        controller: &mut Journal,
        cache: &CacheResidencyWriterReadbackV2,
        proof: RootV8ReleasedProofV1,
    ) -> Result<(), CurrentCreatePolicySourceErrorV1> {
        let ack = controller
            .controller_policy_v8_effect_ack_v1()?
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if ack.attempt().hold() != self.controller_hold
            || ack.cache_quota() != cache.quota_digest()
            || !proof.matches_controller_ack(ack, self.controller_uid)
            || controller.controller_policy_v8_root_receipt_v1()? != Some(proof.ack())
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        Ok(())
    }

    fn record_pre_release_floor(
        &self,
        controller: &mut Journal,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        cache: &CacheResidencyWriterReadbackV2,
        proof: RootV8ReleasedProofV1,
    ) -> Result<(), CurrentCreatePolicySourceErrorV1> {
        let source_held = self.current_source_hold(source_domains)?;
        let cache_held = cache.hold();

        // The Controller journal verifies exact postcommit readback before returning.
        controller.record_controller_policy_v8_pre_release_floor_v1(
            self.controller_hold,
            proof.ack(),
            proof.release_marker_digest(),
            cache_held,
            source_held,
        )?;
        Ok(())
    }

    fn require_pre_release_floor(
        &self,
        controller: &Journal,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        cache_held: CachePolicyHoldV1,
        proof: RootV8ReleasedProofV1,
    ) -> Result<(), CurrentCreatePolicySourceErrorV1> {
        let source_held = self.current_source_hold(source_domains)?;
        if !cache_held.is_held() {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let floor = controller
            .controller_policy_v8_pre_release_floor_v1()?
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if floor.root_release_marker_digest() != proof.release_marker_digest()
            || floor.cache_held_digest()
                != cache_held
                    .record_digest()
                    .map_err(crate::journal::JournalError::from)?
            || floor.source_held_digest()
                != source_held
                    .record_digest()
                    .map_err(crate::journal::JournalError::from)?
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        Ok(())
    }

    fn current_source_hold(
        &self,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<SourceDomainPolicyHoldV1, CurrentCreatePolicySourceErrorV1> {
        let row = source_domains
            .closed_policy_source_hold_v1()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?
            .filter(|row| *row == self.source_hold && row.is_held())
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok(row)
    }
}

#[cfg(target_os = "linux")]
fn finish_held_create_source_cut<T>(
    result: Result<T, CurrentCreatePolicySourceErrorV1>,
    postflight: impl FnOnce() -> Result<(), CurrentCreatePolicySourceErrorV1>,
) -> Result<T, CurrentCreatePolicySourceErrorV1> {
    postflight()?;
    result
}

#[cfg(target_os = "linux")]
fn matching_held_create_sources(
    source: &CurrentCreateProjectPolicySourceV1,
    ancestry: ObjectDigest,
    controller: ControllerPolicyHoldV1,
    source_domain: SourceDomainPolicyHoldV1,
) -> bool {
    controller.is_held()
        && source_domain.is_held()
        && controller.operation() == source.operation()
        && controller.sandbox() == source.sandbox()
        && controller.source() == source.commitment()
        && source_domain.operation() == source.operation()
        && source_domain.sandbox() == source.sandbox()
        && source_domain.controller_source() == source.commitment()
        && source_domain.ancestry() == ancestry
        && source_domain.binding() == controller.binding()
        && source_domain.epoch() == controller.epoch()
}

fn current_source_domain_ancestry(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
) -> Result<ObjectDigest, CurrentCreatePolicySourceErrorV1> {
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(source_domains)
        .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?;
    let ancestry = hierarchy
        .project_ancestry_head(project)
        .map_err(CurrentCreatePolicySourceErrorV1::Hierarchy)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?
        .evidence()
        .head();
    Ok(ancestry)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use aos_sandbox_model::model::{
        CacheDomainKind, LimitDimension, RevocationMode, RevocationPolicy,
    };
    use aos_sandbox_model::{CacheDomainId, ObjectDescriptor, ResourceDimension};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::policy_compiler::{
        ClosedPolicyRootCasBaseV2, propose_closed_current_create_explicit_policy_binding_v2,
    };
    use aos_sandbox_policy::{
        AuthenticatedCacheDomainV1, AuthenticatedEndpointCatalogV1,
        AuthenticatedNamespaceCatalogV1, AuthenticatedSandboxProjectRelationV1,
        CacheDomainBindingV1, CacheDomainVerifierV1, EndpointCatalogVerifierV1, HardLimitRequestV1,
        HardResourceKeyV1, HardResourceProfileV1, NamespaceCatalogVerifierV1,
        PORTABLE_LIMIT_DIMENSIONS, PolicyCompilationError, PolicyCompilerLimitsV1,
        PolicyCompilerV1, PolicyLayerV1, ProjectPolicyInputV1, RequestPolicyInputV1,
        SandboxProjectRelationVerifierV1,
    };

    struct FixtureVerifier;

    impl SandboxProjectRelationVerifierV1 for FixtureVerifier {
        fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl EndpointCatalogVerifierV1 for FixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl NamespaceCatalogVerifierV1 for FixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl CacheDomainVerifierV1 for FixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    fn inherited_layer() -> PolicyLayerV1 {
        let portable = PORTABLE_LIMIT_DIMENSIONS
            .into_iter()
            .map(|dimension| {
                HardLimitRequestV1::new(
                    HardResourceKeyV1::Portable(dimension),
                    HardLimitValueV1::Inherit,
                    None,
                )
                .expect("portable limit")
            })
            .collect();
        let accounting = ResourceDimension::ALL
            .into_iter()
            .map(|dimension| {
                HardLimitRequestV1::new(
                    HardResourceKeyV1::Accounting(dimension),
                    HardLimitValueV1::Inherit,
                    None,
                )
                .expect("accounting limit")
            })
            .collect();
        PolicyLayerV1::new(
            Vec::new(),
            HardResourceProfileV1::new(portable, accounting).expect("complete profile"),
            Vec::new(),
            Vec::new(),
            CacheDomainInputV1::Inherit,
            RevocationInputV1::Inherit,
        )
        .expect("inherited layer")
    }

    fn sign_packet(payload: &mut Vec<u8>, key: &SigningKey, domain: &[u8]) {
        let mut signed = domain.to_vec();
        signed.extend_from_slice(payload);
        payload.extend_from_slice(&key.sign(&signed).to_bytes());
    }

    fn fixture_held_source(
        operation: OperationId,
        operation_revision: ObjectDigest,
        accepted_generation: u64,
    ) -> CurrentCreateProjectPolicySourceV1 {
        let project = ProjectId::from_bytes([3; 16]);
        CurrentCreateProjectPolicySourceV1 {
            operation,
            operation_revision,
            accepted_generation,
            sandbox: SandboxId::from_bytes([4; 16]),
            project,
            projection_revision: ObjectDigest::from_bytes([5; 32]),
            policy_generation: 1,
            policy_digest: ObjectDigest::from_bytes([6; 32]),
            cache_domain: CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes(*project.as_bytes()),
            ),
            cache_domain_head: ObjectDigest::from_bytes([7; 32]),
            revocation_scope: RevocationScopeId::from_bytes([8; 16]),
            revocation_generation: 1,
            revocation_head: ObjectDigest::from_bytes([9; 32]),
            canonical_policy: Vec::new(),
            commitment: operation_revision,
        }
    }

    #[test]
    fn held_controller_source_cut_rejects_changed_admission_revision() {
        let operation = OperationId::from_bytes([1; 16]);
        let revision = Cell::new(ObjectDigest::from_bytes([2; 32]));
        let ancestry = ObjectDigest::from_bytes([10; 32]);

        let result = with_rechecked_create_ancestry(
            || Ok(fixture_held_source(operation, revision.get(), 1)),
            |_| Ok(ancestry),
            |_, _| revision.set(ObjectDigest::from_bytes([3; 32])),
        );
        assert!(matches!(
            result,
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
        ));
    }

    #[test]
    fn held_controller_source_cut_rejects_ancestry_replacement() {
        let operation = OperationId::from_bytes([1; 16]);
        let revision = ObjectDigest::from_bytes([2; 32]);
        let ancestry = Cell::new(ObjectDigest::from_bytes([10; 32]));

        let result = with_rechecked_create_ancestry(
            || Ok(fixture_held_source(operation, revision, 7)),
            |_| Ok(ancestry.get()),
            |_, _| ancestry.set(ObjectDigest::from_bytes([11; 32])),
        );
        assert!(matches!(
            result,
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
        ));
    }

    #[test]
    fn held_controller_source_cut_rejects_changed_projection_or_publisher() {
        let operation = OperationId::from_bytes([1; 16]);
        let revision = ObjectDigest::from_bytes([2; 32]);
        let ancestry = ObjectDigest::from_bytes([10; 32]);

        for change_publisher in [false, true] {
            let changed = Cell::new(false);
            let result = with_rechecked_create_ancestry(
                || {
                    let mut source = fixture_held_source(operation, revision, 7);
                    if changed.get() {
                        if change_publisher {
                            source.policy_digest = ObjectDigest::from_bytes([12; 32]);
                        } else {
                            source.projection_revision = ObjectDigest::from_bytes([12; 32]);
                        }
                        source.commitment = ObjectDigest::from_bytes([13; 32]);
                    }
                    Ok(source)
                },
                |_| Ok(ancestry),
                |_, _| changed.set(true),
            );
            assert!(matches!(
                result,
                Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_cut_requires_matching_controller_and_source_holds() {
        let operation = OperationId::from_bytes([1; 16]);
        let source = fixture_held_source(operation, ObjectDigest::from_bytes([2; 32]), 7);
        let ancestry = ObjectDigest::from_bytes([10; 32]);
        let binding = ObjectDigest::from_bytes([11; 32]);
        let controller = ControllerPolicyHoldV1::new(
            operation,
            source.sandbox(),
            source.commitment(),
            binding,
            9,
        )
        .expect("Controller hold");
        let source_hold = SourceDomainPolicyHoldV1::new(
            operation,
            source.sandbox(),
            source.commitment(),
            ancestry,
            binding,
            9,
        )
        .expect("Source hold");
        assert!(matching_held_create_sources(
            &source,
            ancestry,
            controller,
            source_hold
        ));
        assert!(!matching_held_create_sources(
            &source,
            ObjectDigest::from_bytes([12; 32]),
            controller,
            source_hold,
        ));
        for other in [
            SourceDomainPolicyHoldV1::new(
                operation,
                source.sandbox(),
                ObjectDigest::from_bytes([12; 32]),
                ancestry,
                binding,
                9,
            )
            .expect("other Controller source"),
            SourceDomainPolicyHoldV1::new(
                operation,
                source.sandbox(),
                source.commitment(),
                ancestry,
                ObjectDigest::from_bytes([12; 32]),
                9,
            )
            .expect("other binding"),
            SourceDomainPolicyHoldV1::new(
                operation,
                source.sandbox(),
                source.commitment(),
                ancestry,
                binding,
                10,
            )
            .expect("other epoch"),
        ] {
            assert!(!matching_held_create_sources(
                &source, ancestry, controller, other
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_cut_postflights_even_when_nested_action_reports_error() {
        let calls = Cell::new(0);
        let error = finish_held_create_source_cut::<()>(
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            error,
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
        ));
        assert_eq!(calls.get(), 1);

        let error = finish_held_create_source_cut(Ok(()), || {
            calls.set(calls.get() + 1);
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
        });
        assert!(matches!(
            error,
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent)
        ));
        assert_eq!(calls.get(), 2);

        let error = finish_held_create_source_cut::<()>(
            Err(CurrentCreatePolicySourceErrorV1::NotCurrent),
            || {
                calls.set(calls.get() + 1);
                Err(CurrentCreatePolicySourceErrorV1::Journal(
                    JournalError::ProtectedBoundary,
                ))
            },
        );
        assert!(matches!(
            error,
            Err(CurrentCreatePolicySourceErrorV1::Journal(
                JournalError::ProtectedBoundary
            ))
        ));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn checked_create_draft_binds_signed_source_and_exact_claims() {
        let project = ProjectId::from_bytes([3; 16]);
        let sandbox = SandboxId::from_bytes([4; 16]);
        let portable = PORTABLE_LIMIT_DIMENSIONS
            .map(|dimension| {
                let enforcement = match dimension {
                    LimitDimension::Bytes
                    | LimitDimension::Inodes
                    | LimitDimension::SnapshotCount => "zfs-quota",
                    LimitDimension::Processes
                    | LimitDimension::Memory
                    | LimitDimension::CpuWeight
                    | LimitDimension::CpuQuota
                    | LimitDimension::IoWeight
                    | LimitDimension::IoBandwidth => "cgroup-v2",
                    LimitDimension::OpenFiles => "combined-file-descriptor",
                    LimitDimension::FuseMemory => "combined-memory-accounting",
                    LimitDimension::CacheBytes => "node-bounded-shared-residency",
                    LimitDimension::MountCount
                    | LimitDimension::FuseRequests
                    | LimitDimension::ChildCount
                    | LimitDimension::ExecutionCount => "broker-ledger",
                };
                serde_json::json!({
                    "amount": 4096,
                    "enforcement": enforcement,
                    "kind": "bounded",
                })
            })
            .to_vec();
        let accounting = vec![
            serde_json::json!({
                "amount": 4096,
                "enforcement": "broker-ledger",
                "kind": "bounded",
            });
            ResourceDimension::COUNT
        ];

        let node = serde_json::to_vec(&serde_json::json!({
            "generation": 1, "input": {"portable": portable, "accounting": accounting},
            "magic": "AOSPNI01",
        }))
        .expect("node bytes");
        let site = String::from_utf8(node.clone())
            .expect("UTF-8")
            .replace("AOSPNI01", "AOSPSI01")
            .into_bytes();
        let backend = br#"{"generation":1,"input":{"enforcement":["cgroup-v2","broker-ledger","zfs-quota","node-bounded-shared-residency","combined-file-descriptor","combined-memory-accounting"]},"magic":"AOSPBI01"}"#;
        let catalogs =
            br#"{"generation":1,"input":{"destinations":[],"endpoints":[]},"magic":"AOSPCI01"}"#;
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: &node,
            site: &site,
            backend,
            catalogs,
        };
        let deployment_key = SigningKey::from_bytes(&[9; 32]);
        let mut deployment_packet = b"AOSPDH01".to_vec();
        deployment_packet.extend_from_slice(&1_u64.to_be_bytes());
        deployment_packet.extend_from_slice(&10_i64.to_be_bytes());
        deployment_packet.extend_from_slice(&30_i64.to_be_bytes());
        for bytes in [node.as_slice(), site.as_slice(), backend, catalogs] {
            deployment_packet.extend_from_slice(&Sha256::digest(bytes));
        }
        sign_packet(
            &mut deployment_packet,
            &deployment_key,
            b"aos.sandbox.policy-deployment-head.v1\0",
        );
        let deployment_head = verify_policy_deployment_head_v1(
            &deployment_packet,
            &deployment_inputs,
            &deployment_key.verifying_key(),
            20,
        )
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)
        .expect("signed deployment");
        let deployment = decode_policy_deployment_sources_v1(&deployment_inputs, deployment_head)
            .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)
            .expect("typed deployment");

        let prerequisites = PolicyPublicationPrerequisitesV1::new(
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes(Sha256::digest(&deployment_packet).into()),
            ObjectDigest::from_bytes([7; 32]),
            ObjectDigest::from_bytes([8; 32]),
            1,
        )
        .expect("prerequisite tuple");
        let project_key = SigningKey::from_bytes(&[21; 32]);
        let verifier = FixtureVerifier;
        let relation =
            AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)
                .expect("relation");
        let input = PolicyCompilerInputV1::new(
            relation,
            deployment.node().clone(),
            deployment.site().clone(),
            ProjectPolicyInputV1::new(project, inherited_layer()).expect("project layer"),
            Vec::new(),
            RequestPolicyInputV1::new(inherited_layer()).expect("request layer"),
            AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("endpoint catalog"),
            AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("namespace catalog"),
            deployment.backend().clone(),
            PolicyCompilerLimitsV1::DEFAULT,
        )
        .expect("compiler input");
        let mut source = CurrentCreateProjectPolicySourceV1 {
            operation: OperationId::from_bytes([1; 16]),
            operation_revision: ObjectDigest::from_bytes([10; 32]),
            accepted_generation: 1,
            sandbox,
            project,
            projection_revision: ObjectDigest::from_bytes([2; 32]),
            policy_generation: 2,
            policy_digest: ObjectDigest::from_bytes([6; 32]),
            cache_domain: CacheDomain::new(
                CacheDomainKind::Project,
                CacheDomainId::from_bytes(*project.as_bytes()),
            ),
            cache_domain_head: prerequisites.cache_domain_head(),
            revocation_scope: RevocationScopeId::from_bytes([12; 16]),
            revocation_generation: 1,
            revocation_head: prerequisites.revocation_head(),
            canonical_policy: Vec::new(),
            commitment: ObjectDigest::from_bytes([9; 32]),
        };

        let heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry: prerequisites.ancestry_head(),
            physical_partition: ObjectDigest::from_bytes([22; 32]),
            physical_cache: ObjectDigest::from_bytes([23; 32]),
        };
        let root_base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
            [24; 16],
            ObjectDigest::from_bytes([0; 32]),
            1,
            1,
            1,
        )
        .expect("canonical remote root base");
        // An inherited candidate still cannot invent a cache-domain choice.
        assert!(matches!(
            PolicyCompilerV1::compile(input.clone()),
            Err(PolicyCompilationError::UnresolvedCacheDomain)
        ));

        let explicit_project_input = serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {
                "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
                "advisory_actions": [],
                "cache_domain": "project",
                "grants": [],
                "namespace_rules": [],
                "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
                "revocation": {"grace_nanos": 0, "mode": "deny-new"},
            },
            "magic": "AOSPPL02",
            "project_id": project.to_string(),
        }))
        .expect("explicit project bytes");
        let mut explicit_project_packet = b"AOSPPH02".to_vec();
        explicit_project_packet.extend_from_slice(project.as_bytes());
        explicit_project_packet.extend_from_slice(&1_u64.to_be_bytes());
        explicit_project_packet.extend_from_slice(&10_i64.to_be_bytes());
        explicit_project_packet.extend_from_slice(&30_i64.to_be_bytes());
        explicit_project_packet.extend_from_slice(&source.policy_generation.to_be_bytes());
        explicit_project_packet.extend_from_slice(source.policy_digest.as_bytes());
        explicit_project_packet.extend_from_slice(&Sha256::digest(&explicit_project_input));
        for head in [
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            prerequisites.cache_domain_head(),
            prerequisites.revocation_head(),
        ] {
            explicit_project_packet.extend_from_slice(head.as_bytes());
        }
        explicit_project_packet.extend_from_slice(&1_u64.to_be_bytes());
        explicit_project_packet.extend_from_slice(&1_u64.to_be_bytes());
        sign_packet(
            &mut explicit_project_packet,
            &project_key,
            b"aos.sandbox.policy-project-head.v2\0",
        );
        let explicit_project = verify_signed_project_policy_source_v2(
            &explicit_project_packet,
            &explicit_project_input,
            &project_key.verifying_key(),
            20,
        )
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)
        .expect("explicit signed source");
        let binding = AuthenticatedCacheDomainV1::authenticate(
            source.cache_domain,
            CacheDomainBindingV1::Project(project),
            &verifier,
        )
        .expect("candidate project domain");
        let explicit_layer = PolicyLayerV1::new(
            Vec::new(),
            inherited_layer().resources().clone(),
            Vec::new(),
            Vec::new(),
            CacheDomainInputV1::Exact(binding),
            RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
        )
        .expect("candidate project layer");
        let explicit_input = PolicyCompilerInputV1::new(
            AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)
                .expect("relation"),
            deployment.node().clone(),
            deployment.site().clone(),
            ProjectPolicyInputV1::new(project, explicit_layer).expect("project layer"),
            Vec::new(),
            RequestPolicyInputV1::new(inherited_layer()).expect("request layer"),
            AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("endpoint catalog"),
            AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("namespace catalog"),
            deployment.backend().clone(),
            PolicyCompilerLimitsV1::DEFAULT,
        )
        .expect("explicit compiler input");
        let draft = checked_parentless_create_verified_policy_draft_v2(
            &source,
            &explicit_project,
            &deployment,
            &explicit_input,
            &prerequisites,
            20,
        )
        .expect("matching supported draft");
        assert_ne!(draft.as_bytes(), &[0; 32]);

        let explicit_binding = propose_closed_current_create_explicit_policy_binding_v2(
            &source,
            heads,
            &explicit_project,
            deployment_head,
            &deployment,
            &explicit_input,
            root_base,
            20,
        )
        .expect("inert V2 proposal");
        assert!(!explicit_binding.is_empty());
        assert!(
            propose_closed_current_create_explicit_policy_binding_v2(
                &source,
                heads,
                &explicit_project,
                deployment_head,
                &deployment,
                &input,
                root_base,
                20,
            )
            .is_err()
        );

        let stale_heads = CurrentCreatePolicyBarrierHeadsV2 {
            ancestry: ObjectDigest::from_bytes([25; 32]),
            ..heads
        };
        assert!(
            propose_closed_current_create_explicit_policy_binding_v2(
                &source,
                stale_heads,
                &explicit_project,
                deployment_head,
                &deployment,
                &explicit_input,
                root_base,
                20,
            )
            .is_err()
        );

        source.policy_generation += 1;
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &explicit_project,
                &deployment,
                &explicit_input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.policy_generation -= 1;

        source.revocation_head = ObjectDigest::from_bytes([11; 32]);
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &explicit_project,
                &deployment,
                &explicit_input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.revocation_head = prerequisites.revocation_head();

        source.cache_domain_head = ObjectDigest::from_bytes([11; 32]);
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &explicit_project,
                &deployment,
                &explicit_input,
                &prerequisites,
                20,
            )
            .is_err()
        );
        source.cache_domain_head = prerequisites.cache_domain_head();

        let stale_revocation_head = ObjectDigest::from_bytes([11; 32]);
        let stale_revocation = PolicyPublicationPrerequisitesV1::new(
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            prerequisites.cache_domain_head(),
            stale_revocation_head,
            1,
        )
        .expect("changed revocation head");
        let mut stale_project_packet = explicit_project_packet[..264].to_vec();
        stale_project_packet[216..248].copy_from_slice(stale_revocation_head.as_bytes());
        sign_packet(
            &mut stale_project_packet,
            &project_key,
            b"aos.sandbox.policy-project-head.v2\0",
        );
        let stale_signed_project = verify_signed_project_policy_source_v2(
            &stale_project_packet,
            &explicit_project_input,
            &project_key.verifying_key(),
            20,
        )
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)
        .expect("signed project with changed revocation claim");
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &stale_signed_project,
                &deployment,
                &explicit_input,
                &stale_revocation,
                20,
            )
            .is_err()
        );

        let stale_cache = PolicyPublicationPrerequisitesV1::new(
            prerequisites.ancestry_head(),
            prerequisites.compiler_authority_head(),
            ObjectDigest::from_bytes([10; 32]),
            prerequisites.revocation_head(),
            1,
        )
        .expect("changed cache head");
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &explicit_project,
                &deployment,
                &explicit_input,
                &stale_cache,
                20,
            )
            .is_err()
        );
        assert!(
            checked_parentless_create_verified_policy_draft_v2(
                &source,
                &explicit_project,
                &deployment,
                &explicit_input,
                &prerequisites,
                30,
            )
            .is_err()
        );
    }
}

impl From<aos_sandbox_protocol::publisher_policy::current_create::CurrentCreateProjectSourceDataErrorV1>
    for CurrentCreatePolicySourceErrorV1
{
    fn from(error: aos_sandbox_protocol::publisher_policy::current_create::CurrentCreateProjectSourceDataErrorV1) -> Self {
        use aos_sandbox_protocol::publisher_policy::current_create::CurrentCreateProjectSourceDataErrorV1;
        match error {
            CurrentCreateProjectSourceDataErrorV1::NotCurrent => Self::NotCurrent,
            CurrentCreateProjectSourceDataErrorV1::Operation(error) => Self::Operation(error.into()),
            CurrentCreateProjectSourceDataErrorV1::Projection(error) => Self::Projection(error),
            CurrentCreateProjectSourceDataErrorV1::Publisher(error) => error.into(),
        }
    }
}

impl From<aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2>
    for CurrentCreatePolicySourceErrorV1
{
    fn from(error: aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2) -> Self {
        use aos_sandbox_protocol::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2;
        match error {
            CurrentPublisherPolicyDataErrorV2::NotCurrent => Self::NotCurrent,
            CurrentPublisherPolicyDataErrorV2::Publisher(error) => Self::Publisher(error.into()),
        }
    }
}
