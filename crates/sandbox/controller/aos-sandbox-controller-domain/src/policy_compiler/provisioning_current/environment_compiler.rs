//! Recompiles the current Environment parent's policy from actual fresh owners.
//!
//! The closed Environment stage pays before typed materialization. Current
//! Controller publisher/binding/spec, held Root signed sources, actual Source
//! ancestry, all five Cache journals, physical objects and public memory16 are
//! comparison inputs to the sole compiler. No saved policy row reconstructs an
//! authenticated validator. The actual issuer still owns accepted execution,
//! template/artifact, original horizon and output; this owner grants none.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{DecodeLimits, MediaType, NodeId, ObjectDescriptor, ProjectId,
    RawPairedClockSample, ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_model::format::{decode_policy, descriptor_for_bytes};
use aos_sandbox_model::model::{CacheDomain, Policy, SandboxSpec};
use aos_sandbox_policy::{CompiledPolicyCandidateV1, PolicyCompilerInputV1};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::execution_parent_resource::{ExecutionParentResourceSourceV1,
    revalidate_execution_parent_resource_from_observation_v2};
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootEnvironmentStageReceivingV1};
use crate::publisher_admin::policy::{PublisherPolicyLimits, PublisherPolicyObservationV2};
use crate::policy_compiler::continuation_policy::RootEnvironmentPolicyOriginalV1;
use super::current_compiler_complete_receiving_demand_v1;
use super::horizon::{RootContinuationHorizonDataV1, RootContinuationClockGateV1};
use super::{RootEnvironmentReadonlyContextV1, RootProvisioningNativeViewsV1};

type Cause = Box<dyn Error>;

#[derive(Debug, thiserror::Error)]
#[error("fresh Environment compiler sources differ from the current parent")]
struct Changed;

struct ValuesV1 {
    parent: ExecutionParentResourceSourceV1,
    specification: SandboxSpec,
    publisher: Policy,
    input: PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
    observed: RawPairedClockSample,
    expires: i64,
}

/// Retains the actual fresh compiler result without issuing a generation.
pub(crate) struct RootEnvironmentCompilerOriginalV1 {
    frontier_clock: Option<Box<RootContinuationClockGateV1>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    result: Option<Result<Box<ValuesV1>, Cause>>,
    closed: Option<JournalError>,
}

impl RootEnvironmentCompilerOriginalV1 {
    /// Creates dormant comparison storage without allocation or observation.
    pub(crate) fn new() -> Self {
        Self { frontier_clock: None, geometry: None, funding: None, result: None, closed: None }
    }

    /// Pays and retains one derivation against the actual Environment owners.
    ///
    /// # Errors
    /// Refuses reentry, unavailable funding, stale native sources or any
    /// canonical policy/specification/assignment mismatch.
    pub(crate) fn observe_once(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        readonly: &mut RootEnvironmentReadonlyContextV1, native: &RootProvisioningNativeViewsV1,
        policy: &RootEnvironmentPolicyOriginalV1, parent: &ExecutionParentResourceSourceV1,
        horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            let bytes = readonly.compiler_input_bytes_v1()?;
            let header = u64::try_from(size_of::<ValuesV1>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
                .and_then(|bytes| bytes.checked_add(crate::execution_parent_resource::observed_revalidation_control_bytes_v2()?))
                .and_then(|bytes| bytes.checked_add(crate::sandbox_spec_state::observed_get_control_bytes_v2()?))
                .and_then(|bytes| bytes.checked_add(crate::publisher_admin::policy::publisher_observation_control_bytes_v2()?))
                .ok_or(JournalError::JournalTooLarge)?).map_err(|_| JournalError::JournalTooLarge)?;
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            let shared = current_compiler_complete_receiving_demand_v1(bytes, readonly.compiler_controller_state_v1()?, signed)?
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
                .map_err(|_| JournalError::JournalTooLarge)?;
            shared.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))
                .map_err(|_| JournalError::JournalTooLarge)
        })());
        let demand = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_environment_compiler_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        // Enrollment is borrowed from this SAME armed R recipient, never the
        // query's NodeId or an unrelated policy layer. Both C and Root bind it.
        self.frontier_clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
        self.result = Some((|| {
            let clock = self.frontier_clock.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let sample = clock.check_next_once_v1()?;
            let node = NodeId::from_bytes(stage.enrolled_node_v1()?);
            compile_current_v1(readonly, native, policy, parent, node, sample, clock).map(Box::new)
        })());
        self.values_v1().map(|_| ())
    }

    fn values_v1(&self) -> Result<&ValuesV1, JournalError> {
        if self.closed.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result.as_ref().and_then(|value| value.as_ref().ok()).map(Box::as_ref)
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows the derived candidate as comparison DATA before final posts.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or fenced derivation.
    pub(crate) fn candidate_v1(&self) -> Result<&CompiledPolicyCandidateV1, JournalError> {
        Ok(&self.values_v1()?.candidate)
    }

    /// Borrows the specification read from the same current Controller model.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or fenced derivation.
    pub(crate) fn specification_v1(&self) -> Result<&SandboxSpec, JournalError> {
        Ok(&self.values_v1()?.specification)
    }

    /// Borrows the exact parent revalidated against the same Controller model.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or fenced derivation.
    pub(crate) fn parent_v1(&self) -> Result<&ExecutionParentResourceSourceV1, JournalError> {
        Ok(&self.values_v1()?.parent)
    }

    /// Returns the minimum actual publisher and signed-source expiry.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or fenced derivation.
    pub(crate) fn expires_at_v1(&self) -> Result<i64, JournalError> {
        Ok(self.values_v1()?.expires)
    }

    /// Checks the actual independently owed native and policy intervals.
    /// The issuer separately enforces its original accepted-execution horizon.
    ///
    /// # Errors
    /// Refuses missing or failed final posts, a changed boot, clock regression
    /// or expiry of any retained signed/publisher source.
    pub(crate) fn final_require_complete_v1(&self, readonly: &RootEnvironmentReadonlyContextV1,
        native: &RootProvisioningNativeViewsV1, policy: &RootEnvironmentPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        let values = self.values_v1()?;
        readonly.final_require_complete_v1()?;
        native.require_complete_v1()?;
        policy.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let clock = self.frontier_clock.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        for sample in [readonly.completed_clock_v1()?, native.clock_v1()?] {
            clock.require_final_sample_v1(sample)?;
            if sample.host_boot_id() != values.observed.host_boot_id()
                || sample.boottime_nanoseconds() < values.observed.boottime_nanoseconds()
                || sample.wall_seconds() >= values.expires
            { return Err(JournalError::ProtectedBoundary); }
        }
        Ok(())
    }

    /// Reports only an actual failed admission after positive geometry.
    pub(crate) fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.funding, Some(Err(_)))
    }

    /// Borrows the first retained cause without moving or reconstructing it.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.frontier_clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn compile_current_v1(readonly: &mut RootEnvironmentReadonlyContextV1,
    native: &RootProvisioningNativeViewsV1, policy: &RootEnvironmentPolicyOriginalV1,
    parent: &ExecutionParentResourceSourceV1, node: NodeId, sample: RawPairedClockSample,
    clock: &mut RootContinuationClockGateV1,
) -> Result<ValuesV1, Cause> {
    let source_sample = native.prepared_environment_clock_v1()?;
    source_sample.validate_later_sample(sample).map_err(|_| Changed)?;
    let signed = policy.verified_v1().ok_or(Changed)?;
    let verified_at = policy.verified_at_v1().ok_or(Changed)?;
    if verified_at.host_boot_id() != sample.host_boot_id()
        || verified_at.boottime_nanoseconds() > sample.boottime_nanoseconds()
    { return Err(Changed.into()); }
    let (project, deployment_head, deployment) = signed;
    let manifest = parent.assignment().manifest();
    if manifest.node() != node || manifest.project() != project.head().project()
        || !manifest.ancestry().ancestors().is_empty()
    { return Err(Changed.into()); }

    let tree = native.prepared_environment_tree_v1()?;
    let member = tree.tree.record(manifest.sandbox()).ok_or(Changed)?;
    if tree.tree.project() != manifest.project() || member.parent().is_some()
        || member.project() != manifest.project()
        || member.desired_generation() != manifest.desired_generation()
        || member.incarnation() != Some(manifest.incarnation())
    { return Err(Changed.into()); }
    let cache = native.prepared_environment_cache_v1()?;
    let _physical = native.prepared_environment_physical_v1()?;
    let _actual_limits = native.prepared_environment_limits_digest_v1()?;
    if cache.selected_v1().project != manifest.project() { return Err(Changed.into()); }

    let (controller, _) = readonly.models_v1()?;
    revalidate_execution_parent_resource_from_observation_v2(controller, parent)?;
    let specification = crate::sandbox_spec_state::get_from_observation_v2(controller, parent.specification_descriptor())?
        .ok_or(Changed)?.spec().clone();
    let store = PublisherPolicyObservationV2::load_from_observation_v2(controller, PublisherPolicyLimits::default())?;
    let revision = store.current_policy(manifest.project())?.ok_or(Changed)?;
    let revocation = store.project_revocation_head(manifest.project())?.ok_or(Changed)?;
    let cache_domain = store.project_cache_domain_head(manifest.project())?.ok_or(Changed)?;
    let publisher = decode_policy(revision.canonical_policy(), DecodeLimits::default())?;
    let project_head = project.head();
    let expires = revision.expires_at().min(project_head.expires_at()).min(deployment_head.expires_at());
    if sample.wall_seconds() < revision.not_before() || sample.wall_seconds() >= expires
        || project_head.publisher_generation() != revision.generation()
        || project_head.publisher_digest() != revision.descriptor().digest()
        || project.cache_domain() != cache_domain.domain()
        || project.revocation() != publisher.revocation()
        || project_head.prerequisite_claims() != [tree.head, deployment_head.packet_digest(),
            cache_domain.digest(), revocation.digest()]
        || !deployment.endpoints().entries().is_empty()
        || !deployment.destinations().entries().is_empty()
    { return Err(Changed.into()); }

    // This selected Root recipe is the existing parentless, fully inherited
    // request recipe. A nonempty ancestry is refused above, never erased.
    clock.check_next_once_v1()?;
    let (input, candidate) = super::parentless_compiler::compile_parentless_current_v1(
        signed, manifest.project(), manifest.sandbox(), cache_domain.domain()).map_err(|cause| cause as Cause)?;
    super::parentless_compiler::require_manifest_candidate_v1(parent.assignment(), &specification, &candidate)
        .map_err(|cause| {
            if cause.is::<super::parentless_compiler::RootParentlessComparisonChangedV1>() {
                Box::new(Changed) as Cause
            } else { cause }
        })?;

    Ok(ValuesV1 { parent: parent.clone(), specification, publisher, input, candidate,
        observed: sample, expires })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dormant_compiler_cannot_lend_a_policy_spec_parent_or_expiry() {
        let actual = RootEnvironmentCompilerOriginalV1::new();

        assert!(actual.candidate_v1().is_err());
        assert!(actual.specification_v1().is_err());
        assert!(actual.parent_v1().is_err());
        assert!(actual.expires_at_v1().is_err());
        assert!(!actual.funding_failure_is_selected_v1());
        assert!(actual.failure().is_none());
    }
}
