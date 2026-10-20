//! Derives Apply's policy from its actual fresh joined parent Create inputs.
//!
//! This purpose never adopts the old Prepare permission. The genuine Apply
//! stage pays the complete selector/compiler cardinality before typed work;
//! every candidate is rebuilt by the same inherited parentless recipe used by
//! Environment and compared with actual accepted Create, Source ancestry,
//! publisher/Root heads, all five Cache journals, physical objects and memory16.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_model::{DecodeLimits, OperationId, ResourceDimension as D, ResourceVector,
    RawPairedClockSample};
use aos_sandbox_model::format::decode_policy;
use aos_sandbox_model::model::{Policy, SandboxSpec};
use aos_sandbox_policy::{CompiledPolicyCandidateV1, PolicyCompilerInputV1};
use aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3;
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{RootApplyStageReceivingV1, NormalRootStartupErrorV1};
use crate::policy_compiler::{continuation_policy::RootApplyPolicyOriginalV1,
    public_create_source::{CurrentCreateProjectPolicySourceV1,
        current_parentless_create_project_source_with_observed_wall_v1}};
use crate::publisher_admin::policy::{PublisherPolicyStore, PublisherPolicyLimits};
use super::{RootProvisioningNativeViewsV1, RootContinuationHorizonDataV1, RootContinuationClockGateV1,
    current_compiler_complete_receiving_demand_v1};
use super::{apply_readonly::RootApplyReadonlyContextV1, apply_inputs::RootApplyInputsOriginalV1};

type Cause = Box<dyn Error>;

struct ValuesV1 {
    source: CurrentCreateProjectPolicySourceV1,
    publisher: Policy,
    specification: SandboxSpec,
    input: PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
    origin: RetainedPublisherCompilerOriginV3,
    sample: RawPairedClockSample,
    expires: i64,
}

pub(crate) struct RootApplyCompilerOriginalV1 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Box<RootContinuationClockGateV1>>,
    result: Option<Result<Box<ValuesV1>, Cause>>,
    closed: bool,
}

impl RootApplyCompilerOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { geometry: None, funding: None, clock: None, result: None, closed: false }
    }

    pub(crate) fn observe_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        readonly: &mut RootApplyReadonlyContextV1, native: &RootProvisioningNativeViewsV1,
        policy: &RootApplyPolicyOriginalV1, inputs: &RootApplyInputsOriginalV1,
        ready: ReadyBundleDataV1<'_>, operation: OperationId, horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError>
    {
        if self.geometry.is_some() { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.geometry = Some((|| {
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            let width = readonly.compiler_input_bytes_v1()?
                .checked_add(native.apply_source_input_bytes_v1()?).ok_or(JournalError::JournalTooLarge)?;
            let extra = size_of::<ValuesV1>().checked_mul(2).and_then(|bytes| bytes.checked_add(2 * size_of::<Self>()))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            current_compiler_complete_receiving_demand_v1(width, readonly.controller_state_v1()?, signed)?
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
                .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra)))
                .map_err(|_| JournalError::JournalTooLarge)
        })());
        let required = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.funding = Some(stage.admit_compiler_once_v1(RootContinuationDemandV1::from_demand_v1(required)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
        self.result = Some((|| {
            let clock = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let sample = clock.check_next_once_v1()?;
            compile_once_v1(readonly, native, policy, inputs, ready, operation, sample, clock).map(Box::new)
        })());
        self.values_v1().map(|_| ())
    }

    fn values_v1(&self) -> Result<&ValuesV1, JournalError> {
        if self.closed || !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.result.as_ref().and_then(|value| value.as_ref().ok()).map(Box::as_ref)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn candidate_v1(&self) -> Result<&CompiledPolicyCandidateV1, JournalError> {
        Ok(&self.values_v1()?.candidate)
    }

    pub(crate) fn expires_at_v1(&self) -> Result<i64, JournalError> { Ok(self.values_v1()?.expires) }

    pub(crate) fn require_final_v1(&self, readonly: &RootApplyReadonlyContextV1,
        native: &RootProvisioningNativeViewsV1, policy: &RootApplyPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        let values = self.values_v1()?;
        readonly.require_complete_v1()?;
        native.require_complete_v1()?;
        policy.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        for sample in [readonly.completed_clock_v1()?, native.clock_v1()?] {
            self.clock.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_final_sample_v1(sample)?;
            values.sample.validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
            if sample.wall_seconds() >= values.expires { return Err(JournalError::ProtectedBoundary); }
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref()))
            .or_else(|| self.closed.then_some(&CLOSED as _))
    }
}

fn compile_once_v1(readonly: &mut RootApplyReadonlyContextV1, native: &RootProvisioningNativeViewsV1,
    policy: &RootApplyPolicyOriginalV1, inputs: &RootApplyInputsOriginalV1,
    ready: ReadyBundleDataV1<'_>, operation: OperationId, sample: RawPairedClockSample,
    clock: &mut RootContinuationClockGateV1,
) -> Result<ValuesV1, Cause> {
    let assignment = inputs.manifest_v1()?;
    let manifest = assignment.manifest();
    let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
    let verified_at = policy.verified_at_v1().ok_or(JournalError::ProtectedBoundary)?;
    verified_at.validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
    let tree = native.prepared_apply_tree_v1()?;
    let member = tree.tree.record(manifest.sandbox()).ok_or(JournalError::ProtectedBoundary)?;
    if !manifest.ancestry().ancestors().is_empty() || member.parent().is_some()
        || tree.tree.project() != manifest.project() || member.project() != manifest.project()
        || member.incarnation() != Some(manifest.incarnation())
        || member.desired_generation() != manifest.desired_generation()
        || native.prepared_apply_cache_v1()?.selected_v1().project != manifest.project()
    { return Err(JournalError::ProtectedBoundary.into()); }
    native.prepared_apply_physical_v1()?;
    native.prepared_apply_limits_digest_v1()?;
    let controller = readonly.controller_mut_v1()?;
    let source = current_parentless_create_project_source_with_observed_wall_v1(controller,
        operation, manifest.sandbox(), Some(sample.wall_seconds()))?;
    if source.project() != manifest.project() { return Err(JournalError::ProtectedBoundary.into()); }
    let specification = crate::sandbox_spec_state::get(controller, manifest.sandbox_spec())?
        .ok_or(JournalError::ProtectedBoundary)?.spec().clone();
    if specification != aos_sandbox_model::decode_sandbox_spec(ready.specification, DecodeLimits::default())? {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let publisher = decode_policy(source.canonical_policy(), DecodeLimits::default())?;
    let expires = PublisherPolicyStore::load(controller, PublisherPolicyLimits::default())?
        .current_policy(source.project())?.ok_or(JournalError::ProtectedBoundary)?.expires_at()
        .min(signed.0.head().expires_at()).min(signed.1.expires_at());
    let project = signed.0.head();
    if sample.wall_seconds() >= expires || project.project() != source.project()
        || project.publisher_generation() != source.policy_generation()
        || project.publisher_digest() != source.policy_digest()
        || signed.0.cache_domain() != source.cache_domain() || signed.0.revocation() != publisher.revocation()
        || project.prerequisite_claims() != [tree.head, signed.1.packet_digest(),
            source.cache_domain_head(), source.revocation_head()]
    { return Err(JournalError::ProtectedBoundary.into()); }
    clock.check_next_once_v1()?;
    let (input, candidate) = super::parentless_compiler::compile_parentless_current_v1(signed,
        manifest.project(), manifest.sandbox(), source.cache_domain()).map_err(|cause| cause as Cause)?;
    let origin = RetainedPublisherCompilerOriginV3::from_record_bytes(ready.compiler_origin)?;
    aos_sandbox_policy::compare_publisher_compiler_derivation_v3(&origin, &input, &candidate)?;
    super::parentless_compiler::require_manifest_candidate_v1(assignment, &specification, &candidate).map_err(|cause| cause as Cause)?;
    Ok(ValuesV1 { source, publisher, specification, input, candidate, origin, sample, expires })
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
