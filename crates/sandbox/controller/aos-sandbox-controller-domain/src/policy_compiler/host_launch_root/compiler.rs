//! Rebuilds the accepted Start's gen2 manifest from the actual Root read cut.
//!
//! Historical manifest1 is compared against protected C publication1. The
//! shared current-Start selector and parentless compiler derive manifest2;
//! no supplied manifest, historical Create grant or successful DTO adopts it.

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::lifecycle::{
    LifecycleHistoricalReadOriginalV1, retained_lifecycle_replay_receiving_demand_v1,
};
use crate::normal_root::{NormalRootStartupErrorV1, RootHostLaunchStageReceivingV1};
use crate::policy_compiler::continuation_policy::RootHostLaunchPolicyOriginalV1;
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1, RootContinuationHorizonDataV1, RootProvisioningNativeViewsV1,
    apply_readonly::RootHostReadonlyContextV2,
    current_compiler_complete_receiving_demand_v1,
    current_manifest::{CurrentProtectedAssignmentDataV2, current_protected_assignment_data_v2},
    StartAssignmentCompilationDataV2, compile_root_start_assignment_v2,
};
use aos_sandbox_model::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1;

type Cause = Box<dyn std::error::Error>;

pub(super) struct RootStartResourceCompilerOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    compiler_geometry: Option<Result<ResourceVector, JournalError>>,
    compiler_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    source: LifecycleHistoricalReadOriginalV1,
    previous: Option<CurrentProtectedAssignmentDataV2>,
    specification: Option<crate::sandbox_spec_state::DurableSandboxSpecV1>,
    clock: Option<Box<RootContinuationClockGateV1>>,
    result: Option<Result<StartAssignmentCompilationDataV2, Cause>>,
    observed: Option<RawPairedClockSample>,
    closed: bool,
}

impl RootStartResourceCompilerOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            compiler_geometry: None,
            compiler_funding: None,
            source: LifecycleHistoricalReadOriginalV1::new(),
            previous: None,
            specification: None,
            clock: None,
            result: None,
            observed: None,
            closed: false,
        }
    }

    pub(super) fn observe_once_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        readonly: &mut RootHostReadonlyContextV2,
        views: &RootProvisioningNativeViewsV1,
        policy: &RootHostLaunchPolicyOriginalV1,
        bundle: ReadyBundleDataV1<'_>,
        operation: OperationId,
        horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            let source = views.prepared_host_launch_source_v2()?;
            let source_models = retained_lifecycle_replay_receiving_demand_v1(source.all_records())
                .ok_or(JournalError::JournalTooLarge)?;
            let width = source
                .all_records()
                .try_fold(
                    readonly.compiler_input_bytes_v2()?,
                    |sum, (_, key, value)| {
                        sum.checked_add(u64::try_from(key.len()).ok()?)?
                            .checked_add(u64::try_from(value.len()).ok()?)
                    },
                )
                .ok_or(JournalError::JournalTooLarge)?;
            let fixed = std::mem::size_of::<Self>()
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(2 * std::mem::size_of::<StartAssignmentCompilationDataV2>())
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            self.compiler_geometry = Some(current_compiler_complete_receiving_demand_v1(
                width,
                readonly.controller_state_v2()?,
                policy
                    .verified_v1()
                    .ok_or(JournalError::ProtectedBoundary)?,
            ));
            source_models
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::JournalTooLarge)?;
        self.funding =
            Some(stage.admit_host_accepted_start_once_v1(
                RootContinuationDemandV1::from_demand_v1(demand),
            ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let compiler = self
            .compiler_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::JournalTooLarge)?;
        self.compiler_funding =
            Some(stage.admit_compiler_once_v1(RootContinuationDemandV1::from_demand_v1(compiler)));
        if !matches!(self.compiler_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
        self.result = Some(self.compile_once_v2(readonly, views, policy, bundle, operation));
        self.compiled_v2().map(|_| ())
    }

    fn compile_once_v2(
        &mut self,
        readonly: &mut RootHostReadonlyContextV2,
        views: &RootProvisioningNativeViewsV1,
        policy: &RootHostLaunchPolicyOriginalV1,
        bundle: ReadyBundleDataV1<'_>,
        operation: OperationId,
    ) -> Result<StartAssignmentCompilationDataV2, Cause> {
        let sample = self
            .clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1()?;
        self.observed = Some(sample);
        policy
            .verified_at_v1()
            .ok_or(JournalError::ProtectedBoundary)?
            .validate_later_sample(sample)?;
        let planned = crate::policy_compiler::create_storage_current::bundle_ownership::
            planned_assignment_v1(bundle)?;
        self.source
            .observe_once_v1(views.prepared_host_launch_source_v2()?, operation)?;
        let (_, _, sandbox) = readonly.historical_v2()?.target_v2();
        let controller = readonly.controller_mut_v2()?;
        self.previous = Some(current_protected_assignment_data_v2(controller, sandbox)?);
        let previous = self
            .previous
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if previous.manifest_v2().canonical_bytes() != planned.manifest {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.specification = Some(
            crate::sandbox_spec_state::get(
                controller,
                previous.manifest_v2().manifest().sandbox_spec(),
            )?
            .ok_or(JournalError::ProtectedBoundary)?,
        );
        let specification = self
            .specification
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if aos_sandbox_model::encode_sandbox_spec(specification.spec()) != bundle.specification {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let compiled = compile_root_start_assignment_v2(
            controller,
            operation,
            &self.source,
            previous.manifest_v2(),
            specification,
            policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
            views.prepared_host_launch_tree_v1()?.head,
            sample,
        ).map_err(|cause| cause as Cause)?;
        let manifest = previous.manifest_v2().manifest();
        let tree = views.prepared_host_launch_tree_v1()?;
        let member = tree
            .tree_v2()
            .record(manifest.sandbox())
            .ok_or(JournalError::ProtectedBoundary)?;
        if member.parent().is_some()
            || !manifest.ancestry().ancestors().is_empty()
            || tree.tree_v2().project() != manifest.project()
            || member.project() != manifest.project()
            || member.incarnation() != Some(manifest.incarnation())
            || member.desired_generation() != manifest.desired_generation()
            || views.prepared_host_launch_cache_v1()?.selected_v1().project != manifest.project()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        views.prepared_host_launch_physical_v1()?;
        views.prepared_host_launch_limits_digest_v1()?;
        Ok(compiled)
    }

    pub(super) fn compiled_v2(&self) -> Result<&StartAssignmentCompilationDataV2, JournalError> {
        if self.closed
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.compiler_funding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn previous_v2(&self) -> Result<&CurrentProtectedAssignmentDataV2, JournalError> {
        self.compiled_v2()?;
        self.previous
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn specification_v2(
        &self,
    ) -> Result<&crate::sandbox_spec_state::DurableSandboxSpecV1, JournalError> {
        self.compiled_v2()?;
        self.specification
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn expires_v2(
        &self,
        policy: &RootHostLaunchPolicyOriginalV1,
    ) -> Result<i64, JournalError> {
        let signed = policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(self
            .compiled_v2()?
            .source_v2()
            .publisher_v2()
            .expires
            .min(signed.0.head().expires_at())
            .min(signed.1.expires_at()))
    }

    pub(super) fn require_posts_v2(
        &self,
        readonly: &RootHostReadonlyContextV2,
        views: &RootProvisioningNativeViewsV1,
        policy: &RootHostLaunchPolicyOriginalV1,
    ) -> Result<(), JournalError> {
        self.compiled_v2()?;
        readonly.require_complete_v2()?;
        views.require_complete_v1()?;
        policy
            .require_complete_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let origin = self.observed.ok_or(JournalError::ProtectedBoundary)?;
        for sample in [readonly.completed_clock_v2()?, views.clock_v1()?] {
            self.clock
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .require_final_sample_v1(sample)?;
            origin
                .validate_later_sample(sample)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if sample.wall_seconds() >= self.expires_v2(policy)? {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.compiler_geometry
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.compiler_funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.source.failure())
            .or_else(|| {
                self.result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.closed.then_some(&JournalError::ProtectedBoundary as _))
    }
}
