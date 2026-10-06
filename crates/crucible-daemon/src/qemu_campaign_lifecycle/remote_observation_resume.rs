//! Campaign-owned authentication and restore for remote observation resumes.
//!
//! The API transports opaque proof and evidence bytes. This module decodes
//! them, reproduces the source from scenario genesis under bounded QEMU
//! resources, captures the exact observed boundary without continuing it, and
//! restores that physical checkpoint into an ordinary lifecycle loop.

use std::sync::Arc;

use crucible::Configuration;
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig, ProductionVmLifecycleLoop,
    ResumeObservationPreparationContext, ResumeSessionRequest,
};
#[cfg(test)]
use crucible_campaign::AttemptResourceLimits;
use crucible_campaign::ObservationStopProof;
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
#[cfg(test)]
use crucible_qemu::LinuxQemuAttemptHostConfig;

use super::campaign_run::{
    GuardedCampaignOwner, GuardedCampaignReplayClosure, GuardedDefaultCampaignObservationSource,
    GuardedDefaultCampaignRunRequest, run_guarded_default_campaign,
};
use crate::supervision::ProcessDeadline;
use crate::{
    ComposedQemuAttemptResourceGuardFactory, CrucibleMeasurementReplayEvidence,
    ExecutionCancellation,
};

/// Replays, authenticates, captures, and restores one remote observation source.
#[derive(Clone)]
pub struct RemoteObservationResumeFactory {
    engine_build_id: String,
    qemu_build_id: String,
    lifecycle: Arc<ProductionVmLifecycleConfig>,
    owner: Option<GuardedCampaignOwner>,
    verify_determinism_findings: bool,
}

impl RemoteObservationResumeFactory {
    /// Canonical transport-envelope version consumed by this factory.
    pub const SOURCE_SCHEMA_VERSION: u32 = 1;

    /// Creates a resume factory sharing an already admitted campaign owner.
    ///
    /// # Errors
    ///
    /// Refuses an owner lacking its original assignment and lifecycle authority.
    pub fn new(
        engine_build_id: impl Into<String>,
        qemu_build_id: impl Into<String>,
        owner: GuardedCampaignOwner,
        verify_determinism_findings: bool,
    ) -> Result<Self, LifecycleApiError> {
        let (lifecycle, _, _) = owner
            .inner
            .config
            .guarded_inputs()
            .ok_or_else(|| observation_error("guarded owner lacks assignment authority"))?;
        Ok(Self {
            engine_build_id: engine_build_id.into(),
            qemu_build_id: qemu_build_id.into(),
            lifecycle,
            owner: Some(owner),
            verify_determinism_findings,
        })
    }

    /// Creates policy-only component fixtures without native launch authority.
    #[cfg(test)]
    fn new_component(
        engine_build_id: impl Into<String>,
        qemu_build_id: impl Into<String>,
        lifecycle: ProductionVmLifecycleConfig,
        _host: LinuxQemuAttemptHostConfig,
        _resources: AttemptResourceLimits,
        verify_determinism_findings: bool,
    ) -> Self {
        Self {
            engine_build_id: engine_build_id.into(),
            qemu_build_id: qemu_build_id.into(),
            lifecycle: Arc::new(lifecycle),
            owner: None,
            verify_determinism_findings,
        }
    }

    fn apply_determinism_finding_policy(
        &self,
        request: GuardedDefaultCampaignRunRequest,
    ) -> GuardedDefaultCampaignRunRequest {
        if self.verify_determinism_findings {
            request.with_determinism_finding_verification()
        } else {
            request
        }
    }

    /// Authenticates the pending source and returns a loop restored at its boundary.
    ///
    /// Source replay and capture use the deployment's fixed campaign resource
    /// limits and the original campaign actor. The captured raw root receives
    /// independent replay promotion before a fresh charged Service consumes
    /// its selected-root authority. The loop retains that Service through
    /// final native cleanup; uncertain cleanup quarantines its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeObservationSource`] for a missing,
    /// malformed, mismatched, unreproduced, uncaptured, canceled, timed-out, or
    /// unrestorable source, including failed replay or physical cleanup.
    pub fn resume_loop(
        &self,
        request: &ResumeSessionRequest,
        configuration: &Configuration,
        context: &ResumeObservationPreparationContext,
    ) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
        if self.owner.is_none() {
            return Err(observation_error(
                "policy-only component fixture has no native resume authority",
            ));
        }
        self.prepare_resume_loop(request, configuration, context)
    }

    fn prepare_resume_loop(
        &self,
        request: &ResumeSessionRequest,
        configuration: &Configuration,
        context: &ResumeObservationPreparationContext,
    ) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
        let execution_cancellation = ExecutionCancellation::default();
        let cancel_execution = execution_cancellation.clone();
        let cancellation_registration = context
            .cancellation()
            .register(move || cancel_execution.cancel());
        let preparation_deadline = ProcessDeadline::at(context.deadline());
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;
        let owner = self
            .owner
            .as_ref()
            .ok_or_else(|| observation_error("component fixture has no native owner"))?;
        let decoding = crucible::owned_decode::DecodeBudget::for_store(
            owner.repository_metadata_resources().map_err(|error| {
                observation_error(format!("admit observation input resources: {error}"))
            })?,
        )
        .map_err(|error| observation_error(format!("admit observation decoding: {error}")))?;
        let _decode_scope = decoding.enter();
        let preparation_budgets =
            owner.inner.config.host_operation_budgets().ok_or_else(|| {
                observation_error("guarded owner lacks deployed preparation budgets")
            })?;
        let preparation_supervisor = HostOperationSupervisor::new(
            preparation_budgets,
            Some(preparation_deadline.remaining()),
        )
        .map_err(|error| observation_error(format!("admit original preparation cap: {error}")))?;

        let source = &request.observation_source;
        if source.schema_version() != Self::SOURCE_SCHEMA_VERSION {
            return Err(observation_error(format!(
                "portable observation source schema {} is unsupported; expected {}",
                source.schema_version(),
                Self::SOURCE_SCHEMA_VERSION,
            )));
        }
        let proof = ObservationStopProof::from_canonical_bytes(source.proof())
            .map_err(|error| observation_error(format!("decode observation proof: {error}")))?;
        let evidence = CrucibleMeasurementReplayEvidence::from_canonical_bytes(source.evidence())
            .map_err(|error| {
            observation_error(format!("decode observation evidence: {error}"))
        })?;
        evidence
            .verify_observation_stop_proof(&proof)
            .map_err(|error| observation_error(format!("validate observation source: {error}")))?;
        let closure = decode_replay_closure(request)?;
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;

        let remaining = preparation_deadline.remaining();
        let operation_timeout = self.lifecycle.completion_timeout().min(remaining);
        if operation_timeout.is_zero() {
            execution_cancellation.cancel();
            return Err(observation_error(
                "portable observation preparation deadline elapsed",
            ));
        }
        let source_lifecycle = Arc::new(
            self.lifecycle
                .try_clone_admitted()
                .map_err(|error| {
                    observation_error(format!("copy admitted source lifecycle: {error}"))
                })?
                .with_completion_timeout(operation_timeout),
        );
        // Publication and later selected-root authentication use the original
        // owner's actual CAS namespace and durable reader authority.
        let checkpoints = Arc::clone(&owner.inner.checkpoints);
        let campaign_request = self.apply_determinism_finding_policy(
            GuardedDefaultCampaignRunRequest::new(
                request.scenario.try_clone_admitted().map_err(|error| {
                    observation_error(format!("copy admitted observation scenario: {error}"))
                })?,
                request.seed,
                self.engine_build_id.clone(),
                self.qemu_build_id.clone(),
                self.owner
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| observation_error("component fixture has no native owner"))?,
            )
            .map_err(|error| observation_error(format!("bind guarded source owner: {error}")))?
            .with_guarded_lifecycle(source_lifecycle.try_clone_admitted().map_err(|error| {
                observation_error(format!("copy admitted campaign lifecycle: {error}"))
            })?)
            .map_err(|error| observation_error(format!("bind source lifecycle: {error}")))?
            .with_execution_cancellation(execution_cancellation.clone())
            .with_observation_resume_source_capture_only(
                request.schedule.try_clone_admitted().map_err(|error| {
                    observation_error(format!("copy admitted observation schedule: {error}"))
                })?,
                closure,
                request.checkpoint.try_clone_admitted().map_err(|error| {
                    observation_error(format!("copy admitted observation checkpoint: {error}"))
                })?,
                GuardedDefaultCampaignObservationSource::new(proof, evidence),
                Arc::clone(&checkpoints),
            ),
        );
        let campaign = run_guarded_default_campaign(campaign_request)
            .map_err(|error| observation_error(format!("authenticate source campaign: {error}")))?;
        campaign
            .resume()
            .and_then(|proof| proof.source_savepoint())
            .ok_or_else(|| observation_error("source campaign did not retain an exact capture"))?;
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;

        let continuation = owner
            .continuation(
                &campaign,
                execution_cancellation.clone(),
                preparation_supervisor,
                &source_lifecycle,
            )
            .map_err(|error| observation_error(format!("promote source checkpoint: {error}")))?;
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;
        // Promotion can consume most of the original allowance. Restore must
        // use the remaining cap at launch, rather than a pre-promotion sample.
        let restore_timeout = self
            .lifecycle
            .completion_timeout()
            .min(preparation_deadline.remaining());
        if restore_timeout.is_zero() {
            execution_cancellation.cancel();
            return Err(observation_error(
                "portable observation preparation deadline elapsed before restore",
            ));
        }
        let resumed_lifecycle = source_lifecycle
            .try_clone_admitted()
            .map_err(|error| {
                observation_error(format!("copy admitted restored lifecycle: {error}"))
            })?
            .with_completion_timeout(restore_timeout);
        let mut restore_factory = super::QemuAttemptProductionVmLifecycleFactory::new(
            resumed_lifecycle,
            ComposedQemuAttemptResourceGuardFactory::new(owner.inner.host.clone()),
        );
        let restored = restore_factory.begin_resume(
            &checkpoints,
            continuation.checkpoint,
            super::QemuExactResumeBasis::new(
                &configuration.def,
                &request.scenario,
                configuration,
                None,
            ),
            continuation.service.context(),
        );
        drop(restore_factory);
        let loop_instance = match restored {
            Ok(loop_instance) => loop_instance,
            Err(error) => {
                continuation.service.retain_after_unknown_cleanup();
                return Err(observation_error(format!(
                    "restore source checkpoint: {error}"
                )));
            }
        };
        let loop_instance =
            loop_instance.with_retained_resource_owner(Arc::new(continuation.service));
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;
        Ok(loop_instance.with_retained_resource_owner(cancellation_registration))
    }
}

fn ensure_preparation_active(
    context: &ResumeObservationPreparationContext,
    execution_cancellation: &ExecutionCancellation,
    deadline: ProcessDeadline,
) -> Result<(), LifecycleApiError> {
    if context.cancellation().is_canceled() {
        execution_cancellation.cancel();
        return Err(observation_error(
            "portable observation source preparation was canceled",
        ));
    }
    if deadline.expired() {
        execution_cancellation.cancel();
        return Err(observation_error(
            "portable observation preparation deadline elapsed",
        ));
    }
    Ok(())
}

fn decode_replay_closure(
    request: &ResumeSessionRequest,
) -> Result<GuardedCampaignReplayClosure, LifecycleApiError> {
    let envelope = request
        .replay_closure
        .as_ref()
        .ok_or_else(|| observation_error("campaign replay closure envelope is missing"))?;
    if envelope.schema_version() != GuardedCampaignReplayClosure::SCHEMA_VERSION {
        return Err(observation_error(format!(
            "campaign replay closure schema {} is unsupported",
            envelope.schema_version(),
        )));
    }
    GuardedCampaignReplayClosure::from_canonical_bytes(envelope.payload())
        .map_err(|error| observation_error(format!("decode replay closure: {error}")))
}

fn observation_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::ResumeObservationSource {
        message: message.into(),
    }
}

// Fixture policy reserves an explicit finite descriptor ceiling independently of vCPU count.
#[cfg(test)]
const TEST_HOST_FILE_DESCRIPTORS: u64 = 1_024;

// Host-side pager workers and sockets have independent finite fixture entitlements.
#[cfg(test)]
const TEST_HOST_SERVICE_TASKS: u64 = 4;
#[cfg(test)]
const TEST_HOST_SERVICE_FILE_DESCRIPTORS: u64 = 32;

// Operational services retain their own authored memory budgets outside QEMU.
#[cfg(test)]
const TEST_HOST_SERVICE_RESIDENT_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(test)]
const TEST_WATCHER_SERVICE_RESIDENT_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crucible::{
        Icount, NodeId, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioDefForm, Seed,
        WhiteBoxPolicy, World, WorldNode,
    };

    #[test]
    fn factory_applies_deployment_determinism_policy_to_authentication_campaign()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = factory(false)?.apply_determinism_finding_policy(campaign_request()?);
        assert!(!request.verifies_determinism_findings());

        let request = factory(true)?.apply_determinism_finding_policy(campaign_request()?);
        assert!(request.verifies_determinism_findings());
        Ok(())
    }

    fn factory(
        verify_determinism_findings: bool,
    ) -> Result<RemoteObservationResumeFactory, Box<dyn std::error::Error>> {
        Ok(RemoteObservationResumeFactory::new_component(
            "remote-observation-policy-engine",
            "remote-observation-policy-qemu",
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
            host()?,
            resources()?,
            verify_determinism_findings,
        ))
    }

    fn campaign_request() -> Result<GuardedDefaultCampaignRunRequest, Box<dyn std::error::Error>> {
        let seed = Seed::from_u64(0x7265_6d6f_7465_706f);
        let world = World::from_nodes(vec![WorldNode {
            id: NodeId {
                name: String::from("remote-observation-policy-node"),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("remote-observation-policy-test"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            kernel: None,
            root_image: None,
            initrd: None,
        }])?;
        let scenario =
            ScenarioDefForm::from_components(&world, &Plan::empty(), &Properties::empty(), seed)?;

        Ok(GuardedDefaultCampaignRunRequest::new_component(
            scenario,
            seed,
            "remote-observation-policy-engine",
            "remote-observation-policy-qemu",
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
            host()?,
            resources()?,
        ))
    }

    fn host() -> Result<LinuxQemuAttemptHostConfig, Box<dyn std::error::Error>> {
        Ok(LinuxQemuAttemptHostConfig::new(
            "/sys/fs/cgroup/crucible-remote-observation-policy-test",
            "/tmp/crucible-remote-observation-policy-test",
            "remote-observation-policy-test",
            1,
            1,
            65_527,
            65_527,
            16,
            TEST_HOST_FILE_DESCRIPTORS,
            TEST_HOST_SERVICE_TASKS,
            TEST_HOST_SERVICE_FILE_DESCRIPTORS,
            TEST_HOST_SERVICE_RESIDENT_BYTES,
            TEST_WATCHER_SERVICE_RESIDENT_BYTES,
            1_024,
            Duration::from_secs(1),
        )?)
    }

    fn resources() -> Result<AttemptResourceLimits, Box<dyn std::error::Error>> {
        Ok(AttemptResourceLimits::new(
            1,
            256 * 1024 * 1024,
            1024 * 1024,
            16,
        )?)
    }
}
