//! Campaign-owned authentication and restore for remote observation resumes.
//!
//! The API transports opaque proof and evidence bytes. This module decodes
//! them, reproduces the source from scenario genesis under bounded QEMU
//! resources, captures the exact observed boundary without continuing it, and
//! restores that physical checkpoint into an ordinary lifecycle loop.

use std::path::Path;
use std::sync::Arc;

use crucible::Configuration;
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig, ProductionVmLifecycleLoop,
    ResumeObservationPreparationContext, ResumeSessionRequest,
};
use crucible_campaign::{AttemptResourceLimits, ExecutionRetentionIntent, ObservationStopProof};
use crucible_cas::content_store::DirectoryBlobBackend;
use crucible_qemu::LinuxQemuAttemptHostConfig;

use super::campaign_run::{
    GuardedCampaignReplayClosure, GuardedDefaultCampaignObservationSource,
    GuardedDefaultCampaignRunRequest, run_guarded_default_campaign_with_host,
};
use crate::qemu_resource_guard::RetainedLinuxQemuAttemptWorkspace;
use crate::supervision::ProcessDeadline;
use crate::{
    AttemptExecutionContext, ComposedQemuAttemptResourceGuardFactory,
    CrucibleMeasurementReplayEvidence, ExactCheckpointStore, ExecutionCancellation,
    ExecutionCheckpointRequest,
};

/// Replays, authenticates, captures, and restores one remote observation source.
#[derive(Clone)]
pub struct RemoteObservationResumeFactory {
    engine_build_id: String,
    qemu_build_id: String,
    lifecycle: ProductionVmLifecycleConfig,
    host: LinuxQemuAttemptHostConfig,
    resources: AttemptResourceLimits,
    verify_determinism_findings: bool,
}

impl RemoteObservationResumeFactory {
    /// Canonical transport-envelope version consumed by this factory.
    pub const SOURCE_SCHEMA_VERSION: u32 = 1;

    /// Creates a factory from fixed daemon deployment and resource authority.
    #[must_use]
    pub fn new(
        engine_build_id: impl Into<String>,
        qemu_build_id: impl Into<String>,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
        verify_determinism_findings: bool,
    ) -> Self {
        Self {
            engine_build_id: engine_build_id.into(),
            qemu_build_id: qemu_build_id.into(),
            lifecycle,
            host,
            resources,
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
    /// limits. Native bytes stream through a quota-bound request-local
    /// directory, and the returned lifecycle retains that directory until its
    /// final process generation has been torn down. Error paths clean up after
    /// process reap when safe and otherwise retain the owner in quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::ResumeObservationSource`] for a missing,
    /// malformed, mismatched, unreproduced, uncaptured, canceled, timed-out, or
    /// unrestorable source, including a failed request-local cleanup.
    pub fn resume_loop(
        &self,
        request: &ResumeSessionRequest,
        configuration: &Configuration,
        context: &ResumeObservationPreparationContext,
    ) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
        let workspace =
            RetainedLinuxQemuAttemptWorkspace::allocate(self.host.clone(), self.resources)
                .map_err(|error| {
                    observation_error(format!("allocate request workspace: {error}"))
                })?;
        let outcome = self.resume_loop_in_workspace(
            request,
            configuration,
            context,
            workspace.path(),
            &workspace,
        );
        match outcome {
            Ok(loop_instance) => Ok(loop_instance.with_retained_resource_owner(workspace)),
            Err(error) => match workspace.close() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(observation_error(format!(
                    "{error}; remove request workspace: {cleanup}"
                ))),
            },
        }
    }

    fn resume_loop_in_workspace(
        &self,
        request: &ResumeSessionRequest,
        configuration: &Configuration,
        context: &ResumeObservationPreparationContext,
        workspace_path: &Path,
        workspace: &RetainedLinuxQemuAttemptWorkspace,
    ) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
        let execution_cancellation = ExecutionCancellation::default();
        let cancel_execution = execution_cancellation.clone();
        let cancellation_registration = context
            .cancellation()
            .register(move || cancel_execution.cancel());
        let preparation_deadline = ProcessDeadline::at(context.deadline());
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;

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
        let source_lifecycle = self
            .lifecycle
            .clone()
            .with_run_state_root(workspace_path.join("source-run-state"))
            .with_completion_timeout(operation_timeout);
        let resumed_run_state = workspace_path.join("resumed-run-state");
        let checkpoint_backend = Arc::new(DirectoryBlobBackend::new(
            "remote-observation-resume",
            workspace_path.join("exact-checkpoints"),
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(checkpoint_backend, self.resources.maximum_disk_bytes())
                .map_err(|error| {
                    observation_error(format!("open exact checkpoint store: {error}"))
                })?,
        );
        let campaign_request = self.apply_determinism_finding_policy(
            GuardedDefaultCampaignRunRequest::new(
                request.scenario.clone(),
                request.seed,
                self.engine_build_id.clone(),
                self.qemu_build_id.clone(),
                source_lifecycle,
                self.host.clone(),
                self.resources,
            )
            .with_execution_cancellation(execution_cancellation.clone())
            .with_observation_resume_source_capture_only(
                request.schedule.clone(),
                closure,
                request.checkpoint.clone(),
                GuardedDefaultCampaignObservationSource::new(proof, evidence),
                Arc::clone(&checkpoints),
            ),
        );
        let campaign =
            run_guarded_default_campaign_with_host(campaign_request, workspace.factory()).map_err(
                |error| observation_error(format!("authenticate source campaign: {error}")),
            )?;
        let captured = campaign
            .resume()
            .and_then(|proof| proof.source_savepoint())
            .ok_or_else(|| observation_error("source campaign did not retain an exact capture"))?;
        ensure_preparation_active(context, &execution_cancellation, preparation_deadline)?;

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
        let resumed_lifecycle = self
            .lifecycle
            .clone()
            .with_run_state_root(resumed_run_state)
            .with_completion_timeout(restore_timeout);
        let restore_context = AttemptExecutionContext::new(
            self.resources,
            ExecutionRetentionIntent::Discard,
            execution_cancellation.clone(),
            ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        )
        .with_resume_checkpoint(Some(captured.checkpoint()));
        let mut restore_factory = super::QemuAttemptProductionVmLifecycleFactory::new(
            resumed_lifecycle,
            ComposedQemuAttemptResourceGuardFactory::new(workspace.factory()),
        );
        let loop_instance = restore_factory
            .begin_resume(
                &checkpoints,
                captured.checkpoint(),
                super::QemuExactResumeBasis::new(
                    &configuration.def,
                    &request.scenario,
                    configuration,
                    None,
                ),
                &restore_context,
            )
            .map_err(|error| observation_error(format!("restore source checkpoint: {error}")))?;
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
        Ok(RemoteObservationResumeFactory::new(
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
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])?;
        let scenario =
            ScenarioDefForm::from_components(&world, &Plan::empty(), &Properties::empty(), seed)?;

        Ok(GuardedDefaultCampaignRunRequest::new(
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
