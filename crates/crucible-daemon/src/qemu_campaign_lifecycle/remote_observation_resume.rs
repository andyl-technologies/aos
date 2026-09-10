//! Campaign-owned authentication and restore for remote observation resumes.
//!
//! The API transports opaque proof and evidence bytes. This module decodes
//! them, reproduces the source from scenario genesis under bounded QEMU
//! resources, captures the exact observed boundary without continuing it, and
//! restores that physical checkpoint into an ordinary lifecycle loop.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crucible::{Configuration, Schedule};
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig, ProductionVmLifecycleLoop,
    ResumeObservationPreparationContext, ResumeSessionRequest,
};
use crucible_campaign::{AttemptResourceLimits, ExecutionRetentionIntent, ObservationStopProof};
use crucible_cas::content_store::DirectoryBlobBackend;
use crucible_qemu::LinuxQemuAttemptHostConfig;

use super::legacy_run::{
    GuardedCampaignReplayClosure, GuardedDefaultCampaignObservationSource,
    GuardedDefaultCampaignRunRequest, run_guarded_default_campaign_with_host,
};
use crate::qemu_resource_guard::RetainedLinuxQemuAttemptWorkspace;
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
    ) -> Self {
        Self {
            engine_build_id: engine_build_id.into(),
            qemu_build_id: qemu_build_id.into(),
            lifecycle,
            host,
            resources,
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
        ensure_preparation_active(context, &execution_cancellation)?;

        let source = request
            .observation_source
            .as_ref()
            .ok_or_else(|| observation_error("portable observation source envelope is missing"))?;
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
        let closure = decode_replay_closure(request, &configuration.schedule)?;
        ensure_preparation_active(context, &execution_cancellation)?;

        let remaining = context
            .deadline()
            .saturating_duration_since(observation_preparation_now());
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
        let campaign_request = GuardedDefaultCampaignRunRequest::new(
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
        );
        let campaign =
            run_guarded_default_campaign_with_host(campaign_request, workspace.factory()).map_err(
                |error| observation_error(format!("authenticate source campaign: {error}")),
            )?;
        let captured = campaign
            .resume()
            .and_then(|proof| proof.source_savepoint())
            .ok_or_else(|| observation_error("source campaign did not retain an exact capture"))?;
        ensure_preparation_active(context, &execution_cancellation)?;

        let restore_timeout = self.lifecycle.completion_timeout().min(
            context
                .deadline()
                .saturating_duration_since(observation_preparation_now()),
        );
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
                &configuration.def,
                &request.scenario,
                configuration,
                None,
                &restore_context,
            )
            .map_err(|error| observation_error(format!("restore source checkpoint: {error}")))?;
        ensure_preparation_active(context, &execution_cancellation)?;
        Ok(loop_instance.with_retained_resource_owner(cancellation_registration))
    }
}

fn ensure_preparation_active(
    context: &ResumeObservationPreparationContext,
    execution_cancellation: &ExecutionCancellation,
) -> Result<(), LifecycleApiError> {
    if context.cancellation().is_canceled() {
        execution_cancellation.cancel();
        return Err(observation_error(
            "portable observation source preparation was canceled",
        ));
    }
    if observation_preparation_now() >= context.deadline() {
        execution_cancellation.cancel();
        return Err(observation_error(
            "portable observation preparation deadline elapsed",
        ));
    }
    Ok(())
}

// Monotonic host time limits request preparation and process ownership only;
// it never enters campaign evidence, checkpoint identity, or guest execution.
// crucible-lint: allow clippy-disallowed-method -- this deadline is an operational resource bound only.
#[allow(clippy::disallowed_methods)]
fn observation_preparation_now() -> Instant {
    Instant::now()
}

fn decode_replay_closure(
    request: &ResumeSessionRequest,
    schedule: &Schedule,
) -> Result<GuardedCampaignReplayClosure, LifecycleApiError> {
    match request.replay_closure.as_ref() {
        Some(envelope) => {
            if envelope.schema_version() != GuardedCampaignReplayClosure::SCHEMA_VERSION {
                return Err(observation_error(format!(
                    "campaign replay closure schema {} is unsupported",
                    envelope.schema_version(),
                )));
            }
            GuardedCampaignReplayClosure::from_canonical_bytes(envelope.payload())
                .map_err(|error| observation_error(format!("decode replay closure: {error}")))
        }
        None => GuardedCampaignReplayClosure::empty_for_selection_free_schedule(schedule)
            .map_err(|error| observation_error(format!("construct empty replay closure: {error}"))),
    }
}

fn observation_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::ResumeObservationSource {
        message: message.into(),
    }
}
