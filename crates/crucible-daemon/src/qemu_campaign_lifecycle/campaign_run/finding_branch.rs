//! Canonical target-attempt execution on an imported finding's original actor.
//!
//! The accepted proposal, selection and attempt already exist in the receiver
//! repository. Its ordinary executor driver consumes that durable target using
//! the same charged queue and production worker; it creates no second executor.

use super::*;
use crucible_campaign::{AttemptId, ExecutorClient, WorkerSlotId};
use std::io;

/// Failure executing an admitted branch on its genuine retained campaign owner.
#[derive(Debug, Error)]
pub enum GuardedFindingBranchError {
    /// The receiver's immutable campaign records failed authentication.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The branch request or its bounded driver configuration was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// The original actor refused admission or caller authority.
    #[error(transparent)]
    Authority(#[from] crucible_api::host_operational::HostOperationalError),
    /// The caller's original operation boundary refused another effect.
    #[error("original branch operation boundary failed: {0}")]
    Boundary(#[source] io::Error),
    /// The production driver failed while retaining its original cleanup custody.
    #[error("admitted branch execution failed: {0}")]
    Execution(#[source] Box<dyn Error + Send + Sync>),
    /// The target did not produce the expected canonical observation.
    #[error("admitted branch invariant failed: {0}")]
    Refused(&'static str),
}

impl GuardedFindingBranchError {
    fn execution(error: impl Error + Send + 'static) -> Self {
        Self::Execution(Box::new(
            crate::packaged_qemu_executor::guarded::RetainedOperationError::new(error),
        ))
    }
}

pub(crate) fn run_admitted_finding_branch(
    owner: &GuardedCampaignOwner,
    campaign: &CampaignName,
    target: AttemptId,
    cancellation: ExecutionCancellation,
    caller_supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
    boundary: &mut dyn FnMut() -> io::Result<()>,
) -> Result<Observation, GuardedFindingBranchError> {
    boundary().map_err(GuardedFindingBranchError::Boundary)?;
    let repository = owner.inner.repository.clone();
    let head = repository.head(campaign.as_str())?;
    let lineage = repository.load_lineage(head.snapshot().lineage())?;
    owner.bind_profile(
        ExecutorCompatibilityProfile::from_lineage(&lineage),
        BTreeSet::from([lineage.scenario_content()]),
    )?;
    let resources = owner
        .inner
        .config
        .assignment_limits()
        .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?;
    // The admitted worker authenticates and decodes the scenario under its
    // original metadata authority before native setup. Avoid a second copy
    // merely to preflight the already accepted request here.

    let store = CampaignExecutorStore::new(repository.clone());
    let exact_retention = Arc::new(CampaignRunFindingExactRetentionSource::new(
        store.clone(),
        owner.inner.checkpoints.clone(),
    ));
    let (lifecycle, _, _) = owner
        .inner
        .config
        .guarded_inputs()
        .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?;
    let (runner, _) = production_campaign_runner(
        lifecycle,
        owner.inner.host.clone(),
        store.clone(),
        owner.inner.checkpoints.clone(),
        exact_retention.clone(),
        None,
        owner.inner.config.verifies_determinism_findings(),
    );
    let model = CrucibleExecutionModel::new(store.clone(), runner);
    let service = SynchronousCampaignExecutor::new_admitted(
        store,
        exact_retention,
        model,
        cancellation.clone(),
        owner.clone(),
    )
    .under_caller(caller_supervisor);
    let mut driver = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(service),
        owner.inner.config.guarded_epoch(),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        DEFAULT_RUN_EXECUTOR_SCAN,
    )
    .map_err(GuardedFindingBranchError::execution)?
    .for_private_target_attempt(target);

    for _ in 0..DEFAULT_RUN_MAX_SUPERVISOR_STEPS {
        if let Err(error) = boundary() {
            cancellation.cancel();
            driver
                .cancel_one(campaign.as_str())
                .map_err(GuardedFindingBranchError::execution)?;
            return Err(GuardedFindingBranchError::Boundary(error));
        }
        let outcome = driver
            .step(campaign.as_str(), WorkerSlotId::new(0))
            .map_err(GuardedFindingBranchError::execution)?;
        match outcome {
            CampaignExecutorStepOutcome::Incorporated(completed) => {
                let observation =
                    repository.load_observation(completed.observation_result().observation)?;
                if observation.attempt() != target {
                    return Err(GuardedFindingBranchError::Refused(
                        "completion names another attempt",
                    ));
                }
                boundary().map_err(GuardedFindingBranchError::Boundary)?;
                return Ok(observation);
            }
            CampaignExecutorStepOutcome::Blocked { .. }
            | CampaignExecutorStepOutcome::Closed(_)
            | CampaignExecutorStepOutcome::Inactive { .. }
            | CampaignExecutorStepOutcome::AlreadyResolved { .. }
            | CampaignExecutorStepOutcome::Idle { .. } => {
                cancellation.cancel();
                driver
                    .cancel_one(campaign.as_str())
                    .map_err(GuardedFindingBranchError::execution)?;
                return Err(GuardedFindingBranchError::Refused(
                    "target has no accepted completion",
                ));
            }
            _ => {}
        }
    }
    cancellation.cancel();
    driver
        .cancel_one(campaign.as_str())
        .map_err(GuardedFindingBranchError::execution)?;
    Err(GuardedFindingBranchError::Refused(
        "bounded target driver step limit exceeded",
    ))
}
