//! Authenticated native baked-genesis checkpoints for production replay.
//!
//! A concrete replay-oracle worker needs an independently captured thin base
//! before it can compare a newly paused fat checkpoint. This module turns the
//! ordinary guarded fresh-lifecycle capture into an authenticated, read-only
//! modeled snapshot set. It deliberately does not publish a campaign root.
//! Packaged composition advertises exact restore only after it has installed
//! the fixed replay factories under disjoint thin bindings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use crucible::{
    Configuration, ContentHash, NodeId, ScenarioDef, ScenarioDefForm,
    SchedulerOperationalFailureClass, World,
};
use crucible_api::{
    LifecycleApiError, ProductionBakedSnapshotSet, ProductionVmLifecycleConfig,
    ProductionVmNodeReplayLaunchProfile, ProductionVmReplayExactNodeRestoreAdmission,
};
use crucible_campaign::{AttemptResourceLimits, ExecutionRetentionIntent};
use crucible_qemu::{
    QemuBakedGenesisSnapshot, QemuLiveNodeStepGateConfig, QemuReplayValidationExecutor,
    QemuReplayValidationThinAdmission, QemuVmRealizationError,
};
use thiserror::Error;

use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure,
    CrucibleAttemptExecution, CrucibleExecutionRunner, ExecutionCancellation,
    ExecutionCheckpointRequest, ProductionPausedCheckpointReplayFactory,
    ProductionPausedCheckpointReplaySession, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmLifecycleFactory, QemuAttemptResourceGuardFactory,
    QemuFreshAttemptLifecycleFactory, QemuFreshExecutionRunner,
    QemuFreshGenesisCheckpointCandidate, QemuFreshGenesisCheckpointError, QemuSavepointReplayProbe,
    QemuSavepointReplayProof, capture_fresh_genesis_checkpoint_candidate,
};

/// One completely authenticated baked-genesis snapshot set.
///
/// The capability retains authenticated modeled snapshots captured before
/// retirement of the native closure. It exposes no mutation, campaign-ref, or
/// machine-state artifact authority. Cloned replay factories share the set.
#[derive(Clone)]
pub struct ProductionBakedGenesisCheckpoint {
    world: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    closure: ContentHash,
    targets: Arc<ProductionBakedSnapshotSet>,
    launch_profiles: Arc<BTreeMap<NodeId, ProductionVmNodeReplayLaunchProfile>>,
}

/// Read-only baked-genesis realization store for one World VM.
///
/// Exact-target selection is supplied explicitly by the replay comparison, so
/// this store deliberately exposes neither an exact cache hit nor an ancestor.
/// Its only thin source is the already authenticated native baked checkpoint.
pub(crate) struct ProductionBakedGenesisReplayStore {
    world: ContentHash,
    scenario: ContentHash,
    baked: QemuBakedGenesisSnapshot,
}

/// Concrete guarded replay factory backed by authenticated baked genesis state.
///
/// The factory opens one baked snapshot by node, installs one attempt resource
/// guard, materializes only the repository-rooted exact target, and realizes
/// the comparison leg from a fresh launch at the authenticated modeled genesis.
/// It owns no campaign mutation or checkpoint-publication capability.
struct ProductionBakedGenesisReplayFactory {
    baked: ProductionBakedGenesisCheckpoint,
}

/// Scenario-routed native baked-genesis replay authority.
///
/// A packaged executor may admit several exact scenario artifacts while still
/// sharing one aggregate host-resource allocator and worker pool. This catalog
/// selects the immutable baked checkpoint by the authenticated World and
/// scenario identities supplied by promotion recovery. It never falls back to
/// another scenario.
#[derive(Clone)]
pub struct ProductionBakedGenesisReplayCatalogFactory<R> {
    baked_by_basis: BTreeMap<(ContentHash, ContentHash), ProductionBakedGenesisCheckpoint>,
    resources: R,
    savepoint_replay_config: Option<ProductionVmLifecycleConfig>,
}

struct ReplayTargetPreparation<'a> {
    exact: ProductionVmReplayExactNodeRestoreAdmission,
    baked_snapshot: &'a crucible_qemu::QemuVmSnapshot,
    profile: &'a ProductionVmNodeReplayLaunchProfile,
    world: ContentHash,
    scenario: ContentHash,
}

impl std::fmt::Debug for ProductionBakedGenesisCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBakedGenesisCheckpoint")
            .field("world", &self.world)
            .field("scenario", &self.scenario)
            .field("configuration", &self.configuration)
            .field("closure", &self.closure)
            .field("launch_profile_count", &self.launch_profiles.len())
            .finish_non_exhaustive()
    }
}

/// Rejection while admitting a fresh capture as baked-genesis authority.
#[derive(Debug, Error)]
pub enum ProductionBakedGenesisCheckpointError {
    /// The native closure failed complete production authentication.
    #[error(transparent)]
    Closure(#[from] LifecycleApiError),
    /// The closure names another scenario or a non-genesis configuration.
    #[error("baked-genesis closure does not authenticate the exact scenario genesis")]
    SemanticBasisMismatch,
    /// The fresh closure omitted one World VM or named a foreign/duplicate VM.
    #[error("baked-genesis closure live-node set does not equal the scenario World")]
    NodeSetMismatch,
}

/// Failure while capturing and admitting one production baked genesis.
#[derive(Debug, Error)]
pub enum ProductionBakedGenesisCaptureError<E> {
    /// Guarded fresh-lifecycle capture or teardown failed.
    #[error(transparent)]
    Capture(#[from] QemuFreshGenesisCheckpointError<E>),
    /// The completed capture did not satisfy baked-genesis admission.
    #[error(transparent)]
    Admission(#[from] ProductionBakedGenesisCheckpointError),
}

impl ProductionBakedGenesisCheckpoint {
    /// Admits one fresh exact capture as a native baked-genesis checkpoint.
    ///
    /// Admission requires the production root carrying a version-nine manifest,
    /// complete closure authentication, exact scenario genesis, and exactly one
    /// live target for every VM in the World. No destination or campaign store
    /// is written.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBakedGenesisCheckpointError`] when the capture has a malformed manifest or any closure,
    /// semantic-basis, or node-set invariant fails.
    pub fn admit(
        source: &ScenarioDefForm,
        candidate: QemuFreshGenesisCheckpointCandidate,
        cancellation: &ExecutionCancellation,
    ) -> Result<Self, ProductionBakedGenesisCheckpointError> {
        let (capture, launch_profiles) = candidate.into_parts();
        let closure = Arc::new(capture.into_closure());
        let scenario = source.scenario_def();
        let genesis = Configuration::genesis(scenario.clone());
        if closure.scenario() != scenario.id() || closure.configuration() != genesis.id() {
            return Err(ProductionBakedGenesisCheckpointError::SemanticBasisMismatch);
        }

        let mut expected = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| node.id.clone())
            .collect::<BTreeSet<NodeId>>();
        if expected.is_empty() || expected.len() > crate::MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
        }
        let launch_profiles = launch_profiles
            .into_iter()
            .map(|profile| (profile.node().clone(), profile))
            .collect::<BTreeMap<_, _>>();
        if launch_profiles.len() != expected.len() || launch_profiles.keys().ne(expected.iter()) {
            return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
        }
        let mut boundary = || cancellation_boundary(cancellation);
        let targets = closure
            .baked_snapshot_catalog_with_boundary(&mut boundary)?
            .materialize_with_boundary(&mut boundary)?;
        for node in targets.nodes() {
            let snapshot = targets
                .snapshot(node)
                .ok_or(ProductionBakedGenesisCheckpointError::NodeSetMismatch)?;
            if !expected.remove(node) || snapshot.checkpoint().configuration != genesis.id() {
                return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
            }
        }
        if !expected.is_empty() {
            return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
        }

        Ok(Self {
            world: source.world().id,
            scenario: scenario.id(),
            configuration: genesis.id(),
            closure: closure.identity(),
            targets: Arc::new(targets),
            launch_profiles: Arc::new(launch_profiles),
        })
    }

    /// Returns the exact World identity whose ready boundary was captured.
    #[must_use]
    pub const fn world(&self) -> ContentHash {
        self.world
    }

    /// Returns the authenticated scenario identity.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact genesis configuration identity.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the immutable scenario-aware launch profile for one World node.
    #[must_use]
    fn launch_profile(&self, node: &NodeId) -> Option<&ProductionVmNodeReplayLaunchProfile> {
        self.launch_profiles.get(node)
    }

    /// Returns one authenticated baked snapshot without reopening native state.
    fn snapshot(&self, node: &NodeId) -> Option<&crucible_qemu::QemuVmSnapshot> {
        self.targets.snapshot(node)
    }
}

impl ProductionBakedGenesisReplayStore {
    fn new(world: ContentHash, scenario: ContentHash, baked: QemuBakedGenesisSnapshot) -> Self {
        Self {
            world,
            scenario,
            baked,
        }
    }

    pub(crate) fn baked_genesis(
        &mut self,
        world: &World,
        def: &ScenarioDef,
    ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
        if world.id != self.world || def.id() != self.scenario {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "native baked-genesis realization store",
                message: String::from("requested World or scenario does not match the store"),
            });
        }
        Ok(self.baked.clone())
    }
}

impl ProductionBakedGenesisReplayFactory {
    const fn new(baked: ProductionBakedGenesisCheckpoint) -> Self {
        Self { baked }
    }
}

impl<R> ProductionBakedGenesisReplayCatalogFactory<R> {
    /// Binds a nonempty exact World/scenario catalog to one shared allocator.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBakedGenesisReplayCatalogError`] when the catalog is
    /// empty or contains two independently captured entries for one exact
    /// World/scenario basis.
    pub fn new(
        baked: impl IntoIterator<Item = ProductionBakedGenesisCheckpoint>,
        resources: R,
    ) -> Result<Self, ProductionBakedGenesisReplayCatalogError> {
        let mut baked_by_basis = BTreeMap::new();
        for checkpoint in baked {
            let basis = (checkpoint.world(), checkpoint.scenario());
            if baked_by_basis.insert(basis, checkpoint).is_some() {
                return Err(ProductionBakedGenesisReplayCatalogError::DuplicateBasis);
            }
        }
        if baked_by_basis.is_empty() {
            return Err(ProductionBakedGenesisReplayCatalogError::Empty);
        }
        Ok(Self {
            baked_by_basis,
            resources,
            savepoint_replay_config: None,
        })
    }

    /// Enables independent full-attempt replay for savepoint promotion.
    #[must_use]
    pub(crate) fn with_savepoint_replay_config(
        mut self,
        config: ProductionVmLifecycleConfig,
    ) -> Self {
        self.savepoint_replay_config = Some(config);
        self
    }

    /// Returns the number of exact World/scenario checkpoints in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.baked_by_basis.len()
    }

    /// Returns whether the catalog contains no checkpoint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.baked_by_basis.is_empty()
    }

    /// Authenticates that this catalog retains one exact World/scenario basis.
    ///
    /// This read-only check neither allocates an attempt resource guard nor
    /// opens a replay target. Hot-checkpoint demotion uses it to prove that a
    /// thin fallback remains realizable before releasing its live source.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no admitted native baked
    /// checkpoint has the exact requested World and scenario identities.
    pub(crate) fn require_basis(
        &self,
        world: ContentHash,
        scenario: ContentHash,
    ) -> Result<(), QemuVmRealizationError> {
        select_baked_catalog_entry(&self.baked_by_basis, world, scenario).map(|_| ())
    }
}

/// Invalid native baked-genesis replay catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProductionBakedGenesisReplayCatalogError {
    /// No scenario checkpoint was supplied.
    #[error("production baked-genesis replay catalog is empty")]
    Empty,
    /// Two captured checkpoints claim one exact World/scenario basis.
    #[error("production baked-genesis replay catalog repeats a World/scenario basis")]
    DuplicateBasis,
}

impl ProductionBakedGenesisReplayFactory {
    fn begin_target<G>(
        &mut self,
        world: &World,
        configuration: &Configuration,
        target: ProductionVmReplayExactNodeRestoreAdmission,
        guard: &mut G,
    ) -> Result<ProductionPausedCheckpointReplaySession, QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        if world.id != self.baked.world()
            || configuration.def.id() != self.baked.scenario()
            || target.configuration_id() != configuration.id()
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from(
                    "raw target, World, or configuration does not match baked replay authority",
                ),
            });
        }
        let node = target.node().clone();
        let profile = self
            .baked
            .launch_profile(&node)
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from("target node has no retained launch profile"),
            })?
            .clone();
        guard.check_operational_boundary()?;
        let baked_snapshot = self
            .baked
            .snapshot(&node)
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from("target node has no authenticated baked snapshot"),
            })?
            .clone();
        if baked_snapshot.checkpoint().configuration != self.baked.configuration() {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from("baked snapshot does not match the scenario genesis"),
            });
        }

        let prepared = prepare_replay_target_generations(
            ReplayTargetPreparation {
                exact: target,
                baked_snapshot: &baked_snapshot,
                profile: &profile,
                world: self.baked.world(),
                scenario: self.baked.scenario(),
            },
            guard,
        );
        let (store, executor) = prepared?;
        Ok(ProductionPausedCheckpointReplaySession::new(
            store, executor,
        ))
    }
}

impl<R> ProductionPausedCheckpointReplayFactory for ProductionBakedGenesisReplayCatalogFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Clone,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Guard = R::Guard;

    fn begin_replay(
        &mut self,
        selected_checkpoint: SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        self.resources
            .begin(resources, cancellation.clone(), Some(selected_checkpoint))
    }

    fn begin_target(
        &mut self,
        world: &World,
        configuration: &Configuration,
        target: ProductionVmReplayExactNodeRestoreAdmission,
        guard: &mut Self::Guard,
    ) -> Result<ProductionPausedCheckpointReplaySession, QemuVmRealizationError> {
        let baked =
            select_baked_catalog_entry(&self.baked_by_basis, world.id, configuration.def.id())?;
        let mut selected = ProductionBakedGenesisReplayFactory::new(baked.clone());
        selected.begin_target(world, configuration, target, guard)
    }

    fn replay_savepoint_capture(
        &mut self,
        attempt: &CrucibleAttemptExecution,
        run_state_root: &std::path::Path,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<QemuSavepointReplayProof, QemuVmRealizationError> {
        let lifecycle = self
            .savepoint_replay_config
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "savepoint capture replay",
                message: String::from("packaged lifecycle replay configuration is unavailable"),
            })?
            .clone()
            .with_run_state_root(run_state_root.join("savepoint-replay"));
        let factory =
            QemuAttemptProductionVmLifecycleFactory::new(lifecycle, self.resources.clone());
        let (probe, receipt) = QemuSavepointReplayProbe::new();
        let mut runner = QemuFreshExecutionRunner::new(factory, probe);
        let context = AttemptExecutionContext::new(
            resources,
            ExecutionRetentionIntent::Discard,
            cancellation.clone(),
            ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        );
        let outcome = runner
            .execute(attempt, &context)
            .map_err(map_savepoint_replay_failure)?;
        match outcome.product() {
            AttemptExecutionProduct::PreparedSemantic(_) => {}
            AttemptExecutionProduct::ExactCheckpoint(_) => {
                return Err(QemuVmRealizationError::InvalidCheckpoint {
                    role: "savepoint capture replay",
                    message: String::from(
                        "independent attempt replay did not produce an observation",
                    ),
                });
            }
        }
        receipt
            .take()
            .map_err(|error| QemuVmRealizationError::Executor {
                operation: "collect savepoint capture replay proof",
                message: error.to_string(),
            })
    }
}

fn map_savepoint_replay_failure<E: std::fmt::Display>(
    failure: AttemptWorkerFailure<E>,
) -> QemuVmRealizationError {
    match failure {
        AttemptWorkerFailure::Retryable(error) => QemuVmRealizationError::ExecutorUnavailable {
            operation: "replay savepoint capture attempt",
            message: error.to_string(),
        },
        AttemptWorkerFailure::Canceled(_) => QemuVmRealizationError::Canceled {
            operation: "replay savepoint capture attempt",
        },
        AttemptWorkerFailure::Terminal(error) => QemuVmRealizationError::Executor {
            operation: "replay savepoint capture attempt",
            message: error.to_string(),
        },
    }
}

fn select_baked_catalog_entry<T>(
    catalog: &BTreeMap<(ContentHash, ContentHash), T>,
    world: ContentHash,
    scenario: ContentHash,
) -> Result<&T, QemuVmRealizationError> {
    catalog
        .get(&(world, scenario))
        .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
            role: "production baked-genesis replay catalog",
            message: String::from(
                "requested World/scenario has no admitted native baked checkpoint",
            ),
        })
}

fn prepare_replay_target_generations<G>(
    preparation: ReplayTargetPreparation<'_>,
    guard: &mut G,
) -> Result<
    (
        ProductionBakedGenesisReplayStore,
        QemuReplayValidationExecutor,
    ),
    QemuVmRealizationError,
>
where
    G: QemuAttemptProcessResourceGuard,
{
    let ReplayTargetPreparation {
        exact,
        baked_snapshot,
        profile,
        world,
        scenario,
    } = preparation;
    guard.check_operational_boundary()?;
    let requirements = profile.resource_requirements();
    let exact_directory = guard.prepare_generation_run_directory(requirements)?;

    guard.check_operational_boundary()?;
    let mut thin_directory = guard.prepare_generation_run_directory(requirements)?;
    guard.check_operational_boundary()?;

    let (exact_config, thin_config) = replay_oracle_launch_configs(
        profile,
        exact_directory.path(),
        thin_directory.path(),
        exact.process_generation(),
    )?;
    // The thin leg cold-boots QEMU, so its pinned directory needs the same
    // guarded VMState and root-overlay preparation as an ordinary fresh launch.
    let preparation = thin_directory.prepare_fresh_artifacts_guarded(
        thin_config.qemu_executable(),
        thin_config.root_image(),
        guard.child_process_contract()?,
    );
    if let Err(mut error) = preparation {
        let message = error.to_string();
        if let Some(child) = error.take_unreaped_child() {
            guard.retain_failed_launch_child(child);
            guard.quarantine();
            return Err(QemuVmRealizationError::ReapQuarantined {
                operation: "prepare fresh thin replay artifacts",
                message,
            });
        }
        return Err(QemuVmRealizationError::Executor {
            operation: "prepare fresh thin replay artifacts",
            message,
        });
    }
    guard.check_operational_boundary()?;

    let exact_node = exact.node().clone();
    let exact_launcher = exact
        .into_replay_admission(
            exact_config,
            exact_directory,
            guard.child_process_contract()?,
            "crucible-replay-oracle-exact",
        )
        .map_err(map_replay_admission_error)?;
    let thin_launcher = QemuReplayValidationThinAdmission::admit(
        thin_config,
        thin_directory,
        baked_snapshot,
        exact_node,
        "crucible-replay-oracle-thin",
    )?;
    let store = ProductionBakedGenesisReplayStore::new(
        world,
        scenario,
        QemuBakedGenesisSnapshot::new(world, baked_snapshot),
    );
    let executor = QemuReplayValidationExecutor::new(exact_launcher, thin_launcher)?;
    Ok((store, executor))
}

fn replay_oracle_launch_configs(
    profile: &ProductionVmNodeReplayLaunchProfile,
    exact_directory: &Path,
    thin_directory: &Path,
    process_generation: u64,
) -> Result<(QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateConfig), QemuVmRealizationError> {
    // The legs run sequentially in separate guarded directories. Their
    // lifecycle generation belongs to the authenticated continuation state.
    if process_generation == 0 {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "replay-oracle lifecycle generation",
            message: String::from("authenticated process generation is zero"),
        });
    }

    Ok((
        profile.for_generation(exact_directory, process_generation),
        profile.for_generation(thin_directory, process_generation),
    ))
}

fn map_replay_admission_error(error: LifecycleApiError) -> QemuVmRealizationError {
    match error {
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            ..
        } => QemuVmRealizationError::Canceled {
            operation: "admitting repository replay-oracle checkpoint source",
        },
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Retryable,
            message,
        } => QemuVmRealizationError::ExecutorUnavailable {
            operation: "admit repository replay-oracle checkpoint source",
            message,
        },
        error => QemuVmRealizationError::Store {
            operation: "admit repository replay-oracle checkpoint source",
            message: error.to_string(),
        },
    }
}

/// Captures and admits one production baked-genesis checkpoint.
///
/// The helper composes the guarded fresh-lifecycle capture with complete native
/// closure admission. It performs no modeled quantum and returns only after the
/// QEMU lifecycle has been torn down.
///
/// # Errors
///
/// Returns [`ProductionBakedGenesisCaptureError`] when lifecycle startup,
/// capture, teardown, or complete baked-genesis admission fails.
pub(crate) fn capture_production_baked_genesis<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<ProductionBakedGenesisCheckpoint, ProductionBakedGenesisCaptureError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let candidate = capture_fresh_genesis_checkpoint_candidate(factory, source, context)?;
    ProductionBakedGenesisCheckpoint::admit(source, candidate, context.cancellation())
        .map_err(Into::into)
}

fn cancellation_boundary(cancellation: &ExecutionCancellation) -> Result<(), LifecycleApiError> {
    if cancellation.is_canceled() {
        return Err(LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            message: String::from("baked-genesis authentication was canceled"),
        });
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn replay_oracle_legs_share_lifecycle_generation_in_distinct_directories() {
        let profile = ProductionVmNodeReplayLaunchProfile::new(
            NodeId {
                name: String::from("choice-node"),
            },
            QemuLiveNodeStepGateConfig::new(
                "/qemu",
                "/plugin",
                "/kernel",
                "/firmware",
                "/run/source",
            ),
        );

        let (exact, thin) = replay_oracle_launch_configs(
            &profile,
            Path::new("/run/exact"),
            Path::new("/run/thin"),
            2,
        )
        .expect("authenticated generation");

        assert_eq!(exact, profile.for_generation("/run/exact", 2));
        assert_eq!(thin, exact.clone().with_run_directory("/run/thin"));
        assert_ne!(thin, profile.for_generation("/run/thin", 1));
        assert_ne!(exact.run_directory(), thin.run_directory());
        assert!(
            replay_oracle_launch_configs(
                &profile,
                Path::new("/run/exact"),
                Path::new("/run/thin"),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn baked_catalog_routes_by_the_complete_world_scenario_basis() {
        let world = ContentHash::from_bytes(b"shared-world");
        let first = ContentHash::from_bytes(b"first-scenario");
        let second = ContentHash::from_bytes(b"second-scenario");
        let catalog = BTreeMap::from([((world, first), 11), ((world, second), 22)]);

        assert_eq!(
            *select_baked_catalog_entry(&catalog, world, first).expect("first exact basis"),
            11
        );
        assert_eq!(
            *select_baked_catalog_entry(&catalog, world, second).expect("second exact basis"),
            22
        );
        assert!(matches!(
            select_baked_catalog_entry(
                &catalog,
                world,
                ContentHash::from_bytes(b"foreign-scenario")
            ),
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay catalog",
                ..
            })
        ));
    }
}
