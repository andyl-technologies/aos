//! Authenticated native baked-genesis checkpoints for production replay.
//!
//! A concrete replay-oracle worker needs an independently captured thin base
//! before it can compare a newly paused fat checkpoint. This module turns the
//! ordinary guarded fresh-lifecycle capture into that native, read-only
//! capability. It deliberately does not publish a campaign root. Packaged
//! composition advertises exact restore only after it has installed the fixed
//! replay factories that materialize these artifacts under disjoint thin
//! bindings.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible::{Configuration, ContentHash, NodeId, ScenarioDef, ScenarioDefForm, World};
use crucible_api::{
    LifecycleApiError, ProductionExactCheckpointClosure, ProductionExactCheckpointReplayCatalog,
    ProductionExactCheckpointReplayTargets, ProductionVmNodeReplayLaunchProfile,
};
use crucible_campaign::{AttemptResourceLimits, ExactCheckpointId};
use crucible_qemu::{
    QemuBakedGenesisSnapshot, QemuCachedAncestor, QemuExactProfileWarmRestoreNodeLauncher,
    QemuNodeRealizationExecutor, QemuReplayValidationNodeLauncher,
    QemuThinProfileWarmRestoreNodeLauncher, QemuVmRealizationError, QemuVmRealizationStore,
    QemuVmSnapshot, QemuVmStateBinding,
};
use thiserror::Error;

use crate::{
    AttemptExecutionContext, CapturedAttemptCheckpoint, ProductionPausedCheckpointReplayFactory,
    ProductionPausedCheckpointReplaySession, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuAttemptResourceGuardFactory,
    QemuFreshAttemptLifecycleFactory, QemuFreshGenesisCheckpointCandidate,
    QemuFreshGenesisCheckpointError, capture_fresh_genesis_checkpoint_candidate,
};

/// One completely authenticated native baked-genesis checkpoint closure.
///
/// The capability retains the production lifecycle's bounded native closure,
/// not a second unversioned cache format. It exposes no mutation or campaign-ref
/// authority. Admission authenticates one compact random-access catalog shared
/// by every cloned replay factory; opening one node decodes only that target.
#[derive(Clone)]
pub struct ProductionBakedGenesisCheckpoint {
    world: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    closure: Arc<ProductionExactCheckpointClosure>,
    targets: Arc<ProductionExactCheckpointReplayCatalog>,
    launch_profiles: Arc<BTreeMap<NodeId, ProductionVmNodeReplayLaunchProfile>>,
}

/// Read-only baked-genesis realization store for one World VM.
///
/// Exact-target selection is supplied explicitly by the replay comparison, so
/// this store deliberately exposes neither an exact cache hit nor an ancestor.
/// Its only thin source is the already authenticated native baked checkpoint.
pub struct ProductionBakedGenesisReplayStore {
    world: ContentHash,
    scenario: ContentHash,
    baked: QemuBakedGenesisSnapshot,
}

/// Concrete guarded replay factory backed by native baked genesis artifacts.
///
/// The factory opens one baked target by node, installs one attempt resource
/// guard, streams the selected exact and baked artifact pairs into distinct
/// descriptor-pinned generations, and returns a fixed-node executor. It owns no
/// campaign mutation or checkpoint-publication capability.
pub struct ProductionBakedGenesisReplayFactory<R> {
    baked: ProductionBakedGenesisCheckpoint,
    resources: R,
}

/// Concrete exact/thin launcher pair produced for one replay target.
pub type ProductionBakedGenesisReplayLauncher = QemuReplayValidationNodeLauncher<
    QemuExactProfileWarmRestoreNodeLauncher,
    QemuThinProfileWarmRestoreNodeLauncher,
>;

struct ReplayTargetPreparation<'a> {
    exact_root: ExactCheckpointId,
    exact: &'a crucible_api::ProductionExactCheckpointReplayTarget,
    baked: &'a crucible_api::ProductionExactCheckpointReplayTarget,
    profile: &'a ProductionVmNodeReplayLaunchProfile,
    world: ContentHash,
    scenario: ContentHash,
    baked_closure: ContentHash,
}

impl std::fmt::Debug for ProductionBakedGenesisCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBakedGenesisCheckpoint")
            .field("world", &self.world)
            .field("scenario", &self.scenario)
            .field("configuration", &self.configuration)
            .field("closure", &self.closure.identity())
            .field("launch_profile_count", &self.launch_profiles.len())
            .finish_non_exhaustive()
    }
}

/// Rejection while admitting a fresh capture as baked-genesis authority.
#[derive(Debug, Error)]
pub enum ProductionBakedGenesisCheckpointError {
    /// A compatibility single-node capture cannot back production replay.
    #[error("baked genesis requires a version-four production checkpoint closure")]
    CompatibilityCapture,
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
    /// Admission requires the version-four production variant, complete closure
    /// authentication, exact scenario genesis, and exactly one live target for
    /// every VM in the World. No destination or campaign store is written.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBakedGenesisCheckpointError`] when the capture uses
    /// the legacy single-node format or any closure, semantic-basis, or node-set
    /// invariant fails.
    pub fn admit(
        source: &ScenarioDefForm,
        candidate: QemuFreshGenesisCheckpointCandidate,
    ) -> Result<Self, ProductionBakedGenesisCheckpointError> {
        let (capture, launch_profiles) = candidate.into_parts();
        let CapturedAttemptCheckpoint::Production(closure) = capture else {
            return Err(ProductionBakedGenesisCheckpointError::CompatibilityCapture);
        };
        let closure = Arc::new(*closure);
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
        let targets = closure.replay_oracle_catalog()?;
        for node in targets.nodes() {
            let target = targets.open_target(node)?;
            if !expected.remove(target.node())
                || target.snapshot().checkpoint().configuration != genesis.id()
            {
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
            closure,
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

    /// Returns the native closure identity retained by this capability.
    #[must_use]
    pub fn closure_identity(&self) -> ContentHash {
        self.closure.identity()
    }

    /// Returns the immutable scenario-aware launch profile for one World node.
    #[must_use]
    pub fn launch_profile(&self, node: &NodeId) -> Option<&ProductionVmNodeReplayLaunchProfile> {
        self.launch_profiles.get(node)
    }

    /// Opens one authenticated baked target without rescanning the closure.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `node` is absent or its retained
    /// snapshot body became unavailable, corrupt, or semantically inconsistent.
    pub fn open_target(
        &self,
        node: &NodeId,
    ) -> Result<crucible_api::ProductionExactCheckpointReplayTarget, LifecycleApiError> {
        self.targets.open_target(node)
    }

    /// Authenticates a bounded cursor over baked targets in World node order.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the retained native closure became
    /// unavailable, corrupt, or inconsistent after admission.
    pub fn replay_targets(
        &self,
    ) -> Result<ProductionExactCheckpointReplayTargets<'_>, LifecycleApiError> {
        self.closure.replay_oracle_targets()
    }

    /// Consumes the baked capability into its shared read-only closure.
    ///
    /// The returned authority preserves the same compact catalog sharing used
    /// by cloned replay factories and never clones the potentially large
    /// manifest or object inventory.
    #[must_use]
    pub fn into_shared_closure(self) -> Arc<ProductionExactCheckpointClosure> {
        self.closure
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
}

impl QemuVmRealizationStore for ProductionBakedGenesisReplayStore {
    fn exact_snapshot(
        &mut self,
        _config: &Configuration,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
        Ok(None)
    }

    fn nearest_cached_ancestor(
        &mut self,
        _config: &Configuration,
    ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError> {
        Ok(None)
    }

    fn baked_genesis(
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

impl<R> ProductionBakedGenesisReplayFactory<R> {
    /// Binds native baked authority to one resource-guard allocator.
    #[must_use]
    pub const fn new(baked: ProductionBakedGenesisCheckpoint, resources: R) -> Self {
        Self { baked, resources }
    }

    /// Returns the retained native baked-genesis capability.
    #[must_use]
    pub const fn baked(&self) -> &ProductionBakedGenesisCheckpoint {
        &self.baked
    }

    /// Returns mutable access to the resource-guard allocator.
    #[must_use]
    pub const fn resources_mut(&mut self) -> &mut R {
        &mut self.resources
    }

    /// Consumes the factory into its native checkpoint and allocator.
    #[must_use]
    pub fn into_parts(self) -> (ProductionBakedGenesisCheckpoint, R) {
        (self.baked, self.resources)
    }
}

impl<R> ProductionPausedCheckpointReplayFactory for ProductionBakedGenesisReplayFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard,
{
    type Store = ProductionBakedGenesisReplayStore;
    type Launcher = ProductionBakedGenesisReplayLauncher;
    type Guard = R::Guard;

    fn begin_target(
        &mut self,
        exact_root: ExactCheckpointId,
        world: &World,
        configuration: &Configuration,
        target: &crucible_api::ProductionExactCheckpointReplayTarget,
        cancellation: &crate::ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<
        ProductionPausedCheckpointReplaySession<Self::Store, Self::Launcher, Self::Guard>,
        QemuVmRealizationError,
    > {
        if world.id != self.baked.world()
            || configuration.def.id() != self.baked.scenario()
            || target.snapshot().checkpoint().configuration != configuration.id()
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from(
                    "raw target, World, or configuration does not match baked replay authority",
                ),
            });
        }
        let profile = self
            .baked
            .launch_profile(target.node())
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from("target node has no retained launch profile"),
            })?
            .clone();
        let baked = self
            .baked
            .open_target(target.node())
            .map_err(map_baked_artifact_error)?;
        if baked.node() != target.node()
            || baked.snapshot().checkpoint().configuration != self.baked.configuration()
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "production baked-genesis replay target",
                message: String::from("baked target does not match the requested node or genesis"),
            });
        }

        let mut guard = self.resources.begin(resources, cancellation.clone())?;
        let prepared = prepare_replay_target_generations(
            ReplayTargetPreparation {
                exact_root,
                exact: target,
                baked: &baked,
                profile: &profile,
                world: self.baked.world(),
                scenario: self.baked.scenario(),
                baked_closure: self.baked.closure_identity(),
            },
            &mut guard,
        );
        let (store, executor) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(release_unlaunched_replay_guard(&mut guard, error)),
        };
        Ok(ProductionPausedCheckpointReplaySession::new(
            store, executor, guard,
        ))
    }
}

fn prepare_replay_target_generations<G>(
    preparation: ReplayTargetPreparation<'_>,
    guard: &mut G,
) -> Result<
    (
        ProductionBakedGenesisReplayStore,
        QemuNodeRealizationExecutor<ProductionBakedGenesisReplayLauncher>,
    ),
    QemuVmRealizationError,
>
where
    G: QemuAttemptProcessResourceGuard,
{
    let ReplayTargetPreparation {
        exact_root,
        exact,
        baked,
        profile,
        world,
        scenario,
        baked_closure,
    } = preparation;
    guard.check_operational_boundary()?;
    let requirements = profile.resource_requirements();
    let mut exact_directory = guard.prepare_generation_run_directory(requirements)?;
    let exact_binding =
        QemuVmStateBinding::from_exact_checkpoint_root_digest(exact_root.content_id().digest());
    materialize_target(exact, &mut exact_directory, exact_binding, guard)?;

    guard.check_operational_boundary()?;
    let mut thin_directory = guard.prepare_generation_run_directory(requirements)?;
    let thin_binding =
        QemuVmStateBinding::from_thin_checkpoint_artifact_digest(baked_closure.bytes);
    materialize_target(baked, &mut thin_directory, thin_binding, guard)?;
    guard.check_operational_boundary()?;

    let exact_config = profile.for_generation(exact_directory.path(), 1);
    let thin_config = profile.for_generation(thin_directory.path(), 2);
    let node_name = exact.node().name.clone();
    let exact_launcher = QemuExactProfileWarmRestoreNodeLauncher::new(
        exact_config,
        exact_directory,
        exact_binding,
        exact.snapshot(),
        node_name.clone(),
        "crucible-replay-oracle-exact",
    )?;
    let thin_launcher = QemuThinProfileWarmRestoreNodeLauncher::new(
        thin_config,
        thin_directory,
        thin_binding,
        baked.snapshot().checkpoint().id,
        node_name,
        "crucible-replay-oracle-thin",
    )?;
    let store = ProductionBakedGenesisReplayStore::new(
        world,
        scenario,
        QemuBakedGenesisSnapshot {
            world_id: world,
            checkpoint: baked.snapshot().checkpoint().clone(),
        },
    );
    let executor = QemuNodeRealizationExecutor::new(
        exact.node().clone(),
        QemuReplayValidationNodeLauncher::new(exact_launcher, thin_launcher),
    );
    Ok((store, executor))
}

fn materialize_target<G>(
    target: &crucible_api::ProductionExactCheckpointReplayTarget,
    directory: &mut crucible_qemu::QemuPreparedRunDirectory,
    binding: QemuVmStateBinding,
    guard: &mut G,
) -> Result<(), QemuVmRealizationError>
where
    G: QemuAttemptOperationalBoundary,
{
    let mut overlay = directory
        .begin_exact_root_overlay_materialization(binding, target.overlay().length())
        .map_err(map_materialization_spawn_error)?;
    stream_replay_artifact(target.overlay(), &mut overlay, guard)?;
    overlay.finish().map_err(map_materialization_spawn_error)?;

    guard.check_operational_boundary()?;
    let mut vmstate = directory
        .begin_exact_vmstate_materialization(binding, target.vmstate().length())
        .map_err(map_materialization_spawn_error)?;
    stream_replay_artifact(target.vmstate(), &mut vmstate, guard)?;
    vmstate.finish().map_err(map_materialization_spawn_error)?;
    guard.check_operational_boundary()
}

fn stream_replay_artifact(
    artifact: &crucible_api::ProductionExactCheckpointReplayArtifact,
    destination: &mut impl std::io::Write,
    guard: &mut impl QemuAttemptOperationalBoundary,
) -> Result<(), QemuVmRealizationError> {
    let mut operational_error = None;
    let result = artifact.stream_into_with_boundary(destination, &mut || match guard
        .check_operational_boundary()
    {
        Ok(()) => Ok(()),
        Err(error) => {
            let message = error.to_string();
            operational_error = Some(error);
            Err(LifecycleApiError::LoopFactory { message })
        }
    });
    if let Some(error) = operational_error {
        return Err(error);
    }
    result.map_err(map_baked_artifact_error)
}

fn release_unlaunched_replay_guard(
    guard: &mut impl QemuAttemptProcessResourceGuard,
    primary: QemuVmRealizationError,
) -> QemuVmRealizationError {
    match guard.finish() {
        Ok(()) => primary,
        Err(cleanup) => cleanup,
    }
}

fn map_baked_artifact_error(error: LifecycleApiError) -> QemuVmRealizationError {
    QemuVmRealizationError::Store {
        operation: "open native replay-oracle checkpoint artifact",
        message: error.to_string(),
    }
}

fn map_materialization_spawn_error(error: crucible_qemu::QemuSpawnError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "materialize native replay-oracle checkpoint artifact",
        message: error.to_string(),
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
pub fn capture_production_baked_genesis<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<ProductionBakedGenesisCheckpoint, ProductionBakedGenesisCaptureError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let candidate = capture_fresh_genesis_checkpoint_candidate(factory, source, context)?;
    ProductionBakedGenesisCheckpoint::admit(source, candidate).map_err(Into::into)
}
