//! Process-neutral production-world continuation for QEMU hot fork.
//!
//! A hot-fork child inherits guest memory from each paused source QEMU, but it
//! does not inherit the host scheduler, network, trigger, assertion, selectable,
//! or fault owners. This module captures that complete host continuation at one
//! exact world boundary. The opaque token is the semantic half of a future
//! atomic world-fork transaction; it grants no process launch, child admission,
//! mutable run-directory, or source-template recovery authority.

use super::*;

mod resource_usage;
pub use resource_usage::ProductionVmHotForkSourceWorldResourceUsage;

const MAXIMUM_HOT_FORK_RING_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE: usize = 100;
const HOT_FORK_ROLLBACK_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct HotForkRollbackTarget {
    node: NodeId,
    template_generation: Option<u64>,
}

struct HotForkRollbackReport {
    nodes: Vec<NodeId>,
    diagnostics: BTreeMap<NodeId, String>,
}

/// Prepared, stopped production source world at one exact scheduler boundary.
///
/// The capability owns the complete lifecycle while every retained source is
/// prepared at the same captured scheduler boundary. QEMU nodes, generation
/// leases, run directories, the enclosing run lock, resource guards, and the
/// host continuation cannot be detached from one another through this API.
#[must_use = "install the complete source world or recover every prepared QEMU source"]
pub struct ProductionVmHotForkSourceWorld {
    lifecycle: Option<Box<ProductionVmLifecycleLoop>>,
    continuation: ProductionVmHotForkWorldContinuation,
    prepared: Vec<QemuNodeSetPreparedHotForkTemplate>,
}

impl ProductionVmHotForkSourceWorld {
    /// Returns the captured process-neutral world continuation.
    pub const fn continuation(&self) -> &ProductionVmHotForkWorldContinuation {
        &self.continuation
    }

    /// Replaces one immutable-root identity for construction-failure tests.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when `node` is absent from the captured
    /// world continuation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn replace_immutable_root_for_test(
        &mut self,
        node: &NodeId,
        root: ContentHash,
    ) -> Result<(), LifecycleApiError> {
        let retained = self
            .continuation
            .immutable_root_images
            .get_mut(node)
            .ok_or_else(|| loop_factory_error("test immutable-root node is absent"))?;
        *retained = root;
        Ok(())
    }

    /// Marks the source as having crossed its canonical initial boundary.
    ///
    /// This simulates a later pause with the same decision schedule so
    /// cross-crate admission tests can prove that configuration identity alone
    /// does not authorize source reuse.
    #[cfg(any(test, feature = "test-support"))]
    pub fn mark_reuse_boundary_advanced_for_test(&mut self) {
        self.continuation.initial_lifecycle_observations_pending = false;
    }

    /// Returns the canonically ordered prepared retained-source nodes.
    #[must_use]
    pub fn prepared_nodes(&self) -> impl ExactSizeIterator<Item = &NodeId> {
        self.prepared
            .iter()
            .map(QemuNodeSetPreparedHotForkTemplate::node)
    }

    /// Mints a process-neutral continuation for one child world.
    ///
    /// The retained sources and their enclosing production lifecycle remain
    /// owned by this source-world capability. The returned continuation has no
    /// process, descriptor, run-directory, lease, or resource-guard authority.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when any retained source no longer matches
    /// its process incarnation or exact prepared transaction generation, or
    /// when the copied continuation fails its complete-state validation.
    pub fn fork_continuation(
        &mut self,
    ) -> Result<ProductionVmHotForkWorldContinuation, SchedulerError> {
        self.validate_source_ownership()?;

        let continuation = self.continuation.try_clone_for_branch()?;
        continuation.validate_complete_internal_state()?;
        Ok(continuation)
    }

    /// Borrows one retained source through a narrow operational capability.
    ///
    /// The source stays installed in the complete lifecycle. The loan exposes
    /// only fork and ordered source-side child reconciliation operations, and
    /// every QMP exchange revalidates the source process and transaction
    /// generation bound during preparation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `node` was not prepared, the lifecycle
    /// owner is unavailable, or the exact source identity cannot be validated.
    pub fn prepared_source(
        &mut self,
        node: &NodeId,
    ) -> Result<QemuNodeSetPreparedHotForkSource<'_>, SchedulerError> {
        let prepared = self
            .prepared
            .iter()
            .find(|prepared| prepared.node() == node)
            .ok_or_else(|| {
                hot_fork_boundary_error(format!(
                    "production hot-fork source world has no prepared node `{}`",
                    node.name
                ))
            })?;
        let lifecycle = self.lifecycle.as_deref_mut().ok_or_else(|| {
            hot_fork_boundary_error("production hot-fork source world lost its lifecycle owner")
        })?;
        lifecycle
            .inner
            .backend_mut()
            .prepared_hot_fork_source(prepared)
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "authenticate retained hot-fork source `{}`: {error}",
                    node.name
                ))
            })
    }

    /// Borrows one source during ordered child reconciliation.
    ///
    /// The loan authenticates the same source process and active transaction
    /// generation captured at preparation while permitting branch-private
    /// resources to have entered their ordered release sequence.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `node` was not prepared, the lifecycle
    /// owner is unavailable, or the retained transaction identity changed.
    pub fn retained_source(
        &mut self,
        node: &NodeId,
    ) -> Result<QemuNodeSetPreparedHotForkSource<'_>, SchedulerError> {
        let prepared = self
            .prepared
            .iter()
            .find(|prepared| prepared.node() == node)
            .ok_or_else(|| {
                hot_fork_boundary_error(format!(
                    "production hot-fork source world has no retained node `{}`",
                    node.name
                ))
            })?;
        let lifecycle = self.lifecycle.as_deref_mut().ok_or_else(|| {
            hot_fork_boundary_error("production hot-fork source world lost its lifecycle owner")
        })?;
        lifecycle
            .inner
            .backend_mut()
            .retained_hot_fork_source(prepared)
            .map_err(|error| {
                hot_fork_boundary_error(format!(
                    "authenticate reconciling hot-fork source `{}`: {error}",
                    node.name
                ))
            })
    }

    /// Returns a fully prepared reusable source world.
    ///
    /// A world that still owns its complete prepared transaction is returned
    /// unchanged. A reconciled child transaction is first rolled back to its
    /// stopped lifecycle and then prepared again, minting fresh exact tokens
    /// and branch-resource generations for the next fork.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionVmHotForkSourceWorldPreparationFailure`] retaining
    /// the source lifecycle when rollback or renewed preparation fails.
    pub fn into_reusable(
        mut self,
    ) -> Result<Self, ProductionVmHotForkSourceWorldPreparationFailure> {
        if self.validate_source_ownership().is_ok() {
            return Ok(self);
        }

        self.recover()?.prepare_hot_fork_source_world()
    }

    /// Aborts every retained-template transaction and recovers the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionVmHotForkSourceWorldPreparationFailure`] retaining
    /// the complete world when any source rollback cannot be authenticated as
    /// complete within the finite rollback bound.
    pub fn recover(
        mut self,
    ) -> Result<ProductionVmLifecycleLoop, ProductionVmHotForkSourceWorldPreparationFailure> {
        let Some(mut lifecycle) = self.lifecycle.take() else {
            return Err(
                ProductionVmHotForkSourceWorldPreparationFailure::new_without_lifecycle(
                    "prepared source world lost its lifecycle owner",
                ),
            );
        };
        let targets = self
            .prepared
            .iter()
            .map(|prepared| HotForkRollbackTarget {
                node: prepared.node().clone(),
                template_generation: Some(prepared.template_generation()),
            })
            .collect::<Vec<_>>();
        let rollback = rollback_hot_fork_sources(&mut lifecycle, &targets);
        if rollback.nodes.is_empty() {
            self.prepared.clear();
            return Ok(*lifecycle);
        }
        self.prepared.clear();
        Err(
            ProductionVmHotForkSourceWorldPreparationFailure::with_rollback(
                *lifecycle,
                "one or more prepared sources did not complete rollback",
                rollback,
            ),
        )
    }

    /// Reaps every retained source and releases the complete production world.
    ///
    /// This is the irreversible hot-to-exact/thin demotion boundary. Prepared
    /// transactions are first rolled back, then the ordinary production
    /// lifecycle shutdown attests process reap, lease release, launcher
    /// release, and clean run-state persistence. A lifecycle whose shutdown
    /// cannot be attested is retained for the daemon process lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when source rollback or production
    /// lifecycle shutdown cannot be authenticated as complete.
    pub fn retire(self) -> Result<(), LifecycleApiError> {
        let mut lifecycle = self
            .recover()
            .map_err(|failure| loop_factory_error(failure.to_string()))?;
        if let Err(error) = lifecycle.shutdown() {
            let _retained_for_process_lifetime = Box::leak(Box::new(lifecycle));
            return Err(loop_factory_error(format!(
                "retire production hot-fork source world: {error}"
            )));
        }
        Ok(())
    }

    fn validate_source_ownership(&mut self) -> Result<(), SchedulerError> {
        let lifecycle = self.lifecycle.as_deref_mut().ok_or_else(|| {
            hot_fork_boundary_error("prepared source world lost its lifecycle owner")
        })?;
        for prepared in &self.prepared {
            let node = prepared.node();
            let generation = lifecycle
                .node_generations
                .get(node)
                .copied()
                .ok_or_else(|| {
                    hot_fork_boundary_error(format!(
                        "prepared source `{}` has no process generation",
                        node.name
                    ))
                })?;
            let expected = ProductionVmNodeGeneration::new(node.clone(), generation)
                .map_err(|error| hot_fork_boundary_error(error.to_string()))?;
            let lease = lifecycle.node_leases.get(node).ok_or_else(|| {
                hot_fork_boundary_error(format!(
                    "prepared source `{}` has no retained lease",
                    node.name
                ))
            })?;
            if lease.identity() != &expected {
                return Err(hot_fork_boundary_error(format!(
                    "prepared source `{}` lease names another generation",
                    node.name
                )));
            }
            if !lifecycle.node_run_directories.contains_key(node) {
                return Err(hot_fork_boundary_error(format!(
                    "prepared source `{}` has no retained run directory",
                    node.name
                )));
            }
            if !lifecycle.inner.backend().contains(node) {
                return Err(hot_fork_boundary_error(format!(
                    "prepared source `{}` disappeared from the authoritative backend set",
                    node.name
                )));
            }
            let expected_resources = lifecycle
                .launch_configs
                .get(node)
                .map(ProductionLiveNodeStepGateConfig::resource_requirements)
                .ok_or_else(|| {
                    hot_fork_boundary_error(format!(
                        "prepared source `{}` has no exact launch profile",
                        node.name
                    ))
                })?;
            if prepared.configuration() != self.continuation.configuration().id()
                || prepared.event_log().offset() != self.continuation.event_log_offset()
                || prepared.launch_resources() != expected_resources
            {
                return Err(hot_fork_boundary_error(format!(
                    "prepared source `{}` semantic token differs from the captured world",
                    node.name
                )));
            }
            lifecycle
                .inner
                .backend_mut()
                .validate_retained_hot_fork_template(prepared)
                .map_err(|error| {
                    hot_fork_boundary_error(format!(
                        "revalidate prepared source `{}`: {error}",
                        node.name
                    ))
                })?;
        }
        Ok(())
    }
}

impl Drop for ProductionVmHotForkSourceWorld {
    fn drop(&mut self) {
        let Some(mut lifecycle) = self.lifecycle.take() else {
            return;
        };
        let targets = self
            .prepared
            .iter()
            .map(|prepared| HotForkRollbackTarget {
                node: prepared.node().clone(),
                template_generation: Some(prepared.template_generation()),
            })
            .collect::<Vec<_>>();
        let rollback = rollback_hot_fork_sources(&mut lifecycle, &targets);
        if !rollback.nodes.is_empty() {
            quarantine_unreconciled_hot_fork_lifecycle(lifecycle);
        }
    }
}

/// Failed source-world preparation retaining all process and guard authority.
#[must_use = "recover the lifecycle or retain it for fail-closed cleanup"]
pub struct ProductionVmHotForkSourceWorldPreparationFailure {
    lifecycle: Option<Box<ProductionVmLifecycleLoop>>,
    message: String,
    unreconciled_nodes: Vec<NodeId>,
    rollback_diagnostics: BTreeMap<NodeId, String>,
}

impl ProductionVmHotForkSourceWorldPreparationFailure {
    fn new(
        lifecycle: ProductionVmLifecycleLoop,
        message: impl Into<String>,
        unreconciled_nodes: Vec<NodeId>,
    ) -> Self {
        Self {
            lifecycle: Some(Box::new(lifecycle)),
            message: message.into(),
            unreconciled_nodes,
            rollback_diagnostics: BTreeMap::new(),
        }
    }

    fn new_without_lifecycle(message: impl Into<String>) -> Self {
        Self {
            lifecycle: None,
            message: message.into(),
            unreconciled_nodes: Vec::new(),
            rollback_diagnostics: BTreeMap::new(),
        }
    }

    fn with_rollback(
        lifecycle: ProductionVmLifecycleLoop,
        message: impl Into<String>,
        rollback: HotForkRollbackReport,
    ) -> Self {
        Self {
            lifecycle: Some(Box::new(lifecycle)),
            message: message.into(),
            unreconciled_nodes: rollback.nodes,
            rollback_diagnostics: rollback.diagnostics,
        }
    }

    /// Returns sources whose rollback could not be authenticated as complete.
    #[must_use]
    pub fn unreconciled_nodes(&self) -> &[NodeId] {
        &self.unreconciled_nodes
    }

    /// Returns the bounded cleanup diagnostic for each unresolved source.
    #[must_use]
    pub const fn rollback_diagnostics(&self) -> &BTreeMap<NodeId, String> {
        &self.rollback_diagnostics
    }

    /// Recovers the lifecycle only after every prepared source rolled back.
    ///
    /// # Errors
    ///
    /// Returns the unchanged failure while any source still owns unresolved
    /// retained-template state.
    pub fn into_recovered_lifecycle(mut self) -> Result<ProductionVmLifecycleLoop, Self> {
        if self.unreconciled_nodes.is_empty() {
            match self.lifecycle.take() {
                Some(lifecycle) => Ok(*lifecycle),
                None => Err(self),
            }
        } else {
            Err(self)
        }
    }
}

impl std::fmt::Debug for ProductionVmHotForkSourceWorldPreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionVmHotForkSourceWorldPreparationFailure")
            .field("message", &self.message)
            .field("unreconciled_nodes", &self.unreconciled_nodes)
            .field("rollback_diagnostics", &self.rollback_diagnostics)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProductionVmHotForkSourceWorldPreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "prepare production hot-fork source world: {}",
            self.message
        )
    }
}

impl std::error::Error for ProductionVmHotForkSourceWorldPreparationFailure {}

impl Drop for ProductionVmHotForkSourceWorldPreparationFailure {
    fn drop(&mut self) {
        if self.unreconciled_nodes.is_empty() {
            return;
        }
        if let Some(lifecycle) = self.lifecycle.take() {
            quarantine_unreconciled_hot_fork_lifecycle(lifecycle);
        }
    }
}

fn quarantine_unreconciled_hot_fork_lifecycle(lifecycle: Box<ProductionVmLifecycleLoop>) {
    let _retained_for_process_lifetime = Box::leak(lifecycle);
}

/// Modeled service state of one node in a hot-fork world continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmHotForkNodeServiceState {
    /// The node has one paused source QEMU that must participate in the fork.
    Running,
    /// The node is powered off but retains a paused source for a later Boot.
    PoweredOff,
    /// The node is permanently failed and cannot acquire a child process.
    PermanentlyFailed,
}

impl From<ProductionNodeServiceState> for ProductionVmHotForkNodeServiceState {
    fn from(state: ProductionNodeServiceState) -> Self {
        match state {
            ProductionNodeServiceState::Running => Self::Running,
            ProductionNodeServiceState::PoweredOff => Self::PoweredOff,
            ProductionNodeServiceState::PermanentlyFailed => Self::PermanentlyFailed,
        }
    }
}

/// Exact process and scheduler boundary for one World node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVmHotForkNodeBoundary {
    node: NodeId,
    generation: u64,
    service_state: ProductionVmHotForkNodeServiceState,
    scheduler_time: VirtualTime,
    physical_time: Option<VirtualTime>,
    process: Option<QemuProcessIdentity>,
}

impl ProductionVmHotForkNodeBoundary {
    /// Returns the canonical World node identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the positive source process generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the modeled node service state.
    #[must_use]
    pub const fn service_state(&self) -> ProductionVmHotForkNodeServiceState {
        self.service_state
    }

    /// Returns the scheduler time paired with the paused source boundary.
    #[must_use]
    pub const fn scheduler_time(&self) -> VirtualTime {
        self.scheduler_time
    }

    /// Returns the physical QEMU time for a running or powered-off source node.
    #[must_use]
    pub const fn physical_time(&self) -> Option<VirtualTime> {
        self.physical_time
    }

    /// Returns the exact Linux incarnation of a retained source process.
    #[must_use]
    pub const fn process(&self) -> Option<&QemuProcessIdentity> {
        self.process.as_ref()
    }
}

/// Complete process-neutral host continuation captured for one world hot fork.
///
/// The token intentionally retains the same scheduler, network/fault,
/// selectable, trigger, assertion, terminal, and evidence state used by the
/// durable exact-checkpoint path. It is process-local and opaque: only the
/// production lifecycle implementation may consume its private state when all
/// node children have been authenticated atomically.
#[must_use = "install the continuation into an atomic child world or discard it before forking"]
pub struct ProductionVmHotForkWorldContinuation {
    config: ProductionVmLifecycleConfig,
    configuration: Configuration,
    scheduler: SingleSchedulerCheckpoint,
    event_log_objects: BTreeMap<ContentHash, Vec<u8>>,
    signal_artifact_objects: BTreeMap<ContentHash, Vec<u8>>,
    trigger_state: EventGraphState,
    assertion_state: HostAssertionEvaluatorCheckpoint,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    selectable_catalog_plans:
        BTreeMap<NodeId, crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    fault_checkpoint: ProductionFaultRuntimeCheckpoint,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    nodes: Vec<ProductionVmHotForkNodeBoundary>,
}

impl ProductionVmHotForkWorldContinuation {
    fn try_clone_for_branch(&self) -> Result<Self, SchedulerError> {
        let fault_checkpoint = self.fault_checkpoint.try_clone().map_err(|error| {
            hot_fork_boundary_error(format!("clone production fault continuation: {error}"))
        })?;

        Ok(Self {
            config: self.config.clone(),
            configuration: self.configuration.clone(),
            scheduler: self.scheduler.clone(),
            event_log_objects: self.event_log_objects.clone(),
            signal_artifact_objects: self.signal_artifact_objects.clone(),
            trigger_state: self.trigger_state.clone(),
            assertion_state: self.assertion_state.clone(),
            terminal_verdict: self.terminal_verdict.clone(),
            terminal_cause: self.terminal_cause.clone(),
            initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
            branch: self.branch.clone(),
            recorded_controls: self.recorded_controls.clone(),
            selectable_catalog_plans: self.selectable_catalog_plans.clone(),
            fault_checkpoint,
            node_generations: self.node_generations.clone(),
            node_service_states: self.node_service_states.clone(),
            immutable_root_images: self.immutable_root_images.clone(),
            block_bindings: self.block_bindings.clone(),
            ninep_bindings: self.ninep_bindings.clone(),
            nodes: self.nodes.clone(),
        })
    }

    /// Returns the exact modeled configuration inherited by every child.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the canonical scheduler continuation at the fork boundary.
    #[must_use]
    pub const fn scheduler(&self) -> &SingleSchedulerCheckpoint {
        &self.scheduler
    }

    /// Returns the exact unified event-log offset at the fork boundary.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.scheduler.event_log_offset()
    }

    /// Returns the ordered complete World node boundary set.
    #[must_use]
    pub fn nodes(&self) -> &[ProductionVmHotForkNodeBoundary] {
        &self.nodes
    }

    /// Returns the fault/network continuation identity paired with the scheduler.
    #[must_use]
    pub fn fault_checkpoint_identity(&self) -> ContentHash {
        self.fault_checkpoint.id()
    }

    /// Returns the number of authenticated event-log dependency objects.
    #[must_use]
    pub fn event_log_object_count(&self) -> usize {
        self.event_log_objects.len()
    }

    /// Returns the number of retained signal-artifact dependency objects.
    #[must_use]
    pub fn signal_artifact_object_count(&self) -> usize {
        self.signal_artifact_objects.len()
    }

    /// Returns whether initial lifecycle observations remain to be emitted.
    #[must_use]
    pub const fn initial_lifecycle_observations_pending(&self) -> bool {
        self.initial_lifecycle_observations_pending
    }

    /// Returns the number of node-local selectable continuations.
    #[must_use]
    pub fn selectable_catalog_count(&self) -> usize {
        self.selectable_catalog_plans.len()
    }

    /// Returns whether the captured lifecycle already has a terminal verdict.
    #[must_use]
    pub const fn terminal_verdict(&self) -> Option<&QuantumTerminalVerdict> {
        self.terminal_verdict.as_ref()
    }

    pub(super) fn validate_complete_internal_state(&self) -> Result<(), SchedulerError> {
        if self
            .scheduler
            .configuration_for(&self.configuration.def)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("validate hot-fork scheduler continuation: {error}"),
            })?
            != self.configuration
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "hot-fork scheduler continuation names another configuration",
                ),
            });
        }
        let node_ids = self
            .nodes
            .iter()
            .map(|boundary| boundary.node.clone())
            .collect::<BTreeSet<_>>();
        if node_ids.len() != self.nodes.len()
            || self.node_generations.keys().ne(node_ids.iter())
            || self.node_service_states.keys().ne(node_ids.iter())
            || self.immutable_root_images.keys().ne(node_ids.iter())
            || self
                .block_bindings
                .keys()
                .any(|node| !node_ids.contains(node))
            || self
                .ninep_bindings
                .keys()
                .any(|node| !node_ids.contains(node))
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("hot-fork node continuation is incomplete"),
            });
        }
        for boundary in &self.nodes {
            let generation = self
                .node_generations
                .get(&boundary.node)
                .copied()
                .ok_or_else(|| hot_fork_boundary_error("hot-fork node generation disappeared"))?;
            let service_state = self
                .node_service_states
                .get(&boundary.node)
                .copied()
                .ok_or_else(|| hot_fork_boundary_error("hot-fork node state disappeared"))?;
            let retained =
                boundary.service_state != ProductionVmHotForkNodeServiceState::PermanentlyFailed;
            if generation != boundary.generation
                || ProductionVmHotForkNodeServiceState::from(service_state)
                    != boundary.service_state
                || boundary.physical_time.is_some() != retained
                || boundary.process.is_some() != retained
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "hot-fork node boundary for `{}` disagrees with its retained world state",
                        boundary.node.name
                    ),
                });
            }
        }
        if self
            .scheduler
            .event_log_segment_dependencies()
            .iter()
            .any(|identity| !self.event_log_objects.contains_key(identity))
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("hot-fork event-log dependency closure is incomplete"),
            });
        }
        let _retained_semantic_state = (
            &self.trigger_state,
            &self.assertion_state,
            &self.terminal_cause,
            &self.branch,
            &self.recorded_controls,
        );
        Ok(())
    }

    pub(super) fn into_restore_parts(
        self,
        node_generations: BTreeMap<NodeId, u64>,
        run_state_root: impl Into<PathBuf>,
    ) -> ProductionVmHotForkRestoreParts {
        let config = self.config.with_run_state_root(run_state_root);
        let checkpoint = ProductionVmExactCheckpointSet {
            identity: self.configuration.id(),
            configuration: self.configuration,
            scheduler: self.scheduler,
            event_log_objects: self.event_log_objects,
            signal_artifact_objects: self.signal_artifact_objects,
            trigger_state: self.trigger_state,
            assertion_state: self.assertion_state,
            terminal_verdict: self.terminal_verdict,
            terminal_cause: self.terminal_cause,
            initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
            branch: self.branch,
            recorded_controls: self.recorded_controls,
            selectable_catalog_plans: self.selectable_catalog_plans,
            fault_checkpoint: Some(self.fault_checkpoint),
            targets: BTreeMap::new(),
            node_generations,
            node_service_states: self.node_service_states,
        };
        ProductionVmHotForkRestoreParts {
            config,
            checkpoint,
            immutable_root_images: self.immutable_root_images,
            block_bindings: self.block_bindings,
            ninep_bindings: self.ninep_bindings,
        }
    }
}

impl ProductionVmLifecycleLoop {
    /// Releases reaped child-world process loans before source-world recovery.
    ///
    /// This operation is valid after complete lifecycle shutdown and final
    /// child reconciliation. It drops the modeled node channels that retain
    /// non-owning source-process references; lifecycle metadata and generation
    /// leases remain available for failure containment.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when shutdown is incomplete or any modeled
    /// child has not reached terminal reap.
    pub fn release_reaped_hot_fork_process_loans(&mut self) -> Result<(), LifecycleApiError> {
        if !self.run_manifest.clean_shutdown {
            return Err(loop_factory_error(
                "cannot release hot-fork process loans before lifecycle shutdown",
            ));
        }
        self.inner
            .backend_mut()
            .release_reaped_nodes()
            .map_err(|error| {
                loop_factory_error(format!("release reaped hot-fork process loans: {error}"))
            })
    }

    /// Prepares every retained QEMU source as one failure-atomic source world.
    ///
    /// The lifecycle is consumed before preparation begins. Each per-node
    /// preparation token binds the captured configuration, event-log prefix,
    /// resource profile, and exact source process incarnation. No QEMU node or
    /// generation lease is extracted from the lifecycle in this phase.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionVmHotForkSourceWorldPreparationFailure`] retaining
    /// the lifecycle and every process/resource authority when continuation
    /// capture, ownership validation, source preparation, or rollback fails.
    pub fn prepare_hot_fork_source_world(
        mut self,
    ) -> Result<ProductionVmHotForkSourceWorld, ProductionVmHotForkSourceWorldPreparationFailure>
    {
        let continuation = match self.capture_hot_fork_world_continuation() {
            Ok(continuation) => continuation,
            Err(error) => {
                return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                    self,
                    error.to_string(),
                    Vec::new(),
                ));
            }
        };
        let retained_nodes = continuation
            .nodes()
            .iter()
            .filter(|boundary| {
                boundary.service_state() != ProductionVmHotForkNodeServiceState::PermanentlyFailed
            })
            .map(|boundary| boundary.node().clone())
            .collect::<Vec<_>>();
        if let Err(error) = validate_retained_source_ownership(&self, &retained_nodes) {
            return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                self,
                error.to_string(),
                Vec::new(),
            ));
        }

        let mut prepared: Vec<QemuNodeSetPreparedHotForkTemplate> = Vec::new();
        if prepared.try_reserve_exact(retained_nodes.len()).is_err() {
            return Err(ProductionVmHotForkSourceWorldPreparationFailure::new(
                self,
                "reserve retained source preparation tokens",
                Vec::new(),
            ));
        }
        let configuration = continuation.configuration().id();
        let event_log = self.inner.loop_impl().event_log().clone();
        for node in &retained_nodes {
            let launch_resources = match self.launch_configs.get(node) {
                Some(config) => config.resource_requirements(),
                None => {
                    let rollback = rollback_hot_fork_sources(
                        &mut self,
                        &prepared
                            .iter()
                            .map(|token| HotForkRollbackTarget {
                                node: token.node().clone(),
                                template_generation: Some(token.template_generation()),
                            })
                            .collect::<Vec<_>>(),
                    );
                    return Err(
                        ProductionVmHotForkSourceWorldPreparationFailure::with_rollback(
                            self,
                            format!("retained source `{}` has no launch profile", node.name),
                            rollback,
                        ),
                    );
                }
            };
            match self.inner.backend_mut().prepare_retained_hot_fork_template(
                node,
                configuration,
                event_log.clone(),
                launch_resources,
                &[],
                MAXIMUM_HOT_FORK_RING_IMAGE_BYTES,
            ) {
                Ok(token) => prepared.push(token),
                Err(error) => {
                    let mut rollback_targets = prepared
                        .iter()
                        .map(|token| HotForkRollbackTarget {
                            node: token.node().clone(),
                            template_generation: Some(token.template_generation()),
                        })
                        .collect::<Vec<_>>();
                    // Preparation can fail after QEMU acquired barriers or
                    // transferred descriptors, so the failing node participates
                    // in the same explicit rollback transaction.
                    rollback_targets.push(HotForkRollbackTarget {
                        node: node.clone(),
                        template_generation: None,
                    });
                    let rollback = rollback_hot_fork_sources(&mut self, &rollback_targets);
                    return Err(
                        ProductionVmHotForkSourceWorldPreparationFailure::with_rollback(
                            self,
                            format!("prepare retained source `{}`: {error}", node.name),
                            rollback,
                        ),
                    );
                }
            }
        }

        let after = self.hot_fork_node_boundaries();
        if after.as_ref() != Ok(&continuation.nodes) {
            let rollback_targets = prepared
                .iter()
                .map(|token| HotForkRollbackTarget {
                    node: token.node().clone(),
                    template_generation: Some(token.template_generation()),
                })
                .collect::<Vec<_>>();
            let rollback = rollback_hot_fork_sources(&mut self, &rollback_targets);
            let message = after.map_or_else(
                |error| format!("revalidate prepared source world: {error}"),
                |_boundaries| String::from("prepared source world changed after capture"),
            );
            return Err(
                ProductionVmHotForkSourceWorldPreparationFailure::with_rollback(
                    self, message, rollback,
                ),
            );
        }

        let mut world = ProductionVmHotForkSourceWorld {
            lifecycle: Some(Box::new(self)),
            continuation,
            prepared,
        };
        if let Err(error) = world.validate_source_ownership() {
            let message = error.to_string();
            let targets = world
                .prepared
                .iter()
                .map(|token| HotForkRollbackTarget {
                    node: token.node().clone(),
                    template_generation: Some(token.template_generation()),
                })
                .collect::<Vec<_>>();
            let Some(mut lifecycle) = world.lifecycle.take() else {
                return Err(
                    ProductionVmHotForkSourceWorldPreparationFailure::new_without_lifecycle(
                        message,
                    ),
                );
            };
            let rollback = rollback_hot_fork_sources(&mut lifecycle, &targets);
            world.prepared.clear();
            return Err(
                ProductionVmHotForkSourceWorldPreparationFailure::with_rollback(
                    *lifecycle, message, rollback,
                ),
            );
        }
        Ok(world)
    }

    /// Captures the complete process-neutral half of one atomic world hot fork.
    ///
    /// The lifecycle must already own every source QEMU at an exact global
    /// checkpoint boundary. This method performs no process fork and exposes no
    /// child world. It sandwiches scheduler/fault capture between two identical
    /// source-process and time inventories so an unexpected exit or boundary
    /// change fails before any caller can issue a QEMU fork command.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the world is not exactly quiescent,
    /// mutable debug/checkpoint work is active, network output is unsettled, a
    /// source process changes during capture, or any canonical host continuation
    /// cannot be captured completely.
    pub fn capture_hot_fork_world_continuation(
        &mut self,
    ) -> Result<ProductionVmHotForkWorldContinuation, SchedulerError> {
        if !self.exact_checkpoint_ready()? {
            return Err(hot_fork_boundary_error(
                "production world is not at an exact checkpoint boundary",
            ));
        }
        if self.inner.pending_network_output_count() != 0 {
            return Err(hot_fork_boundary_error(
                "production world retains uncommitted network output",
            ));
        }
        if self.debug_gateway.is_some()
            || self.debug_attach.is_some()
            || self.debug_gateway_teardown_required
            || self.indeterminate_debug_candidate.is_some()
            || !self.checkpoint_targets.is_empty()
        {
            return Err(hot_fork_boundary_error(
                "production world has mutable debug or checkpoint ownership",
            ));
        }
        // A committed journal retains completed-exit history, not unfinished
        // ownership. It remains committed until the next lifecycle event.
        // Completed history does not block capture; live journal entries and
        // staged replacements still do.
        if self.node_lease_cleanup_failed
            || !self.lifecycle_journal.nodes.is_empty()
            || !self.run_manifest.staged_processes.is_empty()
            || !matches!(
                self.lifecycle_journal.phase,
                ProductionLifecycleJournalPhase::Idle | ProductionLifecycleJournalPhase::Committed
            )
        {
            return Err(hot_fork_boundary_error(
                "production world has unresolved process-lifecycle ownership",
            ));
        }

        let before = self.hot_fork_node_boundaries()?;
        let configuration = self.inner.loop_impl().configuration().clone();
        let checkpoint_virtual_time = self.inner.loop_impl().frontier();
        let network_committed_frontier = self.inner.committed_frontier();
        let fault_checkpoint = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor
                .checkpoint(
                    scheduler,
                    network_committed_frontier,
                    pending_outputs,
                    backend,
                )
                .map_err(|error| hot_fork_capture_error("fault/network continuation", error))?
        };
        let scheduler = self.inner.loop_impl().checkpoint().map_err(|error| {
            hot_fork_boundary_error(format!("capture scheduler continuation: {error}"))
        })?;
        let event_log_objects = self
            .inner
            .loop_impl()
            .event_log_dependency_objects()
            .map_err(|error| {
                hot_fork_boundary_error(format!("capture event-log closure: {error}"))
            })?
            .into_iter()
            .collect();
        let selectable_catalog_plans = self.inner.backend().selectable_catalog_plans();
        let after = self.hot_fork_node_boundaries()?;
        if before != after || scheduler.frontier() != checkpoint_virtual_time {
            return Err(hot_fork_boundary_error(
                "production source world changed during continuation capture",
            ));
        }

        let continuation = ProductionVmHotForkWorldContinuation {
            config: self.config.clone(),
            configuration,
            scheduler,
            event_log_objects,
            signal_artifact_objects: self.signal_artifact_objects.clone(),
            trigger_state: self.trigger_state.clone(),
            assertion_state: self.assertion_evaluator.checkpoint(),
            terminal_verdict: self.terminal_verdict.clone(),
            terminal_cause: self.checkpoint_terminal_cause.clone(),
            initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
            branch: self.branch.clone(),
            recorded_controls: self.recorded_controls.clone(),
            selectable_catalog_plans,
            fault_checkpoint,
            node_generations: self.node_generations.clone(),
            node_service_states: self.node_service_states.clone(),
            immutable_root_images: self.immutable_root_images.clone(),
            block_bindings: self
                .block_bindings
                .iter()
                .filter(|(node, _binding)| {
                    self.node_service_states.get(*node)
                        != Some(&ProductionNodeServiceState::PermanentlyFailed)
                })
                .map(|(node, binding)| (node.clone(), binding.clone()))
                .collect(),
            ninep_bindings: self
                .ninep_bindings
                .iter()
                .filter(|(node, _binding)| {
                    self.node_service_states.get(*node)
                        != Some(&ProductionNodeServiceState::PermanentlyFailed)
                })
                .map(|(node, binding)| (node.clone(), binding.clone()))
                .collect(),
            nodes: before,
        };
        continuation.validate_complete_internal_state()?;
        Ok(continuation)
    }

    fn hot_fork_node_boundaries(
        &self,
    ) -> Result<Vec<ProductionVmHotForkNodeBoundary>, SchedulerError> {
        let mut boundaries = Vec::new();
        boundaries
            .try_reserve_exact(self.source.world().vm_nodes().len())
            .map_err(|_error| hot_fork_boundary_error("reserve hot-fork node inventory"))?;
        for vm in self.source.world().vm_nodes() {
            let generation = self.node_generations.get(&vm.id).copied().ok_or_else(|| {
                hot_fork_boundary_error(format!(
                    "hot-fork world has no process generation for `{}`",
                    vm.id.name
                ))
            })?;
            if generation == 0 {
                return Err(hot_fork_boundary_error(format!(
                    "hot-fork world has a zero process generation for `{}`",
                    vm.id.name
                )));
            }
            let service_state = self
                .node_service_states
                .get(&vm.id)
                .copied()
                .ok_or_else(|| {
                    hot_fork_boundary_error(format!(
                        "hot-fork world has no service state for `{}`",
                        vm.id.name
                    ))
                })?;
            let scheduler_time = self.inner.loop_impl().scheduler_time_for_node(&vm.id)?;
            let (physical_time, process) = match service_state {
                ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => (
                    Some(self.inner.backend().node_now(&vm.id)?),
                    Some(self.inner.backend().process_identity(&vm.id)?),
                ),
                ProductionNodeServiceState::PermanentlyFailed => (None, None),
            };
            boundaries.push(ProductionVmHotForkNodeBoundary {
                node: vm.id.clone(),
                generation,
                service_state: service_state.into(),
                scheduler_time,
                physical_time,
                process,
            });
        }
        Ok(boundaries)
    }
}

fn validate_retained_source_ownership(
    lifecycle: &ProductionVmLifecycleLoop,
    retained_nodes: &[NodeId],
) -> Result<(), SchedulerError> {
    for node in retained_nodes {
        let generation = lifecycle
            .node_generations
            .get(node)
            .copied()
            .ok_or_else(|| {
                hot_fork_boundary_error(format!(
                    "retained source `{}` has no process generation",
                    node.name
                ))
            })?;
        let expected = ProductionVmNodeGeneration::new(node.clone(), generation)
            .map_err(|error| hot_fork_boundary_error(error.to_string()))?;
        let lease = lifecycle.node_leases.get(node).ok_or_else(|| {
            hot_fork_boundary_error(format!(
                "retained source `{}` has no generation lease",
                node.name
            ))
        })?;
        if lease.identity() != &expected {
            return Err(hot_fork_boundary_error(format!(
                "retained source `{}` lease names another generation",
                node.name
            )));
        }
        if !lifecycle.node_run_directories.contains_key(node) {
            return Err(hot_fork_boundary_error(format!(
                "retained source `{}` has no owned run directory",
                node.name
            )));
        }
        if !lifecycle.launch_configs.contains_key(node) {
            return Err(hot_fork_boundary_error(format!(
                "retained source `{}` has no exact launch profile",
                node.name
            )));
        }
        if !lifecycle.inner.backend().contains(node) {
            return Err(hot_fork_boundary_error(format!(
                "retained source `{}` has no authoritative QEMU node",
                node.name
            )));
        }
    }
    Ok(())
}

fn rollback_hot_fork_sources(
    lifecycle: &mut ProductionVmLifecycleLoop,
    targets: &[HotForkRollbackTarget],
) -> HotForkRollbackReport {
    let mut diagnostics = BTreeMap::new();
    for target in targets.iter().rev() {
        let mut complete = false;
        let mut diagnostic = None;
        for poll in 0..MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE {
            match lifecycle
                .inner
                .backend_mut()
                .abort_retained_hot_fork_template(&target.node, target.template_generation)
            {
                Ok(true) => {
                    complete = true;
                    break;
                }
                Ok(false) => {
                    if poll + 1 < MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE {
                        std::thread::sleep(HOT_FORK_ROLLBACK_POLL_INTERVAL);
                    }
                }
                Err(error) => {
                    diagnostic = Some(error.to_string());
                    break;
                }
            }
        }
        if !complete {
            diagnostics.insert(
                target.node.clone(),
                diagnostic.unwrap_or_else(|| {
                    format!(
                        "retained-template rollback exceeded {} bounded exchanges",
                        MAXIMUM_HOT_FORK_ROLLBACK_POLLS_PER_NODE
                    )
                }),
            );
        }
    }
    HotForkRollbackReport {
        nodes: diagnostics.keys().cloned().collect(),
        diagnostics,
    }
}

fn hot_fork_capture_error(role: &str, error: SchedulerError) -> SchedulerError {
    hot_fork_boundary_error(format!("capture hot-fork {role}: {error}"))
}

fn hot_fork_boundary_error(message: impl Into<String>) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.into(),
    }
}

#[cfg(feature = "test-support")]
mod test_support;
#[cfg(feature = "test-support")]
pub(super) use test_support::record_hot_fork_adoption_for_test;
#[cfg(feature = "test-support")]
pub use test_support::{
    hot_fork_adoption_count_for_test, prepared_hot_fork_source_world_for_test,
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_for_test, reset_hot_fork_adoption_count_for_test,
};

#[cfg(test)]
#[path = "hot_fork/tests.rs"]
mod tests;
