//! Process-neutral production-world continuation for QEMU hot fork.
//!
//! A hot-fork child inherits guest memory from each paused source QEMU, but it
//! does not inherit the host scheduler, network, trigger, assertion, selectable,
//! or fault owners. This module captures that complete host continuation at one
//! exact world boundary. The opaque token is the semantic half of a future
//! atomic world-fork transaction; it grants no process launch, child admission,
//! mutable run-directory, or source-template recovery authority.

use super::*;

/// Modeled service state of one node in a hot-fork world continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmHotForkNodeServiceState {
    /// The node has one paused source QEMU that must participate in the fork.
    Running,
    /// The node is modeled as powered off and has no source process.
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

    /// Returns the physical QEMU time for a running source node.
    #[must_use]
    pub const fn physical_time(&self) -> Option<VirtualTime> {
        self.physical_time
    }

    /// Returns the exact Linux source-process incarnation for a running node.
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
            let running = boundary.service_state == ProductionVmHotForkNodeServiceState::Running;
            if generation != boundary.generation
                || ProductionVmHotForkNodeServiceState::from(service_state)
                    != boundary.service_state
                || boundary.physical_time.is_some() != running
                || boundary.process.is_some() != running
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
        if self.node_lease_cleanup_failed
            || !matches!(
                self.lifecycle_journal.phase,
                ProductionLifecycleJournalPhase::Idle
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
                ProductionNodeServiceState::Running => (
                    Some(self.inner.backend().node_now(&vm.id)?),
                    Some(self.inner.backend().process_identity(&vm.id)?),
                ),
                ProductionNodeServiceState::PoweredOff
                | ProductionNodeServiceState::PermanentlyFailed => (None, None),
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

fn hot_fork_capture_error(role: &str, error: SchedulerError) -> SchedulerError {
    hot_fork_boundary_error(format!("capture hot-fork {role}: {error}"))
}

fn hot_fork_boundary_error(message: impl Into<String>) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.into(),
    }
}

#[cfg(test)]
#[path = "hot_fork/tests.rs"]
mod tests;
