//! Production lifecycle installation for one complete hot-fork child world.
//!
//! This module is the sole consumer of a complete world assembly. It converts
//! every installed child directly into the API's opaque adoption capability,
//! installs one production scheduler lifecycle, and keeps the source world,
//! aggregate target guard, and post-shutdown reconciliation set together until
//! the supervisor supplies a durable semantic disposition.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// crucible-lint: allow host-nondeterminism-state -- The lifecycle owns canonical scheduler progress; host observations only govern process cleanup and never select modeled transitions.
use crucible::{
    Configuration, ContentHash, FingerprintSample, NodeId, QuantumLoop, QuantumOutcome,
    QuantumRequest, QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SelectionDecision, VirtualTime,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmHotForkNodeServiceState,
    ProductionVmHotForkSourceWorld, ProductionVmLifecycleLoop, ProductionVmNodeGeneration,
    ProductionVmNodeReplayLaunchProfile,
    build_production_vm_lifecycle_loop_from_hot_fork_with_launcher,
};
use crucible_protocol::SelectionReply;
use crucible_qemu::{QemuNodeSelectablePendingRequest, QemuParkedCampaignMarker};

use super::QemuHotForkCompleteWorldAssembly;
use crate::qemu_hot_fork_reconciliation::LinuxQemuHotForkWorldReconciliationSet;
use crate::qemu_hot_fork_world_resource::QemuHotForkWorldAuxiliaryResourceBinding;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptExecutionRuntimeBasis, CapturedAttemptCheckpoint, ExactCheckpointStore,
    ExecutionCancellation, LinuxQemuHotForkReconciliationBackend,
    QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmNodeLauncher, QemuFreshAttemptLifecycleOwner,
    QemuFreshStartMaterialization, QemuHotForkAttemptReconciliation, QemuHotForkSourceWorldLease,
    QemuHotForkWorldAuxiliaryResourceBroker, QemuHotForkWorldNodeTarget,
    QemuHotForkWorldResourceOwner,
};

type ProductionWorldChild<G> = QemuHotForkAttemptReconciliation<
    LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
>;

/// Immutable inputs used to install one complete hot-fork world.
pub(crate) struct QemuHotForkProductionLifecycleContext<'a> {
    scenario: &'a crucible::ScenarioDef,
    source: &'a crucible::ScenarioDefForm,
    runtime_basis: AttemptExecutionRuntimeBasis,
    run_state_root: PathBuf,
    terminal_checkpoints: Option<Arc<ExactCheckpointStore>>,
    cancellation: Option<ExecutionCancellation>,
}

impl<'a> QemuHotForkProductionLifecycleContext<'a> {
    /// Groups one installation's semantic and runtime inputs.
    pub(crate) fn new(
        scenario: &'a crucible::ScenarioDef,
        source: &'a crucible::ScenarioDefForm,
        runtime_basis: AttemptExecutionRuntimeBasis,
        run_state_root: PathBuf,
    ) -> Self {
        Self {
            scenario,
            source,
            runtime_basis,
            run_state_root,
            terminal_checkpoints: None,
            cancellation: None,
        }
    }

    pub(crate) fn with_terminal_checkpoints(
        mut self,
        checkpoints: Option<Arc<ExactCheckpointStore>>,
        cancellation: ExecutionCancellation,
    ) -> Self {
        self.terminal_checkpoints = checkpoints;
        self.cancellation = Some(cancellation);
        self
    }
}

struct QuarantinedProductionHotForkLifecycleInstall<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    _source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    _reconciliations: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    _resources: QemuHotForkWorldResourceOwner<G>,
}

/// Complete production lifecycle plus every authority retained past shutdown.
#[must_use = "reconcile the hot-fork world through durable publication or quarantine it"]
pub struct QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    runtime_basis: AttemptExecutionRuntimeBasis,
    lifecycle: ProductionVmLifecycleLoop,
    source_lease: Option<QemuHotForkSourceWorldLease>,
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    reconciliations: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    resources: QemuHotForkWorldResourceOwner<G>,
    auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<G>>,
    auxiliary_binding: Option<QemuHotForkWorldAuxiliaryResourceBinding<G>>,
    shutdown_complete: bool,
    aggregate_released: bool,
    source_recovery_failed: bool,
}

/// Authorities retained while one adopted child serves as a descendant template.
///
/// Each link owns the previous template lease, the child reconciliation set,
/// and the aggregate resources that protect the promoted process. Links are
/// nested so final retirement can unwind the lineage from its youngest source
/// back to the original template without detaching any process authority.
pub struct QemuProductionHotForkRetainedLineage<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    source_lease: QemuHotForkSourceWorldLease,
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    reconciliations: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    resources: QemuHotForkWorldResourceOwner<G>,
    auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<G>>,
    auxiliary_binding: Option<QemuHotForkWorldAuxiliaryResourceBinding<G>>,
    ancestor: Option<Box<Self>>,
}

impl<G> QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Re-adopts this child and prepares it as the next descendant template.
    ///
    /// The returned lineage authority must remain paired with the prepared
    /// world. A failure quarantines all authorities rather than returning a
    /// partially promoted process.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error when the child was already shut down, any
    /// authority is missing, or re-adoption and template preparation fails.
    pub fn promote_into_descendant_template(
        self,
        ancestor: Option<Box<QemuProductionHotForkRetainedLineage<G>>>,
    ) -> Result<
        (
            ProductionVmHotForkSourceWorld,
            QemuProductionHotForkRetainedLineage<G>,
        ),
        LifecycleApiError,
    > {
        let Self {
            runtime_basis: _,
            lifecycle,
            source_lease,
            source_world,
            reconciliations,
            mut resources,
            auxiliary_resources,
            auxiliary_binding,
            shutdown_complete,
            aggregate_released,
            source_recovery_failed,
        } = self;
        if shutdown_complete || aggregate_released || source_recovery_failed {
            resources.quarantine();
            let _retained = Box::leak(Box::new((source_lease, source_world, reconciliations)));
            return Err(lifecycle_error(
                "hot-fork child promotion requires a live unreconciled lifecycle",
            ));
        }
        let Some(source_lease) = source_lease else {
            resources.quarantine();
            let _retained = Box::leak(Box::new((source_world, reconciliations)));
            return Err(lifecycle_error(
                "hot-fork child promotion lost its parent source lease",
            ));
        };
        let world = match lifecycle.promote_hot_fork_child_source_world() {
            Ok(world) => world,
            Err(failure) => {
                resources.quarantine();
                let _retained = Box::leak(Box::new((
                    failure,
                    source_lease,
                    source_world,
                    reconciliations,
                    auxiliary_binding,
                    ancestor,
                )));
                return Err(lifecycle_error(
                    "re-adopt and prepare hot-fork child as descendant template",
                ));
            }
        };
        let lineage = QemuProductionHotForkRetainedLineage {
            source_lease,
            source_world,
            reconciliations,
            resources,
            auxiliary_resources,
            auxiliary_binding,
            ancestor,
        };
        Ok((world, lineage))
    }

    /// Returns the exact supervisor incarnation that owns this child world.
    #[must_use]
    pub const fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }

    /// Reconstructs the already-materialized start evidence from the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a scheduler error when the adopted lifecycle cannot expose its
    /// exact boundary, retained only a suffix, or its event bytes overflow.
    pub fn start_materialization(&self) -> Result<QemuFreshStartMaterialization, SchedulerError> {
        let (
            configuration,
            event_log,
            base_events,
            completed_quanta,
            frontier,
            quiescence,
            terminal_verdict,
        ) = self.lifecycle.resume_state()?.into_parts();
        if base_events != 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "hot-fork start retained only an event-log suffix instead of the complete prefix",
                ),
            });
        }
        let event_log_bytes = event_log.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.canonical_material_len())
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("hot-fork start event-log byte count overflowed"),
                })
        })?;
        Ok(QemuFreshStartMaterialization::from_resume_parts(
            configuration,
            event_log,
            event_log_bytes,
            completed_quanta,
            frontier,
            quiescence,
            terminal_verdict,
        ))
    }

    /// Advances one bounded post-publication reconciliation operation.
    ///
    /// Aggregate enforcement is released only after every source-parent status
    /// record and child process contract was released under the same disposition.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error before shutdown, on child reconciliation
    /// failure, or when aggregate release cannot be attested.
    pub fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, LifecycleApiError> {
        if !self.shutdown_complete {
            return Err(lifecycle_error(
                "hot-fork world publication reconciliation preceded lifecycle shutdown",
            ));
        }
        if self.aggregate_released {
            return Ok(AttemptExecutionReconciliationStep::Complete);
        }
        let step = self
            .reconciliations
            .reconcile_execution_disposition(disposition)?;
        if step == AttemptExecutionReconciliationStep::Progressed {
            return Ok(step);
        }
        self.resources.finish().map_err(|error| {
            lifecycle_error(format!(
                "release hot-fork world aggregate resources after publication: {error}"
            ))
        })?;
        self.auxiliary_binding = None;
        self.aggregate_released = true;
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    /// Transfers child and aggregate ownership to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        self.auxiliary_binding = None;
        self.reconciliations.quarantine();
        self.resources.quarantine();
    }

    /// Recovers the authenticated source lease after final reconciliation.
    ///
    /// # Errors
    ///
    /// Returns the lifecycle with all live process and resource ownership when
    /// aggregate release is incomplete, the source lock is poisoned, modeled
    /// process-loan release fails, or the lease is absent. Reaped modeled-channel
    /// loans may already have been released after final reconciliation.
    pub(crate) fn into_source_lease(mut self) -> Result<QemuHotForkSourceWorldLease, Box<Self>> {
        if !self.aggregate_released
            || self.source_recovery_failed
            || self.source_world.is_poisoned()
        {
            return Err(Box::new(self));
        }
        if self
            .lifecycle
            .release_reaped_hot_fork_process_loans()
            .is_err()
        {
            self.source_recovery_failed = true;
            return Err(Box::new(self));
        }
        self.source_lease.take().ok_or_else(|| Box::new(self))
    }

    #[cfg(test)]
    pub(crate) fn source_world_owner_for_test(&self) -> Arc<Mutex<ProductionVmHotForkSourceWorld>> {
        Arc::clone(&self.source_world)
    }

    /// Commits a selected Boot through the adopted production lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a scheduler error when the retained node cannot reactivate.
    #[cfg(test)]
    pub(crate) fn commit_modeled_boot_for_test(
        &mut self,
        node: &NodeId,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.commit_modeled_boot_for_test(node)
    }
}

impl<G> QemuProductionHotForkRetainedLineage<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Retires one prepared descendant and then unwinds every retained parent.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error when shutdown, reconciliation, resource
    /// release, process-loan release, or parent-source recovery fails.
    pub fn retire_source_world(
        mut self,
        source: ProductionVmHotForkSourceWorld,
    ) -> Result<(), LifecycleApiError> {
        let mut lifecycle = source
            .recover()
            .map_err(|failure| lifecycle_error(failure.to_string()))?;
        QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).map_err(|error| {
            lifecycle_error(format!("shutdown promoted hot-fork source: {error}"))
        })?;
        if let Some(broker) = &self.auxiliary_resources {
            self.auxiliary_binding = Some(broker.bind(&self.resources).map_err(|error| {
                lifecycle_error(format!(
                    "bind promoted hot-fork auxiliary resources after shutdown: {error}"
                ))
            })?);
        }

        let mut reconciliation_complete = false;
        for _ in 0..1024 {
            if self
                .reconciliations
                .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)?
                == AttemptExecutionReconciliationStep::Complete
            {
                reconciliation_complete = true;
                break;
            }
        }
        if !reconciliation_complete {
            self.quarantine();
            let _retained = Box::leak(Box::new((self, lifecycle)));
            return Err(lifecycle_error(
                "promoted hot-fork child did not reconcile within the bounded retirement",
            ));
        }
        self.resources.finish().map_err(|error| {
            lifecycle_error(format!("release promoted hot-fork resources: {error}"))
        })?;
        self.auxiliary_binding = None;
        lifecycle.release_reaped_hot_fork_process_loans()?;
        drop(lifecycle);

        drop(self.source_world);
        let parent = self.source_lease.into_exclusive_source().map_err(|lease| {
            let _retained = Box::leak(lease);
            lifecycle_error("recover exclusive parent template after descendant retirement")
        })?;
        match self.ancestor {
            Some(ancestor) => ancestor.retire_source_world(parent),
            None => parent.retire(),
        }
    }

    fn quarantine(&mut self) {
        self.auxiliary_binding = None;
        self.reconciliations.quarantine();
        self.resources.quarantine();
    }
}

impl<G> QemuFreshAttemptLifecycleOwner for QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.lifecycle.enable_signal_fault_campaign_promotion();
    }

    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.set_attempt_stop_frontier(frontier)
    }

    fn set_live_network_choice_pause(&mut self, enabled: bool) {
        self.lifecycle.set_live_network_choice_pause(enabled);
    }

    fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        self.lifecycle.set_choice_free_parallel_boot(enabled);
    }

    fn live_network_preselection(&self) -> Option<crucible::LiveNetworkPreselection> {
        self.lifecycle.live_network_preselection()
    }

    fn select_live_network_preselection(
        &mut self,
        selection: SelectionDecision,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.lifecycle.select_live_network_preselection(selection)
    }

    fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        self.lifecycle.settle_live_network_preselection()
    }

    fn handoff_live_network_preselection(
        &mut self,
        expected: &crucible::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.handoff_live_network_preselection(expected)
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QuantumLoop::drive_quantum(&mut self.lifecycle, request)
    }

    fn completed_quanta(&self) -> u64 {
        self.lifecycle.completed_quanta()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QuantumLoop::terminal_verdict_for_stop(&mut self.lifecycle)
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        QuantumLoop::prepare_terminal_checkpoint(&mut self.lifecycle, cause)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.lifecycle.exact_checkpoint_ready()
    }

    fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        self.lifecycle.parked_campaign_marker(node)
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        self.lifecycle
            .release_parked_campaign_marker(node, marker, selected)
    }

    fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        Ok(self
            .lifecycle
            .campaign_marker_release_committed(node, marker, selected))
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        self.lifecycle.campaign_network_queues_empty()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.lifecycle.drain_pending_selectable_requests()
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.lifecycle
            .apply_selectable_reply(parent, decision, selected, pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.lifecycle
            .capture_portable_exact_checkpoint_with_boundary(&mut || {
                if context.cancellation().is_canceled() {
                    return Err(SchedulerError::OperationalBoundary {
                        class: SchedulerOperationalFailureClass::Canceled,
                        message: String::from("checkpoint capture canceled"),
                    });
                }
                Ok(())
            })
            .map(CapturedAttemptCheckpoint::from_production_closure)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        self.lifecycle
            .replay_launch_profiles()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("derive hot-fork production replay launch profiles: {error}"),
            })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.lifecycle.fault_evidence_snapshot()
    }

    fn pending_network_output_count(&self) -> usize {
        self.lifecycle.pending_network_output_count()
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- this forwards canonical QEMU fingerprint evidence; host sampling timing cannot select or mutate modeled execution.
        QuantumLoop::sample_fingerprint(&mut self.lifecycle, node)
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- this copies the scheduler-retained RecomputedCause trace; the observation never feeds back into modeled execution.
        QuantumLoop::resolved_effect_trace(&self.lifecycle)
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.shutdown_complete {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("hot-fork world lifecycle was shut down more than once"),
            });
        }
        let events = QuantumLoop::shutdown(&mut self.lifecycle)?;
        self.reconciliations
            .validate_operational_handoff()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })?;
        if let Some(broker) = &self.auxiliary_resources {
            let binding = broker.bind(&self.resources).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("bind hot-fork auxiliary resources after shutdown: {error}"),
                }
            })?;
            self.auxiliary_binding = Some(binding);
        }
        self.shutdown_complete = true;
        Ok(events)
    }
}

impl<G>
    QemuHotForkCompleteWorldAssembly<
        QemuHotForkAttemptReconciliation<
            LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
        >,
    >
where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Installs this complete assembly as one production lifecycle transaction.
    // crucible-lint: allow rust-allow -- installation binds every semantic basis and owned runtime resource in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_production_lifecycle(
        self,
        context: QemuHotForkProductionLifecycleContext<'_>,
        source_lease: QemuHotForkSourceWorldLease,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        mut resources: QemuHotForkWorldResourceOwner<G>,
        auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<G>>,
    ) -> Result<QemuProductionHotForkWorldLifecycle<G>, LifecycleApiError> {
        let QemuHotForkProductionLifecycleContext {
            scenario,
            source,
            runtime_basis,
            run_state_root,
            terminal_checkpoints,
            cancellation,
        } = context;
        let boundaries = self
            .continuation
            .nodes()
            .iter()
            .map(|boundary| {
                (
                    boundary.node().clone(),
                    (boundary.service_state(), boundary.generation()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let child_nodes = self.children.keys().cloned().collect::<Vec<_>>();
        for node in child_nodes {
            let Some(boundary) = boundaries.get(&node) else {
                return retain_complete_install_failure(
                    source_world,
                    resources,
                    self,
                    lifecycle_error(format!(
                        "assembled hot-fork child `{}` is absent from its continuation",
                        node.name
                    )),
                );
            };
            if boundary.0 == ProductionVmHotForkNodeServiceState::PermanentlyFailed {
                return retain_complete_install_failure(
                    source_world,
                    resources,
                    self,
                    lifecycle_error(format!(
                        "assembled hot-fork child `{}` is not a retained source node",
                        node.name
                    )),
                );
            }
            let Some(generation) = boundary.1.checked_add(1) else {
                return retain_complete_install_failure(
                    source_world,
                    resources,
                    self,
                    lifecycle_error(format!(
                        "hot-fork source generation for `{}` cannot advance",
                        node.name
                    )),
                );
            };
            if let Err(error) = ProductionVmNodeGeneration::new(node, generation) {
                return retain_complete_install_failure(source_world, resources, self, error);
            }
        }
        let expected = self.children.keys().cloned().collect::<BTreeSet<NodeId>>();
        let completed = LinuxQemuHotForkWorldReconciliationSet::new(expected);
        let maximum_nodes = source.world().vm_nodes().len();
        let lifecycle_guard = match resources.lifecycle_guard() {
            Ok(guard) => guard,
            Err(error) => {
                return retain_complete_install_failure(
                    source_world,
                    resources,
                    self,
                    lifecycle_error(format!(
                        "install hot-fork world lifecycle launcher: {error}"
                    )),
                );
            }
        };
        let generation_owner =
            match QemuAttemptGenerationResourceOwner::new(lifecycle_guard, maximum_nodes) {
                Ok(owner) => owner,
                Err(error) => {
                    return retain_complete_install_failure(source_world, resources, self, error);
                }
            };
        let mut launcher = QemuAttemptProductionVmNodeLauncher::new(generation_owner);
        if let (Some(checkpoints), Some(cancellation)) = (terminal_checkpoints, cancellation) {
            launcher =
                launcher.with_terminal_checkpoint_import(checkpoints, source.clone(), cancellation);
        }

        let Self {
            continuation,
            mut children,
        } = self;
        let mut adoptions = Vec::with_capacity(children.len());
        while let Some(node) = children.keys().next().cloned() {
            let child = match children.remove(&node) {
                Some(child) => child,
                None => {
                    let error =
                        lifecycle_error("assembled hot-fork child disappeared during adoption");
                    retain_remaining_install_failure(source_world, resources, completed, children);
                    return Err(error);
                }
            };
            let generation = match boundaries
                .get(&node)
                .and_then(|(_state, generation)| generation.checked_add(1))
            {
                Some(generation) => generation,
                None => {
                    let error = lifecycle_error(format!(
                        "hot-fork source generation for `{}` changed during adoption",
                        node.name
                    ));
                    child.quarantine_and_retain();
                    retain_remaining_install_failure(source_world, resources, completed, children);
                    return Err(error);
                }
            };
            let identity = match ProductionVmNodeGeneration::new(node, generation) {
                Ok(identity) => identity,
                Err(error) => {
                    child.quarantine_and_retain();
                    retain_remaining_install_failure(source_world, resources, completed, children);
                    return Err(error);
                }
            };
            let adoption = match child.into_world_node_adoption(identity, completed.clone()) {
                Ok(adoption) => adoption,
                Err(error) => {
                    retain_remaining_install_failure(source_world, resources, completed, children);
                    return Err(error);
                }
            };
            adoptions.push(adoption);
        }
        let lifecycle = match build_production_vm_lifecycle_loop_from_hot_fork_with_launcher(
            scenario,
            source,
            continuation,
            adoptions,
            run_state_root,
            launcher,
        ) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                retain_remaining_install_failure(source_world, resources, completed, children);
                return Err(error);
            }
        };
        Ok(QemuProductionHotForkWorldLifecycle {
            runtime_basis,
            lifecycle,
            source_lease: Some(source_lease),
            source_world,
            reconciliations: completed,
            resources,
            auxiliary_resources,
            auxiliary_binding: None,
            shutdown_complete: false,
            aggregate_released: false,
            source_recovery_failed: false,
        })
    }
}

trait RetainFailedWorldChild {
    fn quarantine_and_retain(self);
}

impl<G> RetainFailedWorldChild for ProductionWorldChild<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn quarantine_and_retain(mut self) {
        self.quarantine();
        std::mem::forget(self);
    }
}

fn retain_complete_install_failure<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    complete: QemuHotForkCompleteWorldAssembly<ProductionWorldChild<G>>,
    error: LifecycleApiError,
) -> Result<QemuProductionHotForkWorldLifecycle<G>, LifecycleApiError>
where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
{
    complete.quarantine();
    resources.quarantine();
    let reconciliations = LinuxQemuHotForkWorldReconciliationSet::new(BTreeSet::new());
    let quarantine = QuarantinedProductionHotForkLifecycleInstall {
        _source_world: source_world,
        _reconciliations: reconciliations,
        _resources: resources,
    };
    let _retained_for_process_lifetime = Box::leak(Box::new(quarantine));
    Err(error)
}

fn retain_remaining_install_failure<G>(
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    mut resources: QemuHotForkWorldResourceOwner<G>,
    mut reconciliations: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    children: BTreeMap<NodeId, ProductionWorldChild<G>>,
) where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
{
    for (_node, child) in children {
        child.quarantine_and_retain();
    }
    reconciliations.quarantine();
    resources.quarantine();
    let quarantine = QuarantinedProductionHotForkLifecycleInstall {
        _source_world: source_world,
        _reconciliations: reconciliations,
        _resources: resources,
    };
    let _retained_for_process_lifetime = Box::leak(Box::new(quarantine));
}

fn lifecycle_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}
