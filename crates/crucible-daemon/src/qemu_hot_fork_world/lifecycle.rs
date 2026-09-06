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

use crucible::{
    NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, SchedulerError,
    SchedulerEventLogEntry, SchedulerOperationalFailureClass,
};
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmHotForkNodeServiceState,
    ProductionVmHotForkSourceWorld, ProductionVmLifecycleLoop, ProductionVmNodeGeneration,
    ProductionVmNodeReplayLaunchProfile,
    build_production_vm_lifecycle_loop_from_hot_fork_with_launcher,
};
use crucible_protocol::SelectionReply;
use crucible_qemu::QemuNodeSelectablePendingRequest;

use super::QemuHotForkCompleteWorldAssembly;
use crate::qemu_hot_fork_reconciliation::LinuxQemuHotForkWorldReconciliationSet;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptExecutionRuntimeBasis, CapturedAttemptCheckpoint, LinuxQemuHotForkReconciliationBackend,
    QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmNodeLauncher, QemuFreshAttemptLifecycleOwner,
    QemuFreshStartMaterialization, QemuHotForkAttemptReconciliation, QemuHotForkWorldNodeTarget,
    QemuHotForkWorldResourceOwner,
};

type ProductionWorldChild<G> = QemuHotForkAttemptReconciliation<
    LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
>;

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
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    reconciliations: LinuxQemuHotForkWorldReconciliationSet<QemuHotForkWorldNodeTarget<G>>,
    resources: QemuHotForkWorldResourceOwner<G>,
    shutdown_complete: bool,
    aggregate_released: bool,
    source_recovery_failed: bool,
}

impl<G> QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
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
        let (event_log, base_events, quiescence, terminal_verdict) =
            self.lifecycle.resume_state()?.into_parts();
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
            event_log,
            event_log_bytes,
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
        self.aggregate_released = true;
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    /// Transfers child and aggregate ownership to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        self.reconciliations.quarantine();
        self.resources.quarantine();
    }

    /// Recovers the complete prepared source world after final reconciliation.
    ///
    /// # Errors
    ///
    /// Returns the lifecycle with all live process and resource ownership until
    /// aggregate release completes, or when another owner still retains the
    /// source-world capability. Reaped modeled-channel loans may already have
    /// been released after final reconciliation.
    pub fn into_source_world(mut self) -> Result<ProductionVmHotForkSourceWorld, Box<Self>> {
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
        let Self {
            source_world,
            runtime_basis,
            lifecycle,
            reconciliations,
            resources,
            shutdown_complete,
            aggregate_released,
            source_recovery_failed,
        } = self;
        let source_world = match Arc::try_unwrap(source_world) {
            Ok(source_world) => source_world,
            Err(source_world) => {
                return Err(Box::new(Self {
                    runtime_basis,
                    lifecycle,
                    source_world,
                    reconciliations,
                    resources,
                    shutdown_complete,
                    aggregate_released,
                    source_recovery_failed,
                }));
            }
        };
        match source_world.into_inner() {
            Ok(source_world) => Ok(source_world),
            Err(poisoned) => {
                let source_world = Arc::new(Mutex::new(poisoned.into_inner()));
                Err(Box::new(Self {
                    runtime_basis,
                    lifecycle,
                    source_world,
                    reconciliations,
                    resources,
                    shutdown_complete,
                    aggregate_released,
                    source_recovery_failed: true,
                }))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn source_world_owner_for_test(&self) -> Arc<Mutex<ProductionVmHotForkSourceWorld>> {
        Arc::clone(&self.source_world)
    }
}

impl<G> QemuFreshAttemptLifecycleOwner for QemuProductionHotForkWorldLifecycle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.lifecycle.enable_signal_fault_campaign_promotion();
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QuantumLoop::drive_quantum(&mut self.lifecycle, request)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QuantumLoop::terminal_verdict_for_stop(&mut self.lifecycle)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.lifecycle.exact_checkpoint_ready()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.lifecycle.drain_pending_selectable_requests()
    }

    fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.enqueue_selectable_reply(pending, reply)
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
            .map(Into::into)
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
    pub(crate) fn install_production_lifecycle(
        self,
        scenario: &crucible::ScenarioDef,
        source: &crucible::ScenarioDefForm,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        runtime_basis: AttemptExecutionRuntimeBasis,
        run_state_root: PathBuf,
        mut resources: QemuHotForkWorldResourceOwner<G>,
    ) -> Result<QemuProductionHotForkWorldLifecycle<G>, LifecycleApiError> {
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
        if boundaries
            .values()
            .any(|(state, _generation)| *state == ProductionVmHotForkNodeServiceState::PoweredOff)
        {
            return retain_complete_install_failure(
                source_world,
                resources,
                self,
                lifecycle_error("powered-off source nodes require exact/thin fallback"),
            );
        }
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
            if boundary.0 != ProductionVmHotForkNodeServiceState::Running {
                return retain_complete_install_failure(
                    source_world,
                    resources,
                    self,
                    lifecycle_error(format!(
                        "assembled hot-fork child `{}` is not a running source node",
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
        let launcher = QemuAttemptProductionVmNodeLauncher::new(generation_owner);

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
            source_world,
            reconciliations: completed,
            resources,
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
