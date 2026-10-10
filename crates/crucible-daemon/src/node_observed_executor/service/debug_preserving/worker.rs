//! Retains original capture and fresh stopped owners across fallible actor steps.
//!
//! An archive link is authenticated data. Only the installed factory and actual
//! native restore produce a replacement owner; current durable reconciliation
//! remains mandatory before that owner's original Resume.

use std::{
    rc::Rc,
    task::{Context, Poll, Waker},
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        BeginResult, NodeRuntime, OperationToken, PublicationStatus, RuntimeSnapshot,
        WorldActivation,
    },
    node_state::{
        HostArchive, HostArchiveRecord, HostWorldRestoreDriver, RestorePublication, RestoredWorld,
        StateLimits, StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::RefName;
use crucible_node_contract::{ContentRef, Id, U64};

use super::super::{ActorStorage, NodeObservationServiceError};
use super::{
    NodePreservingDebugAction, NodePreservingDebugCapture, NodePreservingDebugRequest,
    NodePreservingDebugResumeRequest, NodePreservingDebugState, Reservation, refused,
};
use crate::{
    node_observed_executor::{
        ConditionExecution, InstalledNodeCatalog, StoredConditionResultPublisher,
        StoredWorldActivationPublisher,
    },
    node_scenario::NodeScenario,
};

enum Phase {
    Prepare,
    Stop,
    Held,
    Resume,
    PublishSuffix,
    StoreSuffix,
    ReconcileSuffix,
    Reclaim,
    Released,
}

/// Owns all effect-capable state outside the service's callback unwind scopes.
pub(in crate::node_observed_executor::service) struct Worker {
    pub(super) reservation: Reservation,
    pub(super) outcome: Option<NodePreservingDebugState>,
    pub(super) published: bool,
    request: NodePreservingDebugRequest,
    graph: Option<Rc<AdmittedGraph>>,
    capabilities: Option<crate::node_observed_executor::ResolvedCapabilityWorld>,
    runtime: Option<NodeRuntime>,
    restored: Option<Box<RestoredWorld>>,
    activation: Option<WorldActivation>,
    archive: HostArchive,
    capture: Option<NodePreservingDebugCapture>,
    original_record: Option<HostArchiveRecord>,
    driver: ConditionExecution,
    token: Option<OperationToken>,
    resume: Option<NodePreservingDebugResumeRequest>,
    completed: Option<NodePreservingDebugState>,
    completed_receipt: Option<ContentRef>,
    completed_ledger: Option<RuntimeSnapshot>,
    // Original suffix effects may already exist. Their complete owning data
    // must survive any seal/storage failure independently of native cleanup.
    suffix_unsealed: bool,
    sealed_suffix: Option<super::ledger::SealedOutputs>,
    phase: Phase,
}

impl Worker {
    pub(super) fn new(
        request: NodePreservingDebugRequest,
        reservation: Reservation,
        storage: &ActorStorage,
    ) -> Result<Self, NodeObservationServiceError> {
        request.validate()?;
        let archive = HostArchive::open(storage.condition_archive.clone(), limits(&request)?)
            .map_err(refused)?;
        let capture = reservation.record.capture.clone();
        Ok(Self {
            reservation,
            outcome: None,
            published: false,
            request,
            graph: None,
            capabilities: None,
            runtime: None,
            restored: None,
            activation: None,
            archive,
            capture,
            original_record: None,
            driver: ConditionExecution::new(8192).map_err(refused)?,
            token: None,
            resume: None,
            completed: None,
            completed_receipt: None,
            completed_ledger: None,
            suffix_unsealed: false,
            sealed_suffix: None,
            phase: Phase::Prepare,
        })
    }

    /// Advances only the original step while the actor retains this owner.
    pub(super) fn poll(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
        storage: &ActorStorage,
        stopping: bool,
    ) -> Result<(), NodeObservationServiceError> {
        if stopping {
            self.contain();
        }
        match self.phase {
            Phase::Prepare => self.prepare(catalog, storage),
            Phase::Stop => self.finish_stop(catalog, storage),
            Phase::Held => Ok(()),
            Phase::Resume => self.finish_resume(),
            Phase::PublishSuffix => self.publish_suffix(storage),
            Phase::StoreSuffix => self.store_suffix(storage),
            Phase::ReconcileSuffix => self.reconcile_suffix(storage),
            Phase::Reclaim => {
                let mut context = Context::from_waker(Waker::noop());
                let _ = catalog.custody().poll_reclamation(&mut context);
                // Other current worlds may remain live. A transferred cleanup
                // capsule (including a currently polled one) must actually vanish.
                if catalog.custody().retained_worlds() == 0 {
                    if self.outcome.is_none() {
                        self.outcome = self.completed.take().or_else(|| {
                            Some(NodePreservingDebugState::Unknown {
                                reason:
                                    "original preserving actor contained without Resume authority"
                                        .into(),
                            })
                        });
                    }
                    self.phase = Phase::Released;
                }
                Ok(())
            }
            Phase::Released => Ok(()),
        }
    }

    fn prepare(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        if self.graph.is_some() || self.runtime.is_some() || self.restored.is_some() {
            return Err(refused(
                "original preserving preparation cannot be dispatched again",
            ));
        }
        let scenario =
            NodeScenario::from_json(self.request.scenario.as_slice()).map_err(refused)?;
        let execution =
            super::super::conditional_preparation::execution_id(&self.request.execution)?;
        match &self.request.action {
            NodePreservingDebugAction::Capture {} => {
                self.capabilities = super::capabilities::resolve(catalog, &self.request, None)?;
                if self.capabilities.is_none()
                    && catalog
                        .scenario(&self.request.selections)
                        .map_err(refused)?
                        .canonical_bytes()
                        .map_err(refused)?
                        != self.request.scenario.as_slice()
                {
                    return Err(refused(
                        "preserving source scenario differs from current installation",
                    ));
                }
                let prepared = match &self.capabilities {
                    Some(resolved) => catalog.prepare_capability_world(resolved, execution),
                    None => catalog.prepare_world(&self.request.selections, scenario, execution),
                }
                .map_err(refused)?;
                self.graph = Some(Rc::new(prepared.graph));
                let graph = self
                    .graph
                    .as_ref()
                    .ok_or_else(|| refused("original graph absent"))?;
                self.runtime = Some(
                    prepared
                        .realization
                        .admit(graph)
                        .map_err(|failure| refused(&failure.error))?,
                );
                let runtime = self
                    .runtime
                    .as_mut()
                    .ok_or_else(|| refused("original runtime absent"))?;
                runtime.arm_all().map_err(refused)?;
                self.activation = Some(
                    runtime
                        .activate(&mut activation_publisher(storage, &self.request.execution)?)
                        .map_err(refused)?,
                );
                let activation = self
                    .activation
                    .as_ref()
                    .ok_or_else(|| refused("original activation absent"))?;
                let barrier = self
                    .driver
                    .stop_at_first_hit(
                        runtime,
                        graph,
                        activation,
                        &self.request.observer,
                        self.request.maximum_physical_cut,
                    )
                    .map_err(refused)?;
                self.token = Some(retain_begin(
                    runtime.begin_condition_stop(barrier).map_err(refused)?,
                )?);
                self.phase = Phase::Stop;
                Ok(())
            }
            NodePreservingDebugAction::Restore { capture, .. } => {
                // Reauthenticate the common source relation before archive load
                // or fresh graph/native allocation; the reservation is no permit.
                let link = storage
                    .preserving_debug
                    .source_capture(&self.request)?
                    .ok_or_else(|| refused("original source relation absent"))?;
                let record = self.archive.load(capture).map_err(refused)?;
                if record.artifact() != &link.artifact || record.manifest().cut != link.cut {
                    return Err(refused(
                        "signed capture differs from its original operator record",
                    ));
                }
                self.capabilities =
                    super::capabilities::resolve(catalog, &self.request, Some(&record))?;
                let factory = super::capabilities::factory(
                    catalog,
                    &self.request,
                    self.capabilities.as_ref(),
                    Some(&record),
                )?;
                self.original_record = Some(record.clone());
                let (graph, target) = match &self.capabilities {
                    Some(resolved) => {
                        catalog.prepare_capability_condition_restore(resolved, execution, &record)
                    }
                    None => catalog.prepare_host_restore_graph(
                        &self.request.selections,
                        &scenario,
                        &record,
                        execution,
                    ),
                }
                .map_err(refused)?;
                self.graph = Some(Rc::new(graph));
                let graph = self
                    .graph
                    .as_ref()
                    .ok_or_else(|| refused("fresh graph absent"))?;
                let verified = record
                    .admit(
                        graph,
                        requirements()?,
                        factory.as_ref(),
                        limits(&self.request)?,
                    )
                    .map_err(refused)?;
                let mut driver = HostWorldRestoreDriver::new(
                    graph.clone(),
                    record,
                    factory,
                    catalog.custody().clone(),
                )
                .map_err(refused)?;
                let prepared =
                    stage_restore(graph, verified, target, &mut driver, limits(&self.request)?)
                        .map_err(|failure| refused(&failure.error))?;
                match prepared.publish(&mut activation_publisher(storage, &self.request.execution)?)
                {
                    RestorePublication::Committed(restored) => {
                        self.activation = Some(restored.activation().clone());
                        self.restored = Some(restored);
                    }
                    RestorePublication::Failed(failure) => return Err(refused(&failure.error)),
                    RestorePublication::Uncertain(pending) => {
                        // This original pending generation transfers into its
                        // existing complete native custody queue, never retries.
                        drop(pending);
                        return Err(refused(
                            "original fresh publication is uncertain; custody retained",
                        ));
                    }
                }
                let runtime = runtime_mut(&mut self.runtime, &mut self.restored)?;
                authenticate_stop(runtime, &link)?;
                self.capture = Some(link);
                self.phase = Phase::Held;
                self.outcome = Some(NodePreservingDebugState::Stopped {});
                Ok(())
            }
        }
    }

    fn finish_stop(
        &mut self,
        catalog: &InstalledNodeCatalog,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        let runtime = runtime_mut(&mut self.runtime, &mut self.restored)?;
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| refused("original Stop token absent"))?;
        let mut context = Context::from_waker(Waker::noop());
        match runtime.poll(token, &mut context) {
            Poll::Pending => return Ok(()),
            Poll::Ready(Err(error)) => return Err(refused(error)),
            Poll::Ready(Ok(_)) => {}
        }
        let mut publisher = result_publisher(storage, &self.request.execution)?;
        let (status, permit) = runtime
            .publish_condition_result(token, &mut publisher, 32 << 20)
            .map_err(refused)?;
        if status != PublicationStatus::Committed {
            return Ok(());
        }
        runtime
            .acknowledge_condition_result(
                token,
                &permit.ok_or_else(|| refused("original Stop has no actual commit"))?,
            )
            .map_err(refused)?;
        let saved = runtime
            .condition_stop_checkpoint()
            .ok_or_else(|| refused("original Stop history absent"))?;
        let report = saved
            .report
            .as_ref()
            .ok_or_else(|| refused("original report absent"))?
            .reference
            .clone();
        let cut = saved.record.cut;
        let barrier = saved.reference.clone();
        require_source_activation(&saved.record.source.activation_id, &self.request.execution)?;
        let factory =
            super::capabilities::factory(catalog, &self.request, self.capabilities.as_ref(), None)?;
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("original graph absent"))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("original activation absent"))?;
        let record = self
            .archive
            .capture_condition_world(
                graph,
                runtime,
                activation,
                cut,
                U64::new(1),
                Id::new(format!(
                    "debug-preserving/{}/capture",
                    self.request.execution
                ))
                .map_err(refused)?,
                requirements()?,
                factory.as_ref(),
                factory.as_ref(),
            )
            .map_err(refused)?;
        self.capture = Some(NodePreservingDebugCapture {
            source_execution: self.request.execution.clone(),
            source_request: self.reservation.record.request.clone(),
            artifact: record.artifact().clone(),
            cut,
            barrier,
            report,
        });
        self.original_record = Some(record);
        self.phase = Phase::Held;
        self.outcome = Some(NodePreservingDebugState::Stopped {});
        Ok(())
    }

    /// Commits the immutable original Resume reservation before any callback.
    pub(super) fn resume(
        &mut self,
        request: NodePreservingDebugResumeRequest,
        reservation: Reservation,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        self.adopt_resume(request, reservation)?;
        let capture = self
            .capture
            .as_ref()
            .ok_or_else(|| refused("original capture relation absent"))?;
        if matches!(
            self.request.action,
            NodePreservingDebugAction::Restore { .. }
        ) && storage
            .preserving_debug
            .source_capture(&self.request)?
            .as_ref()
            != Some(capture)
        {
            return Err(refused(
                "original source capture relation changed before Resume",
            ));
        }
        let runtime = runtime_mut(&mut self.runtime, &mut self.restored)?;
        authenticate_stop(runtime, capture)?;
        let original = runtime
            .condition_stop_checkpoint()
            .ok_or_else(|| refused("Stop absent"))?
            .record
            .operation
            .clone();
        let stop = runtime.recover(&original).map_err(refused)?;
        let mut publisher = result_publisher(storage, &capture.source_execution)?;
        let (status, permit) = runtime
            .publish_condition_result(&stop, &mut publisher, 32 << 20)
            .map_err(refused)?;
        if status != PublicationStatus::Committed || permit.is_none() {
            return Err(refused(
                "original current durable Stop roots are unavailable before Resume",
            ));
        }
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("current activation absent"))?;
        let operation = Id::new(format!(
            "debug-preserving/{}/resume",
            self.request.execution
        ))
        .map_err(refused)?;
        self.token = Some(retain_begin(
            runtime
                .begin_condition_resume(activation, operation)
                .map_err(refused)?,
        )?);
        self.phase = Phase::Resume;
        Ok(())
    }

    fn finish_resume(&mut self) -> Result<(), NodeObservationServiceError> {
        let runtime = runtime_mut(&mut self.runtime, &mut self.restored)?;
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| refused("original Resume token absent"))?;
        let mut context = Context::from_waker(Waker::noop());
        match runtime.poll(token, &mut context) {
            Poll::Pending => Ok(()),
            Poll::Ready(Err(error)) => Err(refused(error)),
            Poll::Ready(Ok(_)) => {
                self.phase = Phase::PublishSuffix;
                Ok(())
            }
        }
    }

    fn publish_suffix(
        &mut self,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        let runtime = runtime_mut(&mut self.runtime, &mut self.restored)?;
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| refused("original Resume token absent"))?;
        let mut publisher = result_publisher(storage, &self.request.execution)?;
        let (status, permit) = runtime
            .publish_condition_result(token, &mut publisher, 32 << 20)
            .map_err(refused)?;
        if status != PublicationStatus::Committed {
            return Ok(());
        }
        runtime
            .acknowledge_condition_result(
                token,
                &permit.ok_or_else(|| refused("original Resume commit absent"))?,
            )
            .map_err(refused)?;
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("current graph absent"))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("current activation absent"))?;
        if matches!(
            self.request.action,
            NodePreservingDebugAction::Restore { .. }
        ) {
            self.driver = ConditionExecution::for_restored_resume(runtime, graph, activation, 8192)
                .map_err(refused)?;
        }
        let horizon = self
            .resume
            .as_ref()
            .ok_or_else(|| refused("original Resume request absent"))?
            .horizon_ps;
        // Set before the first suffix effect, including a partial execution
        // error or unwind. Unknown metadata cannot replace the owning ledger.
        self.suffix_unsealed = true;
        self.driver
            .continue_original_after_resume(
                runtime,
                graph,
                activation,
                &self.request.observer,
                horizon,
            )
            .map_err(refused)?;
        let receipt = runtime
            .condition_stop_checkpoint()
            .and_then(|saved| saved.resume_receipt.as_ref())
            .ok_or_else(|| refused("actual Resume receipt absent"))?
            .reference
            .clone();
        // Seal actual native completion before any storage callback. A durable
        // retry must not execute the suffix or Resume a second time.
        self.completed_receipt = Some(receipt);
        self.phase = Phase::StoreSuffix;
        Ok(())
    }

    fn adopt_resume(
        &mut self,
        request: NodePreservingDebugResumeRequest,
        reservation: Reservation,
    ) -> Result<(), NodeObservationServiceError> {
        let eligible = matches!(self.phase, Phase::Held) && self.resume.is_none() && self.published;

        // A durable Stop CAS may precede local completion reconciliation. The
        // incoming original Resume must remain owned even when that local
        // fence refuses dispatch; its Unknown record replaces AwaitingResume.
        self.resume = Some(request);
        self.reservation = reservation;
        self.outcome = None;
        self.published = false;
        if !eligible {
            return Err(refused(
                "Resume requires the unchanged current stopped owner",
            ));
        }
        Ok(())
    }

    fn store_suffix(&mut self, storage: &ActorStorage) -> Result<(), NodeObservationServiceError> {
        let receipt = self
            .completed_receipt
            .as_ref()
            .ok_or_else(|| refused("original suffix completion absent"))?
            .clone();
        if self.completed_ledger.is_none() {
            let horizon = self
                .resume
                .as_ref()
                .ok_or_else(|| refused("original horizon absent"))?
                .horizon_ps;
            let snapshot = runtime_mut(&mut self.runtime, &mut self.restored)?
                .condition_runtime_snapshot(
                    crucible_node_contract::Position::new(
                        horizon,
                        0.into(),
                        crucible_node_contract::Phase::BoundaryControl,
                    ),
                    1.into(),
                    usize::try_from(self.request.maximum_record_bytes.get()).map_err(refused)?,
                )
                .map_err(refused)?;
            self.completed_ledger = Some(snapshot);
        }
        let ledger = self
            .completed_ledger
            .as_ref()
            .ok_or_else(|| refused("original suffix ledger absent"))?;
        if self.sealed_suffix.is_none() {
            self.sealed_suffix = Some(storage.preserving_debug.seal_outputs(
                &self.request.execution,
                self.driver.publications(),
                ledger,
                usize::try_from(self.request.maximum_record_bytes.get()).map_err(refused)?,
            )?);
        }
        let original = self
            .sealed_suffix
            .as_ref()
            .ok_or_else(|| refused("original sealed suffix absent"))?;
        self.completed = Some(NodePreservingDebugState::Resumed {
            receipt,
            publications: storage.preserving_debug.place_outputs(original)?,
        });
        self.suffix_unsealed = false;
        self.runtime.take();
        self.restored.take();
        self.phase = Phase::Reclaim;
        Ok(())
    }

    fn reconcile_suffix(
        &mut self,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        let original = self
            .sealed_suffix
            .as_ref()
            .ok_or_else(|| refused("original sealed suffix absent"))?;
        storage.preserving_debug.place_outputs(original)?;

        // The original Unknown verdict remains unchanged. Only the exact data
        // placement is reconciled; neither Resume nor suffix execution recurs.
        self.suffix_unsealed = false;
        self.runtime.take();
        self.restored.take();
        self.phase = Phase::Reclaim;
        Ok(())
    }

    pub(super) fn capture(&self) -> Option<NodePreservingDebugCapture> {
        self.capture.clone()
    }

    pub(super) fn released(&self) -> bool {
        matches!(self.phase, Phase::Released)
    }

    pub(super) fn fail(&mut self, error: impl std::fmt::Display) {
        if self.outcome.is_none() {
            self.outcome = Some(NodePreservingDebugState::Unknown {
                reason: error.to_string().chars().take(2048).collect(),
            });
        }
        // Only immutable data placement may retry. Missing/failed sealing
        // keeps the whole original capsule Held, including on shutdown.
        self.phase = if self.suffix_unsealed && self.sealed_suffix.is_some() {
            Phase::ReconcileSuffix
        } else {
            Phase::Held
        };
    }

    pub(super) fn contain(&mut self) {
        if self.released() || self.suffix_unsealed {
            // A storage failure must keep the exact original native runtime,
            // publications and operation/input/ACK bodies in this finite owner.
            // No shutdown or cached retry may replace them with Unknown alone.
            return;
        }
        self.runtime.take();
        self.restored.take();
        self.phase = Phase::Reclaim;
    }
}

fn runtime_mut<'a>(
    initial: &'a mut Option<NodeRuntime>,
    restored: &'a mut Option<Box<RestoredWorld>>,
) -> Result<&'a mut NodeRuntime, NodeObservationServiceError> {
    match restored {
        Some(world) => Ok(world.runtime_mut()),
        None => initial
            .as_mut()
            .ok_or_else(|| refused("original native runtime absent")),
    }
}

fn require_source_activation(
    activation: &Id,
    execution: &str,
) -> Result<(), NodeObservationServiceError> {
    if activation.as_str() != format!("activation/{execution}") {
        return Err(refused("Stop is outside its original operator activation"));
    }
    Ok(())
}

fn authenticate_stop(
    runtime: &NodeRuntime,
    capture: &NodePreservingDebugCapture,
) -> Result<(), NodeObservationServiceError> {
    let saved = runtime
        .condition_stop_checkpoint()
        .ok_or_else(|| refused("native stopped history absent"))?;
    require_source_activation(
        &saved.record.source.activation_id,
        &capture.source_execution,
    )?;
    if !saved.acknowledged
        || saved.resumed
        || saved.reference != capture.barrier
        || saved.record.cut != capture.cut
        || saved.report.as_ref().map(|report| &report.reference) != Some(&capture.report)
    {
        return Err(refused(
            "actual native Stop differs from original source capture",
        ));
    }
    Ok(())
}

fn activation_publisher(
    storage: &ActorStorage,
    execution: &str,
) -> Result<StoredWorldActivationPublisher, NodeObservationServiceError> {
    StoredWorldActivationPublisher::new(
        storage.blobs.clone(),
        storage.refs.clone(),
        RefName::new(format!(
            "node-world-activations/debug-preserving-{execution}"
        ))
        .map_err(refused)?,
    )
    .map_err(refused)
}

fn result_publisher(
    storage: &ActorStorage,
    execution: &str,
) -> Result<StoredConditionResultPublisher, NodeObservationServiceError> {
    super::super::conditional_preparation::validate_execution(execution)?;
    StoredConditionResultPublisher::new(
        storage.blobs.clone(),
        storage.refs.clone(),
        RefName::new(format!(
            "node-world-coordinators/condition/debug-preserving-{execution}"
        ))
        .map_err(refused)?,
        32 << 20,
    )
    .map_err(refused)
}

fn retain_begin(result: BeginResult) -> Result<OperationToken, NodeObservationServiceError> {
    match result {
        BeginResult::Accepted(token) | BeginResult::Uncertain { token, .. } => Ok(token),
        BeginResult::Refused(error) => Err(refused(error.reason)),
    }
}

fn requirements() -> Result<StateRequirements, NodeObservationServiceError> {
    Ok(StateRequirements {
        preservation_contract: Id::new("host/preservation-v1").map_err(refused)?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn limits(
    request: &NodePreservingDebugRequest,
) -> Result<StateLimits, NodeObservationServiceError> {
    let maximum_record_bytes =
        usize::try_from(request.maximum_record_bytes.get()).map_err(refused)?;
    Ok(StateLimits {
        maximum_record_bytes,
        maximum_content_bytes: 512 << 20,
        maximum_total_content_bytes: 1024 << 20,
        ..StateLimits::default()
    })
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
