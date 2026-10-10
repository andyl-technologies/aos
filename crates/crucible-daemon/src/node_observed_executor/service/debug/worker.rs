//! Retains one complete original live Debug world outside actor unwind scopes.

use super::super::ActorStorage;
use super::{
    DebugReservation, NodeDebugResumeRequest, NodeDebugStartRequest, NodeDebugState,
    NodeObservationServiceError, refused,
};
use crate::node_observed_executor::{
    ConditionExecution, InstalledNodeCatalog, StoredConditionResultPublisher,
    StoredWorldActivationPublisher,
};
use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationToken, PublicationStatus, WorldActivation},
};
use crucible_cas::content_store::RefName;
use std::task::{Context, Poll, Waker};

pub(in crate::node_observed_executor::service) struct DebugWorker {
    pub(in crate::node_observed_executor::service) reservation: DebugReservation,
    pub(in crate::node_observed_executor::service) outcome: Option<NodeDebugState>,
    pub(in crate::node_observed_executor::service) published: bool,
    start: NodeDebugStartRequest,
    graph: Option<AdmittedGraph>,
    runtime: Option<NodeRuntime>,
    activation: Option<WorldActivation>,
    driver: ConditionExecution,
    original_control: Option<OperationToken>,
    resume: Option<NodeDebugResumeRequest>,
    completed_resume: Option<crucible_node_contract::ContentRef>,
}

impl DebugWorker {
    pub(in crate::node_observed_executor::service) fn new(
        start: NodeDebugStartRequest,
        reservation: DebugReservation,
    ) -> Result<Self, NodeObservationServiceError> {
        Ok(Self {
            reservation,
            outcome: None,
            published: false,
            start,
            graph: None,
            runtime: None,
            activation: None,
            driver: ConditionExecution::new(8192).map_err(refused)?,
            original_control: None,
            resume: None,
            completed_resume: None,
        })
    }

    /// Called only after this complete owner is inserted in the actor map.
    pub(in crate::node_observed_executor::service) fn start(
        &mut self,
        catalog: &mut InstalledNodeCatalog,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        if self.graph.is_some() || self.runtime.is_some() || self.original_control.is_some() {
            return Err(refused(
                "original Debug preparation cannot be dispatched again",
            ));
        }
        let scenario = catalog.scenario(&self.start.selections).map_err(refused)?;
        let execution = super::super::conditional_preparation::execution_id(&self.start.execution)?;
        let prepared = catalog
            .prepare_world(&self.start.selections, scenario, execution)
            .map_err(refused)?;
        self.graph = Some(prepared.graph);
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("Debug graph custody absent"))?;
        // Admission's owned failure transfers the same native realization to
        // the catalog's pre-reserved queue. It cannot authorize a replacement.
        self.runtime = Some(
            prepared
                .realization
                .admit(graph)
                .map_err(|failure| refused(&failure.error))?,
        );
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Debug runtime custody absent"))?;
        runtime.arm_all().map_err(refused)?;
        let reference = RefName::new(format!(
            "node-world-activations/debug-{}",
            self.start.execution
        ))
        .map_err(refused)?;
        let mut publisher = StoredWorldActivationPublisher::new(
            storage.blobs.clone(),
            storage.refs.clone(),
            reference,
        )
        .map_err(refused)?;
        self.activation = Some(runtime.activate(&mut publisher).map_err(refused)?);
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("Debug activation absent"))?;
        let barrier = self
            .driver
            .stop_at_first_hit(
                runtime,
                graph,
                activation,
                &self.start.observer,
                self.start.maximum_physical_cut,
            )
            .map_err(refused)?;
        self.original_control = Some(retain_begin(
            runtime.begin_condition_stop(barrier).map_err(refused)?,
        )?);
        Ok(())
    }

    pub(in crate::node_observed_executor::service) fn resume(
        &mut self,
        request: NodeDebugResumeRequest,
        reservation: DebugReservation,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        if self.resume.is_some() || !matches!(self.outcome, Some(NodeDebugState::Stopped { .. })) {
            return Err(refused(
                "Debug resume requires unchanged current-actor stop custody",
            ));
        }
        // Preserve the original request/reservation before Begin. A callback
        // unwind leaves this exact operation committed to this owning world.
        self.resume = Some(request);
        self.reservation = reservation;
        self.outcome = None;
        self.published = false;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Debug runtime absent"))?;
        let stop = self
            .original_control
            .as_ref()
            .ok_or_else(|| refused("Debug original stop operation absent"))?;
        let reference = RefName::new(format!(
            "node-world-coordinators/condition/debug-{}",
            self.start.execution
        ))
        .map_err(refused)?;
        let mut publisher = StoredConditionResultPublisher::new(
            storage.blobs.clone(),
            storage.refs.clone(),
            reference,
            32 << 20,
        )
        .map_err(refused)?;
        let (status, permit) = runtime
            .publish_condition_result(stop, &mut publisher, 32 << 20)
            .map_err(refused)?;
        if status != PublicationStatus::Committed || permit.is_none() {
            return Err(refused(
                "Debug original durable report is unavailable before resume",
            ));
        }
        self.original_control = None;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("Debug activation absent"))?;
        let request = self
            .resume
            .as_ref()
            .ok_or_else(|| refused("Debug original resume absent"))?;
        self.original_control = Some(retain_begin(
            runtime
                .begin_condition_resume(activation, request.operation.clone())
                .map_err(refused)?,
        )?);
        Ok(())
    }

    pub(in crate::node_observed_executor::service) fn poll(
        &mut self,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        if self.outcome.is_some() {
            return Ok(());
        }
        if self.completed_resume.is_some() {
            return self.publish_completed_suffix(storage);
        }
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Debug original runtime absent"))?;
        let original = self
            .original_control
            .as_ref()
            .ok_or_else(|| refused("Debug original control absent"))?;
        let mut context = Context::from_waker(Waker::noop());
        match runtime.poll(original, &mut context) {
            Poll::Pending => return Ok(()),
            Poll::Ready(Err(error)) => return Err(refused(error)),
            Poll::Ready(Ok(_)) => {}
        }
        let reference = RefName::new(format!(
            "node-world-coordinators/condition/debug-{}",
            self.start.execution
        ))
        .map_err(refused)?;
        let mut publisher = StoredConditionResultPublisher::new(
            storage.blobs.clone(),
            storage.refs.clone(),
            reference,
            32 << 20,
        )
        .map_err(refused)?;
        let (status, permit) = runtime
            .publish_condition_result(original, &mut publisher, 32 << 20)
            .map_err(refused)?;
        if status != PublicationStatus::Committed {
            return Ok(());
        }
        let permit =
            permit.ok_or_else(|| refused("Debug durable result has no actual commit authority"))?;
        runtime
            .acknowledge_condition_result(original, &permit)
            .map_err(refused)?;

        if let Some(request) = &self.resume {
            let graph = self
                .graph
                .as_ref()
                .ok_or_else(|| refused("Debug graph absent"))?;
            let activation = self
                .activation
                .as_ref()
                .ok_or_else(|| refused("Debug activation absent"))?;
            self.driver
                .continue_original_after_resume(
                    runtime,
                    graph,
                    activation,
                    &self.start.observer,
                    request.horizon_ps,
                )
                .map_err(refused)?;
            let receipt = runtime
                .condition_stop_checkpoint()
                .and_then(|saved| saved.resume_receipt.as_ref())
                .ok_or_else(|| refused("Debug original resume receipt absent"))?
                .reference
                .clone();
            // Retain completion before invoking another backend callback. A
            // retry republishes these exact bytes, never drives the suffix again.
            self.completed_resume = Some(receipt);
            self.publish_completed_suffix(storage)?;
        } else {
            let saved = runtime
                .condition_stop_checkpoint()
                .ok_or_else(|| refused("Debug original stop absent"))?;
            let report = saved
                .report
                .as_ref()
                .ok_or_else(|| refused("Debug original report absent"))?
                .reference
                .clone();
            self.outcome = Some(NodeDebugState::Stopped {
                cut: saved.record.cut,
                barrier: saved.reference.clone(),
                report,
            });
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::service) fn publication_pending(&self) -> bool {
        self.completed_resume.is_some() && self.outcome.is_none()
    }

    pub(in crate::node_observed_executor::service) fn publish_completed_suffix(
        &mut self,
        storage: &ActorStorage,
    ) -> Result<(), NodeObservationServiceError> {
        let receipt = self
            .completed_resume
            .as_ref()
            .ok_or_else(|| refused("Debug original suffix completion absent"))?;
        let publications = storage
            .debug
            .publish_outputs(&self.start.execution, self.driver.publications())?;
        self.outcome = Some(NodeDebugState::Resumed {
            receipt: receipt.clone(),
            publications,
        });
        Ok(())
    }

    pub(in crate::node_observed_executor::service) fn fail(
        &mut self,
        reason: impl std::fmt::Display,
    ) {
        if self.outcome.is_none() {
            self.outcome = Some(NodeDebugState::Unknown {
                reason: reason.to_string().chars().take(2048).collect(),
            });
        }
    }

    pub(in crate::node_observed_executor::service) fn contain(&mut self) {
        // Runtime Drop transfers the complete original capsule to its existing
        // reserved native queue. The owner still retains unpublished outcomes.
        self.runtime.take();
        if self.outcome.is_none() && self.completed_resume.is_none() {
            self.fail("owning Debug actor stopped with original custody retained");
        }
    }
}

fn retain_begin(result: BeginResult) -> Result<OperationToken, NodeObservationServiceError> {
    match result {
        BeginResult::Accepted(token) | BeginResult::Uncertain { token, .. } => Ok(token),
        BeginResult::Refused(error) => Err(refused(error.reason)),
    }
}
