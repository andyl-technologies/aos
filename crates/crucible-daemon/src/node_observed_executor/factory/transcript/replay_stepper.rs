//! Bounded original-request dispatch for an installed conditional replay actor.
//!
//! Metadata supplies names, never permissions. Every input and execution step
//! obtains fresh common-runtime authority. A completed outcome is returned to
//! the owning backend before its scheduler publication or native ACK.

use crucible::{
    node_adapters::transcript::{ReplayRequestMetadata, TranscriptAction},
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationRequest, Submission, WorldActivation,
    },
    node_scheduling::SchedulingError,
};
use std::task::{Context, Poll};

use super::*;

pub(crate) enum ReplayStep {
    Waiting,
    Progress {
        incoming: Option<serde_json::Value>,
    },
    Complete {
        node: Id,
        outcome: Box<OperationOutcome>,
    },
    Finished,
}

pub(crate) struct ReplayStepper {
    requests: BTreeMap<Id, Vec<ReplayRequestMetadata>>,
    close_results: BTreeMap<(Id, usize), Submission>,
    offsets: BTreeMap<Id, usize>,
    pending_complete: Option<Id>,
}

impl ReplayStepper {
    pub(super) fn new(
        source: &source_enrollment::VerifiedRecordedWorld,
    ) -> Result<Self, NodeObservedError> {
        let mut requests = BTreeMap::new();
        let mut close_results = BTreeMap::new();
        for (node, source) in &source.sources {
            let mut metadata = Vec::new();
            metadata
                .try_reserve_exact(source.transcript().records.len())
                .map_err(native)?;
            for (index, record) in source.transcript().records.iter().enumerate() {
                let request = record.request.request_metadata().map_err(native)?;
                if request.action == TranscriptAction::CloseWindow {
                    let response: serde_json::Value =
                        serde_json::from_slice(&record.response_bytes)?;
                    let expected = serde_json::from_value(response["value"].clone())?;
                    close_results.insert((node.clone(), index), expected);
                }
                metadata.push(request);
            }
            requests.insert(node.clone(), metadata);
        }
        let offsets = requests.keys().map(|node| (node.clone(), 0)).collect();
        Ok(Self {
            requests,
            close_results,
            offsets,
            pending_complete: None,
        })
    }

    pub(crate) fn poll(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        context: &mut Context<'_>,
    ) -> Result<ReplayStep, NodeObservedError> {
        if self.pending_complete.is_some() {
            return Err(refused(
                "original replay completion has not been durably committed",
            ));
        }
        let mut remaining = false;
        for (node, requests) in &self.requests {
            let offset = *self
                .offsets
                .get(node)
                .ok_or_else(|| refused("original replay cursor absent"))?;
            let Some(request) = requests.get(offset) else {
                continue;
            };
            remaining = true;
            if matches!(
                request.action,
                TranscriptAction::StageInput | TranscriptAction::Begin
            ) && runtime
                .scheduler(graph, activation)?
                .output_backpressure(node)
                .map_err(native)?
            {
                continue;
            }
            let mut incoming = None;
            match request.action {
                TranscriptAction::Observe => {
                    let observed = runtime
                        .observe_scheduling(activation, node)
                        .map_err(native)?;
                    runtime
                        .scheduler(graph, activation)?
                        .accept_boundary_observation(observed)
                        .map_err(native)?;
                }
                TranscriptAction::StageInput => {
                    let batch = runtime.scheduler(graph, activation)?.prepare_input_batch(
                        node,
                        request
                            .input_stage
                            .clone()
                            .ok_or_else(|| refused("original stage identity absent"))?,
                        request
                            .input_batch
                            .clone()
                            .ok_or_else(|| refused("original batch identity absent"))?,
                        request
                            .input_cut
                            .ok_or_else(|| refused("original input cut absent"))?,
                    );
                    let batch = match batch {
                        Ok(batch) => batch,
                        Err(error) if blocked(&error) => continue,
                        Err(error) => return Err(native(error)),
                    };
                    incoming = Some(serde_json::json!({
                        "node":node,"batch":batch.batch(),"inventory":batch.inventory(),
                        "cutoff":batch.cutoff(),"deliveries":batch.deliveries(),"payloads":batch.payloads()
                    }));
                    let ack = runtime.stage_inputs(batch).map_err(native)?;
                    let commit = runtime.commit_input_acknowledgement(ack).map_err(native)?;
                    runtime.commit_input_staging(&commit).map_err(native)?;
                }
                TranscriptAction::Begin => {
                    let Some(OperationRequest::QuantumBegin {
                        window,
                        input_batch,
                        ..
                    }) = &request.operation
                    else {
                        return Err(refused(
                            "original operation is outside installed quantized replay policy",
                        ));
                    };
                    let grant = runtime.scheduler(graph, activation)?.admit_quantum(
                        node,
                        request.identity.clone(),
                        window.clone(),
                        input_batch.clone(),
                    );
                    let grant = match grant {
                        Ok(grant) => grant,
                        Err(error) if blocked(&error) => continue,
                        Err(error) => return Err(native(error)),
                    };
                    if !matches!(
                        runtime.begin_admitted(grant).map_err(native)?,
                        BeginResult::Accepted(_)
                    ) {
                        return Err(refused("original replay Begin response differs"));
                    }
                }
                TranscriptAction::CloseWindow => {
                    let token = runtime.recover(&request.identity).map_err(native)?;
                    let expected = self
                        .close_results
                        .get(&(node.clone(), offset))
                        .ok_or_else(|| refused("original close response absent"))?;
                    if &runtime.close_quantum(&token).map_err(native)? != expected {
                        return Err(refused("original replay close response differs"));
                    }
                }
                TranscriptAction::Complete => {
                    let token = runtime.recover(&request.identity).map_err(native)?;
                    let outcome = match runtime.poll(&token, context) {
                        Poll::Pending => continue,
                        Poll::Ready(result) => result.map_err(native)?,
                    };
                    self.pending_complete = Some(node.clone());
                    return Ok(ReplayStep::Complete {
                        node: node.clone(),
                        outcome: Box::new(outcome),
                    });
                }
                TranscriptAction::Acknowledge => {
                    let token = runtime.recover(&request.identity).map_err(native)?;
                    let commit = runtime.recover_scheduling_commit(&token).map_err(native)?;
                    runtime
                        .acknowledge_scheduled(&token, &commit)
                        .map_err(native)?;
                }
                TranscriptAction::Cancel => {
                    return Err(refused("installed original replay excludes cancellation"));
                }
            }
            *self
                .offsets
                .get_mut(node)
                .ok_or_else(|| refused("original replay cursor absent"))? += 1;
            return Ok(ReplayStep::Progress { incoming });
        }
        Ok(if remaining {
            ReplayStep::Waiting
        } else {
            ReplayStep::Finished
        })
    }

    pub(crate) fn commit_complete(
        &mut self,
        node: &Id,
        runtime: &mut NodeRuntime,
    ) -> Result<(), NodeObservedError> {
        if self.pending_complete.as_ref() != Some(node) {
            return Err(refused("foreign original replay completion commitment"));
        }
        let offset = *self
            .offsets
            .get(node)
            .ok_or_else(|| refused("original replay cursor absent"))?;
        let original = self
            .requests
            .get(node)
            .and_then(|requests| requests.get(offset))
            .ok_or_else(|| refused("original completion absent"))?;
        let token = runtime.recover(&original.identity).map_err(native)?;
        let receipt = runtime.scheduling_receipt(&token).map_err(native)?;
        runtime.commit_scheduling_receipt(receipt).map_err(native)?;
        *self
            .offsets
            .get_mut(node)
            .ok_or_else(|| refused("original replay cursor absent"))? += 1;
        self.pending_complete = None;
        Ok(())
    }
}

fn blocked(error: &SchedulingError) -> bool {
    matches!(
        error,
        SchedulingError::InputBlocked(_)
            | SchedulingError::NoSafeProgress
            | SchedulingError::OwnerBusy
    )
}
