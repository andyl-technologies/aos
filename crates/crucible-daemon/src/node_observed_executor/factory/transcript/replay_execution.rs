//! Metadata-driven original semantic admissions through the common runtime.
//!
//! Recorded request metadata selects IDs and scopes only. Every run and frozen
//! input transfer still obtains opaque coordinator authority, and the owning
//! replay node independently compares the complete original request bytes.

use crucible::{
    node_adapters::transcript::{ReplayRequestMetadata, TranscriptAction},
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationRequest, Submission, WorldActivation,
    },
    node_scheduling::SchedulingError,
};
use std::task::{Context, Poll, Waker};

use super::*;

pub(super) struct OriginalPlan {
    requests: BTreeMap<Id, Vec<ReplayRequestMetadata>>,
    offsets: BTreeMap<Id, usize>,
}

impl OriginalPlan {
    pub(super) fn new(
        source: &source_enrollment::VerifiedRecordedWorld,
    ) -> Result<Self, NodeObservedError> {
        let requests = source
            .sources
            .iter()
            .map(|(node, source)| {
                let metadata = source
                    .transcript()
                    .records
                    .iter()
                    .map(|record| record.request.request_metadata().map_err(native))
                    .collect::<Result<Vec<_>, NodeObservedError>>()?;
                Ok((node.clone(), metadata))
            })
            .collect::<Result<BTreeMap<_, _>, NodeObservedError>>()?;
        let offsets = requests.keys().map(|node| (node.clone(), 0)).collect();
        Ok(Self { requests, offsets })
    }

    pub(super) fn execute_to_retained_cut(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
    ) -> Result<Vec<OperationOutcome>, NodeObservedError> {
        self.drive(runtime, graph, activation, true)
    }

    pub(super) fn execute(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
    ) -> Result<Vec<OperationOutcome>, NodeObservedError> {
        self.drive(runtime, graph, activation, false)
    }

    fn drive(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        retain_cut: bool,
    ) -> Result<Vec<OperationOutcome>, NodeObservedError> {
        let mut outcomes = Vec::new();
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..2048 {
            let mut progress = false;
            for (node, requests) in &self.requests {
                let offset = *self
                    .offsets
                    .get(node)
                    .ok_or_else(|| refused("original replay plan node absent"))?;
                let Some(request) = requests.get(offset) else {
                    continue;
                };
                if matches!(
                    request.action,
                    TranscriptAction::StageInput | TranscriptAction::Begin
                ) && runtime
                    .scheduler(graph, activation)
                    .map_err(native)?
                    .output_backpressure(node)
                    .map_err(native)?
                {
                    continue;
                }
                match request.action {
                    TranscriptAction::Observe => {
                        let observation = runtime
                            .observe_scheduling(activation, node)
                            .map_err(native)?;
                        runtime
                            .scheduler(graph, activation)
                            .map_err(native)?
                            .accept_boundary_observation(observation)
                            .map_err(native)?;
                    }
                    TranscriptAction::StageInput => {
                        let cut = request
                            .input_cut
                            .ok_or_else(|| refused("original input cut absent"))?;
                        let batch = runtime
                            .scheduler(graph, activation)
                            .map_err(native)?
                            .prepare_input_batch(
                                node,
                                request
                                    .input_stage
                                    .clone()
                                    .ok_or_else(|| refused("original stage ID absent"))?,
                                request
                                    .input_batch
                                    .clone()
                                    .ok_or_else(|| refused("original batch ID absent"))?,
                                cut,
                            );
                        let batch = match batch {
                            Ok(batch) => batch,
                            Err(error) if blocked(&error) => continue,
                            Err(error) => return Err(native(error)),
                        };
                        let acknowledged = runtime.stage_inputs(batch).map_err(native)?;
                        let commit = runtime
                            .commit_input_acknowledgement(acknowledged)
                            .map_err(native)?;
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
                                "original replay operation is outside selected quantized profile",
                            ));
                        };
                        let grant = runtime
                            .scheduler(graph, activation)
                            .map_err(native)?
                            .admit_quantum(
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
                        match runtime.begin_admitted(grant).map_err(native)? {
                            BeginResult::Accepted(_) => {}
                            other => {
                                return Err(refused(&format!(
                                    "original replay submission differs: {other:?}"
                                )));
                            }
                        }
                    }
                    TranscriptAction::CloseWindow => {
                        let token = runtime.recover(&request.identity).map_err(native)?;
                        if runtime.close_quantum(&token).map_err(native)? != Submission::Accepted {
                            return Err(refused("original replay close submission differs"));
                        }
                    }
                    TranscriptAction::Complete => {
                        let token = runtime.recover(&request.identity).map_err(native)?;
                        let outcome = match runtime.poll(&token, &mut context) {
                            Poll::Pending => continue,
                            Poll::Ready(result) => result.map_err(native)?,
                        };
                        let receipt = runtime.scheduling_receipt(&token).map_err(native)?;
                        runtime.commit_scheduling_receipt(receipt).map_err(native)?;
                        outcomes.push(outcome);
                    }
                    TranscriptAction::Acknowledge => {
                        let token = runtime.recover(&request.identity).map_err(native)?;
                        let commit = runtime.recover_scheduling_commit(&token).map_err(native)?;
                        runtime
                            .acknowledge_scheduled(&token, &commit)
                            .map_err(native)?;
                    }
                    TranscriptAction::Cancel => {
                        return Err(refused(
                            "installed normal reference replay does not admit cancellation",
                        ));
                    }
                }
                *self
                    .offsets
                    .get_mut(node)
                    .ok_or_else(|| refused("original replay plan node absent"))? += 1;
                progress = true;
                if retain_cut && request.action == TranscriptAction::Complete {
                    let saved = runtime
                        .runtime_snapshot(
                            activation.record().boundary,
                            U64::new(1),
                            16 * 1024 * 1024,
                        )
                        .map_err(native)?;
                    let has_consumed_input = saved.operations.iter().any(|operation| operation.input_batch.is_some() && matches!(&operation.result, crucible::node_contract::SavedRuntimeResult::Complete(outcome) if !outcome.retained_outputs.is_empty()));
                    let has_nonempty_frozen_input = saved.inputs.iter().any(|input| {
                        !input.deliveries.is_empty() && input.acknowledgement.is_some()
                    });
                    if has_consumed_input && has_nonempty_frozen_input {
                        return Ok(outcomes);
                    }
                }
            }
            if self
                .requests
                .iter()
                .all(|(node, requests)| self.offsets.get(node) == Some(&requests.len()))
            {
                return Ok(outcomes);
            }
            if !progress {
                return Err(refused(
                    "original replay partial order has no admitted progress",
                ));
            }
        }
        Err(refused(
            "original replay exceeds finite control-turn budget",
        ))
    }
}

impl OriginalPlan {
    pub(super) fn restore_offsets(
        &mut self,
        cursors: &BTreeMap<Id, crucible::node_adapters::transcript::ReplayCursorSnapshot>,
    ) -> Result<(), NodeObservedError> {
        if cursors.len() != self.offsets.len() {
            return Err(refused("authenticated replay cursor roster differs"));
        }
        let mut offsets = BTreeMap::new();
        for (node, requests) in &self.requests {
            let cursor = cursors
                .get(node)
                .ok_or_else(|| refused("authenticated replay cursor absent"))?;
            let next = usize::try_from(cursor.next_record.get()).map_err(native)?;
            if cursor.diverged || next > requests.len() {
                return Err(refused(
                    "authenticated replay cursor is divergent or exceeds source",
                ));
            }
            offsets.insert(node.clone(), next);
        }
        self.offsets = offsets;
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
