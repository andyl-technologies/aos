//! Original event-frontier rounds for a selected live condition observer.
//!
//! Every native operation is individually admitted, completed, published and
//! acknowledged. The driver never runs past a known next native reaction to
//! discover a condition retrospectively. A hit stops physical advancement and
//! obtains a separately authenticated common-world fence with future work intact.

use std::task::{Context, Poll, Waker};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{AuthenticatedConditionStop, BeginResult, NodeRuntime, WorldActivation},
    node_scheduling::SchedulingError,
};
use crucible_node_contract::{Id, Phase, Position, U64};

use super::NodeObservedError;
use crate::node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation};

/// Owns bounded original event-frontier dispatch and retained uncertain tokens.
///
/// A caller retains this driver beside its complete native runtime until all
/// original custody is acknowledged or authentically reclaimed. A failed drive
/// cannot issue replacement work through this instance.
pub struct ConditionExecution {
    sequence: u64,
    publications: Vec<crucible::node_scheduling::NativePublication>,
    maximum_publications: usize,
    pending: Option<crucible::node_contract::OperationToken>,
    failed: bool,
}

impl ConditionExecution {
    /// Reserves finite publication retention before any native dispatch.
    ///
    /// # Errors
    /// Refuses a budget below one native batch, above 65,536 publications or
    /// unavailable host allocation. The selected Source and Block adapters
    /// each publish at most sixteen original events in one admitted grant.
    pub fn new(maximum_publications: usize) -> Result<Self, NodeObservedError> {
        if !(16..=65_536).contains(&maximum_publications) {
            return Err(refused("condition publication retention budget refused"));
        }
        let mut publications = Vec::new();
        publications
            .try_reserve_exact(maximum_publications)
            .map_err(|_| refused("condition publication retention unavailable"))?;
        Ok(Self {
            sequence: 0,
            publications,
            maximum_publications,
            pending: None,
            failed: false,
        })
    }

    /// Borrows the exact original token retained across an unresolved native effect.
    ///
    /// This read creates no replacement grant and cannot clear failed custody.
    pub fn pending_operation(&self) -> Option<&crucible::node_contract::OperationToken> {
        self.pending.as_ref()
    }

    /// Drives to the first real condition and obtains a distinct live world fence.
    ///
    /// The physical budget is an exclusive work limit, not EOF or quiescence.
    ///
    /// # Errors
    /// Refuses unsupported topology, unavailable frontier proof, finite credits
    /// or original native failure. The caller keeps this driver and runtime
    /// together; uncertain original work remains owned and is never reissued.
    pub fn stop_at_first_hit(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        observer: &Id,
        maximum_physical_cut: U64,
    ) -> Result<AuthenticatedConditionStop, NodeObservedError> {
        let result = self
            .drive(
                runtime,
                graph,
                activation,
                observer,
                maximum_physical_cut,
                true,
            )
            .and_then(|stop| {
                stop.ok_or_else(|| {
                    refused("condition did not hit before its explicit physical budget")
                })
            });
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Continues original future work after authentic report and resume ACKs.
    ///
    /// # Errors
    /// Refuses an unresolved original stop, a previously failed driver, finite
    /// credits or native failure while retaining original token custody.
    pub fn continue_original_after_resume(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        observer: &Id,
        horizon: U64,
    ) -> Result<(), NodeObservedError> {
        if !runtime
            .condition_stop_checkpoint()
            .is_some_and(|stop| stop.resumed)
        {
            return Err(refused(
                "suffix requires actual original acknowledged resume custody",
            ));
        }
        let result = self.drive(runtime, graph, activation, observer, horizon, false);
        if result.is_err() {
            self.failed = true;
        }
        result.map(|_| ())
    }

    /// Borrows the complete ordered original native publications retained so far.
    pub fn publications(&self) -> &[crucible::node_scheduling::NativePublication] {
        &self.publications
    }

    fn drive(
        &mut self,
        runtime: &mut NodeRuntime,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        observer: &Id,
        maximum_physical_cut: U64,
        stop_on_hit: bool,
    ) -> Result<Option<AuthenticatedConditionStop>, NodeObservedError> {
        if self.failed || self.pending.is_some() {
            return Err(refused("condition driver retains failed original custody"));
        }
        let order = causal_order(graph)?;
        for _ in 0..4096 {
            observe(runtime, graph, activation)?;
            let hit = runtime
                .condition_hit_candidate(activation, observer)
                .map_err(|error| context_error("candidate", observer, error))?;
            let mut next = None;
            let mut common = None;
            let mut maximum = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
            for node in &order {
                let frontier = runtime
                    .observe_condition_frontier(activation, node, 16 << 20)
                    .map_err(|error| context_error("frontier", node, error))?;
                maximum = maximum.max(frontier.boundary);
                common = match common {
                    None => Some(Some(frontier.boundary)),
                    Some(Some(cut)) if cut == frontier.boundary => Some(Some(cut)),
                    _ => Some(None),
                };
                if let Some(event) = frontier.next {
                    next = Some(next.map_or(event, |original: Position| original.min(event)));
                }
                for delivery in runtime.scheduler(graph, activation)?.pending_inputs(node)? {
                    let reaction = Position::new(
                        delivery.delivery.time_ps,
                        delivery.delivery.microstep.checked_add(1.into())?,
                        Phase::Reaction,
                    );
                    next = Some(next.map_or(reaction, |original: Position| original.min(reaction)));
                }
            }
            if !stop_on_hit
                && common
                    .is_some_and(|cut| cut.is_some_and(|cut| cut.time_ps == maximum_physical_cut))
            {
                // This is only an actual reached execution cut. It does not
                // authorize terminal finalization or claim input/world EOF.
                return Ok(None);
            }
            if stop_on_hit && hit.is_some() && common.is_some_and(|cut| cut.is_some()) {
                return runtime
                    .condition_stop_barrier(
                        graph,
                        activation,
                        observer,
                        self.name("stop", observer)?,
                        32 << 20,
                    )
                    .map(Some)
                    .map_err(|error| context_error("stop barrier", observer, error));
            }
            let target = if hit.is_some() {
                // Settlement reconciles local cuts only at the original physical
                // instant. It cannot move a past match to a later tick.
                if hit
                    .as_ref()
                    .is_some_and(|hit| hit.evaluation.time_ps != maximum.time_ps)
                {
                    return Err(refused(
                        "condition was observed after another node outran its instant",
                    ));
                }
                maximum
            } else {
                let event = match next {
                    Some(event) if event.time_ps <= maximum_physical_cut => event,
                    _ if !stop_on_hit => {
                        Position::new(maximum_physical_cut, 0.into(), Phase::BoundaryControl)
                    }
                    _ => {
                        return Err(refused(
                            "condition budget excludes the next original event; absence is not EOF",
                        ));
                    }
                };
                if event.time_ps > maximum.time_ps {
                    Position::new(event.time_ps, 0.into(), Phase::BoundaryControl)
                } else {
                    Position::new(
                        maximum.time_ps,
                        maximum.microstep.checked_add(1.into())?,
                        Phase::BoundaryControl,
                    )
                }
            };
            let mut progress = false;
            for node in &order {
                observe(runtime, graph, activation)?;
                let cursor = runtime.scheduler(graph, activation)?.position(node)?;
                if cursor >= target {
                    continue;
                }
                if node == observer {
                    let inputs = runtime.scheduler(graph, activation)?.pending_inputs(node)?;
                    if let Some(delivery) = inputs.first() {
                        // A complete input cut promises consumption of every
                        // earlier delivery. Do not stage that cut before the
                        // observer's actual successor reaction fits its grant.
                        // Other owners may settle meanwhile; a later original
                        // grant consumes this unchanged queued delivery.
                        if !condition_input_fits(delivery.delivery, target)? {
                            continue;
                        }
                    }
                }
                let grant = if cursor.time_ps < target.time_ps {
                    let names = ExactOperationNames {
                        operation: self.name("run", node)?,
                        stage: self.name("stage", node)?,
                        batch: self.name("batch", node)?,
                    };
                    match plan_exact_operation::<ConditionPlanError, _>(
                        runtime,
                        ExactOperationRequest {
                            graph,
                            activation,
                            node,
                            horizon: target.time_ps,
                            names,
                        },
                        |_| Ok(()),
                    ) {
                        Ok(grant) => grant,
                        Err(ConditionPlanError::Scheduling(
                            SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress,
                        )) => None,
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    if runtime
                        .scheduler(graph, activation)?
                        .pending_inputs(node)?
                        .iter()
                        .any(|delivery| delivery.delivery < target)
                        && !runtime
                            .scheduler(graph, activation)?
                            .condition_input_cut_retained(node)?
                    {
                        let stage = self.name("stage", node)?;
                        let batch = self.name("batch", node)?;
                        match runtime
                            .scheduler(graph, activation)?
                            .prepare_input_batch(node, stage, batch, target)
                        {
                            Ok(input) => {
                                let acknowledgement = runtime.stage_inputs(input)?;
                                let commit =
                                    runtime.commit_input_acknowledgement(acknowledgement)?;
                                runtime.commit_input_staging(&commit)?;
                            }
                            Err(
                                SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress,
                            ) => continue,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    let operation = self.name("settle", node)?;
                    match runtime
                        .scheduler(graph, activation)?
                        .admit_boundary_settlement(node, operation, target)
                    {
                        Ok(grant) => Some(grant),
                        Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) => {
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                if let Some(grant) = grant {
                    // Reserve the whole source-qualified native batch before
                    // Begin. Exhaustion leaves the original grant in runtime
                    // custody and cannot silently drop published records.
                    if self
                        .maximum_publications
                        .saturating_sub(self.publications.len())
                        < 16
                    {
                        self.failed = true;
                        return Err(refused("condition original publication credit exhausted"));
                    }
                    let token = match runtime.begin_admitted(grant)? {
                        BeginResult::Accepted(token) => token,
                        BeginResult::Refused(original) => {
                            return Err(NodeObservedError::Native(format!(
                                "condition original node {node} from {cursor:?} to {target:?} refused: {}",
                                original.reason
                            )));
                        }
                        BeginResult::Uncertain { token, effects } => {
                            self.pending = Some(token.clone());
                            self.failed = true;
                            // Observe only the original retained result; this is
                            // never another Begin or a replacement grant.
                            let mut context = Context::from_waker(Waker::noop());
                            let original = runtime.poll(&token, &mut context);
                            return Err(NodeObservedError::Native(format!(
                                "condition original {} retained uncertain custody: {effects:?}; original query: {original:?}",
                                token.operation()
                            )));
                        }
                    };
                    self.pending = Some(token.clone());
                    let mut context = Context::from_waker(Waker::noop());
                    match runtime.poll(&token, &mut context) {
                        Poll::Ready(Ok(outcome)) => {
                            if let Some(observation) = &outcome.scheduling {
                                if observation.publications.len() > 16 {
                                    self.failed = true;
                                    return Err(refused(
                                        "condition original output exceeds selected native batch",
                                    ));
                                }
                                self.publications.extend(observation.publications.clone());
                            }
                        }
                        Poll::Ready(Err(error)) => return Err(error.into()),
                        Poll::Pending => {
                            return Err(refused(
                                "condition live profile retained unexpected asynchronous custody",
                            ));
                        }
                    }
                    let receipt = runtime.scheduling_receipt(&token)?;
                    let commit = runtime.commit_scheduling_receipt(receipt)?;
                    runtime.acknowledge_scheduled(&token, &commit)?;
                    self.pending = None;
                    progress = true;
                    // Observer is topologically last. Its actual hit is checked
                    // before any later physical grant is considered.
                }
            }
            if !progress {
                return Err(refused("authentic event frontier is causally blocked"));
            }
        }
        Err(refused(
            "condition driver exhausted its finite original round credit",
        ))
    }

    fn name(&mut self, kind: &str, node: &Id) -> Result<Id, NodeObservedError> {
        let original = self.sequence;
        self.sequence = original
            .checked_add(1)
            .ok_or_else(|| refused("condition sequence overflow"))?;
        Ok(Id::new(format!("condition/{original}/{kind}/{node}"))?)
    }
}

fn observe(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
) -> Result<(), NodeObservedError> {
    for node in graph.node_ids() {
        let observation = runtime
            .observe_scheduling(activation, node)
            .map_err(|error| context_error("boundary observation", node, error))?;
        runtime
            .scheduler(graph, activation)?
            .accept_boundary_observation(observation)
            .map_err(|error| context_error("boundary receipt", node, error))?;
    }
    Ok(())
}

fn causal_order(graph: &AdmittedGraph) -> Result<Vec<Id>, NodeObservedError> {
    let mut remaining: std::collections::BTreeSet<_> = graph.node_ids().cloned().collect();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|node| {
                graph.world().connections.iter().all(|connection| {
                    &connection.consumer.node_id != *node
                        || !remaining.contains(&connection.producer.node_id)
                })
            })
            .cloned()
            .ok_or_else(|| refused("condition profile requires an acyclic actual input graph"))?;
        remaining.remove(&next);
        ordered.push(next);
    }
    Ok(ordered)
}

fn refused(reason: &str) -> NodeObservedError {
    NodeObservedError::Native(reason.to_owned())
}

fn context_error(stage: &str, node: &Id, error: impl std::fmt::Display) -> NodeObservedError {
    NodeObservedError::Native(format!("condition {stage} for {node}: {error}"))
}

fn condition_input_fits(delivery: Position, cutoff: Position) -> Result<bool, NodeObservedError> {
    let reaction = Position::new(
        delivery.time_ps,
        delivery.microstep.checked_add(1.into())?,
        Phase::Reaction,
    );
    Ok(delivery >= cutoff || reaction < cutoff)
}

#[cfg(test)]
#[path = "condition_execution_tests.rs"]
mod tests;

enum ConditionPlanError {
    Scheduling(SchedulingError),
    Native(NodeObservedError),
}

impl From<SchedulingError> for ConditionPlanError {
    fn from(error: SchedulingError) -> Self {
        Self::Scheduling(error)
    }
}

impl From<crucible::node_contract::RuntimeError> for ConditionPlanError {
    fn from(error: crucible::node_contract::RuntimeError) -> Self {
        Self::Native(error.into())
    }
}

impl From<crucible::node_contract::RuntimePollFailure> for ConditionPlanError {
    fn from(error: crucible::node_contract::RuntimePollFailure) -> Self {
        Self::Native(error.into())
    }
}

impl From<ConditionPlanError> for NodeObservedError {
    fn from(error: ConditionPlanError) -> Self {
        match error {
            ConditionPlanError::Scheduling(error) => error.into(),
            ConditionPlanError::Native(error) => error,
        }
    }
}
