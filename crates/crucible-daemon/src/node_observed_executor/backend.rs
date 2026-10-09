//! Retained native rounds and exact planned-to-observed artifact admission.

#[path = "backend/replay.rs"]
mod replay;

use std::{
    collections::BTreeSet,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationPublisher, NodeRuntime, QuarantinedRuntime, RuntimeError, RuntimePollFailure,
        WorldActivation,
    },
    node_dispatch::DispatchRound,
    node_scheduling::{ExecutionPolicy, SchedulingError},
};
use crucible_campaign::{
    CampaignCodecError, ConfigurationArtifact, ExecutionId, ScenarioArtifact,
    executor_node_capabilities::{ExecutorNodeCapabilities, NodeMaterializationStrategy},
    observed_node_attempt::{
        ConditionalReplayScope, ObservedAttemptAdmission, ObservedAttemptBackend,
        ObservedAttemptOutcome, ObservedAttemptRequest, ObservedAttemptResult,
    },
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, StoreError,
};
use crucible_node_contract::{Id, Phase, Position, U64, canonical};

use crate::{
    executor_node_capabilities::roster_from_admitted_graph,
    node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation},
    node_scenario::{NodeRunConfiguration, NodeScenario, NodeScenarioError},
    supervision::ProcessDeadline,
};

use super::factory::{ReplayStep, ReplayStepper};
use super::{InstalledConditionalReplay, InstalledPreparedWorld, StoredWorldActivationPublisher};

/// Authenticates exact planned artifacts against one complete sealed realization.
#[derive(Clone)]
pub struct NodeObservedAdmission {
    execution: ExecutionId,
    scenario: ScenarioArtifact,
    configuration: ConfigurationArtifact,
    capabilities: ExecutorNodeCapabilities,
    inputs: ContentId,
    conditional: Option<ConditionalReplayScope>,
}

impl ObservedAttemptAdmission for NodeObservedAdmission {
    fn authenticate(
        &self,
        request: &ObservedAttemptRequest,
        scenario: &ScenarioArtifact,
        configuration: &ConfigurationArtifact,
    ) -> Result<(), CampaignCodecError> {
        if request.execution() != self.execution
            || scenario != &self.scenario
            || configuration != &self.configuration
            || request.capabilities() != &self.capabilities
            || request.inputs() != self.inputs
            || request.conditional_scope() != self.conditional.as_ref()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "observed request differs from sealed node artifacts or authenticated inputs",
            });
        }
        Ok(())
    }
}

/// Reports a refused, uncertain, or incomplete native-world observation.
#[derive(Debug, thiserror::Error)]
pub enum NodeObservedError {
    /// Portable scenario/configuration or artifact validation failed.
    #[error(transparent)]
    Scenario(#[from] NodeScenarioError),
    /// Campaign realization identity or result construction failed.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// Durable provenance storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Native or causal authority could not establish the requested operation.
    #[error("node observation refused: {0}")]
    Native(String),
    /// Provenance serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Portable identity construction failed.
    #[error(transparent)]
    Contract(#[from] crucible_node_contract::ContractError),
}

impl From<RuntimeError> for NodeObservedError {
    fn from(error: RuntimeError) -> Self {
        native(error)
    }
}

impl From<SchedulingError> for NodeObservedError {
    fn from(error: SchedulingError) -> Self {
        native(error)
    }
}

impl From<RuntimePollFailure> for NodeObservedError {
    fn from(error: RuntimePollFailure) -> Self {
        native(error)
    }
}

struct ActiveRound {
    round: DispatchRound,
    quantized: Vec<Id>,
    close_at: ProcessDeadline,
    closed: bool,
}

struct CompletedNative {
    custody: QuarantinedRuntime,
    outcome: ObservedAttemptOutcome,
}

/// Executes one locally prepared world using its authentic runtime and scheduler.
///
/// This actor-local value is deliberately not `Send`. Native providers are
/// prepared on the same owning actor that polls it. Each backend incarnation is
/// single-use; its nonce cannot be reused or replaced after activation. Runtime
/// destruction transfers complete native, operation, input and scheduler custody
/// into the factory's already-reserved owning supervision slot.
pub struct NodeObservedBackend {
    graph: AdmittedGraph,
    preparation_record: crucible::node_contract::ActivationRecord,
    runtime: Option<NodeRuntime>,
    activation: Option<WorldActivation>,
    publisher: Box<dyn ActivationPublisher>,
    admission: NodeObservedAdmission,
    configuration: NodeRunConfiguration,
    blobs: Arc<dyn ImmutableBlobBackend>,
    request: Option<ObservedAttemptRequest>,
    round: Option<ActiveRound>,
    replay: Option<ReplayStepper>,
    prearmed: bool,
    rounds: u64,
    incoming: Vec<serde_json::Value>,
    outgoing: Vec<serde_json::Value>,
    native_evidence: Vec<serde_json::Value>,
    provenance_bytes: usize,
    evidence_roots: BTreeSet<ContentId>,
    completed: Option<CompletedNative>,
    result: Option<ObservedAttemptResult>,
}

impl NodeObservedBackend {
    /// Forms an executable observation from a genuinely prepared complete world.
    ///
    /// The caller supplies authenticated immutable input context in the same CAS
    /// namespace as the campaign repository. The initial implementation accepts
    /// no authored external root events: actual external ingress requires the
    /// scheduler's authenticated inventory path. It never invents empty closure.
    ///
    /// # Errors
    /// Refuses changed graph/artifact relations, unavailable input bytes, invalid
    /// native preparation, or authored external ingress unsupported by this path.
    pub fn from_prepared(
        world: InstalledPreparedWorld,
        configuration: NodeRunConfiguration,
        publisher: Box<dyn ActivationPublisher>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        inputs: ContentId,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        Self::from_prepared_with(world, configuration, blobs, inputs, execution, |_, _| {
            Ok(publisher)
        })
    }

    fn from_prepared_with(
        world: InstalledPreparedWorld,
        configuration: NodeRunConfiguration,
        blobs: Arc<dyn ImmutableBlobBackend>,
        inputs: ContentId,
        execution: ExecutionId,
        publisher: impl FnOnce(
            &mut NodeRuntime,
            &AdmittedGraph,
        ) -> Result<Box<dyn ActivationPublisher>, NodeObservedError>,
    ) -> Result<Self, NodeObservedError> {
        let InstalledPreparedWorld {
            scenario,
            graph,
            realization: prepared,
        } = world;
        let scenario_artifact = scenario.artifact()?;
        let configuration_artifact = configuration.artifact(&scenario)?;
        if graph.world() != &scenario.world
            || canonical::json_hash("cnp.admission-requirements.v1", graph.requirements())?
                != canonical::json_hash("cnp.admission-requirements.v1", &scenario.requirements)?
            || graph.node_ids().count() != scenario.descriptors.len()
            || graph.owners().count() != scenario.owners.len()
            || scenario
                .descriptors
                .iter()
                .any(|descriptor| graph.descriptor(&descriptor.id) != Some(descriptor))
            || scenario.compatibility.iter().any(|binding| {
                graph
                    .binding(&binding.node_id)
                    .is_none_or(|actual| &actual.compatibility != binding)
            })
            || scenario
                .owners
                .iter()
                .any(|owner| graph.owner(&owner.owner.id) != Some(owner))
        {
            return Err(NodeObservedError::Native(
                "sealed graph differs from planned scenario bytes".into(),
            ));
        }
        if !graph.coordinator_policy().external_inputs.is_empty() {
            return Err(NodeObservedError::Native(
                "authored external ingress requires a qualified live inventory source".into(),
            ));
        }
        // This edition accepts a closed no-ingress/no-fault context only. Exact
        // canonical bytes bind the complete world and run policy; opaque labels
        // or an arbitrary trace object cannot authenticate a different context.
        let actual_inputs = blobs.read(inputs, None)?.read_all(16 * 1024 * 1024)?;
        if actual_inputs != input_context_bytes(&scenario, &configuration)? {
            return Err(NodeObservedError::Native(
                "input context differs from the implemented complete world policy".into(),
            ));
        }
        let roster = roster_from_admitted_graph(
            &graph,
            scenario_artifact.id()?,
            configuration_artifact.id()?,
        )?;
        let capabilities = ExecutorNodeCapabilities::new(
            roster,
            BTreeSet::from([NodeMaterializationStrategy::FreshExecution]),
        )?;
        let preparation_record = prepared.activation_record().clone();
        let mut runtime = prepared.admit(&graph).map_err(|failure| {
            NodeObservedError::Native(format!("native preparation refused: {:?}", failure.error))
        })?;

        let publisher = publisher(&mut runtime, &graph)?;
        Ok(Self {
            graph,
            preparation_record,
            runtime: Some(runtime),
            activation: None,
            publisher,
            admission: NodeObservedAdmission {
                execution,
                scenario: scenario_artifact,
                configuration: configuration_artifact,
                capabilities,
                inputs,
                conditional: None,
            },
            configuration,
            blobs,
            request: None,
            round: None,
            replay: None,
            prearmed: false,
            rounds: 0,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            native_evidence: Vec::new(),
            provenance_bytes: 0,
            evidence_roots: BTreeSet::new(),
            completed: None,
            result: None,
        })
    }

    /// Returns immutable admission authority for the prepared world.
    pub fn admission(&self) -> &NodeObservedAdmission {
        &self.admission
    }

    /// Constructs a fresh observation request for this exact prepared realization.
    ///
    /// # Errors
    /// Refuses malformed capability/request records. This does not reserve or run.
    pub fn request(
        &self,
        execution: ExecutionId,
    ) -> Result<ObservedAttemptRequest, CampaignCodecError> {
        if execution != self.admission.execution {
            return Err(CampaignCodecError::InvalidValue {
                reason: "execution nonce differs from prepared native world",
            });
        }
        match &self.admission.conditional {
            Some(scope) => ObservedAttemptRequest::conditional_replay(
                execution,
                self.admission.capabilities.clone(),
                self.admission.inputs,
                scope.clone(),
            ),
            None => ObservedAttemptRequest::new(
                execution,
                self.admission.capabilities.clone(),
                self.admission.inputs,
            ),
        }
    }

    /// Returns the authenticated scenario artifact to publish before submission.
    pub fn scenario_artifact(&self) -> &ScenarioArtifact {
        &self.admission.scenario
    }

    /// Returns the authenticated configuration artifact to publish before submission.
    pub fn configuration_artifact(&self) -> &ConfigurationArtifact {
        &self.admission.configuration
    }

    fn begin_round(&mut self) -> Result<bool, NodeObservedError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| NodeObservedError::Native("world is contained".into()))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| NodeObservedError::Native("world is not activated".into()))?;
        let mut grants = Vec::new();
        let mut quantized = Vec::new();
        let mut maximum_budget = Duration::ZERO;
        let mut dispatched_owners = BTreeSet::new();
        for node in self.graph.node_ids() {
            let binding = self
                .graph
                .binding(node)
                .ok_or_else(|| NodeObservedError::Native("sealed node disappeared".into()))?;
            // A blocked public alias does not reserve its shared execution owner.
            // Reserve only after obtaining a grant, so a runnable sibling can progress.
            if dispatched_owners.contains(&binding.compatibility.execution_owner.id) {
                continue;
            }
            if self
                .graph
                .owner_conflicts(&binding.compatibility.execution_owner.id)
                .is_some_and(|conflicts| {
                    conflicts
                        .iter()
                        .any(|owner| dispatched_owners.contains(owner))
                })
            {
                continue;
            }
            if runtime
                .scheduler(&self.graph, activation)
                .map_err(native)?
                .output_backpressure(node)
                .map_err(native)?
            {
                continue;
            }
            let previous_grants = grants.len();
            let current = runtime
                .scheduler(&self.graph, activation)
                .map_err(native)?
                .position(node)
                .map_err(native)?;
            if current.time_ps >= self.configuration.horizon_ps {
                continue;
            }
            let operation = Id::new(format!("observe/{}/{node}", self.rounds))?;
            let policy = self.graph.operating_policy(node).ok_or_else(|| {
                NodeObservedError::Native("sealed operating policy disappeared".into())
            })?;
            match policy {
                ExecutionPolicy::Exact { .. } => {
                    let grant = plan_exact_operation(
                        runtime,
                        ExactOperationRequest {
                            graph: &self.graph,
                            activation,
                            node,
                            horizon: self.configuration.horizon_ps,
                            names: ExactOperationNames {
                                operation,
                                stage: Id::new(format!("stage/{}/{node}", self.rounds))?,
                                batch: Id::new(format!("batch/{}/{node}", self.rounds))?,
                            },
                        },
                        |observed| {
                            retain_event(&mut self.incoming, &mut self.provenance_bytes, observed)
                        },
                    )?;
                    if let Some(grant) = grant {
                        grants.push(grant);
                    }
                }
                ExecutionPolicy::Quantized {
                    host_budget_ns,
                    quantum_ps,
                    ..
                } => {
                    if current.time_ps.checked_add(*quantum_ps)? > self.configuration.horizon_ps {
                        return Err(NodeObservedError::Native(
                            "requested horizon truncates a quantized window".into(),
                        ));
                    }
                    let stage = Id::new(format!("stage/{}/{node}", self.rounds))?;
                    let batch = Id::new(format!("batch/{}/{node}", self.rounds))?;
                    let cutoff = Position::new(
                        current.time_ps.checked_add(U64::new(1))?,
                        U64::new(0),
                        Phase::BoundaryControl,
                    );
                    let input = match runtime
                        .scheduler(&self.graph, activation)
                        .map_err(native)?
                        .prepare_input_batch(node, stage, batch.clone(), cutoff)
                    {
                        Ok(input) => input,
                        Err(SchedulingError::InputBlocked(_) | SchedulingError::NoSafeProgress) => {
                            continue;
                        }
                        Err(error) => return Err(native(error)),
                    };
                    let observed = serde_json::json!({"node":node,"batch":input.batch(),
                        "inventory":input.inventory(),"cutoff":input.cutoff(),
                        "deliveries":input.deliveries(),"payloads":input.payloads()});
                    let acknowledgement = runtime.stage_inputs(input).map_err(native)?;
                    let commit = runtime
                        .commit_input_acknowledgement(acknowledgement)
                        .map_err(native)?;
                    runtime.commit_input_staging(&commit).map_err(native)?;
                    retain_event(&mut self.incoming, &mut self.provenance_bytes, observed)?;
                    grants.push(
                        runtime
                            .scheduler(&self.graph, activation)
                            .map_err(native)?
                            .admit_quantum(
                                node,
                                operation.clone(),
                                Id::new(format!("window/{}/{node}", self.rounds))?,
                                batch,
                            )
                            .map_err(native)?,
                    );
                    quantized.push(operation);
                    maximum_budget = maximum_budget.max(Duration::from_nanos(host_budget_ns.get()));
                }
            }
            if grants.len() > previous_grants {
                dispatched_owners.insert(binding.compatibility.execution_owner.id.clone());
            }
        }
        if grants.is_empty() {
            for node in self.graph.node_ids() {
                if runtime
                    .scheduler(&self.graph, activation)
                    .map_err(native)?
                    .position(node)
                    .map_err(native)?
                    .time_ps
                    < self.configuration.horizon_ps
                {
                    return Err(NodeObservedError::Native("complete world is causally blocked before requested horizon; no native grant was widened".into()));
                }
            }
            return Ok(false);
        }
        let close_at = ProcessDeadline::after(maximum_budget).ok_or_else(|| {
            NodeObservedError::Native("host budget overflows monotonic clock".into())
        })?;
        let round = DispatchRound::start(runtime, grants, self.graph.node_ids().count())
            .map_err(|failure| NodeObservedError::Native(failure.reason))?;
        self.round = Some(ActiveRound {
            round,
            quantized,
            close_at,
            closed: false,
        });
        Ok(true)
    }

    fn begin_completion(
        &mut self,
        outcome: ObservedAttemptOutcome,
    ) -> Result<(), NodeObservedError> {
        let runtime = self
            .runtime
            .take()
            .ok_or_else(|| NodeObservedError::Native("native world custody is missing".into()))?;
        self.completed = Some(CompletedNative {
            custody: runtime.into_quarantine(),
            outcome,
        });
        Ok(())
    }

    fn provenance(&self, values: &[serde_json::Value]) -> Result<ContentId, NodeObservedError> {
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.node-observed-boundary","version":1,"events":values}))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(NodeObservedError::Native(
                "actual boundary provenance exceeds finite limit".into(),
            ));
        }
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))?;
        if !receipt.is_durable() {
            return Err(NodeObservedError::Native(
                "provenance placement is not durable".into(),
            ));
        }
        Ok(id)
    }
}

impl ObservedAttemptBackend for NodeObservedBackend {
    type Error = NodeObservedError;

    fn retention_roots(&self) -> BTreeSet<ContentId> {
        let mut roots = self.evidence_roots.clone();
        roots.insert(self.admission.inputs);
        roots.insert(self.admission.capabilities.roster().scenario().content_id());
        roots.insert(
            self.admission
                .capabilities
                .roster()
                .configuration()
                .content_id(),
        );
        if let Some(result) = &self.result {
            roots.extend([result.incoming(), result.outgoing(), result.evidence()]);
        }
        roots
    }

    fn validate_realization(
        &mut self,
        request: &ObservedAttemptRequest,
    ) -> Result<(), Self::Error> {
        self.admission.authenticate(
            request,
            &self.admission.scenario,
            &self.admission.configuration,
        )?;
        if self
            .request
            .as_ref()
            .is_some_and(|original| original != request)
            || self.runtime.is_none() && self.request.is_none()
        {
            return Err(NodeObservedError::Native(
                "single-use native realization is unavailable".into(),
            ));
        }
        Ok(())
    }

    fn start(&mut self, request: &ObservedAttemptRequest) -> Result<(), Self::Error> {
        if self.request.is_some() {
            return Err(NodeObservedError::Native(
                "native execution was already dispatched".into(),
            ));
        }
        self.validate_realization(request)?;
        self.request = Some(request.clone());
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| NodeObservedError::Native("prepared world is unavailable".into()))?;
        if !self.prearmed {
            runtime.arm_all().map_err(native)?;
            // Complete preparation is required only for the public owner-map
            // contract, matching the runtime activation barrier's publication path.
            if let Ok(nodes) = runtime.prepared_node_records()
                && nodes.iter().any(|node| node.prepared_owners().is_some())
            {
                let nodes = nodes.to_vec();
                let coordinator = runtime
                    .initial_coordinator_snapshot(
                        &self.graph,
                        crucible::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES,
                    )
                    .map_err(native)?;
                self.publisher
                    .retain_initial_coordinator(&self.preparation_record, nodes, coordinator)
                    .map_err(native)?;
            }
        }
        self.activation = Some(runtime.activate(self.publisher.as_mut()).map_err(native)?);
        Ok(())
    }

    fn poll(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<ObservedAttemptResult>, Self::Error> {
        let request = self
            .request
            .as_ref()
            .ok_or_else(|| NodeObservedError::Native("execution was never dispatched".into()))?;
        if request.execution() != execution {
            return Err(NodeObservedError::Native("foreign execution nonce".into()));
        }
        if let Some(result) = &self.result {
            return Ok(Some(result.clone()));
        }
        let mut context = Context::from_waker(Waker::noop());
        if self.completed.is_some() {
            let outcome = {
                let completed = self.completed.as_mut().ok_or_else(|| {
                    NodeObservedError::Native("contained world disappeared".into())
                })?;
                match completed.custody.poll_reclamation(&mut context) {
                    Poll::Pending => return Ok(None),
                    Poll::Ready(Err(error)) => return Err(native(error)),
                    Poll::Ready(Ok(())) => completed.outcome,
                }
            };
            let incoming = self.provenance(&self.incoming)?;
            let outgoing = self.provenance(&self.outgoing)?;
            let evidence = self.provenance(&self.native_evidence)?;
            // Original authenticated input context is retained independently of
            // actual transcripts; it is never substituted for observed ingress.
            let result = ObservedAttemptResult::new(
                self.request.clone().ok_or_else(|| {
                    NodeObservedError::Native("original request disappeared".into())
                })?,
                incoming,
                outgoing,
                evidence,
                outcome,
            )?;
            self.result = Some(result.clone());
            return Ok(Some(result));
        }
        if self.replay.is_some() {
            self.poll_original_replay(&mut context)?;
            return Ok(None);
        }
        if self.round.is_none() {
            if self.rounds >= self.configuration.maximum_rounds.get() {
                self.begin_completion(ObservedAttemptOutcome::BudgetExhausted)?;
                return Ok(None);
            }
            if !self.begin_round()? {
                self.begin_completion(ObservedAttemptOutcome::Completed)?;
                return Ok(None);
            }
        }
        let round = self
            .round
            .as_mut()
            .ok_or_else(|| NodeObservedError::Native("original round disappeared".into()))?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| NodeObservedError::Native("native runtime disappeared".into()))?;
        if !round.closed && round.close_at.expired() {
            for operation in &round.quantized {
                let closure = round
                    .round
                    .close_quantum(runtime, operation)
                    .map_err(native)?;
                if !matches!(closure, crucible::node_contract::Submission::Accepted) {
                    return Err(NodeObservedError::Native(format!(
                        "original native window closure was not accepted: {closure:?}",
                    )));
                }
            }
            round.closed = true;
        }
        match round.round.poll(runtime, &mut context) {
            Poll::Pending => Ok(None),
            Poll::Ready(Err(error)) => Err(native(error)),
            Poll::Ready(Ok(())) => {
                let outcomes = round.round.ready_outcomes().map_err(native)?;
                let mut round_evidence = Vec::new();
                for token in round.round.tokens() {
                    let outcome = outcomes
                        .iter()
                        .find(|outcome| &outcome.operation == token.operation())
                        .ok_or_else(|| {
                            NodeObservedError::Native(
                                "original round outcome is unavailable".into(),
                            )
                        })?;
                    let references = evidence_references(outcome);
                    let objects = runtime
                        .operation_evidence(token, &references, U64::new(16 * 1024 * 1024))
                        .map_err(native)?;
                    let objects = objects
                        .into_iter()
                        .map(|object| {
                            serde_json::json!({
                                "reference":object.reference,
                                "bytes":crucible_node_contract::Bytes::new(object.bytes),
                            })
                        })
                        .collect::<Vec<_>>();
                    let event =
                        serde_json::json!({"operation":token.operation(),"objects":objects});
                    round_evidence.push(event.clone());
                    retain_event(&mut self.native_evidence, &mut self.provenance_bytes, event)?;
                }
                for outcome in &outcomes {
                    retain_event(
                        &mut self.outgoing,
                        &mut self.provenance_bytes,
                        serde_json::to_value(outcome)?,
                    )?;
                }
                // Persist authentic receipt bodies before output ACK can release
                // native publication custody. Operational GC retains this exact
                // copy until original whole-world reclamation completes.
                let bytes = canonical::canonical_json(&serde_json::json!({
                    "format":"crucible.node-observed-boundary","version":1,"events":round_evidence}))?;
                let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
                let receipt = self
                    .blobs
                    .put_if_absent(id, &BlobHandle::from_bytes(bytes))?;
                if !receipt.is_durable() {
                    return Err(NodeObservedError::Native(
                        "original receipt copy is not durable".into(),
                    ));
                }
                self.evidence_roots.insert(id);
                round.round.publish(runtime).map_err(native)?;
                self.rounds = self
                    .rounds
                    .checked_add(1)
                    .ok_or_else(|| NodeObservedError::Native("round counter overflow".into()))?;
                self.round = None;
                Ok(None)
            }
        }
    }

    fn contain(&mut self, execution: ExecutionId) -> Result<bool, Self::Error> {
        if self
            .request
            .as_ref()
            .is_none_or(|request| request.execution() != execution)
        {
            return Err(NodeObservedError::Native(
                "foreign containment nonce".into(),
            ));
        }
        self.round = None;
        if self.completed.is_none() {
            self.begin_completion(ObservedAttemptOutcome::Cancelled)?;
        }
        let mut context = Context::from_waker(Waker::noop());
        match self
            .completed
            .as_mut()
            .ok_or_else(|| {
                NodeObservedError::Native("whole-world containment custody disappeared".into())
            })?
            .custody
            .poll_reclamation(&mut context)
        {
            Poll::Pending => Ok(false),
            Poll::Ready(Ok(())) => Ok(true),
            Poll::Ready(Err(error)) => Err(native(error)),
        }
    }
}

fn native(error: impl std::fmt::Debug) -> NodeObservedError {
    NodeObservedError::Native(format!("{error:?}"))
}

pub(super) fn input_context_bytes(
    scenario: &NodeScenario,
    configuration: &NodeRunConfiguration,
) -> Result<Vec<u8>, NodeObservedError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "format":"crucible.node-input-context","version":1,
        "world":scenario.world.identity()?,
        "configuration":configuration.artifact(scenario)?.id()?.to_text(),
        "external_inputs":[],"faults":[],"ordering_profile":"superdense-v1",
        "clock_policy":"selected-complete-operating-contracts"
    }))?)
}

fn evidence_references(
    outcome: &crucible::node_contract::OperationOutcome,
) -> Vec<crucible_node_contract::ContentRef> {
    use crucible::node_contract::ProgressEvidence;
    let mut references = BTreeSet::new();
    match &outcome.progress {
        ProgressEvidence::Quantized { closure, .. } => {
            references.extend([
                closure.close_receipt.clone(),
                closure.output_inventory.clone(),
                closure.pending_inventory.clone(),
                closure.clock_evidence.clone(),
            ]);
        }
        ProgressEvidence::Paused { stop_receipt, .. } => {
            references.insert(stop_receipt.clone());
        }
        ProgressEvidence::AssertionsFinalized {
            barrier, report, ..
        } => {
            references.insert(barrier.clone());
            references.insert(report.clone());
        }
        ProgressEvidence::Exact { .. } | ProgressEvidence::Administrative => {}
    }
    if let Some(observation) = &outcome.scheduling {
        references.insert(observation.proof_ref.clone());
        references.extend(
            observation
                .bounds
                .iter()
                .map(|bound| bound.proof_ref.clone()),
        );
        if let Some(progress) = &observation.input_progress {
            references.insert(progress.proof_ref.clone());
        }
        for inventory in &observation.external_inputs {
            references.insert(inventory.proof_ref.clone());
            references.extend(
                inventory
                    .inputs
                    .iter()
                    .map(|input| input.provenance_ref.clone()),
            );
        }
    }
    references.into_iter().collect()
}

fn retain_event(
    events: &mut Vec<serde_json::Value>,
    total: &mut usize,
    value: serde_json::Value,
) -> Result<(), NodeObservedError> {
    let bytes = canonical::canonical_json(&value)?.len();
    let next = total
        .checked_add(bytes)
        .filter(|next| *next <= 16 * 1024 * 1024)
        .ok_or_else(|| {
            NodeObservedError::Native(
                "complete actual provenance exceeds finite retention ceiling".into(),
            )
        })?;
    *total = next;
    events.push(value);
    Ok(())
}

#[cfg(test)]
#[path = "backend/shared_owner_tests.rs"]
mod shared_owner_tests;
