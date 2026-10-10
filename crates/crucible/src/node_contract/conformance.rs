//! Owns live collection-only runtime custody without an ordinary runtime escape.
//!
//! Only the opaque installed collection graph can create this owner. It retains
//! current plan authority through readiness, every original grant, polling and
//! result publication. It exposes no capture, restore, cache, replay, debugger,
//! mutable runtime, or ordinary admitted-graph conversion.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{Direction, Id, OperatingMode, U64};

#[path = "conformance/quantized.rs"]
mod quantized;

use super::*;
use crate::node_admission::{ConformanceGraph, ConformancePlanEvidence, EvidenceError};

/// Retains a refused collecting constructor and its complete original native owners.
pub struct ConformanceRuntimeFailure {
    /// Describes the original refusal without claiming native reclamation.
    pub reason: String,
    _retained: Option<Box<PreparedRealization>>,
    _preparation: Option<Box<RuntimePreparationFailure>>,
}

impl ConformanceRuntimeFailure {
    pub(crate) fn retained(reason: impl Into<String>, retained: PreparedRealization) -> Self {
        Self {
            reason: reason.into(),
            _retained: Some(Box::new(retained)),
            _preparation: None,
        }
    }
}

/// Authenticates durable retention of one original collected completion before ACK.
///
/// The installed publisher must retain all original native proof and payload
/// bodies under the exact plan/operation, not just a decoded outcome. Failure or
/// uncertain durability leaves that same runtime and native output reserved.
pub trait ConformanceResultPublisher {
    /// Publishes or reconciles the same original result without reexecuting it.
    ///
    /// # Errors
    /// Defaults to refusal; rejects missing original bodies, changed publication
    /// identities, unavailable storage or unverified current durable roots.
    fn publish_original(
        &mut self,
        _plan: ConformancePlanEvidence<'_>,
        _original: &OriginalCompletedOperation<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        Err(RuntimeError::ForeignAuthority)
    }
}

/// Owns authentic native collection lifecycle under an opaque original plan.
///
/// The underlying runtime and graph are private. Every callback uses the same
/// native handles and original ledgers; failed attempts are never redispatched.
/// Drop transfers the complete original runtime into its pre-reserved supervisor.
pub struct ConformanceRuntime {
    graph: Rc<ConformanceGraph>,
    runtime: NodeRuntime,
    activation: Option<WorldActivation>,
    quantized: bool,
}

impl ConformanceRuntime {
    /// Admits actual inactive collection nodes beneath their original graph/plan.
    ///
    /// # Errors
    /// Retains all supplied originals on failed current collection authority,
    /// ordinary nodes, changed plan/custody, malformed roster or finite limits.
    pub fn from_prepared(
        graph: ConformanceGraph,
        prepared: PreparedRealization,
    ) -> Result<Self, ConformanceRuntimeFailure> {
        Self::from_prepared_scope(graph, prepared, false)
    }

    fn from_prepared_scope(
        graph: ConformanceGraph,
        mut prepared: PreparedRealization,
        quantized: bool,
    ) -> Result<Self, ConformanceRuntimeFailure> {
        let checked: Result<(), EvidenceError> = (|| {
            graph.reauthenticate()?;
            if prepared.nodes.iter().any(|node| {
                !node
                    .collection_scope()
                    .is_some_and(|scope| scope.same_original(graph.plan()))
            }) {
                return Err(EvidenceError {
                    message:
                        "collecting runtime requires the same original plan on every native owner"
                            .into(),
                });
            }
            if quantized {
                graph.authenticate_quantized()?;
            }
            if graph.graph.node_ids().any(|node| {
                graph.graph.descriptor(node).is_some_and(|descriptor| {
                    let input = descriptor.ports.iter().any(|port| {
                        port.lanes
                            .iter()
                            .any(|lane| lane.direction == Direction::Input)
                    });
                    input
                        && (!quantized
                            || graph.graph.binding(node).is_none_or(|binding| {
                                binding.compatibility.operating_contract.mode
                                    != OperatingMode::Quantized
                            }))
                })
            }) {
                return Err(EvidenceError {
                    message: "initial collection runtime refuses nonempty ingress scope".into(),
                });
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(ConformanceRuntimeFailure::retained(error.message, prepared));
        }
        let Some(slot) = prepared.custody_slot.take() else {
            return Err(ConformanceRuntimeFailure::retained(
                "original collection custody slot is unavailable",
                prepared,
            ));
        };
        let nodes = std::mem::take(&mut prepared.nodes);
        let graph = Rc::new(graph);
        let runtime = NodeRuntime::new_for_purpose(
            &graph.graph,
            nodes,
            prepared.activation.clone(),
            prepared.limits,
            slot,
            Some(Rc::clone(&graph)),
        )
        .map_err(|failure| ConformanceRuntimeFailure {
            reason: failure.error.to_string(),
            _retained: None,
            _preparation: Some(failure),
        })?;
        Ok(Self {
            graph,
            runtime,
            activation: None,
            quantized,
        })
    }

    /// Collects authentic readiness from every original native owner.
    ///
    /// # Errors
    /// Refuses revoked/changed collection authority or incomplete actual readiness.
    pub fn arm_all(&mut self) -> Result<(), RuntimeError> {
        self.current()?;
        self.runtime.arm_all()?;
        self.current()
    }

    /// Extracts and durably publishes the same genuine initial collecting world.
    ///
    /// The original complete native Arm records and coordinator are read only
    /// after every owner authenticates initial state. The installed publisher
    /// retains their exact finite bodies before the same runtime's activation.
    /// Neither graph access nor reusable ordinary readiness escapes this owner.
    ///
    /// # Errors
    /// Refuses changed plan/source, missing native preparation, restored state,
    /// exhausted coordinator bytes, unavailable durable storage or uncertain
    /// publication. The same original runtime and receipts remain retained.
    pub fn activate_initial(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        if self.activation.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let coordinator = self
            .runtime
            .initial_coordinator_snapshot(&self.graph.graph, maximum_record_bytes)?;
        // Full extraction bounds every original preparation before its owned
        // copy; an opaque Ready label cannot substitute for these native rows.
        let nodes = self.runtime.prepared_node_records()?.to_vec();
        self.current()?;
        publisher.retain_initial_coordinator(
            self.runtime.original_preparation_record(),
            nodes,
            coordinator,
        )?;
        self.current()?;
        self.activate(publisher)
    }

    /// Durably publishes the actual collection world without returning ordinary authority.
    ///
    /// # Errors
    /// Refuses failed current fixture authority, incomplete readiness or uncertain
    /// original publication. The same owner remains retained on every failure.
    pub fn activate(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        if self.activation.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.activation = Some(self.runtime.activate_collection(&self.graph, publisher)?);
        self.current()
    }

    /// Reserves and submits one authentic original exact collection grant.
    ///
    /// # Errors
    /// Refuses changed plan/source/request, missing activation, duplicate original
    /// operation, unsafe causal progress, unsupported mode or exhausted credit.
    pub fn begin_exact(
        &mut self,
        node: &Id,
        operation: Id,
        horizon: U64,
    ) -> Result<BeginResult, RuntimeError> {
        self.current()?;
        let activation = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let admission = self
            .runtime
            .scheduler(&self.graph.graph, activation)?
            .admit_exact(node, operation, horizon)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        let authenticated = self
            .graph
            .authenticate_operation(node, admission.operation(), &admission.request())
            .map_err(|error| RuntimeError::SchedulerRefused(error.message));
        let authenticated = authenticated.and_then(|()| self.native_current());
        if let Err(error) = authenticated {
            // This is the same original no-effect scheduler reservation, not a
            // retry or a replacement grant. Clear only that authentic reservation.
            self.runtime
                .scheduler(
                    &self.graph.graph,
                    self.activation.as_ref().ok_or(RuntimeError::NotActivated)?,
                )?
                .reconcile_no_effect(&admission)
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
            return Err(error);
        }
        self.runtime.begin_admitted(admission)
    }

    /// Polls the same retained original operation without submitting another Begin.
    ///
    /// # Errors
    /// Returns a refused poll on revoked plan/source scope, foreign token or invalid
    /// native result; all original native/runtime obligations remain retained.
    pub fn poll(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, RuntimePollFailure>> {
        if let Err(error) = self.current_operation(token) {
            return Poll::Ready(Err(RuntimePollFailure::Admission(error)));
        }
        self.runtime.poll(token, context)
    }

    /// Borrows the actual original completion for bounded independent collection.
    ///
    /// # Errors
    /// Refuses changed current scope, foreign tokens or incomplete native results.
    pub fn original_completed_operation(
        &mut self,
        token: &OperationToken,
    ) -> Result<OriginalCompletedOperation<'_>, RuntimeError> {
        self.current_operation(token)?;
        self.runtime.original_completed_operation(token)
    }

    /// Borrows the restricted original-evidence facade under current collection custody.
    ///
    /// # Errors
    /// Refuses revoked plan/world/source authority or changed actual native
    /// ownership. The witness exposes no runtime, activation or execution getter.
    pub fn original_witness(&mut self) -> Result<OriginalRuntimeWitness<'_>, RuntimeError> {
        self.current()?;
        Ok(self.runtime.original_witness())
    }

    /// Reconciles durable original bodies, commits original scheduling, then ACKs once.
    ///
    /// # Errors
    /// Refuses missing/uncertain current durable roots, foreign tokens, invalid
    /// original scheduling or native ACK uncertainty. Retry retains the same
    /// operation and never reruns its native callbacks or semantic publication.
    pub fn publish_and_acknowledge(
        &mut self,
        token: &OperationToken,
        publisher: &mut dyn ConformanceResultPublisher,
    ) -> Result<(), RuntimePollFailure> {
        self.current_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        let original = self
            .runtime
            .original_completed_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        self.graph.authenticate_current_scope().map_err(|error| {
            RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.message))
        })?;
        if publisher
            .publish_original(self.graph.plan().evidence(), &original)
            .map_err(RuntimePollFailure::Admission)?
            != PublicationStatus::Committed
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        self.current_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        let receipt = self
            .runtime
            .scheduling_receipt(token)
            .map_err(RuntimePollFailure::Admission)?;
        let commit = self
            .runtime
            .commit_scheduling_receipt(receipt)
            .map_err(RuntimePollFailure::Admission)?;
        self.runtime.acknowledge_scheduled(token, &commit)
    }

    fn current_operation(&mut self, token: &OperationToken) -> Result<(), RuntimeError> {
        self.current()?;
        let original = self.runtime.collection_admission(token)?;
        self.graph
            .authenticate_operation(
                &original.token().route().node,
                original.token().operation(),
                original.request(),
            )
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        self.native_current()
    }

    fn current(&mut self) -> Result<(), RuntimeError> {
        self.graph
            .reauthenticate()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        self.native_current()
    }

    fn native_current(&mut self) -> Result<(), RuntimeError> {
        self.runtime
            .validate_collection_custody(self.graph.plan())?;
        self.graph
            .authenticate_current_scope()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))
    }
}
