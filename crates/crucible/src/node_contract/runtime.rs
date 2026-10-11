//! Exclusive owner routing, retained operation custody and receipt validation.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{Id, NodeBinding, NodeDescriptor, NodeId, OperationId};

use super::{
    ActivationPublisher, ActivationRecord, BeginResult, CancelStatus, EffectKnowledge, FacetKind,
    Lifecycle, NodeFacet, NodeRoute, OperationAdmission, OperationFailure, OperationOutcome,
    OperationRequest, OperationToken, OwnerIdentity, QuarantinedRuntime, RuntimeError,
    RuntimeLimits, SimulationNode, Submission, ValidatedNodePreparation, WorldActivation,
    activation::ActivationBarrier,
    validation::{valid_outcome, validate_request, validate_roster},
};

#[path = "runtime/conformance_dispatch.rs"]
mod conformance_dispatch;

use conformance_dispatch::final_collection_scope;

struct OwnerCustody {
    identity: OwnerIdentity,
    lifecycle: Lifecycle,
    operation: Option<OperationId>,
    domains: std::collections::BTreeSet<Id>,
}

enum RetainedResult {
    Pending,
    Complete(OperationOutcome),
    Failed(OperationFailure),
    Acknowledged(OperationOutcome),
}

struct RetainedOperation {
    admission: OperationAdmission,
    result: RetainedResult,
    close_submission: Option<Submission>,
    submission_effects: Option<EffectKnowledge>,
    scheduling_commit: Option<crate::node_scheduling::SchedulingCommit>,
}

struct NodeSnapshot {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    facets: Vec<FacetKind>,
    thread_affinity: super::ThreadAffinity,
}

impl NodeSnapshot {
    fn validate_current(&self, node: &dyn SimulationNode) -> Result<(), RuntimeError> {
        if !self.thread_affinity.permits_current_thread() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if node.descriptor() != &self.descriptor
            || node.binding() != &self.binding
            || node.route() != &self.route
            || node.facets() != self.facets
            || node.thread_affinity() != self.thread_affinity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

// Native validation hooks may expose changed declarations through interior
// state. Recheck the frozen admission before and after all readiness effects.
fn prepare_node_for_activation(
    node: &mut dyn SimulationNode,
    snapshot: &NodeSnapshot,
    record: &ActivationRecord,
    bindings: &BTreeMap<Id, Vec<crucible_node_contract::HashRef>>,
    collecting: Option<&crate::node_admission::ConformanceGraph>,
) -> Result<ValidatedNodePreparation, RuntimeError> {
    snapshot.validate_current(node)?;
    final_collection_scope(collecting)?;
    let readiness = node.arm(record).map_err(|_| RuntimeError::InvalidReceipt)?;
    snapshot.validate_current(node)?;
    if readiness.owners != snapshot.route.owners
        || readiness.boundary != record.boundary
        || node.validate_readiness(record, &readiness).is_err()
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    let owners = node
        .prepared_owners(record, &readiness)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if let Some(owners) = &owners {
        node.validate_prepared_owners(record, &readiness, owners)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    snapshot.validate_current(node)?;

    let preparation = ValidatedNodePreparation {
        node: snapshot.route.node.clone(),
        readiness,
        prepared_owners: owners,
    };
    super::activation_preparation::validate_owner_mapping(&preparation, bindings)?;
    final_collection_scope(collecting)?;
    Ok(preparation)
}

/// Owns admitted heterogeneous nodes and serializes all shared-owner mutations.
///
/// The ledger retains terminal results and unresolved publications independently
/// of caller tokens. Cancellation, timeout, lost replies and token drops never
/// release an owner. No public accessor returns mutable node handles.
///
/// Native adapters must retain resource supervision through their own drop
/// paths; this routing registry does not make process handles disposable.
pub struct NodeRuntime {
    authority: Rc<()>,
    nodes: BTreeMap<NodeId, Box<dyn SimulationNode>>,
    snapshots: BTreeMap<NodeId, NodeSnapshot>,
    owners: BTreeMap<Id, OwnerCustody>,
    operations: BTreeMap<OperationId, RetainedOperation>,
    input_batches: BTreeMap<Id, inputs::RetainedInput>,
    barrier: ActivationBarrier,
    activated: bool,
    limits: RuntimeLimits,
    scheduler: Option<crate::node_scheduling::CausalScheduler>,
    custody_slot: Option<Box<dyn RuntimeCustodySlot>>,
    terminal: Option<super::terminal::TerminalState>,
    condition_stop: Option<super::condition_debug::ConditionStopState>,
    collecting: Option<Rc<crate::node_admission::ConformanceGraph>>,
    // Fixed before any graceful adapter callback, including unsupported reads.
    pub(super) graceful_retirement: bool,
}

impl NodeRuntime {
    pub(super) fn collection_admission(
        &self,
        token: &OperationToken,
    ) -> Result<&OperationAdmission, RuntimeError> {
        self.validate_token(token)?;
        self.operations
            .get(token.operation())
            .map(|entry| &entry.admission)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(super) fn validate_collection_custody(
        &mut self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.validate_all_declarations()?;
        for node in self.nodes.values() {
            node.validate_collection_scope(plan)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        Ok(())
    }

    /// Constructs an inactive runtime from the complete admitted realized graph.
    ///
    /// All descriptors and bindings must equal the graph's admission snapshot.
    /// Native handles remain retained in the returned error on refusal.
    ///
    /// # Errors
    /// Returns the supplied native handles with an admission error when bindings,
    /// routes, owner incarnations or the complete activation roster mismatch.
    pub fn new(
        graph: &crate::node_admission::AdmittedGraph,
        nodes: Vec<Box<dyn SimulationNode>>,
        activation: ActivationRecord,
        limits: RuntimeLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
    ) -> Result<Self, Box<RuntimePreparationFailure>> {
        Self::new_for_purpose(graph, nodes, activation, limits, custody_slot, None)
    }

    pub(super) fn new_for_purpose(
        graph: &crate::node_admission::AdmittedGraph,
        nodes: Vec<Box<dyn SimulationNode>>,
        activation: ActivationRecord,
        limits: RuntimeLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
        collecting: Option<Rc<crate::node_admission::ConformanceGraph>>,
    ) -> Result<Self, Box<RuntimePreparationFailure>> {
        if graph.collecting != collecting.is_some()
            || collecting
                .as_ref()
                .is_some_and(|scope| !std::ptr::eq(&scope.graph, graph))
            || nodes
                .iter()
                .any(|node| node.collection_scope().is_some() != collecting.is_some())
        {
            return Err(RuntimePreparationFailure::retain(
                RuntimeError::ForeignAuthority,
                nodes,
                activation,
                limits,
                custody_slot,
            ));
        }
        if let Err(error) = custody_slot.validate_world(&activation, limits) {
            return Err(RuntimePreparationFailure::retain(
                error,
                nodes,
                activation,
                limits,
                custody_slot,
            ));
        }
        if nodes.len() > limits.maximum_nodes || activation.owners.len() > limits.maximum_owners {
            return Err(RuntimePreparationFailure::retain(
                RuntimeError::ResourceLimit,
                nodes,
                activation,
                limits,
                custody_slot,
            ));
        }
        if let Err(error) = validate_roster(graph, &nodes, &activation) {
            return Err(RuntimePreparationFailure::retain(
                error,
                nodes,
                activation,
                limits,
                custody_slot,
            ));
        }

        let barrier = match ActivationBarrier::new(activation.clone()) {
            Ok(barrier) => barrier,
            Err(error) => {
                return Err(RuntimePreparationFailure::retain(
                    error,
                    nodes,
                    activation,
                    limits,
                    custody_slot,
                ));
            }
        };
        let mut owners = BTreeMap::new();
        for identity in activation.owners.iter().cloned() {
            let Some(binding) = graph.owner(&identity.owner) else {
                return Err(RuntimePreparationFailure::retain(
                    RuntimeError::InvalidRoute,
                    nodes,
                    activation,
                    limits,
                    custody_slot,
                ));
            };
            let domains = binding.owner.state_domain_ids.iter().cloned().collect();
            owners.insert(
                identity.owner.clone(),
                OwnerCustody {
                    domains,
                    identity,
                    lifecycle: Lifecycle::Prepared,
                    operation: None,
                },
            );
        }
        let snapshots = nodes
            .iter()
            .map(|node| {
                (
                    node.route().node.clone(),
                    NodeSnapshot {
                        descriptor: node.descriptor().clone(),
                        binding: node.binding().clone(),
                        route: node.route().clone(),
                        facets: node.facets().to_vec(),
                        thread_affinity: node.thread_affinity(),
                    },
                )
            })
            .collect();
        let nodes = nodes
            .into_iter()
            .map(|node| (node.route().node.clone(), node))
            .collect();

        Ok(Self {
            authority: Rc::new(()),
            nodes,
            snapshots,
            owners,
            operations: BTreeMap::new(),
            input_batches: BTreeMap::new(),
            barrier,
            activated: false,
            limits,
            scheduler: None,
            custody_slot: Some(custody_slot),
            terminal: None,
            condition_stop: None,
            collecting,
            graceful_retirement: false,
        })
    }

    /// Stages authentic provider readiness for every owner without execution.
    ///
    /// Providers sharing an owner must make repeated arming idempotent. A failed
    /// or inconsistent attestation contains the affected native owner roster.
    ///
    /// # Errors
    /// Returns a native staging failure or invalid attestation. No execution
    /// permission is issued, and all handles remain under runtime custody.
    pub fn arm_all(&mut self) -> Result<(), RuntimeError> {
        if self.activated
            || !self.barrier.can_arm()
            || self
                .owners
                .values()
                .any(|owner| owner.lifecycle != Lifecycle::Prepared)
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let record = self.barrier.record().clone();
        // Reserve preparation custody and compute the complete alias inventory
        // before the first native arm. No adapter supplies its own binding scope.
        let mut ready = Vec::new();
        ready
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut bindings = BTreeMap::<Id, Vec<crucible_node_contract::HashRef>>::new();
        for snapshot in self.snapshots.values() {
            let binding = snapshot
                .binding
                .identity()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            for owner in &snapshot.route.owners {
                bindings
                    .entry(owner.owner.clone())
                    .or_default()
                    .push(binding.clone());
            }
        }
        for hashes in bindings.values_mut() {
            hashes.sort_by(|left, right| {
                (&left.domain, &left.digest).cmp(&(&right.domain, &right.digest))
            });
            hashes.dedup();
        }
        let collecting = self.collecting.as_deref();
        for (node_id, node) in &mut self.nodes {
            let Some(snapshot) = self.snapshots.get(node_id) else {
                self.barrier.abandon(ready);
                return Err(RuntimeError::UnknownNode);
            };
            let original_route = snapshot.route.clone();
            match prepare_node_for_activation(
                node.as_mut(),
                snapshot,
                &record,
                &bindings,
                collecting,
            ) {
                Ok(preparation) => ready.push(preparation),
                Err(error) => {
                    self.barrier.abandon(ready);
                    self.contain_roster(&original_route);
                    return Err(error);
                }
            }
        }

        if self
            .barrier
            .prepared_nodes()
            .is_ok_and(|original| original != ready)
        {
            self.barrier.abandon(ready);
            self.contain_roster(&NodeRoute {
                node: record.activation_id,
                owners: record.owners,
            });
            return Err(RuntimeError::InvalidReceipt);
        }
        self.barrier.ready(ready)
    }

    // This borrowed record stays inside the opaque collecting owner. It avoids
    // copying owner scope merely to publish the same authentic initial body.
    pub(super) fn original_preparation_record(&self) -> &ActivationRecord {
        self.barrier.record()
    }

    /// Borrows complete original readiness for preparing durable coordinator state.
    ///
    /// These data records grant no execution or publication authority.
    ///
    /// # Errors
    /// Refuses incomplete, abandoned, already published or uncertain preparation.
    pub fn prepared_node_records(&self) -> Result<&[ValidatedNodePreparation], RuntimeError> {
        self.barrier.prepared_nodes()
    }

    pub(crate) fn reconcile_contained_publication(
        &mut self,
        record: &ActivationRecord,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<super::PublicationStatus, RuntimeError> {
        self.barrier.reconcile_contained(record, publisher)
    }

    /// Durably publishes complete world readiness and mints local authority.
    ///
    /// # Errors
    /// Refuses incomplete readiness. Failed or uncertain publication retains the
    /// staged world without execution permission and requires reconciliation.
    pub fn activate(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        if !self.activated
            && self
                .owners
                .values()
                .any(|owner| owner.lifecycle != Lifecycle::Prepared)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.validate_all_declarations()?;
        let activation = self.barrier.publish(&self.authority, publisher)?;
        self.finish_activation();
        Ok(activation)
    }

    /// Reconciles the original uncertain durable world publication.
    ///
    /// # Errors
    /// Refuses a known noncommitted, unattempted or still uncertain publication.
    pub fn reconcile_activation(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        self.validate_all_declarations()?;
        let activation = self.barrier.reconcile(&self.authority, publisher)?;
        self.finish_activation();
        Ok(activation)
    }

    fn finish_activation(&mut self) {
        self.activated = true;
        for owner in self.owners.values_mut() {
            if owner.lifecycle == Lifecycle::Prepared {
                owner.lifecycle = Lifecycle::Stopped;
            }
        }
    }

    /// Borrows the single retained causal scheduler for this complete world.
    ///
    /// Repeated calls recover the same scheduler and its original cursors, input
    /// queues and reservations. Borrower cancellation cannot reset authority or
    /// mint an independent scheduler from a cloned activation token.
    ///
    /// # Errors
    /// Refuses foreign activation or world binding and incompatible scheduling
    /// contracts before issuing any execution permission.
    pub fn scheduler(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
    ) -> Result<&mut crate::node_scheduling::CausalScheduler, RuntimeError> {
        self.validate_activation(activation)?;
        if self.terminal.is_some() || self.condition_fenced() {
            return Err(RuntimeError::OutstandingObligations);
        }
        if graph.world_binding_hash() != &activation.record.world_binding_hash {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.scheduler.is_none() {
            let scheduler = crate::node_scheduling::CausalScheduler::new(graph, activation.clone())
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
            self.scheduler = Some(scheduler);
        }

        self.scheduler.as_mut().ok_or(RuntimeError::NotActivated)
    }

    pub(crate) fn install_restored_scheduler(
        &mut self,
        activation: &WorldActivation,
        scheduler: crate::node_scheduling::CausalScheduler,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(activation)?;
        self.validate_activation(scheduler.activation())?;
        if self.scheduler.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.scheduler = Some(scheduler);
        Ok(())
    }

    /// Polls and validates original evidence before permitting publication.
    ///
    /// Terminal results remain cached, and owners remain reserved until their
    /// retained publication and boundary obligations are acknowledged.
    ///
    /// # Errors
    /// Refuses foreign tokens. Invalid receipts quarantine their original owners;
    /// native failures retain classified effects and completion custody.
    pub fn poll(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, RuntimePollFailure>> {
        if let Err(error) = self.validate_token(token) {
            return Poll::Ready(Err(RuntimePollFailure::Admission(error)));
        }
        let entry = match self.operations.get(token.operation()) {
            Some(entry) => entry,
            None => {
                return Poll::Ready(Err(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                )));
            }
        };
        match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => {
                return Poll::Ready(Ok(outcome.clone()));
            }
            RetainedResult::Failed(failure) => {
                return Poll::Ready(Err(RuntimePollFailure::Native(failure.clone())));
            }
            RetainedResult::Pending => {}
        }
        let admission = entry.admission.clone();
        let close_requested = entry.close_submission.is_some();
        if let Err(error) = final_collection_scope(self.collecting.as_deref()) {
            return Poll::Ready(Err(RuntimePollFailure::Admission(error)));
        }
        let result = match self.nodes.get_mut(&token.route.node) {
            Some(handle) => handle.poll_operation(token, context),
            None => {
                return Poll::Ready(Err(RuntimePollFailure::Admission(
                    RuntimeError::UnknownNode,
                )));
            }
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(outcome)) => {
                let native_evidence_valid = self
                    .nodes
                    .get(&token.route.node)
                    .is_some_and(|handle| handle.validate_outcome(&admission, &outcome).is_ok());
                let quantum_closed =
                    !matches!(admission.request, OperationRequest::QuantumBegin { .. })
                        || close_requested;
                if outcome.retained_outputs.len() > self.limits.maximum_retained_outputs
                    || !quantum_closed
                    || !native_evidence_valid
                    || !valid_outcome(&admission, &outcome)
                {
                    self.contain_roster(token.route());
                    let failure = OperationFailure {
                        effects: EffectKnowledge::Unknown,
                        reason: "invalid original operation receipt".into(),
                    };
                    if let Some(entry) = self.operations.get_mut(token.operation()) {
                        entry.result = RetainedResult::Failed(failure);
                    }
                    return Poll::Ready(Err(RuntimePollFailure::Admission(
                        RuntimeError::InvalidReceipt,
                    )));
                }
                if let Some(entry) = self.operations.get_mut(token.operation()) {
                    entry.result = RetainedResult::Complete(outcome.clone());
                }
                Poll::Ready(Ok(outcome))
            }
            Poll::Ready(Err(failure)) => {
                self.contain_roster(token.route());
                if let Some(entry) = self.operations.get_mut(token.operation()) {
                    entry.result = RetainedResult::Failed(failure.clone());
                }
                Poll::Ready(Err(RuntimePollFailure::Native(failure)))
            }
        }
    }

    /// Requests termination while retaining the original owner reservation.
    ///
    /// # Errors
    /// Refuses foreign tokens or reports native failure without releasing custody.
    pub fn cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        if self
            .operations
            .get(token.operation())
            .is_some_and(|entry| !matches!(entry.result, RetainedResult::Pending))
        {
            return Ok(CancelStatus::Terminal);
        }

        final_collection_scope(self.collecting.as_deref())
            .map_err(RuntimePollFailure::Admission)?;
        self.nodes
            .get_mut(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .request_cancel(token)
            .map_err(RuntimePollFailure::Native)
    }

    /// Closes the original quantized window without submitting another run.
    ///
    /// # Errors
    /// Refuses foreign tokens, nonquantized operations and terminal windows. An
    /// uncertain close contains the same owners and preserves original custody.
    pub fn close_quantum(&mut self, token: &OperationToken) -> Result<Submission, RuntimeError> {
        self.validate_token(token)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !matches!(
            entry.admission.request,
            OperationRequest::QuantumBegin { .. }
        ) || !matches!(entry.result, RetainedResult::Pending)
        {
            return Err(RuntimeError::InvalidTiming);
        }
        if let Some(original) = &entry.close_submission {
            return Ok(original.clone());
        }

        let admission = entry.admission.clone();
        final_collection_scope(self.collecting.as_deref())?;
        let result = self
            .nodes
            .get_mut(&token.route.node)
            .ok_or(RuntimeError::UnknownNode)?
            .close_quantum(&admission);
        if !matches!(result, Submission::Refused(_))
            && let Some(entry) = self.operations.get_mut(token.operation())
        {
            entry.close_submission = Some(result.clone());
        }
        if matches!(result, Submission::Uncertain(_)) {
            self.contain_roster(token.route());
        }
        Ok(result)
    }

    /// Acknowledges the exact retained output inventory without rerunning work.
    ///
    /// The caller must have completed canonical coordinator publication. This
    /// method only settles native custody and cannot select publication order.
    ///
    /// # Errors
    /// Refuses pending or failed operations and changed output inventories. Native
    /// acknowledgement failure retains the complete original obligation.
    pub(crate) fn acknowledge(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let outcome = match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome)
                if outcome.retained_outputs == outputs =>
            {
                outcome.clone()
            }
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        if matches!(entry.result, RetainedResult::Acknowledged(_)) {
            return Ok(());
        }

        final_collection_scope(self.collecting.as_deref())
            .map_err(RuntimePollFailure::Admission)?;
        self.nodes
            .get_mut(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .acknowledge_publication(token, outputs)
            .map_err(RuntimePollFailure::Native)?;
        if let Some(entry) = self.operations.get_mut(token.operation()) {
            entry.result = RetainedResult::Acknowledged(outcome);
        }
        self.release_reservation(token);
        Ok(())
    }

    /// Settles native custody using the coordinator's opaque original commit.
    ///
    /// Caller-created output identifiers cannot authorize this operation. The
    /// borrowed commit remains available for idempotent retries after native
    /// acknowledgement failure; retrying never republishes semantic outputs.
    ///
    /// # Errors
    /// Refuses foreign activation, node or operation associations, incomplete
    /// native receipts and mismatched retained output inventories.
    pub fn acknowledge_scheduled(
        &mut self,
        token: &OperationToken,
        commit: &crate::node_scheduling::SchedulingCommit,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_activation(commit.activation())
            .map_err(RuntimePollFailure::Admission)?;
        if commit.node() != &token.route.node || commit.operation() != token.operation() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }

        let retained = self
            .operations
            .get(token.operation())
            .and_then(|entry| entry.scheduling_commit.as_ref())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ))?;
        if retained.node() != commit.node()
            || retained.operation() != commit.operation()
            || retained.retained_outputs() != commit.retained_outputs()
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        self.acknowledge(token, commit.retained_outputs())
    }

    /// Acquires one explicitly advertised observation-only facet.
    ///
    /// # Errors
    /// Refuses unknown nodes, unsupported or incorrectly returned facet kinds.
    pub fn facet(&mut self, node: &NodeId, kind: FacetKind) -> Result<NodeFacet<'_>, RuntimeError> {
        if self.condition_fenced() && kind != FacetKind::Debugging {
            return Err(RuntimeError::OutstandingObligations);
        }
        if self.terminal.is_some() && kind != FacetKind::TerminalAssertions {
            return Err(RuntimeError::OutstandingObligations);
        }
        let handle = self.nodes.get_mut(node).ok_or(RuntimeError::UnknownNode)?;
        if !handle.facets().contains(&kind) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let selected_profiles: Vec<_> = handle
            .binding()
            .compatibility
            .operating_contract
            .facets
            .iter()
            .map(|facet| facet.id.clone())
            .collect();
        let facet = handle
            .facet(kind)
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        if facet.kind() != kind || !selected_profiles.contains(facet.profile()) {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(facet)
    }

    /// Returns retained owner lifecycle without inferring physical suspension.
    pub fn owner_lifecycle(&self, owner: &Id) -> Option<Lifecycle> {
        self.owners.get(owner).map(|entry| entry.lifecycle)
    }

    /// Reports current native activity without releasing retained owner custody.
    ///
    /// An unknown physical status remains unknown. The observation cannot prove
    /// output closure, settle publication or acknowledge physical pause requests.
    ///
    /// # Errors
    /// Refuses unknown or changed bindings, and reports native observation failure
    /// while retaining all outstanding operations and resource obligations.
    pub fn status(&mut self, node: &NodeId) -> Result<super::NodeStatus, RuntimePollFailure> {
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        let mut status = self
            .nodes
            .get_mut(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .status()
            .map_err(RuntimePollFailure::Native)?;
        if matches!(
            status.lifecycle,
            Lifecycle::FailedContained | Lifecycle::Quarantined
        ) {
            self.contain_roster(&route);
        }
        let lifecycles: Vec<_> = route
            .owners
            .iter()
            .filter_map(|owner| self.owner_lifecycle(&owner.owner))
            .collect();
        status.lifecycle = if lifecycles.contains(&Lifecycle::Quarantined) {
            Lifecycle::Quarantined
        } else if lifecycles.contains(&Lifecycle::Executing) {
            Lifecycle::Executing
        } else if lifecycles
            .iter()
            .all(|lifecycle| *lifecycle == Lifecycle::Released)
        {
            Lifecycle::Released
        } else if lifecycles.contains(&Lifecycle::Prepared) {
            Lifecycle::Prepared
        } else {
            Lifecycle::Stopped
        };
        Ok(status)
    }

    /// Transfers the complete world into retained containment without rollback.
    ///
    /// The returned owner keeps original operations, effect evidence, native
    /// handles and scheduler custody while revoking ordinary execution access.
    pub fn into_quarantine(mut self) -> QuarantinedRuntime {
        for owner in self.owners.values_mut() {
            if owner.lifecycle != Lifecycle::Released {
                owner.lifecycle = Lifecycle::Quarantined;
            }
        }
        for node in self.nodes.values_mut() {
            node.quarantine_resources();
        }

        QuarantinedRuntime {
            runtime: self,
            cursor: None,
            shutdown_failure: None,
            retirement_transferred: false,
        }
    }

    /// Takes an original capsule only after every adapter supports graceful cleanup.
    ///
    /// An unsupported owner retains the caller's same runtime slot, fenced
    /// for retirement. Every native/model handle and original ledger remains owned.
    /// Each selected adapter receives its original Shutdown hook once; a lost
    /// reply remains held in the returned capsule without signaling fallback.
    /// The caller must independently authenticate the installed cleanup scope.
    /// Actual native reclamation alone never authorizes state or history discard.
    ///
    /// # Errors
    /// Refuses an empty slot or an unsupported actual adapter. An occupied
    /// slot is fenced for retirement before adapter reads; no Shutdown frame
    /// is sent until every actual adapter supports the selected hook.
    pub fn take_graceful_retirement(
        original: &mut Option<Self>,
    ) -> Result<QuarantinedRuntime, RuntimeError> {
        let runtime = original
            .as_mut()
            .ok_or(RuntimeError::OutstandingObligations)?;
        // Purpose is an infallible world-level custody fact. A panic in even
        // the first adapter cannot expose legacy signaling in runtime Drop.
        runtime.graceful_retirement = true;
        for owner in runtime.owners.values_mut() {
            if owner.lifecycle != Lifecycle::Released {
                owner.lifecycle = Lifecycle::Quarantined;
            }
        }
        if runtime
            .nodes
            .values()
            .any(|node| !node.graceful_retirement_available())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut runtime = original
            .take()
            .ok_or(RuntimeError::OutstandingObligations)?;
        let mut failure = None;
        for node in runtime.nodes.values_mut() {
            if let Err(error) = node.shutdown_resources()
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        Ok(QuarantinedRuntime {
            runtime,
            cursor: None,
            shutdown_failure: failure,
            retirement_transferred: false,
        })
    }

    pub(super) fn transfer_reclaimed_adapters(&mut self) -> Result<(), RuntimeError> {
        for node in self.nodes.values_mut() {
            node.transfer_retirement_resources()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
        }
        Ok(())
    }

    /// Reads the existing original scheduler without initializing or advancing it.
    ///
    /// This operational history retains unresolved queues and original cursors;
    /// it grants no capture, scheduling, continuation or release permission.
    ///
    /// # Errors
    /// Refuses foreign activation, an absent original scheduler or invalid
    /// snapshot geometry while retaining the same owning runtime.
    pub fn retirement_scheduler_snapshot(
        &self,
        activation: &WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
    ) -> Result<crate::node_scheduling::SchedulingSnapshot, RuntimeError> {
        self.validate_activation(activation)?;
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .snapshot(cut, ordinal)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    /// Reads complete original adapter histories within prebirth aggregate credit.
    ///
    /// Every actual adapter's upper bound is charged before the first history
    /// reader is called. The result retains operational bodies only and grants
    /// no execution, capture, restoration or native resource-release authority.
    ///
    /// # Errors
    /// Refuses unsupported adapters, exhausted aggregate credit, changed routes
    /// or nonmatching original full-content bodies while retaining this runtime.
    pub fn retirement_histories(
        &self,
        activation: &WorldActivation,
        maximum_total_bytes: usize,
    ) -> Result<Vec<super::RetainedRetirementHistory>, RuntimeError> {
        self.validate_activation(activation)?;
        if self.nodes.is_empty()
            || self.nodes.len() > 64
            || maximum_total_bytes == 0
            || maximum_total_bytes > 2 * 1024 * 1024 * 1024
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.nodes.values().try_fold(0usize, |total, node| {
            let credit = node
                .retirement_history_credit()
                .ok_or(RuntimeError::UnsupportedFacet)?;
            total
                .checked_add(credit)
                .filter(|total| *total <= maximum_total_bytes)
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        let mut histories = Vec::new();
        histories
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for (node_id, node) in &self.nodes {
            let maximum = node
                .retirement_history_credit()
                .ok_or(RuntimeError::UnsupportedFacet)?;
            let bodies = node
                .retirement_history(maximum)
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            if node.route().node != *node_id || bodies.is_empty() || bodies.len() > 16 {
                return Err(RuntimeError::InvalidRoute);
            }
            bodies.iter().try_fold(0usize, |total, object| {
                object
                    .reference
                    .verify(&object.bytes)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                total
                    .checked_add(object.bytes.len())
                    .filter(|total| *total <= maximum)
                    .ok_or(RuntimeError::ResourceLimit)
            })?;
            histories.push(super::RetainedRetirementHistory {
                route: node.route().clone(),
                bodies,
            });
        }
        Ok(histories)
    }

    pub(crate) fn unreleased_owner_count(&self) -> usize {
        self.owners
            .values()
            .filter(|owner| owner.lifecycle != Lifecycle::Released)
            .count()
    }

    pub(crate) fn retained_observation(
        &self,
        operation: &OperationId,
    ) -> Option<super::RetainedOperationObservation> {
        use super::RetainedOperationObservation;

        self.operations
            .get(operation)
            .map(|entry| match &entry.result {
                RetainedResult::Pending => RetainedOperationObservation::Pending {
                    effects: entry.submission_effects.clone(),
                    close_submission: entry.close_submission.clone(),
                },
                RetainedResult::Complete(outcome) => RetainedOperationObservation::Complete {
                    outcome: Box::new(outcome.clone()),
                    acknowledged: false,
                },
                RetainedResult::Acknowledged(outcome) => RetainedOperationObservation::Complete {
                    outcome: Box::new(outcome.clone()),
                    acknowledged: true,
                },
                RetainedResult::Failed(failure) => {
                    RetainedOperationObservation::Failed(failure.clone())
                }
            })
    }

    pub(crate) fn poll_quarantined_reclamation(
        &mut self,
        cursor: &mut Option<Id>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), RuntimePollFailure>> {
        let unresolved = |(_, owner): &(&Id, &OwnerCustody)| owner.lifecycle != Lifecycle::Released;
        let next = self
            .owners
            .iter()
            .filter(unresolved)
            .find(|(id, _)| cursor.as_ref().is_none_or(|previous| *id > previous))
            .or_else(|| self.owners.iter().find(unresolved))
            .map(|(_, owner)| owner.identity.clone());
        let Some(identity) = next else {
            return Poll::Ready(Ok(()));
        };
        *cursor = Some(identity.owner.clone());
        let Some(node) = self
            .nodes
            .values_mut()
            .find(|node| node.route().owners.contains(&identity))
        else {
            return Poll::Ready(Err(RuntimePollFailure::Admission(
                RuntimeError::InvalidRoute,
            )));
        };

        match node.poll_reclamation(&identity, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(failure)) => Poll::Ready(Err(RuntimePollFailure::Native(failure))),
            Poll::Ready(Ok(receipt)) => {
                if receipt.owner != identity || node.validate_reclamation(&receipt).is_err() {
                    return Poll::Ready(Err(RuntimePollFailure::Admission(
                        RuntimeError::InvalidReceipt,
                    )));
                }
                if let Some(owner) = self.owners.get_mut(&identity.owner) {
                    owner.lifecycle = Lifecycle::Released;
                }
                if self.unreleased_owner_count() == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }

    pub(super) fn validate_activation(
        &self,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if !self.activated {
            return Err(RuntimeError::NotActivated);
        }
        if !Rc::ptr_eq(&self.authority, &activation.authority)
            || activation.record != *self.barrier.record()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn release_retired_custody_slot(&mut self) -> Result<(), RuntimeError> {
        if !self.graceful_retirement || self.unreleased_owner_count() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        // The installed release callback has already discharged durable history
        // and original supervisor custody. Dropping this unused mailbox handle
        // releases only the same runtime's reservation, without cleanup hooks.
        self.custody_slot.take();
        Ok(())
    }

    fn validate_all_declarations(&mut self) -> Result<(), RuntimeError> {
        if self.nodes.len() != self.snapshots.len() {
            return Err(RuntimeError::UnknownNode);
        }
        let changed = self.snapshots.iter().find_map(|(id, snapshot)| {
            let result = match self.nodes.get(id) {
                Some(node) => snapshot.validate_current(node.as_ref()),
                None => Err(RuntimeError::UnknownNode),
            };
            result.err().map(|error| (snapshot.route.clone(), error))
        });
        if let Some((route, error)) = changed {
            if error != RuntimeError::ThreadAffinity {
                self.contain_roster(&route);
            }
            return Err(error);
        }
        Ok(())
    }

    fn checked_route(&mut self, node: &NodeId) -> Result<NodeRoute, RuntimeError> {
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let original = snapshot.route.clone();
        if !snapshot.thread_affinity.permits_current_thread() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if handle.descriptor() != &snapshot.descriptor
            || handle.binding() != &snapshot.binding
            || handle.route() != &snapshot.route
            || handle.facets() != snapshot.facets
            || handle.thread_affinity() != snapshot.thread_affinity
        {
            self.contain_roster(&original);
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(original)
    }

    fn validate_token(&self, token: &OperationToken) -> Result<(), RuntimeError> {
        if !Rc::ptr_eq(&self.authority, &token.authority) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        if entry.admission.token.route != token.route {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn validate_owners_available(&self, route: &NodeRoute) -> Result<(), RuntimeError> {
        for identity in &route.owners {
            let owner = self
                .owners
                .get(&identity.owner)
                .ok_or(RuntimeError::InvalidRoute)?;
            if owner.identity != *identity {
                return Err(RuntimeError::ForeignAuthority);
            }
            if owner.operation.is_some() {
                return Err(RuntimeError::OwnerBusy);
            }
            if owner.lifecycle != Lifecycle::Stopped {
                return Err(RuntimeError::OwnerUnavailable);
            }
        }
        let domains = self.route_domains(route);
        for owner in self.owners.values() {
            if owner.domains.is_disjoint(&domains) {
                continue;
            }
            if owner.lifecycle == Lifecycle::Quarantined {
                return Err(RuntimeError::OwnerUnavailable);
            }
            if owner.operation.is_some() {
                return Err(RuntimeError::OwnerBusy);
            }
        }
        Ok(())
    }

    fn route_domains(&self, route: &NodeRoute) -> std::collections::BTreeSet<Id> {
        route
            .owners
            .iter()
            .filter_map(|owner| self.owners.get(&owner.owner))
            .flat_map(|owner| owner.domains.iter().cloned())
            .collect()
    }

    fn reserve(&mut self, token: &OperationToken) {
        for identity in &token.route.owners {
            if let Some(owner) = self.owners.get_mut(&identity.owner) {
                owner.operation = Some(token.operation.clone());
                owner.lifecycle = Lifecycle::Executing;
            }
        }
    }

    fn release_reservation(&mut self, token: &OperationToken) {
        for identity in &token.route.owners {
            if let Some(owner) = self.owners.get_mut(&identity.owner)
                && owner.operation.as_ref() == Some(token.operation())
            {
                owner.operation = None;
                if owner.lifecycle == Lifecycle::Executing {
                    owner.lifecycle = Lifecycle::Stopped;
                }
            }
        }
    }

    fn contain_roster(&mut self, route: &NodeRoute) {
        let mut affected: std::collections::BTreeSet<_> = route
            .owners
            .iter()
            .map(|owner| owner.owner.clone())
            .collect();
        let mut domains = self.route_domains(route);

        // An uncertain shared domain also taints its other native owners.
        // Expand the finite admitted ownership component before containment;
        // native aliases can span several otherwise distinct state domains.
        loop {
            let previous_count = affected.len();
            for (owner_id, owner) in &self.owners {
                if affected.contains(owner_id) || !owner.domains.is_disjoint(&domains) {
                    affected.insert(owner_id.clone());
                    domains.extend(owner.domains.iter().cloned());
                }
            }
            for snapshot in self.snapshots.values() {
                if snapshot
                    .route
                    .owners
                    .iter()
                    .any(|owner| affected.contains(&owner.owner))
                {
                    for identity in &snapshot.route.owners {
                        affected.insert(identity.owner.clone());
                        if let Some(owner) = self.owners.get(&identity.owner) {
                            domains.extend(owner.domains.iter().cloned());
                        }
                    }
                }
            }
            if previous_count == affected.len() {
                break;
            }
        }

        let mut newly_contained = std::collections::BTreeSet::new();
        for identity in affected {
            if let Some(owner) = self.owners.get_mut(&identity) {
                if owner.lifecycle != Lifecycle::Quarantined {
                    newly_contained.insert(identity);
                }
                owner.lifecycle = Lifecycle::Quarantined;
            }
        }

        // Logical refusal alone cannot contain a live native process. Use the
        // admitted snapshot rather than a potentially changed live route, and
        // retain all original operations and native reclamation obligations.
        for (node_id, snapshot) in &self.snapshots {
            if snapshot
                .route
                .owners
                .iter()
                .any(|owner| newly_contained.contains(&owner.owner))
                && let Some(node) = self.nodes.get_mut(node_id)
            {
                node.quarantine_resources();
            }
        }
    }
}

impl Drop for NodeRuntime {
    fn drop(&mut self) {
        self.transfer_whole_custody();
    }
}

/// Retains native handles when runtime admission fails without effects.
pub struct RuntimePreparationFailure {
    /// Unmet admission precondition.
    pub error: RuntimeError,
    /// Original native handles still requiring supervised cleanup.
    pub nodes: Vec<Box<dyn SimulationNode>>,
    /// Retains the exact proposed generation without granting local authority.
    pub original_activation: ActivationRecord,
    /// Retains the original complete preparation resource ceilings.
    pub limits: RuntimeLimits,
    custody_slot: Option<Box<dyn RuntimeCustodySlot>>,
}

impl RuntimePreparationFailure {
    pub(super) fn without_resources(
        error: RuntimeError,
        original_activation: ActivationRecord,
        limits: RuntimeLimits,
    ) -> Box<Self> {
        Box::new(Self {
            error,
            nodes: Vec::new(),
            original_activation,
            limits,
            custody_slot: None,
        })
    }

    pub(super) fn retain(
        error: RuntimeError,
        nodes: Vec<Box<dyn SimulationNode>>,
        original_activation: ActivationRecord,
        limits: RuntimeLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
    ) -> Box<Self> {
        Box::new(Self {
            error,
            nodes,
            original_activation,
            limits,
            custody_slot: Some(custody_slot),
        })
    }
}

impl Drop for RuntimePreparationFailure {
    fn drop(&mut self) {
        if let Some(slot) = self.custody_slot.take() {
            slot.retain(WholeRuntimeCustody::from_prepared(
                std::mem::take(&mut self.nodes),
                self.original_activation.clone(),
                self.limits,
            ));
        }
    }
}

/// Separates local authority errors from native failures with effect knowledge.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimePollFailure {
    /// Local admission or receipt validation failed.
    #[error("node runtime admission failed: {0}")]
    Admission(RuntimeError),
    /// Native effects remain classified and retained.
    #[error("native node operation failed: {}", .0.reason)]
    Native(OperationFailure),
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn test_original_admission(name: &str) -> OperationAdmission {
    tests::original_admission(name)
}

#[cfg(test)]
pub(crate) fn test_nodes(
    graph: &crate::node_admission::AdmittedGraph,
) -> Vec<Box<dyn SimulationNode>> {
    tests::test_nodes(graph)
}

#[cfg(test)]
pub(crate) fn test_custody_slot() -> Box<dyn RuntimeCustodySlot> {
    continuation::test_custody_slot()
}

#[path = "runtime_terminal.rs"]
mod terminal_runtime;

#[path = "runtime_dispatch.rs"]
mod dispatch;

#[path = "runtime_fault.rs"]
mod fault_runtime;

#[path = "runtime_inputs.rs"]
mod inputs;

#[path = "runtime_input_provenance.rs"]
mod input_provenance;

pub use input_provenance::{InputProvenanceClosure, InputProvenanceLimits, SavedInputProvenance};

mod initial;

mod conformance_activation;

#[path = "runtime_evidence.rs"]
mod evidence;

#[path = "runtime_original_completion.rs"]
mod original_completion;

pub use original_completion::OriginalCompletedOperation;

#[path = "runtime_original_witness.rs"]
mod original_witness;
pub use original_witness::OriginalRuntimeWitness;

#[path = "runtime_original_input_observation.rs"]
mod original_input_observation;

pub use original_input_observation::OriginalStagedInput;

#[path = "runtime_original_input_evidence.rs"]
mod original_input_evidence;
pub use original_input_evidence::OriginalInputEvidence;

#[path = "runtime_boundary_evidence.rs"]
mod boundary_evidence;

#[path = "runtime_continuation.rs"]
mod continuation;

pub use continuation::*;

#[path = "runtime_condition_debug.rs"]
mod condition_debug_runtime;

#[path = "runtime_original_input_lineage.rs"]
mod original_input_lineage;
pub use original_input_lineage::{
    OriginalInputLineage, OriginalInputLineageLimits, OriginalLineageInputRecord,
    OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
    OriginalLineageProvenanceRecord, OriginalLineageRestoration, OriginalLineageRestorationLimits,
    OriginalLineageRow, OriginalLineageRuntimeRecord, OriginalPublicationClaim,
    OriginalPublicationOrigin, SavedOriginalInputLineage, SavedOriginalInputScope,
    SavedOriginalPublication,
};
