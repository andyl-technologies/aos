//! Owns live collection-only runtime custody without an ordinary runtime escape.
//!
//! Only the opaque installed collection graph can create this owner. It retains
//! current plan authority through readiness, every original grant, polling and
//! result publication. It exposes no ordinary capture, restoration, cache, replay,
//! debugger, mutable runtime, or admitted-graph conversion. The separate guarded
//! complete-capture route retains collecting provenance and defaults to refusal.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{Direction, Id, OperatingMode, U64};

#[path = "conformance/quantized.rs"]
mod quantized;

#[path = "conformance/complete_capture.rs"]
mod complete_capture;
pub(crate) use complete_capture::OriginalCollectingCaptureScope;
pub use complete_capture::{
    CollectingCompleteRestorationSource, CollectingOriginalLineageCaptureRequest,
};

#[path = "conformance/exact_inputs.rs"]
mod exact_inputs;

#[path = "conformance/restoration_installation_storage.rs"]
mod restoration_installation_storage;

#[path = "conformance/construction_storage.rs"]
mod construction_storage;

use super::*;
use crate::node_admission::{ConformanceGraph, ConformancePlanEvidence, EvidenceError};

/// Retains a refused collecting constructor and its complete original native owners.
pub struct ConformanceRuntimeFailure {
    /// Describes the original refusal without claiming native reclamation.
    pub reason: String,
    _retained: Option<Box<PreparedRealization>>,
    _preparation: Option<Box<RuntimePreparationFailure>>,
    _runtime: Option<Box<NodeRuntime>>,
}

impl ConformanceRuntimeFailure {
    /// Transfers original failed native owners while retaining all preparation metadata.
    ///
    /// # Errors
    /// Refuses unsupported borrowed custody without dropping the failure.
    pub fn retire_original(&mut self) -> Result<(), RuntimeError> {
        if let Some(original) = self._retained.as_mut() {
            original.retire_original()?;
        }
        if let Some(original) = self._preparation.as_mut() {
            original.retire_original()?;
        }
        if let Some(original) = self._runtime.as_mut() {
            original.retire_collecting_original()?;
        }
        Ok(())
    }

    pub(crate) fn retained(reason: impl Into<String>, retained: PreparedRealization) -> Self {
        Self {
            reason: reason.into(),
            _retained: Some(Box::new(retained)),
            _preparation: None,
            _runtime: None,
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

// Initial and restored worlds have distinct lifecycle entry points. A restored
// runtime cannot activate its blank birth model through ordinary initial APIs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CollectionOrigin {
    Initial,
    CompleteRestoration,
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
    exact_inputs: Option<Rc<super::HostSchedulingSource>>,
    origin: CollectionOrigin,
}

impl ConformanceRuntime {
    pub(crate) fn authenticate_complete_original_restoration_origin(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.origin != CollectionOrigin::CompleteRestoration {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_restoration_target_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        if self.activation.is_some() || !self.graph.plan().is_same_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .authenticate_original_restoration_target_data(source, plan, activation)
    }

    /// Names fixed raw target/plan loan headers before original identity checks.
    ///
    /// This getter performs no callbacks or allocation and grants no restoration
    /// permission. Counter/recursive compiler frames remain separate.
    pub fn original_restoration_target_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&crate::node_state::CompleteOriginalRestorationSource>()
            + std::mem::size_of::<&crate::node_admission::InstalledConformancePlan>()
            + std::mem::size_of::<&ActivationRecord>()
            // authenticate_retained upgrades its actual original Weak authority.
            + std::mem::size_of::<Rc<()>>()
            + crate::node_state::CompleteOriginalSource::original_target_plan_counter_scratch_data()
    }

    fn authenticate_initial_origin(&self) -> Result<(), RuntimeError> {
        if self.origin != CollectionOrigin::Initial {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Attaches the actual host queue owner before collecting original readiness.
    ///
    /// The source-created node must already belong to this same complete graph;
    /// the retained attachment is the original runtime's actual lazy scheduler.
    ///
    /// # Errors
    /// Refuses foreign source/node/world, repeated attachment, initialized or
    /// activated runtime, revoked original custody or reentrant storage access.
    pub fn attach_host_scheduling_owner(
        &mut self,
        source: &Rc<super::HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        self.runtime.attach_host_scheduling_owner(source)?;
        self.current()
    }

    /// Borrows actual common-runtime scheduling facts under the original host owner.
    ///
    /// # Errors
    /// Refuses stale plan/native custody or a foreign original host attachment.
    pub fn host_scheduling_observation<'a>(
        &'a mut self,
        source: &'a super::HostSchedulingSource,
    ) -> Result<super::HostSchedulingObservation<'a>, RuntimeError> {
        self.current()?;
        super::HostSchedulingObservation::new(&self.runtime, source)
    }

    /// Borrows the same opaque original collecting plan retained by this runtime.
    ///
    /// This view grants no execution or current-scope permission. Callers still
    /// authenticate the original installed authority before dispatch; neither
    /// the graph nor the underlying ordinary runtime can escape through it.
    pub fn collection_plan(&self) -> &crate::node_admission::InstalledConformancePlan {
        self.graph.plan()
    }

    /// Authenticates an inactive owner against the exact retained collecting plan.
    ///
    /// This read grants no execution, ordinary graph, activation or mutable
    /// runtime access. It permits an owning source caller to reject a foreign
    /// runtime before its first Arm or grant.
    ///
    /// # Errors
    /// Refuses another original plan, an already activated runtime or stale
    /// whole-world/source/native custody under the original installed authority.
    pub fn validate_inactive_collection_plan(
        &mut self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        if self.activation.is_some() || !self.graph.plan().same_original(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.current()
    }

    /// Checks Complete preservation descriptions on actual admitted test nodes.
    ///
    /// This test-double observation lends no node, runtime or capture authority.
    ///
    /// # Errors
    /// Refuses an active or non-Complete world, absent selected descriptions,
    /// changed current custody, or an exact-profile alias for preservation.
    #[cfg(feature = "test-double")]
    #[doc(hidden)]
    pub fn validate_inactive_complete_preservation_descriptions_for_test(
        &mut self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.validate_inactive_collection_plan(plan)?;
        let nodes: Vec<_> = self.graph.graph.node_ids().cloned().collect();
        let mut checked = 0usize;
        for node in nodes {
            let binding = self
                .graph
                .graph
                .binding(&node)
                .ok_or(RuntimeError::UnknownNode)?;
            if binding
                .compatibility
                .implementation
                .implementation_id
                .as_str()
                != "source-owned.packet-native/5"
            {
                continue;
            }
            let selected = binding
                .compatibility
                .operating_contract
                .facets
                .iter()
                .find(|facet| {
                    facet.id.as_str() == "source-owned.packet-complete-original-lineage/5"
                        && facet.version == 5
                })
                .ok_or(RuntimeError::UnsupportedFacet)?;
            let acquired = self.runtime.facet(&node, FacetKind::Preservation)?;
            if acquired.kind() != FacetKind::Preservation || acquired.profile() != &selected.id {
                return Err(RuntimeError::InvalidReceipt);
            }
            checked += 1;
        }
        if checked != 3 {
            return Err(RuntimeError::InvalidRoute);
        }
        self.current()
    }

    /// Authenticates the actual retained runtime slot against its original queue.
    ///
    /// # Errors
    /// Refuses foreign current plan/custody or a different actual queue, including
    /// equal-proposal queues. This creates no execution or readiness authority.
    pub fn authenticate_original_custody_queue(
        &mut self,
        queue: &RuntimeCustodyQueue,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        self.runtime.authenticate_original_custody_queue(queue)?;
        self.current()
    }

    /// Checks the same inactive collecting plan and original activation proposal.
    ///
    /// This borrows the actual runtime barrier; an equal external proposal does
    /// not issue activation, readiness or permission to dispatch native work.
    ///
    /// # Errors
    /// Refuses another original plan/proposal, an activated runtime or stale
    /// whole-world source custody under the installed authority.
    pub fn validate_inactive_collection_proposal(
        &mut self,
        plan: &crate::node_admission::InstalledConformancePlan,
        proposal: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.validate_inactive_collection_plan(plan)?;
        if !self.runtime.has_original_activation_proposal(proposal) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Transfers the exact collecting world before any operational cleanup callback.
    ///
    /// The private runtime shell remains owned; no ordinary runtime or graph is
    /// exposed. Only authentic supervisor completion can discharge its custody.
    ///
    /// # Errors
    /// Retains original state on unsupported handoff or unresolved supervision.
    pub fn retire_original(&mut self) -> Result<(), RuntimeError> {
        self.activation = None;
        self.runtime.retire_collecting_original()
    }

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
            _runtime: None,
        })?;
        Ok(Self {
            graph,
            runtime,
            activation: None,
            quantized,
            exact_inputs: None,
            origin: CollectionOrigin::Initial,
        })
    }

    /// Collects authentic readiness from every original native owner.
    ///
    /// # Errors
    /// Refuses revoked/changed collection authority or incomplete actual readiness.
    pub fn arm_all(&mut self) -> Result<(), RuntimeError> {
        self.current()?;
        self.authenticate_initial_origin()?;
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
        self.authenticate_initial_origin()?;
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
        self.authenticate_initial_origin()?;
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
        let coordinator_stored = self.runtime.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::StoredResult,
            Some(token.operation()), Some(&token.route.node), None, 0,
        ).map_err(RuntimePollFailure::Admission)?;
        let original = self
            .runtime
            .original_completed_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        self.graph.authenticate_current_scope().map_err(|error| {
            RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.message))
        })?;
        let publication = publisher.publish_original(self.graph.plan().evidence(), &original);
        let disposition = match &publication {
            Ok(PublicationStatus::Committed) => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed,
            Ok(PublicationStatus::NotCommitted) => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Refused,
            _ => crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Uncertain,
        };
        self.runtime
            .finish_coordinator_attempt_data(coordinator_stored, disposition)
            .map_err(RuntimePollFailure::Admission)?;
        if publication.map_err(RuntimePollFailure::Admission)? != PublicationStatus::Committed {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        self.runtime
            .reconcile_coordinator_stored_result_data(token)
            .map_err(RuntimePollFailure::Admission)?;
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

impl ConformanceRuntime {
    pub(crate) fn quote_original_restoration_node_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        maximum: usize,
    ) -> Result<crate::node_admission::OriginalRestorationNodeConstructionData, RuntimeError> {
        inputs.authenticate_original_group_data()?;
        if !inputs
            .runtime
            .is_original_runtime_data(std::ptr::from_ref(self))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        inputs.ticket.authenticate_source(inputs.archive)?;
        inputs
            .source
            .authenticate_original_restoration_target_data(
                inputs.ticket,
                inputs.archive,
                self,
                plan,
                inputs.activation,
            )?;
        let node_inputs = crate::node_admission::OriginalRestorationNodeInputs {
            source: inputs.source,
            plan,
            ticket: inputs.ticket,
            launch: inputs.launch,
            encoded_launch: inputs.encoded_launch,
            prepare_id: inputs.prepare_id,
            maximum_requested_bytes: maximum,
            signing: None,
        };
        let result = self
            .runtime
            .quote_original_restoration_node_data(&node_inputs)?;
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        Ok(result)
    }

    pub(crate) fn quote_original_restoration_group_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        maximum: usize,
    ) -> Result<[crate::node_admission::OriginalRestorationNodeConstructionData; 3], RuntimeError>
    {
        inputs.authenticate_original_group_data()?;
        if !inputs
            .runtime
            .is_original_runtime_data(std::ptr::from_ref(self))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        let mut rows = [None, None, None];
        for (index, slot) in rows.iter_mut().enumerate() {
            let source = &inputs.sources[index];
            source.authenticate_original_restoration_target_data(
                inputs.tickets[index],
                inputs.archive,
                self,
                plan,
                inputs.activation,
            )?;
            let node_inputs = crate::node_admission::OriginalRestorationNodeInputs {
                source,
                plan,
                ticket: inputs.tickets[index],
                launch: &inputs.launches[index],
                encoded_launch: inputs.encoded_launches[index],
                prepare_id: &inputs.prepare_ids[index],
                maximum_requested_bytes: maximum,
                signing: None,
            };
            *slot = Some(
                self.runtime
                    .quote_original_restoration_node_data(&node_inputs)?,
            );
        }
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        let [first, second, third] = rows;
        Ok([
            first.ok_or(RuntimeError::OwnerUnavailable)?,
            second.ok_or(RuntimeError::OwnerUnavailable)?,
            third.ok_or(RuntimeError::OwnerUnavailable)?,
        ])
    }

    pub(crate) fn original_restoration_group_counter_scratch_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<usize, RuntimeError> {
        use crate::node_admission::{
            OriginalRestorationConstructionInputs, OriginalRestorationNodeConstructionData,
            OriginalRestorationNodeInputs,
        };
        inputs.authenticate_original_group_data()?;
        if !inputs
            .runtime
            .is_original_runtime_data(std::ptr::from_ref(self))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        let mut largest_node = 0usize;
        for ticket in inputs.tickets {
            largest_node = largest_node.max(
                self.runtime
                    .original_restoration_node_counter_scratch_data(ticket)?,
            );
        }
        let owning = self.original_inactive_retained_storage_counter_scratch_data()?;
        let terms = [
            std::mem::size_of::<OriginalRestorationConstructionInputs<'static>>(),
            ConformanceRuntimeObservation::counter_scratch_data(),
            std::mem::size_of::<OriginalRestorationNodeInputs<'static>>(),
            std::mem::size_of::<[Option<OriginalRestorationNodeConstructionData>; 3]>(),
            std::mem::size_of::<[OriginalRestorationNodeConstructionData; 3]>(),
            std::mem::size_of::<Result<[OriginalRestorationNodeConstructionData; 3], RuntimeError>>(),
            std::mem::size_of::<[usize; 16]>(),
            std::mem::size_of::<std::slice::IterMut<'static, Option<OriginalRestorationNodeConstructionData>>>(),
            std::mem::size_of::<std::iter::Enumerate<std::slice::IterMut<'static, Option<OriginalRestorationNodeConstructionData>>>>(),
            Self::original_restoration_target_counter_scratch_data(),
            crate::node_adapters::cnp::PacketCompleteSemanticSource::original_restoration_target_counter_scratch_data(),
            crate::node_state::NativeArchiveRecord::original_restoration_index_counter_scratch_data(),
            crate::node_adapters::cnp::OriginalRestorationColdGroup::counter_scratch_data(),
            crate::node_adapters::cnp::OriginalRestorationColdGroup::inline_root_storage_data(),
            largest_node, owning,
        ];
        terms.into_iter().try_fold(0usize, |sum, term| {
            sum.checked_add(term).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl ConformanceRuntime {
    pub(crate) fn begin_original_restoration_transaction(
        &mut self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<super::OriginalRuntimeStorageIdentity, RuntimeError> {
        self.authenticate_original_restoration_target_data(source, plan, activation)?;
        self.runtime
            .begin_original_restoration_transaction(source, ticket, plan, activation)
    }

    pub(crate) fn authenticate_original_restoration_transaction_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
        identity: &super::OriginalRuntimeStorageIdentity,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_restoration_target_data(source, plan, activation)?;
        self.runtime
            .authenticate_original_restoration_transaction_data(
                source, ticket, plan, activation, identity,
            )
    }
}

impl ConformanceRuntime {
    pub(crate) fn original_restoration_live_member_identity_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<super::OriginalRestorationRuntimeMemberIdentity, RuntimeError> {
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        self.runtime
            .original_restoration_live_member_identity_data(archive, plan, activation)
    }
}

impl ConformanceRuntime {
    pub(crate) fn quote_original_restoration_signer_node_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        cold: &crate::node_adapters::cnp::OriginalRestorationColdGroup,
        activation_request_ids: &[Id; 2],
        observation_request_id: Option<&Id>,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum_record_bytes: usize,
        observed_other_retained_bytes: usize,
        maximum: usize,
    ) -> Result<crate::node_admission::OriginalRestorationNodeConstructionData, RuntimeError> {
        inputs.authenticate_original_group_data()?;
        if !inputs
            .runtime
            .is_original_runtime_data(std::ptr::from_ref(self))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        inputs
            .source
            .authenticate_original_restoration_target_data(
                inputs.ticket,
                inputs.archive,
                self,
                plan,
                inputs.activation,
            )?;
        let node_inputs = crate::node_admission::OriginalRestorationNodeInputs {
            source: inputs.source,
            plan,
            ticket: inputs.ticket,
            launch: inputs.launch,
            encoded_launch: inputs.encoded_launch,
            prepare_id: inputs.prepare_id,
            maximum_requested_bytes: maximum,
            signing: Some(crate::node_admission::OriginalRestorationSigningCollector {
                inputs,
                cold,
                activation_request_ids,
                observation_request_id,
                coordinator,
                maximum_record_bytes,
                observed_other_retained_bytes,
            }),
        };
        let result = self
            .runtime
            .quote_original_restoration_node_data(&node_inputs)?;
        self.authenticate_original_restoration_target_data(
            inputs.archive,
            plan,
            inputs.activation,
        )?;
        Ok(result)
    }
}

impl ConformanceRuntime {
    pub(crate) fn execute_original_restoration_transaction(
        &mut self,
        dispatch: crate::node_admission::OriginalRestorationNodeDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        dispatch.authenticate_runtime_data(self)?;
        self.runtime
            .execute_original_restoration_node_dispatch(dispatch)
    }
}

impl ConformanceRuntime {
    pub(crate) fn inspect_original_restoration_continuation(
        &self,
        inspection: crate::node_admission::OriginalRestorationNodeContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        inspection.authenticate_runtime_data(self)?;
        self.runtime
            .inspect_original_restoration_node_continuation(inspection)
    }
}

impl ConformanceRuntime {
    pub(crate) fn inspect_original_host_restoration_continuation(
        &self,
        inspection: crate::node_admission::OriginalRestorationHostContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        inspection.authenticate_runtime_data(self)?;
        self.runtime
            .inspect_original_host_restoration_continuation(inspection)
    }
}

impl ConformanceRuntime {
    pub(crate) fn prepare_original_installed_restoration_context_data<'a>(
        &self,
        window: &'a Rc<crate::node_admission::CompleteOriginalRestorationWindow>,
        plan: &'a crate::node_admission::InstalledConformancePlan,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        self.runtime
            .prepare_original_installed_restoration_context_data(window, plan)
    }
}

impl ConformanceRuntime {
    pub(crate) fn original_restoration_coordinator_sources_data(
        &self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<
        (
            &crucible_node_contract::WorldBinding,
            &super::HostSchedulingSource,
        ),
        RuntimeError,
    > {
        self.observation_data()
            .original_restoration_coordinator_sources_data(plan)
    }
}

#[path = "conformance/installed_restoration.rs"]
mod installed_restoration;

#[path = "conformance/current_observation.rs"]
mod current_observation;

#[path = "conformance/restored_producer_publication.rs"]
mod restored_producer_publication;
pub use restored_producer_publication::{
    OriginalRestoredProducerPublicationConstructionData, OriginalRestoredProducerPublicationScope,
    OriginalRestoredProducerReportReadScope, OriginalRestoredProducerResultPublisher,
};

#[path = "conformance/producer_execution.rs"]
mod producer_execution;

pub(crate) use restored_producer_publication::OriginalRestoredProducerReportFence;

impl ConformanceRuntime {
    /// Selects the separately funded original coordinator17 append owner.
    ///
    /// The actual initial factory calls this only after authenticating its
    /// complete upfront17 Source declaration and admitting this same row with
    /// all existing World owners. Old factories never call this entry point.
    ///
    /// # Errors
    /// Refuses a restored/active/foreign World, missing exact Host custody,
    /// changed current plan, prior initialization or bank allocation failure.
    pub fn initialize_original_coordinator17_data(
        &mut self,
        row: &super::OriginalCoordinator17ConstructionData,
    ) -> Result<(), RuntimeError> {
        self.current()?;
        self.authenticate_initial_origin()?;
        if self.activation.is_some() || self.exact_inputs.is_none() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime.initialize_original_coordinator17_data(row)?;
        self.current()
    }
}

#[path = "conformance/restored_capture.rs"]
mod restored_capture;

pub use restored_capture::RestoredCollectingCaptureScope17;

#[path = "conformance/observation.rs"]
mod observation;
pub use observation::ConformanceRuntimeObservation;
pub(crate) use observation::ConformanceRuntimeObservationFields;

#[path = "conformance/initial_preparation.rs"]
mod initial_preparation;
