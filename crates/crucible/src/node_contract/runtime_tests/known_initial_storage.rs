//! Observes a closed initial-only modeled node family for real Core budget tests.
//!
//! The actual admitted NodeRuntime, node metadata, Rc/RefCell and zero-field
//! custody slot are owned normally. Dynamic model state is unsupported, including
//! empty vectors with spare capacity. These observers qualify no native codec,
//! Capture, restoration, publication or Ready implementation.

// crucible-lint: allow panic-shortcut -- These model-only fixtures panic on invalid admitted construction; controls use Result for observed budget failures.

use super::*;
use crate::node_contract::runtime::RuntimeOwnedStorage;
use std::mem::size_of;

struct KnownInitialNode(TestNode);

impl KnownInitialNode {
    fn nested_storage(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let TestNode {
            descriptor,
            binding,
            route,
            facets,
            profile,
            state,
        } = &self.0;
        let saved = state
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let NativeState {
            terminal_failure,
            deferred_results,
            deferred_calls,
            terminal_scheduling,
            lineage_claim,
            lineage_required: _,
            conditional_lineage_scope,
            conditional_scope_validations: _,
            conditional_target_supported: _,
            conditional_target_validations: _,
            lineage_invalid: _,
            lineage_reads: _,
            lineage_validations: _,
            exact_lineage_supported: _,
            exact_lineage_validations: _,
            exact_restoration_record,
            exact_restoration_calls: _,
            lineage_restoration_supported: _,
            lineage_restoration_calls: _,
            lineage_restoration_refuse: _,
            lineage_restoration_admit: _,
            lineage_install_supported: _,
            lineage_install_calls: _,
            arm_fail: _,
            change_declarations_on_arm: _,
            changed_declarations: _,
            pending: _,
            invalid_evidence: _,
            overshoot: _,
            refuse: _,
            uncertain: _,
            facet_calls: _,
            thread_affinity_override: _,
            retained_dispatches: _,
            retained_dispatch_address: _,
            retained_dispatch_clone_refused: _,
            retained_dispatch_foreign_world,
            retained_dispatch_foreign_refused: _,
            begin_calls: _,
            poll_calls: _,
            close_calls: _,
            ack_calls: _,
            ack_fail: _,
            quarantine_calls: _,
            graceful_available: _,
            graceful_panics: _,
            graceful_calls: _,
            retirement_transfer_calls: _,
            reclamation_pending: _,
            invalid_reclamation: _,
            retained_outputs,
            admission,
            scheduling_observation,
            evidence_objects,
            evidence_reads: _,
            evidence_corrupt: _,
            progress_override,
            native_capture_calls: _,
            native_capture_effects: _,
            native_capture_bytes,
            native_capture_artifacts,
            native_capture_limits,
        } = &*saved;
        if terminal_failure.is_some()
            || deferred_results.capacity() != 0
            || deferred_calls.capacity() != 0
            || terminal_scheduling.is_some()
            || lineage_claim.is_some()
            || conditional_lineage_scope.is_some()
            || exact_restoration_record.is_some()
            || retained_outputs.capacity() != 0
            || admission.is_some()
            || retained_dispatch_foreign_world.is_some()
            || scheduling_observation.is_some()
            || evidence_objects.capacity() != 0
            || progress_override.is_some()
            || native_capture_bytes.is_some()
            || native_capture_artifacts.capacity() != 0
            || native_capture_limits.capacity() != 0
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let shared = NodeRuntime::capture_shared_allocation_storage::<RefCell<NativeState>>();
        let bytes = [
            descriptor.owned_storage()?,
            binding.owned_storage()?,
            route.owned_storage()?,
            facets
                .capacity()
                .checked_mul(size_of::<FacetKind>())
                .ok_or(RuntimeError::ResourceLimit)?,
            profile.owned_storage()?,
            shared,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl SimulationNode for KnownInitialNode {
    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        self.nested_storage(maximum)
            .map(Some)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::None,
                reason: format!("initial model backing: {error:?}"),
            })
    }

    fn descriptor(&self) -> &NodeDescriptor {
        self.0.descriptor()
    }

    fn binding(&self) -> &NodeBinding {
        self.0.binding()
    }

    fn route(&self) -> &NodeRoute {
        self.0.route()
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        self.0.thread_affinity()
    }

    fn facets(&self) -> &[FacetKind] {
        self.0.facets()
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.0.status()
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.0.arm(world)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.0.validate_readiness(world, readiness)
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        self.0.begin_operation(admission)
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.0.poll_operation(operation, context)
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.0.validate_outcome(original, outcome)
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.0.request_cancel(operation)
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.0.close_quantum(original)
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.0.acknowledge_publication(operation, outputs)
    }

    fn facet(&mut self, kind: FacetKind) -> Result<crate::node_contract::NodeFacet<'_>, Refusal> {
        self.0.facet(kind)
    }

    fn quarantine_resources(&mut self) {
        self.0.quarantine_resources();
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.0.poll_reclamation(owner, context)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.0.validate_reclamation(receipt)
    }
}

// This actual test-only slot has no fields or heap backing before handoff. Its
// normal Drop transfer uses the existing modeled custody sink. No native owner
// is inferred from it; native-capable nodes retain their own required observer.
struct KnownInitialSlot;

impl RuntimeCustodySlot for KnownInitialSlot {
    fn retained_requested_storage_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        Ok(Some(0))
    }

    fn validate_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeError> {
        crate::node_contract::test_custody_slot().validate_world(activation, limits)
    }

    fn retain(self: Box<Self>, custody: WholeRuntimeCustody) {
        crate::node_contract::test_custody_slot().retain(custody);
    }
}

/// Retains the same actual model state used by the known initial node observer.
pub(crate) struct InitialStorageControl {
    states: Vec<Rc<RefCell<NativeState>>>,
}

impl InitialStorageControl {
    /// Adds real spare backing which this closed initial family must refuse.
    ///
    /// # Panics
    /// Panics if the fixture lost its first state or a test holds its mutable borrow.
    pub(crate) fn reserve_output_bank(&self) {
        self.states[0]
            .borrow_mut()
            .retained_outputs
            .reserve_exact(17);
    }

    /// Reads actual effect counters without taking or replacing any owner.
    ///
    /// # Panics
    /// Panics if a test holds one of the original model state borrows mutably.
    pub(crate) fn effect_counts(&self) -> Vec<(usize, usize, usize, usize)> {
        self.states
            .iter()
            .map(|state| {
                let state = state.borrow();
                (
                    state.begin_calls,
                    state.poll_calls,
                    state.ack_calls,
                    state.native_capture_calls,
                )
            })
            .collect()
    }
}

/// Constructs genuine admitted Core owners with initial-only model observers.
///
/// # Panics
/// Panics if the existing graph fixture or its ordinary runtime formation is invalid.
pub(crate) fn fixture() -> (NodeRuntime, InitialStorageControl) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, states, record) =
        admitted_parts_with_node(graph, |node| Box::new(KnownInitialNode(node)));
    let runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        Box::new(KnownInitialSlot),
    )
    .unwrap_or_else(|failure| panic!("initial admitted runtime: {}", failure.error));
    (runtime, InitialStorageControl { states })
}
