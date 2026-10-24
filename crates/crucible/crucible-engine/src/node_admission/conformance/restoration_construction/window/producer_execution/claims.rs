//! Seals distinct monotone execution phases without exposing a constructor.

use super::*;

/// Retains a single genuine whole-census admission across its Producer phases.
///
/// This owner has no public constructor, decoder or renewal. Dropping an
/// incomplete action leaves its grant, future rows and monotone slot spent.
pub struct OriginalRestoredProducerExecutionAdmission {
    pub(super) window: Rc<CompleteOriginalRestorationWindow>,
    pub(super) runtime: *const NodeRuntime,
    pub(super) selected: usize,
    pub(super) slot: usize,
}

impl OriginalRestoredProducerExecutionAdmission {
    pub(crate) fn after_original_census_data(
        window: &Rc<CompleteOriginalRestorationWindow>,
        runtime: &NodeRuntime,
        selected: usize,
        slot: usize,
    ) -> Result<Self, RuntimeError> {
        window.whole_observation.authenticate_dispatch_data()?;
        let ledger = window
            .producer_executions
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.last_data(slot)?;
        if attempt.stage.get() != ProducerExecutionStage::Quoted {
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt.row_data()?.requested_bytes_data()?;
        Ok(Self {
            window: Rc::clone(window),
            runtime,
            selected,
            slot,
        })
    }

    pub(crate) fn with_original_grant_data<R>(
        &self,
        runtime: &NodeRuntime,
        inspect: impl FnOnce(&ExecutionAdmission) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.window.origin()?;
        if !std::ptr::eq(runtime, self.runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        inspect(ledger.last_data(self.slot)?.grant_data())
    }

    pub(crate) fn begin_phase_data<'a>(
        &'a mut self,
        runtime: &NodeRuntime,
        world: &'a WorldActivation,
        launch: &'a crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &'a [u8],
        phase: ProducerExecutionPhase,
    ) -> Result<OriginalRestoredProducerExecutionClaim<'a>, RuntimeError> {
        self.window.origin()?;
        if !std::ptr::eq(runtime, self.runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.window
            .runtime
            .authenticate_runtime_data(runtime, &world.record().world_binding_hash)?;
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.last_data(self.slot)?;
        if !attempt.grant.activation().same_authority(world) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let row = *attempt.row_data()?;
        let (from, started, _) = phase.stages_data();
        let source = &self.window.sources[self.selected];
        row.authenticate_owner_data(source, row.controller)?;
        self.window.authenticate_suffix_identity_data(
            self.selected,
            source,
            row.read_owner,
            world,
            self.window.original_complete_scope_proof_identity_data()?,
        )?;
        if phase == ProducerExecutionPhase::Begin {
            self.window.whole_observation.authenticate_dispatch_data()?;
        }
        attempt.advance_data(from, started)?;
        Ok(OriginalRestoredProducerExecutionClaim {
            window: &self.window,
            runtime: self.runtime,
            selected: self.selected,
            slot: self.slot,
            world,
            launch,
            canonical_launch5,
            row,
            phase,
            completed: Cell::new(false),
            source_completed: Cell::new(false),
            scheduling_completed: Cell::new(false),
        })
    }
}

impl Drop for OriginalRestoredProducerExecutionAdmission {
    fn drop(&mut self) {
        if let Ok(ledger) = self.window.producer_executions[self.selected].try_borrow()
            && let Ok(attempt) = ledger.last_data(self.slot)
            && attempt.stage.get() != ProducerExecutionStage::Verified
        {
            attempt.fail_data();
        }
        self.window.whole_observation.require_observation();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProducerExecutionPhase {
    Begin,
    Poll,
    Publication,
    Retirement,
    Observation,
}

impl ProducerExecutionPhase {
    fn stages_data(
        self,
    ) -> (
        ProducerExecutionStage,
        ProducerExecutionStage,
        ProducerExecutionStage,
    ) {
        use ProducerExecutionStage::*;
        match self {
            Self::Begin => (Quoted, BeginStarted, Begun),
            Self::Poll => (Begun, PollStarted, Completed),
            Self::Publication => (Completed, PublicationStarted, Published),
            Self::Retirement => (Published, RetirementStarted, Retired),
            Self::Observation => (Retired, ObservationStarted, Verified),
        }
    }
}

/// Borrows the exact admitted phase while its real Source read is held.
///
/// No constructor, Clone or portable conversion is exposed. The Source must
/// authenticate its real completion before the owning Runtime advances phase.
pub struct OriginalRestoredProducerExecutionClaim<'a> {
    pub(super) window: &'a CompleteOriginalRestorationWindow,
    pub(super) runtime: *const NodeRuntime,
    pub(super) selected: usize,
    pub(super) slot: usize,
    pub(super) world: &'a WorldActivation,
    pub(super) launch:
        &'a crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
    pub(super) canonical_launch5: &'a [u8],
    pub(super) row: OriginalRestoredProducerExecutionConstructionData,
    pub(super) phase: ProducerExecutionPhase,
    pub(super) completed: Cell<bool>,
    pub(super) source_completed: Cell<bool>,
    pub(super) scheduling_completed: Cell<bool>,
}

impl OriginalRestoredProducerExecutionClaim<'_> {
    pub(crate) fn row_data(&self) -> &OriginalRestoredProducerExecutionConstructionData {
        &self.row
    }

    pub(crate) fn slot_data(&self) -> usize {
        self.slot
    }

    pub(crate) fn phase_data(&self) -> ProducerExecutionPhase {
        self.phase
    }

    pub(crate) fn world_data(&self) -> &WorldActivation {
        self.world
    }

    pub(crate) fn window_data(&self) -> &CompleteOriginalRestorationWindow {
        self.window
    }

    pub(crate) fn launch_data(
        &self,
    ) -> (
        &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        &[u8],
    ) {
        (self.launch, self.canonical_launch5)
    }

    pub(crate) fn with_original_grant_data<R>(
        &self,
        inspect: impl FnOnce(&ExecutionAdmission) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        inspect(ledger.last_data(self.slot)?.grant_data())
    }

    pub(crate) fn authenticate_current_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const crucible_node_transport::client::CnpController,
    ) -> Result<(), RuntimeError> {
        self.row.authenticate_owner_data(source, controller)?;
        if self.completed.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.window.authenticate_suffix_identity_data(
            self.selected,
            source,
            self.row.read_owner,
            self.world,
            self.window.original_complete_scope_proof_identity_data()?,
        )?;
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.last_data(self.slot)?;
        if attempt.stage.get() != self.phase.stages_data().1
            || !attempt.grant.activation().same_authority(self.world)
            || attempt.row_data()?.source != self.row.source
            || attempt.row_data()?.controller != self.row.controller
            || attempt.row_data()?.provider != self.row.provider
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
        admission: &crate::node_contract::OperationAdmission,
        route: &crate::node_contract::NodeRoute,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(runtime, self.runtime)
            || admission.token().route() != route
            || !admission.activation().same_authority(self.world)
            || admission.inputs().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.with_original_grant_data(|grant| {
            if grant.node() != &route.node
                || grant.operation() != admission.token().operation()
                || &grant.request() != admission.request()
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)
    }

    pub(crate) fn with_original_inputs_data<R>(
        &self,
        source: &PacketCompleteSemanticSource,
        inspect: impl FnOnce(
            &OriginalInstalledRestorationObservationSigningInputs<'_>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.authenticate_current_data(source, self.row.controller)?;
        let mut result = None;
        self.window.with_original_observation_signing_inputs_data(
            self.selected,
            source,
            self.window.original_complete_scope_proof_identity_data()?,
            |inputs| {
                result = Some(inspect(inputs)?);
                Ok(())
            },
        )?;
        result.ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(crate) fn authenticate_terminal_member_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_data(source, controller)?;
        let plan = self
            .window
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .window
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.window
            .authenticate_original_complete_member_data(&plan, scope)?;
        self.authenticate_current_data(source, controller)
    }
}

impl Drop for OriginalRestoredProducerExecutionClaim<'_> {
    fn drop(&mut self) {
        if !self.completed.get()
            && let Ok(ledger) = self.window.producer_executions[self.selected].try_borrow()
            && let Ok(attempt) = ledger.last_data(self.slot)
        {
            attempt.fail_data();
        }
        self.window.whole_observation.require_observation();
    }
}

impl OriginalRestoredProducerExecutionClaim<'_> {
    pub(crate) fn authenticate_request_data(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        node: &crucible_node_format::Id,
        operation: &crucible_node_format::Id,
        request: &crate::node_contract::OperationRequest,
    ) -> Result<(), RuntimeError> {
        if self.phase != ProducerExecutionPhase::Begin
            || !std::ptr::eq(runtime, self.runtime)
            || !world.same_authority(self.world)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.with_original_grant_data(|grant| {
            if grant.node() != node || grant.operation() != operation || &grant.request() != request
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)
    }
}

impl OriginalRestoredProducerExecutionClaim<'_> {
    pub(crate) fn retain_source_phase_completion_data(
        &self,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestoredProducerPhaseCompletion<'_>,
    ) -> Result<(), RuntimeError> {
        evidence.authenticate_claim_data(&self.row, self.slot, self.phase, self.world)?;
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)?;
        if self.source_completed.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn complete_runtime_phase_data(
        &self,
        runtime: &NodeRuntime,
        token: &crate::node_contract::OperationToken,
    ) -> Result<(), RuntimeError> {
        if !self.source_completed.get()
            || !std::ptr::eq(runtime, self.runtime)
            || (self.phase == ProducerExecutionPhase::Observation
                && !self.scheduling_completed.get())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_original_restored_producer_phase_result_data(token, self)?;
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)?;
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let (_, started, completed) = self.phase.stages_data();
        ledger
            .last_data(self.slot)?
            .advance_data(started, completed)?;
        self.completed.set(true);
        if self.phase == ProducerExecutionPhase::Observation {
            // The real prior grant and every row remain retained. This opens
            // only construction of the next separately admitted fresh slot.
            self.window.producer_grant_started[self.selected].set(false);
        }
        self.window.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn complete_retryable_publication_data(&self) -> Result<(), RuntimeError> {
        if self.phase != ProducerExecutionPhase::Publication || !self.source_completed.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)?;
        let ledger = self.window.producer_executions[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.last_data(self.slot)?;
        if attempt.stage.get() != ProducerExecutionStage::PublicationStarted {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Only the same report/placement may reconcile. Begin/Poll and every
        // native original remain spent; no construction future row is renewed.
        attempt.stage.set(ProducerExecutionStage::Completed);
        self.completed.set(true);
        self.window.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn publisher_data(
        &self,
    ) -> Result<
        (
            *const (),
            &OriginalRestoredProducerPublicationConstructionData,
        ),
        RuntimeError,
    > {
        let candidate = self
            .window
            .producer_publication
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if candidate.selected != self.selected || !candidate.constructed.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok((candidate.publisher, &candidate.row))
    }

    pub(crate) fn authenticate_original_dispatch_data(
        &self,
        dispatch: &crate::node_contract::OriginalRuntimeOperationDispatch<'_>,
        route: &crate::node_contract::NodeRoute,
    ) -> Result<(), RuntimeError> {
        let original = dispatch.admission_data();
        dispatch.authenticate_original_data(original, self.world, route)?;
        if self.phase != ProducerExecutionPhase::Begin || original.inputs().is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.with_original_grant_data(|grant| {
            if grant.node() != &route.node
                || grant.operation() != original.token().operation()
                || &grant.request() != original.request()
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)
    }
}

impl OriginalRestoredProducerExecutionClaim<'_> {
    pub(crate) fn authenticate_inputs_data(
        &self,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.window, inputs.activation.window)
            || self.selected != inputs.activation.selected
            || inputs
                .activation
                .world
                .is_none_or(|world| !world.same_authority(self.world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)?;
        inputs.activation.inspection.authenticate_current()
    }
}

impl OriginalRestoredProducerExecutionClaim<'_> {
    pub(crate) fn retain_runtime_checkpoint_data(
        &self,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        if self.phase != ProducerExecutionPhase::Observation
            || !std::ptr::eq(runtime, self.runtime)
            || !self.source_completed.get()
            || self.scheduling_completed.replace(true)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_current_data(&self.window.sources[self.selected], self.row.controller)
    }
}

impl OriginalRestoredProducerExecutionAdmission {
    /// Observes this exact retained handle without reopening any Window bank.
    ///
    /// The Window's nested owners are walked independently by the genuine whole
    /// observer. This fixed root/header view grants no action or new allocation.
    ///
    /// # Errors
    /// Refuses a null original Runtime identity or the supplied requested bound.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.runtime.is_null() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let bytes =
            NodeRuntime::capture_shared_allocation_storage::<CompleteOriginalRestorationWindow>();
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Names this fixed owning handle and its bank-free counter return views.
    pub fn retained_counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<Rc<CompleteOriginalRestorationWindow>>()
            + size_of::<Result<usize, RuntimeError>>()
    }
}

impl OriginalRestoredProducerExecutionAdmission {
    /// Returns the genuine admitted group member index as classification DATA.
    pub fn selected_data(&self) -> usize {
        self.selected
    }

    /// Returns the nonrecycled global slot retained by this actual Window.
    pub fn slot_data(&self) -> usize {
        self.slot
    }
}
