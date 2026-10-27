//! Admits actual grant construction and appends each fully quoted action.

use super::*;

impl CompleteOriginalRestorationWindow {
    /// Retains actual grant/dispatch constructor work before Scheduler allocation.
    ///
    /// Each invocation adds a new commitment. The old banks remain in the raw
    /// census and prior future commitments never disappear on failure or Drop.
    pub(crate) fn retain_original_producer_grant_work_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        node: &crucible_node_format::Id,
        work: (usize, usize, usize),
    ) -> Result<usize, RuntimeError> {
        if self.restored_capture_in_flight.get() {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.authenticate_current_observation_runtime_data(runtime, plan, world)?;
        let candidate = self
            .producer_publication
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = self.current_observation_source_index_data(node)?;
        if selected != candidate.selected || !candidate.constructed.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.producer_next_slot.get() >= candidate.row.maximum_slots_data() {
            return Err(RuntimeError::ResourceLimit);
        }
        self.suffix_seeds[selected]
            .authenticate(super::continuation_suffix::SeedStage::Verified)?;
        let ledger = self.producer_executions[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        ledger.require_available_data()?;
        if self.producer_grant_started[selected].get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let first = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.source_observation.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // Quoting the new checkpoint first reauthenticates historical World/
        // Commit under a real read fence. Its old row is not reused as credit:
        // retain a new independent pair of complete validation windows before
        // that preflight can deserialize or clone any of those actual owners.
        let work = (
            work.0
                .checked_add(
                    first
                        .retained_requested_bytes_data()
                        .checked_mul(2)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?,
            work.1
                .checked_add(
                    first
                        .maximum_simultaneous_transient_bytes_data()
                        .checked_mul(2)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?,
            work.2
                .checked_add(
                    first
                        .counter_scratch_bytes_data()
                        .checked_mul(2)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        checked_sum(
            &[work.0, work.1, work.2],
            self.policy.maximum_requested_bytes,
        )?;
        if work.2 > self.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let previous = self.producer_grant_work[selected]
            .get()
            .unwrap_or((0, 0, 0));
        let accumulated = (
            previous
                .0
                .checked_add(work.0)
                .ok_or(RuntimeError::ResourceLimit)?,
            previous
                .1
                .checked_add(work.1)
                .ok_or(RuntimeError::ResourceLimit)?,
            previous
                .2
                .checked_add(work.2)
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        checked_sum(
            &[accumulated.0, accumulated.1, accumulated.2],
            self.policy.maximum_requested_bytes,
        )?;
        self.producer_grant_work[selected].set(Some(accumulated));
        self.whole_observation.require_observation();
        Ok(selected)
    }

    /// Spends the whole-census grant-construction step before any real reserve.
    pub(crate) fn begin_original_producer_grant_construction_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        if self.restored_capture_in_flight.get() {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.authenticate_current_observation_runtime_data(runtime, plan, world)?;
        self.whole_observation.authenticate_dispatch_data()?;
        let candidate = self
            .producer_publication
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if selected != candidate.selected
            || self.producer_grant_work[selected].get().is_none()
            || self.producer_next_slot.get() >= candidate.row.maximum_slots_data()
            || self.producer_grant_started[selected].replace(true)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.producer_executions[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .require_available_data()?;
        // Failure before the grant is retained still spends this constructor.
        // No alternate caller can renew its prior successful whole census.
        self.whole_observation.require_observation();
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn retain_original_producer_pending_grant_data(
        &self,
        runtime: &NodeRuntime,
        selected: usize,
        grant: ExecutionAdmission,
    ) -> Result<usize, (RuntimeError, ExecutionAdmission)> {
        let prepare = || -> Result<usize, RuntimeError> {
            self.origin()?;
            let candidate = self
                .producer_publication
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            if selected != candidate.selected || !self.producer_grant_started[selected].get() {
                return Err(RuntimeError::ForeignAuthority);
            }
            let slot = self.producer_next_slot.get();
            if slot >= candidate.row.maximum_slots_data() {
                return Err(RuntimeError::ResourceLimit);
            }
            runtime.authenticate_restored_producer_grant_data(&grant)?;
            self.runtime.authenticate_runtime_data(
                runtime,
                &grant.activation().record().world_binding_hash,
            )?;
            let source = &self.sources[selected];
            if grant.node() != &source.installation().binding.compatibility.node_id {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(slot)
        };
        let slot = match prepare() {
            Ok(slot) => slot,
            Err(error) => return Err((error, grant)),
        };
        let mut ledger = match self.producer_executions[selected].try_borrow_mut() {
            Ok(ledger) => ledger,
            Err(_) => return Err((RuntimeError::OwnerBusy, grant)),
        };
        let next = match slot.checked_add(1) {
            Some(next) => next,
            None => return Err((RuntimeError::ResourceLimit, grant)),
        };
        ledger.retain_pending_data(grant, slot)?;
        self.producer_next_slot.set(next);
        self.whole_observation.require_observation();
        Ok(slot)
    }

    pub(crate) fn with_original_pending_producer_grant_data<R>(
        &self,
        selected: usize,
        inspect: impl FnOnce(&ExecutionAdmission) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.origin()?;
        let ledger = self
            .producer_executions
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        inspect(ledger.pending_grant_data()?)
    }

    pub(crate) fn retain_original_producer_execution_quote_data(
        &self,
        runtime: &NodeRuntime,
        selected: usize,
        mut row: OriginalRestoredProducerExecutionConstructionData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let mut ledger = self
            .producer_executions
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let pending = ledger.pending_grant_data()?;
        let source = &self.sources[selected];
        row.authenticate_owner_data(source, row.controller)?;
        if pending.node() != &source.installation().binding.compatibility.node_id {
            return Err(RuntimeError::ForeignAuthority);
        }
        let projection = source
            .original_restored_producer_outcome_projection_data(pending.activation().record())?;
        let (node, port, lane) = projection.endpoint_parts_data();
        let scheduling = runtime.original_restored_producer_scheduling_construction_data(
            node,
            port,
            lane,
            row.provider.population_data().newborn_publications_data(),
            row.maximum,
        )?;
        // The durable common receipt creates a first update. The later genuine
        // grant-free Observe creates another update from that progressed state.
        // The first complete retained upper bank bounds the second clone too;
        // both banks remain committed independently, never refunded as a phase max.
        row.runtime_work.0 = row
            .runtime_work
            .0
            .checked_add(
                scheduling
                    .0
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.1 = row
            .runtime_work
            .1
            .checked_add(scheduling.1)
            .and_then(|bytes| bytes.checked_add(scheduling.0))
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.2 = row
            .runtime_work
            .2
            .checked_add(scheduling.2)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.runtime_work.1 = row
            .runtime_work
            .1
            .checked_add(ledger.append_bank_requested_bytes_data()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        row.complete_scratch = row
            .scratch
            .checked_add(row.runtime_work.2)
            .ok_or(RuntimeError::ResourceLimit)?;
        if row.complete_scratch > self.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        ledger.retain_quote_data(row)?;
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn append_original_admitted_producer_execution_data(
        &self,
        selected: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let mut ledger = self
            .producer_executions
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let result = ledger.append_after_census_data();
        self.whole_observation.require_observation();
        result
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn quote_original_producer_execution_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        grant: &ExecutionAdmission,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        maximum: usize,
    ) -> Result<OriginalRestoredProducerExecutionConstructionData, RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected
            || maximum != self.policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        node.authenticate_original_owner_data(source, read_owner)?;
        let first = node
            .source_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if PacketCompleteSemanticSource::original_restored_producer_execution_counter_scratch_data()
            > self.policy.declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let ledger = self.producer_executions[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let pending = ledger
            .pending
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        if !std::ptr::eq(&pending.grant, grant)
            || pending.stage.get() != ProducerExecutionStage::Pending
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut row = None;
        self.with_original_observation_signing_inputs_data(
            selected,
            source,
            self.original_complete_scope_proof_identity_data()?,
            |inputs| {
                row = Some(
                    source.original_restored_producer_execution_construction_data(
                        controller, read_owner, launch, raw5, grant, inputs, first, maximum,
                    )?,
                );
                Ok(())
            },
        )?;
        row.ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(crate) fn with_original_producer_execution_source_data<R>(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: *const crucible_node_transport::client::CnpController,
        read_owner: *const (),
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        inspect: impl FnOnce(
            &PacketCompleteSemanticSource,
            &OriginalInstalledRestorationObservationSigningInputs<'_>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        if self.original_installed_source_index_data(erased)? != selected
            || !std::ptr::eq(self, claim.window)
            || selected != claim.selected
            || read_owner != claim.row.read_owner
            || controller != claim.row.controller
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        claim.authenticate_current_data(source, controller)?;
        claim.with_original_inputs_data(source, |inputs| inspect(source, inputs))
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn with_original_producer_deferred_source_data<R>(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        world: &WorldActivation,
        inspect: impl FnOnce(&PacketCompleteSemanticSource) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        if self.original_installed_source_index_data(erased)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_suffix_identity_data(
            selected,
            source,
            read_owner,
            world,
            self.original_complete_scope_proof_identity_data()?,
        )?;
        let row = self.producer_executions[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let latest = row.attempts.last().ok_or(RuntimeError::OwnerUnavailable)?;
        latest
            .row_data()?
            .authenticate_owner_data(source, controller)?;
        if latest.stage.get() != ProducerExecutionStage::PublicationStarted {
            return Err(RuntimeError::OutstandingObligations);
        }
        inspect(source)
    }
}
