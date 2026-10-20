//! Keeps actual role receiving and independent afters on the same residual.

use super::*;

impl OperatorReconciliationObservationOriginalV2 {
    /// Latches an actual caller refusal before the independently owed posts.
    ///
    /// This negative-only port cannot adopt a result or create completion.
    pub fn retain_body_refusal_once_v2(&mut self) {
        self.latch_v2();
        if self.body.is_none() { self.body = Some(Err(CLOSED)); }
        self.latch_v2();
    }

    pub(super) fn fixed_demand_v2() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<Box<Self>>())?
            .checked_add(2 * std::mem::size_of::<OperatorReconciliationObservationCustodyV2>())?
            .checked_add(3 * std::mem::size_of::<OperatorFirstLocalReconciliationCompleteV2<'_, '_>>())?
            .checked_add(3 * 3 * std::mem::size_of::<OperatorReconciliationInventoryProofV2<'_>>())?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(Clock::controller_authorization_receiving_demand_v1().ok()?).ok()?
            .checked_add(crate::controller::RetainedControllerProtectedClockAttemptV1::receiving_demand_v1().ok()?).ok()
    }

    fn require_native_current_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.first.is_some() || self.controller_after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_operator_recover_current_v1(
                self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                controller, &self.profile)
    }

    pub(super) fn completed_resident_v2(&self, seed: &OperatorRecoveredStoppedCreateSeedV1<'_>,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_completed_native_v2(seed, controller, source)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .completed_operator_recover_resident_demand_v1(
                self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                controller, &self.profile)
    }

    /// Borrows this actual role after checking the same completed predecessor.
    ///
    /// # Errors
    /// Refuses another seed, C, Source or failed/finished native interval.
    pub fn borrow_once_v2<'owner, 'seed, 'completed, 'controller>(
        &'owner mut self, seed: &'seed OperatorRecoveredStoppedCreateSeedV1<'completed>,
        controller: &'controller Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<OperatorReconciliationObservationLoanV2<'owner, 'seed, 'completed, 'controller>,
        ResourceReservationErrorV1>
    {
        self.require_native_current_v2(controller)?;
        if self.target != seed.target_v1() || !Arc::ptr_eq(&self.bank, &seed.owner.bank)
            || !Arc::ptr_eq(&self.profile, &seed.owner.profile)
            || !Arc::ptr_eq(&self.runtime, &seed.owner.runtime) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        seed.require_same_current_source_v1(source).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(OperatorReconciliationObservationLoanV2 { owner: self, seed, controller })
    }

    /// Finishes actual Source, C and final-clock destinations independently.
    ///
    /// This observes no successful SDK/model state and proves no physical
    /// absence. The Runtime must separately join actual completed query owners.
    /// Earlier failures stay selected while every entered destination runs.
    pub fn finish_native_once_v2(&mut self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) {
        self.latch_v2();
        if self.source_after.is_none() {
            if let Some(Ok(pair)) = self.source.as_mut() {
                self.source_after = Some(source.journal().finish_source_operator_recover_native_v1(pair));
            }
        }
        self.latch_v2();
        if self.controller_after.is_none() {
            self.controller_after = Some((|| {
                let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .finish_operator_recover_native_once_v1(native, controller, &self.profile)
            })());
        }
        self.latch_v2();
        if self.source_disposal.is_none() {
            if let Some(Ok(pair)) = self.source.as_mut() {
                self.source_disposal = Some((|| {
                    let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
                    self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                        .dispose_source_operator_recover_v1(pair, native, controller, source, &self.profile)
                })());
            }
        }
        self.latch_v2();
        if self.final_clock.is_none() {
            let paid = self.native.as_ref().is_ok_and(|native|
                native.require_prepaid_owed_observation_v1().is_ok());
            self.final_clock = Some(if paid { self.final_clock_native.observe_once_v1() }
                else { Err(crate::JournalError::ProtectedBoundary) });
            if let Some(Ok(sample)) = self.final_clock.as_ref() {
                self.final_comparison = Some(self.clock.require_final_sample_v1(*sample));
            }
        }
        self.latch_v2();
    }

    // This is native/Source completion only, never a physical reconciliation
    // proof. It permits only a following read-only role under the same R.
    pub(super) fn require_completed_native_v2(&self, seed: &OperatorRecoveredStoppedCreateSeedV1<'_>,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.require_completed_native_with_bank_v2(seed, controller, source, &bank)
    }

    pub(super) fn require_completed_native_with_bank_v2(&self, seed: &OperatorRecoveredStoppedCreateSeedV1<'_>,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
        bank: &ControllerResourceBankOpeningV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.target != seed.target_v1() || !Arc::ptr_eq(&self.bank, &seed.owner.bank)
            || !Arc::ptr_eq(&self.profile, &seed.owner.profile)
            || !Arc::ptr_eq(&self.runtime, &seed.owner.runtime)
            || self.first.is_some() || self.failure_v2().is_some()
            || !self.receiver_taken || !matches!(self.preparation, Some(Ok(())))
            || !self.inventory[..self.required_inventory_count_v2()].iter()
                .all(|state| state.is_completed_query_v2())
            || !matches!(self.source_after, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !matches!(self.source_disposal, Some(Ok(())))
            || !matches!(self.final_comparison, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        seed.require_same_current_source_v1(source).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        source.journal_ref_v1().require_current_source_provisioning_identity_v1(
            self.source_identity.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        bank.require_operator_recover_disposed_v1(
                self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?, controller, &self.profile)
    }

    pub(super) fn required_inventory_count_v2(&self) -> usize {
        match self.role {
            ControllerReconciliationInventoryRoleV2::Host
            | ControllerReconciliationInventoryRoleV2::Network
            | ControllerReconciliationInventoryRoleV2::Mount => 1,
        }
    }

    fn selected_v2(&self) -> Option<First> {
        if self.native.as_ref().is_err() || self.native.as_ref().is_ok_and(|native| native.failure().is_some()) { return Some(First::Native); }
        if self.clock.failure().is_some() { return Some(First::Clock); }
        if self.source.as_ref().is_some_and(|value| value.is_err() || value.as_ref().is_ok_and(|pair| pair.failure().is_some())) { return Some(First::SourceBefore); }
        if matches!(self.source_identity, Some(Err(_))) { return Some(First::SourceIdentity); }
        if matches!(self.source_comparison, Some(Err(_))) { return Some(First::SourceComparison); }
        if matches!(self.funding, Some(Err(_))) { return Some(First::Funding); }
        if matches!(self.preparation, Some(Err(_))) || self.receiver.as_ref().is_some_and(|receiver| receiver.failure().is_some()) { return Some(First::Preparation); }
        if self.inventory.iter().any(|state| state.failure_v1().is_some()) { return Some(First::Inventory); }
        if self.sdk_refusal.is_some() { return Some(First::Sdk); }
        if matches!(self.body, Some(Err(_))) { return Some(First::Body); }
        if matches!(self.source_after, Some(Err(_))) { return Some(First::SourceAfter); }
        if matches!(self.controller_after, Some(Err(_))) { return Some(First::ControllerAfter); }
        if matches!(self.source_disposal, Some(Err(_))) { return Some(First::SourceDisposal); }
        if self.final_clock_native.failure().is_some() || matches!(self.final_clock, Some(Err(_)))
            || matches!(self.final_comparison, Some(Err(_))) { return Some(First::FinalClock); }
        None
    }

    fn latch_v2(&mut self) {
        if self.first.is_none() { self.first = self.selected_v2(); }
    }

    /// Selects the retained SDK original only at its actual failure boundary.
    ///
    /// Later Source, C and final-clock refusals cannot replace this selection.
    pub fn sdk_failure_is_selected_v2(&self, index: usize) -> bool {
        match self.first.or_else(|| self.selected_v2()) {
            Some(First::Sdk) => true,
            Some(First::Inventory) => self.inventory.iter().enumerate()
                .find(|(_, state)| state.failure_v1().is_some())
                .is_some_and(|(selected, state)| selected == index && state.sdk_failure_is_selected_v2()),
            _ => false,
        }
    }

    /// Borrows the actual first native/financial/error original.
    ///
    /// An SDK marker is resolved only against this role's retained SDK owner
    /// by the Runtime, rather than selecting a later outer native refusal.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first.or_else(|| self.selected_v2())? {
            First::Native => match &self.native { Err(cause) => Some(cause), Ok(native) => native.failure() },
            First::Clock => self.clock.failure(),
            First::SourceBefore => match self.source.as_ref()? { Err(cause) => Some(cause), Ok(pair) => pair.failure() },
            First::SourceIdentity => self.source_identity.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceComparison => self.source_comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Preparation => self.preparation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.receiver.as_ref().and_then(|receiver| receiver.failure())),
            First::Inventory => self.inventory.iter().find_map(|state| state.failure_v1()),
            First::Sdk => self.sdk_refusal.as_ref().map(|cause| cause as _),
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceAfter => self.source_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ControllerAfter => self.controller_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceDisposal => self.source_disposal.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::FinalClock => self.final_clock_native.failure()
                .or_else(|| self.final_clock.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.final_comparison.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
        }
    }
}

impl OperatorReconciliationObservationLoanV2<'_, '_, '_, '_> {
    /// Requires the actual current native recipient and unchanged predecessor.
    ///
    /// # Errors
    /// Refuses a failed native/SDK stage, changed C or unfinished prior recovery.
    pub fn require_current_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_native_current_v2(self.controller)?;
        self.seed.owner.completed_metadata_operation_v1(self.controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::operator_create_recovery)
    fn require_completed_cold_v2(&self, receiving: &crate::ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        receiving.require_completed_reconciliation_journal_v2(
            self.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?,
            journal, self.owner.cutoff, self.owner.role)
    }

    /// Adds reached representation and traffic to this same actual interval.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or original-affinity refusal.
    pub fn reserve_additional_v2(&mut self, additional: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.owner.funding = Some((|| {
            let reached = self.owner.reached.checked_add(additional)?;
            self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_operator_recover_complete_v1(
                    self.owner.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                    self.controller, &self.owner.profile, self.owner.fixed.checked_add(reached)?)?;
            self.owner.reached = reached;
            Ok(())
        })());
        self.owner.latch_v2();
        if matches!(self.owner.funding, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Observes the same authorized CLI-origin clock before body work.
    ///
    /// # Errors
    /// Retains native, provenance, boot, original-cutoff or wall-expiry refusal.
    pub fn check_frontier_v2(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        let result = self.owner.clock.check_next_once_v1().map_err(ResourceReservationErrorV1::Journal);
        self.owner.latch_v2();
        result
    }

    /// Observes a paid after without requiring a healthy body.
    ///
    /// # Errors
    /// Retains an unpaid entry or the same original clock refusal.
    pub fn observe_owed_clock_after_once_v2(&mut self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.owner.latch_v2();
        self.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .require_prepaid_owed_observation_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let result = self.owner.clock.check_next_once_v1().map_err(ResourceReservationErrorV1::Journal);
        self.owner.latch_v2();
        result
    }

    /// Checks the unchanged full Source under a new genuine native pair.
    ///
    /// # Errors
    /// Retains actual Source entry, identity/cut, clock and funding refusals.
    pub fn observe_source_once_v2(&mut self, source: &mut ProtectedSourceDomainJournalOwnerV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.check_frontier_v2()?;
        if self.owner.source.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let pair_demand = SourcePair::receiving_demand_v1().map_err(ResourceReservationErrorV1::from)?;
        self.owner.source = Some((|| {
            let native = self.owner.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_source_operator_recover_v1(native, self.controller, source, &self.owner.profile,
                    self.owner.fixed.checked_add(self.owner.reached)?)
        })());
        self.owner.latch_v2();
        if !matches!(self.owner.source, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        // The lower pair entry itself prepaid this reached plane. Keep it in
        // every subsequent complete Session/query requirement.
        self.owner.reached = self.owner.reached.checked_add(pair_demand)?;
        self.owner.source_identity = Some(source.journal().source_provisioning_identity_v1());
        self.owner.latch_v2();
        if !matches!(self.owner.source_identity, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.owner.source_comparison = Some(self.seed.require_same_current_source_v1(source));
        self.owner.latch_v2();
        if !matches!(self.owner.source_comparison, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.check_frontier_v2().map(|_| ())
    }

    /// Returns the fixed role selected by this actual owner as comparison DATA.
    pub fn role_v2(&self) -> ControllerReconciliationInventoryRoleV2 { self.owner.role }

    /// Prepares the finite endpoint on this actual residual native interval.
    ///
    /// # Errors
    /// Retains repeated preparation, original expiry or the whole native cold
    /// receiver's refusal. Old initial claims are never selected here.
    pub fn prepare_session_once_v2(&mut self, shape: crate::ControllerInitialBrokerSessionShapeV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if self.owner.preparation.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.owner.preparation = Some((|| {
            if !matches!(self.owner.source_comparison, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.owner.receiver = Some(self.owner.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .prepare_operator_reconciliation_inventory_session_v2(
                    self.owner.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?,
                    self.controller, Arc::clone(&self.owner.profile), self.owner.role, shape,
                    Arc::clone(&self.owner.runtime), self.owner.cutoff)?);
            if self.owner.receiver.as_ref().is_some_and(|receiver| receiver.failure().is_none()) {
                Ok(())
            } else { Err(ResourceReservationErrorV1::Conflict) }
        })());
        self.owner.latch_v2();
        if matches!(self.owner.preparation, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Moves the whole genuine prepared endpoint into its SDK cold capture.
    ///
    /// # Errors
    /// Refuses failed, expired, unprepared or already transferred native state.
    pub fn take_session_receiver_once_v2(&mut self)
        -> Result<crate::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if self.owner.receiver_taken || !matches!(self.owner.preparation, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let receiver = self.owner.receiver.take().ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner.receiver_taken = true;
        Ok(receiver)
    }

    /// Returns the actual enrolled node, rather than a caller-supplied identity.
    ///
    /// # Errors
    /// Refuses failed receiving or missing current enrolled native identity.
    pub fn node_v2(&self) -> Result<NodeId, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .operator_recover_node_v1(self.controller, &self.owner.profile)
    }

    /// Returns the original authorized absolute cutoff without rearming it.
    ///
    /// # Errors
    /// Refuses a failed or already completed interval.
    pub fn original_cutoff_v2(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        Ok(self.owner.cutoff)
    }

    /// Borrows the same startup profile, without creating another allowance.
    pub fn profile_v2(&self) -> &Arc<ProductionControllerNormalRootProfileV1> { &self.owner.profile }

    /// Borrows the startup runtime retained by the genuine recovery owner.
    pub fn runtime_v2(&self) -> &Arc<tokio::runtime::Runtime> { &self.owner.runtime }

    /// Latches an external SDK refusal before any independent outer post.
    pub fn retain_sdk_refusal_once_v2(&mut self) {
        self.owner.latch_v2();
        self.owner.sdk_refusal.get_or_insert(OperatorCreateRecoveryClosedV1);
        self.owner.latch_v2();
    }

    /// Borrows the retained actual role failure without releasing its custody.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> { self.owner.failure_v2() }
}
