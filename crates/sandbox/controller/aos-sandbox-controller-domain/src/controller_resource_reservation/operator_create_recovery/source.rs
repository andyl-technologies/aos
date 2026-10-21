//! Retains a fresh same-Source observation through Recover inventory and posts.

use super::*;
use aos_sandbox_broker::source_receiving::SourceOperatorRecoverCurrentnessOriginalV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::lifecycle::LifecycleHistoricalReadOriginalV1;
use crate::{JournalError, RecordNamespace};

type Pair = SourceOperatorRecoverCurrentnessOriginalV1;

#[derive(Clone, Copy)]
enum First { Pair, Identity, Geometry, Funding, Model, Observation, After, Disposed }

pub(super) struct SourceObservationV1 {
    first: Option<First>,
    pair: Option<Result<Pair, ResourceReservationErrorV1>>,
    identity: Option<Result<crate::journal::source_provisioning::SourceProvisioningIdentityV1, JournalError>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    model: Option<LifecycleHistoricalReadOriginalV1>,
    observed: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    disposed: Option<Result<(), ResourceReservationErrorV1>>,
}

impl SourceObservationV1 {
    // Only the Source owner can inspect its private captured identity. This
    // comparison grants no Source loan or completed native observation.
    pub(super) fn require_current_identity_v2(&self,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let identity = self.identity.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.journal_ref_v1().require_current_source_provisioning_identity_v1(identity)?;
        Ok(())
    }

    pub(super) fn require_first_local_source_v1(&self,
        parent: aos_sandbox_model::OperationId, expected_terminal: [u8; 32],
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let closed = OperatorCreateRecoveryClosedV1;
        if !matches!(self.disposed, Some(Ok(()))) || self.failure().is_some() { return Err(closed); }
        let identity = self.identity.as_ref().and_then(|value| value.as_ref().ok()).ok_or(closed)?;
        source.journal_ref_v1().require_current_source_provisioning_identity_v1(identity).map_err(|_| closed)?;
        let model = self.model.as_ref().ok_or(closed)?;
        crate::controller_resource_reservation::source_family::require_first_local_source_families_data_v2(
            source.journal_ref_v1(), model, Some((parent, expected_terminal)),
        ).map_err(|_| closed)?;
        Ok(())
    }

    pub(super) fn root_terminal_digest_v1(&self) -> Result<[u8; 32], ResourceReservationErrorV1> {
        self.require_observed_for_root_v1()?;
        let (_, record) = self.model.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.operation_v1()?;
        Ok(*record.digest().as_bytes())
    }

    /// Borrows the exact A7 commitment without exposing the retained model.
    ///
    /// The caller first validates its completed handoff and current Source/target
    /// binding. The existing decoder checks the same completed auxiliary pair.
    ///
    /// # Errors
    /// Refuses a missing, failed or incomplete retained dispatch decoder.
    pub(super) fn stop_dispatch_record_digest_data_v1(&self)
        -> Result<aos_sandbox_model::ObjectDigest, ResourceReservationErrorV1> {
        self.model.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .stop_dispatch_record_digest_data_v1().map_err(Into::into)
    }

    pub(super) fn new() -> Self {
        Self { first: None, pair: None, identity: None, geometry: None, funding: None, model: None,
            observed: None, after: None, disposed: None }
    }

    // This is only a completed observation/header fence. The independent Root
    // still reconstructs the full historical Completing→Terminal relation.
    pub(super) fn require_observed_for_root_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.observed, Some(Ok(()))) || self.after.is_some()
            || self.disposed.is_some() || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (operation, _) = self.model.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .operation_v1()?;
        if operation.phase() != crate::lifecycle::LifecyclePhaseV1::Terminal
            || operation.terminal_result() != Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let first = self.first.or_else(|| self.current_source())?;
        match first {
            First::Pair => self.pair.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.pair.as_ref().and_then(|value|value.as_ref().ok()).and_then(Pair::failure)),
            First::Identity => self.identity.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Model => self.model.as_ref()?.failure(),
            First::Observation => self.observed.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::After => self.after.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Disposed => self.disposed.as_ref()?.as_ref().err().map(|cause|cause as _),
        }
    }
}

impl SourceObservationV1 {
    fn current_source(&self) -> Option<First> {
        if self.pair.as_ref().is_some_and(|value| value.is_err() || value.as_ref().is_ok_and(|pair|pair.failure().is_some())) { return Some(First::Pair); }
        if matches!(self.identity, Some(Err(_))) { return Some(First::Identity); }
        if matches!(self.geometry, Some(Err(_))) { return Some(First::Geometry); }
        if matches!(self.funding, Some(Err(_))) { return Some(First::Funding); }
        if self.model.as_ref().is_some_and(|model|model.failure().is_some()) { return Some(First::Model); }
        if matches!(self.observed, Some(Err(_))) { return Some(First::Observation); }
        if matches!(self.after, Some(Err(_))) { return Some(First::After); }
        if matches!(self.disposed, Some(Err(_))) { return Some(First::Disposed); }
        None
    }

    fn latch(&mut self) {
        if self.first.is_none() { self.first = self.current_source(); }
    }
}

impl OperatorCreateRecoveryLoanV1<'_, '_> {
    /// Reads the actual Source Lifecycle projection under paid fixed bookends.
    ///
    /// # Errors
    /// Retains any original, geometry, funding, native or full-schema refusal.
    pub fn observe_source_once_v1(&mut self, source: &mut ProtectedSourceDomainJournalOwnerV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1()?;
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1;
        let purpose = self.owner.recovery_purpose_data_v1(self.controller)?;
        let stop_cleanup = purpose == PublicRecoveryKindV1::StopCleanup;
        if self.owner.source.pair.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.check_frontier_v1()?;
        let before = self.owner.fixed.checked_add(self.owner.reached)?;
        let pair_demand = Pair::receiving_demand_v1().map_err(ResourceReservationErrorV1::from)?;
        // The same lower Source entry admits its concrete pair BEFORE arming;
        // preserve that reached plane in subsequent Session/model admissions.
        self.owner.source.pair = Some((|| {
            let native = self.owner.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_source_operator_recover_v1(native, self.controller, source, &self.owner.profile, before)
        })());
        if !matches!(self.owner.source.pair, Some(Ok(_))) {
            self.owner.source.latch();
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.reached = self.owner.reached.checked_add(pair_demand)?;
        // The actual native entry has already joined this Source original.
        // This private Arc/cut identity only denies substitution after disposal;
        // it creates no writer, read interval or positive reconciliation proof.
        self.owner.source.identity = Some(source.journal().source_provisioning_identity_v1());
        if !matches!(self.owner.source.identity, Some(Ok(_))) {
            self.owner.source.latch();
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.source.geometry = Some((|| {
            let journal = source.journal();
            let graph = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(journal.all_records())
                .ok_or(JournalError::JournalTooLarge)?;
            let historical = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::additional_selection_receiving_v1(journal.all_records())
                .ok_or(JournalError::JournalTooLarge)?;
            // The current projection and historical selection stay resident.
            // The Stop pair adds two independently retained auxiliary models
            // through that same bounded supplier before either decode grows.
            // The pair and its direct-residual canonical reconstruction may
            // coexist. Prepay that additional pure model plane before either
            // decoder or the shared successor comparison allocates it.
            let dispatch = if stop_cleanup { historical.checked_add(historical)? }
                else { ResourceVector::ZERO };
            let carrier = LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()
                .and_then(|bytes|u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            graph.checked_add(historical)
                .and_then(|demand| demand.checked_add(dispatch))
                .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier)))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let geometry = self.owner.source.geometry.as_ref().and_then(|value|value.as_ref().ok()).copied();
        self.owner.source.funding = Some(match geometry {
            Some(geometry) => self.reserve_additional_v1(geometry),
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.owner.source.funding, Some(Ok(()))) {
            self.owner.source.latch();
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v1()?;
        let parent = self.owner.target.ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner.source.model = Some(LifecycleHistoricalReadOriginalV1::new());
        self.owner.source.observed = Some((|| {
            let model = self.owner.source.model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            if purpose == PublicRecoveryKindV1::ExecutionNoApply {
                // Before-argument Execution may have no Lifecycle operation.
                // Reconstruct the actual full Source schema without inventing
                // one; Root independently classifies its exact execution rows.
                model.observe_rows_projection_once_v3(source.journal().historical_read_view_v1().rows_data_v2())?;
            } else {
                model.observe_once_v1(source.journal().historical_read_view_v1().rows_data_v2(), parent)?;
            }
            if stop_cleanup {
                model.select_stop_dispatch_once_v1()?;
            }
            Ok(())
        })());
        self.owner.source.latch();
        self.owner.latch_primary_failure_v1();
        if !matches!(self.owner.source.observed, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v1()?;
        Ok(())
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Observes only current Source before the distinct NoApply financial handoff.
    ///
    /// This finite entrance lends no Storage Session or effect and opens no
    /// Root stream. All independently owed Source posts remain outer-owned.
    ///
    /// # Errors
    /// Retains wrong purpose, failed authorization, native, Source or clock
    /// refusal on this same admitted Recover original.
    #[doc(hidden)]
    pub fn observe_no_apply_source_once_v2(&mut self, controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.recovery_purpose_data_v1(controller)?
            != aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply
            || !matches!(self.horizon, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut loan = OperatorCreateRecoveryLoanV1 { owner: self, controller };
        loan.observe_source_once_v1(source)
    }

    /// Borrows the immutable dispatch association under the actual live Source.
    ///
    /// The public target, old Source operation and literal SDK packet remain
    /// distinct. This comparison creates no effect, new request or old owner.
    ///
    /// # Errors
    /// Refuses another purpose, stale C/Source, missing actual dispatch pair,
    /// changed protected Stop target, failed observation or entered afters.
    #[doc(hidden)]
    pub(crate) fn stop_dispatch_source_data_v1(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(&aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
        crate::lifecycle::LifecycleRecordDigestV1), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1;
        if self.recovery_purpose_data_v1(controller)? != PublicRecoveryKindV1::StopCleanup
            || !matches!(self.source.observed, Some(Ok(())))
            || self.source.after.is_some() || self.source.disposed.is_some()
            || self.source.failure().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.stop_dispatch_binding_data_v1(controller, source)
    }

    // Shared comparison of the same selected canonical A7 model, before or
    // after its own native disposition. The caller supplies the phase gate;
    // this helper lends no Source writer and never refreshes its captured cut.
    pub(super) fn stop_dispatch_binding_data_v1(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(&aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
        crate::lifecycle::LifecycleRecordDigestV1), ResourceReservationErrorV1> {
        if !matches!(self.source.observed, Some(Ok(()))) || self.source.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source.require_current_identity_v2(source)?;
        let model = self.source.model.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let target = self.request.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(RequestModelsV1::stop_cleanup_target_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let record = target.source_parent_data_v1(
            crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(controller),
            model,
        )
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let binding = model.stop_dispatch_data_v1()?;
        // The held decoder proved the complete immutable A7 pair and either
        // this exact Completing snapshot or its direct residual successor.
        // Its old SDK record remains unchanged when the current record differs.
        if binding.operation() != target.operation_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((binding, record))
    }

    /// Requires the actual Source pair's completed independent disposition.
    ///
    /// # Errors
    /// Refuses missing entry, failed body, after or native disposal.
    #[doc(hidden)]
    pub fn require_source_disposed_v1(&self) -> Result<(), OperatorCreateRecoveryClosedV1> {
        if matches!(self.source.observed, Some(Ok(())))
            && matches!(self.source.after, Some(Ok(())))
            && matches!(self.source.disposed, Some(Ok(())))
            && self.source.failure().is_none() {
            Ok(())
        } else {
            Err(OperatorCreateRecoveryClosedV1)
        }
    }

    /// Runs an entered Source after even when inventory or its debit refused.
    #[doc(hidden)]
    pub fn finish_source_after_once_v1(&mut self,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) {
        self.source.latch();
        self.latch_primary_failure_v1();
        if self.source.after.is_some() { return; }
        if let Some(Ok(pair)) = self.source.pair.as_mut() {
            // No new debit, healthy turn or semantic-positive gate may suppress
            // an independently owed observation after an entered body refused.
            self.source.after = Some(source.journal().finish_source_operator_recover_native_v1(pair));
        }
        self.source.latch();
        self.latch_primary_failure_v1();
    }

    /// Settles Source only after its actual after and the enclosing C posts.
    #[doc(hidden)]
    pub fn dispose_source_after_native_posts_v1(&mut self, controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) {
        if self.source.disposed.is_some() { return; }
        if let Some(Ok(pair)) = self.source.pair.as_mut() {
            self.source.disposed = Some((|| {
                let native = self.native.as_ref().map_err(|_|ResourceReservationErrorV1::Conflict)?;
                self.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dispose_source_operator_recover_v1(pair, native, controller, source, &self.profile)
            })());
        }
        self.source.latch();
        self.latch_primary_failure_v1();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_geometry_refusal_precedes_a_later_owed_source_after() {
        let mut owner = SourceObservationV1::new();
        owner.geometry = Some(Err(JournalError::JournalTooLarge));
        owner.latch();
        let primary = owner.failure().unwrap() as *const dyn Error;

        owner.after = Some(Err(JournalError::ProtectedBoundary));
        owner.latch();

        assert!(std::ptr::eq(primary, owner.failure().unwrap() as *const dyn Error));
        assert!(matches!(owner.failure().unwrap().downcast_ref::<JournalError>(), Some(JournalError::JournalTooLarge)));
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    // This is a comparison against already completed retained Root/joint rows.
    // Only the new paid maintenance selects and replays current Source; no old
    // Recover native interval, horizon or physical observation is reused.
    pub(crate) fn completed_source_family_for_maintenance_data_v2(
        &self,
        controller: &Journal,
    ) -> Result<(aos_sandbox_model::OperationId, [u8; 32]), JournalError> {
        let completed = self
            .first_local_completed_fields_v1(controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let native = self
            .completed_native_for_resumption_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        // The old native interval is already complete and disposed. Rejoin its
        // real writer, launch and image-bound current recipient without entering
        // that interval or sampling its old deadline again.
        self.bank
            .try_lock()
            .map_err(|_| JournalError::ProtectedBoundary)?
            .require_operator_recover_disposed_v1(native, controller, &self.profile)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((completed.resources.fields_v1().parent, completed.source_terminal))
    }
}
