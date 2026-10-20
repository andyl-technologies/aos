//! Pays fresh D-only profile bookends on the same consumed C17 operation.
//!
//! Outer native destinations0..3 retain their once-only law. These separate
//! destinations4..7 reuse the same Producer engine only after actual complete
//! upper IO disposal. Their traffic is cumulative on the original finite slot.

use super::*;
use crate::receiving::OriginalEnrollment;
use crate::controller_receiving::ControllerReceivingErrorV1;
use aos_sandbox_core::component_receiving::{complete_bound_delta_v1, operation_traffic_demand_v1};

/// Retains a genuine D preaccept turn's native before and independently owed after.
///
/// Construction requires the actual active C17 loan's joined Source scope.
/// This owner clones only the SAME financial/identity Arcs, never a native
/// writer, File, capacity vector or account. It grants no Inventory or effect.
#[must_use]
pub struct ControllerDeletePreacceptTurnOriginalV1<'profile> {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    profile: &'profile ControllerSelfProfileOriginalV1,
    before: ControllerOriginalObservationV1,
    after: ControllerOriginalObservationV1,
    entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    entry_financial: bool,
    before_result: Option<Result<OriginalEnrollment, ControllerReceivingErrorV1>>,
    before_gate: Option<Result<(), ControllerBankLaunchErrorV1>>,
    before_gate_financial: bool,
    after_result: Option<Result<OriginalEnrollment, ControllerReceivingErrorV1>>,
    after_gate: Option<Result<(), ControllerBankLaunchErrorV1>>,
    after_gate_financial: bool,
    reentry: Option<ControllerBankLaunchErrorV1>,
    refusal_stage: Option<RefusalStage>,
    completed: bool,
    ordinal: u64,
}

#[derive(Clone, Copy)]
enum RefusalStage { Before, Between, After }

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    /// Prepays a D-only native turn before any primary profile or upper IO.
    ///
    /// The caller supplies complete reached upper demand, not a capacity.
    /// Private per-turn profile costs are added to the SAME actual complete
    /// frontier, preserving interleaved append/Root/IO debt. Already-entered
    /// outer posts stay separately paid; no caller stage max restores traffic.
    ///
    /// # Errors
    /// Refuses absent Source association, foreign C/profile/Launch, an active
    /// prior turn, overflow or actual same-C17 complete admission before IO.
    pub fn prepare_delete_preaccept_turn_v1<'profile, P>(
        &mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerDeletePreacceptTurnOriginalV1<'profile>, ControllerBankLaunchErrorV1> {
        match self.prepare_delete_preaccept_turn_inner_v1(writer, launch, profile, complete) {
            Ok(turn) => Ok(turn),
            Err(cause) => Err(self.retain_delete_preaccept_refusal_v1(writer, cause)),
        }
    }

    fn prepare_delete_preaccept_turn_inner_v1<'profile, P>(
        &mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerDeletePreacceptTurnOriginalV1<'profile>, ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Delete
            || !self.delete_source_scope_entered || !self.owner.delete_source_scope_open
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.require_active_v1(writer, launch, profile)?;
        let (next, previous_resident) = {
            let mut state = self.owner.original.operation_intakes.try_lock()
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let slot = state.slot_mut(OperationIntakePurposeV1::Delete);
            (slot.next_delete_preaccept_turn_v1()?, slot.delete_preaccept_resident_v1())
        };
        let profile_demand = profile.operation_intake_demand_v1()?;
        let observation = ControllerOriginalObservationV1::receiving_demand_v1()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let fixed = std::mem::size_of::<ControllerDeletePreacceptTurnOriginalV1<'_>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerDeletePreacceptTurnDisposalV1<'_>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerOperationIntakeFailureViewV1<'_>>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let private = profile_demand.checked_add(observation)?.checked_add(observation)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))?;
        let native = ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?;
        let previous = *self.owner.entry.whole_required.as_ref()
            .and_then(|required| required.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let (required, resident) = complete_preaccept_requirement_v1(
            previous, native, complete.demand, previous_resident, private,
        )?;
        self.require_delete_complete_v1(writer, launch, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(required))?;
        self.owner.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(OperationIntakePurposeV1::Delete).arm_delete_preaccept_turn_v1(next, resident)?;
        Ok(ControllerDeletePreacceptTurnOriginalV1 {
            original: Arc::clone(&self.owner.original), identity: Arc::clone(&self.owner.identity),
            profile, before: ControllerOriginalObservationV1::new(), after: ControllerOriginalObservationV1::new(),
            entry: None, entry_financial: false,
            before_result: None, before_gate: None, before_gate_financial: false,
            after_result: None, after_gate: None, after_gate_financial: false,
            reentry: None, refusal_stage: None, completed: false, ordinal: next,
        })
    }
}

impl ControllerDeletePreacceptTurnOriginalV1<'_> {
    /// Returns the actual finite turn ordinal selected by the same D slot.
    ///
    /// This immutable DATA cannot construct a turn or authorize IO. Genuine
    /// borrowers separately require this same entered/current native owner.
    #[doc(hidden)]
    #[must_use]
    pub const fn native_turn_ordinal_data_v3(&self) -> u64 {
        self.ordinal
    }

    /// Samples the same fixed profile/pair/profile before primary upper IO.
    ///
    /// # Errors
    /// Retains the actual native/profile cause or refuses reentry/foreign C.
    /// The separately paid after remains owed even when this sample refuses.
    pub fn observe_before_once_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if self.completed || self.entry.is_some() || self.before_result.is_some() || self.after_result.is_some()
            || !self.same_writer(writer) {
            self.refuse();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let (entry, financial) = self.active_gate();
        self.entry = Some(entry);
        self.entry_financial = financial;
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.before_result = Some(self.before.observe_operation_intake_once_v1(
            &self.original, self.profile, OperationIntakePurposeV1::Delete, 4));
        // A separate attempted turn can close this SAME financial slot while
        // a profile/native sample is resident. It cannot authorize primary IO.
        let (gate, financial) = self.active_gate();
        self.before_gate = Some(gate);
        self.before_gate_financial = financial;
        if matches!(self.before_result, Some(Ok(_)))
            && matches!(self.before_gate, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerBankLaunchErrorV1::Conflict) }
    }

    /// Checks this entered Delete turn before a prepaid Cache read frontier.
    ///
    /// This lends no new capacity and performs no IO, observation, debit or
    /// rearm. The actual same-C caller already paid the complete five-owner
    /// bound; the Cache reader remains inside this original primary interval.
    ///
    /// # Errors
    /// Refuses an unentered, failed, finished, substituted or closed D slot and
    /// keeps its independent already-paid after observation owed.
    pub fn require_prepaid_cache_read_frontier_v1(&mut self)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_prepaid_primary_frontier_v2()
    }

    /// Requires the entered paid D construction interval before plan signing.
    ///
    /// This performs no IO, debit, observation, capacity reset or effect
    /// admission. The enclosing actual D borrower must independently retain
    /// its Source/Root association, full canonical plan and original horizon.
    ///
    /// # Errors
    /// Retains reentry, incomplete/failed native before or the same active
    /// original financial gate's refusal; the independent after stays owed.
    pub fn require_prepaid_delete_plan_signing_frontier_v2(&mut self)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_prepaid_primary_frontier_v2()
    }

    fn require_prepaid_primary_frontier_v2(&mut self)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if self.completed || self.reentry.is_some() || self.after_result.is_some()
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.before_result, Some(Ok(_)))
            || !matches!(self.before_gate, Some(Ok(()))) || self.before.value().is_none()
        {
            self.refuse();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // This is a pure strengthening of the primary financial gate. Keep
        // its actual failure classification for the existing first-cause view;
        // the complete native before observation remains independently held.
        let (gate, financial) = self.active_gate();
        self.before_gate = Some(gate);
        self.before_gate_financial = financial;
        if matches!(self.before_gate, Some(Ok(()))) { Ok(()) }
        else {
            self.refuse();
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    /// Attempts the independently prepaid after even after primary refusal.
    ///
    /// This uses the same entered finite slot directly. It performs no fresh
    /// healthy admission or debit after the body/profile may have poisoned C17.
    ///
    /// # Errors
    /// Retains the actual after cause and any earlier before/reentry refusal.
    pub fn observe_after_once_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if self.completed || self.after_result.is_some() {
            self.refuse();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        if !self.same_writer(writer) || self.before_result.is_none() { self.refuse(); }
        self.after_result = Some(self.after.observe_operation_intake_once_v1(
            &self.original, self.profile, OperationIntakePurposeV1::Delete, 6));
        let (gate, financial) = self.active_gate();
        self.after_gate = Some(gate);
        self.after_gate_financial = financial;
        if self.reentry.is_none() && matches!(self.before_result, Some(Ok(_)))
            && matches!(self.before_gate, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(_)))
            && matches!(self.after_gate, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerBankLaunchErrorV1::Conflict) }
    }

    /// Refuses a failed consumer while preserving its independently owed after.
    ///
    /// The actual caller retains its complete primary error before this call.
    /// This performs no Native IO or new debit and cannot restore any capacity.
    /// It also makes failed reentry after a prior local disposal sticky on the
    /// SAME outer C17, rather than leaving its release predicate positive.
    pub fn refuse_primary_v1(&mut self) {
        self.refuse();
    }

    fn active_gate(&self) -> (Result<(), ControllerBankLaunchErrorV1>, bool) {
        match self.original.operation_intakes.try_lock() {
            Ok(state) => {
                let slot = state.slot(OperationIntakePurposeV1::Delete);
                (slot.require_active().map_err(ControllerBankLaunchErrorV1::from), slot.failure().is_some())
            }
            Err(_) => (Err(ControllerBankLaunchErrorV1::Conflict), false),
        }
    }

    // Only a financial failure present at this actual gate can replace its
    // marker. A later failed stage must not mask an earlier concrete refusal.
    fn gate_failure<'cause>(&'cause self,
        result: &'cause Option<Result<(), ControllerBankLaunchErrorV1>>,
        financial: bool,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'cause>> {
        let cause = result.as_ref()?.as_ref().err()?;
        if financial {
            if let Ok(state) = self.original.operation_intakes.try_lock() {
                if state.slot(OperationIntakePurposeV1::Delete).failure().is_some() {
                    return Some(ControllerOperationIntakeFailureViewV1 {
                        cause: FailureCause::Financial(state, OperationIntakePurposeV1::Delete),
                    });
                }
            }
        }
        Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Native(cause) })
    }

    fn same_writer<P>(&self, writer: &ControllerCoordinatorWriterV1<P>) -> bool {
        Arc::ptr_eq(&self.identity, writer.fixed.identity())
            && writer.fixed.has_original(&self.original)
            && self.profile.has_same_baseline_original(&self.original)
    }

    fn refuse(&mut self) {
        self.reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
        if self.refusal_stage.is_none() {
            self.refusal_stage = Some(if self.after_result.is_some() { RefusalStage::After }
                else if self.before_result.is_some() { RefusalStage::Between } else { RefusalStage::Before });
        }
        match self.original.operation_intakes.try_lock() {
            Ok(mut state) => state.slot_mut(OperationIntakePurposeV1::Delete).refuse_delete_preaccept_turn_v1(),
            Err(_) => std::process::abort(),
        }
    }

    /// Borrows the exact first raw cause under the same original/profile guard.
    ///
    /// The upper caller resolves only its actual native marker through this
    /// view, preserving an earlier concrete IO/decoder failure over later posts.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<ControllerOperationIntakeFailureViewV1<'_>> {
        if let Some(view) = self.gate_failure(&self.entry, self.entry_financial) {
            return Some(view);
        }
        if matches!(self.refusal_stage, Some(RefusalStage::Before)) {
            return self.reentry.as_ref().map(|cause| ControllerOperationIntakeFailureViewV1 {
                cause: FailureCause::Native(cause),
            });
        }
        for (observation, first_slot) in [(&self.before, 4), (&self.after, 6)] {
            if first_slot == 6 {
                if let Some(view) = self.gate_failure(&self.before_gate, self.before_gate_financial) {
                    return Some(view);
                }
            }
            if first_slot == 6 && matches!(self.refusal_stage, Some(RefusalStage::Between)) {
                return self.reentry.as_ref().map(|cause| ControllerOperationIntakeFailureViewV1 {
                    cause: FailureCause::Native(cause),
                });
            }
            if let Some(slot) = observation.operation_profile_failure_slot_v1(first_slot) {
                if let Some(view) = self.profile.operation_intake_failure_view_v1(OperationIntakePurposeV1::Delete, slot) {
                    return Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Profile(view) });
                }
            }
            if let Some(cause) = observation.failure() {
                return Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Native(cause) });
            }
        }
        if let Some(view) = self.gate_failure(&self.after_gate, self.after_gate_financial) {
            return Some(view);
        }
        if let Some(cause) = &self.reentry {
            return Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Native(cause) });
        }
        let state = self.original.operation_intakes.try_lock().ok()?;
        state.slot(OperationIntakePurposeV1::Delete).failure().is_some().then_some(
            ControllerOperationIntakeFailureViewV1 {
                cause: FailureCause::Financial(state, OperationIntakePurposeV1::Delete),
            },
        )
    }

    /// Keeps the same finite slot closed while successful upper receipts dispose.
    ///
    /// The actual Security caller must drop its same successful/nonconsuming IO
    /// capsule before this token completes. No semantic completion is inferred.
    ///
    /// # Errors
    /// Refuses incomplete/failed/foreign/repeated native intervals. The returned
    /// guard holds the exact slot lock, so completion performs no fallible work.
    pub fn prepare_positive_disposal_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>)
        -> Result<ControllerDeletePreacceptTurnDisposalV1<'_>, ControllerBankLaunchErrorV1>
    {
        if self.completed || self.reentry.is_some() || !self.same_writer(writer)
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.before_result, Some(Ok(_))) || !matches!(self.before_gate, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(_))) || !matches!(self.after_gate, Some(Ok(())))
            || self.before.value().is_none() || self.after.value().is_none()
        {
            self.refuse();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let mut state = self.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        state.slot_mut(OperationIntakePurposeV1::Delete).prepare_delete_preaccept_disposal_v1()?;
        Ok(ControllerDeletePreacceptTurnDisposalV1 { state,
            before: &mut self.before, after: &mut self.after,
            completed: &mut self.completed, token_completed: false,
        })
    }
}

/// Holds the actual D slot through positive upper and native disposal.
#[must_use]
pub struct ControllerDeletePreacceptTurnDisposalV1<'turn> {
    state: MutexGuard<'turn, ControllerOperationIntakesV1>,
    before: &'turn mut ControllerOriginalObservationV1,
    after: &'turn mut ControllerOriginalObservationV1,
    completed: &'turn mut bool,
    token_completed: bool,
}

impl ControllerDeletePreacceptTurnDisposalV1<'_> {
    /// Disposes actual positive native observations after the same upper capsule.
    ///
    /// No capacity or spent traffic is restored. Clearing these distinct slots
    /// permits only another separately prepaid D turn under the same C17.
    pub fn complete_after_upper_disposal_v1(mut self) {
        drop(std::mem::replace(self.before, ControllerOriginalObservationV1::new()));
        drop(std::mem::replace(self.after, ControllerOriginalObservationV1::new()));
        self.state.slot_mut(OperationIntakePurposeV1::Delete).complete_delete_preaccept_disposal_v1();
        *self.completed = true;
        self.token_completed = true;
    }
}

impl Drop for ControllerDeletePreacceptTurnDisposalV1<'_> {
    fn drop(&mut self) {
        if !self.token_completed {
            self.state.slot_mut(OperationIntakePurposeV1::Delete).refuse_delete_preaccept_turn_v1();
        }
    }
}

impl Drop for ControllerDeletePreacceptTurnOriginalV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Keep all native/financial originals resident through termination.
            std::process::abort();
        }
    }
}

// The common complete checker adds the outer native tranche back once.
// This increment starts from the actual held frontier, including all earlier
// interleaved callers, rather than reconstructing it from their DATA maxima.
pub(super) fn additional_preaccept_requirement_v1(
    previous: ResourceVector,
    native: ResourceVector,
    additional: ResourceVector,
) -> Result<ResourceVector, aos_sandbox_core::AccountingError> {
    previous.checked_sub(native)?.checked_add(additional)
}

// A reached private turn adds traffic to the real whole-flight frontier. Only
// a positively retired private resident peak can be reused; interleaved upper
// append/Root/transport debt is never replaced by a caller's smaller stage max.
fn complete_preaccept_requirement_v1(
    previous: ResourceVector,
    native: ResourceVector,
    complete: ResourceVector,
    previous_resident: ResourceVector,
    private: ResourceVector,
) -> Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError> {
    let traffic = operation_traffic_demand_v1(private);
    let resident = private.checked_sub(traffic)?;
    let (_, resident_delta) = complete_bound_delta_v1(previous_resident, resident)?;
    // The existing common complete checker adds this outer tranche once.
    let base = previous.checked_sub(native)?.componentwise_max(complete);
    Ok((base.checked_add(resident_delta)?.checked_add(traffic)?, resident))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_append_debt_survives_an_equal_next_profile_stage() {
        let outer = ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::NetworkBytes, 10);
        let upper = ResourceVector::ZERO.with(D::MemoryBytes, 200).with(D::NetworkBytes, 20)
            .with(D::LogBytes, 30);
        let private = ResourceVector::ZERO.with(D::MemoryBytes, 300).with(D::OpenFiles, 2)
            .with(D::NetworkBytes, 5).with(D::LogBytes, 7);
        let initial = upper.checked_add(outer).unwrap();
        let (first, peak) = complete_preaccept_requirement_v1(
            initial, outer, upper, ResourceVector::ZERO, private,
        ).unwrap();
        // The common checker adds outer exactly once, then an independently
        // reached real append schedule is admitted before the next native turn.
        let append = ResourceVector::ZERO.with(D::LogBytes, 41).with(D::StorageBytes, 43);
        let previous = additional_preaccept_requirement_v1(
            first.checked_add(outer).unwrap(), outer, append,
        ).unwrap().checked_add(outer).unwrap();

        let (second, next_peak) = complete_preaccept_requirement_v1(
            previous, outer, upper, peak, private,
        ).unwrap();
        let actual_complete = second.checked_add(outer).unwrap();

        assert_eq!(actual_complete.get(D::NetworkBytes), 40);
        assert_eq!(actual_complete.get(D::LogBytes), 85);
        assert_eq!(actual_complete.get(D::StorageBytes), 43);
        assert_eq!(actual_complete.get(D::MemoryBytes), 600);
        assert_eq!(actual_complete.get(D::OpenFiles), 2);
        assert_eq!(next_peak, peak);
        assert!(complete_preaccept_requirement_v1(
            ResourceVector::ZERO, outer, upper, peak, private,
        ).is_err());
        assert!(additional_preaccept_requirement_v1(
            ResourceVector::ZERO, outer, append,
        ).is_err());
    }
}
