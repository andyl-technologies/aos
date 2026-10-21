//! Commits the actual U exactly once after the genuine Root5 acknowledgment.
//!
//! The positive bank append remains resident even if an independent post or a
//! later original held release fails. Nothing resets, refunds or releases U.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::{AccountTransition, ReturnedAppend, bank};
use super::bank_append::{CreateStorageUseBankOriginalsV1, UseBankObservationOriginalsV1};
use super::super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1};
use std::error::Error;

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct UseCommitOriginalsV1 {
    entered: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<super::super::cache_receiving::OriginalCacheAssociationV1, ResourceReservationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    observations: UseBankObservationOriginalsV1,
    append: Option<ReturnedAppend>,
    history: Option<Result<(), ResourceReservationErrorV1>>,
    primary: Option<Result<(), ResourceReservationErrorV1>>,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
}

pub(in crate::controller_resource_reservation)
fn commit_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bytes = std::mem::size_of::<UseCommitOriginalsV1>().checked_mul(2)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let mut demand = ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .checked_add(CreateStorageUseBankOriginalsV1::fixed_receiving_demand_v1()?)?
        .checked_add(CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2)?)?;
    let (wire, logs) = ProductionControllerNormalRootProfileV1::create_storage_producer_traffic_bound_v1(2)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    demand = demand.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))?;
    Ok(demand)
}

impl UseCommitOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.returned_position()
    }

    fn returned_position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.require_committed()?;
        self.observations.completed_position_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry).or_else(|| error(&self.association)).or_else(|| error(&self.funding))
            .or_else(|| self.before.failure()).or_else(|| error(&self.before_result))
            .or_else(|| self.observations.primary_failure())
            .or_else(|| self.append.as_ref().and_then(ReturnedAppend::failure))
            .or_else(|| self.observations.post_failure()).or_else(|| error(&self.history))
            .or_else(|| error(&self.primary)).or_else(|| self.after.failure()).or_else(|| error(&self.after_result))
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Commits the original U only after the actual completed Root5 turn.
    ///
    /// The same native bank engine checks the immutable U binding, exact C9
    /// position and original Root5 clock/cutoff at both crossings. Its positive
    /// append remains permanently retained if any later post or release fails.
    ///
    /// # Errors
    /// Refuses reentry, incomplete C9/Root5, changed originals, admission debt,
    /// bank/native/readback/history or an independently owed currentness post.
    #[doc(hidden)]
    pub fn commit_original_storage_use_once(&mut self) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.commit.started() {
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.owner.storage_use.commit.entered = true;
        let entry = self.original.require_operation_currentness_peak_v1(&self.cache);
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        let progress = &mut actual.commit;
        progress.entry = Some(entry);
        progress.primary = Some((|| {
            if !matches!(progress.entry, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
            let state = self.original.controller.controller_resource_state_v1()?;
            actual.reservation.require_current_state_v1(&owner.parent, state)?;
            let original_claim = actual.reservation.returned_transition_v1()?.claim;
            let before = bank::find_head(state, original_claim.native_fields().account)?;
            let (prepared, append, width, receiving) = actual.reservation.split_commit_inputs_v1()?;
            let reserved = OriginalCreateStorageUseReservedV1 { append, request_shape_bytes: width, record: &actual.reserved };
            let recorded = super::outcome::completed_outcome_view_v1(reserved, &actual.outcome)?;
            let root = owner.root_exchange.borrow_outcome_v1(&recorded)?;
            progress.association = Some(owner.cache_capture.currentness_association_v1());
            let expected = progress.association.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            progress.funding = Some(commit_receiving_demand_v1().and_then(|demand| receiving.reserve_once(demand)));
            if !matches!(progress.funding, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
            progress.before_result = Some(progress.before.observe_operation_once(CacheControlOriginalsV1 {
                parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
                source: self.original.source, profile: self.original.profile,
            }, &(&self.cache).currentness_original_v1(), expected, recorded.position_v1()));
            if !matches!(progress.before_result, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
            let authorization = owner.root_exchange.borrow_use_authorization_v1()?;
            let transition = AccountTransition::commit_create_storage_use(before, prepared.claim,
                prepared.binding, root.clock_v1()?);
            let original = CreateStorageUseBankOriginalsV1::commit(&owner.parent, &owner.intake,
                &actual.validated, &authorization, prepared, &progress.observations, &recorded, &root)?;
            progress.append = Some(ReturnedAppend::new());
            progress.append.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .append_create_storage_use_into(self.original.controller, transition, original);
            progress.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.require_committed()?;
            let mut loan = receiving.borrow_native_history_once(
                &owner.parent, &owner.intake, &authorization)?;
            progress.history = Some(self.original.controller.require_controller_resource_history_for_create_storage_use_v1(&mut loan));
            if matches!(progress.history, Some(Ok(()))) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
        })());
        if matches!(progress.funding, Some(Ok(()))) {
            // A failed or ambiguous commit supplies Err rather than an earlier
            // C9 position. The same independent observation still runs.
            if let Some(expected) = progress.association.as_ref().map(|result| result.as_ref()).and_then(Result::ok).copied() {
                let current = progress.returned_position();
                progress.after_result = Some(progress.after.observe_operation_once(CacheControlOriginalsV1 {
                    parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
                    source: self.original.source, profile: self.original.profile,
                }, &(&self.cache).currentness_original_v1(), expected, current));
            }
        }
        progress.complete = matches!(progress.primary, Some(Ok(())))
            && matches!(progress.after_result, Some(Ok(()))) && progress.failure().is_none();
        if !progress.complete {
            // Earlier native/semantic cause stays in the commit owner. This
            // sole negative post borrows only the already paid original U.
            if let Ok((_, receiving)) = actual.reservation.split_retained_root_receiving_after_debt_v1() {
                let _ = owner.root_exchange.observe_use_commit_entry_refusal_once(&owner.parent, &mut owner.intake,
                    self.original.controller, self.original.source, self.original.profile, &mut self.cache,
                    progress, receiving);
            }
            return Err(CreateStorageReadyClosedV1);
        }
        Ok(())
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

/// Borrows only the completed native positive commit beside its real C9/U.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageUseCommittedV1<'held> {
    commit: &'held UseCommitOriginalsV1,
    recorded: OriginalCreateStorageOutcomeV1<'held>,
}

pub(super) fn completed_committed_view_v1<'held>(reserved: OriginalCreateStorageUseReservedV1<'held>,
    outcome: &'held super::super::super::history::outcome::OutcomeOriginalsV1,
    commit: &'held UseCommitOriginalsV1,
) -> Result<OriginalCreateStorageUseCommittedV1<'held>, ResourceReservationErrorV1> {
    commit.position()?;
    let recorded = super::outcome::completed_outcome_view_v1(reserved, outcome)?;
    Ok(OriginalCreateStorageUseCommittedV1 { commit, recorded })
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn split_committed_receiving_v1(&mut self)
        -> Result<(OriginalCreateStorageUseCommittedV1<'_>, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.commit.position()?;
        let (_, append, width, receiving) = self.reservation.split_commit_inputs_v1()?;
        let reserved = OriginalCreateStorageUseReservedV1 { append, request_shape_bytes: width, record: &self.reserved };
        Ok((completed_committed_view_v1(reserved, &self.outcome, &self.commit)?, receiving))
    }
}

impl<'held> OriginalCreateStorageUseCommittedV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> { self.commit.position() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn recorded_v1(&self) -> &OriginalCreateStorageOutcomeV1<'held> { &self.recorded }

    pub(in crate::controller_resource_reservation::create_intake)
    fn transition_v1(&self) -> Result<&'held AccountTransition, ResourceReservationErrorV1> {
        self.position_v1()?;
        let actual: &'held UseCommitOriginalsV1 = self.commit;
        let transition = actual.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.require_committed()?;
        if transition.claim.native_fields().state != bank::ClaimState::Committed
            || transition.previous_claim != Some(self.recorded.reserved_v1().claim_v1()?) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(transition)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_current_state_v1(&self, state: &crate::controller_resource_reservation::State)
        -> Result<(), ResourceReservationErrorV1> {
        let actual = self.transition_v1()?;
        let binding = actual.create_storage_use.ok_or(ResourceReservationErrorV1::Conflict)?;
        let (head, claim) = binding.committed_replayed_pair_v1(state, self.recorded.reserved_v1().claim_v1()?)?;
        if head != actual.after || claim != actual.claim { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_commit_keeps_original_native_cause_and_has_no_completed_position() {
        let mut actual = UseCommitOriginalsV1::default();
        actual.entered = true;
        let mut append = ReturnedAppend::new();
        append.native = Some(Err(crate::journal::JournalError::Io(std::io::Error::from_raw_os_error(5))));
        actual.append = Some(append);
        actual.after_result = Some(Err(ResourceReservationErrorV1::Conflict));

        let first = actual.failure().unwrap();

        assert!(matches!(first.downcast_ref::<crate::journal::JournalError>(),
            Some(crate::journal::JournalError::Io(error)) if error.raw_os_error() == Some(5)));
        assert!(actual.position().is_err());
        assert!(actual.append.as_ref().unwrap().native.is_some());
    }
}
