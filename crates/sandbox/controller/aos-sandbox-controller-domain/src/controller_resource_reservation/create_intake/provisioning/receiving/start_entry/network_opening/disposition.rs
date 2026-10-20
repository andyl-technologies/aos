//! Retires one completed resource's actual upper and native representations.
//!
//! A borrowed genuine Root completion precedes construction. The actual SDK
//! consumes its Session, control and IO owners before completing this token;
//! no decoded acknowledgement or caller amount can prepare this transition.

use super::*;
use super::super::resource_state::StartResourceKindV2;
use crate::normal_root::RootStartResourceCompletedOriginalV2;

/// Holds the same Entry and endpoint until actual SDK disposal completes.
#[doc(hidden)]
#[must_use = "complete only after physically disposing the same successful SDK owners"]
pub struct StartResourceUpperDisposalV2<'held> {
    kind: StartResourceKindV2,
    entry: &'held mut AcceptedStartEntryOriginalV1,
    opening: Option<&'held mut StartResourceSessionOpeningOriginalV2>,
    prepared: &'held mut PreparedStartResourceRequestOriginalV2,
    completed_resident: ResourceVector,
    completed_model_turn: u64,
    finished: bool,
}

impl AcceptedStartEntryOriginalV1 {
    /// Prepares only the genuine Network completion's physical upper disposal.
    ///
    /// # Errors
    /// Refuses a foreign Root/Entry/C, an incomplete purpose stage, missing
    /// actual SDK/Session association or any retained financial/native error.
    #[doc(hidden)]
    pub fn prepare_completed_network_upper_disposal_v2<'held>(
        &'held mut self,
        opening: &'held mut StartResourceSessionOpeningOriginalV2,
        prepared: &'held mut PreparedStartResourceRequestOriginalV2,
        completed: &RootStartResourceCompletedOriginalV2,
        controller: &Journal,
        retained_model_bytes: usize,
    ) -> Result<StartResourceUpperDisposalV2<'held>, ResourceReservationErrorV1> {
        self.prepare_completed_resource_upper_disposal_v2(StartResourceKindV2::Network,
            opening, prepared, completed, controller, retained_model_bytes)
    }

    /// Prepares the actual Mount completion's physical upper disposal.
    ///
    /// # Errors
    /// Refuses a foreign completion, incomplete four-turn stage or live failure.
    #[doc(hidden)]
    pub fn prepare_completed_mount_upper_disposal_v2<'held>(
        &'held mut self,
        opening: &'held mut StartResourceSessionOpeningOriginalV2,
        prepared: &'held mut PreparedStartResourceRequestOriginalV2,
        completed: &RootStartResourceCompletedOriginalV2,
        controller: &Journal,
        retained_model_bytes: usize,
    ) -> Result<StartResourceUpperDisposalV2<'held>, ResourceReservationErrorV1> {
        self.prepare_completed_resource_upper_disposal_v2(StartResourceKindV2::Mount,
            opening, prepared, completed, controller, retained_model_bytes)
    }

    /// Prepares the actual Host completion's physical upper disposal.
    ///
    /// # Errors
    /// Refuses a foreign completion, incomplete four-turn stage or live failure.
    #[doc(hidden)]
    pub fn prepare_completed_host_upper_disposal_v2<'held>(
        &'held mut self,
        opening: &'held mut StartResourceSessionOpeningOriginalV2,
        prepared: &'held mut PreparedStartResourceRequestOriginalV2,
        completed: &RootStartResourceCompletedOriginalV2,
        controller: &Journal,
    ) -> Result<StartResourceUpperDisposalV2<'held>, ResourceReservationErrorV1> {
        self.prepare_completed_resource_upper_disposal_v2(StartResourceKindV2::Host,
            opening, prepared, completed, controller, 0)
    }

    fn prepare_completed_resource_upper_disposal_v2<'held>(
        &'held mut self,
        kind: StartResourceKindV2,
        opening: &'held mut StartResourceSessionOpeningOriginalV2,
        prepared: &'held mut PreparedStartResourceRequestOriginalV2,
        completed: &RootStartResourceCompletedOriginalV2,
        controller: &Journal,
        retained_model_bytes: usize,
    ) -> Result<StartResourceUpperDisposalV2<'held>, ResourceReservationErrorV1> {
        match kind {
            StartResourceKindV2::Network => completed.require_network_disposition_v2(self, controller),
            StartResourceKindV2::Mount => completed.require_mount_disposition_v2(self, controller),
            StartResourceKindV2::Host => completed.require_host_disposition_v2(self, controller),
            StartResourceKindV2::Storage => return Err(CLOSED),
        }.map_err(|_| CLOSED)?;
        let stages = self.resource_entries.member_v2(kind);
        let required_turns = if kind == StartResourceKindV2::Host { 7 } else { 4 };
        if self.failure().is_some() || opening.failure().is_some() || prepared.failure().is_some()
            || prepared.purpose_data_v2() != kind.purpose_v2()
            || opening.actual_role_v2() != kind.role_v2()
            || stages.turn_next.iter().take(required_turns).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_before.iter().take(required_turns).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_after.iter().take(required_turns).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_root_after.iter().take(required_turns).any(|value| !matches!(value, Some(Ok(())))) {
            return Err(CLOSED);
        }
        let state = self.native_state.as_mut().ok_or(CLOSED)?;
        let member = state.resources.member_v2(kind);
        if member.completed_resident.is_some() || !member.io_loan_entered
            || member.session_resident.as_ref().is_none_or(|value| value.is_err()) {
            return Err(CLOSED);
        }
        let identity = self.identity.as_ref().map_err(|_| CLOSED)?;
        opening.completed_session_association_v4().ok_or(CLOSED)?
            .require_start_v4(identity, self.body.plan_v1()?.operation_id(), &state.profile)?;
        let native = state.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .prepare_start_resource_endpoint_disposition_v2(&mut opening.endpoint,
                native.original_v1(), controller, state.profile.as_ref())?;
        // Actual SDK passes the format-owned residue of its sole-decoded
        // models. They move without allocation from the already-paid flight.
        let completed_resident = completed.completed_receiving_demand_v2().map_err(|_| CLOSED)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(retained_model_bytes).map_err(|_| CLOSED)?))?;
        let completed_model_turn = completed.completed_model_turn_data_v2();
        Ok(StartResourceUpperDisposalV2 {
            kind, entry: self, opening: Some(opening), prepared, completed_resident, completed_model_turn, finished: false,
        })
    }
}

impl StartResourceUpperDisposalV2<'_> {
    /// Physically retires the positive Domain representations after SDK disposal.
    ///
    /// # Errors
    /// Refuses an unexpected remaining native custody borrower. The token's
    /// abandonment guard keeps such a failed disposition fail closed.
    pub fn complete_after_sdk_disposal_v2(mut self) -> Result<(), ResourceReservationErrorV1> {
        // The completed association is the Domain half of the same endpoint.
        // SDK has disposed its Journal/socket first; no future native debt is
        // represented by the positive cold-completion controls below.
        if let Some(opening) = self.opening.as_mut() {
            opening.completion = StartResourceColdCompletionOriginalV4::new();
            opening.opening = None;
            opening.endpoint.complete_positive_disposition_v2().map_err(ResourceReservationErrorV1::from)?;
        }
        self.prepared.dispose_completed_representation_v2();
        let state = self.entry.native_state.as_mut().ok_or(CLOSED)?;
        let member = state.resources.member_mut_v2(self.kind);
        *member.io = Default::default();
        member.retained_create_join = None;
        member.retained_create_demand = None;
        member.retained_create_funding = None;
        *member.post = Default::default();
        member.content_resident = None;
        member.preparation_resident = None;
        member.session_resident = None;
        member.completed_resident = Some(self.completed_resident);
        member.completed_model_turn = Some(self.completed_model_turn);
        // The original C ledger retains every spent traffic dimension and its
        // highwater. Only physically absent resident owners leave the next sum.
        self.finished = true;
        Ok(())
    }
}

impl Drop for StartResourceUpperDisposalV2<'_> {
    fn drop(&mut self) {
        if !self.finished { std::process::abort(); }
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Prepares retirement of fresh31/18 while the actual Create Session stays held.
    ///
    /// The original Session remains represented by permanent Create history.
    /// Only completed native observations retire; the exact decoded model residue survives.
    ///
    /// # Errors
    /// Refuses changed Storage completion, incomplete four-turn posts, missing
    /// actual held-session rejoin, unfinished IO or any retained original failure.
    #[doc(hidden)]
    pub fn prepare_completed_storage_upper_disposal_v2<'held>(
        &'held mut self,
        prepared: &'held mut PreparedStartResourceRequestOriginalV2,
        completed: &RootStartResourceCompletedOriginalV2,
        controller: &Journal,
        retained_model_bytes: usize,
    ) -> Result<StartResourceUpperDisposalV2<'held>, ResourceReservationErrorV1> {
        completed.require_storage_disposition_v2(self, controller).map_err(|_| CLOSED)?;
        let stages = &self.resource_entries.storage;
        if self.failure().is_some() || prepared.failure().is_some()
            || prepared.purpose_data_v2() != StartResourceKindV2::Storage.purpose_v2()
            || stages.turn_next.iter().take(4).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_before.iter().take(4).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_after.iter().take(4).any(|value| !matches!(value, Some(Ok(()))))
            || stages.turn_root_after.iter().take(4).any(|value| !matches!(value, Some(Ok(())))) {
            return Err(CLOSED);
        }
        let member = &self.native_state.as_ref().ok_or(CLOSED)?.resources.storage;
        if member.completed_resident.is_some() || !member.io_loan_entered
            || !matches!(member.session_resident, Some(Ok(_)))
            || !matches!(member.retained_create_join, Some(Ok(()))) {
            return Err(CLOSED);
        }
        // Actual SDK passes the format-owned residue of its sole-decoded
        // models. They move without allocation from the already-paid flight.
        let completed_resident = completed.completed_receiving_demand_v2().map_err(|_| CLOSED)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(retained_model_bytes).map_err(|_| CLOSED)?))?;
        let completed_model_turn = completed.completed_model_turn_data_v2();
        Ok(StartResourceUpperDisposalV2 {
            kind: StartResourceKindV2::Storage, entry: self, opening: None,
            prepared, completed_resident, completed_model_turn, finished: false,
        })
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Checks the actual disposed Host before entering public Start terminal work.
    ///
    /// The marker below is written only by the consuming SDK/native disposal
    /// above. The opaque Root original independently binds the same Entry,
    /// profile and actual final C ordinal. This does not advance C or mint a
    /// source transaction, terminal record or another native account.
    ///
    /// # Errors
    /// Refuses missing SDK/native disposal, a foreign Host completion, incomplete
    /// seven-stage posts, changed current C or any retained Entry failure.
    #[doc(hidden)]
    pub fn require_completed_host_disposition_v2(
        &self, completed: &RootStartResourceCompletedOriginalV2, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        completed.require_host_disposition_v2(self, controller).map_err(|_| CLOSED)?;
        let stages = &self.resource_entries.host;
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        let member = &state.resources.host;
        if self.failure().is_some() || stages.active_turn != Some(3)
            || stages.turn_next.iter().any(|result| !matches!(result, Some(Ok(()))))
            || stages.turn_before.iter().any(|result| !matches!(result, Some(Ok(()))))
            || stages.turn_after.iter().any(|result| !matches!(result, Some(Ok(()))))
            || stages.turn_root_after.iter().any(|result| !matches!(result, Some(Ok(()))))
            || member.completed_resident.is_none()
            || member.completed_model_turn != Some(completed.completed_model_turn_data_v2())
            || member.content_resident.is_some() || member.preparation_resident.is_some()
            || member.session_resident.is_some()
        {
            return Err(CLOSED);
        }
        Ok(())
    }
}
