//! Retains a finite cleanup flight on the same consumed current Control.
//!
//! The private constructor first pays the concrete identity/flight carriers on
//! the original residual ledger. Its non-Clone token only rejoins this actual
//! retained original; amounts, request DATA or a stored row cannot recreate it.
//! Every sibling preparation is excluded until genuine native/Sent retirement.

use super::*;
use std::sync::Arc;
use aos_sandbox_model::component_receiving::complete_bound_delta_v1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::plan::deployment::control) enum ControlCleanupPurposeV1 {
    Stop,
    NoApply,
}

struct CleanupIdentityV1 {
    purpose: ControlCleanupPurposeV1,
    initial: Request,
    cutoff: u64,
    resident_launch: Option<Request>,
}

/// Rejoins the actual current-Control cleanup flight without issuing authority.
///
/// Construction is private to the paid native entry. The whole token remains
/// held across authenticated responses; dropping it cannot reset the flight,
/// refund any plane or make an unrelated preparation admissible.
#[must_use = "retain the actual cleanup token through native and authenticated retirement"]
pub(crate) struct HostControlCleanupTokenV1 {
    identity: Arc<CleanupIdentityV1>,
}

impl HostControlCleanupTokenV1 {
    /// Compares actual private identity, never a reconstructed DATA identifier.
    pub(crate) fn rejoins_same_original_v1(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }

    pub(in crate::plan::deployment::control) fn borrow_original_v1(&self) -> Self {
        Self { identity: Arc::clone(&self.identity) }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupTurnV1 {
    Entered,
    BeforeEntered,
    AfterEntered,
    NativeFinished,
    PendingAuthenticated,
    Authenticated,
    Disposing,
}

pub(super) struct ControlCleanupFlightV1 {
    identity: Arc<CleanupIdentityV1>,
    current: Request,
    reached: ResourceVector,
    turn: CleanupTurnV1,
    // One Stop exchange, or NoApply's Preliminary/Lease/Seal/ACK exchanges.
    // Actual destinations remain on the SAME Control; this table only pins
    // the finite native ranges for its final concrete disposal proof.
    destinations: [Option<(usize, usize)>; 4],
    used: usize,
    worker_files_peak: u64,
}

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn cleanup_construction_demand_v1()
        -> Result<ResourceVector, Closed> {
        let bytes = std::mem::size_of::<ControlCleanupFlightV1>().checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<HostControlCleanupTokenV1>().checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<CleanupIdentityV1>()))
            .and_then(|n| n.checked_add(3 * std::mem::size_of::<usize>()))
            .and_then(|n| u64::try_from(n).ok()).ok_or(Closed)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    // Only finite Stop/NoApply current-authorization constructors call this
    // financial body. It creates no effect or permission to restore old owners.
    pub(in crate::plan::deployment::control) fn begin_control_cleanup_v1(
        &mut self,
        purpose: ControlCleanupPurposeV1,
        request: Request,
        cutoff: u64,
        complete: ResourceVector,
    ) -> Result<HostControlCleanupTokenV1, Closed> {
        self.begin_control_cleanup_engine_v2(purpose, request, cutoff, complete, None)
    }

    pub(in crate::plan::deployment::control) fn begin_live_stop_cleanup_v1(
        &mut self,
        request: Request,
        cutoff: u64,
        complete: ResourceVector,
        parent: &crate::broker::HostLiveCleanupParentV1<'_>,
    ) -> Result<HostControlCleanupTokenV1, Closed> {
        let (launch, capture) = parent.original_bindings_v1();
        if capture.is_some()
            || parent
                .resident_native_v1()
                .map_err(|_| Closed)?
                .request_identity_v4()
                != (launch.id, launch.session, launch.signed)
        {
            return Err(Closed);
        }
        self.require_live_cleanup_parent_v1(launch, None)?;
        self.begin_control_cleanup_engine_v2(
            ControlCleanupPurposeV1::Stop,
            request,
            cutoff,
            complete,
            Some(launch),
        )
    }

    fn begin_control_cleanup_engine_v2(
        &mut self,
        purpose: ControlCleanupPurposeV1,
        request: Request,
        cutoff: u64,
        complete: ResourceVector,
        resident_launch: Option<Request>,
    ) -> Result<HostControlCleanupTokenV1, Closed> {
        if !self.control_was_consumed()
            || !self.execution_admitted
            || self.cleanup.is_some()
            || self.active.is_some()
            || self.prepared.is_some()
            || self.flights.iter().enumerate().any(|(index, flight)| {
                flight.request.is_some()
                    && !(index == Phase::Launch.index() && flight.request == resident_launch)
            })
            || self.stop_admission.is_some()
            || self.stop_containment.is_some()
            || request.id == [0; 16]
            || request.session == [0; 32]
            || request.signed == [0; 32]
            || cutoff == 0
        {
            return Err(Closed);
        }
        let complete = complete
            .checked_add(Self::cleanup_construction_demand_v1()?)
            .map_err(|_| Closed)?;
        self.account_control_preparation_engine_v6(complete)?;

        let identity = Arc::new(CleanupIdentityV1 {
            purpose,
            initial: request,
            cutoff,
            resident_launch,
        });
        self.cleanup = Some(ControlCleanupFlightV1 {
            identity: Arc::clone(&identity),
            current: request,
            reached: complete,
            turn: CleanupTurnV1::Entered,
            destinations: [None; 4],
            used: 0,
            worker_files_peak: 0,
        });
        Ok(HostControlCleanupTokenV1 { identity })
    }

    fn cleanup_original_v1(&self, token: &HostControlCleanupTokenV1)
        -> Result<&ControlCleanupFlightV1, Closed> {
        let flight = self.cleanup.as_ref().ok_or(Closed)?;
        if !Arc::ptr_eq(&flight.identity, &token.identity) { return Err(Closed); }
        Ok(flight)
    }

    pub(in crate::plan::deployment::control) fn require_cleanup_current_v1(&self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1, request: Request,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        if !self.control_was_consumed() || !self.execution_admitted
            || flight.identity.purpose != purpose || flight.current != request
            || !matches!(flight.turn, CleanupTurnV1::Entered | CleanupTurnV1::BeforeEntered)
        { return Err(Closed); }
        Ok(())
    }

    // Owed posts rejoin prepaid identity even when later body/financial health
    // failed. They neither admit another body nor replace the first cause.
    pub(in crate::plan::deployment::control) fn require_cleanup_owed_v1(&self,
        token: &HostControlCleanupTokenV1, request: Request,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        if flight.current != request || !matches!(flight.turn,
            CleanupTurnV1::BeforeEntered | CleanupTurnV1::AfterEntered | CleanupTurnV1::NativeFinished)
        { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn raise_cleanup_complete_v1(&mut self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1, request: Request,
        absolute: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_cleanup_current_v1(token, purpose, request)?;
        let previous = self.cleanup_original_v1(token)?.reached;
        let absolute = absolute.checked_add(Self::cleanup_construction_demand_v1()?).map_err(|_| Closed)?;
        let (reached, delta) = complete_bound_delta_v1(previous, absolute).map_err(|_| Closed)?;
        self.account_control_preparation_engine_v6(delta)?;
        self.cleanup.as_mut().ok_or(Closed)?.reached = reached;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn cleanup_remaining_capacity_v1(&self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1, request: Request,
    ) -> Result<ResourceVector, Closed> {
        self.require_cleanup_current_v1(token, purpose, request)?;
        self.control_requirement.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(Closed)
    }

    // Source sample/loan carriers belong to each real exchange. They are not
    // part of the caller's cumulative native/model highwater and never reset it.
    pub(in crate::plan::deployment::control) fn admit_cleanup_observation_v1(&mut self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1,
        request: Request, complete: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_cleanup_current_v1(token, purpose, request)?;
        self.account_control_preparation_engine_v6(complete)
    }

    pub(in crate::plan::deployment::control) fn enter_cleanup_worker_phase_v1(&mut self,
        token: &HostControlCleanupTokenV1, request: Request,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        self.require_cleanup_current_v1(token, ControlCleanupPurposeV1::Stop, request)?;
        if phase.request_identity_v4() != (request.id, request.session, request.signed) {
            return Err(Closed);
        }
        // The actual mechanical roster supplies its live native descriptor
        // term after predecessor disposal. Earlier peaks remain fully charged.
        let files = u64::try_from(phase.current_native_files_v4()).map_err(|_| Closed)?;
        let previous = self.cleanup_original_v1(token)?.worker_files_peak;
        let reached = previous.max(files);
        self.account_control_preparation_engine_v6(ResourceVector::ZERO.with(
            D::OpenFiles, reached.checked_sub(previous).ok_or(Closed)?))?;
        self.cleanup.as_mut().ok_or(Closed)?.worker_files_peak = reached;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn register_cleanup_destinations_v1(&mut self,
        token: &HostControlCleanupTokenV1, round_start: usize, manager_slot: usize,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        let maximum = match flight.identity.purpose { ControlCleanupPurposeV1::Stop => 1,
            ControlCleanupPurposeV1::NoApply => 4 };
        if flight.turn != CleanupTurnV1::Entered || flight.used >= maximum
            || flight.destinations[..flight.used].iter().any(|value|
                value.is_some_and(|(round, slot)| round == round_start || slot == manager_slot))
        { return Err(Closed); }
        let flight = self.cleanup.as_mut().ok_or(Closed)?;
        flight.destinations[flight.used] = Some((round_start, manager_slot));
        flight.used += 1;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn cleanup_destinations_v1(&self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<[Option<(usize, usize)>; 4], Closed> {
        Ok(self.cleanup_original_v1(token)?.destinations)
    }

    pub(in crate::plan::deployment::control) fn require_cleanup_resident_binding_v1(
        &self,
        token: &HostControlCleanupTokenV1,
        resident: Option<Request>,
    ) -> Result<(), Closed> {
        if self.cleanup_original_v1(token)?.identity.resident_launch != resident {
            return Err(Closed);
        }
        Ok(())
    }

    // Each transition is called at the corresponding real current-Control
    // native entry/positive completion, never from a returned success DTO.
    pub(in crate::plan::deployment::control) fn cleanup_before_entered_v1(&mut self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        if self.cleanup_original_v1(token)?.turn != CleanupTurnV1::Entered { return Err(Closed); }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::BeforeEntered;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn cleanup_after_entered_v1(&mut self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        if self.cleanup_original_v1(token)?.turn != CleanupTurnV1::BeforeEntered { return Err(Closed); }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::AfterEntered;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn cleanup_native_finished_v1(&mut self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        if !self.control_was_consumed() || self.cleanup_original_v1(token)?.turn != CleanupTurnV1::AfterEntered {
            return Err(Closed);
        }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::NativeFinished;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn cleanup_retain_pending_v1(&mut self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        if !self.control_was_consumed() || self.cleanup_original_v1(token)?.turn != CleanupTurnV1::NativeFinished {
            return Err(Closed);
        }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::PendingAuthenticated;
        Ok(())
    }

    // The native caller first validates its actual Sent + final Session posts.
    // This financial comparison independently cross-links that whole outcome;
    // decoding an outcome alone cannot create the private flight token.
    pub(in crate::plan::deployment::control) fn mark_cleanup_authenticated_sent_v1(&mut self,
        token: &HostControlCleanupTokenV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), Closed> {
        use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod as Method;
        use aos_sandbox_protocol::authenticated_session::all_methods::{
            AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerMethodResultV1,
        };
        let request = Request { id: outcome.request().request_id(),
            session: outcome.request().session_binding(), signed: outcome.request().signed_request_digest() };
        let flight = self.cleanup_original_v1(token)?;
        let method = match flight.identity.purpose {
            ControlCleanupPurposeV1::Stop => outcome.method() == Method::BROKER_METHOD_HOST_APPLY_RUNTIME,
            ControlCleanupPurposeV1::NoApply => matches!(outcome.method(),
                Method::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                    | Method::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2),
        };
        if !method || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ServerSend
            || !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
        { return Err(Closed); }
        if !self.control_was_consumed() || flight.current != request
            || !matches!(flight.turn, CleanupTurnV1::PendingAuthenticated | CleanupTurnV1::Authenticated)
        { return Err(Closed); }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::Authenticated;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn resume_control_cleanup_v1(&mut self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1,
        request: Request, cutoff: u64,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        if !self.control_was_consumed() || !self.execution_admitted
            || purpose != ControlCleanupPurposeV1::NoApply || flight.identity.purpose != purpose
            || flight.identity.initial.session != request.session
            || request.id == [0; 16] || request.signed == [0; 32]
            || cutoff == 0 || cutoff > flight.identity.cutoff
            || request == flight.current || flight.used >= 4
            || flight.turn != CleanupTurnV1::Authenticated
        { return Err(Closed); }
        let flight = self.cleanup.as_mut().ok_or(Closed)?;
        flight.current = request;
        flight.turn = CleanupTurnV1::Entered;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_cleanup_authenticated_response_v1(&self,
        token: &HostControlCleanupTokenV1, request: Request,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        if !self.control_was_consumed() || flight.current != request
            || flight.turn != CleanupTurnV1::Authenticated
        { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn prepare_cleanup_disposal_v1(&mut self,
        token: &HostControlCleanupTokenV1, purpose: ControlCleanupPurposeV1,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        let expected = match purpose { ControlCleanupPurposeV1::Stop => 1,
            ControlCleanupPurposeV1::NoApply => 4 };
        if !self.control_was_consumed() || flight.identity.purpose != purpose || flight.used != expected
            || flight.turn != CleanupTurnV1::Authenticated
        { return Err(Closed); }
        self.cleanup.as_mut().ok_or(Closed)?.turn = CleanupTurnV1::Disposing;
        Ok(())
    }

    // The upper native disposer first consumes its concrete positive proof and
    // physically drops the last native scope/writer owner. The only remaining
    // key copies must then be this original and that same armed disposer.
    pub(in crate::plan::deployment::control) fn complete_cleanup_after_native_drop_v1(&mut self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        self.require_cleanup_native_dropped_v1(token)?;
        if let Some(launch) = self.cleanup_original_v1(token)?.identity.resident_launch {
            let slot = &mut self.flights[Phase::Launch.index()];
            if slot.request != Some(launch)
                || slot.resident_stop.is_some()
                || slot.capture_negative.is_some()
                || !slot.native_positive
            {
                return Err(Closed);
            }
            self.retire_launch_operation_after_disposal_v1()?;
        }
        self.cleanup = None;
        // Every earlier resident requirement/highwater and spent traffic stays
        // charged on the SAME consumed Control; this clears only isolation.
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_cleanup_native_dropped_v1(&self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<(), Closed> {
        let flight = self.cleanup_original_v1(token)?;
        if !self.control_was_consumed() || flight.turn != CleanupTurnV1::Disposing
            || Arc::strong_count(&flight.identity) != 2
        { return Err(Closed); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Accounting DATA fixtures do not own a captured Control, authenticated
    // request, native interval or permission to enter any SDK method.
    fn original() -> HostExecutionReceivingV2 {
        let profile = ExecutionReceivingProfileV2 { prepare: [1_000_000; 22],
            accept: [1_000_000; 22], launch: [1_000_000; 22], boot_preparation: None };
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4_000_000; 22]), profile, ResourceVector::new([1_000_000; 22])).unwrap();
        owner.execution_admitted = false;
        owner.consume_control_once(ResourceVector::ZERO).unwrap();
        owner.admit_execution_once().unwrap();
        owner
    }

    fn request(id: u8) -> Request { Request { id: [id; 16], session: [2; 32], signed: [3; 32] } }

    #[test]
    fn held_cleanup_isolates_sibling_preparations_without_reminting_control() {
        let mut owner = original();
        let charged = owner.ledger.charged();
        let complete = ResourceVector::ZERO.with(D::MemoryBytes, 64).with(D::OutputBytes, 11);
        let token = owner.begin_control_cleanup_v1(ControlCleanupPurposeV1::NoApply, request(1), 50, complete).unwrap();
        let remaining = *owner.control_requirement.as_ref().unwrap().as_ref().unwrap();

        assert!(owner.admit_terminal_inventory_v4(ResourceVector::ZERO).is_err());
        assert!(owner.account_control_preparation_v5(ResourceVector::ZERO).is_err());
        assert!(owner.begin(Phase::Prepare, request(4)).is_err());
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().unwrap(), &remaining);
        assert_eq!(owner.ledger.charged(), charged);

        owner.raise_cleanup_complete_v1(&token, ControlCleanupPurposeV1::NoApply, request(1), complete).unwrap();
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().unwrap(), &remaining);
        let raised = complete.with(D::OutputBytes, 14);
        owner.raise_cleanup_complete_v1(&token, ControlCleanupPurposeV1::NoApply, request(1), raised).unwrap();
        let after = owner.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(after.get(D::MemoryBytes), remaining.get(D::MemoryBytes));
        assert_eq!(after.get(D::OutputBytes), remaining.get(D::OutputBytes) - 3);
        assert_eq!(owner.ledger.charged(), charged);
    }

    #[test]
    fn matching_data_never_rejoins_another_actual_cleanup_flight() {
        let mut first = original();
        let mut second = original();
        let complete = ResourceVector::ZERO.with(D::MemoryBytes, 64);
        let first_token = first.begin_control_cleanup_v1(ControlCleanupPurposeV1::Stop, request(1), 50, complete).unwrap();
        let second_token = second.begin_control_cleanup_v1(ControlCleanupPurposeV1::Stop, request(1), 50, complete).unwrap();
        assert!(!first_token.rejoins_same_original_v1(&second_token));
        let before = *first.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert!(first.raise_cleanup_complete_v1(&second_token, ControlCleanupPurposeV1::Stop, request(1), complete).is_err());
        assert_eq!(first.control_requirement.as_ref().unwrap().as_ref().unwrap(), &before);
        assert!(first.require_cleanup_current_v1(&first_token, ControlCleanupPurposeV1::NoApply, request(1)).is_err());

        drop(first_token);
        assert!(first.admit_terminal_inventory_v4(ResourceVector::ZERO).is_err());
        assert!(first.cleanup.is_some(), "dropping a token never retires actual native liability");
    }

    #[test]
    fn live_cleanup_keeps_old_operation_until_its_final_disposal_and_never_refunds() {
        // Private accounting phases alone: no native proof or installed
        // constructor is synthesized by this financial fixture.
        let mut owner = original();
        let launch = request(7);
        owner
            .require_baseline_before_growth_v2(ResourceVector::ZERO)
            .unwrap();
        owner.begin(Phase::Launch, launch).unwrap();
        owner
            .require_complete(
                Phase::Launch,
                launch,
                ResourceVector::ZERO
                    .with(D::OpenFiles, 3)
                    .with(D::NetworkBytes, 4),
            )
            .unwrap();
        owner.finish_native_positive(Phase::Launch, launch).unwrap();
        owner.retain_authenticated_launch_v2(launch).unwrap();
        let old_reached = owner.flights[Phase::Launch.index()].reached;
        let old_current = owner.flights[Phase::Launch.index()].current;
        let charged = owner.ledger.charged();
        owner.require_live_cleanup_parent_v1(launch, None).unwrap();
        let complete = ResourceVector::ZERO
            .with(D::MemoryBytes, 64)
            .with(D::OutputBytes, 11);
        let token = owner
            .begin_control_cleanup_engine_v2(
                ControlCleanupPurposeV1::Stop,
                request(8),
                50,
                complete,
                Some(launch),
            )
            .unwrap();
        let spent = *owner
            .control_requirement
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();

        assert_eq!(owner.flights[Phase::Launch.index()].current, old_current);
        assert!(
            owner.flights[Phase::Launch.index()]
                .operation
                .as_ref()
                .unwrap()
                .is_consumed_current()
        );
        assert!(
            owner
                .require_cleanup_resident_binding_v1(&token, None)
                .is_err()
        );
        assert!(
            owner
                .require_cleanup_resident_binding_v1(&token, Some(launch))
                .is_ok()
        );
        assert!(
            owner
                .account_control_preparation_v5(ResourceVector::ZERO)
                .is_err()
        );
        assert!(owner.complete_cleanup_after_native_drop_v1(&token).is_err());
        owner
            .register_cleanup_destinations_v1(&token, 0, 0)
            .unwrap();
        owner.cleanup.as_mut().unwrap().turn = CleanupTurnV1::Authenticated;
        owner
            .prepare_cleanup_disposal_v1(&token, ControlCleanupPurposeV1::Stop)
            .unwrap();
        owner.complete_cleanup_after_native_drop_v1(&token).unwrap();

        assert!(owner.flights[Phase::Launch.index()].request.is_none());
        assert!(owner.flights[Phase::Launch.index()].operation.is_none());
        assert_eq!(owner.flights[Phase::Launch.index()].reached, old_reached);
        assert_eq!(
            owner.flights[Phase::Launch.index()]
                .current
                .get(D::OpenFiles),
            0
        );
        assert_eq!(
            *owner
                .control_requirement
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap(),
            spent
        );
        assert_eq!(owner.ledger.charged(), charged);
    }

    #[test]
    fn four_turn_limit_and_original_cutoff_precede_any_fifth_destination() {
        let mut owner = original();
        let token = owner
            .begin_control_cleanup_v1(
                ControlCleanupPurposeV1::NoApply,
                request(1),
                50,
                ResourceVector::ZERO,
            )
            .unwrap();
        for turn in 0..4 {
            if turn != 0 {
                owner.resume_control_cleanup_v1(&token, ControlCleanupPurposeV1::NoApply,
                    request(turn + 1), 50).unwrap();
            }
            owner.register_cleanup_destinations_v1(&token, usize::from(turn) * 2,
                usize::from(turn)).unwrap();
            // Only accounting phases are selected in this DATA fixture; there
            // is no authenticated Sent/native proof and thus no upper disposer.
            owner.cleanup.as_mut().unwrap().turn = CleanupTurnV1::Authenticated;
        }
        let remaining = *owner.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert!(owner.resume_control_cleanup_v1(&token, ControlCleanupPurposeV1::NoApply,
            request(5), 50).is_err());
        assert_eq!(owner.cleanup.as_ref().unwrap().used, 4);
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().unwrap(), &remaining);

        let mut fresh = original();
        let fresh_token = fresh.begin_control_cleanup_v1(ControlCleanupPurposeV1::NoApply,
            request(1), 50, ResourceVector::ZERO).unwrap();
        fresh.cleanup.as_mut().unwrap().turn = CleanupTurnV1::Authenticated;
        assert!(fresh.resume_control_cleanup_v1(&fresh_token, ControlCleanupPurposeV1::NoApply,
            request(2), 51).is_err());
        assert!(fresh.cleanup.as_ref().unwrap().current == request(1));
        assert!(fresh.prepare_cleanup_disposal_v1(&fresh_token, ControlCleanupPurposeV1::NoApply).is_err());
    }
}
