//! Pays one fresh Stop containment interval without repairing failed execution.
//!
//! The actual broker supplies Stop permission and the genuine failed Stage.
//! This private accounting child rejoins their already-consumed Launch/Accept
//! identities and debits the existing control operation. It keeps all execution
//! originals, declarations, spent traffic, native highwaters and sticky errors.

use super::*;
use super::super::recurring_observation::RecurringObservationDestinationsV4;

pub(super) struct StopContainmentFlightV4 {
    launch: Request,
    accept: Request,
    request: Request,
    requirement: ResourceVector,
    base_files: u64,
    destinations: Option<RecurringObservationDestinationsV4>,
    native_positive: bool,
    financial_failure_selected: bool,
    allocation_failure_selected: bool,
}

// This is a paid read/verification interval, not Stop effect permission. Its
// identity remains distinct from the later genuinely admitted containment.
pub(super) struct StopAdmissionFlightV4 {
    request: Request,
    launch: Request,
    accept: Request,
    financial_selected: bool,
    allocation_selected: bool,
    destinations: Option<(usize, usize)>,
}

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn begin_stop_admission_preparation_v4(
        &mut self, launch: Request, accept: Request, request: Request, complete: ResourceVector,
    ) -> Result<(), Closed> {
        let old_launch = &self.flights[Phase::Launch.index()];
        let old_accept = &self.flights[Phase::Accept.index()];
        if self.stop_admission.is_some() || !self.has_consumed_control_v2()
            || !self.execution_admitted || self.reservation.is_err()
            || old_launch.request != Some(launch) || old_accept.request != Some(accept)
            || old_launch.capture_negative.as_ref().is_none_or(|negative|
                negative.accept != accept || negative.entry != CaptureNegativeEntryV3::Armed)
            || !old_launch.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !old_accept.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || request == launch || request == accept || request.id == [0; 16]
            || request.session == [0; 32] || request.signed == [0; 32]
        {
            return Err(Closed);
        }
        self.stop_admission = Some(StopAdmissionFlightV4 {
            request, launch, accept, financial_selected: false, allocation_selected: false,
            destinations: None,
        });
        let outcome = self.account_control_preparation_v5(complete);
        let selected = outcome.is_err() && self.control_preparation_failure_v2().is_some();
        self.stop_admission.as_mut().ok_or(Closed)?.financial_selected = selected;
        outcome
    }

    pub(in crate::plan::deployment::control) fn extend_stop_admission_preparation_v4(
        &mut self, request: Request, additional: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_stop_admission_owed_v4(request)?;
        let outcome = self.account_control_preparation_v5(additional);
        if outcome.is_err() && self.control_preparation_failure_v2().is_some() {
            self.stop_admission.as_mut().ok_or(Closed)?.financial_selected = true;
        }
        outcome
    }

    pub(in crate::plan::deployment::control) fn require_stop_admission_owed_v4(
        &self, request: Request,
    ) -> Result<(), Closed> {
        let original = self.stop_admission.as_ref().ok_or(Closed)?;
        if original.request != request || !self.has_consumed_control_v2()
            || self.flights[Phase::Launch.index()].request != Some(original.launch)
            || self.flights[Phase::Accept.index()].request != Some(original.accept)
            || !self.flights[Phase::Launch.index()].operation.as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
            || !self.flights[Phase::Accept.index()].operation.as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn park_stop_admission_destinations_v4(
        &mut self, request: Request, round: usize, manager: usize,
    ) -> Result<(), Closed> {
        self.require_stop_admission_owed_v4(request)?;
        let original = self.stop_admission.as_mut().ok_or(Closed)?;
        if original.destinations.is_some() { return Err(Closed); }
        original.destinations = Some((round, manager));
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn stop_admission_destinations_v4(
        &self, request: Request,
    ) -> Option<(usize, usize)> {
        self.stop_admission.as_ref().filter(|original| original.request == request)?.destinations
    }

    pub(in crate::plan::deployment::control) fn record_stop_admission_allocation_refusal_v4(
        &mut self, request: Request,
    ) {
        if let Some(original) = self.stop_admission.as_mut().filter(|original| original.request == request) {
            original.allocation_selected = true;
        }
    }

    pub(in crate::plan::deployment::control) fn stop_admission_financial_failure_v4(
        &self, request: Request,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        let original = self.stop_admission.as_ref().filter(|original| original.request == request)?;
        if !original.financial_selected { return None; }
        self.control_preparation_failure_v2()
    }

    pub(in crate::plan::deployment::control) fn stop_admission_allocation_refused_v4(
        &self, request: Request,
    ) -> bool {
        self.stop_admission.as_ref().is_some_and(|original|
            original.request == request && original.allocation_selected)
    }

    pub(in crate::plan::deployment::control) fn begin_capture_stop_containment_v4(
        &mut self,
        reservation: &CaptureNegativeReservationV3,
        request: Request,
        complete: ResourceVector,
    ) -> Result<(), Closed> {
        // The old operation may be closed, but its actual consumed owner and
        // exact prearmed disposition must remain. No old healthy gate is reset.
        self.require_capture_negative_owed_v3(reservation)?;
        let launch = reservation.launch;
        let accept = reservation.accept;
        if !self.execution_admitted || self.reservation.is_err()
            || !self.has_consumed_control_v2()
            || !matches!(self.control_requirement, Some(Ok(_)))
            || self.stop_containment.is_some()
            || request == launch || request == accept
            || request.id == [0; 16] || request.session == [0; 32]
            || request.signed == [0; 32]
        {
            return Err(Closed);
        }
        // Park the once-only destination before the financial comparison. A
        // refusal cannot retry this source or reconstruct a fresh cleanup slot.
        self.stop_containment = Some(StopContainmentFlightV4 {
            launch, accept, request, requirement: ResourceVector::ZERO,
            base_files: complete.get(D::OpenFiles), destinations: None,
            native_positive: false, financial_failure_selected: false, allocation_failure_selected: false,
        });
        self.require_capture_stop_complete_v4(launch, request, complete)
    }

    pub(in crate::plan::deployment::control) fn require_capture_stop_owed_v4(
        &self, launch: Request, request: Request,
    ) -> Result<(), Closed> {
        let stop = self.stop_containment.as_ref().ok_or(Closed)?;
        if stop.launch != launch || stop.request != request
            || !self.has_consumed_control_v2()
            || self.flights[Phase::Launch.index()].request != Some(stop.launch)
            || self.flights[Phase::Accept.index()].request != Some(stop.accept)
            || !self.flights[Phase::Launch.index()].operation.as_ref()
                .is_some_and(|owner| owner.is_consumed_current())
            || !self.flights[Phase::Accept.index()].operation.as_ref()
                .is_some_and(|owner| owner.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_capture_stop_current_v4(
        &self, launch: Request, request: Request,
    ) -> Result<(), Closed> {
        self.require_capture_stop_owed_v4(launch, request)?;
        if !matches!(self.control_requirement, Some(Ok(_))) { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn capture_stop_destinations_v4(
        &self, request: Request,
    ) -> Option<(usize, usize)> {
        let flight = self.stop_containment.as_ref()?;
        if flight.request != request { return None; }
        let destinations = flight.destinations.as_ref()?;
        Some((destinations.round_start, destinations.manager_slot))
    }

    pub(in crate::plan::deployment::control) fn record_capture_stop_allocation_refusal_v4(&mut self,
        launch: Request, request: Request,
    ) -> Result<(), Closed> {
        self.require_capture_stop_owed_v4(launch, request)?;
        self.stop_containment.as_mut().ok_or(Closed)?.allocation_failure_selected = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn capture_stop_allocation_refused_v4(&self,
        request: Request,
    ) -> bool {
        self.stop_containment.as_ref().is_some_and(|flight|
            flight.request == request && flight.allocation_failure_selected)
    }

    pub(in crate::plan::deployment::control) fn capture_stop_financial_failure_v4(
        &self, request: Request,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        let flight = self.stop_containment.as_ref()?;
        if flight.request != request || !flight.financial_failure_selected { return None; }
        self.control_preparation_failure_v2()
    }

    pub(in crate::plan::deployment::control) fn require_capture_stop_complete_v4(
        &mut self, launch: Request, request: Request, actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_capture_stop_current_v4(launch, request)?;
        let stop = self.stop_containment.as_ref().ok_or(Closed)?;
        if stop.native_positive { return Err(Closed); }
        let complete = stop.requirement.componentwise_max(actual);
        let additional = complete.checked_sub(stop.requirement).map_err(|_| Closed)?;
        if self.account_control_preparation_v5(additional).is_err() {
            let selected = self.control_preparation_failure_v2().is_some();
            self.stop_containment.as_mut().ok_or(Closed)?.financial_failure_selected = selected;
            return Err(Closed);
        }
        self.stop_containment.as_mut().ok_or(Closed)?.requirement = complete;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn remaining_capture_stop_capacity_v4(
        &self, launch: Request, request: Request, complete: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        self.require_capture_stop_owed_v4(launch, request)?;
        let stop = self.stop_containment.as_ref().ok_or(Closed)?;
        if stop.native_positive || stop.requirement != complete { return Err(Closed); }
        self.control_requirement.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Closed)
    }

    pub(in crate::plan::deployment::control) fn enter_capture_stop_worker_phase_v4(
        &mut self, launch: Request, request: Request,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        self.require_capture_stop_owed_v4(launch, request)?;
        if phase.request_identity_v4() != (request.id, request.session, request.signed) {
            return Err(Closed);
        }
        let stop = self.stop_containment.as_ref().ok_or(Closed)?;
        let files = stop.base_files.checked_add(
            u64::try_from(phase.current_native_files_v4()).map_err(|_| Closed)?,
        ).ok_or(Closed)?;
        // This prices the new worker peak only. No current/reached amount of
        // either failed old flight is reduced by this fresh Stop phase.
        let complete = stop.requirement.with(D::OpenFiles, files);
        self.require_capture_stop_complete_v4(launch, request, complete)
    }

    pub(in crate::plan::deployment::control) fn park_capture_stop_destinations_v4(
        &mut self, launch: Request, request: Request,
        destinations: RecurringObservationDestinationsV4,
    ) -> Result<(), Closed> {
        self.require_capture_stop_owed_v4(launch, request)?;
        let stop = self.stop_containment.as_mut().ok_or(Closed)?;
        if stop.destinations.is_some() || stop.native_positive { return Err(Closed); }
        stop.destinations = Some(destinations);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_capture_stop_native_v4(
        &mut self, launch: Request, request: Request,
    ) -> Result<(), Closed> {
        self.require_capture_stop_current_v4(launch, request)?;
        let stop = self.stop_containment.as_mut().ok_or(Closed)?;
        if stop.destinations.is_none() || stop.native_positive { return Err(Closed); }
        stop.native_positive = true;
        // This finishes only the new financial/native interval. It disposes
        // no Accept/Launch operation, Stage, captured output, aliases or debt.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: u8) -> Request {
        Request { id: [value; 16], session: [2; 32], signed: [value; 32] }
    }

    // This builds only private accounting custody. It supplies no signed Stop,
    // failed native Stage, cleanup permission or physical quiescence receipt.
    fn failed_original() -> (HostExecutionReceivingV2, CaptureNegativeReservationV3) {
        let profile = ExecutionReceivingProfileV2 {
            launch: [100; 22], prepare: [100; 22], accept: [100; 22],
            boot_preparation: None,
        };
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([400; 22]), profile, ResourceVector::new([100; 22]),
        ).unwrap();
        owner.execution_admitted = false;
        owner.consume_control_once(ResourceVector::ZERO).unwrap();
        owner.admit_execution_once().unwrap();
        owner.require_baseline_before_growth_v2(ResourceVector::ZERO).unwrap();
        owner.begin(Phase::Launch, request(7)).unwrap();
        owner.require_complete(Phase::Launch, request(7), ResourceVector::ZERO).unwrap();
        owner.finish_native_positive(Phase::Launch, request(7)).unwrap();
        owner.retain_authenticated_launch_v2(request(7)).unwrap();

        // Accept requires the same Session's actual completed Prepare. This
        // private financial fixture exercises its ordinary disposal transition;
        // none of these scalar phases supplies an installed native grant.
        owner.begin(Phase::Prepare, request(6)).unwrap();
        owner.require_complete(Phase::Prepare, request(6), ResourceVector::ZERO).unwrap();
        owner.finish_native_positive(Phase::Prepare, request(6)).unwrap();
        owner.retire_after_disposal(Phase::Prepare, request(6)).unwrap();

        owner.begin(Phase::Accept, request(8)).unwrap();
        owner.require_complete(Phase::Accept, request(8), ResourceVector::ZERO).unwrap();

        let identity = std::sync::Arc::new(());
        let source = aos_sandbox_core::ObjectDigest::from_bytes([3; 32]);
        let execution = aos_sandbox_core::ExecutionId::from_bytes([4; 16]);
        owner.flights[Phase::Launch.index()].capture_negative = Some(CaptureNegativeFlightV3 {
            identity: std::sync::Arc::clone(&identity), source, execution,
            accept: request(8), requirement: ResourceVector::ZERO.with(D::MemoryBytes, 1),
            entry: CaptureNegativeEntryV3::Armed,
        });
        owner.close();
        (owner, CaptureNegativeReservationV3 {
            identity, source, execution, launch: request(7), accept: request(8),
        })
    }

    #[test]
    fn fresh_stop_adds_only_new_control_work_without_repairing_failed_flights() {
        let (mut owner, reservation) = failed_original();
        let charged = owner.ledger.charged();
        let old_launch = owner.flights[Phase::Launch.index()].reached;
        let old_accept = owner.flights[Phase::Accept.index()].reached;
        let complete = ResourceVector::ZERO.with(D::OpenFiles, 5).with(D::NetworkBytes, 11);

        owner.begin_capture_stop_containment_v4(&reservation, request(9), complete).unwrap();
        owner.require_capture_stop_complete_v4(request(7), request(9), complete).unwrap();
        owner.require_capture_stop_complete_v4(request(7), request(9),
            complete.with(D::NetworkBytes, 19)).unwrap();

        let remaining = owner.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(remaining.get(D::OpenFiles), 95);
        assert_eq!(remaining.get(D::NetworkBytes), 81);
        assert_eq!(owner.ledger.charged(), charged);
        assert_eq!(owner.flights[Phase::Launch.index()].reached, old_launch);
        assert_eq!(owner.flights[Phase::Accept.index()].reached, old_accept);
        assert!(owner.closed);
        assert_eq!(owner.active, Some(Phase::Accept));
        assert!(owner.flights[Phase::Launch.index()].operation.as_ref().unwrap().is_consumed_current());
        assert!(owner.flights[Phase::Accept.index()].operation.as_ref().unwrap().is_consumed_current());
    }

    #[test]
    fn overdrawn_stop_is_once_only_and_keeps_both_original_operations() {
        let (mut owner, reservation) = failed_original();
        let charged = owner.ledger.charged();

        assert!(owner.begin_capture_stop_containment_v4(&reservation, request(9),
            ResourceVector::ZERO.with(D::OpenFiles, 101)).is_err());
        let cause = *owner.control_requirement.as_ref().unwrap().as_ref().err().unwrap();
        assert!(owner.begin_capture_stop_containment_v4(&reservation, request(10), ResourceVector::ZERO).is_err());
        assert!(owner.require_capture_stop_complete_v4(request(7), request(9), ResourceVector::ZERO).is_err());

        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().err(), Some(&cause));
        assert_eq!(owner.ledger.charged(), charged);
        assert!(owner.stop_containment.is_some());
        assert!(owner.flights[Phase::Launch.index()].request == Some(request(7)));
        assert!(owner.flights[Phase::Accept.index()].request == Some(request(8)));
        assert!(owner.closed);
    }

    #[test]
    fn later_overdraw_closes_primary_but_preserves_the_paid_after_obligation() {
        let (mut owner, reservation) = failed_original();
        owner.begin_capture_stop_containment_v4(&reservation, request(9),
            ResourceVector::ZERO.with(D::OpenFiles, 5)).unwrap();

        assert!(owner.require_capture_stop_complete_v4(request(7), request(9),
            ResourceVector::ZERO.with(D::OpenFiles, 101)).is_err());

        assert!(owner.require_capture_stop_owed_v4(request(7), request(9)).is_ok());
        assert!(owner.require_capture_stop_current_v4(request(7), request(9)).is_err());
        assert!(owner.finish_capture_stop_native_v4(request(7), request(9)).is_err());
        assert!(owner.capture_stop_financial_failure_v4(request(9)).is_some());
        assert!(owner.closed);
        assert!(owner.flights[Phase::Accept.index()].operation.as_ref().unwrap().is_consumed_current());
    }

    #[test]
    fn matching_source_data_cannot_replace_the_original_prearm_identity() {
        let (mut owner, reservation) = failed_original();
        let forged = CaptureNegativeReservationV3 {
            identity: std::sync::Arc::new(()), source: reservation.source,
            execution: reservation.execution, launch: reservation.launch, accept: reservation.accept,
        };

        assert!(owner.begin_capture_stop_containment_v4(&forged, request(9), ResourceVector::ZERO).is_err());
        assert!(owner.stop_containment.is_none());
        owner.begin_capture_stop_containment_v4(&reservation, request(9), ResourceVector::ZERO).unwrap();
    }

    #[test]
    fn stop_verification_pays_a_new_read_without_consuming_negative_effect_custody() {
        let (mut owner, reservation) = failed_original();
        let old = owner.ledger.charged();
        owner.begin_stop_admission_preparation_v4(request(7), request(8), request(9),
            ResourceVector::ZERO.with(D::NetworkBytes, 13)).unwrap();
        owner.extend_stop_admission_preparation_v4(request(9),
            ResourceVector::ZERO.with(D::NetworkBytes, 7)).unwrap();

        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().unwrap()
            .get(D::NetworkBytes), 80);
        assert_eq!(owner.ledger.charged(), old);
        assert!(owner.closed);
        assert_eq!(owner.active, Some(Phase::Accept));
        assert!(owner.enter_capture_negative_v3(&reservation).is_ok());
        assert!(owner.begin_stop_admission_preparation_v4(request(7), request(8), request(10),
            ResourceVector::ZERO).is_err());
    }

    #[test]
    fn stop_verification_overdraw_retains_owed_identity_and_the_original_accounting_error() {
        let (mut owner, _) = failed_original();
        assert!(owner.begin_stop_admission_preparation_v4(request(7), request(8), request(9),
            ResourceVector::ZERO.with(D::OpenFiles, 101)).is_err());
        let selected = *owner.control_requirement.as_ref().unwrap().as_ref().err().unwrap();

        assert!(owner.require_stop_admission_owed_v4(request(9)).is_ok());
        assert!(owner.require_stop_admission_owed_v4(request(10)).is_err());
        assert!(owner.stop_admission_financial_failure_v4(request(9)).is_some());
        assert!(owner.begin_stop_admission_preparation_v4(request(7), request(8), request(10),
            ResourceVector::ZERO).is_err());
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().err(), Some(&selected));
    }

    #[test]
    fn foreign_launch_or_accept_cannot_spend_the_verification_interval() {
        let (mut owner, _) = failed_original();
        assert!(owner.begin_stop_admission_preparation_v4(request(6), request(8), request(9),
            ResourceVector::ZERO).is_err());
        assert!(owner.stop_admission.is_none());
        assert!(owner.begin_stop_admission_preparation_v4(request(7), request(6), request(9),
            ResourceVector::ZERO).is_err());
        assert!(owner.stop_admission.is_none());
    }

}
