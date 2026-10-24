//! Accounts fresh signed Stop work against the same occupied Launch flight.
//!
//! Physical prior-acquisition disposal is established by the actual upper
//! native owner. The original declared account and native highwater remain
//! charged. Every fresh Stop adds its reached traffic to all earlier spent
//! traffic; a smaller collector or successful response cannot subtract debt.

use aos_sandbox_model::component_receiving::{
    operation_traffic_demand_v1, without_operation_traffic_v1,
};

use super::*;
use super::super::recurring_observation::RecurringObservationDestinationsV4;

pub(in crate::plan::deployment::control) struct ResidentStopFlightV4 {
    request: Request,
    traffic_before: ResourceVector,
    native_before: ResourceVector,
    requirement: ResourceVector,
    destinations: Option<RecurringObservationDestinationsV4>,
    native_positive: bool,
    authenticated_positive: bool,
}

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn require_unsent_native_stop_v1(
        &self,
        launch: Request,
        proof: &crate::broker::HostResidentStopNativeCompletedV4,
    ) -> Result<(), Closed> {
        let request = proof.request_identity_v4();
        let request = Request { id: request.0, session: request.1, signed: request.2 };
        let slot = &self.flights[Phase::Launch.index()];
        self.resident_stop_destinations_v4(request)?;
        if slot.request != Some(launch)
            || !slot.native_positive
            || self.prepared.is_some()
            || self.cleanup.is_some()
            || self.stop_admission.is_some()
            || self.stop_containment.is_some()
            || !self.control_was_consumed()
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn admit_unsent_stop_disposal_v1(
        &mut self,
        launch: Request,
        proof: &crate::broker::HostResidentStopNativeCompletedV4,
        complete: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_unsent_native_stop_v1(launch, proof)?;
        self.account_control_preparation_v5(complete)
    }

    pub(in crate::plan::deployment::control) fn complete_unsent_stop_disposal_v1(
        &mut self,
        launch: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.resident_stop_destinations_v4(request)?;
        if self.flights[Phase::Launch.index()].request != Some(launch) {
            return Err(Closed);
        }
        // Physical disposal ends the consumed original without inventing an
        // authenticated Sent transition. Reached traffic and highwater remain.
        self.active = None;
        self.retire_launch_operation_after_disposal_v1()
    }

    pub(in crate::plan::deployment::control) fn remaining_capacity_for_stop_or_launch_v4(
        &self,
        purpose: super::super::execution_operation::HostExecutionLoanPurposeV4,
        launch: Request,
        request: Request,
        complete: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        use super::super::execution_operation::HostExecutionLoanPurposeV4;
        match purpose {
            HostExecutionLoanPurposeV4::Initial => self.remaining_launch_capacity_v2(request, complete),
            HostExecutionLoanPurposeV4::ResidentStop =>
                self.remaining_resident_stop_capacity_v4(launch, request, complete),
            HostExecutionLoanPurposeV4::StopContainment =>
                self.remaining_capture_stop_capacity_v4(launch, request, complete),
            HostExecutionLoanPurposeV4::Availability
                | HostExecutionLoanPurposeV4::RetainedAvailabilityAccept
                | HostExecutionLoanPurposeV4::ExecutionMonitor { .. }
                | HostExecutionLoanPurposeV4::ExecutionQuery { .. } => Err(Closed),
        }
    }

    pub(in crate::plan::deployment::control) fn begin_resident_stop_v4(
        &mut self,
        launch: Request,
        request: Request,
        actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_launch_resident_v2(launch)?;
        if self.active.is_some()
            || request == launch
            || request.id == [0; 16]
            || request.session == [0; 32]
            || request.signed == [0; 32]
            || self.flights[Phase::Prepare.index()].request.is_some()
            || self.flights[Phase::Accept.index()].request.is_some()
        {
            return Err(Closed);
        }
        let slot = &mut self.flights[Phase::Launch.index()];
        if slot.capture_negative.is_some() || slot.resident_stop.is_some()
            || slot.monitor_interval.is_some() || slot.query_interval.is_some()
        {
            // A retained Capture or unresolved previous control cannot be
            // relabeled as a disposable Stop interval.
            return Err(Closed);
        }
        slot.resident_stop = Some(ResidentStopFlightV4 {
            request,
            traffic_before: operation_traffic_demand_v1(slot.reached),
            native_before: without_operation_traffic_v1(slot.current),
            requirement: ResourceVector::ZERO,
            destinations: None,
            native_positive: false,
            authenticated_positive: false,
        });
        self.active = Some(Phase::Launch);
        self.require_resident_stop_complete_v4(launch, request, actual)
    }

    pub(in crate::plan::deployment::control) fn require_resident_stop_owed_v4(
        &self,
        launch: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.require_owed_post(Phase::Launch, launch)?;
        let slot = &self.flights[Phase::Launch.index()];
        if !slot.resident_stop.as_ref().is_some_and(|stop| {
            stop.request == request && !stop.authenticated_positive
        }) {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_resident_stop_complete_v4(
        &mut self,
        launch: Request,
        request: Request,
        actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_resident_stop_owed_v4(launch, request)?;
        if self.closed || self.reservation.is_err() {
            return Err(Closed);
        }
        let slot = &self.flights[Phase::Launch.index()];
        let stop = slot.resident_stop.as_ref().ok_or(Closed)?;
        if stop.native_positive || slot.representation.as_ref().is_some_and(Result::is_err) {
            return Err(Closed);
        }
        let requirement = stop.requirement.componentwise_max(actual);
        let native_before = stop.native_before;
        let traffic_before = stop.traffic_before;
        self.account_resident_interval_bound_v5(native_before, traffic_before, requirement)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        slot.current = native_before.checked_add(without_operation_traffic_v1(requirement))
            .and_then(|native| native.checked_add(operation_traffic_demand_v1(slot.reached)))
            .map_err(|_| Closed)?;
        slot.resident_stop.as_mut().ok_or(Closed)?.requirement = requirement;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn remaining_resident_stop_capacity_v4(
        &self,
        launch: Request,
        request: Request,
        actual: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        self.require_resident_stop_owed_v4(launch, request)?;
        let slot = &self.flights[Phase::Launch.index()];
        let stop = slot.resident_stop.as_ref().ok_or(Closed)?;
        if self.closed || stop.native_positive || stop.requirement != actual
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        slot.capacity.checked_sub(slot.current).map_err(|_| Closed)
    }

    pub(in crate::plan::deployment::control) fn enter_resident_stop_worker_phase_v4(
        &mut self,
        launch: Request,
        request: Request,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        self.require_resident_stop_owed_v4(launch, request)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let stop = slot.resident_stop.as_ref().ok_or(Closed)?;
        if self.closed || stop.native_positive
            || phase.request_identity_v4() != (request.id, request.session, request.signed)
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        if slot.enter_worker_files_v4(phase).is_err() {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn park_resident_stop_destinations_v4(
        &mut self,
        launch: Request,
        request: Request,
        destinations: RecurringObservationDestinationsV4,
    ) -> Result<(), Closed> {
        self.require_resident_stop_owed_v4(launch, request)?;
        let stop = self.flights[Phase::Launch.index()].resident_stop.as_mut().ok_or(Closed)?;
        if stop.destinations.is_some() || stop.native_positive {
            return Err(Closed);
        }
        stop.destinations = Some(destinations);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_resident_stop_native_v4(
        &mut self,
        launch: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.require_resident_stop_owed_v4(launch, request)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let stop = slot.resident_stop.as_mut().ok_or(Closed)?;
        if self.closed || stop.native_positive || stop.destinations.is_none()
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        stop.native_positive = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn resident_stop_destinations_v4(
        &self,
        request: Request,
    ) -> Result<(usize, usize), Closed> {
        let slot = &self.flights[Phase::Launch.index()];
        let stop = slot.resident_stop.as_ref().ok_or(Closed)?;
        if self.closed || self.active != Some(Phase::Launch)
            || stop.request != request || !stop.native_positive || stop.authenticated_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        let destinations = stop.destinations.as_ref().ok_or(Closed)?;
        Ok((destinations.round_start, destinations.manager_slot))
    }

    pub(in crate::plan::deployment::control) fn retain_authenticated_resident_stop_v4(
        &mut self,
        request: Request,
    ) -> Result<(), Closed> {
        self.resident_stop_destinations_v4(request)?;
        self.flights[Phase::Launch.index()].resident_stop.as_mut().ok_or(Closed)?
            .authenticated_positive = true;
        self.active = None;
        Ok(())
    }

    // Only the actual sealed terminal caller invokes this after native unit,
    // cgroup, process and SAME Agent disposal. The declaration/highwater and
    // spent traffic stay held; only this actual old operation ends.
    pub(in crate::plan::deployment::control) fn complete_resident_stop_terminal_v4(
        &mut self,
        launch: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.require_launch_resident_v2(launch)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        if slot.capture_negative.is_some()
            || !slot.resident_stop.as_ref().is_some_and(|stop| {
                stop.request == request && stop.native_positive && stop.authenticated_positive
            })
        {
            return Err(Closed);
        }
        self.retire_launch_operation_after_disposal_v1()
    }

    // Both ordinary Stop and fresh cleanup call this only after their own
    // concrete terminal/Sent/native-last-owner proof. Preserve one accounting
    // body for the old consumed operation and its historical traffic.
    pub(super) fn retire_launch_operation_after_disposal_v1(&mut self) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Launch.index()];
        let operation = slot.operation.take().ok_or(Closed)?;
        operation.complete_after_disposal();
        slot.traffic_before_operation = operation_traffic_demand_v1(slot.reached);
        slot.operation_requirement = ResourceVector::ZERO;
        slot.current = slot.current.with(D::OpenFiles, 0);
        slot.worker_current_files = 0;
        slot.request = None;
        slot.native_positive = false;
        slot.representation = None;
        slot.resident_stop = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "Financial fixture failures intentionally panic.")]

    use super::*;

    fn request(value: u8) -> Request {
        Request { id: [value; 16], session: [2; 32], signed: [value; 32] }
    }

    fn native_and_network(files: u64, network: u64) -> ResourceVector {
        ResourceVector::ZERO.with(D::OpenFiles, files).with(D::NetworkBytes, network)
    }

    // This fixture exercises only private financial transitions. It supplies
    // no public native proof or receiving grant to an installed caller.
    fn resident() -> HostExecutionReceivingV2 {
        let profile = ExecutionReceivingProfileV2 {
            launch: [100; 22], prepare: [100; 22], accept: [100; 22],
            boot_preparation: None,
        };
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([400; 22]), profile, ResourceVector::ZERO,
        ).unwrap();
        owner.require_baseline_before_growth_v2(ResourceVector::ZERO).unwrap();
        owner.begin(Phase::Launch, request(7)).unwrap();
        owner.require_complete(Phase::Launch, request(7), native_and_network(11, 10)).unwrap();
        owner.finish_native_positive(Phase::Launch, request(7)).unwrap();
        owner.retain_authenticated_launch_v2(request(7)).unwrap();
        owner
    }

    #[test]
    fn unsent_terminal_disposal_requires_native_completion_and_preserves_spent_debt() {
        let mut owner = resident();
        let charged = owner.ledger.charged();
        owner.begin_resident_stop_v4(request(7), request(8), native_and_network(5, 17)).unwrap();
        owner.park_resident_stop_destinations_v4(request(7), request(8), RecurringObservationDestinationsV4 {
            round_start: 18, manager_slot: 5,
        }).unwrap();

        assert!(owner.complete_unsent_stop_disposal_v1(request(7), request(8)).is_err());
        assert_eq!(owner.active, Some(Phase::Launch));
        owner.finish_resident_stop_native_v4(request(7), request(8)).unwrap();
        let reached = owner.flights[Phase::Launch.index()].reached;
        assert!(!owner.flights[Phase::Launch.index()].resident_stop.as_ref().unwrap().authenticated_positive);
        assert!(owner.complete_unsent_stop_disposal_v1(request(9), request(8)).is_err());
        assert_eq!(owner.active, Some(Phase::Launch));

        // Private financial fixture only: the installed caller must physically
        // drop its actual terminal native owners before this final transition.
        owner.complete_unsent_stop_disposal_v1(request(7), request(8)).unwrap();

        let slot = &owner.flights[Phase::Launch.index()];
        assert_eq!(owner.active, None);
        assert_eq!(slot.reached, reached);
        assert!(slot.request.is_none());
        assert!(slot.resident_stop.is_none());
        assert!(slot.operation.is_none());
        assert_eq!(owner.ledger.charged(), charged);
        assert!(owner.complete_unsent_stop_disposal_v1(request(7), request(8)).is_err());
    }

    #[test]
    fn stop_updates_its_bound_without_debiting_the_same_traffic_twice() {
        let mut owner = resident();
        let declared = owner.ledger.charged();
        owner.begin_resident_stop_v4(request(7), request(8), native_and_network(3, 11)).unwrap();
        owner.require_resident_stop_complete_v4(request(7), request(8), native_and_network(5, 17)).unwrap();

        let flight = &owner.flights[Phase::Launch.index()];
        assert_eq!(flight.reached.get(D::NetworkBytes), 27);
        assert_eq!(flight.current.get(D::OpenFiles), 16);
        assert_eq!(owner.ledger.charged(), declared);
        assert!(flight.operation.as_ref().is_some_and(|operation| operation.is_consumed_current()));
    }

    #[test]
    fn terminal_transition_keeps_spent_traffic_for_the_next_distinct_launch() {
        let mut owner = resident();
        let declared = owner.ledger.charged();
        owner.begin_resident_stop_v4(request(7), request(8), native_and_network(5, 17)).unwrap();
        owner.park_resident_stop_destinations_v4(request(7), request(8), RecurringObservationDestinationsV4 {
            round_start: 18, manager_slot: 5,
        }).unwrap();
        owner.finish_resident_stop_native_v4(request(7), request(8)).unwrap();
        owner.retain_authenticated_resident_stop_v4(request(8)).unwrap();
        owner.complete_resident_stop_terminal_v4(request(7), request(8)).unwrap();
        owner.begin(Phase::Launch, request(9)).unwrap();
        owner.require_complete(Phase::Launch, request(9), native_and_network(2, 19)).unwrap();

        let flight = &owner.flights[Phase::Launch.index()];
        assert_eq!(flight.reached.get(D::NetworkBytes), 46);
        assert_eq!(flight.reached.get(D::OpenFiles), 16);
        assert_eq!(flight.current.get(D::OpenFiles), 2);
        assert_eq!(owner.ledger.charged(), declared);
        assert!(owner.require_owed_post(Phase::Launch, request(7)).is_err());
        assert!(owner.require_owed_post(Phase::Launch, request(9)).is_ok());
    }

    #[test]
    fn overdrawn_stop_keeps_the_actual_old_operation_and_accounting_cause() {
        let mut owner = resident();
        let declared = owner.ledger.charged();
        assert!(owner.begin_resident_stop_v4(request(7), request(8), native_and_network(90, 1)).is_err());

        let flight = &owner.flights[Phase::Launch.index()];
        assert!(flight.request == Some(request(7)));
        assert!(flight.operation.as_ref().is_some_and(|operation| operation.is_consumed_current()));
        assert!(flight.resident_stop.is_some());
        assert!(owner.failure().unwrap().downcast_ref::<AccountingError>().is_some());
        assert_eq!(owner.ledger.charged(), declared);
    }
}
