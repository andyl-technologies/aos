//! Accounts terminal reads on the same once-consumed control operation.

use super::*;

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn require_live_cleanup_parent_v1(
        &self,
        launch: Request,
        capture: Option<(Request, Request)>,
    ) -> Result<(), Closed> {
        self.require_launch_resident_v2(launch)?;
        if !self.control_was_consumed()
            || self.prepared.is_some()
            || self.cleanup.is_some()
            || self.stop_admission.is_some()
            || self.stop_containment.is_some()
        {
            return Err(Closed);
        }
        match capture {
            Some((accept, observe)) => {
                self.require_capture_after_observe_v3(launch, accept, observe)?
            }
            None if self.active.is_none()
                && self.flights[Phase::Prepare.index()].request.is_none()
                && self.flights[Phase::Accept.index()].request.is_none() => {}
            None => return Err(Closed),
        }
        let slot = &self.flights[Phase::Launch.index()];
        if slot.resident_stop.is_some()
            || slot.capture_negative.is_some()
            || slot.monitor_interval.is_some()
            || slot.query_interval.is_some()
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn admit_live_inventory_v1(
        &mut self,
        launch: Request,
        capture: Option<(Request, Request)>,
        complete: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_live_cleanup_parent_v1(launch, capture)?;
        self.account_control_preparation_v5(complete)
    }

    pub(in crate::plan::deployment::control) fn live_inventory_available_v1(
        &self,
        launch: Request,
        capture: Option<(Request, Request)>,
    ) -> Result<ResourceVector, Closed> {
        self.require_live_cleanup_parent_v1(launch, capture)?;
        self.control_requirement
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    pub(in crate::plan::deployment::control) fn admit_terminal_inventory_v4(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), Closed> {
        if !self.control_was_consumed()
            || !self.execution_admitted
            || self.active.is_some()
            || self.prepared.is_some()
            || self.flights.iter().any(|flight| flight.request.is_some())
        {
            self.closed = true;
            return Err(Closed);
        }
        self.account_control_preparation_v5(complete)
    }

    pub(in crate::plan::deployment::control) fn admit_execution_transition_preparation_v5(
        &mut self, launch: Request, accept: Request, observe: Request, complete: ResourceVector,
    ) -> Result<(), Closed> {
        if !self.control_was_consumed() || !self.execution_admitted {
            return Err(Closed);
        }
        self.require_capture_after_observe_v3(launch, accept, observe)?;
        self.account_control_preparation_v5(complete)
    }

    pub(in crate::plan::deployment::control) fn extend_execution_transition_preparation_v5(
        &mut self, additional: ResourceVector,
    ) -> Result<(), Closed> {
        if self.closed || !self.control_was_consumed() || !self.execution_admitted {
            return Err(Closed);
        }
        self.account_control_preparation_v5(additional)
    }

    pub(in crate::plan::deployment::control) fn native_inventory_available_v5(&self)
        -> Result<ResourceVector, Closed>
    {
        if !self.control_was_consumed() || !self.execution_admitted
            || self.active.is_some() || self.prepared.is_some()
            || self.flights.iter().any(|flight| flight.request.is_some())
        { return Err(Closed); }
        self.control_requirement.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(Closed)
    }

    pub(in crate::plan::deployment::control) fn account_control_preparation_v5(&mut self, complete: ResourceVector) -> Result<(), Closed> {
        if self.cleanup.is_some() {
            return Err(Closed);
        }
        self.account_control_preparation_engine_v6(complete)
    }

    // Only the exact private cleanup-flight path may bypass its own isolation
    // gate; the original residual ledger and physical comparison stay shared.
    pub(super) fn account_control_preparation_engine_v6(&mut self, complete: ResourceVector) -> Result<(), Closed> {
        if self.control_preparation_failure_v2().is_some() {
            return Err(Closed);
        }
        // Conservatively retain every prior plane and all spent traffic.
        // Positive native disposal never subtracts from this consumed invoice.
        let reached = self.control_capacity.checked_sub(*self.control_requirement.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(Closed)?)
            .map_err(|_| Closed)?;
        self.control_requirement = Some(reached.checked_add(complete)
            .and_then(|sum| self.control_capacity.checked_sub(sum)));
        if !matches!(self.control_requirement, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        // Financial Control traffic stays spent. Only resident requirements
        // are compared with the same process's remaining physical capacity.
        let complete_control = self.control_capacity.checked_sub(*self.control_requirement.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(Closed)?)
            .map_err(|_| Closed)?;
        self.require_control_physical_fit_v2(complete_control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> HostExecutionReceivingV2 {
        let profile = ExecutionReceivingProfileV2 { prepare: [100; 22],
            accept: [100; 22], launch: [100; 22], boot_preparation: None };
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([400; 22]), profile, ResourceVector::new([100; 22])).unwrap();
        owner.execution_admitted = false;
        owner.consume_control_once(ResourceVector::ZERO).unwrap();
        owner.admit_execution_once().unwrap();
        owner
    }

    #[test]
    fn terminal_reads_add_traffic_without_reminting_control_and_failure_cannot_repair() {
        let mut owner = original();
        let charged = owner.ledger.charged();
        let amount = ResourceVector::ZERO.with(D::MemoryBytes, 7).with(D::OutputBytes, 11);
        owner.admit_terminal_inventory_v4(amount).unwrap();
        owner.admit_terminal_inventory_v4(amount).unwrap();

        let remaining = owner.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(remaining.get(D::MemoryBytes), 86);
        assert_eq!(remaining.get(D::OutputBytes), 78);
        assert_eq!(owner.ledger.charged(), charged);
        assert!(owner.control_operation.as_ref().unwrap().is_consumed_current());

        assert!(owner.admit_terminal_inventory_v4(
            ResourceVector::ZERO.with(D::OutputBytes, 79)).is_err());
        let retained = *owner.control_requirement.as_ref().unwrap().as_ref().err().unwrap();
        assert!(owner.admit_terminal_inventory_v4(ResourceVector::ZERO).is_err());
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().err(), Some(&retained));
        assert_eq!(owner.ledger.charged(), charged);
    }

    #[test]
    fn a_live_launch_never_lends_the_control_terminal_read_interval() {
        let mut owner = original();
        owner.active = Some(Phase::Launch);
        assert!(
            owner
                .admit_terminal_inventory_v4(ResourceVector::ZERO)
                .is_err()
        );
        assert!(owner.closed);
    }

    #[test]
    fn finite_live_read_preserves_the_old_launch_and_spends_only_current_control() {
        let mut owner = original();
        let launch = Request {
            id: [7; 16],
            session: [8; 32],
            signed: [9; 32],
        };
        owner
            .require_baseline_before_growth_v2(ResourceVector::ZERO)
            .unwrap();
        owner.begin(Phase::Launch, launch).unwrap();
        let old = ResourceVector::ZERO
            .with(D::OpenFiles, 3)
            .with(D::NetworkBytes, 4);
        owner.require_complete(Phase::Launch, launch, old).unwrap();
        owner.finish_native_positive(Phase::Launch, launch).unwrap();
        owner.retain_authenticated_launch_v2(launch).unwrap();
        let charged = owner.ledger.charged();
        let reached = owner.flights[Phase::Launch.index()].reached;
        let current = owner.flights[Phase::Launch.index()].current;
        let read = ResourceVector::ZERO
            .with(D::MemoryBytes, 7)
            .with(D::OutputBytes, 11);

        owner.admit_live_inventory_v1(launch, None, read).unwrap();

        assert_eq!(owner.ledger.charged(), charged);
        let slot = &owner.flights[Phase::Launch.index()];
        assert_eq!(slot.reached, reached);
        assert_eq!(slot.current, current);
        assert!(slot.request == Some(launch));
        assert!(slot.operation.as_ref().unwrap().is_consumed_current());
        let remaining = owner.live_inventory_available_v1(launch, None).unwrap();
        assert_eq!(remaining.get(D::MemoryBytes), 93);
        assert_eq!(remaining.get(D::OutputBytes), 89);
        let foreign = Request {
            id: [10; 16],
            ..launch
        };
        assert!(owner.admit_live_inventory_v1(foreign, None, read).is_err());
        assert_eq!(
            owner.live_inventory_available_v1(launch, None).unwrap(),
            remaining
        );
    }
}
