//! Debits a finite monitor interval on the same occupied Launch original.
//!
//! The actual signed admission-five owner supplies permission elsewhere. This
//! module only associates its already-prearmed Launch/Accept liability with
//! one paid interval. Traffic stays cumulative; no initial operation is
//! rearmed, replaced or refunded. Negative and ambiguous intervals remain.

use std::sync::Arc;

use aos_sandbox_core::component_receiving::{
    operation_traffic_demand_v1, without_operation_traffic_v1,
};

use super::*;
use super::super::recurring_observation::RecurringObservationDestinationsV4;

pub(in crate::plan::deployment::control) struct ExecutionMonitorFlightV5 {
    identity: Arc<()>,
    accept: Request,
    observe: Request,
    prior_ordinal: u64,
    terminal: Option<(aos_sandbox_core::ObjectDigest, u64)>,
    ordinal: Option<u64>,
    traffic_before: ResourceVector,
    native_before: ResourceVector,
    requirement: ResourceVector,
    destinations: Option<RecurringObservationDestinationsV4>,
    native_positive: bool,
    storage_disposed: bool,
}

impl ExecutionMonitorFlightV5 {
    pub(super) fn storage_disposed_data_v3(&self) -> bool { self.storage_disposed }
}

/// Associates one resource interval with its actual resident flights.
///
/// This opaque resource token supplies no execution permission, native scope,
/// requested amount, deadline or operation completion authority.
pub(crate) struct ExecutionMonitorReservationV5 {
    identity: Arc<()>,
    launch: Request,
    accept: Request,
    observe: Request,
}

impl ExecutionMonitorReservationV5 {
    /// Prices the exact shared identity and constructor/body overlap.
    #[must_use]
    pub(crate) fn receiving_bytes_v5() -> Option<usize> {
        std::mem::size_of::<ExecutionMonitorFlightV5>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<usize>())
    }

    pub(crate) fn duplicate_disposal_identity_v5(&self) -> Self {
        Self { identity: Arc::clone(&self.identity), launch: self.launch,
            accept: self.accept, observe: self.observe }
    }

    pub(in crate::plan::deployment::control) fn accept_v5(&self) -> Request {
        self.accept
    }
}

impl HostExecutionReceivingV2 {
    // A finite interval adds its complete concurrent liability to the actual
    // resident baseline while keeping every earlier traffic invoice spent.
    // The declaration remains consumed; this records only its reached bound.
    pub(in crate::plan::deployment::control) fn account_resident_interval_bound_v5(
        &mut self, native_before: ResourceVector, traffic_before: ResourceVector,
        requirement: ResourceVector,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Launch.index()];
        let complete = native_before.checked_add(requirement).and_then(|current|
            without_operation_traffic_v1(slot.reached)
                .componentwise_max(without_operation_traffic_v1(current))
                .checked_add(traffic_before.checked_add(operation_traffic_demand_v1(requirement))?));
        slot.representation = Some(complete.and_then(|value| slot.capacity.checked_sub(value)));
        if !matches!(slot.representation, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        slot.reached = slot.capacity.checked_sub(*slot.representation.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(Closed)?).map_err(|_| Closed)?;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn prepare_execution_monitor_v5(
        &mut self, launch: Request, accept: Request, observe: Request,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        actual: ResourceVector,
    ) -> Result<ExecutionMonitorReservationV5, Closed> {
        self.prepare_resident_monitor_interval_v3(launch, accept, observe, source, execution, actual, None)
    }

    pub(in crate::plan::deployment::control) fn prepare_capture_terminal_v3(
        &mut self, launch: Request, accept: Request, observe: Request,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        actual: ResourceVector, terminal: (aos_sandbox_core::ObjectDigest, u64),
    ) -> Result<ExecutionMonitorReservationV5, Closed> {
        if terminal.0.as_bytes() == &[0; 32] || terminal.1 == 0 || terminal.1 == u64::MAX {
            return Err(Closed);
        }
        self.prepare_resident_monitor_interval_v3(launch, accept, observe, source, execution, actual, Some(terminal))
    }

    fn prepare_resident_monitor_interval_v3(
        &mut self, launch: Request, accept: Request, observe: Request,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        actual: ResourceVector, terminal: Option<(aos_sandbox_core::ObjectDigest, u64)>,
    ) -> Result<ExecutionMonitorReservationV5, Closed> {
        self.require_capture_after_observe_v3(launch, accept, observe)?;
        let slot = &self.flights[Phase::Launch.index()];
        if slot.query_interval.as_ref().is_some_and(|query| !query.storage_disposed_data_v3()) {
            return Err(Closed);
        }
        let held = slot.capture_negative.as_ref().ok_or(Closed)?;
        if self.closed || held.source != source || held.execution != execution
            || held.accept != accept || held.entry != CaptureNegativeEntryV3::Armed
        {
            return Err(Closed);
        }
        let prior_ordinal = match slot.monitor_interval.as_ref() {
            None => 0,
            Some(prior) if prior.native_positive && prior.storage_disposed && prior.terminal.is_none() =>
                prior.ordinal.ok_or(Closed)?,
            Some(_) => return Err(Closed),
        };
        if terminal.is_some_and(|(_, ordinal)| prior_ordinal != 0 && ordinal != prior_ordinal) { return Err(Closed); }
        // The whole prefix precedes even this shared identity allocation. A
        // semantic-claim failure leaves the interval unresolved.
        let traffic_before = operation_traffic_demand_v1(slot.reached);
        let native_before = without_operation_traffic_v1(slot.current);
        self.account_resident_interval_bound_v5(native_before, traffic_before, actual)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let identity = Arc::new(());
        slot.monitor_interval = Some(ExecutionMonitorFlightV5 {
            identity: Arc::clone(&identity), accept, observe, prior_ordinal, terminal,
            ordinal: None, traffic_before, native_before, requirement: actual,
            destinations: None, native_positive: false, storage_disposed: false,
        });
        Ok(ExecutionMonitorReservationV5 { identity, launch, accept, observe })
    }

    fn require_execution_monitor_identity_v5(
        &self, reservation: &ExecutionMonitorReservationV5,
    ) -> Result<(), Closed> {
        // Owed posts retain access after an earlier primary poisoned health.
        self.require_owed_post(Phase::Accept, reservation.accept)?;
        let launch = &self.flights[Phase::Launch.index()];
        let interval = launch.monitor_interval.as_ref().ok_or(Closed)?;
        if launch.request != Some(reservation.launch)
            || !launch.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !Arc::ptr_eq(&interval.identity, &reservation.identity)
            || interval.accept != reservation.accept || interval.observe != reservation.observe
            || interval.storage_disposed
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn extend_execution_monitor_v5(
        &mut self, reservation: &ExecutionMonitorReservationV5, actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_identity_v5(reservation)?;
        let interval = self.flights[Phase::Launch.index()].monitor_interval.as_ref().ok_or(Closed)?;
        if self.closed || interval.ordinal.is_some() || interval.destinations.is_some() {
            return Err(Closed);
        }
        let requirement = interval.requirement.componentwise_max(actual);
        self.account_resident_interval_bound_v5(interval.native_before,
            interval.traffic_before, requirement)?;
        self.flights[Phase::Launch.index()].monitor_interval.as_mut().ok_or(Closed)?
            .requirement = requirement;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_execution_monitor_native_positive_v5(
        &self, accept: Request, ordinal: u64,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_owed_v5(accept, ordinal)?;
        let interval = self.flights[Phase::Launch.index()].monitor_interval.as_ref().ok_or(Closed)?;
        if self.closed || !interval.native_positive { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn bind_execution_monitor_sequence_v5(
        &mut self, reservation: &ExecutionMonitorReservationV5,
        ordinal: u64, actual_native: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_identity_v5(reservation)?;
        let interval = self.flights[Phase::Launch.index()].monitor_interval.as_mut().ok_or(Closed)?;
        let permitted = match interval.terminal {
            None => ordinal > interval.prior_ordinal,
            Some((_, terminal_ordinal)) => ordinal == terminal_ordinal && ordinal >= interval.prior_ordinal,
        };
        if self.closed || ordinal == u64::MAX || !permitted
            || interval.ordinal.is_some() || !actual_native.is_within(interval.requirement)
        {
            return Err(Closed);
        }
        interval.ordinal = Some(ordinal);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_capture_terminal_identity_v3(
        &self, reservation: &ExecutionMonitorReservationV5,
        terminal: aos_sandbox_core::ObjectDigest, ordinal: u64,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_identity_v5(reservation)?;
        if self.flights[Phase::Launch.index()].monitor_interval.as_ref().ok_or(Closed)?.terminal
            != Some((terminal, ordinal)) { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_execution_monitor_owed_v5(
        &self, accept: Request, ordinal: u64,
    ) -> Result<(), Closed> {
        self.require_owed_post(Phase::Accept, accept)?;
        let launch = &self.flights[Phase::Launch.index()];
        let interval = launch.monitor_interval.as_ref().ok_or(Closed)?;
        if interval.accept != accept || interval.ordinal != Some(ordinal)
            || interval.storage_disposed
            || !launch.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_execution_monitor_complete_v5(
        &mut self, accept: Request, ordinal: u64, actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_owed_v5(accept, ordinal)?;
        let interval = self.flights[Phase::Launch.index()].monitor_interval.as_ref().ok_or(Closed)?;
        if self.closed || interval.native_positive { return Err(Closed); }
        let requirement = interval.requirement.componentwise_max(actual);
        self.account_resident_interval_bound_v5(interval.native_before,
            interval.traffic_before, requirement)?;
        self.flights[Phase::Launch.index()].monitor_interval.as_mut().ok_or(Closed)?
            .requirement = requirement;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn park_execution_monitor_destinations_v5(
        &mut self, reservation: &ExecutionMonitorReservationV5,
        ordinal: u64, destinations: RecurringObservationDestinationsV4,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_identity_v5(reservation)?;
        let interval = self.flights[Phase::Launch.index()].monitor_interval.as_mut().ok_or(Closed)?;
        if self.closed || interval.ordinal != Some(ordinal) || interval.destinations.is_some()
            || interval.native_positive
        {
            return Err(Closed);
        }
        interval.destinations = Some(destinations);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_execution_monitor_storage_v5(
        &mut self, reservation: &ExecutionMonitorReservationV5,
        accept: Request, ordinal: u64, actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_identity_v5(reservation)?;
        self.require_execution_monitor_native_positive_v5(accept, ordinal)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let interval = slot.monitor_interval.as_mut().ok_or(Closed)?;
        if actual.get(D::OpenFiles) != 0
            || interval.requirement.checked_sub(actual).is_err()
        { return Err(Closed); }
        // Only the upper opaque actual-disposal frontier can call this through
        // the same Loan. Reached highwater and all spent traffic remain intact.
        slot.current = interval.native_before.checked_add(actual)
            .and_then(|value| value.checked_add(interval.traffic_before
                .checked_add(operation_traffic_demand_v1(interval.requirement))?))
            .map_err(|_| Closed)?;
        interval.storage_disposed = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_execution_monitor_native_v5(
        &mut self, accept: Request, ordinal: u64,
    ) -> Result<(), Closed> {
        self.require_execution_monitor_owed_v5(accept, ordinal)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let interval = slot.monitor_interval.as_mut().ok_or(Closed)?;
        if self.closed || interval.native_positive || interval.destinations.is_none()
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        interval.native_positive = true;
        Ok(())
    }
}
