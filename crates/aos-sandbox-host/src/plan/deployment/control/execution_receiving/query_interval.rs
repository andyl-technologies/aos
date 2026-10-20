//! Prices actual authenticated historical queries on the same resident Launch.
//!
//! This finite resource destination grants no read or effect permission. The
//! caller separately admits the fresh signed HostQueryExecution27 scope and keeps its own clock.
//! Original execution expiry remains unchanged. Every byte/traffic invoice and
//! prior ambiguous native prefix remains charged to the occupied image account.

use std::sync::Arc;
use aos_sandbox_core::component_receiving::{operation_traffic_demand_v1, without_operation_traffic_v1};
use super::*;
use super::super::recurring_observation::RecurringObservationDestinationsV4;

pub(in crate::plan::deployment::control) struct ExecutionQueryFlightV3 {
    identity: Arc<()>,
    request: Request,
    sequence: u64,
    traffic_before: ResourceVector,
    native_before: ResourceVector,
    requirement: ResourceVector,
    destinations: Option<RecurringObservationDestinationsV4>,
    native_positive: bool,
    storage_disposed: bool,
}

/// Associates one prepaid query with its actual authenticated Session request.
pub(crate) struct ExecutionQueryReservationV3 {
    identity: Arc<()>,
    launch: Request,
    accept: Request,
    query: Request,
    sequence: u64,
}

impl ExecutionQueryFlightV3 {
    pub(super) fn storage_disposed_data_v3(&self) -> bool { self.storage_disposed }
}

impl ExecutionQueryReservationV3 {
    pub(crate) fn receiving_bytes_v3() -> Option<usize> {
        std::mem::size_of::<ExecutionQueryFlightV3>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<usize>())
    }

    pub(crate) fn duplicate_disposal_identity_v3(&self) -> Self {
        Self { identity: Arc::clone(&self.identity), launch: self.launch,
            accept: self.accept, query: self.query, sequence: self.sequence }
    }

    pub(in crate::plan::deployment::control) fn accept_v3(&self) -> Request { self.accept }
    pub(in crate::plan::deployment::control) fn query_v3(&self) -> Request { self.query }
    pub(in crate::plan::deployment::control) fn sequence_v3(&self) -> u64 { self.sequence }
}

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn prepare_execution_query_v3(&mut self,
        launch: Request, accept: Request, observe: Request, query: Request, sequence: u64,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        actual: ResourceVector) -> Result<ExecutionQueryReservationV3, Closed> {
        self.require_capture_after_observe_v3(launch, accept, observe)?;
        let slot = &self.flights[Phase::Launch.index()];
        let original = slot.capture_negative.as_ref().ok_or(Closed)?;
        if self.closed || query.id == [0; 16] || query.session == [0; 32] || query.signed == [0; 32]
            || sequence == 0 || sequence == u64::MAX || query == launch || query == accept
            || original.source != source || original.execution != execution || original.accept != accept
        { return Err(Closed); }
        if let Some(previous) = &slot.query_interval {
            // A resident Session cannot be replaced or rewound by a new read.
            // Reconnection needs its own genuine retained Session transition.
            if !previous.storage_disposed || !previous.native_positive
                || previous.request.session != query.session || previous.sequence >= sequence
                || previous.request.id == query.id
            { return Err(Closed); }
        }
        let traffic_before = operation_traffic_demand_v1(slot.reached);
        let mut native_before = without_operation_traffic_v1(slot.current);
        if slot.monitor_interval.as_ref().is_some_and(|interval| !interval.storage_disposed_data_v3()) {
            // No FD/memory reuse is credited for an unresolved prior monitor.
            native_before = native_before.componentwise_max(without_operation_traffic_v1(slot.reached));
        }
        self.account_resident_interval_bound_v5(native_before, traffic_before, actual)?;
        let identity = Arc::new(());
        self.flights[Phase::Launch.index()].query_interval = Some(ExecutionQueryFlightV3 {
            identity: Arc::clone(&identity), request: query, sequence, traffic_before,
            native_before, requirement: actual, destinations: None,
            native_positive: false, storage_disposed: false,
        });
        Ok(ExecutionQueryReservationV3 { identity, launch, accept, query, sequence })
    }

    fn require_execution_query_identity_v3(&self, token: &ExecutionQueryReservationV3)
        -> Result<(), Closed> {
        self.require_execution_query_owed_v3(token.accept, token.query, token.sequence)?;
        let slot = &self.flights[Phase::Launch.index()];
        if slot.request != Some(token.launch) || !slot.query_interval.as_ref().is_some_and(
            |query| Arc::ptr_eq(&query.identity, &token.identity)) { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_execution_query_owed_v3(&self,
        accept: Request, request: Request, sequence: u64) -> Result<(), Closed> {
        self.require_owed_post(Phase::Accept, accept)?;
        let slot = &self.flights[Phase::Launch.index()];
        if !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !slot.query_interval.as_ref().is_some_and(|query| query.request == request
                && query.sequence == sequence && !query.storage_disposed)
        { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn extend_execution_query_v3(&mut self,
        token: &ExecutionQueryReservationV3, complete: ResourceVector) -> Result<(), Closed> {
        self.require_execution_query_identity_v3(token)?;
        self.require_execution_query_complete_v3(token.accept, token.query, token.sequence, complete)
    }

    pub(in crate::plan::deployment::control) fn require_execution_query_complete_v3(&mut self,
        accept: Request, request: Request, sequence: u64, complete: ResourceVector)
        -> Result<(), Closed> {
        self.require_execution_query_owed_v3(accept, request, sequence)?;
        let query = self.flights[Phase::Launch.index()].query_interval.as_ref().ok_or(Closed)?;
        if self.closed || query.native_positive { return Err(Closed); }
        let complete = query.requirement.componentwise_max(complete);
        self.account_resident_interval_bound_v5(query.native_before, query.traffic_before, complete)?;
        self.flights[Phase::Launch.index()].query_interval.as_mut().ok_or(Closed)?.requirement = complete;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn park_execution_query_destinations_v3(&mut self,
        token: &ExecutionQueryReservationV3, destinations: RecurringObservationDestinationsV4)
        -> Result<(), Closed> {
        self.require_execution_query_identity_v3(token)?;
        let query = self.flights[Phase::Launch.index()].query_interval.as_mut().ok_or(Closed)?;
        if self.closed || query.destinations.is_some() || query.native_positive { return Err(Closed); }
        query.destinations = Some(destinations);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_execution_query_native_v3(&mut self,
        accept: Request, request: Request, sequence: u64) -> Result<(), Closed> {
        self.require_execution_query_owed_v3(accept, request, sequence)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let query = slot.query_interval.as_mut().ok_or(Closed)?;
        if self.closed || query.native_positive || query.destinations.is_none()
            || !matches!(slot.representation, Some(Ok(_))) { return Err(Closed); }
        query.native_positive = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn execution_query_disposal_destinations_v3(&self,
        token: &ExecutionQueryReservationV3) -> Result<(usize, usize), Closed> {
        self.require_execution_query_identity_v3(token)?;
        let query = self.flights[Phase::Launch.index()].query_interval.as_ref().ok_or(Closed)?;
        if self.closed || !query.native_positive { return Err(Closed); }
        query.destinations.as_ref().map(|destinations| (destinations.round_start, destinations.manager_slot)).ok_or(Closed)
    }

    pub(in crate::plan::deployment::control) fn finish_execution_query_storage_v3(&mut self,
        token: &ExecutionQueryReservationV3, kept: ResourceVector) -> Result<(), Closed> {
        self.execution_query_disposal_destinations_v3(token)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        let query = slot.query_interval.as_mut().ok_or(Closed)?;
        if kept.get(D::OpenFiles) != 0 || query.requirement.checked_sub(kept).is_err() { return Err(Closed); }
        slot.current = query.native_before.checked_add(kept).and_then(|current| current.checked_add(
            query.traffic_before.checked_add(operation_traffic_demand_v1(query.requirement))?))
            .map_err(|_| Closed)?;
        query.storage_disposed = true;
        Ok(())
    }
}
