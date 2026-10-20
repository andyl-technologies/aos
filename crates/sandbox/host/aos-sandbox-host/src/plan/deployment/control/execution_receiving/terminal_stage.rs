//! Finishes exact Accept custody only after the real terminal Stage drops.
//!
//! The original Launch remains consumed. All reached bytes, namespace and
//! cumulative traffic stay charged; only actual physical descriptor liability
//! may end. This child creates no bank, role, deadline or execution permission.

use super::*;

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn require_terminal_stage_disposal_v3(
        &self,
        launch: Request,
        accept: Request,
        observe: Request,
        prepare: Option<Request>,
    ) -> Result<(), Closed> {
        self.require_capture_after_observe_v3(launch, accept, observe)?;
        if self.retained_prepare_for_accept_v2(accept)? != prepare {
            return Err(Closed);
        }
        let slot = &self.flights[Phase::Launch.index()];
        if !slot.capture_negative.as_ref().is_some_and(|negative| {
            negative.accept == accept && negative.entry == CaptureNegativeEntryV3::Armed
        }) || slot
            .monitor_interval
            .as_ref()
            .is_some_and(|interval| !interval.storage_disposed_data_v3())
            || slot
                .query_interval
                .as_ref()
                .is_some_and(|interval| !interval.storage_disposed_data_v3())
            || slot.resident_stop.is_some()
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn complete_terminal_stage_disposal_v3(
        &mut self,
        launch: Request,
        accept: Request,
        observe: Request,
        prepare: Option<Request>,
    ) -> Result<(), Closed> {
        self.require_terminal_stage_disposal_v3(launch, accept, observe, prepare)?;
        if prepare.is_some() {
            let before = &mut self.flights[Phase::Prepare.index()];
            before
                .operation
                .take()
                .ok_or(Closed)?
                .complete_after_disposal();
            before.current = before.current.with(D::OpenFiles, 0);
            before.worker_current_files = 0;
            before.request = None;
            before.native_positive = false;
            before.representation = None;
            before.availability_interval = None;
        }
        let slot = &mut self.flights[Phase::Accept.index()];
        let operation = slot.operation.take().ok_or(Closed)?;
        operation.complete_after_disposal();
        // Preserve every reached/spent amount. The permanent declaration is
        // neither released nor reconstructed for the next distinct interval.
        slot.current = slot.current.with(D::OpenFiles, 0);
        slot.worker_current_files = 0;
        slot.request = None;
        slot.native_positive = false;
        slot.authenticated_accept = false;
        slot.continuations = std::array::from_fn(|_| ContinuationFlightV2::new());
        slot.active_continuation = None;
        let launch = &mut self.flights[Phase::Launch.index()];
        launch.capture_negative = None;
        launch.monitor_interval = None;
        launch.query_interval = None;
        self.active = None;
        self.prepared = None;
        Ok(())
    }
}
