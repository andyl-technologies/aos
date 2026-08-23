//! Quantum-loop test doubles for debugger attach and runtime repositioning.

use super::*;

pub(in super::super) struct DebugGdbLoop;

impl QuantumLoop for DebugGdbLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
    }

    fn activate_debug_guest(&mut self, _node: NodeId) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn receive_guest_introspection(
        &mut self,
        _node: NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, SchedulerError> {
        Ok(Some(
            GuestIntrospectionRecord::new(
                GUEST_INTROSPECTION_FEATURE_CHANNEL_ID,
                GuestIntrospectionMessage::Features(GuestIntrospectionFeatures::new(
                    true, true, true, true, 8,
                )),
            )
            .unwrap_or_else(|error| panic!("feature response should be valid: {error}")),
        ))
    }

    fn reposition_debug_runtime(
        &mut self,
        request: DebugRuntimeRepositionRequest,
    ) -> Result<crucible::DebugRuntimeRepositionReport, SchedulerError> {
        let next_endpoint = if request.current_qemu_gdbstub.as_str().ends_with(":9001") {
            "tcp:127.0.0.1:9002"
        } else {
            "tcp:127.0.0.1:9001"
        };
        let endpoint = DebugGdbEndpoint::new("qemu_gdbstub", next_endpoint)
            .unwrap_or_else(|error| panic!("replacement endpoint should be valid: {error}"));
        Ok(crucible::DebugRuntimeRepositionReport::completed(
            &request, endpoint, 1,
        ))
    }
}

pub(in super::super) struct MismatchingDebugRepositionLoop;

impl QuantumLoop for MismatchingDebugRepositionLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
    }

    fn reposition_debug_runtime(
        &mut self,
        request: DebugRuntimeRepositionRequest,
    ) -> Result<crucible::DebugRuntimeRepositionReport, SchedulerError> {
        let endpoint = DebugGdbEndpoint::new("qemu_gdbstub", "tcp:127.0.0.1:9002")
            .unwrap_or_else(|error| panic!("replacement endpoint should be valid: {error}"));
        let mut report = crucible::DebugRuntimeRepositionReport::completed(&request, endpoint, 1);
        report.gateway_generation = 0;
        Ok(report)
    }
}

pub(in super::super) struct RejectingDebugRepositionLoop {
    pub(in super::super) scheduler_run_active: bool,
    pub(in super::super) acquire_attempts: u64,
    pub(in super::super) release_attempts: u64,
}

impl QuantumLoop for RejectingDebugRepositionLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
    }

    fn acquire_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(!self.scheduler_run_active);
        self.scheduler_run_active = true;
        self.acquire_attempts = self.acquire_attempts.saturating_add(1);
        Ok(())
    }

    fn release_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        assert!(self.scheduler_run_active);
        self.scheduler_run_active = false;
        self.release_attempts = self.release_attempts.saturating_add(1);
        Ok(())
    }

    fn reposition_debug_runtime(
        &mut self,
        _request: DebugRuntimeRepositionRequest,
    ) -> Result<crucible::DebugRuntimeRepositionReport, SchedulerError> {
        assert!(
            !self.scheduler_run_active,
            "runtime replacement must start after guest scheduler ownership is suspended"
        );
        Err(BackendError::Rejected {
            message: String::from("candidate runtime verification failed"),
        }
        .into())
    }
}
