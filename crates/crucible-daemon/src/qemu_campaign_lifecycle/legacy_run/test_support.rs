//! Test fixture for exercising the guarded campaign savepoint projection path.
//!
//! The lifecycle is a deterministic modeled test double. It covers campaign
//! capture ownership and legacy result projection; native-QEMU acceptance is a
//! separate packaged VM gate.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, EventLog, ExecutionFingerprint,
    FingerprintSample, Icount, MarkerId, NodeId, ObservableEvent, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry, VirtualTime,
};
use crucible_campaign::StopCondition;
use crucible_cas::content_store::BlobHandle;
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::{
    GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest,
    QemuObservedFreshAttemptLifecycleFactory, run_guarded_default_campaign_with_runner,
};
use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    QemuFreshAttemptLifecycleFactory, QemuFreshAttemptLifecycleOwner, QemuFreshExecutionRunner,
    QemuFreshModeledDriver,
};

const TEST_EFFECT_TRACE: &[u8] = b"guarded-default-run-test-support-effect-trace";

struct TestLifecycle {
    node: NodeId,
    event_log: EventLog,
    quantum_nanoseconds: u64,
    frontier: VirtualTime,
    completed_quanta: u64,
    configuration: Option<Configuration>,
}

impl QemuFreshAttemptLifecycleOwner for TestLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.completed_quanta = self.completed_quanta.saturating_add(1);
        self.frontier.ticks = self.frontier.ticks.saturating_add(self.quantum_nanoseconds);
        let append = self
            .event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount {
                    retired: self.frontier.ticks,
                },
                self.node.clone(),
                MarkerId::from_name("guarded-campaign-save-fixture-quantum"),
            )])?;
        self.configuration = Some(request.configuration.clone());

        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: self.frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: append.entries,
            event_log_segment_bytes: append.segment_bytes,
            event_log_segment_text: append.segment_text,
            event_log_segment_hash: append.segment_hash,
            event_log_offset: append.offset,
            scheduler_quiescence: None,
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        let configuration =
            self.configuration
                .as_ref()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("checkpoint requested before a completed quantum"),
                })?;
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            None,
            self.frontier,
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: error.to_string(),
        })?;
        let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })?;

        Ok(
            crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![0x5a; 512]))
                .into(),
        )
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<crucible_api::ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "guarded campaign save fixture fault evidence",
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        Ok(FingerprintSample {
            node,
            at: self.frontier,
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"guarded-campaign-save-fixture-fingerprint"),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(Some(TEST_EFFECT_TRACE.to_vec()))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }
}

struct TestLifecycleFactory {
    node: NodeId,
    quantum_nanoseconds: u64,
}

impl QemuFreshAttemptLifecycleFactory for TestLifecycleFactory {
    type Lifecycle = TestLifecycle;
    type Error = io::Error;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &crucible::ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        Ok(TestLifecycle {
            node: self.node.clone(),
            event_log: EventLog::new(),
            quantum_nanoseconds: self.quantum_nanoseconds,
            frontier: VirtualTime::default(),
            completed_quanta: 0,
            configuration: None,
        })
    }
}

/// Runs a deterministic modeled lifecycle through the campaign capture owner.
///
/// The request must name a virtual-time discovery stop and a scenario with one
/// or more VM nodes. The fixture uses the requested deadline as one quantum so
/// the accepted attempt and its capture replay produce identical evidence.
///
/// # Errors
///
/// Returns an error when the request is not a virtual-time save fixture or the
/// guarded campaign cannot complete and authenticate its exact checkpoint.
pub fn run_guarded_default_campaign_test_fixture(
    request: GuardedDefaultCampaignRunRequest,
) -> Result<GuardedDefaultCampaignRun, Box<dyn Error + Send + Sync>> {
    let quantum_nanoseconds = match request.discovery_stop {
        StopCondition::VirtualTimeNanoseconds(deadline) if deadline > 0 => deadline,
        _ => {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the guarded campaign fixture requires a nonzero virtual-time stop",
            )));
        }
    };
    let node = request
        .scenario
        .world()
        .vm_nodes()
        .first()
        .map(|node| node.id.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the guarded campaign fixture requires at least one VM node",
            )
        })?;
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(TestLifecycleFactory {
            node,
            quantum_nanoseconds,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    run_guarded_default_campaign_with_runner(request, runner, evidence)
        .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
}
