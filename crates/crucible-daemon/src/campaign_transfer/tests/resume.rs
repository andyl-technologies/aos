//! Executable-archive checkpoint authentication and origin-routing coverage.
//!
//! These tests use real production checkpoint codecs and public campaign,
//! supervisor, worker, and router boundaries. The checkpoint remains at a
//! zero-progress scheduler boundary, while the verifier, resumed lifecycle,
//! and observation driver are test doubles. Native QEMU restore and progressed
//! selected-origin replay require separate acceptance coverage.

// crucible-lint: allow panic-shortcut -- integration fixtures require exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::{
    Configuration, QuantumRequest, Schedule, SchedulerError, SchedulerEventLogEntry,
    SchedulerQuiescence,
};
use crucible_api::{
    AuthenticatedProductionCheckpointCodecFixture, ProductionFaultEvidenceSnapshot,
    ProductionVmLifecycleResumeState, authenticate_portable_exact_checkpoint_resume_basis,
    build_authenticated_production_checkpoint_codec_fixture,
};
use crucible_campaign::{
    AssignmentId, Attempt, AttemptResourceLimits, AttemptStart, AttemptStartMode, BudgetGrant,
    CampaignArchiveCheckpointResolver, CampaignArchivePolicy, CampaignCommandId,
    CampaignControlAction, CampaignExecutorDriver, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
    CampaignPolicy, ConfigurationArtifact, ControlRequest, CoverageProjection, DaemonEpoch,
    DiscoveryRequest, ExecutionRetentionIntent, ExecutorClient, ExecutorCompatibilityProfile,
    ExplorerPolicy, FairnessPolicy, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    MeasurementSet, NonModeledAttemptDisposition, Observation, ObservationCandidate,
    PropertyVerdictSet, SavepointCaptureOutcome, SavepointCaptureRequest,
    SavepointCaptureResolution, SavepointContinuationSelection, StopCondition, StopOutcome,
    SubmitAttemptDisposition, WorkerSlotId,
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement, ImmutableBlobBackend,
};

use super::super::*;
use crate::{
    AttemptExecutionOrigin, AttemptExecutionProduct, AttemptWorkerFailure,
    CheckpointCompletionOutcome, CheckpointPublicationOutcome, CrucibleAttemptExecution,
    CrucibleExecutionModel, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, DirectoryAssignmentLedger, ExactCheckpointStore,
    LocalExecutorSupervisor, QemuAttemptExecutionRouter, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycle, QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome,
    QemuFreshStartMaterialization, QemuProductionExactResumeExecutionRunner,
    QemuProductionExactResumeLifecycleFactory, QemuProductionExactResumeLifecycleOwner,
    QemuSavepointReplayProof, QemuSelectedOriginVerifier, RepositoryAttemptAdmission,
    RepositoryAttemptWorker, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};

struct FixedCheckpoint(crucible_campaign::ExactCheckpointId);

impl CampaignArchiveCheckpointResolver for FixedCheckpoint {
    fn resolve_checkpoint(
        &mut self,
        _configuration: crucible_campaign::ConfigurationId,
        _pin_fact: crucible_campaign::CampaignFactId,
    ) -> Result<crucible_campaign::ExactCheckpointId, crucible_campaign::CampaignRepositoryError>
    {
        Ok(self.0)
    }
}

#[test]
fn executable_archive_import_authenticates_checkpoint_and_routes_selected_origin() {
    let temporary = tempfile::tempdir().expect("archive checkpoint routing root");
    let production = build_authenticated_production_checkpoint_codec_fixture(
        &temporary.path().join("codec-checkpoint"),
    )
    .expect("build authenticated production checkpoint codec fixture");
    let fixture_basis = authenticate_portable_exact_checkpoint_resume_basis(
        production.source(),
        production.closure(),
    )
    .expect("authenticate checkpoint codec fixture");
    assert!(production.configuration().schedule.is_empty());
    assert_eq!(fixture_basis.scheduler().quanta(), 0);
    assert_eq!(
        fixture_basis.scheduler().frontier(),
        crucible::VirtualTime::default()
    );
    assert!(
        fixture_basis
            .scheduler()
            .retained_event_log_entries()
            .is_empty()
    );
    let source_backend = Arc::new(DirectoryBlobBackend::new(
        "archive-resume-source",
        temporary.path().join("source-objects"),
    ));
    let source = Arc::new(crucible_campaign::CampaignRepository::new(
        source_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("source-refs"),
        )),
    ));
    let (lineage, campaign, head) = running_campaign(&source, &production);
    let source_checkpoints = ExactCheckpointStore::new(
        source_backend as Arc<dyn ImmutableBlobBackend>,
        64 * 1024 * 1024,
    )
    .expect("open source checkpoint store");
    let prepared = source_checkpoints
        .prepare_production_closure(production.closure().clone())
        .expect("prepare production checkpoint for campaign store");
    let checkpoint = source_checkpoints
        .publish_production_closure(&prepared)
        .expect("publish production checkpoint")
        .root();

    let discovery = DiscoveryRequest::new(
        command_id("discover-capture-origin"),
        head,
        lineage.genesis_content(),
        StopCondition::ExecutionQuanta(1),
    )
    .expect("discovery request");
    let admitted = source
        .submit_discovery_request(campaign.as_str(), &discovery)
        .expect("admit capture origin");
    let capture_attempt = source
        .load_attempt(admitted.attempt)
        .expect("load capture origin");
    let capture_request = SavepointCaptureRequest::new(
        command_id("capture-request"),
        admitted.new_snapshot,
        admitted.attempt,
        lineage.genesis_content(),
        lineage.genesis(),
        StopCondition::ExecutionQuanta(1),
        "archive resume source",
    )
    .expect("capture request");
    let accepted = source
        .request_savepoint_capture(campaign.as_str(), &capture_request)
        .expect("accept savepoint capture");

    let epoch = DaemonEpoch::from_bytes([0x71; 16]).expect("source epoch");
    let assignment = crucible_campaign::SubmitAttemptRequest::new_savepoint_capture(
        AssignmentId::from_bytes([0x72; 16]).expect("source assignment"),
        epoch,
        lineage.id().expect("lineage identity"),
        accepted.attempt,
        attempt_resources(),
        ExecutionRetentionIntent::RetainAlways,
        accepted.request,
        accepted.configuration,
    )
    .expect("capture assignment");
    let ledger_root = temporary.path().join("assignment-ledger");
    let mut source_supervisor = LocalExecutorSupervisor::new(
        DirectoryAssignmentLedger::open(&ledger_root).expect("open source ledger"),
        RepositoryAttemptAdmission::new(
            Arc::clone(&source),
            ExecutorCompatibilityProfile::from_lineage(&lineage),
        ),
        epoch,
        executor_capacity(),
    );
    let execution = match crucible_campaign::ExecutorService::submit_attempt(
        &mut source_supervisor,
        &assignment,
    )
    .expect("submit source capture")
    .disposition()
    {
        SubmitAttemptDisposition::Accepted { execution } => execution,
        other => panic!("unexpected source capture disposition: {other:?}"),
    };
    // Seed the public ledger's Paused routing state without claiming that a
    // QEMU capture occurred. Both the stored checkpoint and reached
    // configuration are the fixture's zero-progress genesis boundary.
    let capture_token = source_supervisor
        .next_queued()
        .expect("source capture token");
    assert_eq!(
        source_supervisor
            .stage_checkpoint_publication(&capture_token, checkpoint)
            .expect("stage source checkpoint"),
        CheckpointPublicationOutcome::Staged
    );
    assert_eq!(
        source_supervisor
            .complete_checkpoint(&capture_token, checkpoint)
            .expect("pause source checkpoint"),
        CheckpointCompletionOutcome::Paused
    );
    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("source status request");
    let status = crucible_campaign::ExecutorStatusService::get_attempt_execution(
        &mut source_supervisor,
        &status_request,
    )
    .expect("source paused status");
    assert_eq!(
        status.disposition(),
        GetAttemptExecutionDisposition::Paused { checkpoint }
    );
    drop(source_supervisor);

    let ready = SavepointCaptureResolution {
        command: command_id("capture-ready"),
        expected_snapshot: accepted.new_snapshot,
        request: accepted.request,
        outcome: SavepointCaptureOutcome::Ready,
    };
    let resolved = source
        .resolve_savepoint_capture(campaign.as_str(), &ready, &assignment, &status)
        .expect("resolve ready capture");
    let continuation = Attempt::new(
        AttemptStart::AfterAttempt {
            origin: accepted.attempt,
            reached: lineage.genesis_content(),
        },
        capture_attempt.path(),
        StopCondition::ExecutionQuanta(2),
    )
    .expect("selected continuation");
    let selection = SavepointContinuationSelection {
        command: command_id("select-continuation"),
        expected_snapshot: resolved.new_snapshot,
        request: accepted.request,
        ready: crucible_campaign::CampaignFact::SavepointCaptureResolved(ready)
            .id()
            .expect("ready fact identity"),
        continuation: continuation.id().expect("continuation identity"),
    };
    let selected = source
        .select_savepoint_continuation(campaign.as_str(), &selection, &continuation)
        .expect("select savepoint continuation");
    let closed = source
        .close_attempt_non_modeled(
            campaign.as_str(),
            selected.new_snapshot,
            admitted.attempt,
            NonModeledAttemptDisposition::TerminalWorkerFailure,
        )
        .expect("close captured semantic origin");
    let pinned = source
        .apply_pin(
            campaign.as_str(),
            &crucible_campaign::PinRequest {
                command: command_id("pin-checkpoint"),
                expected_snapshot: closed.new_snapshot,
                change: crucible_campaign::PinChange::new(
                    lineage.genesis(),
                    Some(crucible_campaign::PinRetention::Exact),
                    "retain imported continuation checkpoint",
                )
                .expect("exact pin"),
            },
        )
        .expect("pin continuation checkpoint");
    let mut checkpoint_resolver = FixedCheckpoint(checkpoint);
    let plan = source
        .plan_campaign_archive(
            pinned.new_snapshot,
            CampaignArchivePolicy::Executable,
            [],
            Some(&mut checkpoint_resolver),
        )
        .expect("plan executable archive");

    let destination_backend = Arc::new(DirectoryBlobBackend::new(
        "archive-resume-destination",
        temporary.path().join("destination-objects"),
    ));
    let destination = Arc::new(crucible_campaign::CampaignRepository::new(
        destination_backend.clone(),
        Arc::new(DirectoryRefBackend::new(
            temporary.path().join("destination-refs"),
        )),
    ));
    let destination_checkpoints = Arc::new(
        ExactCheckpointStore::new(
            destination_backend as Arc<dyn ImmutableBlobBackend>,
            64 * 1024 * 1024,
        )
        .expect("open destination checkpoint store"),
    );
    let mut destination_exact_pins = DirectoryExactPinMaterializationStore::open(
        temporary.path().join("destination-exact-pins"),
    )
    .expect("open destination exact-pin store");
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-transfer-journal"))
            .expect("open source transfer journal");
    let mut destination_journal = DirectoryCampaignTransferJournal::open(
        temporary.path().join("destination-transfer-journal"),
    )
    .expect("open destination transfer journal");
    let mut source_endpoint =
        CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true);
    let mut destination_endpoint =
        CampaignArchiveTransferEndpoint::new_with_operational_checkpoints(
            &destination,
            &mut destination_journal,
            "destination",
            true,
            destination_checkpoints.as_ref(),
            &mut destination_exact_pins,
        );
    transfer_campaign_archive_durably(
        &mut source_endpoint,
        &mut destination_endpoint,
        &plan,
        "executable",
        Some("imported"),
        DurabilityRequirement::new(1, false).expect("transfer durability"),
    )
    .expect("transfer executable archive");

    let imported_head = destination
        .head("imported")
        .expect("imported campaign head");
    assert_eq!(imported_head.snapshot_id(), pinned.new_snapshot);
    let imported_campaign = CampaignName::new("imported").expect("imported campaign name");
    let imported_selection = destination_exact_pins
        .acquire_exact_pin_retention_fence()
        .expect("exact-pin fence")
        .selection(&imported_campaign, lineage.genesis())
        .expect("imported exact selection")
        .expect("imported exact selection exists");
    assert_eq!(imported_selection.checkpoint(), checkpoint);
    assert!(
        imported_selection
            .authenticate_current(&destination, destination_checkpoints.as_ref())
            .expect("authenticate imported exact selection")
            .as_production()
            .is_some()
    );

    let destination_epoch = DaemonEpoch::from_bytes([0x73; 16]).expect("destination epoch");
    // Assignment ledgers are executor-local operational state and are not part
    // of an executable campaign archive. Reopening the source ledger here is an
    // explicit routing-fixture input that makes the selected checkpoint
    // available to the destination supervisor.
    let destination_supervisor = LocalExecutorSupervisor::new(
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen source ledger at destination"),
        RepositoryAttemptAdmission::new(
            Arc::clone(&destination),
            ExecutorCompatibilityProfile::from_lineage(&lineage),
        ),
        destination_epoch,
        executor_capacity(),
    );
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&destination),
        ExecutorClient::new(destination_supervisor),
        destination_epoch,
        1,
        attempt_resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("destination campaign driver");
    assert!(matches!(
        driver
            .step("imported", WorkerSlotId::new(0))
            .expect("submit imported continuation"),
        CampaignExecutorStepOutcome::Running {
            attempt,
            newly_accepted: true,
            ..
        } if attempt == selected.continuation
    ));
    let mut destination_supervisor = driver.into_executor().into_inner();
    let queued = destination_supervisor
        .next_queued()
        .expect("imported selected continuation token");
    assert!(matches!(
        queued.origin(),
        AttemptExecutionOrigin::SelectedSavepoint {
            source_attempt,
            source_checkpoint,
            resume: None,
            ..
        } if source_attempt == accepted.attempt && source_checkpoint == checkpoint
    ));
    assert_eq!(queued.request().attempt(), selected.continuation);

    let resume_calls = Arc::new(ResumeCalls::default());
    let cold_route_calls = Arc::new(AtomicUsize::new(0));
    let verifier_route_calls = Arc::new(AtomicUsize::new(0));
    let resume = QemuProductionExactResumeExecutionRunner::new(
        Arc::clone(&destination_checkpoints),
        CheckpointLoadingResumeFactory {
            calls: Arc::clone(&resume_calls),
            basis: None,
        },
        NonDrivingObservationDriver,
    );
    let router = QemuAttemptExecutionRouter::new(
        CannedSelectedOriginVerifier {
            cold_route_calls: Arc::clone(&cold_route_calls),
            verification_route_calls: Arc::clone(&verifier_route_calls),
        },
        resume,
    );
    let store = CampaignExecutorStore::new(Arc::clone(&destination));
    let model = CrucibleExecutionModel::new(store.clone(), router);
    let mut worker = RepositoryAttemptWorker::new(store, model);
    let (_, result) = worker.execute(queued).into_parts();
    let product = result.expect("route imported checkpoint through test lifecycle");

    assert!(matches!(product, AttemptExecutionProduct::Observation(_)));
    assert_eq!(
        worker.model().last_materialization(),
        Some(CrucibleMaterializationTier::ExactRestore)
    );
    assert_eq!(verifier_route_calls.load(Ordering::SeqCst), 1);
    assert_eq!(cold_route_calls.load(Ordering::SeqCst), 0);
    assert_eq!(resume_calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(resume_calls.shutdowns.load(Ordering::SeqCst), 1);

    let fallback_epoch = DaemonEpoch::from_bytes([0x75; 16]).expect("fallback route epoch");
    let fallback_supervisor = LocalExecutorSupervisor::new(
        DirectoryAssignmentLedger::open(temporary.path().join("empty-assignment-ledger"))
            .expect("open empty destination ledger"),
        RepositoryAttemptAdmission::new(
            Arc::clone(&destination),
            ExecutorCompatibilityProfile::from_lineage(&lineage),
        ),
        fallback_epoch,
        executor_capacity(),
    );
    let mut fallback_driver = CampaignExecutorDriver::new(
        Arc::clone(&destination),
        ExecutorClient::new(fallback_supervisor),
        fallback_epoch,
        1,
        attempt_resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("source-absent fallback campaign driver");
    assert!(matches!(
        fallback_driver
            .step("imported", WorkerSlotId::new(0))
            .expect("submit imported continuation without source ledger"),
        CampaignExecutorStepOutcome::Running {
            attempt,
            newly_accepted: true,
            ..
        } if attempt == selected.continuation
    ));
    let mut fallback_supervisor = fallback_driver.into_executor().into_inner();
    let fallback_queued = fallback_supervisor
        .next_queued()
        .expect("source-absent selected continuation token");
    assert_eq!(fallback_queued.origin(), AttemptExecutionOrigin::Initial);
    assert!(matches!(
        fallback_queued.request().start_mode(),
        AttemptStartMode::SelectedSavepoint { .. }
    ));

    let fallback_route_calls = Arc::new(AtomicUsize::new(0));
    let verifier_route_calls = Arc::new(AtomicUsize::new(0));
    let resume_calls = Arc::new(ResumeCalls::default());
    let resume = QemuProductionExactResumeExecutionRunner::new(
        Arc::clone(&destination_checkpoints),
        CheckpointLoadingResumeFactory {
            calls: Arc::clone(&resume_calls),
            basis: None,
        },
        NonDrivingObservationDriver,
    );
    let router = QemuAttemptExecutionRouter::new(
        CannedSelectedOriginVerifier {
            cold_route_calls: Arc::clone(&fallback_route_calls),
            verification_route_calls: Arc::clone(&verifier_route_calls),
        },
        resume,
    );
    let store = CampaignExecutorStore::new(Arc::clone(&destination));
    let model = CrucibleExecutionModel::new(store.clone(), router);
    let mut worker = RepositoryAttemptWorker::new(store, model);
    let (_, result) = worker.execute(fallback_queued).into_parts();
    let product = result.expect("route imported continuation without source ledger");

    assert!(matches!(product, AttemptExecutionProduct::Observation(_)));
    assert_eq!(
        worker.model().last_materialization(),
        Some(CrucibleMaterializationTier::ThinReplay)
    );
    assert_eq!(fallback_route_calls.load(Ordering::SeqCst), 1);
    assert_eq!(verifier_route_calls.load(Ordering::SeqCst), 0);
    assert_eq!(resume_calls.starts.load(Ordering::SeqCst), 0);
    assert_eq!(resume_calls.shutdowns.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct ResumeCalls {
    starts: AtomicUsize,
    shutdowns: AtomicUsize,
}

struct CheckpointLoadingResumeFactory {
    calls: Arc<ResumeCalls>,
    basis: Option<crucible_api::ProductionExactCheckpointResumeBasis>,
}

impl QemuProductionExactResumeLifecycleFactory for CheckpointLoadingResumeFactory {
    type Lifecycle = NonDrivingResumeLifecycle;
    type Error = &'static str;

    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: crucible_campaign::ExactCheckpointId,
        _scenario: &crucible::ScenarioDef,
        source: &crucible::ScenarioDefForm,
        _initial: &Configuration,
        _post_selection: Option<&Configuration>,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        let loaded = checkpoints
            .load_production_closure(checkpoint)
            .map_err(|_| AttemptWorkerFailure::Terminal("load imported production checkpoint"))?;
        let basis = authenticate_portable_exact_checkpoint_resume_basis(source, &loaded)
            .map_err(|_| AttemptWorkerFailure::Terminal("authenticate imported resume basis"))?;
        let scheduler = basis.scheduler();
        let proof = QemuSavepointReplayProof::from_reached_boundary(
            basis.configuration(),
            scheduler.quanta(),
            scheduler.frontier(),
            scheduler.retained_event_log_entries(),
        )
        .map_err(|_| AttemptWorkerFailure::Terminal("build imported resume proof"))?;
        let boundary = crate::qemu_campaign_driver::QemuSelectedResumeBoundary::new(
            basis.configuration().clone(),
            proof,
        );
        self.basis = Some(basis);
        Ok(Some(boundary))
    }

    fn start_resume_lifecycle(
        &mut self,
        _checkpoints: &ExactCheckpointStore,
        _checkpoint: crucible_campaign::ExactCheckpointId,
        _scenario: &crucible::ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _initial: &Configuration,
        _post_selection: Option<&Configuration>,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let basis = self.basis.take().ok_or(AttemptWorkerFailure::Terminal(
            "resume began before checkpoint authentication",
        ))?;
        let scheduler = basis.scheduler();
        let state = ProductionVmLifecycleResumeState::new(
            basis.configuration().clone(),
            scheduler.retained_event_log_entries().to_vec(),
            scheduler.retained_event_log_base_events(),
            scheduler.quanta(),
            scheduler.frontier(),
            SchedulerQuiescence::default(),
            None,
        );
        self.calls.starts.fetch_add(1, Ordering::SeqCst);
        Ok(NonDrivingResumeLifecycle {
            calls: Arc::clone(&self.calls),
            state,
        })
    }
}

struct NonDrivingResumeLifecycle {
    calls: Arc<ResumeCalls>,
    state: ProductionVmLifecycleResumeState,
}

impl QemuFreshAttemptLifecycleOwner for NonDrivingResumeLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("archive resume fixture does not advance a quantum"),
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.state.scheduler_quanta()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
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
        Err(SchedulerError::BoundaryViolation {
            message: String::from("archive resume fixture has no selectable transport"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("archive resume fixture does not capture a checkpoint"),
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("archive resume fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.calls.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

impl QemuProductionExactResumeLifecycleOwner for NonDrivingResumeLifecycle {
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError> {
        Ok(self.state.clone())
    }
}

struct CannedSelectedOriginVerifier {
    cold_route_calls: Arc<AtomicUsize>,
    verification_route_calls: Arc<AtomicUsize>,
}

impl CrucibleExecutionRunner for CannedSelectedOriginVerifier {
    type Error = &'static str;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if !matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Err(AttemptWorkerFailure::Terminal(
                "selected cold route lost its authenticated AfterAttempt ancestry",
            ));
        }
        self.cold_route_calls.fetch_add(1, Ordering::SeqCst);
        Ok(CrucibleExecutionOutcome::new(
            observation_product(input)?,
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

impl QemuSelectedOriginVerifier for CannedSelectedOriginVerifier {
    fn verify_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        _context: &crate::AttemptExecutionContext,
        target: &crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
    ) -> Result<QemuSavepointReplayProof, AttemptWorkerFailure<Self::Error>> {
        if input.start().configuration() != target.configuration() {
            return Err(AttemptWorkerFailure::Terminal(
                "selected replay target differs from the semantic boundary",
            ));
        }
        self.verification_route_calls.fetch_add(1, Ordering::SeqCst);
        target
            .proof()
            .with_attempt_event_count(0)
            .map_err(|_| AttemptWorkerFailure::Terminal("bind selected attempt event count"))
    }
}

impl crate::QemuAttemptStartVerifier for CannedSelectedOriginVerifier {
    fn verify_attempt_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::QemuAttemptStartReplayProof, AttemptWorkerFailure<Self::Error>> {
        panic!("selected-origin transfer fixture must not verify an ordinary start")
    }
}

struct NonDrivingObservationDriver;

impl QemuFreshAttemptDriver for NonDrivingObservationDriver {
    type Pending = ObservationCandidate;
    type Error = &'static str;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        _context: &crate::AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        let AttemptExecutionProduct::Observation(candidate) = observation_product(input)? else {
            return Err(AttemptWorkerFailure::Terminal(
                "archive resume fixture produced a non-observation",
            ));
        };
        Ok(QemuFreshDriveOutcome::Observation(*candidate))
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        if !final_events.is_empty() {
            return Err(AttemptWorkerFailure::Terminal(
                "archive resume fixture observed unexpected final events",
            ));
        }
        Ok(AttemptExecutionProduct::Observation(Box::new(pending)))
    }
}

fn observation_product(
    input: &CrucibleAttemptExecution,
) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<&'static str>> {
    let configuration = input.start().configuration();
    let configuration_id = crucible_campaign::ConfigurationId::from_hash(CampaignHash::from_bytes(
        configuration.id().bytes,
    ));
    let child = ConfigurationArtifact::new(
        input.lineage().scenario(),
        input.lineage().scenario_content(),
        configuration_id,
        2,
        configuration.schedule.to_compact_binary(),
    )
    .map_err(|_| AttemptWorkerFailure::Terminal("build resumed child artifact"))?;
    let measurements = MeasurementSet::new(BTreeMap::new())
        .map_err(|_| AttemptWorkerFailure::Terminal("build empty measurements"))?;
    let properties = PropertyVerdictSet::new(BTreeMap::new())
        .map_err(|_| AttemptWorkerFailure::Terminal("build empty properties"))?;
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
        .map_err(|_| AttemptWorkerFailure::Terminal("build empty coverage"))?;
    let observation = Observation::new(
        input
            .attempt()
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive resumed attempt identity"))?,
        configuration_id,
        child
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive resumed child identity"))?,
        input
            .path()
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive resumed path identity"))?,
        StopOutcome::TerminalSuccess,
        measurements
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive measurement identity"))?,
        properties
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive property identity"))?,
        coverage
            .id()
            .map_err(|_| AttemptWorkerFailure::Terminal("derive coverage identity"))?,
        BTreeSet::new(),
    )
    .map_err(|_| AttemptWorkerFailure::Terminal("build resumed observation"))?;
    let candidate = ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        Vec::new(),
        observation,
    )
    .map_err(|_| AttemptWorkerFailure::Terminal("build resumed observation candidate"))?;
    Ok(AttemptExecutionProduct::Observation(Box::new(candidate)))
}

fn running_campaign(
    repository: &crucible_campaign::CampaignRepository,
    production: &AuthenticatedProductionCheckpointCodecFixture,
) -> (
    CampaignLineage,
    CampaignName,
    crucible_campaign::CampaignSnapshotId,
) {
    let scenario =
        encode_crucible_scenario_artifact(production.source()).expect("encode checkpoint scenario");
    let scenario_id = repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .expect("publish checkpoint scenario");
    let configuration = encode_crucible_configuration_artifact(&scenario, &Schedule::empty())
        .expect("encode checkpoint configuration");
    assert_eq!(
        configuration.configuration(),
        crucible_campaign::ConfigurationId::from_hash(CampaignHash::from_bytes(
            production.configuration().id().bytes,
        ))
    );
    let configuration_id = repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .expect("publish checkpoint configuration");
    let lineage = CampaignLineage::new(
        scenario.scenario(),
        scenario_id,
        configuration.configuration(),
        configuration_id,
        "crucible-archive-resume-test",
        "qemu-archive-resume-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario.payload_schema(),
        4,
    )
    .expect("campaign lineage");
    let policy = CampaignPolicy::new(
        scenario.scenario(),
        crucible_campaign::CampaignSeed::from_bytes([0x74; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        crucible_campaign::RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("campaign policy");
    let campaign = CampaignName::new("source").expect("source campaign name");
    let created = repository
        .create(campaign.as_str(), &lineage, &policy, &BTreeMap::new())
        .expect("create source campaign");
    let funded = repository
        .apply_control(
            campaign.as_str(),
            &ControlRequest {
                command: command_id("grant-budget"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 2).expect("attempt budget"),
                ),
            },
        )
        .expect("fund source campaign");
    let running = repository
        .apply_control(
            campaign.as_str(),
            &ControlRequest {
                command: command_id("resume-campaign"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("run source campaign");
    (lineage, campaign, running.new_snapshot)
}

fn command_id(label: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.test.archive-resume.command",
        label.as_bytes(),
    ))
}

fn attempt_resources() -> AttemptResourceLimits {
    AttemptResourceLimits::new(1, 512 * 1024 * 1024, 64 * 1024 * 1024, 8)
        .expect("attempt resources")
}

fn executor_capacity() -> crate::ExecutorCapacity {
    crate::ExecutorCapacity::new(2, 2, 1024 * 1024 * 1024, 128 * 1024 * 1024, 16)
        .expect("executor capacity")
}
