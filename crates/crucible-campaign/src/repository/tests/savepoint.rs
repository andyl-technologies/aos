//! Savepoint capture intent, scope authentication, and resolution regressions.

use super::*;
use crate::{
    CampaignCommandId, CampaignExecutorCancelOutcome, CampaignExecutorCheckpointOutcome,
    CampaignExecutorDriver, CampaignExecutorStepOutcome, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionDisposition, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, DaemonEpoch, ExactCheckpointId, ExecutionId,
    ExecutionRetentionIntent, ExecutorClient, ExecutorCompatibilityProfile, ExecutorControlService,
    ExecutorResumeService, ExecutorService, ExecutorStatusService, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, ResumeAttemptExecutionDisposition,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptDisposition,
    SubmitAttemptRequest, SubmitAttemptResponse, WorkerSlotId,
};
use crucible_cas::content_store::{BackendCapabilities, ByteRange, PutReceipt};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CaptureReadCountingBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl ImmutableBlobBackend for CaptureReadCountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put_if_absent(id, source)
    }
}

struct PausingCaptureExecutor {
    requests: Vec<SubmitAttemptRequest>,
    status_requests: Vec<GetAttemptExecutionRequest>,
    resume_requests: Vec<ResumeAttemptExecutionRequest>,
    execution: ExecutionId,
    checkpoint: ExactCheckpointId,
    cancellation_requested: bool,
    checkpoint_requests: Vec<CheckpointAttemptExecutionRequest>,
    cancel_requests: Vec<CancelAttemptExecutionRequest>,
}

struct FairCaptureExecutor {
    requests: Vec<SubmitAttemptRequest>,
    status_requests: Vec<GetAttemptExecutionRequest>,
    unavailable_capture: CampaignFactId,
    ordinary_execution: ExecutionId,
    capture_execution: ExecutionId,
    observation: ObservationId,
    checkpoint: ExactCheckpointId,
}

impl ExecutorService for FairCaptureExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.requests.push(request.clone());
        let disposition = match request.start_mode() {
            AttemptStartMode::Execute => SubmitAttemptDisposition::Accepted {
                execution: self.ordinary_execution,
            },
            AttemptStartMode::SavepointCapture {
                request: capture, ..
            } if capture == self.unavailable_capture => SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::UnavailableInput,
            },
            AttemptStartMode::SavepointCapture { .. } => SubmitAttemptDisposition::Accepted {
                execution: self.capture_execution,
            },
            AttemptStartMode::CaptureMaterializedStart { .. } => {
                return Err("unexpected materialized-start capture");
            }
        };
        SubmitAttemptResponse::new(request, disposition).map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for FairCaptureExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_requests.push(request.clone());
        let disposition = if request.execution() == self.ordinary_execution {
            GetAttemptExecutionDisposition::Completed {
                observation: self.observation,
            }
        } else if request.execution() == self.capture_execution {
            GetAttemptExecutionDisposition::Paused {
                checkpoint: self.checkpoint,
            }
        } else {
            return Err("unexpected execution");
        };
        GetAttemptExecutionResponse::new(request, disposition).map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for FairCaptureExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorService for PausingCaptureExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.requests.push(request.clone());
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for PausingCaptureExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_requests.push(request.clone());
        let disposition = if self.cancellation_requested {
            GetAttemptExecutionDisposition::Canceled
        } else {
            GetAttemptExecutionDisposition::Paused {
                checkpoint: self.checkpoint,
            }
        };
        GetAttemptExecutionResponse::new(request, disposition).map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for PausingCaptureExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.resume_requests.push(request.clone());
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorControlService for PausingCaptureExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.checkpoint_requests.push(request.clone());
        CheckpointAttemptExecutionResponse::new(
            request,
            CheckpointAttemptExecutionDisposition::Requested,
        )
        .map_err(|_| "response encoding")
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.cancel_requests.push(request.clone());
        self.cancellation_requested = true;
        CancelAttemptExecutionResponse::new(request, CancelAttemptExecutionDisposition::Canceled)
            .map_err(|_| "response encoding")
    }
}

#[test]
fn capture_request_owns_no_semantic_admission_budget_or_configuration_pin() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-atomic", 2);
    let baseline_budget = repository
        .budget_projection("savepoint-atomic")
        .expect("baseline budget");
    let baseline_pins = repository
        .visit_pin_retention_roots("savepoint-atomic", &mut |_| {})
        .expect("baseline pins");
    let request = capture_request(
        &repository,
        "capture",
        &head,
        &lineage,
        StopCondition::Terminal,
    );
    let request_fact = CampaignFact::SavepointCaptureRequested(request.clone());
    let request_bytes = request_fact.canonical_bytes();
    assert_eq!(&request_bytes[..4], &11_u32.to_be_bytes());
    assert_eq!(
        CampaignFact::from_canonical_bytes(&request_bytes).expect("decode v11 capture request"),
        request_fact
    );
    let mut request_as_v12 = request_bytes;
    request_as_v12[..4].copy_from_slice(&12_u32.to_be_bytes());
    assert!(CampaignFact::from_canonical_bytes(&request_as_v12).is_err());

    let accepted = repository
        .request_savepoint_capture("savepoint-atomic", &request)
        .expect("accept savepoint capture");
    assert_eq!(accepted.prior_snapshot, head.snapshot_id());
    assert_eq!(accepted.attempt, request.attempt);
    assert_eq!(accepted.configuration, lineage.genesis_content());
    assert!(!accepted.replayed);

    let next = repository.head("savepoint-atomic").expect("capture head");
    let prior_roots = head.snapshot().roots();
    let next_roots = next.snapshot().roots();
    assert_eq!(prior_roots.graph, next_roots.graph);
    assert_eq!(prior_roots.exploration, next_roots.exploration);
    assert_eq!(prior_roots.observations, next_roots.observations);
    assert_eq!(prior_roots.corpus, next_roots.corpus);
    assert_eq!(prior_roots.coverage, next_roots.coverage);
    assert_eq!(prior_roots.findings, next_roots.findings);
    assert_eq!(prior_roots.pins, next_roots.pins);
    assert_ne!(prior_roots.accounting, next_roots.accounting);
    assert_budget_usage_eq(
        repository
            .budget_projection("savepoint-atomic")
            .expect("unchanged budget"),
        baseline_budget,
    );
    let current_pins = repository
        .visit_pin_retention_roots("savepoint-atomic", &mut |_| {})
        .expect("unchanged configuration pins");
    assert_eq!(current_pins.pins_root(), baseline_pins.pins_root());
    assert_eq!(current_pins.entries(), baseline_pins.entries());
    assert_eq!(current_pins.thin_pins(), baseline_pins.thin_pins());
    assert_eq!(current_pins.exact_pins(), baseline_pins.exact_pins());
    assert_eq!(current_pins.tombstones(), baseline_pins.tombstones());
    assert!(
        repository
            .project_claimable_attempts("savepoint-atomic", None, 10_000)
            .expect("semantic work projection")
            .attempts()
            .is_empty()
    );

    assert_eq!(
        repository
            .savepoint_capture_request_at(accepted.new_snapshot, accepted.request)
            .expect("load capture intent"),
        Some(request.clone())
    );
    let pending = repository
        .project_pending_savepoint_captures("savepoint-atomic", None, 10_000)
        .expect("pending capture projection");
    assert_eq!(pending.captures().len(), 1);
    assert_eq!(pending.captures()[0].request(), accepted.request);
    assert_eq!(pending.captures()[0].capture(), &request);
    assert!(pending.next().is_none());

    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let assignment = scoped_assignment(&lineage, &accepted, [0xa1; 16], [0xa2; 16]);
    repository
        .validate_executor_request_with_profile(&assignment, &profile)
        .expect("ordinary immutable capture basis");
    repository
        .validate_executor_execution_scope_with_profile(&assignment, &profile)
        .expect("capture fact owns scope");

    let paused = repository
        .apply_control(
            "savepoint-atomic",
            &command(
                "pause-after-capture",
                accepted.new_snapshot,
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("later mutation");
    let replayed = repository
        .request_savepoint_capture("savepoint-atomic", &request)
        .expect("exact replay");
    assert_eq!(replayed.new_snapshot, accepted.new_snapshot);
    assert_eq!(replayed.request, accepted.request);
    assert!(replayed.replayed);
    assert_ne!(paused.new_snapshot, replayed.new_snapshot);

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .savepoint_capture_request_at(accepted.new_snapshot, accepted.request)
            .expect("cold capture intent"),
        Some(request)
    );
}

#[test]
fn capture_scope_rejects_changed_fact_basis_and_wrong_fact_kind() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-auth", 2);
    let request = capture_request(
        &repository,
        "capture-auth",
        &head,
        &lineage,
        StopCondition::Terminal,
    );
    let accepted = repository
        .request_savepoint_capture("savepoint-auth", &request)
        .expect("capture request");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);

    let wrong_configuration = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        b"wrong configuration",
    ))
    .expect("configuration ID");
    let mismatched = SubmitAttemptRequest::new_savepoint_capture(
        AssignmentId::from_bytes([0xb1; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0xb2; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        accepted.attempt,
        resources(),
        ExecutionRetentionIntent::RetainAlways,
        accepted.request,
        wrong_configuration,
    )
    .expect("mismatched scoped assignment");
    assert!(matches!(
        repository.validate_executor_execution_scope_with_profile(&mismatched, &profile),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-savepoint-capture-scope-request-basis-mismatch"
        })
    ));

    let wrong_fact = repository
        .put_fact(&CampaignFact::BudgetGranted(
            BudgetGrant::new(1, 1).expect("budget grant"),
        ))
        .expect("publish wrong fact kind");
    let forged = SubmitAttemptRequest::new_savepoint_capture(
        AssignmentId::from_bytes([0xb3; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0xb2; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        accepted.attempt,
        resources(),
        ExecutionRetentionIntent::RetainAlways,
        CampaignFactId::from_content_id(wrong_fact).expect("fact ID"),
        accepted.configuration,
    )
    .expect("wrong-fact scoped assignment");
    assert!(matches!(
        repository.validate_executor_execution_scope_with_profile(&forged, &profile),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-savepoint-capture-scope-is-not-capture-request"
        })
    ));

    let paused = repository
        .apply_control(
            "savepoint-auth",
            &command(
                "pause-before-orphan-capture",
                accepted.new_snapshot,
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause campaign");
    let orphan = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"paused-orphan-capture")),
        paused.new_snapshot,
        accepted.attempt,
        accepted.configuration,
        lineage.genesis(),
        request.stop.clone(),
        "orphan capture at paused parent",
    )
    .expect("orphan capture request");
    let orphan_content = repository
        .put_fact(&CampaignFact::SavepointCaptureRequested(orphan))
        .expect("publish orphan capture fact");
    let orphan_assignment = SubmitAttemptRequest::new_savepoint_capture(
        AssignmentId::from_bytes([0xb7; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0xb8; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        accepted.attempt,
        resources(),
        ExecutionRetentionIntent::RetainAlways,
        CampaignFactId::from_content_id(orphan_content).expect("orphan fact ID"),
        accepted.configuration,
    )
    .expect("orphan scoped assignment");
    assert!(matches!(
        repository.validate_executor_execution_scope_with_profile(&orphan_assignment, &profile),
        Err(CampaignRepositoryError::InvalidTransition {
            state: CampaignState::Paused
        })
    ));
}

#[test]
fn capture_scope_authenticates_an_existing_branch_attempt() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-branch", 2);
    let branch = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "savepoint-branch-request",
    );
    let proposal = finite_proposal(&branch, &policy, &head, ChoiceValue::Boolean(true), 1);
    let (selection, path, attempt) = branch_attempt(&repository, &branch, &proposal);
    repository
        .put_branch_request(&branch)
        .expect("publish branch request");
    repository
        .put_proposal(&proposal)
        .expect("publish branch proposal");
    repository
        .put_selection(&selection)
        .expect("publish branch selection");
    repository
        .put_branch_path(&path)
        .expect("publish branch path");
    repository
        .put_attempt(&attempt)
        .expect("publish branch attempt");

    let request = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"capture-existing-branch-attempt",
        )),
        head.snapshot_id(),
        attempt.id().expect("branch attempt ID"),
        lineage.genesis_content(),
        lineage.genesis(),
        branch.stop().clone(),
        "capture branch attempt stop",
    )
    .expect("branch capture request");
    let accepted = repository
        .request_savepoint_capture("savepoint-branch", &request)
        .expect("accept branch capture");
    let assignment = scoped_assignment(&lineage, &accepted, [0xb5; 16], [0xb6; 16]);
    repository
        .validate_executor_execution_scope_with_profile(
            &assignment,
            &ExecutorCompatibilityProfile::from_lineage(&lineage),
        )
        .expect("authenticate branch capture scope");
}

#[test]
fn mutated_capture_reason_is_rejected_before_repository_writes() {
    let (original, lineage, policy) = fixture();
    let head = running_campaign(&original, &lineage, &policy, "savepoint-reason", 1);
    let writes = Arc::new(CaptureReadCountingBackend {
        inner: original.blobs.clone(),
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let repository = CampaignRepository::new(writes.clone(), original.refs.clone());
    let mut request = capture_request(
        &repository,
        "mutated-reason",
        &head,
        &lineage,
        StopCondition::Terminal,
    );
    writes.writes.store(0, Ordering::SeqCst);
    request.reason = String::from("invalid\0reason");

    assert!(matches!(
        repository.request_savepoint_capture("savepoint-reason", &request),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "savepoint capture reason is invalid"
            }
        ))
    ));
    assert_eq!(writes.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        repository
            .head("savepoint-reason")
            .expect("unchanged head")
            .snapshot_id(),
        head.snapshot_id()
    );
}

#[test]
fn cold_validation_rejects_a_forged_capture_successor_while_paused() {
    let (repository, lineage, policy) = fixture();
    let running = running_campaign(&repository, &lineage, &policy, "savepoint-forged", 1);
    let paused = repository
        .apply_control(
            "savepoint-forged",
            &command(
                "pause-before-forged-capture",
                running.snapshot_id(),
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause campaign");
    let parent = repository
        .read_snapshot(paused.new_snapshot.content_id())
        .expect("paused parent");
    let attempt = capture_attempt(&repository, &lineage, StopCondition::Terminal);
    let request = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"forged-paused-capture")),
        paused.new_snapshot,
        attempt,
        lineage.genesis_content(),
        lineage.genesis(),
        StopCondition::Terminal,
        "forged paused capture",
    )
    .expect("forged capture request");
    let transition_content = repository
        .put_fact(&CampaignFact::SavepointCaptureRequested(request.clone()))
        .expect("publish forged transition");
    let transition =
        CampaignFactId::from_content_id(transition_content).expect("forged transition ID");
    let mut roots = parent.snapshot.roots();
    for (key, value) in [
        (
            map_key_hash("accounting.command", request.command.as_hash()),
            transition_content,
        ),
        (
            savepoint_capture_request_key(transition),
            transition_content,
        ),
    ] {
        roots.accounting = repository
            .merkle
            .insert(roots.accounting, key, value)
            .expect("forged accounting insertion")
            .content_id();
    }
    roots.coordination = repository
        .coordination_with_parent_result(parent.envelope.content_id(), &parent)
        .expect("forged coordination root");
    let forged = repository
        .budgeted_successor(
            paused.new_snapshot,
            parent.snapshot.lineage(),
            parent.snapshot.active_policy(),
            roots,
            transition,
        )
        .expect("forged successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("publish forged successor");

    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        cold.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "savepoint-capture-parent-is-not-running"
        })
    ));
}

#[test]
fn ordinary_attempt_and_scoped_capture_coexist_and_resolution_survives_restart() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-coexist", 2);
    let discovery = DiscoveryRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"ordinary-discovery")),
        head.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("discovery request");
    let admitted = repository
        .submit_discovery_request("savepoint-coexist", &discovery)
        .expect("admit ordinary attempt");
    let capture_head = repository
        .head("savepoint-coexist")
        .expect("admission head");
    let budget_before_capture = repository
        .budget_projection("savepoint-coexist")
        .expect("budget after semantic admission");
    let request = capture_request(
        &repository,
        "coexisting-capture",
        &capture_head,
        &lineage,
        StopCondition::Terminal,
    );
    assert_eq!(request.attempt, admitted.attempt);

    let accepted = repository
        .request_savepoint_capture("savepoint-coexist", &request)
        .expect("same attempt in distinct execution scope");
    assert_budget_usage_eq(
        repository
            .budget_projection("savepoint-coexist")
            .expect("capture did not consume budget"),
        budget_before_capture,
    );
    assert_eq!(
        repository
            .project_claimable_attempts("savepoint-coexist", None, 10_000)
            .expect("semantic attempt remains claimable")
            .attempts(),
        &[admitted.attempt]
    );

    let assignment = scoped_assignment(&lineage, &accepted, [0xc1; 16], [0xc2; 16]);
    let execution = ExecutionId::from_bytes([0xc3; 16]).expect("execution");
    let query = GetAttemptExecutionRequest::new(&assignment, execution).expect("status query");
    let checkpoint = exact_checkpoint("coexisting-capture-checkpoint");
    let status = GetAttemptExecutionResponse::new(
        &query,
        GetAttemptExecutionDisposition::Paused { checkpoint },
    )
    .expect("paused status");
    let resolution = SavepointCaptureResolution {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"resolve-coexisting-capture",
        )),
        expected_snapshot: accepted.new_snapshot,
        request: accepted.request,
        outcome: SavepointCaptureOutcome::Ready,
    };
    let resolution_fact = CampaignFact::SavepointCaptureResolved(resolution.clone());
    let resolution_bytes = resolution_fact.canonical_bytes();
    assert_eq!(&resolution_bytes[..4], &12_u32.to_be_bytes());
    assert_eq!(
        CampaignFact::from_canonical_bytes(&resolution_bytes)
            .expect("decode v12 capture resolution"),
        resolution_fact
    );
    let mut resolution_as_v11 = resolution_bytes;
    resolution_as_v11[..4].copy_from_slice(&11_u32.to_be_bytes());
    assert!(CampaignFact::from_canonical_bytes(&resolution_as_v11).is_err());
    let resolved = repository
        .resolve_savepoint_capture("savepoint-coexist", &resolution, &assignment, &status)
        .expect("resolve paused capture");
    assert_eq!(resolved.request, accepted.request);
    assert_eq!(resolved.outcome, SavepointCaptureOutcome::Ready);
    assert!(!resolved.replayed);
    assert!(
        repository
            .project_pending_savepoint_captures("savepoint-coexist", None, 10_000)
            .expect("resolved projection")
            .captures()
            .is_empty()
    );

    let discard = SavepointCaptureResolution {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"discard-coexisting-capture",
        )),
        expected_snapshot: resolved.new_snapshot,
        request: accepted.request,
        outcome: SavepointCaptureOutcome::Discarded,
    };
    assert!(matches!(
        repository.resolve_savepoint_capture("savepoint-coexist", &discard, &assignment, &status,),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-discard-is-not-yet-supported"
        })
    ));
    assert_eq!(
        repository
            .head("savepoint-coexist")
            .expect("discard rejection leaves head unchanged")
            .snapshot_id(),
        resolved.new_snapshot
    );

    let discarded = repository
        .install_historical_savepoint_capture_resolution(
            "savepoint-coexist",
            &discard,
            &assignment,
            &status,
        )
        .expect("install formerly supported discard history");
    assert_eq!(discarded.outcome, SavepointCaptureOutcome::Discarded);
    assert_eq!(
        repository
            .savepoint_capture_resolution_at(discarded.new_snapshot, accepted.request)
            .expect("historical capture disposition")
            .expect("historical capture is resolved")
            .outcome,
        SavepointCaptureOutcome::Discarded
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(
        restarted
            .project_pending_savepoint_captures("savepoint-coexist", None, 10_000)
            .expect("cold resolved projection")
            .captures()
            .is_empty()
    );
    let ready_replay = restarted
        .resolve_savepoint_capture("savepoint-coexist", &resolution, &assignment, &status)
        .expect("ready resolution replay after discard");
    assert_eq!(ready_replay.new_snapshot, resolved.new_snapshot);
    assert!(ready_replay.replayed);
    let discard_replay = restarted
        .resolve_savepoint_capture("savepoint-coexist", &discard, &assignment, &status)
        .expect("historical discard command replay after restart");
    assert_eq!(discard_replay.new_snapshot, discarded.new_snapshot);
    assert!(discard_replay.replayed);
}

#[test]
fn cold_capture_history_validation_is_iterative_and_linearly_bounded() {
    const CAPTURES: usize = 128;
    const CAMPAIGN: &str = "savepoint-cold-scale";

    let (repository, lineage, policy) = fixture();
    running_campaign(&repository, &lineage, &policy, CAMPAIGN, 1);
    let attempt = capture_attempt(&repository, &lineage, StopCondition::Terminal);
    for ordinal in 0..CAPTURES {
        let head = repository.head(CAMPAIGN).expect("capture head");
        let request = SavepointCaptureRequest::new(
            CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                format!("cold-capture-{ordinal}").as_bytes(),
            )),
            head.snapshot_id(),
            attempt,
            lineage.genesis_content(),
            lineage.genesis(),
            StopCondition::Terminal,
            "cold validation scale",
        )
        .expect("capture request");
        let accepted = repository
            .request_savepoint_capture(CAMPAIGN, &request)
            .expect("append capture request");
        let identity = u8::try_from(ordinal + 1).expect("bounded capture identity");
        let assignment = scoped_assignment(&lineage, &accepted, [identity; 16], [0xd1; 16]);
        let execution = ExecutionId::from_bytes([identity; 16]).expect("capture execution");
        let query =
            GetAttemptExecutionRequest::new(&assignment, execution).expect("capture status query");
        let status = GetAttemptExecutionResponse::new(
            &query,
            GetAttemptExecutionDisposition::Paused {
                checkpoint: exact_checkpoint(&format!("cold-capture-{ordinal}")),
            },
        )
        .expect("paused capture status");
        let resolution = SavepointCaptureResolution {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                format!("cold-resolution-{ordinal}").as_bytes(),
            )),
            expected_snapshot: accepted.new_snapshot,
            request: accepted.request,
            outcome: SavepointCaptureOutcome::Ready,
        };
        repository
            .resolve_savepoint_capture(CAMPAIGN, &resolution, &assignment, &status)
            .expect("append capture resolution");
    }

    let reads = Arc::new(CaptureReadCountingBackend {
        inner: repository.blobs.clone(),
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let refs = repository.refs.clone();
    let thread_reads = reads.clone();
    let validated = std::thread::Builder::new()
        .name(String::from("cold-capture-validation"))
        .stack_size(256 * 1024)
        .spawn(move || {
            let cold = CampaignRepository::new(thread_reads, refs);
            cold.head(CAMPAIGN).map(|head| head.snapshot_id())
        })
        .expect("spawn small-stack cold validator")
        .join()
        .expect("cold validator did not overflow its stack")
        .expect("cold capture history validates");
    assert_eq!(
        validated,
        repository.head(CAMPAIGN).expect("warm head").snapshot_id()
    );

    let read_count = reads.reads.load(Ordering::SeqCst);
    assert!(
        read_count <= CAPTURES * 2 * 128,
        "cold validation used {read_count} reads for {CAPTURES} capture pairs"
    );
}

#[test]
fn capture_rejects_stale_and_mismatched_configuration_without_state_change() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-negative", 2);
    let baseline_budget = repository
        .budget_projection("savepoint-negative")
        .expect("baseline budget");

    let stale_snapshot = head.snapshot().parent().expect("running snapshot parent");
    let stale = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"stale-capture")),
        stale_snapshot,
        capture_attempt(&repository, &lineage, StopCondition::Terminal),
        lineage.genesis_content(),
        lineage.genesis(),
        StopCondition::Terminal,
        "stale savepoint",
    )
    .expect("stale request");
    assert!(matches!(
        repository.request_savepoint_capture("savepoint-negative", &stale),
        Err(CampaignRepositoryError::Stale { expected, current })
            if expected == stale_snapshot && current == head.snapshot_id()
    ));

    let mismatched = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"mismatched-capture")),
        head.snapshot_id(),
        capture_attempt(&repository, &lineage, StopCondition::Terminal),
        lineage.genesis_content(),
        ConfigurationId::from_hash(CampaignHash::derive("test", b"wrong-configuration")),
        StopCondition::Terminal,
        "mismatched savepoint",
    )
    .expect("mismatched request");
    assert!(matches!(
        repository.request_savepoint_capture("savepoint-negative", &mismatched),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-configuration-is-not-authoritative"
        })
    ));
    assert_eq!(
        repository
            .head("savepoint-negative")
            .expect("unchanged head")
            .snapshot_id(),
        head.snapshot_id()
    );
    assert_budget_usage_eq(
        repository
            .budget_projection("savepoint-negative")
            .expect("unchanged budget"),
        baseline_budget,
    );
}

#[test]
fn executor_driver_runs_scoped_capture_to_ready_without_resume_or_semantic_ownership() {
    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, "savepoint-driver", 2);
    let request = capture_request(
        &repository,
        "savepoint-driver-request",
        &head,
        &lineage,
        StopCondition::ExecutionQuanta(200),
    );
    let accepted = repository
        .request_savepoint_capture("savepoint-driver", &request)
        .expect("accept driver capture");
    let repository = Arc::new(repository);
    let execution = ExecutionId::from_bytes([0xd1; 16]).expect("capture execution");
    let checkpoint = exact_checkpoint("savepoint-driver-ready");
    let service = PausingCaptureExecutor {
        requests: Vec::new(),
        status_requests: Vec::new(),
        resume_requests: Vec::new(),
        execution,
        checkpoint,
        cancellation_requested: false,
        checkpoint_requests: Vec::new(),
        cancel_requests: Vec::new(),
    };
    let mut driver = CampaignExecutorDriver::new(
        repository.clone(),
        ExecutorClient::new(service),
        DaemonEpoch::from_bytes([0xd2; 16]).expect("daemon epoch"),
        1,
        resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("capture driver");

    assert!(matches!(
        driver
            .step("savepoint-driver", WorkerSlotId::new(0))
            .expect("submit scoped capture"),
        CampaignExecutorStepOutcome::CaptureRunning {
            request,
            attempt,
            execution: actual_execution,
            newly_accepted: true,
        } if request == accepted.request
            && attempt == accepted.attempt
            && actual_execution == execution
    ));
    assert_eq!(driver.reservation_count(), 1);
    assert_eq!(driver.active_execution_count(), 1);

    let resolved = driver
        .checkpoint_one("savepoint-driver")
        .expect("checkpoint policy polls prelatched capture");
    let CampaignExecutorCheckpointOutcome::CaptureResolved {
        result,
        attempt,
        execution: actual_execution,
        checkpoint: actual_checkpoint,
    } = resolved
    else {
        panic!("expected ready capture resolution")
    };
    assert_eq!(result.request, accepted.request);
    assert_eq!(result.outcome, SavepointCaptureOutcome::Ready);
    assert_eq!(attempt, accepted.attempt);
    assert_eq!(actual_execution, execution);
    assert_eq!(actual_checkpoint, Some(checkpoint));
    assert_eq!(driver.reservation_count(), 0);
    assert_eq!(driver.active_execution_count(), 0);

    let service = driver.into_executor().into_inner();
    assert_eq!(service.requests.len(), 1);
    assert_eq!(service.status_requests.len(), 1);
    assert!(service.resume_requests.is_empty());
    assert!(service.checkpoint_requests.is_empty());
    assert!(service.cancel_requests.is_empty());
    let assignment = &service.requests[0];
    assert_eq!(
        assignment.retention(),
        ExecutionRetentionIntent::RetainAlways
    );
    assert_eq!(assignment.resources(), resources());
    assert_eq!(
        assignment.start_mode(),
        AttemptStartMode::SavepointCapture {
            request: accepted.request,
            configuration: accepted.configuration,
        }
    );

    let restarted_repository = Arc::new(CampaignRepository::new(
        repository.blobs.clone(),
        repository.refs.clone(),
    ));
    let mut restarted = CampaignExecutorDriver::new(
        restarted_repository,
        ExecutorClient::new(PausingCaptureExecutor {
            requests: Vec::new(),
            status_requests: Vec::new(),
            resume_requests: Vec::new(),
            execution,
            checkpoint,
            cancellation_requested: false,
            checkpoint_requests: Vec::new(),
            cancel_requests: Vec::new(),
        }),
        DaemonEpoch::from_bytes([0xd3; 16]).expect("restart epoch"),
        1,
        resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("restarted capture driver");
    assert!(matches!(
        restarted
            .step("savepoint-driver", WorkerSlotId::new(0))
            .expect("restart excludes resolved capture"),
        CampaignExecutorStepOutcome::Idle { snapshot }
            if snapshot == result.new_snapshot
    ));
    assert!(restarted.into_executor().into_inner().requests.is_empty());
}

#[test]
fn executor_driver_cancels_capture_then_records_authenticated_terminal_status() {
    const CAMPAIGN: &str = "savepoint-driver-cancel";

    let (repository, lineage, policy) = fixture();
    let head = running_campaign(&repository, &lineage, &policy, CAMPAIGN, 2);
    let request = capture_request(
        &repository,
        "savepoint-driver-cancel-request",
        &head,
        &lineage,
        StopCondition::ExecutionQuanta(200),
    );
    let accepted = repository
        .request_savepoint_capture(CAMPAIGN, &request)
        .expect("accept cancelable capture");
    let execution = ExecutionId::from_bytes([0xd4; 16]).expect("capture execution");
    let repository = Arc::new(repository);
    let mut driver = CampaignExecutorDriver::new(
        repository,
        ExecutorClient::new(PausingCaptureExecutor {
            requests: Vec::new(),
            status_requests: Vec::new(),
            resume_requests: Vec::new(),
            execution,
            checkpoint: exact_checkpoint("unused-canceled-savepoint"),
            cancellation_requested: false,
            checkpoint_requests: Vec::new(),
            cancel_requests: Vec::new(),
        }),
        DaemonEpoch::from_bytes([0xd5; 16]).expect("daemon epoch"),
        1,
        resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("capture driver");
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::CaptureRunning { request, .. })
            if request == accepted.request
    ));

    assert!(matches!(
        driver.cancel_one(CAMPAIGN),
        Ok(CampaignExecutorCancelOutcome::CaptureCancellationRequested {
            request,
            execution: actual_execution,
            already_canceled: false,
            ..
        }) if request == accepted.request && actual_execution == execution
    ));
    assert_eq!(driver.reservation_count(), 1);
    assert_eq!(driver.active_execution_count(), 1);
    assert!(matches!(
        driver.cancel_one(CAMPAIGN),
        Ok(CampaignExecutorCancelOutcome::CaptureResolved {
            ref result,
            execution: actual_execution,
            ..
        }) if result.request == accepted.request
            && result.outcome == SavepointCaptureOutcome::Canceled
            && actual_execution == execution
    ));
    assert_eq!(driver.reservation_count(), 0);
    assert_eq!(driver.active_execution_count(), 0);

    let service = driver.into_executor().into_inner();
    assert_eq!(service.cancel_requests.len(), 1);
    assert_eq!(service.status_requests.len(), 1);
    assert!(service.resume_requests.is_empty());
    assert!(service.checkpoint_requests.is_empty());
}

#[test]
fn transient_capture_failure_cannot_starve_semantic_work_or_later_captures() {
    const CAMPAIGN: &str = "savepoint-driver-fairness";

    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, CAMPAIGN);
    let observation_id = observation.id().expect("ordinary observation ID");
    repository
        .put_observation(&observation)
        .expect("publish ordinary observation");
    let running = repository
        .apply_control(
            CAMPAIGN,
            &command(
                "savepoint-driver-fairness-resume",
                admitted.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("start campaign");
    let attempt = repository
        .load_attempt(admitted.attempt)
        .expect("load admitted attempt");

    let first_request = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"fair-capture-one")),
        running.new_snapshot,
        admitted.attempt,
        lineage.genesis_content(),
        lineage.genesis(),
        attempt.stop().clone(),
        "first capture",
    )
    .expect("first capture request");
    let first = repository
        .request_savepoint_capture(CAMPAIGN, &first_request)
        .expect("accept first capture");
    let second_request = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"fair-capture-two")),
        first.new_snapshot,
        admitted.attempt,
        lineage.genesis_content(),
        lineage.genesis(),
        attempt.stop().clone(),
        "second capture",
    )
    .expect("second capture request");
    let second = repository
        .request_savepoint_capture(CAMPAIGN, &second_request)
        .expect("accept second capture");
    let pending = repository
        .project_pending_savepoint_captures(CAMPAIGN, None, 10_000)
        .expect("pending captures");
    assert_eq!(pending.captures().len(), 2);
    let unavailable_capture = pending.captures()[0].request();
    let ready_capture = pending.captures()[1].request();
    assert_eq!(
        BTreeSet::from([first.request, second.request]),
        BTreeSet::from([unavailable_capture, ready_capture])
    );

    let ordinary_execution = ExecutionId::from_bytes([0xe1; 16]).expect("ordinary execution");
    let capture_execution = ExecutionId::from_bytes([0xe2; 16]).expect("capture execution");
    let checkpoint = exact_checkpoint("savepoint-driver-fairness-ready");
    let repository = Arc::new(repository);
    let mut driver = CampaignExecutorDriver::new(
        repository,
        ExecutorClient::new(FairCaptureExecutor {
            requests: Vec::new(),
            status_requests: Vec::new(),
            unavailable_capture,
            ordinary_execution,
            capture_execution,
            observation: observation_id,
            checkpoint,
        }),
        DaemonEpoch::from_bytes([0xe3; 16]).expect("daemon epoch"),
        1,
        resources(),
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("fair capture driver");

    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::CaptureRetryScheduled {
            request,
            reason: ExecutorRejection::UnavailableInput,
            ..
        }) if request == unavailable_capture
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::Running {
            attempt,
            execution,
            newly_accepted: true,
        }) if attempt == admitted.attempt && execution == ordinary_execution
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::Incorporated(ref result))
            if result.observation == observation_id
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::CaptureRunning {
            request,
            execution,
            newly_accepted: true,
            ..
        }) if request == ready_capture && execution == capture_execution
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::CaptureResolved {
            ref result,
            checkpoint: Some(actual_checkpoint),
            ..
        }) if result.request == ready_capture && actual_checkpoint == checkpoint
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::Idle { .. })
    ));
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(0)),
        Ok(CampaignExecutorStepOutcome::CaptureRetryScheduled { request, .. })
            if request == unavailable_capture
    ));

    let service = driver.into_executor().into_inner();
    assert_eq!(
        service
            .requests
            .iter()
            .filter(|request| {
                matches!(
                    request.start_mode(),
                    AttemptStartMode::SavepointCapture { request, .. }
                        if request == unavailable_capture
                )
            })
            .count(),
        2
    );
    assert_eq!(
        service
            .requests
            .iter()
            .filter(|request| request.start_mode() == AttemptStartMode::Execute)
            .count(),
        1
    );
}

#[test]
fn capture_scan_rechecks_lower_keys_inserted_while_finishing_an_old_suffix() {
    const CAMPAIGN: &str = "savepoint-driver-head-advance";

    let (repository, lineage, policy) = fixture();
    let running = running_campaign(&repository, &lineage, &policy, CAMPAIGN, 1);
    let attempt = capture_attempt(&repository, &lineage, StopCondition::Terminal);
    let (initial_request, _) = (0_u64..10_000)
        .find_map(|nonce| {
            let command = CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                format!("savepoint-driver-head-advance-initial-{nonce}").as_bytes(),
            ));
            let request = SavepointCaptureRequest::new(
                command,
                running.snapshot_id(),
                attempt,
                lineage.genesis_content(),
                lineage.genesis(),
                StopCondition::Terminal,
                "initial capture",
            )
            .expect("initial capture candidate");
            let id = CampaignFact::SavepointCaptureRequested(request.clone())
                .id()
                .expect("initial capture fact ID");
            let request_key = savepoint_capture_request_key(id);
            let command_key = map_key_hash("accounting.command", command.as_hash());
            (request_key < command_key).then_some((request, id))
        })
        .expect("find initial capture with an accounting suffix");
    let initial = repository
        .request_savepoint_capture(CAMPAIGN, &initial_request)
        .expect("accept initial capture");
    let capture_execution = ExecutionId::from_bytes([0xf1; 16]).expect("capture execution");
    let checkpoint = exact_checkpoint("savepoint-driver-head-advance-ready");
    let repository = Arc::new(repository);
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(PausingCaptureExecutor {
            requests: Vec::new(),
            status_requests: Vec::new(),
            resume_requests: Vec::new(),
            execution: capture_execution,
            checkpoint,
            cancellation_requested: false,
            checkpoint_requests: Vec::new(),
            cancel_requests: Vec::new(),
        }),
        DaemonEpoch::from_bytes([0xf3; 16]).expect("daemon epoch"),
        2,
        resources(),
        ExecutionRetentionIntent::Discard,
        1,
    )
    .expect("head-advance capture driver");

    let mut submitted_initial = false;
    for _ in 0..64 {
        match driver
            .step(CAMPAIGN, WorkerSlotId::new(0))
            .expect("scan initial capture")
        {
            CampaignExecutorStepOutcome::CaptureRunning {
                request,
                newly_accepted: true,
                ..
            } if request == initial.request => {
                submitted_initial = true;
                break;
            }
            CampaignExecutorStepOutcome::CaptureScanPending { .. }
            | CampaignExecutorStepOutcome::ScanPending { .. }
            | CampaignExecutorStepOutcome::Idle { .. } => continue,
            other => panic!("unexpected initial scan outcome: {other:?}"),
        }
    }
    assert!(submitted_initial, "initial capture page was not reached");
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(1)),
        Ok(CampaignExecutorStepOutcome::CaptureScanPending { .. })
    ));

    let current = repository.head(CAMPAIGN).expect("current capture head");
    let (inserted_request, inserted_id) = (0_u64..10_000)
        .find_map(|nonce| {
            let request = SavepointCaptureRequest::new(
                CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    format!("savepoint-driver-head-advance-inserted-{nonce}").as_bytes(),
                )),
                current.snapshot_id(),
                attempt,
                lineage.genesis_content(),
                lineage.genesis(),
                StopCondition::Terminal,
                "inserted capture",
            )
            .expect("inserted capture candidate");
            let id = CampaignFact::SavepointCaptureRequested(request.clone())
                .id()
                .expect("candidate capture fact ID");
            (savepoint_capture_request_key(id) < savepoint_capture_request_key(initial.request))
                .then_some((request, id))
        })
        .expect("find a lower-key capture request");
    let inserted = repository
        .request_savepoint_capture(CAMPAIGN, &inserted_request)
        .expect("insert lower-key capture under a newer head");
    assert_eq!(inserted.request, inserted_id);

    let mut submitted_inserted = false;
    for _ in 0..128 {
        match driver
            .step(CAMPAIGN, WorkerSlotId::new(1))
            .expect("finish old suffix and rescan new head")
        {
            CampaignExecutorStepOutcome::CaptureRunning {
                request,
                execution,
                newly_accepted: true,
                ..
            } if request == inserted.request && execution == capture_execution => {
                submitted_inserted = true;
                break;
            }
            CampaignExecutorStepOutcome::CaptureScanPending { .. }
            | CampaignExecutorStepOutcome::ScanPending { .. }
            | CampaignExecutorStepOutcome::Idle { .. } => continue,
            other => panic!("unexpected rescan outcome: {other:?}"),
        }
    }
    assert!(
        submitted_inserted,
        "lower-key capture was skipped after head advance"
    );
    assert!(matches!(
        driver.step(CAMPAIGN, WorkerSlotId::new(1)),
        Ok(CampaignExecutorStepOutcome::CaptureResolved {
            ref result,
            checkpoint: Some(actual_checkpoint),
            ..
        }) if result.request == inserted.request && actual_checkpoint == checkpoint
    ));

    let service = driver.into_executor().into_inner();
    assert!(service.requests.iter().any(|request| {
        matches!(
            request.start_mode(),
            AttemptStartMode::SavepointCapture { request, .. }
                if request == inserted.request
        )
    }));
}

fn running_campaign(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
    name: &str,
    attempts: u64,
) -> CampaignHead {
    let created = repository
        .create(name, lineage, policy, &BTreeMap::new())
        .expect("create campaign");
    let funded = repository
        .apply_control(
            name,
            &command(
                &format!("{name}-budget"),
                created.snapshot_id(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, attempts).expect("attempt grant"),
                ),
            ),
        )
        .expect("fund campaign");
    repository
        .apply_control(
            name,
            &command(
                &format!("{name}-resume"),
                funded.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("start campaign");
    repository.head(name).expect("running head")
}

fn capture_request(
    repository: &CampaignRepository,
    command_name: &str,
    head: &CampaignHead,
    lineage: &CampaignLineage,
    stop: StopCondition,
) -> SavepointCaptureRequest {
    SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", command_name.as_bytes())),
        head.snapshot_id(),
        capture_attempt(repository, lineage, stop.clone()),
        lineage.genesis_content(),
        lineage.genesis(),
        stop,
        "operator savepoint",
    )
    .expect("capture request")
}

fn capture_attempt(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    stop: StopCondition,
) -> AttemptId {
    let path = BranchPath::new(Vec::new()).expect("capture path");
    repository
        .put_branch_path(&path)
        .expect("publish capture path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: lineage.genesis_content(),
        },
        path.id().expect("capture path ID"),
        stop,
    )
    .expect("capture attempt");
    repository
        .put_attempt(&attempt)
        .expect("publish capture attempt");
    attempt.id().expect("capture attempt ID")
}

fn scoped_assignment(
    lineage: &CampaignLineage,
    accepted: &SavepointCaptureResult,
    assignment: [u8; 16],
    epoch: [u8; 16],
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new_savepoint_capture(
        AssignmentId::from_bytes(assignment).expect("assignment"),
        DaemonEpoch::from_bytes(epoch).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        accepted.attempt,
        resources(),
        ExecutionRetentionIntent::RetainAlways,
        accepted.request,
        accepted.configuration,
    )
    .expect("scoped capture assignment")
}

fn resources() -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits")
}

fn exact_checkpoint(label: &str) -> ExactCheckpointId {
    ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        label.as_bytes(),
    ))
    .expect("exact checkpoint")
}

fn assert_budget_usage_eq(actual: CampaignBudgetProjection, expected: CampaignBudgetProjection) {
    assert_eq!(actual.granted_proposals, expected.granted_proposals);
    assert_eq!(actual.granted_attempts, expected.granted_attempts);
    assert_eq!(actual.spent_proposals, expected.spent_proposals);
    assert_eq!(actual.spent_attempts, expected.spent_attempts);
}
