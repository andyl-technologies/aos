//! Process and campaign fixtures for the component contract test.

use super::*;

#[derive(Clone)]
pub(super) struct ComponentExecutorService {
    inner: Arc<
        Mutex<
            LocalExecutorCapabilityService<DirectoryAssignmentLedger, RepositoryAttemptAdmission>,
        >,
    >,
    store: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    pub(super) candidate: ObservationCandidate,
}

impl ComponentExecutorService {
    pub(super) fn new(
        paths: &FixturePaths,
        repository: Arc<CampaignRepository>,
        lineage: &CampaignLineage,
        daemon_epoch: DaemonEpoch,
        candidate: ObservationCandidate,
    ) -> Self {
        let capacity = executor_capacity();
        let profile = ExecutorCompatibilityProfile::from_lineage(lineage);
        let supervisor = LocalExecutorSupervisor::new(
            DirectoryAssignmentLedger::open(&paths.ledger_root).expect("open executor ledger"),
            RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
            daemon_epoch,
            capacity,
        );
        let description = executor_description(lineage, profile, daemon_epoch, capacity);
        let service = LocalExecutorCapabilityService::new(supervisor, description)
            .expect("executor capability service");
        Self {
            inner: Arc::new(Mutex::new(service)),
            store: CampaignExecutorStore::new(repository),
            checkpoints: Arc::new(
                ExactCheckpointStore::new(
                    Arc::new(DirectoryBlobBackend::new(
                        "component-contract-exact-checkpoints",
                        paths.root.join("exact-checkpoints"),
                    )),
                    64 * 1024 * 1024,
                )
                .expect("component contract checkpoint store"),
            ),
            candidate,
        }
    }

    pub(super) fn complete_queued_attempt(&self) -> ObservationId {
        let mut service = self.inner.lock().expect("executor service lock");
        let queued = service
            .supervisor_mut()
            .next_queued()
            .expect("semantic execution is queued");
        let semantic = PreparedSemanticAttemptResult::new(self.candidate.clone(), Vec::new(), None)
            .expect("prepare semantic result");
        let work = AttemptWorkResult::<()>::new(
            queued,
            Ok(AttemptExecutionProduct::prepared_semantic(semantic)),
        );
        let prepared = prepare_attempt_result(&self.store, &self.checkpoints, work)
            .expect("preflight semantic result");
        let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
            panic!("component semantic result returned a checkpoint")
        };
        let observation = prepared.observation();
        let staged = stage_prepared_attempt_result(service.supervisor_mut(), *prepared)
            .expect("stage semantic completion");
        let AttemptResultStageOutcome::Publish(staged) = staged else {
            panic!("current semantic result must publish")
        };
        let published = publish_prepared_attempt_result(
            &self.store,
            &RejectUnexpectedFindingCheckpoint,
            staged,
        )
        .expect("publish semantic completion");
        reconcile_published_attempt_result::<_, _, ()>(service.supervisor_mut(), published)
            .expect("reconcile semantic completion");
        observation
    }
}

struct RejectUnexpectedFindingCheckpoint;

impl FindingExactCheckpointAuthenticator for RejectUnexpectedFindingCheckpoint {
    fn authenticate_finding_exact_checkpoint(
        &self,
        _checkpoint: crucible_campaign::ExactCheckpointId,
        _scenario: crucible_campaign::ScenarioDefId,
        _scenario_artifact: crucible_campaign::ScenarioArtifactId,
        _configuration: crucible_campaign::ConfigurationId,
        _maximum_metadata_bytes: u64,
    ) -> Result<
        crucible_campaign::AuthenticatedFindingExactCheckpoint,
        FindingExactCheckpointAuthenticationError,
    > {
        Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        _object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

type ExecutorFailure = LocalExecutorError<AssignmentLedgerError>;

impl ExecutorService for ComponentExecutorService {
    type Error = ExecutorFailure;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        ExecutorService::submit_attempt(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorStatusService for ComponentExecutorService {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        ExecutorStatusService::get_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorControlService for ComponentExecutorService {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &crucible_campaign::CheckpointAttemptExecutionRequest,
    ) -> Result<crucible_campaign::CheckpointAttemptExecutionResponse, Self::Error> {
        ExecutorControlService::checkpoint_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &crucible_campaign::CancelAttemptExecutionRequest,
    ) -> Result<crucible_campaign::CancelAttemptExecutionResponse, Self::Error> {
        ExecutorControlService::cancel_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorResumeService for ComponentExecutorService {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ExecutorResumeService::resume_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorCapabilityService for ComponentExecutorService {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        ExecutorCapabilityService::describe_executor(
            &mut *self.inner.lock().expect("executor service lock"),
        )
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        ExecutorCapabilityService::watch_capacity(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

pub(super) struct AllowAllCampaignAccess;

impl CampaignPrincipalAuthorizer for AllowAllCampaignAccess {
    fn authorize_all_campaigns(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }

    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

pub(super) struct CampaignFixture {
    pub(super) lineage: CampaignLineage,
    pub(super) create_request: CreateCampaignRequest,
    pub(super) admitted_snapshot: crucible_campaign::CampaignSnapshotId,
    pub(super) attempt: AttemptId,
    pub(super) branch_point: BranchPointId,
    pub(super) candidate: ObservationCandidate,
}

pub(super) fn create_direct_campaign_fixture(paths: &FixturePaths) -> CampaignFixture {
    let repository = Arc::new(repository(paths));
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = crucible::Schedule::empty();
    let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let scenario_id = artifacts
        .import_scenario(&scenario)
        .expect("import scenario");
    let configuration_id = artifacts
        .import_configuration(&scenario, &schedule)
        .expect("import configuration");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("stored scenario");
    let stored_configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("stored configuration");
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        scenario_id,
        stored_configuration.configuration(),
        configuration_id,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        stored_scenario.payload_schema(),
        stored_configuration.payload_schema(),
    )
    .expect("lineage");
    let create_request = CreateCampaignRequest::new(
        principal(),
        campaign_name(),
        lineage.clone(),
        creation_policy(lineage.scenario()),
    )
    .expect("create request");
    let direct = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        AllowAllCampaignAccess,
    ));
    let created = direct
        .create_campaign(&create_request)
        .expect("direct campaign creation");
    assert!(!created.replayed());
    let direct_replay = direct
        .create_campaign(&create_request)
        .expect("direct campaign creation replay");
    assert!(direct_replay.replayed());
    assert_eq!(direct_replay.snapshot(), created.snapshot());

    let budget_request = ApplyCampaignCommandRequest::new(
        principal(),
        campaign_name(),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("budget")),
            expected_snapshot: created.snapshot(),
            action: CampaignControlAction::GrantBudget(
                BudgetGrant::new(2, 2).expect("campaign budget"),
            ),
        },
    )
    .expect("budget request");
    let budgeted = direct
        .apply_campaign_command(&budget_request)
        .expect("direct budget grant");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.component-contract",
        ChoiceSource::Workload {
            producer: String::from("component-contract"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("component-contract")]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "component-contract",
        None,
    )
    .expect("choice opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish choice opportunity");
    let opportunity_id = opportunity.id().expect("choice opportunity ID");
    let discovered = repository
        .discover_operator_choice_opportunity(
            CAMPAIGN_NAME,
            budgeted.new_snapshot(),
            lineage.genesis_content(),
            opportunity_id,
        )
        .expect("discover operator choice");
    let branch_request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            opportunity_id,
            domain.id().expect("choice domain ID"),
        ),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite candidate source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("branch"))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request");
    let requested = repository
        .submit_operator_branch_request(CAMPAIGN_NAME, discovered.new_snapshot, &branch_request)
        .expect("submit branch request");
    let request_head = repository.head(CAMPAIGN_NAME).expect("branch request head");
    let policy = creation_policy(lineage.scenario());
    let proposal = Proposal::new(
        branch_request.branch_point(),
        branch_request.id().expect("branch request ID"),
        branch_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy ID"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view ID"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(CAMPAIGN_NAME, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        branch_request.branch_point(),
    )
    .expect("campaign branch selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection origin")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(
        branch_request.branch_point(),
        edge,
    )])
    .expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: branch_request.parent(),
            selection: selection.id().expect("selection ID"),
        },
        path.id().expect("path ID"),
        branch_request.stop().clone(),
    )
    .expect("attempt");
    let admitted = repository
        .admit_proposal(
            CAMPAIGN_NAME,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal");
    let candidate = observation_candidate(
        repository.as_ref(),
        &lineage,
        admitted.attempt,
        opportunity_id,
    );

    fs::write(
        &paths.lineage_id,
        lineage.id().expect("lineage ID").to_string(),
    )
    .expect("write lineage ID");
    fs::write(&paths.attempt_id, admitted.attempt.to_string()).expect("write attempt ID");
    fs::write(&paths.opportunity_id, opportunity_id.to_string()).expect("write opportunity ID");

    CampaignFixture {
        lineage,
        create_request,
        admitted_snapshot: admitted.new_snapshot,
        attempt: admitted.attempt,
        branch_point: branch_request.branch_point(),
        candidate,
    }
}

pub(super) fn observation_candidate(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    attempt_id: AttemptId,
    opportunity_id: ChoiceOpportunityId,
) -> ObservationCandidate {
    let attempt = repository.load_attempt(attempt_id).expect("load attempt");
    let opportunity = repository
        .load_choice_opportunity(opportunity_id)
        .expect("load choice opportunity");
    let declaration = repository
        .load_selectable(opportunity.declaration())
        .expect("load selectable declaration");
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .expect("load choice domain");
    let AttemptStart::Branch { selection, .. } = attempt.start() else {
        panic!("component-contract branch attempt")
    };
    let resolved_selection = repository
        .resolve_selection(selection)
        .expect("resolve branch selection");
    let schedule = crucible::Schedule::from_decisions([crucible::Decision::Selection(
        crucible::SelectionDecision::new(resolved_selection.selection()),
    )]);
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .expect("load scenario artifact");
    let child_artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("encode child configuration artifact");
    let child = child_artifact.configuration();
    let measurements = MeasurementSet::from_evaluation(
        CampaignHash::derive(
            "crucible.test.component-contract.measurements.v1",
            b"definitions",
        ),
        1,
        CampaignHash::derive(
            "crucible.test.component-contract.evaluation.v1",
            b"evaluation",
        ),
        b"empty evaluation".to_vec(),
        BTreeSet::new(),
    )
    .expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("property verdicts");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        attempt_id,
        Observation::outcome(
            child,
            child_artifact.id().expect("child artifact ID"),
            attempt.path(),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement ID"),
            properties.id().expect("property verdict ID"),
            coverage.id().expect("coverage ID"),
        ),
        BTreeSet::from([opportunity_id]),
    )
    .expect("observation");
    ObservationCandidate::new(
        child_artifact,
        measurements,
        properties,
        coverage,
        vec![ChoiceDiscovery::new(declaration, domain, opportunity).expect("choice discovery")],
        observation,
    )
    .expect("observation candidate")
}

pub(super) fn direct_submit_pair(
    paths: &FixturePaths,
    lineage: &CampaignLineage,
    request: &SubmitAttemptRequest,
) -> (SubmitAttemptResponse, SubmitAttemptResponse) {
    let capacity = executor_capacity();
    let repository = Arc::new(repository(paths));
    let profile = ExecutorCompatibilityProfile::from_lineage(lineage);
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        RepositoryAttemptAdmission::new(repository, profile.clone()),
        request.daemon_epoch(),
        capacity,
    );
    let description = executor_description(lineage, profile, request.daemon_epoch(), capacity);
    let service =
        LocalExecutorCapabilityService::new(supervisor, description).expect("direct executor");
    let mut client = ExecutorClient::new(service);
    let submitted = client.submit_attempt(request).expect("direct submit");
    let replayed = client
        .submit_attempt(request)
        .expect("direct submit replay");
    (submitted, replayed)
}

pub(super) fn executor_description(
    lineage: &CampaignLineage,
    profile: ExecutorCompatibilityProfile,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
) -> ExecutorDescription {
    let capabilities = crucible_campaign::ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        capacity.maximum_concurrent_executions(),
        executor_resource_ceiling(),
        BTreeSet::from([hash("store-namespace")]),
    )
    .expect("executor capabilities");
    let description =
        ExecutorDescription::new(daemon_epoch, capabilities).expect("executor description");
    assert_eq!(
        description.capabilities().compatibility(),
        &ExecutorCompatibilityProfile::from_lineage(lineage)
    );
    description
}

pub(super) struct FixturePaths {
    pub(super) root: PathBuf,
    pub(super) blobs: PathBuf,
    pub(super) refs: PathBuf,
    pub(super) ledger_root: PathBuf,
    pub(super) coordinator_socket: PathBuf,
    pub(super) executor_socket: PathBuf,
    pub(super) lineage_id: PathBuf,
    pub(super) attempt_id: PathBuf,
    pub(super) opportunity_id: PathBuf,
}

impl FixturePaths {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            blobs: root.join("blobs"),
            refs: root.join("refs"),
            ledger_root: root.join("ledger"),
            coordinator_socket: root.join("coordinator.sock"),
            executor_socket: root.join("executor.sock"),
            lineage_id: root.join("lineage-id"),
            attempt_id: root.join("attempt-id"),
            opportunity_id: root.join("opportunity-id"),
        }
    }

    pub(super) fn from_environment() -> Self {
        Self::new(Path::new(&required_environment("CRUCIBLE_COMPONENT_ROOT")))
    }
}

pub(super) struct ProcessGuard {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    output: Receiver<String>,
    reader: Option<JoinHandle<()>>,
    socket: PathBuf,
}

impl ProcessGuard {
    pub(super) fn spawn(
        helper: &str,
        paths: &FixturePaths,
        daemon_epoch: Option<DaemonEpoch>,
    ) -> Self {
        let socket = if helper == COORDINATOR_HELPER {
            paths.coordinator_socket.clone()
        } else {
            paths.executor_socket.clone()
        };
        remove_stale_socket(&socket);

        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--ignored")
            .arg("--exact")
            .arg(helper)
            .arg("--nocapture")
            .env("CRUCIBLE_COMPONENT_ROOT", &paths.root)
            .env(
                "CRUCIBLE_COMPONENT_LINEAGE",
                fs::read_to_string(&paths.lineage_id).expect("read lineage ID"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(daemon_epoch) = daemon_epoch {
            command.env(
                "CRUCIBLE_COMPONENT_EPOCH",
                encode_hex(&daemon_epoch.as_bytes()),
            );
        }
        let mut child = command.spawn().expect("spawn component process");
        let stdin = child.stdin.take().expect("component control input");
        let stdout = child.stdout.take().expect("component protocol output");
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut guard = Self {
            child: Some(child),
            stdin: Some(stdin),
            output,
            reader: Some(reader),
            socket,
        };
        assert_eq!(guard.read_protocol_reply(), "READY");
        guard
    }

    pub(super) fn command(&mut self, command: &str) -> String {
        let stdin = self.stdin.as_mut().expect("live component input");
        writeln!(stdin, "{command}").expect("write component command");
        stdin.flush().expect("flush component command");
        self.read_protocol_reply()
    }

    pub(super) fn read_protocol_reply(&mut self) -> String {
        let deadline = Instant::now() + PROCESS_RESPONSE_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(remaining) {
                Ok(line) if is_protocol_reply(&line) => return line,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().expect("inspect component process"));
                    panic!("component protocol response timed out; status={status:?}");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().expect("inspect component process"));
                    panic!("component protocol closed before response; status={status:?}");
                }
            }
        }
    }

    pub(super) fn kill_and_wait(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child
                .try_wait()
                .expect("inspect component before cleanup")
                .is_none()
            {
                child.kill().expect("kill component process");
            }
            child.wait().expect("wait for component process");
            remove_stale_socket(&self.socket);
        }
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join component output reader");
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

pub(super) fn is_protocol_reply(line: &str) -> bool {
    line == "READY" || line == "INCORPORATED" || line == "IDLE" || line.starts_with("COMPLETED ")
}

pub(super) fn protocol_reply(reply: &str) {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{reply}").expect("write process protocol reply");
    stdout.flush().expect("flush process protocol reply");
}

pub(super) fn repository(paths: &FixturePaths) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "component-contract",
            &paths.blobs,
        )),
        Arc::new(DirectoryRefBackend::new(&paths.refs)),
    )
}

pub(super) fn coordinator_client(paths: &FixturePaths) -> CampaignClient<LoopbackCampaignService> {
    let stream = UnixStream::connect(&paths.coordinator_socket).expect("connect coordinator");
    CampaignClient::new(LoopbackCampaignService::new(stream).expect("coordinator client"))
}

pub(super) fn executor_client(paths: &FixturePaths) -> ExecutorClient<LoopbackExecutorService> {
    let stream = UnixStream::connect(&paths.executor_socket).expect("connect executor");
    ExecutorClient::new(LoopbackExecutorService::new(stream).expect("executor client"))
}

pub(super) fn assignment(
    lineage: CampaignLineageId,
    attempt: AttemptId,
    daemon_epoch: DaemonEpoch,
    assignment_byte: u8,
    retention_basis: AttemptRetentionPolicyBasis,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment ID"),
        daemon_epoch,
        lineage,
        attempt,
        executor_resources(),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
    )
    .expect("assignment request")
}

pub(super) fn executor_resources() -> AttemptResourceLimits {
    AttemptResourceLimits::new(1, 1024, 2048, 32).expect("executor resources")
}

pub(super) fn executor_resource_ceiling() -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 2048, 4096, 64).expect("executor resource ceiling")
}

pub(super) fn executor_capacity() -> ExecutorCapacity {
    ExecutorCapacity::new(2, 2, 2048, 4096, 64).expect("executor capacity")
}

pub(super) fn accepted_execution(response: &SubmitAttemptResponse) -> ExecutionId {
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment was not accepted: {:?}", response.disposition())
    };
    execution
}

pub(super) fn creation_policy(scenario: crucible_campaign::ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening constant"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy")
}

pub(super) fn campaign_name() -> CampaignName {
    CampaignName::new(CAMPAIGN_NAME).expect("campaign name")
}

pub(super) fn principal() -> CampaignPrincipal {
    CampaignPrincipal::new("operator:component-contract").expect("campaign principal")
}

pub(super) fn epoch(byte: u8) -> DaemonEpoch {
    DaemonEpoch::from_bytes([byte; 16]).expect("daemon epoch")
}

pub(super) fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive(
        "crucible.test.component-contract-process.v1",
        label.as_bytes(),
    )
}

pub(super) fn required_attempt(paths: &FixturePaths) -> AttemptId {
    AttemptId::parse(&fs::read_to_string(&paths.attempt_id).expect("read attempt ID"))
        .expect("attempt ID")
}

pub(super) fn required_opportunity(paths: &FixturePaths) -> ChoiceOpportunityId {
    ChoiceOpportunityId::parse(
        &fs::read_to_string(&paths.opportunity_id).expect("read opportunity ID"),
    )
    .expect("choice opportunity ID")
}

pub(super) fn required_epoch() -> DaemonEpoch {
    DaemonEpoch::from_bytes(
        decode_hex_16(&required_environment("CRUCIBLE_COMPONENT_EPOCH"))
            .expect("executor epoch bytes"),
    )
    .expect("executor epoch")
}

pub(super) fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

pub(super) fn remove_stale_socket(socket: &Path) {
    match fs::remove_file(socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale socket {}: {error}", socket.display()),
    }
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn decode_hex_16(value: &str) -> Result<[u8; 16], ()> {
    if value.len() != 32 {
        return Err(());
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| ())?;
    }
    Ok(output)
}
