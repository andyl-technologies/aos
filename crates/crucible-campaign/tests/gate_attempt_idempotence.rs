//! Attempt admission, execution, publication, and credit idempotence matrix.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- conformance fixtures fail at the violated invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use crucible_campaign::{
    AssignmentId, Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchBudget,
    BranchPath, BranchPathSegment, BranchRequest, BranchRequestCause, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode, CampaignPolicy,
    CampaignRepository, CampaignRepositoryError, CampaignSeed, CandidateSource, ChoiceClassContext,
    ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoicePolicy, ChoiceSource, ChoiceValue,
    ConfigurationId, ControlRequest, CoverageProjection, DaemonEpoch, ExecutionId,
    ExecutionRetentionIntent, ExecutorClient, ExecutorRejection, ExecutorService, ExplorerPolicy,
    FairnessPolicy, MeasurementSeries, MeasurementSet, MetricValue, Observation,
    ObservationDisposition, ProgressiveWideningPolicy, PropertyEvidence, PropertyVerdict,
    PropertyVerdictSet, Proposal, PuctPolicy, RetentionPolicy, ScenarioDefId,
    SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse,
};
use crucible_cas::content_store::{
    ContentId, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend, RefCasOutcome, RefName,
    RefPublicationGuard, RefScanPage, StoreError,
};

const CAMPAIGN: &str = "attempt-idempotence";

struct ConflictOnceRefBackend {
    inner: MemoryRefBackend,
    conflict_next_update: Mutex<bool>,
}

impl ConflictOnceRefBackend {
    fn new() -> Self {
        Self {
            inner: MemoryRefBackend::new(),
            conflict_next_update: Mutex::new(false),
        }
    }

    fn arm(&self) {
        *self.conflict_next_update.lock().expect("conflict flag") = true;
    }
}

impl MutableRefBackend for ConflictOnceRefBackend {
    fn capabilities(&self) -> crucible_cas::content_store::RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let mut conflict = self
            .conflict_next_update
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "attempt-idempotence-conflict-flag",
            })?;
        if expected.is_some() && *conflict {
            *conflict = false;
            return Ok(RefCasOutcome::Conflict {
                expected,
                current: self.inner.read_ref(name)?,
            });
        }
        self.inner.compare_exchange(name, expected, next)
    }
}

#[derive(Default)]
struct ExactExecutorLedger {
    accepted: Option<(
        AssignmentId,
        crucible_campaign::CampaignHash,
        crucible_campaign::CampaignHash,
        SubmitAttemptResponse,
    )>,
}

impl ExecutorService for ExactExecutorLedger {
    type Error = Infallible;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        let basis = request.execution_basis_digest();
        let disposition = match &self.accepted {
            None => {
                let execution = ExecutionId::from_bytes([0x51; 16]).expect("execution id");
                let response = SubmitAttemptResponse::new(
                    request,
                    SubmitAttemptDisposition::Accepted { execution },
                )
                .expect("acceptance response");
                self.accepted = Some((
                    request.assignment(),
                    request.request_digest(),
                    basis,
                    response.clone(),
                ));
                return Ok(response);
            }
            Some((assignment, digest, _, response)) if *assignment == request.assignment() => {
                if *digest == request.request_digest() {
                    return Ok(response.clone());
                }
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::ConflictingAssignment,
                }
            }
            Some((_, _, accepted_basis, response)) if *accepted_basis == basis => {
                let SubmitAttemptDisposition::Accepted { execution } = response.disposition()
                else {
                    unreachable!("ledger stores only acceptance")
                };
                SubmitAttemptDisposition::AlreadyRunning { execution }
            }
            Some(_) => SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Incompatible,
            },
        };

        Ok(SubmitAttemptResponse::new(request, disposition).expect("ledger response"))
    }
}

#[test]
fn public_repository_and_executor_seams_cover_the_idempotence_matrix() {
    let (repository, blobs, refs, lineage, policy) = fixture();
    let (admission_prior, request, proposal, selection, path, attempt, admitted) =
        admit_attempt(&repository, &lineage, &policy);
    let budget_after_admission = repository
        .budget_projection(CAMPAIGN)
        .expect("budget after admission");

    // Retry before acceptance acknowledgement: replay wins over stale-head
    // rejection and cannot spend proposal or attempt budget twice.
    let admission_replay = repository
        .admit_proposal(
            CAMPAIGN,
            admission_prior,
            proposal.id().expect("proposal id"),
            &selection,
            &path,
            &attempt,
        )
        .expect("admission replay");
    assert!(admission_replay.replayed);
    assert_eq!(admission_replay.new_snapshot, admitted.new_snapshot);
    assert_eq!(
        repository
            .budget_projection(CAMPAIGN)
            .expect("budget after admission replay"),
        budget_after_admission
    );

    // Daemon death after admission and before result publication rebuilds from
    // repository truth. The executor independently deduplicates an exact retry
    // during execution and rejects a conflicting execution basis.
    drop(repository);
    let before_publication = CampaignRepository::new(blobs.clone(), refs.clone());
    let resources =
        AttemptResourceLimits::new(1, 256 * 1024 * 1024, 0, 10_000).expect("resource limits");
    let first_assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x41; 16]).expect("first assignment"),
        DaemonEpoch::from_bytes([0x42; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage id"),
        admitted.attempt,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("first assignment request");
    before_publication
        .validate_executor_request(&first_assignment)
        .expect("repository validates assignment");
    let mut executor = ExecutorClient::new(ExactExecutorLedger::default());
    let accepted = executor
        .submit_attempt(&first_assignment)
        .expect("first execution acceptance");
    let SubmitAttemptDisposition::Accepted { execution } = accepted.disposition() else {
        panic!("first assignment was not accepted")
    };
    assert_eq!(
        executor
            .submit_attempt(&first_assignment)
            .expect("exact assignment replay"),
        accepted
    );
    let same_basis_assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x43; 16]).expect("retry assignment"),
        first_assignment.daemon_epoch(),
        first_assignment.lineage(),
        first_assignment.attempt(),
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("retry assignment request");
    let during_execution = executor
        .submit_attempt(&same_basis_assignment)
        .expect("retry during execution");
    assert_eq!(
        during_execution.disposition(),
        SubmitAttemptDisposition::AlreadyRunning { execution }
    );
    let conflicting_assignment = SubmitAttemptRequest::new(
        first_assignment.assignment(),
        first_assignment.daemon_epoch(),
        first_assignment.lineage(),
        first_assignment.attempt(),
        AttemptResourceLimits::new(2, 256 * 1024 * 1024, 0, 10_000).expect("conflicting limits"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("conflicting assignment request");
    assert_eq!(
        executor
            .submit_attempt(&conflicting_assignment)
            .expect("conflicting execution response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::ConflictingAssignment,
        }
    );

    let observation = build_observation(
        &before_publication,
        &lineage,
        &request,
        &path,
        admitted.attempt,
        7,
    );

    // Daemon death after immutable result objects are placed but before the
    // ref CAS leaves the admitted snapshot authoritative. A new coordinator
    // can publish the exact same result without rerunning the executor.
    refs.arm();
    assert!(matches!(
        before_publication.publish_observation(CAMPAIGN, admitted.new_snapshot, &observation),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    drop(before_publication);
    let publication_recovery = CampaignRepository::new(blobs.clone(), refs.clone());
    let published = publication_recovery
        .publish_observation(CAMPAIGN, admitted.new_snapshot, &observation)
        .expect("publish after pre-CAS death");
    assert_eq!(published.disposition, ObservationDisposition::Canonical);
    assert!(!published.replayed);
    let credited = publication_recovery
        .project_branch_edge_visits(published.new_snapshot, request.branch_point())
        .expect("canonical visit credit");
    assert_eq!(credited.parent_visits(), 1);
    assert_eq!(credited.edge_visits().values().copied().sum::<u64>(), 1);

    // Daemon death after the ref CAS but before acknowledgement replays the
    // canonical publication, produces an equal completion, and adds no credit.
    drop(publication_recovery);
    let after_publication = CampaignRepository::new(blobs.clone(), refs.clone());
    let equal = after_publication
        .publish_observation(CAMPAIGN, admitted.new_snapshot, &observation)
        .expect("retry after publication");
    assert!(equal.replayed);
    assert_eq!(equal.new_snapshot, published.new_snapshot);
    assert_eq!(
        after_publication
            .project_branch_edge_visits(equal.new_snapshot, request.branch_point())
            .expect("credit after equal replay"),
        credited
    );
    let equal_completion = SubmitAttemptResponse::new(
        &first_assignment,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observation.id().expect("observation id"),
        },
    )
    .expect("equal completion response");
    after_publication
        .validate_executor_response(&first_assignment, &equal_completion)
        .expect("equal completion validates");

    // A different result for the same attempt is retained as a determinism
    // conflict. It cannot replace the canonical result or receive a second
    // branch-expansion credit, and exact conflict retry remains idempotent.
    let conflict = build_observation(
        &after_publication,
        &lineage,
        &request,
        &path,
        admitted.attempt,
        8,
    );
    let conflicted = after_publication
        .publish_observation(CAMPAIGN, published.new_snapshot, &conflict)
        .expect("retain conflicting completion");
    assert_eq!(
        conflicted.disposition,
        ObservationDisposition::DeterminismConflict {
            canonical: observation.id().expect("canonical observation id"),
        }
    );
    assert_eq!(
        after_publication
            .project_branch_edge_visits(conflicted.new_snapshot, request.branch_point())
            .expect("credit after conflict"),
        credited
    );
    let conflict_replay = after_publication
        .publish_observation(CAMPAIGN, admitted.new_snapshot, &conflict)
        .expect("conflicting completion replay");
    assert!(conflict_replay.replayed);
    assert_eq!(conflict_replay.new_snapshot, conflicted.new_snapshot);
    let conflicting_completion = SubmitAttemptResponse::new(
        &first_assignment,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: conflict.id().expect("conflicting observation id"),
        },
    )
    .expect("conflicting completion response");
    after_publication
        .validate_executor_response(&first_assignment, &conflicting_completion)
        .expect("retained conflicting completion validates as exact attempt evidence");
}

fn fixture() -> (
    CampaignRepository,
    Arc<MemoryBlobBackend>,
    Arc<ConflictOnceRefBackend>,
    CampaignLineage,
    CampaignPolicy,
) {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("gate", b"idempotence-scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("gate", b"idempotence-genesis"));
    let blobs = Arc::new(MemoryBlobBackend::new(
        "attempt-idempotence",
        128 * 1024 * 1024,
    ));
    let refs = Arc::new(ConflictOnceRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("rational"),
        crucible_campaign::ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::<String, ChoicePolicy>::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");

    (repository, blobs, refs, lineage, policy)
}

#[allow(clippy::type_complexity)]
fn admit_attempt(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
) -> (
    crucible_campaign::CampaignSnapshotId,
    BranchRequest,
    Proposal,
    Selection,
    BranchPath,
    Attempt,
    crucible_campaign::AttemptAdmissionResult,
) {
    let genesis = repository
        .create(CAMPAIGN, lineage, policy, &BTreeMap::new())
        .expect("create campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "gate.attempt-idempotence",
                    b"fund",
                )),
                expected_snapshot: genesis.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    crucible_campaign::BudgetGrant::new(2, 2).expect("grant"),
                ),
            },
        )
        .expect("fund campaign");
    let (request, opportunity, domain) = branch_request(repository, lineage);
    let discovered = repository
        .discover_choice_opportunity(
            CAMPAIGN,
            funded.new_snapshot,
            lineage.genesis_content(),
            opportunity.id().expect("opportunity id"),
        )
        .expect("discover choice");
    let requested = repository
        .submit_branch_request(CAMPAIGN, discovered.new_snapshot, &request)
        .expect("submit request");
    let request_head = repository.head(CAMPAIGN).expect("request head");
    let proposal = Proposal::new(
        request.branch_point(),
        request.id().expect("request id"),
        request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(CAMPAIGN, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )
    .expect("selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])
        .expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id().expect("selection id"),
        },
        path.id().expect("path id"),
        request.stop().clone(),
    )
    .expect("attempt");
    let admission_prior = proposed.new_snapshot;
    let admitted = repository
        .admit_proposal(
            CAMPAIGN,
            admission_prior,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit attempt");

    (
        admission_prior,
        request,
        proposal,
        selection,
        path,
        attempt,
        admitted,
    )
}

fn branch_request(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
) -> (BranchRequest, ChoiceOpportunity, ChoiceDomain) {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: "network-product".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("gate", b"attempt-idempotence"),
            producer: CampaignHash::derive("gate", b"network-product"),
        },
        "attempt-idempotence",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "gate.attempt-idempotence",
            b"request",
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request");

    (request, opportunity, domain)
}

fn build_observation(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    request: &BranchRequest,
    path: &BranchPath,
    attempt: crucible_campaign::AttemptId,
    latency: u64,
) -> Observation {
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "gate.attempt-idempotence.child",
        &latency.to_be_bytes(),
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            format!("child:{latency}").into_bytes(),
        )
        .expect("child artifact");
    let measurements = MeasurementSet::new(BTreeMap::from([(
        "latency".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(latency)],
            MetricValue::Unsigned(latency),
            BTreeSet::new(),
        )
        .expect("measurement series"),
    )]))
    .expect("measurement set");
    let measurements = repository
        .publish_measurement_set(&measurements)
        .expect("publish measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        "network-recovers".to_owned(),
        PropertyEvidence::new(PropertyVerdict::Passed, BTreeSet::new()).expect("property evidence"),
    )]))
    .expect("property verdict set");
    let properties = repository
        .publish_property_verdict_set(&properties)
        .expect("publish properties");
    let coverage = CoverageProjection::new(
        BTreeSet::from([CampaignHash::derive(
            "gate.attempt-idempotence.coverage",
            b"canonical-credit",
        )]),
        BTreeSet::new(),
    )
    .expect("coverage projection");
    let coverage = repository
        .publish_coverage_projection(&coverage)
        .expect("publish coverage");

    Observation::new(
        attempt,
        child,
        child_content,
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([request.opportunity()]),
    )
    .expect("observation")
}
