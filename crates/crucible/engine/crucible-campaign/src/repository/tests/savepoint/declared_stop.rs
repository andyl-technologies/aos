//! Public exact-stop capture and selection through authenticated repository fixtures.

use super::*;
use crate::{
    BoundedStopProof, CampaignAttemptOrigin, CampaignAttemptPhase, CampaignAttemptRuntime,
    CampaignOperationalStatus, CampaignOperationalStatusProvider, CampaignSavepointAction,
    CampaignSavepointRequest, CampaignSavepointResult, CampaignService,
    PUBLIC_EXACT_CAPTURE_REASON, RepositoryCampaignServiceError,
};

const CAMPAIGN: &str = "public-declared-stop";

fn named_stop() -> StopCondition {
    StopCondition::bounded(
        StopCondition::NamedBoundary("selected-marker".to_owned()),
        Some(1_000),
        Some(10),
    )
    .expect("bounded named stop")
}

fn reached_named_stop() -> StopOutcome {
    StopOutcome::BoundedPrimaryReached {
        stop: named_stop(),
        proof: BoundedStopProof::new(900, 9),
    }
}

fn completed_source(outcome: StopOutcome) -> (CampaignRepository, CampaignLineage, AttemptId) {
    let (repository, lineage, policy) = fixture();
    let policy = policy
        .with_attempt_timeout_policy(
            crate::CampaignAttemptTimeoutPolicy::new(Some(1_000), Some(10), None)
                .expect("source deadline"),
        )
        .expect("bounded source policy");
    let (_, admitted, observation) = admitted_observation_fixture_with_stop(
        &repository,
        &lineage,
        &policy,
        CAMPAIGN,
        named_stop(),
        outcome,
        false,
    );
    repository
        .publish_observation(CAMPAIGN, admitted.new_snapshot, &observation)
        .expect("authenticate and credit the completed source");
    let current = repository.head(CAMPAIGN).expect("observed head");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                "public-source-resume",
                current.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("run source campaign for capture");
    (repository, lineage, admitted.attempt)
}

fn public_request(
    snapshot: CampaignSnapshotId,
    action: CampaignSavepointAction,
) -> CampaignSavepointRequest {
    CampaignSavepointRequest::new(
        CampaignPrincipal::new("operator").expect("principal"),
        CampaignName::new(CAMPAIGN).expect("campaign"),
        snapshot,
        action,
    )
    .expect("public savepoint request")
}

fn capture_action(attempt: AttemptId) -> CampaignSavepointAction {
    CampaignSavepointAction::Capture {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"public-capture")),
        attempt,
    }
}

fn exact_capture(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    attempt: AttemptId,
) -> SavepointCaptureResult {
    let request = SavepointCaptureRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive("test", b"lower-exact-capture")),
        repository
            .head(CAMPAIGN)
            .expect("capture head")
            .snapshot_id(),
        attempt,
        lineage.genesis_content(),
        lineage.genesis(),
        named_stop(),
        PUBLIC_EXACT_CAPTURE_REASON,
    )
    .expect("original source-stop capture");
    repository
        .request_savepoint_capture(CAMPAIGN, &request)
        .expect("lower exact-stop contract")
}

// The runtime provider models a daemon certificate only for the exact Ready
// resolution produced below; repository admission and resolution are real.
struct PausedCapture {
    snapshot: CampaignSnapshotId,
    request: CampaignFactId,
    attempt: AttemptId,
    runtime: CampaignAttemptRuntime,
}

impl CampaignOperationalStatusProvider for PausedCapture {
    fn operational_status(
        &self,
        _campaign: &CampaignName,
        _snapshot: CampaignSnapshotId,
    ) -> CampaignOperationalStatus {
        CampaignOperationalStatus::Unavailable
    }

    fn capture_runtime(
        &self,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
        request: CampaignFactId,
        attempt: AttemptId,
    ) -> Option<CampaignAttemptRuntime> {
        (campaign.as_str() == CAMPAIGN
            && snapshot == self.snapshot
            && request == self.request
            && attempt == self.attempt)
            .then_some(self.runtime)
    }
}

fn resolve_capture(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    capture: &SavepointCaptureResult,
) -> PausedCapture {
    let assignment = scoped_assignment(lineage, capture, [0xa1; 16], [0xa2; 16]);
    let execution = ExecutionId::from_bytes([0xa3; 16]).expect("capture execution");
    let checkpoint = exact_checkpoint("public-named-stop-root");
    let query = GetAttemptExecutionRequest::new(&assignment, execution).expect("status query");
    let status = GetAttemptExecutionResponse::new(
        &query,
        GetAttemptExecutionDisposition::Paused { checkpoint },
    )
    .expect("request-bound paused certificate");
    let resolution = SavepointCaptureResolution {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"public-ready")),
        expected_snapshot: capture.new_snapshot,
        request: capture.request,
        outcome: SavepointCaptureOutcome::Ready,
    };
    let resolved = repository
        .resolve_savepoint_capture(CAMPAIGN, &resolution, &assignment, &status)
        .expect("authenticate Ready resolution");
    PausedCapture {
        snapshot: resolved.new_snapshot,
        request: capture.request,
        attempt: capture.attempt,
        runtime: CampaignAttemptRuntime::new(
            CampaignAttemptPhase::Paused,
            CampaignAttemptOrigin::Initial,
            execution,
            Some(checkpoint),
            None,
            None,
        )
        .expect("exact paused root"),
    }
}

fn selection_action(request: CampaignFactId) -> CampaignSavepointAction {
    CampaignSavepointAction::Select {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"public-select")),
        request,
        stop: StopCondition::ExecutionQuanta(20),
    }
}

#[test]
fn public_capture_preserves_the_completed_named_stop_and_exact_restore_identity() {
    let (repository, lineage, attempt) = completed_source(reached_named_stop());
    let head = repository.head(CAMPAIGN).expect("completed source head");
    let request = public_request(head.snapshot_id(), capture_action(attempt));
    let response = RepositoryCampaignService::new(&repository, AllowCampaignQueries)
        .campaign_savepoint(&request)
        .expect("public capture accepts its exact reached named stop");
    let CampaignSavepointResult::Captured {
        snapshot, request, ..
    } = response.result()
    else {
        panic!("expected capture result");
    };
    let capture = repository
        .savepoint_capture_request_at(*snapshot, *request)
        .expect("capture membership")
        .expect("retained request");
    assert_eq!(capture.attempt, attempt);
    assert_eq!(capture.stop, named_stop());
    assert_eq!(capture.configuration, lineage.genesis_content());
    assert_eq!(capture.semantic_configuration, lineage.genesis());
    assert_eq!(capture.reason, PUBLIC_EXACT_CAPTURE_REASON);
}

#[test]
fn public_selection_uses_the_authenticated_named_stop_ready_root() {
    let (repository, lineage, attempt) = completed_source(reached_named_stop());
    let capture = exact_capture(&repository, &lineage, attempt);
    let paused = resolve_capture(&repository, &lineage, &capture);
    let request = public_request(paused.snapshot, selection_action(capture.request));
    let response = RepositoryCampaignService::new(&repository, AllowCampaignQueries)
        .with_operational_status(&paused)
        .campaign_savepoint(&request)
        .expect("public selection accepts the exact reached named source stop");
    let CampaignSavepointResult::Selected {
        attempt: selected, ..
    } = response.result()
    else {
        panic!("expected selection result");
    };
    let continuation = repository
        .load_attempt(*selected)
        .expect("selected attempt");
    let source = repository.load_attempt(attempt).expect("source attempt");
    assert_eq!(continuation.path(), source.path());
    assert_eq!(continuation.stop(), &StopCondition::ExecutionQuanta(20));
    assert!(
        matches!(continuation.start(), AttemptStart::AfterAttempt { origin, .. } if origin == attempt)
    );
}

#[test]
fn public_capture_and_selection_reject_terminal_success_and_policy_timeout() {
    for outcome in [
        StopOutcome::TerminalSuccess,
        StopOutcome::PolicyTimeout {
            stop: named_stop(),
            kind: crate::PolicyTimeoutKind::VirtualTime,
            proof: BoundedStopProof::new(1_000, 9),
        },
    ] {
        let (repository, lineage, attempt) = completed_source(outcome);
        let prior = repository.head(CAMPAIGN).expect("prior head").snapshot_id();
        let request = public_request(prior, capture_action(attempt));
        assert!(matches!(
            RepositoryCampaignService::new(&repository, AllowCampaignQueries)
                .campaign_savepoint(&request),
            Err(RepositoryCampaignServiceError::Repository(
                CampaignRepositoryError::InvalidRequest { .. }
            ))
        ));
        assert_eq!(
            repository
                .head(CAMPAIGN)
                .expect("unchanged head")
                .snapshot_id(),
            prior
        );
        let capture = exact_capture(&repository, &lineage, attempt);
        let paused = resolve_capture(&repository, &lineage, &capture);
        let select = public_request(paused.snapshot, selection_action(capture.request));
        assert!(matches!(
            RepositoryCampaignService::new(&repository, AllowCampaignQueries)
                .with_operational_status(&paused)
                .campaign_savepoint(&select),
            Err(RepositoryCampaignServiceError::Repository(
                CampaignRepositoryError::Integrity {
                    reason: "selected capture source did not reach its declared stop"
                }
            ))
        ));
        assert_eq!(
            repository
                .head(CAMPAIGN)
                .expect("selection refusal atomic")
                .snapshot_id(),
            paused.snapshot
        );
    }
}

struct DenySavepoint;

impl CampaignPrincipalAuthorizer for DenySavepoint {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Err(CampaignAuthorizationError::Unauthorized)
    }
}

#[test]
fn public_exact_stop_operations_preserve_authorization_snapshot_and_ready_guards() {
    let (repository, lineage, attempt) = completed_source(reached_named_stop());
    let prior = repository.head(CAMPAIGN).expect("prior head").snapshot_id();
    let capture_request = public_request(prior, capture_action(attempt));
    assert!(matches!(
        RepositoryCampaignService::new(&repository, DenySavepoint)
            .campaign_savepoint(&capture_request),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("unchanged head")
            .snapshot_id(),
        prior
    );

    let capture = exact_capture(&repository, &lineage, attempt);
    assert!(matches!(
        RepositoryCampaignService::new(&repository, AllowCampaignQueries)
            .campaign_savepoint(&capture_request),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::Stale { .. }
        ))
    ));
    let unresolved = public_request(capture.new_snapshot, selection_action(capture.request));
    assert!(matches!(
        RepositoryCampaignService::new(&repository, AllowCampaignQueries)
            .campaign_savepoint(&unresolved),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::InvalidRequest {
                reason: "selected capture has no Ready resolution"
            }
        ))
    ));

    let paused = resolve_capture(&repository, &lineage, &capture);
    let request = public_request(paused.snapshot, selection_action(capture.request));
    assert!(matches!(
        RepositoryCampaignService::new(&repository, DenySavepoint)
            .with_operational_status(&paused)
            .campaign_savepoint(&request),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
    assert!(matches!(
        RepositoryCampaignService::new(&repository, AllowCampaignQueries)
            .campaign_savepoint(&request),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::Integrity {
                reason: "selected capture has no stable exact runtime root"
            }
        ))
    ));
    for (phase, checkpoint) in [
        (
            CampaignAttemptPhase::Running,
            Some(exact_checkpoint("not-paused")),
        ),
        (CampaignAttemptPhase::Paused, None),
    ] {
        let runtime = PausedCapture {
            runtime: CampaignAttemptRuntime::new(
                phase,
                CampaignAttemptOrigin::Initial,
                paused.runtime.execution(),
                checkpoint,
                None,
                None,
            )
            .expect("negative runtime"),
            ..paused
        };
        assert!(matches!(
            RepositoryCampaignService::new(&repository, AllowCampaignQueries)
                .with_operational_status(&runtime)
                .campaign_savepoint(&request),
            Err(RepositoryCampaignServiceError::Repository(
                CampaignRepositoryError::Integrity {
                    reason: "selected capture is not durably paused at an exact root"
                }
            ))
        ));
    }
    let next_choice = public_request(
        paused.snapshot,
        CampaignSavepointAction::Select {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                b"invalid-continuation",
            )),
            request: capture.request,
            stop: StopCondition::NextChoice,
        },
    );
    assert!(matches!(
        RepositoryCampaignService::new(&repository, AllowCampaignQueries)
            .with_operational_status(&paused)
            .campaign_savepoint(&next_choice),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::InvalidRequest { .. }
        ))
    ));
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("all refusals atomic")
            .snapshot_id(),
        paused.snapshot
    );
}

#[test]
fn mismatched_named_stop_and_invalid_bounded_proof_cannot_supply_capture_evidence() {
    let (repository, lineage, policy) = fixture();
    let policy = policy
        .with_attempt_timeout_policy(
            crate::CampaignAttemptTimeoutPolicy::new(Some(1_000), Some(10), None)
                .expect("deadline"),
        )
        .expect("bounded policy");
    let wrong_stop = StopCondition::bounded(
        StopCondition::NamedBoundary("different-marker".to_owned()),
        Some(1_000),
        Some(10),
    )
    .expect("wrong marker stop");
    let (_, admitted, observation) = admitted_observation_fixture_with_stop(
        &repository,
        &lineage,
        &policy,
        CAMPAIGN,
        named_stop(),
        StopOutcome::BoundedPrimaryReached {
            stop: wrong_stop,
            proof: BoundedStopProof::new(900, 9),
        },
        false,
    );
    assert!(
        repository
            .publish_observation(CAMPAIGN, admitted.new_snapshot, &observation)
            .is_err()
    );
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("wrong marker not credited")
            .snapshot_id(),
        admitted.new_snapshot
    );
    let request = public_request(admitted.new_snapshot, capture_action(admitted.attempt));
    assert!(matches!(
        RepositoryCampaignService::new(&repository, AllowCampaignQueries)
            .campaign_savepoint(&request),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::InvalidRequest { .. }
        ))
    ));

    for proof in [
        BoundedStopProof::new(1_000, 9),
        BoundedStopProof::new(900, 10),
    ] {
        let invalid = Observation::new(
            admitted.attempt,
            Observation::outcome(
                observation.child(),
                observation.child_content(),
                observation.path(),
                StopOutcome::BoundedPrimaryReached {
                    stop: named_stop(),
                    proof,
                },
                observation.measurements(),
                observation.properties(),
                observation.coverage(),
            ),
            BTreeSet::new(),
        );
        assert!(
            invalid.is_err(),
            "deadline proof must fail before repository publication"
        );
    }
}
