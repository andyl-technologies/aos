//! Unit tests for campaign attempt execution messages.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::*;
use crate::CampaignHash;
use crucible_cas::content_store::{ContentId, ObjectKind};

mod retention_policy;

use retention_policy::assert_retention_policy_materialized_start;

fn fixture_request() -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x11; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x22; 16]).expect("daemon epoch"),
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"executor-lineage",
        ))
        .expect("lineage"),
        AttemptId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            8,
            b"executor-attempt",
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(4, 8 * 1024 * 1024 * 1024, 32 * 1024 * 1024, 500_000)
            .expect("resource limits"),
        ExecutionRetentionIntent::RetainOnFailure,
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("submit attempt request")
}

fn fixture_finding_candidate() -> FindingCandidateBundleId {
    FindingCandidateBundleId::from_content_id(ContentId::for_bytes(
        ObjectKind::Finding,
        6,
        b"executor-finding-candidate",
    ))
    .expect("finding candidate")
}

fn fixture_configuration(byte: u8) -> ConfigurationArtifactId {
    ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        &[byte; 32],
    ))
    .expect("configuration")
}

fn fixture_campaign_fact(byte: u8) -> CampaignFactId {
    CampaignFactId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        14,
        &[byte; 32],
    ))
    .expect("campaign fact")
}

#[test]
fn completed_responses_encode_current_optional_finding_candidates() {
    let assignment = fixture_request();
    let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        12,
        b"candidate-bearing-completion",
    ))
    .expect("observation");
    let candidate = fixture_finding_candidate();

    let submit_disposition = SubmitAttemptDisposition::AlreadyCompleted { observation };
    let submit = SubmitAttemptResponse::new_with_finding_candidate(
        &assignment,
        submit_disposition,
        candidate,
    )
    .expect("candidate submit response");
    let submit_bytes = submit.canonical_bytes();
    assert_eq!(&submit_bytes[..4], &4_u32.to_be_bytes());
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes_for(&assignment, &submit_bytes)
            .expect("decode candidate submit response")
            .finding_candidate(),
        Some(candidate)
    );
    assert_eq!(
        SubmitAttemptResponse::new(&assignment, submit_disposition)
            .expect("candidate-free submit response")
            .finding_candidate(),
        None
    );

    let status_request =
        GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    let status = GetAttemptExecutionResponse::new_with_finding_candidate(
        &status_request,
        GetAttemptExecutionDisposition::Completed { observation },
        candidate,
    )
    .expect("candidate status response");
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes_for(
            &status_request,
            &status.canonical_bytes(),
        )
        .expect("decode candidate status response")
        .finding_candidate(),
        Some(candidate)
    );

    let checkpoint_request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    let checkpoint = CheckpointAttemptExecutionResponse::new_with_finding_candidate(
        &checkpoint_request,
        CheckpointAttemptExecutionDisposition::AlreadyCompleted { observation },
        candidate,
    )
    .expect("candidate checkpoint response");
    assert_eq!(
        CheckpointAttemptExecutionResponse::from_canonical_bytes_for(
            &checkpoint_request,
            &checkpoint.canonical_bytes(),
        )
        .expect("decode candidate checkpoint response")
        .finding_candidate(),
        Some(candidate)
    );

    let cancel_request =
        CancelAttemptExecutionRequest::new(&assignment, execution).expect("cancel request");
    let cancel = CancelAttemptExecutionResponse::new_with_finding_candidate(
        &cancel_request,
        CancelAttemptExecutionDisposition::AlreadyCompleted { observation },
        candidate,
    )
    .expect("candidate cancel response");
    assert_eq!(
        CancelAttemptExecutionResponse::from_canonical_bytes_for(
            &cancel_request,
            &cancel.canonical_bytes(),
        )
        .expect("decode candidate cancel response")
        .finding_candidate(),
        Some(candidate)
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"candidate-resume-checkpoint",
    ))
    .expect("resume checkpoint");
    let resume_request = ResumeAttemptExecutionRequest::new(&assignment, execution, checkpoint)
        .expect("resume request");
    let resume = ResumeAttemptExecutionResponse::new_with_finding_candidate(
        &resume_request,
        ResumeAttemptExecutionDisposition::AlreadyCompleted { observation },
        candidate,
    )
    .expect("candidate resume response");
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes_for(
            &resume_request,
            &resume.canonical_bytes(),
        )
        .expect("decode candidate resume response")
        .finding_candidate(),
        Some(candidate)
    );

    assert_eq!(
        SubmitAttemptResponse::new_with_finding_candidate(
            &assignment,
            SubmitAttemptDisposition::AlreadyRunning { execution },
            candidate,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "finding candidate requires a completed executor response",
        })
    );
}

#[test]
fn submit_attempt_messages_are_strict_bounded_and_request_bound() {
    let request = fixture_request();
    let request_bytes = request.canonical_bytes();
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&request_bytes).expect("request decode"),
        request
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.submit-attempt-request-vector.v2",
            &request_bytes
        )
        .to_hex(),
        "73098d610ed7d29555b0ae966698d03e892f38e22f5829e6eb9047fcad70f132"
    );

    let response = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::Accepted {
            execution: ExecutionId::from_bytes([0x33; 16]).expect("execution"),
        },
    )
    .expect("submit attempt response");
    let response_bytes = response.canonical_bytes();
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes(&response_bytes).expect("response decode"),
        response
    );
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes_for(&request, &response_bytes)
            .expect("request-bound response decode"),
        response
    );
    assert!(response.matches_request(&request));
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.submit-attempt-response-vector.v2",
            &response_bytes,
        )
        .to_hex(),
        "aab0d3330280a22dff35425a5e7105d8d1f0016b8f70322945676a25a06e92f2"
    );

    let different = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x44; 16]).expect("different assignment"),
        request.daemon_epoch(),
        request.lineage(),
        request.attempt(),
        request.resources(),
        request.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("different request");
    assert!(!response.matches_request(&different));
    assert_eq!(
        request.execution_basis_digest(),
        different.execution_basis_digest()
    );

    let changed_resources = SubmitAttemptRequest::new(
        request.assignment(),
        request.daemon_epoch(),
        request.lineage(),
        request.attempt(),
        AttemptResourceLimits::new(2, 4 * 1024 * 1024, 0, 100).expect("changed resources"),
        request.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("changed-resource request");
    assert_ne!(
        request.execution_basis_digest(),
        changed_resources.execution_basis_digest()
    );
    assert!(!response.matches_request(&changed_resources));
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes_for(&changed_resources, &response_bytes),
        Err(CampaignCodecError::InvalidValue {
            reason: "submit attempt response does not match request"
        })
    );

    let mut unsupported_version = request_bytes.clone();
    unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version"
        })
    );
    let mut zero_assignment = request_bytes.clone();
    zero_assignment[4..20].fill(0);
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&zero_assignment),
        Err(CampaignCodecError::InvalidValue {
            reason: "executor assignment identity is all zero"
        })
    );
    let discard_request = SubmitAttemptRequest::new(
        request.assignment(),
        request.daemon_epoch(),
        request.lineage(),
        request.attempt(),
        request.resources(),
        ExecutionRetentionIntent::Discard,
        request.retention_policy(),
    )
    .expect("discard request");
    let retention_tag = request_bytes
        .iter()
        .zip(discard_request.canonical_bytes())
        .position(|(retained, discarded)| *retained != discarded)
        .expect("retention intent tag");
    let mut unknown_retention = request_bytes.clone();
    unknown_retention[retention_tag] = 0xff;
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&unknown_retention),
        Err(CampaignCodecError::UnknownTag {
            kind: "execution-retention-intent",
            tag: 0xff
        })
    );
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&request_bytes[..request_bytes.len() - 1]),
        Err(CampaignCodecError::Truncated)
    );

    let terminal = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::TerminalFailure,
        },
    )
    .expect("terminal submit response");
    let terminal_bytes = terminal.canonical_bytes();
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes_for(&request, &terminal_bytes)
            .expect("terminal submit response decode"),
        terminal
    );
    let mut terminal_with_unsupported_version = terminal_bytes;
    terminal_with_unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes(&terminal_with_unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported submit attempt response schema version"
        })
    );
    let mut accepted_with_unsupported_version = response_bytes;
    accepted_with_unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes(&accepted_with_unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported submit attempt response schema version"
        })
    );
}

#[test]
fn materialized_start_capture_is_explicit_versioned_and_basis_bound() {
    let execute = fixture_request();
    let configuration = fixture_configuration(0x91);
    let capture = SubmitAttemptRequest::new(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, configuration)
    })
    .expect("capture request");

    let bytes = capture.canonical_bytes();
    assert_eq!(&bytes[..4], &6_u32.to_be_bytes());
    assert_eq!(
        capture.start_mode(),
        AttemptStartMode::CaptureMaterializedStart { configuration }
    );
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&bytes).expect("decode capture request"),
        capture
    );
    assert_ne!(capture.request_digest(), execute.request_digest());
    assert_ne!(
        capture.execution_basis_digest(),
        execute.execution_basis_digest()
    );
    assert_eq!(
        attempt_execution_basis_digest_for_start_mode(
            execute.lineage(),
            execute.attempt(),
            execute.resources(),
            execute.retention(),
            AttemptStartMode::Execute,
            execute.retention_policy(),
        ),
        execute.execution_basis_digest()
    );

    let changed_configuration = SubmitAttemptRequest::new(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(
            assignment,
            fixture_configuration(0x92),
        )
    })
    .expect("changed configuration request");
    assert_ne!(
        capture.execution_basis_digest(),
        changed_configuration.execution_basis_digest()
    );

    let mut unknown_mode = bytes;
    unknown_mode[execute.canonical_bytes().len() - 2] = 0xff;
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&unknown_mode),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-start-mode",
            tag: 0xff,
        })
    );

    let mut unsupported_execute_version = capture.canonical_bytes();
    unsupported_execute_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&unsupported_execute_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    );
}

#[test]
fn savepoint_capture_scope_is_explicit_versioned_and_control_bound() {
    let execute = fixture_request();
    let capture_fact = fixture_campaign_fact(0xa1);
    let configuration = fixture_configuration(0xa2);
    let capture = SubmitAttemptRequest::new(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_savepoint_capture(assignment, capture_fact, configuration)
    })
    .expect("scoped capture request");
    let scope = AttemptExecutionScope::SavepointCapture {
        request: capture_fact,
    };

    assert_eq!(&capture.canonical_bytes()[..4], &6_u32.to_be_bytes());
    assert_eq!(capture.execution_scope(), scope);
    assert_eq!(
        capture.start_mode(),
        AttemptStartMode::SavepointCapture {
            request: capture_fact,
            configuration,
        }
    );
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&capture.canonical_bytes())
            .expect("decode scoped capture"),
        capture
    );
    assert_ne!(capture.request_digest(), execute.request_digest());
    assert_ne!(
        capture.execution_basis_digest(),
        execute.execution_basis_digest()
    );

    let changed_fact = SubmitAttemptRequest::new(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_savepoint_capture(
            assignment,
            fixture_campaign_fact(0xa3),
            configuration,
        )
    })
    .expect("capture with changed fact");
    let changed_configuration = SubmitAttemptRequest::new(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_savepoint_capture(
            assignment,
            capture_fact,
            fixture_configuration(0xa4),
        )
    })
    .expect("capture with changed configuration");
    assert_ne!(
        capture.execution_basis_digest(),
        changed_fact.execution_basis_digest()
    );
    assert_ne!(
        capture.execution_basis_digest(),
        changed_configuration.execution_basis_digest()
    );

    assert_eq!(
        AttemptExecutionScope::from_canonical_bytes(&scope.canonical_bytes())
            .expect("decode capture scope"),
        scope
    );
    assert_eq!(
        AttemptExecutionScope::from_canonical_bytes(&[0xff]),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-execution-scope",
            tag: 0xff,
        })
    );

    let execution = ExecutionId::from_bytes([0xa5; 16]).expect("execution");
    let status = GetAttemptExecutionRequest::new(&capture, execution).expect("status request");
    let checkpoint =
        CheckpointAttemptExecutionRequest::new(&capture, execution).expect("checkpoint request");
    let cancel =
        CancelAttemptExecutionRequest::new(&capture, execution).expect("cancellation request");
    assert_eq!(status.execution_scope(), scope);
    assert_eq!(checkpoint.execution_scope(), scope);
    assert_eq!(cancel.execution_scope(), scope);
    assert_eq!(&status.canonical_bytes()[..4], &3_u32.to_be_bytes());
    assert_eq!(&checkpoint.canonical_bytes()[..4], &3_u32.to_be_bytes());
    assert_eq!(&cancel.canonical_bytes()[..4], &3_u32.to_be_bytes());
    assert_eq!(
        GetAttemptExecutionRequest::from_canonical_bytes(&status.canonical_bytes())
            .expect("decode scoped status"),
        status
    );
    assert_eq!(
        CheckpointAttemptExecutionRequest::from_canonical_bytes(&checkpoint.canonical_bytes())
            .expect("decode scoped checkpoint"),
        checkpoint
    );
    assert_eq!(
        CancelAttemptExecutionRequest::from_canonical_bytes(&cancel.canonical_bytes())
            .expect("decode scoped cancellation"),
        cancel
    );

    let mut unsupported_status_version = status.canonical_bytes();
    unsupported_status_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        GetAttemptExecutionRequest::from_canonical_bytes(&unsupported_status_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor control-request schema version"
        })
    ));

    let mut unsupported_checkpoint_version = checkpoint.canonical_bytes();
    unsupported_checkpoint_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        CheckpointAttemptExecutionRequest::from_canonical_bytes(&unsupported_checkpoint_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor control-request schema version"
        })
    ));

    let mut unsupported_cancel_version = cancel.canonical_bytes();
    unsupported_cancel_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        CancelAttemptExecutionRequest::from_canonical_bytes(&unsupported_cancel_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor control-request schema version"
        })
    ));
}

#[test]
fn get_attempt_execution_messages_are_strict_and_exact_request_bound() {
    let assignment = fixture_request();
    let execution = ExecutionId::from_bytes([0x37; 16]).expect("execution");
    let request = GetAttemptExecutionRequest::new(&assignment, execution).expect("status request");
    let request_bytes = request.canonical_bytes();
    assert_eq!(
        GetAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
            .expect("status request decode"),
        request
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.get-attempt-execution-request-vector.v3",
            &request_bytes,
        )
        .to_hex(),
        "2d7a8087238c6807aca5bd3e056d12082cad8aa8516ded847617dd1e972ef8ac"
    );

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        12,
        b"executor-status-observation",
    ))
    .expect("observation");
    let response = GetAttemptExecutionResponse::new(
        &request,
        GetAttemptExecutionDisposition::Completed { observation },
    )
    .expect("status response");
    let response_bytes = response.canonical_bytes();
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
            .expect("status response decode"),
        response
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.get-attempt-execution-response-vector.v2",
            &response_bytes,
        )
        .to_hex(),
        "96f31d687e20741befb022fc96b3d5cb4dcef93ca01a2175101abf8e50d94b3c"
    );

    let other_execution = ExecutionId::from_bytes([0x38; 16]).expect("other execution");
    let other = GetAttemptExecutionRequest::new(&assignment, other_execution)
        .expect("other status request");
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
        Err(CampaignCodecError::InvalidValue {
            reason: "get attempt execution response does not match request"
        })
    );

    let mut unknown_disposition =
        GetAttemptExecutionResponse::new(&request, GetAttemptExecutionDisposition::Canceled)
            .expect("canceled status response")
            .canonical_bytes();
    let disposition_tag = unknown_disposition.len() - 2;
    unknown_disposition[disposition_tag] = 0xff;
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
        Err(CampaignCodecError::UnknownTag {
            kind: "get-attempt-execution-disposition",
            tag: 0xff
        })
    );

    let terminal =
        GetAttemptExecutionResponse::new(&request, GetAttemptExecutionDisposition::TerminalFailure)
            .expect("terminal status response");
    let terminal_bytes = terminal.canonical_bytes();
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes_for(&request, &terminal_bytes)
            .expect("terminal status decode"),
        terminal
    );
    let mut terminal_with_unsupported_version = terminal_bytes;
    terminal_with_unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes(&terminal_with_unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported get attempt execution response schema version"
        })
    );
}

#[test]
fn resume_attempt_execution_messages_bind_the_exact_paused_root() {
    let assignment = fixture_request();
    let prior_execution = ExecutionId::from_bytes([0x3d; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"executor-resume-checkpoint-root",
    ))
    .expect("checkpoint root");
    let request = ResumeAttemptExecutionRequest::new(&assignment, prior_execution, checkpoint)
        .expect("resume request");
    let request_bytes = request.canonical_bytes();
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
            .expect("resume request decode"),
        request
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.resume-attempt-execution-request-vector.v2",
            &request_bytes,
        )
        .to_hex(),
        "9b2f4e71c5997bbe499970e3b286916cc82310d2278010895f98cebee76b35da"
    );

    let execution = ExecutionId::from_bytes([0x3e; 16]).expect("resumed execution");
    let response = ResumeAttemptExecutionResponse::new(
        &request,
        ResumeAttemptExecutionDisposition::Accepted { execution },
    )
    .expect("resume response");
    let response_bytes = response.canonical_bytes();
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
            .expect("resume response decode"),
        response
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.resume-attempt-execution-response-vector.v2",
            &response_bytes,
        )
        .to_hex(),
        "baf2aeeab856d79e15dc7f06908e53e5a548f774b25110855920aa89548165af"
    );

    let other_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"other-resume-checkpoint-root",
    ))
    .expect("other checkpoint root");
    let other = ResumeAttemptExecutionRequest::new(&assignment, prior_execution, other_checkpoint)
        .expect("other resume request");
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume attempt execution response does not match request"
        })
    );

    let mut unknown_disposition = ResumeAttemptExecutionResponse::new(
        &request,
        ResumeAttemptExecutionDisposition::AlreadyCanceled,
    )
    .expect("already canceled response")
    .canonical_bytes();
    let disposition_tag = unknown_disposition.len() - 2;
    unknown_disposition[disposition_tag] = 0xff;
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
        Err(CampaignCodecError::UnknownTag {
            kind: "resume-attempt-execution-disposition",
            tag: 0xff
        })
    );

    let terminal = ResumeAttemptExecutionResponse::new(
        &request,
        ResumeAttemptExecutionDisposition::Rejected {
            reason: ExecutorRejection::TerminalFailure,
        },
    )
    .expect("terminal resume response");
    let terminal_bytes = terminal.canonical_bytes();
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes_for(&request, &terminal_bytes)
            .expect("terminal resume response decode"),
        terminal
    );
    let mut terminal_with_unsupported_version = terminal_bytes;
    terminal_with_unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes(&terminal_with_unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported resume attempt execution response schema version"
        })
    );
    let mut accepted_with_unsupported_version = response_bytes;
    accepted_with_unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes(&accepted_with_unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported resume attempt execution response schema version"
        })
    );
}

#[test]
fn materialized_start_resume_authenticates_prior_and_new_execution_bases() {
    let assignment = fixture_request();
    let prior_execution = ExecutionId::from_bytes([0x4d; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"materialized-start-resume-checkpoint",
    ))
    .expect("checkpoint root");
    let configuration = fixture_configuration(0x93);
    let request = ResumeAttemptExecutionRequest::new_from_materialized_start(
        &assignment,
        prior_execution,
        checkpoint,
        configuration,
    )
    .expect("materialized-start resume request");

    let bytes = request.canonical_bytes();
    assert_eq!(&bytes[..4], &6_u32.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&bytes)
            .expect("decode materialized-start resume"),
        request
    );
    assert_eq!(
        request.prior_start_mode(),
        AttemptStartMode::CaptureMaterializedStart { configuration }
    );
    assert_eq!(
        request.execution_basis_digest(),
        assignment.execution_basis_digest()
    );
    assert_eq!(
        request.prior_execution_basis_digest(),
        attempt_execution_basis_digest_with_retention_policy(
            assignment.lineage(),
            assignment.attempt(),
            assignment.resources(),
            assignment.retention(),
            AttemptStartMode::CaptureMaterializedStart { configuration },
            crate::AttemptRetentionPolicyDisposition::Disabled,
        )
    );
    assert_ne!(
        request.prior_execution_basis_digest(),
        request.execution_basis_digest()
    );

    assert_retention_policy_materialized_start(
        &assignment,
        prior_execution,
        checkpoint,
        configuration,
    );

    let standard = ResumeAttemptExecutionRequest::new(&assignment, prior_execution, checkpoint)
        .expect("standard resume request");
    assert_eq!(
        standard.prior_execution_basis_digest(),
        standard.execution_basis_digest()
    );

    let capture_assignment = SubmitAttemptRequest::new(
        assignment.assignment(),
        assignment.daemon_epoch(),
        assignment.lineage(),
        assignment.attempt(),
        assignment.resources(),
        assignment.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, configuration)
    })
    .expect("capture assignment");
    assert_eq!(
        ResumeAttemptExecutionRequest::new(&capture_assignment, prior_execution, checkpoint),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume requires a semantic assignment",
        })
    );
    assert_eq!(
        ResumeAttemptExecutionRequest::new_from_materialized_start(
            &capture_assignment,
            prior_execution,
            checkpoint,
            configuration,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume requires an execute assignment",
        })
    );

    let standard_bytes = standard.canonical_bytes();
    let start_mode_tag = bytes
        .iter()
        .zip(&standard_bytes)
        .position(|(materialized, ordinary)| materialized != ordinary)
        .expect("prior start mode tag");
    let mut unknown_mode = bytes;
    unknown_mode[start_mode_tag] = 0xff;
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&unknown_mode),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-start-mode",
            tag: 0xff,
        })
    );

    let mut unsupported_execute_version = request.canonical_bytes();
    unsupported_execute_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&unsupported_execute_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    );
}

#[test]
fn selected_savepoint_resume_preserves_the_semantic_start_authority() {
    let ordinary = fixture_request();
    let snapshot = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        3,
        b"selected-resume-snapshot",
    ))
    .expect("snapshot");
    let selected = SubmitAttemptRequest::new(
        ordinary.assignment(),
        ordinary.daemon_epoch(),
        ordinary.lineage(),
        ordinary.attempt(),
        ordinary.resources(),
        ordinary.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_selected_savepoint(
            assignment,
            snapshot,
            fixture_campaign_fact(0xb1),
            fixture_campaign_fact(0xb2),
        )
    })
    .expect("selected assignment");
    let prior_execution = ExecutionId::from_bytes([0xb3; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"selected-resume-checkpoint",
    ))
    .expect("checkpoint");

    let request = ResumeAttemptExecutionRequest::new(&selected, prior_execution, checkpoint)
        .expect("selected resume request");
    let bytes = request.canonical_bytes();

    assert_eq!(&bytes[..4], &6_u32.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&bytes)
            .expect("decode selected resume"),
        request
    );
    assert_eq!(request.assignment_request().expect("assignment"), selected);
    assert_eq!(
        request.execution_basis_digest(),
        selected.execution_basis_digest()
    );
    assert_eq!(
        request.prior_execution_basis_digest(),
        selected.execution_basis_digest()
    );

    let mut unsupported_selected_version = bytes.clone();
    unsupported_selected_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&unsupported_selected_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    );

    let mut unsupported_version = bytes;
    unsupported_version[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&unsupported_version),
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor component-message schema version",
        })
    );
}

#[test]
fn cancel_attempt_execution_messages_are_strict_and_exact_request_bound() {
    let assignment = fixture_request();
    let execution = ExecutionId::from_bytes([0x39; 16]).expect("execution");
    let request =
        CancelAttemptExecutionRequest::new(&assignment, execution).expect("cancellation request");
    let request_bytes = request.canonical_bytes();
    assert_eq!(
        CancelAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
            .expect("cancellation request decode"),
        request
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.cancel-attempt-execution-request-vector.v3",
            &request_bytes,
        )
        .to_hex(),
        "7f143a2bb2e74ae9cdc3f568633b016e30b3a7ba3d8651d1e351e0a6dc62123c"
    );

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        12,
        b"executor-cancellation-observation",
    ))
    .expect("observation");
    let response = CancelAttemptExecutionResponse::new(
        &request,
        CancelAttemptExecutionDisposition::AlreadyCompleted { observation },
    )
    .expect("cancellation response");
    let response_bytes = response.canonical_bytes();
    assert_eq!(
        CancelAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes)
            .expect("cancellation response decode"),
        response
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.cancel-attempt-execution-response-vector.v2",
            &response_bytes,
        )
        .to_hex(),
        "00fb0f2cb19b855b630d79d0c09fa67e78c6a3f7e2eef6975e11cd283be5b701"
    );

    let other = CancelAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x3a; 16]).expect("other execution"),
    )
    .expect("other cancellation request");
    assert_eq!(
        CancelAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
        Err(CampaignCodecError::InvalidValue {
            reason: "cancel attempt execution response does not match request"
        })
    );

    let mut unknown_disposition = CancelAttemptExecutionResponse::new(
        &request,
        CancelAttemptExecutionDisposition::AlreadyCanceled,
    )
    .expect("already canceled response")
    .canonical_bytes();
    let disposition_tag = unknown_disposition.len() - 2;
    unknown_disposition[disposition_tag] = 0xff;
    assert_eq!(
        CancelAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
        Err(CampaignCodecError::UnknownTag {
            kind: "cancel-attempt-execution-disposition",
            tag: 0xff
        })
    );
}

#[test]
fn checkpoint_attempt_execution_messages_bind_the_exact_root_and_request() {
    let assignment = fixture_request();
    let execution = ExecutionId::from_bytes([0x3b; 16]).expect("execution");
    let request =
        CheckpointAttemptExecutionRequest::new(&assignment, execution).expect("checkpoint request");
    let request_bytes = request.canonical_bytes();
    assert_eq!(
        CheckpointAttemptExecutionRequest::from_canonical_bytes(&request_bytes)
            .expect("checkpoint request decode"),
        request
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.checkpoint-attempt-execution-request-vector.v3",
            &request_bytes,
        )
        .to_hex(),
        "3aae78e714d18563b0b87b5f8c74e36b7fd05ec22c049e254f825d762deccea3"
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        b"executor-checkpoint-root",
    ))
    .expect("checkpoint root");
    let response = CheckpointAttemptExecutionResponse::new(
        &request,
        CheckpointAttemptExecutionDisposition::Paused { checkpoint },
    )
    .expect("checkpoint response");
    let response_bytes = response.canonical_bytes();
    assert_eq!(
        CheckpointAttemptExecutionResponse::from_canonical_bytes_for(&request, &response_bytes,)
            .expect("checkpoint response decode"),
        response
    );
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.checkpoint-attempt-execution-response-vector.v2",
            &response_bytes,
        )
        .to_hex(),
        "dcb9d6626c2fcbff2957ccc3dee1eff9b8f522269b70fbc5af9e979395cb8082"
    );

    let other = CheckpointAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([0x3c; 16]).expect("other execution"),
    )
    .expect("other checkpoint request");
    assert_eq!(
        CheckpointAttemptExecutionResponse::from_canonical_bytes_for(&other, &response_bytes),
        Err(CampaignCodecError::InvalidValue {
            reason: "checkpoint attempt execution response does not match request"
        })
    );

    let mut unknown_disposition = CheckpointAttemptExecutionResponse::new(
        &request,
        CheckpointAttemptExecutionDisposition::AlreadyRequested,
    )
    .expect("already requested response")
    .canonical_bytes();
    let disposition_tag = unknown_disposition.len() - 2;
    unknown_disposition[disposition_tag] = 0xff;
    assert_eq!(
        CheckpointAttemptExecutionResponse::from_canonical_bytes(&unknown_disposition),
        Err(CampaignCodecError::UnknownTag {
            kind: "checkpoint-attempt-execution-disposition",
            tag: 0xff
        })
    );
}

#[test]
fn executor_service_uses_rejections_as_protocol_outcomes() {
    struct RejectingExecutor;

    impl ExecutorService for RejectingExecutor {
        type Error = std::convert::Infallible;

        fn submit_attempt(
            &mut self,
            request: &SubmitAttemptRequest,
        ) -> Result<SubmitAttemptResponse, Self::Error> {
            Ok(SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Backpressure,
                },
            )
            .expect("bounded rejection"))
        }
    }

    let request = fixture_request();
    let response = ExecutorClient::new(RejectingExecutor)
        .submit_attempt(&request)
        .expect("checked infallible service");
    assert!(response.matches_request(&request));
    assert_eq!(
        response.disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Backpressure
        }
    );
    assert_eq!(
        AttemptResourceLimits::new(0, 1, 0, 1),
        Err(CampaignCodecError::InvalidValue {
            reason: "executor resource limit has zero vcpus"
        })
    );
    assert!(ExecutorRejection::Backpressure.retry_with_new_assignment());
    assert!(!ExecutorRejection::ConflictingAssignment.retry_with_new_assignment());
}

#[test]
fn checked_client_rejects_cross_request_replay_and_ledger_is_exact() {
    struct ReplayingExecutor {
        prior: SubmitAttemptResponse,
    }

    impl ExecutorService for ReplayingExecutor {
        type Error = std::convert::Infallible;

        fn submit_attempt(
            &mut self,
            _request: &SubmitAttemptRequest,
        ) -> Result<SubmitAttemptResponse, Self::Error> {
            Ok(self.prior.clone())
        }
    }

    let prior_request = fixture_request();
    let prior_response = SubmitAttemptResponse::new(
        &prior_request,
        SubmitAttemptDisposition::Accepted {
            execution: ExecutionId::from_bytes([0x55; 16]).expect("prior execution"),
        },
    )
    .expect("prior response");
    let changed_request = SubmitAttemptRequest::new(
        prior_request.assignment(),
        prior_request.daemon_epoch(),
        prior_request.lineage(),
        prior_request.attempt(),
        AttemptResourceLimits::new(8, 16 * 1024 * 1024, 0, 1_000).expect("changed limits"),
        prior_request.retention(),
        crate::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("changed request");
    assert_eq!(
        ExecutorClient::new(ReplayingExecutor {
            prior: prior_response,
        })
        .submit_attempt(&changed_request),
        Err(ExecutorClientError::InvalidResponse(
            CampaignCodecError::InvalidValue {
                reason: "submit attempt response does not match request"
            }
        ))
    );

    #[derive(Default)]
    struct ExactLedger {
        accepted: Option<(AssignmentId, CampaignHash, SubmitAttemptResponse)>,
    }

    impl ExecutorService for ExactLedger {
        type Error = std::convert::Infallible;

        fn submit_attempt(
            &mut self,
            request: &SubmitAttemptRequest,
        ) -> Result<SubmitAttemptResponse, Self::Error> {
            if let Some((assignment, digest, response)) = &self.accepted
                && *assignment == request.assignment()
            {
                return if *digest == request.request_digest() {
                    Ok(response.clone())
                } else {
                    Ok(SubmitAttemptResponse::new(
                        request,
                        SubmitAttemptDisposition::Rejected {
                            reason: ExecutorRejection::ConflictingAssignment,
                        },
                    )
                    .expect("bounded conflict"))
                };
            }
            let response = SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Accepted {
                    execution: ExecutionId::from_bytes([0x66; 16]).expect("execution"),
                },
            )
            .expect("bounded acceptance");
            self.accepted = Some((
                request.assignment(),
                request.request_digest(),
                response.clone(),
            ));
            Ok(response)
        }
    }

    let mut ledger = ExecutorClient::new(ExactLedger::default());
    let accepted = ledger
        .submit_attempt(&prior_request)
        .expect("initial exact assignment");
    assert_eq!(
        ledger
            .submit_attempt(&prior_request)
            .expect("exact assignment replay"),
        accepted
    );
    assert_eq!(
        ledger
            .submit_attempt(&changed_request)
            .expect("stable assignment conflict")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::ConflictingAssignment
        }
    );
}
