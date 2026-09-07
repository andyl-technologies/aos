//! Unit tests for campaign attempt execution messages.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::*;
use crate::CampaignHash;
use crucible_cas::content_store::{ContentId, ObjectKind};

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
            1,
            b"executor-attempt",
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(4, 8 * 1024 * 1024 * 1024, 32 * 1024 * 1024, 500_000)
            .expect("resource limits"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit attempt request")
}

fn fixture_finding_candidate() -> FindingCandidateBundleId {
    FindingCandidateBundleId::from_content_id(ContentId::for_bytes(
        ObjectKind::Finding,
        1,
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

#[test]
fn completed_responses_version_finding_candidates_and_decode_legacy_none() {
    let assignment = fixture_request();
    let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
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
            .expect("legacy submit response")
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
        2,
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
        "0e799560b178b6f6d2a8fe1822e141ac55f436b3600bed1e5fa07ce27aaf5e69"
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
        "9bf8c3a08b4637c75bca9ff467de181a98ea2828c5e302ed0ed5552dfc60f698"
    );

    let different = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x44; 16]).expect("different assignment"),
        request.daemon_epoch(),
        request.lineage(),
        request.attempt(),
        request.resources(),
        request.retention(),
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
    unsupported_version[..4].copy_from_slice(&1_u32.to_be_bytes());
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
    let mut unknown_retention = request_bytes.clone();
    *unknown_retention.last_mut().expect("retention tag") = 0xff;
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
    let mut terminal_as_v2 = terminal_bytes;
    terminal_as_v2[..4].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes(&terminal_as_v2),
        Err(CampaignCodecError::InvalidValue {
            reason: "submit attempt response schema/disposition mismatch"
        })
    );
    let mut accepted_as_v3 = response_bytes;
    accepted_as_v3[..4].copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(
        SubmitAttemptResponse::from_canonical_bytes(&accepted_as_v3),
        Err(CampaignCodecError::InvalidValue {
            reason: "submit attempt response schema/disposition mismatch"
        })
    );
}

#[test]
fn materialized_start_capture_is_explicit_versioned_and_basis_bound() {
    let execute = fixture_request();
    let configuration = fixture_configuration(0x91);
    let capture = SubmitAttemptRequest::new_capture_materialized_start(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        configuration,
    )
    .expect("capture request");

    let bytes = capture.canonical_bytes();
    assert_eq!(&bytes[..4], &3_u32.to_be_bytes());
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
        ),
        attempt_execution_basis_digest(
            execute.lineage(),
            execute.attempt(),
            execute.resources(),
            execute.retention(),
        )
    );

    let changed_configuration = SubmitAttemptRequest::new_capture_materialized_start(
        execute.assignment(),
        execute.daemon_epoch(),
        execute.lineage(),
        execute.attempt(),
        execute.resources(),
        execute.retention(),
        fixture_configuration(0x92),
    )
    .expect("changed configuration request");
    assert_ne!(
        capture.execution_basis_digest(),
        changed_configuration.execution_basis_digest()
    );

    let mut unknown_mode = bytes;
    unknown_mode[execute.canonical_bytes().len()] = 0xff;
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&unknown_mode),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-start-mode",
            tag: 0xff,
        })
    );

    let mut version_three_execute = capture.canonical_bytes();
    version_three_execute.truncate(execute.canonical_bytes().len() + 1);
    *version_three_execute.last_mut().expect("start mode tag") = 0;
    assert_eq!(
        SubmitAttemptRequest::from_canonical_bytes(&version_three_execute),
        Err(CampaignCodecError::InvalidValue {
            reason: "submit attempt request version 3 requires materialized-start capture",
        })
    );
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
            "crucible.test.get-attempt-execution-request-vector.v2",
            &request_bytes,
        )
        .to_hex(),
        "ef1b1a52e9f1bce2ad5f56a3d038c2a48cbd7c3e1809e0cd999edb4f1f64d5f3"
    );

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
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
        "52a161cda68e3b020734a39e141906ba8b707768a93964e597884cd1777b03fb"
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
    *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
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
    let mut terminal_as_v2 = terminal_bytes;
    terminal_as_v2[..4].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(
        GetAttemptExecutionResponse::from_canonical_bytes(&terminal_as_v2),
        Err(CampaignCodecError::InvalidValue {
            reason: "get attempt execution response schema/disposition mismatch"
        })
    );
}

#[test]
fn resume_attempt_execution_messages_bind_the_exact_paused_root() {
    let assignment = fixture_request();
    let prior_execution = ExecutionId::from_bytes([0x3d; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
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
        "5ac0a6c32480b9b337a39f9b4768db543de765dbe7de44099066565ee6b4a24c"
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
        "fda096f0dfd2bccd0d8cc060fb90eed72e0e965c62e2f3c597113663a73c34e4"
    );

    let other_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
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
    *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
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
    let mut terminal_as_v2 = terminal_bytes;
    terminal_as_v2[..4].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes(&terminal_as_v2),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume attempt execution response schema/disposition mismatch"
        })
    );
    let mut accepted_as_v3 = response_bytes;
    accepted_as_v3[..4].copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(
        ResumeAttemptExecutionResponse::from_canonical_bytes(&accepted_as_v3),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume attempt execution response schema/disposition mismatch"
        })
    );
}

#[test]
fn materialized_start_resume_authenticates_prior_and_new_execution_bases() {
    let assignment = fixture_request();
    let prior_execution = ExecutionId::from_bytes([0x4d; 16]).expect("prior execution");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
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
    assert_eq!(&bytes[..4], &3_u32.to_be_bytes());
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
        attempt_execution_basis_digest_for_start_mode(
            assignment.lineage(),
            assignment.attempt(),
            assignment.resources(),
            assignment.retention(),
            AttemptStartMode::CaptureMaterializedStart { configuration },
        )
    );
    assert_ne!(
        request.prior_execution_basis_digest(),
        request.execution_basis_digest()
    );

    let standard = ResumeAttemptExecutionRequest::new(&assignment, prior_execution, checkpoint)
        .expect("standard resume request");
    assert_eq!(
        standard.prior_execution_basis_digest(),
        standard.execution_basis_digest()
    );

    let capture_assignment = SubmitAttemptRequest::new_capture_materialized_start(
        assignment.assignment(),
        assignment.daemon_epoch(),
        assignment.lineage(),
        assignment.attempt(),
        assignment.resources(),
        assignment.retention(),
        configuration,
    )
    .expect("capture assignment");
    assert_eq!(
        ResumeAttemptExecutionRequest::new(&capture_assignment, prior_execution, checkpoint),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume requires an execute assignment",
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

    let mut unknown_mode = bytes;
    unknown_mode[standard.canonical_bytes().len()] = 0xff;
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&unknown_mode),
        Err(CampaignCodecError::UnknownTag {
            kind: "attempt-start-mode",
            tag: 0xff,
        })
    );

    let mut version_three_execute = request.canonical_bytes();
    version_three_execute.truncate(standard.canonical_bytes().len() + 1);
    *version_three_execute
        .last_mut()
        .expect("prior start mode tag") = 0;
    assert_eq!(
        ResumeAttemptExecutionRequest::from_canonical_bytes(&version_three_execute),
        Err(CampaignCodecError::InvalidValue {
            reason: "resume attempt request version 3 requires materialized-start capture",
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
            "crucible.test.cancel-attempt-execution-request-vector.v2",
            &request_bytes,
        )
        .to_hex(),
        "b3ca93e0286e939ba61708de078d38588c5e9298611b4c30482453ee649e367e"
    );

    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
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
        "fd77a046700eedf86394ce59e290a5396105a04b9f1fe224d767eaa79d119fac"
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
    *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
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
            "crucible.test.checkpoint-attempt-execution-request-vector.v2",
            &request_bytes,
        )
        .to_hex(),
        "2f1dfdb45541a18fd2b09e3033e982af8e110c8ebd443bc06823751c45cc4a2e"
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
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
        "ff859c55efc7e56f7e81c6dd969fbe068a0c583e346a37023531a81a8a61877d"
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
    *unknown_disposition.last_mut().expect("disposition tag") = 0xff;
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
