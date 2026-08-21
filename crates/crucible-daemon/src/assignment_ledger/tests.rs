//! Conformance tests for memory and crash-safe directory assignment ledgers.

#![allow(clippy::expect_used)]

use std::fs;

use crucible_campaign::{
    AttemptResourceLimits, CampaignLineageId, ExecutionRetentionIntent, ExecutorRejection,
    SubmitAttemptDisposition,
};

use super::*;

#[test]
fn directory_ledger_reopens_exact_records_and_attempt_state() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x11, 0x31, 2);
    let response = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::Accepted {
            execution: execution(0x51),
        },
    )
    .expect("accepted response");
    let record =
        AssignmentRecord::new(request.clone(), response.clone()).expect("valid assignment record");
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let execution_basis = request.execution_basis_digest();
    let running = AttemptRuntimeState::Running {
        execution_basis,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
    };
    let completed = AttemptRuntimeState::Completed {
        execution_basis,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
        observation: observation(0x71),
    };
    let publishing = AttemptRuntimeState::Publishing {
        execution_basis,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
        observation: observation(0x71),
    };

    {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        assert!(DirectoryAssignmentLedger::open(directory.path()).is_err());
        assert_eq!(
            ledger
                .publish_assignment(&record)
                .expect("publish assignment"),
            AssignmentPublish::Stored
        );
        assert_eq!(
            ledger
                .publish_assignment(&record)
                .expect("replay assignment"),
            AssignmentPublish::Existing
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(running))
                .expect("publish running state"),
            AttemptStateCas::Advanced
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(completed))
                .expect("stale attempt state compare"),
            AttemptStateCas::Conflict {
                current: Some(running)
            }
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(running), Some(publishing))
                .expect("publish observation root"),
            AttemptStateCas::Advanced
        );
        let mut roots = Vec::new();
        ledger
            .visit_observation_roots(&mut |root| roots.push(root))
            .expect("stream publishing roots");
        assert_eq!(roots, vec![observation(0x71)]);
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(publishing), Some(completed))
                .expect("publish completed state"),
            AttemptStateCas::Advanced
        );
    }

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert_eq!(
        ledger
            .load_assignment(request.assignment())
            .expect("load assignment"),
        Some(record)
    );
    assert_eq!(
        ledger.load_attempt(key).expect("load attempt state"),
        Some(completed)
    );
    let mut roots = Vec::new();
    ledger
        .visit_observation_roots(&mut |root| roots.push(root))
        .expect("stream reopened roots");
    assert_eq!(roots, vec![observation(0x71)]);
    assert_eq!(response.validate_for(&request), Ok(()));
}

#[test]
fn assignment_identity_conflict_never_overwrites_first_response() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let mut ledger =
        DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
    let request = request(0x12, 0x32, 1);
    let original = AssignmentRecord::new(
        request.clone(),
        SubmitAttemptResponse::new(
            &request,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Backpressure,
            },
        )
        .expect("backpressure response"),
    )
    .expect("original record");
    assert_eq!(
        ledger
            .publish_assignment(&original)
            .expect("publish original"),
        AssignmentPublish::Stored
    );

    let changed = SubmitAttemptRequest::new(
        request.assignment(),
        request.daemon_epoch(),
        request.lineage(),
        request.attempt(),
        AttemptResourceLimits::new(2, 4096, 8192, 17).expect("changed resources"),
        request.retention(),
    )
    .expect("changed request");
    let conflicting = AssignmentRecord::new(
        changed.clone(),
        SubmitAttemptResponse::new(
            &changed,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment,
            },
        )
        .expect("conflict response"),
    )
    .expect("conflicting record");
    assert_eq!(
        ledger
            .publish_assignment(&conflicting)
            .expect("detect conflict"),
        AssignmentPublish::Conflict
    );
    assert_eq!(
        ledger
            .load_assignment(request.assignment())
            .expect("reload original"),
        Some(original)
    );
}

#[test]
fn checkpoint_states_round_trip_and_remain_gc_roots_after_restart() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x18, 0x38, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let basis = request.execution_basis_digest();
    let execution = execution(0x58);
    let checkpoint = checkpoint(0x78);
    let running = AttemptRuntimeState::Running {
        execution_basis: basis,
        daemon_epoch: request.daemon_epoch(),
        execution,
    };
    let requested = AttemptRuntimeState::CheckpointRequested {
        execution_basis: basis,
        daemon_epoch: request.daemon_epoch(),
        execution,
    };
    let publishing = AttemptRuntimeState::CheckpointPublishing {
        execution_basis: basis,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint,
    };
    let paused = AttemptRuntimeState::Paused {
        execution_basis: basis,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint,
    };

    {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(running))
                .expect("publish running"),
            AttemptStateCas::Advanced
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(running), Some(requested))
                .expect("request checkpoint"),
            AttemptStateCas::Advanced
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(requested), Some(publishing))
                .expect("stage checkpoint root"),
            AttemptStateCas::Advanced
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(publishing), Some(paused))
                .expect("pause checkpoint"),
            AttemptStateCas::Advanced
        );
    }

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert_eq!(ledger.load_attempt(key).expect("load paused"), Some(paused));
    let mut checkpoints = Vec::new();
    ledger
        .visit_checkpoint_roots(&mut |root| checkpoints.push(root))
        .expect("stream checkpoint roots");
    assert_eq!(checkpoints, vec![checkpoint]);
    let mut observations = Vec::new();
    ledger
        .visit_observation_roots(&mut |root| observations.push(root))
        .expect("stream observation roots");
    assert!(observations.is_empty());
}

#[test]
fn directory_ledger_rejects_corrupt_bounded_records() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x13, 0x33, 1);
    let path = {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        let record = AssignmentRecord::new(
            request.clone(),
            SubmitAttemptResponse::new(
                &request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            )
            .expect("response"),
        )
        .expect("record");
        ledger
            .publish_assignment(&record)
            .expect("publish assignment");
        ledger.assignment_path(request.assignment())
    };
    fs::write(&path, b"truncated-record").expect("corrupt assignment file");

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert!(matches!(
        ledger.load_assignment(request.assignment()),
        Err(AssignmentLedgerError::Corrupt { .. })
    ));
}

#[test]
fn memory_ledger_matches_conditional_publish_contract() {
    let request = request(0x14, 0x34, 1);
    let record = AssignmentRecord::new(
        request.clone(),
        SubmitAttemptResponse::new(
            &request,
            SubmitAttemptDisposition::AlreadyRunning {
                execution: execution(0x54),
            },
        )
        .expect("response"),
    )
    .expect("record");
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger.publish_assignment(&record),
        Ok(AssignmentPublish::Stored)
    );
    assert_eq!(
        ledger.publish_assignment(&record),
        Ok(AssignmentPublish::Existing)
    );
    assert_eq!(
        ledger.load_assignment(request.assignment()),
        Ok(Some(record))
    );
}

#[test]
fn directory_ledger_reads_legacy_v1_attempt_state() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x15, 0x35, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x55),
        observation: observation(0x75),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V1);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x55).as_bytes());
    push_bytes(&mut payload, observation(0x75).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V1))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v2_publishing_state() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x16, 0x36, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x56),
        observation: observation(0x76),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V2);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x56).as_bytes());
    push_bytes(&mut payload, observation(0x76).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V2))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

fn request(assignment_byte: u8, attempt_byte: u8, vcpus: u32) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x21; 16]).expect("daemon epoch"),
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            0x41,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            attempt_byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(vcpus, 4096, 8192, 16).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("request")
}

fn observation(byte: u8) -> ObservationId {
    ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        byte,
    ))
    .expect("observation")
}

fn checkpoint(byte: u8) -> ExactCheckpointId {
    ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.2.{}",
        encode_hex(&[byte; 32])
    ))
    .expect("checkpoint")
}

fn execution(byte: u8) -> ExecutionId {
    ExecutionId::from_bytes([byte; 16]).expect("execution")
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}
