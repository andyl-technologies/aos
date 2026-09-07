//! Conformance tests for memory and crash-safe directory assignment ledgers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::fs;

use crucible_campaign::{
    AttemptResourceLimits, AttemptStartMode, CampaignLineageId, ConfigurationArtifactId,
    ExecutionRetentionIntent, ExecutorRejection, SubmitAttemptDisposition,
};

use super::*;

#[test]
fn writer_owner_drop_releases_lock_held_by_a_duplicated_descriptor() {
    let directory = tempfile::tempdir().expect("ledger directory");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("first writer");
    let inherited = ledger
        .writer_lock
        .try_clone()
        .expect("duplicate inherited writer descriptor");

    assert!(DirectoryAssignmentLedger::open(directory.path()).is_err());
    drop(ledger);

    let replacement = DirectoryAssignmentLedger::open(directory.path())
        .expect("owner drop releases inherited lock");
    drop(replacement);
    drop(inherited);
}

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
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
    };
    let completed = AttemptRuntimeState::Completed {
        execution_basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
        observation: observation(0x71),
        finding_candidate: CompletedFindingCandidate::Pending(finding_candidate(0x72)),
    };
    let publishing = AttemptRuntimeState::Publishing {
        execution_basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
        observation: observation(0x71),
        finding_candidate: Some(finding_candidate(0x72)),
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
    let raw_checkpoint = checkpoint(0x78);
    let promoted_checkpoint = checkpoint(0x79);
    let promotion_basis = Some(CheckpointPromotionExecutionBasis::new(
        request.resources(),
        request.retention(),
    ));
    let running = AttemptRuntimeState::Running {
        execution_basis: basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
    };
    let requested = AttemptRuntimeState::CheckpointRequested {
        execution_basis: basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
    };
    let publishing = AttemptRuntimeState::CheckpointPublishing {
        execution_basis: basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint: raw_checkpoint,
    };
    let paused = AttemptRuntimeState::Paused {
        execution_basis: basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        checkpoint: raw_checkpoint,
        promotion_basis,
    };
    let promoting = AttemptRuntimeState::CheckpointPromoting {
        execution_basis: basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        source_checkpoint: raw_checkpoint,
        promoted_checkpoint,
        promotion_basis,
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
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(paused), Some(promoting))
                .expect("stage replay-oracle promotion"),
            AttemptStateCas::Advanced
        );
    }

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert_eq!(
        ledger.load_attempt(key).expect("load promoting"),
        Some(promoting)
    );
    let mut checkpoints = Vec::new();
    ledger
        .visit_checkpoint_roots(&mut |root| checkpoints.push(root))
        .expect("stream checkpoint roots");
    assert_eq!(checkpoints, vec![promoted_checkpoint, raw_checkpoint]);
    let mut observations = Vec::new();
    ledger
        .visit_observation_roots(&mut |root| observations.push(root))
        .expect("stream observation roots");
    assert!(observations.is_empty());
}

#[test]
fn current_checkpoint_promotion_basis_must_match_the_execution_digest() {
    let request = request(0x1b, 0x3b, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let mismatched_resources = AttemptResourceLimits::new(
        2,
        request.resources().maximum_resident_bytes(),
        request.resources().maximum_disk_bytes(),
        request.resources().maximum_execution_quanta(),
    )
    .expect("different valid resources");
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5b),
        checkpoint: checkpoint(0x7c),
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            mismatched_resources,
            request.retention(),
        )),
    };

    assert!(matches!(
        decode_attempt_state(&encode_attempt_state(key, state)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "checkpoint-promotion-execution-basis-mismatch"
        })
    ));
}

#[test]
fn materialized_start_capture_basis_round_trips_and_rejects_unknown_modes() {
    let capture = capture_request(0x2a, 0x4a, 1, configuration(0x8a));
    let key = AttemptExecutionKey::new(capture.lineage(), capture.attempt());
    let state = AttemptRuntimeState::Paused {
        execution_basis: capture.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: capture.daemon_epoch(),
        execution: execution(0x6a),
        checkpoint: checkpoint(0x8b),
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            capture.resources(),
            capture.retention(),
            capture.start_mode(),
        )),
    };

    let encoded = encode_attempt_state(key, state);
    assert_eq!(
        decode_attempt_state(&encoded).expect("decode capture promotion basis"),
        (key, state)
    );

    let execute = request(0x2b, 0x4b, 1);
    let execute_state = AttemptRuntimeState::Paused {
        execution_basis: execute.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: execute.daemon_epoch(),
        execution: execution(0x6b),
        checkpoint: checkpoint(0x8c),
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            execute.resources(),
            execute.retention(),
        )),
    };
    let encoded_execute = encode_attempt_state(
        AttemptExecutionKey::new(execute.lineage(), execute.attempt()),
        execute_state,
    );
    let mut payload = open_sealed(&encoded_execute, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .expect("open current attempt state")
        .to_vec();
    *payload.last_mut().expect("start mode tag") = 0xff;
    assert!(matches!(
        decode_attempt_state(&seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "checkpoint-promotion-start-mode-tag"
        })
    ));
}

#[test]
fn terminal_failure_state_round_trips_through_current_ledger_format() {
    let request = request(0x1c, 0x3c, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::TerminalFailure {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5c),
    };

    assert_eq!(
        decode_attempt_state(&encode_attempt_state(key, state)).expect("decode terminal state"),
        (key, state)
    );
}

#[test]
fn resumed_origin_round_trips_and_retains_input_and_output_roots() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x19, 0x39, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let input = checkpoint(0x79);
    let output = checkpoint(0x7a);
    let origin = AttemptExecutionOrigin::ExactCheckpoint {
        assignment: request.assignment(),
        request_digest: CampaignHash::derive("crucible.test.resume-origin.v1", b"resume"),
        prior_execution: execution(0x59),
        checkpoint: input,
    };
    let running = AttemptRuntimeState::Running {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5a),
    };
    let publishing = AttemptRuntimeState::CheckpointPublishing {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5a),
        checkpoint: output,
    };

    {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(running))
                .expect("publish resumed running state"),
            AttemptStateCas::Advanced
        );
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, Some(running), Some(publishing))
                .expect("publish resumed checkpoint state"),
            AttemptStateCas::Advanced
        );
    }

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert_eq!(
        ledger.load_attempt(key).expect("load resumed state"),
        Some(publishing)
    );
    let mut roots = Vec::new();
    ledger
        .visit_checkpoint_roots(&mut |checkpoint| roots.push(checkpoint))
        .expect("visit resumed checkpoint roots");
    roots.sort();
    assert_eq!(roots, vec![input, output]);
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
fn memory_retention_inventory_is_generation_bound_and_single_pass() {
    let first = request(0x21, 0x41, 1);
    let first_key = AttemptExecutionKey::new(first.lineage(), first.attempt());
    let first_state = AttemptRuntimeState::Publishing {
        execution_basis: first.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: first.daemon_epoch(),
        execution: execution(0x61),
        observation: observation(0x81),
        finding_candidate: Some(finding_candidate(0x91)),
    };
    let second = request(0x22, 0x42, 1);
    let second_key = AttemptExecutionKey::new(second.lineage(), second.attempt());
    let second_state = AttemptRuntimeState::CheckpointPublishing {
        execution_basis: second.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: second.daemon_epoch(),
        execution: execution(0x62),
        checkpoint: checkpoint(0x82),
    };
    let mut ledger = MemoryAssignmentLedger::default();

    let initial = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire initial retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit empty inventory")
    };
    assert_eq!(initial.attempt_records(), 0);

    assert_eq!(
        ledger
            .compare_exchange_attempt(first_key, None, Some(first_state))
            .expect("publish observation root"),
        AttemptStateCas::Advanced
    );
    let first_generation = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire first retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit first inventory")
            .generation()
    };
    assert_ne!(initial.generation(), first_generation);

    assert_eq!(
        ledger
            .compare_exchange_attempt(first_key, None, Some(first_state))
            .expect("reject stale attempt compare"),
        AttemptStateCas::Conflict {
            current: Some(first_state)
        }
    );
    let after_conflict = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire post-conflict fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit post-conflict inventory")
            .generation()
    };
    assert_eq!(after_conflict, first_generation);

    assert_eq!(
        ledger
            .compare_exchange_attempt(first_key, Some(first_state), Some(first_state))
            .expect("accept same-value attempt replacement"),
        AttemptStateCas::Advanced
    );
    let after_same_value = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire same-value retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit same-value inventory")
            .generation()
    };
    assert_ne!(after_same_value, first_generation);

    ledger
        .compare_exchange_attempt(second_key, None, Some(second_state))
        .expect("publish checkpoint root");
    let mut roots = Vec::new();
    let summary = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire complete retention fence");
        fence
            .visit_roots(&mut |root| {
                roots.push(root);
                Ok(())
            })
            .expect("visit complete inventory")
    };
    assert_eq!(summary.attempt_records(), 2);
    assert_eq!(summary.observation_roots(), 1);
    assert_eq!(summary.checkpoint_roots(), 1);
    assert_eq!(summary.finding_candidate_roots(), 1);
    assert!(roots.contains(&AssignmentRetentionRoot::Observation(observation(0x81))));
    assert!(roots.contains(&AssignmentRetentionRoot::ExactCheckpoint(checkpoint(0x82))));
    assert!(roots.contains(&AssignmentRetentionRoot::FindingCandidate(
        finding_candidate(0x91)
    )));

    let failure = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire rejecting retention fence");
        fence.visit_roots(&mut |_| Err(AssignmentRetentionVisitorError::LimitExceeded))
    };
    assert!(matches!(
        failure,
        Err(AssignmentRetentionInventoryError::Visitor(
            AssignmentRetentionVisitorError::LimitExceeded
        ))
    ));
}

#[test]
fn directory_retention_generation_survives_restart_and_distinguishes_aba() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x23, 0x43, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let publishing = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x63),
        observation: observation(0x83),
        finding_candidate: None,
    };
    let running = AttemptRuntimeState::Running {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x63),
    };

    let published_generation = {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        ledger
            .compare_exchange_attempt(key, None, Some(publishing))
            .expect("publish observation root");
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire published retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit published root")
            .generation()
    };

    let mut ledger =
        DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    let reopened_generation = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire reopened retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit reopened root")
            .generation()
    };
    assert_eq!(reopened_generation, published_generation);

    ledger
        .compare_exchange_attempt(key, Some(publishing), Some(running))
        .expect("remove observation root");
    ledger
        .compare_exchange_attempt(key, Some(running), Some(publishing))
        .expect("restore observation root");
    let restored_generation = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire restored retention fence");
        fence
            .visit_roots(&mut |_| Ok(()))
            .expect("visit restored root")
            .generation()
    };
    assert_ne!(restored_generation, published_generation);
    drop(ledger);

    fs::write(
        directory.path().join(RETENTION_STATE_FILE),
        vec![0_u8; (MAX_RETENTION_STATE_BYTES + 1) as usize],
    )
    .expect("write oversized retention state");
    assert!(matches!(
        DirectoryAssignmentLedger::open(directory.path()),
        Err(AssignmentLedgerError::Corrupt {
            reason: "retention-state-size"
        })
    ));
}

#[test]
fn directory_retention_inventory_rejects_misplaced_attempt_records() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x24, 0x44, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x64),
        observation: observation(0x84),
        finding_candidate: None,
    };
    let mut ledger =
        DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
    ledger
        .compare_exchange_attempt(key, None, Some(state))
        .expect("publish attempt state");

    let canonical = ledger.attempt_path(key);
    let canonical_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .expect("canonical attempt name");
    let mut wrong_name = canonical_name.as_bytes().to_vec();
    wrong_name[0] = if wrong_name[0] == b'a' { b'b' } else { b'a' };
    let misplaced = canonical
        .parent()
        .expect("attempt shard")
        .join(String::from_utf8(wrong_name).expect("changed hex name"));
    fs::copy(&canonical, &misplaced).expect("copy misplaced attempt state");

    let result = {
        let mut fence = ledger
            .acquire_retention_fence()
            .expect("acquire retention fence");
        fence.visit_roots(&mut |_| Ok(()))
    };
    assert!(matches!(
        result,
        Err(AssignmentRetentionInventoryError::Backend(
            AssignmentLedgerError::Corrupt {
                reason: "attempt-root-record-path-identity-mismatch"
            }
        ))
    ));
}

#[test]
fn directory_ledger_reads_legacy_v1_attempt_state() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x15, 0x35, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x55),
        observation: observation(0x75),
        finding_candidate: CompletedFindingCandidate::None,
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
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x56),
        observation: observation(0x76),
        finding_candidate: None,
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

#[test]
fn directory_ledger_reads_legacy_v3_paused_state_as_initial_origin() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x17, 0x37, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x57),
        checkpoint: checkpoint(0x77),
        promotion_basis: None,
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V3);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x57).as_bytes());
    push_bytes(&mut payload, checkpoint(0x77).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V3))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v4_paused_state_with_resume_origin() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x19, 0x39, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let origin = AttemptExecutionOrigin::ExactCheckpoint {
        assignment: request.assignment(),
        request_digest: CampaignHash::derive("crucible.test.legacy-v4-resume.v1", b"resume"),
        prior_execution: execution(0x58),
        checkpoint: checkpoint(0x78),
    };
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x59),
        checkpoint: checkpoint(0x79),
        promotion_basis: None,
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V4);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, origin);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x59).as_bytes());
    push_bytes(&mut payload, checkpoint(0x79).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V4))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v5_promotion_without_execution_basis_details() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x1a, 0x3a, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let origin = AttemptExecutionOrigin::Initial;
    let state = AttemptRuntimeState::CheckpointPromoting {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5a),
        source_checkpoint: checkpoint(0x7a),
        promoted_checkpoint: checkpoint(0x7b),
        promotion_basis: None,
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V5);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, origin);
    payload.push(7);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5a).as_bytes());
    push_bytes(&mut payload, checkpoint(0x7a).to_text().as_bytes());
    push_bytes(&mut payload, checkpoint(0x7b).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V5))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v6_state_with_execution_basis_details() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x1d, 0x3d, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let origin = AttemptExecutionOrigin::Initial;
    let promotion_basis =
        CheckpointPromotionExecutionBasis::new(request.resources(), request.retention());
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5d),
        checkpoint: checkpoint(0x7d),
        promotion_basis: Some(promotion_basis),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V6);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, origin);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5d).as_bytes());
    push_bytes(&mut payload, checkpoint(0x7d).to_text().as_bytes());
    encode_legacy_checkpoint_promotion_basis(&mut payload, promotion_basis);
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V6))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v7_publishing_state_without_finding_candidate() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x1e, 0x3e, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let origin = AttemptExecutionOrigin::Initial;
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5e),
        observation: observation(0x7e),
        finding_candidate: None,
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V7);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, origin);
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5e).as_bytes());
    push_bytes(&mut payload, observation(0x7e).to_text().as_bytes());
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V7))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
}

#[test]
fn directory_ledger_reads_legacy_v8_candidate_as_pending() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x1f, 0x3f, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let candidate = finding_candidate(0x7f);
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5f),
        observation: observation(0x7f),
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V8);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, AttemptExecutionOrigin::Initial);
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5f).as_bytes());
    push_bytes(&mut payload, observation(0x7f).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(candidate));
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V8))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
    assert_eq!(state.pending_finding_candidate(), Some(candidate));
    assert!(!state.finding_candidate_acknowledged());
}

#[test]
fn directory_ledger_reads_legacy_v9_acknowledged_candidate() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x20, 0x40, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let candidate = finding_candidate(0x80);
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x60),
        observation: observation(0x80),
        finding_candidate: CompletedFindingCandidate::Acknowledged(candidate),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V9);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, AttemptExecutionOrigin::Initial);
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x60).as_bytes());
    push_bytes(&mut payload, observation(0x80).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(candidate));
    payload.push(1);
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V9))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy attempt state"),
        Some(state)
    );
    assert!(state.finding_candidate_acknowledged());
}

#[test]
fn directory_ledger_reads_legacy_v9_promotion_basis_as_execute_mode() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let request = request(0x21, 0x41, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let promotion_basis =
        CheckpointPromotionExecutionBasis::new(request.resources(), request.retention());
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x61),
        checkpoint: checkpoint(0x81),
        promotion_basis: Some(promotion_basis),
    };
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC_V9);
    push_bytes(&mut payload, request.lineage().to_text().as_bytes());
    push_bytes(&mut payload, request.attempt().to_text().as_bytes());
    payload.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut payload, AttemptExecutionOrigin::Initial);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x61).as_bytes());
    push_bytes(&mut payload, checkpoint(0x81).to_text().as_bytes());
    encode_legacy_checkpoint_promotion_basis(&mut payload, promotion_basis);
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN_V9))
        .expect("write legacy attempt state");

    assert_eq!(
        ledger.load_attempt(key).expect("load legacy paused state"),
        Some(state)
    );
    assert_eq!(promotion_basis.start_mode(), AttemptStartMode::Execute);
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

fn capture_request(
    assignment_byte: u8,
    attempt_byte: u8,
    vcpus: u32,
    configuration: ConfigurationArtifactId,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new_capture_materialized_start(
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
        configuration,
    )
    .expect("capture request")
}

fn configuration(byte: u8) -> ConfigurationArtifactId {
    ConfigurationArtifactId::parse(&typed_id(
        "crucible.campaign.configuration-artifact",
        "configuration",
        byte,
    ))
    .expect("configuration")
}

fn encode_legacy_checkpoint_promotion_basis(
    payload: &mut Vec<u8>,
    basis: CheckpointPromotionExecutionBasis,
) {
    payload.push(1);
    let resources = basis.resources();
    payload.extend_from_slice(&resources.maximum_vcpus().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_resident_bytes().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_disk_bytes().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_execution_quanta().to_be_bytes());
    payload.push(match basis.retention() {
        ExecutionRetentionIntent::Discard => 0,
        ExecutionRetentionIntent::RetainOnFailure => 1,
        ExecutionRetentionIntent::RetainAlways => 2,
    });
}

fn observation(byte: u8) -> ObservationId {
    ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        byte,
    ))
    .expect("observation")
}

fn finding_candidate(byte: u8) -> FindingCandidateBundleId {
    FindingCandidateBundleId::parse(&typed_id(
        "crucible.campaign.finding-candidate-bundle",
        "finding",
        byte,
    ))
    .expect("finding candidate")
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
