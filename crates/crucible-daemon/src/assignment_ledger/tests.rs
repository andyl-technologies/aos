//! Conformance tests for memory and crash-safe directory assignment ledgers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::symlink;

use crucible_campaign::{
    AttemptResourceLimits, AttemptStartMode, CampaignFactId, CampaignLineageId,
    ConfigurationArtifactId, ExecutionRetentionIntent, ExecutorRejection, SubmitAttemptDisposition,
};

use super::*;

#[test]
fn writer_owner_drop_releases_lock_held_by_a_duplicated_descriptor() {
    let directory = tempfile::tempdir().expect("ledger directory");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("first writer");
    let inherited = ledger
        .writer_lock
        .file()
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
fn directory_ledger_fences_a_replaced_root_and_writer_lock() {
    for replaced in ["root", "writer-lock"] {
        let parent = tempfile::tempdir().expect("ledger parent");
        let root = parent.path().join("ledger");
        fs::create_dir(&root).expect("ledger root");
        let mut ledger = DirectoryAssignmentLedger::open(&root).expect("ledger owner");
        let detached = parent.path().join(format!("detached-{replaced}"));

        if replaced == "root" {
            fs::rename(&root, &detached).expect("detach ledger root");
            fs::create_dir(&root).expect("replacement ledger root");
        } else {
            let lock = root.join("writer.lock");
            fs::rename(&lock, &detached).expect("detach writer lock");
            fs::write(&lock, []).expect("replacement writer lock");
        }

        let record = AssignmentRecord::new(
            request(0x15, 0x35, 1),
            SubmitAttemptResponse::new(
                &request(0x15, 0x35, 1),
                SubmitAttemptDisposition::Accepted {
                    execution: execution(0x55),
                },
            )
            .expect("response"),
        )
        .expect("record");
        assert!(ledger.publish_assignment(&record).is_err());
    }
}

#[test]
fn directory_ledger_rejects_stale_staging_at_open() {
    let directory = tempfile::tempdir().expect("ledger directory");
    {
        let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("initialize ledger");
        drop(ledger);
    }
    let shard = directory.path().join("attempts/ab");
    fs::create_dir_all(&shard).expect("attempt shard");
    fs::write(shard.join(".staging-12-34"), b"stale").expect("stale staging record");

    assert!(DirectoryAssignmentLedger::open(directory.path()).is_err());
}

#[test]
fn directory_ledger_rejects_a_writer_lock_symlink() {
    let parent = tempfile::tempdir().expect("ledger parent");
    let root = parent.path().join("ledger");
    fs::create_dir(&root).expect("ledger root");
    let target = parent.path().join("outside-lock");
    fs::write(&target, b"outside").expect("outside file");
    symlink(&target, root.join("writer.lock")).expect("writer lock symlink");

    assert!(DirectoryAssignmentLedger::open(&root).is_err());
    assert_eq!(fs::read(target).expect("outside bytes"), b"outside");
}

#[test]
fn directory_ledger_rejects_a_replaced_attempt_shard_without_external_access() {
    let parent = tempfile::tempdir().expect("ledger parent");
    let root = parent.path().join("ledger");
    fs::create_dir(&root).expect("ledger root");
    let mut ledger = DirectoryAssignmentLedger::open(&root).expect("ledger owner");
    let request = request(0x16, 0x36, 1);
    let key = AttemptExecutionKey::for_request(&request);
    let state = AttemptRuntimeState::Running {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x56),
    };
    ledger
        .compare_exchange_attempt(key, None, Some(state))
        .expect("publish initial state");

    let record = ledger.attempt_path(key);
    let shard = record.parent().expect("attempt shard").to_path_buf();
    let detached = parent.path().join("detached-shard");
    let outside = parent.path().join("outside-shard");
    fs::create_dir(&outside).expect("outside shard");
    let outside_record = outside.join(record.file_name().expect("record name"));
    let exact_bytes = fs::read(&record).expect("exact state bytes");
    fs::write(&outside_record, &exact_bytes).expect("outside state bytes");
    fs::rename(&shard, &detached).expect("detach attempt shard");
    symlink(&outside, &shard).expect("replace shard with symlink");

    for error in [
        ledger.load_attempt(key).expect_err("reject shard symlink"),
        ledger
            .compare_exchange_attempt(key, Some(state), None)
            .expect_err("reject shard symlink before mutation"),
    ] {
        let AssignmentLedgerError::Io { source, .. } = error else {
            panic!("shard symlink must fail during descriptor-relative resolution");
        };
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::LOOP.raw_os_error())
        );
    }
    assert_eq!(
        fs::read(&outside_record).expect("outside state remains"),
        exact_bytes
    );
    assert_eq!(
        fs::read_dir(&outside)
            .expect("outside shard inventory")
            .count(),
        1
    );
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
fn current_storage_digest_binds_every_scope_under_one_domain() {
    let semantic_request = request(0x17, 0x37, 1);
    let capture_request =
        savepoint_capture_request(0x18, 0x37, 1, campaign_fact(0x57), configuration(0x58));

    for key in [
        AttemptExecutionKey::for_request(&semantic_request),
        AttemptExecutionKey::for_request(&capture_request),
    ] {
        let mut material = Vec::new();
        push_bytes(&mut material, key.lineage().to_text().as_bytes());
        push_bytes(&mut material, key.attempt().to_text().as_bytes());
        push_bytes(&mut material, &key.scope().canonical_bytes());

        assert_eq!(
            key.storage_digest(),
            CampaignHash::derive("crucible.executor.attempt-execution-key.v2", &material)
        );
    }
}

#[test]
fn scoped_capture_and_semantic_attempt_states_are_physically_isolated() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let semantic = request(0x12, 0x32, 1);
    let capture =
        savepoint_capture_request(0x13, 0x32, 1, campaign_fact(0x52), configuration(0x53));
    let semantic_key = AttemptExecutionKey::for_request(&semantic);
    let capture_key = AttemptExecutionKey::for_request(&capture);
    let semantic_state = AttemptRuntimeState::Running {
        execution_basis: semantic.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: semantic.daemon_epoch(),
        execution: execution(0x54),
    };
    let capture_state = AttemptRuntimeState::CheckpointRequested {
        execution_basis: capture.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: capture.daemon_epoch(),
        execution: execution(0x55),
    };

    assert_eq!(semantic_key.scope(), AttemptExecutionScope::Semantic);
    assert_eq!(capture_key.scope(), capture.execution_scope());
    assert_ne!(semantic_key.storage_digest(), capture_key.storage_digest());

    let mut memory = MemoryAssignmentLedger::default();
    assert_eq!(
        memory
            .compare_exchange_attempt(semantic_key, None, Some(semantic_state))
            .expect("store semantic state"),
        AttemptStateCas::Advanced
    );
    assert_eq!(
        memory
            .compare_exchange_attempt(capture_key, None, Some(capture_state))
            .expect("store capture state"),
        AttemptStateCas::Advanced
    );
    assert_eq!(memory.load_attempt(semantic_key), Ok(Some(semantic_state)));
    assert_eq!(memory.load_attempt(capture_key), Ok(Some(capture_state)));

    let mut durable = DirectoryAssignmentLedger::open(directory.path()).expect("durable ledger");
    assert_ne!(
        durable.attempt_path(semantic_key),
        durable.attempt_path(capture_key)
    );
    durable
        .compare_exchange_attempt(semantic_key, None, Some(semantic_state))
        .expect("store durable semantic state");
    durable
        .compare_exchange_attempt(capture_key, None, Some(capture_state))
        .expect("store durable capture state");
    assert_eq!(
        durable
            .load_attempt(semantic_key)
            .expect("load semantic state"),
        Some(semantic_state)
    );
    assert_eq!(
        durable
            .load_attempt(capture_key)
            .expect("load capture state"),
        Some(capture_state)
    );
}

#[test]
fn scoped_capture_state_rejects_semantic_and_mismatched_promotion_shapes() {
    let capture =
        savepoint_capture_request(0x14, 0x34, 1, campaign_fact(0x56), configuration(0x57));
    let key = AttemptExecutionKey::for_request(&capture);
    let running = AttemptRuntimeState::Running {
        execution_basis: capture.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: capture.daemon_epoch(),
        execution: execution(0x58),
    };
    let wrong_promotion = AttemptRuntimeState::Paused {
        execution_basis: capture.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: capture.daemon_epoch(),
        execution: execution(0x58),
        checkpoint: checkpoint(0x59),
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            capture.resources(),
            capture.retention(),
            AttemptStartMode::CaptureMaterializedStart {
                configuration: configuration(0x57),
            },
            capture.retention_policy(),
        )),
    };
    let mut memory = MemoryAssignmentLedger::default();

    assert_eq!(
        memory.compare_exchange_attempt(key, None, Some(running)),
        Ok(AttemptStateCas::Conflict { current: None })
    );
    assert_eq!(
        memory.compare_exchange_attempt(key, None, Some(wrong_promotion)),
        Ok(AttemptStateCas::Conflict { current: None })
    );
    assert!(decode_attempt_state(&encode_attempt_state(key, wrong_promotion)).is_err());
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
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
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
        request.retention_policy(),
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
            request.retention_policy(),
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
            capture.retention_policy(),
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
            execute.retention_policy(),
        )),
    };
    let encoded_execute = encode_attempt_state(
        AttemptExecutionKey::new(execute.lineage(), execute.attempt()),
        execute_state,
    );
    let mut payload = open_sealed(&encoded_execute, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .expect("open current attempt state")
        .to_vec();
    let start_mode_tag = payload
        .len()
        .checked_sub(2)
        .expect("start mode precedes retention policy");
    payload[start_mode_tag] = 0xff;
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
fn selected_origin_round_trips_and_retains_certificate_resume_and_output_roots() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let submit = request(0x1a, 0x3a, 1);
    let key = AttemptExecutionKey::new(submit.lineage(), submit.attempt());
    let source = checkpoint(0x7b);
    let resume = checkpoint(0x7c);
    let output = checkpoint(0x7d);
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact(0x8a),
        request: campaign_fact(0x8b),
        source_attempt: request(0x2a, 0x4a, 1).attempt(),
        source_execution: execution(0x5b),
        source_checkpoint: source,
        resume: Some(ExactCheckpointResumeBasis {
            assignment: AssignmentId::from_bytes([0x6b; 16]).expect("resume assignment"),
            request_digest: CampaignHash::derive("crucible.test.selected-resume.v1", b"resume"),
            prior_execution: execution(0x5c),
            checkpoint: resume,
        }),
    };
    let state = AttemptRuntimeState::CheckpointPublishing {
        execution_basis: submit.execution_basis_digest(),
        origin,
        daemon_epoch: submit.daemon_epoch(),
        execution: execution(0x5d),
        checkpoint: output,
    };

    {
        let mut ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open durable ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(state))
                .expect("publish selected resumed state"),
            AttemptStateCas::Advanced
        );
    }

    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("reopen durable ledger");
    assert_eq!(
        ledger.load_attempt(key).expect("load selected state"),
        Some(state)
    );
    let mut roots = Vec::new();
    ledger
        .visit_checkpoint_roots(&mut |checkpoint| roots.push(checkpoint))
        .expect("visit selected checkpoint roots");
    roots.sort();
    assert_eq!(roots, vec![source, resume, output]);
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
        let encoded = encode_hex(&request.assignment().as_bytes());
        directory
            .path()
            .join("assignments")
            .join(&encoded[..2])
            .join(encoded)
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

fn request(assignment_byte: u8, attempt_byte: u8, vcpus: u32) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x21; 16]).expect("daemon epoch"),
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x41,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            9,
            attempt_byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(vcpus, 4096, 8192, 16).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .expect("request")
}

fn capture_request(
    assignment_byte: u8,
    attempt_byte: u8,
    vcpus: u32,
    configuration: ConfigurationArtifactId,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x21; 16]).expect("daemon epoch"),
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x41,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            9,
            attempt_byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(vcpus, 4096, 8192, 16).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_capture_materialized_start(assignment, configuration)
    })
    .expect("capture request")
}

fn savepoint_capture_request(
    assignment_byte: u8,
    attempt_byte: u8,
    vcpus: u32,
    request: CampaignFactId,
    configuration: ConfigurationArtifactId,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x21; 16]).expect("daemon epoch"),
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            1,
            0x41,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            9,
            attempt_byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(vcpus, 4096, 8192, 16).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_savepoint_capture(assignment, request, configuration)
    })
    .expect("savepoint capture request")
}

fn campaign_fact(byte: u8) -> CampaignFactId {
    CampaignFactId::parse(&format!(
        "crucible.campaign.fact@campaign-fact.15.{}",
        encode_hex(&[byte; 32])
    ))
    .expect("campaign fact")
}

fn configuration(byte: u8) -> ConfigurationArtifactId {
    ConfigurationArtifactId::parse(&typed_id(
        "crucible.campaign.configuration-artifact",
        "configuration",
        1,
        byte,
    ))
    .expect("configuration")
}

fn observation(byte: u8) -> ObservationId {
    ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        13,
        byte,
    ))
    .expect("observation")
}

fn finding_candidate(byte: u8) -> FindingCandidateBundleId {
    FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@finding.7.{}",
        encode_hex(&[byte; 32])
    ))
    .expect("finding candidate")
}

fn checkpoint(byte: u8) -> ExactCheckpointId {
    ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        encode_hex(&[byte; 32])
    ))
    .expect("checkpoint")
}

fn execution(byte: u8) -> ExecutionId {
    ExecutionId::from_bytes([byte; 16]).expect("execution")
}

fn typed_id(tag: &str, kind: &str, version: u32, byte: u8) -> String {
    format!("{tag}@{kind}.{version}.{}", encode_hex(&[byte; 32]))
}
