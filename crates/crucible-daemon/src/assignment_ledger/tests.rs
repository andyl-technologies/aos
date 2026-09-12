//! Conformance tests for memory and crash-safe directory assignment ledgers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::symlink;

use crucible_campaign::{
    AttemptResourceLimits, AttemptStartMode, CampaignFactId, CampaignLineageId,
    ConfigurationArtifactId, ExecutionRetentionIntent, ExecutorRejection, SubmitAttemptDisposition,
};

use super::*;

#[test]
fn existing_ledger_open_never_initializes_missing_state() {
    let temporary = tempfile::tempdir().expect("ledger parent");
    let root = temporary.path().join("ledger");

    assert!(DirectoryAssignmentLedger::open_existing(&root).is_err());
    assert!(!root.exists());

    drop(DirectoryAssignmentLedger::open(&root).expect("initialize ledger"));
    let ledger = DirectoryAssignmentLedger::open_existing(&root).expect("open existing ledger");
    assert_eq!(ledger.root(), root);
    drop(ledger);

    fs::rename(
        root.join(RETENTION_STATE_FILE),
        root.join("real-retention-state"),
    )
    .expect("move real retention state");
    symlink("real-retention-state", root.join(RETENTION_STATE_FILE))
        .expect("replace retention state with symlink");
    assert!(DirectoryAssignmentLedger::open_existing(&root).is_err());
    fs::remove_file(root.join(RETENTION_STATE_FILE)).expect("remove retention symlink");
    fs::rename(
        root.join("real-retention-state"),
        root.join(RETENTION_STATE_FILE),
    )
    .expect("restore retention state");

    fs::rename(root.join("writer.lock"), root.join("real.lock")).expect("move real lock");
    symlink("real.lock", root.join("writer.lock")).expect("replace lock with symlink");
    assert!(DirectoryAssignmentLedger::open_existing(&root).is_err());
}

#[test]
fn optional_retention_reader_treats_only_a_missing_root_as_empty() {
    let temporary = tempfile::tempdir().expect("ledger parent");
    let root = temporary.path().join("optional-ledger");

    let mut absent = DirectoryAssignmentRetentionReader::open_optional_existing(&root)
        .expect("missing optional ledger");
    assert!(!absent.is_present());
    let summary = absent
        .acquire_retention_fence()
        .expect("absent ledger fence")
        .visit_roots(&mut |_| Ok(()))
        .expect("empty absent inventory");
    assert_eq!(summary.attempt_records(), 0);
    assert_eq!(summary.observation_roots(), 0);
    assert_eq!(summary.checkpoint_roots(), 0);
    drop(absent);
    assert!(!root.exists());

    fs::write(&root, b"not a ledger").expect("write malformed ledger root");
    assert!(DirectoryAssignmentRetentionReader::open_optional_existing(&root).is_err());
    fs::remove_file(&root).expect("remove malformed ledger root");
    fs::create_dir(&root).expect("create incomplete ledger root");
    assert!(DirectoryAssignmentRetentionReader::open_optional_existing(&root).is_err());
    assert!(
        fs::read_dir(&root)
            .expect("read incomplete ledger")
            .next()
            .is_none()
    );

    fs::remove_dir(&root).expect("remove incomplete ledger root");
    drop(DirectoryAssignmentLedger::open(&root).expect("initialize ledger"));
    let present = DirectoryAssignmentRetentionReader::open_optional_existing(&root)
        .expect("open existing optional ledger");
    assert!(present.is_present());
}

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
fn writer_lock_replacement_during_open_fails_closed() {
    let directory = tempfile::tempdir().expect("ledger directory");
    let moved_parent = tempfile::tempdir().expect("moved lock parent");
    drop(DirectoryAssignmentLedger::open(directory.path()).expect("initialize ledger"));
    let lock = directory.path().join("writer.lock");
    let moved = moved_parent.path().join("writer.lock");
    crate::owned_advisory_lock::install_lock_race_hook({
        let lock = lock.clone();
        let moved = moved.clone();
        move || {
            fs::rename(&lock, &moved).expect("move locked file");
            fs::write(&lock, b"replacement").expect("replace lock file");
        }
    });

    assert!(DirectoryAssignmentLedger::open_existing(directory.path()).is_err());
    assert_eq!(fs::read(lock).expect("replacement remains"), b"replacement");
}

#[test]
fn writer_lock_replacement_after_open_blocks_subsequent_mutation() {
    let directory = tempfile::tempdir().expect("ledger directory");
    let moved_parent = tempfile::tempdir().expect("moved lock parent");
    let mut ledger = DirectoryAssignmentLedger::open(directory.path()).expect("first writer");
    let lock = directory.path().join("writer.lock");
    let moved = moved_parent.path().join("writer.lock");
    fs::rename(&lock, &moved).expect("move locked file");
    fs::write(&lock, b"replacement").expect("replace lock file");
    let replacement_inode = fs::metadata(&lock).expect("replacement metadata").ino();
    let second = DirectoryAssignmentLedger::open_existing(directory.path())
        .expect("replacement lock has an independent owner");

    let request = request(0x71, 0x72, 1);
    let response = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::Accepted {
            execution: execution(0x73),
        },
    )
    .expect("accepted response");
    let record = AssignmentRecord::new(request, response).expect("assignment record");
    assert!(ledger.publish_assignment(&record).is_err());
    assert_eq!(
        fs::metadata(&lock).expect("replacement survives").ino(),
        replacement_inode
    );
    drop(second);
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
        prepared_result_digest: Some(CampaignHash::derive(
            "crucible.test.prepared-result",
            b"current completed payload",
        )),
    };
    let publishing = AttemptRuntimeState::Publishing {
        execution_basis,
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x51),
        observation: observation(0x71),
        finding_candidate: Some(finding_candidate(0x72)),
        finding_replay_captures: None,
        finding_exact_retention_roots: [Some(checkpoint(0x73)), Some(checkpoint(0x74)), None],
        prepared_result_digest: None,
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
        let mut checkpoint_roots = Vec::new();
        ledger
            .visit_checkpoint_roots(&mut |root| checkpoint_roots.push(root))
            .expect("stream publishing exact roots");
        assert_eq!(checkpoint_roots, vec![checkpoint(0x73), checkpoint(0x74)]);
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
fn publishing_exact_roots_require_a_dense_sorted_candidate_owned_set() {
    let request = request(0x14, 0x34, 1);
    let key = AttemptExecutionKey::for_request(&request);
    let publishing =
        |finding_candidate, finding_exact_retention_roots| AttemptRuntimeState::Publishing {
            execution_basis: request.execution_basis_digest(),
            origin: AttemptExecutionOrigin::Initial,
            daemon_epoch: request.daemon_epoch(),
            execution: execution(0x54),
            observation: observation(0x74),
            finding_candidate,
            finding_replay_captures: None,
            finding_exact_retention_roots,
            prepared_result_digest: None,
        };
    let invalid = [
        publishing(None, [Some(checkpoint(0x81)), None, None]),
        publishing(
            Some(finding_candidate(0x75)),
            [None, Some(checkpoint(0x81)), None],
        ),
        publishing(
            Some(finding_candidate(0x75)),
            [Some(checkpoint(0x81)), Some(checkpoint(0x81)), None],
        ),
        publishing(
            Some(finding_candidate(0x75)),
            [Some(checkpoint(0x82)), Some(checkpoint(0x81)), None],
        ),
    ];

    for state in invalid {
        let mut ledger = MemoryAssignmentLedger::default();
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(state))
                .expect("infallible ledger"),
            AttemptStateCas::Conflict { current: None }
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
fn unsupported_attempt_state_schema_fails_closed() {
    let request = request(0x2c, 0x4c, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Running {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x6c),
    };
    let encoded = encode_attempt_state(key, state);
    let mut payload = open_sealed(&encoded, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .expect("open current attempt state")
        .to_vec();
    payload[ATTEMPT_STATE_MAGIC.len() - 3] = b'x';

    assert!(matches!(
        decode_attempt_state(&seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "record-magic"
        })
    ));
}

#[test]
fn migration_v14_publishing_preserves_the_prepared_result_digest() {
    let request = request(0x2c, 0x4c, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x6c),
        observation: observation(0x8d),
        finding_candidate: Some(finding_candidate(0x8e)),
        finding_replay_captures: None,
        finding_exact_retention_roots: [Some(checkpoint(0x8f)), None, None],
        prepared_result_digest: Some(CampaignHash::derive(
            "crucible.test.prepared-result",
            b"legacy v14 publishing payload",
        )),
    };
    let encoded = encode_attempt_state(key, state);
    let mut payload = open_sealed(&encoded, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .expect("open current publishing state")
        .to_vec();
    assert_eq!(ATTEMPT_STATE_MAGIC.len(), legacy_magic(14).len());
    payload[..ATTEMPT_STATE_MAGIC.len()].copy_from_slice(&legacy_magic(14));
    let legacy = seal(payload, &legacy_domain(14));

    assert!(decode_attempt_state(&legacy).is_err());
    assert_eq!(
        decode_migratable_attempt_state(&legacy).expect("decode migratable v14 publishing state"),
        (key, state)
    );
}

#[test]
fn assignment_migration_validates_all_records_before_replacement() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let first_request = request(0x2d, 0x4d, 1);
    let first_key = AttemptExecutionKey::new(first_request.lineage(), first_request.attempt());
    let first_state = publishing_state(&first_request, 0x6d, 0x8d);
    let first_path = write_v14_attempt_state(&ledger, first_key, first_state);
    let second_request = request(0x2e, 0x4e, 1);
    let second_key = AttemptExecutionKey::new(second_request.lineage(), second_request.attempt());
    let second_path = ledger.attempt_path(second_key);
    fs::create_dir_all(second_path.parent().expect("second record parent"))
        .expect("create second record parent");
    fs::write(&second_path, b"corrupt attempt record").expect("write corrupt record");

    assert!(ledger.migrate_attempt_records_for_test(2).is_err());
    let unchanged = fs::read(first_path).expect("read unchanged legacy record");
    assert!(decode_attempt_state(&unchanged).is_err());
    assert_eq!(
        decode_migratable_attempt_state(&unchanged).expect("authenticate unchanged legacy record"),
        (first_key, first_state)
    );
}

#[test]
fn assignment_migration_rejects_a_raced_forged_receipt_before_replacement() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x36, 0x56, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = publishing_state(&request, 0x76, 0x96);
    let record = write_v14_attempt_state(&ledger, key, state);
    let original = fs::read(&record).expect("legacy source");
    let receipt_parent = tempfile::tempdir().expect("receipt parent");
    let receipt_path = receipt_parent.path().join("receipt");
    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &receipt_path,
    )
    .expect("receipt directory");
    crate::operational_state_migration::receipt::install_receipt_publish_race_hook({
        let destination =
            receipt_path.join(crate::operational_state_migration::receipt::ASSIGNMENT_RECEIPT);
        move || fs::write(destination, b"forged receipt").expect("install forged receipt")
    });

    assert!(matches!(
        ledger.migrate_attempt_records(&receipt, 257, u64::MAX),
        Err(crate::OperationalStateMigrationError::InvalidReceipt)
    ));
    assert_eq!(fs::read(record).expect("legacy source remains"), original);
}

#[test]
fn assignment_migration_resumes_a_mixed_current_and_v14_inventory() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let mut ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let current_request = request(0x2f, 0x4f, 1);
    let current_key =
        AttemptExecutionKey::new(current_request.lineage(), current_request.attempt());
    let current_state = publishing_state(&current_request, 0x6f, 0x8f);
    assert_eq!(
        ledger
            .compare_exchange_attempt(current_key, None, Some(current_state))
            .expect("write current record"),
        AttemptStateCas::Advanced
    );
    let legacy_request = request(0x30, 0x50, 1);
    let legacy_key = AttemptExecutionKey::new(legacy_request.lineage(), legacy_request.attempt());
    let legacy_state = publishing_state(&legacy_request, 0x70, 0x90);
    write_v14_attempt_state(&ledger, legacy_key, legacy_state);

    let summary = ledger
        .migrate_attempt_records_for_test(2)
        .expect("resume mixed migration");
    assert_eq!(summary.records, 2);
    assert_eq!(summary.migrated, 1);
    assert_eq!(
        ledger.load_attempt(current_key).expect("current state"),
        Some(current_state)
    );
    assert_eq!(
        ledger.load_attempt(legacy_key).expect("migrated state"),
        Some(legacy_state)
    );
}

#[test]
fn assignment_migration_reconciles_bounded_orphan_staging() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x31, 0x51, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = publishing_state(&request, 0x71, 0x91);
    let record = write_v14_attempt_state(&ledger, key, state);
    let staging = record
        .parent()
        .expect("attempt shard")
        .join(".staging-123-456");
    let stale_bytes = b"interrupted staging bytes";
    fs::write(&staging, stale_bytes).expect("stale staging");
    let metadata = staging.metadata().expect("staging metadata");
    let quarantine = staging.with_file_name(format!(
        ".{}.removing-v1-{:x}-{:x}",
        staging.file_name().expect("staging name").to_string_lossy(),
        metadata.dev(),
        metadata.ino()
    ));

    let receipt_parent = tempfile::tempdir().expect("receipt parent");
    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &receipt_parent.path().join("receipt"),
    )
    .expect("receipt directory");
    let summary = ledger
        .migrate_attempt_records(&receipt, 258, u64::MAX)
        .expect("resume with stale staging");
    assert_eq!(summary.migrated, 1);
    assert!(!staging.exists());
    assert_eq!(quarantine.metadata().expect("cleanup tombstone").len(), 0);
    assert_eq!(
        ledger.load_attempt(key).expect("migrated state"),
        Some(state)
    );

    fs::write(&quarantine, stale_bytes).expect("restore post-rename crash bytes");

    ledger
        .migrate_attempt_records(&receipt, 258, u64::MAX)
        .expect("finish interrupted staging removal");
    assert_eq!(quarantine.metadata().expect("finished tombstone").len(), 0);
    let stable_entries = fs::read_dir(record.parent().expect("attempt shard"))
        .expect("inventory shard")
        .count();
    for _ in 0..3 {
        ledger
            .migrate_attempt_records(&receipt, 258, u64::MAX)
            .expect("repeat idempotent migration");
    }
    assert_eq!(
        fs::read_dir(record.parent().expect("attempt shard"))
            .expect("inventory shard")
            .count(),
        stable_entries
    );

    let forged_source = record
        .parent()
        .expect("attempt shard")
        .join(".staging-forged");
    fs::write(&forged_source, stale_bytes).expect("same-bytes forged staging");
    let metadata = forged_source.metadata().expect("forged metadata");
    let forged = forged_source.with_file_name(format!(
        ".staging-forged.removing-v1-{:x}-{:x}",
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(forged_source, &forged).expect("publish forged quarantine");
    assert!(
        ledger
            .migrate_attempt_records(&receipt, 258, u64::MAX)
            .is_err()
    );
    assert!(forged.exists());
}

#[test]
fn assignment_migration_recovers_an_interrupted_destination_write() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x34, 0x54, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = publishing_state(&request, 0x74, 0x94);
    let record = write_v14_attempt_state(&ledger, key, state);
    let current = encode_attempt_state(key, state);
    let receipt_parent = tempfile::tempdir().expect("receipt parent");
    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &receipt_parent.path().join("receipt"),
    )
    .expect("receipt directory");

    let staging = record
        .parent()
        .expect("attempt shard")
        .join(".staging-123-456");
    fs::write(&staging, &current).expect("retain staged current record");
    fs::write(&record, &current[..current.len() / 2]).expect("interrupt destination write");

    ledger
        .migrate_attempt_records(&receipt, 257, u64::MAX)
        .expect("resume interrupted destination write");
    assert_eq!(
        ledger.load_attempt(key).expect("current state"),
        Some(state)
    );
    assert!(!staging.exists());
}

#[test]
fn assignment_generated_staging_cleanup_is_presealed_and_resumable() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x35, 0x55, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = publishing_state(&request, 0x75, 0x95);
    let record = write_v14_attempt_state(&ledger, key, state);
    let current = encode_attempt_state(key, state);
    let receipt_parent = tempfile::tempdir().expect("receipt parent");
    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &receipt_parent.path().join("receipt"),
    )
    .expect("receipt directory");

    let summary = ledger
        .migrate_attempt_records(&receipt, 257, u64::MAX)
        .expect("migrate with generated staging");
    let shard = record.parent().expect("attempt shard");
    let quarantine = fs::read_dir(shard)
        .expect("inventory generated cleanup")
        .map(|entry| entry.expect("staging entry"))
        .find(|entry| {
            crate::anchored_fs::removal_original_name(&entry.file_name())
                .as_deref()
                .and_then(|name| name.to_str())
                .is_some_and(super::is_staging_name)
        })
        .expect("generated staging tombstone")
        .path();
    assert_eq!(quarantine.metadata().expect("tombstone").len(), 0);
    assert!(summary.receipt.objects.iter().any(|object| {
        object.source_object_id
            == crate::operational_state_migration::receipt::authenticated_id(
                "crucible.assignment-migration-cleanup-source.v1",
                &[&current],
            )
    }));

    fs::write(&quarantine, &current).expect("restore post-rename generated stage");
    ledger
        .migrate_attempt_records(&receipt, 257, u64::MAX)
        .expect("resume generated staging destruction");
    assert_eq!(quarantine.metadata().expect("resumed tombstone").len(), 0);
}

#[test]
fn runtime_open_rejects_unfenced_assignment_staging() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let mut ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x32, 0x52, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = publishing_state(&request, 0x72, 0x92);
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("write current record"),
        AttemptStateCas::Advanced
    );
    let record = super::attempt_path_at(directory.path(), key);
    let staging = record
        .parent()
        .expect("attempt shard")
        .join(".staging-123-456");
    fs::write(&staging, b"interrupted staging bytes").expect("stale staging");
    drop(ledger);

    assert!(DirectoryAssignmentLedger::open_existing(directory.path()).is_err());
    fs::remove_file(&staging).expect("remove unfenced staging");
    fs::write(&staging, []).expect("empty forged staging");
    let metadata = staging.metadata().expect("forged staging identity");
    let forged = staging.with_file_name(format!(
        ".{}.removing-v1-{:x}-{:x}",
        staging.file_name().expect("staging name").to_string_lossy(),
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(staging, &forged).expect("publish unsealed tombstone");
    assert!(DirectoryAssignmentLedger::open_existing(directory.path()).is_err());
}

#[test]
fn assignment_migration_rejects_unknown_root_entries() {
    for kind in ["file", "directory", "symlink"] {
        let directory = tempfile::tempdir().expect("ledger tempdir");
        let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
        let junk = directory.path().join(format!("unknown-{kind}"));
        match kind {
            "file" => fs::write(&junk, b"junk").expect("junk file"),
            "directory" => fs::create_dir(&junk).expect("junk directory"),
            "symlink" => std::os::unix::fs::symlink("missing", &junk).expect("junk symlink"),
            _ => unreachable!(),
        }

        assert!(ledger.migrate_attempt_records_for_test(1).is_err());
        drop(ledger);
        assert!(DirectoryAssignmentLedger::open_existing(directory.path()).is_err());
    }
}

#[test]
fn assignment_migration_destination_replacement_fails_pinned_commit_check() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("ledger");
    let request = request(0x33, 0x53, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let record = write_v14_attempt_state(&ledger, key, publishing_state(&request, 0x73, 0x93));
    let source = ledger
        .authority()
        .open_regular_optional(&record, "pin-test-migration-source")
        .expect("open source")
        .expect("source exists");
    let moved = record.with_extension("moved");
    fs::rename(&record, &moved).expect("move authenticated destination");
    fs::write(&record, b"replacement").expect("replace destination");

    assert!(source.replace_contents(b"staged-current").is_err());
    assert_eq!(
        fs::read(&record).expect("replacement bytes"),
        b"replacement"
    );
    assert_ne!(
        fs::read(&moved).expect("moved source bytes"),
        b"staged-current"
    );
}

fn publishing_state(
    request: &SubmitAttemptRequest,
    execution_marker: u8,
    observation_marker: u8,
) -> AttemptRuntimeState {
    AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(execution_marker),
        observation: observation(observation_marker),
        finding_candidate: None,
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    }
}

fn write_v14_attempt_state(
    ledger: &DirectoryAssignmentLedger,
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
) -> PathBuf {
    let encoded = encode_attempt_state(key, state);
    let mut payload = open_sealed(&encoded, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .expect("open current state")
        .to_vec();
    payload[..ATTEMPT_STATE_MAGIC.len()].copy_from_slice(&legacy_magic(14));
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt record parent"))
        .expect("create attempt record parent");
    fs::write(&path, seal(payload, &legacy_domain(14))).expect("write v14 attempt record");
    path
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
    {
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
        let path = ledger.assignment_path(request.assignment());
        fs::write(path, b"truncated-record").expect("corrupt assignment file");
    }

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
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
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
    assert!(
        roots.contains(&AssignmentRetentionRoot::PublishingObservation(
            observation(0x81)
        ))
    );
    assert!(roots.contains(&AssignmentRetentionRoot::ExactCheckpoint(checkpoint(0x82))));
    assert!(
        roots.contains(&AssignmentRetentionRoot::PublishingFindingCandidate(
            finding_candidate(0x91)
        ))
    );

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
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
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
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
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

fn legacy_domain(version: u8) -> String {
    format!("crucible.executor.attempt-state-record.v{version}")
}

fn legacy_magic(version: u8) -> Vec<u8> {
    let mut magic = legacy_domain(version).into_bytes();
    magic.push(0);
    magic
}

fn legacy_attempt_payload(
    version: u8,
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&legacy_magic(version));
    push_bytes(&mut payload, key.lineage().to_text().as_bytes());
    push_bytes(&mut payload, key.attempt().to_text().as_bytes());
    if version >= 11 {
        push_bytes(&mut payload, &key.scope().canonical_bytes());
    }
    payload.extend_from_slice(&state.execution_basis().as_bytes());
    if version >= 4 {
        encode_attempt_origin(&mut payload, state.origin());
    }
    payload
}

fn persist_and_assert_legacy_migration(
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
    payload: Vec<u8>,
    version: u8,
) {
    let directory = tempfile::tempdir().expect("legacy ledger tempdir");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open legacy ledger");
    let path = ledger.attempt_path(key);
    fs::create_dir_all(path.parent().expect("attempt-state parent"))
        .expect("create legacy attempt-state parent");
    fs::write(path, seal(payload, &legacy_domain(version))).expect("write legacy attempt state");

    let summary = ledger
        .migrate_attempt_records_for_test(256)
        .expect("migrate legacy attempt record");
    assert_eq!(summary.migrated, 1);
    assert_eq!(
        ledger.load_attempt(key).expect("load migrated state"),
        Some(state)
    );
}

#[test]
fn every_legacy_assignment_version_migrates_to_v15() {
    let request = self::request(0x15, 0x35, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x55),
        observation: observation(0x75),
        finding_candidate: CompletedFindingCandidate::None,
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(1, key, state);
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x55).as_bytes());
    push_bytes(&mut payload, observation(0x75).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 1);

    let request = self::request(0x16, 0x36, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x56),
        observation: observation(0x76),
        finding_candidate: None,
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(2, key, state);
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x56).as_bytes());
    push_bytes(&mut payload, observation(0x76).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 2);

    let request = self::request(0x17, 0x37, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x57),
        checkpoint: checkpoint(0x77),
        promotion_basis: None,
    };

    let mut payload = legacy_attempt_payload(3, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x57).as_bytes());
    push_bytes(&mut payload, checkpoint(0x77).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 3);

    let request = self::request(0x19, 0x39, 1);
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

    let mut payload = legacy_attempt_payload(4, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x59).as_bytes());
    push_bytes(&mut payload, checkpoint(0x79).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 4);

    let request = self::request(0x1a, 0x3a, 1);
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

    let mut payload = legacy_attempt_payload(5, key, state);
    payload.push(7);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5a).as_bytes());
    push_bytes(&mut payload, checkpoint(0x7a).to_text().as_bytes());
    push_bytes(&mut payload, checkpoint(0x7b).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 5);

    let request = self::request(0x1d, 0x3d, 1);
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

    let mut payload = legacy_attempt_payload(6, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5d).as_bytes());
    push_bytes(&mut payload, checkpoint(0x7d).to_text().as_bytes());
    encode_legacy_checkpoint_promotion_basis(&mut payload, promotion_basis);
    persist_and_assert_legacy_migration(key, state, payload, 6);

    let request = self::request(0x1e, 0x3e, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let origin = AttemptExecutionOrigin::Initial;
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5e),
        observation: observation(0x7e),
        finding_candidate: None,
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(7, key, state);
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5e).as_bytes());
    push_bytes(&mut payload, observation(0x7e).to_text().as_bytes());
    persist_and_assert_legacy_migration(key, state, payload, 7);

    let request = self::request(0x1f, 0x3f, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let candidate = finding_candidate(0x7f);
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x5f),
        observation: observation(0x7f),
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(8, key, state);
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x5f).as_bytes());
    push_bytes(&mut payload, observation(0x7f).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(candidate));
    persist_and_assert_legacy_migration(key, state, payload, 8);

    let request = self::request(0x20, 0x40, 1);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let candidate = finding_candidate(0x80);
    let state = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x60),
        observation: observation(0x80),
        finding_candidate: CompletedFindingCandidate::Acknowledged(candidate),
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(9, key, state);
    payload.push(1);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x60).as_bytes());
    push_bytes(&mut payload, observation(0x80).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(candidate));
    payload.push(1);
    persist_and_assert_legacy_migration(key, state, payload, 9);

    let request = self::request(0x21, 0x41, 1);
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

    let mut payload = legacy_attempt_payload(9, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x61).as_bytes());
    push_bytes(&mut payload, checkpoint(0x81).to_text().as_bytes());
    encode_legacy_checkpoint_promotion_basis(&mut payload, promotion_basis);
    persist_and_assert_legacy_migration(key, state, payload, 9);

    let configuration = configuration(0x91);
    let request = capture_request(0x22, 0x42, 1, configuration);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let promotion_basis = CheckpointPromotionExecutionBasis::new_for_start_mode(
        request.resources(),
        request.retention(),
        request.start_mode(),
    );
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x62),
        checkpoint: checkpoint(0x82),
        promotion_basis: Some(promotion_basis),
    };

    let mut payload = legacy_attempt_payload(10, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x62).as_bytes());
    push_bytes(&mut payload, checkpoint(0x82).to_text().as_bytes());
    encode_checkpoint_promotion_basis(&mut payload, Some(promotion_basis));
    persist_and_assert_legacy_migration(key, state, payload, 10);

    let capture_fact = campaign_fact(0x92);
    let request = savepoint_capture_request(0x23, 0x43, 1, capture_fact, self::configuration(0x93));
    let key = AttemptExecutionKey::for_request(&request);
    let promotion_basis = CheckpointPromotionExecutionBasis::new_for_start_mode(
        request.resources(),
        request.retention(),
        request.start_mode(),
    );
    let state = AttemptRuntimeState::Paused {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x63),
        checkpoint: checkpoint(0x83),
        promotion_basis: Some(promotion_basis),
    };

    let mut payload = legacy_attempt_payload(11, key, state);
    payload.push(6);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x63).as_bytes());
    push_bytes(&mut payload, checkpoint(0x83).to_text().as_bytes());
    encode_checkpoint_promotion_basis(&mut payload, Some(promotion_basis));
    persist_and_assert_legacy_migration(key, state, payload, 11);

    let request = self::request(0x71, 0x72, 1);
    let key = AttemptExecutionKey::for_request(&request);
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x73),
        observation: observation(0x74),
        finding_candidate: Some(finding_candidate(0x75)),
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(12, key, state);
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x73).as_bytes());
    push_bytes(&mut payload, observation(0x74).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(finding_candidate(0x75)));
    persist_and_assert_legacy_migration(key, state, payload, 12);

    let request = self::request(0x76, 0x77, 1);
    let key = AttemptExecutionKey::for_request(&request);
    let state = AttemptRuntimeState::Publishing {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: execution(0x78),
        observation: observation(0x79),
        finding_candidate: Some(finding_candidate(0x7a)),
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    };

    let mut payload = legacy_attempt_payload(13, key, state);
    payload.push(3);
    payload.extend_from_slice(&request.daemon_epoch().as_bytes());
    payload.extend_from_slice(&execution(0x78).as_bytes());
    push_bytes(&mut payload, observation(0x79).to_text().as_bytes());
    encode_optional_finding_candidate(&mut payload, Some(finding_candidate(0x7a)));
    encode_optional_finding_replay_captures(&mut payload, None);
    persist_and_assert_legacy_migration(key, state, payload, 13);
}

#[test]
fn v11_rejects_v12_selected_origin_and_promotion_tags() {
    let request = request(0x24, 0x44, 1);
    let key = AttemptExecutionKey::for_request(&request);

    let mut selected_origin = Vec::with_capacity(512);
    selected_origin.extend_from_slice(&legacy_magic(11));
    push_bytes(&mut selected_origin, request.lineage().to_text().as_bytes());
    push_bytes(&mut selected_origin, request.attempt().to_text().as_bytes());
    push_bytes(
        &mut selected_origin,
        &request.execution_scope().canonical_bytes(),
    );
    selected_origin.extend_from_slice(&request.execution_basis_digest().as_bytes());
    selected_origin.push(2);
    assert!(matches!(
        decode_migratable_attempt_state(&seal(selected_origin, &legacy_domain(11),)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "attempt-state-origin-unknown-tag"
        })
    ));

    let mut selected_promotion = Vec::with_capacity(512);
    selected_promotion.extend_from_slice(&legacy_magic(11));
    push_bytes(
        &mut selected_promotion,
        request.lineage().to_text().as_bytes(),
    );
    push_bytes(
        &mut selected_promotion,
        request.attempt().to_text().as_bytes(),
    );
    push_bytes(
        &mut selected_promotion,
        &request.execution_scope().canonical_bytes(),
    );
    selected_promotion.extend_from_slice(&request.execution_basis_digest().as_bytes());
    encode_attempt_origin(&mut selected_promotion, AttemptExecutionOrigin::Initial);
    selected_promotion.push(6);
    selected_promotion.extend_from_slice(&request.daemon_epoch().as_bytes());
    selected_promotion.extend_from_slice(&execution(0x64).as_bytes());
    push_bytes(
        &mut selected_promotion,
        checkpoint(0x84).to_text().as_bytes(),
    );
    selected_promotion.push(1);
    selected_promotion.extend_from_slice(&request.resources().maximum_vcpus().to_be_bytes());
    selected_promotion
        .extend_from_slice(&request.resources().maximum_resident_bytes().to_be_bytes());
    selected_promotion.extend_from_slice(&request.resources().maximum_disk_bytes().to_be_bytes());
    selected_promotion
        .extend_from_slice(&request.resources().maximum_execution_quanta().to_be_bytes());
    selected_promotion.push(1);
    selected_promotion.push(3);
    assert!(matches!(
        decode_migratable_attempt_state(&seal(selected_promotion, &legacy_domain(11),)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "checkpoint-promotion-start-mode-tag"
        })
    ));

    assert_eq!(key.scope(), AttemptExecutionScope::Semantic);
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

fn savepoint_capture_request(
    assignment_byte: u8,
    attempt_byte: u8,
    vcpus: u32,
    request: CampaignFactId,
    configuration: ConfigurationArtifactId,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new_savepoint_capture(
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
        request,
        configuration,
    )
    .expect("savepoint capture request")
}

fn campaign_fact(byte: u8) -> CampaignFactId {
    CampaignFactId::parse(&format!(
        "crucible.campaign.fact@campaign-fact.10.{}",
        encode_hex(&[byte; 32])
    ))
    .expect("campaign fact")
}

fn configuration(byte: u8) -> ConfigurationArtifactId {
    ConfigurationArtifactId::parse(&typed_id(
        "crucible.campaign.configuration-artifact",
        "configuration",
        byte,
    ))
    .expect("configuration")
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
