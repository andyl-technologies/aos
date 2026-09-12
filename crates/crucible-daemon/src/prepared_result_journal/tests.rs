//! Prepared-result journal migration, fencing, and lifecycle tests.

// crucible-lint: allow panic-shortcut -- journal tests use panic shortcuts for precise fixture failures.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};

use crucible_campaign::{
    AttemptExecutionScope, AttemptId, BranchPathId, CampaignFactId, CampaignHash,
    CampaignLineageId, ConfigurationArtifact, ConfigurationId, CoverageProjection, DaemonEpoch,
    ExecutionId, MeasurementSet, Observation, ObservationCandidate, PropertyVerdictSet,
    ScenarioArtifactId, ScenarioDefId, StopOutcome,
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use tempfile::TempDir;

use crate::{
    AttemptExecutionOrigin, AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger,
};

use super::*;

const TEST_PAYLOAD_LIMIT: usize = 1024 * 1024;

struct LegacyJournalFixture {
    _ledger_root: TempDir,
    namespace: TempDir,
    _receipt_root: TempDir,
    receipt: PathBuf,
    ledger: DirectoryAssignmentLedger,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    result: PreparedSemanticAttemptResult,
}

impl LegacyJournalFixture {
    fn migrate(
        &mut self,
    ) -> Result<PreparedResultJournalMigrationSummary, crate::OperationalStateMigrationError> {
        let receipt_guard =
            crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
                &self.receipt,
            )?;
        let namespace_guard =
            crate::anchored_fs::AnchoredDirectory::new(self.namespace.path().to_owned())?;
        migrate_prepared_result_journals(
            &namespace_guard,
            &receipt_guard,
            &mut self.ledger,
            16,
            TEST_PAYLOAD_LIMIT,
        )
    }

    fn open(&self) -> Result<DirectoryPreparedResultJournal, PreparedResultJournalError> {
        let namespace = PreparedResultJournalNamespace::open(self.namespace.path())?;
        DirectoryPreparedResultJournal::open(
            &namespace,
            self.key,
            self.execution,
            TEST_PAYLOAD_LIMIT,
        )
    }
}

fn legacy_journal_fixture(marker: u8) -> LegacyJournalFixture {
    let ledger_root = TempDir::new().expect("ledger root");
    let namespace = TempDir::new().expect("journal namespace");
    let receipt_root = TempDir::new().expect("receipt root");
    let receipt = receipt_root.path().join("receipt");
    let key = semantic_key(&[marker]);
    let execution = ExecutionId::from_bytes([marker; 16]).expect("execution");
    let result = observation_result(marker.wrapping_add(1), key.attempt());
    let observation = result
        .observation()
        .observation()
        .id()
        .expect("observation ID");
    let state = AttemptRuntimeState::Publishing {
        execution_basis: CampaignHash::derive("test.execution-basis.v1", &[marker]),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: DaemonEpoch::from_bytes([marker.wrapping_add(2); 16]).expect("daemon epoch"),
        execution,
        observation,
        finding_candidate: None,
        finding_replay_captures: None,
        finding_exact_retention_roots: [None; 3],
        prepared_result_digest: None,
    };
    let mut ledger = DirectoryAssignmentLedger::open(ledger_root.path()).expect("ledger");
    assert_eq!(
        ledger
            .compare_exchange_attempt(key, None, Some(state))
            .expect("publish ledger state"),
        AttemptStateCas::Advanced
    );
    migration::write_legacy_journal_for_test(
        namespace.path(),
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        &result,
    )
    .expect("legacy journal");
    LegacyJournalFixture {
        _ledger_root: ledger_root,
        namespace,
        _receipt_root: receipt_root,
        receipt,
        ledger,
        key,
        execution,
        result,
    }
}

#[test]
fn legacy_journal_requires_explicit_migration_before_runtime_open() {
    let mut fixture = legacy_journal_fixture(0x61);

    assert!(matches!(
        fixture.open(),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(matches!(
        PreparedResultJournalNamespace::open(fixture.namespace.path()),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));

    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &fixture.receipt,
    )
    .expect("receipt directory");
    let namespace = crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
        .expect("namespace authority");
    let marker = crate::operational_state_migration::receipt::activate_marker(
        &namespace,
        &receipt,
        &fixture.ledger.root().canonicalize().expect("ledger root"),
        &fixture
            .namespace
            .path()
            .canonicalize()
            .expect("namespace root"),
    )
    .expect("activate migration marker");
    let summary = fixture.migrate().expect("migrate journal");
    crate::operational_state_migration::receipt::finish_marker(&marker, &receipt)
        .expect("finish migration marker");
    assert_eq!(summary.journals, 1);
    assert_eq!(summary.migrated, 1);
    assert_eq!(summary.receipt.id.len(), 64);
    let journal = fixture.open().expect("open migrated journal");
    assert_eq!(journal.result(), &fixture.result);
}

#[test]
fn legacy_semantic_payload_rewrite_resumes_after_every_file_cut() {
    for (marker, cut) in (0x69..=0x70).zip(0..=7) {
        let mut fixture = legacy_journal_fixture(marker);
        let root = journal_path(fixture.namespace.path(), fixture.key);
        let legacy_payload = crate::crucible_artifact::encode_version_for_test(
            &fixture.result,
            2,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("encode legacy semantic payload");
        let legacy_state = encode_state(
            fixture.key,
            fixture.execution,
            TEST_PAYLOAD_LIMIT,
            &fixture.result,
            &legacy_payload,
        )
        .expect("encode legacy semantic state");
        fs::remove_file(root.join(migration::JOURNAL_RESULT_FILE_V1))
            .expect("remove legacy result name");
        fs::remove_file(root.join(migration::JOURNAL_STATE_FILE_V1))
            .expect("remove legacy state name");
        fs::write(root.join(JOURNAL_RESULT_FILE), &legacy_payload).expect("write legacy payload");
        fs::write(root.join(JOURNAL_STATE_FILE), &legacy_state).expect("write legacy state");
        let current_payload = fixture
            .result
            .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
            .expect("current payload");
        let current_state = encode_state(
            fixture.key,
            fixture.execution,
            TEST_PAYLOAD_LIMIT,
            &fixture.result,
            &current_payload,
        )
        .expect("current state");

        let receipt_parent = TempDir::new().expect("receipt parent");
        let receipt =
            crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
                &receipt_parent.path().join("receipt"),
            )
            .expect("receipt directory");
        let namespace =
            crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
                .expect("namespace authority");
        let marker = crate::operational_state_migration::receipt::activate_marker(
            &namespace,
            &receipt,
            &fixture.ledger.root().canonicalize().expect("ledger root"),
            &fixture
                .namespace
                .path()
                .canonicalize()
                .expect("namespace root"),
        )
        .expect("activate migration marker");
        if cut >= 5 {
            migrate_prepared_result_journals(
                &namespace,
                &receipt,
                &mut fixture.ledger,
                8,
                TEST_PAYLOAD_LIMIT,
            )
            .expect("establish semantic rewrite receipt");
            fs::write(root.join(JOURNAL_RESULT_FILE), &legacy_payload)
                .expect("restore old payload");
            fs::write(root.join(JOURNAL_STATE_FILE), &legacy_state).expect("restore old state");
            for (logical, bytes) in [
                (
                    migration::CURRENT_RESULT_PENDING,
                    current_payload.as_slice(),
                ),
                (migration::CURRENT_STATE_PENDING, current_state.as_slice()),
            ] {
                let quarantine = fs::read_dir(&root)
                    .expect("inventory cleanup tombstones")
                    .map(|entry| entry.expect("cleanup entry"))
                    .find(|entry| {
                        crate::anchored_fs::removal_original_name(&entry.file_name()).as_deref()
                            == Some(std::ffi::OsStr::new(logical))
                    })
                    .expect("pending cleanup tombstone")
                    .path();
                let pending = root.join(logical);
                fs::rename(quarantine, &pending).expect("restore pending identity");
                fs::write(pending, bytes).expect("restore pending bytes");
            }
        }
        match cut {
            0 => {}
            1 => fs::write(
                root.join(migration::CURRENT_RESULT_PENDING),
                &current_payload[..current_payload.len() / 2],
            )
            .expect("interrupt pending result write"),
            2 => fs::write(
                root.join(migration::CURRENT_RESULT_PENDING),
                &current_payload,
            )
            .expect("complete pending result write"),
            3 => {
                fs::write(
                    root.join(migration::CURRENT_RESULT_PENDING),
                    &current_payload,
                )
                .expect("complete pending result write");
                fs::write(
                    root.join(migration::CURRENT_STATE_PENDING),
                    &current_state[..current_state.len() / 2],
                )
                .expect("interrupt pending state write");
            }
            4 => {
                fs::write(
                    root.join(migration::CURRENT_RESULT_PENDING),
                    &current_payload,
                )
                .expect("complete pending result write");
                fs::write(root.join(migration::CURRENT_STATE_PENDING), &current_state)
                    .expect("complete pending state write");
            }
            5 => fs::write(
                root.join(JOURNAL_RESULT_FILE),
                &current_payload[..current_payload.len() / 2],
            )
            .expect("interrupt result replacement"),
            6 => {
                fs::write(root.join(JOURNAL_RESULT_FILE), &current_payload)
                    .expect("complete result replacement");
                fs::write(
                    root.join(JOURNAL_STATE_FILE),
                    &current_state[..current_state.len() / 2],
                )
                .expect("interrupt state replacement");
            }
            7 => {
                fs::write(root.join(JOURNAL_RESULT_FILE), &current_payload)
                    .expect("complete result replacement");
                fs::write(root.join(JOURNAL_STATE_FILE), &current_state)
                    .expect("complete state replacement");
            }
            _ => unreachable!(),
        }

        migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .unwrap_or_else(|error| panic!("resume semantic rewrite at cut {cut}: {error}"));
        crate::operational_state_migration::receipt::finish_marker(&marker, &receipt)
            .expect("finish migration marker");
        let runtime_namespace = PreparedResultJournalNamespace::open(fixture.namespace.path())
            .expect("runtime namespace");
        DirectoryPreparedResultJournal::open(
            &runtime_namespace,
            fixture.key,
            fixture.execution,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("open rewritten semantic payload");
    }
}

#[test]
fn v1_migration_resumes_after_every_internal_pending_and_publish_cut() {
    for (marker, cut) in (0x71..=0x7d).zip(0..=12) {
        let mut fixture = legacy_journal_fixture(marker);
        let receipt_parent = TempDir::new().expect("receipt parent");
        let receipt =
            crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
                &receipt_parent.path().join("receipt"),
            )
            .expect("receipt directory");
        let namespace =
            crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
                .expect("namespace authority");
        let marker = crate::operational_state_migration::receipt::activate_marker(
            &namespace,
            &receipt,
            &fixture.ledger.root().canonicalize().expect("ledger root"),
            &fixture
                .namespace
                .path()
                .canonicalize()
                .expect("namespace root"),
        )
        .expect("activate migration marker");

        assert!(matches!(
            fixture.open(),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        migration::interrupt_migration_after_for_test(cut);
        assert!(matches!(
            migrate_prepared_result_journals(
                &namespace,
                &receipt,
                &mut fixture.ledger,
                8,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(crate::OperationalStateMigrationError::PreparedResult(
                PreparedResultJournalError::RecoveryRequired
            ))
        ));
        let summary = migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .unwrap_or_else(|error| panic!("resume migration at cut {cut}: {error}"));
        assert_eq!(summary.migrated, 1);
        let root = journal_path(fixture.namespace.path(), fixture.key);
        assert!(!root.join(migration::JOURNAL_RESULT_FILE_V1).exists());
        assert!(!root.join(migration::JOURNAL_STATE_FILE_V1).exists());
        crate::operational_state_migration::receipt::finish_marker(&marker, &receipt)
            .expect("finish migration marker");
        fixture.open().expect("open resumed journal");
    }
}

#[test]
fn orphan_inventory_reads_beyond_receipt_and_child_limit_before_mutation() {
    let namespace = TempDir::new().expect("journal namespace");
    let key = semantic_key(b"orphan-inventory-boundary");
    let staged = staged_path(namespace.path(), key);
    fs::create_dir(&staged).expect("staged directory");
    fs::write(staged.join(ORPHAN_CLEANUP_RECEIPT), b"receipt").expect("orphan receipt placeholder");
    for name in [
        JOURNAL_STATE_FILE,
        JOURNAL_RESULT_FILE,
        "lock",
        ".state-v2.0",
        ".state-v2.1",
        ".result-v2.0",
        ".result-v2.1",
    ] {
        fs::write(staged.join(name), name).expect("orphan child");
    }
    let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
        namespace
            .path()
            .canonicalize()
            .expect("canonical namespace"),
    )
    .expect("namespace authority");

    assert!(matches!(
        inventory_orphan_directory(&namespace_guard, &staged),
        Err(PreparedResultJournalError::InvalidDirectory)
    ));
    assert_eq!(
        fs::read_dir(&staged)
            .expect("unchanged over-limit orphan")
            .count(),
        MAX_ORPHAN_DIRECTORY_ENTRIES + 2
    );
}

#[test]
fn orphan_inventory_rejects_complete_and_pending_receipts_before_mutation() {
    let namespace = TempDir::new().expect("journal namespace");
    let key = semantic_key(b"orphan-receipt-pair");
    let staged = staged_path(namespace.path(), key);
    fs::create_dir(&staged).expect("staged directory");
    fs::write(staged.join(ORPHAN_CLEANUP_RECEIPT), b"complete")
        .expect("complete receipt placeholder");
    fs::write(staged.join(ORPHAN_CLEANUP_RECEIPT_PENDING), b"pending")
        .expect("pending receipt placeholder");
    fs::write(staged.join(JOURNAL_STATE_FILE), b"state").expect("orphan state");
    let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
        namespace
            .path()
            .canonicalize()
            .expect("canonical namespace"),
    )
    .expect("namespace authority");

    assert!(matches!(
        inventory_orphan_directory(&namespace_guard, &staged),
        Err(PreparedResultJournalError::InvalidDirectory)
    ));
    assert_eq!(
        fs::read_dir(&staged)
            .expect("unchanged ambiguous orphan")
            .count(),
        3
    );
}

#[test]
fn migration_resumes_after_first_legacy_file_removal() {
    let mut fixture = legacy_journal_fixture(0x77);
    let root = journal_path(fixture.namespace.path(), fixture.key);
    let legacy_state = fs::read(root.join(migration::JOURNAL_STATE_FILE_V1))
        .expect("legacy state before migration");
    let legacy_path = root.join(migration::JOURNAL_STATE_FILE_V1);
    let metadata = fs::metadata(&legacy_path).expect("legacy state identity");
    let quarantine = root.join(format!(
        ".{}.removing-v1-{:x}-{:x}",
        migration::JOURNAL_STATE_FILE_V1,
        metadata.dev(),
        metadata.ino()
    ));
    let receipt_parent = TempDir::new().expect("receipt parent");
    let receipt_path = receipt_parent.path().join("receipt");
    let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
        &receipt_path,
    )
    .expect("receipt directory");
    let namespace = crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
        .expect("namespace authority");

    migrate_prepared_result_journals(
        &namespace,
        &receipt,
        &mut fixture.ledger,
        8,
        TEST_PAYLOAD_LIMIT,
    )
    .expect("initial migration");
    fs::write(&quarantine, &legacy_state).expect("restore post-rename crash bytes");
    assert!(matches!(
        fixture.open(),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));

    let resumed = migrate_prepared_result_journals(
        &namespace,
        &receipt,
        &mut fixture.ledger,
        8,
        TEST_PAYLOAD_LIMIT,
    )
    .expect("resume legacy cleanup");
    assert_eq!(resumed.migrated, 1);
    assert!(!legacy_path.exists());
    assert_eq!(quarantine.metadata().expect("cleanup tombstone").len(), 0);
    let stable_entries = fs::read_dir(&root).expect("journal inventory").count();
    for _ in 0..3 {
        migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("repeat idempotent journal migration");
    }
    assert_eq!(
        fs::read_dir(&root).expect("journal inventory").count(),
        stable_entries
    );

    fs::write(&legacy_path, &legacy_state).expect("same-bytes forged legacy state");
    let metadata = fs::metadata(&legacy_path).expect("forged legacy identity");
    let forged = root.join(format!(
        ".{}.removing-v1-{:x}-{:x}",
        migration::JOURNAL_STATE_FILE_V1,
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(&legacy_path, &forged).expect("publish forged removal state");
    assert!(
        migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .is_err()
    );
    assert!(forged.exists());
}

#[test]
fn migration_rejects_corruption_before_staging_or_replacement() {
    let mut fixture = legacy_journal_fixture(0x79);
    let root = journal_path(fixture.namespace.path(), fixture.key);
    let result_path = root.join(migration::JOURNAL_RESULT_FILE_V1);
    let state_path = root.join(migration::JOURNAL_STATE_FILE_V1);
    let original_state = fs::read(&state_path).expect("read legacy state");
    fs::write(&result_path, b"corrupt legacy payload").expect("corrupt payload");

    assert!(fixture.migrate().is_err());
    assert_eq!(
        fs::read(state_path).expect("read unchanged state"),
        original_state
    );
    assert!(!root.join(JOURNAL_RESULT_FILE).exists());
}

#[test]
fn migration_rejects_a_held_journal_lock_before_staging() {
    let mut fixture = legacy_journal_fixture(0x7d);
    let namespace = crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
        .expect("namespace authority");
    let lock = acquire_namespace_lock(&namespace, fixture.key).expect("hold journal lock");
    assert!(fixture.migrate().is_err());
    assert!(
        !journal_path(fixture.namespace.path(), fixture.key)
            .join(JOURNAL_RESULT_FILE)
            .exists()
    );
    drop(lock);
}

#[test]
fn active_migration_fences_every_runtime_mutation_entry() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let assignment = TempDir::new().expect("assignment root");
    let receipt_parent = TempDir::new().expect("receipt parent");
    let receipt_path = receipt_parent.path().join("receipt");
    let receipt_guard =
        crate::operational_state_migration::receipt::prepare_receipt_directory_for_test(
            &receipt_path,
        )
        .expect("receipt directory");
    let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
        namespace
            .path()
            .canonicalize()
            .expect("canonical namespace"),
    )
    .expect("namespace guard");
    let assignment_path = assignment
        .path()
        .canonicalize()
        .expect("canonical assignment root");
    let prepared_path = namespace
        .path()
        .canonicalize()
        .expect("canonical prepared root");

    let staged_key = semantic_key(b"fenced-stage");
    let staged_execution = ExecutionId::from_bytes([0x91; 16]).expect("staged execution");
    let staged_result = observation_result(0x92, staged_key.attempt());
    let (mut staged, _) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime_namespace,
        staged_key,
        staged_execution,
        TEST_PAYLOAD_LIMIT,
        staged_result,
    )
    .expect("prepare journal before migration");

    let visible_key = semantic_key(b"fenced-visible");
    let visible_execution = ExecutionId::from_bytes([0x93; 16]).expect("visible execution");
    let visible_result = observation_result(0x94, visible_key.attempt());
    let (visible, _) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        visible_key,
        visible_execution,
        TEST_PAYLOAD_LIMIT,
        visible_result,
    )
    .expect("create journal before migration");

    crate::operational_state_migration::receipt::activate_marker(
        &namespace_guard,
        &receipt_guard,
        &assignment_path,
        &prepared_path,
    )
    .expect("activate migration fence");

    let absent_key = semantic_key(b"fenced-absent");
    let absent_result = observation_result(0x95, absent_key.attempt());
    assert!(matches!(
        DirectoryPreparedResultJournal::prepare_staged(
            &runtime_namespace,
            absent_key,
            ExecutionId::from_bytes([0x96; 16]).expect("absent execution"),
            TEST_PAYLOAD_LIMIT,
            absent_result,
        ),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(matches!(
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
            &runtime_namespace,
            absent_key,
        ),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(matches!(
        staged.commit_staged(),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(matches!(
        visible.remove(),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
}

#[test]
fn runtime_rejects_nonregular_and_tampered_migration_markers() {
    for marker_kind in ["directory", "symlink", "tampered"] {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime_namespace =
            PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
        let marker = namespace
            .path()
            .join(crate::operational_state_migration::receipt::ACTIVE_MARKER);
        match marker_kind {
            "directory" => fs::create_dir(&marker).expect("marker directory"),
            "symlink" => symlink("missing-marker-target", &marker).expect("marker symlink"),
            "tampered" => {
                fs::write(&marker, b"not an authenticated marker").expect("tampered marker")
            }
            _ => unreachable!(),
        }
        let key = semantic_key(marker_kind.as_bytes());
        let result = observation_result(0x97, key.attempt());

        assert!(
            DirectoryPreparedResultJournal::prepare_staged(
                &runtime_namespace,
                key,
                ExecutionId::from_bytes([0x98; 16]).expect("execution"),
                TEST_PAYLOAD_LIMIT,
                result,
            )
            .is_err()
        );
        assert!(!staged_path(namespace.path(), key).exists());
    }
}

#[test]
fn runtime_inventory_rejects_nonregular_or_oversized_journal_children() {
    for kind in ["visible-symlink", "staged-symlink", "retired-oversized"] {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(kind.as_bytes());
        let root = match kind {
            "visible-symlink" => journal_path(namespace.path(), key),
            "staged-symlink" => staged_path(namespace.path(), key),
            "retired-oversized" => retired_path(namespace.path(), key),
            _ => unreachable!(),
        };
        fs::create_dir(&root).expect("journal directory");
        if kind.ends_with("symlink") {
            std::os::unix::fs::symlink("missing", root.join(JOURNAL_RESULT_FILE))
                .expect("journal symlink");
        } else {
            let file = fs::File::create(root.join(JOURNAL_RESULT_FILE)).expect("oversized result");
            file.set_len(MAX_PREPARED_SEMANTIC_RESULT_BYTES as u64 + 1)
                .expect("extend result");
        }

        let runtime_namespace = PreparedResultJournalNamespace::open(namespace.path())
            .expect_err("invalid journal inventory must fail startup");
        assert!(matches!(
            runtime_namespace,
            PreparedResultJournalError::InvalidDirectory
                | PreparedResultJournalError::RecoveryRequired
        ));
    }
}

#[test]
fn runtime_rejects_an_unsealed_zero_length_migration_tombstone() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"unsealed-tombstone");
    let execution = ExecutionId::from_bytes([0x4d; 16]).expect("execution");
    let (journal, _) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        observation_result(0x5d, key.attempt()),
    )
    .expect("create current journal");
    let legacy = journal.root().join(migration::JOURNAL_STATE_FILE_V1);
    fs::write(&legacy, []).expect("empty forged legacy state");
    let metadata = legacy.metadata().expect("forged identity");
    let forged = journal.root().join(format!(
        ".{}.removing-v1-{:x}-{:x}",
        migration::JOURNAL_STATE_FILE_V1,
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(legacy, &forged).expect("publish forged tombstone");
    drop(journal);

    assert!(
        DirectoryPreparedResultJournal::open(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
        )
        .is_err()
    );
    assert!(forged.exists());
}

#[test]
fn staged_journal_is_durable_hidden_and_promotes_exactly() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"staged");
    let execution = ExecutionId::from_bytes([0x4f; 16]).expect("execution");
    let result = observation_result(0x5f, key.attempt());

    let (staged, disposition) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result.clone(),
    )
    .expect("prepare hidden journal");
    assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
    assert_eq!(staged.root(), staged_path(namespace.path(), key));
    assert!(!journal_path(namespace.path(), key).exists());
    drop(staged);
    assert!(matches!(
        DirectoryPreparedResultJournal::open_for_recovery(
            &runtime_namespace,
            key,
            TEST_PAYLOAD_LIMIT,
        ),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));

    let mut recovered = DirectoryPreparedResultJournal::open_staged_for_recovery(
        &runtime_namespace,
        key,
        TEST_PAYLOAD_LIMIT,
    )
    .expect("authenticate staged journal")
    .expect("staged journal exists");
    assert_eq!(recovered.result(), &result);
    recovered.commit_staged().expect("promote staged journal");
    assert_eq!(recovered.root(), journal_path(namespace.path(), key));
    assert!(!staged_path(namespace.path(), key).exists());
    assert!(journal_path(namespace.path(), key).is_dir());
}

#[test]
fn staged_journal_rejects_result_substitution() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"staged-substitution");
    let execution = ExecutionId::from_bytes([0x4e; 16]).expect("execution");
    let result = observation_result(0x5e, key.attempt());
    let (staged, _) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result,
    )
    .expect("prepare hidden journal");
    drop(staged);

    assert!(matches!(
        DirectoryPreparedResultJournal::prepare_staged(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x5d, key.attempt()),
        ),
        Err(PreparedResultJournalError::ResultMismatch)
    ));
}

#[test]
fn journal_create_reopen_authenticate_and_remove_are_exact() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"main");
    let execution = ExecutionId::from_bytes([0x51; 16]).expect("execution");
    let result = observation_result(0x61, key.attempt());

    let (journal, disposition) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result.clone(),
    )
    .expect("create journal");
    assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
    assert_eq!(journal.result(), &result);
    assert!(journal.root().is_dir());
    let namespace_lock = namespace_lock_path(namespace.path(), key);
    let lock_inode = fs::metadata(&namespace_lock)
        .expect("namespace lock metadata")
        .ino();
    assert!(matches!(
        DirectoryPreparedResultJournal::open(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
        ),
        Err(PreparedResultJournalError::Io {
            operation: "lock-journal-namespace",
            ..
        })
    ));
    let root = journal.root().to_path_buf();
    let retained_owner_description = journal
        .namespace_lock
        .file()
        .try_clone()
        .expect("duplicate successful owner lock descriptor");
    drop(journal);

    let failed_open_lock = acquire_namespace_lock(&runtime_namespace.runtime, key)
        .expect("acquire lock for failed authenticated open");
    let failed_open_guard = Arc::clone(&runtime_namespace.runtime);
    let retained_failed_open_description = failed_open_lock
        .file()
        .try_clone()
        .expect("duplicate failed-open lock descriptor");
    assert!(matches!(
        DirectoryPreparedResultJournal::open_locked(
            root.clone(),
            key,
            Some(ExecutionId::from_bytes([0x52; 16]).expect("other execution")),
            TEST_PAYLOAD_LIMIT,
            failed_open_lock,
            failed_open_guard,
            false,
        ),
        Err(PreparedResultJournalError::InvalidState)
    ));
    let reopened_after_failure = DirectoryPreparedResultJournal::open(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
    )
    .expect("failed authenticated open releases retained lock description");
    drop(reopened_after_failure);
    drop(retained_failed_open_description);
    assert!(matches!(
        DirectoryPreparedResultJournal::open(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT / 2,
        ),
        Err(PreparedResultJournalError::InvalidState)
    ));

    let (journal, disposition) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result.clone(),
    )
    .expect("reopen exact journal");
    assert_eq!(
        disposition,
        PreparedResultJournalCreateDisposition::Existing
    );
    drop(journal);
    assert!(matches!(
        DirectoryPreparedResultJournal::create(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x62, key.attempt()),
        ),
        Err(PreparedResultJournalError::ResultMismatch)
    ));

    let journal = DirectoryPreparedResultJournal::open(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
    )
    .expect("open complete journal");
    journal.remove().expect("remove journal");
    journal.remove().expect("repeat durable removal");
    assert!(!root.exists());
    assert_eq!(
        fs::metadata(&namespace_lock)
            .expect("persistent namespace lock metadata")
            .ino(),
        lock_inode
    );
    drop(journal);
    let terminal_count = fs::read_dir(namespace.path())
        .expect("count terminal journal state")
        .count();
    assert!(matches!(
        DirectoryPreparedResultJournal::create(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        ),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert_eq!(
        fs::read_dir(namespace.path())
            .expect("recount terminal journal state")
            .count(),
        terminal_count
    );
    assert_eq!(
        fs::metadata(&namespace_lock)
            .expect("reused namespace lock metadata")
            .ino(),
        lock_inode
    );
    drop(retained_owner_description);
}

#[test]
fn journal_rejects_corrupt_incomplete_and_nonsemantic_state() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"corrupt");
    let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
    let (journal, _) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        observation_result(0x72, key.attempt()),
    )
    .expect("create journal");
    let root = journal.root().to_path_buf();
    drop(journal);

    let state_path = root.join(JOURNAL_STATE_FILE);
    let mut state = fs::read(&state_path).expect("read state");
    state[0] ^= 0xff;
    fs::write(&state_path, state).expect("corrupt state");
    assert!(matches!(
        DirectoryPreparedResultJournal::open(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
        ),
        Err(PreparedResultJournalError::InvalidState)
    ));

    let incomplete_namespace = TempDir::new().expect("incomplete namespace");
    fs::create_dir(journal_path(incomplete_namespace.path(), key))
        .expect("incomplete journal directory");
    assert!(matches!(
        PreparedResultJournalNamespace::open(incomplete_namespace.path()),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));

    let request = CampaignFactId::parse(&typed_content_text(
        "crucible.campaign.fact",
        ObjectKind::CampaignFact,
        10,
        b"savepoint-capture-request",
    ))
    .expect("capture request ID");
    let nonsemantic = AttemptExecutionKey::new_scoped(
        key.lineage(),
        key.attempt(),
        AttemptExecutionScope::SavepointCapture { request },
    );
    assert!(matches!(
        DirectoryPreparedResultJournal::create(
            &runtime_namespace,
            nonsemantic,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x73, key.attempt()),
        ),
        Err(PreparedResultJournalError::NonSemanticKey)
    ));
}

#[test]
fn journal_rejects_attempt_mismatch_before_creating_lock_or_staging() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"attempt-binding");
    let other = semantic_key(b"other-attempt").attempt();
    let execution = ExecutionId::from_bytes([0x81; 16]).expect("execution");

    assert!(matches!(
        DirectoryPreparedResultJournal::create(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x82, other),
        ),
        Err(PreparedResultJournalError::AttemptMismatch)
    ));
    let entries = fs::read_dir(namespace.path())
        .expect("read namespace")
        .map(|entry| entry.expect("namespace entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from(JOURNAL_OWNER_LOCK)]);
}

#[test]
fn ledger_gated_cleanup_recovers_fixed_partial_staging_and_retirement() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"orphan-recovery");
    let execution = ExecutionId::from_bytes([0x91; 16]).expect("execution");
    let result = observation_result(0x92, key.attempt());

    let staged = staged_path(namespace.path(), key);
    fs::create_dir(&staged).expect("partial staging directory");
    fs::write(staged.join(JOURNAL_RESULT_FILE), b"partial").expect("partial result");
    fs::write(staged.join(".state-v2.123.0"), b"partial").expect("partial atomic state temporary");
    assert!(matches!(
        DirectoryPreparedResultJournal::create(
            &runtime_namespace,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result.clone(),
        ),
        Err(PreparedResultJournalError::Incomplete)
    ));
    let cleaned =
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime_namespace, key)
            .expect("clean partial staging");
    assert_eq!(
        cleaned,
        PreparedResultJournalCleanupDisposition {
            staged_removed: true,
            retired_removed: false,
        }
    );
    let staged_terminal_count = fs::read_dir(namespace.path())
        .expect("count staged terminal state")
        .count();
    for _ in 0..3 {
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                &runtime_namespace,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result.clone(),
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        assert_eq!(
            fs::read_dir(namespace.path())
                .expect("recount staged terminal state")
                .count(),
            staged_terminal_count
        );
    }

    let key = semantic_key(b"retired-orphan-recovery");
    let result = observation_result(0x93, key.attempt());
    let (journal, _) = DirectoryPreparedResultJournal::create(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result,
    )
    .expect("create after staged cleanup");
    let root = journal.root().to_path_buf();
    drop(journal);
    let retired = retired_path(namespace.path(), key);
    fs::rename(&root, &retired).expect("simulate completed retirement rename");
    fs::remove_file(retired.join(JOURNAL_RESULT_FILE)).expect("simulate partial retired cleanup");

    let cleaned =
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime_namespace, key)
            .expect("finish partial retirement");
    assert_eq!(
        cleaned,
        PreparedResultJournalCleanupDisposition {
            staged_removed: false,
            retired_removed: true,
        }
    );
    assert_eq!(
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
            &runtime_namespace,
            key,
        )
        .expect("idempotent orphan cleanup"),
        PreparedResultJournalCleanupDisposition::default()
    );
    let retired_terminal_count = fs::read_dir(namespace.path())
        .expect("count retired terminal state")
        .count();
    for _ in 0..3 {
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                &runtime_namespace,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x93, key.attempt()),
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        assert_eq!(
            fs::read_dir(namespace.path())
                .expect("recount retired terminal state")
                .count(),
            retired_terminal_count
        );
    }
}

#[test]
fn public_and_startup_orphan_cleanup_reject_substituted_files_and_directories() {
    for kind in ["file", "directory"] {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(kind.as_bytes());
        let staged = staged_path(namespace.path(), key);
        fs::create_dir(&staged).expect("staged directory");
        if kind == "file" {
            fs::write(staged.join(JOURNAL_RESULT_FILE), b"pinned").expect("staged result");
        }
        let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
            namespace
                .path()
                .canonicalize()
                .expect("canonical namespace"),
        )
        .expect("namespace authority");
        let (root_guard, entries) = inventory_orphan_directory(&namespace_guard, &staged)
            .expect("inventory orphan")
            .expect("orphan exists");

        let moved = namespace.path().join(format!("moved-{kind}"));
        if kind == "file" {
            let result = staged.join(JOURNAL_RESULT_FILE);
            fs::rename(&result, &moved).expect("move pinned file");
            fs::write(&result, b"replacement").expect("replace file");
        } else {
            fs::rename(&staged, &moved).expect("move pinned directory");
            fs::create_dir(&staged).expect("replace directory");
        }

        assert!(remove_orphan_inventory(&namespace_guard, root_guard, entries).is_err());
        assert!(staged.exists());
        assert!(moved.exists());
    }
}

#[test]
fn bound_orphan_removal_rejects_a_renamed_away_directory() {
    let namespace = TempDir::new().expect("journal namespace");
    let key = semantic_key(b"renamed-bound-orphan");
    let staged = staged_path(namespace.path(), key);
    fs::create_dir(&staged).expect("staged directory");
    let runtime =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let root_guard = runtime
        .runtime
        .open_child(&staged, "pin-staged-directory")
        .expect("staged authority");
    let moved = namespace.path().join("moved-staged");
    fs::rename(&staged, &moved).expect("move staged directory");

    assert!(matches!(
        remove_bound_orphan_directory(&runtime.runtime, &staged, &root_guard),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(moved.exists());
}

#[test]
fn public_commit_and_remove_reject_same_byte_directory_substitution() {
    for transition in ["commit", "remove"] {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime_namespace =
            PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
        let moved_parent = TempDir::new().expect("moved journal parent");
        let key = semantic_key(transition.as_bytes());
        let execution = ExecutionId::from_bytes([0xa4; 16]).expect("execution");
        let result = observation_result(0xa5, key.attempt());
        let (mut journal, _) = if transition == "commit" {
            DirectoryPreparedResultJournal::prepare_staged(
                &runtime_namespace,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result,
            )
            .expect("prepare staged journal")
        } else {
            DirectoryPreparedResultJournal::create(
                &runtime_namespace,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result,
            )
            .expect("create visible journal")
        };
        let original = journal.root().to_owned();
        let moved = moved_parent.path().join(transition);
        let raced_original = original.clone();
        let raced_moved = moved.clone();
        install_journal_race_hook(move || {
            fs::rename(&raced_original, &raced_moved).expect("move pinned journal");
            fs::create_dir(&raced_original).expect("replacement journal directory");
            for name in [JOURNAL_RESULT_FILE, JOURNAL_STATE_FILE] {
                fs::copy(raced_moved.join(name), raced_original.join(name))
                    .expect("copy exact journal bytes");
            }
        });

        let result = if transition == "commit" {
            journal.commit_staged()
        } else {
            journal.remove()
        };
        assert!(result.is_err());
        assert!(original.exists());
        assert!(moved.exists());
        assert!(!retired_path(namespace.path(), key).exists());
        assert_eq!(
            journal_path(namespace.path(), key).exists(),
            transition == "remove"
        );
    }
}

#[test]
fn cleanup_rejects_a_dangling_visible_symlink_created_after_namespace_scan() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"cleanup-visible-race");
    let visible = journal_path(namespace.path(), key);
    let raced_visible = visible.clone();
    install_journal_race_hook(move || {
        std::os::unix::fs::symlink("missing-journal", raced_visible)
            .expect("install dangling visible journal");
    });

    assert!(matches!(
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime_namespace, key,),
        Err(PreparedResultJournalError::RecoveryRequired)
    ));
    assert!(
        fs::symlink_metadata(visible)
            .expect("dangling visible journal remains")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn orphan_cleanup_tombstone_is_sealed_bounded_and_idempotent() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"sealed-orphan");
    let staged = staged_path(namespace.path(), key);
    fs::create_dir(&staged).expect("empty staged directory");
    let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
        namespace
            .path()
            .canonicalize()
            .expect("canonical namespace"),
    )
    .expect("namespace authority");
    let (root_guard, entries) = inventory_orphan_directory(&namespace_guard, &staged)
        .expect("inventory empty orphan")
        .expect("empty orphan exists");
    let objects =
        orphan_cleanup_objects(&root_guard, &entries, true).expect("orphan cleanup objects");
    crate::operational_state_migration::receipt::persist_phase_receipt(
        &root_guard,
        ORPHAN_CLEANUP_RECEIPT,
        ORPHAN_CLEANUP_OUTPUT_SCHEMA,
        objects,
    )
    .expect("complete receipt before simulated cut");
    let receipt = staged.join(ORPHAN_CLEANUP_RECEIPT);
    let pending = staged.join(ORPHAN_CLEANUP_RECEIPT_PENDING);
    fs::rename(&receipt, &pending).expect("interrupt receipt publication");
    let bytes = fs::read(&pending).expect("read pending receipt");
    fs::write(&pending, &bytes[..bytes.len() / 2]).expect("partial receipt write");
    drop(root_guard);
    drop(namespace_guard);

    let first =
        DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime_namespace, key)
            .expect("seal empty orphan cleanup");
    assert!(first.staged_removed);
    let cardinality = fs::read_dir(namespace.path())
        .expect("count terminal entries")
        .count();
    for _ in 0..3 {
        assert_eq!(
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
                &runtime_namespace,
                key,
            )
            .expect("repeat sealed cleanup"),
            PreparedResultJournalCleanupDisposition::default()
        );
        assert_eq!(
            fs::read_dir(namespace.path())
                .expect("recount terminal entries")
                .count(),
            cardinality
        );
    }
    drop(runtime_namespace);
    drop(
        PreparedResultJournalNamespace::open(namespace.path())
            .expect("sealed tombstone is runtime-safe"),
    );

    let logical = staged.file_name().expect("staged name");
    let tombstone = fs::read_dir(namespace.path())
        .expect("find terminal tombstone")
        .map(|entry| entry.expect("terminal entry"))
        .find(|entry| {
            crate::anchored_fs::removal_original_name(&entry.file_name()).as_deref()
                == Some(logical)
        })
        .expect("terminal tombstone")
        .path();
    let moved_parent = TempDir::new().expect("moved tombstone parent");
    let moved = moved_parent.path().join("terminal-tombstone");
    fs::rename(&tombstone, &moved).expect("move authenticated tombstone");
    fs::create_dir(&staged).expect("replacement directory");
    fs::copy(
        moved.join(ORPHAN_CLEANUP_RECEIPT),
        staged.join(ORPHAN_CLEANUP_RECEIPT),
    )
    .expect("copy authenticated bytes to new inode");
    let metadata = staged.metadata().expect("replacement identity");
    let forged = staged.with_file_name(format!(
        ".{}.removing-v1-{:x}-{:x}",
        logical.to_string_lossy(),
        metadata.dev(),
        metadata.ino()
    ));
    fs::rename(&staged, forged).expect("publish self-consistent forged tombstone");
    assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
}

#[test]
fn staged_recovery_rejects_live_replacement_beside_terminal_state() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let snapshot = TempDir::new().expect("snapshot");
    let key = semantic_key(b"staged-terminal-replacement");
    let execution = ExecutionId::from_bytes([0xb4; 16]).expect("execution");
    let result = observation_result(0xb5, key.attempt());
    let (journal, _) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result,
    )
    .expect("prepare staged journal");
    let staged = journal.root().to_owned();
    for name in [JOURNAL_RESULT_FILE, JOURNAL_STATE_FILE] {
        fs::copy(staged.join(name), snapshot.path().join(name)).expect("snapshot journal file");
    }
    journal.remove().expect("retire staged journal");
    drop(journal);
    fs::create_dir(&staged).expect("replacement staged directory");
    for name in [JOURNAL_RESULT_FILE, JOURNAL_STATE_FILE] {
        fs::copy(snapshot.path().join(name), staged.join(name)).expect("restore exact bytes");
    }

    assert!(matches!(
        DirectoryPreparedResultJournal::open_staged_for_recovery(
            &runtime_namespace,
            key,
            TEST_PAYLOAD_LIMIT,
        ),
        Err(PreparedResultJournalError::InvalidDirectory)
            | Err(PreparedResultJournalError::RecoveryRequired)
    ));
}

#[test]
fn runtime_rejects_hardlinked_noncanonical_tombstone_alias() {
    let namespace = TempDir::new().expect("journal namespace");
    let runtime_namespace =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"noncanonical-tombstone-alias");
    let execution = ExecutionId::from_bytes([0xc4; 16]).expect("execution");
    let (journal, _) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime_namespace,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        observation_result(0xc5, key.attempt()),
    )
    .expect("prepare staged journal");
    journal.remove().expect("retire staged journal");
    drop(journal);

    let terminal = fs::read_dir(namespace.path())
        .expect("terminal inventory")
        .map(|entry| entry.expect("terminal entry"))
        .find(|entry| {
            crate::anchored_fs::removal_original_name(&entry.file_name())
                == staged_path(namespace.path(), key)
                    .file_name()
                    .map(ToOwned::to_owned)
        })
        .expect("terminal directory")
        .path();
    let child = fs::read_dir(&terminal)
        .expect("terminal children")
        .map(|entry| entry.expect("terminal child"))
        .find(|entry| crate::anchored_fs::removal_original_name(&entry.file_name()).is_some())
        .expect("child tombstone")
        .path();
    let name = child.file_name().expect("child name").to_string_lossy();
    let marker = name.rfind(".removing-v1-").expect("removal marker");
    let identity = &name[marker + ".removing-v1-".len()..];
    let alias = terminal.join(format!("{}removing-v1-0{identity}", &name[..=marker]));
    fs::hard_link(&child, alias).expect("hardlink numeric alias");

    drop(runtime_namespace);
    assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
}

#[test]
fn runtime_namespace_has_one_process_owner() {
    let namespace = TempDir::new().expect("journal namespace");
    let first = PreparedResultJournalNamespace::open(namespace.path())
        .expect("initial namespace authority");

    assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
    drop(first);
    PreparedResultJournalNamespace::open(namespace.path())
        .expect("namespace reopens after owner shutdown");
}

#[test]
fn runtime_namespace_rejects_replacement_during_and_after_startup() {
    let namespace = TempDir::new().expect("journal namespace");
    let moved_parent = TempDir::new().expect("moved parent");
    let moved = moved_parent.path().join("namespace");
    let path = namespace.path().to_owned();
    let raced_path = path.clone();
    let raced_moved = moved.clone();
    install_journal_race_hook(move || {
        fs::rename(&raced_path, &raced_moved).expect("move namespace during startup");
        fs::create_dir(&raced_path).expect("replace namespace during startup");
    });
    assert!(matches!(
        PreparedResultJournalNamespace::open(&path),
        Err(PreparedResultJournalError::Io { .. })
    ));

    fs::remove_dir(&path).expect("remove first replacement");
    fs::rename(&moved, &path).expect("restore namespace");
    let original = PreparedResultJournalNamespace::open(&path).expect("runtime namespace");
    fs::rename(&path, &moved).expect("detach running namespace");
    fs::create_dir(&path).expect("replace running namespace");
    let replacement =
        PreparedResultJournalNamespace::open(&path).expect("replacement owns configured namespace");
    let key = semantic_key(b"detached-runtime");

    assert!(DirectoryPreparedResultJournal::artifacts_present(&original, key).is_err());
    assert!(
        !DirectoryPreparedResultJournal::artifacts_present(&replacement, key)
            .expect("replacement inventory")
    );
}

#[test]
fn runtime_namespace_owner_lock_rejects_nonregular_entries() {
    for kind in ["symlink", "directory"] {
        let namespace = TempDir::new().expect("journal namespace");
        let lock = namespace.path().join(JOURNAL_OWNER_LOCK);
        if kind == "symlink" {
            symlink("owner-target", &lock).expect("owner-lock symlink");
        } else {
            fs::create_dir(&lock).expect("owner-lock directory");
        }

        assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
        assert!(!namespace.path().join("owner-target").exists());
    }
}

#[test]
fn runtime_owner_lock_replacement_during_open_fails_closed() {
    let namespace = TempDir::new().expect("journal namespace");
    let moved_parent = TempDir::new().expect("moved lock parent");
    let lock = namespace.path().join(JOURNAL_OWNER_LOCK);
    let moved = moved_parent.path().join("owner-lock");
    crate::owned_advisory_lock::install_lock_race_hook({
        let lock = lock.clone();
        move || {
            fs::rename(&lock, &moved).expect("move locked owner file");
            fs::write(&lock, b"replacement").expect("replace owner lock");
        }
    });

    assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
    assert_eq!(
        fs::read(&lock).expect("replacement remains"),
        b"replacement"
    );
    PreparedResultJournalNamespace::open(namespace.path())
        .expect("replacement lock remains usable");
}

#[test]
fn runtime_owner_lock_replacement_after_open_fences_operations() {
    let namespace = TempDir::new().expect("journal namespace");
    let moved_parent = TempDir::new().expect("moved lock parent");
    let runtime =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let lock = namespace.path().join(JOURNAL_OWNER_LOCK);
    let moved = moved_parent.path().join("owner-lock");
    fs::rename(&lock, &moved).expect("move locked owner file");
    fs::write(&lock, b"replacement").expect("replace owner lock");
    let replacement = PreparedResultJournalNamespace::open(namespace.path())
        .expect("replacement has an independent owner");
    let key = semantic_key(b"replaced-owner-lock");

    assert!(DirectoryPreparedResultJournal::artifacts_present(&runtime, key).is_err());
    assert!(
        !DirectoryPreparedResultJournal::artifacts_present(&replacement, key)
            .expect("replacement namespace remains usable")
    );
}

#[test]
fn keyed_namespace_lock_rejects_nonregular_entries() {
    for kind in ["symlink", "directory"] {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime =
            PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
        let key = semantic_key(kind.as_bytes());
        let lock = namespace_lock_path(namespace.path(), key);
        if kind == "symlink" {
            symlink("key-target", &lock).expect("key-lock symlink");
        } else {
            fs::create_dir(&lock).expect("key-lock directory");
        }

        assert!(
            DirectoryPreparedResultJournal::prepare_staged(
                &runtime,
                key,
                ExecutionId::from_bytes([0xd1; 16]).expect("execution"),
                TEST_PAYLOAD_LIMIT,
                observation_result(0xd2, key.attempt()),
            )
            .is_err()
        );
        assert!(!namespace.path().join("key-target").exists());
    }
}

#[test]
fn keyed_namespace_lock_replacement_during_acquire_fails_closed() {
    let namespace = TempDir::new().expect("journal namespace");
    let moved_parent = TempDir::new().expect("moved lock parent");
    let runtime =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"replaced-key-lock");
    let lock = namespace_lock_path(namespace.path(), key);
    let moved = moved_parent.path().join("key-lock");
    crate::owned_advisory_lock::install_lock_race_hook({
        let lock = lock.clone();
        move || {
            fs::rename(&lock, &moved).expect("move locked key file");
            fs::write(&lock, b"replacement").expect("replace key lock");
        }
    });
    let execution = ExecutionId::from_bytes([0xd3; 16]).expect("execution");

    assert!(
        DirectoryPreparedResultJournal::prepare_staged(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0xd4, key.attempt()),
        )
        .is_err()
    );
    assert!(!staged_path(namespace.path(), key).exists());
    DirectoryPreparedResultJournal::prepare_staged(
        &runtime,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        observation_result(0xd4, key.attempt()),
    )
    .expect("replacement key lock remains usable");
}

#[test]
fn keyed_namespace_lock_replacement_after_prepare_fences_commit() {
    let namespace = TempDir::new().expect("journal namespace");
    let moved_parent = TempDir::new().expect("moved lock parent");
    let runtime =
        PreparedResultJournalNamespace::open(namespace.path()).expect("runtime namespace");
    let key = semantic_key(b"replaced-held-key-lock");
    let execution = ExecutionId::from_bytes([0xd5; 16]).expect("execution");
    let (mut journal, _) = DirectoryPreparedResultJournal::prepare_staged(
        &runtime,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        observation_result(0xd6, key.attempt()),
    )
    .expect("prepare staged journal");
    let lock = namespace_lock_path(namespace.path(), key);
    fs::rename(&lock, moved_parent.path().join("key-lock")).expect("move held key lock");
    fs::write(&lock, b"replacement").expect("replace key lock");
    let second = acquire_namespace_lock(&runtime.runtime, key)
        .expect("replacement key lock has independent owner");

    assert!(journal.commit_staged().is_err());
    assert!(staged_path(namespace.path(), key).is_dir());
    assert!(!journal_path(namespace.path(), key).exists());
    drop(second);
}

fn semantic_key(marker: &[u8]) -> AttemptExecutionKey {
    let lineage = CampaignLineageId::parse(&typed_content_text(
        "crucible.campaign.lineage",
        ObjectKind::CampaignFact,
        1,
        marker,
    ))
    .expect("lineage ID");
    let attempt = AttemptId::parse(&typed_content_text(
        "crucible.campaign.attempt",
        ObjectKind::CampaignFact,
        1,
        marker,
    ))
    .expect("attempt ID");
    AttemptExecutionKey::new(lineage, attempt)
}

fn observation_result(marker: u8, attempt: AttemptId) -> PreparedSemanticAttemptResult {
    let candidate = observation_candidate(
        marker,
        attempt,
        crate::crucible_measurement::empty_test_measurement_set(),
    );
    PreparedSemanticAttemptResult::new(candidate, None).expect("prepared result")
}

fn observation_candidate(
    marker: u8,
    attempt: AttemptId,
    measurements: MeasurementSet,
) -> ObservationCandidate {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", &[marker, 0]));
    let scenario_artifact = ScenarioArtifactId::parse(&typed_content_text(
        "crucible.campaign.scenario-artifact",
        ObjectKind::Scenario,
        1,
        &[marker, 1],
    ))
    .expect("scenario artifact ID");
    let configuration = ConfigurationId::from_hash(CampaignHash::derive("test", &[marker, 2]));
    let child =
        ConfigurationArtifact::new(scenario, scenario_artifact, configuration, 1, vec![marker])
            .expect("configuration artifact");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let path = BranchPathId::parse(&typed_content_text(
        "crucible.campaign.branch-path",
        ObjectKind::CampaignFact,
        2,
        &[marker, 4],
    ))
    .expect("branch path ID");
    let observation = Observation::new(
        attempt,
        configuration,
        child.id().expect("configuration artifact ID"),
        path,
        StopOutcome::TerminalSuccess,
        measurements.id().expect("measurement ID"),
        properties.id().expect("property ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("observation");
    ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        Vec::new(),
        observation,
    )
    .expect("observation candidate")
}

fn typed_content_text(tag: &str, kind: ObjectKind, schema_version: u32, marker: &[u8]) -> String {
    let content = ContentId::for_bytes(kind, schema_version, marker);
    format!("{tag}@{}", content.encode())
}
