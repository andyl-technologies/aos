//! Durable run-state admission and ownership regressions.

use super::*;

fn recovery_process(process_id: u32, executable: &str) -> QemuProcessIdentity {
    QemuProcessIdentity {
        process_id,
        start_time_ticks: u64::from(process_id) + 100,
        executable: PathBuf::from(executable),
    }
}

fn recovery_manifest(
    current: QemuProcessIdentity,
    staged: Option<QemuProcessIdentity>,
) -> ProductionRunManifest {
    ProductionRunManifest {
        version: 2,
        scenario: "3".repeat(64),
        owner: recovery_process(1, "/aos/controller"),
        processes: BTreeMap::from([(String::from("node-a"), current)]),
        staged_processes: staged
            .map(|identity| BTreeMap::from([(String::from("node-a"), identity)]))
            .unwrap_or_default(),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    }
}

fn recovery_journal(
    phase: ProductionLifecycleJournalPhase,
    current: QemuProcessIdentity,
    replacement: Option<QemuProcessIdentity>,
) -> ProductionLifecycleJournal {
    ProductionLifecycleJournal {
        version: 1,
        transaction: 1,
        phase,
        nodes: vec![ProductionLifecycleJournalNode {
            node: String::from("node-a"),
            current_process: current,
            replacement_process: replacement,
            current_generation: 1,
            next_generation: 2,
            transition: String::from("Crash"),
            action_sha256: "1".repeat(64),
            evidence_sha256: "2".repeat(64),
            expected_exit_code: Some(70),
        }],
        completed_exits: Vec::new(),
    }
}

#[test]
fn durable_run_state_allows_concurrent_sessions_for_one_scenario() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, _, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("first run owner should acquire: {error}"));
    let (second, _, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("concurrent session should acquire: {error}"));
    assert_ne!(first.path(), second.path());
}

#[test]
fn durable_run_state_recovers_an_unfinished_run_before_reuse() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, mut first_manifest, first_journal) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("first run should build: {error}"));
    let first_path = first.path().to_path_buf();
    first_manifest.owner.process_id = u32::MAX;
    persist_run_state_atomic(
        &first_path.join(PRODUCTION_RUN_STATE_FILE),
        &first_manifest,
        &first_journal,
        source.plan().fault_signals().resource_limits(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("dead owner fixture should persist: {error}"));
    drop(first);

    let (second, _, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("recovered run should build: {error}"));
    assert_ne!(first_path, second.path());
    let recovered: ProductionRunState =
        decode_run_json(&first_path.join(PRODUCTION_RUN_STATE_FILE))
            .unwrap_or_else(|error| panic!("recovered state should decode: {error}"));
    assert!(recovered.manifest.clean_shutdown);
    assert!(recovered.manifest.recovered_after_host_exit);
    assert!(matches!(
        recovered.journal.phase,
        ProductionLifecycleJournalPhase::Quarantined
    ));
}

#[test]
fn durable_run_state_rejects_an_unowned_journal_process_identity() {
    let identity = QemuProcessIdentity {
        process_id: 7,
        start_time_ticks: 11,
        executable: PathBuf::from("/aos/qemu"),
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 1,
        phase: ProductionLifecycleJournalPhase::Prepared,
        nodes: vec![ProductionLifecycleJournalNode {
            node: String::from("node-a"),
            current_process: identity.clone(),
            replacement_process: Some(identity),
            current_generation: 1,
            next_generation: 2,
            transition: String::from("Crash"),
            action_sha256: "1".repeat(64),
            evidence_sha256: "2".repeat(64),
            expected_exit_code: Some(70),
        }],
        completed_exits: Vec::new(),
    };
    let manifest = ProductionRunManifest {
        version: 2,
        scenario: "3".repeat(64),
        owner: QemuProcessIdentity {
            process_id: 1,
            start_time_ticks: 1,
            executable: PathBuf::from("/aos/controller"),
        },
        processes: BTreeMap::new(),
        staged_processes: BTreeMap::new(),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };

    let error = quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("unowned journal process should fail closed"));
    assert!(error.contains("not bound to manifest process ownership"));
}

#[test]
fn durable_run_state_rejects_an_arbitrary_current_with_an_owned_replacement() {
    let current = QemuProcessIdentity {
        process_id: 7,
        start_time_ticks: 11,
        executable: PathBuf::from("/aos/qemu-current"),
    };
    let replacement = QemuProcessIdentity {
        process_id: 8,
        start_time_ticks: 12,
        executable: PathBuf::from("/aos/qemu-replacement"),
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 1,
        phase: ProductionLifecycleJournalPhase::Prepared,
        nodes: vec![ProductionLifecycleJournalNode {
            node: String::from("node-a"),
            current_process: QemuProcessIdentity {
                process_id: 99,
                start_time_ticks: 100,
                executable: PathBuf::from("/aos/unowned-qemu"),
            },
            replacement_process: Some(replacement.clone()),
            current_generation: 1,
            next_generation: 2,
            transition: String::from("Crash"),
            action_sha256: "1".repeat(64),
            evidence_sha256: "2".repeat(64),
            expected_exit_code: Some(70),
        }],
        completed_exits: Vec::new(),
    };
    let manifest = ProductionRunManifest {
        version: 2,
        scenario: "3".repeat(64),
        owner: QemuProcessIdentity {
            process_id: 1,
            start_time_ticks: 1,
            executable: PathBuf::from("/aos/controller"),
        },
        processes: BTreeMap::from([(String::from("node-a"), current)]),
        staged_processes: BTreeMap::from([(String::from("node-a"), replacement)]),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };

    let error = quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("arbitrary current identity should fail closed"));
    assert!(error.contains("not bound to manifest process ownership"));
}

#[test]
fn durable_run_state_accepts_a_prepared_replacement_at_the_exact_node_limit() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let current = QemuProcessIdentity {
        process_id: 7,
        start_time_ticks: 11,
        executable: PathBuf::from("/aos/qemu-current"),
    };
    let replacement = QemuProcessIdentity {
        process_id: 8,
        start_time_ticks: 12,
        executable: PathBuf::from("/aos/qemu-replacement"),
    };
    let manifest = ProductionRunManifest {
        version: 2,
        scenario: "3".repeat(64),
        owner: QemuProcessIdentity {
            process_id: 1,
            start_time_ticks: 1,
            executable: PathBuf::from("/aos/controller"),
        },
        processes: BTreeMap::from([(String::from("node-a"), current.clone())]),
        staged_processes: BTreeMap::from([(String::from("node-a"), replacement.clone())]),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 1,
        phase: ProductionLifecycleJournalPhase::Prepared,
        nodes: vec![ProductionLifecycleJournalNode {
            node: String::from("node-a"),
            current_process: current,
            replacement_process: Some(replacement),
            current_generation: 1,
            next_generation: 2,
            transition: String::from("Crash"),
            action_sha256: "1".repeat(64),
            evidence_sha256: "2".repeat(64),
            expected_exit_code: Some(70),
        }],
        completed_exits: Vec::new(),
    };
    persist_run_state_atomic(
        &root.path().join(PRODUCTION_RUN_STATE_FILE),
        &manifest,
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("prepared state should persist: {error}"));
    let mut limits = FaultResourceLimits::default();
    limits.nodes = 1;

    let (decoded_manifest, decoded_journal) =
        quantum_loop::decode_prior_run_state(root.path(), &manifest.scenario, limits)
            .unwrap_or_else(|error| panic!("one-node Prepared state should recover: {error}"));
    assert_eq!(decoded_manifest.processes.len(), 1);
    assert_eq!(decoded_manifest.staged_processes.len(), 1);
    assert_eq!(decoded_journal.nodes.len(), 1);
    assert!(matches!(
        decoded_journal.phase,
        ProductionLifecycleJournalPhase::Prepared
    ));
}

#[test]
fn durable_run_state_rejects_prepared_ownership_in_intent_or_committed_phase() {
    let current = recovery_process(7, "/aos/qemu-current");
    let replacement = recovery_process(8, "/aos/qemu-replacement");
    let manifest = recovery_manifest(current.clone(), Some(replacement.clone()));

    for phase in [
        ProductionLifecycleJournalPhase::Intent,
        ProductionLifecycleJournalPhase::Committed,
    ] {
        let journal = recovery_journal(phase, current.clone(), Some(replacement.clone()));
        let error = quantum_loop::validate_recovered_lifecycle_journal(
            &journal,
            &manifest,
            FaultResourceLimits::default(),
        )
        .err()
        .unwrap_or_else(|| panic!("impossible phase ownership should fail closed"));
        assert!(
            error.contains("cannot retain live node ownership")
                || error.contains("not bound to manifest process ownership")
        );
    }
}

#[test]
fn durable_run_state_accepts_both_quarantined_manifest_commit_windows() {
    let current = recovery_process(7, "/aos/qemu-current");
    let replacement = recovery_process(8, "/aos/qemu-replacement");
    let journal = recovery_journal(
        ProductionLifecycleJournalPhase::Quarantined,
        current.clone(),
        Some(replacement.clone()),
    );

    let unpublished = recovery_manifest(current, Some(replacement.clone()));
    quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &unpublished,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("pre-rename quarantine state should recover: {error}"));

    let published = recovery_manifest(replacement, None);
    quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &published,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("post-rename quarantine state should recover: {error}"));
}

#[test]
fn durable_run_state_rejects_split_file_intermediate_ownership() {
    let current = recovery_process(7, "/aos/qemu-current");
    let replacement = recovery_process(8, "/aos/qemu-replacement");

    let intent = recovery_journal(
        ProductionLifecycleJournalPhase::Intent,
        current.clone(),
        None,
    );
    let staged_manifest = recovery_manifest(current.clone(), Some(replacement.clone()));
    let intent_error = quantum_loop::validate_recovered_lifecycle_journal(
        &intent,
        &staged_manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("split-file Intent ownership should fail closed"));
    assert!(intent_error.contains("no exact lifecycle journal owner"));

    let exits_reaped = recovery_journal(
        ProductionLifecycleJournalPhase::ExitsReaped,
        current,
        Some(replacement.clone()),
    );
    let committed_manifest = recovery_manifest(replacement, None);
    let exits_error = quantum_loop::validate_recovered_lifecycle_journal(
        &exits_reaped,
        &committed_manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("split-file ExitsReaped ownership should fail closed"));
    assert!(exits_error.contains("not bound to manifest process ownership"));
}

#[test]
fn durable_run_state_rejects_impossible_permanent_failure_ownership() {
    let current = recovery_process(7, "/aos/qemu-current");
    let replacement = recovery_process(8, "/aos/qemu-replacement");
    let empty_manifest = ProductionRunManifest {
        version: 2,
        scenario: "3".repeat(64),
        owner: recovery_process(1, "/aos/controller"),
        processes: BTreeMap::new(),
        staged_processes: BTreeMap::new(),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };
    let mut advanced = recovery_journal(
        ProductionLifecycleJournalPhase::Quarantined,
        current.clone(),
        None,
    );
    advanced.nodes[0].transition = String::from("PermanentFailure");
    let advanced_error = quantum_loop::validate_recovered_lifecycle_journal(
        &advanced,
        &empty_manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("generation-advancing permanent failure should fail closed"));
    assert!(advanced_error.contains("invalid canonical fields"));

    let mut replacement_owned = recovery_journal(
        ProductionLifecycleJournalPhase::Prepared,
        current.clone(),
        Some(replacement.clone()),
    );
    replacement_owned.nodes[0].transition = String::from("PermanentFailure");
    replacement_owned.nodes[0].next_generation = 1;
    let manifest = recovery_manifest(current, Some(replacement));
    let replacement_error = quantum_loop::validate_recovered_lifecycle_journal(
        &replacement_owned,
        &manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("replacement-owned permanent failure should fail closed"));
    assert!(replacement_error.contains("not bound to manifest process ownership"));
}

#[test]
fn durable_run_state_rejects_unjournaled_staged_process_owner() {
    let current = recovery_process(7, "/aos/qemu-current");
    let staged = recovery_process(8, "/aos/qemu-staged");
    let manifest = recovery_manifest(current, Some(staged));
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 0,
        phase: ProductionLifecycleJournalPhase::Idle,
        nodes: Vec::new(),
        completed_exits: Vec::new(),
    };
    let error = quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("unjournaled staged owner should fail closed"));
    assert!(error.contains("no exact lifecycle journal owner"));
}

#[test]
fn durable_run_state_rejects_unrelated_quarantined_postcommit_owner() {
    let current = recovery_process(7, "/aos/qemu-current");
    let unrelated = recovery_process(99, "/aos/unrelated-qemu");
    let journal = recovery_journal(ProductionLifecycleJournalPhase::Quarantined, current, None);
    let manifest = recovery_manifest(unrelated, None);

    let error = quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &manifest,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("unrelated quarantined process owner should fail closed"));
    assert!(error.contains("not bound to manifest process ownership"));
}

#[test]
fn durable_run_state_rejects_oversized_json_before_decode() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let path = root.path().join("oversized.json");
    fs::write(&path, b"{\"padding\":\"0123456789\"}")
        .unwrap_or_else(|error| panic!("oversized fixture should write: {error}"));

    let error = decode_run_json_bounded::<ProductionLifecycleJournal>(&path, 8)
        .err()
        .unwrap_or_else(|| panic!("oversized run state should fail before decode"));
    assert!(error.contains("above the bounded maximum 8"));
}

#[test]
fn durable_run_state_persists_one_aggregate_envelope() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (run, _, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("aggregate run state should initialize: {error}"));

    assert!(run.path().join(PRODUCTION_RUN_STATE_FILE).is_file());
    assert!(!run.path().join("run-manifest.json").exists());
    assert!(!run.path().join("lifecycle-journal.json").exists());
    let state: ProductionRunState = decode_run_json(&run.path().join(PRODUCTION_RUN_STATE_FILE))
        .unwrap_or_else(|error| panic!("aggregate run state should decode: {error}"));
    assert_eq!(state.version, 1);
    assert_eq!(state.runtime_event_records, 0);
    assert_eq!(state.runtime_event_log_bytes, 0);
}

#[test]
fn durable_run_state_preflights_aggregate_bytes_before_owned_decode() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let state = ProductionRunState {
        version: 1,
        runtime_event_records: 0,
        runtime_event_log_bytes: 8,
        manifest: ProductionRunManifest {
            version: 2,
            scenario: "3".repeat(64),
            owner: recovery_process(1, "/aos/controller"),
            processes: BTreeMap::new(),
            staged_processes: BTreeMap::new(),
            clean_shutdown: false,
            recovered_after_host_exit: false,
        },
        journal: ProductionLifecycleJournal {
            version: 1,
            transaction: 0,
            phase: ProductionLifecycleJournalPhase::Idle,
            nodes: Vec::new(),
            completed_exits: Vec::new(),
        },
    };
    let bytes = serde_json::to_vec_pretty(&state)
        .unwrap_or_else(|error| panic!("aggregate preflight fixture should encode: {error}"));
    fs::write(root.path().join(PRODUCTION_RUN_STATE_FILE), &bytes)
        .unwrap_or_else(|error| panic!("aggregate preflight fixture should write: {error}"));
    let mut limits = FaultResourceLimits::default();
    limits.event_log_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

    let error = quantum_loop::decode_prior_run_state(root.path(), &"3".repeat(64), limits)
        .err()
        .unwrap_or_else(|| panic!("aggregate byte overflow should precede owned decode"));
    assert!(error.contains("admit aggregate prior run state"));
}

#[test]
fn durable_run_state_preflights_process_count_before_owned_map_decode() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let bytes = br#"{
      "version": 1,
      "runtime_event_records": 0,
      "runtime_event_log_bytes": 0,
      "manifest": {
        "version": 2,
        "scenario": null,
        "owner": null,
        "processes": {"node-a": null, "node-b": null},
        "staged_processes": {},
        "clean_shutdown": false,
        "recovered_after_host_exit": false
      },
      "journal": {
        "version": 1,
        "transaction": 0,
        "phase": null,
        "nodes": [],
        "completed_exits": []
      }
    }"#;
    fs::write(root.path().join(PRODUCTION_RUN_STATE_FILE), bytes)
        .unwrap_or_else(|error| panic!("count preflight fixture should write: {error}"));
    let mut limits = FaultResourceLimits::default();
    limits.nodes = 1;

    let error = quantum_loop::decode_prior_run_state(root.path(), &"3".repeat(64), limits)
        .err()
        .unwrap_or_else(|| panic!("process count should fail before owned map decode"));
    assert!(error.contains("admit current process count before owned decode"));
}
