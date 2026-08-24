//! Durable run-state aggregate resource admission regressions.

use super::*;

#[test]
fn durable_run_state_rejects_old_outer_version_before_owned_decode() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let manifest = recovery_manifest(recovery_process(7, "/aos/qemu-current"), None);
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 0,
        phase: ProductionLifecycleJournalPhase::Idle,
        nodes: Vec::new().into(),
        completed_exits: Vec::new().into(),
    };
    let path = root.path().join(PRODUCTION_RUN_STATE_FILE);
    persist_run_state_atomic(
        &path,
        &manifest,
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("current run state should persist: {error}"));
    let current = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("current run state should read: {error}"));
    let old = current.replacen("\"version\": 2", "\"version\": 1", 1);
    fs::write(&path, old)
        .unwrap_or_else(|error| panic!("old-version fixture should write: {error}"));

    let error = quantum_loop::decode_prior_run_state(
        root.path(),
        &manifest.scenario,
        FaultResourceLimits::default(),
    )
    .err()
    .unwrap_or_else(|| panic!("old outer version should fail before owned decode"));
    assert!(error.contains("incompatible version 1"));
}

#[test]
fn durable_run_state_rejects_impossible_completed_exit_history() {
    let manifest = recovery_manifest(recovery_process(7, "/aos/qemu-current"), None);
    let valid_exit = ProductionLifecycleCompletedExit {
        transaction: 1,
        node: String::from("node-a"),
        process: recovery_process(6, "/aos/qemu-prior"),
        generation: 1,
        transition: String::from("Crash"),
        action_sha256: "1".repeat(64),
        evidence_sha256: "2".repeat(64),
        expected_exit_code: 70,
        observed_exit_code: 70,
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 2,
        phase: ProductionLifecycleJournalPhase::Committed,
        nodes: Vec::new().into(),
        completed_exits: vec![valid_exit.clone()].into(),
    };
    quantum_loop::validate_recovered_lifecycle_journal(
        &journal,
        &manifest,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("canonical completed exit should recover: {error}"));

    for invalid in [
        ProductionLifecycleCompletedExit {
            transition: String::from("Boot"),
            expected_exit_code: 70,
            ..valid_exit.clone()
        },
        ProductionLifecycleCompletedExit {
            transaction: 0,
            ..valid_exit.clone()
        },
        ProductionLifecycleCompletedExit {
            transaction: 3,
            ..valid_exit.clone()
        },
        ProductionLifecycleCompletedExit {
            expected_exit_code: 71,
            observed_exit_code: 71,
            ..valid_exit.clone()
        },
    ] {
        let mut invalid_journal = journal.clone();
        invalid_journal.completed_exits = vec![invalid].into();
        assert!(
            quantum_loop::validate_recovered_lifecycle_journal(
                &invalid_journal,
                &manifest,
                FaultResourceLimits::default(),
            )
            .is_err()
        );
    }

    let mut duplicated = journal;
    duplicated.completed_exits = vec![valid_exit.clone(), valid_exit].into();
    assert!(
        quantum_loop::validate_recovered_lifecycle_journal(
            &duplicated,
            &manifest,
            FaultResourceLimits::default(),
        )
        .is_err()
    );
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
    assert_eq!(state.version, 2);
    assert_eq!(state.runtime_event_records, 0);
    assert_eq!(state.runtime_event_log_bytes, 0);
}

#[test]
fn durable_run_state_preflights_aggregate_bytes_before_owned_decode() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let state = ProductionRunState {
        version: 2,
        runtime_event_records: 0,
        runtime_event_log_bytes: 8,
        manifest: ProductionRunManifest {
            version: 2,
            scenario: "3".repeat(64),
            owner: recovery_process(1, "/aos/controller"),
            processes: process_owners::ProductionProcessOwners::new(),
            staged_processes: process_owners::ProductionProcessOwners::new(),
            clean_shutdown: false,
            recovered_after_host_exit: false,
        },
        journal: ProductionLifecycleJournal {
            version: 1,
            transaction: 0,
            phase: ProductionLifecycleJournalPhase::Idle,
            nodes: Vec::new().into(),
            completed_exits: Vec::new().into(),
        },
    };
    let bytes = serde_json::to_vec_pretty(&state)
        .unwrap_or_else(|error| panic!("aggregate preflight fixture should encode: {error}"));
    fs::write(root.path().join(PRODUCTION_RUN_STATE_FILE), &bytes)
        .unwrap_or_else(|error| panic!("aggregate preflight fixture should write: {error}"));
    let limits = FaultResourceLimits {
        event_log_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ..FaultResourceLimits::default()
    };

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
      "version": 2,
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
    let limits = FaultResourceLimits {
        nodes: 1,
        ..FaultResourceLimits::default()
    };

    let error = quantum_loop::decode_prior_run_state(root.path(), &"3".repeat(64), limits)
        .err()
        .unwrap_or_else(|| panic!("process count should fail before owned map decode"));
    assert!(error.contains("admit current process count before owned decode"));
}

#[test]
fn durable_run_state_owned_decode_is_canonical_and_escape_free() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let current = recovery_process(7, "/aos/qemu-a");
    let mut manifest = recovery_manifest(current, None);
    manifest
        .processes
        .try_reserve_exact(1)
        .unwrap_or_else(|()| panic!("second process owner should reserve"));
    manifest
        .processes
        .insert_reserved(String::from("node-b"), recovery_process(8, "/aos/qemu-b"))
        .unwrap_or_else(|()| panic!("reserved second process owner should insert"));
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 0,
        phase: ProductionLifecycleJournalPhase::Idle,
        nodes: Vec::new().into(),
        completed_exits: Vec::new().into(),
    };
    let path = root.path().join(PRODUCTION_RUN_STATE_FILE);
    persist_run_state_atomic(
        &path,
        &manifest,
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("canonical process owners should persist: {error}"));
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("run state should read: {error}"));
    let node_a = bytes
        .windows(b"node-a".len())
        .position(|window| window == b"node-a")
        .unwrap_or_else(|| panic!("node-a should be encoded"));
    let node_b = bytes
        .windows(b"node-b".len())
        .position(|window| window == b"node-b")
        .unwrap_or_else(|| panic!("node-b should be encoded"));
    assert!(node_a < node_b);

    let (decoded, _, _, _) = quantum_loop::decode_prior_run_state(
        root.path(),
        &"3".repeat(64),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("fallible owned decode should succeed: {error}"));
    assert_eq!(decoded.processes, manifest.processes);

    manifest.owner.executable = PathBuf::from("/aos/control\"ler");
    let error = persist_run_state_atomic(
        &root.path().join("escaped.json"),
        &manifest,
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .err()
    .unwrap_or_else(|| panic!("escaped durable ownership should fail before publication"));
    assert!(error.contains("without escape sequences"));
}
