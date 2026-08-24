//! Durable run-state admission and ownership regressions.

use super::*;

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
    let (first, mut first_manifest, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("first run should build: {error}"));
    let first_path = first.path().to_path_buf();
    first_manifest.owner.process_id = u32::MAX;
    persist_atomic_json(&first_path.join("run-manifest.json"), &first_manifest)
        .unwrap_or_else(|error| panic!("dead owner fixture should persist: {error}"));
    drop(first);

    let (second, _, _) = production_run_directory(
        &scenario,
        &config,
        source.plan().fault_signals().resource_limits(),
    )
    .unwrap_or_else(|error| panic!("recovered run should build: {error}"));
    assert_ne!(first_path, second.path());
    let recovered: ProductionRunManifest = decode_run_json(&first_path.join("run-manifest.json"))
        .unwrap_or_else(|error| panic!("recovered manifest should decode: {error}"));
    assert!(recovered.clean_shutdown);
    assert!(recovered.recovered_after_host_exit);
    let journal: ProductionLifecycleJournal =
        decode_run_json(&first_path.join("lifecycle-journal.json"))
            .unwrap_or_else(|error| panic!("recovered journal should decode: {error}"));
    assert!(matches!(
        journal.phase,
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
