//! Exact-checkpoint capture ownership regressions.

use super::*;

#[test]
fn preparation_is_all_or_nothing_before_qmp_capture() {
    let source = crucible::crash_restart_scenario()
        .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
        .scenario;
    let configuration = Configuration::genesis(source.scenario_def());
    let node_a = NodeId {
        name: String::from("node-a"),
    };
    let node_b = NodeId {
        name: String::from("node-b"),
    };
    let node_icounts = BTreeMap::from([
        (node_a.clone(), crucible::Icount { retired: 11 }),
        (node_b.clone(), crucible::Icount { retired: 13 }),
    ]);
    let boundaries = || {
        vec![
            (
                node_a.clone(),
                11,
                VirtualTime { ticks: 17 },
                ProductionNodeServiceState::Running,
            ),
            (
                node_b.clone(),
                13,
                VirtualTime { ticks: 19 },
                ProductionNodeServiceState::PoweredOff,
            ),
        ]
    };
    let indexes = BTreeMap::from([(node_a.clone(), 0), (node_b.clone(), 1)]);
    let directories = BTreeMap::from([
        (node_a.clone(), PathBuf::from("generation-a")),
        (node_b.clone(), PathBuf::from("generation-b")),
    ]);
    let staging = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("checkpoint staging should build: {error}"));

    let prepared = prepare_exact_checkpoint_targets(
        &configuration,
        VirtualTime { ticks: 23 },
        &node_icounts,
        boundaries(),
        &indexes,
        &directories,
        staging.path(),
    )
    .unwrap_or_else(|error| panic!("every target should prepare: {error}"));
    assert_eq!(prepared.len(), 2);
    assert_eq!(prepared[0].node, node_a);
    assert_eq!(prepared[0].checkpoint.node_icounts, node_icounts);
    assert_eq!(
        prepared[1].staged_vmstate,
        staging.path().join("node-1-vmstate.qcow2")
    );

    let incomplete_directories = BTreeMap::from([(node_a.clone(), PathBuf::from("generation-a"))]);
    let error = prepare_exact_checkpoint_targets(
        &configuration,
        VirtualTime { ticks: 23 },
        &node_icounts,
        boundaries(),
        &indexes,
        &incomplete_directories,
        staging.path(),
    )
    .err()
    .unwrap_or_else(|| panic!("a missing later target owner should fail preparation"));
    assert!(error.to_string().contains("node-b"));
}
