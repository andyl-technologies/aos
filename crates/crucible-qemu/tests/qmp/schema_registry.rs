//! Hot-fork QMP schema ownership and version checks.

#[test]
fn hot_fork_qmp_schemas_have_current_registry_owners() {
    use crucible_qemu::{
        QMP_HOT_FORK_ASYNC_WORKER_BARRIER_SCHEMA_VERSION,
        QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION, QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION,
        QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION,
        QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION,
        QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION,
        QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION, QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION,
        QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION, QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION,
        QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION,
        QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION,
        QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION, QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION,
        QMP_HOT_FORK_SCHEMA_VERSION, QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION,
    };

    let registry =
        include_str!("../../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");
    let schemas = [
        ("template", QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION),
        ("fork", QMP_HOT_FORK_SCHEMA_VERSION),
        (
            "plugin-resource-inventory",
            QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION,
        ),
        ("plugin-barrier", QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION),
        ("child-runtime", QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION),
        (
            "async-worker-barrier",
            QMP_HOT_FORK_ASYNC_WORKER_BARRIER_SCHEMA_VERSION,
        ),
        ("block-barrier", QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION),
        (
            "block-source-proof",
            QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION,
        ),
        ("rcu-barrier", QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION),
        ("private-rings", QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION),
        (
            "plugin-endpoints",
            QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION,
        ),
        ("child-process", QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION),
        (
            "child-process-contract",
            QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION,
        ),
        ("child-files", QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION),
        ("child-qmp", QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION),
        ("child-console", QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION),
        (
            "child-diagnostics",
            QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION,
        ),
    ];

    for (name, version) in schemas {
        let row = format!(
            "crucible.qemu.hot-fork.{name}\t{version}\tcrucible-qemu::qmp::hot_fork\tprocess-protocol-message\t"
        );
        assert!(
            registry.lines().any(|line| line.starts_with(&row)),
            "missing current hot-fork QMP schema {name}"
        );
    }

    let registered = registry
        .lines()
        .filter(|line| line.contains("\tcrucible-qemu::qmp::hot_fork\tprocess-protocol-message\t"))
        .filter_map(|line| line.split_once('\t'))
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("crucible.qemu.hot-fork."))
        .collect::<std::collections::BTreeSet<_>>();
    let current = schemas
        .map(|(name, _)| format!("crucible.qemu.hot-fork.{name}"))
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(registered.len(), current.len());
    assert!(
        current
            .iter()
            .all(|name| registered.contains(name.as_str()))
    );
}
