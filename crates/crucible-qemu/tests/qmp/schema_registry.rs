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
        QMP_HOT_FORK_SCHEMA_VERSION, QMP_HOT_FORK_TEMPLATE_RESOURCE_STAGE_SCHEMA_VERSION,
        QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION,
    };

    let registry =
        include_str!("../../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");
    let schemas = [
        ("template", QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION),
        (
            "template-resource-stage",
            QMP_HOT_FORK_TEMPLATE_RESOURCE_STAGE_SCHEMA_VERSION,
        ),
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

#[test]
fn patched_qapi_commands_have_schema_owners_or_qapi_only_contracts() {
    use std::collections::BTreeSet;

    let patch = include_str!("../../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch");
    let registry =
        include_str!("../../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");

    // These commands exchange a separately versioned Crucible payload.
    let versioned = [
        (
            "query-crucible-fingerprint-projection-manifest",
            "crucible.qemu.fingerprint-projection-manifest",
        ),
        (
            "crucible-hot-fork-block-barrier",
            "crucible.qemu.hot-fork.block-barrier",
        ),
        (
            "query-crucible-hot-fork-plugin-resource-inventory",
            "crucible.qemu.hot-fork.plugin-resource-inventory",
        ),
        (
            "crucible-hot-fork-plugin-barrier",
            "crucible.qemu.hot-fork.plugin-barrier",
        ),
        (
            "query-crucible-hot-fork-child-runtime",
            "crucible.qemu.hot-fork.child-runtime",
        ),
        (
            "crucible-hot-fork-rcu-barrier",
            "crucible.qemu.hot-fork.rcu-barrier",
        ),
        (
            "crucible-hot-fork-async-worker-barrier",
            "crucible.qemu.hot-fork.async-worker-barrier",
        ),
        (
            "crucible-hot-fork-template",
            "crucible.qemu.hot-fork.template",
        ),
        ("crucible-hot-fork", "crucible.qemu.hot-fork.fork"),
        (
            "crucible-hot-fork-child-process",
            "crucible.qemu.hot-fork.child-process",
        ),
        (
            "crucible-hot-fork-child-process-contract",
            "crucible.qemu.hot-fork.child-process-contract",
        ),
        (
            "crucible-hot-fork-child-files",
            "crucible.qemu.hot-fork.child-files",
        ),
        (
            "crucible-hot-fork-private-rings",
            "crucible.qemu.hot-fork.private-rings",
        ),
        (
            "crucible-hot-fork-plugin-endpoints",
            "crucible.qemu.hot-fork.plugin-endpoints",
        ),
        (
            "crucible-hot-fork-child-diagnostics",
            "crucible.qemu.hot-fork.child-diagnostics",
        ),
        (
            "crucible-hot-fork-child-qmp",
            "crucible.qemu.hot-fork.child-qmp",
        ),
        (
            "crucible-hot-fork-child-console",
            "crucible.qemu.hot-fork.child-console",
        ),
        (
            "crucible-checkpoint-capture",
            "crucible.qemu.checkpoint-qmp",
        ),
        ("crucible-checkpoint-commit", "crucible.qemu.checkpoint-qmp"),
        ("crucible-checkpoint-abort", "crucible.qemu.checkpoint-qmp"),
        (
            "query-crucible-checkpoint-epoch",
            "crucible.qemu.checkpoint-qmp",
        ),
        (
            "crucible-checkpoint-restore",
            "crucible.qemu.checkpoint-qmp",
        ),
    ];

    // These additions have no independent schema-version field. QAPI owns
    // their shape, and the pinned patched-QEMU release is their version.
    let qapi_only = [
        "crucible-complete-terminal-lifecycle",
        "query-crucible-selectable-reply-boundary",
        "crucible-complete-selectable-reply",
        "x-crucible-adopt-launch-fdsets",
    ];

    let declared = patch
        .lines()
        .filter_map(|line| line.strip_prefix("+{ 'command': '"))
        .filter_map(|line| line.split_once('\''))
        .map(|(name, _)| name)
        .filter(|name| name.contains("crucible"))
        .collect::<BTreeSet<_>>();
    let classified = versioned
        .iter()
        .map(|(command, _)| *command)
        .chain(qapi_only)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared, classified,
        "Crucible QAPI command inventory drift"
    );

    for (_, schema) in versioned {
        assert!(
            registry
                .lines()
                .any(|line| line.starts_with(&format!("{schema}\t"))),
            "missing QMP schema owner {schema}"
        );
    }
}
