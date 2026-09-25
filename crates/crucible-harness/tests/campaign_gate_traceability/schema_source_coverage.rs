//! Source-backed coverage for durable campaign and operator formats.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const SOURCES: &[(&str, &str)] = &[
    (
        "crates/crucible/src/model/store_artifacts.rs",
        include_str!("../../../crucible/src/model/store_artifacts.rs"),
    ),
    (
        "crates/crucible/src/trigger/evidence.rs",
        include_str!("../../../crucible/src/trigger/evidence.rs"),
    ),
    (
        "tests/crucible/_e2e-determinism-native-runner.sh",
        include_str!("../../../../tests/crucible/_e2e-determinism-native-runner.sh"),
    ),
    (
        "tests/crucible/_phase9-campaign-release-acceptance.sh",
        include_str!("../../../../tests/crucible/_phase9-campaign-release-acceptance.sh"),
    ),
    (
        "tests/crucible/_campaign-manual-evidence-spec.nix",
        include_str!("../../../../tests/crucible/_campaign-manual-evidence-spec.nix"),
    ),
    (
        "tests/crucible/e2e-determinism-evidence-contract.toml",
        include_str!("../../../../tests/crucible/e2e-determinism-evidence-contract.toml"),
    ),
    (
        "tests/crucible/campaign-release-acceptance-contract.toml",
        include_str!("../../../../tests/crucible/campaign-release-acceptance-contract.toml"),
    ),
    (
        "tests/crucible/campaign-gate-matrix-inventory.toml",
        include_str!("../../../../tests/crucible/campaign-gate-matrix-inventory.toml"),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-flight-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-flight-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml"
        ),
    ),
];

#[test]
fn reviewed_durable_source_tags_have_matching_registry_versions() {
    let registry = super::SCHEMA_REGISTRY
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next().expect("registry name");
            let version = fields
                .next()
                .expect("registry version")
                .parse::<u32>()
                .expect("numeric registry version");
            (name, version)
        })
        .collect::<BTreeMap<_, _>>();

    let mut covered = BTreeSet::new();
    for (path, source) in SOURCES {
        let tags = versioned_tags(source);
        assert!(!tags.is_empty(), "{path} has no versioned source tags");

        for (name, version) in tags {
            // This token domains a ContentHash; it is not encoded or decoded
            // as an independently versioned object.
            if name == "crucible.reproduction.event-log-artifact" {
                assert_eq!(version, 2, "{path} hash domain changed");
                continue;
            }

            assert_eq!(
                registry.get(name),
                Some(&version),
                "{path} source format {name}.v{version} lacks a matching registry row"
            );
            covered.insert(name);
        }
    }

    for name in [
        "crucible.dag-store.scenario-def",
        "crucible.dag-store.checkpoint-node",
        "crucible.dag-store.schedule-delta",
        "crucible.dag-store.cow-delta-ref",
        "crucible.external-formal-trace",
        "crucible.e2e.native-host-evidence",
        "aos.crucible.campaign-release-acceptance",
    ] {
        assert!(
            covered.contains(name),
            "reviewed source format {name} disappeared"
        );
    }

    let evaluator = include_str!("../../../crucible/src/model/fault_signal/evaluator.rs");
    assert!(evaluator.contains("EVALUATOR_CHECKPOINT_MAGIC: &[u8; 8] = b\"CREVAL02\""));
    let evaluator_version = include_str!("../../../crucible/src/model/fault_signal/mod.rs");
    assert!(evaluator_version.contains("SIGNAL_EVALUATOR_VERSION: u16 = 2"));
    assert_eq!(
        registry.get("crucible.execution.signal-evaluator-checkpoint"),
        Some(&2)
    );
}

fn versioned_tags(source: &str) -> BTreeSet<(&str, u32)> {
    source
        .split(|byte: char| !byte.is_ascii_alphanumeric() && !matches!(byte, '.' | '-' | '_'))
        .filter(|token| token.starts_with("crucible.") || token.starts_with("aos.crucible."))
        .filter_map(|token| {
            let (name, version) = token.rsplit_once(".v")?;
            let version = version.parse::<u32>().ok()?;
            Some((name, version))
        })
        .collect()
}

// Each row points at a production encoder/decoder declaration. The registry
// spelling may differ from the on-wire magic; that alias is explicit here.
// Hash domains and test literals are deliberately absent: neither has an
// independent decoder or compatibility version.
const VERSION_ANCHORS: &str = r#"
crucible.api.rpc|crates/crucible-api/src/rpc_abi.rs|number|RPC_PROTOCOL_MAJOR
crucible.production-network-adapter-checkpoint|crates/crucible-api/src/vm_lifecycle/network_faults.rs|number|NETWORK_ADAPTER_CHECKPOINT_VERSION
crucible.production-run-lock|crates/crucible-api/src/vm_lifecycle.rs|number|PRODUCTION_RUN_LOCK_VERSION
crucible.production-run-state|crates/crucible-api/src/vm_lifecycle/quantum_loop/lifecycle/persistence.rs|number|PRODUCTION_RUN_STATE_VERSION
crucible.shmem.region|crates/crucible-shmem/src/lib.rs|number|ABI_VERSION
crucible.shmem.fault-clock-evidence|crates/crucible-shmem/src/shmem/fault_clock_evidence.rs|magic|FAULT_CLOCK_EVIDENCE_MAGIC_V2
crucible.shmem.fault-clock-manifest|crates/crucible-shmem/src/shmem/fault_target_manifest.rs|number|FAULT_CLOCK_MANIFEST_VERSION_V2
crucible.executor.crucible-scenario-payload|crates/crucible-daemon/src/crucible_artifact.rs|number|CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5
crucible.executor.crucible-configuration-payload|crates/crucible-daemon/src/crucible_artifact.rs|number|CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V4
crucible.executor.finding-production-replay-capture|crates/crucible-daemon/src/finding_production_replay.rs|number|FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION
crucible.execution.scenario-form|crates/crucible/src/model/toml.rs|magic|SCENARIO_FORM_BINARY_MAGIC_V9
crucible.execution.reproduction-artifact|crates/crucible/src/model/toml.rs|magic|REPRODUCTION_ARTIFACT_BINARY_MAGIC_V9
crucible.execution.schedule|crates/crucible/src/model/toml.rs|magic|SCHEDULE_BINARY_MAGIC_V4
crucible.execution.checkpoint|crates/crucible/src/model/toml.rs|magic|CHECKPOINT_BINARY_MAGIC_V6
crucible.execution.event-log-segment|crates/crucible/src/scheduler.rs|number|EVENT_LOG_SEGMENT_BINARY_VERSION
crucible.execution.backend-network-output|crates/crucible/src/backend/io/network_checkpoint.rs|number|BACKEND_NETWORK_OUTPUT_VERSION
crucible.execution.scheduler-network|crates/crucible/src/scheduler/runtime_state/network_checkpoint.rs|magic|SCHEDULER_NETWORK_CHECKPOINT_MAGIC
crucible.execution.event-graph-state|crates/crucible/src/trigger/event_graph.rs|magic|crucible.event-graph-state.v2
crucible.execution.signal-trace-manifest|crates/crucible/src/model/fault_signal/trace.rs|magic|MANIFEST_MAGIC
crucible.execution.signal-trace-chunk|crates/crucible/src/model/fault_signal/trace.rs|magic|CHUNK_MAGIC
crucible.execution.failure-triage-replay-evidence|crates/crucible/src/model/failure/replay_evidence.rs|number|FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
crucible.execution.host-assertion-continuation|crates/crucible/src/trigger/assertions.rs|magic|HOST_ASSERTION_CHECKPOINT_MAGIC
crucible.execution.single-scheduler-continuation|crates/crucible/src/scheduler/checkpoint.rs|magic|crucible.single-scheduler-continuation.v3
crucible.execution.device-scheduling-subnode|crates/crucible/src/device_subnode/checkpoint.rs|magic|crucible.device-scheduling-subnode.v1
crucible.execution.scenario-selectable-component|crates/crucible/src/model/scenario_selectables.rs|number|SCENARIO_SELECTABLE_VERSION
crucible.execution.fault-adapter-checkpoint|crates/crucible/src/model/fault_signal/adapter_runtime.rs|number|ADAPTER_CHECKPOINT_VERSION
crucible.execution.fault-runtime-checkpoint|crates/crucible/src/model/fault_signal/runtime.rs|number|FAULT_RUNTIME_STATE_VERSION
crucible.execution.resolved-effect-trace|crates/crucible/src/model/fault_signal/runtime.rs|magic|RESOLVED_EFFECT_TRACE_MAGIC
crucible.execution.signal-inverse-cdf-table|crates/crucible/src/model/fault_signal/sampler.rs|magic|CRCDFTB1
crucible.execution.signal-spatial-artifact|crates/crucible/src/model/fault_signal/spatial.rs|magic|CRSPAT01
crucible.execution.signal-evaluator-checkpoint|crates/crucible/src/model/fault_signal/evaluator.rs|magic|EVALUATOR_CHECKPOINT_MAGIC
crucible.device.block-fault-state|crates/crucible-device/src/block/fault/checkpoint_codec.rs|magic|BLOCK_FAULT_STATE_MAGIC
crucible.device.block-snapshot|crates/crucible-device/src/block/device/snapshot.rs|magic|BLOCK_SNAPSHOT_MAGIC
crucible.device.io-core-snapshot|crates/crucible-device/src/subnode/snapshot.rs|magic|IO_CORE_SNAPSHOT_MAGIC
crucible.device.link-snapshot|crates/crucible-device/src/netlink/link/snapshot.rs|magic|LINK_SNAPSHOT_MAGIC
crucible.device.ninep-snapshot|crates/crucible-device/src/ninep/device/snapshot.rs|magic|NINEP_SNAPSHOT_MAGIC
crucible.qemu.checkpoint-qmp|crates/crucible-qemu/src/qmp/ram_delta.rs|number|QMP_CHECKPOINT_SCHEMA_VERSION
crucible.qemu.host-io-checkpoint|crates/crucible-qemu/src/checkpoint/host_io_codec.rs|magic|crucible.qemu-host-io-checkpoint.v5
crucible.qemu.production-fault-runtime|crates/crucible-qemu/src/production_fault_runtime/checkpoint_codec.rs|magic|crucible.production-fault-runtime.v7
crucible.qemu.node-continuation|crates/crucible-qemu/src/checkpoint.rs|magic|crucible.qemu-node-continuation.v7
crucible.qemu.accelerator-checkpoint|crates/crucible-qemu/src/supervision/accelerator_io_servicer.rs|magic|ACCELERATOR_CHECKPOINT_MAGIC
crucible.live-qemu-replay-contract|crates/crucible-cli/src/cli/artifact/live_qemu.rs|magic|LIVE_QEMU_REPLAY_CONTRACT_SCHEMA
crucible.qemu.hot-fork.template|crates/crucible-qemu/src/qmp/hot_fork/template.rs|number|QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION
crucible.qemu.hot-fork.template-resource-stage|crates/crucible-qemu/src/qmp/hot_fork/template.rs|number|QMP_HOT_FORK_TEMPLATE_RESOURCE_STAGE_SCHEMA_VERSION
crucible.qemu.hot-fork.fork|crates/crucible-qemu/src/qmp/hot_fork/fork.rs|number|QMP_HOT_FORK_SCHEMA_VERSION
crucible.qemu.hot-fork.plugin-endpoints|crates/crucible-qemu/src/qmp/hot_fork/plugin_endpoints.rs|number|QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION
crucible.qemu.hot-fork.private-rings|crates/crucible-qemu/src/qmp/hot_fork/private_rings.rs|number|QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION
crucible.qemu.hot-fork.async-worker-barrier|crates/crucible-qemu/src/qmp/hot_fork/async_worker_barrier.rs|number|QMP_HOT_FORK_ASYNC_WORKER_BARRIER_SCHEMA_VERSION
crucible.qemu.hot-fork.block-barrier|crates/crucible-qemu/src/qmp/hot_fork/block_barrier.rs|number|QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION
crucible.qemu.hot-fork.block-source-proof|crates/crucible-qemu/src/qmp/hot_fork/block_barrier/source_proof.rs|number|QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION
crucible.qemu.hot-fork.rcu-barrier|crates/crucible-qemu/src/qmp/hot_fork/rcu_barrier.rs|number|QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION
crucible.qemu.hot-fork.child-process|crates/crucible-qemu/src/qmp/hot_fork/child_process.rs|number|QMP_HOT_FORK_CHILD_PROCESS_SCHEMA_VERSION
crucible.qemu.hot-fork.child-process-contract|crates/crucible-qemu/src/qmp/hot_fork/child_process_contract.rs|number|QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_SCHEMA_VERSION
crucible.qemu.hot-fork.child-files|crates/crucible-qemu/src/qmp/hot_fork/child_files.rs|number|QMP_HOT_FORK_CHILD_FILES_SCHEMA_VERSION
crucible.qemu.hot-fork.child-qmp|crates/crucible-qemu/src/qmp/hot_fork/child_qmp.rs|number|QMP_HOT_FORK_CHILD_QMP_SCHEMA_VERSION
crucible.qemu.hot-fork.child-console|crates/crucible-qemu/src/qmp/hot_fork/child_console.rs|number|QMP_HOT_FORK_CHILD_CONSOLE_SCHEMA_VERSION
crucible.qemu.hot-fork.child-diagnostics|crates/crucible-qemu/src/qmp/hot_fork/diagnostics.rs|number|QMP_HOT_FORK_CHILD_DIAGNOSTICS_SCHEMA_VERSION
"#;

#[test]
fn production_codec_declarations_match_registry_versions() {
    let registry = registry_versions(super::SCHEMA_REGISTRY);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut covered = BTreeSet::new();

    for line in VERSION_ANCHORS.lines().filter(|line| !line.is_empty()) {
        let [name, path, kind, marker] = line
            .split('|')
            .collect::<Vec<_>>()
            .try_into()
            .expect("anchor fields");
        assert!(covered.insert(name), "duplicate source anchor {name}");

        let source =
            fs::read_to_string(root.join(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        if let Some(drift) = source_registry_drift(&registry, name, &source, kind, marker) {
            panic!("{path}: {drift}");
        }
    }

    assert_eq!(
        covered.len(),
        VERSION_ANCHORS
            .lines()
            .filter(|line| !line.is_empty())
            .count()
    );
}

fn registry_versions(registry: &str) -> BTreeMap<&str, u32> {
    registry
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next().expect("registry name");
            let version = fields
                .next()
                .expect("registry version")
                .parse()
                .expect("numeric registry version");
            (name, version)
        })
        .collect()
}

fn source_registry_drift(
    registry: &BTreeMap<&str, u32>,
    name: &str,
    source: &str,
    kind: &str,
    marker: &str,
) -> Option<String> {
    let source_version = source_anchor_version(source, kind, marker);
    (registry.get(name) != Some(&source_version)).then(|| {
        format!(
            "{name} source version {source_version} differs from registry {:?}",
            registry.get(name)
        )
    })
}

fn source_anchor_version(source: &str, kind: &str, marker: &str) -> u32 {
    let literal_marker = kind == "magic" && marker.contains(".v");
    let declaration = source
        .lines()
        .find(|line| line.contains(marker) && (line.contains("const ") || literal_marker))
        .unwrap_or_else(|| panic!("source declaration {marker} is absent"));

    match kind {
        "number" => {
            let value = declaration
                .split_once('=')
                .expect("numeric anchor assignment")
                .1
                .trim();
            value
                .trim_end_matches(';')
                .parse()
                .expect("literal numeric source version")
        }
        "magic" => {
            let tail = &source[source.find(declaration).expect("magic declaration")..];
            let (_, value) = tail
                .split_once('"')
                .unwrap_or_else(|| panic!("{marker}: magic opening quote"));
            let (value, _) = value
                .split_once('"')
                .unwrap_or_else(|| panic!("{marker}: magic closing quote"));
            let digits = if let Some((_, suffix)) = value.rsplit_once(".v") {
                suffix
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>()
            } else {
                value
                    .chars()
                    .rev()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect()
            };
            digits.parse().expect("numeric magic version")
        }
        other => panic!("unknown source anchor kind {other}"),
    }
}

#[test]
fn source_version_changes_fail_registry_lint() {
    let source = "pub const RPC_PROTOCOL_MAJOR: u16 = 9;";
    let registry = registry_versions(super::SCHEMA_REGISTRY);
    assert!(
        source_registry_drift(
            &registry,
            "crucible.api.rpc",
            source,
            "number",
            "RPC_PROTOCOL_MAJOR"
        )
        .is_some(),
        "a changed source declaration must fail the same registry check"
    );
}

#[test]
fn measurement_hash_domains_do_not_relabel_payload_versions() {
    let definitions = include_str!("../../../crucible/src/model/measurement.rs");
    let evaluation = include_str!("../../../crucible/src/model/measurement/runtime.rs");
    let registry = registry_versions(super::SCHEMA_REGISTRY);

    assert!(definitions.contains(
        "ContentHash::from_canonical_hex_bytes(\n            \"crucible.model.measurement-definitions.v2\""
    ));
    assert!(evaluation.contains(
        "ContentHash::from_canonical_hex_bytes(\n            \"crucible.model.measurement-evaluation.v2\""
    ));
    assert_eq!(
        registry.get("crucible.execution.measurement-definitions"),
        Some(&1)
    );
    assert_eq!(
        registry.get("crucible.execution.measurement-evaluation"),
        Some(&1)
    );
}

#[test]
fn qemu_vmstate_section_versions_match_registry() {
    let registry = registry_versions(super::SCHEMA_REGISTRY);
    let patch = include_str!("../../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch");
    let lines = patch.lines().collect::<Vec<_>>();
    let mut covered = BTreeSet::new();

    for (index, line) in lines.iter().enumerate() {
        let Some(name) = line
            .strip_prefix("+    .name = \"")
            .and_then(|line| line.split_once('"').map(|(name, _)| name))
        else {
            continue;
        };
        // This Crucible-owned section deliberately retains QEMU's existing name.
        if !name.contains("crucible") && name != "virtio-blk/dropped-requests" {
            continue;
        }

        let Some(version) = lines[index + 1..]
            .iter()
            .take(4)
            .find_map(|line| line.strip_prefix("+    .version_id = "))
            .and_then(|version| version.trim_end_matches(',').parse::<u32>().ok())
        else {
            continue; // A QOM or transport name, not a VMStateDescription.
        };

        let normalized = name.replace('/', "-").replace('_', "-").replace(' ', "-");
        let registry_name = format!("crucible.qemu.vmstate.{normalized}");
        assert!(
            covered.insert(registry_name.clone()),
            "duplicate QEMU VMState section {name}"
        );
        assert_eq!(
            registry.get(registry_name.as_str()),
            Some(&version),
            "QEMU VMState section {name} version {version} differs from registry"
        );
    }

    let registered = registry
        .keys()
        .filter(|name| name.starts_with("crucible.qemu.vmstate."))
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        registered,
        "QEMU VMState inventory differs from the registry"
    );
}
