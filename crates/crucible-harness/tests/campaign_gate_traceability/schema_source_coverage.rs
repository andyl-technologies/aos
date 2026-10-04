//! Source-backed coverage for durable campaign and gate-evidence formats.

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
        "tests/crucible/campaign-release-acceptance-contract.toml",
        include_str!("../../../../tests/crucible/campaign-release-acceptance-contract.toml"),
    ),
    (
        "tests/crucible/campaign-gate-matrix-inventory.toml",
        include_str!("../../../../tests/crucible/campaign-gate-matrix-inventory.toml"),
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
        "crucible.e2e.native-gate-evidence",
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
crucible.execution.single-scheduler-continuation|crates/crucible/src/scheduler/checkpoint.rs|magic|crucible.single-scheduler-continuation.v6
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
crucible.qemu.host-io-checkpoint|crates/crucible-qemu/src/checkpoint/host_io_codec.rs|magic|crucible.qemu-host-io-checkpoint.v6
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

// Added production VMStateDescription declarations with an owned name or
// declaration identify this inventory. Diagnostic test descriptors and
// upstream declarations that are merely context remain outside it.
fn owned_qemu_vmstate_sections(patch: &str) -> Result<BTreeMap<String, u32>, String> {
    let lines = patch.lines().collect::<Vec<_>>();
    let mut sections = BTreeMap::new();
    // Bare declaration snippets exercise the same production rules in tests.
    let mut production_file = true;

    if lines.iter().any(|line| pinned_qemu_macro_changed(line)) {
        return Err("Pinned QEMU VMState macro definition changed".to_owned());
    }

    for (index, line) in lines.iter().enumerate() {
        if line.starts_with("diff --git ") {
            production_file = true;
        }
        if let Some(path) = line.strip_prefix("+++ ") {
            let path = path.trim_matches('"');
            production_file = path
                .strip_prefix("b/")
                .is_some_and(|path| !path.starts_with("tests/"));
            continue;
        }
        if !production_file {
            continue;
        }
        let Some(declaration) = line.strip_prefix('+').map(str::trim) else {
            continue;
        };
        if !declaration.contains("VMStateDescription ") || !declaration.ends_with("= {") {
            continue;
        }

        let mut name = None;
        let mut version = None;
        for field in &lines[index + 1..] {
            let Some(field) = field.strip_prefix('+').map(str::trim) else {
                break;
            };
            if field.starts_with(".fields =") || field == "};" {
                break;
            }
            if let Some(value) = field.strip_prefix(".name = ") {
                name = qemu_vmstate_literal_name(value)?;
            }
            if let Some(value) = field.strip_prefix(".version_id = ") {
                version = value.trim_end_matches(',').parse::<u32>().ok();
            }
        }

        let declaration_identifies_owned =
            declaration.contains("crucible") || declaration.contains("_wide");
        let Some(name) = name else {
            if declaration_identifies_owned {
                return Err(format!(
                    "Owned QEMU VMState declaration has no literal name: {declaration}"
                ));
            }
            continue;
        };
        let owned = name.contains("crucible")
            || name == "virtio-blk/dropped-requests"
            || name.ends_with("-wide")
            || name.ends_with("/wide");
        if !owned {
            continue;
        }
        let version = version.filter(|version| *version != 0).ok_or_else(|| {
            format!("Owned QEMU VMState section {name} has no positive literal version")
        })?;

        // New wide formats have distinct literal names across targets (for
        // example cpu/timer versus cpu_timer). Escape separators losslessly;
        // preserve the established IDs of previously registered formats.
        let wide = name.ends_with("-wide") || name.ends_with("/wide");
        let normalized = if wide {
            name.replace('%', "%25")
                .replace('/', "%2f")
                .replace(' ', "%20")
        } else {
            name.replace(['/', '_', ' '], "-")
        };
        let registry_name = format!("crucible.qemu.vmstate.{normalized}");
        if sections.insert(registry_name.clone(), version).is_some() {
            return Err(format!(
                "Duplicate or colliding QEMU VMState name {registry_name}"
            ));
        }
    }
    Ok(sections)
}

fn pinned_qemu_macro_changed(line: &str) -> bool {
    let Some(changed) = line.strip_prefix(['+', '-']) else {
        return false;
    };
    let Some(directive) = changed.trim_start().strip_prefix('#') else {
        return false;
    };
    let mut tokens = directive.split_ascii_whitespace();
    if !matches!(tokens.next(), Some("define" | "undef")) {
        return false;
    }
    let Some(name) = tokens.next() else {
        return false;
    };
    // Function-like definitions must not evade the same alias check.
    name.split(|byte: char| !byte.is_ascii_alphanumeric() && byte != '_')
        .next()
        == Some("TYPE_IMX6UL_LCDIF")
}

fn qemu_vmstate_literal_name(expression: &str) -> Result<Option<String>, String> {
    let expression = expression.trim_end_matches(',').trim();
    if let Some(literal) = expression
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        && !literal.contains(['"', '\\'])
    {
        return Ok(Some(literal.to_owned()));
    }

    // This unchanged header constant is from the pinned sole upstream source:
    // include/hw/display/imx6ul_lcdif.h defines TYPE_IMX6UL_LCDIF as
    // "imx6ul-lcdif". The owned subsection concatenates this exact suffix.
    if expression == "TYPE_IMX6UL_LCDIF \"/crucible-clock\"" {
        return Ok(Some("imx6ul-lcdif/crucible-clock".to_owned()));
    }
    if expression.contains("crucible")
        || expression.contains("-wide")
        || expression.contains("/wide")
    {
        return Err(format!("Unresolved owned QEMU VMState name: {expression}"));
    }
    Ok(None)
}

fn validate_qemu_vmstate_registry(
    patch: &str,
    registry: &BTreeMap<&str, u32>,
) -> Result<(), String> {
    let sections = owned_qemu_vmstate_sections(patch)?;
    let registered = registry
        .iter()
        .filter(|(name, _)| name.starts_with("crucible.qemu.vmstate."))
        .map(|(name, version)| ((*name).to_owned(), *version))
        .collect::<BTreeMap<_, _>>();

    if sections != registered {
        return Err(format!(
            "QEMU VMState inventory or versions differ: actual={sections:?}, registry={registered:?}"
        ));
    }
    Ok(())
}

const QEMU_PATCH: &str =
    include_str!("../../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch");

#[test]
fn qemu_vmstate_section_versions_match_registry() {
    // The single macro alias above is anchored to this immutable header base.
    let descriptor = include_str!("../../../../pkgs/emulation/qemu-patches/_atomic-patch.nix");
    assert!(descriptor.contains("baseCommit = \"1ed046750938db278a12dc55c6a7934d5fc68c14\";"));
    validate_qemu_vmstate_registry(QEMU_PATCH, &registry_versions(super::SCHEMA_REGISTRY))
        .expect("Every owned QEMU VMState format has its exact current registry version");
}

#[test]
fn qemu_vmstate_registry_rejects_missing_wide_format() {
    let mut registry = registry_versions(super::SCHEMA_REGISTRY);
    assert_eq!(
        registry.remove("crucible.qemu.vmstate.ptimer%2fexact-wide"),
        Some(1)
    );
    assert!(validate_qemu_vmstate_registry(QEMU_PATCH, &registry).is_err());
}

#[test]
fn qemu_vmstate_registry_rejects_deleted_format() {
    let mut registry = registry_versions(super::SCHEMA_REGISTRY);
    assert!(
        registry
            .insert("crucible.qemu.vmstate.apic-crucible-clock", 3)
            .is_none()
    );
    assert!(validate_qemu_vmstate_registry(QEMU_PATCH, &registry).is_err());
}

#[test]
fn qemu_vmstate_registry_rejects_version_drift() {
    let mut registry = registry_versions(super::SCHEMA_REGISTRY);
    assert_eq!(
        registry.insert("crucible.qemu.vmstate.apic%2ftimer-wide", 2),
        Some(1)
    );
    assert!(validate_qemu_vmstate_registry(QEMU_PATCH, &registry).is_err());
}

#[test]
fn qemu_vmstate_discovery_rejects_missing_owned_version() {
    let patch = "+static const VMStateDescription vmstate_timer_wide = {\n\
                 +    .name = \"clock/timer-wide\",\n\
                 +    .fields = (const VMStateField[]) {\n\
                 +    }\n+};\n";
    assert!(owned_qemu_vmstate_sections(patch).is_err());
}

#[test]
fn qemu_vmstate_discovery_rejects_normalization_collision() {
    let patch = "+static const VMStateDescription vmstate_one_wide = {\n\
                 +    .name = \"clock/crucible-timer\",\n\
                 +    .version_id = 1,\n+};\n\
                 +static const VMStateDescription vmstate_two_wide = {\n\
                 +    .name = \"clock_crucible-timer\",\n\
                 +    .version_id = 1,\n+};\n";
    assert!(owned_qemu_vmstate_sections(patch).is_err());
}

#[test]
fn qemu_vmstate_discovery_preserves_actual_target_name_separation() {
    let sections = owned_qemu_vmstate_sections(QEMU_PATCH)
        .expect("Actual packaged target formats have valid distinct names");
    assert_eq!(
        sections.get("crucible.qemu.vmstate.cpu%2ftimer%2fclock-wide"),
        Some(&1)
    );
    assert_eq!(
        sections.get("crucible.qemu.vmstate.cpu_timer%2fclock-wide"),
        Some(&1)
    );
}

#[test]
fn qemu_vmstate_discovery_rejects_invalid_owned_versions() {
    for version in ["0", "-1", "4294967296", "VERSION_MACRO"] {
        let patch = format!(
            "+static const VMStateDescription vmstate_timer_wide = {{\n\
             +    .name = \"clock/timer-wide\",\n\
             +    .version_id = {version},\n+}};\n"
        );
        assert!(owned_qemu_vmstate_sections(&patch).is_err(), "{version}");
    }
}

#[test]
fn qemu_vmstate_discovery_excludes_qom_and_existing_upstream_formats() {
    let patch = "+static const TypeInfo timer_type = {\n\
                 +    .name = \"clock/timer-wide\",\n\
                 +    .version_id = 1,\n+};\n\
                  static const VMStateDescription vmstate_upstream = {\n\
                 +    .name = \"upstream/timer-wide\",\n\
                 +    .version_id = 1,\n };\n";
    assert!(
        owned_qemu_vmstate_sections(patch)
            .expect("QOM and unchanged upstream declarations are outside the inventory")
            .is_empty()
    );
}

#[test]
fn qemu_vmstate_discovery_excludes_diagnostic_test_descriptors() {
    let patch = "diff --git a/tests/unit/test-clock.c b/tests/unit/test-clock.c\n\
                 +++ b/tests/unit/test-clock.c\n\
                 +static const VMStateDescription diagnostic_clock_wide = {\n\
                 +    .name = \"diagnostic/clock-wide\",\n\
                 +    .version_id = 9,\n+};\n\
                 diff --git a/hw/timer/clock.c b/hw/timer/clock.c\n\
                 +++ b/hw/timer/clock.c\n\
                 +static const VMStateDescription vmstate_clock_wide = {\n\
                 +    .name = \"device/clock-wide\",\n\
                 +    .version_id = 2,\n+};\n";
    assert_eq!(
        owned_qemu_vmstate_sections(patch).expect("Production declarations remain covered"),
        BTreeMap::from([("crucible.qemu.vmstate.device%2fclock-wide".to_owned(), 2)])
    );
}

#[test]
fn qemu_vmstate_discovery_resolves_pinned_owned_macro_name() {
    let patch = "+static const VMStateDescription vmstate_imx6ul_lcdif_crucible_clock = {\n\
                 +    .name = TYPE_IMX6UL_LCDIF \"/crucible-clock\",\n\
                 +    .version_id = 1,\n+};\n";
    let sections = owned_qemu_vmstate_sections(patch)
        .expect("The source-pinned macro resolves its actual section name");
    assert_eq!(
        sections.get("crucible.qemu.vmstate.imx6ul-lcdif-crucible-clock"),
        Some(&1)
    );
    let unresolved = patch.replace("TYPE_IMX6UL_LCDIF", "UNKNOWN_DEVICE_TYPE");
    assert!(owned_qemu_vmstate_sections(&unresolved).is_err());

    let changed_definition = format!("+#define TYPE_IMX6UL_LCDIF \"different-device\"\n{patch}");
    assert!(owned_qemu_vmstate_sections(&changed_definition).is_err());

    for directive in [
        "#define\tTYPE_IMX6UL_LCDIF\t\"different-device\"",
        "# define TYPE_IMX6UL_LCDIF \"different-device\"",
        "#\tdefine\tTYPE_IMX6UL_LCDIF\t\"different-device\"",
        "#undef TYPE_IMX6UL_LCDIF",
        "# undef\tTYPE_IMX6UL_LCDIF",
        "#define TYPE_IMX6UL_LCDIF() \"different-device\"",
    ] {
        for change in ['+', '-'] {
            let changed = format!("{change}{directive}\n{patch}");
            assert!(owned_qemu_vmstate_sections(&changed).is_err(), "{changed}");
        }
    }
}
