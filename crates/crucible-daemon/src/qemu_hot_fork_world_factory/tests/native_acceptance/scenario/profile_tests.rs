//! Checks native fixture profiles against production workload admission.

// crucible-lint: allow panic-shortcut -- fixture admission assertions must fail on invalid construction.

use std::fs;
use std::path::PathBuf;

use crucible::model::GuestWorkloadBinary;
use crucible::{EngineError, LocalDagStore};

use super::*;

#[path = "profile_tests/factory_preflight.rs"]
mod factory_preflight;

const FIXTURE: &str =
    include_str!("../../../../../../../tests/crucible/fixtures/e2e-determinism.scenario.toml");

struct FixtureAssets {
    _directory: tempfile::TempDir,
    kernel: PathBuf,
    root_image: PathBuf,
    artifacts: Arc<dyn DagStore>,
}

impl FixtureAssets {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create fixture assets directory");
        let kernel = directory.path().join("kernel");
        let root_image = directory.path().join("root.ext4");
        fs::write(&kernel, b"fixture kernel bytes").expect("write fixture kernel");
        fs::write(&root_image, b"fixture root image bytes").expect("write fixture root image");
        let artifacts = Arc::new(LocalDagStore::new(directory.path().join("artifacts")));

        Self {
            _directory: directory,
            kernel,
            root_image,
            artifacts,
        }
    }
}

#[test]
fn single_node_equivalence_admits_benchmark_and_preserves_owned_state() {
    let assets = FixtureAssets::new();
    let (source, _) = build_single_node_equivalence(
        FIXTURE,
        Arc::clone(&assets.artifacts),
        &assets.kernel,
        &assets.root_image,
    )
    .expect("admit single-node benchmark fixture");

    assert_benchmark_profile(&source, "hot-fork-single", 256);
    assert_single_node_io(&source);
}

#[test]
fn single_node_equivalence_with_memory_admits_benchmark_and_preserves_owned_state() {
    let assets = FixtureAssets::new();
    let (source, _) = build_single_node_equivalence_with_memory(
        FIXTURE,
        Arc::clone(&assets.artifacts),
        64,
        &assets.kernel,
        &assets.root_image,
    )
    .expect("admit 64 MiB single-node benchmark fixture");

    assert_benchmark_profile(&source, "hot-fork-single", 64);
    assert_single_node_io(&source);
}

#[test]
fn single_node_scaling_admits_benchmark_without_adding_io_nodes() {
    let assets = FixtureAssets::new();
    let (source, _) = build_single_node_scaling(
        FIXTURE,
        Arc::clone(&assets.artifacts),
        &assets.kernel,
        &assets.root_image,
    )
    .expect("admit scaling benchmark fixture");

    assert_benchmark_profile(&source, "hot-fork-scaling", 256);
    assert_eq!(source.world().io_nodes().count(), 0);
}

#[test]
fn unsupported_hot_fork_workload_values_remain_rejected() {
    let base = ScenarioDefForm::from_canonical_toml(FIXTURE).expect("parse reviewed fixture");
    let node = base
        .world()
        .vm_nodes()
        .iter()
        .find(|node| node.id.name == "curl")
        .cloned()
        .expect("fixture curl VM");

    for value in ["hot-fork-single", "hot-fork-scaling"] {
        let mut legacy = node.clone();
        legacy.cmdline = format!("console=ttyS0 crucible.workload={value}");
        let result = World::from_node_defs_and_links(vec![WorldNodeDef::Vm(legacy)], Vec::new());

        assert!(matches!(
            result,
            Err(EngineError::WorldNodeUnsupportedWorkload { node: rejected, value: rejected_value })
                if rejected == node.id && rejected_value == value
        ));
    }
}

fn assert_benchmark_profile(source: &ScenarioDefForm, role: &str, memory_mib: u32) {
    let nodes = source.world().vm_nodes();
    assert_eq!(nodes.len(), 1);
    let node = nodes.iter().next().expect("single fixture VM");
    assert_eq!(node.id.name, "curl");
    assert_eq!(node.guest_workload(), Some(GuestWorkloadBinary::Benchmark));
    let expected_role = format!("role={role}");
    assert!(
        node.cmdline
            .split_whitespace()
            .any(|token| token == expected_role)
    );
    assert_eq!(node.memory_mib, memory_mib);
    assert_eq!(
        node.kernel.map(ContentAddressedBlobRef::hash),
        Some(ContentHash::from_bytes(b"fixture kernel bytes"))
    );
    assert_eq!(
        node.root_image.map(ContentAddressedBlobRef::hash),
        Some(ContentHash::from_bytes(b"fixture root image bytes"))
    );
    assert!(node.white_box.is_enabled());
    assert!(source.world().links().is_empty());

    let declarations = source.selectables().declarations();
    assert_eq!(declarations.len(), 1);
    let declaration = declarations.values().next().expect("guest choice");
    assert_eq!(declaration.name(), "hot-fork.retry-quanta");
    assert_eq!(
        declaration.source(),
        &ChoiceSource::Guest {
            node: String::from("curl"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        }
    );
    assert_eq!(
        declaration.default(),
        &ChoiceValue::Integer(IntegerValue::Unsigned(3))
    );

    let measurements = source.measurements().definitions();
    assert_eq!(measurements.len(), 1);
    assert_eq!(measurements[0].id.as_str(), "hot-fork-window");
    assert_eq!(measurements[0].metrics[0].id.as_str(), "selected-retry");
    assert_eq!(
        measurements[0].cohort,
        CohortPolicy::All(vec![node_id("curl")])
    );
}

fn assert_single_node_io(source: &ScenarioDefForm) {
    let base = ScenarioDefForm::from_canonical_toml(FIXTURE).expect("parse reviewed fixture");
    let expected: Vec<_> = base
        .world()
        .io_nodes()
        .cloned()
        .map(|mut node| {
            node.owner = node_id("curl");
            node
        })
        .collect();
    let actual: Vec<_> = source.world().io_nodes().cloned().collect();

    assert_eq!(actual.len(), 2);
    assert_eq!(actual, expected);
}
