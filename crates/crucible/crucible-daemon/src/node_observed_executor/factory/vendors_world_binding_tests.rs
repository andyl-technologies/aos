//! Checks authored world identity before installed vendor callbacks or reservation.

// crucible-lint: allow panic-shortcut -- These inert prebirth controls fail when a foreign world reaches installed admission or consumes an original world slot.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use crucible_engine::node_contract::{
    ActivationRecord, ProviderPlanningRequest, ProviderRegistryLimits, RuntimeLimits,
};
use crucible_node_format::{Extensions, Id, Phase, Position, ResourceLimits, U64, canonical};

use super::super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, measure_executable,
};

#[test]
fn foreign_vendor_world_refuses_before_installation_lookup_or_world_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let identity = measure_executable(&executable).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        identity,
        directory.path().to_path_buf(),
        Duration::from_secs(1),
        1,
    )
    .unwrap();
    let node = Id::new("clock").unwrap();
    let scenario = catalog
        .scenario(&[InstalledNodeSelection {
            node: node.clone(),
            owner: Id::new("clock-owner").unwrap(),
            kind: InstalledNodeKind::HostClock,
        }])
        .unwrap();
    let authored = scenario.world.identity().unwrap();
    let activation = ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("vendor-activation").unwrap(),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"foreign authored world")
            .unwrap(),
        owners: Vec::new(),
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(1_000_000),
        memory_bytes: U64::new(1024 * 1024),
        writable_bytes: U64::new(1024),
        processes: U64::new(1),
        descriptors: U64::new(8),
        pending_events: U64::new(1),
        content_bytes: U64::new(1024),
        maximum_operations: U64::new(1),
        extensions: Extensions::new(),
    };
    let profile = Id::new("installed-checksum").unwrap();
    let configuration =
        canonical::content_ref(b"inert selected configuration", "text/plain").unwrap();
    let nodes = [node];
    let selection = ProviderPlanningRequest {
        profile: &profile,
        configuration: &configuration,
        nodes: &nodes,
        resources: &resources,
        limits: ProviderRegistryLimits::default(),
    };

    // No provider or class authority is installed. Reaching either lookup would
    // produce another refusal, so this exact reason establishes the early guard.
    let refused = catalog
        .prepare_vendor_world(
            &Id::new("vendor").unwrap(),
            selection,
            scenario.clone(),
            &activation,
            RuntimeLimits::default(),
        )
        .err()
        .unwrap();
    assert!(
        refused
            .to_string()
            .contains("vendor activation differs from authored whole world")
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);

    // Correct data does not grant installation or behavioral qualification.
    let current = ActivationRecord {
        world_binding_hash: authored,
        ..activation
    };
    let refused = catalog
        .prepare_vendor_world(
            &Id::new("vendor").unwrap(),
            selection,
            scenario,
            &current,
            RuntimeLimits::default(),
        )
        .err()
        .unwrap();
    assert!(
        refused
            .to_string()
            .contains("normal installed behavioral acceptance")
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
