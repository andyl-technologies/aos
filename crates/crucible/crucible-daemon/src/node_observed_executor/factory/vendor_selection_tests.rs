//! Checks legacy wire stability and vendor data refusal before native allocation.

// crucible-lint: allow panic-shortcut -- These native-free controls deliberately fail on wire drift or accidental admission of uninstalled or foreign vendor scope.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use crucible_node_format::{Id, canonical};

use super::super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, measure_executable,
};

fn selector() -> InstalledNodeSelection {
    InstalledNodeSelection {
        node: Id::new("checksum").unwrap(),
        owner: Id::new("checksum-owner").unwrap(),
        kind: InstalledNodeKind::InstalledVendor {
            provider: Id::new("installed-reference").unwrap(),
            profile: Id::new("closed-checksum").unwrap(),
            configuration: canonical::content_ref(b"source configuration", "text/plain").unwrap(),
        },
    }
}

#[test]
fn legacy_clock_wire_is_unchanged_and_vendor_wire_is_closed() {
    let legacy = InstalledNodeKind::HostClock;
    assert_eq!(
        serde_json::to_string(&legacy).unwrap(),
        "{\"implementation\":\"host_clock\"}"
    );
    let selected = selector();
    let bytes = serde_json::to_vec(&selected).unwrap();
    let decoded: InstalledNodeSelection = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);

    let mut foreign = serde_json::to_value(&selected).unwrap();
    foreign["kind"]["accepted"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<InstalledNodeSelection>(foreign).is_err());
    assert!(
        serde_json::from_str::<InstalledNodeKind>("{\"implementation\":\"vendor_restore\"}")
            .is_err()
    );
}

#[test]
fn uninstalled_vendor_and_foreign_mixed_scope_refuse_before_world_or_child() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let identity = measure_executable(&executable).unwrap();
    let catalog = InstalledNodeCatalog::new(
        executable,
        identity,
        directory.path().to_path_buf(),
        Duration::from_secs(1),
        1,
    )
    .unwrap();
    let vendor = selector();

    let error = catalog
        .scenario(std::slice::from_ref(&vendor))
        .err()
        .unwrap();
    assert!(error.to_string().contains("vendor world is not installed"));
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);

    let clock = InstalledNodeSelection {
        node: Id::new("clock").unwrap(),
        owner: Id::new("clock-owner").unwrap(),
        kind: InstalledNodeKind::HostClock,
    };
    let error = catalog.scenario(&[vendor, clock]).err().unwrap();
    assert!(error.to_string().contains("complete singleton world"));
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
