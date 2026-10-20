//! Binds explicit native test inputs to the complete source-built fixture.

use crucible_daemon::node_qualification::{PacketFixtureArtifact, PacketFixtureMeasurements};
use crucible_node_format::{ContentRef, canonical};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn required_path(variable: &str) -> PathBuf {
    let value = std::env::var_os(variable)
        .unwrap_or_else(|| panic!("required native fixture input omitted: {variable}"));
    fs::canonicalize(value).unwrap()
}

pub(super) fn measured(path: &Path, media_type: &str) -> ContentRef {
    let extent = path.metadata().unwrap().len();
    assert!(extent > 0 && extent <= 512 * 1024 * 1024);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.len() as u64, extent);
    canonical::content_ref(&bytes, media_type).unwrap()
}

pub(super) fn measurements(
    peer: &Path,
    source: &Path,
    inventory: &Path,
    recipe: &Path,
    member: usize,
) -> PacketFixtureMeasurements {
    let roles = [
        (
            "adapter_source",
            source.join(if member == 0 {
                "crates/crucible/engine/crucible-engine/src/node_adapters/cnp/semantic/packet_source.rs"
            } else {
                "crates/crucible/engine/crucible-engine/src/node_adapters/cnp/semantic/packet_connected_source.rs"
            }),
        ),
        ("build_closure", inventory.to_path_buf()),
        (
            "contract_source",
            source.join("crates/crucible/host/crucible-node-transport/src/reference_packet/contracts.rs"),
        ),
        (
            "harness_source",
            source.join("crates/crucible/control/crucible-daemon/tests/packet_connected_world_collection.rs"),
        ),
        (
            "native_source",
            source.join(if member == 0 {
                "crates/crucible/host/crucible-node-transport/src/reference_packet.rs"
            } else {
                "crates/crucible/host/crucible-node-transport/src/reference_packet/connected.rs"
            }),
        ),
        (
            "program_source",
            source.join(
                "crates/crucible/control/crucible-daemon/tests/packet_connected_world_collection/configuration.rs",
            ),
        ),
        (
            "provider_source",
            source.join("crates/crucible/host/crucible-node-transport/src/reference_packet/control.rs"),
        ),
        ("recipe", recipe.to_path_buf()),
    ];
    PacketFixtureMeasurements {
        peer: PacketFixtureArtifact {
            role: "executable".into(),
            path: peer.to_path_buf(),
            content: measured(peer, "application/octet-stream"),
        },
        host: measured(Path::new("/proc/self/exe"), "application/octet-stream"),
        sources: roles
            .into_iter()
            .map(|(role, path)| PacketFixtureArtifact {
                role: role.into(),
                content: measured(&path, "application/octet-stream"),
                path,
            })
            .collect(),
    }
}
