//! Host-parallel native selector and immutable guest asset binding.
//!
//! Accepted assignment, replay, and restore ownership live in the shared
//! packaged native fixture. This module keeps the independently selected
//! guest assets and the historical behavioral gate entrypoint.

use super::*;
use crucible::model::WorldNodeDef;
use crucible::{ContentAddressedBlobRef, ContentHash, Plan, Properties, Seed};
use std::fs;
use std::path::Path;

#[test]
#[ignore = "requires the isolated native VM, actual assignments and project quotas"]
fn production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable() {
    let source = two_node_source(
        &required_path("CRUCIBLE_HOST_PARALLEL_SCENARIO"),
        &required_path("CRUCIBLE_PAGING_KERNEL"),
        &required_path("CRUCIBLE_PAGING_ROOT"),
    );
    crate::packaged_qemu_executor::run_host_parallel_native(source);
}

fn two_node_source(fixture: &Path, kernel: &Path, root_image: &Path) -> ScenarioDefForm {
    let fixture = fs::read_to_string(fixture).expect("read production host-parallel scenario");
    let base = ScenarioDefForm::from_canonical_toml(&fixture).expect("parse scenario fixture");
    let kernel = content_addressed_file(kernel, "kernel");
    let root_image = content_addressed_file(root_image, "root image");
    let nodes = base
        .world()
        .vm_nodes()
        .iter()
        .take(2)
        .cloned()
        .map(|mut node| {
            node.kernel = Some(kernel);
            node.root_image = Some(root_image);
            WorldNodeDef::Vm(node)
        })
        .collect();
    let world = World::from_node_defs_and_links(nodes, Vec::new()).expect("build two-node world");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(29),
    )
    .expect("build production host-parallel source")
}

fn content_addressed_file(path: &Path, label: &str) -> ContentAddressedBlobRef {
    let file = fs::File::open(path)
        .unwrap_or_else(|error| panic!("open selected {label} {}: {error}", path.display()));
    let hash = ContentHash::from_reader(file)
        .unwrap_or_else(|error| panic!("hash selected {label} {}: {error}", path.display()));
    ContentAddressedBlobRef::from_hash(hash)
}

#[test]
fn host_parallel_source_binds_selected_guest_asset_bytes() {
    let temporary = tempfile::tempdir().expect("create guest asset fixture directory");
    let kernel = temporary.path().join("vmlinuz");
    let root_image = temporary.path().join("root.ext4");
    fs::write(&kernel, b"current production kernel").expect("write kernel fixture");
    fs::write(&root_image, b"current production root image").expect("write root fixture");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/crucible/fixtures/e2e-determinism.scenario.toml");

    let source = two_node_source(&fixture, &kernel, &root_image);
    let expected_kernel =
        ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"current production kernel"));
    let expected_root_image = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        b"current production root image",
    ));
    let nodes = source.world().vm_nodes().iter().collect::<Vec<_>>();

    assert_eq!(nodes.len(), 2);
    for node in nodes {
        assert_eq!(node.kernel, Some(expected_kernel));
        assert_eq!(node.root_image, Some(expected_root_image));
    }
}

fn required_path(name: &str) -> std::path::PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("native gate must supply {name}"))
        .into()
}
