//! Actual installed-driver regression for a dirty disk with a pending reply.

// crucible-lint: allow rust-allow -- genuine source fixtures and byte-preservation oracles panic on failure.
// crucible-lint: allow panic-shortcut -- These host state execution tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use crucible_device::BlockRequest;
use crucible_node_contract::canonical;

use crate::node_observed_executor::{InstalledIoArtifact, InstalledNodeSelection};

#[test]
#[ignore = "requires the actual source-built native companion"]
fn installed_exact_driver_captures_consumed_write_and_pending_original_reply() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let reference =
        |bytes: &[u8]| canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        device.clone(),
        reference(&fs::read(&device).unwrap()),
        directory.to_path_buf(),
        Duration::from_secs(3),
        2,
    )
    .unwrap();

    let base = vec![0xab; 4096];
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let base_path = directory.join("base.img");
    let script_path = directory.join("requests.bin");
    fs::write(&base_path, &base).unwrap();
    fs::write(&script_path, &script).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(base_path.clone(), reference(&base)),
            InstalledIoArtifact::path(script_path, reference(&script)),
        ])
        .unwrap();
    let selections: Vec<InstalledNodeSelection> = serde_json::from_value(serde_json::json!([
        {"node":"disk","owner":"disk-owner","kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":reference(&base),"source_node":7,
            "read_ns":"1","write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"}}},
        {"node":"source","owner":"source-owner","kind":{"implementation":"host_scripted","profile":{
            "script":reference(&script),"consumer":"disk"}}}
    ]))
    .unwrap();
    let scenario = catalog.scenario(&selections).unwrap();
    let request = NodeHostStateRequest::capture(
        "61616161616161616161616161616161".into(),
        selections,
        scenario.canonical_bytes().unwrap(),
        11,
    )
    .unwrap();
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive = HostArchive::open(directory.join("archives"), limits).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "actual-installed-state-test",
        directory.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));

    let captured = execute(&request, &mut catalog, &archive, limits, &blobs, &refs)
        .expect("the real installed exact driver must capture the pending original reply");

    assert_eq!(captured.manifest().cut.time_ps, U64::new(11));
    assert_eq!(captured.manifest().event_ordinal, U64::new(3));
    let disk = captured
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id.as_str() == "disk-owner")
        .unwrap();
    let native: serde_json::Value = serde_json::from_slice(
        &captured
            .content_bytes(disk.state_ref.as_ref().unwrap(), 16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let inputs: Vec<_> = native["input_history"]
        .as_array()
        .unwrap()
        .iter()
        .chain(native.get("staged").filter(|input| !input.is_null()))
        .collect();
    assert_eq!(
        inputs.len(),
        2,
        "one original parking batch and one actual write; no blocked empty restaging"
    );
    let consumed: u64 = inputs
        .iter()
        .map(|input| input["consumed"].as_str().unwrap().parse::<u64>().unwrap())
        .sum();
    assert_eq!(consumed, 1, "the original write is consumed exactly once");
    assert_eq!(native["pending_causes"].as_array().unwrap().len(), 1);
    assert_eq!(native["operations"].as_array().unwrap().len(), 2);
    assert_eq!(fs::read(base_path).unwrap(), base);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}
