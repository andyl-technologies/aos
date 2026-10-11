//! Native archive storage/authentication tests without manufacturing backend qualification.

// crucible-lint: allow panic-shortcut -- These native tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, io::Read, os::unix::fs::PermissionsExt, path::PathBuf};

use crucible_node_contract::{CaptureManifest, ContentRef, Id, Phase, Position, canonical};

use super::storage::{Index, NativeArtifactState, Object};
use super::*;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-native-archive-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn store(archive: &NativeArchive, mut bytes: &[u8]) -> ContentRef {
    let reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
    archive.store(&reference, &mut bytes).unwrap();
    reference
}

fn storage_index(archive: &NativeArchive, image: ContentRef) -> Index {
    let (graph, _) = crate::node_admission::test_fixture_host_model(
        "clock",
        crate::node_adapters::host_clock_initial_bytes(0),
    );
    let binding = graph.binding(&id("a")).unwrap();
    let state = store(archive, b"storage-test-metadata; no native qualification");
    let coordinator = store(
        archive,
        b"storage-test-coordinator; no native qualification",
    );
    let manifest = CaptureManifest {
        schema_version: 1,
        capture_id: id("storage-test"),
        world_binding_hash: graph.world_binding_hash().clone(),
        scenario_ref: graph.world().scenario_ref.clone(),
        preservation_contract: id("storage-test"),
        cut: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        event_ordinal: 1.into(),
        ordering_profile: graph.world().ordering_profile.clone(),
        guarantees_ref: coordinator.clone(),
        coordinator_state_ref: coordinator.clone(),
        owners: vec![],
        immutable_refs: vec![],
        provenance_ref: coordinator.clone(),
        extensions: Default::default(),
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let artifact = canonical::content_ref(&bytes, "application/json").unwrap();
    archive.store(&artifact, &mut bytes.as_slice()).unwrap();
    Index {
        selected_extensions: None,
        schema_version: 1,
        artifact: artifact.clone(),
        objects: vec![
            Object {
                reference: artifact,
                dependencies: vec![coordinator.clone()],
            },
            Object {
                reference: state.clone(),
                dependencies: vec![],
            },
            Object {
                reference: coordinator,
                dependencies: vec![],
            },
        ],
        owners: vec![NativeOwnerState {
            owner: id("storage-owner"),
            participants: vec![id("a")],
            key: crate::node_contract::NativeStateKey {
                implementation: binding
                    .compatibility
                    .implementation
                    .implementation_id
                    .clone(),
                profile: id("storage-test"),
                schema: binding.compatibility.implementation.formats[0].clone(),
            },
            cut: manifest.cut,
            state,
            evidence: vec![],
            artifacts: vec![NativeArtifactState {
                role: id("process-image"),
                name: "image/source.dmtcp".into(),
                content: image,
            }],
        }],
    }
}

#[test]
fn descriptor_streams_preserve_bytes_after_source_path_removal() {
    let directory = TestDirectory::new();
    let original = directory.0.join("original-image");
    let bytes = vec![0xa5; 128 * 1024 + 17];
    fs::write(&original, &bytes).unwrap();
    let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let source = crate::node_contract::NativeCaptureArtifact::from_file(
        id("process-image"),
        "image/source.dmtcp".into(),
        reference.clone(),
        fs::File::open(&original).unwrap(),
    )
    .unwrap();
    fs::remove_file(original).unwrap();

    let archive_root = directory.0.join("archive");
    let archive = NativeArchive::open(&archive_root, NativeArchiveLimits::default()).unwrap();
    archive.store(&reference, &mut source.reader()).unwrap();
    let record = archive.persist(storage_index(&archive, reference)).unwrap();
    let artifact = record.artifact().clone();
    drop(record);
    drop(source);
    drop(archive);

    let archive = NativeArchive::open(&archive_root, NativeArchiveLimits::default()).unwrap();
    let record = archive.load(&artifact).unwrap();
    let ledger = record.owners()[0].state.clone();
    assert!(record.object_bytes(&ledger, 0).is_err());
    assert_eq!(
        record.object_bytes(&ledger, 1024).unwrap(),
        b"storage-test-metadata; no native qualification"
    );
    let files = record.owner_artifacts(&id("storage-owner")).unwrap();
    assert!(
        record
            .object_bytes(files[0].reference(), bytes.len())
            .is_err()
    );
    let mut first = files[0].reader();
    let mut second = files[0].reader();
    let mut prefix = [0u8; 17];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, [0xa5; 17]);
    let mut independent = Vec::new();
    second.read_to_end(&mut independent).unwrap();
    assert_eq!(independent, bytes);
    let mut suffix = Vec::new();
    first.read_to_end(&mut suffix).unwrap();
    assert_eq!(suffix, bytes[17..]);
}

#[test]
fn corrupted_stream_never_publishes_an_object_and_signed_files_are_reverified() {
    let directory = TestDirectory::new();
    let archive_root = directory.0.join("archive");
    let archive = NativeArchive::open(&archive_root, NativeArchiveLimits::default()).unwrap();
    let image = canonical::content_ref(b"original image", "application/octet-stream").unwrap();
    assert!(
        archive
            .store(&image, &mut b"tampered image".as_slice())
            .is_err()
    );
    assert!(
        !archive_root
            .join(format!("{}.native-object-v1", image.hash.digest))
            .exists()
    );
    archive
        .store(&image, &mut b"original image".as_slice())
        .unwrap();
    let record = archive
        .persist(storage_index(&archive, image.clone()))
        .unwrap();
    let artifact = record.artifact().clone();

    fs::write(
        archive_root.join(format!("{}.native-object-v1", image.hash.digest)),
        b"corrupt bytes!",
    )
    .unwrap();
    assert!(archive.load(&artifact).is_err());
}

#[test]
fn independent_signing_keys_and_backend_metadata_are_bound() {
    let directory = TestDirectory::new();
    let left_root = directory.0.join("left");
    let left = NativeArchive::open(&left_root, NativeArchiveLimits::default()).unwrap();
    let image = store(&left, b"image");
    let original = left.persist(storage_index(&left, image)).unwrap();
    let right_root = directory.0.join("right");
    let right = NativeArchive::open(&right_root, NativeArchiveLimits::default()).unwrap();
    let name = format!("{}.native-index-v1", original.artifact().hash.digest);
    fs::copy(left_root.join(&name), right_root.join(&name)).unwrap();
    assert!(right.load(original.artifact()).is_err());

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(left_root.join(&name)).unwrap()).unwrap();
    envelope["body"]["owners"][0]["key"]["implementation"] = serde_json::json!("other/backend");
    fs::write(left_root.join(name), serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(left.load(original.artifact()).is_err());
}

#[test]
fn typed_inventory_preserves_two_authentic_media_roles_and_their_adjacency() {
    let directory = TestDirectory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let body = b"{\"bytes_processed\":\"0\",\"checksum\":\"0\"}";
    let json = canonical::content_ref(body, "application/json").unwrap();
    let payload = canonical::content_ref(body, "application/octet-stream").unwrap();
    archive.store(&json, &mut body.as_slice()).unwrap();
    archive.store(&payload, &mut body.as_slice()).unwrap();
    let mut index = storage_index(&archive, store(&archive, b"image"));
    index.schema_version = 2;
    index.objects.push(Object {
        reference: json.clone(),
        dependencies: vec![],
    });
    index.objects.push(Object {
        reference: payload.clone(),
        dependencies: vec![json.clone()],
    });
    index
        .objects
        .iter_mut()
        .find(|object| object.reference == index.artifact)
        .unwrap()
        .dependencies
        .push(payload.clone());
    for object in &mut index.objects {
        object.dependencies.sort();
    }
    index
        .objects
        .sort_by(|left, right| left.reference.cmp(&right.reference));

    let record = archive.persist(index.clone()).unwrap();
    let loaded = archive.load(record.artifact()).unwrap();
    assert_eq!(loaded.object_bytes(&json, body.len()).unwrap(), body);
    assert_eq!(loaded.object_bytes(&payload, body.len()).unwrap(), body);
    let row = loaded
        .index
        .objects
        .iter()
        .find(|object| object.reference == payload)
        .unwrap();
    assert_eq!(row.dependencies, vec![json.clone()]);
    assert!(
        loaded
            .index
            .objects
            .iter()
            .find(|object| object.reference == json)
            .unwrap()
            .dependencies
            .is_empty()
    );

    index.schema_version = 1;
    assert!(archive.record(index).is_err());
}

#[test]
fn typed_inventory_requires_its_explicit_edition_and_nullable_extension_root() {
    let directory = TestDirectory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let mut index = storage_index(&archive, store(&archive, b"image"));
    let old = serde_json::to_value(&index).unwrap();
    assert_eq!(
        old.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        ["schema_version", "artifact", "objects", "owners"]
            .map(str::to_owned)
            .into_iter()
            .collect()
    );
    let mut changed = old.clone();
    changed["selected_extensions"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Index>(changed).is_err());

    index.schema_version = 2;
    index
        .objects
        .sort_by(|left, right| left.reference.cmp(&right.reference));
    let value = serde_json::to_value(&index).unwrap();
    assert!(value.get("objects").is_none());
    assert_eq!(value["typed_inventory"]["schema_version"], 2);
    assert!(value["selected_extensions"].is_null());
    // Edition two follows the portable integral-number convention without
    // changing the original edition-one decoder or canonical writer bytes.
    for spelling in ["2.0", "2e0"] {
        let number: serde_json::Value = serde_json::from_str(spelling).unwrap();
        let mut integral = value.clone();
        integral["schema_version"] = number.clone();
        integral["typed_inventory"]["schema_version"] = number;
        let decoded = serde_json::from_value::<Index>(integral).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }
    let mut fractional = value.clone();
    fractional["schema_version"] = serde_json::from_str("2.5").unwrap();
    assert!(serde_json::from_value::<Index>(fractional).is_err());
    let mut missing = value.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("selected_extensions");
    assert!(serde_json::from_value::<Index>(missing).is_err());
    let mut legacy_objects = value.clone();
    legacy_objects["objects"] = old["objects"].clone();
    assert!(serde_json::from_value::<Index>(legacy_objects).is_err());
    let mut unsupported = value.clone();
    unsupported["typed_inventory"]["schema_version"] = 1.into();
    assert!(serde_json::from_value::<Index>(unsupported).is_err());
    let mut uninstalled = value;
    // A selected root must have its own enrolled typed row. Installed native
    // interpretation is checked separately before admission or allocation.
    let missing_root =
        canonical::content_ref(b"missing selected semantic body", "application/json").unwrap();
    uninstalled["selected_extensions"] = serde_json::to_value(missing_root).unwrap();
    assert!(
        archive
            .record(serde_json::from_value(uninstalled).unwrap())
            .is_err()
    );
}

#[test]
fn typed_inventory_refuses_unenrolled_media_alias_duplicate_and_reordered_rows() {
    let directory = TestDirectory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let mut index = storage_index(&archive, store(&archive, b"image"));
    index.schema_version = 2;
    index
        .objects
        .sort_by(|left, right| left.reference.cmp(&right.reference));
    let mut unknown = index.clone();
    let mut alias = unknown.objects[0].reference.clone();
    alias.media_type = "text/plain".into();
    unknown.objects[0].dependencies.push(alias);
    unknown.objects[0].dependencies.sort();
    assert!(archive.record(unknown).is_err());
    let mut duplicate = index.clone();
    duplicate.objects.push(duplicate.objects[0].clone());
    duplicate
        .objects
        .sort_by(|left, right| left.reference.cmp(&right.reference));
    assert!(archive.record(duplicate).is_err());
    index.objects.reverse();
    assert!(archive.record(index).is_err());
    let expected = canonical::content_ref(b"unwritten original", "application/json").unwrap();
    assert!(
        archive
            .store(&expected, &mut b"different".as_slice())
            .is_err()
    );
}

#[test]
fn legacy_native_index_retains_exact_original_canonical_wire() {
    let directory = TestDirectory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let index = storage_index(&archive, store(&archive, b"image"));
    // The independent old envelope view has exactly its original four fields,
    // including the original paged outer object table and dependency rows.
    let expected = serde_json::json!({
        "schema_version":1,
        "artifact":index.artifact,
        "objects":index.objects.chunks(256).collect::<Vec<_>>(),
        "owners":index.owners,
    });
    let actual = serde_json::to_value(&index).unwrap();
    assert_eq!(
        canonical::canonical_json(&actual).unwrap(),
        canonical::canonical_json(&expected).unwrap()
    );
    let decoded: Index = serde_json::from_value(expected).unwrap();
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(decoded).unwrap()).unwrap(),
        canonical::canonical_json(&actual).unwrap()
    );
}

#[test]
fn unselected_archive_dialect_refuses_extensions_before_native_source_work() {
    let graph = crate::node_admission::test_model_graph_with_extension();
    assert!(!graph.selected_extensions().is_empty());
    assert!(require_supported_extensions(&graph).is_err());
}
