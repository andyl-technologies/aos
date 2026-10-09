//! Native archive storage/authentication tests without manufacturing backend qualification.

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
