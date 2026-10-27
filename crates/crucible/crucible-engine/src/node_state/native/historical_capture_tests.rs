//! Checks signed historical data copying without issuing restoration authority.
//!
//! These archives intentionally have no native owners or capture mechanism.
//! They exercise the mechanical dependency and finite-credit path only.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::node_state::closure::ContentInventoryEdition;
use crate::node_state::native::storage::Index;
use crate::node_state::native::{NativeArchive, NativeArchiveLimits};
use crucible_node_format::{CaptureManifest, Id, Phase, Position, canonical};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crucible-historical-data-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn object(archive: &NativeArchive, bytes: &[u8], media: &str) -> ContentRef {
    let reference = canonical::content_ref(bytes, media).unwrap();
    let mut input = bytes;
    archive.store(&reference, &mut input).unwrap();
    reference
}

fn signed_data(
    archive: &NativeArchive,
    root: &ContentRef,
    mut rows: Vec<Object>,
) -> NativeArchiveRecord {
    let (graph, _) = crate::node_admission::test_fixture_with_content();
    let manifest = CaptureManifest {
        schema_version: 1,
        capture_id: Id::new("historical-data-only").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        scenario_ref: graph.world().scenario_ref.clone(),
        preservation_contract: Id::new("historical-data-only").unwrap(),
        cut: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        event_ordinal: 0.into(),
        ordering_profile: graph.world().ordering_profile.clone(),
        guarantees_ref: root.clone(),
        coordinator_state_ref: root.clone(),
        owners: Vec::new(),
        immutable_refs: Vec::new(),
        provenance_ref: root.clone(),
        extensions: Default::default(),
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(manifest).unwrap()).unwrap();
    let artifact = object(archive, &bytes, "application/json");
    rows.push(Object {
        reference: artifact.clone(),
        dependencies: vec![root.clone()],
    });
    rows.sort_by(|a, b| a.reference.cmp(&b.reference));
    archive
        .persist(Index {
            schema_version: 2,
            artifact,
            objects: rows,
            owners: Vec::new(),
            selected_extensions: None,
            original_capture_journal: None,
        })
        .unwrap()
}

#[test]
fn historical_signed_transitive_typed_roles_copy_without_current_callbacks() {
    let source_dir = Directory::new();
    let source = NativeArchive::open(&source_dir.0, NativeArchiveLimits::default()).unwrap();
    let leaf = object(&source, b"original bytes", "application/octet-stream");
    let alternate = object(
        &source,
        b"original bytes",
        "application/vnd.crucible.test-history",
    );
    let root = object(&source, b"root", "application/octet-stream");
    let unrelated = object(&source, b"unrelated", "application/octet-stream");
    let mut dependencies = vec![leaf.clone(), alternate.clone()];
    dependencies.sort();
    let signed = signed_data(
        &source,
        &root,
        vec![
            Object {
                reference: root.clone(),
                dependencies,
            },
            Object {
                reference: leaf.clone(),
                dependencies: Vec::new(),
            },
            Object {
                reference: alternate.clone(),
                dependencies: Vec::new(),
            },
            Object {
                reference: unrelated,
                dependencies: Vec::new(),
            },
        ],
    );
    let plan = HistoricalCaptureClosure::from_roots(
        &[&signed],
        std::slice::from_ref(&root),
        StateLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.geometry(),
        (3, b"root".len() + b"original bytes".len())
    );

    let target_dir = Directory::new();
    let target = NativeArchive::open(&target_dir.0, NativeArchiveLimits::default()).unwrap();
    let mut objects = Objects::new(&target, ContentInventoryEdition::Typed);
    plan.enroll(&mut objects, StateLimits::default()).unwrap();
    let rows = objects.finish();

    assert_eq!(rows.len(), 3);
    let target_record = signed_data(&target, &root, rows.clone());
    assert_eq!(
        target_record.object_bytes(&leaf, 1024).unwrap(),
        b"original bytes"
    );
    assert_eq!(
        target_record.object_bytes(&alternate, 1024).unwrap(),
        b"original bytes"
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.reference == root)
            .unwrap()
            .dependencies
            .len(),
        2
    );
    assert!(signed.original_capture_journal().is_err());
}

#[test]
fn historical_dependency_conflict_and_absent_root_refuse_before_copy() {
    let a_dir = Directory::new();
    let a = NativeArchive::open(&a_dir.0, NativeArchiveLimits::default()).unwrap();
    let root = object(&a, b"root", "application/octet-stream");
    let leaf = object(&a, b"leaf", "application/octet-stream");
    let a_signed = signed_data(
        &a,
        &root,
        vec![
            Object {
                reference: root.clone(),
                dependencies: vec![leaf.clone()],
            },
            Object {
                reference: leaf,
                dependencies: Vec::new(),
            },
        ],
    );
    let b_dir = Directory::new();
    let b = NativeArchive::open(&b_dir.0, NativeArchiveLimits::default()).unwrap();
    let root_b = object(&b, b"root", "application/octet-stream");
    let b_signed = signed_data(
        &b,
        &root_b,
        vec![Object {
            reference: root_b.clone(),
            dependencies: Vec::new(),
        }],
    );

    assert!(
        HistoricalCaptureClosure::from_roots(
            &[&a_signed, &b_signed],
            &[root],
            StateLimits::default()
        )
        .is_err()
    );
    let absent = canonical::content_ref(b"missing", "application/octet-stream").unwrap();
    assert!(
        HistoricalCaptureClosure::from_roots(&[&a_signed], &[absent], StateLimits::default())
            .is_err()
    );
}

#[test]
fn historical_aggregate_bytes_roles_and_edges_refuse_before_copy() {
    let directory = Directory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let root = object(&archive, b"root", "application/octet-stream");
    let leaf = object(&archive, b"leaf", "application/octet-stream");
    let signed = signed_data(
        &archive,
        &root,
        vec![
            Object {
                reference: root.clone(),
                dependencies: vec![leaf.clone()],
            },
            Object {
                reference: leaf,
                dependencies: Vec::new(),
            },
        ],
    );
    for mode in 0..3 {
        let mut limits = StateLimits::default();
        match mode {
            0 => limits.maximum_total_content_bytes = 7,
            1 => limits.maximum_content_objects = 1,
            2 => limits.maximum_dependency_edges = 0,
            _ => unreachable!(),
        }
        assert!(
            HistoricalCaptureClosure::from_roots(&[&signed], std::slice::from_ref(&root), limits)
                .is_err()
        );
    }
}
