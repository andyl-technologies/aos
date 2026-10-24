//! Exercises actual signed files and loader accounting with modeled native rows.
//!
//! These controls qualify no native snapshot, source factory, ticket or restore.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_contract::{
    OriginalCaptureAttemptRecord, OriginalCaptureOwnerRecord, OriginalCaptureOwnerState,
    OwnerIdentity, RuntimeOriginalCaptureJournal, SavedRuntimeActivation,
};
use crate::node_state::native::lineage_source::OriginalLineageCoordinator;
use crucible_node_format::{Phase, Repeatability, SchemaRef};

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-complete-loader-{}-{sequence}",
            std::process::id(),
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

fn id(value: impl Into<String>) -> Id {
    Id::new(value).unwrap()
}

fn store(archive: &NativeArchive, bytes: &[u8], media: &str) -> ContentRef {
    let reference = canonical::content_ref(bytes, media).unwrap();
    archive.store(&reference, &mut &*bytes).unwrap();
    reference
}

pub(in crate::node_state::native) fn fixture(archive: &NativeArchive) -> NativeArchiveRecord {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let cut = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let runtime = store(
        archive,
        b"{}",
        super::super::super::ORIGINAL_LINEAGE_RUNTIME_MEDIA,
    );
    let scheduler = store(archive, b"[]", "application/json");
    let schema = store(
        archive,
        b"modeled schema; no native qualifier",
        "model/schema",
    );
    let snapshot = store(archive, b"model snapshot", "model/snapshot");
    let settlement = store(archive, b"model settlement", "model/settlement");
    let provenance = store(archive, b"{}", "application/json");
    let owners: Vec<_> = (0..4)
        .map(|index| OwnerIdentity {
            owner: id(format!("model/owner/{index}")),
            incarnation: id(format!("model/incarnation/{index}")),
            generation: 1.into(),
        })
        .collect();
    let journal = RuntimeOriginalCaptureJournal {
        schema_version: 1,
        maximum_attempts: 64.into(),
        attempts: vec![OriginalCaptureAttemptRecord {
            sequence: 1.into(),
            capture_id: id("model/capture"),
            source_runtime: runtime.clone(),
            source_activation: SavedRuntimeActivation {
                generation: 1.into(),
                activation_id: id("model/activation"),
                world_binding_hash: graph.world_binding_hash().clone(),
                owners: owners.clone(),
                boundary: cut,
            },
            cut,
            ordinal: 0.into(),
            owners: owners
                .iter()
                .enumerate()
                .map(|(index, owner)| OriginalCaptureOwnerRecord {
                    owner: owner.clone(),
                    participants: vec![id(format!("model/node/{index}"))],
                    operation: id(format!("native-capture/1/{index}")),
                    state: OriginalCaptureOwnerState::Settled {
                        snapshot: snapshot.clone(),
                        journal: Box::new(settlement.clone()),
                    },
                })
                .collect(),
        }],
    };
    let journal_bytes =
        canonical::canonical_json(&serde_json::to_value(&journal).unwrap()).unwrap();
    let journal_ref = store(
        archive,
        &journal_bytes,
        super::super::super::complete_original_index::JOURNAL_MEDIA,
    );
    let coordinator = OriginalLineageCoordinator {
        schema_version: 7,
        runtime: runtime.clone(),
        scheduler: scheduler.clone(),
        world_repeatability: Repeatability::Nondeterministic,
    };
    let coordinator_bytes =
        canonical::canonical_json(&serde_json::to_value(&coordinator).unwrap()).unwrap();
    let coordinator_ref = store(archive, &coordinator_bytes, "application/json");
    let manifest = CaptureManifest {
        schema_version: 1,
        capture_id: id("model/capture"),
        world_binding_hash: graph.world_binding_hash().clone(),
        scenario_ref: graph.world().scenario_ref.clone(),
        preservation_contract: id("source-owned.packet-complete-original-lineage/5"),
        cut,
        event_ordinal: 0.into(),
        ordering_profile: graph.world().ordering_profile.clone(),
        guarantees_ref: provenance.clone(),
        coordinator_state_ref: coordinator_ref.clone(),
        owners: vec![],
        immutable_refs: vec![],
        provenance_ref: provenance.clone(),
        extensions: Default::default(),
    };
    let manifest_bytes =
        canonical::canonical_json(&serde_json::to_value(&manifest).unwrap()).unwrap();
    let artifact = store(archive, &manifest_bytes, "application/json");
    let mut objects: Vec<_> = [
        artifact.clone(),
        runtime.clone(),
        scheduler.clone(),
        schema.clone(),
        snapshot.clone(),
        settlement.clone(),
        provenance,
        journal_ref.clone(),
        coordinator_ref,
    ]
    .into_iter()
    .map(|reference| Object {
        reference,
        dependencies: vec![],
    })
    .collect();
    for object in &mut objects {
        if object.reference == journal_ref {
            object.dependencies = vec![runtime.clone(), snapshot.clone(), settlement.clone()];
            object.dependencies.sort();
        }
    }
    objects.sort_by(|a, b| a.reference.cmp(&b.reference));
    let index = Index {
        schema_version: 3,
        artifact,
        objects,
        owners: owners
            .iter()
            .enumerate()
            .map(|(index, owner)| {
                let (implementation, profile, schema_id, version) = if index == 3 {
                    (
                        "source-owned.host-scheduling-owner/2",
                        "source-owned.host-scheduling-original-lineage/2",
                        "source-owned.host-scheduling-continuation/2",
                        2,
                    )
                } else {
                    (
                        "source-owned.packet-native/5",
                        "source-owned.packet-complete-original-lineage/5",
                        "source-owned.packet-native-continuation/5",
                        5,
                    )
                };
                NativeOwnerState {
                    owner: owner.owner.clone(),
                    participants: vec![id(format!("model/node/{index}"))],
                    key: NativeStateKey {
                        implementation: id(implementation),
                        profile: id(profile),
                        schema: SchemaRef {
                            id: id(schema_id),
                            version,
                            definition: schema.clone(),
                            extensions: Default::default(),
                        },
                    },
                    cut,
                    state: snapshot.clone(),
                    evidence: vec![settlement.clone()],
                    artifacts: vec![],
                }
            })
            .collect(),
        selected_extensions: None,
        original_capture_journal: Some(journal_ref),
    };
    archive.persist(index).unwrap()
}

#[test]
fn selected_signed_loader_binds_accounting_receipt_and_rejects_legacy_or_foreign_thread() {
    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let saved = fixture(&archive);
    assert!(saved.authenticate_complete_load_admission().is_err());
    let ordinary = archive.load(saved.artifact()).unwrap();
    assert!(ordinary.authenticate_complete_load_admission().is_err());

    let selected = archive.load_complete_original(saved.artifact()).unwrap();
    selected.authenticate_complete_load_admission().unwrap();
    selected
        .clone()
        .authenticate_complete_load_admission()
        .unwrap();
    let foreign = selected.clone();
    assert!(
        std::thread::spawn(move || foreign.authenticate_complete_load_admission())
            .join()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        selected.original_capture_journal().unwrap(),
        ordinary.original_capture_journal().unwrap()
    );

    let index_path = directory
        .0
        .join("archive")
        .join(index_name(saved.artifact()));
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    // Flip an actual byte even if its original MAC byte was 255.
    let original =
        serde_json::from_slice::<serde_json::Value>(&fs::read(&index_path).unwrap()).unwrap();
    value["authentication"][0] =
        serde_json::json!(original["authentication"][0].as_u64().unwrap() ^ 1);
    fs::write(index_path, canonical::canonical_json(&value).unwrap()).unwrap();
    assert!(archive.load_complete_original(saved.artifact()).is_err());
}

#[test]
fn selected_file_growth_and_decoder_credit_refuse_before_parse() {
    let directory = Directory::new();
    let reference = canonical::content_ref(b"artifact", "application/json").unwrap();
    let mut archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    fs::write(
        directory.0.join("archive").join(index_name(&reference)),
        vec![b'x'; 65536],
    )
    .unwrap();
    archive.limits.state.maximum_total_content_bytes = 32 * 1024;

    assert_eq!(
        archive
            .load_complete_original(&reference)
            .err()
            .unwrap()
            .code,
        StateErrorCode::ResourceLimit
    );
    assert_ne!(
        archive.load(&reference).err().unwrap().code,
        StateErrorCode::ResourceLimit
    );
    let raw = br#"{"duplicate":["\u1234"],"duplicate":[1,2,3]}"#.to_vec();
    let credit = core_decode_credit::preflight_archive(&raw, 512 * 1024 * 1024).unwrap();
    let needed = fixed_storage() + raw.capacity() + credit.total().unwrap();
    assert!(admit_decode(&raw, 0, needed).is_ok());
    assert!(admit_decode(&raw, 0, needed - 1).is_err());
}

#[test]
fn selected_administrative_read_accounts_existing_content_before_decoder_or_validation() {
    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let saved = fixture(&archive);
    let selected = archive.load_complete_original(saved.artifact()).unwrap();
    let maximum = archive.limits.state.maximum_total_content_bytes;
    let refused = super::super::super::complete_original_index::authenticate_admitted(
        &selected, maximum, maximum,
    )
    .unwrap_err();
    assert_eq!(refused.code, StateErrorCode::ResourceLimit);
    assert_eq!(
        selected.original_capture_journal().unwrap().attempts.len(),
        1
    );
    let journal = selected.index.original_capture_journal.as_ref().unwrap();
    fs::write(
        directory.0.join("archive").join(object_name(journal)),
        vec![b' '; usize::try_from(journal.length.get()).unwrap() + 1],
    )
    .unwrap();
    assert_eq!(
        selected.original_capture_journal().unwrap_err().code,
        StateErrorCode::ResourceLimit
    );
    assert_eq!(selected.manifest().capture_id, id("model/capture"));
}

#[test]
fn selected_fifo_without_writer_refuses_before_blocking_open() {
    use std::os::unix::fs::FileTypeExt;

    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let reference = canonical::content_ref(b"fifo-name-only", "application/json").unwrap();
    rustix::fs::mkfifoat(
        archive.directory.as_ref(),
        index_name(&reference),
        Mode::RUSR | Mode::WUSR,
    )
    .unwrap();
    let path = directory.0.join("archive").join(index_name(&reference));
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());

    // No writer is ever opened. The harness additionally gives this original
    // test subprocess a ten-second deadline, so a blocking-open regression is
    // contained rather than waiting indefinitely for a fabricated writer.
    let failure = archive.load_complete_original(&reference).err().unwrap();
    assert_eq!(failure.code, StateErrorCode::ResourceLimit);
}

impl NativeArchive {
    // Reuses actual signed local storage while keeping modeled native rows
    // distinct from installed Source5/factory verification in sibling controls.
    pub(in crate::node_state::native) fn modeled_complete_archive_for_ticket_controls(
        &self,
    ) -> NativeArchiveRecord {
        let saved = fixture(self);
        self.load_complete_original(saved.artifact()).unwrap()
    }
}

#[test]
fn complete_index_identity_covers_backend_keys_beyond_the_manifest() {
    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let saved = fixture(&archive);
    let selected = archive.load_complete_original(saved.artifact()).unwrap();
    let first = selected
        .complete_original_index_identity(1024 * 1024, 0)
        .unwrap();
    let bytes =
        canonical::canonical_json(&serde_json::to_value(selected.index.as_ref()).unwrap()).unwrap();
    assert_eq!(
        first,
        canonical::content_ref(
            &bytes,
            "application/vnd.crucible.native-signed-index-body.v3+json",
        )
        .unwrap(),
    );
    assert_ne!(&first, selected.artifact());

    // A signer can preserve the same manifest while changing a backend schema definition in
    // its authenticated index. The manifest alone cannot bind a restore request.
    let mut changed = selected.index.as_ref().clone();
    changed.owners[0].key.schema.definition = changed.owners[0].state.clone();
    fs::remove_file(
        directory
            .0
            .join("archive")
            .join(index_name(saved.artifact())),
    )
    .unwrap();
    let changed = archive.persist(changed).unwrap();
    let changed = archive.load_complete_original(changed.artifact()).unwrap();

    assert_eq!(changed.artifact(), selected.artifact());
    assert_ne!(
        changed
            .complete_original_index_identity(1024 * 1024, 0)
            .unwrap(),
        first,
    );
    // An old admitted allocation remains an immutable historical value even
    // when a later signed file exists under the same manifest-derived name.
    assert_eq!(
        selected
            .complete_original_index_identity(1024 * 1024, 0)
            .unwrap(),
        first
    );
}

#[test]
fn complete_index_identity_refuses_unadmitted_foreign_and_exhausted_calls() {
    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let saved = fixture(&archive);
    assert!(
        saved
            .complete_original_index_identity(1024 * 1024, 0)
            .is_err()
    );
    assert!(
        archive
            .load(saved.artifact())
            .unwrap()
            .complete_original_index_identity(1024 * 1024, 0)
            .is_err(),
    );
    let selected = archive.load_complete_original(saved.artifact()).unwrap();
    assert!(selected.complete_original_index_identity(1, 0).is_err());
    assert!(
        selected
            .complete_original_index_identity(1024 * 1024, usize::MAX)
            .is_err()
    );
    let expected = selected
        .complete_original_index_identity(1024 * 1024, 0)
        .unwrap();
    let foreign = selected.clone();

    assert!(
        std::thread::spawn(move || foreign.complete_original_index_identity(1024 * 1024, 0))
            .join()
            .unwrap()
            .is_err(),
    );
    assert_eq!(
        selected
            .complete_original_index_identity(1024 * 1024, 0)
            .unwrap(),
        expected
    );
}
