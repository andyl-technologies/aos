//! Exercises real Core origin and filesystem receipts with modeled native rows.
//!
//! These controls do not qualify a full four-owner native Capture, source codec,
//! signer, restore or Ready. Original-write purpose is deliberately pre-sign.

// crucible-lint: allow panic-shortcut -- Modeled origin controls fail at the exact custody or filesystem invariant.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_contract::OriginalLineageWorldCapture;
use crate::node_state::native::storage::{Index, NativeOwnerState};
use crucible_node_format::{CaptureManifest, Id};

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "complete-write-origin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

fn provisional_model_record(
    archive: &NativeArchive,
    source: &crate::node_contract::OriginalLineageRuntimeRecord,
    captures: &OriginalLineageWorldCapture,
) -> NativeArchiveRecord {
    let read = captures.read().unwrap();
    let captured = read.owners().next().unwrap();
    let native = captured.native();
    let body = native.state().reference.clone();
    let journal = captured.journal().reference.clone();
    let manifest = CaptureManifest {
        schema_version: 1,
        capture_id: Id::new("model/capture").unwrap(),
        world_binding_hash: source.source_activation.world_binding_hash.clone(),
        scenario_ref: body.clone(),
        preservation_contract: Id::new("source-owned.packet-complete-original-lineage/5").unwrap(),
        cut: source.capture_cut,
        event_ordinal: source.capture_ordinal,
        ordering_profile: "superdense-v1".into(),
        guarantees_ref: body.clone(),
        coordinator_state_ref: body.clone(),
        owners: vec![],
        immutable_refs: vec![],
        provenance_ref: journal.clone(),
        extensions: Default::default(),
    };
    // This one-owner model tests only private origin correspondence. The actual
    // production writer creates its record through record(), whose complete
    // four-owner grammar and source validation remain independent mandatory gates.
    NativeArchiveRecord {
        complete_load: None,
        index: Arc::new(Index {
            schema_version: 3,
            artifact: body.clone(),
            objects: vec![],
            owners: vec![NativeOwnerState {
                owner: native.owner().clone(),
                participants: native.participants().to_vec(),
                key: native.key().clone(),
                cut: source.capture_cut,
                state: body,
                evidence: vec![journal.clone()],
                artifacts: vec![],
            }],
            selected_extensions: None,
            original_capture_journal: Some(journal),
        }),
        manifest,
        directory: Arc::clone(&archive.directory),
        limits: archive.limits,
    }
}

#[test]
fn original_pre_sign_origin_is_exact_and_does_not_fake_historical_load_admission() {
    let directory = Directory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let (runtime, source, captures) =
        OriginalLineageWorldCapture::modeled_archive_write_origin_fixture();
    let record = provisional_model_record(&archive, &source, &captures);
    let origin =
        CompleteArchiveValidationOrigin::original_write(&archive, &record, &captures, &runtime)
            .unwrap();
    origin.authenticate(&record).unwrap();
    assert!(std::ptr::eq(
        origin
            .original_write_runtime_data(&record)
            .unwrap()
            .unwrap(),
        &runtime,
    ));
    assert!(origin.original_write_runtime_data(&record.clone()).is_err());
    let identity =
        index_identity_data(&record, archive.limits.state.maximum_record_bytes, 0).unwrap();
    assert_ne!(identity, *record.artifact());
    assert!(CompleteArchiveValidationOrigin::selected_load(&record).is_err());
    assert!(
        record
            .complete_original_index_identity(archive.limits.state.maximum_record_bytes, 0)
            .is_err()
    );
    assert!(origin.authenticate(&record.clone()).is_err());
    assert!(captures.modeled_archive_write_hold_retained(&runtime));
}

#[test]
fn original_origin_rejects_foreign_creator_wrong_directory_and_stale_attempt() {
    let first = Directory::new();
    let second = Directory::new();
    let archive = NativeArchive::open(&first.0, NativeArchiveLimits::default()).unwrap();
    let other = NativeArchive::open(&second.0, NativeArchiveLimits::default()).unwrap();
    let (runtime, source, captures) =
        OriginalLineageWorldCapture::modeled_archive_write_origin_fixture();
    let record = provisional_model_record(&archive, &source, &captures);
    assert!(
        CompleteArchiveValidationOrigin::original_write(&other, &record, &captures, &runtime)
            .is_err()
    );
    let mut origin =
        CompleteArchiveValidationOrigin::original_write(&archive, &record, &captures, &runtime)
            .unwrap();
    if let CompleteArchiveValidationOrigin::OriginalWrite { process, .. } = &mut origin {
        *process = process.wrapping_add(1);
    }
    assert!(origin.authenticate(&record).is_err());
    let original =
        CompleteArchiveValidationOrigin::original_write(&archive, &record, &captures, &runtime)
            .unwrap();
    captures.erase_modeled_archive_write_active();
    assert!(original.authenticate(&record).is_err());
    assert!(original.original_write_runtime_data(&record).is_err());
}

#[test]
fn refused_persistence_does_not_release_the_original_capture_hold() {
    let directory = Directory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let (runtime, source, captures) =
        OriginalLineageWorldCapture::modeled_archive_write_origin_fixture();
    let record = provisional_model_record(&archive, &source, &captures);
    let original =
        CompleteArchiveValidationOrigin::original_write(&archive, &record, &captures, &runtime)
            .unwrap();
    // Actual persistence rejects this deliberately incomplete model index before
    // signing. This is validation refusal, not a simulated filesystem success.
    assert!(archive.persist(record.index.as_ref().clone()).is_err());
    original.authenticate(&record).unwrap();
    assert!(captures.modeled_archive_write_hold_retained(&runtime));
    assert_eq!(captures.read().unwrap().owners().count(), 1);
}

#[test]
fn original_origin_rejects_changed_participant_roster_without_releasing_capture_hold() {
    let directory = Directory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let (runtime, source, captures) =
        OriginalLineageWorldCapture::modeled_archive_write_origin_fixture();
    let mut record = provisional_model_record(&archive, &source, &captures);
    let original_participants = record.owners()[0].participants.clone();
    assert_eq!(original_participants.len(), 2);

    assert!(
        Arc::make_mut(&mut record.index).owners[0]
            .participants
            .pop()
            .is_some()
    );
    assert!(
        CompleteArchiveValidationOrigin::original_write(&archive, &record, &captures, &runtime)
            .is_err()
    );

    assert!(captures.modeled_archive_write_hold_retained(&runtime));
    let read = captures.read().unwrap();
    assert_eq!(
        read.owners().next().unwrap().native().participants(),
        original_participants,
    );
}

#[test]
fn historical_origin_requires_actual_selected_load_receipt_for_the_same_record() {
    let directory = Directory::new();
    let archive = NativeArchive::open(&directory.0, NativeArchiveLimits::default()).unwrap();
    let durable = super::super::complete_original_loader::tests::fixture(&archive);
    let legacy = archive.load(durable.artifact()).unwrap();
    assert!(CompleteArchiveValidationOrigin::selected_load(&legacy).is_err());
    let selected = archive.load_complete_original(durable.artifact()).unwrap();
    let original = CompleteArchiveValidationOrigin::selected_load(&selected).unwrap();
    original.authenticate(&selected).unwrap();
    assert!(
        original
            .original_write_runtime_data(&selected)
            .unwrap()
            .is_none()
    );
    assert!(
        original
            .original_write_runtime_data(&selected.clone())
            .is_err()
    );
    assert!(original.authenticate(&selected.clone()).is_err());
    let expected = selected
        .complete_original_index_identity(archive.limits.state.maximum_record_bytes, 0)
        .unwrap();
    assert_eq!(
        index_identity_data(&selected, archive.limits.state.maximum_record_bytes, 0).unwrap(),
        expected
    );
}

#[test]
fn selected_load_limits_loan_keeps_actual_lower_archive_and_rejects_replaced_record() {
    let directory = Directory::new();
    let installed = NativeArchiveLimits::default();
    let writer = NativeArchive::open(&directory.0, installed).unwrap();
    let durable = super::super::complete_original_loader::tests::fixture(&writer);
    let mut lower = installed;
    lower.state.maximum_total_content_bytes -= 1;
    lower.native.maximum_total_record_bytes -= 2;
    lower.state.maximum_native_memory_bytes -= 3;
    let reader = NativeArchive::open(&directory.0, lower).unwrap();
    let selected = reader.load_complete_original(durable.artifact()).unwrap();
    let origin = CompleteArchiveValidationOrigin::selected_load(&selected).unwrap();

    let observed = origin.archive_limits_data(&selected).unwrap();

    assert_eq!(
        observed.state.maximum_total_content_bytes,
        lower.state.maximum_total_content_bytes
    );
    assert_eq!(
        observed.native.maximum_total_record_bytes,
        lower.native.maximum_total_record_bytes
    );
    assert_eq!(
        observed.state.maximum_native_memory_bytes,
        lower.state.maximum_native_memory_bytes
    );
    assert!(
        observed.state.maximum_total_content_bytes < installed.state.maximum_total_content_bytes
    );
    assert!(origin.archive_limits_data(&selected.clone()).is_err());
    assert!(
        origin
            .original_write_runtime_data(&selected)
            .unwrap()
            .is_none()
    );
}

#[test]
fn original_loaded_inventory_checks_effective_counts_bytes_and_unproved_depth_without_copies() {
    let directory = Directory::new();
    let limits = NativeArchiveLimits::default();
    let archive = NativeArchive::open(&directory.0, limits).unwrap();
    let durable = super::super::complete_original_loader::tests::fixture(&archive);
    let selected = archive.load_complete_original(durable.artifact()).unwrap();
    selected
        .authenticate_cold_inventory_limits_data(limits)
        .unwrap();

    let mut lower = limits;
    lower.state.maximum_owners_or_domains = 0;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    lower = limits;
    lower.state.maximum_content_objects = selected.index.objects.len() - 1;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    lower = limits;
    lower.state.maximum_content_bytes = 0;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    lower = limits;
    lower.native.maximum_objects = 0;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    lower = limits;
    lower.native.maximum_record_bytes = 0;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    lower = limits;
    lower.state.maximum_dependency_depth -= 1;
    assert!(
        selected
            .authenticate_cold_inventory_limits_data(lower)
            .is_err()
    );
    selected
        .authenticate_cold_inventory_limits_data(limits)
        .unwrap();
    assert_eq!(
        selected.index.objects.len(),
        archive
            .load_complete_original(durable.artifact())
            .unwrap()
            .index
            .objects
            .len()
    );
}
