//! Closed mirror originals, exact private progress and lifecycle reconstruction.

use super::*;
use crate::mirror_work::{
    digest, MirrorOriginal, MirrorPart, MirrorProgress, MirrorVerification, MirrorVerifiedObject,
};
use crate::storage_work::StorageObjectIdentity;

fn original() -> MirrorOriginal {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("4".repeat(32)),
        registry_id: 7,
        registry_resource_version: 2,
        mirror_resource_version: 1,
        upstream_base: "https://upstream.example.invalid/registry".into(),
        path: "nar/source.nar.zst".into(),
        placement_id: 3,
        placement_resource_version: 4,
        write_spec_version: 5,
        binding_id: 6,
        binding_resource_version: 7,
        protected_profile_digest: "3".repeat(64),
        placement_prefix: "mirror".into(),
        verification: MirrorVerification::Nar {
            file_sha256: Some("1".repeat(64)),
            file_size: 11,
            compression: "zstd".into(),
            nar_sha256: "2".repeat(64),
            nar_size: 17,
        },
    };
    original.job_id = original.identity().unwrap();
    original
}

fn progress(original: &MirrorOriginal) -> MirrorProgress {
    let stage = StorageObjectIdentity {
        key: original.stage_key(),
        size: 11,
        etag: "\"stage-etag\"".into(),
        provider_version: Some("stage-incarnation".into()),
    };
    let verified = MirrorVerifiedObject {
        object: stage.clone(),
        sha256: "1".repeat(64),
        nar_sha256: Some("2".repeat(64)),
        nar_size: Some(17),
    };
    let part = MirrorPart {
        part_number: 1,
        size: 11,
        sha256: "1".repeat(64),
        etag: "\"part-etag\"".into(),
    };
    let destination = MirrorVerifiedObject {
        object: StorageObjectIdentity {
            key: crate::keymap::r2_key(&original.placement_prefix, &original.path),
            size: 11,
            etag: "\"final-etag\"".into(),
            provider_version: Some("final-incarnation".into()),
        },
        ..verified.clone()
    };
    MirrorProgress {
        original_digest: digest(original).unwrap(),
        upstream_etag: Some("\"upstream-etag\"".into()),
        stage_upload_id: Some("private-stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(stage),
        verified: Some(verified),
        destination_upload_id: Some("private-final-upload".into()),
        destination_parts: vec![part],
        destination: Some(destination),
    }
}

fn source(original: &MirrorOriginal, progress: Option<&MirrorProgress>, state: &str) -> Row {
    row(
        "mirror_import_objects",
        &[
            ("job_id", Value::Text(original.job_id.clone())),
            ("registry_id", Value::Int(original.registry_id)),
            ("original_digest", Value::Text(digest(original).unwrap())),
            (
                "original_json",
                Value::Text(serde_json::to_string(original).unwrap()),
            ),
            (
                "progress_json",
                progress
                    .map(|progress| Value::Text(serde_json::to_string(progress).unwrap()))
                    .unwrap_or(Value::Null),
            ),
            ("state", Value::Text(state.into())),
            (
                "commit_digest",
                if state == "committed" {
                    Value::Text(progress.unwrap().commit_digest(original).unwrap())
                } else {
                    Value::Null
                },
            ),
            ("created_at", Value::Int(1)),
            ("updated_at", Value::Int(2)),
            ("source_path", Value::Text(original.path.clone())),
            (
                "source_path_digest",
                Value::Text(original.source_path_digest()),
            ),
            (
                "copy_operation_id",
                original
                    .copy_operation_id
                    .clone()
                    .map(Value::Text)
                    .unwrap_or(Value::Null),
            ),
        ],
    )
}

fn change(source: &Row, column: &str, value: Value) -> Row {
    let columns = &contract().unwrap()["mirror_import_objects"].columns;
    Row::new(
        columns
            .iter()
            .enumerate()
            .map(|(index, definition)| {
                if definition.name == column {
                    value.clone()
                } else {
                    source.value(index).unwrap().clone()
                }
            })
            .collect(),
    )
}

#[test]
fn mirror_original_and_all_positive_phases_preserve_exact_private_bytes() {
    let original = original();
    let full = progress(&original);
    let mut staged = full.clone();
    staged.destination_upload_id = None;
    staged.destination_parts.clear();
    staged.destination = None;

    for (state, progress) in [
        ("admitted", None),
        ("staged_verified", Some(&staged)),
        ("published", Some(&full)),
        ("committed", Some(&full)),
    ] {
        let source = source(&original, progress, state);
        let capture = classifier()
            .capture_private_row("mirror_import_objects", &source)
            .unwrap();
        assert_eq!(
            capture.private_cells().len(),
            if progress.is_some() { 3 } else { 2 }
        );
        let SnapshotRowDisposition::Retained(classified) = capture.classified() else {
            panic!("mirror original omitted")
        };
        let public = serde_json::to_string(classified).unwrap();
        for private in [
            "upstream.example.invalid",
            "private-stage-upload",
            "final-incarnation",
            "nar/source.nar.zst",
        ] {
            assert!(!public.contains(private));
        }
        let reconstructed = classifier()
            .reconstruct_private_row(classified, capture.private_cells())
            .unwrap();
        reconstructed.with_private_row(|row| assert_eq!(row, &source));
    }
}

#[test]
fn mirror_scalar_identity_phase_and_terminal_proof_cannot_disagree() {
    let original = original();
    let source = source(&original, Some(&progress(&original)), "committed");
    for (column, value) in [
        ("job_id", Value::Text("8".repeat(64))),
        ("registry_id", Value::Int(8)),
        ("original_digest", Value::Text("9".repeat(64))),
        ("state", Value::Text("admitted".into())),
        ("commit_digest", Value::Text("a".repeat(64))),
        ("created_at", Value::Int(0)),
        ("updated_at", Value::Int(0)),
        ("progress_json", Value::Null),
        ("source_path", Value::Null),
        ("source_path", Value::Text("nar/other.nar.zst".into())),
        ("source_path_digest", Value::Null),
        ("source_path_digest", Value::Text("b".repeat(64))),
        ("copy_operation_id", Value::Null),
        ("copy_operation_id", Value::Text("5".repeat(32))),
    ] {
        assert!(
            classifier()
                .classify("mirror_import_objects", &change(&source, column, value))
                .is_err(),
            "{column}"
        );
    }
}

#[test]
fn changed_original_or_noncanonical_unknown_json_is_refused() {
    let original = original();
    let source = source(&original, None, "admitted");
    let canonical = serde_json::to_string(&original).unwrap();
    let mut changed = original.clone();
    changed.path = "nar/other.nar.zst".into();
    let mut changed_source = original.clone();
    changed_source.mirror_resource_version += 1;
    for json in [
        serde_json::to_string(&changed).unwrap(),
        serde_json::to_string(&changed_source).unwrap(),
        serde_json::to_string_pretty(&original).unwrap(),
        canonical.replacen('{', "{\"unknown\":true,", 1),
        canonical.replacen('{', "{\"job_id\":\"changed\",", 1),
    ] {
        assert!(classifier()
            .classify(
                "mirror_import_objects",
                &change(&source, "original_json", Value::Text(json))
            )
            .is_err());
    }
}

#[test]
fn mirror_progress_requires_original_nar_geometry_and_provider_incarnations() {
    let original = original();
    let full = progress(&original);
    let source = source(&original, Some(&full), "committed");
    let mut variants = Vec::new();
    let mut changed = full.clone();
    changed.stage_upload_id = None;
    variants.push(changed);
    let mut changed = full.clone();
    changed.destination_upload_id = None;
    variants.push(changed);
    let mut changed = full.clone();
    changed.verified = None;
    variants.push(changed);
    let mut changed = full.clone();
    changed.original_digest = "8".repeat(64);
    variants.push(changed);
    let mut changed = full.clone();
    changed.stage_parts[0].size += 1;
    variants.push(changed);
    let mut changed = full.clone();
    changed.verified.as_mut().unwrap().object.provider_version = Some("different-stage".into());
    variants.push(changed);
    let mut changed = full.clone();
    changed
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = None;
    variants.push(changed);
    let mut changed = full.clone();
    changed.destination.as_mut().unwrap().nar_sha256 = Some("8".repeat(64));
    variants.push(changed);
    let mut changed = full.clone();
    changed
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = Some("different-final".into());
    variants.push(changed);

    for changed in variants {
        assert!(classifier()
            .classify(
                "mirror_import_objects",
                &change(
                    &source,
                    "progress_json",
                    Value::Text(serde_json::to_string(&changed).unwrap())
                )
            )
            .is_err());
    }
}

#[test]
fn missing_or_duplicate_mirror_private_originals_cannot_reconstruct() {
    let original = original();
    let source = source(&original, Some(&progress(&original)), "committed");
    let capture = classifier()
        .capture_private_row("mirror_import_objects", &source)
        .unwrap();
    let SnapshotRowDisposition::Retained(classified) = capture.classified() else {
        panic!("mirror original omitted")
    };
    assert!(classifier()
        .reconstruct_private_row(classified, &capture.private_cells()[..1])
        .is_err());
    let mut encoded = Vec::new();
    capture.private_cells()[0]
        .write_private_scalar_json(&mut encoded)
        .unwrap();
    let duplicate = PrivateSnapshotCell::from_private_scalar_json(
        capture.private_cells()[0].dependency().clone(),
        &encoded,
    )
    .unwrap();
    let duplicates = [
        duplicate,
        PrivateSnapshotCell::from_private_scalar_json(
            capture.private_cells()[0].dependency().clone(),
            &encoded,
        )
        .unwrap(),
    ];
    assert!(classifier()
        .reconstruct_private_row(classified, &duplicates)
        .is_err());
}

#[test]
fn historical5_original_bytes_remain_canonical_and_backfilled6_indexes_are_exact() {
    let mut original = original();
    original.copy_operation_id = None;
    original.job_id = original.identity().unwrap();
    let canonical = serde_json::to_string(&original).unwrap();
    assert!(!canonical.contains("copy_operation_id"));

    let current = source(&original, None, "admitted");
    let legacy = Row::new(
        (0..9)
            .map(|index| current.value(index).unwrap().clone())
            .collect(),
    );
    let historical = SnapshotClassifier::for_supported_generation(5).unwrap();
    let capture = historical
        .capture_private_row("mirror_import_objects", &legacy)
        .unwrap();
    let SnapshotRowDisposition::Retained(classified) = capture.classified() else {
        panic!("historical mirror original omitted")
    };
    historical
        .reconstruct_private_row(classified, capture.private_cells())
        .unwrap()
        .with_private_row(|recovered| assert_eq!(recovered, &legacy));
    assert!(classifier()
        .classify("mirror_import_objects", &current)
        .is_ok());

    // A future operation cannot enter the closed historical schema by hiding
    // its index fields. Migrated old originals retain their omitted field.
    let fresh = source(&self::original(), None, "admitted");
    let disguised = Row::new(
        (0..9)
            .map(|index| fresh.value(index).unwrap().clone())
            .collect(),
    );
    assert!(historical
        .classify("mirror_import_objects", &disguised)
        .is_err());
}

#[test]
fn mirror_index_preserves_full_maximum_path_without_truncation() {
    let mut original = original();
    original.path = format!("nar/{}", "x".repeat(2044));
    original.job_id = original.identity().unwrap();
    let source = source(&original, None, "admitted");
    let capture = classifier()
        .capture_private_row("mirror_import_objects", &source)
        .unwrap();
    let SnapshotRowDisposition::Retained(classified) = capture.classified() else {
        panic!("mirror original omitted")
    };
    classifier()
        .reconstruct_private_row(classified, capture.private_cells())
        .unwrap()
        .with_private_row(|recovered| assert_eq!(recovered, &source));
    assert_eq!(original.path.len(), 2048);
}
