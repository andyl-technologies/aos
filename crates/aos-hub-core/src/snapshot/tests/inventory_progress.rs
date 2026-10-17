//! Durable inventory progress stays private and bound to its exact SQL row.

use super::*;
use crate::db::{OciInventoryObjectProgress, OciInventoryProgress};

fn progress() -> OciInventoryProgress {
    let digest = aos_oci_types::Sha256Digest::digest(b"bounded source");
    OciInventoryProgress {
        version: 1,
        generation_id: format!("ociinv-{}", "a".repeat(32)),
        next_provider_cursor: Some("oci-blobs-v1:next".into()),
        object: OciInventoryObjectProgress::initial(
            1,
            2,
            Some("oci-blobs-v1:requested".into()),
            &format!("oci/blobs/sha256/{}", digest.encoded()),
            digest,
            14,
            "\"tag\"".into(),
            None,
        )
        .unwrap(),
    }
}

#[test]
fn exact_progress_is_private_and_row_substitution_refuses() {
    let value = progress();
    let encoded = value.encode().unwrap().into_bytes();
    let classify = |id: String, placement: i64, ordinal: i64, cursor: String| {
        classifier().classify(
            "oci_provider_inventory_generations",
            &row(
                "oci_provider_inventory_generations",
                &[
                    ("id", Value::Text(id)),
                    ("placement_id", Value::Int(placement)),
                    ("checkpoint_ordinal", Value::Int(ordinal)),
                    ("provider_cursor", Value::Text(cursor)),
                    ("object_progress", Value::Bytes(encoded.clone())),
                ],
            ),
        )
    };
    let SnapshotRowDisposition::Retained(accepted) = classify(
        value.generation_id.clone(),
        1,
        2,
        "oci-blobs-v1:requested".into(),
    )
    .unwrap() else {
        panic!("retained progress row")
    };
    assert!(matches!(
        accepted.cells["object_progress"],
        ClassifiedCell::External(_)
    ));
    assert_eq!(accepted.private_dependencies.len(), 1);

    assert!(
        classify(
            format!("ociinv-{}", "b".repeat(32)),
            1,
            2,
            "oci-blobs-v1:requested".into()
        )
        .is_err()
    );
    assert!(
        classify(
            value.generation_id.clone(),
            2,
            2,
            "oci-blobs-v1:requested".into()
        )
        .is_err()
    );
    assert!(
        classify(
            value.generation_id.clone(),
            1,
            3,
            "oci-blobs-v1:requested".into()
        )
        .is_err()
    );
    assert!(classify(value.generation_id, 1, 2, "requested".into()).is_err());
}

#[test]
fn generation_twelve_adds_progress_without_rewriting_generation_eight() {
    let historical = SnapshotClassifier::for_supported_generation(8).unwrap();
    let current = SnapshotClassifier::for_supported_generation(12).unwrap();
    assert_eq!(
        historical.manifest().identity,
        "aos-hub/canonical-serving/8"
    );
    assert_eq!(historical.manifest().migration_digests, digests()[..8]);
    assert!(
        !historical.tables["oci_provider_inventory_generations"]
            .columns
            .iter()
            .any(|column| column.name == "object_progress")
    );
    assert!(
        current.tables["oci_provider_inventory_generations"]
            .columns
            .iter()
            .any(|column| column.name == "object_progress")
    );
    for intermediate in [9, 10, 11] {
        assert!(SnapshotClassifier::for_supported_generation(intermediate).is_err());
    }
}
