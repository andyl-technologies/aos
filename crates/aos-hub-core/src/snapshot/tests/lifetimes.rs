//! Presence source references preserve nonversioned provider receipt kinds.

use super::*;

#[test]
fn registry_accounting_origin_roundtrips_without_adopting_legacy_or_cache_charges() {
    let fresh = row(
        "surface_objects",
        &[
            ("registry_id", Value::Int(2)),
            ("accounting_origin_version", Value::Int(7)),
        ],
    );
    let record = retained(classifier().classify("surface_objects", &fresh).unwrap());
    assert_eq!(
        record.cells["accounting_origin_version"],
        ClassifiedCell::Scalar(SnapshotScalar::Integer("7".into()))
    );

    let legacy = row("surface_objects", &[("registry_id", Value::Int(2))]);
    let record = retained(classifier().classify("surface_objects", &legacy).unwrap());
    assert_eq!(
        record.cells["accounting_origin_version"],
        ClassifiedCell::Scalar(SnapshotScalar::Null)
    );

    for overrides in [
        vec![
            ("registry_id", Value::Int(2)),
            ("accounting_origin_version", Value::Int(8)),
        ],
        vec![
            ("cache_id", Value::Int(2)),
            ("accounting_origin_version", Value::Int(7)),
        ],
    ] {
        assert!(
            classifier()
                .classify("surface_objects", &row("surface_objects", &overrides))
                .is_err()
        );
    }
}

#[test]
fn nonversioned_direct_presence_retains_exact_session_source_without_provider_version() {
    let input = row(
        "object_placements",
        &[
            ("state", Value::Text("present".into())),
            ("etag", Value::Text("\"final-etag\"".into())),
            ("observed_placement_resource_version", Value::Int(3)),
            ("observed_write_spec_version", Value::Int(4)),
            ("observed_binding_resource_version", Value::Int(5)),
            (
                "direct_upload_session_id",
                Value::Text("exact-session".into()),
            ),
        ],
    );
    let classified = retained(classifier().classify("object_placements", &input).unwrap());
    assert_eq!(
        classified.cells["provider_version"],
        ClassifiedCell::Scalar(SnapshotScalar::Null)
    );
    assert_eq!(
        classified.cells["direct_upload_session_id"],
        ClassifiedCell::Scalar(SnapshotScalar::Text("exact-session".into()))
    );

    // Shape checking grants no receipt authority; relational replay must then
    // resolve this exact retained session and its canonical terminal evidence.
    let contract = contract().unwrap();
    let columns = &contract["object_placements"].columns;
    let index = columns
        .iter()
        .position(|column| column.name == "direct_upload_session_id")
        .unwrap();
    let mut missing_source: Vec<_> = (0..input.len())
        .map(|index| input.value(index).unwrap().clone())
        .collect();
    missing_source[index] = Value::Null;
    assert!(
        classifier()
            .classify("object_placements", &Row::new(missing_source))
            .is_err()
    );

    let index = columns
        .iter()
        .position(|column| column.name == "observed_binding_resource_version")
        .unwrap();
    let mut partial_source: Vec<_> = (0..input.len())
        .map(|index| input.value(index).unwrap().clone())
        .collect();
    partial_source[index] = Value::Null;
    assert!(
        classifier()
            .classify("object_placements", &Row::new(partial_source))
            .is_err()
    );
}
