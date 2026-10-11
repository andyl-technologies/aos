//! Closed retained allocation cells preserve identity without granting live authority.

use super::*;
use crate::direct_upload::{DirectActorKind, DirectActorSlot, WireInteger};

fn allocation() -> Row {
    let actor = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(7),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let principal = actor.principal_id("deployment-one").unwrap();
    let operation = "1".repeat(64);
    let business = crate::direct_upload::deterministic_business_operation_id(
        "deployment-one",
        &principal,
        &operation,
    )
    .unwrap();
    let values = contract().unwrap()["direct_oci_allocations"]
        .columns
        .iter()
        .map(|column| match column.name.as_str() {
            "business_id" => Value::Text(business.clone()),
            "deployment_id" => Value::Text("deployment-one".into()),
            "principal_id" => Value::Text(principal.clone()),
            "client_operation_id" => Value::Text(operation.clone()),
            "actor_kind" => Value::Text("user".into()),
            "actor_id" => Value::Int(7),
            "actor_incarnation" => Value::Text(actor.incarnation.clone()),
            "registry_id" | "repository_id" | "created_at" => Value::Int(1),
            "registry_stable_id" => Value::Text("registry:0123456789abcdef0123456789abcdef".into()),
            "repository_name" => Value::Text("team/image".into()),
            "source_sha256" => Value::Text("2".repeat(64)),
            "declared_size" => Value::Int(0),
            "upload_id" => Value::Text("0123456789abcdef0123456789abcdef".into()),
            "original_token_id" => Value::Text("01234567-89ab-4def-8123-456789abcdef".into()),
            unknown => panic!("unreviewed allocation column {unknown}"),
        })
        .collect();
    Row::new(values)
}

#[test]
fn retained_oci_allocation_cells_roundtrip_exact_original_identity() {
    let classifier = SnapshotClassifier::for_supported_generation(4).unwrap();
    let original = allocation();
    let captured = classifier
        .capture_private_row("direct_oci_allocations", &original)
        .unwrap();
    let SnapshotRowDisposition::Retained(row) = captured.classified() else {
        panic!("allocation was omitted");
    };
    let reconstructed = classifier
        .reconstruct_private_row(row, captured.private_cells())
        .unwrap();
    reconstructed.with_private_row(|row| assert_eq!(row, &original));
}

#[test]
fn allocation_identity_substitution_and_invalid_closed_cells_refuse() {
    let classifier = SnapshotClassifier::for_supported_generation(4).unwrap();
    let original = allocation();
    for (column, value) in [
        ("business_id", Value::Text("3".repeat(64))),
        ("principal_id", Value::Text("4".repeat(64))),
        ("actor_kind", Value::Text("org".into())),
        (
            "actor_incarnation",
            Value::Text("01234567-89ab-4def-0123-456789abcdef".into()),
        ),
        ("client_operation_id", Value::Text("A".repeat(64))),
        ("registry_id", Value::Int(0)),
        ("declared_size", Value::Int(17_179_869_185)),
        ("source_sha256", Value::Text("x".repeat(64))),
        ("repository_name", Value::Text("UPPER/image".into())),
        ("original_token_id", Value::Text("legacy-token".into())),
    ] {
        let mut values = (0..original.len())
            .map(|i| original.value(i).unwrap().clone())
            .collect::<Vec<_>>();
        let index = contract().unwrap()["direct_oci_allocations"]
            .columns
            .iter()
            .position(|item| item.name == column)
            .unwrap();
        values[index] = value;
        assert!(
            classifier
                .capture_private_row("direct_oci_allocations", &Row::new(values))
                .is_err(),
            "{column}"
        );
    }
}
