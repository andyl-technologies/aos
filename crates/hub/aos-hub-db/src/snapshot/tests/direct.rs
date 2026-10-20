//! Exact closed direct-session records and immutable business identity checks.

use super::*;
use crate::direct_upload::*;

fn credential(purpose: &str) -> DirectCredentialRevision {
    DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "protected-profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "worker-profile:1".into(),
        credential_fingerprint: "3".repeat(64),
    }
}

pub(super) fn admission() -> DirectUploadAdmission {
    let placement = DirectPlacement {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        final_key: "cache/object".into(),
        staging_prefix: ".aos-direct-upload".into(),
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "reviewed-policy".into(),
            policy_digest: "4".repeat(64),
            namespace: "private-bucket".into(),
        },
        protected_profile_digest: "5".repeat(64),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        physical: DirectPhysicalContext::DeploymentR2 {
            deployment_id: "deployment".into(),
            bucket_namespace: "permanent-bucket".into(),
        },
        write_credential: credential("write"),
        read_credential: credential("read"),
        presign_credential: credential("presign"),
    };
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(7),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "5".repeat(64),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "1".repeat(64),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache:stable".into(),
                path: "object".into(),
            },
            expected_sha256: "2".repeat(64),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1000),
        placements: vec![placement],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    admission
}

fn original_row(admission: &DirectUploadAdmission) -> Row {
    row(
        "direct_upload_sessions",
        &[
            ("session_id", Value::Text(admission.session_id.clone())),
            ("deployment_id", Value::Text("deployment".into())),
            ("principal_id", Value::Text(admission.principal_id.clone())),
            (
                "client_operation_id",
                Value::Text(admission.intent.client_operation_id.clone()),
            ),
            ("target_kind", Value::Text("cache_object".into())),
            ("cache_id", Value::Int(17)),
            ("cache_identifier", Value::Text("cache:stable".into())),
            (
                "cache_ticket_id",
                Value::Text("retained-cache-ticket".into()),
            ),
            ("object_path", Value::Text("object".into())),
            (
                "intent_json",
                Value::Text(
                    String::from_utf8(encode_direct_control(&admission.intent).unwrap()).unwrap(),
                ),
            ),
            (
                "admission_json",
                Value::Text(String::from_utf8(encode_direct_control(admission).unwrap()).unwrap()),
            ),
            (
                "logical_fingerprint",
                Value::Text(admission.logical_fingerprint.clone()),
            ),
            (
                "source_sha256",
                Value::Text(admission.intent.expected_sha256.clone()),
            ),
            ("declared_size", Value::Int(1)),
            ("part_size", Value::Int(8 * 1024 * 1024)),
            ("declared_dependency_phase", Value::Text("content".into())),
            ("state", Value::Text("admitted".into())),
            ("expires_at", Value::Int(1000)),
        ],
    )
}

fn change(row: Row, name: &str, value: Value) -> Row {
    let mut values = (0..row.len())
        .map(|index| row.value(index).unwrap().clone())
        .collect::<Vec<_>>();
    let index = contract().unwrap()["direct_upload_sessions"]
        .columns
        .iter()
        .position(|column| column.name == name)
        .unwrap();
    values[index] = value;
    Row::new(values)
}

#[test]
fn direct_closed_admission_preserves_exact_private_bytes_and_original_owner() {
    let original = admission();
    let source = original_row(&original);
    let captured = classifier()
        .capture_private_row("direct_upload_sessions", &source)
        .unwrap();
    assert_eq!(captured.private_cells().len(), 2);
    let SnapshotRowDisposition::Retained(classified) = captured.classified() else {
        panic!("direct record omitted");
    };
    let reconstructed = classifier()
        .reconstruct_private_row(classified, captured.private_cells())
        .unwrap();
    reconstructed.with_private_row(|row| assert_eq!(row, &source));
}

#[test]
fn changed_scalar_source_owner_domain_phase_or_state_rejects_closed_admission() {
    let source = original_row(&admission());
    for (column, value) in [
        ("declared_size", Value::Int(2)),
        ("source_sha256", Value::Text("8".repeat(64))),
        ("cache_identifier", Value::Text("cache:other".into())),
        ("deployment_id", Value::Text("different-deployment".into())),
        (
            "declared_dependency_phase",
            Value::Text("visibility".into()),
        ),
        ("state", Value::Text("settled_after_expiry".into())),
        ("completed_at", Value::Int(100)),
    ] {
        assert!(classifier()
            .classify(
                "direct_upload_sessions",
                &change(source.clone(), column, value)
            )
            .is_err());
    }
}

#[test]
fn opaque_unknown_duplicate_and_noncanonical_direct_json_rejects() {
    let original = admission();
    let source = original_row(&original);
    let json = String::from_utf8(encode_direct_control(&original).unwrap()).unwrap();
    for value in [
        "{}".to_owned(),
        json.replacen('{', "{\"unknown\":true,", 1),
        json.replacen('{', "{\"sessionId\":\"changed\",", 1),
        serde_json::to_string_pretty(&original).unwrap(),
    ] {
        assert!(classifier()
            .classify(
                "direct_upload_sessions",
                &change(source.clone(), "admission_json", Value::Text(value))
            )
            .is_err());
    }
}

#[test]
fn completion_intent_pins_original_cas_and_canonical_manifests() {
    let admission = admission();
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint,
        },
        operation_id: "6".repeat(64),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![DirectManifestCommitment {
            placement: admission.placements[0].public_ref("deployment").unwrap(),
            part_count: 1,
            manifest_digest: "7".repeat(64),
        }],
    };
    let input = row(
        "direct_upload_completion_intents",
        &[
            (
                "session_id",
                Value::Text(complete.session.session_id.clone()),
            ),
            ("deployment_id", Value::Text("deployment".into())),
            ("operation_id", Value::Text(complete.operation_id.clone())),
            (
                "intent_digest",
                Value::Text(complete.fingerprint().unwrap()),
            ),
            (
                "intent_json",
                Value::Text(String::from_utf8(encode_direct_control(&complete).unwrap()).unwrap()),
            ),
        ],
    );
    assert!(classifier()
        .classify("direct_upload_completion_intents", &input)
        .is_ok());
    let mut changed = complete;
    changed.expected_resource_version = WireInteger::new(2);
    let input = row(
        "direct_upload_completion_intents",
        &[
            (
                "session_id",
                Value::Text(changed.session.session_id.clone()),
            ),
            ("operation_id", Value::Text(changed.operation_id.clone())),
            ("intent_digest", Value::Text(changed.fingerprint().unwrap())),
            (
                "intent_json",
                Value::Text(String::from_utf8(encode_direct_control(&changed).unwrap()).unwrap()),
            ),
        ],
    );
    assert!(classifier()
        .classify("direct_upload_completion_intents", &input)
        .is_err());
}

#[test]
fn new_principal_columns_validate_canonical_uuid_without_backfilling_legacy_cells() {
    let valid = "01234567-89ab-4def-8123-456789abcdef";
    for (table_name, column) in [
        ("users", "principal_incarnation"),
        ("service_accounts", "principal_incarnation"),
        ("tokens", "owner_incarnation"),
        ("topology_plans", "actor_incarnation"),
    ] {
        let tables = contract().unwrap();
        let table = &tables[table_name];
        for value in [Value::Null, Value::Text(valid.into())] {
            let input = row(table_name, &[(column, value)]);
            super::super::direct::validate_row(table_name, table, &input).unwrap();
        }
        for invalid in [
            "01234567-89AB-4def-8123-456789abcdef",
            "01234567-89ab-1def-8123-456789abcdef",
            "not-a-uuid",
            "01234567-89ab-4def-0123-456789abcdef",
            "01234567-89ab-4def-c123-456789abcdef",
            "01234567-89ab-4def-e123-456789abcdef",
        ] {
            let input = row(table_name, &[(column, Value::Text(invalid.into()))]);
            assert!(super::super::direct::validate_row(table_name, table, &input).is_err());
        }
    }
}
