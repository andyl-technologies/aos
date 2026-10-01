//! Exact private baseline and final-guard snapshot contracts.

use super::*;
use crate::direct_upload::*;

fn originals() -> (
    DirectUploadAdmission,
    DirectCompleteRequest,
    DirectFinalGuardRecord,
) {
    let admission = direct::admission();
    let placement = &admission.placements[0];
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "6".repeat(64),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![DirectManifestCommitment {
            placement: placement.public_ref("deployment").unwrap(),
            manifest_digest: "7".repeat(64),
            part_count: 1,
        }],
    };
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: DirectDestinationBaselineBinding {
            deployment_id: "deployment".into(),
            session: complete.session.clone(),
            admission_expires_at: admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: placement.public_ref("deployment").unwrap(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
            final_key_digest: direct_destination_key_digest(&placement.final_key).unwrap(),
            scope: DirectDestinationReservationScope::Managed {
                bucket_namespace: "permanent-bucket".into(),
            },
            reservation_operation_id: direct_destination_promotion_operation_id(
                &complete.session,
                placement.placement_id,
                &complete.operation_id,
            )
            .unwrap(),
            reservation_nonce: "8".repeat(64),
            reservation_revision: WireInteger::new(1),
        },
        selected: DirectSelectedCompleteCommitment {
            version: 1,
            session: complete.session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: complete.expected_resource_version,
            complete_intent_digest: complete.fingerprint().unwrap(),
            manifest: complete.manifests[0].clone(),
            protected_profile_digest: placement.protected_profile_digest.clone(),
        },
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        source_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "stage-original".into(),
        },
        final_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "final-original".into(),
        },
        final_etag: "\"etag-original\"".into(),
    };
    (admission, complete, guard)
}

fn text<T: serde::Serialize>(value: &T) -> Value {
    Value::Text(String::from_utf8(encode_direct_control(value).unwrap()).unwrap())
}

#[test]
fn baseline_keeps_private_original_reservation_and_refuses_scalar_substitution() {
    let (_, _, guard) = originals();
    let baseline = DirectDestinationBaselineEvidence {
        binding: guard.reservation,
        observation_operation_id: "9".repeat(64),
        issued_at: WireInteger::new(10),
        expires_at: WireInteger::new(100),
        state: DirectDestinationBaselineState::Missing {},
    };
    let make_row = |digest: String| {
        row(
            "direct_upload_baselines",
            &[
                ("deployment_id", Value::Text("deployment".into())),
                (
                    "session_id",
                    Value::Text(baseline.binding.session.session_id.clone()),
                ),
                ("placement_id", Value::Int(1)),
                (
                    "complete_operation_id",
                    Value::Text(baseline.binding.complete_operation_id.clone()),
                ),
                ("baseline_digest", Value::Text(digest)),
                ("evidence_json", text(&baseline)),
                ("activated_at", Value::Int(10)),
            ],
        )
    };
    let source = make_row(baseline.fingerprint().unwrap());
    let captured = classifier()
        .capture_private_row("direct_upload_baselines", &source)
        .unwrap();
    let SnapshotRowDisposition::Retained(classified) = captured.classified() else {
        panic!("baseline omitted")
    };
    assert_eq!(captured.private_cells().len(), 1);
    let restored = classifier()
        .reconstruct_private_row(classified, captured.private_cells())
        .unwrap();
    restored.with_private_row(|row| assert_eq!(row, &source));
    assert!(classifier()
        .classify("direct_upload_baselines", &make_row("0".repeat(64)))
        .is_err());
}

#[test]
fn final_guard_requires_exact_source_and_destination_incarnations() {
    let (admission, complete, guard) = originals();
    let placement = &admission.placements[0];
    let evidence = DirectCompletionEvidence {
        session_id: admission.session_id,
        logical_fingerprint: admission.logical_fingerprint,
        operation_id: complete.operation_id,
        part_count: 1,
        sha256: guard.sha256.clone(),
        byte_size: guard.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: placement.placement_id,
            placement_resource_version: placement.placement_resource_version,
            write_spec_version: placement.write_spec_version,
            binding_id: placement.binding_id,
            binding_resource_version: placement.binding_resource_version,
            binding_write_revision: placement.binding_write_revision,
            manifest: guard.selected.manifest.clone(),
            promotion_operation_id: guard.reservation.reservation_operation_id.clone(),
            staging_incarnation: guard.source_incarnation.clone(),
            final_incarnation: guard.final_incarnation.clone(),
            final_etag: guard.final_etag.clone(),
        }],
    };
    let make_row = |guards: Vec<DirectFinalGuardRecord>| {
        row(
            "direct_upload_completion_receipts",
            &[
                ("deployment_id", Value::Text("deployment".into())),
                ("session_id", Value::Text(evidence.session_id.clone())),
                ("operation_id", Value::Text(evidence.operation_id.clone())),
                (
                    "logical_fingerprint",
                    Value::Text(evidence.logical_fingerprint.clone()),
                ),
                (
                    "evidence_digest",
                    Value::Text(hex::encode(Sha256::digest(
                        encode_direct_control(&evidence).unwrap(),
                    ))),
                ),
                ("evidence_json", text(&evidence)),
                ("final_guards_json", text(&guards)),
                ("committed_at", Value::Int(20)),
                ("resulting_resource_version", Value::Int(3)),
            ],
        )
    };
    let source = make_row(vec![guard.clone()]);
    let captured = classifier()
        .capture_private_row("direct_upload_completion_receipts", &source)
        .unwrap();
    assert_eq!(captured.private_cells().len(), 2);
    let SnapshotRowDisposition::Retained(classified) = captured.classified() else {
        panic!("receipt omitted")
    };
    let restored = classifier()
        .reconstruct_private_row(classified, captured.private_cells())
        .unwrap();
    restored.with_private_row(|row| assert_eq!(row, &source));
    let mut changed = guard;
    changed.final_incarnation = DirectObjectIncarnation::ProviderVersion {
        version: "substituted".into(),
    };
    assert!(classifier()
        .classify(
            "direct_upload_completion_receipts",
            &make_row(vec![changed])
        )
        .is_err());
    assert!(classifier()
        .classify("direct_upload_completion_receipts", &make_row(vec![]))
        .is_err());
}

#[test]
fn abort_terminal_receipt_and_settlement_time_remain_a_pair() {
    let (_, complete, _) = originals();
    let intent = DirectAbortRequest {
        session: complete.session,
        operation_id: "a".repeat(64),
        expected_resource_version: WireInteger::new(2),
    };
    let make_row = |digest: Value, settled: Value| {
        row(
            "direct_upload_abort_intents",
            &[
                ("deployment_id", Value::Text("deployment".into())),
                ("session_id", Value::Text(intent.session.session_id.clone())),
                ("operation_id", Value::Text(intent.operation_id.clone())),
                ("expected_resource_version", Value::Int(2)),
                (
                    "intent_digest",
                    Value::Text(hex::encode(Sha256::digest(
                        encode_direct_control(&intent).unwrap(),
                    ))),
                ),
                ("intent_json", text(&intent)),
                ("admitted_at", Value::Int(10)),
                ("terminal_receipt_digest", digest),
                ("settled_at", settled),
            ],
        )
    };
    for input in [
        make_row(Value::Null, Value::Null),
        make_row(Value::Text("b".repeat(64)), Value::Int(11)),
    ] {
        assert!(classifier()
            .classify("direct_upload_abort_intents", &input)
            .is_ok());
    }
    for input in [
        make_row(Value::Null, Value::Int(11)),
        make_row(Value::Text("b".repeat(64)), Value::Null),
        make_row(Value::Text("b".repeat(64)), Value::Int(9)),
    ] {
        assert!(classifier()
            .classify("direct_upload_abort_intents", &input)
            .is_err());
    }
}

#[test]
fn authenticated_oci_source_is_complete_and_keeps_native_stream_progress_true() {
    let sha = "c".repeat(64);
    let make_row = |source_bytes: Value, streamed: i64| {
        row(
            "oci_upload_sessions",
            &[
                ("state", Value::Text("complete".into())),
                ("authenticated_source_sha256", Value::Text(sha.clone())),
                ("authenticated_source_bytes", source_bytes),
                ("uploaded_size", Value::Int(streamed)),
                ("sha256_total_bytes", Value::Int(streamed)),
                ("expected_size", Value::Int(1)),
                ("expected_digest", Value::Text(format!("sha256:{sha}"))),
                ("final_digest", Value::Text(format!("sha256:{sha}"))),
            ],
        )
    };
    let tables = contract().unwrap();
    let table = &tables["oci_upload_sessions"];
    let validate =
        |input: &Row| super::super::direct::validate_row("oci_upload_sessions", table, input);
    assert!(validate(&make_row(Value::Int(1), 0)).is_ok());
    assert!(validate(&make_row(Value::Null, 0)).is_err());
    assert!(validate(&make_row(Value::Int(2), 0)).is_err());
    assert!(validate(&make_row(Value::Int(1), 1)).is_err());
}
