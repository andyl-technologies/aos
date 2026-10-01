//! Real source captures and correctly signed violations of global SQL constraints.

use std::io::{self, Cursor, Read};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_hub_core::snapshot::archive::root::{
    ArchiveSignerTrust, ArchiveSigningKey, ArchiveWrappingKey, ArchiveWrappingKeys,
};
use serde_json::{Value as Json, json};

use super::budget::TestControls;
use super::fixture::*;
use super::*;

mod mirror;

fn inputs(fixture: &Fixture) -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    ScratchVerificationInputs {
        root: fixture.output.root.as_bytes().to_vec(),
        trust: trust(fixture),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(fixture.output.metadata.clone()),
        private: Cursor::new(fixture.output.private.clone()),
    }
}

async fn scratch(fixture: &Fixture) -> ScratchResult<VerifiedRetainedSqliteCapture> {
    verify_capture_in_scratch(inputs(fixture), Default::default(), Default::default()).await
}

fn mutate(fixture: &mut Fixture, change: impl FnOnce(&mut Vec<Json>, &mut Vec<Json>)) {
    let (metadata, private) = plaintext(fixture);
    let mut metadata = lines(&metadata);
    let mut private = lines(&private);
    change(&mut metadata, &mut private);
    reseal(fixture, metadata, private);

    // Each hostile archive has real valid framing, signatures, row reconstruction
    // and counts. SQL rejection must therefore come from the new verifier.
    assert_eq!(verify(fixture).unwrap().counts(), &fixture.output.counts);
}

fn change_cell(metadata: &mut [Json], table: &str, row_index: usize, column: &str, scalar: Json) {
    let start = metadata
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == table)
        .unwrap();
    let mut row = 0;
    for line in &mut metadata[start + 1..] {
        if line["kind"] == "table_end" {
            break;
        }
        if line["kind"] == "cell" && line["column"] == column && row == row_index {
            assert!(!line["scalar"].is_null());
            line["scalar"] = scalar;
            return;
        }
        if line["kind"] == "row_end" {
            row += 1;
        }
    }
    panic!("test fixture cell absent");
}

#[tokio::test]
async fn valid_capture_enforces_child_before_parent_and_preserves_private_originals() {
    let fixture = fixture().await;
    let result = scratch(&fixture).await.unwrap();
    assert_eq!(result.records().counts(), &fixture.output.counts);
    assert_eq!(result.checked_tables(), 269);
    assert_eq!(result.synthetic_lineage_rows(), 2);
    assert!(result.records().counts().private_cells >= 2);
    assert!(!format!("{result:?}").contains("private-credential"));

    let (metadata, _) = plaintext(&fixture);
    let names: Vec<_> = lines(&metadata)
        .into_iter()
        .filter(|line| line["kind"] == "table_start")
        .map(|line| line["table"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        names.iter().position(|name| name == "user_identities")
            < names.iter().position(|name| name == "users")
    );
}

#[tokio::test]
async fn valid_extreme_integers_utf8_embedded_nul_blob_and_sql_null_survive_replay() {
    let (_directory, path, pool) = source().await;
    sqlx::query("UPDATE users SET display_name=?1,created_at=?2,deleted_at=?3 WHERE id=17")
        .bind("UTF8 snowman ☃\0private tail")
        .bind(i64::MIN)
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();
    let fixture = capture_path(&path, options()).await;
    pool.close().await;
    let report = scratch(&fixture).await.unwrap();
    assert_eq!(report.records().counts(), &fixture.output.counts);
    // The fixture includes a 32-byte compiled BLOB constraint and nullable
    // identity fields, all checked by the production typed readback path.
}

#[tokio::test]
async fn actual_compiled_check_keeps_sql_null_pass_semantics() {
    let (_directory, path, pool) = source().await;
    sqlx::raw_sql("INSERT INTO signing_keys(stable_id,scope_key,name,created_at,updated_at) VALUES ('key-one','instance','key-one',1,1); INSERT INTO signing_key_generations(signing_key_id,generation,algorithm,public_key,public_key_fingerprint,custody,state,active_slot,created_at,retired_at) VALUES ('key-one',1,'ed25519','private-public-key-original','fingerprint','external','active',NULL,1,NULL)")
        .execute(&pool).await.unwrap();
    // The first slot CHECK evaluates to NULL, which SQLite permits. This
    // verifies actual SQL constraints without inventing application validation.
    let null_result: Option<i64> = sqlx::query_scalar(
        "SELECT (state='active' AND active_slot=1) OR (state='retired' AND active_slot IS NULL) FROM signing_key_generations",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(null_result, None);
    let fixture = capture_path(&path, options()).await;
    pool.close().await;
    assert_eq!(
        scratch(&fixture).await.unwrap().records().counts(),
        &fixture.output.counts
    );
}

#[tokio::test]
async fn resigned_duplicate_integer_primary_key_is_rejected() {
    let mut fixture = fixture().await;
    mutate(&mut fixture, |metadata, private| {
        let table = metadata
            .iter()
            .position(|line| line["kind"] == "table_start" && line["table"] == "users")
            .unwrap();
        let first_start = table + 1;
        let first_end = first_start
            + metadata[first_start..]
                .iter()
                .position(|line| line["kind"] == "row_end")
                .unwrap();
        let second_start = first_end + 1;
        let second_end = second_start
            + metadata[second_start..]
                .iter()
                .position(|line| line["kind"] == "row_end")
                .unwrap();
        let sequence = metadata[second_start]["row"].clone();
        let mut replacement = metadata[first_start..=first_end].to_vec();
        for line in &mut replacement {
            if line.get("row").is_some() {
                line["row"] = sequence.clone();
            }
        }
        metadata.splice(second_start..=second_end, replacement);
        let originals: Vec<_> = private
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line["kind"] == "private_cell" && line["dependency"]["table"] == "users"
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(originals.len(), 2);
        let mut repeated = private[originals[0]].clone();
        repeated["row"] = sequence;
        private[originals[1]] = repeated;
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::RetainedRow
    );
}

#[tokio::test]
async fn resigned_duplicate_composite_primary_key_is_rejected() {
    let mut fixture = fixture().await;
    mutate(&mut fixture, |metadata, _| {
        change_cell(
            metadata,
            "user_identities",
            1,
            "subject",
            json!({"kind":"text","value":"subject-a"}),
        );
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::RetainedRow
    );
}

#[tokio::test]
async fn resigned_unique_email_collision_is_rejected() {
    let mut fixture = fixture().await;
    mutate(&mut fixture, |metadata, _| {
        change_cell(
            metadata,
            "users",
            1,
            "email",
            json!({"kind":"text","value":"a@example.invalid"}),
        );
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::RetainedRow
    );
}

#[tokio::test]
async fn resigned_false_compiled_check_is_rejected() {
    let mut fixture = fixture().await;
    mutate(&mut fixture, |metadata, _| {
        change_cell(
            metadata,
            "egress_request_nonces",
            0,
            "expires_at",
            json!({"kind":"integer","value":"1"}),
        );
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::RetainedRow
    );
}

#[tokio::test]
async fn resigned_missing_retained_parent_fails_after_paired_completion() {
    let mut fixture = fixture().await;
    mutate(&mut fixture, |metadata, _| {
        change_cell(
            metadata,
            "user_identities",
            0,
            "user_id",
            json!({"kind":"integer","value":"9999"}),
        );
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::Constraints
    );
}

#[tokio::test]
async fn truncated_private_end_cannot_return_a_constraint_report() {
    let mut fixture = fixture().await;
    fixture.output.private.pop();
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::Records
    );
}

#[tokio::test]
async fn trailing_metadata_after_provisional_rows_cannot_return_a_report() {
    let mut fixture = fixture().await;
    fixture.output.metadata.push(0);
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::Records
    );
}

#[tokio::test]
async fn paired_eof_failure_still_closes_provisional_database() {
    let mut fixture = fixture().await;
    fixture.output.private.pop();
    let (cleaned, closed) = tokio::sync::oneshot::channel();
    let controls = TestControls {
        cleaned: Some(Arc::new(Mutex::new(Some(cleaned)))),
        ..Default::default()
    };
    assert_eq!(
        verify_inner(
            inputs(&fixture),
            Default::default(),
            Default::default(),
            controls
        )
        .await
        .unwrap_err(),
        ScratchVerificationError::Records
    );
    closed.await.unwrap();
}

#[tokio::test]
async fn row_and_payload_caps_fail_closed() {
    let fixture = fixture().await;
    for limits in [
        ScratchVerificationLimits {
            max_retained_rows: 1,
            ..Default::default()
        },
        ScratchVerificationLimits {
            max_value_bytes: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            verify_capture_in_scratch(inputs(&fixture), limits, Default::default())
                .await
                .unwrap_err(),
            ScratchVerificationError::Limits
        );
    }
}

#[tokio::test]
async fn database_page_cap_is_applied_before_schema_allocation() {
    let fixture = fixture().await;
    let limits = ScratchVerificationLimits {
        max_database_bytes: 4096,
        ..Default::default()
    };
    assert_eq!(
        verify_capture_in_scratch(inputs(&fixture), limits, Default::default())
            .await
            .unwrap_err(),
        ScratchVerificationError::Limits
    );
}

#[tokio::test]
async fn progress_and_deadline_caps_stop_work_without_reports() {
    let fixture = fixture().await;
    for limits in [
        ScratchVerificationLimits {
            max_progress_callbacks: 1,
            ..Default::default()
        },
        ScratchVerificationLimits {
            max_duration: Duration::from_nanos(1),
            ..Default::default()
        },
    ] {
        assert_eq!(
            verify_capture_in_scratch(inputs(&fixture), limits, Default::default())
                .await
                .unwrap_err(),
            ScratchVerificationError::Limits
        );
    }
}

#[tokio::test]
async fn invalid_limits_and_preexisting_cancellation_are_checked_first() {
    let fixture = fixture().await;
    let limits = ScratchVerificationLimits {
        max_duration: Duration::ZERO,
        ..Default::default()
    };
    assert_eq!(
        verify_capture_in_scratch(inputs(&fixture), limits, Default::default())
            .await
            .unwrap_err(),
        ScratchVerificationError::InvalidLimits
    );
    let cancelled = ScratchCancellation::default();
    cancelled.cancel();
    assert_eq!(
        verify_capture_in_scratch(inputs(&fixture), Default::default(), cancelled)
            .await
            .unwrap_err(),
        ScratchVerificationError::Cancelled
    );
}

#[tokio::test]
async fn future_drop_and_cancellation_interrupt_active_vm_and_close_private_connection() {
    let (_directory, path, pool) = source().await;
    sqlx::raw_sql("WITH RECURSIVE n(x) AS (VALUES(100) UNION ALL SELECT x+1 FROM n WHERE x<2100) INSERT INTO users(id,email,created_at) SELECT x,'user-'||x||'@example.invalid',1 FROM n")
        .execute(&pool).await.unwrap();
    let fixture = capture_path(&path, options()).await;
    pool.close().await;
    for drop_future in [true, false] {
        let (started, observed) = tokio::sync::oneshot::channel();
        let (cleaned, closed) = tokio::sync::oneshot::channel();
        let controls = TestControls {
            started: Some(Arc::new(Mutex::new(Some(started)))),
            cleaned: Some(Arc::new(Mutex::new(Some(cleaned)))),
            pause_final_progress: true,
        };
        let cancellation = ScratchCancellation::default();
        let task = tokio::spawn(verify_inner(
            inputs(&fixture),
            Default::default(),
            cancellation.clone(),
            controls,
        ));
        tokio::time::timeout(Duration::from_secs(30), observed)
            .await
            .unwrap()
            .unwrap();

        if drop_future {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            cancellation.cancel();
            assert_eq!(
                task.await.unwrap().unwrap_err(),
                ScratchVerificationError::Cancelled
            );
        }
        tokio::time::timeout(Duration::from_secs(5), closed)
            .await
            .unwrap()
            .unwrap();
    }
}

struct ConfidentialReader;

impl Read for ConfidentialReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("private-reader-SECRET"))
    }
}

#[tokio::test]
async fn public_inputs_reports_and_errors_hide_private_diagnostics() {
    let fixture = fixture().await;
    let original = inputs(&fixture);
    assert!(!format!("{original:?}").contains("private-credential"));
    let failed = ScratchVerificationInputs {
        root: original.root,
        trust: original.trust,
        wrapping: original.wrapping,
        exclusions: original.exclusions,
        metadata: ConfidentialReader,
        private: original.private,
    };
    let error = verify_capture_in_scratch(failed, Default::default(), Default::default())
        .await
        .unwrap_err();
    assert_eq!(error, ScratchVerificationError::Records);
    assert!(!format!("{error:?}: {error}").contains("SECRET"));
}

// These encrypted bytes were produced by the actual generation-3 initializer
// and capture implementation; neither schema headers nor migration digests
// were rewritten to construct backward-compatibility evidence.
fn historical_generation3_inputs() -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();

    ScratchVerificationInputs {
        root: include_bytes!("fixtures/generation3-root.json").to_vec(),
        trust: ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap(),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(include_bytes!("fixtures/generation3-metadata.enc").to_vec()),
        private: Cursor::new(include_bytes!("fixtures/generation3-private.enc").to_vec()),
    }
}

#[tokio::test]
async fn genuine_generation3_capture_replays_with_matching_historical_ddl() {
    let report = verify_capture_in_scratch(
        historical_generation3_inputs(),
        Default::default(),
        Default::default(),
    )
    .await
    .unwrap();

    assert_eq!(report.records().counts().tables, 267);
    assert_eq!(report.checked_tables(), 257);
    assert_eq!(report.synthetic_lineage_rows(), 2);
}

#[tokio::test]
async fn truncated_generation3_capture_cannot_return_a_constraint_report() {
    let mut inputs = historical_generation3_inputs();
    inputs.private.get_mut().pop();

    let result = verify_capture_in_scratch(inputs, Default::default(), Default::default()).await;

    assert!(result.is_err());
}

// This archive was captured by the generation-4 production implementation,
// before migration 005 existed. Its schema commitments are never rewritten.
fn historical_generation4_inputs() -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();

    ScratchVerificationInputs {
        root: include_bytes!("fixtures/generation4-root.json").to_vec(),
        trust: ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap(),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(include_bytes!("fixtures/generation4-metadata.enc").to_vec()),
        private: Cursor::new(include_bytes!("fixtures/generation4-private.enc").to_vec()),
    }
}

#[tokio::test]
async fn genuine_generation4_capture_replays_with_matching_historical_ddl() {
    let report = verify_capture_in_scratch(
        historical_generation4_inputs(),
        Default::default(),
        Default::default(),
    )
    .await
    .unwrap();

    assert_eq!(report.records().counts().tables, 275);
    assert_eq!(report.checked_tables(), 265);
    assert_eq!(report.synthetic_lineage_rows(), 2);
    assert!(report.records().counts().private_cells >= 2);
}

#[tokio::test]
async fn truncated_generation4_capture_cannot_return_a_constraint_report() {
    let mut inputs = historical_generation4_inputs();
    inputs.private.get_mut().pop();

    let result = verify_capture_in_scratch(inputs, Default::default(), Default::default()).await;

    assert!(result.is_err());
}

// Captured by the committed generation-5 production implementation before
// migration 006. Its committed mirror row has no copy operation or index cells.
fn historical_generation5_inputs() -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();

    ScratchVerificationInputs {
        root: include_bytes!("fixtures/generation5-root.json").to_vec(),
        trust: ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap(),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(include_bytes!("fixtures/generation5-metadata.enc").to_vec()),
        private: Cursor::new(include_bytes!("fixtures/generation5-private.enc").to_vec()),
    }
}

#[tokio::test]
async fn genuine_generation5_capture_replays_original_without_future_index_or_operation() {
    let inputs = historical_generation5_inputs();
    let mut originals = Vec::new();
    aos_hub_core::snapshot::archive::records::verify_database_capture(
        &inputs.root,
        &inputs.trust,
        &inputs.wrapping,
        &inputs.exclusions,
        inputs.metadata,
        inputs.private,
        Default::default(),
        |table, _, row| {
            if table == "mirror_import_objects" {
                row.with_private_row(|row| originals.push(row.clone()));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].len(), 9);
    let original_json: String = originals[0].get(3).unwrap();
    let original: aos_hub_core::mirror_work::MirrorOriginal =
        serde_json::from_str(&original_json).unwrap();
    assert!(original.copy_operation_id.is_none());
    assert_eq!(serde_json::to_string(&original).unwrap(), original_json);
    let report = verify_capture_in_scratch(
        historical_generation5_inputs(),
        Default::default(),
        Default::default(),
    )
    .await
    .unwrap();

    assert_eq!(report.records().counts().tables, 276);
    assert_eq!(report.checked_tables(), 266);
    assert_eq!(report.synthetic_lineage_rows(), 2);
}

#[tokio::test]
async fn truncated_generation5_capture_cannot_return_a_constraint_report() {
    let mut inputs = historical_generation5_inputs();
    inputs.private.get_mut().pop();

    let result = verify_capture_in_scratch(inputs, Default::default(), Default::default()).await;

    assert!(result.is_err());
}

fn historical_generation6_inputs() -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    ScratchVerificationInputs {
        root: include_bytes!("fixtures/generation6-root.json").to_vec(),
        trust: ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap(),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(include_bytes!("fixtures/generation6-metadata.enc").to_vec()),
        private: Cursor::new(include_bytes!("fixtures/generation6-private.enc").to_vec()),
    }
}

#[tokio::test]
async fn genuine_generation6_preserves_indexed_original_without_future_accounting() {
    let inputs = historical_generation6_inputs();
    let mut originals = Vec::new();
    aos_hub_core::snapshot::archive::records::verify_database_capture(
        &inputs.root,
        &inputs.trust,
        &inputs.wrapping,
        &inputs.exclusions,
        inputs.metadata,
        inputs.private,
        Default::default(),
        |table, _, row| {
            if table == "mirror_import_objects" {
                row.with_private_row(|row| originals.push(row.clone()));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].len(), 12);
    let raw: String = originals[0].get(3).unwrap();
    let original: aos_hub_core::mirror_work::MirrorOriginal = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        original.copy_operation_id.as_deref(),
        Some("44444444444444444444444444444444")
    );
    assert_eq!(serde_json::to_string(&original).unwrap(), raw);
    assert_eq!(originals[0].get::<String>(9).unwrap(), original.path);
    assert_eq!(
        originals[0].get::<String>(10).unwrap(),
        original.source_path_digest()
    );

    let report = verify_capture_in_scratch(
        historical_generation6_inputs(),
        Default::default(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.records().counts().tables, 276);
    assert_eq!(report.checked_tables(), 266);
}

#[tokio::test]
async fn truncated_generation6_capture_cannot_return_a_constraint_report() {
    let mut inputs = historical_generation6_inputs();
    inputs.private.get_mut().pop();
    assert!(
        verify_capture_in_scratch(inputs, Default::default(), Default::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn generation7_nonempty_charge_totals_are_checked_without_aggregate_aliasing() {
    let (_directory, path, pool) = source().await;
    let db = aos_hub_core::db::Database::with_backend(Box::new(
        aos_hub_core::backend::SqlxBackend::Sqlite(pool.clone()),
    ))
    .await
    .unwrap();
    let org = db
        .create_org("snapshot-charge", "Snapshot charge")
        .await
        .unwrap();
    let registry = db
        .create_managed_registry(org, "", "snapshot-charge", "public", &[], false)
        .await
        .unwrap();
    for (id, bytes) in [(801_i64, 7_i64), (802, 11)] {
        sqlx::query("INSERT INTO surface_objects(id,registry_id,object_key,object_kind,partition_key,content_hash,size,created_at,updated_at) VALUES (?1,?2,?3,'immutable',?4,?5,?6,1,1)")
            .bind(id).bind(registry).bind(format!("nar/{id}.nar")).bind(vec![0_u8; 32]).bind("a".repeat(64)).bind(bytes).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO surface_object_usage(surface_object_id,org_id,accounted_bytes,updated_at) VALUES (?1,?2,?3,1)")
            .bind(id).bind(org).bind(bytes).execute(&pool).await.unwrap();
    }
    sqlx::query("UPDATE org_usage SET used_bytes=18,object_count=2 WHERE org_id=?1")
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();
    let valid = capture_path(&path, options()).await;
    assert!(scratch(&valid).await.is_ok());

    sqlx::query("UPDATE org_usage SET used_bytes=17 WHERE org_id=?1")
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();
    let deficit = capture_path(&path, options()).await;
    assert!(verify(&deficit).is_ok());
    assert!(scratch(&deficit).await.is_err());
    pool.close().await;
}

#[tokio::test]
async fn generation7_private_delete_history_requires_exact_confirmation_and_permanent_identity() {
    use sha2::{Digest as _, Sha256};

    let (_directory, path, pool) = source().await;
    let db = aos_hub_core::db::Database::with_backend(Box::new(
        aos_hub_core::backend::SqlxBackend::Sqlite(pool.clone()),
    ))
    .await
    .unwrap();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let identity = db
        .binding_identity_reservation(&binding.stable_id)
        .await
        .unwrap()
        .unwrap();
    let document = json!({ "stable_id": binding.stable_id, "owner_scope_key": binding.owner_scope_key,
        "org_id": binding.org_id, "binding_db_id": binding.id, "baseline_resource_version": binding.resource_version,
        "reservation_id": identity.reservation_id });
    let original = serde_json::to_string(&document).unwrap();
    let confirmation = hex::encode(Sha256::digest(original.as_bytes()));
    sqlx::query("INSERT INTO topology_plans(plan_id,plan_kind,actor_kind,actor_label,scope,input_versions_json,effects_json,warnings_json,confirmation_hash,created_at,expires_at,apply_idempotency_key) VALUES ('binding-history','delete_binding','system','fixture','instance',?1,'[]','[]',?2,1,100,'claimed-original')")
        .bind(&original).bind(&confirmation).execute(&pool).await.unwrap();
    let valid = capture_path(&path, options()).await;
    assert!(scratch(&valid).await.is_ok());

    let mut forged = document.clone();
    forged["reservation_id"] = json!("01234567-89ab-4def-8123-456789abcdef");
    let forged_raw = serde_json::to_string(&forged).unwrap();
    sqlx::query("UPDATE topology_plans SET input_versions_json=?1 WHERE plan_id='binding-history'")
        .bind(&forged_raw)
        .execute(&pool)
        .await
        .unwrap();
    let altered_original = capture_path(&path, options()).await;
    assert!(verify(&altered_original).is_ok());
    assert!(scratch(&altered_original).await.is_err());

    sqlx::query("UPDATE topology_plans SET confirmation_hash=?1 WHERE plan_id='binding-history'")
        .bind(hex::encode(Sha256::digest(forged_raw.as_bytes())))
        .execute(&pool)
        .await
        .unwrap();
    let changed_lifetime = capture_path(&path, options()).await;
    assert!(scratch(&changed_lifetime).await.is_err());

    let mut legacy = document.clone();
    legacy.as_object_mut().unwrap().remove("reservation_id");
    let legacy_raw = serde_json::to_string(&legacy).unwrap();
    sqlx::query("UPDATE topology_plans SET input_versions_json=?1,confirmation_hash=?2 WHERE plan_id='binding-history'")
        .bind(&legacy_raw).bind(hex::encode(Sha256::digest(legacy_raw.as_bytes()))).execute(&pool).await.unwrap();
    assert!(
        scratch(&capture_path(&path, options()).await)
            .await
            .is_err()
    );

    sqlx::query("UPDATE topology_plans SET input_versions_json=?1,confirmation_hash=?2 WHERE plan_id='binding-history'")
        .bind(&original).bind(&confirmation).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM binding_identity_reservations WHERE stable_id=?1")
        .bind(&binding.stable_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        scratch(&capture_path(&path, options()).await)
            .await
            .is_err()
    );
    pool.close().await;
}

// Captured and privately replayed by genuine generation-seven code before append008.
fn historical_generation7_inputs() -> ScratchVerificationInputs<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    ScratchVerificationInputs {
        root: include_bytes!("fixtures/generation7-root.json").to_vec(),
        trust: ArchiveSignerTrust::new([(signer.id().to_owned(), signer.public_key())]).unwrap(),
        wrapping: ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap(),
        exclusions: Vec::new(),
        metadata: Cursor::new(include_bytes!("fixtures/generation7-metadata.enc").to_vec()),
        private: Cursor::new(include_bytes!("fixtures/generation7-private.enc").to_vec()),
    }
}

#[tokio::test]
async fn genuine_generation7_uses_original_catalogue_without_channel_backfill() {
    let inputs = historical_generation7_inputs();
    let retained = verify_capture_in_scratch(inputs, Default::default(), Default::default())
        .await
        .unwrap();
    assert_eq!(retained.checked_tables(), 268);
    assert_eq!(retained.synthetic_lineage_rows(), 2);
}
