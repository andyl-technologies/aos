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
    assert_eq!(result.checked_tables(), 263);
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
