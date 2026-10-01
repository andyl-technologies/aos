//! Actual SQLite capture and correctly authenticated hostile record regressions.

use std::io::Cursor;
use std::time::Duration;

use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value as Json};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::TempDir;

use super::super::root::{ArchiveSigningKey, ArchiveWrappingKey};
use super::*;
use crate::backend::{sqlite_snapshot::*, SqlxBackend};
use crate::db::Database;

struct Fixture {
    output: DatabaseCaptureOutput<Vec<u8>, Vec<u8>>,
    signer: ArchiveSigningKey,
    wrapping: ArchiveWrappingKeys,
}

#[test]
fn historical_wire_arrays_round_trip_without_rewriting_and_unknown_lengths_fail() {
    for version in [3, 4, 5, 6, 7, 8] {
        let classifier = SnapshotClassifier::for_supported_generation(version).unwrap();
        let schema = schema(&classifier).unwrap();
        let original = serde_json::to_vec(&schema).unwrap();
        let decoded: Schema = serde_json::from_slice(&original).unwrap();
        assert_eq!(original, serde_json::to_vec(&decoded).unwrap());
        let value: Json = serde_json::from_slice(&original).unwrap();
        assert_eq!(
            value["migration_digests"].as_array().unwrap().len(),
            version
        );
    }

    let mut value = serde_json::to_value(schema(&current_classifier().unwrap()).unwrap()).unwrap();

    for count in [0, 1, 2, 9] {
        value["migration_digests"] = json!(vec!["1".repeat(64); count]);
        assert!(serde_json::from_value::<Schema>(value.clone()).is_err());
    }
}

#[tokio::test]
async fn schema_callback_runs_after_both_headers_and_before_any_row() {
    use std::cell::Cell;

    let f = fixture().await;
    let called = Cell::new(false);
    let report = verify_database_capture_with_schema(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |manifest| {
            assert_eq!(manifest.version, 8);
            assert!(!called.replace(true));
            Ok(())
        },
        |_, _, _| {
            assert!(called.get());
            Ok(())
        },
    )
    .unwrap();
    assert!(called.get());
    assert_eq!(report.counts().tables, 279);

    let mut bad = fixture().await;
    let (metadata, private) = plaintext(&bad);
    let mut private = lines(&private);
    private[0]["schema"]["classification_digest"] = json!("1".repeat(64));
    reseal(&mut bad, lines(&metadata), private);
    let called = Cell::new(false);
    assert!(verify_database_capture_with_schema(
        bad.output.root.as_bytes(),
        &trust(&bad),
        &bad.wrapping,
        &[],
        Cursor::new(&bad.output.metadata),
        Cursor::new(&bad.output.private),
        StreamLimits::default(),
        |_| {
            called.set(true);
            Ok(())
        },
        |_, _, _| panic!("row exposed after mismatched private header"),
    )
    .is_err());
    assert!(!called.get());
}

#[tokio::test]
async fn rejected_schema_callback_exposes_no_provisional_rows() {
    let f = fixture().await;
    let error = verify_database_capture_with_schema(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |_| anyhow::bail!("private original schema callback detail"),
        |_, _, _| panic!("row exposed after schema refusal"),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "snapshot schema callback failed");
}

fn options() -> SqliteCaptureOptions {
    SqliteCaptureOptions {
        audit: SqliteSnapshotAuditLimits {
            max_duration: Duration::from_secs(30),
            max_progress_callbacks: 100_000,
        },
        pages: SqliteSnapshotLimits {
            max_rows: 1,
            ..Default::default()
        },
        streams: StreamLimits::default(),
    }
}

async fn source() -> (TempDir, std::path::PathBuf, sqlx::SqlitePool) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hub.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    let database = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    drop(database);
    sqlx::raw_sql("INSERT INTO users(id,email,password_hash,created_at) VALUES (17,'a@example.invalid','private-credential-RAW',1),(18,'b@example.invalid','private-credential-TWO',2); INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,last_authenticated_at) VALUES ('transient-NOT-EXPORTED',17,1,1,2,1)")
        .execute(&pool).await.unwrap();
    (dir, path, pool)
}

async fn fixture() -> Fixture {
    let (_dir, path, pool) = source().await;
    let output = capture_path(&path, options()).await;
    pool.close().await;
    output
}

async fn capture_path(path: &std::path::Path, options: SqliteCaptureOptions) -> Fixture {
    capture_path_seed(path, options, 471).await
}

async fn capture_path_seed(
    path: &std::path::Path,
    options: SqliteCaptureOptions,
    seed: u64,
) -> Fixture {
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    let wrapping = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
    )
    .unwrap();
    let output = capture_sqlite(
        SqliteSnapshotReader::open(&path).await.unwrap(),
        Vec::new(),
        Vec::new(),
        CaptureKeyCustody {
            signer: &signer,
            wrapping: &wrapping,
            exclusions: &[],
        },
        &mut StdRng::seed_from_u64(seed),
        options,
    )
    .await
    .unwrap();
    Fixture {
        output,
        signer,
        wrapping,
    }
}

fn trust(f: &Fixture) -> ArchiveSignerTrust {
    ArchiveSignerTrust::new([(f.signer.id().to_owned(), f.signer.public_key())]).unwrap()
}

fn verify(f: &Fixture) -> Result<VerifiedDatabaseCaptureRecords> {
    verify_database_capture(
        f.output.root.as_bytes(),
        &trust(f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |_, _, _| Ok(()),
    )
}

#[tokio::test]
async fn actual_sqlite_capture_reconstructs_every_retained_row_and_omits_sessions() {
    let f = fixture().await;
    let mut users = Vec::new();
    let report = verify_database_capture(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |table, _, row| {
            if table == "users" {
                row.with_private_row(|row| users.push(row.clone()));
            }
            assert_ne!(table, "sessions");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.counts(), &f.output.counts);
    assert_eq!(report.counts().tables, 279);
    assert_eq!(users.len(), 2);
    assert!(report.counts().private_cells >= 2);
    assert!(report.counts().omitted_rows >= 3);
    let columns = &current_classifier().unwrap().tables["users"].columns;
    let password = columns
        .iter()
        .position(|column| column.name == "password_hash")
        .unwrap();
    assert_eq!(
        users[0].get::<String>(password).unwrap(),
        "private-credential-RAW"
    );
    assert!(report.declared_source_audit().checked_expressions() > 0);
    assert!(!format!("{:?}", f.output).contains("private-credential"));
}

fn plaintext(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
    let root = verify_declared_root(f.output.root.as_bytes(), &trust(f)).unwrap();
    let (meta_key, private_key) = root
        .unwrap_reader_keys(&f.wrapping, &[])
        .unwrap()
        .into_role_keys();
    fn decode(
        bytes: &[u8],
        key: super::super::StreamDecryptionKey,
        context: super::super::StreamContext,
    ) -> Vec<u8> {
        let mut decoder =
            StreamDecoder::new(Cursor::new(bytes), key, context, StreamLimits::default()).unwrap();
        let mut plain = Vec::new();
        while let Some(chunk) = decoder.next_chunk().unwrap() {
            chunk.with_private_bytes(|bytes| plain.extend_from_slice(bytes));
        }
        plain
    }
    (
        decode(
            &f.output.metadata,
            meta_key,
            root.stream_context(StreamRole::Metadata),
        ),
        decode(
            &f.output.private,
            private_key,
            root.stream_context(StreamRole::Private),
        ),
    )
}

fn lines(bytes: &[u8]) -> Vec<Json> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn bytes(lines: &[Json]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for line in lines {
        serde_json::to_writer(&mut bytes, line).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

// Malformed logical streams get fresh keys/identity and a correct signature.
// Rejecting them must come from records/reconstruction, not a stale byte hash.
fn reseal(f: &mut Fixture, mut metadata: Vec<Json>, mut private: Vec<Json>) {
    use super::super::root::{prepare_archive_keys, sign_declared_root, FreshArchiveId};
    use super::super::{FreshStreamKey, StreamContext, StreamEncoder};
    let mut rng = StdRng::seed_from_u64(89789);
    let id = FreshArchiveId::generate(&mut rng).unwrap();
    for line in metadata.iter_mut().chain(private.iter_mut()) {
        if line.get("archive_id").is_some() {
            line["archive_id"] = json!(hex::encode(id.bytes()));
        }
    }
    let mk = FreshStreamKey::generate(&mut rng).unwrap();
    let pk = FreshStreamKey::generate(&mut rng).unwrap();
    let prepared = prepare_archive_keys(&id, &f.signer, &f.wrapping, &mk, &pk, &[]).unwrap();
    let mut meta = StreamEncoder::new(
        Vec::new(),
        mk,
        StreamContext::new(id.bytes(), StreamRole::Metadata),
        StreamLimits::default(),
    )
    .unwrap();
    meta.write_plaintext(&bytes(&metadata)).unwrap();
    let (metadata, ms) = meta.finish().unwrap();
    let mut secret = StreamEncoder::new(
        Vec::new(),
        pk,
        StreamContext::new(id.bytes(), StreamRole::Private),
        StreamLimits::default(),
    )
    .unwrap();
    secret.write_plaintext(&bytes(&private)).unwrap();
    let (private, ps) = secret.finish().unwrap();
    f.output.root = sign_declared_root(prepared, &f.signer, &ms, &ps).unwrap();
    f.output.metadata = metadata;
    f.output.private = private;
}

fn hostile(f: &mut Fixture, change: impl FnOnce(&mut Vec<Json>, &mut Vec<Json>)) {
    let (metadata, private) = plaintext(f);
    let mut metadata = lines(&metadata);
    let mut private = lines(&private);
    change(&mut metadata, &mut private);
    reseal(f, metadata, private);
    let error = verify(f).err().unwrap().to_string();
    assert!(!error.contains("private-credential"));
}

#[tokio::test]
async fn empty_tables_and_explicit_omission_counts_are_all_present() {
    let f = fixture().await;
    let (m, p) = plaintext(&f);
    let meta = lines(&m);
    assert_eq!(
        meta.iter()
            .filter(|line| line["kind"] == "table_start")
            .count(),
        279
    );
    assert_eq!(
        meta.iter()
            .filter(|line| line["kind"] == "table_end")
            .count(),
        279
    );
    assert!(meta
        .iter()
        .any(|line| line["kind"] == "table_start" && line["source_rows"] == "0"));
    let sessions = meta
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == "sessions")
        .unwrap();
    assert_eq!(meta[sessions]["disposition"], "auth_transient");
    assert_eq!(meta[sessions + 1]["omitted_rows"], "1");
    assert!(!String::from_utf8(m).unwrap().contains("private-credential"));
    assert!(!String::from_utf8(p)
        .unwrap()
        .contains("transient-NOT-EXPORTED"));
    let root: Json = serde_json::from_slice(f.output.root.as_bytes()).unwrap();
    assert_eq!(root["payload"]["profile"], "framing_only");
}

#[tokio::test]
async fn signed_schema_profile_and_role_changes_reject() {
    for field in ["profile", "role", "table_count"] {
        let mut f = fixture().await;
        hostile(&mut f, |m, _| {
            m[0][field] = json!("unsupported-SECRET");
        });
    }
    let mut f = fixture().await;
    hostile(&mut f, |m, _| {
        m[0]["schema"]["classification_digest"] = json!("a".repeat(64));
    });
}

#[tokio::test]
async fn signed_unknown_members_and_canonical_count_rules_reject() {
    for value in [
        json!(1),
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut f = fixture().await;
        hostile(&mut f, |m, _| {
            m[1]["source_rows"] = value;
        });
    }
    let mut f = fixture().await;
    hostile(&mut f, |m, _| {
        m[0]["activation_authorized"] = json!(true);
    });
}

#[tokio::test]
async fn signed_missing_duplicate_or_reordered_empty_table_rejects() {
    for mode in 0..3 {
        let mut f = fixture().await;
        hostile(&mut f, |m, _| match mode {
            0 => {
                m.drain(1..3);
            }
            1 => {
                let duplicate = m[1].clone();
                m.insert(1, duplicate);
            }
            _ => {
                m.swap(1, 3);
            }
        });
    }
}

#[tokio::test]
async fn signed_row_cell_order_and_scalar_private_substitution_reject() {
    for mode in 0..3 {
        let mut f = fixture().await;
        hostile(&mut f, |m, _| {
            let first = m
                .iter()
                .position(|line| line["kind"] == "row_start")
                .unwrap();
            match mode {
                0 => {
                    m[first]["row"] = json!("1");
                }
                1 => {
                    m.swap(first + 1, first + 2);
                }
                _ => {
                    let cell = m
                        .iter_mut()
                        .find(|line| line["kind"] == "cell" && line["column"] == "password_hash")
                        .unwrap();
                    cell["scalar"] = json!({"kind":"text","value":"private-credential-RAW"});
                    cell["external"] = Json::Null;
                }
            }
        });
    }
}

#[tokio::test]
async fn signed_private_payload_locator_swap_missing_or_extra_rejects() {
    for mode in 0..6 {
        let mut f = fixture().await;
        hostile(&mut f, |_, p| match mode {
            0 => {
                p[1]["scalar"]["value"] = json!("swapped-SECRET");
            }
            1 => {
                p[1]["dependency"]["primary_key_digest"] = json!("a".repeat(64));
            }
            2 => {
                p.swap(1, 2);
            }
            3 => {
                p.remove(1);
            }
            4 => {
                let extra = p[1].clone();
                p.insert(2, extra);
            }
            _ => {
                p[1]["dependency"]["payload_bytes"] = json!("0");
            }
        });
    }
}

#[tokio::test]
async fn signed_table_and_logical_end_counts_reject() {
    for mode in 0..5 {
        let mut f = fixture().await;
        hostile(&mut f, |m, p| match mode {
            0 => {
                m[2]["retained_rows"] = json!("1");
            }
            1 => {
                m.last_mut().unwrap()["records"] = json!("0");
            }
            2 => {
                p.last_mut().unwrap()["private_cells"] = json!("0");
            }
            3 => {
                m.pop();
            }
            _ => {
                p.pop();
            }
        });
    }
}

#[tokio::test]
async fn signed_trailing_records_reject_after_provisional_callbacks() {
    let mut f = fixture().await;
    let (m, p) = plaintext(&f);
    let mut m = lines(&m);
    m.push(json!({"kind":"unexpected"}));
    reseal(&mut f, m, lines(&p));
    let mut provisional = 0;
    let result = verify_database_capture(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |_, _, _| {
            provisional += 1;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(provisional > 0);
}

#[tokio::test]
async fn ciphertext_truncation_cross_capture_and_wrong_trust_reject() {
    let mut f = fixture().await;
    f.output.private.pop();
    assert!(verify(&f).is_err());
    let (_dir, path, _pool) = source().await;
    let mut first = capture_path_seed(&path, options(), 471).await;
    let second = capture_path_seed(&path, options(), 472).await;
    let first_id = verify_declared_root(first.output.root.as_bytes(), &trust(&first))
        .unwrap()
        .archive_id();
    let second_id = verify_declared_root(second.output.root.as_bytes(), &trust(&second))
        .unwrap()
        .archive_id();
    assert_ne!(first_id, second_id);
    first.output.private = second.output.private;
    assert!(verify(&first).is_err());
    let f = fixture().await;
    let trust = ArchiveSignerTrust::new([("snapshot-operator".into(), [9; 32])]).unwrap();
    assert!(verify_database_capture(
        f.output.root.as_bytes(),
        &trust,
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |_, _, _| Ok(())
    )
    .is_err());
}

#[tokio::test]
async fn callback_failure_and_debug_never_disclose_private_originals() {
    let f = fixture().await;
    let error = verify_database_capture(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |_, _, row| {
            assert!(!format!("{row:?}").contains("private-credential"));
            anyhow::bail!("private-credential-RAW")
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "snapshot private row callback failed");
    let report = verify(&f).unwrap();
    assert!(!format!("{report:?}").contains("private-credential"));
}

#[tokio::test]
async fn one_mib_escaped_private_text_and_extreme_integers_cross_frames_losslessly() {
    let (_dir, path, pool) = source().await;
    let secret = "\u{0001}".repeat(1024 * 1024);
    sqlx::query("UPDATE users SET password_hash=?1,created_at=?2 WHERE id=17")
        .bind(&secret)
        .bind(i64::MIN)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET created_at=?1 WHERE id=18")
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();
    let original_json = " {\"opaque\":true, \"text\":\"unchanged\"} \n";
    sqlx::query("INSERT INTO instance_config(config_key,value) VALUES ('signup_domains',?1)")
        .bind(original_json)
        .execute(&pool)
        .await
        .unwrap();
    let f = capture_path(&path, options()).await;
    let classifier = current_classifier().unwrap();
    let mut matched = 0;
    verify_database_capture(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        StreamLimits::default(),
        |table, _, reconstructed| {
            reconstructed.with_private_row(|row| {
                let cols = &classifier.tables[table].columns;
                let index = |name: &str| cols.iter().position(|col| col.name == name).unwrap();
                if table == "users" {
                    let id = row.get::<i64>(index("id")).unwrap();
                    let created = row.get::<i64>(index("created_at")).unwrap();
                    assert_eq!(created, if id == 17 { i64::MIN } else { i64::MAX });
                    if id == 17 {
                        assert_eq!(row.get::<String>(index("password_hash")).unwrap(), secret);
                    }
                    matched += 1;
                }
                if table == "instance_config" && row.get::<String>(0).unwrap() == "signup_domains" {
                    assert_eq!(row.get::<String>(1).unwrap(), original_json);
                    matched += 1;
                }
            });
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(matched, 3);
}

#[tokio::test]
async fn source_changed_after_reader_open_keeps_the_pinned_sql_image() {
    let (_dir, path, pool) = source().await;
    let source = SqliteSnapshotReader::open(&path).await.unwrap();
    sqlx::query("UPDATE users SET password_hash='NEW-CREDENTIAL' WHERE id=17")
        .execute(&pool)
        .await
        .unwrap();
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    let wrapping = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
    )
    .unwrap();
    let output = capture_sqlite(
        source,
        Vec::new(),
        Vec::new(),
        CaptureKeyCustody {
            signer: &signer,
            wrapping: &wrapping,
            exclusions: &[],
        },
        &mut StdRng::seed_from_u64(471),
        options(),
    )
    .await
    .unwrap();
    let f = Fixture {
        output,
        signer,
        wrapping,
    };
    let (_, private) = plaintext(&f);
    let text = String::from_utf8(private).unwrap();
    assert!(text.contains("private-credential-RAW"));
    assert!(!text.contains("NEW-CREDENTIAL"));
    verify(&f).unwrap();
}

#[tokio::test]
async fn source_audit_and_unknown_dynamic_key_fail_without_completed_output() {
    for bad_sql in [
        "PRAGMA foreign_keys=OFF; UPDATE sessions SET user_id=9999",
        "INSERT INTO instance_config(config_key,value) VALUES ('future_secret_key','SECRET-UNKNOWN')",
    ] {
        let (_dir, path, pool) = source().await;
        sqlx::raw_sql(bad_sql).execute(&pool).await.unwrap();
        let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
        let wrapping = ArchiveWrappingKeys::new(
            ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
            ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
        )
        .unwrap();
        let error = capture_sqlite(
            SqliteSnapshotReader::open(&path).await.unwrap(),
            Vec::new(),
            Vec::new(),
            CaptureKeyCustody {
                signer: &signer,
                wrapping: &wrapping,
                exclusions: &[],
            },
            &mut StdRng::seed_from_u64(471),
            options(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "snapshot SQLite database capture failed");
    }
}

#[tokio::test]
async fn sink_error_is_redacted_and_never_returns_a_completed_root() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-sink-SECRET"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_dir, path, _pool) = source().await;
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    let wrapping = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
    )
    .unwrap();
    let error = capture_sqlite(
        SqliteSnapshotReader::open(&path).await.unwrap(),
        Failing,
        Vec::new(),
        CaptureKeyCustody {
            signer: &signer,
            wrapping: &wrapping,
            exclusions: &[],
        },
        &mut StdRng::seed_from_u64(471),
        options(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "snapshot SQLite database capture failed");
}

#[tokio::test]
async fn malformed_scalar_and_raw_parser_details_are_redacted() {
    for scalar in [
        json!({"kind":"integer","value":"01-SECRET"}),
        json!({"kind":"bytes_hex","value":"FF-SECRET"}),
        json!({"kind":"real_bits","value":"7ff0000000000000"}),
        json!({"kind":"text","value":["SECRET"]}),
        json!({"kind":"null","value":"SECRET"}),
    ] {
        let mut f = fixture().await;
        hostile(&mut f, |_, p| {
            p[1]["scalar"] = scalar;
        });
    }
}

#[test]
fn bounded_scalar_record_codec_preserves_blob_null_and_signed_zero() {
    for scalar in [
        crate::snapshot::SnapshotScalar::BytesHex("00ff8010".into()),
        crate::snapshot::SnapshotScalar::Null,
        crate::snapshot::SnapshotScalar::RealBits("8000000000000000".into()),
        crate::snapshot::SnapshotScalar::Integer(i64::MIN.to_string()),
    ] {
        let encoded = serde_json::to_vec(&WireScalar(scalar.clone())).unwrap();
        let decoded: WireScalar = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.0, scalar);
        crate::snapshot::capture::scalar_payload_len(&decoded.0).unwrap();
    }
    // REAL is a scalar codec proof; no current schema row admits REAL storage.
}

#[tokio::test]
async fn explicit_small_framing_limits_reject_actual_capture_and_verification() {
    let f = fixture().await;
    let mut limits = StreamLimits::default();
    limits.max_plaintext_bytes = 1;
    assert!(verify_database_capture(
        f.output.root.as_bytes(),
        &trust(&f),
        &f.wrapping,
        &[],
        Cursor::new(&f.output.metadata),
        Cursor::new(&f.output.private),
        limits,
        |_, _, _| Ok(())
    )
    .is_err());
    let (_dir, path, _pool) = source().await;
    let mut bounded = options();
    bounded.streams = limits;
    assert!(capture_sqlite(
        SqliteSnapshotReader::open(&path).await.unwrap(),
        Vec::new(),
        Vec::new(),
        CaptureKeyCustody {
            signer: &f.signer,
            wrapping: &f.wrapping,
            exclusions: &[]
        },
        &mut StdRng::seed_from_u64(980),
        bounded,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn duplicate_primary_key_substitution_is_explicitly_outside_record_proof() {
    let mut f = fixture().await;
    let (m, p) = plaintext(&f);
    let mut m = lines(&m);
    let mut p = lines(&p);
    let table = m
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == "users")
        .unwrap();
    let first_start = table + 1;
    let first_end = m[first_start..]
        .iter()
        .position(|line| line["kind"] == "row_end")
        .unwrap()
        + first_start;
    let second_start = first_end + 1;
    let second_end = m[second_start..]
        .iter()
        .position(|line| line["kind"] == "row_end")
        .unwrap()
        + second_start;
    let second_seq = m[second_start]["row"].clone();
    let mut replacement = m[first_start..=first_end].to_vec();
    for line in &mut replacement {
        if line.get("row").is_some() {
            line["row"] = second_seq.clone();
        }
    }
    m.splice(second_start..=second_end, replacement);
    let originals: Vec<_> = p
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            line["kind"] == "private_cell" && line["dependency"]["table"] == "users"
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(originals.len(), 2);
    let mut repeated = p[originals[0]].clone();
    repeated["row"] = second_seq;
    p[originals[1]] = repeated;
    reseal(&mut f, m, p);
    // Exact per-row reconstruction/count proof holds; a private scratch SQL
    // replay must still reject the duplicate user PK before restore acceptance.
    let report = verify(&f).unwrap();
    assert_eq!(report.counts(), &f.output.counts);
}

#[test]
fn duplicate_and_unknown_scalar_members_fail_without_large_generic_trees() {
    for raw in [
        br#"{"kind":"text","kind":"text","value":"SECRET"}"#.as_slice(),
        br#"{"kind":"text","value":"SECRET","extra":true}"#.as_slice(),
        br#"{"kind":"text","value":{"SECRET":[]}}"#.as_slice(),
    ] {
        assert!(serde_json::from_slice::<WireScalar>(raw).is_err());
    }
}

#[test]
fn record_line_bounds_blank_and_unterminated_records_fail_closed() {
    use super::super::{FreshStreamKey, StreamContext, StreamDecryptionKey, StreamEncoder};
    fn reader(plain: &[u8]) -> RecordReader<Cursor<Vec<u8>>> {
        let mut rng = StdRng::seed_from_u64(907);
        let key = FreshStreamKey::generate(&mut rng).unwrap();
        let reader_key =
            key.with_private_key_bytes(|bytes| StreamDecryptionKey::from_bytes(*bytes));
        let context = StreamContext::new([9; 16], StreamRole::Metadata);
        let mut encoder =
            StreamEncoder::new(Vec::new(), key, context, StreamLimits::default()).unwrap();
        encoder.write_plaintext(plain).unwrap();
        let (ciphertext, _) = encoder.finish().unwrap();
        RecordReader::new(
            StreamDecoder::new(
                Cursor::new(ciphertext),
                reader_key,
                context,
                StreamLimits::default(),
            )
            .unwrap(),
        )
    }
    assert!(reader(b"\n").read::<RowMark>(CONTROL_CAP).is_err());
    assert!(reader(br#"{"kind":"row_start","row":"0"}"#)
        .read::<RowMark>(CONTROL_CAP)
        .is_err());
    assert!(reader(&vec![b'a'; CONTROL_CAP + 1])
        .read::<RowMark>(CONTROL_CAP)
        .is_err());
    let mut json = br#"{"kind":"row_start","row":"0","row":"0"}"#.to_vec();
    json.push(b'\n');
    assert!(reader(&json).read::<RowMark>(CONTROL_CAP).is_err());
    assert!(number("9223372036854775808").is_ok()); // rejected specifically as a SQL source count
}

#[tokio::test]
async fn actual_capture_does_not_write_source_database_or_wal_contents() {
    let (_dir, path, pool) = source().await;
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    let before_db = std::fs::read(&path).unwrap();
    let before_wal = std::fs::read(&wal).unwrap();
    let before_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    let f = capture_path(&path, options()).await;
    verify(&f).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before_db);
    assert_eq!(std::fs::read(&wal).unwrap(), before_wal);
    let after_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after_mode, before_mode);
}

#[tokio::test]
async fn failing_source_audit_touches_neither_ciphertext_sink() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct Counting(Rc<Cell<usize>>);
    impl std::io::Write for Counting {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.set(self.0.get() + bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_dir, path, pool) = source().await;
    sqlx::raw_sql("PRAGMA foreign_keys=OFF; UPDATE sessions SET user_id=9999")
        .execute(&pool)
        .await
        .unwrap();
    let signer = ArchiveSigningKey::from_seed("snapshot-operator", [1; 32]).unwrap();
    let wrapping = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("metadata-wrap", [2; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("private-wrap", [3; 32]).unwrap(),
    )
    .unwrap();
    let written = Rc::new(Cell::new(0));
    let result = capture_sqlite(
        SqliteSnapshotReader::open(&path).await.unwrap(),
        Counting(written.clone()),
        Counting(written.clone()),
        CaptureKeyCustody {
            signer: &signer,
            wrapping: &wrapping,
            exclusions: &[],
        },
        &mut StdRng::seed_from_u64(999),
        options(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(written.get(), 0);
}

#[tokio::test]
async fn signed_invalid_sql_count_and_metadata_singleton_counts_reject() {
    for mode in 0..2 {
        let mut f = fixture().await;
        hostile(&mut f, |m, _| {
            if mode == 0 {
                m[1]["source_rows"] = json!("9223372036854775808");
            } else {
                let singleton = m
                    .iter_mut()
                    .find(|line| {
                        line["kind"] == "table_start" && line["table"] == "hub_schema_identity"
                    })
                    .unwrap();
                singleton["source_rows"] = json!("0");
            }
        });
    }
}

#[test]
fn distinct_postgres_header_requires_exact_closed_source_and_generation() {
    let classifier = current_classifier().unwrap();
    let mut header = Header {
        kind: "header".into(),
        profile: POSTGRES_PROFILE.into(),
        archive_id: "test-archive".into(),
        role: "metadata".into(),
        schema: schema(&classifier).unwrap(),
        table_count: classifier.tables.len().to_string(),
        audit: Audit {
            integrity: "not_observed".into(),
            compiled_checks: "passed".into(),
            declared_foreign_keys: "passed".into(),
            checked_expressions: "1200".into(),
        },
        source: Some(PostgresSource::expected()),
    };
    check_header(&header, &classifier, "test-archive", "metadata").unwrap();
    for (field, value) in [
        ("major", "17"),
        ("isolation", "read_committed"),
        ("access", "read_write"),
        ("audit", "provider_qualified"),
        ("catalogue_sha256", "untrusted"),
    ] {
        let mut malformed = serde_json::to_value(&header).unwrap();
        malformed["source"][field] = json!(value);
        let malformed: Header = serde_json::from_value(malformed).unwrap();
        assert!(check_header(&malformed, &classifier, "test-archive", "metadata").is_err());
    }
    header.source = None;
    assert!(check_header(&header, &classifier, "test-archive", "metadata").is_err());
    header.source = Some(PostgresSource::expected());
    header.profile = PROFILE.into();
    assert!(check_header(&header, &classifier, "test-archive", "metadata").is_err());
    let legacy = SnapshotClassifier::for_supported_generation(7).unwrap();
    header.profile = POSTGRES_PROFILE.into();
    header.schema = schema(&legacy).unwrap();
    header.table_count = legacy.tables.len().to_string();
    assert!(check_header(&header, &legacy, "test-archive", "metadata").is_err());
}
