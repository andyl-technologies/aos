//! Genuine capture fixtures and correctly resigned hostile archive mutations.

use std::io::Cursor;
use std::time::Duration;

use anyhow::Result;

use aos_hub_core::backend::{sqlite_snapshot::*, SqlxBackend};
use aos_hub_core::db::Database;
use aos_hub_core::snapshot::archive::records::*;
use aos_hub_core::snapshot::archive::root::*;
use aos_hub_core::snapshot::archive::*;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value as Json};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::TempDir;

pub(super) struct Fixture {
    pub output: DatabaseCaptureOutput<Vec<u8>, Vec<u8>>,
    pub signer: ArchiveSigningKey,
    pub wrapping: ArchiveWrappingKeys,
}

pub(super) fn options() -> SqliteCaptureOptions {
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

pub(super) async fn source() -> (TempDir, std::path::PathBuf, sqlx::SqlitePool) {
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
    sqlx::raw_sql("INSERT INTO user_identities(user_id,issuer,subject,email,last_login) VALUES (17,'issuer','subject-a',NULL,NULL),(18,'issuer','subject-b','b@example.invalid',2); INSERT INTO egress_request_nonces(nonce,request_digest,accepted_at,expires_at) VALUES ('nonce-one','digest-one',1,2); INSERT INTO route_url_reservations(id,digest_scheme,reservation_key_version,reservation_digest,created_at) VALUES ('reservation-one','hmac_sha256_v1',1,X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',1)")
        .execute(&pool).await.unwrap();
    (dir, path, pool)
}

pub(super) async fn fixture() -> Fixture {
    let (_dir, path, pool) = source().await;
    let output = capture_path(&path, options()).await;
    pool.close().await;
    output
}

pub(super) async fn capture_path(path: &std::path::Path, options: SqliteCaptureOptions) -> Fixture {
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

pub(super) fn trust(f: &Fixture) -> ArchiveSignerTrust {
    ArchiveSignerTrust::new([(f.signer.id().to_owned(), f.signer.public_key())]).unwrap()
}

pub(super) fn verify(f: &Fixture) -> Result<VerifiedDatabaseCaptureRecords> {
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

pub(super) fn plaintext(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
    let root = verify_declared_root(f.output.root.as_bytes(), &trust(f)).unwrap();
    let (meta_key, private_key) = root
        .unwrap_reader_keys(&f.wrapping, &[])
        .unwrap()
        .into_role_keys();
    fn decode(bytes: &[u8], key: StreamDecryptionKey, context: StreamContext) -> Vec<u8> {
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

pub(super) fn lines(bytes: &[u8]) -> Vec<Json> {
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
pub(super) fn reseal(f: &mut Fixture, mut metadata: Vec<Json>, mut private: Vec<Json>) {
    use aos_hub_core::snapshot::archive::root::{
        prepare_archive_keys, sign_declared_root, FreshArchiveId,
    };
    use aos_hub_core::snapshot::archive::{FreshStreamKey, StreamContext, StreamEncoder};
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
