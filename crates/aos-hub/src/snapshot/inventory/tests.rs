//! Actual SQL capture, private replay and metadata-only requirement workflows.

use super::*;
use crate::snapshot::inventory;
use aos_hub_core::backend::Backend;
use aos_hub_core::snapshot::inventory::ObjectRequirementsLimits;
use std::net::TcpListener;

async fn dependencies(database: &Database, listener: &TcpListener) {
    let org = database
        .create_org("requirements", "Requirements fixture")
        .await
        .unwrap();
    let owner = database.org_by_id(org).await.unwrap().unwrap();
    let binding = database
        .create_topology_binding(
            Some(org),
            "requirements-binding",
            &owner.stable_id,
            "Unvalidated provider",
            "s3",
            None,
            Some("fixture-only-bucket"),
            Some("archive/source"),
            Some("https"),
            Some("ipv4"),
            Some(&[127, 0, 0, 1]),
            Some(i64::from(listener.local_addr().unwrap().port())),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    database
        .set_binding_credential_revision(
            binding,
            "read",
            "secret://requirements/not-installed/v1",
            0,
            &"b".repeat(64),
            "fixture-operator",
        )
        .await
        .unwrap();
}

fn no_network(listener: &TcpListener) {
    let error = listener.accept().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

async fn sqlite_dependencies(source: &Path, listener: &TcpListener) {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(source)
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let db = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    dependencies(&db, listener).await;
    sqlx::query(
        "INSERT INTO image_snapshots(digest,byte_size,state,created_at) VALUES (?1,4096,'live',1)",
    )
    .bind("e".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    drop(db);
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
}

fn limits() -> ObjectRequirementsLimits {
    ObjectRequirementsLimits::default()
}

#[tokio::test]
async fn actual_sqlite_capture_projects_private_requirements_and_refuses_mismatch() {
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let source = source(f.directory.path()).await;
    sqlite_dependencies(&source, &listener).await;
    let before = Sha256::digest(fs::read(&source).unwrap());
    let archive = f.directory.path().join("source-capture");
    workflow::capture(&source, &archive, &f.credentials, budget())
        .await
        .unwrap();
    let output = f.directory.path().join("requirements");

    let derived = inventory::derive_object_requirements(
        &archive,
        &output,
        &f.credentials,
        limits(),
        budget(),
    )
    .await
    .unwrap();
    let checked = inventory::verify_object_requirements(
        &archive,
        &output,
        &reader_credentials(&f),
        limits(),
        budget(),
    )
    .await
    .unwrap();

    assert_eq!(
        derived.verification_scope,
        "retained_sql_and_incomplete_object_requirements"
    );
    assert_eq!(derived.object_requirements, checked.object_requirements);
    let counts = derived.object_requirements.unwrap();
    assert_eq!(counts.source_retained_rows, derived.retained_rows);
    assert_eq!(counts.families.get("image_root"), Some(&1));
    assert!(
        counts
            .families
            .get("authority_dependency")
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(counts.excluded_secret_cells > 0);
    assert_eq!(checked.signed_root_profile, "framing_only");
    assert_eq!(Sha256::digest(fs::read(&source).unwrap()), before);
    assert!(checked
        .pending_recovery_requirements
        .contains(&"application_and_object_closure"));
    assert!(!f.directory.path().join("sealing.key").exists());
    assert!(!f.directory.path().join("not-installed").exists());
    no_network(&listener);
    for name in filesystem::FILES {
        let path = output.join(name);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(path).unwrap();
        for forbidden in [
            b"private-credential-NEVER-PRINT".as_slice(),
            b"secret://requirements/not-installed/v1".as_slice(),
        ] {
            assert!(!bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
    }
    let printed = serde_json::to_string(&checked).unwrap();
    assert!(!printed.contains("fixture-only-bucket") && !printed.contains("NEVER-PRINT"));

    // A newly signed capture of even unchanged SQL has a different immutable
    // archive root. Its inventory cannot be substituted for this original.
    let another = f.directory.path().join("another-capture");
    workflow::capture(&source, &another, &f.credentials, budget())
        .await
        .unwrap();
    assert!(inventory::verify_object_requirements(
        &another,
        &output,
        &reader_credentials(&f),
        limits(),
        budget()
    )
    .await
    .is_err());
    let small = f.directory.path().join("bounded-refusal");
    assert!(inventory::derive_object_requirements(
        &archive,
        &small,
        &f.credentials,
        ObjectRequirementsLimits { max_rows: 1 },
        budget()
    )
    .await
    .is_err());
    assert!(!small.exists());
    assert!(inventory::derive_object_requirements(
        Path::new("missing"),
        &small,
        &f.credentials,
        ObjectRequirementsLimits { max_rows: 0 },
        budget()
    )
    .await
    .is_err());
    assert!(!small.exists());
    assert!(inventory::derive_object_requirements(
        &archive,
        &output,
        &f.credentials,
        limits(),
        budget()
    )
    .await
    .is_err());
    assert!(output.exists());

    // Physical framing corruption refuses exact-source verification. Neither
    // capture nor requirements cleanup removes already published originals.
    fs::OpenOptions::new()
        .append(true)
        .open(output.join("private.aosh"))
        .unwrap()
        .write_all(b"trailing")
        .unwrap();
    assert!(inventory::verify_object_requirements(
        &archive,
        &output,
        &reader_credentials(&f),
        limits(),
        budget()
    )
    .await
    .is_err());
    assert!(archive.exists() && output.exists());
    no_network(&listener);
}

#[tokio::test]
async fn cancelled_requirements_never_publish_provisional_rows() {
    let f = fixture();
    let source = source(f.directory.path()).await;
    let archive = f.directory.path().join("source-capture");
    workflow::capture(&source, &archive, &f.credentials, budget())
        .await
        .unwrap();
    let output = f.directory.path().join("cancelled");
    let stopped = budget();
    stopped.cancel();
    assert!(matches!(
        inventory::derive_object_requirements(&archive, &output, &f.credentials, limits(), stopped)
            .await
            .unwrap_err(),
        SnapshotError::Cancelled
    ));
    assert!(!output.exists());
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires a dedicated disposable PostgreSQL 18 source URL file"]
async fn actual_postgres_capture_replays_object_requirements_without_provider_access() {
    let connection =
        std::env::var_os("AOS_PG_SNAPSHOT_TEST_URL_FILE").expect("private disposable source URL");
    let url = fs::read(connection).unwrap();
    let f = fixture();
    let private_url = private_file(f.directory.path(), "postgres.url", &url);
    let backend = SqlxBackend::connect_postgres(std::str::from_utf8(&url).unwrap().trim())
        .await
        .unwrap();
    backend.migrate_schema().await.unwrap();
    let SqlxBackend::Postgres(pool) = backend else {
        panic!("PostgreSQL required");
    };
    let db = Database::with_backend(Box::new(SqlxBackend::Postgres(pool.clone())))
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    dependencies(&db, &listener).await;
    sqlx::query(
        "INSERT INTO image_snapshots(digest,byte_size,state,created_at) VALUES ($1,8192,'live',1)",
    )
    .bind("f".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash,created_at) VALUES (7017,'requirements@fixture.invalid','PG-PRIVATE-NEVER-PRINT',1)").execute(&pool).await.unwrap();
    drop(db);
    let archive = f.directory.path().join("postgres-capture");
    let requirements = f.directory.path().join("postgres-requirements");
    workflow::capture_postgres(&private_url, &archive, &f.credentials, budget())
        .await
        .unwrap();

    let derived = inventory::derive_object_requirements(
        &archive,
        &requirements,
        &f.credentials,
        limits(),
        budget(),
    )
    .await
    .unwrap();
    let checked = inventory::verify_object_requirements(
        &archive,
        &requirements,
        &reader_credentials(&f),
        limits(),
        budget(),
    )
    .await
    .unwrap();

    assert_eq!(checked.source_engine, Some("postgresql"));
    assert_eq!(derived.object_requirements, checked.object_requirements);
    assert_eq!(
        checked
            .object_requirements
            .as_ref()
            .unwrap()
            .families
            .get("image_root"),
        Some(&1)
    );
    let original: String = sqlx::query_scalar("SELECT validation_state FROM binding_credential_revisions WHERE secret_version_ref='secret://requirements/not-installed/v1'").fetch_one(&pool).await.unwrap();
    assert_eq!(original, "unknown");
    let password: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=7017")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(password, "PG-PRIVATE-NEVER-PRINT");
    for name in filesystem::FILES {
        let bytes = fs::read(requirements.join(name)).unwrap();
        assert!(!bytes
            .windows(b"PG-PRIVATE-NEVER-PRINT".len())
            .any(|part| part == b"PG-PRIVATE-NEVER-PRINT"));
    }
    no_network(&listener);
    pool.close().await;
}
