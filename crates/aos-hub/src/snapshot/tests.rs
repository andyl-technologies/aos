//! Real database capture, private custody and irreversible filesystem boundaries.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_hub_core::backend::sqlite_snapshot::SqliteSnapshotReader;
use aos_hub_core::backend::SqlxBackend;
use aos_hub_core::db::Database;
use aos_hub_core::snapshot::archive::root::ArchiveSigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::TempDir;

use super::credentials::{load_capture, load_trust, load_wrapping};
use super::filesystem::{self, Directory, PublishError, SourceAdmission, Stage};
use super::workflow::{self, SnapshotBudget, SnapshotError};
use super::*;

struct Fixture {
    directory: PrivateFixtureDirectory,
    credentials: CaptureCredentials,
}

struct PrivateFixtureDirectory {
    _owner: TempDir,
    relative_path: PathBuf,
}

impl PrivateFixtureDirectory {
    fn path(&self) -> &Path {
        &self.relative_path
    }
}

fn private_file(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn fixture() -> Fixture {
    // Keep tempfile's absolute cleanup owner, but exercise custody through the
    // relative path rooted at the trusted working-directory descriptor.
    let owner = tempfile::tempdir_in(".").unwrap();
    let relative_path = PathBuf::from(owner.path().file_name().unwrap());
    assert!(relative_path.is_relative());
    let directory = PrivateFixtureDirectory {
        _owner: owner,
        relative_path,
    };
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = ArchiveSigningKey::from_seed("offline-export", [91; 32]).unwrap();
    let trust = serde_json::to_vec(&json!({"version":1,"signers":[{
        "id":signer.id(),"ed25519_public_key_hex":hex::encode(signer.public_key())
    }]}))
    .unwrap();
    let credentials = CaptureCredentials {
        signer_id: "offline-export".into(),
        signing_seed_file: private_file(directory.path(), "signer.seed", &[91; 32]),
        wrapping: WrappingFiles {
            metadata_id: "metadata-wrap".into(),
            metadata_file: private_file(directory.path(), "metadata.key", &[92; 32]),
            private_id: "private-wrap".into(),
            private_file: private_file(directory.path(), "private.key", &[93; 32]),
        },
        signer_trust_file: private_file(directory.path(), "trust.json", &trust),
        exclusion_files: vec![],
    };
    Fixture {
        directory,
        credentials,
    }
}

fn reader_credentials(f: &Fixture) -> VerifyCredentials {
    VerifyCredentials {
        wrapping: WrappingFiles {
            metadata_id: f.credentials.wrapping.metadata_id.clone(),
            metadata_file: f.credentials.wrapping.metadata_file.clone(),
            private_id: f.credentials.wrapping.private_id.clone(),
            private_file: f.credentials.wrapping.private_file.clone(),
        },
        signer_trust_file: f.credentials.signer_trust_file.clone(),
        exclusion_files: vec![],
    }
}

fn budget() -> SnapshotBudget {
    SnapshotBudget::new(Duration::from_secs(120), 16 * 1024 * 1024).unwrap()
}

async fn source(directory: &Path) -> PathBuf {
    let path = directory.join("hub.db");
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
    sqlx::raw_sql("INSERT INTO users(id,email,password_hash,created_at) VALUES (17,'fixture@example.invalid','private-credential-NEVER-PRINT',1); INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,last_authenticated_at) VALUES ('omitted-session-NEVER-PRINT',17,1,1,2,1)")
        .execute(&pool).await.unwrap();
    // Tests later copy/rename the main file. Checkpoint this test-owned writer
    // explicitly rather than assuming asynchronous pool teardown persists WAL.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    path
}

#[tokio::test]
async fn actual_capture_publishes_private_files_and_verifies_without_source_mutation() {
    let f = fixture();
    let source = source(f.directory.path()).await;
    let before = Sha256::digest(fs::read(&source).unwrap());
    let expected_tables = {
        let reader = SqliteSnapshotReader::open(&source).await.unwrap();
        u64::try_from(reader.schema().tables.len()).unwrap()
    };
    let destination = f.directory.path().join("capture");

    let captured = workflow::capture(&source, &destination, &f.credentials, budget())
        .await
        .unwrap();
    let verified = workflow::verify(&destination, &reader_credentials(&f), budget())
        .await
        .unwrap();

    assert_eq!(captured.tables, expected_tables);
    assert_eq!(verified.tables, expected_tables);
    assert_eq!(captured.retained_rows, verified.retained_rows);
    assert!(captured.private_cells > 0);
    assert!(captured.omitted_rows > 0);
    assert_eq!(captured.verification_scope, "retained_sqlite_constraints");
    assert_eq!(
        captured.schema_version,
        "aos.hub.offline-database-capture-report/v2"
    );
    assert_eq!(captured.checked_retained_tables, 269);
    assert_eq!(captured.synthetic_lineage_rows, 2);
    assert_eq!(verified.checked_retained_tables, 269);
    assert_eq!(captured.signed_root_profile, "framing_only");
    assert!(!captured
        .pending_recovery_requirements
        .contains(&"unique_keys_and_global_sql_constraints"));
    assert_eq!(captured.pending_recovery_requirements.len(), 5);
    assert_eq!(Sha256::digest(fs::read(&source).unwrap()), before);
    assert!(!f.directory.path().join("sealing.key").exists());
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let entries: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 3);
    for name in filesystem::FILES {
        let path = destination.join(name);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = fs::read(path).unwrap();
        assert!(!bytes
            .windows(b"private-credential-NEVER-PRINT".len())
            .any(|window| window == b"private-credential-NEVER-PRINT"));
    }
    let printed = serde_json::to_string(&captured).unwrap();
    assert!(!printed.contains("NEVER-PRINT"));
    assert!(!printed.contains(&f.directory.path().display().to_string()));
    assert!(!format!("{captured:?}").contains("NEVER-PRINT"));
    if let Some(output) = std::env::var_os("AOS_SNAPSHOT_TEST_FIXTURE_DIR") {
        let output = Path::new(&output);
        private_file(output, "valid-source.db", &fs::read(&source).unwrap());
        private_file(output, "capture-signer.seed", &[91; 32]);
        private_file(
            output,
            "capture-pins.json",
            &fs::read(&f.credentials.signer_trust_file).unwrap(),
        );
        private_file(output, "capture-metadata.key", &[92; 32]);
        private_file(output, "capture-private.key", &[93; 32]);
    }
}

#[tokio::test]
async fn missing_and_unknown_schema_sources_create_neither_source_nor_output() {
    let f = fixture();
    let missing = f.directory.path().join("missing.db");
    let destination = f.directory.path().join("capture");
    assert!(matches!(
        workflow::capture(&missing, &destination, &f.credentials, budget()).await,
        Err(SnapshotError::Source)
    ));
    assert!(!missing.exists());
    assert!(!destination.exists());

    let source = source(f.directory.path()).await;
    let pool = SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(&source))
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE future_unknown_private_payload(secret TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let before = fs::read(&source).unwrap();
    assert!(matches!(
        workflow::capture(&source, &destination, &f.credentials, budget()).await,
        Err(SnapshotError::Source)
    ));
    assert_eq!(fs::read(source).unwrap(), before);
    assert!(!destination.exists());
    assert!(!fs::read_dir(f.directory.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".aos-snapshot-")));
}

#[test]
fn bounded_raw_credentials_reject_lengths_public_links_and_fifo_without_leaking() {
    let mut f = fixture();
    for bytes in [
        vec![9; 31],
        vec![9; 33],
        b"PRIVATE-KEY-NEVER-PRINT-hex-text-input".to_vec(),
    ] {
        fs::write(&f.credentials.signing_seed_file, bytes).unwrap();
        let error = load_capture(&f.credentials).err().unwrap();
        assert!(!format!("{error:#}").contains("NEVER-PRINT"));
    }
    fs::write(&f.credentials.signing_seed_file, [91; 32]).unwrap();
    fs::set_permissions(
        &f.credentials.signing_seed_file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(load_capture(&f.credentials).is_err());
    fs::set_permissions(
        &f.credentials.signing_seed_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let hard = f.directory.path().join("hard-key");
    fs::hard_link(&f.credentials.signing_seed_file, &hard).unwrap();
    assert!(load_capture(&f.credentials).is_err());
    fs::remove_file(hard).unwrap();
    let link = f.directory.path().join("link-key");
    symlink(&f.credentials.signing_seed_file, &link).unwrap();
    f.credentials.signing_seed_file = link;
    assert!(load_capture(&f.credentials).is_err());
    let fifo = f.directory.path().join("fifo-key");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    f.credentials.signing_seed_file = fifo;
    assert!(load_capture(&f.credentials).is_err());

    let unsafe_ancestor = f.directory.path().join("writable-ancestor");
    fs::create_dir(&unsafe_ancestor).unwrap();
    fs::set_permissions(&unsafe_ancestor, fs::Permissions::from_mode(0o777)).unwrap();
    let private_child = unsafe_ancestor.join("private");
    fs::create_dir(&private_child).unwrap();
    fs::set_permissions(&private_child, fs::Permissions::from_mode(0o700)).unwrap();
    f.credentials.signing_seed_file = private_file(&private_child, "signer.seed", &[91; 32]);
    assert!(load_capture(&f.credentials).is_err());
}

#[test]
fn closed_external_trust_and_role_custody_reject_aliases_and_unpinned_producers() {
    let f = fixture();
    let original = fs::read(&f.credentials.signer_trust_file).unwrap();
    for document in [
        json!({"version":2,"signers":[]}),
        json!({"version":1,"signers":[],"source_key":"NEVER-PRINT"}),
        json!({"version":1,"signers":[{"id":"offline-export","ed25519_public_key_hex":"NEVER-PRINT"}]}),
    ] {
        fs::write(
            &f.credentials.signer_trust_file,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let error = load_trust(&f.credentials.signer_trust_file).err().unwrap();
        assert!(!format!("{error:#}").contains("NEVER-PRINT"));
    }
    fs::write(
        &f.credentials.signer_trust_file,
        br#"{"version":1,"version":1,"signers":[]}"#,
    )
    .unwrap();
    assert!(load_trust(&f.credentials.signer_trust_file).is_err());
    fs::write(&f.credentials.signer_trust_file, vec![b' '; 65537]).unwrap();
    assert!(load_trust(&f.credentials.signer_trust_file).is_err());
    fs::write(&f.credentials.signer_trust_file, original).unwrap();
    fs::write(&f.credentials.signing_seed_file, [94; 32]).unwrap();
    assert!(load_capture(&f.credentials).is_err());
    fs::write(&f.credentials.wrapping.private_file, [92; 32]).unwrap();
    assert!(load_wrapping(&f.credentials.wrapping).is_err());
}

#[test]
fn private_descriptor_admission_rejects_unsafe_sources_directories_and_streams() {
    let f = fixture();
    let source = private_file(f.directory.path(), "source.db", b"existing-source");
    let admitted = SourceAdmission::open(&source).unwrap();
    let substitute = f.directory.path().join("replacement.db");
    fs::rename(&source, &substitute).unwrap();
    private_file(f.directory.path(), "source.db", b"foreign-source");
    assert!(admitted.check_identity().is_err());
    let linked = f.directory.path().join("linked-source");
    symlink(&substitute, &linked).unwrap();
    assert!(SourceAdmission::open(&linked).is_err());
    let directory_link = f.directory.path().join("linked-directory");
    symlink(f.directory.path(), &directory_link).unwrap();
    assert!(Directory::open(&directory_link, true).is_err());
    let mut stage = Stage::create(&f.directory.path().join("capture")).unwrap();
    for name in filesystem::FILES {
        stage.create_file(name).unwrap();
    }
    stage.directory().exact_entries().unwrap();
    let stream = stage.directory().file("metadata.aosh").unwrap();
    stream
        .set_permissions(fs::Permissions::from_mode(0o644))
        .unwrap();
    assert!(stage.directory().file("metadata.aosh").is_err());
    assert!(stage.create_file("../escape").is_err());
    assert!(stage.directory().file("unknown").is_err());
    assert!(stage.publish().is_ok());
    fs::set_permissions(
        f.directory.path().join("capture"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Directory::open(&f.directory.path().join("capture"), true).is_err());
}

#[test]
fn no_replace_race_preserves_foreign_destination_and_cleans_only_staging() {
    let f = fixture();
    let destination = f.directory.path().join("capture");
    let mut stage = Stage::create(&destination).unwrap();
    stage
        .create_file("metadata.aosh")
        .unwrap()
        .write_all(b"partial-ciphertext")
        .unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("foreign"), b"preserve-foreign").unwrap();
    assert!(matches!(stage.publish(), Err(PublishError::BeforeRename)));
    drop(stage);
    assert_eq!(
        fs::read(destination.join("foreign")).unwrap(),
        b"preserve-foreign"
    );
    assert!(!fs::read_dir(f.directory.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".aos-snapshot-")));
}

#[test]
fn replaced_staging_name_never_publishes_or_removes_foreign_directory() {
    let f = fixture();
    let destination = f.directory.path().join("capture");
    let mut stage = Stage::create(&destination).unwrap();
    stage
        .create_file("metadata.aosh")
        .unwrap()
        .write_all(b"owned-ciphertext")
        .unwrap();
    let temporary = fs::read_dir(f.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".aos-snapshot-")
        })
        .unwrap();
    let moved = f.directory.path().join("retained-original");
    fs::rename(&temporary, &moved).unwrap();
    fs::create_dir(&temporary).unwrap();
    fs::write(temporary.join("foreign"), b"preserve-foreign").unwrap();

    assert!(matches!(stage.publish(), Err(PublishError::BeforeRename)));
    drop(stage);

    assert!(!destination.exists());
    assert_eq!(
        fs::read(temporary.join("foreign")).unwrap(),
        b"preserve-foreign"
    );
    assert!(!moved.join("metadata.aosh").exists());
}

#[test]
fn staging_fsync_failure_cleans_but_post_rename_failure_keeps_published_directory() {
    let f = fixture();
    let destination = f.directory.path().join("capture");
    let mut stage = Stage::create(&destination).unwrap();
    stage.create_file("metadata.aosh").unwrap();
    assert!(matches!(
        stage.publish_with_sync(|_| Err(rustix::io::Errno::IO)),
        Err(PublishError::BeforeRename)
    ));
    drop(stage);
    assert!(!destination.exists());

    let mut stage = Stage::create(&destination).unwrap();
    for name in filesystem::FILES {
        stage.create_file(name).unwrap();
    }
    let mut calls = 0;
    assert!(matches!(
        stage.publish_with_sync(|fd| {
            calls += 1;
            if calls == 2 {
                Err(rustix::io::Errno::IO)
            } else {
                rustix::fs::fsync(fd)
            }
        }),
        Err(PublishError::DurabilityUnconfirmed)
    ));
    drop(stage);
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 3);
    assert_eq!(
        SnapshotError::PublishedDurabilityUnconfirmed.to_string(),
        "snapshot directory published; durability was not confirmed"
    );
}

#[tokio::test]
async fn explicit_limits_and_cancellation_remove_incomplete_staging() {
    let f = fixture();
    let source = source(f.directory.path()).await;
    let destination = f.directory.path().join("capture");
    let tiny = SnapshotBudget::new(Duration::from_secs(120), 1).unwrap();
    assert!(matches!(
        workflow::capture(&source, &destination, &f.credentials, tiny).await,
        Err(SnapshotError::Capture)
    ));
    assert!(!destination.exists());
    assert!(!fs::read_dir(f.directory.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".aos-snapshot-")));
    let cancelled = budget();
    cancelled.cancel();
    assert!(matches!(
        workflow::capture(&source, &destination, &f.credentials, cancelled).await,
        Err(SnapshotError::Cancelled)
    ));
    assert!(!destination.exists());
    assert!(SnapshotBudget::new(Duration::ZERO, 1).is_err());
    assert!(SnapshotBudget::new(Duration::from_secs(86401), 1).is_err());
    assert!(SnapshotBudget::new(Duration::from_secs(1), 0).is_err());
    assert!(SnapshotBudget::new(Duration::from_secs(1), 64 * 1024 * 1024 * 1024 + 1).is_err());
}

#[tokio::test]
async fn actual_verification_requires_trusted_root_complete_eofs_and_exact_entries() {
    let f = fixture();
    let source = source(f.directory.path()).await;
    let destination = f.directory.path().join("capture");
    workflow::capture(&source, &destination, &f.credentials, budget())
        .await
        .unwrap();
    let reader = reader_credentials(&f);
    let private = destination.join("private.aosh");
    let original = fs::read(&private).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&private)
        .unwrap()
        .write_all(b"trailing-NEVER-PRINT")
        .unwrap();
    let error = workflow::verify(&destination, &reader, budget())
        .await
        .unwrap_err();
    assert!(matches!(error, SnapshotError::Verification));
    assert!(!format!("{error:?} {error}").contains("NEVER-PRINT"));
    assert!(destination.exists());
    fs::write(&private, &original[..original.len() - 1]).unwrap();
    assert!(workflow::verify(&destination, &reader, budget())
        .await
        .is_err());
    fs::write(&private, original).unwrap();
    private_file(&destination, "unexpected", b"NEVER-PRINT");
    assert!(workflow::verify(&destination, &reader, budget())
        .await
        .is_err());
    fs::remove_file(destination.join("unexpected")).unwrap();
    let signer = ArchiveSigningKey::from_seed("offline-export", [95; 32]).unwrap();
    fs::write(
        &reader.signer_trust_file,
        serde_json::to_vec(&json!({"version":1,"signers":[{
            "id":signer.id(),"ed25519_public_key_hex":hex::encode(signer.public_key())
        }]}))
        .unwrap(),
    )
    .unwrap();
    fs::remove_file(&reader.wrapping.metadata_file).unwrap();
    // Signature/trust failure wins before any wrapping key file is opened.
    assert!(matches!(
        workflow::verify(&destination, &reader, budget()).await,
        Err(SnapshotError::Verification)
    ));
}

#[tokio::test]
async fn literal_file_uri_filename_is_anchored_before_sqlite_open() {
    let f = fixture();
    let ordinary = source(f.directory.path()).await;
    let other = f.directory.path().join("other.db");
    fs::rename(ordinary, &other).unwrap();
    let literal = private_file(
        f.directory.path(),
        "file:other.db?mode=ro",
        &fs::read(&other).unwrap(),
    );
    let pool = SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(&literal))
        .await
        .unwrap();
    sqlx::raw_sql("UPDATE users SET email='literal@example.invalid' WHERE id=17")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let admitted = SourceAdmission::open(&literal).unwrap();
    assert_eq!(admitted.path, std::env::current_dir().unwrap().join(&literal));
    assert!(admitted.path.is_absolute());
    admitted.check_identity().unwrap();
    // A URI interpretation would wrongly open the other valid production DB.
    use aos_hub_core::backend::sqlite_snapshot::{SqliteSnapshotLimits, SqliteSnapshotReader};
    let mut reader = SqliteSnapshotReader::open(&admitted.path).await.unwrap();
    let email_column = reader
        .schema()
        .tables
        .iter()
        .find(|table| table.name == "users")
        .unwrap()
        .columns
        .iter()
        .position(|column| column == "email")
        .unwrap();
    let page = reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(
        page.rows[0].get::<String>(email_column).unwrap(),
        "literal@example.invalid"
    );
    let mut other_reader = SqliteSnapshotReader::open(&other).await.unwrap();
    let other_page = other_reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(
        other_page.rows[0].get::<String>(email_column).unwrap(),
        "fixture@example.invalid"
    );
    assert!(SourceAdmission::open_with_working_directory(
        Path::new("../other.db"),
        f.directory.path()
    )
    .is_err());
}

#[test]
fn replacement_during_directory_sync_is_rechecked_before_rename() {
    let f = fixture();
    let destination = f.directory.path().join("capture");
    let mut stage = Stage::create(&destination).unwrap();
    let temporary = fs::read_dir(f.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".aos-snapshot-")
        })
        .unwrap();
    let moved = f.directory.path().join("retained-original");
    let result = stage.publish_with_sync(|fd| {
        rustix::fs::fsync(fd)?;
        fs::rename(&temporary, &moved).unwrap();
        fs::create_dir(&temporary).unwrap();
        fs::write(temporary.join("foreign"), b"preserve-foreign").unwrap();
        Ok(())
    });
    assert!(matches!(result, Err(PublishError::BeforeRename)));
    drop(stage);
    assert!(!destination.exists());
    assert_eq!(
        fs::read(temporary.join("foreign")).unwrap(),
        b"preserve-foreign"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observed_cancellation_during_capture_cleans_unpublished_stage() {
    let f = fixture();
    let source = source(f.directory.path()).await;
    let destination = f.directory.path().join("capture");
    let budget = budget();
    let cancellation = budget.clone();
    let directory = f.directory.path().to_owned();
    let watcher = tokio::spawn(async move {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if fs::read_dir(&directory).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aos-snapshot-")
            }) {
                cancellation.cancel();
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::task::yield_now().await;
        }
    });
    let result = workflow::capture(&source, &destination, &f.credentials, budget).await;
    assert!(watcher.await.unwrap());
    assert!(matches!(result, Err(SnapshotError::Cancelled)));
    assert!(!destination.exists());
    assert!(!fs::read_dir(f.directory.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".aos-snapshot-")));
}

#[test]
fn archive_key_refuses_systemd_group_exception_without_changing_runtime_loader() {
    const CHILD_PATH: &str = "AOS_SNAPSHOT_TEST_PRIVATE_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let path = PathBuf::from(path);
        // The existing runtime policy deliberately admits systemd group read.
        assert_eq!(
            crate::auth::seal::read_secret_file_zeroizing(&path)
                .unwrap()
                .len(),
            32
        );
        assert!(crate::auth::seal::read_secret_file_zeroizing_capped(&path, 32).is_err());
        return;
    }
    let f = fixture();
    fs::set_permissions(
        &f.credentials.signing_seed_file,
        fs::Permissions::from_mode(0o440),
    )
    .unwrap();
    // A separate process avoids mutating process-wide environment during other
    // secret-policy tests while exercising the real context-dependent policy.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "snapshot::tests::archive_key_refuses_systemd_group_exception_without_changing_runtime_loader", "--nocapture"])
        .env(CHILD_PATH, &f.credentials.signing_seed_file)
        .env("CREDENTIALS_DIRECTORY", f.directory.path()).output().unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
}

#[path = "tests/constraints.rs"]
mod constraints;

#[test]
fn relative_source_custody_rechecks_private_ancestors_and_absolute_identity() {
    let f = fixture();
    let parent = f.directory.path().join("source-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let source = private_file(&parent, "source.db", b"original-source");
    let admitted = SourceAdmission::open(&source).unwrap();
    admitted.check_identity().unwrap();

    fs::set_permissions(&parent, fs::Permissions::from_mode(0o720)).unwrap();
    assert!(SourceAdmission::open(&source).is_err());
    assert!(admitted.check_identity().is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();

    let retained_parent = f.directory.path().join("retained-parent");
    fs::rename(&parent, &retained_parent).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&parent, "source.db", b"substitute-source");
    assert!(admitted.check_identity().is_err());

    let linked_parent = f.directory.path().join("linked-parent");
    symlink(&retained_parent, &linked_parent).unwrap();
    assert!(SourceAdmission::open(&linked_parent.join("source.db")).is_err());
}

#[test]
fn absolute_source_keeps_full_ancestor_custody_when_root_is_foreign() {
    use std::os::unix::fs::MetadataExt;

    let f = fixture();
    let source = private_file(f.directory.path(), "source.db", b"original-source");
    let relative = SourceAdmission::open(&source).unwrap();
    relative.check_identity().unwrap();
    let root_owner = fs::metadata("/").unwrap().uid();
    let absolute = std::env::current_dir().unwrap().join(&source);
    if root_owner != 0 && root_owner != rustix::process::geteuid().as_raw() {
        assert!(SourceAdmission::open(&absolute).is_err());
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires the dedicated disposable PostgreSQL 18 test source"]
async fn actual_postgres_capture_and_private_sqlite_readback_preserve_originals() {
    use aos_hub_core::backend::Backend;
    use aos_hub_core::snapshot::archive::records::verify_database_capture;
    use aos_hub_core::snapshot::archive::StreamLimits;
    use aos_hub_core::value::Value;

    let url_path =
        std::env::var_os("AOS_PG_SNAPSHOT_TEST_URL_FILE").expect("private disposable source URL");
    let url = fs::read(url_path).unwrap();
    let f = fixture();
    let connection_file = private_file(f.directory.path(), "postgres.url", &url);
    let bad_connection_file = private_file(
        f.directory.path(),
        "invalid-postgres.url",
        b"https://PRIVATE-URL-NEVER-PRINT.invalid/source",
    );
    let absent_output = f.directory.path().join("refused-postgres-capture");
    let refusal = workflow::capture_postgres(
        &bad_connection_file,
        &absent_output,
        &f.credentials,
        budget(),
    )
    .await
    .unwrap_err();
    assert!(matches!(refusal, SnapshotError::PostgresSource));
    assert!(!refusal.to_string().contains("PRIVATE-URL-NEVER-PRINT"));
    assert!(!absent_output.exists());
    fs::set_permissions(&connection_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        workflow::capture_postgres(&connection_file, &absent_output, &f.credentials, budget())
            .await
            .unwrap_err(),
        SnapshotError::PostgresSource
    ));
    assert!(!absent_output.exists());
    fs::set_permissions(&connection_file, fs::Permissions::from_mode(0o600)).unwrap();

    let backend = SqlxBackend::connect_postgres(std::str::from_utf8(&url).unwrap().trim())
        .await
        .unwrap();
    backend.migrate_schema().await.unwrap();
    let SqlxBackend::Postgres(pool) = backend else {
        panic!("PostgreSQL required")
    };
    sqlx::query("INSERT INTO users(id,email,display_name,created_at,password_hash) VALUES \
        (17017,'pg-original@snapshot.invalid','λ original\nname',9223372036854775807,'private-credential-PG-NEVER-PRINT')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO route_url_reservations(id,digest_scheme,reservation_key_version,reservation_digest,created_at) \
        VALUES ('snapshot-binary','hmac_sha256_v1',1,$1,1)")
        .bind(vec![7_u8; 32]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,last_authenticated_at) \
        VALUES ('pg-transient-NOT-EXPORTED',17017,1,1,2,1)").execute(&pool).await.unwrap();
    let destination = f.directory.path().join("postgres-capture");

    let captured =
        workflow::capture_postgres(&connection_file, &destination, &f.credentials, budget())
            .await
            .unwrap();
    let checked = workflow::verify(&destination, &reader_credentials(&f), budget())
        .await
        .unwrap();
    assert_eq!(captured.operation, "capture_postgres");
    assert_eq!(captured.source_engine, Some("postgresql"));
    assert_eq!(checked.source_engine, Some("postgresql"));
    assert_eq!(captured.tables, 279);
    assert_eq!(checked.retained_rows, captured.retained_rows);
    assert!(captured.private_cells > 0);
    assert_eq!(captured.signed_root_profile, "framing_only");
    assert_eq!(captured.verification_scope, "retained_sqlite_constraints");

    let custody = load_capture(&f.credentials).unwrap();
    let mut originals = Vec::new();
    let mut binary = Vec::new();
    let record_report = verify_database_capture(
        &fs::read(destination.join("archive.json")).unwrap(),
        &custody.trust,
        &custody.wrapping,
        &custody.exclusions,
        fs::File::open(destination.join("metadata.aosh")).unwrap(),
        fs::File::open(destination.join("private.aosh")).unwrap(),
        StreamLimits::default(),
        |table, _, row| {
            if table == "users" {
                row.with_private_row(|row| originals.push(row.clone()));
            }
            if table == "route_url_reservations" {
                row.with_private_row(|row| binary.push(row.clone()));
            }
            assert_ne!(table, "sessions");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        record_report.declared_source_audit().source_engine(),
        "postgresql"
    );
    assert_eq!(originals.len(), 1);
    assert_eq!(
        originals[0].value(2),
        Some(&Value::Text("λ original\nname".into()))
    );
    assert_eq!(originals[0].value(3), Some(&Value::Int(i64::MAX)));
    assert_eq!(
        originals[0].value(5),
        Some(&Value::Text("private-credential-PG-NEVER-PRINT".into()))
    );
    assert_eq!(binary[0].value(3), Some(&Value::Bytes(vec![7_u8; 32])));
    for name in filesystem::FILES {
        let bytes = fs::read(destination.join(name)).unwrap();
        for secret in [
            &url[..],
            b"private-credential-PG-NEVER-PRINT",
            b"pg-transient-NOT-EXPORTED",
        ] {
            assert!(!bytes.windows(secret.len()).any(|value| value == secret));
        }
    }
    let unchanged: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=17017")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(unchanged, "private-credential-PG-NEVER-PRINT");
    sqlx::query("DELETE FROM route_url_reservations WHERE id='snapshot-binary'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=17017")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[path = "inventory/tests.rs"]
mod object_requirements;
