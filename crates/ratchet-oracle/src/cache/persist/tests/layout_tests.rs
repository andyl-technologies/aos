//! Tests for cache-root layout creation and corruption handling.

use super::*;
use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockError, AdvisoryFileLockMode};
use std::io::ErrorKind;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn open_creates_versioned_layout() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout();

    assert_eq!(
        layout.root(),
        fs::canonicalize(&root)
            .expect("root canonicalizes")
            .as_path()
    );
    assert!(layout.nodes_dir().is_dir());
    assert!(layout.values_dir().is_dir());
    assert!(layout.files_dir().is_dir());
    assert_eq!(
        layout.open_lock_path(),
        layout.locks_dir().join("open.lock")
    );
    assert_eq!(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        layout.locks_dir().join("values.lock")
    );
    assert_eq!(
        layout.blob_store_lock_path(PersistBlobStore::Files),
        layout.locks_dir().join("files.lock")
    );
    assert_eq!(
        layout.file_artifact_lock_path(),
        layout.locks_dir().join("file-artifacts.lock")
    );
    assert_eq!(
        layout.parse_artifact_lock_path(),
        layout.locks_dir().join("parse-artifacts.lock")
    );
    assert_eq!(
        layout.node_metadata_lock_path(),
        layout.locks_dir().join("node-metadata.lock")
    );
    assert_eq!(
        layout.node_traces_lock_path(),
        layout.locks_dir().join("node-traces.lock")
    );
    assert!(layout.open_lock_path().is_file());
    assert_eq!(cache.value_pack().path(), layout.value_packfile_path());
    assert_eq!(cache.file_pack().path(), layout.file_packfile_path());
    assert_eq!(cache.value_index().path(), layout.value_index_path());
    assert_eq!(cache.file_index().path(), layout.file_index_path());
    assert_eq!(
        cache.file_artifact_index().path(),
        layout.file_artifact_index_path()
    );
    assert_eq!(
        cache.parse_artifact_index().path(),
        layout.parse_artifact_index_path()
    );
    assert_eq!(
        cache.node_metadata_index().path(),
        layout.node_metadata_index_path()
    );
    assert_eq!(
        cache.blob_pack(PersistBlobStore::Values).path(),
        layout.value_packfile_path()
    );
    assert_eq!(
        cache.blob_pack(PersistBlobStore::Files).path(),
        layout.file_packfile_path()
    );
    assert_eq!(
        cache.blob_index(PersistBlobStore::Values).path(),
        layout.value_index_path()
    );
    assert_eq!(
        cache.blob_index(PersistBlobStore::Files).path(),
        layout.file_index_path()
    );
    assert_eq!(
        fs::read(layout.value_packfile_path())
            .expect("value pack header reads")
            .as_slice(),
        PersistBlobPackHeader::current().encode().as_slice()
    );
    assert_eq!(
        fs::read(layout.file_packfile_path())
            .expect("file pack header reads")
            .as_slice(),
        PersistBlobPackHeader::current().encode().as_slice()
    );
    assert_eq!(
        fs::metadata(layout.value_index_path())
            .expect("value index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(layout.file_index_path())
            .expect("file index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(layout.file_artifact_index_path())
            .expect("file artifact index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(layout.parse_artifact_index_path())
            .expect("parse artifact index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(layout.node_metadata_index_path())
            .expect("node metadata index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::read_to_string(layout.schema_path()).expect("schema reads"),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"blake3\"\n"
        )
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn opened_cache_layout_uses_canonical_paths_after_symlink_retarget() {
    let root = temp_root();
    let first = root.join("first");
    let second = root.join("second");
    let link = root.join("cache-link");
    fs::create_dir_all(&first).expect("first target creates");
    fs::create_dir_all(&second).expect("second target creates");
    std::os::unix::fs::symlink(&first, &link).expect("cache symlink creates");

    let first_cache = PersistCache::open(&link).expect("first symlink cache opens");
    let first_canonical = fs::canonicalize(&first).expect("first target canonicalizes");
    assert_eq!(first_cache.layout().root(), first_canonical.as_path());
    assert!(
        first_cache
            .value_pack()
            .path()
            .starts_with(&first_canonical)
    );

    fs::remove_file(&link).expect("cache symlink removes");
    std::os::unix::fs::symlink(&second, &link).expect("cache symlink retargets");
    let second_cache = PersistCache::open(&link).expect("second symlink cache opens");
    let second_canonical = fs::canonicalize(&second).expect("second target canonicalizes");
    assert_eq!(second_cache.layout().root(), second_canonical.as_path());
    assert!(
        second_cache
            .value_pack()
            .path()
            .starts_with(&second_canonical)
    );

    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    first_cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("first target materializes");
    second_cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("second target materializes");

    assert_eq!(
        first_cache
            .value_pack()
            .records()
            .expect("first pack records")
            .len(),
        1
    );
    assert_eq!(
        second_cache
            .value_pack()
            .records()
            .expect("second pack records")
            .len(),
        1
    );

    let _ = fs::remove_dir_all(root);
}

fn wait_until_advisory_open_try_lock_blocks(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match AdvisoryFileLock::try_lock(path, AdvisoryFileLockMode::Exclusive) {
            Ok(lock) => drop(lock),
            Err(AdvisoryFileLockError::Lock { source, .. })
                if source.kind() == ErrorKind::WouldBlock =>
            {
                return;
            }
            Err(error) => panic!("advisory open lock probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "opener did not acquire advisory open lock before the deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn open_acquires_advisory_open_lock_before_same_process_open_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let same_process_open_guard = cache
        .lock_open_for_tests()
        .expect("same-process open lock acquires");
    let (tx, rx) = mpsc::channel();
    let open_root = root.clone();

    let opener = thread::spawn(move || {
        let result = PersistCache::open(&open_root)
            .map(|cache| cache.layout().open_lock_path().is_file())
            .map_err(|error| error.to_string());
        tx.send(result).expect("open result sends");
    });

    wait_until_advisory_open_try_lock_blocks(&layout.open_lock_path());
    drop(same_process_open_guard);

    let opened = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("open completes after same-process lock release")
        .expect("cache opens");
    assert!(opened);
    opener.join().expect("opener joins");
    let released_lock =
        AdvisoryFileLock::try_lock(layout.open_lock_path(), AdvisoryFileLockMode::Exclusive)
            .expect("advisory open lock releases after open");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn open_reports_poisoned_live_same_root_initialization_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = cache.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = poison_cache
            .lock_open_for_tests()
            .expect("open lock acquires");
        panic!("poison persistent root open lock");
    });
    assert!(poisoner.join().is_err());

    let error = PersistCache::open(&root).expect_err("poisoned open lock rejects reopen");
    assert!(matches!(error, PersistError::RootOpenLockPoisoned));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_blob_pack_errors_without_rewriting() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    fs::write(layout.value_packfile_path(), b"bad").expect("value pack corrupts");

    let error = PersistCache::open(&root).expect_err("corrupt value pack errors");

    assert!(matches!(
        error,
        PersistError::OpenBlobPack {
            source: PersistBlobPackError::Format {
                source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fs::read(layout.value_packfile_path())
            .expect("corrupt pack reads")
            .as_slice(),
        b"bad"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_blob_index_errors_without_rewriting() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    fs::write(layout.value_index_path(), b"partial").expect("value index corrupts");

    let error = PersistCache::open(&root).expect_err("corrupt value index errors");

    assert!(matches!(
        error,
        PersistError::OpenBlobIndex {
            source: PersistBlobIndexError::Format {
                source: PersistPackFormatError::ShortBlobIndexEntry { actual: 7, .. },
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fs::read(layout.value_index_path())
            .expect("corrupt index reads")
            .as_slice(),
        b"partial"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_file_artifact_index_errors_without_rewriting() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    fs::write(layout.file_artifact_index_path(), b"partial").expect("file artifact index corrupts");

    let error = PersistCache::open(&root).expect_err("corrupt file artifact index errors");

    assert!(matches!(
        error,
        PersistError::OpenFileArtifactIndex {
            source: PersistFileArtifactIndexError::Format {
                source: PersistPackFormatError::ShortFileArtifactIndexEntry { actual: 7, .. },
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fs::read(layout.file_artifact_index_path())
            .expect("corrupt index reads")
            .as_slice(),
        b"partial"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_parse_artifact_index_errors_without_rewriting() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    fs::write(layout.parse_artifact_index_path(), b"partial")
        .expect("parse artifact index corrupts");

    let error = PersistCache::open(&root).expect_err("corrupt parse artifact index errors");

    assert!(matches!(
        error,
        PersistError::OpenParseArtifactIndex {
            source: PersistParseArtifactIndexError::Format {
                source: PersistPackFormatError::ShortParseArtifactIndexEntry { actual: 7, .. },
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fs::read(layout.parse_artifact_index_path())
            .expect("corrupt index reads")
            .as_slice(),
        b"partial"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_node_metadata_index_errors_without_rewriting() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    fs::write(layout.node_metadata_index_path(), b"partial").expect("node metadata index corrupts");

    let error = PersistCache::open(&root).expect_err("corrupt node metadata index errors");

    assert!(matches!(
        error,
        PersistError::OpenNodeMetadataIndex {
            source: PersistNodeMetadataIndexError::Format {
                source: PersistPackFormatError::ShortNodeMetadataIndexEntry { actual: 7, .. },
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fs::read(layout.node_metadata_index_path())
            .expect("corrupt index reads")
            .as_slice(),
        b"partial"
    );

    let _ = fs::remove_dir_all(root);
}
