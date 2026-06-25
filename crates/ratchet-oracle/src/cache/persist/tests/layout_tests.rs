//! Tests for cache-root layout creation and corruption handling.

use super::*;

#[test]
fn open_creates_versioned_layout() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout();

    assert_eq!(layout.root(), root.as_path());
    assert!(layout.nodes_dir().is_dir());
    assert!(layout.values_dir().is_dir());
    assert!(layout.files_dir().is_dir());
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
        "format = \"aos-nix-eval-cache\"\nschema_version = 3\n"
    );

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
