//! Cross-crate blob index format compatibility checks.
//!
//! These tests prove the safe oracle-side typed sidecar wrapper and the
//! engine-side generic fixed-record sidecar wrapper agree on the current
//! hash-to-offset index format.

use ratchet_cache::blob_index::{BlobIndex, BlobIndexEntry, BlobIndexKey, BlobIndexNamespace};
use ratchet_cache::blob_pack::{BlobPackHash, BlobPackLocation};
use ratchet_oracle::cache::{
    DurableBlake3Hash, PersistBlobIndex, PersistBlobIndexEntry, PersistBlobIndexError,
    PersistBlobKey, PersistBlobLocation, PersistBlobStore, PersistPackFormatError,
};

const VALUES: BlobIndexNamespace = BlobIndexNamespace::from_tag(1);
const FILES: BlobIndexNamespace = BlobIndexNamespace::from_tag(2);

#[test]
fn oracle_blob_index_writer_is_readable_by_engine_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("values.index");
    let oracle = PersistBlobIndex::open(&index_path).expect("oracle index opens");
    let value_hash = DurableBlake3Hash::for_bytes(b"value payload");
    let file_hash = DurableBlake3Hash::for_bytes(b"file payload");
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, value_hash);
    let file_key = PersistBlobKey::for_file(file_hash);
    let value_location = PersistBlobLocation::new(24, 13);
    let file_location = PersistBlobLocation::new(77, 12);

    oracle
        .append_entry(PersistBlobIndexEntry::new(value_key, value_location))
        .expect("value entry appends through oracle");
    oracle
        .append_entry(PersistBlobIndexEntry::new(file_key, file_location))
        .expect("file entry appends through oracle");

    let engine = BlobIndex::open(&index_path).expect("engine index opens oracle sidecar");

    assert_eq!(
        engine
            .lookup(BlobIndexKey::new(
                VALUES,
                BlobPackHash::from_bytes(value_hash.as_bytes())
            ))
            .expect("value lookup succeeds through engine"),
        Some(BlobPackLocation::new(
            value_location.record_offset(),
            value_location.payload_len()
        ))
    );
    assert_eq!(
        engine
            .lookup(BlobIndexKey::new(
                FILES,
                BlobPackHash::from_bytes(file_hash.as_bytes())
            ))
            .expect("file lookup succeeds through engine"),
        Some(BlobPackLocation::new(
            file_location.record_offset(),
            file_location.payload_len()
        ))
    );
}

#[test]
fn engine_blob_index_writer_is_readable_by_oracle_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("values.index");
    let engine = BlobIndex::open(&index_path).expect("engine index opens");
    let value_hash = BlobPackHash::for_bytes(b"engine value payload");
    let file_hash = BlobPackHash::for_bytes(b"engine file payload");
    let value_location = BlobPackLocation::new(24, 20);
    let file_location = BlobPackLocation::new(84, 19);

    engine
        .append_entry(BlobIndexEntry::new(
            BlobIndexKey::new(VALUES, value_hash),
            value_location,
        ))
        .expect("value entry appends through engine");
    engine
        .append_entry(BlobIndexEntry::new(
            BlobIndexKey::new(FILES, file_hash),
            file_location,
        ))
        .expect("file entry appends through engine");

    let oracle = PersistBlobIndex::open(&index_path).expect("oracle index opens engine sidecar");

    assert_eq!(
        oracle
            .lookup(PersistBlobKey::new(
                PersistBlobStore::Values,
                DurableBlake3Hash::from_bytes(value_hash.as_bytes())
            ))
            .expect("value lookup succeeds through oracle"),
        Some(PersistBlobLocation::new(
            value_location.record_offset(),
            value_location.payload_len()
        ))
    );
    assert_eq!(
        oracle
            .lookup(PersistBlobKey::for_file(DurableBlake3Hash::from_bytes(
                file_hash.as_bytes()
            )))
            .expect("file lookup succeeds through oracle"),
        Some(PersistBlobLocation::new(
            file_location.record_offset(),
            file_location.payload_len()
        ))
    );
}

#[test]
fn oracle_rejects_engine_sidecar_with_unknown_namespace() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("values.index");
    let engine = BlobIndex::open(&index_path).expect("engine index opens");
    engine
        .append_entry(BlobIndexEntry::new(
            BlobIndexKey::new(
                BlobIndexNamespace::from_tag(99),
                BlobPackHash::for_bytes(b"invalid namespace payload"),
            ),
            BlobPackLocation::new(24, 25),
        ))
        .expect("generic engine accepts unknown namespace");
    let oracle = PersistBlobIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(PersistBlobKey::new(
            PersistBlobStore::Values,
            DurableBlake3Hash::for_bytes(b"missing payload"),
        ))
        .expect_err("oracle rejects invalid namespace during scan");

    assert!(matches!(
        error,
        PersistBlobIndexError::Format {
            source: PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 },
            ..
        }
    ));
}
