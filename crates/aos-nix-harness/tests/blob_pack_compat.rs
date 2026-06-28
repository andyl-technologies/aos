//! Cross-crate blob pack format compatibility checks.
//!
//! These tests intentionally live outside `ratchet-oracle`, which forbids
//! unsafe code. They prove the safe oracle-side packfile adapters and the
//! unsafe-engine packfile code agree on the current packfile format.

use ratchet_cache::blob_pack::{BlobPackAppender, BlobPackHash, BlobPackLocation, MappedBlobPack};
use ratchet_oracle::cache::{DurableBlake3Hash, PersistBlobLocation, PersistBlobPack};

#[test]
fn oracle_blob_pack_writer_is_readable_by_mapped_engine_reader() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let pack_path = temp.path().join("values.pack");
    let pack = PersistBlobPack::open(&pack_path).expect("oracle pack opens");
    let first = b"first persistent payload".as_slice();
    let second = b"second persistent payload".as_slice();
    let first_hash = DurableBlake3Hash::for_bytes(first);
    let second_hash = DurableBlake3Hash::for_bytes(second);
    let first_location = pack
        .append_blob(first_hash, first)
        .expect("first payload appends through oracle writer");
    let second_location = pack
        .append_blob(second_hash, second)
        .expect("second payload appends through oracle writer");

    let file = std::fs::File::open(&pack_path).expect("pack opens read-only");
    let mapped = unsafe {
        // SAFETY: The test writes the pack completely through `PersistBlobPack`
        // before mapping it and performs no mutation while mapped payload
        // slices are alive.
        MappedBlobPack::map_file(&file)
    }
    .expect("mapped engine reader opens oracle pack");

    let first_payload = mapped
        .payload(
            BlobPackLocation::new(first_location.record_offset(), first_location.payload_len()),
            BlobPackHash::from_bytes(first_hash.as_bytes()),
        )
        .expect("first oracle payload reads through mapped engine");
    let second_payload = mapped
        .payload(
            BlobPackLocation::new(
                second_location.record_offset(),
                second_location.payload_len(),
            ),
            BlobPackHash::from_bytes(second_hash.as_bytes()),
        )
        .expect("second oracle payload reads through mapped engine");

    assert_eq!(first_payload.as_bytes(), first);
    assert_eq!(second_payload.as_bytes(), second);
}

#[test]
fn engine_blob_pack_appender_is_readable_by_oracle_reader() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let pack_path = temp.path().join("values.pack");
    let appender = BlobPackAppender::open(&pack_path).expect("engine appender opens");
    let first = b"first engine payload".as_slice();
    let second = b"second engine payload".as_slice();
    let first_hash = BlobPackHash::for_bytes(first);
    let second_hash = BlobPackHash::for_bytes(second);
    let first_location = appender
        .append_payload(first_hash, first)
        .expect("first payload appends through engine writer");
    let second_location = appender
        .append_payload(second_hash, second)
        .expect("second payload appends through engine writer");

    let pack = PersistBlobPack::open(&pack_path).expect("oracle pack opens engine pack");
    let first_payload = pack
        .read_blob(
            PersistBlobLocation::new(first_location.record_offset(), first_location.payload_len()),
            DurableBlake3Hash::from_bytes(first_hash.as_bytes()),
        )
        .expect("first engine payload reads through oracle");
    let second_payload = pack
        .read_blob(
            PersistBlobLocation::new(
                second_location.record_offset(),
                second_location.payload_len(),
            ),
            DurableBlake3Hash::from_bytes(second_hash.as_bytes()),
        )
        .expect("second engine payload reads through oracle");

    assert_eq!(first_payload.as_slice(), first);
    assert_eq!(second_payload.as_slice(), second);
}
