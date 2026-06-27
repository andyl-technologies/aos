//! Cross-crate blob pack format compatibility checks.
//!
//! These tests intentionally live outside `ratchet-oracle`, which forbids
//! unsafe code. They prove the safe oracle-side buffered writer and the
//! unsafe-engine mapped reader agree on the current packfile format.

use ratchet_cache::blob_pack::{BlobPackHash, BlobPackLocation, MappedBlobPack};
use ratchet_oracle::cache::{DurableBlake3Hash, PersistBlobPack};

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
