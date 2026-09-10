//! Campaign-store leaf equivalence gate.
//!
//! The gate applies one shared semantic contract to every local immutable
//! implementation and to every local mutable-ref implementation. S3-compatible
//! leaves use the same contract in `crucible-s3-store`'s live conformance target.

// crucible-lint: allow panic-shortcut -- gate assertions identify the violated backend contract.
#![allow(clippy::expect_used)]

use crucible_cas::content_store::conformance::{
    assert_blob_leaf_conformance, assert_blob_leaf_conformance_with_durability,
    assert_ref_leaf_conformance,
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, MemoryBlobBackend, MemoryRefBackend,
    PackedBlobBackend,
};
use tempfile::TempDir;

const CONFORMANCE_CAPACITY: u64 = 4 * 1024 * 1024;
const PACK_TARGET_BYTES: u64 = 64 * 1024;

#[test]
fn local_store_leaves_share_their_declared_semantics() {
    let temporary = TempDir::new().expect("campaign-store equivalence roots");

    let memory_blobs = MemoryBlobBackend::new("equivalence-memory", CONFORMANCE_CAPACITY);
    assert_blob_leaf_conformance_with_durability(&memory_blobs, false);

    let memory_refs = MemoryRefBackend::new();
    assert_ref_leaf_conformance(&memory_refs);

    let directory_blobs =
        DirectoryBlobBackend::new("equivalence-directory", temporary.path().join("directory"));
    assert_blob_leaf_conformance(&directory_blobs);

    let directory_refs = DirectoryRefBackend::new(temporary.path().join("refs"));
    assert_ref_leaf_conformance(&directory_refs);

    let packed = PackedBlobBackend::open(
        "equivalence-packed",
        temporary.path().join("packed"),
        PACK_TARGET_BYTES,
    )
    .expect("open packed conformance leaf");
    assert_blob_leaf_conformance(&packed);
}
