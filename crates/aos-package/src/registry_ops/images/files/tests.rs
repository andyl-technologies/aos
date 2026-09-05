//! Tests for pinned image files, bounded decompression, and stable filesystem identity checks.

use super::{
    decompress_pinned_raw_disk, decompress_raw_disk, open_stable_regular_file_with_links,
    sha256_open_file, validate_single_filename,
};
use std::fs;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn portable_filename_accepts_sd_boot_counting_suffix() {
    validate_single_filename("aos-server-2026.08+3.efi", "UKI filename")
        .expect("sd-boot counting filename");
}

#[cfg(unix)]
#[test]
fn stable_file_open_allows_store_optimizer_links_after_store_validation() {
    let temp = TempDir::new().unwrap();
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, b"immutable store bytes").unwrap();
    fs::hard_link(&artifact, temp.path().join("store-optimizer-link")).unwrap();

    assert!(open_stable_regular_file_with_links(&artifact, false).is_err());
    assert!(open_stable_regular_file_with_links(&artifact, true).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn compressed_raw_materialization_enforces_exact_logical_size() {
    let logical = b"canonical raw disk bytes";
    let compressed = zstd::stream::encode_all(&logical[..], 1).unwrap();

    let mut output = Vec::new();
    decompress_raw_disk(&compressed[..], &mut output, logical.len() as u64).unwrap();
    assert_eq!(output, logical);

    assert!(
        decompress_raw_disk(&compressed[..], &mut Vec::new(), logical.len() as u64 - 1).is_err()
    );
    assert!(
        decompress_raw_disk(&compressed[..], &mut Vec::new(), logical.len() as u64 + 1).is_err()
    );
    assert!(
        decompress_raw_disk(
            &compressed[..compressed.len() - 1],
            &mut Vec::new(),
            logical.len() as u64,
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn pinned_raw_materialization_rewinds_after_hashing() {
    let logical = b"canonical raw disk bytes";
    let compressed = zstd::stream::encode_all(&logical[..], 1).unwrap();
    let mut pinned = tempfile::tempfile().unwrap();
    pinned.write_all(&compressed).unwrap();
    pinned.seek(SeekFrom::Start(0)).unwrap();
    sha256_open_file(&mut pinned, Path::new("<compressed test image>")).unwrap();

    let mut output = Vec::new();
    decompress_pinned_raw_disk(&pinned, &mut output, logical.len() as u64).unwrap();

    assert_eq!(output, logical);
}
