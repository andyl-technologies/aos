//! Exercises actual per-pass full hashing without reusing callback currency.

// crucible-lint: allow panic-shortcut -- Exact original file and refusal controls.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::canonical;

#[test]
fn exact_aliases_share_only_this_pass_and_keep_each_namespace_fence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    let alias = directory.path().join("original-alias");
    let replacement = directory.path().join("replacement");
    let bytes = b"original complete body";
    std::fs::write(&path, bytes).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let mut selected = [(path.as_path(), &reference); 10];
    selected[9] = (alias.as_path(), &reference);
    let files = complete_byte_originals(&selected).unwrap();

    assert_eq!(files.read_current().unwrap(), 1);
    assert_eq!(files.read_current().unwrap(), 1);
    assert!(files.current().is_ok());

    std::fs::write(&replacement, bytes).unwrap();
    std::fs::rename(&replacement, &alias).unwrap();

    assert!(files.current().is_err());
    assert!(files.revoked.get());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn equal_bytes_in_distinct_inodes_require_separate_complete_measurements() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    let bytes = b"same complete bytes";
    std::fs::write(&first, bytes).unwrap();
    std::fs::write(&second, bytes).unwrap();
    assert_ne!(std::fs::metadata(&first).unwrap().ino(), std::fs::metadata(&second).unwrap().ino());
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let mut selected = [(first.as_path(), &reference); 10];
    selected[9] = (second.as_path(), &reference);
    let files = complete_byte_originals(&selected).unwrap();

    assert_eq!(files.read_current().unwrap(), 2);
    assert_eq!(files.read_current().unwrap(), 2);
    assert!(files.current().is_ok());
}

#[test]
fn same_inode_with_a_different_media_pin_requires_another_full_measurement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    let bytes = b"same inode and bytes";
    std::fs::write(&path, bytes).unwrap();
    let plain = canonical::content_ref(bytes, "text/plain").unwrap();
    let binary = canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let mut selected = [(path.as_path(), &plain); 10];
    selected[9] = (path.as_path(), &binary);
    let files = complete_byte_originals(&selected).unwrap();

    assert_eq!(files.read_current().unwrap(), 2);
    assert!(files.current().is_ok());
}

#[test]
fn alias_byte_drift_revokes_and_restoring_the_original_bytes_does_not_clear_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    let alias = directory.path().join("alias");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let mut selected = [(path.as_path(), &reference); 10];
    selected[9] = (alias.as_path(), &reference);
    let files = complete_byte_originals(&selected).unwrap();
    assert_eq!(files.read_current().unwrap(), 1);

    let writer = std::fs::File::options().write(true).open(&alias).unwrap();
    writer.write_all_at(b"source-two", 0).unwrap();
    assert!(files.current().is_err());
    writer.write_all_at(bytes, 0).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(files.current().is_err());
    assert!(files.revoked.get());
}
