//! Tests for schema-version matching, mismatch discard, and malformed-schema handling.

use super::*;

#[test]
fn matching_schema_preserves_payload_directories() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let node_file = sentinel(layout.nodes_dir().join("node"));
    let value_file = sentinel(layout.values_dir().join("value"));
    let file_file = sentinel(layout.files_dir().join("file"));

    PersistCache::open(&root).expect("matching schema opens");

    assert!(node_file.is_file());
    assert!(value_file.is_file());
    assert!(file_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn mismatched_schema_discards_payload_and_rewrites_version() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let node_file = sentinel(layout.nodes_dir().join("stale-node"));
    let value_file = sentinel(layout.values_dir().join("stale-value"));
    let file_file = sentinel(layout.files_dir().join("stale-file"));
    fs::write(
        layout.schema_path(),
        "format = \"aos-nix-eval-cache\"\nschema_version = 3\n",
    )
    .expect("schema downgrades");

    PersistCache::open(&root).expect("mismatched schema opens");

    assert!(!node_file.exists());
    assert!(!value_file.exists());
    assert!(!file_file.exists());
    assert!(layout.nodes_dir().is_dir());
    assert!(layout.values_dir().is_dir());
    assert!(layout.files_dir().is_dir());
    assert_eq!(
        fs::read_to_string(layout.schema_path()).expect("schema reads"),
        "format = \"aos-nix-eval-cache\"\nschema_version = 4\n"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn malformed_schema_errors_without_discarding_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let node_file = sentinel(layout.nodes_dir().join("node"));
    fs::write(layout.schema_path(), "schema_version =").expect("schema corrupts");

    let error = PersistCache::open(&root).expect_err("malformed schema errors");

    assert!(matches!(error, PersistError::ParseSchema { .. }));
    assert!(node_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn wrong_schema_format_errors_without_discarding_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));
    fs::write(
        layout.schema_path(),
        "format = \"other-cache\"\nschema_version = 4\n",
    )
    .expect("schema rewrites");

    let error = PersistCache::open(&root).expect_err("wrong format errors");

    assert!(matches!(error, PersistError::InvalidFormat { .. }));
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}
