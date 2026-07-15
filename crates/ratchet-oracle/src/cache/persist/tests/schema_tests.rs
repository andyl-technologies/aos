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
        "format = \"aos-nix-eval-cache\"\nschema_version = 4\n",
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
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"blake3\"\n"
        )
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn mismatched_schema_discards_payload_symlink_without_following() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let external = root.join("external-nodes");
    let external_file = sentinel(external.join("keep"));
    fs::remove_dir_all(layout.nodes_dir()).expect("nodes dir removes");
    std::os::unix::fs::symlink(&external, layout.nodes_dir()).expect("nodes symlink creates");
    fs::write(
        layout.schema_path(),
        "format = \"aos-nix-eval-cache\"\nschema_version = 4\n",
    )
    .expect("schema downgrades");

    PersistCache::open(&root).expect("mismatched schema opens");

    assert!(external_file.is_file());
    assert!(layout.nodes_dir().is_dir());
    assert!(
        !fs::symlink_metadata(layout.nodes_dir())
            .expect("nodes metadata reads")
            .file_type()
            .is_symlink()
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
        format!("format = \"other-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\n"),
    )
    .expect("schema rewrites");

    let error = PersistCache::open(&root).expect_err("wrong format errors");

    assert!(matches!(error, PersistError::InvalidFormat { .. }));
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn missing_schema_format_errors_without_discarding_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));
    fs::write(
        layout.schema_path(),
        format!("schema_version = {PERSIST_CACHE_SCHEMA_VERSION}\n"),
    )
    .expect("schema rewrites");

    let error = PersistCache::open(&root).expect_err("missing format errors");

    assert!(matches!(error, PersistError::MissingFormat { .. }));
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn missing_schema_version_errors_without_discarding_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));
    fs::write(layout.schema_path(), "format = \"aos-nix-eval-cache\"\n").expect("schema rewrites");

    let error = PersistCache::open(&root).expect_err("missing version errors");

    assert!(matches!(error, PersistError::MissingSchemaVersion { .. }));
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn fresh_open_records_process_hash_family_and_keeps_it_on_reopen() {
    use crate::cache::hashing::CacheHashFamily;

    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    // The test process leaves AOS_NIX_CACHE_HASH unset, so the process family is
    // the BLAKE3 default and a fresh root self-describes as BLAKE3.
    assert_eq!(cache.hash_family(), CacheHashFamily::Blake3);
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));

    let reopened = PersistCache::open(&root).expect("matching family reopens");
    assert_eq!(reopened.hash_family(), CacheHashFamily::Blake3);
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn recorded_family_mismatch_discards_payload_and_rewrites_family() {
    use crate::cache::hashing::CacheHashFamily;

    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("stale-value"));
    // Re-stamp the manifest as an xxh128 root at the current schema version. The
    // process family is BLAKE3, so the recorded data is unreadable and the open
    // must discard it and re-key the manifest under the process family.
    fs::write(
        layout.schema_path(),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"xxh128\"\n"
        ),
    )
    .expect("schema re-stamps");

    let reopened = PersistCache::open(&root).expect("family mismatch reopens");

    assert_eq!(reopened.hash_family(), CacheHashFamily::Blake3);
    assert!(!value_file.exists());
    assert_eq!(
        fs::read_to_string(layout.schema_path()).expect("schema reads"),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"blake3\"\n"
        )
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn legacy_family_less_manifest_is_kept_and_upgraded_under_blake3() {
    use crate::cache::hashing::CacheHashFamily;

    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));
    // Downgrade the manifest to the pre-per-layer, family-less form at the
    // current schema version. A BLAKE3 process reads such a root (its data is
    // the historical BLAKE3 default), keeps the payload, and upgrades the
    // manifest to self-describe.
    fs::write(
        layout.schema_path(),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\n"
        ),
    )
    .expect("schema downgrades");

    let reopened = PersistCache::open(&root).expect("legacy manifest reopens");

    assert_eq!(reopened.hash_family(), CacheHashFamily::Blake3);
    assert!(value_file.is_file());
    assert_eq!(
        fs::read_to_string(layout.schema_path()).expect("schema reads"),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"blake3\"\n"
        )
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn secondary_open_preserves_foreign_family_payload() {
    use crate::cache::hashing::CacheHashFamily;

    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("shared-value"));
    // Mark the root as a foreign (xxh128) family. Opened as a secondary it must
    // report that family and keep the shared payload untouched — a
    // differently-configured reader never wipes safe-to-lose read capacity.
    fs::write(
        layout.schema_path(),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"xxh128\"\n"
        ),
    )
    .expect("schema re-stamps");

    let secondary = PersistCache::open_secondary(&root).expect("secondary opens");

    assert_eq!(secondary.hash_family(), CacheHashFamily::Xxh128);
    assert!(value_file.is_file());
    // The manifest is left exactly as recorded; a secondary never rewrites it.
    assert_eq!(
        fs::read_to_string(layout.schema_path()).expect("schema reads"),
        format!(
            "format = \"aos-nix-eval-cache\"\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\nhash_family = \"xxh128\"\n"
        )
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn unsupported_schema_version_errors_without_discarding_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let value_file = sentinel(layout.values_dir().join("value"));
    fs::write(
        layout.schema_path(),
        "format = \"aos-nix-eval-cache\"\nschema_version = -1\n",
    )
    .expect("schema rewrites");

    let error = PersistCache::open(&root).expect_err("unsupported version errors");

    assert!(matches!(
        error,
        PersistError::InvalidSchemaVersion { version: -1, .. }
    ));
    assert!(value_file.is_file());

    let _ = fs::remove_dir_all(root);
}
