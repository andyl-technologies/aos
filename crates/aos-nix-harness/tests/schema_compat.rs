//! Cross-crate persistent schema sidecar compatibility checks.
//!
//! These tests prove the safe oracle cache root and the cache-engine schema
//! primitive agree on the current `schema.toml` format marker and version.

use ratchet_cache::schema::CacheSchema;
use ratchet_oracle::cache::{PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION, PersistCache};

#[test]
fn oracle_schema_writer_is_readable_by_engine_reader() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    PersistCache::open(temp.path()).expect("oracle cache opens");
    let schema = CacheSchema::new(temp.path().join("schema.toml"));

    assert_eq!(
        schema
            .read_version(PERSIST_CACHE_FORMAT)
            .expect("engine schema reads oracle schema"),
        Some(PERSIST_CACHE_SCHEMA_VERSION)
    );
}

#[test]
fn engine_schema_writer_is_readable_by_oracle_open() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let schema = CacheSchema::new(temp.path().join("schema.toml"));
    schema
        .write_version(PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION)
        .expect("engine schema writes");

    PersistCache::open(temp.path()).expect("oracle opens engine schema");
}
