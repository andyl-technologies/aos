//! Cross-crate frontend artifact index format compatibility checks.
//!
//! These tests prove the safe oracle-side typed file/parse artifact wrappers
//! and the engine-side generic fixed-record sidecar wrapper agree on the
//! current artifact mapping index format.

use ratchet_cache::artifact_index::{
    ArtifactIndex, ArtifactIndexEntry, ArtifactIndexKey, ArtifactIndexValue,
};
use ratchet_oracle::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, PERSIST_BLOB_INDEX_KEY_LEN, ParseCacheFlags,
    ParseCacheKey, ParseFileKey, PersistBlobKey, PersistBlobLocation, PersistFileArtifactIndex,
    PersistFileArtifactIndexEntry, PersistFileArtifactIndexError, PersistFileArtifactIndexValue,
    PersistFileArtifactKey, PersistPackFormatError, PersistParseArtifactIndex,
    PersistParseArtifactIndexEntry, PersistParseArtifactIndexError, PersistParseArtifactIndexValue,
    PersistParseArtifactKey,
};

fn engine_key_from_file_key(key: PersistFileArtifactKey) -> ArtifactIndexKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    ArtifactIndexKey::new(encoded[0], digest)
}

fn engine_key_from_parse_key(key: PersistParseArtifactKey) -> ArtifactIndexKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    ArtifactIndexKey::new(encoded[0], digest)
}

fn engine_value_from_file_value(value: PersistFileArtifactIndexValue) -> ArtifactIndexValue {
    ArtifactIndexValue::from_bytes(value.encode_index_value())
}

fn engine_value_from_parse_value(value: PersistParseArtifactIndexValue) -> ArtifactIndexValue {
    ArtifactIndexValue::from_bytes(value.encode_index_value())
}

fn parse_key(source: &[u8]) -> ParseCacheKey {
    ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags::new())
}

fn file_key(source: &[u8]) -> PersistFileArtifactKey {
    let parse_key = parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key)
}

fn parse_artifact_key(source: &[u8]) -> PersistParseArtifactKey {
    PersistParseArtifactKey::from_parse_cache_key(parse_key(source))
}

fn file_value(name: &[u8], offset: u64) -> PersistFileArtifactIndexValue {
    PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(name),
        PersistBlobLocation::new(offset, name.len() as u64),
    )
}

fn parse_value(name: &[u8], offset: u64) -> PersistParseArtifactIndexValue {
    PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(name),
        PersistBlobLocation::new(offset, name.len() as u64),
    )
}

#[test]
fn oracle_file_artifact_writer_is_readable_by_engine_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("file-artifacts.index");
    let oracle = PersistFileArtifactIndex::open(&index_path).expect("oracle index opens");
    let key = file_key(b"let x = 1; in x");
    let value = file_value(b"oracle file artifact", 24);

    oracle
        .append_entry(PersistFileArtifactIndexEntry::new(key, value))
        .expect("file artifact entry appends through oracle");

    let engine = ArtifactIndex::open(&index_path).expect("engine index opens oracle sidecar");

    assert_eq!(
        engine
            .lookup(engine_key_from_file_key(key))
            .expect("engine lookup succeeds"),
        Some(engine_value_from_file_value(value))
    );
}

#[test]
fn engine_file_artifact_writer_is_readable_by_oracle_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("file-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = file_key(b"let x = 2; in x");
    let value = file_value(b"engine file artifact", 42);

    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_file_key(key),
            engine_value_from_file_value(value),
        ))
        .expect("file artifact entry appends through engine");

    let oracle = PersistFileArtifactIndex::open(&index_path).expect("oracle index opens");

    assert_eq!(
        oracle
            .lookup(key)
            .expect("oracle lookup succeeds through engine sidecar"),
        Some(value)
    );
}

#[test]
fn oracle_parse_artifact_writer_is_readable_by_engine_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("parse-artifacts.index");
    let oracle = PersistParseArtifactIndex::open(&index_path).expect("oracle index opens");
    let key = parse_artifact_key(b"let x = 1; in x");
    let value = parse_value(b"oracle parse artifact", 24);

    oracle
        .append_entry(PersistParseArtifactIndexEntry::new(key, value))
        .expect("parse artifact entry appends through oracle");

    let engine = ArtifactIndex::open(&index_path).expect("engine index opens oracle sidecar");

    assert_eq!(
        engine
            .lookup(engine_key_from_parse_key(key))
            .expect("engine lookup succeeds"),
        Some(engine_value_from_parse_value(value))
    );
}

#[test]
fn engine_parse_artifact_writer_is_readable_by_oracle_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("parse-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = parse_artifact_key(b"let x = 2; in x");
    let value = parse_value(b"engine parse artifact", 42);

    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_parse_key(key),
            engine_value_from_parse_value(value),
        ))
        .expect("parse artifact entry appends through engine");

    let oracle = PersistParseArtifactIndex::open(&index_path).expect("oracle index opens");

    assert_eq!(
        oracle
            .lookup(key)
            .expect("oracle lookup succeeds through engine sidecar"),
        Some(value)
    );
}

#[test]
fn oracle_rejects_engine_file_artifact_sidecar_with_unknown_namespace() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("file-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = file_key(b"valid file artifact");
    let value = file_value(b"value", 24);
    engine
        .append_entry(ArtifactIndexEntry::new(
            ArtifactIndexKey::new(99, DurableBlake3Hash::for_bytes(b"generic").as_bytes()),
            engine_value_from_file_value(value),
        ))
        .expect("generic engine accepts unknown namespace");
    let oracle = PersistFileArtifactIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle rejects unknown file-artifact namespace");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 },
            ..
        }
    ));
}

#[test]
fn oracle_rejects_engine_parse_artifact_sidecar_with_unknown_namespace() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("parse-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = parse_artifact_key(b"valid parse artifact");
    let value = parse_value(b"value", 24);
    engine
        .append_entry(ArtifactIndexEntry::new(
            ArtifactIndexKey::new(99, DurableBlake3Hash::for_bytes(b"generic").as_bytes()),
            engine_value_from_parse_value(value),
        ))
        .expect("generic engine accepts unknown namespace");
    let oracle =
        PersistParseArtifactIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle rejects unknown parse-artifact namespace");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidParseArtifactIndexTag { tag: 99 },
            ..
        }
    ));
}

#[test]
fn oracle_rejects_stale_malformed_engine_file_artifact_value() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("file-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = file_key(b"file artifact");
    let latest_value = file_value(b"latest file artifact", 99);
    let mut malformed_stale = file_value(b"stale file artifact", 24).encode_index_value();
    malformed_stale[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(
        &PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"wrong store")).index_bytes(),
    );

    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_file_key(key),
            ArtifactIndexValue::from_bytes(malformed_stale),
        ))
        .expect("malformed stale record appends through generic engine");
    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_file_key(key),
            engine_value_from_file_value(latest_value),
        ))
        .expect("latest record appends through generic engine");
    let oracle = PersistFileArtifactIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle validates stale file records before newest lookup succeeds");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidFileArtifactBlobStore { .. },
            ..
        }
    ));
}

#[test]
fn oracle_rejects_stale_malformed_engine_parse_artifact_value() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("parse-artifacts.index");
    let engine = ArtifactIndex::open(&index_path).expect("engine index opens");
    let key = parse_artifact_key(b"parse artifact");
    let latest_value = parse_value(b"latest parse artifact", 99);
    let mut malformed_stale = parse_value(b"stale parse artifact", 24).encode_index_value();
    malformed_stale[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(
        &PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"wrong store")).index_bytes(),
    );

    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_parse_key(key),
            ArtifactIndexValue::from_bytes(malformed_stale),
        ))
        .expect("malformed stale record appends through generic engine");
    engine
        .append_entry(ArtifactIndexEntry::new(
            engine_key_from_parse_key(key),
            engine_value_from_parse_value(latest_value),
        ))
        .expect("latest record appends through generic engine");
    let oracle =
        PersistParseArtifactIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle validates stale parse records before newest lookup succeeds");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidParseArtifactBlobStore { .. },
            ..
        }
    ));
}
