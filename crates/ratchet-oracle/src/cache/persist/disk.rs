//! Internal disk helpers for the persistent eval-cache stores.
//!
//! Owns the low-level integer decoders, append-only index file invariants, and
//! root schema-version sidecar adapter. Every helper is `pub(super)` so the
//! sibling `format`, `pack`, and `cache` modules can reach it through
//! `use super::*`.
//!
//! A persistent root currently holds these top-level artifacts:
//!
//! ```text
//! <root>/
//!   schema.toml   format marker and schema version
//!   nodes/        mutable metadata and frontend artifact indexes
//!   values/       value blob pack and hash-to-offset index
//!   files/        file/frontend blob pack and hash-to-offset index
//! ```

use super::*;

use ratchet_cache::schema::{CacheSchema, CacheSchemaError};

fn engine_schema_error_to_persist(error: CacheSchemaError) -> PersistError {
    match error {
        CacheSchemaError::Read { path, source } => PersistError::ReadSchema { path, source },
        CacheSchemaError::Parse { path, source } => PersistError::ParseSchema { path, source },
        CacheSchemaError::MissingSchemaVersion { path } => {
            PersistError::MissingSchemaVersion { path }
        }
        CacheSchemaError::MissingFormat { path } => PersistError::MissingFormat { path },
        CacheSchemaError::InvalidFormat { path, format } => {
            PersistError::InvalidFormat { path, format }
        }
        CacheSchemaError::InvalidSchemaVersion { path, version } => {
            PersistError::InvalidSchemaVersion { path, version }
        }
        CacheSchemaError::Write { path, source } => PersistError::WriteSchema { path, source },
    }
}

pub(super) fn read_u32(bytes: &[u8]) -> u32 {
    let mut raw = [0; 4];
    raw.copy_from_slice(bytes);
    u32::from_le_bytes(raw)
}

pub(super) fn read_u64(bytes: &[u8]) -> u64 {
    let mut raw = [0; 8];
    raw.copy_from_slice(bytes);
    u64::from_le_bytes(raw)
}

pub(super) fn update_persist_index_chunk(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub(super) fn ensure_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    for path in [
        layout.root().to_path_buf(),
        layout.nodes_dir(),
        layout.values_dir(),
        layout.files_dir(),
    ] {
        fs::create_dir_all(&path).map_err(|source| PersistError::CreateDir { path, source })?;
    }
    Ok(())
}

pub(super) fn discard_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    for path in [layout.nodes_dir(), layout.values_dir(), layout.files_dir()] {
        remove_path_if_exists(&path)?;
    }
    Ok(())
}

pub(super) fn remove_path_if_exists(path: &Path) -> Result<(), PersistError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|source| PersistError::DiscardPayload {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => fs::remove_file(path).map_err(|source| PersistError::DiscardPayload {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PersistError::DiscardPayload {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(super) fn read_schema_version(layout: &PersistLayout) -> Result<Option<u32>, PersistError> {
    CacheSchema::new(layout.schema_path())
        .read_version(PERSIST_CACHE_FORMAT)
        .map_err(engine_schema_error_to_persist)
}

pub(super) fn write_schema(layout: &PersistLayout) -> Result<(), PersistError> {
    fs::create_dir_all(layout.root()).map_err(|source| PersistError::CreateDir {
        path: layout.root().to_path_buf(),
        source,
    })?;
    CacheSchema::new(layout.schema_path())
        .write_version(PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION)
        .map_err(engine_schema_error_to_persist)
}
