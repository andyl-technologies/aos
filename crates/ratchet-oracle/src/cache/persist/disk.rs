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
//!   .locks/       advisory lock files
//!   nodes/        mutable metadata and frontend artifact indexes
//!   values/       value blob pack and hash-to-offset index
//!   files/        file/frontend blob pack and hash-to-offset index
//! ```

use crate::cache::hashing::CacheDigestHasher;
use super::*;

use ratchet_cache::owned_paths::{OwnedPathError, OwnedPaths};
use ratchet_cache::schema::{CacheSchema, CacheSchemaError};

fn engine_owned_path_error_to_persist(error: OwnedPathError) -> PersistError {
    match error {
        OwnedPathError::CreateDir { path, source } => PersistError::CreateDir { path, source },
        OwnedPathError::Remove { path, source } => PersistError::DiscardPayload { path, source },
    }
}

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
        CacheSchemaError::InvalidHashFamily { path } => PersistError::InvalidHashFamily { path },
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

pub(super) fn update_persist_index_chunk(hasher: &mut CacheDigestHasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub(super) fn ensure_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    OwnedPaths::new([
        layout.root().to_path_buf(),
        layout.nodes_dir(),
        layout.values_dir(),
        layout.files_dir(),
        layout.roots_dir(),
    ])
    .ensure_dirs()
    .map_err(engine_owned_path_error_to_persist)
}

pub(super) fn discard_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    OwnedPaths::new([
        layout.nodes_dir(),
        layout.values_dir(),
        layout.files_dir(),
        layout.roots_dir(),
    ])
    .discard_existing()
    .map_err(engine_owned_path_error_to_persist)
}

pub(super) fn read_schema_version(layout: &PersistLayout) -> Result<Option<u32>, PersistError> {
    CacheSchema::new(layout.schema_path())
        .read_version(PERSIST_CACHE_FORMAT)
        .map_err(engine_schema_error_to_persist)
}

pub(super) fn write_schema(layout: &PersistLayout) -> Result<(), PersistError> {
    ensure_root_dir(layout.root())?;
    CacheSchema::new(layout.schema_path())
        .write_version(PERSIST_CACHE_FORMAT, PERSIST_CACHE_SCHEMA_VERSION)
        .map_err(engine_schema_error_to_persist)
}

pub(super) fn ensure_root_dir(path: &Path) -> Result<(), PersistError> {
    OwnedPaths::new([path.to_path_buf()])
        .ensure_dirs()
        .map_err(engine_owned_path_error_to_persist)
}
