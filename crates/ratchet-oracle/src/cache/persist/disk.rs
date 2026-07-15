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

use crate::cache::hashing::{CacheDigestHasher, CacheHashFamily};
use super::*;

use ratchet_cache::owned_paths::{OwnedPathError, OwnedPaths};
use ratchet_cache::schema::{CacheSchema, CacheSchemaError, CacheSchemaRecord};

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

pub(super) fn read_schema_record(
    layout: &PersistLayout,
) -> Result<Option<CacheSchemaRecord>, PersistError> {
    CacheSchema::new(layout.schema_path())
        .read_record(PERSIST_CACHE_FORMAT)
        .map_err(engine_schema_error_to_persist)
}

pub(super) fn write_schema(
    layout: &PersistLayout,
    family: CacheHashFamily,
) -> Result<(), PersistError> {
    ensure_root_dir(layout.root())?;
    CacheSchema::new(layout.schema_path())
        .write_record(
            PERSIST_CACHE_FORMAT,
            PERSIST_CACHE_SCHEMA_VERSION,
            Some(family.as_str()),
        )
        .map_err(engine_schema_error_to_persist)
}

/// How a persistent root's payload should be treated at open time.
///
/// Resolving the open disposition is a pure function of the root's recorded
/// schema record and the process cache-hash family (RFC-0007 §P4 Option C), so
/// it is decided by [`resolve_schema_open`] and exercised directly by tests
/// without touching the filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SchemaOpenDisposition {
    /// No sidecar exists yet; create the payload directories and self-describe.
    InitializeFresh,
    /// Schema version and hash family both match; keep the existing payload
    /// untouched and leave the already-self-describing manifest in place.
    KeepPayload,
    /// The payload is valid but the manifest predates per-layer families (it was
    /// written under the historical BLAKE3 default) and this process is BLAKE3;
    /// keep the payload and upgrade the manifest to record its family.
    KeepPayloadRecordFamily,
    /// The schema version or hash family is incompatible with this process; the
    /// payload cannot be read (keys are addressed in a different family, whose
    /// digests can never collide with this family's), so discard and
    /// re-initialize under the process family.
    DiscardAndReinitialize,
}

/// Resolves how to open a primary persistent root from its recorded schema.
///
/// The process opens a root under its own [`CacheHashFamily`] (`process_family`,
/// resolved once from `AOS_NIX_CACHE_HASH`, BLAKE3 by default). A root that was
/// initialized under a different family cannot be read, because the two families
/// domain-separate their digests and never collide; RFC-0007 §P4 Option C keeps
/// every primary root homogeneous by re-initializing on a mismatch, exactly as a
/// schema-version mismatch already does. A legacy family-less manifest is treated
/// as the historical BLAKE3 default.
pub(super) fn resolve_schema_open(
    record: Option<&CacheSchemaRecord>,
    process_family: CacheHashFamily,
) -> SchemaOpenDisposition {
    let Some(record) = record else {
        return SchemaOpenDisposition::InitializeFresh;
    };
    if record.schema_version != PERSIST_CACHE_SCHEMA_VERSION {
        return SchemaOpenDisposition::DiscardAndReinitialize;
    }
    match record.hash_family.as_deref() {
        // A family-less manifest describes a root populated under the historical
        // BLAKE3 default. It is readable only by a BLAKE3 process; a BLAKE3
        // process keeps it and upgrades the manifest, any other family re-keys.
        None => {
            if process_family == CacheHashFamily::Blake3 {
                SchemaOpenDisposition::KeepPayloadRecordFamily
            } else {
                SchemaOpenDisposition::DiscardAndReinitialize
            }
        }
        Some(spelling) => match CacheHashFamily::from_str(spelling) {
            Some(recorded) if recorded == process_family => SchemaOpenDisposition::KeepPayload,
            // A recorded-but-different family, or an unrecognized spelling from a
            // newer format, is incompatible with this process.
            _ => SchemaOpenDisposition::DiscardAndReinitialize,
        },
    }
}

pub(super) fn ensure_root_dir(path: &Path) -> Result<(), PersistError> {
    OwnedPaths::new([path.to_path_buf()])
        .ensure_dirs()
        .map_err(engine_owned_path_error_to_persist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(version: u32, hash_family: Option<&str>) -> CacheSchemaRecord {
        CacheSchemaRecord {
            schema_version: version,
            hash_family: hash_family.map(str::to_owned),
        }
    }

    #[test]
    fn resolve_schema_open_covers_the_family_and_version_matrix() {
        use CacheHashFamily::{Blake3, Xxh128};
        use SchemaOpenDisposition::{
            DiscardAndReinitialize, InitializeFresh, KeepPayload, KeepPayloadRecordFamily,
        };

        let current = PERSIST_CACHE_SCHEMA_VERSION;

        // No sidecar yet.
        assert_eq!(resolve_schema_open(None, Blake3), InitializeFresh);
        assert_eq!(resolve_schema_open(None, Xxh128), InitializeFresh);

        // Matching version and family keep the payload untouched.
        assert_eq!(
            resolve_schema_open(Some(&record(current, Some("blake3"))), Blake3),
            KeepPayload
        );
        assert_eq!(
            resolve_schema_open(Some(&record(current, Some("xxh128"))), Xxh128),
            KeepPayload
        );

        // Matching version, mismatched family re-keys (digests never collide).
        assert_eq!(
            resolve_schema_open(Some(&record(current, Some("blake3"))), Xxh128),
            DiscardAndReinitialize
        );
        assert_eq!(
            resolve_schema_open(Some(&record(current, Some("xxh128"))), Blake3),
            DiscardAndReinitialize
        );

        // A legacy family-less root is the historical BLAKE3 default: kept and
        // upgraded by a BLAKE3 process, re-keyed by any other family.
        assert_eq!(
            resolve_schema_open(Some(&record(current, None)), Blake3),
            KeepPayloadRecordFamily
        );
        assert_eq!(
            resolve_schema_open(Some(&record(current, None)), Xxh128),
            DiscardAndReinitialize
        );

        // An unrecognized family spelling (a newer format) is incompatible.
        assert_eq!(
            resolve_schema_open(Some(&record(current, Some("sha256"))), Blake3),
            DiscardAndReinitialize
        );

        // A schema-version mismatch always re-initializes, regardless of family.
        assert_eq!(
            resolve_schema_open(Some(&record(current + 1, Some("blake3"))), Blake3),
            DiscardAndReinitialize
        );
    }
}
