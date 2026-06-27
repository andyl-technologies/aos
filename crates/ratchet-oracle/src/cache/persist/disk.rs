//! Internal disk helpers for the persistent eval-cache stores.
//!
//! Owns the low-level integer decoders, the append-only index file invariants,
//! and the schema-version sidecar that each store directory carries. Every
//! helper is `pub(super)` so the sibling `format`, `pack`, and `cache` modules
//! can reach it through `use super::*`.
//!
//! Each store directory holds three on-disk artifacts:
//!
//! ```text
//! <store>/
//!   pack        immutable blob packfile (magic header + length-prefixed records)
//!   index       append-only hash-to-offset entries (fixed-width records)
//!   schema      schema-version sidecar ("<format>\n<version>\n")
//! ```

use super::*;

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
    let path = layout.schema_path();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistError::ReadSchema { path, source }),
    };
    let value = text
        .parse::<toml::Value>()
        .map_err(|source| PersistError::ParseSchema {
            path: path.clone(),
            source,
        })?;
    let format = value
        .get("format")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| PersistError::MissingFormat { path: path.clone() })?;
    if format != PERSIST_CACHE_FORMAT {
        return Err(PersistError::InvalidFormat {
            path,
            format: format.to_owned(),
        });
    }
    let version = value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| PersistError::MissingSchemaVersion { path: path.clone() })?;
    let version =
        u32::try_from(version).map_err(|_| PersistError::InvalidSchemaVersion { path, version })?;
    Ok(Some(version))
}

pub(super) fn write_schema(layout: &PersistLayout) -> Result<(), PersistError> {
    fs::create_dir_all(layout.root()).map_err(|source| PersistError::CreateDir {
        path: layout.root().to_path_buf(),
        source,
    })?;
    let path = layout.schema_path();
    let write_id = SCHEMA_WRITE_ID.fetch_add(1, Ordering::Relaxed);
    let tmp_path = layout
        .root()
        .join(format!("schema.toml.tmp-{}-{write_id}", std::process::id()));
    let text = format!(
        "format = {PERSIST_CACHE_FORMAT:?}\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\n"
    );
    fs::write(&tmp_path, text).map_err(|source| PersistError::WriteSchema {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, &path).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        PersistError::WriteSchema { path, source }
    })
}
