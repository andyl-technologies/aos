//! Internal disk helpers for the persistent eval-cache stores.
//!
//! Owns the low-level integer decoders, the append-only index file invariants,
//! the blob-packfile validation, and the schema-version sidecar that each
//! store directory carries. Every helper is `pub(super)` so the sibling
//! `format`, `pack`, and `cache` modules can reach it through `use super::*`.
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

pub(super) fn ensure_blob_index_file(path: &Path) -> Result<(), PersistBlobIndexError> {
    ensure_blob_index_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistBlobIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistBlobIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_blob_index_len(path, len)
}

pub(super) fn ensure_blob_index_parent(path: &Path) -> Result<(), PersistBlobIndexError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistBlobIndexError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

pub(super) fn validate_blob_index_len(path: &Path, len: u64) -> Result<(), PersistBlobIndexError> {
    let remainder = len % PERSIST_BLOB_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(PersistBlobIndexError::Format {
        path: path.to_path_buf(),
        source: PersistPackFormatError::ShortBlobIndexEntry {
            expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

pub(super) fn ensure_file_artifact_index_file(
    path: &Path,
) -> Result<(), PersistFileArtifactIndexError> {
    ensure_file_artifact_index_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistFileArtifactIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistFileArtifactIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_file_artifact_index_len(path, len)
}

pub(super) fn ensure_file_artifact_index_parent(
    path: &Path,
) -> Result<(), PersistFileArtifactIndexError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistFileArtifactIndexError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

pub(super) fn validate_file_artifact_index_len(
    path: &Path,
    len: u64,
) -> Result<(), PersistFileArtifactIndexError> {
    let remainder = len % PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(PersistFileArtifactIndexError::Format {
        path: path.to_path_buf(),
        source: PersistPackFormatError::ShortFileArtifactIndexEntry {
            expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

pub(super) fn ensure_blob_pack_file(path: &Path) -> Result<(), PersistBlobPackError> {
    ensure_blob_pack_parent(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistBlobPackError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    match len {
        0 => file
            .write_all(&PersistBlobPackHeader::current().encode())
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobPackError::Write {
                path: path.to_path_buf(),
                source,
            }),
        len if len < PERSIST_BLOB_PACK_HEADER_LEN as u64 => Err(PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source: PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: len as usize,
            },
        }),
        _ => validate_blob_pack_header(path, &mut file),
    }
}

pub(super) fn ensure_blob_pack_parent(path: &Path) -> Result<(), PersistBlobPackError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistBlobPackError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

pub(super) fn open_validated_blob_pack_for_read(
    path: &Path,
) -> Result<std::fs::File, PersistBlobPackError> {
    let mut file =
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| PersistBlobPackError::Open {
                path: path.to_path_buf(),
                source,
            })?;
    validate_blob_pack_header(path, &mut file)?;
    Ok(file)
}

pub(super) fn validate_blob_pack_header(
    path: &Path,
    file: &mut std::fs::File,
) -> Result<(), PersistBlobPackError> {
    let len = file
        .metadata()
        .map_err(|source| PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if len < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
        return Err(PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source: PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: len as usize,
            },
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| PersistBlobPackError::Seek {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = [0; PERSIST_BLOB_PACK_HEADER_LEN];
    file.read_exact(&mut bytes)
        .map_err(|source| PersistBlobPackError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    PersistBlobPackHeader::decode(&bytes)
        .map(|_| ())
        .map_err(|source| PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source,
        })
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
