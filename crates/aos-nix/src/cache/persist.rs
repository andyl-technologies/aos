//! Versioned persistent-cache layout.
//!
//! The full Phase-2 storage engine will fill `nodes/`, `values/`, and `files/`
//! with verifying traces and content-addressed artifacts. This module owns the
//! on-disk layout contract and schema-version guard those stores share.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// The persistent eval-cache schema format marker.
pub const PERSIST_CACHE_FORMAT: &str = "aos-nix-eval-cache";
/// The persistent eval-cache schema version.
pub const PERSIST_CACHE_SCHEMA_VERSION: u32 = 1;

static SCHEMA_WRITE_ID: AtomicU64 = AtomicU64::new(0);

/// Filesystem paths for one persistent eval-cache root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistLayout {
    root: PathBuf,
}

impl PersistLayout {
    /// Creates paths rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the schema metadata path.
    pub fn schema_path(&self) -> PathBuf {
        self.root.join("schema.toml")
    }

    /// Returns the mutable node metadata directory.
    pub fn nodes_dir(&self) -> PathBuf {
        self.root.join("nodes")
    }

    /// Returns the durable value store directory.
    pub fn values_dir(&self) -> PathBuf {
        self.root.join("values")
    }

    /// Returns the durable file/frontend artifact directory.
    pub fn files_dir(&self) -> PathBuf {
        self.root.join("files")
    }
}

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
}

impl PersistCache {
    /// Opens or initializes a persistent eval-cache root.
    ///
    /// A matching schema preserves existing payload directories. A well-formed
    /// mismatched schema discards `nodes/`, `values/`, and `files/` before
    /// rewriting current metadata. Malformed schema metadata is reported as an
    /// error and is not discarded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if schema metadata cannot be read, parsed,
    /// written, or if cache directories cannot be created or discarded.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let layout = PersistLayout::new(root);
        match read_schema_version(&layout)? {
            Some(PERSIST_CACHE_SCHEMA_VERSION) => {
                ensure_payload_dirs(&layout)?;
            }
            Some(_) => {
                discard_payload_dirs(&layout)?;
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
            None => {
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
        }
        Ok(Self { layout })
    }

    /// Returns this cache's filesystem layout.
    pub const fn layout(&self) -> &PersistLayout {
        &self.layout
    }
}

/// Persistent-cache layout initialization failed.
#[derive(Debug, Error)]
pub enum PersistError {
    /// The cache root or payload directory could not be created.
    #[error("failed to create persistent cache directory {path}")]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Existing cache payload could not be discarded after a schema mismatch.
    #[error("failed to discard persistent cache payload {path}")]
    DiscardPayload {
        /// The path that could not be removed.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be read.
    #[error("failed to read persistent cache schema {path}")]
    ReadSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be parsed as TOML.
    #[error("failed to parse persistent cache schema {path}")]
    ParseSchema {
        /// The schema file path.
        path: PathBuf,
        /// The TOML parse error.
        source: toml::de::Error,
    },
    /// Schema metadata did not contain an integer `schema_version`.
    #[error("persistent cache schema {path} is missing integer schema_version")]
    MissingSchemaVersion {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata did not contain a string `format`.
    #[error("persistent cache schema {path} is missing string format")]
    MissingFormat {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata was for another cache format.
    #[error("persistent cache schema {path} has unsupported format {format:?}")]
    InvalidFormat {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema format.
        format: String,
    },
    /// Schema metadata contained a version outside the supported `u32` range.
    #[error("persistent cache schema {path} has unsupported schema_version {version}")]
    InvalidSchemaVersion {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema version.
        version: i64,
    },
    /// Schema metadata could not be written.
    #[error("failed to write persistent cache schema {path}")]
    WriteSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
}

fn ensure_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
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

fn discard_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    for path in [layout.nodes_dir(), layout.values_dir(), layout.files_dir()] {
        remove_path_if_exists(&path)?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), PersistError> {
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

fn read_schema_version(layout: &PersistLayout) -> Result<Option<u32>, PersistError> {
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

fn write_schema(layout: &PersistLayout) -> Result<(), PersistError> {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("aos-nix-persist-cache-{id}-{}", std::process::id()))
    }

    fn sentinel(path: PathBuf) -> PathBuf {
        fs::create_dir_all(path.parent().expect("sentinel parent exists"))
            .expect("sentinel parent creates");
        fs::write(&path, b"keep me").expect("sentinel writes");
        path
    }

    #[test]
    fn open_creates_versioned_layout() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout();

        assert_eq!(layout.root(), root.as_path());
        assert!(layout.nodes_dir().is_dir());
        assert!(layout.values_dir().is_dir());
        assert!(layout.files_dir().is_dir());
        assert_eq!(
            fs::read_to_string(layout.schema_path()).expect("schema reads"),
            "format = \"aos-nix-eval-cache\"\nschema_version = 1\n"
        );

        let _ = fs::remove_dir_all(root);
    }

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
            "format = \"aos-nix-eval-cache\"\nschema_version = 0\n",
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
            "format = \"aos-nix-eval-cache\"\nschema_version = 1\n"
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
            "format = \"other-cache\"\nschema_version = 1\n",
        )
        .expect("schema rewrites");

        let error = PersistCache::open(&root).expect_err("wrong format errors");

        assert!(matches!(error, PersistError::InvalidFormat { .. }));
        assert!(value_file.is_file());

        let _ = fs::remove_dir_all(root);
    }
}
