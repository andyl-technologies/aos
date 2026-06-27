//! Schema-version sidecars for cache-engine roots.
//!
//! The sidecar is a small TOML file that identifies a cache format and schema
//! version before callers open larger packfiles and sidecars.
//!
//! ```toml
//! format = "aos-nix-eval-cache"
//! schema_version = 5
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

static SCHEMA_WRITE_ID: AtomicU64 = AtomicU64::new(0);

/// A TOML schema-version sidecar.
#[derive(Clone, Debug)]
pub struct CacheSchema {
    path: PathBuf,
}

impl CacheSchema {
    /// Creates a schema sidecar handle at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns this schema sidecar's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the schema version when a sidecar exists.
    ///
    /// Missing sidecars return `Ok(None)`. Existing sidecars must contain a
    /// string `format` that matches `expected_format` and an integer
    /// `schema_version` that fits in `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`CacheSchemaError`] if the sidecar cannot be read, parsed, or
    /// validated.
    pub fn read_version(&self, expected_format: &str) -> Result<Option<u32>, CacheSchemaError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CacheSchemaError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let value = text
            .parse::<toml::Value>()
            .map_err(|source| CacheSchemaError::Parse {
                path: self.path.clone(),
                source,
            })?;
        let format = value
            .get("format")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CacheSchemaError::MissingFormat {
                path: self.path.clone(),
            })?;
        if format != expected_format {
            return Err(CacheSchemaError::InvalidFormat {
                path: self.path.clone(),
                format: format.to_owned(),
            });
        }
        let version = value
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| CacheSchemaError::MissingSchemaVersion {
                path: self.path.clone(),
            })?;
        let version =
            u32::try_from(version).map_err(|_| CacheSchemaError::InvalidSchemaVersion {
                path: self.path.clone(),
                version,
            })?;
        Ok(Some(version))
    }

    /// Replaces the sidecar with `format` and `version`.
    ///
    /// The sidecar is staged through a sibling temporary path and then renamed
    /// into place. Parent directories are not created by this method.
    ///
    /// # Errors
    ///
    /// Returns [`CacheSchemaError::Write`] if the temporary file cannot be
    /// written or renamed over the sidecar.
    pub fn write_version(&self, format: &str, version: u32) -> Result<(), CacheSchemaError> {
        let write_id = SCHEMA_WRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = schema_temp_path(&self.path, write_id);
        let text = format!("format = {format:?}\nschema_version = {version}\n");
        fs::write(&tmp_path, text).map_err(|source| CacheSchemaError::Write {
            path: tmp_path.clone(),
            source,
        })?;
        fs::rename(&tmp_path, &self.path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            CacheSchemaError::Write {
                path: self.path.clone(),
                source,
            }
        })
    }
}

/// A schema-version sidecar operation failed.
#[derive(Debug, Error)]
pub enum CacheSchemaError {
    /// Schema metadata could not be read.
    #[error("failed to read cache schema {path:?}")]
    Read {
        /// The schema file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: io::Error,
    },
    /// Schema metadata could not be parsed as TOML.
    #[error("failed to parse cache schema {path:?}")]
    Parse {
        /// The schema file path.
        path: PathBuf,
        /// The TOML parse error.
        #[source]
        source: toml::de::Error,
    },
    /// Schema metadata did not contain an integer `schema_version`.
    #[error("cache schema {path:?} is missing integer schema_version")]
    MissingSchemaVersion {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata did not contain a string `format`.
    #[error("cache schema {path:?} is missing string format")]
    MissingFormat {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata was for another cache format.
    #[error("cache schema {path:?} has unsupported format {format:?}")]
    InvalidFormat {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema format.
        format: String,
    },
    /// Schema metadata contained a version outside the supported `u32` range.
    #[error("cache schema {path:?} has unsupported schema_version {version}")]
    InvalidSchemaVersion {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema version.
        version: i64,
    },
    /// Schema metadata could not be written.
    #[error("failed to write cache schema {path:?}")]
    Write {
        /// The failed write path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: io::Error,
    },
}

fn schema_temp_path(path: &Path, write_id: u64) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "schema.toml".into());
    let temp_name = format!("{file_name}.tmp-{}-{write_id}", std::process::id());
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SCHEMA_WRITE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ratchet-cache-schema-{name}-{}-{nonce}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn schema_missing_file_returns_none() {
        let path = temp_path("missing");
        let schema = CacheSchema::new(path.clone());

        assert_eq!(
            schema
                .read_version("aos-nix-eval-cache")
                .expect("missing schema reads"),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn schema_write_round_trips_exact_toml() {
        let path = temp_path("round-trip");
        let schema = CacheSchema::new(path.clone());

        schema
            .write_version("aos-nix-eval-cache", 5)
            .expect("schema writes");

        assert_eq!(
            fs::read_to_string(&path).expect("schema text reads"),
            "format = \"aos-nix-eval-cache\"\nschema_version = 5\n"
        );
        assert_eq!(
            schema
                .read_version("aos-nix-eval-cache")
                .expect("schema reads"),
            Some(5)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn schema_read_rejects_invalid_format_without_rewriting() {
        let path = temp_path("invalid-format");
        fs::write(&path, "format = \"other\"\nschema_version = 5\n").expect("schema writes");
        let schema = CacheSchema::new(path.clone());

        let error = schema
            .read_version("aos-nix-eval-cache")
            .expect_err("invalid format errors");

        assert!(matches!(
            error,
            CacheSchemaError::InvalidFormat { format, .. } if format == "other"
        ));
        assert_eq!(
            fs::read_to_string(&path).expect("schema text reads"),
            "format = \"other\"\nschema_version = 5\n"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn schema_read_rejects_missing_fields() {
        let path = temp_path("missing-format");
        fs::write(&path, "schema_version = 5\n").expect("schema writes");
        let schema = CacheSchema::new(path.clone());

        let error = schema
            .read_version("aos-nix-eval-cache")
            .expect_err("missing format errors");
        assert!(matches!(error, CacheSchemaError::MissingFormat { .. }));

        fs::write(&path, "format = \"aos-nix-eval-cache\"\n").expect("schema rewrites");
        let error = schema
            .read_version("aos-nix-eval-cache")
            .expect_err("missing version errors");
        assert!(matches!(
            error,
            CacheSchemaError::MissingSchemaVersion { .. }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn schema_read_rejects_unsupported_version() {
        let path = temp_path("invalid-version");
        fs::write(
            &path,
            "format = \"aos-nix-eval-cache\"\nschema_version = -1\n",
        )
        .expect("schema writes");
        let schema = CacheSchema::new(path.clone());

        let error = schema
            .read_version("aos-nix-eval-cache")
            .expect_err("unsupported version errors");

        assert!(matches!(
            error,
            CacheSchemaError::InvalidSchemaVersion { version: -1, .. }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn schema_read_rejects_malformed_toml() {
        let path = temp_path("malformed");
        fs::write(&path, "schema_version =").expect("schema writes");
        let schema = CacheSchema::new(path.clone());

        let error = schema
            .read_version("aos-nix-eval-cache")
            .expect_err("malformed schema errors");

        assert!(matches!(error, CacheSchemaError::Parse { .. }));

        let _ = fs::remove_file(path);
    }
}
