//! On-disk caching of the documentation index.
//!
//! Building a [`DocIndex`] requires walking and parsing every `.nix` file in
//! the repository (and optionally evaluating the module system), so the
//! result is cached as JSON between runs. Local repositories cache in-tree
//! (`<root>/.aos-doc-cache.json`); remote/flake sources cache under
//! `~/.cache/aos/doc/` keyed by a source hash.
//!
//! Staleness is detected by schema version and a cheap mtime scan: the cache
//! is invalid when its schema is outdated or any `.nix` file under `lib/`,
//! `modules/`, or `pkgs/` is newer than the index's `built_at` timestamp (see
//! [`is_cache_valid`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::{DOC_INDEX_SCHEMA_VERSION, DocIndex};

/// Returns the cache file path for a local source root.
///
/// For local repos: `<root>/.aos-doc-cache.json`
pub fn cache_path_for_local(root: &Path) -> PathBuf {
    root.join(".aos-doc-cache.json")
}

/// Returns the cache file path for a remote/flake source, keyed by a hash.
///
/// Location: `~/.cache/aos/doc/<hash>.json` (honoring `XDG_CACHE_HOME`).
/// Returns `None` if neither `XDG_CACHE_HOME` nor `HOME` is set.
pub fn cache_path_for_remote(source_hash: &str) -> Option<PathBuf> {
    dirs_cache().map(|base| base.join(format!("{source_hash}.json")))
}

/// Loads a cached [`DocIndex`] from disk, if the file exists.
///
/// Returns `Ok(None)` when `cache_file` is not a regular file, so a missing
/// cache is not an error.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read, or if its
/// contents are not a valid JSON-serialized [`DocIndex`].
pub fn load_cache(cache_file: &Path) -> Result<Option<DocIndex>> {
    if !cache_file.is_file() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(cache_file)
        .with_context(|| format!("reading cache at {}", cache_file.display()))?;

    let index: DocIndex = serde_json::from_str(&data)
        .with_context(|| format!("parsing cache at {}", cache_file.display()))?;

    Ok(Some(index))
}

/// Saves a [`DocIndex`] to disk as JSON, creating parent directories.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, if the index
/// fails to serialize, or if the file cannot be written.
pub fn save_cache(cache_file: &Path, index: &DocIndex) -> Result<()> {
    // Ensure parent directory exists (relevant for remote cache paths).
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating cache directory {}", parent.display()))?;
    }

    let data = serde_json::to_string(index).context("serializing doc index")?;
    std::fs::write(cache_file, data)
        .with_context(|| format!("writing cache to {}", cache_file.display()))?;

    Ok(())
}

/// Checks whether a cached index is still valid.
///
/// The cache is considered stale if its schema version is outdated or any
/// `.nix` file under the root's `lib/`, `modules/`, or `pkgs/` directories has
/// an mtime newer than the index's `built_at` timestamp. Directories that
/// cannot be read are treated as unchanged, so I/O problems never force a
/// rebuild loop.
pub fn is_cache_valid(root: &Path, index: &DocIndex) -> bool {
    if index.schema_version != DOC_INDEX_SCHEMA_VERSION {
        return false;
    }

    let built_at = index.built_at;

    for dir_name in &["lib", "modules", "pkgs"] {
        let dir = root.join(dir_name);
        if dir.is_dir() && has_newer_nix_file(&dir, built_at) {
            return false;
        }
    }

    true
}

/// Recursively checks if any `.nix` file in `dir` has an mtime after `cutoff` (unix secs).
fn has_newer_nix_file(dir: &Path, cutoff: u64) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            if has_newer_nix_file(&path, cutoff) {
                return true;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("nix") {
            if let Ok(meta) = path.metadata() {
                if let Ok(mtime) = meta.modified() {
                    let mtime_secs = mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if mtime_secs > cutoff {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Returns the base cache directory, `~/.cache/aos/doc/` (XDG-style).
fn dirs_cache() -> Option<PathBuf> {
    // Respect XDG_CACHE_HOME if set, otherwise use ~/.cache.
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;

    Some(base.join("aos").join("doc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cache_roundtrip() {
        let tmp = std::env::temp_dir().join("aos-doc-cache-test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let cache_file = tmp.join("test-cache.json");

        let index = DocIndex {
            schema_version: DOC_INDEX_SCHEMA_VERSION,
            built_at: 1700000000,
            entries: vec![],
        };

        save_cache(&cache_file, &index).unwrap();
        let loaded = load_cache(&cache_file).unwrap().unwrap();
        assert_eq!(loaded.built_at, 1700000000);
        assert!(loaded.entries.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_load_nonexistent() {
        let result = load_cache(Path::new("/tmp/does-not-exist-aos-test.json")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_validity() {
        let tmp = std::env::temp_dir().join("aos-doc-cache-validity-test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("lib")).unwrap();

        // Write a file.
        fs::write(tmp.join("lib/test.nix"), "{}").unwrap();

        // Index built in the far future should be valid.
        let future_index = DocIndex {
            schema_version: DOC_INDEX_SCHEMA_VERSION,
            built_at: u64::MAX - 1,
            entries: vec![],
        };
        assert!(is_cache_valid(&tmp, &future_index));

        // Index built at epoch should be stale.
        let old_index = DocIndex {
            schema_version: DOC_INDEX_SCHEMA_VERSION,
            built_at: 0,
            entries: vec![],
        };
        assert!(!is_cache_valid(&tmp, &old_index));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn older_schema_is_stale() {
        let index = DocIndex {
            schema_version: DOC_INDEX_SCHEMA_VERSION - 1,
            built_at: u64::MAX,
            entries: vec![],
        };

        assert!(!is_cache_valid(Path::new("/tmp"), &index));
    }

    #[test]
    fn cache_without_schema_deserializes_as_stale() {
        let index: DocIndex =
            serde_json::from_str(r#"{"built_at":18446744073709551615,"entries":[]}"#).unwrap();

        assert_eq!(index.schema_version, 0);
        assert!(!is_cache_valid(Path::new("/tmp"), &index));
    }

    #[test]
    fn test_cache_path_for_local() {
        let p = cache_path_for_local(Path::new("/foo/bar"));
        assert_eq!(p, PathBuf::from("/foo/bar/.aos-doc-cache.json"));
    }
}
