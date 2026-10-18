//! Versioned, bounded configuration source bundles.
//!
//! The complete JSON document is authenticated by the existing provisioning
//! policy before any files become evaluator inputs. File contents are base64;
//! archives, symlinks, devices, and absolute paths are not part of this format.
//!
//! ```json
//! {"schema":"aos.config-bundle/v1","entrypoint":"entry.nix",
//!  "files":{"entry.nix":"e30K"}}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};

use sha2::{Digest as _, Sha256};

/// Computes the exact payload digest used by transport pins and source wrappers.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Maximum encoded bundle size, also applied by the HTTP transport.
pub const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 1024;
/// Exact authenticated source document retained with the materialized tree.
pub const BUNDLE_FILE: &str = "config-bundle.json";
/// Directory containing only authenticated bundle files.
pub const SOURCE_DIR: &str = "source";
/// Capability advertised by images implementing the complete bundle lifecycle.
pub const BUNDLE_SCHEMA: &str = "aos.config-bundle/v1";

/// Portable source-tree envelope authenticated as one provisioning payload.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundle {
    /// Must be `aos.config-bundle/v1`.
    pub schema: String,
    /// Relative Nix entrypoint within `files`.
    pub entrypoint: String,
    /// Relative regular-file paths mapped to standard base64 contents.
    pub files: BTreeMap<String, String>,
}

/// Recognizes and validates a bundle without treating arbitrary Nix as JSON.
///
/// # Errors
///
/// Returns an error for an unsupported bundle schema, malformed envelope,
/// unsafe paths, invalid base64, or exceeded size/file limits.
pub fn parse(bytes: &[u8]) -> Result<Option<ConfigBundle>> {
    ensure!(
        bytes.len() as u64 <= MAX_BUNDLE_BYTES,
        "configuration exceeds the 16 MiB transport limit"
    );
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(None);
    };
    let Some(schema) = value.get("schema").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    if !schema.starts_with("aos.config-bundle") {
        return Ok(None);
    }
    ensure!(
        schema == BUNDLE_SCHEMA,
        "unsupported configuration bundle schema {schema:?}"
    );
    let bundle: ConfigBundle =
        serde_json::from_value(value).context("decoding configuration bundle")?;
    bundle.decoded_files()?;
    Ok(Some(bundle))
}

impl ConfigBundle {
    fn decoded_files(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        ensure!(
            self.schema == BUNDLE_SCHEMA,
            "unsupported configuration bundle schema"
        );
        ensure!(
            !self.files.is_empty() && self.files.len() <= MAX_FILES,
            "bundle must contain 1..=1024 files"
        );
        validate_path(&self.entrypoint)?;
        ensure!(
            self.entrypoint.ends_with(".nix") && self.files.contains_key(&self.entrypoint),
            "bundle entrypoint must name an included Nix file"
        );
        let mut total = 0usize;
        let mut decoded = BTreeMap::new();
        for (path, encoded) in &self.files {
            validate_path(path)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .with_context(|| format!("decoding bundle file {path:?}"))?;
            total = total
                .checked_add(bytes.len())
                .context("bundle size overflow")?;
            ensure!(total <= MAX_SOURCE_BYTES, "bundle sources exceed 8 MiB");
            decoded.insert(path.clone(), bytes);
        }
        // A file must never also be a parent directory of another file.
        for path in decoded.keys() {
            let mut parent = Path::new(path).parent();
            while let Some(directory) = parent {
                if let Some(name) = directory.to_str() {
                    ensure!(
                        !decoded.contains_key(name),
                        "bundle file/directory collision at {name:?}"
                    );
                }
                parent = directory.parent();
            }
        }
        Ok(decoded)
    }

    /// Materializes validated regular files into a new, empty source directory.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid contents, a preexisting destination, or I/O.
    pub fn materialize(&self, root: &Path) -> Result<()> {
        let files = self.decoded_files()?;
        std::fs::create_dir(root).context("creating new bundle source directory")?;
        for (path, bytes) in files {
            let destination = root.join(path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(destination, bytes)?;
        }
        Ok(())
    }

    /// Checks every source byte and rejects extra entries or nonregular files.
    ///
    /// # Errors
    ///
    /// Returns an error when the source tree differs from the authenticated
    /// bundle, has links/special files, or cannot be read.
    pub fn verify_tree(&self, root: &Path) -> Result<()> {
        let expected = self.decoded_files()?;
        let mut actual = BTreeMap::new();
        let mut budget = (0usize, 0usize);
        read_tree(root, root, &expected, &mut actual, &mut budget, 0)?;
        ensure!(
            actual == expected,
            "configuration source tree differs from its authorized bundle"
        );
        Ok(())
    }

    /// Renders the operator module wrapper binding this exact source revision.
    pub fn host_module(&self, bytes: &[u8]) -> String {
        format!(
            "# aos.config-bundle/v1 sha256:{}\nimport ./source/{}\n",
            sha256_hex(bytes),
            self.entrypoint
        )
    }
}

fn read_tree(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
    files: &mut BTreeMap<String, Vec<u8>>,
    budget: &mut (usize, usize),
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 32, "source tree exceeds bundle depth limit");
    ensure!(
        std::fs::symlink_metadata(directory)?.file_type().is_dir(),
        "bundle source root must be a directory"
    );
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        budget.0 += 1;
        ensure!(
            budget.0 <= MAX_FILES * 32,
            "source tree exceeds entry limit"
        );

        let path = entry.path();
        let kind = entry.file_type()?;
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("non-UTF-8 bundle path")?
            .to_string();
        if kind.is_dir() {
            let prefix = format!("{relative}/");
            ensure!(
                expected.keys().any(|name| name.starts_with(&prefix)),
                "bundle source contains an unauthorized directory"
            );
            read_tree(root, &path, expected, files, budget, depth + 1)?;
        } else if kind.is_file() {
            ensure!(
                files.len() < MAX_FILES,
                "source tree exceeds bundle file limit"
            );
            let expected_bytes = expected
                .get(&relative)
                .context("bundle source contains an unauthorized file")?;
            let length =
                usize::try_from(entry.metadata()?.len()).context("source file is too large")?;
            ensure!(
                length == expected_bytes.len(),
                "bundle source file size differs from authorized contents"
            );
            budget.1 = budget
                .1
                .checked_add(length)
                .context("source size overflow")?;
            ensure!(
                budget.1 <= MAX_SOURCE_BYTES,
                "source tree exceeds bundle size limit"
            );
            files.insert(relative, std::fs::read(path)?);
        } else {
            bail!("bundle source contains a link or special file");
        }
    }
    Ok(())
}

/// Validates one portable relative file path.
///
/// # Errors
///
/// Rejects empty, absolute, escaping, excessively nested, or nonportable paths.
pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 512,
        "invalid bundle path length"
    );
    let parts: Vec<_> = path.split('/').collect();
    ensure!(parts.len() <= 32, "bundle path exceeds 32 components");
    ensure!(
        parts.iter().all(|part| !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))),
        "unsafe bundle path {path:?}"
    );
    Ok(())
}

/// Copies a previously authorized bundle and reconstructs its checked tree.
///
/// # Errors
///
/// Returns an error for changed input, unsafe contents, an existing destination
/// tree, or I/O failures. Literal inputs are a successful no-op.
pub fn copy_source(source: &Path, destination: &Path) -> Result<()> {
    let path = source.join(BUNDLE_FILE);
    if !path.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(path)?;
    let bundle = parse(&bytes)?.context("retained bundle has no supported schema")?;
    bundle.verify_tree(&source.join(SOURCE_DIR))?;
    bundle.materialize(&destination.join(SOURCE_DIR))?;
    std::fs::write(destination.join(BUNDLE_FILE), bytes)?;
    if let Some(signature) = ["config-bundle.json.sig", "user-data.sig", "host.nix.sig"]
        .into_iter()
        .find_map(|name| std::fs::read(source.join(name)).ok())
    {
        std::fs::write(destination.join("config-bundle.json.sig"), signature)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_preserves_imports_and_data_and_detects_changes() {
        let bytes = br#"{"schema":"aos.config-bundle/v1","entrypoint":"host.nix","files":{"host.nix":"e30K","data/settings.json":"e30K","data/settings.toml":"eCA9IDEK"}}"#;
        let bundle = parse(bytes).unwrap().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        bundle.materialize(&root).unwrap();
        bundle.verify_tree(&root).unwrap();
        std::fs::create_dir(root.join("unexpected-empty-directory")).unwrap();
        assert!(bundle.verify_tree(&root).is_err());
        std::fs::remove_dir(root.join("unexpected-empty-directory")).unwrap();

        std::fs::write(root.join("data/settings.toml"), b"x = 2\n").unwrap();
        assert!(bundle.verify_tree(&root).is_err());
        assert!(bundle.host_module(bytes).contains(&sha256_hex(bytes)));
    }

    #[test]
    fn rejects_escaping_paths_collisions_and_links() {
        for path in [
            "/host.nix",
            "../host.nix",
            "a/../host.nix",
            "a//b",
            "a/${x}",
            "a\\b",
        ] {
            assert!(validate_path(path).is_err(), "{path}");
        }
        let bytes = br#"{"schema":"aos.config-bundle/v1","entrypoint":"host.nix","files":{"host.nix":"e30K","host.nix/child":"e30K"}}"#;
        assert!(parse(bytes).is_err());
        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            let bundle = parse(br#"{"schema":"aos.config-bundle/v1","entrypoint":"host.nix","files":{"host.nix":"e30K"}}"#).unwrap().unwrap();
            let root = temp.path().join("source");
            bundle.materialize(&root).unwrap();
            std::os::unix::fs::symlink("host.nix", root.join("extra")).unwrap();
            assert!(bundle.verify_tree(&root).is_err());
        }
    }
}
