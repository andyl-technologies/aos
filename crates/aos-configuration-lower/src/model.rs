//! Native configuration file inputs, provenance, and immutable lower results.
//!
//! These values are checked against the package's ordinary operation options.
//! Receipts bind the rendered tree and EROFS bytes to the exact native input.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Contains the final merged OS configuration owned by one lower manager.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// Expands ordered immutable source trees before explicit file overrides.
    #[serde(rename = "etcTrees", default)]
    pub etc_trees: Vec<EtcTree>,
    /// Maps relative configuration paths to typed contents.
    pub files: BTreeMap<String, Entry>,
    /// Retains executable scripts referenced by configuration bodies.
    #[serde(rename = "jobScripts")]
    pub job_scripts: BTreeMap<String, JobScript>,
    /// Records files intentionally hidden from an earlier image lower.
    #[serde(rename = "removedPaths")]
    pub removed_paths: Vec<String>,
    /// Lists managed paths present in the verified image baseline.
    #[serde(rename = "baselinePaths")]
    pub baseline_paths: Vec<String>,
    /// Locates the admitted build-produced baseline leaf inventory.
    #[serde(rename = "baselineInventory", default)]
    pub baseline_inventory: Option<String>,
    /// Retains the declaring owner of every rendered file and script.
    pub ownership: Ownership,
    /// Pins source objects referenced by the file configuration.
    #[serde(rename = "storePaths")]
    pub store_paths: Vec<String>,
    /// Names the OS-owned content-addressed lower repository.
    #[serde(rename = "retainedRoot")]
    pub retained_root: String,
}

/// Retains one package-authored immutable configuration directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EtcTree {
    /// Names the normalized destination relative to `/etc`.
    pub target: String,
    /// Names the retained immutable source directory.
    pub source: String,
}

/// Selects the representation of one configuration entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Entry {
    /// Writes UTF-8 file content with an explicit octal mode.
    Text {
        /// Contains the file body.
        text: String,
        /// Specifies its permissions.
        mode: String,
    },
    /// Creates a relative installation symlink.
    Symlink {
        /// Names the relative target.
        target: String,
    },
    /// Links to a retained immutable file or expands its directory tree.
    StoreSymlink {
        /// Names the immutable target.
        target: String,
    },
    /// Copies an immutable file using explicit permissions.
    StoreFile {
        /// Names the immutable source.
        path: String,
        /// Specifies destination permissions.
        mode: String,
    },
    /// Concatenates public X.509 certificate inputs.
    CertificateBundle {
        /// Contains ordered certificate streams.
        parts: Vec<CertificatePart>,
        /// Specifies destination permissions.
        mode: String,
    },
}

/// Contains a certificate-only input stream.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CertificatePart {
    /// Carries inline public certificates.
    Text {
        /// Contains the PEM stream.
        text: String,
    },
    /// Reads public certificates from a pinned store file.
    StoreFile {
        /// Names the retained source.
        path: String,
    },
}

/// Contains a configured executable script.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobScript {
    /// Contains the complete script body and interpreter line.
    pub text: String,
    /// Specifies its octal permissions.
    pub mode: String,
    /// Supplies an optional human-readable label.
    #[serde(default)]
    pub name: Option<String>,
}

/// Retains declaration provenance for generated artifacts.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    /// Maps each source-tree target to its package or environment owner.
    #[serde(rename = "etcTrees", default)]
    pub etc_trees: BTreeMap<String, String>,
    /// Maps each file to its declaring package or environment owner.
    pub files: BTreeMap<String, String>,
    /// Maps each script to its declaring owner.
    #[serde(rename = "jobScripts")]
    pub job_scripts: BTreeMap<String, String>,
}

/// Describes an immutable, validated native configuration lower.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lower {
    /// Names the content-addressed directory retaining all lower evidence.
    pub directory: String,
    /// Names the EROFS image to mount.
    pub image: String,
    /// Identifies the producing child effect recorded in the lower receipt.
    pub receipt_effect: String,
    /// Binds the final checked configuration inputs.
    pub input_sha256: String,
    /// Binds the exact EROFS image bytes.
    pub image_sha256: String,
    /// Binds paths, types, permissions, targets, and bytes of the source tree.
    pub tree_sha256: String,
}

/// Validates a normalized relative configuration path.
///
/// # Errors
/// Returns an error for an empty path, absolute path, NUL, or traversal component.
pub fn validate_relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.contains('\0')
            && path.split('/').all(|part| !matches!(part, "" | "." | "..")),
        "configuration path is not normalized and relative: {path:?}"
    );
    Ok(())
}

impl Input {
    /// Lists exact managed leaf paths from current files, scripts, and admitted trees.
    ///
    /// # Errors
    /// Returns an error for a source directory cycle, unretained directory
    /// reference, unsupported source file, or malformed destination path.
    pub fn desired_paths(&self) -> Result<std::collections::BTreeSet<String>> {
        let mut paths = self
            .files
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        paths.extend(
            self.job_scripts
                .keys()
                .map(|key| format!("aos-job-scripts/{key}")),
        );
        for (target, entry) in &self.files {
            if let Entry::StoreSymlink { target: source } = entry {
                if std::fs::metadata(source)?.is_dir() {
                    paths.remove(target);
                    collect_tree_paths(
                        self,
                        Path::new(source),
                        target,
                        &mut Vec::new(),
                        &mut paths,
                    )?;
                }
            }
        }
        for tree in &self.etc_trees {
            collect_tree_paths(
                self,
                Path::new(&tree.source),
                &tree.target,
                &mut Vec::new(),
                &mut paths,
            )?;
        }
        Ok(paths)
    }

    /// Imports the exact leaf inventory of the verified image baseline.
    ///
    /// # Errors
    /// Returns an error for an unretained, nonregular, oversized, or malformed
    /// immutable baseline inventory.
    pub fn load_baseline_inventory(&mut self) -> Result<()> {
        let Some(path) = &self.baseline_inventory else {
            return Ok(());
        };
        self.validate_source(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 1024 * 1024,
            "baseline inventory is not a bounded immutable regular file"
        );
        use std::io::Read as _;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "baseline inventory grew beyond its bound"
        );
        let paths: Vec<String> = serde_json::from_slice(&bytes)?;
        for path in &paths {
            validate_relative(path)?;
        }
        self.baseline_paths.extend(paths);
        self.baseline_paths.sort();
        self.baseline_paths.dedup();
        Ok(())
    }

    /// Checks provenance coverage, path conflicts, modes, and source roots.
    ///
    /// # Errors
    /// Returns an error for unsupported paths, conflicting file/directory
    /// definitions, missing ownership, malformed permissions, or unpinned sources.
    pub fn validate(&self) -> Result<()> {
        let root = Path::new(&self.retained_root);
        ensure!(
            root.is_absolute()
                && self
                    .retained_root
                    .split('/')
                    .skip(1)
                    .all(|part| !matches!(part, "" | "." | "..")),
            "lower repository is not normalized"
        );
        ensure!(
            self.files.keys().eq(self.ownership.files.keys())
                && self
                    .job_scripts
                    .keys()
                    .eq(self.ownership.job_scripts.keys()),
            "configuration ownership does not cover its entries exactly"
        );
        ensure!(
            self.ownership
                .files
                .values()
                .chain(self.ownership.job_scripts.values())
                .all(|owner| !owner.is_empty()),
            "configuration owner is empty"
        );
        for root in &self.store_paths {
            ensure!(
                root.starts_with("/nix/store/") && root.split('/').count() == 4,
                "source root is not a store object"
            );
        }
        for path in self
            .files
            .keys()
            .chain(self.removed_paths.iter())
            .chain(self.baseline_paths.iter())
        {
            validate_relative(path)?;
        }
        let targets = self
            .etc_trees
            .iter()
            .map(|tree| tree.target.clone())
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            targets.len() == self.etc_trees.len()
                && targets.iter().eq(self.ownership.etc_trees.keys())
                && self
                    .ownership
                    .etc_trees
                    .values()
                    .all(|owner| !owner.is_empty()),
            "configuration tree ownership does not cover its entries exactly"
        );
        if let Some(inventory) = &self.baseline_inventory {
            self.validate_source(inventory)?;
        }
        for tree in &self.etc_trees {
            validate_relative(&tree.target)?;
            self.validate_source(&tree.source)?;
        }
        for path in self.files.keys() {
            ensure!(
                !self
                    .files
                    .keys()
                    .any(|other| other.starts_with(&format!("{path}/"))),
                "configuration entry shadows a child entry: {path}"
            );
        }
        for entry in self.files.values() {
            match entry {
                Entry::Text { mode, .. } => validate_mode(mode)?,
                Entry::Symlink { target } => ensure!(
                    !target.is_empty() && !target.starts_with('/') && !target.contains('\0'),
                    "installation link is invalid"
                ),
                Entry::StoreSymlink { target } => self.validate_source(target)?,
                Entry::StoreFile { path, mode } => {
                    self.validate_source(path)?;
                    validate_mode(mode)?;
                }
                Entry::CertificateBundle { parts, mode } => {
                    validate_mode(mode)?;
                    ensure!(!parts.is_empty(), "certificate bundle has no inputs");
                    for part in parts {
                        if let CertificatePart::StoreFile { path } = part {
                            self.validate_source(path)?;
                        }
                    }
                }
            }
        }
        for (key, script) in &self.job_scripts {
            validate_relative(key)?;
            validate_mode(&script.mode)?;
        }
        Ok(())
    }

    pub(crate) fn validate_source(&self, source: &str) -> Result<()> {
        ensure!(
            source
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | ".."))
                && self
                    .store_paths
                    .iter()
                    .any(|root| source == root || source.starts_with(&format!("{root}/"))),
            "configuration source is not pinned: {source}"
        );
        Ok(())
    }
}

fn collect_tree_paths(
    input: &Input,
    source: &Path,
    target: &str,
    ancestors: &mut Vec<std::path::PathBuf>,
    paths: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let source = std::fs::canonicalize(source)?;
    input.validate_source(
        source
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("source path is not UTF-8"))?,
    )?;
    ensure!(
        ancestors.len() < 64 && !ancestors.contains(&source),
        "configuration tree contains a directory cycle"
    );
    ancestors.push(source.clone());
    for entry in std::fs::read_dir(&source)? {
        let entry = entry?;
        let destination = format!(
            "{target}/{}",
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("source member is not UTF-8"))?
        );
        validate_relative(&destination)?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.is_dir()
            || (metadata.file_type().is_symlink()
                && std::fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_dir()))
        {
            collect_tree_paths(input, &entry.path(), &destination, ancestors, paths)?;
        } else {
            ensure!(
                metadata.is_file() || metadata.file_type().is_symlink(),
                "configuration source contains a special file"
            );
            paths.insert(destination);
        }
    }
    ancestors.pop();
    Ok(())
}

fn validate_mode(mode: &str) -> Result<()> {
    ensure!(
        (3..=4).contains(&mode.len()) && mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "invalid configuration mode {mode:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input {
            etc_trees: Vec::new(),
            files: BTreeMap::from([(
                "app/config".into(),
                Entry::Text {
                    text: "value".into(),
                    mode: "0444".into(),
                },
            )]),
            job_scripts: BTreeMap::new(),
            removed_paths: Vec::new(),
            baseline_paths: Vec::new(),
            baseline_inventory: None,
            ownership: Ownership {
                etc_trees: BTreeMap::new(),
                files: BTreeMap::from([("app/config".into(), "app".into())]),
                job_scripts: BTreeMap::new(),
            },
            store_paths: Vec::new(),
            retained_root: "/var/lib/aos/configuration-lowers".into(),
        }
    }

    #[test]
    fn rejects_unowned_and_overlapping_paths() {
        let mut input = input();
        input.validate().unwrap();

        input.ownership.files.clear();
        assert!(input.validate().is_err());
        input
            .ownership
            .files
            .insert("app/config".into(), "app".into());
        input.files.insert(
            "app".into(),
            Entry::Text {
                text: String::new(),
                mode: "0444".into(),
            },
        );
        input.ownership.files.insert("app".into(), "app".into());
        assert!(input.validate().is_err());
    }

    #[test]
    fn rejects_unpinned_sources_and_path_traversal() {
        let mut input = input();
        input.files.insert(
            "app/config".into(),
            Entry::StoreFile {
                path: "/tmp/mutable".into(),
                mode: "0444".into(),
            },
        );
        assert!(input.validate().is_err());
        assert!(validate_relative("app/../outside").is_err());
        assert!(validate_relative("/etc/outside").is_err());
    }
    #[test]
    fn rejects_unowned_trees_and_mutable_inventory() {
        let mut input = input();
        input.etc_trees.push(EtcTree {
            target: "app/tree".into(),
            source: "/nix/store/00000000000000000000000000000000-source/tree".into(),
        });
        input
            .store_paths
            .push("/nix/store/00000000000000000000000000000000-source".into());
        assert!(input.validate().is_err());
        input
            .ownership
            .etc_trees
            .insert("app/tree".into(), "app".into());
        input.validate().unwrap();
        input.baseline_inventory = Some("/tmp/inventory.json".into());
        assert!(input.validate().is_err());
        assert!(input.load_baseline_inventory().is_err());
    }
}
