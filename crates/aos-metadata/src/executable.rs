//! Exact executable references supplied by the authenticated ability plan.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ArtifactReference;
use serde::Deserialize;

/// Carries one executable from an authenticated package artifact.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableReference {
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

impl ExecutableReference {
    /// Resolves and validates the executable path.
    ///
    /// # Errors
    ///
    /// Returns an error when preset arguments are present, the artifact is
    /// mutable, the entry point is not a strict relative path, or the resolved
    /// file escapes the artifact or is not executable.
    pub fn resolve(&self) -> Result<PathBuf> {
        ensure!(
            self.arguments.is_empty(),
            "metadata executable carries undeclared arguments"
        );
        let root = Path::new(&self.artifact.store_path);
        ensure!(
            root.is_absolute() && root.starts_with("/nix/store"),
            "metadata executable artifact is outside the immutable store"
        );
        let entry_point = Path::new(&self.entry_point);
        ensure!(
            !self.entry_point.is_empty()
                && !entry_point.is_absolute()
                && entry_point
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "metadata executable entry point is not normalized"
        );

        let canonical_root = fs::canonicalize(root).context("resolving executable artifact")?;
        let executable =
            fs::canonicalize(root.join(entry_point)).context("resolving executable")?;
        ensure!(
            executable.starts_with(canonical_root),
            "metadata executable escapes its artifact"
        );
        let metadata = fs::metadata(&executable).context("inspecting executable")?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "metadata executable is not an executable regular file"
        );
        Ok(executable)
    }
}
