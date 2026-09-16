//! Validation and resolution of executable references retained in checked realizations.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ArtifactReference;
use serde::Deserialize;

/// Carries one exact executable selected by the package-owned provider module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutableReference {
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

/// Holds a validated executable inside one authenticated package artifact.
#[derive(Clone, Debug)]
pub(crate) struct Executable {
    artifact: ArtifactReference,
    entry_point: String,
}

impl ExecutableReference {
    /// Resolves an executable reference that carries no preset arguments.
    pub(crate) fn resolve(self) -> Result<Executable> {
        ensure!(
            self.arguments.is_empty(),
            "systemd executable reference carries undeclared arguments"
        );
        let executable = Executable {
            artifact: self.artifact,
            entry_point: self.entry_point,
        };
        executable.validate()?;
        Ok(executable)
    }
}

impl Executable {
    /// Returns the validated executable path.
    pub(crate) fn path(&self) -> PathBuf {
        Path::new(&self.artifact.store_path).join(&self.entry_point)
    }

    fn validate(&self) -> Result<()> {
        let root = Path::new(&self.artifact.store_path);
        ensure!(
            root.is_absolute()
                && root.starts_with("/nix/store")
                && root.components().all(|component| matches!(
                    component,
                    Component::RootDir | Component::Normal(_)
                )),
            "systemd executable artifact is outside the immutable store"
        );
        let relative = Path::new(&self.entry_point);
        ensure!(
            !self.entry_point.is_empty()
                && !relative.is_absolute()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "systemd executable entry point is not normalized"
        );

        let canonical_root = fs::canonicalize(root).context("resolving executable artifact")?;
        let canonical = validate_store_executable(&self.path(), "systemd executable")?;
        ensure!(
            canonical.starts_with(canonical_root),
            "systemd executable escapes its authenticated artifact"
        );
        Ok(())
    }
}

/// Validates one exact executable path from an immutable package output.
pub(crate) fn validate_store_executable(path: &Path, label: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{label} path is not absolute");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "{label} path is not normalized"
    );

    let store = Path::new("/nix/store");
    let relative = path
        .strip_prefix(store)
        .with_context(|| format!("{label} is outside the immutable store"))?;
    let package = relative
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(package) => Some(package),
            _ => None,
        })
        .with_context(|| format!("{label} store path has no package identity"))?;
    ensure!(
        relative.components().count() > 1,
        "{label} does not name a file inside its package"
    );

    let package_root = fs::canonicalize(store.join(package))
        .with_context(|| format!("resolving {label} package root"))?;
    let executable = fs::canonicalize(path).with_context(|| format!("resolving {label}"))?;
    ensure!(
        executable.starts_with(package_root),
        "{label} escapes its selected package"
    );
    let metadata = fs::metadata(&executable).with_context(|| format!("inspecting {label}"))?;
    ensure!(metadata.is_file(), "{label} is not a regular file");
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "{label} is not executable"
    );

    Ok(executable)
}
