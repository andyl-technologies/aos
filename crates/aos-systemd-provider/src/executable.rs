//! Validates pinned executables inside their exact immutable package roots.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};

/// Validates one exact executable path from an immutable package output.
///
/// # Errors
/// Returns an error for a non-normalized path, a target outside its selected
/// store root, a missing or non-executable file, or a filesystem read failure.
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
