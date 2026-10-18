//! Exact executable references supplied by the authenticated ability plan.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
/// Resolves a native executable input inside the immutable package store.
///
/// # Errors
/// Returns an error when the path is not normalized, escapes its selected
/// package output, or is not an executable regular file.
pub fn resolve_executable(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    let relative = path
        .strip_prefix("/nix/store")
        .context("executable is outside immutable store")?;
    let mut components = relative.components();
    let package = components
        .next()
        .context("executable has no package root")?;
    ensure!(
        matches!(package, Component::Normal(_)),
        "invalid executable package root"
    );
    ensure!(
        components
            .clone()
            .all(|component| matches!(component, Component::Normal(_))),
        "executable path is not normalized"
    );
    let root = Path::new("/nix/store").join(package.as_os_str());
    let root = fs::canonicalize(root)?;
    ensure!(
        root.starts_with("/nix/store"),
        "executable package escapes immutable store"
    );
    let executable = fs::canonicalize(path)?;
    ensure!(
        executable.starts_with(root),
        "executable escapes its package"
    );
    let metadata = fs::metadata(&executable)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "native tool is not executable"
    );
    Ok(executable)
}
