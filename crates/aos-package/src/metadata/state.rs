//! Last-known-good authenticated host input.
//!
//! Storage commit evidence belongs to the checked stage executor. This module
//! retains only the exact accepted configuration bytes needed when a later boot
//! cannot reacquire metadata.

use std::path::Path;

use anyhow::{Context, Result};

use super::provisioning::PROVISIONING_RESULT_FILE;

/// Default durable state directory.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/aos-provisioning";
/// Caches exact authorized runtime inputs after full evaluation succeeded.
///
/// Returns `Ok(false)` when no fresh authorized `host.nix` exists.
///
/// # Errors
///
/// Returns an error when the accepted-byte binding is invalid or the durable
/// cache cannot be atomically replaced.
pub fn cache_runtime_input(stash_dir: &Path, state_dir: &Path) -> Result<bool> {
    let host = stash_dir.join("host.nix");
    if !host.is_file() {
        return Ok(false);
    }
    super::provisioning::verify_host_binding(stash_dir)?;
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let temp = state_dir.join(format!("current.new.{}", std::process::id()));
    if temp.exists() {
        std::fs::remove_dir_all(&temp)
            .with_context(|| format!("removing stale {}", temp.display()))?;
    }
    std::fs::create_dir_all(&temp).with_context(|| format!("creating {}", temp.display()))?;
    copy_required(&host, &temp.join("host.nix"))?;
    copy_required(
        &stash_dir.join(PROVISIONING_RESULT_FILE),
        &temp.join(PROVISIONING_RESULT_FILE),
    )?;
    for file in ["facts.json", ".metadata-result.json"] {
        copy_optional(&stash_dir.join(file), &temp.join(file))?;
    }
    copy_optional(&stash_dir.join("user-data.sig"), &temp.join("host.nix.sig"))?;
    replace_directory(state_dir, "current", &temp)?;
    Ok(true)
}

/// Restores the last fully evaluated host input when fresh metadata is absent.
///
/// Restored bytes are checked against their recorded SHA-256 before becoming
/// visible to stage-2 evaluation.
///
/// # Errors
///
/// Returns an error when cached state is incomplete, its binding is invalid,
/// or files cannot be copied into the volatile stash.
pub fn restore_runtime_input(stash_dir: &Path, state_dir: &Path) -> Result<bool> {
    if stash_dir.join("host.nix").is_file() {
        return Ok(false);
    }
    let current = if state_dir.join("current").is_dir() {
        state_dir.join("current")
    } else if state_dir.join("current.old").is_dir() {
        state_dir.join("current.old")
    } else {
        return Ok(false);
    };
    std::fs::create_dir_all(stash_dir)
        .with_context(|| format!("creating {}", stash_dir.display()))?;
    for file in [
        "host.nix",
        PROVISIONING_RESULT_FILE,
        "facts.json",
        ".metadata-result.json",
        "user-data.sig",
    ] {
        let path = stash_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("clearing stale {}", path.display()))?;
        }
    }
    copy_required(&current.join("host.nix"), &stash_dir.join("host.nix"))?;
    copy_required(
        &current.join(PROVISIONING_RESULT_FILE),
        &stash_dir.join(PROVISIONING_RESULT_FILE),
    )?;
    for file in ["facts.json", ".metadata-result.json"] {
        copy_optional(&current.join(file), &stash_dir.join(file))?;
    }
    copy_optional(
        &current.join("host.nix.sig"),
        &stash_dir.join("user-data.sig"),
    )?;
    if let Err(error) = super::provisioning::verify_host_binding(stash_dir) {
        for file in ["host.nix", PROVISIONING_RESULT_FILE] {
            let path = stash_dir.join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing invalid {}", path.display()))?;
            }
        }
        return Err(error).context("validating cached host input");
    }
    Ok(true)
}

fn replace_directory(state_dir: &Path, name: &str, temp: &Path) -> Result<()> {
    let destination = state_dir.join(name);
    let backup = state_dir.join(format!("{name}.old"));
    if backup.exists() {
        std::fs::remove_dir_all(&backup)
            .with_context(|| format!("removing {}", backup.display()))?;
    }
    if destination.exists() {
        std::fs::rename(&destination, &backup)
            .with_context(|| format!("moving {} to {}", destination.display(), backup.display()))?;
    }
    if let Err(error) = std::fs::rename(temp, &destination) {
        if backup.exists() && !destination.exists() {
            std::fs::rename(&backup, &destination).with_context(|| {
                format!(
                    "restoring {} after failed replacement",
                    destination.display()
                )
            })?;
        }
        return Err(error)
            .with_context(|| format!("installing durable directory {}", destination.display()));
    }
    if backup.exists() {
        std::fs::remove_dir_all(&backup)
            .with_context(|| format!("removing {}", backup.display()))?;
    }
    Ok(())
}

fn copy_required(source: &Path, destination: &Path) -> Result<()> {
    std::fs::copy(source, destination)
        .with_context(|| format!("copying {} to {}", source.display(), destination.display()))?;
    Ok(())
}

fn copy_optional(source: &Path, destination: &Path) -> Result<()> {
    if source.is_file() {
        copy_required(source, destination)?;
    }
    Ok(())
}
