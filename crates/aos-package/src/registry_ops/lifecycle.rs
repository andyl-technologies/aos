//! Authoring-clone discovery, protection against data loss, and registry creation.

use crate::config::ApmConfig;
use crate::registry::keys::{KeysToml, RosterKey};
use crate::registry::{keys, objectstore};
use crate::registry_ops::git::{
    commit_registry, current_git_head, ensure_commit_identity, git, refresh_registry_object_store,
    require_commit_identity,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::trust::validate_roster_key_id;
use crate::registry_ops::workflow::{current_git_branch, git_branch_entries};
use crate::security::parse_signing_key;
use crate::types::validate_registry_name;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::path::{Path, PathBuf};

/// A registry clone present in the scope's registry-storage directory but
/// absent from the consumer configuration (`registries.d/`).
///
/// These are typically authoring clones made by `apr create`, which never
/// writes a `registries.d` entry; without this struct `apr list` would not
/// surface them at all.
#[derive(Debug)]
pub struct LocalRegistry {
    /// Directory name, which doubles as the registry name.
    pub name: String,
    /// Absolute path to the clone.
    pub path: PathBuf,
    /// URL of the `origin` remote, when the clone is a git repository that
    /// has one configured.
    pub origin: Option<String>,
    /// Number of package definition files under `packages/`.
    pub packages: usize,
}

/// List registry clones under `registries_path` whose name is not in
/// `configured`.
///
/// Returns entries sorted by name. Missing or unreadable directories yield an
/// empty list: this feeds an informational `apr list` section, not an
/// integrity check.
pub fn local_registries(registries_path: &Path, configured: &[&str]) -> Vec<LocalRegistry> {
    let Ok(entries) = std::fs::read_dir(registries_path) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if configured.contains(&name.as_str()) {
            continue;
        }
        let origin = git(&path, &["remote", "get-url", "origin"]).ok();
        let packages = count_package_tomls(&path.join("packages"));
        found.push(LocalRegistry {
            name,
            path,
            origin,
            packages,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// Count `.toml` files anywhere under `dir`.
fn count_package_tomls(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += count_package_tomls(&path);
        } else if path.extension().is_some_and(|ext| ext == "toml") {
            count += 1;
        }
    }
    count
}

/// Explain why deleting `dir` would lose work, if it would.
///
/// A directory under the registry-storage path is an authoring clone when it
/// contains a `.git` entry — consumer-side syncs only materialise plain files
/// there. Such a clone is precious when it holds uncommitted changes, has no
/// remote at all (every commit exists only here), or has commits unreachable
/// from any remote-tracking ref. Returns `Ok(None)` for consumer-extracted
/// directories and fully pushed clones.
///
/// # Errors
///
/// Fails when the directory looks like a git repository but git cannot
/// inspect it (e.g. a corrupted clone).
pub fn authoring_clone_precious(dir: &Path) -> Result<Option<String>> {
    if !dir.join(".git").exists() {
        return Ok(None);
    }

    let status = git(dir, &["status", "--porcelain"])?;
    if !status.is_empty() {
        return Ok(Some("uncommitted changes".to_string()));
    }

    if git(dir, &["remote"])?.is_empty() {
        return Ok(Some(
            "commits that exist nowhere else (no remote is configured)".to_string(),
        ));
    }

    let unpushed = git(
        dir,
        &["rev-list", "--count", "--branches", "--not", "--remotes"],
    )?;
    let unpushed: u64 = unpushed
        .parse()
        .with_context(|| format!("parsing unpushed commit count {unpushed:?}"))?;
    if unpushed > 0 {
        return Ok(Some(format!(
            "{unpushed} commit{} not pushed to any remote",
            if unpushed == 1 { "" } else { "s" },
        )));
    }

    Ok(None)
}

/// Build the initial `keys.toml` roster for `apr create`.
///
/// Without `--trust-key` the roster is empty. A provided trust key must
/// belong to `registry_name`; its roster id defaults to `"initial"`.
fn initial_keys_roster(
    registry_name: &str,
    trust_key: Option<&str>,
    trust_key_id: Option<&str>,
) -> Result<KeysToml> {
    let mut roster = KeysToml::default();

    let Some(trust_key) = trust_key else {
        if trust_key_id.is_some() {
            bail!("--trust-key-id requires --trust-key");
        }
        return Ok(roster);
    };

    let trust_key_id = trust_key_id.unwrap_or("initial");
    validate_roster_key_id(trust_key_id)?;

    let (key_registry, _algorithm, _public_key) = parse_signing_key(trust_key)?;
    if key_registry != registry_name {
        bail!(
            "--trust-key belongs to registry '{}', expected '{}'",
            key_registry,
            registry_name,
        );
    }

    roster.active.push(RosterKey {
        id: trust_key_id.to_string(),
        key: trust_key.to_string(),
    });
    Ok(roster)
}

/// `apr create <NAME>` — initializes a new registry authoring clone.
///
/// Creates a SHA-256 git repository at `<registries>/<NAME>` with `stable`
/// as the default branch, containing a skeleton `registry.toml`, an empty
/// `packages/` tree, and a `keys.toml` roster (seeded from `--trust-key` /
/// `--trust-key-id` when given). The initial commit is SSH-signed when a
/// `--key` or `--key-id` is supplied, the static dumb-HTTP object store is
/// refreshed, and `--remote` configures an `origin` remote on the clone.
///
/// # Errors
///
/// Fails when the registry directory already exists; when `--trust-key` is
/// given without a signing key (clients verify head-commit signatures from
/// first contact, so a seeded roster requires a signed root commit); when
/// no git commit identity is configured; when the trust key id is invalid;
/// when the trust key belongs to a different registry; or when a git
/// invocation or file write fails.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    config: &ApmConfig,
    name: &str,
    remote: Option<&str>,
    trust_key: Option<&str>,
    trust_key_id: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let dir = config.scope.registries_path().join(name);

    if dir.exists() {
        bail!("registry '{name}' already exists at {}", dir.display());
    }

    let roster = initial_keys_roster(name, trust_key, trust_key_id)?;

    // A registry seeded with a trust roster must start with a signed
    // commit: clients verify head-commit signatures from first contact,
    // and an unsigned root commit would never validate. Refuse before
    // creating anything on disk.
    if trust_key.is_some() && key.is_none() && key_id.is_none() {
        bail!(
            "--trust-key seeds a trust roster, so the initial commit must be signed: \
             pass --key <path> (or --key-id <id>) with the maintainer's private key"
        );
    }

    // The initial commit needs a maintainer identity; likewise refuse
    // before creating anything on disk.
    require_commit_identity()?;

    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    printer.info(&format!("Initializing registry '{name}'..."));

    git(&dir, &["init", "--object-format=sha256"])?;
    git(&dir, &["symbolic-ref", "HEAD", "refs/heads/stable"])?;
    objectstore::assert_sha256(&dir)?;

    ensure_commit_identity(&dir)?;

    // Create initial directory structure.
    std::fs::create_dir_all(dir.join("packages"))?;

    // Write a default registry.toml.
    let registry_toml = format!(
        r#"[registry]
name = "{name}"
description = ""
"#
    );
    std::fs::write(dir.join("registry.toml"), &registry_toml)?;
    keys::write_keys_toml(&dir, &roster)?;

    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config, &dir, name, key, key_id,
        )?)
    } else {
        None
    };

    // Initial commit.
    commit_registry(
        &dir,
        &format!("Initialize registry '{name}'"),
        signing_key.as_ref().map(|k| k.path()),
    )?;
    refresh_registry_object_store(&dir)
        .context("refreshing dumb-HTTP object store after registry creation")?;

    // Set remote if specified.
    if let Some(url) = remote {
        git(&dir, &["remote", "add", "origin", url])?;
        printer.kv("Remote", url);
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "create",
            "registry": name,
            "path": dir.display().to_string(),
            "remote": remote,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
            "trust_key_id": trust_key.map(|_| trust_key_id.unwrap_or("initial")),
        }));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' created at {}", dir.display()));

    Ok(())
}

#[cfg(test)]
mod tests;
