//! Authoring-clone discovery, protection against data loss, and registry creation.

use aos_registry_client::config::ApmConfig;
use aos_registry_client::registry::keys::{KeysToml, RosterKey};
use crate::registry::{keys, objectstore};
use crate::registry_ops::git::{
    commit_registry, current_git_head, ensure_commit_identity, git, refresh_registry_object_store,
    require_commit_identity,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::trust::validate_roster_key_id;
use crate::registry_ops::workflow::{current_git_branch, git_branch_entries};
use aos_registry_client::security::parse_signing_key;
use aos_registry_client::types::validate_registry_name;
use anyhow::{Context, Result, bail};
use aos_cli_ui::output::{OutputMode, Printer};
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

/// Roster id given to the `--trust-key` entry when `--trust-key-id` is absent.
const DEFAULT_TRUST_KEY_ID: &str = "initial";

/// The trust roster `apr create` commits in a registry's root commit.
///
/// A first canonical release plans from a clone that is exactly its single
/// root commit, so every key that release needs, such as a package-provenance
/// signer distinct from the commit signer, must already be active here. A
/// later `apr keys add` commit would make the clone ineligible as a first
/// release base.
#[derive(Debug, Clone, Copy, Default)]
pub struct InitialRoster<'a> {
    /// Primary `<registry>:Ed25519:<base64>` trust line (`--trust-key`). It is
    /// written first, and its private half signs the root commit.
    pub trust_key: Option<&'a str>,
    /// Roster id for [`Self::trust_key`] (`--trust-key-id`); defaults to
    /// `"initial"`.
    pub trust_key_id: Option<&'a str>,
    /// Additional active keys as `<id>=<registry>:Ed25519:<base64>`
    /// (`--roster-key`), written after the primary key in the given order.
    pub roster_keys: &'a [String],
}

impl InitialRoster<'_> {
    /// Returns the roster id of the primary key, or `None` without
    /// `--trust-key`.
    fn primary_key_id(&self) -> Option<&str> {
        self.trust_key
            .map(|_| self.trust_key_id.unwrap_or(DEFAULT_TRUST_KEY_ID))
    }
}

/// Build the initial `keys.toml` roster for `apr create`.
///
/// Without `--trust-key` the roster is empty, and neither `--trust-key-id`
/// nor `--roster-key` is accepted. Every key must belong to `registry_name`,
/// and no two entries may share an id or a public key.
fn initial_keys_roster(registry_name: &str, request: &InitialRoster<'_>) -> Result<KeysToml> {
    let mut roster = KeysToml::default();

    let Some(trust_key) = request.trust_key else {
        if request.trust_key_id.is_some() {
            bail!("--trust-key-id requires --trust-key");
        }
        if !request.roster_keys.is_empty() {
            bail!("--roster-key requires --trust-key");
        }
        return Ok(roster);
    };

    let trust_key_id = request.trust_key_id.unwrap_or(DEFAULT_TRUST_KEY_ID);
    push_initial_key(
        &mut roster,
        registry_name,
        "--trust-key",
        trust_key_id,
        trust_key,
    )?;

    for argument in request.roster_keys {
        let (id, key) = split_roster_key_argument(argument)?;
        push_initial_key(
            &mut roster,
            registry_name,
            &format!("--roster-key '{id}'"),
            id,
            key,
        )?;
    }

    Ok(roster)
}

/// Split a `--roster-key` value into its roster id and trust line.
///
/// Base64 padding means a bare trust line can contain `=`, but a roster id
/// never contains `:`. A prefix with `:` therefore marks a missing `<id>=`
/// rather than an invalid id.
fn split_roster_key_argument(argument: &str) -> Result<(&str, &str)> {
    argument
        .split_once('=')
        .filter(|(id, _key)| !id.contains(':'))
        .with_context(|| {
            format!(
                "--roster-key '{argument}' must have the form \
                 <id>=<registry>:Ed25519:<base64>"
            )
        })
}

/// Append one active key to an initial roster.
///
/// `flag` names the command-line source of the key in error messages.
/// Validation matches `--trust-key`: a well-formed roster id, a
/// `registry:Ed25519:<base64>` line bound to `registry_name`, and no id or
/// public key already present in the roster.
fn push_initial_key(
    roster: &mut KeysToml,
    registry_name: &str,
    flag: &str,
    id: &str,
    key: &str,
) -> Result<()> {
    validate_roster_key_id(id).with_context(|| format!("invalid {flag} id"))?;
    if keys::active_key_by_id(roster, id).is_some() {
        bail!("{flag} reuses roster key id '{id}'");
    }

    let (key_registry, _algorithm, _public_key) =
        parse_signing_key(key).with_context(|| format!("invalid {flag} trust line"))?;
    if key_registry != registry_name {
        bail!("{flag} belongs to registry '{key_registry}', expected '{registry_name}'");
    }

    // Every accepted line shares this registry and the Ed25519 algorithm, so
    // equal lines are exactly equal public keys.
    if let Some(existing) = roster.active.iter().find(|entry| entry.key == key) {
        bail!(
            "{flag} repeats the public key of roster key '{}'",
            existing.id
        );
    }

    roster.active.push(RosterKey {
        id: id.to_string(),
        key: key.to_string(),
    });
    Ok(())
}

/// `apr create <NAME>` — initializes a new registry authoring clone.
///
/// Creates a SHA-256 git repository at `<registries>/<NAME>` with `stable`
/// as the default branch, containing a skeleton `registry.toml`, an empty
/// `packages/` tree, and a `keys.toml` roster built from `roster` (the
/// `--trust-key` entry first, then each `--roster-key` entry in order). The
/// initial commit is SSH-signed when a `--key` or `--key-id` is supplied, the
/// static dumb-HTTP object store is refreshed, and `--remote` configures an
/// `origin` remote on the clone.
///
/// In dry-run mode ([`crate::dry_run`]), every precondition is still checked
/// and reported, but the function returns before the first write and no
/// registry is created.
///
/// # Errors
///
/// Fails when the registry directory already exists; when `--trust-key` is
/// given without a signing key (clients verify head-commit signatures from
/// first contact, so a seeded roster requires a signed root commit); when
/// no git commit identity is configured; when `--trust-key-id` or
/// `--roster-key` is given without `--trust-key`; when a roster key id is
/// invalid or repeated; when a trust line is malformed, belongs to a
/// different registry, or repeats another entry's public key; or when a git
/// invocation or file write fails.
pub async fn create(
    config: &ApmConfig,
    name: &str,
    remote: Option<&str>,
    roster: &InitialRoster<'_>,
    key: Option<&str>,
    key_id: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let dir = config.scope.registries_path().join(name);

    if dir.exists() {
        bail!("registry '{name}' already exists at {}", dir.display());
    }

    let keys_toml = initial_keys_roster(name, roster)?;
    let roster_key_ids = extra_roster_key_ids(&keys_toml);

    // A registry seeded with a trust roster must start with a signed
    // commit: clients verify head-commit signatures from first contact,
    // and an unsigned root commit would never validate. Refuse before
    // creating anything on disk.
    if roster.trust_key.is_some() && key.is_none() && key_id.is_none() {
        bail!(
            "--trust-key seeds a trust roster, so the initial commit must be signed: \
             pass --key <path> (or --key-id <id>) with the maintainer's private key"
        );
    }

    // The initial commit needs a maintainer identity; likewise refuse
    // before creating anything on disk.
    require_commit_identity()?;

    // Every check above is a pure inspection, so a dry run reaches this point
    // having reported exactly the failures a real run would. Stop before the
    // first write: a registry root commit is a trust anchor, and creating one
    // that the operator only asked to preview would silently establish an
    // identity that later releases pin.
    if aos_registry_client::dry_run::active() {
        report_planned_create(
            name,
            &dir,
            remote,
            roster.primary_key_id(),
            &roster_key_ids,
            printer,
        );
        return Ok(());
    }

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
    keys::write_keys_toml(&dir, &keys_toml)?;

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
            "trust_key_id": roster.primary_key_id(),
            "roster_key_ids": roster_key_ids,
        }));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' created at {}", dir.display()));

    Ok(())
}

/// Returns the ids of the `--roster-key` entries in an initial roster.
///
/// [`initial_keys_roster`] always writes the `--trust-key` entry first, so
/// every later active entry came from `--roster-key`.
fn extra_roster_key_ids(roster: &KeysToml) -> Vec<&str> {
    roster
        .active
        .iter()
        .skip(1)
        .map(|entry| entry.id.as_str())
        .collect()
}

/// Reports the registry a real `create` would write, without touching disk.
///
/// The head commit and branch listing the non-dry-run JSON carries are
/// deliberately absent: they do not exist yet, and inventing them would let a
/// caller mistake a preview for a created registry.
fn report_planned_create(
    name: &str,
    dir: &Path,
    remote: Option<&str>,
    trust_key_id: Option<&str>,
    roster_key_ids: &[&str],
    printer: &Printer,
) {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "create",
            "dry_run": true,
            "registry": name,
            "path": dir.display().to_string(),
            "remote": remote,
            "trust_key_id": trust_key_id,
            "roster_key_ids": roster_key_ids,
        }));
        return;
    }

    printer.info(&format!(
        "Would create registry '{name}' at {}",
        dir.display()
    ));
    if let Some(url) = remote {
        printer.kv("Would set remote", url);
    }
    if let Some(id) = trust_key_id {
        printer.kv("Would seed trust key", id);
    }
    for id in roster_key_ids {
        printer.kv("Would seed roster key", id);
    }
    printer.info("Dry run: nothing was written.");
}

#[cfg(test)]
mod tests;
