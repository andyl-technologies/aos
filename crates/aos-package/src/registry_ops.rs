//! Registry management operations (`apr` / `apm registry`).
//!
//! This module implements producer-side tooling for maintaining AOS package
//! registries. It operates on local git clones stored at
//! `~/.local/share/apm/registries/<name>/`.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_cache::AuthOptions;
use aos_core::nar::info as narinfo;
use aos_core::nix::aos_nix_env;
use serde_json::Value;

use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::gitcmd;
use crate::registry::channel::{self, PartitionMap};
use crate::registry::keys::{self, KeysToml, RevokedKey, RosterKey};
use crate::registry::nixcache;
use crate::registry::objectstore;
use crate::registry::pack;
use crate::registry::state;
use crate::registry::static_upload;
use crate::registry::verify::{TagTarget, parse_tag_object, verify_name_binding};
use crate::security::{
    KeySource, KeyStore, TrustedKey, key_fingerprint, parse_signing_key, verify_tag_signature,
};
use crate::sshkey;
use crate::types::{CacheEntry, RegistryConfig, RegistryRootConfig};
use crate::{
    BranchCommand, CacheCommand, CacheUploadAuthArgs, ChannelCommand, KeysCommand, OriginCommand,
    TrustCommand,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the registry storage directory for a given registry name.
fn registry_dir(config: &ApmConfig, registry: Option<&str>) -> Result<PathBuf> {
    let name = resolve_registry_name(config, registry)?;
    Ok(config.scope.registries_path().join(&name))
}

/// Resolve which registry to operate on.
///
/// If `registry` is specified, use it. Otherwise, if there is exactly one
/// registry, use it. Otherwise bail with an error.
fn resolve_registry_name(config: &ApmConfig, registry: Option<&str>) -> Result<String> {
    if let Some(name) = registry {
        return Ok(name.to_string());
    }

    // Check the registries storage directory for available clones.
    let registries_path = config.scope.registries_path();
    if registries_path.is_dir() {
        let mut names: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&registries_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        if names.len() == 1 {
            return Ok(names.into_iter().next().unwrap());
        }
        if names.len() > 1 {
            bail!(
                "multiple registries found ({}). Use --registry to specify one.",
                names.join(", ")
            );
        }
    }

    // Fall back to configured registries.
    if config.registries.len() == 1 {
        return Ok(config.registries[0].0.name.clone());
    }
    if config.registries.is_empty() {
        bail!("no registries configured. Add one with `apr create <name>` or `apr add <url>`.");
    }
    let names: Vec<&str> = config
        .registries
        .iter()
        .map(|(c, _)| c.name.as_str())
        .collect();
    bail!(
        "multiple registries configured ({}). Use --registry to specify one.",
        names.join(", ")
    );
}

/// Run a git command in the registry directory, returning stdout.
///
/// Runs hermetically (see [`crate::gitcmd`]): host git configuration is
/// hidden. Network transport commands must use [`git_transport`] instead.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = gitcmd::hermetic()
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git network-transport command (push, pull) in the registry
/// directory, returning stdout.
///
/// Unlike [`git`], the host configuration stays visible: credential
/// helpers, proxies, and URL rewrites live there.
fn git_transport(dir: &Path, args: &[&str]) -> Result<String> {
    let output = gitcmd::transport()
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command in the registry directory, returning raw stdout bytes.
fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = gitcmd::hermetic()
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(output.stdout)
}

fn nix_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.envs(aos_nix_env());
    command
}

/// Run a git command that is allowed to fail, returning (success, stdout, stderr).
#[allow(dead_code)]
fn git_try(dir: &Path, args: &[&str]) -> Result<(bool, String, String)> {
    let output = gitcmd::hermetic()
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok((output.status.success(), stdout, stderr))
}

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

/// Parse a Nix store path into (name, version).
///
/// Format: `/nix/store/{hash}-{name}-{version}`
fn parse_store_path(store_path: &str) -> (String, String) {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    // Skip the hash prefix (32 chars + dash).
    let name_version = if basename.len() >= 33 {
        &basename[33..]
    } else {
        basename
    };

    // Split into name and version. The version is the last segment that
    // starts with a digit.
    let parts: Vec<&str> = name_version.split('-').collect();
    let mut name_parts = Vec::new();
    let mut version_parts = Vec::new();
    let mut in_version = false;

    for part in &parts {
        if !in_version
            && part
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            in_version = true;
        }
        if in_version {
            version_parts.push(*part);
        } else {
            name_parts.push(*part);
        }
    }

    let name = if name_parts.is_empty() {
        name_version.to_string()
    } else {
        name_parts.join("-")
    };
    let version = version_parts.join("-");

    (
        name,
        if version.is_empty() {
            "0.0.0".into()
        } else {
            version
        },
    )
}

/// Get the first letter of a name for directory bucketing.
fn first_letter(name: &str) -> String {
    name.chars()
        .next()
        .unwrap_or('_')
        .to_lowercase()
        .to_string()
}

/// Get the default platform string.
#[allow(dead_code)]
fn default_platform() -> String {
    if cfg!(target_arch = "x86_64") {
        "x86_64-linux".to_string()
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-linux".to_string()
    } else {
        "x86_64-linux".to_string()
    }
}

/// Introspect a store path using `nix path-info --json --closure-size`.
fn introspect_store_path(store_path: &str) -> Result<StorePathInfo> {
    let output = nix_command("nix")
        .args(["path-info", "--json", "--closure-size", store_path])
        .output()
        .with_context(|| format!("running nix path-info on {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix path-info failed for {store_path}: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .with_context(|| format!("parsing nix path-info JSON for {store_path}"))?;

    // nix path-info --json returns an array with one element per path,
    // or a map keyed by store path (depending on Nix version).
    let info = if json.is_array() {
        json.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or(json.clone())
    } else if json.is_object() {
        // Newer Nix: { "/nix/store/...": { ... } }
        json.as_object()
            .and_then(|obj| obj.values().next())
            .cloned()
            .unwrap_or(json.clone())
    } else {
        json.clone()
    };

    let nar_hash = info
        .get("narHash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let nar_size = info.get("narSize").and_then(|v| v.as_u64()).unwrap_or(0);
    let path = info
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or(store_path)
        .to_string();
    let closure_size = info
        .get("closureSize")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let references: Vec<String> = info
        .get("references")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|r| *r != store_path)
                .map(|r| {
                    // Extract just the hash from the reference path.
                    let basename = r.rsplit('/').next().unwrap_or(r);
                    basename.split('-').next().unwrap_or(basename).to_string()
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(StorePathInfo {
        path,
        nar_hash,
        nar_size,
        references,
        closure_size,
    })
}

/// Return metadata for the derivation that produced `store_path`, if known.
fn introspect_deriver(store_path: &str) -> Result<Option<StorePathInfo>> {
    let output = nix_command("nix-store")
        .args(["-q", "--deriver", store_path])
        .output()
        .with_context(|| format!("querying deriver for {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store --query --deriver failed for {store_path}: {}",
            stderr.trim()
        );
    }

    let deriver = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if deriver.is_empty() || deriver == "unknown-deriver" || !deriver.starts_with("/nix/store/") {
        return Ok(None);
    }
    if !Path::new(&deriver).exists() {
        return Ok(None);
    }

    introspect_store_path(&deriver)
        .with_context(|| format!("introspecting source derivation {deriver}"))
        .map(Some)
}

struct StorePathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    closure_size: u64,
}

/// Compute the full transitive closure of a store path.
///
/// Returns a list of `(store_hash, Vec<direct_dep_hashes>)` pairs in
/// dependency order (leaves first, root last).  Uses `nix-store -qR` to
/// enumerate the closure and `nix-store -q --references` for each member.
fn compute_closure(store_path: &str) -> Result<Vec<(String, Vec<String>)>> {
    // Get the full closure via nix-store -qR.
    let output = nix_command("nix-store")
        .args(["-qR", store_path])
        .output()
        .with_context(|| format!("running nix-store -qR {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix-store -qR failed for {store_path}: {}", stderr.trim());
    }

    let closure_paths: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    // For each path in the closure, get its direct references.
    let mut result = Vec::with_capacity(closure_paths.len());
    for path in &closure_paths {
        let ref_output = nix_command("nix-store")
            .args(["-q", "--references", path])
            .output()
            .with_context(|| format!("running nix-store -q --references {path}"))?;

        let refs: Vec<String> = if ref_output.status.success() {
            String::from_utf8_lossy(&ref_output.stdout)
                .lines()
                .filter(|l| !l.is_empty() && *l != path)
                .map(|l| extract_hash(l).to_string())
                .collect()
        } else {
            Vec::new()
        };

        result.push((extract_hash(path).to_string(), refs));
    }

    Ok(result)
}

/// Write closure files for a store path and all its closure members.
///
/// Creates `closures/{hash}` for the root store path as an adjacency list.
/// Also ensures `.gitattributes` has the `closures/** -diff` entry.
fn write_closure_files(dir: &Path, store_path: &str) -> Result<()> {
    let closure = compute_closure(store_path)?;
    if closure.is_empty() {
        return Ok(());
    }

    let closures_dir = dir.join("closures");
    std::fs::create_dir_all(&closures_dir)?;

    // Build the adjacency list file content.
    // Root should be first line — nix-store -qR returns deps-first order,
    // so the root is typically last.  Reorder: root first, then the rest.
    let root_hash = extract_hash(store_path).to_string();
    let mut lines = String::new();

    // Root line first.
    if let Some((_, deps)) = closure.iter().find(|(h, _)| *h == root_hash) {
        lines.push_str(&root_hash);
        for dep in deps {
            lines.push(' ');
            lines.push_str(dep);
        }
        lines.push('\n');
    }

    // Then the rest in dependency order.
    for (hash, deps) in &closure {
        if *hash == root_hash {
            continue;
        }
        lines.push_str(hash);
        for dep in deps {
            lines.push(' ');
            lines.push_str(dep);
        }
        lines.push('\n');
    }

    std::fs::write(closures_dir.join(&root_hash), &lines)?;

    // Ensure .gitattributes has the closures entry.
    ensure_gitattributes(dir)?;

    Ok(())
}

/// Ensure `.gitattributes` contains `closures/** -diff`.
fn ensure_gitattributes(dir: &Path) -> Result<()> {
    let path = dir.join(".gitattributes");
    let entry = "closures/** -diff\n";

    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        if content.contains("closures/** -diff") {
            return Ok(());
        }
        // Append the entry.
        let mut new_content = content;
        if !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(entry);
        std::fs::write(&path, new_content)?;
    } else {
        std::fs::write(&path, entry)?;
    }

    Ok(())
}

/// Extract the store path hash from a full store path.
fn extract_hash(store_path: &str) -> &str {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    basename.split('-').next().unwrap_or(basename)
}

/// Whether the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment variables fully
/// specify a commit identity. They take precedence over any git config and
/// are how hermetic environments (VM tests, build sandboxes) provide one.
fn env_commit_identity() -> bool {
    [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ]
    .iter()
    .all(|var| std::env::var_os(var).is_some_and(|value| !value.is_empty()))
}

/// Read `key` from the host's global git config, failing when it is unset.
///
/// Registry commits record who published, so a missing identity is a setup
/// error, not something to paper over with a placeholder.
fn host_identity_value(key: &str) -> Result<String> {
    gitcmd::host_config_value(key).ok_or_else(|| {
        anyhow::anyhow!(
            "registry commits record the maintainer's identity, but git {key} is not set.\n\
             Set it with `git config --global {key} <value>`."
        )
    })
}

/// Check that a commit identity is available, without touching any repo.
///
/// Used by [`create`] to refuse before creating anything on disk.
fn require_commit_identity() -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }
    for key in ["user.email", "user.name"] {
        host_identity_value(key)?;
    }
    Ok(())
}

/// Ensure the maintainer's identity is available for commits in `dir`.
///
/// Registry git invocations are hermetic (see [`crate::gitcmd`]), so an
/// identity living only in the maintainer's global config is invisible to
/// them; capture it into the clone, preserving commit attribution.
///
/// # Errors
///
/// Fails when no identity is configured in the environment, the clone, or
/// the host's global config.
fn ensure_commit_identity(dir: &Path) -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }

    for key in ["user.email", "user.name"] {
        if git(dir, &["config", key]).is_ok() {
            continue;
        }
        let host = host_identity_value(key)?;
        git(dir, &["config", key, &host])?;
    }
    Ok(())
}

fn registry_relative_path(dir: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(dir)
        .with_context(|| format!("{} is not under {}", path.display(), dir.display()))?;
    rel.to_str()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("registry path is not UTF-8: {}", path.display()))
}

fn commit_staged_registry(dir: &Path, message: &str, signing_key: Option<&str>) -> Result<()> {
    match signing_key {
        Some(key) => {
            let signing_key_config = format!("user.signingkey={key}");
            git(
                dir,
                &[
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    &signing_key_config,
                    "commit",
                    "-S",
                    "-m",
                    message,
                ],
            )?;
        }
        None => {
            git(dir, &["commit", "-m", message])?;
        }
    }
    Ok(())
}

/// Create a git commit for a constrained set of registry paths.
fn commit_registry_paths(
    dir: &Path,
    message: &str,
    paths: &[PathBuf],
    signing_key: Option<&str>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("no registry paths supplied for commit");
    }

    ensure_commit_identity(dir)?;

    let relative_paths = paths
        .iter()
        .map(|path| registry_relative_path(dir, path))
        .collect::<Result<Vec<_>>>()?;

    let output = gitcmd::hermetic()
        .arg("add")
        .arg("-A")
        .arg("--")
        .args(&relative_paths)
        .current_dir(dir)
        .output()
        .with_context(|| {
            format!(
                "running git add for {} constrained path(s) in {}",
                relative_paths.len(),
                dir.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git add failed: {}", stderr.trim());
    }

    commit_staged_registry(dir, message, signing_key)
}

/// Create a git commit in the registry directory.
///
/// When `signing_key` is the path to an OpenSSH Ed25519 private key, the
/// commit is SSH-signed (`gpg.format=ssh`), matching the tag-signing setup
/// in [`sign_tag`]. Clients verify head-commit signatures during sync, so
/// commits on registries with a non-empty trust roster should always be
/// signed.
fn commit_registry(dir: &Path, message: &str, signing_key: Option<&str>) -> Result<()> {
    ensure_commit_identity(dir)?;
    git(dir, &["add", "-A"])?;
    commit_staged_registry(dir, message, signing_key)
}

/// Refresh the static dumb-HTTP object indexes after refs or commits change.
fn refresh_registry_object_store(dir: &Path) -> Result<()> {
    objectstore::assert_sha256(dir)?;
    let releases = semver_tag_versions(dir)?;
    for release in &releases {
        objectstore::write_release_objects(dir, release, &release.to_string())
            .with_context(|| format!("preparing release object dir for {release}"))?;
    }
    objectstore::write_alternates(dir, &releases)?;
    objectstore::ensure_loose_completeness(dir)?;
    objectstore::refresh_server_info(dir)?;
    Ok(())
}

fn semver_tag_versions(dir: &Path) -> Result<Vec<semver::Version>> {
    let tags = git(dir, &["tag", "--list"])?;
    Ok(semver_versions_from_tag_list(&tags))
}

fn semver_versions_from_tag_list(tags: &str) -> Vec<semver::Version> {
    let mut versions: Vec<semver::Version> = tags
        .lines()
        .filter_map(|tag| semver::Version::parse(tag.trim()).ok())
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

/// Read and parse registry.toml from a registry directory.
fn read_registry_toml(dir: &Path) -> Result<Option<RegistryRootConfig>> {
    let path = dir.join("registry.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let config: RegistryRootConfig =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

/// Resolve mirror URLs for a registry by reading its registry.toml.
pub fn resolve_mirrors(dir: &Path) -> Vec<CacheEntry> {
    match read_registry_toml(dir) {
        Ok(Some(config)) if !config.caches.is_empty() => {
            let mut caches = config.caches;
            caches.sort_by(|a, b| b.priority.cmp(&a.priority));
            caches
        }
        _ => Vec::new(),
    }
}

/// Resolve mirror URLs from committed registry.toml plus client-side overrides.
pub fn resolve_mirrors_for_registry(
    dir: &Path,
    registry: &crate::types::RegistryConfig,
) -> Vec<CacheEntry> {
    let mut caches = registry.caches.clone();
    caches.extend(resolve_mirrors(dir));
    caches.sort_by(|a, b| b.priority.cmp(&a.priority));
    caches
}

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
    if trust_key_id.trim().is_empty() {
        bail!("--trust-key-id cannot be empty when --trust-key is provided");
    }

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

// ---------------------------------------------------------------------------
// Registry Lifecycle
// ---------------------------------------------------------------------------

/// `apr create <NAME>`
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
    let dir = config.scope.registries_path().join(name);

    if dir.exists() {
        bail!("registry '{name}' already exists at {}", dir.display());
    }

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
    let roster = initial_keys_roster(name, trust_key, trust_key_id)?;
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
        signing_key.as_deref(),
    )?;
    refresh_registry_object_store(&dir)
        .context("refreshing dumb-HTTP object store after registry creation")?;

    // Set remote if specified.
    if let Some(url) = remote {
        git(&dir, &["remote", "add", "origin", url])?;
        printer.kv("Remote", url);
    }

    printer.success(&format!("Registry '{name}' created at {}", dir.display()));

    Ok(())
}

// ---------------------------------------------------------------------------
// Publish / Unpublish
// ---------------------------------------------------------------------------

/// `apr publish <STORE_PATH>`
#[allow(clippy::too_many_arguments)]
pub async fn publish(
    config: &ApmConfig,
    store_path: &str,
    name_override: Option<&str>,
    version_override: Option<&str>,
    platform_override: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_paths: &[String],
    image_formats: &[String],
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&name);
    ensure_writable_registry_clone(&name, &dir)?;
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config, &dir, &name, key, key_id,
        )?)
    } else {
        None
    };

    // Validate image pairs.
    if image_paths.len() != image_formats.len() {
        bail!(
            "--image and --image-format must be specified in pairs ({} images, {} formats)",
            image_paths.len(),
            image_formats.len()
        );
    }

    printer.step(1, 4, "Introspecting store path...");
    let info = introspect_store_path(store_path)?;
    let source_info = introspect_deriver(&info.path)?;

    // Introspect image store paths if provided.
    let mut image_infos: Vec<(String, StorePathInfo)> = Vec::new();
    for (img_path, img_fmt) in image_paths.iter().zip(image_formats.iter()) {
        let img_info = introspect_store_path(img_path)?;
        image_infos.push((img_fmt.clone(), img_info));
    }

    let (parsed_name, parsed_version) = parse_store_path(&info.path);
    let pkg_name = name_override.unwrap_or(&parsed_name);
    let pkg_version = version_override.unwrap_or(&parsed_version);
    let platform = platform_override
        .map(|s| s.to_string())
        .unwrap_or_else(default_platform);

    printer.step(2, 4, "Writing package TOML...");
    let letter = first_letter(pkg_name);
    let pkg_dir = dir.join("packages").join(&letter);
    std::fs::create_dir_all(&pkg_dir)?;

    let toml_path = pkg_dir.join(format!("{pkg_name}.toml"));

    // Read existing TOML if it exists, or create a new one.
    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        String::new()
    };

    let new_content = build_package_toml(
        &content,
        pkg_name,
        pkg_version,
        &platform,
        &info,
        description,
        homepage,
        license,
        maintainer,
        sysroot,
        previous,
        &image_infos,
        source_info.as_ref(),
    )?;

    std::fs::write(&toml_path, &new_content)?;

    printer.step(3, 4, "Computing closure...");
    write_closure_files(&dir, &info.path)
        .with_context(|| format!("writing closure files for {}", info.path))?;

    printer.step(4, 4, "Done.");
    printer.kv("Package", pkg_name);
    printer.kv("Version", pkg_version);
    printer.kv("Platform", &platform);
    printer.kv("Store path", &info.path);
    printer.kv("NAR hash", &info.nar_hash);
    printer.kv("NAR size", &format_size(info.nar_size));
    printer.kv("Closure size", &format_size(info.closure_size));
    if let Some(source_info) = &source_info {
        printer.kv("Source drv", &source_info.path);
    }
    if sysroot {
        printer.kv("Sysroot", "true");
    }
    if let Some(prev) = previous {
        printer.kv("Previous", prev);
    }
    for (fmt, img_info) in &image_infos {
        printer.kv(&format!("Image ({fmt})"), &img_info.path);
    }

    if !no_commit {
        let default_msg = format!("publish {pkg_name} {pkg_version} ({platform})");
        let msg = message.unwrap_or(&default_msg);
        let staged_paths = [
            toml_path,
            dir.join("closures").join(extract_hash(&info.path)),
            dir.join(".gitattributes"),
        ];
        commit_registry_paths(&dir, msg, &staged_paths, signing_key.as_deref())?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after publish")?;
        printer.success(&format!("Committed: {msg}"));
    } else {
        printer.info("Skipped commit (--no-commit).");
    }

    Ok(())
}

fn ensure_writable_registry_clone(name: &str, dir: &Path) -> Result<()> {
    if dir.join(".git").is_dir() {
        return Ok(());
    }

    bail!(
        "registry '{name}' has no writable local clone at {path}.\n\
         `{pkg} update --registry {name}` only syncs consumer metadata; it cannot create an \
         APR publishing worktree.\n\
         To publish, remove and re-add the registry without `--no-clone`, or author a new \
         local registry with `{reg} create {name}`.",
        path = dir.display(),
        reg = aos_core::invocation::package_registry_command(),
        pkg = aos_core::invocation::package_manager_command(),
    );
}

/// Build package TOML content, merging with existing content if present.
#[allow(clippy::too_many_arguments)]
fn build_package_toml(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_infos: &[(String, StorePathInfo)],
    source_info: Option<&StorePathInfo>,
) -> Result<String> {
    let desc = description.unwrap_or("No description");
    let lic = license.unwrap_or("unknown");
    let maint = maintainer.unwrap_or("unknown");
    let source_drv = source_info
        .map(|source| source.path.as_str())
        .unwrap_or_default();
    let source_nar_hash = source_info
        .map(|source| source.nar_hash.as_str())
        .unwrap_or_default();

    if existing.is_empty() {
        // Create new TOML.
        let mut content = format!("[package]\nname = \"{name}\"\ndescription = \"{desc}\"\n");
        if sysroot {
            content.push_str("sysroot = true\n");
        }
        if let Some(hp) = homepage {
            content.push_str(&format!("homepage = \"{hp}\"\n"));
        }
        content.push_str(&format!(
            "license = \"{lic}\"\nmaintainer = \"{maint}\"\n\n"
        ));
        content.push_str(&format!("[[versions]]\nversion = \"{version}\"\n"));
        if let Some(prev) = previous {
            content.push_str(&format!("previous = \"{prev}\"\n"));
        }
        content.push_str(&format!(
            "\n[versions.platforms.{platform}]\n\
             store_path = \"{}\"\n\
             nar_hash = \"{}\"\n\
             nar_size = {}\n\
             closure_size = {}\n\
             source_drv = \"{}\"\n\
             source_nar_hash = \"{}\"\n\
             references = [{}]\n",
            info.path,
            info.nar_hash,
            info.nar_size,
            info.closure_size,
            source_drv,
            source_nar_hash,
            info.references
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", "),
        ));
        // Append image entries if provided.
        for (fmt, img_info) in image_infos {
            content.push_str(&format!(
                "\n[[versions.platforms.{platform}.images]]\n\
                 format = \"{fmt}\"\n\
                 store_path = \"{}\"\n\
                 nar_hash = \"{}\"\n\
                 nar_size = {}\n",
                img_info.path, img_info.nar_hash, img_info.nar_size,
            ));
        }
        Ok(content)
    } else {
        // Parse existing, add/update the version+platform entry.
        let mut toml_val: toml::Value =
            toml::from_str(existing).context("parsing existing package TOML")?;

        // Set sysroot flag on the [package] section if requested.
        if sysroot {
            if let Some(pkg) = toml_val.get_mut("package").and_then(|v| v.as_table_mut()) {
                pkg.insert("sysroot".into(), toml::Value::Boolean(true));
            }
        }

        // Ensure versions array exists.
        let versions = toml_val.get_mut("versions").and_then(|v| v.as_array_mut());

        let platform_table = {
            let mut t = toml::map::Map::new();
            t.insert("store_path".into(), toml::Value::String(info.path.clone()));
            t.insert(
                "nar_hash".into(),
                toml::Value::String(info.nar_hash.clone()),
            );
            t.insert(
                "nar_size".into(),
                toml::Value::Integer(info.nar_size as i64),
            );
            t.insert(
                "closure_size".into(),
                toml::Value::Integer(info.closure_size as i64),
            );
            t.insert(
                "source_drv".into(),
                toml::Value::String(source_drv.to_string()),
            );
            t.insert(
                "source_nar_hash".into(),
                toml::Value::String(source_nar_hash.to_string()),
            );
            let refs: Vec<toml::Value> = info
                .references
                .iter()
                .map(|r| toml::Value::String(r.clone()))
                .collect();
            t.insert("references".into(), toml::Value::Array(refs));
            // Add images if provided.
            if !image_infos.is_empty() {
                let images: Vec<toml::Value> = image_infos
                    .iter()
                    .map(|(fmt, img)| {
                        let mut m = toml::map::Map::new();
                        m.insert("format".into(), toml::Value::String(fmt.clone()));
                        m.insert("store_path".into(), toml::Value::String(img.path.clone()));
                        m.insert("nar_hash".into(), toml::Value::String(img.nar_hash.clone()));
                        m.insert("nar_size".into(), toml::Value::Integer(img.nar_size as i64));
                        toml::Value::Table(m)
                    })
                    .collect();
                t.insert("images".into(), toml::Value::Array(images));
            }
            toml::Value::Table(t)
        };

        if let Some(versions) = versions {
            // Find existing version entry.
            let existing_idx = versions.iter().position(|v| {
                v.get("version")
                    .and_then(|ver| ver.as_str())
                    .map(|ver| ver == version)
                    .unwrap_or(false)
            });

            if let Some(idx) = existing_idx {
                // Update existing version entry.
                let ver_entry = &mut versions[idx];
                if let Some(prev) = previous {
                    ver_entry
                        .as_table_mut()
                        .unwrap()
                        .insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let platforms = ver_entry
                    .as_table_mut()
                    .unwrap()
                    .entry("platforms")
                    .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
                platforms
                    .as_table_mut()
                    .unwrap()
                    .insert(platform.to_string(), platform_table);
            } else {
                // Add new version entry.
                let mut ver_table = toml::map::Map::new();
                ver_table.insert("version".into(), toml::Value::String(version.to_string()));
                if let Some(prev) = previous {
                    ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let mut platforms = toml::map::Map::new();
                platforms.insert(platform.to_string(), platform_table);
                ver_table.insert("platforms".into(), toml::Value::Table(platforms));
                versions.push(toml::Value::Table(ver_table));
            }
        } else {
            // No versions array yet - add one.
            let mut ver_table = toml::map::Map::new();
            ver_table.insert("version".into(), toml::Value::String(version.to_string()));
            if let Some(prev) = previous {
                ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
            }
            let mut platforms = toml::map::Map::new();
            platforms.insert(platform.to_string(), platform_table);
            ver_table.insert("platforms".into(), toml::Value::Table(platforms));

            toml_val.as_table_mut().unwrap().insert(
                "versions".into(),
                toml::Value::Array(vec![toml::Value::Table(ver_table)]),
            );
        }

        Ok(toml::to_string_pretty(&toml_val)?)
    }
}

/// `apr unpublish <PACKAGE> [VERSION]`
#[allow(clippy::too_many_arguments)]
pub async fn unpublish(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config,
            &dir,
            &registry_name,
            key,
            key_id,
        )?)
    } else {
        None
    };
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    if version.is_none() && platform.is_none() {
        // Remove the entire file.
        std::fs::remove_file(&toml_path)?;
        printer.info(&format!("Removed package '{package}' entirely."));
    } else {
        // Parse and selectively remove.
        let content = std::fs::read_to_string(&toml_path)?;
        let mut toml_val: toml::Value = toml::from_str(&content)?;

        if let Some(versions) = toml_val.get_mut("versions").and_then(|v| v.as_array_mut()) {
            if let Some(ver) = version {
                let idx = versions
                    .iter()
                    .position(|v| v.get("version").and_then(|s| s.as_str()) == Some(ver))
                    .ok_or_else(|| {
                        anyhow::anyhow!("package '{package}' does not contain version '{ver}'")
                    })?;
                if let Some(plat) = platform {
                    // Remove specific platform from specific version.
                    let remove_version = {
                        let platforms = versions[idx]
                            .as_table_mut()
                            .and_then(|t| t.get_mut("platforms"))
                            .and_then(|p| p.as_table_mut())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "package '{package}' version '{ver}' has no platform entries"
                                )
                            })?;
                        if !platforms.contains_key(plat) {
                            bail!(
                                "package '{package}' version '{ver}' does not contain platform '{plat}'"
                            );
                        }
                        platforms.remove(plat);
                        platforms.is_empty()
                    };
                    if remove_version {
                        versions.remove(idx);
                    }
                } else {
                    // Remove entire version.
                    versions.remove(idx);
                }
            } else if let Some(plat) = platform {
                // Remove platform from all versions.
                let mut removed = false;
                for ver in versions.iter_mut() {
                    if let Some(platforms) = ver
                        .as_table_mut()
                        .and_then(|t| t.get_mut("platforms"))
                        .and_then(|p| p.as_table_mut())
                    {
                        removed |= platforms.remove(plat).is_some();
                    }
                }
                if !removed {
                    bail!("package '{package}' does not contain platform '{plat}'");
                }
                // Remove empty versions.
                versions.retain(|v| {
                    v.get("platforms")
                        .and_then(|p| p.as_table())
                        .map(|t| !t.is_empty())
                        .unwrap_or(false)
                });
            }

            if versions.is_empty() {
                std::fs::remove_file(&toml_path)?;
                printer.info(&format!(
                    "Removed package '{package}' (no versions remaining)."
                ));
            } else {
                std::fs::write(&toml_path, toml::to_string_pretty(&toml_val)?)?;
                printer.info(&format!("Updated package '{package}'."));
            }
        }
    }

    if !no_commit {
        let default_msg = format!("unpublish {package}");
        let msg = message.unwrap_or(&default_msg);
        commit_registry(&dir, msg, signing_key.as_deref())?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after unpublish")?;
        printer.success(&format!("Committed: {msg}"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Registry Query
// ---------------------------------------------------------------------------

fn selected_package_versions(
    toml_val: &toml::Value,
    version: Option<&str>,
) -> Result<Vec<toml::Value>> {
    let versions = matching_package_versions(toml_val, None);
    let Some(version) = version else {
        return Ok(versions);
    };

    let selected = versions
        .into_iter()
        .filter(|entry| entry.get("version").and_then(|v| v.as_str()) == Some(version))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        bail!("package does not contain version '{version}'");
    }
    Ok(selected)
}

fn matching_package_versions(toml_val: &toml::Value, platform: Option<&str>) -> Vec<toml::Value> {
    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    versions
        .iter()
        .filter(|entry| version_has_platform(entry, platform))
        .cloned()
        .collect()
}

fn version_has_platform(entry: &toml::Value, platform: Option<&str>) -> bool {
    let Some(platform) = platform else {
        return true;
    };
    entry
        .get("platforms")
        .and_then(|platforms| platforms.as_table())
        .map(|platforms| platforms.contains_key(platform))
        .unwrap_or(false)
}

fn latest_version_string(versions: &[toml::Value]) -> Option<String> {
    versions
        .iter()
        .filter_map(|entry| entry.get("version").and_then(|version| version.as_str()))
        .max_by(|left, right| compare_registry_versions(left, right))
        .map(ToString::to_string)
}

fn compare_registry_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

fn package_toml_with_versions(
    toml_val: &toml::Value,
    versions: &[toml::Value],
) -> Result<toml::Value> {
    let mut filtered = toml_val.clone();
    let Some(root) = filtered.as_table_mut() else {
        bail!("package TOML root is not a table");
    };
    root.insert(
        "versions".to_string(),
        toml::Value::Array(versions.to_vec()),
    );
    Ok(filtered)
}

/// `apr show <PACKAGE>`
pub async fn show(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    raw: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    let content = std::fs::read_to_string(&toml_path)?;
    let toml_val: toml::Value = toml::from_str(&content)?;
    let selected_versions = selected_package_versions(&toml_val, version)?;

    if raw {
        if version.is_some() {
            let filtered = package_toml_with_versions(&toml_val, &selected_versions)?;
            printer.plain(&toml::to_string_pretty(&filtered)?);
        } else {
            printer.plain(&content);
        }
    } else {
        if let Some(pkg) = toml_val.get("package") {
            if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                printer.header(&format!("Package: {name}"));
            }
            if let Some(desc) = pkg.get("description").and_then(|v| v.as_str()) {
                printer.kv("Description", desc);
            }
            if pkg
                .get("sysroot")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                printer.kv("Sysroot", "yes");
            }
            if let Some(hp) = pkg.get("homepage").and_then(|v| v.as_str()) {
                printer.kv("Homepage", hp);
            }
            if let Some(lic) = pkg.get("license").and_then(|v| v.as_str()) {
                printer.kv("License", lic);
            }
            if let Some(maint) = pkg.get("maintainer").and_then(|v| v.as_str()) {
                printer.kv("Maintainer", maint);
            }
        }
        for ver in &selected_versions {
            if let Some(v) = ver.get("version").and_then(|v| v.as_str()) {
                printer.kv("Version", v);
            }
            if let Some(prev) = ver.get("previous").and_then(|v| v.as_str()) {
                printer.kv("Previous", prev);
            }
            if let Some(platforms) = ver.get("platforms").and_then(|v| v.as_table()) {
                for (plat, entry) in platforms {
                    printer.kv(&format!("  {plat}"), "");
                    if let Some(sp) = entry.get("store_path").and_then(|v| v.as_str()) {
                        printer.kv("    Store path", sp);
                    }
                    if let Some(ns) = entry.get("nar_size").and_then(|v| v.as_integer()) {
                        printer.kv("    NAR size", &format_size(ns as u64));
                    }
                    if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                        for img in images {
                            if let Some(fmt) = img.get("format").and_then(|v| v.as_str()) {
                                let img_path = img
                                    .get("store_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let img_size = img
                                    .get("nar_size")
                                    .and_then(|v| v.as_integer())
                                    .unwrap_or(0);
                                printer.kv(
                                    &format!("    Image ({fmt})"),
                                    &format!("{img_path} ({})", format_size(img_size as u64)),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// `apr packages`
pub async fn packages(
    config: &ApmConfig,
    platform: Option<&str>,
    outdated: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let packages_dir = dir.join("packages");

    if !packages_dir.is_dir() {
        printer.info("No packages found.");
        return Ok(());
    }

    let mut pkgs = Vec::new();
    for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)?;
                let toml_val: toml::Value = toml::from_str(&content)?;
                let name = toml_val
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let versions = matching_package_versions(&toml_val, platform);
                if outdated && versions.len() < 2 {
                    continue;
                }
                let Some(version) = latest_version_string(&versions) else {
                    continue;
                };
                pkgs.push((name.to_string(), version));
            }
        }
    }

    pkgs.sort();

    if pkgs.is_empty() {
        printer.info("No packages found.");
    } else {
        printer.header(&format!("{} packages:", pkgs.len()));
        for (name, version) in &pkgs {
            printer.plain(&format!("  {name} {version}"));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct RegistryVerifyStoreEntry {
    store_hash: String,
    store_path: String,
    package_name: String,
}

/// `apr verify`
pub async fn verify(
    config: &ApmConfig,
    package: Option<&str>,
    fix: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let packages_dir = dir.join("packages");
    let closures_dir = dir.join("closures");

    let mut errors = 0u32;
    let mut checked = 0u32;

    // Collect all store path hashes from package TOMLs.
    let mut all_store_entries: Vec<RegistryVerifyStoreEntry> = Vec::new();
    let mut all_ref_hashes: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new(); // hash -> references
    let mut matched_package_filter = package.is_none();

    // Verify package TOML files.
    if packages_dir.is_dir() {
        for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
            if !letter_entry.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    let path_matches_filter = match package {
                        Some(filter) => {
                            path.file_stem().and_then(|stem| stem.to_str()) == Some(filter)
                        }
                        None => true,
                    };
                    if !path_matches_filter {
                        continue;
                    }
                    matched_package_filter = true;
                    checked += 1;
                    let content = std::fs::read_to_string(&path)?;
                    match toml::from_str::<toml::Value>(&content) {
                        Ok(val) => {
                            if val.get("package").is_none() {
                                printer.warning(&format!(
                                    "{}: missing [package] section",
                                    path.display()
                                ));
                                errors += 1;
                                continue;
                            }
                            // Extract store hashes from all version/platform entries.
                            let pkg_name = val
                                .get("package")
                                .and_then(|p| p.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown");
                            if let Some(versions) = val.get("versions").and_then(|v| v.as_array()) {
                                for ver in versions {
                                    if let Some(platforms) =
                                        ver.get("platforms").and_then(|p| p.as_table())
                                    {
                                        for (_plat, plat_val) in platforms {
                                            if let Some(sp) =
                                                plat_val.get("store_path").and_then(|s| s.as_str())
                                            {
                                                let hash = extract_hash(sp).to_string();
                                                all_store_entries.push(RegistryVerifyStoreEntry {
                                                    store_hash: hash.clone(),
                                                    store_path: sp.to_string(),
                                                    package_name: pkg_name.to_string(),
                                                });
                                                let refs: Vec<String> = plat_val
                                                    .get("references")
                                                    .and_then(|r| r.as_array())
                                                    .map(|arr| {
                                                        arr.iter()
                                                            .filter_map(|v| {
                                                                v.as_str().map(|s| s.to_string())
                                                            })
                                                            .collect()
                                                    })
                                                    .unwrap_or_default();
                                                all_ref_hashes.insert(hash, refs);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            printer.error(&format!("{}: {e}", path.display()));
                            errors += 1;
                        }
                    }
                }
            }
        }
    }

    if let Some(filter) = package {
        if !matched_package_filter {
            bail!("package '{filter}' not found in registry");
        }
    }

    if fix {
        let mut repaired = 0u32;
        let mut seen = HashSet::new();
        for entry in &all_store_entries {
            if seen.insert(entry.store_hash.clone()) {
                write_closure_files(&dir, &entry.store_path).with_context(|| {
                    format!(
                        "regenerating closure metadata for {} ({})",
                        entry.package_name, entry.store_path
                    )
                })?;
                repaired += 1;
            }
        }
        if repaired > 0 {
            printer.success(&format!("Regenerated {repaired} closure file(s)."));
        }
    }

    // Verify closure files.
    let mut closure_checked = 0u32;

    for entry in &all_store_entries {
        let store_hash = &entry.store_hash;
        let pkg_name = &entry.package_name;
        let closure_path = closures_dir.join(store_hash);

        // Check closure file exists.
        if !closure_path.exists() {
            printer.warning(&format!(
                "{pkg_name}: missing closure file for store hash {store_hash}"
            ));
            errors += 1;
            continue;
        }

        closure_checked += 1;
        let content = std::fs::read_to_string(&closure_path)?;
        let closure = crate::types::ClosureMeta::parse(store_hash, &content);

        // Check root is first member and matches filename.
        if closure.members.first().map(|s| s.as_str()) != Some(store_hash) {
            printer.warning(&format!(
                "{pkg_name}: closure file {store_hash} does not start with root hash"
            ));
            errors += 1;
        }

        // Check that all direct references from the package TOML are in the closure.
        if let Some(refs) = all_ref_hashes.get(store_hash) {
            for ref_hash in refs {
                if !closure.contains(ref_hash) {
                    printer.warning(&format!(
                        "{pkg_name}: reference {ref_hash} not found in closure {store_hash}"
                    ));
                    errors += 1;
                }
            }
        }

        // Check that all closure members that have direct deps in the
        // adjacency list actually reference hashes that are also in the
        // closure (internal consistency).
        for member in &closure.members {
            for dep in closure.direct_deps(member) {
                if !closure.contains(dep) {
                    printer.warning(&format!(
                        "{pkg_name}: closure {store_hash}: member {member} references \
                         {dep} which is not in the closure"
                    ));
                    errors += 1;
                }
            }
        }
    }

    // Check for orphan closure files (closure files with no matching package).
    if closures_dir.is_dir() {
        let known_hashes: std::collections::HashSet<&str> = all_store_entries
            .iter()
            .map(|entry| entry.store_hash.as_str())
            .collect();
        for entry in std::fs::read_dir(&closures_dir)?.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with('.') && !known_hashes.contains(name_str.as_ref()) {
                // Not an error — could be a closure for a dep that isn't a
                // top-level package.  Just note it.
                checked += 1;
            }
        }
    }

    if errors == 0 {
        printer.success(&format!(
            "Verified {checked} package(s), {closure_checked} closure(s), no errors."
        ));
    } else {
        printer.error(&format!(
            "Verified {checked} package(s), {closure_checked} closure(s), {errors} error(s) found."
        ));
        bail!("registry verification failed with {errors} error(s)");
    }

    Ok(())
}

/// `apr diff`
pub async fn diff(
    config: &ApmConfig,
    stat: bool,
    remote: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    if remote {
        let base = remote_diff_base(&dir)?;
        let mut args = vec!["diff", &base, "HEAD"];
        if stat {
            args.push("--stat");
        }
        let output = git(&dir, &args)?;
        if output.is_empty() {
            printer.info("No pending changes.");
        } else {
            printer.plain(&output);
        }
    } else {
        let mut args = vec!["diff"];
        if stat {
            args.push("--stat");
        }
        let output = git(&dir, &args)?;
        if output.is_empty() {
            printer.info("No pending changes.");
        } else {
            printer.plain(&output);
        }
    }

    Ok(())
}

fn remote_diff_base(dir: &Path) -> Result<String> {
    let (has_upstream, upstream, _) = git_try(
        dir,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )?;
    if has_upstream && !upstream.is_empty() {
        return Ok(upstream);
    }

    let current_branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if current_branch != "HEAD" {
        let remote_branch = format!("origin/{current_branch}");
        if git_ref_exists(dir, &remote_branch)? {
            return Ok(remote_branch);
        }
    }

    if git_ref_exists(dir, "origin/HEAD")? {
        return Ok("origin/HEAD".to_string());
    }

    bail!(
        "no remote tracking ref found for diff; push the current branch or set an upstream first"
    );
}

fn git_ref_exists(dir: &Path, reference: &str) -> Result<bool> {
    let (exists, _, _) = git_try(dir, &["rev-parse", "--verify", reference])?;
    Ok(exists)
}

/// `apr validate`
#[allow(clippy::too_many_arguments)]
pub async fn validate(
    config: &ApmConfig,
    package: Option<&str>,
    platform: Option<&str>,
    fix: bool,
    jobs: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let mirrors = resolve_mirrors(&dir);
    if jobs == 0 {
        bail!("--jobs must be greater than zero");
    }

    if mirrors.is_empty() {
        printer.warning("No caches configured in registry.toml. Cannot validate.");
        return Ok(());
    }

    let entries = collect_cache_validation_entries(&dir, package, platform)?;

    if entries.is_empty() {
        printer.info("No entries to validate.");
        return Ok(());
    }

    printer.info(&format!(
        "Validating {} entries against {} cache(s) with {} parallel requests...",
        entries.len(),
        mirrors.len(),
        jobs,
    ));

    let client = reqwest::Client::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs as usize));
    let mut handles = Vec::new();

    for entry in entries {
        let client = client.clone();
        let mirrors = mirrors.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        let handle = tokio::spawn(async move {
            let result = validate_cache_entry(&client, &mirrors, entry).await;
            drop(permit);
            result
        });
        handles.push(handle);
    }

    let mut missing = 0u32;
    let mut ok = 0u32;
    let mut missing_store_paths = HashSet::new();
    for handle in handles {
        let result = handle.await?;
        if result.found {
            ok += 1;
        } else {
            missing += 1;
            missing_store_paths.insert(result.entry.store_path.clone());
            let detail = result
                .details
                .first()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            printer.warning(&format!(
                "{}: {} not found in any cache{}",
                result.entry.name, result.entry.store_path, detail
            ));
        }
    }

    if missing == 0 {
        printer.success(&format!("All {ok} entries found in caches."));
    } else if fix {
        let removed = remove_missing_cache_entries(&dir, &missing_store_paths)?;
        if removed == 0 {
            bail!("{ok} found, {missing} missing; no matching registry entries removed.");
        }
        let noun = if removed == 1 { "entry" } else { "entries" };
        printer.success(&format!(
            "Removed {removed} missing cache {noun} from registry metadata."
        ));
    } else {
        bail!("{ok} found, {missing} missing.");
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationEntry {
    name: String,
    platform: String,
    store_path: String,
    store_hash: String,
    nar_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationResult {
    entry: CacheValidationEntry,
    found: bool,
    details: Vec<String>,
}

fn collect_cache_validation_entries(
    dir: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
) -> Result<Vec<CacheValidationEntry>> {
    let packages_dir = dir.join("packages");
    let mut entries = Vec::new();

    if !packages_dir.is_dir() {
        return Ok(entries);
    }

    for letter_entry in std::fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            collect_cache_validation_entries_from_package(
                &path,
                package_filter,
                platform_filter,
                &mut entries,
            )?;
        }
    }

    entries.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.platform.cmp(&b.platform))
            .then_with(|| a.store_path.cmp(&b.store_path))
    });
    entries.dedup();
    Ok(entries)
}

fn collect_cache_validation_entries_from_package(
    path: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
    entries: &mut Vec<CacheValidationEntry>,
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let name = toml_val
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if package_filter.is_some_and(|filter| filter != name) {
        return Ok(());
    }

    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for version in versions {
        let Some(platforms) = version.get("platforms").and_then(|v| v.as_table()) else {
            continue;
        };
        for (platform, entry) in platforms {
            if platform_filter.is_some_and(|filter| filter != platform) {
                continue;
            }
            let Some(store_path) = entry.get("store_path").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(nar_hash) = entry.get("nar_hash").and_then(|v| v.as_str()) else {
                continue;
            };
            entries.push(CacheValidationEntry {
                name: name.to_string(),
                platform: platform.to_string(),
                store_path: store_path.to_string(),
                store_hash: extract_hash(store_path).to_string(),
                nar_hash: nar_hash.to_string(),
            });
            if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                for image in images {
                    let Some(image_store_path) = image.get("store_path").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    let Some(image_nar_hash) = image.get("nar_hash").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    entries.push(CacheValidationEntry {
                        name: name.to_string(),
                        platform: platform.to_string(),
                        store_path: image_store_path.to_string(),
                        store_hash: extract_hash(image_store_path).to_string(),
                        nar_hash: image_nar_hash.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn remove_missing_cache_entries(
    dir: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    if missing_store_paths.is_empty() {
        return Ok(0);
    }

    let packages_dir = dir.join("packages");
    let mut removed = 0usize;

    if !packages_dir.is_dir() {
        return Ok(removed);
    }

    for letter_entry in fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }

        for entry in fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            removed += remove_missing_cache_entries_from_package(&path, missing_store_paths)?;
        }
    }

    Ok(removed)
}

fn remove_missing_cache_entries_from_package(
    path: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let mut toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let mut removed = 0usize;
    let mut remove_package = false;

    if let Some(versions) = toml_val
        .get_mut("versions")
        .and_then(|value| value.as_array_mut())
    {
        for version in versions.iter_mut() {
            let Some(platforms) = version
                .as_table_mut()
                .and_then(|table| table.get_mut("platforms"))
                .and_then(|value| value.as_table_mut())
            else {
                continue;
            };

            let platform_names: Vec<String> = platforms
                .iter()
                .filter_map(|(platform, entry)| {
                    let store_path = entry.get("store_path").and_then(|value| value.as_str())?;
                    if missing_store_paths.contains(store_path) {
                        Some(platform.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for platform in platform_names {
                if platforms.remove(&platform).is_some() {
                    removed += 1;
                }
            }

            for (_platform_name, platform) in platforms.iter_mut() {
                let Some(platform_table) = platform.as_table_mut() else {
                    continue;
                };
                let remove_images_key = if let Some(images) = platform_table
                    .get_mut("images")
                    .and_then(|value| value.as_array_mut())
                {
                    let before = images.len();
                    images.retain(|image| {
                        let remove = image
                            .get("store_path")
                            .and_then(|value| value.as_str())
                            .map(|store_path| missing_store_paths.contains(store_path))
                            .unwrap_or(false);
                        !remove
                    });
                    removed += before - images.len();
                    images.is_empty()
                } else {
                    false
                };
                if remove_images_key {
                    platform_table.remove("images");
                }
            }
        }

        versions.retain(|version| {
            version
                .get("platforms")
                .and_then(|platforms| platforms.as_table())
                .map(|platforms| !platforms.is_empty())
                .unwrap_or(false)
        });
        remove_package = versions.is_empty();
    }

    if removed > 0 {
        if remove_package {
            fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        } else {
            fs::write(path, toml::to_string_pretty(&toml_val)?)
                .with_context(|| format!("writing {}", path.display()))?;
        }
    }

    Ok(removed)
}

async fn validate_cache_entry(
    client: &reqwest::Client,
    mirrors: &[CacheEntry],
    entry: CacheValidationEntry,
) -> CacheValidationResult {
    let mut details = Vec::new();
    for cache in mirrors {
        let base = cache.url.trim_end_matches('/');
        let narinfo_url =
            crate::download::join_cache_url(base, &format!("{}.narinfo", entry.store_hash));

        let narinfo = match client.get(&narinfo_url).send().await {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(text) => match narinfo::parse(&text) {
                    Ok(narinfo) => narinfo,
                    Err(err) => {
                        details.push(format!("{narinfo_url}: invalid narinfo: {err}"));
                        continue;
                    }
                },
                Err(err) => {
                    details.push(format!("{narinfo_url}: failed reading narinfo body: {err}"));
                    continue;
                }
            },
            Ok(response) => {
                details.push(format!("{narinfo_url}: HTTP {}", response.status()));
                continue;
            }
            Err(err) => {
                details.push(format!("{narinfo_url}: {err}"));
                continue;
            }
        };

        if narinfo.store_path != entry.store_path {
            details.push(format!(
                "{narinfo_url}: narinfo store path {} did not match registry path {}",
                narinfo.store_path, entry.store_path
            ));
            continue;
        }
        if narinfo.nar_hash != entry.nar_hash {
            details.push(format!(
                "{narinfo_url}: narinfo NarHash {} did not match registry NarHash {}",
                narinfo.nar_hash, entry.nar_hash
            ));
            continue;
        }

        let nar_url = crate::download::join_cache_url(base, &narinfo.url);
        match client.head(&nar_url).send().await {
            Ok(response) if response.status().is_success() => {
                return CacheValidationResult {
                    entry,
                    found: true,
                    details,
                };
            }
            Ok(response) => {
                details.push(format!("{nar_url}: HTTP {}", response.status()));
            }
            Err(err) => {
                details.push(format!("{nar_url}: {err}"));
            }
        }
    }

    CacheValidationResult {
        entry,
        found: false,
        details,
    }
}

// ---------------------------------------------------------------------------
// Git Workflow
// ---------------------------------------------------------------------------

/// `apr status`
pub async fn status(config: &ApmConfig, registry: Option<&str>, printer: &Printer) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let output = git(&dir, &["status", "--short", "--untracked-files=all"])?;
    printer.plain(&output);
    Ok(())
}

/// `apr log`
pub async fn log(
    config: &ApmConfig,
    package: Option<&str>,
    n: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let n_str = format!("-{n}");
    let mut args = vec!["log", "--oneline", &n_str];

    let path_filter;
    if let Some(pkg) = package {
        let letter = first_letter(pkg);
        path_filter = format!("packages/{letter}/{pkg}.toml");
        args.push("--");
        args.push(&path_filter);
    }

    let output = git(&dir, &args)?;
    if output.is_empty() {
        printer.info("No commits found.");
    } else {
        printer.plain(&output);
    }

    Ok(())
}

/// Branch subcommands.
pub async fn run_branch(
    config: &ApmConfig,
    command: &BranchCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        BranchCommand::List { registry } => {
            let dir = registry_dir(config, registry.as_deref())?;
            let output = git(&dir, &["branch", "-a"])?;
            printer.plain(&output);
            Ok(())
        }
        BranchCommand::Create { name, registry } => {
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["branch", name])?;
            printer.success(&format!("Created branch '{name}'."));
            Ok(())
        }
        BranchCommand::Switch { name, registry } => {
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["checkout", name])?;
            printer.success(&format!("Switched to branch '{name}'."));
            Ok(())
        }
        BranchCommand::Delete { name, registry } => {
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["branch", "-d", name])?;
            printer.success(&format!("Deleted branch '{name}'."));
            Ok(())
        }
    }
}

/// Channel rollout subcommands.
pub async fn run_channel(
    config: &ApmConfig,
    command: &ChannelCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        ChannelCommand::Init {
            channel,
            semver,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_init(
                config,
                channel,
                &version,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Advance {
            channel,
            semver,
            count,
            partitions,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_advance(
                config,
                channel,
                &version,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Status { channel, registry } => {
            channel_status(config, channel, registry.as_deref(), printer).await
        }
    }
}

/// Static Nix-cache subcommands.
pub async fn run_cache(
    config: &ApmConfig,
    command: &CacheCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        CacheCommand::Generate {
            output,
            key,
            cache_url,
            upload_urls,
            auth,
            priority,
            no_commit,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let report =
                nixcache::generate_static_cache(&dir, output, key.as_deref(), *priority, printer)
                    .await?;

            printer.success(&format!(
                "Generated static cache: {} narinfos, {} NARs in {}",
                report.narinfos,
                report.nars,
                report.output_dir.display(),
            ));

            if !upload_urls.is_empty() {
                let auth = auth
                    .auth_options_with_config(registry_upload_auth_config(config, &registry_name));
                nixcache::upload_static_cache_to_all(output, upload_urls, &auth, printer).await?;
            }

            if let Some(cache_url) = cache_url {
                if nixcache::upsert_registry_cache(&dir, cache_url, *priority)? {
                    printer.info(&format!("Updated registry.toml [[caches]] -> {cache_url}"));
                    if !*no_commit {
                        commit_registry(&dir, "registry: update static cache pointer", None)?;
                        refresh_registry_object_store(&dir)
                            .context("refreshing dumb-HTTP object store after cache update")?;
                    }
                }
            }

            Ok(())
        }
    }
}

/// Static git-origin subcommands.
pub async fn run_origin(
    config: &ApmConfig,
    command: &OriginCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        OriginCommand::Upload {
            upload_urls,
            cache_dir,
            auth,
            registry,
        } => {
            if upload_urls.is_empty() {
                bail!("at least one --upload-url is required");
            }
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            refresh_registry_object_store(&dir)
                .context("refreshing static git origin before upload")?;
            let auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            let report = static_upload::upload_static_origin_to_all(
                &dir,
                cache_dir.as_deref(),
                upload_urls,
                &auth,
                printer,
            )
            .await?;

            printer.success(&format!(
                "Uploaded {} static origin file(s) ({}).",
                report.files,
                format_size(report.bytes),
            ));
            Ok(())
        }
    }
}

/// Registry trust-store subcommands.
pub fn run_trust(config: &ApmConfig, command: &TrustCommand, printer: &Printer) -> Result<()> {
    let store = KeyStore::new(config.scope.trusted_keys_dirs());
    match command {
        TrustCommand::Pin {
            registry,
            key,
            replace,
        } => {
            let trusted = trusted_key_from_line(registry, key)?;
            if *replace {
                let _ = store.remove(registry)?;
            }
            store.store(&trusted)?;
            let action = if *replace { "Re-pinned" } else { "Pinned" };
            printer.success(&format!(
                "{action} trust key for registry '{}' ({})",
                registry, trusted.fingerprint
            ));
            Ok(())
        }
        TrustCommand::List { registry } => {
            let registries = match registry {
                Some(name) => vec![name.clone()],
                None => configured_registry_names(config),
            };
            if registries.is_empty() {
                printer.info("No configured registries to inspect.");
                return Ok(());
            }
            for name in registries {
                let keys = store.lookup_all(&name);
                if keys.is_empty() {
                    printer.plain(&format!("{name}: no pinned keys"));
                    continue;
                }
                for key in keys {
                    printer.plain(&format!(
                        "{}: {} {} ({:?})",
                        name, key.algorithm, key.fingerprint, key.source
                    ));
                }
            }
            Ok(())
        }
        TrustCommand::Remove { registry } => {
            if store.remove(registry)? {
                printer.success(&format!(
                    "Removed pinned trust keys for registry '{registry}'"
                ));
            } else {
                printer.info(&format!(
                    "No pinned trust keys found for registry '{registry}'"
                ));
            }
            Ok(())
        }
    }
}

/// Committed keys.toml roster subcommands.
pub fn run_keys(config: &ApmConfig, command: &KeysCommand, printer: &Printer) -> Result<()> {
    match command {
        KeysCommand::List { registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let roster = load_committed_roster(&dir)?;
            if roster.active.is_empty() && roster.revoked.is_empty() {
                printer.info(&format!(
                    "Registry '{registry_name}' has no keys in keys.toml."
                ));
                return Ok(());
            }

            printer.header(&format!("keys.toml for registry '{registry_name}'"));
            if roster.active.is_empty() {
                printer.plain("active: none");
            } else {
                printer.plain("active:");
                for entry in &roster.active {
                    let (_registry, algorithm, public_key) = parse_signing_key(&entry.key)
                        .with_context(|| format!("invalid active key '{}'", entry.id))?;
                    printer.plain(&format!(
                        "  {}: {} {}",
                        entry.id,
                        algorithm,
                        key_fingerprint(&public_key),
                    ));
                }
            }

            if roster.revoked.is_empty() {
                printer.plain("revoked: none");
            } else {
                printer.plain("revoked:");
                for entry in &roster.revoked {
                    if let Some(reason) = &entry.reason {
                        printer.plain(&format!("  {}: {}", entry.id, reason));
                    } else {
                        printer.plain(&format!("  {}", entry.id));
                    }
                }
            }
            Ok(())
        }
        KeysCommand::Generate {
            id,
            add,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => generate_roster_key(
            config,
            id,
            *add,
            *no_commit,
            signing_key.as_deref(),
            signing_key_id.as_deref(),
            registry.as_deref(),
            printer,
        ),
        KeysCommand::Add {
            id,
            key,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let mut roster = load_committed_roster(&dir)?;
            let commit_key = if *no_commit {
                None
            } else {
                resolve_roster_commit_key(
                    config,
                    &dir,
                    &registry_name,
                    &roster,
                    signing_key.as_deref(),
                    signing_key_id.as_deref(),
                )?
            };
            add_roster_key(&mut roster, &registry_name, id, key)?;
            persist_committed_roster(
                &dir,
                &roster,
                *no_commit,
                &format!("registry: add signing key {id}"),
                commit_key.as_deref(),
            )?;
            printer.success(&format!(
                "Added active signing key '{id}' to registry '{registry_name}'."
            ));
            Ok(())
        }
        KeysCommand::Retire {
            id,
            reason,
            vouched_by,
            no_commit,
            signing_key,
            signing_key_id,
            no_resign,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let mut roster = load_committed_roster(&dir)?;
            let roster_before = roster.clone();
            let vouching_id = retire_roster_key(&mut roster, id, reason.as_deref(), vouched_by)?;
            // The vouching survivor signs the retirement by default; the
            // key resolution runs against the pre-retire roster, where the
            // voucher is still active. Re-signing also needs this key, so
            // resolution failures abort before anything is modified.
            let signer = if *no_commit && *no_resign {
                None
            } else if signing_key.is_none() && signing_key_id.is_none() {
                Some(resolve_producer_signing_key(
                    config,
                    &dir,
                    &registry_name,
                    None,
                    Some(&vouching_id),
                )?)
            } else {
                resolve_roster_commit_key(
                    config,
                    &dir,
                    &registry_name,
                    &roster_before,
                    signing_key.as_deref(),
                    signing_key_id.as_deref(),
                )?
            };
            // Signatures by the retired key become invalid on clients, so
            // every tag a client still resolves must be re-signed by a
            // survivor. Plan against the post-retirement active set before
            // mutating anything.
            let survivors: Vec<String> = roster
                .active
                .iter()
                .map(|entry| entry.key.clone())
                .collect();
            let plan = plan_retirement_resign(&dir, &survivors)?;
            persist_committed_roster(
                &dir,
                &roster,
                *no_commit,
                &format!("registry: retire signing key {id}"),
                if *no_commit { None } else { signer.as_deref() },
            )?;
            if *no_resign {
                print_resign_plan(&plan, printer);
            } else if let Some(vouch_key) = signer.as_deref() {
                execute_retirement_resign(&dir, &plan, vouch_key, printer)?;
            }
            printer.success(&format!(
                "Retired signing key '{id}' from registry '{registry_name}' (vouched by '{vouching_id}')."
            ));
            Ok(())
        }
    }
}

/// Tags whose signatures must be refreshed after a key retirement.
///
/// `affected_partitions` carries the release each partition payload must
/// be rewritten against, captured *before* release tags are force-retagged
/// (re-signing changes the tag-object id, which would otherwise orphan the
/// payload's reference).
struct ResignPlan {
    affected_releases: Vec<semver::Version>,
    affected_partitions: Vec<(String, u8, semver::Version)>,
}

impl ResignPlan {
    fn is_empty(&self) -> bool {
        self.affected_releases.is_empty() && self.affected_partitions.is_empty()
    }
}

/// Enumerate the tags clients resolve and check which no longer verify
/// against the surviving active keys.
///
/// Covers every channel partition payload under `.git/channels/` and each
/// release tag those partitions reference. A partition is also marked
/// affected when its release tag must be re-signed: the new release tag
/// object gets a different id, so the payload has to be regenerated even
/// when its own signature is fine.
fn plan_retirement_resign(dir: &Path, survivors: &[String]) -> Result<ResignPlan> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channels_dir = git_dir.join("channels");

    // (channel, bucket, version, payload signature fails against survivors)
    let mut partitions: Vec<(String, u8, semver::Version, bool)> = Vec::new();
    if channels_dir.exists() {
        let mut channel_names: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&channels_dir)
            .with_context(|| format!("reading {}", channels_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                channel_names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        channel_names.sort();
        for channel_name in channel_names {
            let channel_dir = channels_dir.join(&channel_name);
            for bucket in 0..=u8::MAX {
                let path = channel_dir.join(channel::bucket_hex(bucket));
                if !path.exists() {
                    continue;
                }
                let payload =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                let tag = parse_tag_object(&String::from_utf8_lossy(&payload))
                    .with_context(|| format!("parsing channel partition {}", path.display()))?;
                let version = release_tags.get(&tag.object).ok_or_else(|| {
                    anyhow::anyhow!(
                        "channel partition {} points at unknown release tag object {}",
                        path.display(),
                        tag.object,
                    )
                })?;
                let oid = hash_tag_object(dir, &payload)?;
                let verified = verify_tag_signature(dir, &oid, survivors)?;
                partitions.push((channel_name.clone(), bucket, version.clone(), !verified));
            }
        }
    }

    let referenced: HashSet<semver::Version> = partitions
        .iter()
        .map(|(_, _, version, _)| version.clone())
        .collect();
    let mut affected_releases: Vec<semver::Version> = Vec::new();
    for version in referenced {
        if !verify_tag_signature(dir, &version.to_string(), survivors)? {
            affected_releases.push(version);
        }
    }
    affected_releases.sort();

    let affected_partitions = partitions
        .into_iter()
        .filter(|(_, _, version, failing)| *failing || affected_releases.contains(version))
        .map(|(channel, bucket, version, _)| (channel, bucket, version))
        .collect();

    Ok(ResignPlan {
        affected_releases,
        affected_partitions,
    })
}

/// Re-sign every affected tag with the vouching survivor's private key.
///
/// Release tags are force-retagged against their original commit and
/// message; affected channel partitions are regenerated against the new
/// tag objects, and each touched channel's branch head and object store
/// are refreshed.
fn execute_retirement_resign(
    dir: &Path,
    plan: &ResignPlan,
    vouch_key: &str,
    printer: &Printer,
) -> Result<()> {
    if plan.is_empty() {
        return Ok(());
    }

    for version in &plan.affected_releases {
        let tag = version.to_string();
        let commit = release_commit(dir, version)?;
        let payload = git(dir, &["cat-file", "-p", &format!("{tag}^{{tag}}")])?;
        let message = tag_message_without_signature(&payload);
        sign_tag(dir, &tag, &commit, message.as_deref(), vouch_key, true)?;
        printer.info(&format!("Re-signed release tag {tag}."));
    }

    let mut touched_channels: Vec<&str> = Vec::new();
    for (channel_name, bucket, version) in &plan.affected_partitions {
        write_channel_partition_tag(dir, channel_name, *bucket, version, vouch_key)?;
        if !touched_channels.contains(&channel_name.as_str()) {
            touched_channels.push(channel_name);
        }
    }
    for channel_name in touched_channels {
        let map = read_channel_partition_map(dir, channel_name)?;
        update_channel_frontier(dir, channel_name, &map)?;
        printer.info(&format!("Re-signed channel '{channel_name}' partitions."));
    }

    Ok(())
}

/// Print the re-sign plan for manual handling (`--no-resign`).
fn print_resign_plan(plan: &ResignPlan, printer: &Printer) {
    if plan.is_empty() {
        printer.info("No tags need re-signing.");
        return;
    }
    printer.warning("Skipped re-signing (--no-resign). Affected tags:");
    for version in &plan.affected_releases {
        printer.plain(&format!("  release tag {version}"));
    }
    for (channel, bucket, version) in &plan.affected_partitions {
        printer.plain(&format!(
            "  channel {channel} partition {} -> {version}",
            channel::bucket_hex(*bucket),
        ));
    }
}

/// Extract a signed tag's original message, dropping the SSH signature
/// block git appends to the payload.
fn tag_message_without_signature(payload: &str) -> Option<String> {
    let (_, body) = payload.split_once("\n\n")?;
    let message = match body.find("-----BEGIN SSH SIGNATURE-----") {
        Some(position) => &body[..position],
        None => body,
    };
    Some(message.trim_end().to_string())
}

/// Write a tag object payload into the object database, returning its id.
fn hash_tag_object(dir: &Path, payload: &[u8]) -> Result<String> {
    use std::process::Stdio;
    let mut child = gitcmd::hermetic()
        .args(["hash-object", "-w", "-t", "tag", "--stdin"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning git hash-object")?;
    if let Some(stdin) = child.stdin.as_mut() {
        std::io::Write::write_all(stdin, payload).context("writing tag payload to hash-object")?;
    }
    let output = child
        .wait_with_output()
        .context("running git hash-object")?;
    if !output.status.success() {
        bail!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn load_committed_roster(dir: &Path) -> Result<KeysToml> {
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    Ok(keys::load_keys_toml(dir)?.unwrap_or_default())
}

/// `apr keys generate <id>`
///
/// Generates an OpenSSH Ed25519 maintainer keypair: the private key is
/// written under the per-scope config directory (mode `0600`, never
/// overwriting an existing file), its path is recorded in
/// `[registry.signing_keys]` so `--key-id <id>` resolves, and the public
/// half is printed in `registry:Ed25519:<base64>` form. With `--add` the
/// public key is also appended to the committed `keys.toml` roster via a
/// signed commit.
#[allow(clippy::too_many_arguments)]
fn generate_roster_key(
    config: &ApmConfig,
    id: &str,
    add: bool,
    no_commit: bool,
    signing_key: Option<&str>,
    signing_key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_roster_key_id(id)?;
    let registry_name = resolve_registry_name(config, registry)?;

    let keys_dir = config.scope.config_dir().join("keys");
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&keys_dir)
            .with_context(|| format!("creating key directory {}", keys_dir.display()))?;
    }

    let key_path = keys_dir.join(format!("{registry_name}-{id}.key"));
    let keypair = sshkey::Ed25519Keypair::generate();
    let pem = keypair.to_openssh_private_key(&format!("{registry_name}-{id}"));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&key_path).with_context(|| {
            format!(
                "creating private key file {} (refusing to overwrite an existing key)",
                key_path.display(),
            )
        })?;
        std::io::Write::write_all(&mut file, pem.as_bytes())
            .with_context(|| format!("writing {}", key_path.display()))?;
    }

    let trust_key = keypair.trust_key_line(&registry_name);
    let key_path_str = key_path.display().to_string();

    // Record the private key path so `--key-id <id>` resolves (§2.6).
    let config_path = config
        .scope
        .config_dir()
        .join("registries.d")
        .join(format!("{registry_name}.toml"));
    if config_path.exists() {
        state::upsert_signing_key(&config_path, id, &key_path_str)?;
        printer.kv("Config", &config_path.display().to_string());
    } else {
        printer.warning(&format!(
            "registry '{registry_name}' has no config at {}; to use --key-id {id}, add:\n\
             [registry.signing_keys]\n\"{id}\" = \"{key_path_str}\"",
            config_path.display(),
        ));
    }

    printer.kv("Key id", id);
    printer.kv("Private key", &key_path_str);
    printer.kv("Public key", &trust_key);
    printer.kv(
        "Fingerprint",
        &key_fingerprint(&keypair.public_key_base64()),
    );

    if add {
        let dir = config.scope.registries_path().join(&registry_name);
        let mut roster = load_committed_roster(&dir)?;
        if roster.active.is_empty() {
            bail!(
                "registry '{registry_name}' has an empty trust roster; seed the first key with \
                 `apr create {registry_name} --trust-key {trust_key} --key {key_path_str}` instead \
                 of --add"
            );
        }
        let commit_key = if no_commit {
            None
        } else {
            resolve_roster_commit_key(
                config,
                &dir,
                &registry_name,
                &roster,
                signing_key,
                signing_key_id,
            )?
        };
        add_roster_key(&mut roster, &registry_name, id, &trust_key)?;
        persist_committed_roster(
            &dir,
            &roster,
            no_commit,
            &format!("registry: add signing key {id}"),
            commit_key.as_deref(),
        )?;
        printer.success(&format!(
            "Added active signing key '{id}' to registry '{registry_name}'."
        ));
    }

    Ok(())
}

fn persist_committed_roster(
    dir: &Path,
    roster: &KeysToml,
    no_commit: bool,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    keys::write_keys_toml(dir, roster)?;
    if !no_commit {
        commit_registry(dir, message, signing_key)?;
        refresh_registry_object_store(dir)
            .context("refreshing dumb-HTTP object store after keys.toml update")?;
    }
    Ok(())
}

/// Resolve the signing key for a roster-changing commit.
///
/// Roster commits must be signed whenever the pre-change roster is
/// non-empty: clients verify head-commit signatures against the keys they
/// already trust, so an unsigned roster change would be rejected on sync.
/// Only the bootstrap case (adding the first key to an empty roster, which
/// no client can verify yet) may proceed unsigned without an explicit key.
fn resolve_roster_commit_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    roster_before: &KeysToml,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<String>> {
    if key.is_some() || key_id.is_some() {
        return resolve_producer_signing_key(config, dir, registry_name, key, key_id).map(Some);
    }
    if roster_before.active.is_empty() {
        return Ok(None);
    }
    bail!(
        "registry '{registry_name}' has a non-empty trust roster, so roster changes must be \
         signed commits: pass --key <path> or --key-id <id> with an active maintainer key"
    )
}

fn add_roster_key(roster: &mut KeysToml, registry_name: &str, id: &str, key: &str) -> Result<()> {
    validate_roster_key_id(id)?;
    if roster.active.iter().any(|entry| entry.id == id) {
        bail!("active signing key id '{id}' already exists in keys.toml");
    }
    if roster.revoked.iter().any(|entry| entry.id == id) {
        bail!("signing key id '{id}' is already revoked in keys.toml");
    }
    if roster.active.iter().any(|entry| entry.key == key) {
        bail!("signing key already exists in keys.toml under another id");
    }

    let (key_registry, _algorithm, _public_key) = parse_signing_key(key)?;
    if key_registry != registry_name {
        bail!(
            "signing key belongs to registry '{}', expected '{}'",
            key_registry,
            registry_name,
        );
    }

    roster.active.push(RosterKey {
        id: id.to_string(),
        key: key.to_string(),
    });
    Ok(())
}

fn retire_roster_key(
    roster: &mut KeysToml,
    id: &str,
    reason: Option<&str>,
    vouched_by: &Option<String>,
) -> Result<String> {
    validate_roster_key_id(id)?;
    let Some(position) = roster.active.iter().position(|entry| entry.id == id) else {
        if roster.revoked.iter().any(|entry| entry.id == id) {
            bail!("signing key id '{id}' is already revoked in keys.toml");
        }
        bail!("active signing key id '{id}' does not exist in keys.toml");
    };

    let survivors = roster
        .active
        .iter()
        .filter(|entry| entry.id != id)
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    if survivors.is_empty() {
        bail!("cannot retire signing key '{id}': keys.toml must keep an active survivor key");
    }

    let vouching_id = match vouched_by.as_deref() {
        Some(vouching_id) => {
            validate_roster_key_id(vouching_id)?;
            if vouching_id == id {
                bail!("--vouched-by must name a different active key");
            }
            if !survivors.iter().any(|survivor| survivor == vouching_id) {
                bail!("--vouched-by '{vouching_id}' is not an active survivor key");
            }
            vouching_id.to_string()
        }
        None if survivors.len() == 1 => survivors[0].to_string(),
        None => bail!(
            "--vouched-by is required when more than one active survivor key remains ({})",
            survivors.join(", "),
        ),
    };

    roster.active.remove(position);
    upsert_revoked_key(roster, id, reason);
    Ok(vouching_id)
}

fn upsert_revoked_key(roster: &mut KeysToml, id: &str, reason: Option<&str>) {
    let reason = reason.map(str::to_string);
    if let Some(entry) = roster.revoked.iter_mut().find(|entry| entry.id == id) {
        entry.reason = reason;
    } else {
        roster.revoked.push(RevokedKey {
            id: id.to_string(),
            reason,
        });
    }
}

fn validate_roster_key_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("key id cannot be empty");
    }
    if id.trim() != id
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("key id '{id}' must contain only ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

fn configured_registry_names(config: &ApmConfig) -> Vec<String> {
    config
        .registries
        .iter()
        .map(|(registry, _)| registry.name.clone())
        .collect()
}

fn registry_upload_auth_config<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a crate::types::RegistryUploadAuthConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .and_then(|(registry, _state)| registry.upload_auth.as_ref())
}

fn trusted_key_from_line(expected_registry: &str, key: &str) -> Result<TrustedKey> {
    let (registry, algorithm, public_key) = parse_signing_key(key)?;
    if registry != expected_registry {
        bail!(
            "trust key belongs to registry '{}', expected '{}'",
            registry,
            expected_registry,
        );
    }
    let fingerprint = key_fingerprint(&public_key);
    Ok(TrustedKey {
        registry,
        algorithm,
        public_key,
        fingerprint,
        source: KeySource::Tofu,
    })
}

fn resolve_producer_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<String> {
    match (key, key_id) {
        (Some(_), Some(_)) => bail!("use only one of --key or --key-id"),
        (Some(key), None) => Ok(key.to_string()),
        (None, Some(key_id)) => {
            validate_roster_key_id(key_id)?;
            let roster = load_committed_roster(dir)?;
            if keys::is_revoked(&roster, key_id) {
                bail!("signing key id '{key_id}' is revoked in keys.toml");
            }
            let active = keys::active_key_by_id(&roster, key_id).ok_or_else(|| {
                anyhow::anyhow!("active signing key id '{key_id}' does not exist in keys.toml")
            })?;
            let (entry_registry, _algorithm, _public_key) = parse_signing_key(&active.key)
                .with_context(|| format!("invalid active key '{key_id}'"))?;
            if entry_registry != registry_name {
                bail!(
                    "active signing key id '{key_id}' belongs to registry '{}', expected '{}'",
                    entry_registry,
                    registry_name,
                );
            }

            let registry_config =
                registry_config_by_name(config, registry_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "--key-id requires registry '{}' to be configured in registries.d",
                        registry_name,
                    )
                })?;
            let path = registry_config.signing_keys.get(key_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "no local private key path configured for signing key id '{key_id}'; add [registry.signing_keys] {key_id} = \"/path/to/private-key\" to the registry config or pass --key"
                )
            })?;
            if path.trim().is_empty() {
                bail!("local private key path for signing key id '{key_id}' is empty");
            }
            let path_buf = PathBuf::from(path);
            if !path_buf.exists() {
                bail!(
                    "local private key path for signing key id '{key_id}' does not exist: {}",
                    path_buf.display(),
                );
            }
            Ok(path.clone())
        }
        (None, None) => bail!(
            "--key or --key-id is required: registry release and channel tags must be signed tag objects"
        ),
    }
}

fn registry_config_by_name<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a RegistryConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .map(|(registry, _state)| registry)
}

async fn channel_init(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(&dir, channel_name, bucket, version, &signing_key)?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(())
}

async fn channel_advance(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = read_channel_partition_map(&dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    if selected.is_empty() {
        printer.info("No partitions selected for advancement.");
        return Ok(());
    }

    for bucket in &selected {
        write_channel_partition_tag(&dir, channel_name, *bucket, version, &signing_key)?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(())
}

async fn channel_status(
    config: &ApmConfig,
    channel_name: &str,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let dir = registry_dir(config, registry)?;
    let map = read_channel_partition_map(&dir, channel_name)?;
    let frontier = channel::compute_frontier(&map);
    let missing = map.iter().filter(|(_, target)| target.is_none()).count();
    let mut counts: BTreeMap<semver::Version, usize> = BTreeMap::new();
    for (_, target) in map.iter() {
        if let Some(version) = target {
            *counts.entry(version.clone()).or_default() += 1;
        }
    }

    printer.header(&format!("Channel: {channel_name}"));
    if let Some(frontier) = frontier {
        printer.kv("Frontier", &frontier.to_string());
    } else {
        printer.kv("Frontier", "none");
    }
    printer.kv("Missing partitions", &missing.to_string());
    for (version, count) in counts.iter().rev() {
        printer.kv(&version.to_string(), &format!("{count}/256"));
    }
    Ok(())
}

/// `apr push`
pub async fn push(
    config: &ApmConfig,
    branch: Option<&str>,
    set_upstream: bool,
    force: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["push"];
    if set_upstream {
        args.push("-u");
        args.push("origin");
    }
    if force {
        args.push("--force");
    }
    if let Some(b) = branch {
        if !set_upstream {
            args.push("origin");
        }
        args.push(b);
    }

    let output = git_transport(&dir, &args)?;
    if !output.is_empty() {
        printer.plain(&output);
    }
    printer.success("Pushed.");

    Ok(())
}

/// `apr pull`
pub async fn pull(
    config: &ApmConfig,
    rebase: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["pull"];
    if rebase {
        args.push("--rebase");
    }

    let output = git_transport(&dir, &args)?;
    printer.plain(&output);

    Ok(())
}

/// `apr merge <BRANCH>`
pub async fn merge(
    config: &ApmConfig,
    branch: &str,
    no_ff: bool,
    squash: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["merge"];
    if no_ff {
        args.push("--no-ff");
    }
    if squash {
        args.push("--squash");
    }
    args.push(branch);

    let output = git(&dir, &args)?;
    printer.plain(&output);
    printer.success(&format!("Merged '{branch}'."));

    Ok(())
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReleaseTreeOptions {
    pub version: semver::Version,
    pub signing_key: String,
    pub channel: Option<String>,
    pub init_channel: bool,
    pub count: Option<usize>,
    pub partitions: Option<String>,
    pub cache_output: Option<PathBuf>,
    pub cache_key: Option<PathBuf>,
    pub cache_url: Option<String>,
    pub cache_priority: u32,
    pub upload_urls: Vec<String>,
    pub upload_auth: AuthOptions,
    pub dry_run: bool,
    pub resume: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseReport {
    pub full_pack: Option<String>,
    pub deltas: Vec<String>,
    pub uploaded_files: Option<usize>,
}

struct ReleaseLock {
    path: PathBuf,
}

impl ReleaseLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let git_dir = objectstore::repo_git_dir(dir)?;
        let path = git_dir.join("apr-release.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquiring release lock {}; another publisher may be running",
                    path.display()
                )
            })?;
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ReleaseLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// `apr release <SEMVER>`
#[allow(clippy::too_many_arguments)]
pub async fn release(
    config: &ApmConfig,
    semver: &str,
    store_path: Option<&str>,
    name: Option<&str>,
    platform: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_paths: &[String],
    image_formats: &[String],
    message: Option<&str>,
    channel: Option<&str>,
    init_channel: bool,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    cache_output: Option<&Path>,
    cache_key: Option<&Path>,
    cache_url: Option<&str>,
    cache_priority: u32,
    upload_urls: &[String],
    auth: &CacheUploadAuthArgs,
    dry_run: bool,
    resume: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let version = semver::Version::parse(semver)
        .with_context(|| format!("parsing release semver '{semver}'"))?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;

    if let Some(store_path) = store_path {
        if dry_run {
            printer.info(&format!(
                "Would publish {store_path} into release metadata for {version}."
            ));
        } else {
            ensure_release_worktree_clean(&dir)?;
            let release_version = version.to_string();
            publish(
                config,
                store_path,
                name,
                Some(release_version.as_str()),
                platform,
                description,
                homepage,
                license,
                maintainer,
                sysroot,
                previous,
                image_paths,
                image_formats,
                false,
                message,
                Some(&signing_key),
                None,
                Some(&registry_name),
                printer,
            )
            .await?;
        }
    }

    let upload_auth =
        auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
    let options = ReleaseTreeOptions {
        version,
        signing_key,
        channel: channel.map(ToString::to_string),
        init_channel,
        count,
        partitions: partitions.map(ToString::to_string),
        cache_output: cache_output.map(Path::to_path_buf),
        cache_key: cache_key.map(Path::to_path_buf),
        cache_url: cache_url.map(ToString::to_string),
        cache_priority,
        upload_urls: upload_urls.to_vec(),
        upload_auth,
        dry_run,
        resume,
    };

    release_registry_tree(&dir, &registry_name, &options, printer).await?;
    Ok(())
}

pub async fn release_registry_tree(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<ReleaseReport> {
    validate_release_options(options)?;
    if options.dry_run {
        print_release_plan(dir, registry_name, options, printer);
        return Ok(ReleaseReport::default());
    }

    let _lock = ReleaseLock::acquire(dir)?;
    objectstore::assert_sha256(dir)?;
    ensure_release_worktree_clean(dir)?;

    if let Some(cache_url) = &options.cache_url {
        if nixcache::upsert_registry_cache(dir, cache_url, options.cache_priority)? {
            printer.info(&format!("Updated registry.toml [[caches]] -> {cache_url}"));
            commit_registry(
                dir,
                "registry: update static cache pointer",
                Some(&options.signing_key),
            )?;
        }
    }

    let head = git(dir, &["rev-parse", "HEAD"])?;
    let published_before = semver_tag_versions(dir)?
        .into_iter()
        .filter(|version| version != &options.version)
        .collect::<Vec<_>>();

    ensure_release_tag(dir, options, &head, printer)?;
    refresh_registry_object_store(dir).context("refreshing dumb-HTTP object store after tag")?;

    let artifacts = write_release_artifacts(dir, &published_before, options, printer).await?;
    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after release artifacts")?;

    if let Some(output) = &options.cache_output {
        let report = nixcache::generate_static_cache(
            dir,
            output,
            options.cache_key.as_deref(),
            options.cache_priority,
            printer,
        )
        .await?;
        printer.success(&format!(
            "Generated static cache: {} narinfos, {} NARs in {}",
            report.narinfos,
            report.nars,
            report.output_dir.display(),
        ));
    }

    if let Some(channel) = &options.channel {
        if options.init_channel {
            channel_init_dir(
                dir,
                channel,
                &options.version,
                &options.signing_key,
                printer,
            )?;
        } else {
            channel_advance_dir(
                dir,
                channel,
                &options.version,
                options.count,
                options.partitions.as_deref(),
                &options.signing_key,
                printer,
            )?;
        }
    }

    let mut report = artifacts;
    if !options.upload_urls.is_empty() {
        let upload = static_upload::upload_static_origin_to_all(
            dir,
            options.cache_output.as_deref(),
            &options.upload_urls,
            &options.upload_auth,
            printer,
        )
        .await?;
        report.uploaded_files = Some(upload.files);
        printer.success(&format!(
            "Uploaded {} static origin file(s) ({}).",
            upload.files,
            format_size(upload.bytes),
        ));
    }

    printer.success(&format!("Released {registry_name} {}.", options.version));
    Ok(report)
}

fn validate_release_options(options: &ReleaseTreeOptions) -> Result<()> {
    match (&options.channel, options.init_channel) {
        (None, true) => bail!("--init-channel requires --channel"),
        (None, false) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--count and --partitions require --channel");
            }
        }
        (Some(_), true) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--init-channel cannot be combined with --count or --partitions");
            }
        }
        (Some(_), false) => {
            select_partitions_for_advance(
                options.count,
                options.partitions.as_deref(),
                &PartitionMap::new(),
                &options.version,
            )
            .map(|_| ())?;
        }
    }

    if options.cache_key.is_some() && options.cache_output.is_none() {
        bail!("--cache-key requires --cache-output");
    }
    Ok(())
}

fn print_release_plan(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) {
    printer.header("Release plan");
    printer.kv("Registry", registry_name);
    printer.kv("Directory", &dir.display().to_string());
    printer.kv("Release", &options.version.to_string());
    printer.plain("1. ensure registry working tree is clean");
    if let Some(cache_url) = &options.cache_url {
        printer.plain(&format!(
            "2. commit registry.toml cache pointer {cache_url} if needed"
        ));
    }
    printer.plain("3. create signed release tag if absent");
    printer.plain("4. generate full pack and guaranteed compressed thin deltas");
    if options.cache_output.is_some() {
        printer.plain("5. generate static Nix cache files");
    }
    if let Some(channel) = &options.channel {
        let action = if options.init_channel {
            "initialize"
        } else {
            "advance"
        };
        printer.plain(&format!("6. {action} channel {channel}"));
    }
    if !options.upload_urls.is_empty() {
        printer.plain("7. upload immutable files first and mutable refs/channels last");
    }
}

fn ensure_release_worktree_clean(dir: &Path) -> Result<()> {
    let is_bare = git(dir, &["rev-parse", "--is-bare-repository"])? == "true";
    if is_bare {
        return Ok(());
    }
    let status = git(dir, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("registry working tree has uncommitted changes; commit them or use --store-path");
    }
    Ok(())
}

fn ensure_release_tag(
    dir: &Path,
    options: &ReleaseTreeOptions,
    head: &str,
    printer: &Printer,
) -> Result<()> {
    if let Some(existing_commit) = existing_release_tag_commit(dir, &options.version)? {
        if options.resume && existing_commit == head {
            printer.info(&format!(
                "Release tag {} already exists at HEAD; resuming.",
                options.version
            ));
            return Ok(());
        }
        if existing_commit == head {
            bail!(
                "release tag {} already exists at HEAD; pass --resume to reuse it",
                options.version,
            );
        }
        bail!(
            "release tag {} already exists at {}, but HEAD is {}",
            options.version,
            existing_commit,
            head,
        );
    }

    sign_tag(
        dir,
        &options.version.to_string(),
        head,
        Some("AOS registry release"),
        &options.signing_key,
        false,
    )?;
    printer.success(&format!("Created signed tag '{}'.", options.version));
    Ok(())
}

fn existing_release_tag_commit(dir: &Path, version: &semver::Version) -> Result<Option<String>> {
    let tag = version.to_string();
    let (tag_ok, _, tag_stderr) = git_try(dir, &["rev-parse", &format!("{tag}^{{tag}}")])?;
    if !tag_ok {
        let commit_probe = git_try(dir, &["rev-parse", &format!("{tag}^{{commit}}")])?;
        if commit_probe.0 {
            bail!("release name '{tag}' exists but is not an annotated tag object");
        }
        if !tag_stderr.is_empty() {
            return Ok(None);
        }
        return Ok(None);
    }
    let commit = release_commit(dir, version)?;
    Ok(Some(commit))
}

async fn write_release_artifacts(
    dir: &Path,
    published_before: &[semver::Version],
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<ReleaseReport> {
    let commit = release_commit(dir, &options.version)?;
    let release_objects = objectstore::repo_git_dir(dir)?
        .join("releases")
        .join(objectstore::release_object_dir(&options.version));
    let pack_dir = release_objects.join("pack");
    let info_dir = release_objects.join("info");
    fs::create_dir_all(&pack_dir).with_context(|| format!("creating {}", pack_dir.display()))?;
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;

    let full_pack = match pack::release_kind(&options.version) {
        pack::ReleaseKind::Major | pack::ReleaseKind::Minor => {
            Some(write_full_pack_artifact(dir, &commit, &pack_dir, options.resume, printer).await?)
        }
        pack::ReleaseKind::Patch => None,
    };

    if let Some(full_pack) = &full_pack {
        fs::write(info_dir.join("packs"), format!("P {full_pack}\n"))
            .with_context(|| format!("writing {}", info_dir.join("packs").display()))?;
    }

    let mut deltas = Vec::new();
    for base in pack::scheme_deltas(&options.version, published_before) {
        let base_commit = release_commit(dir, &base)?;
        deltas.push(
            write_delta_artifact(
                dir,
                &base,
                &base_commit,
                &commit,
                &pack_dir,
                options.resume,
                printer,
            )
            .await?,
        );
    }

    Ok(ReleaseReport {
        full_pack,
        deltas,
        uploaded_files: None,
    })
}

async fn write_full_pack_artifact(
    dir: &Path,
    commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    if let Some(existing) = existing_full_pack(pack_dir)? {
        if resume {
            printer.info(&format!("Full pack {existing} already exists; resuming."));
            return Ok(existing);
        }
        bail!("full pack {existing} already exists; pass --resume to reuse it");
    }

    let tmp = tempfile::TempDir::new().context("creating full-pack tempdir")?;
    let pack_path = pack::full_pack(dir, commit, tmp.path()).await?;
    let pack_name = file_name_string(&pack_path)?;
    fs::copy(&pack_path, pack_dir.join(&pack_name))
        .with_context(|| format!("copying {}", pack_path.display()))?;
    let idx_path = pack_path.with_extension("idx");
    if idx_path.exists() {
        let idx_name = file_name_string(&idx_path)?;
        fs::copy(&idx_path, pack_dir.join(idx_name))
            .with_context(|| format!("copying {}", idx_path.display()))?;
    }
    printer.success(&format!("Generated full pack {pack_name}."));
    Ok(pack_name)
}

async fn write_delta_artifact(
    dir: &Path,
    base: &semver::Version,
    base_commit: &str,
    target_commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    let artifact_name = format!("delta-{base}.pack.zst");
    let dest = pack_dir.join(&artifact_name);
    if dest.exists() {
        if resume {
            printer.info(&format!(
                "Delta pack {artifact_name} already exists; resuming."
            ));
            return Ok(artifact_name);
        }
        bail!("delta pack {artifact_name} already exists; pass --resume to reuse it");
    }

    let tmp = tempfile::TempDir::new().context("creating delta-pack tempdir")?;
    let delta = pack::thin_delta(dir, base_commit, target_commit, base, tmp.path()).await?;
    let compressed = pack::zstd_compress(&delta, None).await?;
    fs::copy(&compressed, &dest).with_context(|| format!("copying {}", compressed.display()))?;
    printer.success(&format!("Generated delta pack {artifact_name}."));
    Ok(artifact_name)
}

fn existing_full_pack(pack_dir: &Path) -> Result<Option<String>> {
    if !pack_dir.exists() {
        return Ok(None);
    }
    let mut packs = Vec::new();
    for entry in
        fs::read_dir(pack_dir).with_context(|| format!("reading {}", pack_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("pack-") && name.ends_with(".pack") {
            packs.push(name.to_string());
        }
    }
    packs.sort();
    if packs.len() > 1 {
        bail!(
            "multiple full packs already exist in {}: {}",
            pack_dir.display(),
            packs.join(", "),
        );
    }
    Ok(packs.into_iter().next())
}

fn file_name_string(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("path has no UTF-8 filename: {}", path.display()))
}

fn channel_init_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    signing_key: &str,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(dir, channel_name, bucket, version, signing_key)?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(())
}

fn channel_advance_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    signing_key: &str,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = read_channel_partition_map(dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    if selected.is_empty() {
        printer.info("No partitions selected for advancement.");
        return Ok(());
    }
    for bucket in &selected {
        write_channel_partition_tag(dir, channel_name, *bucket, version, signing_key)?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(())
}

/// `apr tag <NAME>`
pub async fn tag(
    config: &ApmConfig,
    name: &str,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;

    sign_tag(
        &dir,
        name,
        "HEAD",
        message.or(Some("AOS registry release")),
        &signing_key,
        false,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after tag")?;

    printer.success(&format!("Created signed tag '{name}'."));
    Ok(())
}

/// `apr sign <TAG>`
pub async fn sign(
    config: &ApmConfig,
    tag: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let tag_name = tag.ok_or_else(|| {
        anyhow::anyhow!("`apr sign` now signs tag objects; pass the existing tag name to re-sign")
    })?;
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let target = git(&dir, &["rev-list", "-n", "1", tag_name])
        .with_context(|| format!("resolving tag '{tag_name}' target commit"))?;

    sign_tag(
        &dir,
        tag_name,
        &target,
        Some("AOS registry release"),
        &signing_key,
        true,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after sign")?;
    printer.success(&format!("Re-signed tag '{tag_name}'."));

    Ok(())
}

fn validate_channel_name(channel_name: &str) -> Result<()> {
    if channel_name.is_empty()
        || channel_name.contains('/')
        || channel_name.starts_with('-')
        || channel_name.contains("..")
    {
        bail!("channel name must be a single non-empty ref segment");
    }
    Ok(())
}

fn assert_release_tag_exists(dir: &Path, version: &semver::Version) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{tag}}")])
        .with_context(|| format!("resolving signed release tag '{tag}'"))
}

fn release_commit(dir: &Path, version: &semver::Version) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{commit}}")])
        .with_context(|| format!("resolving release tag '{tag}' commit"))
}

fn select_partitions_for_advance(
    count: Option<usize>,
    partitions: Option<&str>,
    map: &PartitionMap,
    version: &semver::Version,
) -> Result<Vec<u8>> {
    match (count, partitions) {
        (Some(_), Some(_)) => bail!("use only one of --count or --partitions"),
        (None, None) => bail!("one of --count or --partitions is required"),
        (Some(count), None) => {
            if count > channel::PARTITION_COUNT {
                bail!("--count must be <= {}", channel::PARTITION_COUNT);
            }
            Ok(channel::ascending_fill(count, map, version))
        }
        (None, Some(spec)) => parse_partition_list(spec),
    }
}

fn parse_partition_list(spec: &str) -> Result<Vec<u8>> {
    let mut buckets = Vec::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bucket = parse_partition(raw)?;
        if !buckets.contains(&bucket) {
            buckets.push(bucket);
        }
    }
    if buckets.is_empty() {
        bail!("partition list is empty");
    }
    Ok(buckets)
}

fn parse_partition(raw: &str) -> Result<u8> {
    if let Some(hex) = raw.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    if raw.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')) {
        return u8::from_str_radix(raw, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    raw.parse::<u8>()
        .with_context(|| format!("invalid decimal partition '{raw}'"))
}

fn read_channel_partition_map(dir: &Path, channel_name: &str) -> Result<PartitionMap> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    let mut map = PartitionMap::new();

    for bucket in 0..=u8::MAX {
        let path = channel_dir.join(channel::bucket_hex(bucket));
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let tag = parse_tag_object(&content)
            .with_context(|| format!("parsing channel partition {}", path.display()))?;
        verify_name_binding(&tag, channel_name)?;
        if tag.target_type != TagTarget::Tag {
            bail!(
                "channel partition {} targets {:?}, expected tag",
                path.display(),
                tag.target_type,
            );
        }
        let version = release_tags.get(&tag.object).ok_or_else(|| {
            anyhow::anyhow!(
                "channel partition {} points at unknown release tag object {}",
                path.display(),
                tag.object,
            )
        })?;
        map.set(bucket as usize, version.clone())?;
    }
    Ok(map)
}

fn semver_tag_object_map(dir: &Path) -> Result<BTreeMap<String, semver::Version>> {
    let mut map = BTreeMap::new();
    for version in semver_tag_versions(dir)? {
        let oid = assert_release_tag_exists(dir, &version)?;
        map.insert(oid, version);
    }
    Ok(map)
}

fn write_channel_partition_tag(
    dir: &Path,
    channel_name: &str,
    bucket: u8,
    version: &semver::Version,
    signing_key: &str,
) -> Result<()> {
    let target = format!("{version}^{{tag}}");
    let message = format!(
        "AOS channel {channel_name} partition {}",
        channel::bucket_hex(bucket)
    );
    sign_tag(
        dir,
        channel_name,
        &target,
        Some(&message),
        signing_key,
        true,
    )?;
    let tag_ref = format!("refs/tags/{channel_name}^{{tag}}");
    let oid = git(dir, &["rev-parse", &tag_ref])?;
    let payload = git_raw(dir, &["cat-file", "-p", &oid])?;

    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    std::fs::create_dir_all(&channel_dir)
        .with_context(|| format!("creating {}", channel_dir.display()))?;
    let partition = channel_dir.join(channel::bucket_hex(bucket));
    std::fs::write(&partition, payload)
        .with_context(|| format!("writing {}", partition.display()))?;

    git(dir, &["tag", "-d", channel_name])
        .with_context(|| format!("deleting temporary channel tag '{channel_name}'"))?;
    Ok(())
}

fn update_channel_frontier(dir: &Path, channel_name: &str, map: &PartitionMap) -> Result<()> {
    channel::assert_full_partition_set(map)?;
    let frontier = channel::compute_frontier(map)
        .ok_or_else(|| anyhow::anyhow!("channel '{channel_name}' has no frontier"))?;
    let commit = release_commit(dir, &frontier)?;
    git(
        dir,
        &["update-ref", &format!("refs/heads/{channel_name}"), &commit],
    )?;
    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after channel update")?;
    Ok(())
}

/// Sign an annotated tag object with git's SSH signing support.
fn sign_tag(
    dir: &Path,
    tag_name: &str,
    target: &str,
    message: Option<&str>,
    signing_key: &str,
    force: bool,
) -> Result<()> {
    let message = message.unwrap_or("AOS registry release");
    ensure_commit_identity(dir)?;
    let signing_key_config = format!("user.signingkey={signing_key}");
    let mut command = gitcmd::hermetic();
    command
        .arg("-c")
        .arg("gpg.format=ssh")
        .arg("-c")
        .arg(signing_key_config)
        .arg("tag")
        .arg("-s");
    if force {
        command.arg("-f");
    }
    command
        .arg(tag_name)
        .arg("-m")
        .arg(message)
        .arg(target)
        .current_dir(dir);

    let output = command
        .output()
        .with_context(|| format!("signing tag '{tag_name}' in {}", dir.display()))?;
    if !output.status.success() {
        bail!(
            "git tag -s failed for '{}': {}",
            tag_name,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers (format)
// ---------------------------------------------------------------------------

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kib = bytes as f64 / 1024.0;
    if kib < 1024.0 {
        return format!("{kib:.1} KiB");
    }
    let mib = kib / 1024.0;
    if mib < 1024.0 {
        return format!("{mib:.1} MiB");
    }
    let gib = mib / 1024.0;
    format!("{gib:.1} GiB")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::verify_tag_signature;
    use crate::testutil;
    use crate::types::{ApmSettings, ProfileScope, RegistryConfig, RegistryUploadAuthConfig};
    use std::fs;
    use tempfile::TempDir;

    struct TestSigningFixture {
        trusted_key: String,
        private_key: PathBuf,
    }

    #[test]
    fn parse_store_path_standard() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-curl-8.5.0");
        assert_eq!(name, "curl");
        assert_eq!(version, "8.5.0");
    }

    #[test]
    fn parse_store_path_multi_dash_name() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-my-cool-package-1.2.3");
        assert_eq!(name, "my-cool-package");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn parse_store_path_no_version() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-just-name");
        assert_eq!(name, "just-name");
        assert_eq!(version, "0.0.0");
    }

    #[test]
    fn first_letter_basic() {
        assert_eq!(first_letter("curl"), "c");
        assert_eq!(first_letter("Zlib"), "z");
    }

    #[test]
    fn semver_tag_list_filters_and_sorts_registry_releases() {
        let versions =
            semver_versions_from_tag_list("not-a-release\n1.2.0\nv1.3.0\n1.1.9\n1.2.0\n");
        assert_eq!(
            versions,
            vec![
                semver::Version::parse("1.1.9").unwrap(),
                semver::Version::parse("1.2.0").unwrap(),
            ],
        );
    }

    #[test]
    fn initial_keys_roster_defaults_to_empty_schema_one_roster() {
        let roster = initial_keys_roster("aos-core", None, None).unwrap();
        assert_eq!(roster.schema, keys::KEYS_TOML_SCHEMA);
        assert!(roster.active.is_empty());
        assert!(roster.revoked.is_empty());
    }

    #[test]
    fn initial_keys_roster_accepts_matching_registry_key() {
        let roster =
            initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), Some("2026a"))
                .unwrap();
        assert_eq!(roster.active.len(), 1);
        assert_eq!(roster.active[0].id, "2026a");
        assert_eq!(roster.active[0].key, "aos-core:Ed25519:YWJjZA==");
    }

    #[test]
    fn initial_keys_roster_defaults_key_id_when_key_is_supplied() {
        let roster =
            initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), None).unwrap();
        assert_eq!(roster.active[0].id, "initial");
    }

    #[test]
    fn initial_keys_roster_rejects_key_id_without_key() {
        let err = initial_keys_roster("aos-core", None, Some("2026a")).unwrap_err();
        assert!(format!("{err:#}").contains("--trust-key-id requires --trust-key"));
    }

    #[test]
    fn initial_keys_roster_rejects_foreign_registry_key() {
        let err = initial_keys_roster("aos-core", Some("other:Ed25519:YWJjZA=="), Some("2026a"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("expected 'aos-core'"));
    }

    #[test]
    fn producer_signing_key_direct_path_bypasses_key_id_lookup() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        };
        let resolved = resolve_producer_signing_key(
            &config,
            Path::new("/missing"),
            "aos-core",
            Some("/tmp/key"),
            None,
        )
        .unwrap();

        assert_eq!(resolved, "/tmp/key");
    }

    #[test]
    fn producer_signing_key_rejects_ambiguous_key_sources() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        };
        let err = resolve_producer_signing_key(
            &config,
            Path::new("/missing"),
            "aos-core",
            Some("/tmp/key"),
            Some("initial"),
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("use only one of --key or --key-id"));
    }

    #[test]
    fn producer_signing_key_id_resolves_configured_private_key() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

        let resolved =
            resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
                .unwrap();

        assert_eq!(PathBuf::from(resolved), signing.private_key);
    }

    #[test]
    fn producer_signing_key_id_rejects_missing_local_mapping() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(test_registry_config("aos-core", None), None)],
            scope: ProfileScope::User,
        };

        let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
            .unwrap_err();

        assert!(format!("{err:#}").contains("no local private key path configured"));
    }

    #[test]
    fn producer_signing_key_id_rejects_revoked_key() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &["initial"]).unwrap();
        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

        let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
            .unwrap_err();

        assert!(format!("{err:#}").contains("revoked"));
    }

    #[test]
    fn producer_signing_key_id_signs_verifiable_release_tag() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);
        let resolved =
            resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
                .unwrap();
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("AOS registry release"),
            &resolved,
            false,
        )
        .unwrap();

        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&signing.trusted_key))
                .unwrap()
        );
    }

    #[test]
    fn remote_diff_base_uses_pushed_current_branch_without_origin_head() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        let origin = tmp.path().join("origin.git");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();
        git(
            tmp.path(),
            &[
                "init",
                "--bare",
                "--object-format=sha256",
                origin.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        )
        .unwrap();
        git(&repo, &["push", "origin", "main"]).unwrap();

        assert!(!git_ref_exists(&repo, "origin/HEAD").unwrap());
        assert_eq!(remote_diff_base(&repo).unwrap(), "origin/main");
    }

    #[test]
    fn registry_upload_auth_config_selects_requested_registry() {
        let config_auth = RegistryUploadAuthConfig {
            token: Some("core-token".into()),
            view: Some("prod".into()),
            ..RegistryUploadAuthConfig::default()
        };
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![
                (test_registry_config("other", None), None),
                (
                    test_registry_config("core", Some(config_auth.clone())),
                    None,
                ),
            ],
            scope: ProfileScope::User,
        };

        let selected = registry_upload_auth_config(&config, "core").expect("core auth config");
        assert_eq!(selected, &config_auth);
        assert!(registry_upload_auth_config(&config, "missing").is_none());
    }

    fn test_registry_config(
        name: &str,
        upload_auth: Option<RegistryUploadAuthConfig>,
    ) -> RegistryConfig {
        RegistryConfig {
            name: name.into(),
            url: format!("https://registry.example.com/{name}"),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            upload_auth,
            signing_keys: Default::default(),
            signing: None,
        }
    }

    fn test_config_with_signing_key(registry: &str, key_id: &str, private_key: &Path) -> ApmConfig {
        let mut registry_config = test_registry_config(registry, None);
        registry_config.signing_keys.insert(
            key_id.to_string(),
            private_key.to_str().unwrap().to_string(),
        );
        ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(registry_config, None)],
            scope: ProfileScope::User,
        }
    }

    fn write_test_roster(
        dir: &Path,
        key_id: &str,
        trusted_key: &str,
        revoked: &[&str],
    ) -> Result<()> {
        let roster = KeysToml {
            active: vec![RosterKey {
                id: key_id.to_string(),
                key: trusted_key.to_string(),
            }],
            revoked: revoked
                .iter()
                .map(|id| RevokedKey {
                    id: (*id).to_string(),
                    reason: Some("test".into()),
                })
                .collect(),
            ..KeysToml::default()
        };
        keys::write_keys_toml(dir, &roster)
    }

    fn write_test_signing_key(root: &Path, registry: &str) -> TestSigningFixture {
        write_seeded_signing_key(root, registry, [9u8; 32], "registry_ed25519")
    }

    fn write_seeded_signing_key(
        root: &Path,
        registry: &str,
        seed: [u8; 32],
        name: &str,
    ) -> TestSigningFixture {
        let signing_dir = root.join("signing");
        fs::create_dir_all(&signing_dir).unwrap();

        let keypair = crate::sshkey::Ed25519Keypair::from_seed(seed);
        let private_key = signing_dir.join(name);

        fs::write(&private_key, keypair.to_openssh_private_key(registry)).unwrap();
        restrict_private_key_permissions(&private_key).unwrap();

        TestSigningFixture {
            trusted_key: keypair.trust_key_line(registry),
            private_key,
        }
    }

    #[test]
    fn retirement_resign_rotates_release_and_partition_signatures() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=stable",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        // Maintainer A signs everything and then retires; B survives.
        let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [9u8; 32], "key_a");
        let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [10u8; 32], "key_b");
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        let version = semver::Version::new(1, 0, 0);
        let key_a_path = key_a.private_key.to_str().unwrap();
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("release 1.0.0"),
            key_a_path,
            false,
        )
        .unwrap();
        let printer = Printer::new(0, true, false);
        channel_init_dir(&repo, "prod", &version, key_a_path, &printer).unwrap();

        // Nothing is affected while A is still a survivor.
        let survivors_both = vec![key_a.trusted_key.clone(), key_b.trusted_key.clone()];
        let plan = plan_retirement_resign(&repo, &survivors_both).unwrap();
        assert!(plan.is_empty());

        // Retiring A: the release tag and every partition need re-signing.
        let survivors = vec![key_b.trusted_key.clone()];
        let plan = plan_retirement_resign(&repo, &survivors).unwrap();
        assert_eq!(plan.affected_releases, vec![version.clone()]);
        assert_eq!(plan.affected_partitions.len(), 256);

        execute_retirement_resign(&repo, &plan, key_b.private_key.to_str().unwrap(), &printer)
            .unwrap();

        // The release tag now verifies only against the survivor.
        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_b.trusted_key)).unwrap()
        );
        assert!(
            !verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_a.trusted_key))
                .unwrap()
        );

        // Partition payloads were regenerated against the new tag object
        // and verify against the survivor.
        let payload = fs::read(repo.join(".git/channels/prod/00")).unwrap();
        let oid = hash_tag_object(&repo, &payload).unwrap();
        assert!(
            verify_tag_signature(&repo, &oid, std::slice::from_ref(&key_b.trusted_key)).unwrap()
        );
        let map = read_channel_partition_map(&repo, "prod").unwrap();
        assert_eq!(channel::compute_frontier(&map), Some(version));

        // Re-planning against the survivor finds nothing left to re-sign.
        let plan = plan_retirement_resign(&repo, &survivors).unwrap();
        assert!(plan.is_empty());
    }

    #[cfg(unix)]
    fn restrict_private_key_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))
    }

    #[cfg(not(unix))]
    fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[test]
    fn partition_list_accepts_decimal_and_hex() {
        assert_eq!(
            parse_partition_list("0,1,0a,0xff,1").unwrap(),
            vec![0, 1, 10, 255],
        );
        assert!(parse_partition_list("").is_err());
        assert!(parse_partition_list("256").is_err());
    }

    #[test]
    fn channel_advance_selector_requires_one_mode() {
        let map = PartitionMap::all(semver::Version::parse("1.0.0").unwrap());
        let target = semver::Version::parse("1.1.0").unwrap();

        assert!(select_partitions_for_advance(None, None, &map, &target).is_err());
        assert!(select_partitions_for_advance(Some(1), Some("0"), &map, &target).is_err());
        assert_eq!(
            select_partitions_for_advance(Some(3), None, &map, &target).unwrap(),
            vec![0, 1, 2],
        );
    }

    #[test]
    fn build_package_toml_new() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec!["ref1".into(), "ref2".into()],
            closure_size: 5242880,
        };
        let content = build_package_toml(
            "",
            "curl",
            "8.5.0",
            "x86_64-linux",
            &info,
            Some("URL transfer tool"),
            Some("https://curl.se"),
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
        )
        .unwrap();
        assert!(content.contains("name = \"curl\""));
        assert!(content.contains("version = \"8.5.0\""));
        assert!(content.contains("x86_64-linux"));
        assert!(content.contains("sha256:deadbeef"));
        assert!(content.contains("source_drv = \"\""));
        assert!(content.contains("source_nar_hash = \"\""));
    }

    #[test]
    fn build_package_toml_records_source_deriver() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let source_info = StorePathInfo {
            path: "/nix/store/drv123-curl-8.5.0.drv".into(),
            nar_hash: "sha256:source".into(),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let content = build_package_toml(
            "",
            "curl",
            "8.5.0",
            "x86_64-linux",
            &info,
            Some("URL transfer tool"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            Some(&source_info),
        )
        .unwrap();
        assert!(content.contains("source_drv = \"/nix/store/drv123-curl-8.5.0.drv\""));
        assert!(content.contains("source_nar_hash = \"sha256:source\""));
    }

    #[test]
    fn build_package_toml_update_existing() {
        let existing = r#"[package]
name = "curl"
description = "URL transfer tool"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/old-curl-8.5.0"
nar_hash = "sha256:old"
nar_size = 100
closure_size = 500
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let info = StorePathInfo {
            path: "/nix/store/new-curl-8.5.0".into(),
            nar_hash: "sha256:new".into(),
            nar_size: 200,
            references: vec![],
            closure_size: 600,
        };
        let content = build_package_toml(
            existing,
            "curl",
            "8.5.0",
            "aarch64-linux",
            &info,
            None,
            None,
            None,
            None,
            false,
            None,
            &[],
            None,
        )
        .unwrap();
        // Should contain both platforms.
        assert!(content.contains("x86_64-linux"));
        assert!(content.contains("aarch64-linux"));
        assert!(content.contains("sha256:new"));
    }

    #[test]
    fn build_package_toml_with_sysroot() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-server-2026.04".into(),
            nar_hash: "sha256:aabb".into(),
            nar_size: 12345678,
            references: vec!["ref1".into()],
            closure_size: 52428800,
        };
        let img_info = StorePathInfo {
            path: "/nix/store/def456-server-2026.04-raw".into(),
            nar_hash: "sha256:ccdd".into(),
            nar_size: 8589934592,
            references: vec![],
            closure_size: 0,
        };
        let content = build_package_toml(
            "",
            "server",
            "2026.04",
            "x86_64-linux",
            &info,
            Some("AOS server"),
            None,
            Some("MIT"),
            Some("aos-team"),
            true,
            Some("2026.03"),
            &[("raw".to_string(), img_info)],
            None,
        )
        .unwrap();
        assert!(content.contains("sysroot = true"));
        assert!(content.contains("previous = \"2026.03\""));
        assert!(content.contains("format = \"raw\""));
        assert!(content.contains("sha256:ccdd"));
    }

    #[test]
    fn selected_package_versions_filters_exact_version() {
        let toml_val: toml::Value = toml::from_str(
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-2.0.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []
"#,
        )
        .unwrap();

        let selected = selected_package_versions(&toml_val, Some("1.0.0")).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0]
                .get("version")
                .and_then(|version| version.as_str()),
            Some("1.0.0")
        );
        assert!(selected_package_versions(&toml_val, Some("9.9.9")).is_err());

        let raw = package_toml_with_versions(&toml_val, &selected).unwrap();
        let rendered = toml::to_string_pretty(&raw).unwrap();
        assert!(rendered.contains("1.0.0"));
        assert!(!rendered.contains("2.0.0"));
    }

    #[test]
    fn latest_version_string_uses_semver_and_platform_filter() {
        let toml_val: toml::Value = toml::from_str(
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.9.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.9.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "1.10.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-1.10.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "3.0.0"

[versions.platforms.aarch64-linux]
store_path = "/nix/store/ccc333-tool-3.0.0"
nar_hash = "sha256:v3"
nar_size = 3
closure_size = 3
source_drv = ""
source_nar_hash = ""
references = []
"#,
        )
        .unwrap();

        assert_eq!(
            latest_version_string(&matching_package_versions(&toml_val, Some("x86_64-linux"))),
            Some("1.10.0".to_string())
        );
        assert_eq!(
            latest_version_string(&matching_package_versions(&toml_val, Some("aarch64-linux"))),
            Some("3.0.0".to_string())
        );
        assert!(matching_package_versions(&toml_val, Some("riscv64-linux")).is_empty());
    }

    #[test]
    fn cache_validation_entries_honor_package_and_platform_filters() {
        let tmp = TempDir::new().unwrap();
        let pkg_dir = tmp.path().join("packages").join("t");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("tool.toml"),
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
        )
        .unwrap();

        let entries =
            collect_cache_validation_entries(tmp.path(), Some("tool"), Some("aarch64-linux"))
                .unwrap();
        assert_eq!(
            entries,
            vec![
                CacheValidationEntry {
                    name: "tool".into(),
                    platform: "aarch64-linux".into(),
                    store_path: "/nix/store/bbb222-tool-1.0.0".into(),
                    store_hash: "bbb222".into(),
                    nar_hash: "sha256:arm".into(),
                },
                CacheValidationEntry {
                    name: "tool".into(),
                    platform: "aarch64-linux".into(),
                    store_path: "/nix/store/ccc333-tool-image-1.0.0".into(),
                    store_hash: "ccc333".into(),
                    nar_hash: "sha256:image".into(),
                },
            ]
        );
        assert!(
            collect_cache_validation_entries(tmp.path(), Some("missing"), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn remove_missing_cache_entries_prunes_platforms_and_images() {
        let tmp = TempDir::new().unwrap();
        let pkg_dir = tmp.path().join("packages/t");
        fs::create_dir_all(&pkg_dir).unwrap();
        let toml_path = pkg_dir.join("tool.toml");
        fs::write(
            &toml_path,
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
        )
        .unwrap();

        let mut missing = std::collections::HashSet::new();
        missing.insert("/nix/store/ccc333-tool-image-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        let toml_val: toml::Value =
            toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
        let aarch64 = toml_val
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("aarch64-linux"))
            .unwrap();
        assert!(aarch64.get("images").is_none());

        missing.clear();
        missing.insert("/nix/store/bbb222-tool-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        let toml_val: toml::Value =
            toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
        let platforms = toml_val
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.as_table())
            .unwrap();
        assert!(platforms.contains_key("x86_64-linux"));
        assert!(!platforms.contains_key("aarch64-linux"));

        missing.clear();
        missing.insert("/nix/store/aaa111-tool-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        assert!(!toml_path.exists());
    }

    #[tokio::test]
    async fn cache_validation_entry_follows_narinfo_url() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let narinfo = concat!(
                    "StorePath: /nix/store/abc123-tool-1.0.0\n",
                    "URL: nar/abc123-sha256-test.nar.zst\n",
                    "Compression: zstd\n",
                    "NarHash: sha256:test\n",
                    "NarSize: 1\n",
                );
                let response = if req.starts_with("GET /abc123.narinfo ") {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        narinfo.len(),
                        narinfo,
                    )
                } else if req.starts_with("HEAD /nar/abc123-sha256-test.nar.zst ") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let result = validate_cache_entry(
            &reqwest::Client::new(),
            &[CacheEntry {
                url: format!("http://{addr}"),
                priority: 100,
            }],
            CacheValidationEntry {
                name: "tool".into(),
                platform: "x86_64-linux".into(),
                store_path: "/nix/store/abc123-tool-1.0.0".into(),
                store_hash: "abc123".into(),
                nar_hash: "sha256:test".into(),
            },
        )
        .await;

        assert!(result.found, "{result:?}");
        server.await.unwrap();
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
        assert_eq!(format_size(3_300_000), "3.1 MiB");
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }

    /// Initialize a git repository with one commit at `dir`.
    fn init_authoring_clone(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        testutil::git(dir, &["init"]);
        fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();
        testutil::git(dir, &["add", "."]);
        testutil::git(dir, &["commit", "-m", "init"]);
    }

    #[test]
    fn local_registries_skips_configured_names() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("configured-reg")).unwrap();
        fs::create_dir_all(tmp.path().join("authored-reg/packages/t")).unwrap();
        fs::write(
            tmp.path().join("authored-reg/packages/t/tool-1.0.0.toml"),
            "",
        )
        .unwrap();

        let local = local_registries(tmp.path(), &["configured-reg"]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "authored-reg");
        assert_eq!(local[0].packages, 1);
        assert_eq!(local[0].origin, None);
    }

    #[test]
    fn local_registries_reports_origin() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        testutil::git(
            &dir,
            &["remote", "add", "origin", "https://cdn.example.com/reg"],
        );

        let local = local_registries(tmp.path(), &[]);
        assert_eq!(local.len(), 1);
        assert_eq!(
            local[0].origin.as_deref(),
            Some("https://cdn.example.com/reg")
        );
    }

    #[test]
    fn local_registries_missing_dir_is_empty() {
        let tmp = TempDir::new().unwrap();
        assert!(local_registries(&tmp.path().join("absent"), &[]).is_empty());
    }

    #[test]
    fn authoring_clone_precious_ignores_plain_dirs() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("consumer-reg");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();

        assert!(authoring_clone_precious(&dir).unwrap().is_none());
        assert!(
            authoring_clone_precious(&tmp.path().join("absent"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn authoring_clone_precious_without_remote() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);

        let reason = authoring_clone_precious(&dir).unwrap();
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("no remote")),
            "got: {reason:?}"
        );
    }

    #[test]
    fn authoring_clone_precious_uncommitted_changes() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        fs::write(dir.join("registry.toml"), "[registry]\nname = \"x\"\n").unwrap();

        let reason = authoring_clone_precious(&dir).unwrap();
        assert_eq!(reason.as_deref(), Some("uncommitted changes"));
    }

    #[test]
    fn authoring_clone_precious_unpushed_and_pushed() {
        let tmp = TempDir::new().unwrap();
        let origin = tmp.path().join("origin.git");
        fs::create_dir_all(&origin).unwrap();
        testutil::git(&origin, &["init", "--bare"]);

        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        testutil::git(&dir, &["remote", "add", "origin", origin.to_str().unwrap()]);

        let reason = authoring_clone_precious(&dir).unwrap();
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("not pushed to any remote")),
            "got: {reason:?}"
        );

        let branch = testutil::git(&dir, &["branch", "--show-current"]);
        testutil::git(&dir, &["push", "origin", &branch]);
        assert!(authoring_clone_precious(&dir).unwrap().is_none());
    }
}
