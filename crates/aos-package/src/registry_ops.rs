//! Registry management operations (`apr` / `apm registry`).
//!
//! This module implements producer-side tooling for maintaining AOS package
//! registries. It operates on local git clones stored at
//! `~/.local/share/apm/registries/<name>/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::registry::channel::{self, PartitionMap};
use crate::registry::nixcache;
use crate::registry::objectstore;
use crate::registry::verify::{TagTarget, parse_tag_object, verify_name_binding};
use crate::types::{CacheEntry, RegistryRootConfig};
use crate::{BranchCommand, CacheCommand, ChannelCommand, PrCommand};

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
            let Some(name) = names.into_iter().next() else {
                bail!("registry directory lookup found no registry names");
            };
            return Ok(name);
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

/// Dispatch a git-shaped registry operation through libgit2, returning stdout.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    git2_dispatch(dir, args).with_context(|| {
        format!(
            "running git2-backed {} in {}",
            args.join(" "),
            dir.display()
        )
    })
}

/// Dispatch a git-shaped registry operation through libgit2, returning raw stdout bytes.
fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    Ok(git(dir, args)?.into_bytes())
}

/// Run a git-shaped operation that is allowed to fail, returning (success, stdout, stderr).
#[allow(dead_code)]
fn git_try(dir: &Path, args: &[&str]) -> Result<(bool, String, String)> {
    match git(dir, args) {
        Ok(stdout) => Ok((true, stdout, String::new())),
        Err(err) => Ok((false, String::new(), err.to_string())),
    }
}

fn git2_dispatch(dir: &Path, args: &[&str]) -> Result<String> {
    match args {
        ["init", "--object-format=sha256"] => {
            crate::git_support::init_sha256(dir, false, "master")?;
            Ok(String::new())
        }
        ["symbolic-ref", "HEAD", refname] => {
            let repo = crate::git_support::open(dir)?;
            repo.set_head(refname)
                .with_context(|| format!("setting HEAD to {refname}"))?;
            Ok(String::new())
        }
        ["add", "-A"] => {
            let repo = crate::git_support::open(dir)?;
            let mut index = repo.index().context("opening git index")?;
            index
                .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
                .context("adding all paths")?;
            index.write().context("writing git index")?;
            Ok(String::new())
        }
        ["commit", "-m", message] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::commit_all(&repo, message)?;
            Ok(String::new())
        }
        ["tag", "--list"] | ["tag", "-l"] => {
            let repo = crate::git_support::open(dir)?;
            Ok(crate::git_support::tag_names(&repo)?.join("\n"))
        }
        ["remote", "add", name, url] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::remote_add(&repo, name, url)?;
            Ok(String::new())
        }
        ["status"] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::status(&repo)
        }
        ["diff"] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::diff(&repo, None, None, false)
        }
        ["diff", "--stat"] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::diff(&repo, None, None, true)
        }
        ["diff", left, right] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::diff(&repo, Some(left), Some(right), false)
        }
        ["diff", left, right, "--stat"] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::diff(&repo, Some(left), Some(right), true)
        }
        ["log", "--oneline", count] => {
            let repo = crate::git_support::open(dir)?;
            let max = count.trim_start_matches('-').parse().unwrap_or(10);
            crate::git_support::log(&repo, max, None)
        }
        ["log", "--oneline", count, "--", path] => {
            let repo = crate::git_support::open(dir)?;
            let max = count.trim_start_matches('-').parse().unwrap_or(10);
            crate::git_support::log(&repo, max, Some(Path::new(path)))
        }
        ["branch", "-a"] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::branch_list(&repo)
        }
        ["branch", name] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::branch_create(&repo, name)?;
            Ok(String::new())
        }
        ["checkout", name] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::checkout_branch(&repo, name)?;
            Ok(String::new())
        }
        ["branch", "-d", name] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::branch_delete(&repo, name)?;
            Ok(String::new())
        }
        ["rev-list", "-n", "1", rev] => {
            let repo = crate::git_support::open(dir)?;
            Ok(crate::git_support::resolve_commit_oid(&repo, rev)?.to_string())
        }
        ["rev-parse", rev] => {
            let repo = crate::git_support::open(dir)?;
            Ok(crate::git_support::resolve_oid(&repo, rev)?.to_string())
        }
        ["cat-file", "-p", rev] => {
            let repo = crate::git_support::open(dir)?;
            let (_kind, data) = crate::git_support::raw_object(&repo, rev)?;
            Ok(String::from_utf8_lossy(&data).to_string())
        }
        ["tag", "-d", name] => {
            let repo = crate::git_support::open(dir)?;
            crate::git_support::delete_tag(&repo, name)?;
            Ok(String::new())
        }
        ["update-ref", refname, commit] => {
            let repo = crate::git_support::open(dir)?;
            let oid = crate::git_support::resolve_commit_oid(&repo, commit)?;
            repo.reference(refname, oid, true, "update ref")
                .with_context(|| format!("updating {refname}"))?;
            Ok(String::new())
        }
        ["push", rest @ ..] => git2_push(dir, rest),
        ["pull"] => git2_pull(dir, false),
        ["pull", "--rebase"] => git2_pull(dir, true),
        ["merge", rest @ ..] => git2_merge(dir, rest),
        _ => bail!("unsupported git2-backed operation: {}", args.join(" ")),
    }
}

fn git2_push(dir: &Path, args: &[&str]) -> Result<String> {
    let repo = crate::git_support::open(dir)?;
    let mut force = false;
    let mut remote = "origin";
    let mut branch = current_branch(&repo)?;
    let mut iter = args.iter().copied().peekable();
    while let Some(arg) = iter.next() {
        match arg {
            "-u" => {
                if let Some(next) = iter.next() {
                    remote = next;
                }
            }
            "--force" => force = true,
            other if other != "origin" => branch = other.to_string(),
            _ => {}
        }
    }
    let prefix = if force { "+" } else { "" };
    crate::git_support::push(
        &repo,
        remote,
        &[format!("{prefix}refs/heads/{branch}:refs/heads/{branch}")],
    )?;
    Ok(String::new())
}

fn git2_pull(dir: &Path, rebase: bool) -> Result<String> {
    if rebase {
        bail!("git2-backed pull --rebase is not supported yet");
    }
    let repo = crate::git_support::open(dir)?;
    let branch = current_branch(&repo)?;
    let remote = repo
        .find_remote("origin")
        .context("opening origin remote")?;
    let url = remote.url().context("reading origin URL")?.to_string();
    let refspec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
    crate::git_support::fetch(dir, &url, &[refspec])?;
    fast_forward_to(&repo, &format!("refs/remotes/origin/{branch}"))?;
    Ok(String::new())
}

fn git2_merge(dir: &Path, args: &[&str]) -> Result<String> {
    if args
        .iter()
        .any(|arg| *arg == "--no-ff" || *arg == "--squash")
    {
        bail!("git2-backed merge currently supports fast-forward merges only");
    }
    let branch = args
        .last()
        .ok_or_else(|| anyhow::anyhow!("merge requires a branch"))?;
    let repo = crate::git_support::open(dir)?;
    fast_forward_to(&repo, branch)?;
    Ok(String::new())
}

fn fast_forward_to(repo: &git2::Repository, rev: &str) -> Result<()> {
    let target = crate::git_support::resolve_commit_oid(repo, rev)?;
    let head = repo.head().context("reading HEAD")?;
    if let Some(current) = head.target() {
        if current == target {
            return Ok(());
        }
        if !repo
            .graph_descendant_of(target, current)
            .context("checking fast-forward relationship")?
        {
            bail!("cannot fast-forward HEAD to {rev}: histories have diverged");
        }
    }
    let head_name = head.name().context("reading HEAD name")?.to_string();
    repo.reference(&head_name, target, true, "fast-forward")?;
    repo.set_head(&head_name)?;
    repo.checkout_head(None)?;
    Ok(())
}

fn current_branch(repo: &git2::Repository) -> Result<String> {
    let head = repo.head().context("reading HEAD")?;
    Ok(head
        .shorthand()
        .context("reading HEAD shorthand")?
        .to_string())
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
    let output = Command::new("nix")
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
    let output = Command::new("nix-store")
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
        let ref_output = Command::new("nix-store")
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

/// Create a git commit in the registry directory.
fn commit_registry(dir: &Path, message: &str) -> Result<()> {
    git(dir, &["add", "-A"])?;
    git(dir, &["commit", "-m", message])?;
    Ok(())
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

// ---------------------------------------------------------------------------
// Registry Lifecycle
// ---------------------------------------------------------------------------

/// `apr create <NAME>`
pub async fn create(
    config: &ApmConfig,
    name: &str,
    remote: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = config.scope.registries_path().join(name);

    if dir.exists() {
        bail!("registry '{name}' already exists at {}", dir.display());
    }

    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    printer.info(&format!("Initializing registry '{name}'..."));

    git(&dir, &["init", "--object-format=sha256"])?;
    git(&dir, &["symbolic-ref", "HEAD", "refs/heads/stable"])?;
    objectstore::assert_sha256(&dir)?;

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

    // Initial commit.
    git(&dir, &["add", "-A"])?;
    git(
        &dir,
        &["commit", "-m", &format!("Initialize registry '{name}'")],
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
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }

    // Validate image pairs.
    if image_paths.len() != image_formats.len() {
        bail!(
            "--image and --image-format must be specified in pairs ({} images, {} formats)",
            image_paths.len(),
            image_formats.len()
        );
    }

    printer.step(1, 3, "Introspecting store path...");
    let info = introspect_store_path(store_path)?;

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
        commit_registry(&dir, msg)?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after publish")?;
        printer.success(&format!("Committed: {msg}"));
    } else {
        printer.info("Skipped commit (--no-commit).");
    }

    Ok(())
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
) -> Result<String> {
    let desc = description.unwrap_or("No description");
    let lic = license.unwrap_or("unknown");
    let maint = maintainer.unwrap_or("unknown");

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
             source_drv = \"\"\n\
             source_nar_hash = \"\"\n\
             references = [{}]\n",
            info.path,
            info.nar_hash,
            info.nar_size,
            info.closure_size,
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
            t.insert("source_drv".into(), toml::Value::String(String::new()));
            t.insert("source_nar_hash".into(), toml::Value::String(String::new()));
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
                if let Some(plat) = platform {
                    // Remove specific platform from specific version.
                    if let Some(idx) = versions
                        .iter()
                        .position(|v| v.get("version").and_then(|s| s.as_str()) == Some(ver))
                    {
                        if let Some(platforms) = versions[idx]
                            .as_table_mut()
                            .and_then(|t| t.get_mut("platforms"))
                            .and_then(|p| p.as_table_mut())
                        {
                            platforms.remove(plat);
                            if platforms.is_empty() {
                                versions.remove(idx);
                            }
                        }
                    }
                } else {
                    // Remove entire version.
                    versions.retain(|v| v.get("version").and_then(|s| s.as_str()) != Some(ver));
                }
            } else if let Some(plat) = platform {
                // Remove platform from all versions.
                for ver in versions.iter_mut() {
                    if let Some(platforms) = ver
                        .as_table_mut()
                        .and_then(|t| t.get_mut("platforms"))
                        .and_then(|p| p.as_table_mut())
                    {
                        platforms.remove(plat);
                    }
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
        commit_registry(&dir, msg)?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after unpublish")?;
        printer.success(&format!("Committed: {msg}"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Registry Query
// ---------------------------------------------------------------------------

/// `apr show <PACKAGE>`
pub async fn show(
    config: &ApmConfig,
    package: &str,
    _version: Option<&str>,
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

    if raw {
        printer.plain(&content);
    } else {
        let toml_val: toml::Value = toml::from_str(&content)?;
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
        if let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) {
            for ver in versions {
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
    }

    Ok(())
}

/// `apr packages`
pub async fn packages(
    config: &ApmConfig,
    _platform: Option<&str>,
    _outdated: bool,
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
                let version = toml_val
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                pkgs.push((name.to_string(), version.to_string()));
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

/// `apr verify`
pub async fn verify(
    config: &ApmConfig,
    _package: Option<&str>,
    _fix: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let packages_dir = dir.join("packages");
    let closures_dir = dir.join("closures");

    let mut errors = 0u32;
    let mut checked = 0u32;

    // Collect all store path hashes from package TOMLs.
    let mut all_store_hashes: Vec<(String, String)> = Vec::new(); // (hash, pkg_name)
    let mut all_ref_hashes: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new(); // hash -> references

    // Verify package TOML files.
    if packages_dir.is_dir() {
        for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
            if !letter_entry.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
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
                                                all_store_hashes
                                                    .push((hash.clone(), pkg_name.to_string()));
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

    // Verify closure files.
    let mut closure_checked = 0u32;

    for (store_hash, pkg_name) in &all_store_hashes {
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
        let known_hashes: std::collections::HashSet<&str> =
            all_store_hashes.iter().map(|(h, _)| h.as_str()).collect();
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
        let mut args = vec!["diff", "HEAD", "origin/HEAD"];
        if stat {
            args.push("--stat");
        }
        let output = git(&dir, &args)?;
        printer.plain(&output);
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

/// `apr validate`
#[allow(clippy::too_many_arguments)]
pub async fn validate(
    config: &ApmConfig,
    _package: Option<&str>,
    _platform: Option<&str>,
    _fix: bool,
    jobs: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let mirrors = resolve_mirrors(&dir);

    if mirrors.is_empty() {
        printer.warning("No caches configured in registry.toml. Cannot validate.");
        return Ok(());
    }

    // Collect all store paths from packages and images.
    let mut store_paths: Vec<(String, String)> = Vec::new(); // (name, nar_hash)

    let packages_dir = dir.join("packages");
    if packages_dir.is_dir() {
        for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
            if !letter_entry.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    let content = std::fs::read_to_string(&path)?;
                    let toml_val: toml::Value = toml::from_str(&content)?;
                    if let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) {
                        for ver in versions {
                            if let Some(platforms) = ver.get("platforms").and_then(|v| v.as_table())
                            {
                                for (_plat, entry) in platforms {
                                    if let Some(nar_hash) =
                                        entry.get("nar_hash").and_then(|v| v.as_str())
                                    {
                                        let name = toml_val
                                            .get("package")
                                            .and_then(|p| p.get("name"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown");
                                        store_paths.push((name.to_string(), nar_hash.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if store_paths.is_empty() {
        printer.info("No entries to validate.");
        return Ok(());
    }

    printer.info(&format!(
        "Validating {} entries against {} cache(s) with {} parallel requests...",
        store_paths.len(),
        mirrors.len(),
        jobs,
    ));

    let client = reqwest::Client::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs as usize));
    let mut handles = Vec::new();

    for (name, nar_hash) in &store_paths {
        let client = client.clone();
        let mirrors = mirrors.clone();
        let name = name.clone();
        let nar_hash = nar_hash.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        let handle = tokio::spawn(async move {
            let mut found = false;
            for cache in &mirrors {
                let url = format!("{}/{}.nar.zst", cache.url.trim_end_matches('/'), nar_hash);
                let resp = client.head(&url).send().await;
                if let Ok(resp) = resp {
                    if resp.status().is_success() {
                        found = true;
                        break;
                    }
                }
            }
            drop(permit);
            (name, nar_hash, found)
        });
        handles.push(handle);
    }

    let mut missing = 0u32;
    let mut ok = 0u32;
    for handle in handles {
        let (name, nar_hash, found) = handle.await?;
        if found {
            ok += 1;
        } else {
            missing += 1;
            printer.warning(&format!("{name}: {nar_hash} not found in any cache"));
        }
    }

    if missing == 0 {
        printer.success(&format!("All {ok} entries found in caches."));
    } else {
        printer.error(&format!("{ok} found, {missing} missing."));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git Workflow
// ---------------------------------------------------------------------------

/// `apr status`
pub async fn status(config: &ApmConfig, registry: Option<&str>, printer: &Printer) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let output = git(&dir, &["status"])?;
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
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_init(config, channel, &version, key, registry.as_deref(), printer).await
        }
        ChannelCommand::Advance {
            channel,
            semver,
            count,
            partitions,
            key,
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
                key,
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
            upload_url,
            priority,
            no_commit,
            registry,
        } => {
            let dir = registry_dir(config, registry.as_deref())?;
            let report =
                nixcache::generate_static_cache(&dir, output, key.as_deref(), *priority, printer)
                    .await?;

            printer.success(&format!(
                "Generated static cache: {} narinfos, {} NARs in {}",
                report.narinfos,
                report.nars,
                report.output_dir.display(),
            ));

            if let Some(upload_url) = upload_url {
                nixcache::upload_static_cache(output, upload_url, printer).await?;
            }

            if let Some(cache_url) = cache_url {
                if nixcache::upsert_registry_cache(&dir, cache_url, *priority)? {
                    printer.info(&format!("Updated registry.toml [[caches]] -> {cache_url}"));
                    if !*no_commit {
                        commit_registry(&dir, "registry: update static cache pointer")?;
                        refresh_registry_object_store(&dir)
                            .context("refreshing dumb-HTTP object store after cache update")?;
                    }
                }
            }

            Ok(())
        }
    }
}

async fn channel_init(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    signing_key: &str,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let dir = registry_dir(config, registry)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(&dir, channel_name, bucket, version, signing_key)?;
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
    signing_key: &str,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let dir = registry_dir(config, registry)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = read_channel_partition_map(&dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    if selected.is_empty() {
        printer.info("No partitions selected for advancement.");
        return Ok(());
    }

    for bucket in &selected {
        write_channel_partition_tag(&dir, channel_name, *bucket, version, signing_key)?;
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

    let output = git(&dir, &args)?;
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

    let output = git(&dir, &args)?;
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
// GitHub Integration
// ---------------------------------------------------------------------------

pub async fn run_pr(config: &ApmConfig, command: &PrCommand, printer: &Printer) -> Result<()> {
    match command {
        PrCommand::Create {
            title,
            body,
            base,
            draft,
            reviewer,
            registry,
        } => {
            pr_create(
                config,
                title.as_deref(),
                body.as_deref(),
                base.as_deref(),
                *draft,
                reviewer,
                registry.as_deref(),
                printer,
            )
            .await
        }
        PrCommand::List {
            author,
            mine,
            registry,
        } => {
            pr_list(
                config,
                author.as_deref(),
                *mine,
                registry.as_deref(),
                printer,
            )
            .await
        }
        PrCommand::Show { number, registry } => {
            pr_show(config, *number, registry.as_deref(), printer).await
        }
        PrCommand::Merge {
            number,
            squash,
            rebase,
            merge,
            delete_branch,
            registry,
        } => {
            pr_merge(
                config,
                *number,
                *squash,
                *rebase,
                *merge,
                *delete_branch,
                registry.as_deref(),
                printer,
            )
            .await
        }
        PrCommand::Diff { number, registry } => {
            pr_diff(config, *number, registry.as_deref(), printer).await
        }
    }
}

/// Run `gh` in the registry directory.
fn gh(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("gh")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running gh {} in {}", args.join(" "), dir.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gh {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[allow(clippy::too_many_arguments)]
async fn pr_create(
    config: &ApmConfig,
    title: Option<&str>,
    body: Option<&str>,
    base: Option<&str>,
    draft: bool,
    reviewers: &[String],
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["pr", "create"];
    let title_str;
    if let Some(t) = title {
        title_str = t.to_string();
        args.push("--title");
        args.push(&title_str);
    }
    let body_str;
    if let Some(b) = body {
        body_str = b.to_string();
        args.push("--body");
        args.push(&body_str);
    }
    let base_str;
    if let Some(b) = base {
        base_str = b.to_string();
        args.push("--base");
        args.push(&base_str);
    }
    if draft {
        args.push("--draft");
    }
    let reviewer_strs: Vec<String> = reviewers.to_vec();
    for r in &reviewer_strs {
        args.push("--reviewer");
        args.push(r);
    }

    let output = gh(&dir, &args)?;
    printer.plain(&output);

    Ok(())
}

async fn pr_list(
    config: &ApmConfig,
    author: Option<&str>,
    mine: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["pr", "list"];
    let author_str;
    if mine {
        args.push("--author");
        args.push("@me");
    } else if let Some(a) = author {
        author_str = a.to_string();
        args.push("--author");
        args.push(&author_str);
    }

    let output = gh(&dir, &args)?;
    printer.plain(&output);

    Ok(())
}

async fn pr_show(
    config: &ApmConfig,
    number: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let n_str = number.to_string();
    let output = gh(&dir, &["pr", "view", &n_str])?;
    printer.plain(&output);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn pr_merge(
    config: &ApmConfig,
    number: u32,
    squash: bool,
    rebase: bool,
    merge: bool,
    delete_branch: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let n_str = number.to_string();
    let mut args = vec!["pr", "merge", &n_str];
    if squash {
        args.push("--squash");
    } else if rebase {
        args.push("--rebase");
    } else if merge {
        args.push("--merge");
    }
    if delete_branch {
        args.push("--delete-branch");
    }

    let output = gh(&dir, &args)?;
    printer.plain(&output);
    printer.success(&format!("PR #{number} merged."));

    Ok(())
}

async fn pr_diff(
    config: &ApmConfig,
    number: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let n_str = number.to_string();
    let output = gh(&dir, &["pr", "diff", &n_str])?;
    printer.plain(&output);
    Ok(())
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

/// `apr tag <NAME>`
pub async fn tag(
    config: &ApmConfig,
    name: &str,
    message: Option<&str>,
    key: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let signing_key = key.ok_or_else(|| {
        anyhow::anyhow!("--key is required: registry release tags must be signed tag objects")
    })?;

    sign_tag(
        &dir,
        name,
        "HEAD",
        message.or(Some("AOS registry release")),
        signing_key,
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
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let tag_name = tag.ok_or_else(|| {
        anyhow::anyhow!("`apr sign` now signs tag objects; pass the existing tag name to re-sign")
    })?;
    let signing_key = key.ok_or_else(|| {
        anyhow::anyhow!("--key is required: registry release tags must be signed tag objects")
    })?;
    let target = git(&dir, &["rev-list", "-n", "1", tag_name])
        .with_context(|| format!("resolving tag '{tag_name}' target commit"))?;

    sign_tag(
        &dir,
        tag_name,
        &target,
        Some("AOS registry release"),
        signing_key,
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

/// Sign an annotated tag object with OpenSSH SSHSIG data.
fn sign_tag(
    dir: &Path,
    tag_name: &str,
    target: &str,
    message: Option<&str>,
    signing_key: &str,
    force: bool,
) -> Result<()> {
    let message = message.unwrap_or("AOS registry release");
    let repo = crate::git_support::open(dir)?;
    crate::git_support::sign_tag(
        &repo,
        tag_name,
        target,
        message,
        Path::new(signing_key),
        force,
    )
    .with_context(|| format!("signing tag '{tag_name}' in {}", dir.display()))?;
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
        )
        .unwrap();
        assert!(content.contains("name = \"curl\""));
        assert!(content.contains("version = \"8.5.0\""));
        assert!(content.contains("x86_64-linux"));
        assert!(content.contains("sha256:deadbeef"));
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
        )
        .unwrap();
        assert!(content.contains("sysroot = true"));
        assert!(content.contains("previous = \"2026.03\""));
        assert!(content.contains("format = \"raw\""));
        assert!(content.contains("sha256:ccdd"));
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
        assert_eq!(format_size(3_300_000), "3.1 MiB");
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }
}
