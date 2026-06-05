//! Native git/dumb-HTTP transport for registry sync.
//!
//! Used when a registry is configured with `git://`, `git+https://`, or
//! `git+ssh://` URL schemes. Runs `git fetch` directly against a git server,
//! verifies commit signatures and fast-forward constraints, and extracts
//! package TOML files into the local registry cache.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::download::join_cache_url;
use crate::registry::{channel, fetch, verify};
use crate::types::{RegistryConfig, RegistryState, SigningConfig, TrackingMode};
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a git transport sync operation.
#[derive(Debug)]
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Number of new packages added.
    pub packages_added: usize,
    /// Number of packages with updated metadata.
    pub packages_updated: usize,
    /// Number of packages removed.
    pub packages_removed: usize,
}

const MIN_SHA256_GIT_VERSION: GitVersion = GitVersion {
    major: 2,
    minor: 42,
    patch: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct GitVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl std::fmt::Display for GitVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Main sync flow
// ---------------------------------------------------------------------------

/// Sync a git-transport registry.
///
/// Full flow:
/// 1. Ensure local bare git repo exists
/// 2. Fetch refs (tag pin, branch tracking, or default)
/// 3. Verify commit signature if required
/// 4. Enforce fast-forward from last known commit
/// 5. Extract package TOML files into the cache directory
pub async fn sync_git(
    config: &RegistryConfig,
    tracking_mode: &TrackingMode,
    cache_dir: &Path,
    registries_dir: &Path,
    state: &mut RegistryState,
    printer: &Printer,
) -> Result<SyncResult> {
    let git_url = normalize_git_url(&config.url);
    let repo_dir = cache_dir.join(&config.name).join("repo.git");

    // Step 1: Ensure repo.
    printer.info(&format!("Syncing registry '{}' via git...", config.name));
    ensure_sha256_capable_git().await?;
    ensure_repo(&repo_dir, &git_url).await?;
    let mut retained_before = fetch::parse_retained(&state.retained)?;
    if let Some(floor) = state.floor.as_deref() {
        let floor = semver::Version::parse(floor)
            .with_context(|| format!("parsing registry semver floor {floor}"))?;
        if !retained_before.contains(&floor) {
            retained_before.push(floor);
        }
    }

    // Step 2: Fetch refs.
    fetch_refs(&repo_dir, &git_url, tracking_mode).await?;

    // Step 3: Determine the new HEAD commit.
    let new_commit = if let TrackingMode::Channel(channel_name) = tracking_mode {
        resolve_channel_head(config, &git_url, channel_name, &repo_dir, state).await?
    } else {
        resolve_fetch_head(&repo_dir, tracking_mode).await?
    };

    if matches!(tracking_mode, TrackingMode::Channel(_)) {
        let target = state
            .floor
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("channel resolution did not persist a semver floor"))?;
        let target = semver::Version::parse(target)
            .with_context(|| format!("parsing resolved channel release {target}"))?;
        fetch::resolve_objects(&repo_dir, &git_url, &target, &retained_before, printer).await?;
    }

    // Step 4: Verify commit signature if signing.required.
    if let Some(ref signing) = config.signing {
        if signing.required && !matches!(tracking_mode, TrackingMode::Channel(_)) {
            verify_commit_signature(&repo_dir, &new_commit, signing).await?;
        }
    }

    // Step 5: Enforce fast-forward.
    if let Some(ref old_commit) = state.last_commit {
        enforce_fast_forward(&repo_dir, old_commit, &new_commit).await?;
    }

    // Step 6: Extract packages into the cache.
    let output_dir = cache_dir.join(&config.name).join("packages");
    let old_packages = count_toml_files(&output_dir).await;
    extract_packages(&repo_dir, &new_commit, &output_dir).await?;
    let new_packages = count_toml_files(&output_dir).await;

    // Step 6b: Materialise registry.toml from the repo root so resolve_mirror
    // can find the [[caches]] entries. Without this, the only fallback is
    // the registry URL itself, which fails for git:// transports.
    let registry_toml_target = registries_dir.join(&config.name);
    extract_registry_root(&repo_dir, &new_commit, &registry_toml_target).await?;

    // Compute rough stats. Without a detailed diff we approximate:
    // - If this is the first sync, everything is "added"
    // - Otherwise, we report the delta
    let (added, updated, removed) = if state.last_commit.is_none() {
        (new_packages, 0, 0)
    } else {
        let added = new_packages.saturating_sub(old_packages);
        let removed = old_packages.saturating_sub(new_packages);
        let common = new_packages.min(old_packages);
        // Approximate: if the commit changed, assume some packages were updated
        let updated = if state.last_commit.as_deref() == Some(&new_commit) {
            0
        } else {
            common
        };
        (added, updated, removed)
    };

    // Update state.
    if let Some(version) = state.floor.as_deref() {
        let version = semver::Version::parse(version)
            .with_context(|| format!("parsing retained target release {version}"))?;
        state.retained = fetch::retained_set(&version)
            .into_iter()
            .map(|version| version.to_string())
            .collect();
    }
    prune_unretained_release_dirs(&repo_dir, &state.retained).await?;
    state.last_commit = Some(new_commit.clone());
    state.last_update = Some(chrono_now());

    printer.info(&format!(
        "Registry '{}': {} packages ({} added, {} updated, {} removed)",
        config.name, new_packages, added, updated, removed,
    ));

    Ok(SyncResult {
        new_commit,
        packages_added: added,
        packages_updated: updated,
        packages_removed: removed,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Normalize a git URL by stripping the `git+` prefix if present.
///
/// `git+https://...` -> `https://...`
/// `git+ssh://...` -> `ssh://...`
/// `http(s)://...` -> unchanged for dumb HTTP.
/// `git://...` -> `git://...` (unchanged)
fn normalize_git_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("git+") {
        rest.to_string()
    } else {
        url.to_string()
    }
}

async fn ensure_sha256_capable_git() -> Result<()> {
    let version_output = Command::new("git")
        .arg("--version")
        .output()
        .await
        .context("running git --version")?;
    if !version_output.status.success() {
        bail!(
            "this registry requires a sha256-capable git {MIN_SHA256_GIT_VERSION} or newer; \
             git --version failed: {}",
            String::from_utf8_lossy(&version_output.stderr).trim(),
        );
    }

    let version_text = String::from_utf8_lossy(&version_output.stdout);
    let version = parse_git_version(&version_text).ok_or_else(|| {
        anyhow::anyhow!(
            "this registry requires a sha256-capable git {MIN_SHA256_GIT_VERSION} or newer; \
             could not parse `git --version` output '{}'",
            version_text.trim(),
        )
    })?;
    if version < MIN_SHA256_GIT_VERSION {
        bail!(
            "this registry requires a sha256-capable git {MIN_SHA256_GIT_VERSION} or newer; \
             found {} from `git --version`. Upgrade git before syncing sha256 dumb-HTTP registries.",
            version_text.trim(),
        );
    }

    let tmp = tempfile::TempDir::new().context("creating temporary git capability probe repo")?;
    let output = Command::new("git")
        .args(["init", "--bare", "--object-format=sha256"])
        .arg(tmp.path())
        .output()
        .await
        .context("running git sha256 capability probe")?;
    if !output.status.success() {
        bail!(
            "this registry requires a sha256-capable git {MIN_SHA256_GIT_VERSION} or newer; \
             {} cannot run `git init --bare --object-format=sha256`: {}",
            version_text.trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    Ok(())
}

fn parse_git_version(output: &str) -> Option<GitVersion> {
    let token = output
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = token.split('.');
    let major = parse_leading_u32(parts.next()?)?;
    let minor = parts.next().and_then(parse_leading_u32).unwrap_or(0);
    let patch = parts.next().and_then(parse_leading_u32).unwrap_or(0);
    Some(GitVersion {
        major,
        minor,
        patch,
    })
}

fn parse_leading_u32(part: &str) -> Option<u32> {
    let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Initialize a bare git repo at `repo_dir` if it does not already exist.
async fn ensure_repo(repo_dir: &Path, _url: &str) -> Result<()> {
    if repo_dir.join("HEAD").exists() {
        return Ok(());
    }

    tokio::fs::create_dir_all(repo_dir)
        .await
        .with_context(|| format!("creating {}", repo_dir.display()))?;

    let output = Command::new("git")
        .args(["init", "--bare", "--object-format=sha256"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("running git init --bare --object-format=sha256")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git init --bare --object-format=sha256 failed: {}",
            stderr.trim()
        );
    }

    Ok(())
}

/// Run `git fetch` with the appropriate refspec based on tracking mode.
async fn fetch_refs(repo_dir: &Path, url: &str, tracking_mode: &TrackingMode) -> Result<()> {
    let mut args = vec!["fetch".to_string(), url.to_string()];

    match tracking_mode {
        TrackingMode::Commit(hash) => {
            // Fetch the specific commit.
            args.push(hash.clone());
        }
        TrackingMode::Branch(branch) => {
            // Fetch the branch.
            args.push(format!("refs/heads/{branch}:refs/remotes/origin/{branch}"));
        }
        TrackingMode::Channel(channel) => {
            args.push(format!(
                "refs/heads/{channel}:refs/remotes/origin/{channel}"
            ));
            args.push("refs/tags/*:refs/tags/*".to_string());
        }
        TrackingMode::Tag(tag) => {
            // Fetch the specific tag.
            args.push(format!("refs/tags/{tag}:refs/tags/{tag}"));
        }
        TrackingMode::Version(_) => {
            // Need all tags to do semver matching.
            args.push("refs/tags/*:refs/tags/*".to_string());
        }
        TrackingMode::Default => {
            // Fetch all tags.
            args.push("refs/tags/*:refs/tags/*".to_string());
        }
    }

    // Add --force to allow tag updates.
    args.push("--force".to_string());

    let output = Command::new("git")
        .args(&args)
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git fetch against {url}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git fetch failed: {}", stderr.trim());
    }

    Ok(())
}

/// Resolve the commit SHA to use after fetching.
async fn resolve_fetch_head(repo_dir: &Path, tracking_mode: &TrackingMode) -> Result<String> {
    let ref_to_resolve = match tracking_mode {
        TrackingMode::Commit(hash) => {
            // Already a commit hash.
            return Ok(hash.clone());
        }
        TrackingMode::Branch(branch) | TrackingMode::Channel(branch) => {
            format!("refs/remotes/origin/{branch}")
        }
        TrackingMode::Tag(tag) => {
            format!("refs/tags/{tag}")
        }
        TrackingMode::Version(req) => {
            // List all tags, parse as semver, pick the best match.
            return resolve_best_version_tag(repo_dir, req).await;
        }
        TrackingMode::Default => {
            // Find the latest tag by listing all tags and picking the last one
            // (lexicographically, which works for our YYYY.MM.patch format).
            return resolve_latest_tag(repo_dir).await;
        }
    };

    let output = Command::new("git")
        .args(["rev-parse", &ref_to_resolve])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving ref {ref_to_resolve}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse {} failed: {}", ref_to_resolve, stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn resolve_channel_head(
    config: &RegistryConfig,
    base_url: &str,
    channel_name: &str,
    repo_dir: &Path,
    state: &mut RegistryState,
) -> Result<String> {
    let signing_key = config
        .signing
        .as_ref()
        .map(|signing| signing.public_key.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "channel tracking for '{}' requires a trusted signing.public_key",
                config.name,
            )
        })?;
    let release_tags = semver_tag_object_map(repo_dir).await?;
    let assigned_bucket = match state.bucket {
        Some(bucket) => bucket,
        None => channel::select_registry_bucket(&config.name, &channel::generate_bucket_salt()),
    };

    let mut last_error = None;
    for bucket in channel::probe_order(assigned_bucket) {
        match fetch_and_verify_partition(
            base_url,
            channel_name,
            bucket,
            repo_dir,
            signing_key,
            &release_tags,
        )
        .await
        {
            Ok(Some(resolved)) => {
                let floor = state
                    .floor
                    .as_deref()
                    .map(semver::Version::parse)
                    .transpose()
                    .context("parsing registry semver floor")?;
                channel::check_floor(floor.as_ref(), &resolved.semver)?;

                state.bucket.get_or_insert(assigned_bucket);
                state.floor = Some(resolved.semver.to_string());
                return Ok(resolved.commit);
            }
            Ok(None) => {}
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    if let Some(err) = last_error {
        bail!("channel '{channel_name}' has no usable partition: {err}");
    }
    bail!("channel '{channel_name}' has no usable partition")
}

async fn fetch_and_verify_partition(
    base_url: &str,
    channel_name: &str,
    bucket: u8,
    repo_dir: &Path,
    signing_key: &str,
    release_tags: &BTreeMap<String, semver::Version>,
) -> Result<Option<verify::VerifiedRelease>> {
    let url = join_cache_url(base_url, &channel::partition_path(channel_name, bucket));
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("fetching channel partition {url}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("GET {url} failed with {}", response.status());
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("reading channel partition {url}"))?;
    let content = String::from_utf8_lossy(&bytes);
    let tag = verify::parse_tag_object(&content)
        .with_context(|| format!("parsing channel partition {url}"))?;
    verify::verify_name_binding(&tag, channel_name)?;
    if tag.target_type != verify::TagTarget::Tag {
        bail!(
            "channel partition {url} targets {:?}, expected tag",
            tag.target_type,
        );
    }
    let Some(release) = release_tags.get(&tag.object) else {
        return Ok(None);
    };

    let channel_oid = hash_tag_object(repo_dir, &bytes)?;
    verify::verify_tag_chain(
        repo_dir,
        &channel_oid,
        channel_name,
        &release.to_string(),
        signing_key,
    )
    .map(Some)
}

fn hash_tag_object(repo_dir: &Path, bytes: &[u8]) -> Result<String> {
    let mut child = std::process::Command::new("git")
        .args(["hash-object", "-w", "-t", "tag", "--stdin"])
        .current_dir(repo_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git hash-object for channel tag")?;
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(bytes)
        .context("writing channel tag to git hash-object")?;
    let output = child
        .wait_with_output()
        .context("waiting for git hash-object")?;
    if !output.status.success() {
        bail!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn semver_tag_object_map(repo_dir: &Path) -> Result<BTreeMap<String, semver::Version>> {
    let output = Command::new("git")
        .args(["tag", "-l"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("listing tags for channel resolution")?;
    if !output.status.success() {
        bail!(
            "git tag -l failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    let mut map = BTreeMap::new();
    for tag in String::from_utf8_lossy(&output.stdout).lines() {
        let tag = tag.trim();
        let Ok(version) = semver::Version::parse(tag) else {
            continue;
        };
        let oid = resolve_tag_object(repo_dir, tag).await?;
        map.insert(oid, version);
    }
    Ok(map)
}

async fn resolve_tag_object(repo_dir: &Path, tag: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", &format!("{tag}^{{tag}}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving tag object for {tag}"))?;
    if !output.status.success() {
        bail!(
            "git rev-parse {tag}^{{tag}} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn prune_unretained_release_dirs(repo_dir: &Path, retained: &[String]) -> Result<()> {
    let releases = repo_dir.join("releases");
    if !releases.exists() {
        return Ok(());
    }
    let retained: std::collections::HashSet<_> = retained.iter().cloned().collect();
    let mut major_dirs = tokio::fs::read_dir(&releases)
        .await
        .with_context(|| format!("reading {}", releases.display()))?;
    while let Some(major) = major_dirs.next_entry().await? {
        if !major.file_type().await?.is_dir() {
            continue;
        }
        let mut minor_dirs = tokio::fs::read_dir(major.path()).await?;
        while let Some(minor) = minor_dirs.next_entry().await? {
            if !minor.file_type().await?.is_dir() {
                continue;
            }
            let mut patch_dirs = tokio::fs::read_dir(minor.path()).await?;
            while let Some(patch) = patch_dirs.next_entry().await? {
                if !patch.file_type().await?.is_dir() {
                    continue;
                }
                let version = format!(
                    "{}.{}.{}",
                    major.file_name().to_string_lossy(),
                    minor.file_name().to_string_lossy(),
                    patch.file_name().to_string_lossy(),
                );
                if !retained.contains(&version) {
                    tokio::fs::remove_dir_all(patch.path())
                        .await
                        .with_context(|| format!("removing {}", patch.path().display()))?;
                }
            }
        }
    }
    Ok(())
}

/// Find the latest tag in the repo (by version sort).
async fn resolve_latest_tag(repo_dir: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["tag", "--sort=-version:refname"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("listing tags")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git tag failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let latest = stdout
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no tags found in registry"))?;

    let output = Command::new("git")
        .args(["rev-parse", &format!("refs/tags/{latest}")])
        .current_dir(repo_dir)
        .output()
        .await?;

    if !output.status.success() {
        bail!("git rev-parse refs/tags/{latest} failed");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Find the best tag matching a semver constraint.
///
/// Lists all tags in the repo, parses each as semver (stripping `v` prefix),
/// filters by the constraint, and resolves the latest matching tag's commit.
async fn resolve_best_version_tag(repo_dir: &Path, req: &semver::VersionReq) -> Result<String> {
    let output = Command::new("git")
        .args(["tag", "-l"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("listing tags for version matching")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git tag -l failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut best: Option<(semver::Version, String)> = None;

    for tag in stdout.lines() {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        if let Some(ver) = parse_tag_as_semver(tag) {
            if req.matches(&ver) {
                match &best {
                    Some((best_ver, _)) if ver > *best_ver => {
                        best = Some((ver, tag.to_string()));
                    }
                    None => {
                        best = Some((ver, tag.to_string()));
                    }
                    _ => {}
                }
            }
        }
    }

    let (_, best_tag) = best.ok_or_else(|| {
        anyhow::anyhow!(
            "no tags matching version constraint '{}' found in registry",
            req,
        )
    })?;

    // Resolve tag to commit.
    let output = Command::new("git")
        .args(["rev-parse", &format!("refs/tags/{best_tag}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving tag {best_tag}"))?;

    if !output.status.success() {
        bail!("git rev-parse refs/tags/{best_tag} failed");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Parse a tag string as a semver `Version`, stripping a leading `v` prefix,
/// removing leading zeros from components (e.g. `02` -> `2`), and appending
/// `.0` for two-component versions like `2026.02`.
fn parse_tag_as_semver(tag: &str) -> Option<semver::Version> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = stripped.split('.').collect();
    let normalized: Vec<String> = parts
        .iter()
        .map(|p| {
            p.parse::<u64>()
                .map(|n| n.to_string())
                .unwrap_or_else(|_| p.to_string())
        })
        .collect();

    let semver_str = if normalized.len() == 2 {
        format!("{}.{}.0", normalized[0], normalized[1])
    } else if normalized.len() == 3 {
        format!("{}.{}.{}", normalized[0], normalized[1], normalized[2])
    } else {
        return None;
    };

    semver::Version::parse(&semver_str).ok()
}

/// Verify the commit signature using `git verify-commit`.
///
/// This checks that the commit was signed and that the signature is valid.
/// The actual key verification depends on the user's git configuration
/// (gpg.ssh.allowedSignersFile or gpg keyring).
async fn verify_commit_signature(
    repo_dir: &Path,
    commit: &str,
    _signing: &SigningConfig,
) -> Result<()> {
    let output = Command::new("git")
        .args(["verify-commit", commit])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git verify-commit {commit}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "commit signature verification failed for {commit}:\n{}\n\n\
             The registry requires signed commits (signing.required = true).\n\
             Ensure the registry maintainer's public key is trusted.",
            stderr.trim(),
        );
    }

    Ok(())
}

/// Enforce that `new_commit` is a descendant of `old_commit` (fast-forward).
///
/// Uses `git merge-base --is-ancestor` to check the relationship.
async fn enforce_fast_forward(repo_dir: &Path, old_commit: &str, new_commit: &str) -> Result<()> {
    if old_commit == new_commit {
        return Ok(());
    }

    let output = Command::new("git")
        .args(["merge-base", "--is-ancestor", old_commit, new_commit])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| {
            format!("running git merge-base --is-ancestor {old_commit} {new_commit}")
        })?;

    if !output.status.success() {
        bail!(
            "registry downgrade detected: commit {new_commit} is not a \
             descendant of previously verified commit {old_commit}.\n\n\
             This could indicate a downgrade attack or a force-pushed \
             registry. If you trust this change, delete the registry state \
             and run `apm update` again.",
        );
    }

    Ok(())
}

/// Extract package TOML files from a git tree into the output directory.
///
/// Uses `git archive` to export the `packages/` directory from the commit
/// and extract it into the output directory.
async fn extract_packages(repo_dir: &Path, commit: &str, output_dir: &Path) -> Result<()> {
    // Clean the output directory first.
    if output_dir.exists() {
        tokio::fs::remove_dir_all(output_dir)
            .await
            .with_context(|| format!("cleaning {}", output_dir.display()))?;
    }
    tokio::fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("creating {}", output_dir.display()))?;

    // Use `git archive` to produce a tar, then pipe through `tar -x`.
    // We use std::process for pipe support (tokio's ChildStdout doesn't
    // directly convert to Stdio for a second process).
    let archive = std::process::Command::new("git")
        .args(["archive", commit, "packages/"])
        .current_dir(repo_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running git archive {commit} packages/"))?;

    let tar = std::process::Command::new("tar")
        .args([
            "-x",
            "--strip-components=1",
            "-C",
            &output_dir.to_string_lossy(),
        ])
        .stdin(archive.stdout.unwrap())
        .output()
        .context("running tar to extract packages")?;

    if !tar.status.success() {
        let stderr = String::from_utf8_lossy(&tar.stderr);
        bail!(
            "failed to extract packages from commit {commit}: {}",
            stderr.trim(),
        );
    }

    Ok(())
}

/// Extract the repo-root `registry.toml` into `target_dir/registry.toml`.
///
/// Missing-file errors are non-fatal: `apm install` falls back to the
/// registry URL when no cache config is present. Other git errors bubble up.
pub async fn extract_registry_root(repo_dir: &Path, commit: &str, target_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(target_dir)
        .await
        .with_context(|| format!("creating {}", target_dir.display()))?;

    let output = Command::new("git")
        .args(["show", &format!("{commit}:registry.toml")])
        .current_dir(repo_dir)
        .output()
        .await
        .context("running git show :registry.toml")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Missing root registry.toml is fine — resolve_mirror falls back to
        // the registry URL. Any other failure (corrupt object, IO error)
        // bubbles up.
        if stderr.contains("does not exist")
            || stderr.contains("exists on disk, but not in")
            || stderr.contains("path 'registry.toml'")
        {
            return Ok(());
        }
        bail!("git show {commit}:registry.toml failed: {}", stderr.trim(),);
    }

    let dest = target_dir.join("registry.toml");
    tokio::fs::write(&dest, &output.stdout)
        .await
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

/// Count .toml files in a packages directory.
async fn count_toml_files(dir: &Path) -> usize {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return 0;
    };

    let mut count = 0;
    while let Ok(Some(letter_entry)) = entries.next_entry().await {
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }
        let Ok(mut sub) = tokio::fs::read_dir(&letter_path).await else {
            continue;
        };
        while let Ok(Some(entry)) = sub.next_entry().await {
            if entry
                .path()
                .extension()
                .map(|e| e == "toml")
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

/// Return the current timestamp in ISO 8601 format.
///
/// Uses a simple implementation to avoid pulling in the `chrono` crate.
fn chrono_now() -> String {
    // Format: 2026-02-16T10:30:00Z
    // We use std::time::SystemTime and manually format.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Simple UTC formatting (no leap seconds, good enough for timestamps).
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to year/month/day.
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil date from day count algorithm (Rata Die variant).
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `git` command for fixture setup with the developer's global
    /// and system config neutralized, so tests don't inherit `~/.gitconfig`
    /// settings (gpg signing, hooks, templates, etc.). Repo-local identity is
    /// still set explicitly by each test via `git config`.
    fn git(dir: &Path) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        cmd
    }

    #[test]
    fn normalize_git_plus_https() {
        assert_eq!(
            normalize_git_url("git+https://github.com/andyl/registry.git"),
            "https://github.com/andyl/registry.git"
        );
    }

    #[test]
    fn normalize_git_plus_ssh() {
        assert_eq!(
            normalize_git_url("git+ssh://git@github.com/andyl/registry.git"),
            "ssh://git@github.com/andyl/registry.git"
        );
    }

    #[test]
    fn normalize_git_native() {
        assert_eq!(
            normalize_git_url("git://github.com/andyl/registry.git"),
            "git://github.com/andyl/registry.git"
        );
    }

    #[test]
    fn parse_git_version_handles_common_formats() {
        assert_eq!(
            parse_git_version("git version 2.42.0\n"),
            Some(GitVersion {
                major: 2,
                minor: 42,
                patch: 0,
            })
        );
        assert_eq!(
            parse_git_version("git version 2.43.1 (Apple Git-155)\n"),
            Some(GitVersion {
                major: 2,
                minor: 43,
                patch: 1,
            })
        );
        assert_eq!(
            parse_git_version("git version 2.42.0.windows.1\n"),
            Some(GitVersion {
                major: 2,
                minor: 42,
                patch: 0,
            })
        );
    }

    #[test]
    fn sha256_git_floor_is_git_2_42_0() {
        let below = parse_git_version("git version 2.41.3").unwrap();
        let floor = parse_git_version("git version 2.42.0").unwrap();
        let above = parse_git_version("git version 2.43.0").unwrap();

        assert!(below < MIN_SHA256_GIT_VERSION);
        assert_eq!(floor, MIN_SHA256_GIT_VERSION);
        assert!(above > MIN_SHA256_GIT_VERSION);
    }

    #[test]
    fn parse_git_version_rejects_unexpected_output() {
        assert_eq!(parse_git_version("not git"), None);
        assert_eq!(parse_git_version("git version vendor-build"), None);
    }

    #[test]
    fn chrono_now_format() {
        let now = chrono_now();
        // Should match ISO 8601 pattern: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(now.len(), 20);
        assert!(now.ends_with('Z'));
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[7..8], "-");
        assert_eq!(&now[10..11], "T");
        assert_eq!(&now[13..14], ":");
        assert_eq!(&now[16..17], ":");
    }

    #[test]
    fn days_to_ymd_epoch() {
        // Unix epoch: 1970-01-01
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2026-02-16 is day 20500 since epoch (approx).
        // Let's verify a well-known date: 2000-01-01 = day 10957.
        let (y, m, d) = days_to_ymd(10957);
        assert_eq!((y, m, d), (2000, 1, 1));
    }

    #[test]
    fn days_to_ymd_leap_year() {
        // 2024-02-29 is a leap day. Day 19782 from epoch.
        // 2024-01-01 = day 19723 from epoch.
        // Feb 29 = day 19723 + 31 (Jan) + 28 (Feb 1-28) = 19723 + 59 = 19782
        let (y, m, d) = days_to_ymd(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[tokio::test]
    async fn ensure_repo_creates_bare_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("test.git");

        ensure_repo(&repo_dir, "https://example.com").await.unwrap();

        // HEAD file should exist in a bare repo.
        assert!(repo_dir.join("HEAD").exists());

        // Calling again should be a no-op.
        ensure_repo(&repo_dir, "https://example.com").await.unwrap();
        assert!(repo_dir.join("HEAD").exists());
    }

    #[tokio::test]
    async fn enforce_fast_forward_same_commit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("test.git");
        ensure_repo(&repo_dir, "https://example.com").await.unwrap();

        // Same commit should always pass.
        let result = enforce_fast_forward(&repo_dir, "abc123", "abc123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn count_toml_files_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let count = count_toml_files(tmp.path()).await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn count_toml_files_with_packages() {
        let tmp = tempfile::TempDir::new().unwrap();
        let c_dir = tmp.path().join("c");
        tokio::fs::create_dir_all(&c_dir).await.unwrap();
        tokio::fs::write(c_dir.join("curl.toml"), "test")
            .await
            .unwrap();
        tokio::fs::write(c_dir.join("coreutils.toml"), "test")
            .await
            .unwrap();

        let z_dir = tmp.path().join("z");
        tokio::fs::create_dir_all(&z_dir).await.unwrap();
        tokio::fs::write(z_dir.join("zlib.toml"), "test")
            .await
            .unwrap();

        let count = count_toml_files(tmp.path()).await;
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn extract_packages_from_real_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("registry.git");

        // Create a non-bare repo, add some package files, commit, then
        // test extraction.
        let work_dir = tmp.path().join("work");
        tokio::fs::create_dir_all(&work_dir).await.unwrap();

        // Init a regular repo.
        let output = git(&work_dir).args(["init"]).output().await.unwrap();
        assert!(output.status.success());

        // Configure git user for commit.
        let _ = git(&work_dir)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .await;
        let _ = git(&work_dir)
            .args(["config", "user.name", "Test"])
            .output()
            .await;

        // Create package files.
        let pkg_dir = work_dir.join("packages").join("c");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("curl.toml"), "[package]\nname = \"curl\"\n")
            .await
            .unwrap();

        // Add and commit.
        let _ = git(&work_dir).args(["add", "."]).output().await;
        let _ = git(&work_dir)
            .args(["commit", "-m", "initial"])
            .output()
            .await;

        // Clone as bare repo.
        let output = git(&work_dir)
            .args([
                "clone",
                "--bare",
                &work_dir.to_string_lossy(),
                &repo_dir.to_string_lossy(),
            ])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());

        // Get the commit SHA.
        let output = git(&repo_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .await
            .unwrap();
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Extract into output directory.
        let output_dir = tmp.path().join("extracted");
        extract_packages(&repo_dir, &commit, &output_dir)
            .await
            .unwrap();

        // Verify extracted files.
        assert!(output_dir.join("c").join("curl.toml").exists());
        let content = tokio::fs::read_to_string(output_dir.join("c").join("curl.toml"))
            .await
            .unwrap();
        assert!(content.contains("curl"));
    }

    #[tokio::test]
    async fn fast_forward_with_real_commits() {
        let tmp = tempfile::TempDir::new().unwrap();
        let work_dir = tmp.path().join("work");
        tokio::fs::create_dir_all(&work_dir).await.unwrap();

        // Init repo.
        let _ = git(&work_dir).args(["init"]).output().await.unwrap();
        let _ = git(&work_dir)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .await;
        let _ = git(&work_dir)
            .args(["config", "user.name", "Test"])
            .output()
            .await;

        // First commit.
        tokio::fs::write(work_dir.join("a.txt"), "a").await.unwrap();
        let _ = git(&work_dir).args(["add", "."]).output().await;
        let _ = git(&work_dir)
            .args(["commit", "-m", "first"])
            .output()
            .await;

        let output = git(&work_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .await
            .unwrap();
        let commit1 = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Second commit.
        tokio::fs::write(work_dir.join("b.txt"), "b").await.unwrap();
        let _ = git(&work_dir).args(["add", "."]).output().await;
        let _ = git(&work_dir)
            .args(["commit", "-m", "second"])
            .output()
            .await;

        let output = git(&work_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .await
            .unwrap();
        let commit2 = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Fast-forward: commit1 -> commit2 should pass.
        enforce_fast_forward(&work_dir, &commit1, &commit2)
            .await
            .unwrap();

        // Reverse: commit2 -> commit1 should fail (downgrade).
        let result = enforce_fast_forward(&work_dir, &commit2, &commit1).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("downgrade"), "got: {err}");
    }
}
