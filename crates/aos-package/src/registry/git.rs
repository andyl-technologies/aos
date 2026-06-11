//! Native git/dumb-HTTP transport for registry sync.
//!
//! Used when a registry is configured with `git://`, `git+https://`, or
//! `git+ssh://` URL schemes. Runs `git fetch` directly against a git server,
//! verifies commit signatures and fast-forward constraints, and extracts
//! package TOML files into the local registry cache.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};

use crate::download::join_cache_url;
use crate::gitcmd;
use crate::registry::{channel, fetch, keys, verify};
use crate::security::{self, KeyStore, KeySyncReport, TrustedKey, key_fingerprint};
use crate::types::{RegistryConfig, RegistryState, TrackingMode};
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a git transport sync operation.
#[derive(Debug)]
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Total number of packages in the registry after sync.
    pub packages_count: usize,
    /// Number of new packages added.
    pub packages_added: usize,
    /// Number of packages with updated metadata.
    pub packages_updated: usize,
    /// Number of packages removed.
    pub packages_removed: usize,
}

struct ResolvedHead {
    commit: String,
    release_tag: Option<String>,
}

const MIN_SHA256_GIT_VERSION: GitVersion = GitVersion {
    major: 2,
    minor: 42,
    patch: 0,
};

const DEFAULT_CHANNEL_MAX_STALENESS_SECONDS: u64 = 14 * 24 * 60 * 60;

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
/// 1. Ensure local bare git repo exists; assemble the trusted key set
/// 2. Fetch refs (tag pin, branch tracking, channel data, or default)
/// 3. Verify and fast-forward the current roster head
/// 4. Pin the roster's `keys.toml` into the writable trusted-key store
/// 5. Resolve and verify the selected release commit/tag/channel against
///    the post-roster trusted set
/// 6. Enforce fast-forward from last known selected commit
/// 7. Extract package TOML files into the cache directory
///
/// Verification is fail-closed: a registry config without a
/// `[registry.signing]` section enforces signatures, and only an explicit
/// `required = false` opts out. Roster changes are accepted only when
/// delivered as a fast-forward in a head commit signed by an
/// already-trusted key, which gives in-band key rotation its continuity
/// guarantee.
pub async fn sync_git(
    config: &RegistryConfig,
    tracking_mode: &TrackingMode,
    cache_dir: &Path,
    registries_dir: &Path,
    trusted_keys_dirs: &[PathBuf],
    state: &mut RegistryState,
    printer: &Printer,
) -> Result<SyncResult> {
    let git_url = normalize_git_url(&config.url);
    let repo_dir = cache_dir.join(&config.name).join("repo.git");

    // Step 1: Ensure repo; assemble the trusted key set.
    printer.info(&format!("Syncing registry '{}' via git...", config.name));
    let key_store = KeyStore::new(trusted_keys_dirs.to_vec());
    let enforcing = signing_enforced(config);
    let trusted_keys = assemble_trusted_set(&key_store, config);
    if enforcing && trusted_keys.is_empty() {
        bail!(
            "registry '{}' requires signed metadata but no trusted key is available.\n\
             Pin a maintainer key with `apr trust pin {} <{}:Ed25519:base64key>`, or set\n\
             [registry.signing] public_key in the registry config.\n\
             (Setting [registry.signing] required = false disables verification.)",
            config.name,
            config.name,
            config.name,
        );
    }
    ensure_sha256_capable_git().await?;
    if is_plain_http_url(&config.url) {
        preflight_git_native_http_origin(&git_url).await?;
    }
    ensure_repo(&repo_dir, &git_url).await?;
    let previous_floor = state.floor.clone();
    let mut retained_before = fetch::parse_retained(&state.retained)?;
    if let Some(floor) = state.floor.as_deref() {
        let floor = semver::Version::parse(floor)
            .with_context(|| format!("parsing registry semver floor {floor}"))?;
        if !retained_before.contains(&floor) {
            retained_before.push(floor);
        }
    }

    // Step 2: Fetch refs.
    let fetch_roster_head = enforcing && uses_remote_head_roster(tracking_mode);
    let fetched_roster_head = if matches!(tracking_mode, TrackingMode::Channel(_)) {
        match fetch_refs(&repo_dir, &git_url, tracking_mode, fetch_roster_head).await {
            Ok(fetched_roster_head) => fetched_roster_head,
            Err(err) => {
                return Err(channel_refresh_error(
                    config,
                    state,
                    "fetching git refs",
                    err,
                ));
            }
        }
    } else {
        fetch_refs(&repo_dir, &git_url, tracking_mode, fetch_roster_head).await?
    };

    let channel_roster_head = if let TrackingMode::Channel(channel_name) = tracking_mode {
        if !fetched_roster_head {
            Some(resolve_ref_to_commit(
                &repo_dir,
                &format!("refs/remotes/origin/{channel_name}"),
            )
            .await?)
        } else {
            None
        }
    } else {
        None
    };

    // Step 3: Resolve the current roster head separately from the selected
    // release. Tag, version, and channel tracking may keep package contents
    // pinned to an old release while trust metadata continues to advance on
    // the registry head.
    let pre_resolved_head = if matches!(tracking_mode, TrackingMode::Channel(_)) {
        None
    } else {
        Some(resolve_fetch_head(&repo_dir, tracking_mode).await?)
    };
    let roster_commit = if fetched_roster_head {
        resolve_origin_head(&repo_dir).await?
    } else if let Some(commit) = channel_roster_head {
        commit
    } else {
        pre_resolved_head
            .as_ref()
            .map(|head| head.commit.clone())
            .unwrap_or_default()
    };

    // Step 4: Pin the verified roster. The roster cursor has its own
    // anti-rollback state because selected release commits can remain fixed
    // under tag/version/channel tracking.
    let mut post_pin_trusted_keys = trusted_keys.clone();
    if enforcing {
        verify_head_commit(&repo_dir, &roster_commit, &trusted_keys)?;
        let previous_roster_commit = state
            .last_roster_commit
            .as_ref()
            .or(state.last_commit.as_ref());
        if let Some(old_commit) = previous_roster_commit {
            enforce_fast_forward(&repo_dir, old_commit, &roster_commit).await?;
        }
        if let Some(report) = apply_roster(&key_store, config, &repo_dir, &roster_commit)? {
            if !report.is_noop() {
                printer.info(&format!(
                    "Registry '{}': trust roster updated ({} pinned, {} unpinned, {} masked)",
                    config.name, report.pinned, report.unpinned, report.masked,
                ));
            }
            post_pin_trusted_keys = assemble_trusted_set(&key_store, config);
        }
    }

    // Step 5: Determine the selected release commit.
    let mut record_successful_freshness = true;
    let resolved_head = if let TrackingMode::Channel(channel_name) = tracking_mode {
        match resolve_channel_head(
            config,
            &git_url,
            channel_name,
            &repo_dir,
            &post_pin_trusted_keys,
            state,
        )
        .await
        {
            Ok((resolved, _channel_oid)) => {
                record_successful_freshness = channel_success_freshness_at(
                    config,
                    state,
                    previous_floor.as_deref(),
                    &resolved.semver,
                    unix_now_secs(),
                )?;
                ResolvedHead {
                    commit: resolved.commit,
                    release_tag: None,
                }
            }
            Err(err) => {
                return Err(channel_refresh_error(
                    config,
                    state,
                    "resolving channel partition",
                    err,
                ));
            }
        }
    } else {
        let Some(resolved) = pre_resolved_head else {
            bail!("internal error: non-channel tracking did not resolve before roster pinning");
        };
        resolved
    };
    let ResolvedHead {
        commit: new_commit,
        release_tag,
    } = resolved_head;

    if matches!(tracking_mode, TrackingMode::Channel(_)) {
        let target = state
            .floor
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("channel resolution did not persist a semver floor"))?;
        let target = semver::Version::parse(target)
            .with_context(|| format!("parsing resolved channel release {target}"))?;
        fetch::resolve_objects(&repo_dir, &git_url, &target, &retained_before, printer).await?;
    }

    // Verify the selected release commit. When the selected commit is also
    // the roster commit, the pre-pin signature check above is the continuity
    // check that authorizes the roster update; otherwise releases are checked
    // against the freshly pinned roster.
    if enforcing {
        let selected_trusted_keys = if new_commit == roster_commit {
            &trusted_keys
        } else {
            &post_pin_trusted_keys
        };
        verify_head_commit(&repo_dir, &new_commit, selected_trusted_keys)?;
    }

    // Step 6: Enforce selected-release fast-forward.
    if let Some(ref old_commit) = state.last_commit {
        enforce_fast_forward(&repo_dir, old_commit, &new_commit).await?;
    }

    if enforcing && let Some(release_tag) = release_tag.as_deref() {
        verify_release_tag(&repo_dir, release_tag, &post_pin_trusted_keys)?;
    }

    // Step 7: Extract authenticated tree files used by consumers.
    let registry_cache_dir = cache_dir.join(&config.name);
    let packages_dir = registry_cache_dir.join("packages");
    let old_packages = count_toml_files(&packages_dir).await;
    extract_packages(&repo_dir, &new_commit, &packages_dir).await?;
    extract_closures(&repo_dir, &new_commit, &registry_cache_dir.join("closures")).await?;
    let new_packages = count_toml_files(&packages_dir).await;

    // Step 7b: Materialise root registry files so resolve_mirror and trust
    // roster helpers can read the authenticated tree after sync. Without
    // registry.toml, the only cache fallback is the registry URL itself, which
    // fails for git:// transports.
    let registry_root_target = registries_dir.join(&config.name);
    extract_registry_root(&repo_dir, &new_commit, &registry_root_target).await?;

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
    if enforcing {
        state.last_roster_commit = Some(roster_commit);
    }
    if record_successful_freshness {
        state.last_update = Some(chrono_now());
    }

    printer.info(&format!(
        "Registry '{}': {} packages ({} added, {} updated, {} removed)",
        config.name, new_packages, added, updated, removed,
    ));

    Ok(SyncResult {
        new_commit,
        packages_count: new_packages,
        packages_added: added,
        packages_updated: updated,
        packages_removed: removed,
    })
}

// ---------------------------------------------------------------------------
// Trust helpers
// ---------------------------------------------------------------------------

/// `true` when signature verification is enforced for this registry.
///
/// Fail-closed: an absent `[registry.signing]` section enforces
/// verification; only an explicit `required = false` opts out.
fn signing_enforced(config: &RegistryConfig) -> bool {
    config
        .signing
        .as_ref()
        .is_none_or(|signing| signing.required)
}

/// Assemble the trusted key set for a registry.
///
/// Every key visible in the trusted-key store (which applies `# revoked:`
/// exclusions) is trusted. The `[registry.signing] public_key` config
/// entry is a *bootstrap* anchor: it is consulted only when the store has
/// no keys for the registry at all, and is superseded once roster keys are
/// pinned — a revoked key lingering in a config file must not stay
/// trusted forever.
fn assemble_trusted_set(store: &KeyStore, config: &RegistryConfig) -> Vec<String> {
    let mut keys: Vec<String> = store
        .lookup_all(&config.name)
        .iter()
        .map(TrustedKey::key_line)
        .collect();
    if keys.is_empty()
        && let Some(anchor) = config.signing.as_ref().and_then(|s| s.public_key.as_ref())
    {
        keys.push(anchor.clone());
    }
    keys
}

/// Verify the new head commit's signature against the trusted set.
fn verify_head_commit(repo_dir: &Path, commit: &str, trusted_keys: &[String]) -> Result<()> {
    let verified = security::verify_commit_signature(repo_dir, commit, trusted_keys)
        .with_context(|| format!("verifying signature of commit {commit}"))?;
    if !verified {
        let fingerprints: Vec<String> = trusted_keys
            .iter()
            .filter_map(|key| {
                security::parse_signing_key(key)
                    .ok()
                    .map(|(_, _, pubkey)| key_fingerprint(&pubkey))
            })
            .collect();
        bail!(
            "commit signature verification failed for {commit}: not signed by any trusted key \
             (trusted fingerprints: {}).\n\
             The registry requires signed commits; if a maintainer key rotated, ensure the\n\
             rotation was delivered through a signed fast-forward sync.",
            fingerprints.join(", "),
        );
    }
    Ok(())
}

fn verify_release_tag(repo_dir: &Path, tag: &str, trusted_keys: &[String]) -> Result<()> {
    let verified = security::verify_tag_signature(repo_dir, tag, trusted_keys)
        .with_context(|| format!("verifying signature of release tag {tag}"))?;
    if !verified {
        let fingerprints: Vec<String> = trusted_keys
            .iter()
            .filter_map(|key| {
                security::parse_signing_key(key)
                    .ok()
                    .map(|(_, _, pubkey)| key_fingerprint(&pubkey))
            })
            .collect();
        bail!(
            "release tag signature verification failed for {tag}: not signed by any trusted key \
             (trusted fingerprints: {}).",
            fingerprints.join(", "),
        );
    }
    Ok(())
}

/// Pin the trust roster committed at the verified head into the writable
/// trusted-key store.
///
/// Returns the sync report, or an error when the verified head has no
/// usable roster: under enforcement a missing or empty `keys.toml` is a
/// misconfigured registry, not a pass.
fn apply_roster(
    store: &KeyStore,
    config: &RegistryConfig,
    repo_dir: &Path,
    commit: &str,
) -> Result<Option<KeySyncReport>> {
    let Some(roster) = keys::load_keys_toml_at_commit(repo_dir, commit)? else {
        bail!(
            "registry '{}' requires signed metadata but commit {commit} has no keys.toml \
             trust roster.\n\
             Publish a roster with `apr keys add`, or set [registry.signing] required = false.",
            config.name,
        );
    };
    if roster.active.is_empty() {
        bail!(
            "registry '{}' requires signed metadata but its keys.toml roster has no active \
             keys at {commit}.\n\
             Publish a roster with `apr keys add`, or set [registry.signing] required = false.",
            config.name,
        );
    }
    keys::pin_rotated_keys(store, &config.name, &roster).map(Some)
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

fn is_plain_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

async fn preflight_git_native_http_origin(base_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let head_url = join_cache_url(base_url, "HEAD");
    let refs_url = join_cache_url(base_url, "info/refs");
    let legacy_url = join_cache_url(base_url, "bundle-list.toml");

    let head_status = probe_static_http_status(&client, &head_url).await?;
    let refs_status = probe_static_http_status(&client, &refs_url).await?;
    if head_status.is_success() && refs_status.is_success() {
        return Ok(());
    }

    let legacy_status = probe_static_http_status(&client, &legacy_url).await?;
    if legacy_status.is_success() {
        bail!(
            "registry origin {base_url} is a legacy bundle-mode registry (`bundle-list.toml` exists) \
             but this apm no longer supports the bundle/creation_token registry model. \
             Upgrade the registry origin to the git-native sha256 dumb-HTTP layout, or use an older apm only with legacy mirrors before cutover."
        );
    }

    bail!(
        "registry origin {base_url} is not a git-native AOS registry: expected dumb-HTTP git files \
         HEAD and info/refs, got HEAD {head_status} and info/refs {refs_status}"
    );
}

async fn probe_static_http_status(
    client: &reqwest::Client,
    url: &str,
) -> Result<reqwest::StatusCode> {
    let response = client
        .head(url)
        .send()
        .await
        .with_context(|| format!("probing {url}"))?;
    if response.status() != reqwest::StatusCode::METHOD_NOT_ALLOWED {
        return Ok(response.status());
    }

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("probing {url}"))?;
    Ok(response.status())
}

async fn ensure_sha256_capable_git() -> Result<()> {
    let version_output = gitcmd::hermetic_async()
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
    let output = gitcmd::hermetic_async()
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

    let output = gitcmd::hermetic_async()
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
async fn fetch_refs(
    repo_dir: &Path,
    url: &str,
    tracking_mode: &TrackingMode,
    fetch_roster_head: bool,
) -> Result<bool> {
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
            // Follow the remote's default branch HEAD when no explicit
            // tracking selector is configured.
            args.push("HEAD:refs/remotes/origin/HEAD".to_string());
        }
    }

    // Add --force to allow tag updates.
    args.push("--force".to_string());

    let output = gitcmd::transport_async()
        .args(&args)
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git fetch against {url}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git fetch failed: {}", stderr.trim());
    }

    if fetch_roster_head {
        fetch_origin_head(repo_dir, url).await
    } else {
        Ok(false)
    }
}

async fn fetch_origin_head(repo_dir: &Path, url: &str) -> Result<bool> {
    let output = gitcmd::transport_async()
        .args(["fetch", url, "HEAD:refs/remotes/origin/HEAD", "--force"])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("fetching remote roster head from {url}"))?;

    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("couldn't find remote ref HEAD")
        || stderr.contains("couldn't find remote ref")
        || stderr.contains("could not find remote ref HEAD")
    {
        return Ok(false);
    }
    bail!("git fetch remote HEAD failed: {}", stderr.trim());
}

fn uses_remote_head_roster(tracking_mode: &TrackingMode) -> bool {
    matches!(
        tracking_mode,
        TrackingMode::Tag(_) | TrackingMode::Version(_) | TrackingMode::Channel(_)
    )
}

async fn resolve_origin_head(repo_dir: &Path) -> Result<String> {
    let output = gitcmd::hermetic_async()
        .args(["rev-parse", "refs/remotes/origin/HEAD"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("resolving remote roster head")?;

    if !output.status.success() {
        bail!(
            "git rev-parse refs/remotes/origin/HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Resolve the authenticated commit to use after fetching.
async fn resolve_fetch_head(repo_dir: &Path, tracking_mode: &TrackingMode) -> Result<ResolvedHead> {
    let ref_to_resolve = match tracking_mode {
        TrackingMode::Commit(hash) => {
            // Already a commit hash.
            return Ok(ResolvedHead {
                commit: hash.clone(),
                release_tag: None,
            });
        }
        TrackingMode::Branch(branch) | TrackingMode::Channel(branch) => {
            format!("refs/remotes/origin/{branch}")
        }
        TrackingMode::Tag(tag) => {
            return Ok(ResolvedHead {
                commit: resolve_ref_to_commit(repo_dir, &format!("refs/tags/{tag}")).await?,
                release_tag: Some(tag.clone()),
            });
        }
        TrackingMode::Version(req) => {
            // List all tags, parse as semver, pick the best match.
            return resolve_best_version_tag(repo_dir, req).await;
        }
        TrackingMode::Default => "refs/remotes/origin/HEAD".to_string(),
    };

    let output = gitcmd::hermetic_async()
        .args(["rev-parse", &ref_to_resolve])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving ref {ref_to_resolve}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse {} failed: {}", ref_to_resolve, stderr.trim());
    }

    Ok(ResolvedHead {
        commit: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        release_tag: None,
    })
}

async fn resolve_ref_to_commit(repo_dir: &Path, ref_to_resolve: &str) -> Result<String> {
    let output = gitcmd::hermetic_async()
        .args(["rev-parse", &format!("{ref_to_resolve}^{{commit}}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving ref {ref_to_resolve} to commit"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git rev-parse {}^{{commit}} failed: {}",
            ref_to_resolve,
            stderr.trim(),
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Resolve a channel partition to a verified release.
///
/// Returns the verified release together with the partition tag object id
/// so callers can re-verify the chain after the trust roster is pinned.
async fn resolve_channel_head(
    config: &RegistryConfig,
    base_url: &str,
    channel_name: &str,
    repo_dir: &Path,
    trusted_keys: &[String],
    state: &mut RegistryState,
) -> Result<(verify::VerifiedRelease, String)> {
    if trusted_keys.is_empty() {
        bail!(
            "channel tracking for '{}' requires a trusted key: pin one with `apr trust pin` \
             or set [registry.signing] public_key",
            config.name,
        );
    }
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
            trusted_keys,
            &release_tags,
        )
        .await
        {
            Ok(Some((resolved, channel_oid))) => {
                let floor = state
                    .floor
                    .as_deref()
                    .map(semver::Version::parse)
                    .transpose()
                    .context("parsing registry semver floor")?;
                channel::check_floor(floor.as_ref(), &resolved.semver)?;

                state.bucket.get_or_insert(assigned_bucket);
                state.floor = Some(resolved.semver.to_string());
                return Ok((resolved, channel_oid));
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
    trusted_keys: &[String],
    release_tags: &BTreeMap<String, semver::Version>,
) -> Result<Option<(verify::VerifiedRelease, String)>> {
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
        trusted_keys,
    )
    .map(|release| Some((release, channel_oid)))
}

fn hash_tag_object(repo_dir: &Path, bytes: &[u8]) -> Result<String> {
    let mut child = gitcmd::hermetic()
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
    let output = gitcmd::hermetic_async()
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
    let output = gitcmd::hermetic_async()
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

/// Find the best tag matching a semver constraint.
///
/// Lists all tags in the repo, parses each as semver (stripping `v` prefix),
/// filters by the constraint, and resolves the latest matching tag's commit.
async fn resolve_best_version_tag(
    repo_dir: &Path,
    req: &semver::VersionReq,
) -> Result<ResolvedHead> {
    let output = gitcmd::hermetic_async()
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

    Ok(ResolvedHead {
        commit: resolve_ref_to_commit(repo_dir, &format!("refs/tags/{best_tag}")).await?,
        release_tag: Some(best_tag),
    })
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

/// Enforce that `new_commit` is a descendant of `old_commit` (fast-forward).
///
/// Uses `git merge-base --is-ancestor` to check the relationship.
async fn enforce_fast_forward(repo_dir: &Path, old_commit: &str, new_commit: &str) -> Result<()> {
    if old_commit == new_commit {
        return Ok(());
    }

    let output = gitcmd::hermetic_async()
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
             and run `{} update` again.",
            aos_core::invocation::package_manager_command()
        );
    }

    Ok(())
}

/// Extract package TOML files from a git tree into the output directory.
///
/// Uses `git archive` to export the `packages/` directory from the commit
/// and extract it into the output directory.
async fn extract_packages(repo_dir: &Path, commit: &str, output_dir: &Path) -> Result<()> {
    extract_tree_dir(repo_dir, commit, "packages", output_dir).await
}

/// Extract precomputed closure adjacency files from a git tree.
async fn extract_closures(repo_dir: &Path, commit: &str, output_dir: &Path) -> Result<()> {
    extract_tree_dir(repo_dir, commit, "closures", output_dir).await
}

async fn extract_tree_dir(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
    output_dir: &Path,
) -> Result<()> {
    if output_dir.exists() {
        tokio::fs::remove_dir_all(output_dir)
            .await
            .with_context(|| format!("cleaning {}", output_dir.display()))?;
    }
    tokio::fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("creating {}", output_dir.display()))?;

    if !tree_path_exists(repo_dir, commit, tree_path).await? {
        return Ok(());
    }

    let tarball = tempfile::NamedTempFile::new().context("creating temporary git archive")?;
    let archive = gitcmd::hermetic_async()
        .args(["archive", "--format=tar", "-o"])
        .arg(tarball.path())
        .arg(commit)
        .arg(format!("{tree_path}/"))
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git archive {commit} {tree_path}/"))?;
    if !archive.status.success() {
        bail!(
            "git archive {commit} {tree_path}/ failed: {}",
            String::from_utf8_lossy(&archive.stderr).trim(),
        );
    }

    let tar = std::process::Command::new("tar")
        .arg("-x")
        .arg("--strip-components=1")
        .arg("-f")
        .arg(tarball.path())
        .arg("-C")
        .arg(output_dir)
        .output()
        .with_context(|| format!("running tar to extract {tree_path}"))?;

    if !tar.status.success() {
        let stderr = String::from_utf8_lossy(&tar.stderr);
        bail!(
            "failed to extract {tree_path} from commit {commit}: {}",
            stderr.trim(),
        );
    }

    Ok(())
}

async fn tree_path_exists(repo_dir: &Path, commit: &str, tree_path: &str) -> Result<bool> {
    let output = gitcmd::hermetic_async()
        .args(["cat-file", "-e", &format!("{commit}:{tree_path}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("checking tree path {commit}:{tree_path}"))?;
    Ok(output.status.success())
}

/// Extract repo-root support files into `target_dir`.
///
/// Missing files are non-fatal: `apm install` falls back to the registry URL
/// when no cache config is present, and older registries may not have a
/// committed trust roster. Any stale local copy is removed when the upstream
/// tree no longer contains the file.
pub async fn extract_registry_root(repo_dir: &Path, commit: &str, target_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(target_dir)
        .await
        .with_context(|| format!("creating {}", target_dir.display()))?;

    for file in ["registry.toml", "keys.toml", ".gitattributes"] {
        extract_optional_root_file(repo_dir, commit, target_dir, file).await?;
    }

    Ok(())
}

async fn extract_optional_root_file(
    repo_dir: &Path,
    commit: &str,
    target_dir: &Path,
    file: &str,
) -> Result<()> {
    let output = gitcmd::hermetic_async()
        .args(["show", &format!("{commit}:{file}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git show {commit}:{file}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_missing_tree_path(&stderr, file) {
            let dest = target_dir.join(file);
            if dest.exists() {
                tokio::fs::remove_file(&dest)
                    .await
                    .with_context(|| format!("removing stale {}", dest.display()))?;
            }
            return Ok(());
        }
        bail!("git show {commit}:{file} failed: {}", stderr.trim(),);
    }

    let dest = target_dir.join(file);
    tokio::fs::write(&dest, &output.stdout)
        .await
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

fn is_missing_tree_path(stderr: &str, file: &str) -> bool {
    stderr.contains("does not exist")
        || stderr.contains("exists on disk, but not in")
        || stderr.contains(&format!("path '{file}'"))
}

fn channel_success_freshness_at(
    config: &RegistryConfig,
    state: &RegistryState,
    previous_floor: Option<&str>,
    resolved: &semver::Version,
    now_secs: u64,
) -> Result<bool> {
    let Some(previous_floor) = previous_floor else {
        return Ok(true);
    };
    let previous_floor = semver::Version::parse(previous_floor)
        .with_context(|| format!("parsing registry semver floor {previous_floor}"))?;
    if resolved > &previous_floor {
        return Ok(true);
    }
    if resolved < &previous_floor {
        bail!(
            "registry '{}' channel resolved release {resolved} below monotonic floor {previous_floor}",
            config.name,
        );
    }

    let max_staleness = config
        .max_staleness_seconds
        .unwrap_or(DEFAULT_CHANNEL_MAX_STALENESS_SECONDS);
    let Some(last_update) = state.last_update.as_deref() else {
        bail!(
            "registry '{}' channel refresh resolved unchanged release {resolved}, but no previous \
             successful freshness observation exists",
            config.name,
        );
    };
    let last_update_secs = parse_iso8601_utc_secs(last_update).with_context(|| {
        format!(
            "registry '{}' channel refresh resolved unchanged release {resolved}, but \
             last_update '{last_update}' could not be parsed for freshness evaluation",
            config.name,
        )
    })?;
    let age = now_secs.saturating_sub(last_update_secs);
    if age > max_staleness {
        bail!(
            "registry '{}' channel refresh resolved unchanged release {resolved}; last successful \
             freshness observation is stale ({age}s old, max_staleness_seconds={max_staleness}); \
             refusing to accept a frozen-but-valid channel pointer",
            config.name,
        );
    }

    Ok(false)
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

fn channel_refresh_error(
    config: &RegistryConfig,
    state: &RegistryState,
    phase: &str,
    err: anyhow::Error,
) -> anyhow::Error {
    channel_refresh_error_at(config, state, phase, err, unix_now_secs())
}

fn channel_refresh_error_at(
    config: &RegistryConfig,
    state: &RegistryState,
    phase: &str,
    err: anyhow::Error,
    now_secs: u64,
) -> anyhow::Error {
    let max_staleness = config
        .max_staleness_seconds
        .unwrap_or(DEFAULT_CHANNEL_MAX_STALENESS_SECONDS);
    let cause = format!("{err:#}");

    let Some(last_update) = state.last_update.as_deref() else {
        return anyhow::anyhow!(
            "registry '{}' channel refresh failed while {phase}, and no previous successful \
             freshness observation exists: {cause}",
            config.name,
        );
    };

    let last_update_secs = match parse_iso8601_utc_secs(last_update) {
        Ok(secs) => secs,
        Err(parse_err) => {
            return anyhow::anyhow!(
                "registry '{}' channel refresh failed while {phase}, and last_update '{}' \
                 could not be parsed for freshness evaluation: {parse_err:#}; original error: {cause}",
                config.name,
                last_update,
            );
        }
    };
    let age = now_secs.saturating_sub(last_update_secs);

    if age > max_staleness {
        anyhow::anyhow!(
            "registry '{}' channel refresh failed while {phase}; last successful freshness \
             observation is stale ({age}s old, max_staleness_seconds={max_staleness}): {cause}",
            config.name,
        )
    } else {
        anyhow::anyhow!(
            "registry '{}' channel refresh failed while {phase}; last successful freshness \
             observation is {age}s old (max_staleness_seconds={max_staleness}): {cause}",
            config.name,
        )
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn parse_iso8601_utc_secs(input: &str) -> Result<u64> {
    if input.len() != 20
        || !input.ends_with('Z')
        || &input[4..5] != "-"
        || &input[7..8] != "-"
        || &input[10..11] != "T"
        || &input[13..14] != ":"
        || &input[16..17] != ":"
    {
        bail!("timestamp must be YYYY-MM-DDTHH:MM:SSZ");
    }

    let year = parse_decimal(&input[0..4], "year")?;
    let month = parse_decimal(&input[5..7], "month")?;
    let day = parse_decimal(&input[8..10], "day")?;
    let hour = parse_decimal(&input[11..13], "hour")?;
    let minute = parse_decimal(&input[14..16], "minute")?;
    let second = parse_decimal(&input[17..19], "second")?;

    if hour > 23 || minute > 59 || second > 59 {
        bail!("timestamp time is out of range");
    }

    let days = ymd_to_days(year, month, day)?;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_decimal(input: &str, field: &str) -> Result<u64> {
    if input.is_empty() || !input.bytes().all(|b| b.is_ascii_digit()) {
        bail!("timestamp {field} is not numeric");
    }
    input
        .parse()
        .with_context(|| format!("parsing timestamp {field}"))
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

fn ymd_to_days(year: u64, month: u64, day: u64) -> Result<u64> {
    if !(1..=12).contains(&month) {
        bail!("timestamp month is out of range");
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        bail!("timestamp day is out of range");
    }

    let year = year as i64;
    let month = month as i64;
    let day = day as i64;
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let yoe = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        bail!("timestamp predates Unix epoch");
    }
    Ok(days as u64)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningConfig;
    use tokio::process::Command;

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

    fn channel_config(max_staleness_seconds: Option<u64>) -> RegistryConfig {
        RegistryConfig {
            name: "core".to_string(),
            url: "https://registry.example.com/core".to_string(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: Some("stable".to_string()),
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds,
            caches: Vec::new(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: Some(SigningConfig {
                required: true,
                public_key: Some("core:Ed25519:base64key".to_string()),
            }),
        }
    }

    #[test]
    fn parse_iso8601_utc_secs_handles_epoch_and_leap_day() {
        assert_eq!(parse_iso8601_utc_secs("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_iso8601_utc_secs("2024-02-29T00:00:00Z").unwrap(),
            1_709_164_800,
        );
        assert!(parse_iso8601_utc_secs("2023-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn channel_refresh_error_reports_first_sync_without_observation() {
        let err = channel_refresh_error_at(
            &channel_config(Some(60)),
            &RegistryState::default(),
            "resolving channel partition",
            anyhow::anyhow!("offline"),
            parse_iso8601_utc_secs("2026-06-01T00:00:00Z").unwrap(),
        );
        let message = format!("{err:#}");
        assert!(message.contains("no previous successful freshness observation"));
        assert!(message.contains("offline"));
    }

    #[test]
    fn channel_refresh_error_reports_fresh_failed_refresh() {
        let mut state = RegistryState {
            last_update: Some("2026-06-01T00:00:00Z".to_string()),
            ..RegistryState::default()
        };
        let err = channel_refresh_error_at(
            &channel_config(Some(120)),
            &state,
            "fetching git refs",
            anyhow::anyhow!("temporary 503"),
            parse_iso8601_utc_secs("2026-06-01T00:01:00Z").unwrap(),
        );
        let message = format!("{err:#}");
        assert!(message.contains("60s old"));
        assert!(!message.contains(" is stale "));

        state.last_update = Some("2026-06-01T00:02:30Z".to_string());
        let err = channel_refresh_error_at(
            &channel_config(Some(120)),
            &state,
            "fetching git refs",
            anyhow::anyhow!("temporary 503"),
            parse_iso8601_utc_secs("2026-06-01T00:02:00Z").unwrap(),
        );
        assert!(format!("{err:#}").contains("0s old"));
    }

    #[test]
    fn channel_refresh_error_reports_stale_failed_refresh() {
        let state = RegistryState {
            last_update: Some("2026-06-01T00:00:00Z".to_string()),
            ..RegistryState::default()
        };
        let err = channel_refresh_error_at(
            &channel_config(Some(120)),
            &state,
            "resolving channel partition",
            anyhow::anyhow!("all partitions missing"),
            parse_iso8601_utc_secs("2026-06-01T00:02:01Z").unwrap(),
        );
        let message = format!("{err:#}");
        assert!(message.contains("is stale (121s old"));
        assert!(message.contains("max_staleness_seconds=120"));
        assert!(message.contains("all partitions missing"));
    }

    #[test]
    fn channel_success_freshness_records_first_sync_and_advances() {
        assert!(
            channel_success_freshness_at(
                &channel_config(Some(120)),
                &RegistryState::default(),
                None,
                &semver::Version::parse("1.0.0").unwrap(),
                parse_iso8601_utc_secs("2026-06-01T00:00:00Z").unwrap(),
            )
            .unwrap()
        );

        let state = RegistryState {
            floor: Some("1.0.0".to_string()),
            last_update: Some("2026-06-01T00:00:00Z".to_string()),
            ..RegistryState::default()
        };
        assert!(
            channel_success_freshness_at(
                &channel_config(Some(120)),
                &state,
                state.floor.as_deref(),
                &semver::Version::parse("1.1.0").unwrap(),
                parse_iso8601_utc_secs("2026-06-02T00:00:00Z").unwrap(),
            )
            .unwrap()
        );
    }

    #[test]
    fn channel_success_freshness_keeps_quiet_channel_within_window() {
        let state = RegistryState {
            floor: Some("1.0.0".to_string()),
            last_update: Some("2026-06-01T00:00:00Z".to_string()),
            ..RegistryState::default()
        };
        assert!(
            !channel_success_freshness_at(
                &channel_config(Some(120)),
                &state,
                state.floor.as_deref(),
                &semver::Version::parse("1.0.0").unwrap(),
                parse_iso8601_utc_secs("2026-06-01T00:01:00Z").unwrap(),
            )
            .unwrap()
        );
    }

    #[test]
    fn channel_success_freshness_rejects_stale_unchanged_pointer() {
        let state = RegistryState {
            floor: Some("1.0.0".to_string()),
            last_update: Some("2026-06-01T00:00:00Z".to_string()),
            ..RegistryState::default()
        };
        let err = channel_success_freshness_at(
            &channel_config(Some(120)),
            &state,
            state.floor.as_deref(),
            &semver::Version::parse("1.0.0").unwrap(),
            parse_iso8601_utc_secs("2026-06-01T00:02:01Z").unwrap(),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("resolved unchanged release 1.0.0"));
        assert!(message.contains("is stale (121s old"));
        assert!(message.contains("frozen-but-valid channel pointer"));
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
    async fn default_tracking_resolves_remote_head_without_tags() {
        let tmp = tempfile::TempDir::new().unwrap();
        let work_dir = tmp.path().join("work");
        let origin_dir = tmp.path().join("origin.git");
        let repo_dir = tmp.path().join("cache.git");
        tokio::fs::create_dir_all(&work_dir).await.unwrap();

        let output = git(&work_dir)
            .args(["init", "--object-format=sha256"])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let _ = git(&work_dir)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .await;
        let _ = git(&work_dir)
            .args(["config", "user.name", "Test"])
            .output()
            .await;
        let output = git(&work_dir)
            .args(["checkout", "-b", "stable"])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());

        tokio::fs::write(
            work_dir.join("registry.toml"),
            "[registry]\nname = \"test\"\n",
        )
        .await
        .unwrap();
        let _ = git(&work_dir).args(["add", "."]).output().await;
        let output = git(&work_dir)
            .args(["commit", "-m", "initial"])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let output = git(&work_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .await
            .unwrap();
        let expected = String::from_utf8_lossy(&output.stdout).trim().to_string();

        let output = git(tmp.path())
            .args([
                "init",
                "--bare",
                "--object-format=sha256",
                &origin_dir.to_string_lossy(),
            ])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let output = git(&origin_dir)
            .args(["symbolic-ref", "HEAD", "refs/heads/stable"])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let output = git(&work_dir)
            .args(["remote", "add", "origin", &origin_dir.to_string_lossy()])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let output = git(&work_dir)
            .args(["push", "origin", "stable"])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());

        ensure_repo(&repo_dir, &origin_dir.to_string_lossy())
            .await
            .unwrap();
        fetch_refs(
            &repo_dir,
            &origin_dir.to_string_lossy(),
            &TrackingMode::Default,
            false,
        )
        .await
        .unwrap();
        let resolved = resolve_fetch_head(&repo_dir, &TrackingMode::Default)
            .await
            .unwrap();

        assert_eq!(resolved.commit, expected);
        assert_eq!(resolved.release_tag, None);
        let output = git(&repo_dir).args(["tag", "-l"]).output().await.unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).trim().is_empty());
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
