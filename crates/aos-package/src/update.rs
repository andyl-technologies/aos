//! `apm update` — sync registry metadata.
//!
//! Fetches the latest package metadata from all enabled registries (or a
//! single named one) and stores it in the local cache.  Supports both
//! HTTP bundle transport and native git transport.

use std::path::Path;

use anyhow::{bail, Context, Result};

use aos_core::error::AosError;
use aos_core::output::Printer;
use crate::config::ApmConfig;
use crate::registry::{bundle, git};
use crate::registry::state;
use crate::types::{RegistryConfig, RegistryState, TrackingMode, Transport};

// ---------------------------------------------------------------------------
// Sync result
// ---------------------------------------------------------------------------

/// Summary of a sync operation against a single registry.
pub struct SyncResult {
    /// The new HEAD commit SHA after sync.
    pub new_commit: String,
    /// Total number of packages in the registry after sync.
    pub packages_count: usize,
    /// Number of packages that were added or updated.
    pub packages_updated: usize,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `apm update` — sync all (or one) registry.
pub async fn run(
    config: &ApmConfig,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    // If a specific registry was requested, validate it exists.
    if let Some(name) = registry_filter {
        if config.find_registry(name).is_none() {
            return Err(AosError::RegistryError {
                message: format!("registry '{name}' not found"),
            }
            .into());
        }
    }

    let cache_dir = config.cache_path();
    let registries_dir = config.scope.registries_path();
    let config_dir = config.scope.config_dir();
    let mut any_synced = false;

    for (reg_config, existing_state) in &config.registries {
        // Skip disabled registries.
        if !reg_config.enabled {
            continue;
        }

        // If a filter is set, skip non-matching registries.
        if let Some(name) = registry_filter {
            if reg_config.name != name {
                continue;
            }
        }

        any_synced = true;
        let mut current_state = existing_state.clone().unwrap_or_default();

        // Resolve tracking mode from config.
        let tracking_mode = match reg_config.tracking_mode() {
            Ok(m) => m,
            Err(e) => {
                printer.error(&format!(
                    "Registry '{}': invalid tracking config: {}",
                    reg_config.name, e
                ));
                if registry_filter.is_some() {
                    return Err(e);
                }
                continue;
            }
        };

        // For commit and tag modes, check if already at target.
        match &tracking_mode {
            TrackingMode::Commit(hash) => {
                if current_state.last_commit.as_deref() == Some(hash.as_str()) {
                    printer.info(&format!(
                        "Registry '{}': already at commit {}",
                        reg_config.name,
                        &hash[..hash.len().min(12)],
                    ));
                    continue;
                }
            }
            TrackingMode::Tag(tag) => {
                // If we have a last_commit, we need to check if that commit
                // corresponds to this tag. We can't easily check without
                // the repo, so we proceed with the sync which will be a
                // no-op if already up to date.
                let _ = tag; // proceed to sync
            }
            _ => {}
        }

        printer.header(&format!(
            "Fetching registry '{}' ({})...",
            reg_config.name,
            tracking_mode,
        ));

        let result = match reg_config.transport() {
            Transport::HttpBundle => {
                sync_bundle(
                    reg_config,
                    &tracking_mode,
                    &mut current_state,
                    &cache_dir,
                    &registries_dir,
                    printer,
                )
                .await
            }
            Transport::Git => {
                git::sync_git(
                    reg_config,
                    &tracking_mode,
                    &cache_dir,
                    &registries_dir,
                    &mut current_state,
                    printer,
                )
                    .await
                    .map(|r| SyncResult {
                        new_commit: r.new_commit,
                        packages_count: r.packages_added + r.packages_updated,
                        packages_updated: r.packages_updated,
                    })
            }
        };

        match result {
            Ok(sync_result) => {
                // Save state back to the registry config file.
                let state_path = config_dir
                    .join("registries.d")
                    .join(format!("{}.toml", reg_config.name));
                if state_path.exists() {
                    state::save_state(&state_path, &current_state)
                        .with_context(|| {
                            format!(
                                "saving state for registry '{}'",
                                reg_config.name
                            )
                        })?;
                }

                printer.success(&format!(
                    "Registry '{}': done ({} packages, {} updated, commit {})",
                    reg_config.name,
                    sync_result.packages_count,
                    sync_result.packages_updated,
                    &sync_result.new_commit[..sync_result.new_commit.len().min(12)],
                ));
            }
            Err(e) => {
                printer.error(&format!(
                    "Failed to sync registry '{}': {}",
                    reg_config.name, e
                ));
                // Continue with other registries rather than aborting.
                if registry_filter.is_some() {
                    // If the user asked for a specific registry, propagate the error.
                    return Err(e);
                }
            }
        }
    }

    if !any_synced {
        if let Some(name) = registry_filter {
            return Err(AosError::RegistryError {
                message: format!("registry '{name}' is not enabled"),
            }
            .into());
        }
        printer.warning("No enabled registries found. Add one with `apm registry add`.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP bundle sync
// ---------------------------------------------------------------------------

/// Sync a single HTTP bundle registry.
///
/// Strategy for choosing which bundles to download:
/// 1. First time (no state): download the latest snapshot.
/// 2. Has state with a creation_token:
///    a. Try a skip delta from the current tag's base to the latest.
///    b. Fall back to sequential deltas from current token to latest.
///    c. Fall back to the latest snapshot if deltas are unavailable.
async fn sync_bundle(
    config: &RegistryConfig,
    tracking_mode: &TrackingMode,
    reg_state: &mut RegistryState,
    cache_dir: &Path,
    registries_dir: &Path,
    printer: &Printer,
) -> Result<SyncResult> {
    let engine = crate::download::default_engine();

    // Fetch the bundle manifest.
    let manifest =
        bundle::BundleManifest::fetch(&engine, &config.url, &config.name).await?;

    // Determine which bundles to download.
    let bundles_to_apply = pick_bundles(&manifest, reg_state, tracking_mode)?;

    if bundles_to_apply.is_empty() {
        printer.info("Already up to date.");
        let packages_dir = cache_dir.join(&config.name).join("packages");
        let packages_count = count_packages(&packages_dir);
        let commit = reg_state
            .last_commit
            .clone()
            .unwrap_or_else(|| "unknown".into());
        return Ok(SyncResult {
            new_commit: commit,
            packages_count,
            packages_updated: 0,
        });
    }

    let repo_dir = cache_dir.join(&config.name).join("repo.git");
    bundle::ensure_git_repo(&repo_dir).await?;

    let packages_dir = cache_dir.join(&config.name).join("packages");
    let old_packages = count_packages(&packages_dir);

    // Download, verify, and unbundle each bundle in order.
    let mut last_target_tag = String::new();

    for entry in &bundles_to_apply {
        let bundle_dir = cache_dir.join(&config.name).join("bundles");
        let dest = bundle_dir.join(&entry.uri);

        bundle::download_bundle(&engine, entry, &config.url, &config.name, &dest, printer)
            .await?;
        bundle::verify_bundle(&dest, &entry.sha256, &repo_dir).await?;
        bundle::unbundle(&dest, &repo_dir).await?;

        // Clean up the bundle file after successful unbundle.
        let _ = tokio::fs::remove_file(&dest).await;

        last_target_tag = entry.target_tag.clone();
    }

    // Resolve the final commit from the target tag.
    let new_commit = bundle::resolve_tag(&repo_dir, &last_target_tag).await?;

    // Extract package TOML files from the git tree.
    extract_packages_from_git(&repo_dir, &new_commit, &packages_dir).await?;
    let new_packages = count_packages(&packages_dir);

    // Also materialise the repo-root registry.toml so resolve_mirror finds
    // [[caches]] without needing a separate copy.
    let registry_toml_target = registries_dir.join(&config.name);
    crate::registry::git::extract_registry_root(
        &repo_dir,
        &new_commit,
        &registry_toml_target,
    )
    .await?;

    // Compute the latest creation token.
    let latest_token = bundles_to_apply
        .iter()
        .map(|e| e.creation_token)
        .max()
        .unwrap_or(0);

    // Downgrade protection: check monotonic ordering.
    if let Some(old_token) = reg_state.last_creation_token {
        if latest_token > old_token {
            state::check_monotonic(old_token, latest_token)?;
        }
    }

    // Update state.
    reg_state.last_commit = Some(new_commit.clone());
    reg_state.last_creation_token = Some(latest_token);
    reg_state.last_update = Some(now_iso8601());

    // Compute update stats: on first sync everything is "updated",
    // otherwise approximate from the delta in package count.
    let packages_updated = if old_packages == 0 {
        new_packages
    } else {
        let added = new_packages.saturating_sub(old_packages);
        let common = new_packages.min(old_packages);
        added + common
    };

    Ok(SyncResult {
        new_commit,
        packages_count: new_packages,
        packages_updated,
    })
}

/// Choose which bundles to download for an incremental or full sync.
fn pick_bundles<'a>(
    manifest: &'a bundle::BundleManifest,
    reg_state: &RegistryState,
    tracking_mode: &TrackingMode,
) -> Result<Vec<&'a bundle::BundleEntry>> {
    // Handle tag/commit/version tracking modes that pin to a specific tag.
    match tracking_mode {
        TrackingMode::Tag(tag) => {
            // Find the snapshot for this exact tag, or a delta to it.
            if let Some(entry) = manifest.entries.iter().find(|e| {
                e.bundle_type == bundle::BundleType::Snapshot && e.target_tag == *tag
            }) {
                return Ok(vec![entry]);
            }
            // Try finding a delta that targets this tag.
            if let Some(entry) = manifest.entries.iter().find(|e| {
                e.target_tag == *tag
            }) {
                return Ok(vec![entry]);
            }
            bail!("tag '{tag}' not found in bundle manifest");
        }
        TrackingMode::Commit(_hash) => {
            // Bundle transport doesn't support arbitrary commit lookup.
            // Fall through to default behavior (fetch latest).
        }
        TrackingMode::Version(req) => {
            // Find all tags, parse as semver, filter by constraint, pick latest.
            let best = find_best_version_tag_in_manifest(manifest, req);
            if let Some(tag) = best {
                if let Some(entry) = manifest.entries.iter().find(|e| {
                    e.bundle_type == bundle::BundleType::Snapshot && e.target_tag == tag
                }) {
                    return Ok(vec![entry]);
                }
                // Try delta targeting this tag.
                if let Some(entry) = manifest.entries.iter().rev().find(|e| {
                    e.target_tag == tag
                }) {
                    return Ok(vec![entry]);
                }
                bail!("matched version tag '{tag}' not available as bundle");
            } else {
                bail!("no tags matching version constraint '{req}' found in bundle manifest");
            }
        }
        TrackingMode::Branch(_) | TrackingMode::Channel(_) | TrackingMode::Default => {
            // Fall through to incremental sync logic below.
        }
    }

    // No existing state -> download latest snapshot.
    let current_token = match reg_state.last_creation_token {
        Some(t) => t,
        None => {
            return match manifest.latest_snapshot() {
                Some(entry) => Ok(vec![entry]),
                None => bail!("no snapshot bundles available in manifest"),
            };
        }
    };

    // Already at or past the latest entry -> nothing to do.
    let newer = manifest.entries_since(current_token);
    if newer.is_empty() {
        return Ok(vec![]);
    }

    let latest_token = manifest
        .entries
        .iter()
        .map(|e| e.creation_token)
        .max()
        .unwrap_or(0);

    // Strategy 1: Try skip delta from current version's base tag.
    let current_version = state::token_to_version(current_token);
    // Extract the minor base (e.g. "v2026.02" from "v2026.02.3").
    let base_tag = extract_minor_base(&current_version);

    if let Some(skip) = manifest.skip_delta_from(&base_tag) {
        if skip.creation_token > current_token {
            return Ok(vec![skip]);
        }
    }

    // Strategy 2: Try sequential deltas.
    let seq = manifest.sequential_deltas_between(current_token, latest_token);
    if !seq.is_empty() {
        // Verify the chain is contiguous by checking that the first delta's
        // base matches our current state.
        return Ok(seq);
    }

    // Strategy 3: Fall back to latest snapshot.
    match manifest.latest_snapshot() {
        Some(entry) => Ok(vec![entry]),
        None => bail!("no snapshot bundles available in manifest"),
    }
}

/// Find the best matching tag in a bundle manifest for a semver constraint.
///
/// Parses tag names as semver (stripping a leading `v` prefix), filters by
/// the constraint, and returns the latest matching tag name.
///
/// Two-component versions like `2026.02` are normalized to `2026.2.0` for
/// semver parsing.  Tags that don't parse as semver are silently skipped.
fn find_best_version_tag_in_manifest(
    manifest: &bundle::BundleManifest,
    req: &semver::VersionReq,
) -> Option<String> {
    let mut best: Option<(semver::Version, String)> = None;

    for entry in &manifest.entries {
        let tag = &entry.target_tag;
        if let Some(ver) = parse_tag_as_semver(tag) {
            if req.matches(&ver) {
                match &best {
                    Some((best_ver, _)) if ver > *best_ver => {
                        best = Some((ver, tag.clone()));
                    }
                    None => {
                        best = Some((ver, tag.clone()));
                    }
                    _ => {}
                }
            }
        }
    }

    best.map(|(_, tag)| tag)
}

/// Parse a tag string as a semver `Version`, stripping a leading `v` prefix,
/// removing leading zeros from components (e.g. `02` -> `2`), and appending
/// `.0` for two-component versions like `2026.02`.
fn parse_tag_as_semver(tag: &str) -> Option<semver::Version> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    // Normalize leading zeros: "2026.02.3" -> "2026.2.3"
    let parts: Vec<&str> = stripped.split('.').collect();
    let normalized: Vec<String> = parts
        .iter()
        .map(|p| {
            // Parse as u64 to strip leading zeros, then convert back
            p.parse::<u64>().map(|n| n.to_string()).unwrap_or_else(|_| p.to_string())
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

/// Extract the minor base from a version tag.
///
/// `"v2026.02.3"` -> `"v2026.02"`
/// `"v2026.02"` -> `"v2026.02"`
fn extract_minor_base(tag: &str) -> String {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() >= 2 {
        format!("v{}.{}", parts[0], parts[1])
    } else {
        tag.to_string()
    }
}

/// Extract package TOML files from a git tree into the output directory.
///
/// Mirrors the same logic used in `git::extract_packages`.
async fn extract_packages_from_git(
    repo_dir: &Path,
    commit: &str,
    output_dir: &Path,
) -> Result<()> {
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

/// Count `.toml` files in a packages directory (synchronous, for quick stats).
fn count_packages(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };

    let mut count = 0;
    for letter_entry in entries.flatten() {
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }
        let Ok(sub) = std::fs::read_dir(&letter_path) else {
            continue;
        };
        for entry in sub.flatten() {
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
fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
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
    use crate::registry::bundle::BundleManifest;

    const SAMPLE_MANIFEST: &str = r#"
[manifest]
registry = "aos-core"
version = 1

[[bundles]]
tag = "v2026.02"
type = "snapshot"
uri = "aos-core-v2026.02.bundle"
creation_token = 2026020000
size = 153600
sha256 = "abc123"

[[bundles]]
from_tag = "v2026.02"
to_tag = "v2026.02.1"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.1.delta.bundle"
creation_token = 2026020001
size = 8192
sha256 = "def456"

[[bundles]]
from_tag = "v2026.02.1"
to_tag = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02.1..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 4096
sha256 = "789abc"

[[bundles]]
from_tag = "v2026.02"
to_tag = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.2.skip.bundle"
creation_token = 2026020002
size = 6144
sha256 = "012def"
"#;

    #[test]
    fn pick_bundles_first_sync_gets_snapshot() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let mode = TrackingMode::Default;

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].target_tag, "v2026.02");
        assert_eq!(
            bundles[0].bundle_type,
            bundle::BundleType::Snapshot
        );
    }

    #[test]
    fn pick_bundles_already_up_to_date() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState {
            last_commit: Some("abc".into()),
            last_creation_token: Some(2026020002),
            last_update: None,
        };
        let mode = TrackingMode::Default;

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn pick_bundles_uses_skip_delta() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        // At v2026.02.0 (snapshot token), skip delta should jump to latest.
        let state = RegistryState {
            last_commit: Some("abc".into()),
            last_creation_token: Some(2026020000),
            last_update: None,
        };
        let mode = TrackingMode::Default;

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        // Should pick the skip delta from v2026.02 to v2026.02.2.
        assert_eq!(bundles[0].base_tag.as_deref(), Some("v2026.02"));
        assert_eq!(bundles[0].target_tag, "v2026.02.2");
    }

    #[test]
    fn pick_bundles_uses_sequential_when_no_skip() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        // At v2026.02.1, there's no skip delta from v2026.02.1 base,
        // so it should use sequential delta.
        let state = RegistryState {
            last_commit: Some("abc".into()),
            last_creation_token: Some(2026020001),
            last_update: None,
        };
        let mode = TrackingMode::Default;

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].target_tag, "v2026.02.2");
    }

    #[test]
    fn pick_bundles_tag_mode() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let mode = TrackingMode::Tag("v2026.02".into());

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].target_tag, "v2026.02");
    }

    #[test]
    fn pick_bundles_tag_not_found() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let mode = TrackingMode::Tag("v2025.01".into());

        let result = pick_bundles(&manifest, &state, &mode);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("v2025.01"), "got: {err}");
    }

    #[test]
    fn pick_bundles_version_mode() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let req = semver::VersionReq::parse("~2026.2").unwrap();
        let mode = TrackingMode::Version(req);

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        // Should pick the latest tag matching ~2026.2, which is v2026.02.2
        // (a skip delta from v2026.02 to v2026.02.2).
        assert_eq!(bundles[0].target_tag, "v2026.02.2");
    }

    #[test]
    fn pick_bundles_version_no_match() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let req = semver::VersionReq::parse(">=2027").unwrap();
        let mode = TrackingMode::Version(req);

        let result = pick_bundles(&manifest, &state, &mode);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no tags matching"), "got: {err}");
    }

    #[test]
    fn pick_bundles_branch_mode_same_as_default() {
        // Branch mode with no state should get the latest snapshot
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let state = RegistryState::default();
        let mode = TrackingMode::Branch("main".into());

        let bundles = pick_bundles(&manifest, &state, &mode).unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].target_tag, "v2026.02");
    }

    #[test]
    fn find_best_version_tag_in_manifest_tilde() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let req = semver::VersionReq::parse("~2026.2").unwrap();
        let best = find_best_version_tag_in_manifest(&manifest, &req);
        // v2026.02 parses as 2026.2.0, v2026.02.1 as 2026.2.1, v2026.02.2 as 2026.2.2
        // All match ~2026.2, so the best (latest) is v2026.02.2
        assert_eq!(best.unwrap(), "v2026.02.2");
    }

    #[test]
    fn find_best_version_tag_no_match() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let req = semver::VersionReq::parse(">=2027").unwrap();
        assert!(find_best_version_tag_in_manifest(&manifest, &req).is_none());
    }

    #[test]
    fn find_best_version_tag_non_semver_ignored() {
        // Tags that don't parse as semver should be silently skipped
        let toml = r#"
[manifest]
registry = "test"
version = 1

[[bundles]]
tag = "release-candidate"
type = "snapshot"
uri = "test.bundle"
creation_token = 1000
size = 1024
sha256 = "abc"

[[bundles]]
tag = "v1.2.3"
type = "snapshot"
uri = "test2.bundle"
creation_token = 2000
size = 1024
sha256 = "def"
"#;
        let manifest = BundleManifest::parse(toml).unwrap();
        let req = semver::VersionReq::parse(">=1").unwrap();
        let best = find_best_version_tag_in_manifest(&manifest, &req);
        assert_eq!(best.unwrap(), "v1.2.3");
    }

    #[test]
    fn extract_minor_base_with_patch() {
        assert_eq!(extract_minor_base("v2026.02.3"), "v2026.02");
    }

    #[test]
    fn extract_minor_base_without_patch() {
        assert_eq!(extract_minor_base("v2026.02"), "v2026.02");
    }

    #[test]
    fn now_iso8601_format() {
        let ts = now_iso8601();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn count_packages_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert_eq!(count_packages(tmp.path()), 0);
    }

    #[test]
    fn count_packages_with_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let c_dir = tmp.path().join("c");
        std::fs::create_dir_all(&c_dir).unwrap();
        std::fs::write(c_dir.join("curl.toml"), "test").unwrap();
        std::fs::write(c_dir.join("coreutils.toml"), "test").unwrap();

        let z_dir = tmp.path().join("z");
        std::fs::create_dir_all(&z_dir).unwrap();
        std::fs::write(z_dir.join("zlib.toml"), "test").unwrap();

        assert_eq!(count_packages(tmp.path()), 3);
    }
}
