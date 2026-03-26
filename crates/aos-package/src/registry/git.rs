//! Native git transport for registry sync.
//!
//! Used when a registry is configured with `git://`, `git+https://`, or
//! `git+ssh://` URL schemes. Runs `git fetch` directly against a git server,
//! verifies commit signatures and fast-forward constraints, and extracts
//! package TOML files into the local registry cache.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use aos_core::output::Printer;
use crate::types::{RegistryConfig, RegistryState, SigningConfig};

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
    cache_dir: &Path,
    state: &mut RegistryState,
    printer: &Printer,
) -> Result<SyncResult> {
    let git_url = normalize_git_url(&config.url);
    let repo_dir = cache_dir.join(&config.name).join("repo.git");

    // Step 1: Ensure repo.
    printer.info(&format!("Syncing registry '{}' via git...", config.name));
    ensure_repo(&repo_dir, &git_url).await?;

    // Step 2: Fetch refs.
    fetch_refs(&repo_dir, &git_url, config).await?;

    // Step 3: Determine the new HEAD commit.
    let new_commit = resolve_fetch_head(&repo_dir, config).await?;

    // Step 4: Verify commit signature if signing.required.
    if let Some(ref signing) = config.signing {
        if signing.required {
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
    state.last_commit = Some(new_commit.clone());
    state.last_update = Some(chrono_now());

    printer.info(&format!(
        "Registry '{}': {} packages ({} added, {} updated, {} removed)",
        config.name,
        new_packages,
        added,
        updated,
        removed,
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
/// `git://...` -> `git://...` (unchanged)
fn normalize_git_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("git+") {
        rest.to_string()
    } else {
        url.to_string()
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
        .args(["init", "--bare"])
        .current_dir(repo_dir)
        .output()
        .await
        .context("running git init --bare")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git init --bare failed: {}", stderr.trim());
    }

    Ok(())
}

/// Run `git fetch` with the appropriate refspec.
///
/// - If `pin` is set and looks like a tag (starts with 'v'), fetch that tag.
/// - If `pin` is set and looks like a SHA, fetch it directly.
/// - If `branch` is set, fetch that branch.
/// - Otherwise, fetch all refs.
async fn fetch_refs(
    repo_dir: &Path,
    url: &str,
    config: &RegistryConfig,
) -> Result<()> {
    let mut args = vec!["fetch".to_string(), url.to_string()];

    if let Some(ref pin) = config.pin {
        if pin.starts_with('v') {
            // Tag pin: fetch the specific tag.
            args.push(format!("refs/tags/{pin}:refs/tags/{pin}"));
        } else {
            // SHA pin: fetch the specific commit.
            args.push(pin.clone());
        }
    } else if let Some(ref branch) = config.branch {
        // Branch tracking: fetch the branch.
        args.push(format!(
            "refs/heads/{branch}:refs/remotes/origin/{branch}"
        ));
    } else {
        // Default: fetch all tags.
        args.push("refs/tags/*:refs/tags/*".to_string());
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
async fn resolve_fetch_head(
    repo_dir: &Path,
    config: &RegistryConfig,
) -> Result<String> {
    let ref_to_resolve = if let Some(ref pin) = config.pin {
        if pin.starts_with('v') {
            format!("refs/tags/{pin}")
        } else {
            // SHA pin: already a commit hash.
            return Ok(pin.clone());
        }
    } else if let Some(ref branch) = config.branch {
        format!("refs/remotes/origin/{branch}")
    } else {
        // Find the latest tag by listing all tags and picking the last one
        // (lexicographically, which works for our YYYY.MM.patch format).
        return resolve_latest_tag(repo_dir).await;
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
async fn enforce_fast_forward(
    repo_dir: &Path,
    old_commit: &str,
    new_commit: &str,
) -> Result<()> {
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
async fn extract_packages(
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

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
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
        let result =
            enforce_fast_forward(&repo_dir, "abc123", "abc123").await;
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
        tokio::fs::write(c_dir.join("curl.toml"), "test").await.unwrap();
        tokio::fs::write(c_dir.join("coreutils.toml"), "test").await.unwrap();

        let z_dir = tmp.path().join("z");
        tokio::fs::create_dir_all(&z_dir).await.unwrap();
        tokio::fs::write(z_dir.join("zlib.toml"), "test").await.unwrap();

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
        let output = Command::new("git")
            .args(["init"])
            .current_dir(&work_dir)
            .output()
            .await
            .unwrap();
        assert!(output.status.success());

        // Configure git user for commit.
        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&work_dir)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&work_dir)
            .output()
            .await;

        // Create package files.
        let pkg_dir = work_dir.join("packages").join("c");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("curl.toml"), "[package]\nname = \"curl\"\n")
            .await
            .unwrap();

        // Add and commit.
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&work_dir)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(&work_dir)
            .output()
            .await;

        // Clone as bare repo.
        let output = Command::new("git")
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
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo_dir)
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
        let _ = Command::new("git")
            .args(["init"])
            .current_dir(&work_dir)
            .output()
            .await
            .unwrap();
        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&work_dir)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&work_dir)
            .output()
            .await;

        // First commit.
        tokio::fs::write(work_dir.join("a.txt"), "a").await.unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&work_dir)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "first"])
            .current_dir(&work_dir)
            .output()
            .await;

        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work_dir)
            .output()
            .await
            .unwrap();
        let commit1 = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Second commit.
        tokio::fs::write(work_dir.join("b.txt"), "b").await.unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(&work_dir)
            .output()
            .await;
        let _ = Command::new("git")
            .args(["commit", "-m", "second"])
            .current_dir(&work_dir)
            .output()
            .await;

        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work_dir)
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
