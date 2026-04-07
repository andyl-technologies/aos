//! Git transport primitives for registry sync.
//!
//! Provides reusable git operations: repo initialization, fetching, tag
//! resolution, fast-forward enforcement, commit verification, and archive
//! extraction. Registry-specific orchestration (sync_git) stays in
//! `aos-package`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

// ---------------------------------------------------------------------------
// Git repo management
// ---------------------------------------------------------------------------

/// Initialize a bare git repo at `repo_dir` if it does not already exist.
pub async fn ensure_repo(repo_dir: &Path) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// Normalize a git URL by stripping the `git+` prefix if present.
///
/// `git+https://...` -> `https://...`
/// `git+ssh://...` -> `ssh://...`
/// `git://...` -> `git://...` (unchanged)
pub fn normalize_git_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("git+") {
        rest.to_string()
    } else {
        url.to_string()
    }
}

/// Run `git fetch` with the given URL and refspecs.
pub async fn fetch(
    repo_dir: &Path,
    url: &str,
    refspecs: &[String],
    force: bool,
) -> Result<()> {
    let mut args = vec!["fetch".to_string(), url.to_string()];
    args.extend(refspecs.iter().cloned());

    if force {
        args.push("--force".to_string());
    }

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

// ---------------------------------------------------------------------------
// Ref resolution
// ---------------------------------------------------------------------------

/// Resolve a git ref to a commit SHA.
pub async fn resolve_ref(repo_dir: &Path, reference: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", reference])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving ref {reference}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse {} failed: {}", reference, stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Find the latest tag in the repo (by version sort).
pub async fn resolve_latest_tag(repo_dir: &Path) -> Result<String> {
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

    resolve_ref(repo_dir, &format!("refs/tags/{latest}")).await
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify the commit signature using `git verify-commit`.
///
/// This checks that the commit was signed and that the signature is valid.
/// The actual key verification depends on the user's git configuration
/// (gpg.ssh.allowedSignersFile or gpg keyring).
pub async fn verify_commit_signature(
    repo_dir: &Path,
    commit: &str,
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
pub async fn enforce_fast_forward(
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

// ---------------------------------------------------------------------------
// Archive extraction
// ---------------------------------------------------------------------------

/// Extract files from a git tree into the output directory.
///
/// Uses `git archive` to export the specified `tree_path` from the commit
/// and extract it into the output directory with `tar`.
pub async fn extract_tree(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
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
        .args(["archive", commit, tree_path])
        .current_dir(repo_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running git archive {commit} {tree_path}"))?;

    let tar = std::process::Command::new("tar")
        .args([
            "-x",
            "--strip-components=1",
            "-C",
            &output_dir.to_string_lossy(),
        ])
        .stdin(archive.stdout.unwrap())
        .output()
        .context("running tar to extract tree")?;

    if !tar.status.success() {
        let stderr = String::from_utf8_lossy(&tar.stderr);
        bail!(
            "failed to extract {} from commit {commit}: {}",
            tree_path,
            stderr.trim(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Return the current timestamp in ISO 8601 format.
///
/// Uses a simple implementation to avoid pulling in the `chrono` crate.
pub fn now_iso8601() -> String {
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

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
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
    fn now_iso8601_format() {
        let now = now_iso8601();
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
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        let (y, m, d) = days_to_ymd(10957);
        assert_eq!((y, m, d), (2000, 1, 1));
    }

    #[test]
    fn days_to_ymd_leap_year() {
        let (y, m, d) = days_to_ymd(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[tokio::test]
    async fn ensure_repo_creates_bare_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("test.git");

        ensure_repo(&repo_dir).await.unwrap();
        assert!(repo_dir.join("HEAD").exists());

        // Calling again should be a no-op.
        ensure_repo(&repo_dir).await.unwrap();
        assert!(repo_dir.join("HEAD").exists());
    }

    #[tokio::test]
    async fn enforce_fast_forward_same_commit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_dir = tmp.path().join("test.git");
        ensure_repo(&repo_dir).await.unwrap();

        let result =
            enforce_fast_forward(&repo_dir, "abc123", "abc123").await;
        assert!(result.is_ok());
    }
}
