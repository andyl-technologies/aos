//! HTTP bundle transport for registry sync.
//!
//! Downloads pre-built git bundle files from static HTTP mirrors, verifies
//! their SHA-256 hashes against the bundle-list.toml manifest, runs
//! `git bundle verify` for pack integrity, and unbundles into the local
//! registry git cache.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Bundle manifest types (parsed from bundle-list.toml)
// ---------------------------------------------------------------------------

/// The type of a git bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleType {
    /// Full snapshot — contains the complete registry state at a tag.
    Snapshot,
    /// Sequential delta — changes from the immediately preceding patch.
    SequentialDelta,
    /// Skip-ahead delta — changes from a minor base tag to a later patch.
    SkipDelta,
}

/// A single entry in the bundle-list.toml manifest.
#[derive(Debug, Clone)]
pub struct BundleEntry {
    pub uri: String,
    pub creation_token: u64,
    pub sha256: String,
    pub size: u64,
    pub bundle_type: BundleType,
    /// For delta bundles, the base tag (prerequisite).
    pub base_tag: Option<String>,
    /// The target tag this bundle brings the repo to.
    pub target_tag: String,
}

/// Parsed bundle-list.toml manifest.
#[derive(Debug)]
pub struct BundleManifest {
    pub registry: String,
    pub version: u32,
    pub entries: Vec<BundleEntry>,
}

// ---------------------------------------------------------------------------
// TOML deserialization schema for bundle-list.toml
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ManifestToml {
    manifest: ManifestHeader,
    #[serde(default)]
    bundles: Vec<BundleEntryToml>,
}

#[derive(Debug, Deserialize)]
struct ManifestHeader {
    registry: String,
    version: u32,
    #[allow(dead_code)]
    #[serde(default)]
    generated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BundleEntryToml {
    /// Present for snapshot bundles.
    #[serde(default)]
    tag: Option<String>,
    /// Present for delta bundles (the base).
    #[serde(default)]
    from_tag: Option<String>,
    /// Present for delta bundles (the target).
    #[serde(default)]
    to_tag: Option<String>,
    #[serde(rename = "type")]
    bundle_type: String,
    uri: String,
    creation_token: u64,
    size: u64,
    sha256: String,
}

impl BundleManifest {
    /// Fetch and parse bundle-list.toml from a registry base URL.
    ///
    /// The manifest URL is: `{base_url}/bundles/{registry_name}/bundle-list.toml`
    /// but callers construct the full base URL, so we just append
    /// `/bundle-list.toml`.
    pub async fn fetch(
        client: &reqwest::Client,
        base_url: &str,
        registry_name: &str,
    ) -> Result<Self> {
        let manifest_url = format!(
            "{}/bundles/{}/bundle-list.toml",
            base_url.trim_end_matches('/'),
            registry_name,
        );

        let response = client
            .get(&manifest_url)
            .send()
            .await
            .with_context(|| format!("fetching bundle manifest from {manifest_url}"))?
            .error_for_status()
            .with_context(|| format!("HTTP error fetching {manifest_url}"))?;

        let body = response
            .text()
            .await
            .with_context(|| format!("reading body of {manifest_url}"))?;

        Self::parse(&body)
    }

    /// Parse a bundle-list.toml string into a `BundleManifest`.
    pub fn parse(content: &str) -> Result<Self> {
        let toml: ManifestToml =
            toml::from_str(content).context("invalid bundle-list.toml")?;

        let mut entries = Vec::with_capacity(toml.bundles.len());
        for b in toml.bundles {
            let (bundle_type, base_tag, target_tag) = match b.bundle_type.as_str() {
                "snapshot" => {
                    let tag = b
                        .tag
                        .ok_or_else(|| anyhow::anyhow!("snapshot bundle missing 'tag' field"))?;
                    (BundleType::Snapshot, None, tag)
                }
                "delta" => {
                    let from = b
                        .from_tag
                        .ok_or_else(|| anyhow::anyhow!("delta bundle missing 'from_tag'"))?;
                    let to = b
                        .to_tag
                        .ok_or_else(|| anyhow::anyhow!("delta bundle missing 'to_tag'"))?;

                    // Classify: if from_tag has no patch component (e.g. "v2026.02")
                    // and to_tag has a patch component, it's a skip delta.
                    // If from_tag also has a patch component, it's sequential.
                    let is_skip = classify_delta(&from, &to);
                    let dt = if is_skip {
                        BundleType::SkipDelta
                    } else {
                        BundleType::SequentialDelta
                    };
                    (dt, Some(from), to)
                }
                other => bail!("unknown bundle type: {other}"),
            };

            entries.push(BundleEntry {
                uri: b.uri,
                creation_token: b.creation_token,
                sha256: b.sha256,
                size: b.size,
                bundle_type,
                base_tag,
                target_tag,
            });
        }

        // Sort by creation_token ascending for deterministic ordering.
        entries.sort_by_key(|e| e.creation_token);

        Ok(Self {
            registry: toml.manifest.registry,
            version: toml.manifest.version,
            entries,
        })
    }

    /// Filter entries with creation_token strictly greater than `token`.
    pub fn entries_since(&self, token: u64) -> Vec<&BundleEntry> {
        self.entries
            .iter()
            .filter(|e| e.creation_token > token)
            .collect()
    }

    /// Find the latest snapshot bundle (highest creation_token among snapshots).
    pub fn latest_snapshot(&self) -> Option<&BundleEntry> {
        self.entries
            .iter()
            .filter(|e| e.bundle_type == BundleType::Snapshot)
            .max_by_key(|e| e.creation_token)
    }

    /// Find a skip-ahead delta from a given base tag to the latest target.
    ///
    /// Returns the skip delta with the highest creation_token whose base_tag
    /// matches the given tag.
    pub fn skip_delta_from(&self, base_tag: &str) -> Option<&BundleEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.bundle_type == BundleType::SkipDelta
                    && e.base_tag.as_deref() == Some(base_tag)
            })
            .max_by_key(|e| e.creation_token)
    }

    /// Find sequential deltas between two creation tokens, ordered.
    pub fn sequential_deltas_between(
        &self,
        from_token: u64,
        to_token: u64,
    ) -> Vec<&BundleEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.bundle_type == BundleType::SequentialDelta
                    && e.creation_token > from_token
                    && e.creation_token <= to_token
            })
            .collect()
    }
}

/// Classify whether a delta is a skip delta or sequential delta.
///
/// A skip delta goes from a minor base (no patch, e.g. "v2026.02") to a
/// patched version (e.g. "v2026.02.3"). A sequential delta goes from one
/// patch to the next (e.g. "v2026.02.1" to "v2026.02.2").
///
/// We classify by counting the number of dot-separated segments after 'v':
/// - "v2026.02" has 2 segments -> minor base
/// - "v2026.02.1" has 3 segments -> patch
///
/// A delta from a 2-segment tag to a 3-segment tag is a skip delta.
fn classify_delta(from: &str, _to: &str) -> bool {
    let from_stripped = from.strip_prefix('v').unwrap_or(from);
    let from_parts: Vec<&str> = from_stripped.split('.').collect();
    // If from_tag has only 2 parts (YYYY.MM), it's a minor base -> skip delta
    from_parts.len() <= 2
}

// ---------------------------------------------------------------------------
// Bundle download, verification, and unbundling
// ---------------------------------------------------------------------------

/// Download a bundle file from `{base_url}/bundles/{registry}/{entry.uri}`,
/// verify its SHA-256 hash, and write it to `dest`.
pub async fn download_bundle(
    client: &reqwest::Client,
    entry: &BundleEntry,
    base_url: &str,
    registry_name: &str,
    dest: &Path,
    printer: &Printer,
) -> Result<()> {
    let url = format!(
        "{}/bundles/{}/{}",
        base_url.trim_end_matches('/'),
        registry_name,
        entry.uri,
    );

    printer.info(&format!("Downloading bundle: {}", entry.uri));

    let mut response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching bundle {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error fetching bundle {url}"))?;

    // Create parent directory if needed.
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let mut hasher = Sha256::new();
    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("creating {}", dest.display()))?;
    let mut downloaded: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading bundle {url}"))?
    {
        hasher.update(&chunk);
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .with_context(|| format!("writing to {}", dest.display()))?;
        downloaded += chunk.len() as u64;
    }

    drop(file);

    // Verify SHA-256.
    let digest = hex::encode(hasher.finalize());
    if digest != entry.sha256 {
        // Clean up the corrupt file.
        let _ = tokio::fs::remove_file(dest).await;
        bail!(
            "SHA-256 mismatch for bundle '{}': expected {}, got {}",
            entry.uri,
            entry.sha256,
            digest,
        );
    }

    printer.info(&format!(
        "Bundle verified: {} ({} bytes)",
        entry.uri, downloaded,
    ));

    Ok(())
}

/// Verify a downloaded bundle file:
/// 1. SHA-256 matches the expected hash
/// 2. `git bundle verify` passes (pack integrity + prerequisites)
pub async fn verify_bundle(
    path: &Path,
    expected_sha256: &str,
    repo_dir: &Path,
) -> Result<()> {
    // Step 1: SHA-256 verification.
    let content = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading bundle {}", path.display()))?;

    let digest = hex::encode(Sha256::digest(&content));
    if digest != expected_sha256 {
        bail!(
            "SHA-256 mismatch for {}: expected {}, got {}",
            path.display(),
            expected_sha256,
            digest,
        );
    }

    // Step 2: git bundle verify.
    let output = Command::new("git")
        .args(["bundle", "verify", &path.to_string_lossy()])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("running git bundle verify on {}", path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git bundle verify failed for {}:\n{}\n\n\
             This may indicate a corrupt download or missing prerequisites.\n\
             Try running `apm update` again, or use `apm update --force` to \
             re-download a full snapshot.",
            path.display(),
            stderr.trim(),
        );
    }

    Ok(())
}

/// Initialize a bare git repo at `repo_dir` if it does not already exist.
pub async fn ensure_git_repo(repo_dir: &Path) -> Result<()> {
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

/// Unbundle a git bundle file into the local registry git cache.
///
/// Runs `git bundle unbundle <path>` in the cache repo directory.
pub async fn unbundle(bundle_path: &Path, repo_dir: &Path) -> Result<()> {
    let output = Command::new("git")
        .args([
            "bundle",
            "unbundle",
            &bundle_path.to_string_lossy(),
        ])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| {
            format!(
                "running git bundle unbundle {} in {}",
                bundle_path.display(),
                repo_dir.display(),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git bundle unbundle failed for {}:\n{}",
            bundle_path.display(),
            stderr.trim(),
        );
    }

    Ok(())
}

/// Get the commit SHA that a tag points to in the local bare repo.
pub async fn resolve_tag(repo_dir: &Path, tag: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", &format!("refs/tags/{tag}")])
        .current_dir(repo_dir)
        .output()
        .await
        .with_context(|| format!("resolving tag {tag}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse refs/tags/{tag} failed: {}", stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MANIFEST: &str = r#"
[manifest]
registry = "aos-core"
version = 1
generated = "2026-02-15T12:00:00Z"

[[bundles]]
tag = "v2026.01"
type = "snapshot"
uri = "aos-core-v2026.01.bundle"
creation_token = 2026010000
size = 102400
sha256 = "aaa111"

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
uri = "aos-core-v2026.02..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 6144
sha256 = "012def"

[[bundles]]
from_tag = "v2026.02.2"
to_tag = "v2026.02.3"
type = "delta"
uri = "aos-core-v2026.02.2..v2026.02.3.delta.bundle"
creation_token = 2026020003
size = 3072
sha256 = "345ghi"

[[bundles]]
from_tag = "v2026.02"
to_tag = "v2026.02.3"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.3.delta.bundle"
creation_token = 2026020003
size = 7168
sha256 = "678jkl"
"#;

    #[test]
    fn parse_manifest() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        assert_eq!(manifest.registry, "aos-core");
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.entries.len(), 7);
    }

    #[test]
    fn entries_sorted_by_creation_token() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let tokens: Vec<u64> = manifest.entries.iter().map(|e| e.creation_token).collect();
        let mut sorted = tokens.clone();
        sorted.sort();
        assert_eq!(tokens, sorted);
    }

    #[test]
    fn snapshot_classification() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let snapshots: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.bundle_type == BundleType::Snapshot)
            .collect();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].target_tag, "v2026.01");
        assert_eq!(snapshots[1].target_tag, "v2026.02");
        // Snapshots have no base_tag.
        assert!(snapshots[0].base_tag.is_none());
        assert!(snapshots[1].base_tag.is_none());
    }

    #[test]
    fn delta_classification() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();

        // Sequential deltas: from a patch to the next patch.
        let sequential: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.bundle_type == BundleType::SequentialDelta)
            .collect();
        assert_eq!(sequential.len(), 2);
        assert_eq!(sequential[0].base_tag.as_deref(), Some("v2026.02.1"));
        assert_eq!(sequential[0].target_tag, "v2026.02.2");
        assert_eq!(sequential[1].base_tag.as_deref(), Some("v2026.02.2"));
        assert_eq!(sequential[1].target_tag, "v2026.02.3");

        // Skip deltas: from a minor base to a later patch.
        let skip: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.bundle_type == BundleType::SkipDelta)
            .collect();
        assert_eq!(skip.len(), 3);
        // All skip deltas have base_tag "v2026.02".
        for s in &skip {
            assert_eq!(s.base_tag.as_deref(), Some("v2026.02"));
        }
    }

    #[test]
    fn entries_since_filters_correctly() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();

        // After token 2026020000 (the v2026.02 snapshot), should get 5 entries.
        let newer = manifest.entries_since(2026020000);
        assert_eq!(newer.len(), 5);
        assert!(newer.iter().all(|e| e.creation_token > 2026020000));

        // After token 2026020002, should get 2 entries (the .3 patch deltas).
        let newer = manifest.entries_since(2026020002);
        assert_eq!(newer.len(), 2);
        assert!(newer.iter().all(|e| e.creation_token == 2026020003));

        // After token 2026020003, nothing.
        let newer = manifest.entries_since(2026020003);
        assert!(newer.is_empty());
    }

    #[test]
    fn latest_snapshot_returns_most_recent() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();
        let latest = manifest.latest_snapshot().unwrap();
        assert_eq!(latest.target_tag, "v2026.02");
        assert_eq!(latest.creation_token, 2026020000);
        assert_eq!(latest.sha256, "abc123");
    }

    #[test]
    fn skip_delta_from_finds_correct_delta() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();

        // Skip delta from v2026.02 should find the latest (to v2026.02.3).
        let skip = manifest.skip_delta_from("v2026.02").unwrap();
        assert_eq!(skip.target_tag, "v2026.02.3");
        assert_eq!(skip.creation_token, 2026020003);

        // No skip delta from v2026.01.
        assert!(manifest.skip_delta_from("v2026.01").is_none());

        // No skip delta from a patch version (those are sequential).
        assert!(manifest.skip_delta_from("v2026.02.1").is_none());
    }

    #[test]
    fn sequential_deltas_between_tokens() {
        let manifest = BundleManifest::parse(SAMPLE_MANIFEST).unwrap();

        // Between token 2026020001 and 2026020003 there are two sequential deltas:
        // .1->.2 at token 2026020002 and .2->.3 at token 2026020003.
        let seq = manifest.sequential_deltas_between(2026020001, 2026020003);
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].base_tag.as_deref(), Some("v2026.02.1"));
        assert_eq!(seq[0].target_tag, "v2026.02.2");
        assert_eq!(seq[1].base_tag.as_deref(), Some("v2026.02.2"));
        assert_eq!(seq[1].target_tag, "v2026.02.3");

        // Between token 2026020002 and 2026020003: just one sequential delta.
        let seq = manifest.sequential_deltas_between(2026020002, 2026020003);
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].base_tag.as_deref(), Some("v2026.02.2"));
        assert_eq!(seq[0].target_tag, "v2026.02.3");
    }

    #[test]
    fn sha256_verification_logic() {
        let data = b"hello world";
        let expected = hex::encode(Sha256::digest(data));

        // Correct hash.
        let actual = hex::encode(Sha256::digest(data));
        assert_eq!(actual, expected);

        // Wrong data produces different hash.
        let wrong = hex::encode(Sha256::digest(b"hello worl"));
        assert_ne!(wrong, expected);
    }

    #[test]
    fn classify_delta_skip_vs_sequential() {
        // Minor base to patch = skip delta.
        assert!(classify_delta("v2026.02", "v2026.02.3"));
        // Patch to patch = sequential delta.
        assert!(!classify_delta("v2026.02.1", "v2026.02.2"));
        // Edge case: single segment.
        assert!(classify_delta("v2026", "v2026.02.1"));
    }

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[manifest]
registry = "test"
version = 1
"#;
        let manifest = BundleManifest::parse(toml).unwrap();
        assert_eq!(manifest.registry, "test");
        assert!(manifest.entries.is_empty());
    }

    #[test]
    fn parse_manifest_snapshot_only() {
        let toml = r#"
[manifest]
registry = "test"
version = 1

[[bundles]]
tag = "v1.0"
type = "snapshot"
uri = "test-v1.0.bundle"
creation_token = 1000000
size = 1024
sha256 = "aabbcc"
"#;
        let manifest = BundleManifest::parse(toml).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].bundle_type, BundleType::Snapshot);
        assert_eq!(manifest.entries[0].target_tag, "v1.0");
        assert!(manifest.entries[0].base_tag.is_none());
    }

    #[test]
    fn parse_manifest_rejects_unknown_type() {
        let toml = r#"
[manifest]
registry = "test"
version = 1

[[bundles]]
tag = "v1.0"
type = "unknown"
uri = "test.bundle"
creation_token = 1000000
size = 1024
sha256 = "abc"
"#;
        let result = BundleManifest::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown bundle type"), "got: {err}");
    }

    #[test]
    fn parse_manifest_delta_missing_from_tag() {
        let toml = r#"
[manifest]
registry = "test"
version = 1

[[bundles]]
to_tag = "v1.0.1"
type = "delta"
uri = "test.bundle"
creation_token = 1000000
size = 1024
sha256 = "abc"
"#;
        let result = BundleManifest::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("from_tag"), "got: {err}");
    }
}
