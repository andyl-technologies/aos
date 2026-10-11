//! Pure bounded projections of upstream release and Repology responses.
//!
//! Transport adapters retain exact response bytes, supply explicit observation
//! time, and persist first-observed history. Parsers never fetch or read a clock.

use std::collections::BTreeSet;
use std::time::UNIX_EPOCH;

use anyhow::{Context as _, Result, bail};
use aos_assessment::discovery::ObservationCandidate;
use aos_contract::limits::JsonLimits;
use serde_json::Value;
use url::Url;

/// Preserves a Repology candidate and its durable first-observed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepologyCandidate {
    /// Exact source repository/version/page identity.
    pub raw_id: String,
    /// Sanitized provider comparison version.
    pub raw_version: String,
    /// Stable history key excluding the response item index.
    pub first_key: String,
    /// Marks an ignored, incorrect or untrusted provider record.
    pub yanked: bool,
    /// Original provider version status.
    pub status: Option<String>,
    /// Provider boolean signal for this exact version.
    pub vulnerable: Option<bool>,
    /// Sorted unique reported license identifiers.
    pub licenses: Vec<String>,
}

/// Counts unfiltered GitHub page entries for conservative pagination proofs.
///
/// Prefix filtering cannot establish exhaustion: a page containing twenty
/// unrelated tags still requires querying its next bounded source position.
///
/// # Errors
/// Returns an error for malformed, duplicate-bearing, oversized or non-array JSON.
pub fn github_page_length(bytes: &[u8]) -> Result<usize> {
    let value = parse_response(bytes, "GitHub page")?;
    Ok(value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("GitHub page is not an array"))?
        .len())
}

/// Parses one GitHub releases page into bounded provider-native candidates.
///
/// # Errors
///
/// Returns an error for malformed, ambiguous, oversized, or incompatible responses.
pub fn github_releases(
    bytes: &[u8],
    tag_prefix: &str,
    retrieved_at: u64,
) -> Result<Vec<ObservationCandidate>> {
    let mut candidates = Vec::new();
    let value = parse_response(bytes, "GitHub releases response")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("GitHub releases response is not an array"))?;
    for entry in entries {
        let raw_id = required_string(entry, "tag_name", "GitHub release")?;
        if raw_id.len() > 512 {
            bail!("GitHub release identity is oversized");
        }
        let Some(raw_version) = normalized_github_tag(&raw_id, tag_prefix) else {
            continue;
        };
        candidates.push(ObservationCandidate {
            raw_id: raw_id.clone(),
            raw_version: raw_version.to_string(),
            published_at_unix: github_release_timestamp(entry)?,
            first_observed_at_unix: retrieved_at,
            prerelease: entry
                .get("prerelease")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            yanked: entry.get("draft").and_then(Value::as_bool).unwrap_or(false),
            release_url: entry
                .get("html_url")
                .and_then(Value::as_str)
                .map(str::to_string),
            status: None,
            vulnerable: None,
            licenses: Vec::new(),
        });
    }
    Ok(candidates)
}

/// Parses the Go release feed into bounded provider-native candidates.
///
/// # Errors
///
/// Returns an error for malformed, ambiguous, oversized, or incompatible responses.
pub fn go_releases(bytes: &[u8], retrieved_at: u64) -> Result<Vec<ObservationCandidate>> {
    let value = parse_response(bytes, "Go release feed")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Go release feed is not an array"))?;
    let mut candidates = Vec::new();
    for entry in entries {
        if !entry
            .get("stable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let raw_id = required_string(entry, "version", "Go release")?;
        let raw_version = raw_id
            .strip_prefix("go")
            .filter(|version| !version.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Go release has an invalid version identity"))?;
        if raw_id.len() > 512 || raw_version.len() > 256 {
            bail!("Go release identity is oversized");
        }
        let source_filename = format!("{raw_id}.src.tar.gz");
        let has_source = entry
            .get("files")
            .and_then(Value::as_array)
            .is_some_and(|files| {
                files.iter().any(|file| {
                    file.get("kind").and_then(Value::as_str) == Some("source")
                        && file.get("filename").and_then(Value::as_str)
                            == Some(source_filename.as_str())
                })
            });
        if !has_source {
            continue;
        }

        candidates.push(ObservationCandidate {
            raw_id: raw_id.clone(),
            raw_version: raw_version.to_string(),
            published_at_unix: None,
            first_observed_at_unix: retrieved_at,
            prerelease: false,
            yanked: false,
            release_url: Some(format!("https://go.dev/dl/#{raw_id}")),
            status: None,
            vulnerable: None,
            licenses: Vec::new(),
        });
    }
    Ok(candidates)
}

/// Parses one GitHub tags page into bounded provider-native candidates.
///
/// # Errors
///
/// Returns an error for malformed, ambiguous, oversized, or incompatible responses.
pub fn github_tags(
    bytes: &[u8],
    repository: &str,
    tag_prefix: &str,
    retrieved_at: u64,
) -> Result<Vec<ObservationCandidate>> {
    let mut candidates = Vec::new();
    let value = parse_response(bytes, "GitHub tags response")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("GitHub tags response is not an array"))?;
    for entry in entries {
        let raw_id = required_string(entry, "name", "GitHub tag")?;
        if raw_id.len() > 512 {
            bail!("GitHub tag identity is oversized");
        }
        let Some(raw_version) = normalized_github_tag(&raw_id, tag_prefix) else {
            continue;
        };
        candidates.push(ObservationCandidate {
            raw_id: raw_id.clone(),
            raw_version: raw_version.to_string(),
            published_at_unix: None,
            first_observed_at_unix: retrieved_at,
            prerelease: false,
            yanked: false,
            release_url: github_release_url(repository, &raw_id).ok(),
            status: None,
            vulnerable: None,
            licenses: Vec::new(),
        });
    }
    Ok(candidates)
}

/// Parses a relevant Repology project projection into bounded provider-native candidates.
///
/// # Errors
///
/// Returns an error for malformed, ambiguous, oversized, or incompatible responses.
pub fn repology(
    bytes: &[u8],
    project: &str,
    relevant_versions: &BTreeSet<String>,
) -> Result<Vec<RepologyCandidate>> {
    let value = parse_response(bytes, "Repology response")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Repology response is not an array"))?;

    let mut parsed = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let status = entry.get("status").and_then(Value::as_str);
        if !repology_version_is_relevant(version, status, relevant_versions) {
            continue;
        }
        let repository = entry
            .get("repo")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let original_version = entry
            .get("origversion")
            .and_then(Value::as_str)
            .unwrap_or(version);
        let raw_id = format!("{repository}:{original_version}:{index}");
        let first_key = format!(
            "repology:{}:{project}:{}:{repository}:{}:{original_version}",
            project.len(),
            repository.len(),
            original_version.len()
        );
        let mut licenses = entry
            .get("licenses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        licenses.sort();
        licenses.dedup();
        parsed.push(RepologyCandidate {
            raw_id,
            raw_version: version.to_string(),
            first_key,
            yanked: matches!(status, Some("ignored" | "incorrect" | "untrusted")),
            status: status.map(str::to_string),
            vulnerable: entry.get("vulnerable").and_then(Value::as_bool),
            licenses,
        });
    }
    Ok(parsed)
}

/// Parses an optional GitHub publication timestamp without reading a clock.
///
/// # Errors
///
/// Returns an error for an invalid source identity or timestamp.
pub fn github_release_timestamp(entry: &Value) -> Result<Option<u64>> {
    let Some(timestamp) = entry.get("published_at").and_then(Value::as_str) else {
        return Ok(None);
    };
    let system_time =
        humantime::parse_rfc3339(timestamp).context("parsing GitHub release publication time")?;
    let seconds = system_time
        .duration_since(UNIX_EPOCH)
        .context("GitHub release publication time predates the Unix epoch")?
        .as_secs();
    Ok(Some(seconds))
}

/// Projects an exact tag prefix without accepting unrelated release families.
pub fn normalized_github_tag<'a>(tag: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        Some(tag)
    } else {
        tag.strip_prefix(prefix)
            .filter(|version| !version.is_empty())
    }
}

fn required_string(value: &Value, field: &str, label: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{label} lacks string field {field}"))
}

/// Validates a provider repository as a safe owner/name identity.
///
/// # Errors
///
/// Returns an error for an invalid source identity or timestamp.
pub fn validate_github_repository(repository: &str) -> Result<()> {
    let mut parts = repository.split('/');
    let owner = parts.next();
    let name = parts.next();
    if owner.is_none_or(|part| part.is_empty() || matches!(part, "." | ".."))
        || name.is_none_or(|part| part.is_empty() || matches!(part, "." | ".."))
        || parts.next().is_some()
        || repository.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        })
    {
        bail!("GitHub repository must use safe owner/name syntax");
    }
    Ok(())
}

/// Encodes a GitHub release tag as one URL path segment.
///
/// # Errors
///
/// Returns an error for an invalid source identity or timestamp.
pub fn github_release_url(repository: &str, tag: &str) -> Result<String> {
    let mut url = Url::parse("https://github.com/")?;
    let mut path = url
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("GitHub URL cannot accept path segments"))?;
    for part in repository.split('/') {
        path.push(part);
    }
    path.push("releases").push("tag").push(tag);
    drop(path);
    Ok(url.to_string())
}

/// Selects current versions and provider-declared newest signals.
pub fn repology_version_is_relevant(
    version: &str,
    status: Option<&str>,
    relevant_versions: &BTreeSet<String>,
) -> bool {
    status == Some("newest") || relevant_versions.contains(version)
}

fn parse_response(bytes: &[u8], label: &str) -> Result<Value> {
    JsonLimits {
        max_bytes: 8 * 1024 * 1024,
        max_depth: 32,
        max_items: 250_000,
        max_string_bytes: 64 * 1024,
    }
    .decode(bytes, label)
}
