//! OSV 1.9.1 query construction, pagination and immutable record normalization.
//!
//! Batch positions remain associated with their original typed queries. Full
//! records are normalized separately from query IDs; receiving IDs does not
//! establish that the corresponding records have been acquired successfully.

use anyhow::{Context as _, Result, bail};
use aos_assessment::advisory::{
    ADVISORY_RECORD_V1, AdvisoryRecordV1, AdvisorySeverity, AffectedProduct, AffectedRange,
    RangeEvent, RangeKind,
};
use aos_assessment::security::SecurityIdentity;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::json::parse;

/// Identifies the admitted OSV API/schema normalization profile.
pub const ADAPTER_VERSION: &str = "aos-osv/1.9.1-v1";

/// Binds an exact OSV query without allowing arbitrary URLs or executable hooks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Query {
    /// Queries a named package in the provider's exact ecosystem.
    Ecosystem {
        /// Exact provider ecosystem spelling.
        ecosystem: String,
        /// Exact upstream package name.
        name: String,
        /// Assessed upstream version.
        version: String,
    },
    /// Queries a canonical Package URL, including its version if present.
    Purl {
        /// Exact Package URL; no duplicate separate version is sent.
        value: String,
    },
    /// Queries an immutable full Git commit under the OSV commit API.
    Git {
        /// Exact full hexadecimal commit.
        commit: String,
    },
}

impl Query {
    /// Constructs a provider request after validating the identity and version.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, control-bearing/oversized
    /// versions, commits or page tokens. No URL is accepted as a page token.
    pub fn request(&self, page_token: Option<&str>) -> Result<Value> {
        let mut request = match self {
            Self::Ecosystem {
                ecosystem,
                name,
                version,
            } => {
                SecurityIdentity::Ecosystem {
                    ecosystem: ecosystem.clone(),
                    name: name.clone(),
                }
                .validate()?;
                bounded(version, 256)?;
                json!({"package":{"ecosystem":ecosystem,"name":name},"version":version})
            }
            Self::Purl { value } => {
                SecurityIdentity::Purl {
                    value: value.clone(),
                }
                .validate()?;
                json!({"package":{"purl":value}})
            }
            Self::Git { commit } => {
                if !matches!(commit.len(), 40 | 64)
                    || !commit
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    bail!("OSV commit query requires a full lowercase immutable commit");
                }
                json!({"commit":commit})
            }
        };
        if let Some(token) = page_token {
            bounded(token, 4096)?;
            request["page_token"] = json!(token);
        }
        Ok(request)
    }

    /// Computes a public, credential-free query identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid query fields or canonical serialization.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical("aos.osv-query/v1", &self.request(None)?)
    }
}

/// Preserves one query page's IDs, modification identities and continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPage {
    /// Source-native advisory IDs and exact source modification identities.
    pub records: Vec<(String, String)>,
    /// This query's continuation; an absent token proves only page exhaustion.
    pub next_page_token: Option<String>,
}

/// Parses a single OSV query response without losing its continuation.
///
/// # Errors
///
/// Returns an error for malformed, ambiguous or excessive response data.
pub fn query_page(bytes: &[u8]) -> Result<QueryPage> {
    page(&parse(bytes)?)
}

/// Parses a batch response while enforcing exact positional correspondence.
///
/// # Errors
///
/// Returns an error for malformed pages, more than 64 queries, or an unexpected
/// number of response positions. Each returned position has its own token.
pub fn batch_pages(bytes: &[u8], expected_queries: usize) -> Result<Vec<QueryPage>> {
    if expected_queries == 0 || expected_queries > 64 {
        bail!("OSV batch query scope exceeds admitted bound");
    }
    let value = parse(bytes)?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .context("OSV batch lacks result positions")?;
    if results.len() != expected_queries {
        bail!("OSV batch positions do not match requested query count");
    }
    results.iter().map(page).collect()
}

/// Normalizes one complete OSV record, preserving source revision identity.
///
/// # Errors
///
/// Returns an error for malformed/ambiguous source fields, unsupported schema
/// major versions, invalid identities/events, unsafe links or normalized bounds.
pub fn record(bytes: &[u8]) -> Result<AdvisoryRecordV1> {
    let value = parse(bytes)?;
    let schema = value
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or("1.0.0");
    let schema_parts = schema.split('.').collect::<Vec<_>>();
    if schema_parts.len() != 3
        || schema_parts[0] != "1"
        || schema_parts.iter().any(|part| part.parse::<u32>().is_err())
    {
        bail!("unsupported OSV schema profile");
    }
    let id = required(&value, "id")?;
    let modified = required(&value, "modified")?;
    humantime::parse_rfc3339(modified).context("invalid OSV modification time")?;
    let withdrawn = optional(&value, "withdrawn")?;
    if let Some(withdrawn) = &withdrawn {
        humantime::parse_rfc3339(withdrawn).context("invalid OSV withdrawal time")?;
    }
    let mut affected = Vec::new();
    let mut severity = severities(&value, "osv")?;
    for (index, entry) in array(&value, "affected")?.iter().enumerate() {
        let package = entry
            .get("package")
            .context("OSV affected product lacks package")?;
        let identity = match (
            package.get("ecosystem").and_then(Value::as_str),
            package.get("name").and_then(Value::as_str),
        ) {
            (Some(ecosystem), Some(name)) => SecurityIdentity::Ecosystem {
                ecosystem: ecosystem.into(),
                name: name.into(),
            },
            _ => SecurityIdentity::Purl {
                value: required(package, "purl")?.into(),
            },
        };
        let mut ranges = Vec::new();
        let mut unsupported = Vec::new();
        for source in array(entry, "ranges")? {
            let kind = match required(source, "type")? {
                "SEMVER" => RangeKind::Semver,
                "ECOSYSTEM" => RangeKind::Ecosystem,
                "GIT" => RangeKind::Git,
                _ => RangeKind::Unsupported,
            };
            let mut events = Vec::new();
            let mut unsupported_event = false;
            for event in array(source, "events")? {
                let fields = event
                    .as_object()
                    .context("OSV range event is not an object")?;
                if fields.len() != 1 {
                    bail!("OSV range event requires exactly one endpoint");
                }
                let (kind, version) = fields.iter().next().context("OSV range event is empty")?;
                let version = version
                    .as_str()
                    .context("OSV range endpoint is not text")?
                    .to_owned();
                events.push(match kind.as_str() {
                    "introduced" => RangeEvent::Introduced(version),
                    "fixed" => RangeEvent::Fixed(version),
                    "last_affected" => RangeEvent::LastAffected(version),
                    "limit" => RangeEvent::Limit(version),
                    _ => {
                        unsupported.push("range-event-unsupported".into());
                        unsupported_event = true;
                        continue;
                    }
                });
            }
            if unsupported_event {
                continue;
            }
            if events.is_empty() {
                unsupported.push("range-events-unavailable".into());
            } else {
                ranges.push(AffectedRange {
                    kind,
                    repository: optional(source, "repo")?,
                    events,
                });
            }
        }
        if entry
            .get("ecosystem_specific")
            .is_some_and(|specific| !specific.as_object().is_some_and(|object| object.is_empty()))
        {
            unsupported.push("ecosystem-specific-constraints".into());
        }
        unsupported.sort();
        unsupported.dedup();
        affected.push(AffectedProduct {
            identity,
            versions: strings(entry, "versions")?,
            ranges,
            unsupported,
        });
        severity.extend(severities(entry, &format!("osv:affected:{index}"))?);
    }
    severity.sort();
    severity.dedup();
    let mut references = array(&value, "references")?
        .iter()
        .map(|reference| required(reference, "url").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    references.sort();
    references.dedup();
    let record = AdvisoryRecordV1 {
        schema: ADVISORY_RECORD_V1.into(),
        provider: "osv".into(),
        id: id.into(),
        modified: modified.into(),
        withdrawn,
        aliases: strings(&value, "aliases")?,
        related: strings(&value, "related")?,
        upstream: strings(&value, "upstream")?,
        summary: crate::sanitized_summary(optional(&value, "summary")?.as_deref().unwrap_or(id)),
        affected,
        configuration: None,
        severity,
        references,
        source_digest: Sha256Digest::of_bytes(bytes),
    };
    record.validate()?;
    if aos_contract::canonical::to_vec(&record)?.len() > 64 * 1024 {
        bail!("normalized OSV record exceeds per-record budget");
    }
    Ok(record)
}

fn page(value: &Value) -> Result<QueryPage> {
    let records = array(value, "vulns")?
        .iter()
        .map(|record| {
            Ok((
                required(record, "id")?.into(),
                required(record, "modified")?.into(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if records.len() > 128 {
        bail!("OSV query page exceeds admitted record budget");
    }
    let next_page_token = optional(value, "next_page_token")?.filter(|token| !token.is_empty());
    if let Some(token) = &next_page_token {
        bounded(token, 4096)?;
    }
    Ok(QueryPage {
        records,
        next_page_token,
    })
}

fn severities(value: &Value, source: &str) -> Result<Vec<AdvisorySeverity>> {
    array(value, "severity")?
        .iter()
        .map(|entry| {
            Ok(AdvisorySeverity {
                source: optional(entry, "source")?.unwrap_or_else(|| source.into()),
                scheme: required(entry, "type")?.into(),
                value: required(entry, "score")?.into(),
                base_score: None,
            })
        })
        .collect()
}

pub(crate) fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("provider record lacks required {field} text"))
}

pub(crate) fn optional(value: &Value, field: &str) -> Result<Option<String>> {
    match value.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.into()))
            .ok_or_else(|| anyhow::anyhow!("invalid provider {field} text")),
    }
}

pub(crate) fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    match value.get(field) {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow::anyhow!("invalid provider {field} array")),
    }
}

fn strings(value: &Value, field: &str) -> Result<Vec<String>> {
    let mut values = array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .context("provider identifier list contains non-text member")
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

fn bounded(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("invalid bounded OSV query text");
    }
    Ok(())
}
