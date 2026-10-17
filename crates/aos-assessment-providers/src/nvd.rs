//! NVD CVE API 2.0 page and complete configuration normalization.
//!
//! All environment terms, logical operators, negation and version bounds are
//! retained. Decimal CVSS scores become strings before canonical AOS encoding.

use anyhow::{Context as _, Result, bail};
use aos_assessment::advisory::{ADVISORY_RECORD_V1, AdvisoryRecordV1, AdvisorySeverity};
use aos_assessment::nvd::{Configuration, Operator};
use aos_contract::Sha256Digest;
use serde_json::Value;

use crate::json::parse;
use crate::osv::{array, optional, required};

/// Identifies the admitted NVD CVE 2.0 normalization profile.
pub const ADAPTER_VERSION: &str = "aos-nvd/cve-2.0-v1";

/// Preserves one validated provider page and its exact continuation position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    /// Complete normalized records from the retained raw page.
    pub records: Vec<AdvisoryRecordV1>,
    /// Source's total records for this exact query/window.
    pub total_results: u64,
    /// Next position when this page does not establish exhaustion.
    pub next_start_index: Option<u64>,
}

/// Normalizes a bounded NVD response without prematurely advancing a checkpoint.
///
/// # Errors
///
/// Returns an error for unexpected pagination, invalid or ambiguous records,
/// unsupported wire versions, malformed configuration or resource limits.
pub fn page(bytes: &[u8], requested_start: u64) -> Result<Page> {
    let value = parse(bytes)?;
    if required(&value, "version")? != "2.0" {
        bail!("unsupported NVD response version");
    }
    let start = integer(&value, "startIndex")?;
    let page_size = integer(&value, "resultsPerPage")?;
    let total = integer(&value, "totalResults")?;
    let entries = array(&value, "vulnerabilities")?;
    if start != requested_start
        || entries.len() > 128
        || entries.len() as u64 > page_size
        || start > total
        || page_size > 2000
    {
        bail!("NVD pagination does not match the bounded requested query");
    }
    let next = start
        .checked_add(entries.len() as u64)
        .context("NVD pagination overflow")?;
    if next > total || (next < total && entries.is_empty()) {
        bail!("NVD pagination cannot prove forward progress");
    }
    let source_digest = Sha256Digest::of_bytes(bytes);
    let records = entries
        .iter()
        .map(|entry| {
            normalize(
                entry.get("cve").context("NVD page entry lacks CVE")?,
                source_digest,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Page {
        records,
        total_results: total,
        next_start_index: (next < total).then_some(next),
    })
}

fn normalize(value: &Value, source_digest: Sha256Digest) -> Result<AdvisoryRecordV1> {
    let id = required(value, "id")?;
    if !crate::kev::is_cve_id(id) {
        bail!("NVD record lacks an exact CVE identifier");
    }
    let modified = required(value, "lastModified")?;
    parse_nvd_time(modified)?;
    let withdrawn = (required(value, "vulnStatus")? == "Rejected").then(|| modified.to_owned());
    let configurations = array(value, "configurations")?;
    let configuration = if configurations.is_empty() {
        Configuration::Unsupported {
            reason: "nvd-configurations-unavailable".into(),
        }
    } else {
        Configuration::Expression {
            operator: Operator::Or,
            negate: false,
            children: configurations
                .iter()
                .map(|configuration| configuration_node(configuration, 1))
                .collect::<Result<Vec<_>>>()?,
        }
    };
    let mut severity = Vec::new();
    if let Some(metrics) = value.get("metrics") {
        let metrics = metrics
            .as_object()
            .context("NVD metrics is not an object")?;
        for (scheme, entries) in metrics {
            for entry in entries
                .as_array()
                .context("NVD metric set is not an array")?
            {
                let data = entry
                    .get("cvssData")
                    .context("NVD metric lacks CVSS data")?;
                let base_score = data
                    .get("baseScore")
                    .map(|score| match score {
                        Value::Number(score) => Ok(score.to_string()),
                        Value::String(score) => Ok(score.clone()),
                        _ => bail!("NVD CVSS base score is not decimal"),
                    })
                    .transpose()?;
                severity.push(AdvisorySeverity {
                    source: required(entry, "source")?.into(),
                    scheme: scheme.clone(),
                    value: required(data, "vectorString")?.into(),
                    base_score,
                });
            }
        }
    }
    severity.sort();
    severity.dedup();
    let descriptions = array(value, "descriptions")?;
    let summary = descriptions
        .iter()
        .find(|entry| entry.get("lang").and_then(Value::as_str) == Some("en"))
        .map(|entry| required(entry, "value"))
        .transpose()?
        .unwrap_or(id);
    let mut references = array(value, "references")?
        .iter()
        .map(|entry| required(entry, "url").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    references.sort();
    references.dedup();
    let record = AdvisoryRecordV1 {
        schema: ADVISORY_RECORD_V1.into(),
        provider: "nvd".into(),
        id: id.into(),
        modified: modified.into(),
        withdrawn,
        aliases: vec![],
        related: vec![],
        upstream: vec![],
        summary: crate::sanitized_summary(summary),
        affected: vec![],
        configuration: Some(configuration),
        severity,
        references,
        source_digest,
    };
    record.validate()?;
    if aos_contract::canonical::to_vec(&record)?.len() > 64 * 1024 {
        bail!("normalized NVD record exceeds per-record budget");
    }
    Ok(record)
}

fn configuration_node(value: &Value, depth: usize) -> Result<Configuration> {
    if depth > 10 {
        bail!("NVD source expression exceeds depth budget");
    }
    let operator = match optional(value, "operator")?.as_deref().unwrap_or("OR") {
        "AND" => Operator::And,
        "OR" => Operator::Or,
        _ => {
            return Ok(Configuration::Unsupported {
                reason: "nvd-operator-unsupported".into(),
            });
        }
    };
    let negate = match value.get("negate") {
        None => false,
        Some(value) => value.as_bool().context("NVD negate is not a boolean")?,
    };
    let mut children = Vec::new();
    for entry in array(value, "nodes")?
        .iter()
        .chain(array(value, "children")?)
    {
        children.push(configuration_node(entry, depth + 1)?);
    }
    for entry in array(value, "cpeMatch")? {
        children.push(Configuration::Match {
            criteria: required(entry, "criteria")?.into(),
            vulnerable: entry
                .get("vulnerable")
                .and_then(Value::as_bool)
                .context("NVD term lacks vulnerable association")?,
            version_start_including: optional(entry, "versionStartIncluding")?,
            version_start_excluding: optional(entry, "versionStartExcluding")?,
            version_end_including: optional(entry, "versionEndIncluding")?,
            version_end_excluding: optional(entry, "versionEndExcluding")?,
        });
    }
    if children.is_empty() {
        return Ok(Configuration::Unsupported {
            reason: "nvd-empty-configuration".into(),
        });
    }
    Ok(Configuration::Expression {
        operator,
        negate,
        children,
    })
}

fn integer(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("NVD pagination lacks {field} integer"))
}

fn parse_nvd_time(value: &str) -> Result<()> {
    // NVD's documented UTC modification identity may omit the trailing Z.
    let canonical = if value.ends_with('Z') {
        value.to_owned()
    } else {
        format!("{value}Z")
    };
    humantime::parse_rfc3339(&canonical).context("invalid NVD modification identity")?;
    Ok(())
}
