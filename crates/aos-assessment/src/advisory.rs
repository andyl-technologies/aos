//! Immutable normalized advisory records and source-scoped snapshots.
//!
//! Raw provider documents remain separate evidence. Normalized records preserve
//! aliases, relationships, withdrawal and unsupported applicability independently.
//! A range event has the closed representation:
//!
//! ```json
//! {"kind":"fixed","version":"1.2.3"}
//! ```

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::observation::ProviderObservationV1;
use crate::security::SecurityIdentity;
use crate::validation::{decode, digest, sorted, text};

/// Identifies the normalized advisory record format.
pub const ADVISORY_RECORD_V1: &str = "aos.advisory-record/v1";

/// Identifies the immutable advisory snapshot format.
pub const ADVISORY_SNAPSHOT_V1: &str = "aos.advisory-snapshot/v1";

/// Retains one source-attributed assertion of known exploitation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KnownExploit {
    /// Exact uppercase CVE identifier.
    pub cve_id: String,
    /// Exact source catalog revision.
    pub catalog_version: String,
    /// Source's exact date of catalog addition.
    pub date_added: String,
    /// Exact retained raw catalog bytes.
    pub source_digest: Sha256Digest,
}

/// Binds a complete supplied exploitation catalog to its freshness observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExploitCatalog {
    /// Exact catalog retrieval/validation/expiry and completeness evidence.
    pub observation: ProviderObservationV1,
    /// Exact source-attributed entries, sorted by CVE and revision.
    pub records: Vec<KnownExploit>,
}

impl ExploitCatalog {
    /// Validates exact source custody, catalog identity and bounded record sets.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/duplicate IDs, dates, custody references,
    /// payload identity, catalog revision conflicts or excessive source scope.
    pub fn validate(&self) -> Result<()> {
        self.observation.validate()?;
        if self.observation.provider != "cisa-kev"
            || self.observation.project != "catalog"
            || self.records.len() > 20_000
        {
            bail!("unsupported or excessive exploitation catalog scope");
        }
        sorted(&self.records, "known-exploitation assertions")?;
        if self
            .records
            .windows(2)
            .any(|pair| pair[0].cve_id == pair[1].cve_id)
        {
            bail!("duplicate exploitation catalog CVE assertion");
        }
        for entry in &self.records {
            if !is_cve_id(&entry.cve_id) || entry.date_added.len() != 10 {
                bail!("invalid exploitation assertion identity/date");
            }
            crate::time::Timestamp::parse(&format!("{}T00:00:00Z", entry.date_added))?;
            text(&entry.catalog_version, 128, "exploitation catalog revision")?;
            if entry.source_digest != self.observation.response_digest {
                bail!("exploitation assertion differs from the retained catalog");
            }
            if self
                .records
                .first()
                .is_some_and(|first| first.catalog_version != entry.catalog_version)
            {
                bail!("exploitation catalog contains conflicting source revisions");
            }
        }
        if self.observation.payload_digest
            != Sha256Digest::of_canonical("aos.known-exploitation-set/v1", &self.records)?
        {
            bail!("exploitation catalog differs from its normalized payload identity");
        }
        Ok(())
    }
}

/// Checks exact CVE grammar without advisory-name or case heuristics.
#[must_use]
pub fn is_cve_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, sequence)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && (4..=20).contains(&sequence.len())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

/// Selects source-defined affected-range semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RangeKind {
    /// Uses OSV Semantic Versioning events.
    Semver,
    /// Uses the explicitly admitted ecosystem comparator.
    Ecosystem,
    /// Requires retained commit ancestry, not chronological ordering.
    Git,
    /// Preserves an unsupported source range without lexical approximation.
    Unsupported,
}

/// Preserves one affected-interval endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "version", rename_all = "kebab-case")]
pub enum RangeEvent {
    /// Starts an inclusive interval; OSV's `0` denotes an unbounded start.
    Introduced(String),
    /// Ends an exclusive interval and identifies an upstream fix.
    Fixed(String),
    /// Ends an inclusive interval without establishing a fix.
    LastAffected(String),
    /// Ends an exclusive interval without establishing a fix.
    Limit(String),
}

/// Binds ordered source events and an optional Git repository.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AffectedRange {
    /// Source range grammar.
    pub kind: RangeKind,
    /// Canonical source repository for Git ranges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Ordered source endpoints, preserved rather than independently sorted.
    pub events: Vec<RangeEvent>,
}

/// Preserves one exact affected-product claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AffectedProduct {
    /// Exact provider identity; API query candidates are checked against it.
    pub identity: SecurityIdentity,
    /// Source's explicit affected versions, sorted and deduplicated by adapter.
    pub versions: Vec<String>,
    /// Source-defined union of intervals.
    pub ranges: Vec<AffectedRange>,
    /// Unsupported constraints retained as an explicit applicability limitation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported: Vec<String>,
}

/// Retains a source-attributed score/vector without canonical JSON floats.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisorySeverity {
    /// Source profile or CNA supplying this score.
    pub source: String,
    /// Versioned scoring scheme, such as CVSS_V3.
    pub scheme: String,
    /// Exact source vector/score text; unsupported schemes remain visible.
    pub value: String,
    /// Optional decimal base score; absence is not low severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_score: Option<String>,
}

/// Retains a complete normalized revision of one provider-native advisory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryRecordV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Installed source profile.
    pub provider: String,
    /// Exact native advisory identifier.
    pub id: String,
    /// Exact source modification identity, including provider precision.
    pub modified: String,
    /// Optional authoritative source withdrawal identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
    /// Equivalent identifiers only; never related/upstream identifiers.
    pub aliases: Vec<String>,
    /// Non-equivalent related advisories.
    pub related: Vec<String>,
    /// Non-equivalent upstream relationships.
    pub upstream: Vec<String>,
    /// Sanitized bounded source summary.
    pub summary: String,
    /// Product claims under the source's original version semantics.
    pub affected: Vec<AffectedProduct>,
    /// Complete NVD configuration expression, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<crate::nvd::Configuration>,
    /// Source-attributed severity entries, sorted and unique.
    pub severity: Vec<AdvisorySeverity>,
    /// Credential-free source links, sorted and unique.
    pub references: Vec<String>,
    /// Exact retained raw record bytes.
    pub source_digest: Sha256Digest,
}

impl AdvisoryRecordV1 {
    /// Decodes and validates one bounded normalized revision.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, ambiguous, excessive or incompatible data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let record: Self = decode(bytes, "advisory record")?;
        record.validate()?;
        Ok(record)
    }

    /// Validates normalized structure without authorizing its origin.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, unordered sets, malformed range
    /// sequences, unsafe links, oversized records or unsupported wire schemas.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ADVISORY_RECORD_V1 {
            bail!("unsupported advisory record schema");
        }
        text(&self.provider, 128, "advisory provider")?;
        text(&self.id, 128, "advisory identifier")?;
        text(&self.modified, 128, "advisory modification identity")?;
        text(&self.summary, 4096, "advisory summary")?;
        if let Some(value) = &self.withdrawn {
            text(value, 128, "advisory withdrawal identity")?;
        }
        for (label, values) in [
            ("advisory aliases", &self.aliases),
            ("related advisories", &self.related),
            ("upstream advisories", &self.upstream),
        ] {
            if values.len() > 128 {
                bail!("advisory identifier set exceeds limit");
            }
            sorted(values, label)?;
            for value in values {
                text(value, 128, label)?;
            }
        }
        if self.affected.len() > 128 || self.severity.len() > 64 || self.references.len() > 128 {
            bail!("advisory normalized scope exceeds limit");
        }
        for product in &self.affected {
            product.validate()?;
        }
        if let Some(configuration) = &self.configuration {
            configuration.validate()?;
        }
        sorted(&self.severity, "advisory severity")?;
        for severity in &self.severity {
            text(&severity.source, 128, "severity source")?;
            text(&severity.scheme, 128, "severity scheme")?;
            text(&severity.value, 4096, "severity value")?;
            if let Some(score) = &severity.base_score {
                validate_decimal_score(score)?;
            }
        }
        sorted(&self.references, "advisory references")?;
        for reference in &self.references {
            text(reference, 2048, "advisory link")?;
            let url = url::Url::parse(reference)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                bail!("advisory reference is not a safe public link");
            }
        }
        Ok(())
    }

    /// Computes a domain-separated identity for this exact revision.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure or canonical resource bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(ADVISORY_RECORD_V1, self)
    }
}

impl AffectedProduct {
    /// Validates source applicability without supplying a missing comparator.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, excessive/ambiguous versions or
    /// invalid interval endpoint sequences.
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        if self.versions.len() > 2048 || self.ranges.len() > 128 || self.unsupported.len() > 128 {
            bail!("affected product scope exceeds limit");
        }
        sorted(&self.versions, "explicit affected versions")?;
        sorted(&self.unsupported, "unsupported applicability constraints")?;
        for value in self.versions.iter().chain(&self.unsupported) {
            text(value, 512, "affected version/constraint")?;
        }
        for range in &self.ranges {
            range.validate()?;
        }
        Ok(())
    }
}

impl AffectedRange {
    /// Checks ordered endpoint structure, retaining unsupported range semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/excessive ranges, malformed endpoint order or
    /// missing/unexpected repository binding.
    pub fn validate(&self) -> Result<()> {
        if self.events.is_empty() || self.events.len() > 256 {
            bail!("advisory range requires bounded endpoints");
        }
        if (self.kind == RangeKind::Git) != self.repository.is_some() {
            bail!("Git advisory range requires an explicit repository");
        }
        if let Some(repository) = &self.repository {
            text(repository, 2048, "range repository")?;
        }
        let mut open = false;
        for event in &self.events {
            match event {
                RangeEvent::Introduced(version) => {
                    if open {
                        bail!("advisory range contains overlapping interval starts");
                    }
                    text(version, 256, "introduced version")?;
                    open = true;
                }
                RangeEvent::Fixed(version)
                | RangeEvent::LastAffected(version)
                | RangeEvent::Limit(version) => {
                    if !open {
                        bail!("advisory range closes an interval without a start");
                    }
                    text(version, 256, "interval endpoint")?;
                    open = false;
                }
            }
        }
        Ok(())
    }
}

/// Records one source's exact snapshot coverage and freshness evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisorySnapshotSource {
    /// Installed source profile.
    pub provider: String,
    /// Query/product identity; coverage cannot leak between queries.
    pub project: String,
    /// Exact immutable observation for this query.
    pub observation: ProviderObservationV1,
    /// Sorted normalized record identities admitted from that observation.
    pub record_digests: Vec<Sha256Digest>,
}

/// Binds every source query to exact advisory revisions and observation coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisorySnapshotV1 {
    /// Exact schema discriminator.
    pub schema: String,
    /// Sources strictly ordered by provider and project.
    pub sources: Vec<AdvisorySnapshotSource>,
    /// Optional retained exploitation catalog; absence is never non-exploitation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_catalog: Option<ExploitCatalog>,
}

impl AdvisorySnapshotV1 {
    /// Validates query partitioning, record sets and immutable observations.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid schema, excessive/duplicate query scopes,
    /// unordered record identities or inconsistent source/observation bindings.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ADVISORY_SNAPSHOT_V1 || self.sources.len() > 100_000 {
            bail!("unsupported or excessive advisory snapshot");
        }
        if let Some(catalog) = &self.exploit_catalog {
            catalog.validate()?;
        }
        let mut previous = None;
        for source in &self.sources {
            let key = (&source.provider, &source.project);
            if previous.is_some_and(|previous| previous >= key) {
                bail!("snapshot queries must be sorted and unique");
            }
            previous = Some(key);
            source.observation.validate()?;
            if source.provider != source.observation.provider
                || source.project != source.observation.project
            {
                bail!("snapshot source differs from its admitted observation");
            }
            if source.record_digests.len() > 100_000 {
                bail!("snapshot query exceeds bounded record count");
            }
            sorted(&source.record_digests, "snapshot advisory records")?;
            if Sha256Digest::of_canonical("aos.advisory-record-set/v1", &source.record_digests)?
                != source.observation.payload_digest
            {
                bail!("snapshot record set does not match its observation payload");
            }
        }
        Ok(())
    }

    /// Computes the exact immutable source/query snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid structure or canonical resource bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        digest(ADVISORY_SNAPSHOT_V1, self)
    }

    /// Decodes a bounded snapshot before evaluation or admission.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid wire or snapshot structure.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = decode(bytes, "advisory snapshot")?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}

fn validate_decimal_score(value: &str) -> Result<()> {
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(
        integer,
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10"
    ) || fraction.len() > 1
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (value.contains('.') && fraction.is_empty())
        || (integer == "10" && !matches!(fraction, "" | "0"))
    {
        bail!("invalid decimal CVSS base score");
    }
    Ok(())
}
