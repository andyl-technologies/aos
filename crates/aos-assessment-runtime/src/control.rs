//! Closed scan controls shared by local journals, Hub APIs and their clients.
//!
//! Callers pin inventory and policy, while the authenticated host supplies the
//! resource and actor identities. A retry names its original terminal operation;
//! it does not silently reselect packages from a changed inventory.

use anyhow::{Result, bail};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::scan::{SCAN_REQUEST_V1, ScanLimits, ScanRequestV1, ScanState};
use crate::validation::{decode, encoded, text};

/// Carries caller-controlled selection without accepting caller-supplied authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanSubmissionV1 {
    /// Exact submission discriminator.
    pub schema: String,
    /// Current inventory revision, pinned before requesting work.
    pub inventory_revision: u64,
    /// Exact immutable inventory selected by the caller.
    pub inventory_digest: Sha256Digest,
    /// Exact policy selected by the caller.
    pub policy_digest: Sha256Digest,
    /// Sorted exact subjects; an empty selector never means all packages.
    pub subjects: Vec<String>,
    /// Sorted explicit assessment profiles.
    pub profiles: Vec<Profile>,
    /// Explicit source acquisition intent.
    pub freshness: FreshnessMode,
    /// Caller key scoped to the authenticated actor and resource.
    pub idempotency_key: String,
    /// Effective ceilings, which deployment policy may further restrict.
    pub limits: ScanLimits,
}

impl ScanSubmissionV1 {
    /// Decodes and validates a bounded submission before durable admission.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, incompatible schemas or invalid scope.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan submission")?;
        value.bind("validation", "validation", "validation")?;
        Ok(value)
    }

    /// Binds selection to independently authenticated host identities.
    ///
    /// # Errors
    /// Returns an error for invalid selection, schema, authority or operation limits.
    pub fn bind(
        &self,
        resource_scope: &str,
        partition: &str,
        actor_ref: &str,
    ) -> Result<ScanRequestV1> {
        if self.schema != "aos.assessment-scan-submission/v1" {
            bail!("unsupported assessment scan submission schema");
        }
        let request = ScanRequestV1 {
            schema: SCAN_REQUEST_V1.into(),
            resource_scope: resource_scope.into(),
            authorization_partition: partition.into(),
            inventory_revision: self.inventory_revision,
            inventory_digest: self.inventory_digest,
            policy_digest: self.policy_digest,
            subjects: self.subjects.clone(),
            profiles: self.profiles.clone(),
            freshness: self.freshness,
            trigger: "manual".into(),
            actor_ref: actor_ref.into(),
            idempotency_key: self.idempotency_key.clone(),
            limits: self.limits.clone(),
        };
        request.validate()?;
        Ok(request)
    }
}

/// Selects one operation without granting access through possession of its ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanLookupV1 {
    /// Exact lookup discriminator.
    pub schema: String,
    /// Operation identity within the independently authorized resource.
    pub scan_id: String,
}

impl ScanLookupV1 {
    /// Decodes an exact operation lookup.
    ///
    /// # Errors
    /// Returns an error for incompatible, ambiguous or invalid operation references.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan lookup")?;
        if value.schema != "aos.assessment-scan-lookup/v1" {
            bail!("unsupported assessment scan lookup schema");
        }
        text(&value.scan_id, 128, "assessment scan identity")?;
        Ok(value)
    }
}

/// Cancels one exact revision without altering prior assessment evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanCancellationV1 {
    /// Exact cancellation discriminator.
    pub schema: String,
    /// Operation within the independently authorized resource.
    pub scan_id: String,
    /// Required current revision; a lost race is a conflict.
    pub expected_revision: u64,
}

impl ScanCancellationV1 {
    /// Decodes a revision-bound cancellation.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, incompatible schemas or invalid revisions.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan cancellation")?;
        if value.schema != "aos.assessment-scan-cancellation/v1"
            || value.expected_revision == 0
            || value.expected_revision > 9_007_199_254_740_991
        {
            bail!("invalid assessment scan cancellation revision/schema");
        }
        text(&value.scan_id, 128, "assessment scan identity")?;
        Ok(value)
    }
}

/// Requests a distinct operation linked to one original terminal request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanRetryV1 {
    /// Exact retry discriminator.
    pub schema: String,
    /// Original terminal operation whose immutable selection is retained.
    pub scan_id: String,
    /// New actor-scoped key for the retry.
    pub idempotency_key: String,
}

impl ScanRetryV1 {
    /// Decodes one explicit retry without permitting selector or allowance changes.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, incompatible schemas or invalid references.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan retry")?;
        if value.schema != "aos.assessment-scan-retry/v1" {
            bail!("unsupported assessment scan retry schema");
        }
        text(&value.scan_id, 128, "assessment scan identity")?;
        text(&value.idempotency_key, 128, "assessment retry key")?;
        Ok(value)
    }
}

/// Selects a finite operation page in stable operation-identity order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanListQueryV1 {
    /// Exact list discriminator.
    pub schema: String,
    /// Maximum summaries, between one and one hundred.
    pub limit: u32,
    /// Opaque hosted page token or exclusive local operation position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_scan: Option<String>,
}

impl ScanListQueryV1 {
    /// Decodes and validates a bounded operation selector.
    ///
    /// # Errors
    /// Returns an error for incompatible schemas, ambiguous data or invalid limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan list query")?;
        if value.schema != "aos.assessment-scan-list-query/v1" || !(1..=100).contains(&value.limit)
        {
            bail!("invalid assessment scan list schema/limit");
        }
        if let Some(position) = &value.after_scan {
            text(position, 128, "assessment scan position")?;
        }
        Ok(value)
    }
}

/// Describes a compact operation without duplicating its full immutable selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanSummary {
    /// Public operation reference.
    pub scan_id: String,
    /// Exact immutable request available through operation detail.
    pub request_digest: Sha256Digest,
    /// Current execution state, independently of finding severity.
    pub state: ScanState,
    /// Desired generation allocated at admission.
    pub generation: u64,
    /// Current revision used by cancellation.
    pub resource_version: u64,
    /// Admission time from the durable journal's clock.
    pub created_at: Timestamp,
    /// Retained result for complete or partial execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
}

/// Returns a bounded operation page without implying chronological UUID ordering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanListV1 {
    /// Exact list response discriminator.
    pub schema: String,
    /// Authorized resource incarnation.
    pub resource_scope: String,
    /// Time at which this page was assembled.
    pub as_of: Timestamp,
    /// Summaries strictly ordered by operation identity.
    pub scans: Vec<ScanSummary>,
    /// Hosted snapshot token or local position, present only when more rows exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_scan: Option<String>,
}

impl ScanListV1 {
    /// Serializes one bounded, ordered operation page.
    ///
    /// # Errors
    /// Returns an error for invalid identities, inconsistent result state or ordering.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encoded(self)
    }

    /// Decodes the same closed operation page used by CLI and web adapters.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON or inconsistent page content.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "scan list")?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-scan-list/v1" || self.scans.len() > 100 {
            bail!("invalid assessment scan list schema/size");
        }
        text(&self.resource_scope, 128, "assessment resource")?;
        if self
            .scans
            .windows(2)
            .any(|pair| pair[0].scan_id >= pair[1].scan_id)
        {
            bail!("assessment scan list is not sorted and unique");
        }
        for scan in &self.scans {
            text(&scan.scan_id, 128, "assessment scan identity")?;
            if scan.generation == 0
                || scan.generation > 9_007_199_254_740_991
                || scan.resource_version == 0
                || scan.resource_version > 9_007_199_254_740_991
                || matches!(scan.state, ScanState::Succeeded | ScanState::Partial)
                    != scan.assessment_digest.is_some()
            {
                bail!("assessment scan summary has inconsistent state/revision");
            }
        }
        if let Some(next) = &self.next_scan
            && self.scans.last().is_none_or(|scan| &scan.scan_id != next)
        {
            crate::read_snapshot::parse_scan_cursor(next)?;
            if self.scans.is_empty() {
                bail!("empty scan page cannot have a continuation");
            }
        }
        Ok(())
    }
}
