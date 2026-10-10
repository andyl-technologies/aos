//! Shared status and operation contracts for Hub and local assessment clients.
//!
//! Canonical inner documents preserve identical domain data across CLI, Connect
//! and web adapters. Numeric database IDs, secret references and raw source
//! response bytes do not appear in this application projection.

use anyhow::{Result, bail};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::scan::{ScanRequestV1, ScanState, ScanUsage};
use crate::validation::{decode, encoded, sorted, text};

/// Selects a bounded read of the current inventory without provider effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusQueryV1 {
    /// Exact status selector discriminator.
    pub schema: String,
    /// Sorted independent profiles to inspect.
    pub profiles: Vec<Profile>,
    /// Maximum subjects on this page, between one and one hundred.
    pub limit: u32,
    /// Exclusive subject position in the exact inventory and policy below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_subject: Option<String>,
    /// Required exact inventory for every continuation page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_digest: Option<Sha256Digest>,
    /// Required exact decision policy for every continuation page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Sha256Digest>,
}

impl StatusQueryV1 {
    /// Decodes and validates one bounded read selector.
    ///
    /// # Errors
    /// Returns an error for incompatible, ambiguous, unknown/null-bearing,
    /// excessive or unbound continuation data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "assessment status query")?;
        query.validate()?;
        Ok(query)
    }

    /// Validates profile order, page limits and exact continuation context.
    ///
    /// # Errors
    /// Returns an error for incompatible schemas, invalid profiles/page limits
    /// or a cursor without its exact inventory and policy identities.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-status-query/v1"
            || self.limit == 0
            || self.limit > 100
            || self.profiles.is_empty()
            || self.profiles.len() > 3
        {
            bail!("assessment status selector exceeds its closed profile/page limits");
        }
        sorted(&self.profiles, "status profiles")?;
        if let Some(subject) = &self.after_subject {
            text(subject, 128, "status subject position")?;
            if self.inventory_digest.is_none() || self.policy_digest.is_none() {
                bail!("assessment status cursor lacks its exact inventory/policy context");
            }
        }
        Ok(())
    }
}

/// Describes one independently fresh or pending profile for an exact subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProfileStatus {
    /// Requested independent assessment profile.
    pub profile: Profile,
    /// Latest requested generation, zero when unassessed.
    pub desired_generation: u64,
    /// Latest committed generation, zero when unassessed.
    pub committed_generation: u64,
    /// Exact retained result, absent when unassessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
    /// Exact frozen input, absent when unassessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<Sha256Digest>,
    /// Exclusive freshness boundary, absent for incomplete evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_until: Option<Timestamp>,
    /// Effective complete freshness at the status page's explicit time.
    pub fresh: bool,
    /// Whether a newer desired generation still has an active scan.
    pub pending: bool,
}

/// Groups profile status under one portable inventory subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubjectStatus {
    /// Exact subject within this page's immutable inventory.
    pub subject_ref: String,
    /// Exact publisher-scoped package coordinate from the admitted inventory.
    pub package_coordinate: String,
    /// Exact AOS package version from this immutable inventory.
    pub version: String,
    /// Exact target platform from this immutable inventory.
    pub platform: String,
    /// Exact package output or aggregate name.
    pub output: String,
    /// Selected profiles in canonical order.
    pub profiles: Vec<ProfileStatus>,
}

/// Carries one inventory-complete status page independently of its transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentStatusV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Non-reusable resource scope independently authorized by the service.
    pub resource_scope: String,
    /// Exact immutable inventory used for this page.
    pub inventory_digest: Sha256Digest,
    /// Monotonic admission revision used when requesting a scan of this inventory.
    pub inventory_revision: u64,
    /// Exact decision policy used for this page.
    pub policy_digest: Sha256Digest,
    /// Database time used for all freshness decisions in this page.
    pub as_of: Timestamp,
    /// Installed source reservation availability; absent when not reported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_status: Vec<crate::source_status::SourceStatus>,
    /// Bounded subject status, including unassessed admitted members.
    pub subjects: Vec<SubjectStatus>,
    /// Exclusive next position, always bound to inventory/policy on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_subject: Option<String>,
}

impl AssessmentStatusV1 {
    /// Serializes the bounded canonical status projection for every client.
    ///
    /// # Errors
    /// Returns an error for invalid schemas, subject order, inconsistent
    /// freshness/pending projections or encoded envelope limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encoded(self)
    }

    /// Decodes the same bounded closed status projection consumed by local clients.
    ///
    /// # Errors
    /// Returns an error for ambiguous, incompatible, excessive or inconsistent data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let status: Self = decode(bytes, "assessment status")?;
        status.validate()?;
        Ok(status)
    }

    fn validate(&self) -> Result<()> {
        if self.source_status.len() > crate::source_status::SOURCE_PROFILES.len()
            || self
                .source_status
                .windows(2)
                .any(|pair| pair[0].provider >= pair[1].provider)
        {
            bail!("assessment source status is not a bounded canonical profile set");
        }
        for source in &self.source_status {
            source.validate(&self.as_of)?;
        }
        if self.schema != "aos.assessment-status/v1"
            || self.subjects.len() > 100
            || self.inventory_revision == 0
            || self.inventory_revision > 9_007_199_254_740_991
        {
            bail!("assessment status exceeds its closed page limits");
        }
        text(&self.resource_scope, 128, "assessment resource scope")?;
        if self
            .subjects
            .windows(2)
            .any(|pair| pair[0].subject_ref >= pair[1].subject_ref)
        {
            bail!("assessment status subjects are not sorted and unique");
        }
        for subject in &self.subjects {
            text(&subject.subject_ref, 128, "assessment status subject")?;
            text(
                &subject.package_coordinate,
                1024,
                "assessment status package",
            )?;
            text(&subject.version, 256, "assessment status version")?;
            text(&subject.platform, 128, "assessment status platform")?;
            text(&subject.output, 128, "assessment status output")?;
            if subject.profiles.is_empty()
                || subject.profiles.len() > 3
                || subject
                    .profiles
                    .windows(2)
                    .any(|pair| pair[0].profile >= pair[1].profile)
            {
                bail!("assessment subject status has invalid profiles");
            }
            for profile in &subject.profiles {
                if profile.desired_generation > 9_007_199_254_740_991
                    || profile.committed_generation > profile.desired_generation
                    || (profile.pending
                        && profile.desired_generation <= profile.committed_generation)
                    || profile.fresh
                        != profile
                            .validated_until
                            .as_ref()
                            .is_some_and(|deadline| &self.as_of < deadline)
                    || (profile.committed_generation > 0) != profile.assessment_digest.is_some()
                    || profile.assessment_digest.is_some() != profile.input_digest.is_some()
                    || (profile.validated_until.is_some() && profile.assessment_digest.is_none())
                {
                    bail!("assessment profile status has inconsistent generation or freshness");
                }
            }
        }
        if let Some(next) = &self.next_subject
            && self
                .subjects
                .last()
                .is_none_or(|subject| &subject.subject_ref != next)
        {
            bail!("assessment status cursor differs from its exact last subject");
        }
        Ok(())
    }
}

/// Returns a durable scan receipt with no raw source or credential contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanReceiptV1 {
    /// Optional stable terminal diagnostic without raw exception or source detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    /// Exact receipt discriminator.
    pub schema: String,
    /// Unpredictable durable operation identity.
    pub scan_id: String,
    /// Immutable request retained under independently checked actor authority.
    pub request: ScanRequestV1,
    /// Exact request association, unchanged on retries or reads.
    pub request_digest: Sha256Digest,
    /// Desired profile generation allocated by the journal.
    pub generation: u64,
    /// Current runtime state, independent of package risk and evidence coverage.
    pub state: ScanState,
    /// Whether every requested target was admitted before work begins.
    pub admission_complete: bool,
    /// Conservative usage, including uncertain physical attempts.
    pub usage: ScanUsage,
    /// Database admission time.
    pub created_at: Timestamp,
    /// Current optimistic operation revision.
    pub resource_version: u64,
    /// Exact committed result when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
}

impl ScanReceiptV1 {
    /// Serializes one exact bounded canonical scan receipt.
    ///
    /// # Errors
    /// Returns an error for malformed identities, mismatched request content,
    /// invalid revisions or encoded envelope bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encoded(self)
    }

    /// Decodes and verifies one bounded immutable scan receipt.
    ///
    /// # Errors
    /// Returns an error for ambiguous, unknown/null-bearing or inconsistent data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let receipt: Self = decode(bytes, "assessment scan receipt")?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<()> {
        self.usage
            .consume(&ScanUsage::default(), &self.request.limits)?;
        if let Some(code) = &self.failure_code
            && (!matches!(
                self.state,
                ScanState::Failed | ScanState::Superseded | ScanState::Cancelled
            ) || code.is_empty()
                || code.len() > 128
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        {
            bail!("assessment receipt has an invalid terminal diagnostic");
        }
        if self.schema != "aos.assessment-scan-receipt/v1"
            || self.request.digest()? != self.request_digest
            || self.generation == 0
            || self.resource_version == 0
            || self.generation > 9_007_199_254_740_991
            || self.resource_version > 9_007_199_254_740_991
            || matches!(self.state, ScanState::Succeeded | ScanState::Partial)
                != self.assessment_digest.is_some()
        {
            bail!("assessment scan receipt differs from its exact immutable request/state");
        }
        text(&self.scan_id, 128, "assessment scan identity")
    }
}
