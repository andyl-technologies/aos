//! Reviewed recurring selections whose executions pin the current inventory.
//!
//! Schedule documents carry package coordinates and operation bounds, never
//! actor credentials. The coordinator retains the original review privately,
//! rechecks current authority, and admits a separate idempotent scan per due slot.

use anyhow::{Result, bail};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::scan::ScanLimits;
use crate::validation::{decode, encoded, sorted, text};

/// Defines one explicitly reviewed, bounded recurring selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleConfigurationV1 {
    /// Exact configuration discriminator.
    pub schema: String,
    /// Sorted exact package coordinates; every current version and platform is selected.
    pub packages: Vec<String>,
    /// Sorted independently evaluated profiles.
    pub profiles: Vec<Profile>,
    /// Explicit acquisition intent, never inferred from reading status.
    pub freshness: FreshnessMode,
    /// Requested interval, from one minute through thirty days.
    pub cadence_seconds: u32,
    /// Exclusive review deadline, additionally limited by the original credential.
    pub review_expires_at: Timestamp,
    /// Per-execution limits, independent of the recurring interval.
    pub limits: ScanLimits,
}

impl ScheduleConfigurationV1 {
    /// Checks closed selectors, finite review and operation ceilings.
    ///
    /// # Errors
    /// Returns an error for invalid schema, duplicate/empty selectors or limits.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-schedule-configuration/v1"
            || self.packages.is_empty()
            || self.packages.len() > 1000
            || self.profiles.is_empty()
            || self.profiles.len() > 3
            || !(60..=2_592_000).contains(&self.cadence_seconds)
        {
            bail!("invalid assessment schedule schema or selection");
        }
        for package in &self.packages {
            text(package, 512, "schedule package coordinate")?;
        }
        sorted(&self.packages, "schedule packages")?;
        sorted(&self.profiles, "schedule profiles")?;
        self.limits.validate()?;
        encoded(self)?;
        Ok(())
    }
}

/// Creates or replaces a reviewed schedule with an exact revision precondition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleWriteV1 {
    /// Exact write discriminator.
    pub schema: String,
    /// Exact non-reusable registry incarnation selected by the reviewer.
    pub resource_scope: String,
    /// Caller-chosen stable identity scoped to the registry.
    pub schedule_id: String,
    /// Zero creates; a positive current revision replaces the complete review.
    pub expected_revision: u64,
    /// Enables due execution; disabling retains the review and audit state.
    pub enabled: bool,
    /// Exact reviewed configuration.
    pub configuration: ScheduleConfigurationV1,
}

impl ScheduleWriteV1 {
    /// Decodes a bounded closed request without accepting principal provenance.
    ///
    /// # Errors
    /// Returns an error for invalid schema, identity, revision or configuration.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment schedule write")?;
        value.validate()?;
        Ok(value)
    }

    /// Validates a complete revision-bound schedule request.
    ///
    /// # Errors
    /// Returns an error for invalid schema, identity, revision or configuration.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-schedule-write/v1"
            || self.expected_revision >= 9_007_199_254_740_991
        {
            bail!("invalid assessment schedule write revision/schema");
        }
        text(&self.resource_scope, 128, "schedule review resource")?;
        text(&self.schedule_id, 128, "schedule identity")?;
        self.configuration.validate()
    }
}

/// Exposes a schedule projection without its private authenticated review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleV1 {
    /// Exact response discriminator.
    pub schema: String,
    /// Registry incarnation independently authorized by the service.
    pub resource_scope: String,
    /// Stable registry-scoped identity.
    pub schedule_id: String,
    /// Current revision required for replacement or disabling.
    pub revision: u64,
    /// Current due-execution setting.
    pub enabled: bool,
    /// Original credential-bounded review deadline.
    pub authority_expires_at: Timestamp,
    /// Durable next due time, including bounded deterministic jitter.
    pub next_due_at: Timestamp,
    /// Exact public reviewed selection.
    pub configuration: ScheduleConfigurationV1,
}

impl ScheduleV1 {
    /// Encodes a bounded public projection without private credential metadata.
    ///
    /// # Errors
    /// Returns an error for inconsistent scope, revision or configuration.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.schema != "aos.assessment-schedule/v1"
            || self.revision == 0
            || self.revision > 9_007_199_254_740_991
        {
            bail!("invalid assessment schedule projection");
        }
        text(&self.resource_scope, 128, "schedule resource")?;
        text(&self.schedule_id, 128, "schedule identity")?;
        self.configuration.validate()?;
        if self.authority_expires_at > self.configuration.review_expires_at {
            bail!("schedule projection exceeds the reviewed authority deadline");
        }
        encoded(self)
    }

    /// Decodes and validates the same response consumed by CLI and web clients.
    ///
    /// # Errors
    /// Returns an error for incompatible or inconsistent projection content.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment schedule")?;
        value.to_bytes()?;
        Ok(value)
    }
}

/// Selects schedule detail or a finite page within an independently authorized registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleQueryV1 {
    /// Exact query discriminator.
    pub schema: String,
    /// Maximum schedules returned, between one and ten.
    pub limit: u32,
    /// Pins the resource incarnation, required for continuation pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Optional exact public identity; cannot be combined with pagination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_id: Option<String>,
    /// Exclusive last public identity from the prior page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_schedule: Option<String>,
}

impl ScheduleQueryV1 {
    /// Decodes a closed finite query without permitting arbitrary selectors.
    ///
    /// # Errors
    /// Returns an error for invalid schema, identity or ambiguous query selection.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, "assessment schedule query")?;
        if value.schema != "aos.assessment-schedule-query/v1"
            || !(1..=10).contains(&value.limit)
            || (value.schedule_id.is_some() && value.after_schedule.is_some())
        {
            bail!("invalid assessment schedule query");
        }
        if value.after_schedule.is_some() && value.resource_scope.is_none() {
            bail!("schedule pagination requires its original resource scope");
        }
        if let Some(scope) = &value.resource_scope {
            text(scope, 128, "schedule query resource")?;
        }
        for identity in value.schedule_id.iter().chain(value.after_schedule.iter()) {
            text(identity, 128, "schedule query identity")?;
        }
        Ok(value)
    }
}

/// Returns a bounded schedule page without private review credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchedulePageV1 {
    /// Exact page discriminator.
    pub schema: String,
    /// Current registry incarnation.
    pub resource_scope: String,
    /// Database time at which this page was assembled.
    pub as_of: Timestamp,
    /// Public projections, in scoped identity digest order.
    pub schedules: Vec<ScheduleV1>,
    /// Exclusive public continuation identity when another schedule exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_schedule: Option<String>,
}

impl SchedulePageV1 {
    /// Encodes a finite page while checking every public schedule projection.
    ///
    /// # Errors
    /// Returns an error for invalid scope, order, projection or aggregate limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.schema != "aos.assessment-schedule-page/v1" || self.schedules.len() > 10 {
            bail!("invalid assessment schedule page");
        }
        text(&self.resource_scope, 128, "schedule page resource")?;
        let mut previous = None;
        for schedule in &self.schedules {
            schedule.to_bytes()?;
            if schedule.resource_scope != self.resource_scope {
                bail!("schedule page mixes resource scopes");
            }
            let key = aos_contract::Sha256Digest::of_canonical(
                "aos.assessment-schedule-key/v1",
                &(&self.resource_scope, &schedule.schedule_id),
            )?;
            if previous.is_some_and(|previous| previous >= key) {
                bail!("schedule page order is invalid");
            }
            previous = Some(key);
        }
        if let Some(next) = &self.next_schedule
            && self
                .schedules
                .last()
                .is_none_or(|schedule| &schedule.schedule_id != next)
        {
            bail!("schedule page cursor differs from its last identity");
        }
        let value = serde_json::to_value(self)?;
        page_limits().check_value(&value, "schedule page")?;
        crate::validation::reject_null(&value)?;
        let mut writer = aos_contract::limits::BoundedWriter::new(
            4 * 1024 * 1024,
            "schedule page exceeds byte limit",
        );
        serde_json::to_writer(&mut writer, self)?;
        aos_contract::canonical::to_vec(&value)
    }

    /// Decodes and validates a bounded page for CLI and web clients.
    ///
    /// # Errors
    /// Returns an error for ambiguous or inconsistent page content or limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = page_limits().decode(bytes, "schedule page")?;
        crate::validation::reject_null(&value)?;
        let page: Self = serde_json::from_value(value)?;
        page.to_bytes()?;
        Ok(page)
    }
}

fn page_limits() -> aos_contract::limits::JsonLimits {
    aos_contract::limits::JsonLimits {
        max_bytes: 4 * 1024 * 1024,
        max_depth: 32,
        max_items: 164_000,
        max_string_bytes: 8192,
    }
}
