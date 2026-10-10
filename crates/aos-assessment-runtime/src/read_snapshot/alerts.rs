//! Immutable alert episode pages independent of current attention mutations.
//!
//! A capture retains original issue revisions, acknowledgement history and its
//! observation time. Current access is checked separately on each continuation.
//!
//! ```json
//! {"schema":"aos.assessment-alert-read-snapshot/v1",
//!  "resourceScope":"registry-incarnation","limit":10,
//!  "asOf":"2026-10-10T12:00:00Z","expiresAt":"2026-10-10T12:15:00Z",
//!  "alerts":[],"pageHandles":[]}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use super::{ScanPageError, parse_cursor, validate_handle};
use crate::alerts::AssessmentAlertV1;
use crate::attention_control::AlertPageV1;
use crate::validation::{reject_null, text};

/// Identifies immutable alert episode captures.
pub const ALERT_READ_SNAPSHOT_V1: &str = "aos.assessment-alert-read-snapshot/v1";

/// Bounds the number of complete alert records acquired for one capture.
pub const MAX_CAPTURE_ALERTS: usize = 128;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8 * 1024,
};

/// Retains complete ordered attention revisions under one finite read selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertReadSnapshotV1 {
    /// Exact snapshot discriminator.
    pub schema: String,
    /// Independently authorized non-reusable resource incarnation.
    pub resource_scope: String,
    /// Fixed page size, from one through ten.
    pub limit: u32,
    /// Observation time shared by all pages.
    pub as_of: Timestamp,
    /// Exclusive custody deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// Complete original revisions in issue identity order.
    pub alerts: Vec<AssessmentAlertV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl AlertReadSnapshotV1 {
    /// Decodes a bounded, closed capture of original attention revisions.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, invalid alerts, selectors, handles,
    /// ordering, timestamps or exceeded record and byte bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "alert read snapshot")?;
        reject_null(&value)?;
        let snapshot: Self = serde_json::from_value(value)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Encodes a validated capture for immutable scoped custody.
    ///
    /// # Errors
    /// Returns an error for invalid content or excessive encoding bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "alert read snapshot")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "alert capture exceeds byte bound"
        );
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture identity.
    ///
    /// # Errors
    /// Returns an error for invalid content or excessive encoding bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value = LIMITS.decode(&self.to_bytes()?, "alert read snapshot")?;
        Sha256Digest::of_canonical(ALERT_READ_SNAPSHOT_V1, &value)
    }

    /// Projects an original page without consulting mutable attention state.
    ///
    /// # Errors
    /// Returns an error for expired custody, changed scope/page size, unknown
    /// handles or invalid content. The caller independently authorizes the read.
    pub fn page(
        &self,
        scope: &str,
        limit: u32,
        handle: Option<&str>,
        now: &Timestamp,
    ) -> Result<AlertPageV1> {
        self.validate()?;
        if scope != self.resource_scope || limit != self.limit {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if now < &self.as_of || now >= &self.expires_at {
            return Err(ScanPageError::CursorExpired.into());
        }
        let index = match handle {
            None => 0,
            Some(handle) => self
                .page_handles
                .iter()
                .position(|candidate| candidate == handle)
                .map(|position| position + 1)
                .ok_or(ScanPageError::InvalidCursor)?,
        };
        let start = index * self.limit as usize;
        let end = (start + self.limit as usize).min(self.alerts.len());
        let next_issue = self
            .page_handles
            .get(index)
            .map(|handle| -> Result<String> { Ok(format!("a1:{}:{handle}", self.digest()?.hex())) })
            .transpose()?;
        let page = AlertPageV1 {
            schema: "aos.assessment-alert-page/v1".into(),
            resource_scope: self.resource_scope.clone(),
            as_of: self.as_of.clone(),
            alerts: self.alerts[start..end].to_vec(),
            next_issue,
        };
        page.to_bytes()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "alert capture scope")?;
        ensure!(
            self.schema == ALERT_READ_SNAPSHOT_V1
                && (1..=10).contains(&self.limit)
                && self.alerts.len() <= MAX_CAPTURE_ALERTS
                && self.expires_at > self.as_of
                && self.expires_at.unix_seconds() - self.as_of.unix_seconds() <= 900,
            "invalid alert capture selector or retention bounds"
        );
        ensure!(
            self.page_handles.len()
                == self
                    .alerts
                    .len()
                    .div_ceil(self.limit as usize)
                    .saturating_sub(1),
            "invalid alert capture page count"
        );
        ensure!(
            self.alerts
                .windows(2)
                .all(|pair| pair[0].issue_key < pair[1].issue_key),
            "alert capture identities are duplicated or unordered"
        );
        for alert in &self.alerts {
            alert.validate()?;
            ensure!(
                alert.updated_at <= self.as_of,
                "alert capture contains a future revision"
            );
        }
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(
                handles.insert(handle),
                "alert capture repeats a page handle"
            );
        }
        Ok(())
    }
}

/// Decodes an opaque alert continuation without granting access.
///
/// # Errors
/// Returns an error for row identities, other cursor kinds or malformed tokens.
pub fn parse_alert_cursor(token: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(token, "a1")
}
