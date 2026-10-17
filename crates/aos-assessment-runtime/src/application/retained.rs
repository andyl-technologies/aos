//! Immutable status captures with explicitly versioned opaque continuations.
//!
//! Every page retains its original inventory, policy, source availability and
//! observation time. Historical freshness describes that time; a capture grants
//! neither current coverage nor execution, publication or read authority.
//!
//! ```json
//! {"schema":"aos.assessment-status-query/v2","profiles":["updates"],"limit":25}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::{input::Profile, time::Timestamp};
use aos_contract::{
    Sha256Digest, canonical,
    limits::{BoundedWriter, JsonLimits},
};
use serde::{Deserialize, Serialize};

use super::{AssessmentStatusV1, StatusQueryV1};
use crate::read_snapshot::{ScanPageError, parse_cursor, validate_handle};
use crate::validation::{decode, encoded, reject_null, text};

/// Identifies immutable scoped status captures.
pub const STATUS_READ_SNAPSHOT_V1: &str = "aos.assessment-status-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 24,
    max_items: 250_000,
    max_string_bytes: 4096,
};

/// Selects a retained status observation with an exact optional input constraint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusQueryV2 {
    /// Exact selector version, separate from mutable subject-position pagination.
    pub schema: String,
    /// Sorted independent profiles, preserved across every continuation.
    pub profiles: Vec<Profile>,
    /// Fixed maximum subjects per page, from one through one hundred.
    pub limit: u32,
    /// Original registry incarnation, required on continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Optional exact inventory constraint, retained as part of the selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_digest: Option<Sha256Digest>,
    /// Optional exact policy constraint, retained as part of the selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Sha256Digest>,
    /// Immutable capture and random page handle, never an authorization token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl StatusQueryV2 {
    /// Decodes a bounded closed retained selector.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid selection or malformed handles.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "retained status query")?;
        query.validate()?;
        Ok(query)
    }

    /// Checks fixed profiles, input constraints and incarnation-bound continuation.
    ///
    /// # Errors
    /// Returns an error for unsupported versions, invalid bounds or unbound cursors.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-status-query/v2",
            "invalid retained status query"
        );
        StatusQueryV1 {
            schema: "aos.assessment-status-query/v1".into(),
            profiles: self.profiles.clone(),
            limit: self.limit,
            after_subject: None,
            inventory_digest: self.inventory_digest,
            policy_digest: self.policy_digest,
        }
        .validate()?;
        if let Some(scope) = &self.resource_scope {
            text(scope, 128, "status resource incarnation")?;
        }
        if let Some(cursor) = &self.cursor {
            ensure!(
                self.resource_scope.is_some(),
                "retained status cursor lacks its original scope"
            );
            parse_status_cursor(cursor)?;
        }
        Ok(())
    }
}

/// Returns an original status payload with a retained opaque continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusPageV2 {
    /// Exact response version.
    pub schema: String,
    /// Original observation with no mutable subject-position continuation.
    pub page: AssessmentStatusV1,
    /// Exclusive custody deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// Next random handle within the same immutable capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl StatusPageV2 {
    /// Encodes a bounded response without reinterpreting historical freshness.
    ///
    /// # Errors
    /// Returns an error for invalid payload, deadline, cursor or response bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-status-page/v2" && self.page.next_subject.is_none(),
            "invalid retained status page"
        );
        self.page.validate()?;
        self.page
            .to_bytes()
            .map_err(|_| ScanPageError::CapacityExceeded)?;
        ensure!(
            self.expires_at > self.page.as_of
                && self.expires_at.elapsed_since(&self.page.as_of)? <= 900,
            "invalid status retention deadline"
        );
        if let Some(cursor) = &self.next_cursor {
            parse_status_cursor(cursor)?;
        }
        encoded(self).map_err(|_| ScanPageError::CapacityExceeded.into())
    }

    /// Decodes the same closed response consumed by hosted clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid payload or exceeded bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode(bytes, "retained status page")?;
        page.to_bytes()?;
        Ok(page)
    }

    /// Checks exact scope, input constraints, profiles and capture continuity.
    ///
    /// # Errors
    /// Returns an error for a response that differs from the requested selection.
    pub fn validate_for(&self, query: &StatusQueryV2) -> Result<()> {
        query.validate()?;
        self.to_bytes()?;
        ensure!(
            query
                .resource_scope
                .as_ref()
                .is_none_or(|scope| scope == &self.page.resource_scope)
                && query
                    .inventory_digest
                    .is_none_or(|digest| digest == self.page.inventory_digest)
                && query
                    .policy_digest
                    .is_none_or(|digest| digest == self.page.policy_digest)
                && self.page.subjects.len() <= query.limit as usize
                && self.page.subjects.iter().all(|subject| subject
                    .profiles
                    .iter()
                    .map(|profile| profile.profile)
                    .eq(query.profiles.iter().copied())),
            "status response selection changed"
        );
        if let (Some(current), Some(next)) = (&query.cursor, &self.next_cursor) {
            let (current_digest, current_handle) = parse_status_cursor(current)?;
            let (next_digest, next_handle) = parse_status_cursor(next)?;
            ensure!(
                current_digest == next_digest && current_handle != next_handle,
                "status continuation changed or repeated its capture"
            );
        }
        Ok(())
    }
}

/// Retains at most ten thousand subjects under one original bounded selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusReadSnapshotV1 {
    /// Exact immutable capture discriminator.
    pub schema: String,
    /// Original selector with explicit scope and no continuation.
    pub selection: StatusQueryV2,
    /// Exclusive capture lifetime, at most fifteen minutes.
    pub expires_at: Timestamp,
    /// Original pages sharing one input, source availability and observation time.
    pub pages: Vec<AssessmentStatusV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl StatusReadSnapshotV1 {
    /// Decodes bounded immutable content without accepting ambiguous JSON.
    ///
    /// # Errors
    /// Returns an error for invalid selection, pages, handles or storage bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "status read snapshot")?;
        reject_null(&value)?;
        let snapshot: Self = serde_json::from_value(value)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Encodes validated immutable custody within its finite storage allowance.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded structural/byte limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut count = BoundedWriter::new(
            LIMITS.max_bytes as u64,
            "status capture exceeds byte allowance",
        );
        serde_json::to_writer(&mut count, self).map_err(|_| ScanPageError::CapacityExceeded)?;
        let value = serde_json::to_value(self)?;
        LIMITS
            .check_value(&value, "status read snapshot")
            .map_err(|_| ScanPageError::CapacityExceeded)?;
        let bytes = canonical::to_vec(&value)?;
        if bytes.len() > LIMITS.max_bytes {
            return Err(ScanPageError::CapacityExceeded.into());
        }
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture commitment.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded capture bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value = LIMITS.decode(&self.to_bytes()?, "status read snapshot")?;
        Sha256Digest::of_canonical(STATUS_READ_SNAPSHOT_V1, &value)
    }

    /// Projects one original page under the exact selector and current custody time.
    ///
    /// Hosts independently recheck current resource and read authority. Freshness
    /// flags continue describing the original observation, never the current time.
    ///
    /// # Errors
    /// Returns an error for expiry, changed selection, forged handles or corruption.
    pub fn page(&self, query: &StatusQueryV2, now: &Timestamp) -> Result<StatusPageV2> {
        self.validate()?;
        query.validate()?;
        let mut selection = query.clone();
        selection.cursor = None;
        if selection.resource_scope.is_none() && query.cursor.is_none() {
            selection.resource_scope = self.selection.resource_scope.clone();
        }
        if selection != self.selection {
            return Err(ScanPageError::SelectorChanged.into());
        }
        let first = self.pages.first().ok_or(ScanPageError::InvalidCursor)?;
        if now < &first.as_of || now >= &self.expires_at {
            return Err(ScanPageError::CursorExpired.into());
        }
        let digest = self.digest()?;
        let index = if let Some(cursor) = &query.cursor {
            let (selected_digest, handle) = parse_status_cursor(cursor)?;
            if selected_digest != digest {
                return Err(ScanPageError::InvalidCursor.into());
            }
            self.page_handles
                .iter()
                .position(|candidate| candidate == handle)
                .map(|index| index + 1)
                .ok_or(ScanPageError::InvalidCursor)?
        } else {
            0
        };
        let page = StatusPageV2 {
            schema: "aos.assessment-status-page/v2".into(),
            page: self
                .pages
                .get(index)
                .ok_or(ScanPageError::InvalidCursor)?
                .clone(),
            expires_at: self.expires_at.clone(),
            next_cursor: self
                .page_handles
                .get(index)
                .map(|handle| format!("t1:{}:{handle}", digest.hex())),
        };
        page.validate_for(query)?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        self.selection.validate()?;
        ensure!(
            self.schema == STATUS_READ_SNAPSHOT_V1
                && self.selection.cursor.is_none()
                && self.selection.resource_scope.is_some()
                && !self.pages.is_empty()
                && self.pages.len() <= 10_000
                && self.page_handles.len() + 1 == self.pages.len(),
            "invalid retained status capture"
        );
        let first = self.pages.first().ok_or(ScanPageError::InvalidCursor)?;
        let mut count = 0usize;
        let mut previous: Option<&str> = None;
        for (index, page) in self.pages.iter().enumerate() {
            StatusPageV2 {
                schema: "aos.assessment-status-page/v2".into(),
                page: page.clone(),
                expires_at: self.expires_at.clone(),
                next_cursor: None,
            }
            .validate_for(&self.selection)?;
            ensure!(
                page.inventory_digest == first.inventory_digest
                    && page.inventory_revision == first.inventory_revision
                    && page.policy_digest == first.policy_digest
                    && page.as_of == first.as_of
                    && page.source_status == first.source_status,
                "status capture changed its original context"
            );
            ensure!(
                index + 1 == self.pages.len()
                    || page.subjects.len() == self.selection.limit as usize,
                "status capture has a short intermediate page"
            );
            ensure!(
                self.pages.len() == 1 || !page.subjects.is_empty(),
                "status capture has an empty continuation"
            );
            for subject in &page.subjects {
                ensure!(
                    previous.is_none_or(|previous| previous < subject.subject_ref.as_str()),
                    "status capture subject order changed"
                );
                previous = Some(&subject.subject_ref);
            }
            count += page.subjects.len();
        }
        ensure!(count <= 10_000, "status capture exceeds subject allowance");
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(handles.insert(handle), "status capture repeats a handle");
        }
        Ok(())
    }
}

/// Parses a retained status cursor without treating it as read authority.
///
/// # Errors
/// Returns an error for wrong-kind, malformed or noncanonical handles.
pub fn parse_status_cursor(cursor: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(cursor, "t1")
}

#[cfg(test)]
#[path = "retained_tests.rs"]
mod tests;
