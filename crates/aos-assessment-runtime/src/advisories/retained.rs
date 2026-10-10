//! Retained advisory selections with versioned opaque continuations.
//!
//! Version two preserves the version-one advisory payload, but a continuation
//! names an immutable selection rather than a changing record position. These
//! contracts grant no source, assessment, publication or read authority.
//!
//! ```json
//! {"schema":"aos.assessment-advisory-query/v2","advisoryId":"CVE-2026-12345","limit":10}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use super::{AdvisoryPageV1, AdvisoryQueryV1};
use crate::read_snapshot::{ScanPageError, parse_cursor, validate_handle};
use crate::validation::{decode, encoded, reject_null};

/// Identifies immutable, scope-bound advisory captures.
pub const ADVISORY_READ_SNAPSHOT_V1: &str = "aos.assessment-advisory-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8192,
};

/// Selects a retained advisory history or exact historical assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryQueryV2 {
    /// Exact query version, distinct from raw record-position pagination.
    pub schema: String,
    /// Exact advisory ID or canonical CVE equivalence.
    pub advisory_id: String,
    /// Original registry incarnation, mandatory on continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<String>,
    /// Optional successfully admitted immutable assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<Sha256Digest>,
    /// Optional exact subject within the selected assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Immutable capture and random page handle, never an authorization token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Fixed page size, from one through ten.
    pub limit: u32,
}

impl AdvisoryQueryV2 {
    /// Decodes a bounded closed selector before persistence or source effects.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid selection or malformed cursors.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let query: Self = decode(bytes, "retained advisory query")?;
        query.validate()?;
        Ok(query)
    }

    /// Checks exact equivalence, finite bounds and incarnation-bound continuation.
    ///
    /// # Errors
    /// Returns an error for invalid versions, identities, scope or cursor grammar.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-advisory-query/v2",
            "invalid retained advisory query"
        );
        self.legacy_selection().validate()?;
        if let Some(cursor) = &self.cursor {
            ensure!(
                self.resource_scope.is_some(),
                "retained advisory cursor lacks its original scope"
            );
            parse_advisory_cursor(cursor)?;
        }
        Ok(())
    }

    /// Converts the semantic selection without converting cursor semantics.
    #[must_use]
    pub fn legacy_selection(&self) -> AdvisoryQueryV1 {
        AdvisoryQueryV1 {
            schema: "aos.assessment-advisory-query/v1".into(),
            advisory_id: self.advisory_id.clone(),
            resource_scope: self.resource_scope.clone(),
            assessment_digest: self.assessment_digest,
            subject_ref: self.subject_ref.clone(),
            after_record: None,
            limit: self.limit,
        }
    }
}

/// Returns the original advisory payload and a retained opaque continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryPageV2 {
    /// Exact response version.
    pub schema: String,
    /// Original semantic payload, with no live record-position continuation.
    pub page: AdvisoryPageV1,
    /// Exclusive custody deadline, within fifteen minutes of observation.
    pub expires_at: Timestamp,
    /// Next random handle within the same immutable capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl AdvisoryPageV2 {
    /// Encodes a closed finite response without changing the advisory payload.
    ///
    /// # Errors
    /// Returns an error for invalid payload, cursor, deadline or response bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-advisory-page/v2" && self.page.next_record.is_none(),
            "invalid retained advisory page"
        );
        self.page.to_bytes()?;
        ensure!(
            self.expires_at > self.page.as_of
                && self.expires_at.elapsed_since(&self.page.as_of)? <= 900,
            "invalid advisory retention deadline"
        );
        if let Some(cursor) = &self.next_cursor {
            parse_advisory_cursor(cursor)?;
        }
        encoded(self)
    }

    /// Decodes the same closed response consumed by hosted clients.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid payload or exceeded bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode(bytes, "retained advisory page")?;
        page.to_bytes()?;
        Ok(page)
    }

    /// Checks that a response preserves the caller's semantic selection.
    ///
    /// # Errors
    /// Returns an error for changed scope, advisory, assessment or subject.
    pub fn validate_for(&self, query: &AdvisoryQueryV2) -> Result<()> {
        query.validate()?;
        self.to_bytes()?;
        self.page.validate_for(&query.legacy_selection())?;
        if let (Some(current), Some(next)) = (&query.cursor, &self.next_cursor) {
            let (current_digest, current_handle) = parse_advisory_cursor(current)?;
            let (next_digest, next_handle) = parse_advisory_cursor(next)?;
            ensure!(
                current_digest == next_digest && current_handle != next_handle,
                "advisory continuation changed or repeated its capture"
            );
        }
        Ok(())
    }
}

/// Retains at most 128 complete revisions under one original finite selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryReadSnapshotV1 {
    /// Exact capture discriminator.
    pub schema: String,
    /// Original selector with explicit scope and no continuation.
    pub selection: AdvisoryQueryV2,
    /// Exclusive capture lifetime, at most fifteen minutes.
    pub expires_at: Timestamp,
    /// Original pages sharing one observation time and historical context.
    pub pages: Vec<AdvisoryPageV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl AdvisoryReadSnapshotV1 {
    /// Decodes a bounded immutable capture without accepting ambiguous JSON.
    ///
    /// # Errors
    /// Returns an error for invalid content, ordering, handles or storage bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "advisory read snapshot")?;
        reject_null(&value)?;
        let snapshot: Self = serde_json::from_value(value)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Encodes a validated bounded capture for immutable custody.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, revisions or encoding bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "advisory read snapshot")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "advisory capture exceeds byte allowance"
        );
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture commitment.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded capture bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value =
            LIMITS.decode(&self.to_bytes()?, "advisory read snapshot")?;
        Sha256Digest::of_canonical(ADVISORY_READ_SNAPSHOT_V1, &value)
    }

    /// Projects one original page under the original selector and current clock.
    ///
    /// Hosts independently recheck current read authority and resource scope.
    /// The payload does not assert current vulnerability applicability.
    ///
    /// # Errors
    /// Returns an error for expiry, changed selection, forged handles or corruption.
    pub fn page(&self, query: &AdvisoryQueryV2, now: &Timestamp) -> Result<AdvisoryPageV2> {
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
            let (selected_digest, handle) = parse_advisory_cursor(cursor)?;
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
        let page = AdvisoryPageV2 {
            schema: "aos.assessment-advisory-page/v2".into(),
            page: self
                .pages
                .get(index)
                .ok_or(ScanPageError::InvalidCursor)?
                .clone(),
            expires_at: self.expires_at.clone(),
            next_cursor: self
                .page_handles
                .get(index)
                .map(|handle| format!("c1:{}:{handle}", digest.hex())),
        };
        page.validate_for(query)?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        self.selection.validate()?;
        ensure!(
            self.schema == ADVISORY_READ_SNAPSHOT_V1
                && self.selection.cursor.is_none()
                && self.selection.resource_scope.is_some()
                && !self.pages.is_empty()
                && self.pages.len() <= 128
                && self.page_handles.len() + 1 == self.pages.len(),
            "invalid retained advisory capture"
        );
        let first = self.pages.first().ok_or(ScanPageError::InvalidCursor)?;
        ensure!(
            self.expires_at > first.as_of && self.expires_at.elapsed_since(&first.as_of)? <= 900,
            "invalid advisory capture deadline"
        );
        let mut count = 0usize;
        let mut previous = None;
        for (index, page) in self.pages.iter().enumerate() {
            page.validate_for(&self.selection.legacy_selection())?;
            ensure!(
                page.next_record.is_none()
                    && page.as_of == first.as_of
                    && page.assessment_context == first.assessment_context,
                "advisory capture changed its original context"
            );
            ensure!(
                index + 1 == self.pages.len()
                    || page.revisions.len() == self.selection.limit as usize,
                "advisory capture has a short intermediate page"
            );
            ensure!(
                self.pages.len() == 1 || !page.revisions.is_empty(),
                "advisory capture has an empty continuation"
            );
            for revision in &page.revisions {
                ensure!(
                    previous.is_none_or(|previous| previous < revision.record_digest),
                    "advisory capture revision order changed"
                );
                previous = Some(revision.record_digest);
            }
            count += page.revisions.len();
        }
        ensure!(count <= 128, "advisory capture exceeds revision allowance");
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(handles.insert(handle), "advisory capture repeats a handle");
        }
        Ok(())
    }
}

/// Parses a retained advisory cursor without treating it as read authority.
///
/// # Errors
/// Returns an error for wrong-kind, malformed or noncanonical handles.
pub fn parse_advisory_cursor(cursor: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(cursor, "c1")
}

#[cfg(test)]
#[path = "retained_tests.rs"]
mod tests;
