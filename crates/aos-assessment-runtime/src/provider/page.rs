//! Source-bound page identities and closed continuations for compact fan-out.
//!
//! OSV query IDs remain distinct from complete advisory records. A page proves
//! source enumeration only; query completeness also requires retaining every
//! referenced full record and all subsequent pages before composing a snapshot.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ProviderOperation;
use crate::validation::{decode, encoded, text};

/// Preserves an exact advisory revision identity returned by a source page.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryRevisionReference {
    /// Exact provider-native ID; no guessed CVE expansion.
    pub id: String,
    /// Exact provider modification identity for full-record retrieval validation.
    pub modified: String,
}

/// Carries one retained source page and its exact permitted successor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderPageV1 {
    /// Exact source-page discriminator.
    pub schema: String,
    /// Exact operation that acquired the source answer.
    pub operation: ProviderOperation,
    /// Original exact project/query scope, independent of pagination tokens.
    pub project: String,
    /// Retained exact source bytes whose parser produced this page.
    pub source_digest: Sha256Digest,
    /// Sorted full-record retrieval references; absence never means a clean result.
    pub records: Vec<AdvisoryRevisionReference>,
    /// Source-bound successor, absent only when this page has no further position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<ProviderOperation>,
}

impl ProviderPageV1 {
    /// Validates bounded revision references and exact continuation scope.
    ///
    /// # Errors
    /// Returns an error for incompatible schemas, duplicate IDs, arbitrary
    /// successors, invalid source configuration or compact-object limits.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.provider-page/v1" || self.records.len() > 128 {
            bail!("source page exceeds its closed revision limits");
        }
        self.operation.validate()?;
        text(&self.project, 1024, "source page project")?;
        if self.records.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            bail!("source page revision IDs must be sorted and unique");
        }
        for record in &self.records {
            text(&record.id, 128, "source page advisory ID")?;
            text(&record.modified, 128, "source page modification identity")?;
        }
        if !self.operation.supports_project(&self.project) {
            bail!("source page differs from its original query/project");
        }
        if let Some(next) = &self.next {
            self.operation.require_successor(next)?;
        }
        if encoded(self)?.len() > 64 * 1024 {
            bail!("source page exceeds compact object size");
        }
        Ok(())
    }

    /// Computes the exact immutable page identity without granting execution authority.
    ///
    /// # Errors
    /// Returns an error for malformed scope or page limits.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Sha256Digest::of_canonical("aos.provider-page/v1", self)
    }

    /// Decodes one closed bounded source page before continuation admission.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, unknown/null fields or invalid scope.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let page: Self = decode(bytes, "source page")?;
        page.validate()?;
        Ok(page)
    }
}

impl ProviderOperation {
    /// Requires a source successor to retain every decision-relevant query field.
    ///
    /// This checks structural scope only. The executor must derive the position
    /// from retained source bytes, and the coordinator independently admits it
    /// against the original page before allocating another budget reservation.
    ///
    /// # Errors
    /// Returns an error for arbitrary operations, changed query/window/project,
    /// duplicate tokens, non-progressing or excessive pagination positions.
    pub fn require_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        let valid = match (self, next) {
            (
                Self::ObserveReleases {
                    repository: a,
                    tag_prefix: x,
                    page: p,
                },
                Self::ObserveReleases {
                    repository: b,
                    tag_prefix: y,
                    page: q,
                },
            )
            | (
                Self::ObserveTags {
                    repository: a,
                    tag_prefix: x,
                    page: p,
                },
                Self::ObserveTags {
                    repository: b,
                    tag_prefix: y,
                    page: q,
                },
            ) => a == b && x == y && p.checked_add(1) == Some(*q),
            (
                Self::QueryOsv {
                    queries: a,
                    projects: x,
                    continuations: old,
                },
                Self::QueryOsv {
                    queries: b,
                    projects: y,
                    continuations: new,
                },
            ) => a == b && x == y && !new.is_empty() && old != new,
            (
                Self::QueryNvd {
                    project: a,
                    identity: x,
                    version: v,
                    start_index: p,
                },
                Self::QueryNvd {
                    project: b,
                    identity: y,
                    version: w,
                    start_index: q,
                },
            ) => a == b && x == y && v == w && q > p && q - p <= 128,
            (
                Self::RefreshNvd {
                    modified_start: a,
                    modified_end: x,
                    start_index: p,
                },
                Self::RefreshNvd {
                    modified_start: b,
                    modified_end: y,
                    start_index: q,
                },
            ) => a == b && x == y && q > p && q - p <= 128,
            (Self::RefreshKev { offset: p }, Self::RefreshKev { offset: q }) => {
                q > p && q - p <= 128
            }
            _ => false,
        };
        if !valid {
            bail!("provider continuation changed its exact original source question");
        }
        Ok(())
    }
}
