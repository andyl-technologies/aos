//! Bounded membership from complete storage-local Git pair verification.
//!
//! A result carries exact encoded source commitments and one ordered answer per
//! requested OID. Absence is authoritative only within that verified pair;
//! missing, expired or incomplete semantic cache state supplies no answer.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::mirror_inspection::{MirrorPackInspection, MirrorPackProjection};

pub mod cache;

/// Maximum exact membership selections in one authenticated control.
pub const MAX_MEMBERSHIP_OBJECTS: usize = 64;
/// Maximum serialized complete semantic catalogue retained beside storage.
pub const MAX_CATALOGUE_BYTES: usize = 8 * 1024 * 1024;

/// One approved pair and a strictly ordered, bounded membership predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorMembershipQuery {
    /// Current Native source, registry, trust-policy and qualified profile pins.
    pub inspection: MirrorPackInspection,
    /// Exact lowercase SHA-256 identities, strictly ordered without duplicates.
    pub oids: Vec<String>,
    /// Previously verified source commitment, required when continuing a pair.
    pub expected_source: Option<String>,
}

impl MirrorMembershipQuery {
    /// Validates the closed predicate and source before any storage read.
    ///
    /// # Errors
    /// Returns an error for changed source shape, invalid OIDs or count/order.
    pub fn validate(&self) -> Result<()> {
        self.inspection.validate()?;
        ensure!(
            self.inspection.selections.is_empty(),
            "membership has no content selector"
        );
        ensure!(
            !self.oids.is_empty()
                && self.oids.len() <= MAX_MEMBERSHIP_OBJECTS
                && self.oids.windows(2).all(|rows| rows[0] < rows[1])
                && self
                    .oids
                    .iter()
                    .all(|oid| crate::direct_upload::valid_direct_digest(oid))
                && self
                    .expected_source
                    .as_ref()
                    .is_none_or(|digest| crate::direct_upload::valid_direct_digest(digest)),
            "membership selection is invalid"
        );
        Ok(())
    }
}

/// Metadata of one whole Git object in the fully verified resolved graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorObjectSummary {
    /// SHA-256 Git object identity.
    pub oid: String,
    /// Closed Git object kind, inherited through verified delta chains.
    pub kind: String,
    /// Full decoded content length; no content is transported.
    pub object_size: u64,
}

impl MirrorObjectSummary {
    /// Checks the complete identity and published decoded object ceiling.
    ///
    /// # Errors
    /// Returns an error for a malformed OID, unknown kind or excessive size.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::direct_upload::valid_direct_digest(&self.oid),
            "catalogue OID is invalid"
        );
        aos_registry_surface::object::ObjectKind::parse(&self.kind)?;
        ensure!(
            self.object_size <= 4 * 1024 * 1024,
            "catalogue object exceeds decoded bound"
        );
        Ok(())
    }
}

/// Complete ordered membership partition, with no encoded or decoded bodies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorMembershipProjection {
    /// Fully verified pair commitments, with content and missing lists empty.
    pub pair: MirrorPackProjection,
    /// One answer per selected OID; `None` means absent from this exact pair.
    pub objects: Vec<Option<MirrorObjectSummary>>,
}

impl MirrorMembershipProjection {
    /// Rechecks exact pair, predicate, optional original commitment and bounds.
    ///
    /// # Errors
    /// Returns an error for a substituted source, incomplete partition or
    /// malformed positive answer. Unknown cache state is never an absence.
    pub fn validate(&self, query: &MirrorMembershipQuery) -> Result<()> {
        query.validate()?;
        self.pair.validate(&query.inspection.index_path, &[])?;
        if let Some(expected) = &query.expected_source {
            ensure!(
                &self.pair.source_commitment()? == expected,
                "membership source changed"
            );
        }
        ensure!(
            self.objects.len() == query.oids.len(),
            "membership partition is incomplete"
        );
        for (oid, answer) in query.oids.iter().zip(&self.objects) {
            if let Some(answer) = answer {
                answer.validate()?;
                ensure!(&answer.oid == oid, "membership answer changed its OID");
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 16 * 1024,
            "membership result exceeds its bound"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
