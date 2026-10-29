//! Complete-cache manifest and exact semantic page validation.
//!
//! Pages are written before their header. Each answer authenticates the page
//! that could contain its OID against that complete manifest. An unavailable or
//! changed page is unknown; it is never converted to negative membership.

use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{MirrorMembershipProjection, MirrorMembershipQuery, MirrorObjectSummary};
use crate::mirror_inspection::MirrorPackProjection;

/// Number of summaries per bounded Durable Object value.
pub const PAGE_OBJECTS: usize = 256;
/// Fixed semantic lifetime; cache hits never renew it.
pub const CACHE_SECONDS: i64 = 600;

/// Commitment to one strictly ordered semantic page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CataloguePageCommitment {
    /// First OID assigned to this page.
    pub first_oid: String,
    /// Exact number of entries in this page.
    pub count: usize,
    /// Canonical page digest, checked before any positive or negative answer.
    pub digest: String,
}

/// Header published only after every complete semantic page is durable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogueHeader {
    /// Actual compiled source and current Native plan authority commitment.
    pub authority_digest: String,
    /// Original start of this cache preparation, never reset by a read.
    pub created_at: i64,
    /// Original fixed expiry, unaffected by reads or alarms.
    pub expires_at: i64,
    /// Exact whole-pair encoded source/incarnation commitments.
    pub pair: MirrorPackProjection,
    /// Complete ordered coverage; an empty list proves an empty verified pair.
    pub pages: Vec<CataloguePageCommitment>,
    /// Full verified graph count, required to match every retained page.
    pub object_count: usize,
}

/// Commits one complete, bounded semantic page.
///
/// # Errors
/// Returns an error for empty, unordered, invalid or oversized summaries.
pub fn page_commitment(rows: &[MirrorObjectSummary]) -> Result<CataloguePageCommitment> {
    ensure!(
        !rows.is_empty() && rows.len() <= PAGE_OBJECTS,
        "catalogue page size is invalid"
    );
    ensure!(
        rows.windows(2).all(|rows| rows[0].oid < rows[1].oid),
        "catalogue page is unordered"
    );
    for row in rows {
        row.validate()?;
    }
    let bytes = serde_json::to_vec(rows)?;
    ensure!(
        bytes.len() <= 48 * 1024,
        "catalogue page exceeds storage value bound"
    );
    let mut hash = Sha256::new();
    hash.update(b"aos.verified-git-catalogue-page.v1\0");
    hash.update(bytes);
    Ok(CataloguePageCommitment {
        first_oid: rows[0].oid.clone(),
        count: rows.len(),
        digest: hex::encode(hash.finalize()),
    })
}

impl CatalogueHeader {
    /// Checks complete manifest geometry and current exact cache authority.
    ///
    /// # Errors
    /// Returns an error for expiry, authority/source substitution or an invalid
    /// page count/order. Cache misses must be recomputed under fresh authority.
    pub fn validate(&self, query: &MirrorMembershipQuery, authority: &str, now: i64) -> Result<()> {
        query.validate()?;
        self.pair.validate(&query.inspection.index_path, &[])?;
        ensure!(
            self.authority_digest == authority
                && now >= self.created_at
                && now < self.expires_at
                && self.created_at.checked_add(CACHE_SECONDS) == Some(self.expires_at),
            "catalogue cache changed or expired"
        );
        if let Some(expected) = &query.expected_source {
            ensure!(
                &self.pair.source_commitment()? == expected,
                "catalogue source was substituted"
            );
        }
        ensure!(
            self.pages.len() <= 256
                && self
                    .pages
                    .windows(2)
                    .all(|rows| rows[0].first_oid < rows[1].first_oid),
            "catalogue manifest geometry is invalid"
        );
        for (index, page) in self.pages.iter().enumerate() {
            ensure!(
                crate::direct_upload::valid_direct_digest(&page.first_oid)
                    && crate::direct_upload::valid_direct_digest(&page.digest)
                    && page.count > 0
                    && page.count <= PAGE_OBJECTS
                    && (index + 1 == self.pages.len() || page.count == PAGE_OBJECTS),
                "catalogue manifest page is invalid"
            );
        }
        ensure!(
            self.object_count <= 65_536
                && self.pages.iter().map(|page| page.count).sum::<usize>() == self.object_count,
            "catalogue manifest coverage is incomplete"
        );
        Ok(())
    }

    /// Selects the only cached page that could contain an exact OID.
    pub fn page_index(&self, oid: &str) -> Option<usize> {
        if self.pages.is_empty() {
            return None;
        }
        Some(
            self.pages
                .partition_point(|page| page.first_oid.as_str() <= oid)
                .saturating_sub(1),
        )
    }

    /// Answers a selection using complete pages authenticated by this header.
    ///
    /// # Errors
    /// Returns an error for missing or substituted pages. A caller must validate
    /// current authority and expiry before and after its actual storage reads.
    pub fn project(
        &self,
        query: &MirrorMembershipQuery,
        pages: &std::collections::BTreeMap<usize, Vec<MirrorObjectSummary>>,
    ) -> Result<MirrorMembershipProjection> {
        let mut objects = Vec::with_capacity(query.oids.len());
        for oid in &query.oids {
            let Some(index) = self.page_index(oid) else {
                objects.push(None);
                continue;
            };
            let rows = pages.get(&index).context("catalogue page is unavailable")?;
            ensure!(
                page_commitment(rows)? == self.pages[index],
                "catalogue page was substituted"
            );
            if let Some(next) = self.pages.get(index + 1) {
                ensure!(
                    rows.last().is_some_and(|row| row.oid < next.first_oid),
                    "catalogue page overlaps its successor"
                );
            }
            let answer = rows
                .binary_search_by(|row| row.oid.as_str().cmp(oid))
                .ok()
                .map(|position| rows[position].clone());
            objects.push(answer);
        }
        let projection = MirrorMembershipProjection {
            pair: self.pair.clone(),
            objects,
        };
        projection.validate(query)?;
        Ok(projection)
    }
}
