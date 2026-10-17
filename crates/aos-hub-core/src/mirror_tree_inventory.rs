//! Complete bounded Git-tree inventories from verified storage-local sources.
//!
//! A cursor fixes the tree and complete pair commitment. Pages contain only
//! canonical name/kind/OID rows; Native never receives decoded tree framing.
//! The producer may cache these semantic pages under current authorization,
//! but cannot cache permission, a decoder checkpoint or provider effect state.
//!
//! ```text
//! verified pair + tree OID -> source-bound ordered pages of at most 16 rows
//! cursor = tree OID + pair source commitment + next exact row index
//! ```

use anyhow::{ensure, Result};
use aos_registry_surface::object::{self, ObjectKind};
use serde::{Deserialize, Serialize};

use crate::mirror_inspection::{MirrorPackInspection, MirrorPackProjection, MirrorPackSource};
use crate::tree_projection::{GitTreeEntryKind, GitTreeEntryProjection};

/// Bounds one canonical semantic page independently of source object bytes.
pub const MAX_INVENTORY_PAGE_BYTES: usize = 16 * 1024;
/// Bounds rows emitted by one inventory page.
pub const MAX_INVENTORY_PAGE_ROWS: usize = 16;
/// Bounds the complete semantic cache, including every page's framing.
pub const MAX_INVENTORY_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Bounds the complete verified tree entry inventory.
pub const MAX_INVENTORY_ROWS: usize = 65536;

/// Selects one exact upstream representation, without generic source paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorTreeInventorySource {
    /// A fully verified immutable pair containing the selected tree.
    Pack {
        /// Exact current upstream and canonical pair selection.
        inspection: MirrorPackInspection,
    },
    /// The canonical loose path derived from the selected tree OID.
    Loose {
        /// Exact registry selecting source trust and placement authority.
        registry_id: i64,
        /// Exact current registry version.
        registry_resource_version: i64,
        /// Exact current mirror source and trust-policy version.
        mirror_resource_version: i64,
        /// Approved HTTPS base, excluding credentials, query and fragment.
        upstream_base: String,
        /// Current independently qualified managed workflow commitment.
        protected_profile_digest: String,
    },
}

impl MirrorTreeInventorySource {
    /// Returns the exact independently qualified profile commitment.
    #[must_use]
    pub fn profile_digest(&self) -> &str {
        match self {
            Self::Pack { inspection } => &inspection.protected_profile_digest,
            Self::Loose {
                protected_profile_digest,
                ..
            } => protected_profile_digest,
        }
    }

    /// Returns the exact approved upstream base.
    #[must_use]
    pub fn upstream_base(&self) -> &str {
        match self {
            Self::Pack { inspection } => &inspection.upstream_base,
            Self::Loose { upstream_base, .. } => upstream_base,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Pack { inspection } => {
                inspection.validate()?;
                ensure!(
                    inspection.selections.is_empty(),
                    "inventory contains another query"
                );
            }
            Self::Loose {
                registry_id,
                registry_resource_version,
                mirror_resource_version,
                upstream_base,
                protected_profile_digest,
            } => {
                let base = url::Url::parse(upstream_base)?;
                ensure!(
                    *registry_id > 0
                        && *registry_resource_version > 0
                        && *mirror_resource_version > 0
                        && crate::direct_upload::valid_direct_digest(protected_profile_digest)
                        && base.scheme() == "https"
                        && base.username().is_empty()
                        && base.password().is_none()
                        && base.query().is_none()
                        && base.fragment().is_none(),
                    "loose inventory authority is invalid"
                );
                crate::url_guard::is_safe_remote_url(upstream_base)?;
            }
        }
        Ok(())
    }
}

/// Commits the complete positive representation parsed beside storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorTreeInventoryCommitment {
    /// Full encoded pair SHA, length, canonical path and source incarnations.
    Pack {
        /// Complete pair verification, without selected content bodies.
        pair: MirrorPackProjection,
    },
    /// Complete encoded loose object SHA, length and same-response incarnation.
    Loose {
        /// Canonical loose source, independently decoded and OID verified.
        object: MirrorPackSource,
    },
}

impl MirrorTreeInventoryCommitment {
    /// Counts actual encoded source bytes for a complete cache fill.
    #[must_use]
    pub fn source_bytes(&self) -> u64 {
        match self {
            Self::Pack { pair } => pair.pack.size + pair.index.size,
            Self::Loose { object } => object.size,
        }
    }

    /// Commits the immutable positive source independently of page positions.
    ///
    /// # Errors
    /// Returns an error if canonical source commitments cannot be encoded.
    pub fn source_commitment(&self) -> Result<String> {
        use sha2::{Digest as _, Sha256};
        match self {
            Self::Pack { pair } => pair.source_commitment(),
            Self::Loose { object } => {
                let mut digest = Sha256::new();
                digest.update(b"aos-mirror-verified-loose-tree-source-v1\0");
                digest.update(serde_json::to_vec(object)?);
                Ok(hex::encode(digest.finalize()))
            }
        }
    }
}

/// Resumes the exact next row in one completely verified source tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTreeInventoryCursor {
    /// Exact requested Git tree OID.
    pub tree_oid: String,
    /// Complete encoded pair identities and same-response incarnations.
    pub source_commitment: String,
    /// Next ordered row, never an opaque decoder offset.
    pub next_index: usize,
}

/// Selects a complete tree inventory under exact Native upstream authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTreeInventoryQuery {
    /// Exact current Native upstream, placement and profile selection.
    pub source: MirrorTreeInventorySource,
    /// Exact tree selected from the authenticated Git graph.
    pub tree_oid: String,
    /// Previous complete-source continuation, if present.
    pub cursor: Option<MirrorTreeInventoryCursor>,
}

impl MirrorTreeInventoryQuery {
    /// Validates the closed inventory selector before any read.
    ///
    /// # Errors
    /// Returns an error for malformed source, tree, selection or cursor.
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        ensure!(
            crate::direct_upload::valid_direct_digest(&self.tree_oid),
            "invalid inventory tree OID"
        );
        if let Some(cursor) = &self.cursor {
            ensure!(
                cursor.tree_oid == self.tree_oid
                    && crate::direct_upload::valid_direct_digest(&cursor.source_commitment)
                    && cursor.next_index > 0
                    && cursor.next_index < MAX_INVENTORY_ROWS
                    && cursor.next_index % MAX_INVENTORY_PAGE_ROWS == 0,
                "inventory cursor changed its tree or position"
            );
        }
        Ok(())
    }
}

/// Returns one exact contiguous page and the complete source row count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTreeInventoryPage {
    /// Exact selected tree OID.
    pub tree_oid: String,
    /// Complete verified pair and incarnation commitment.
    pub source_commitment: String,
    /// Actual complete row count, before paging.
    pub total_entries: usize,
    /// Inclusive first returned row position.
    pub start_index: usize,
    /// Exact canonical rows in strict component-name order.
    pub entries: Vec<GitTreeEntryProjection>,
    /// Next exact row position, absent only on the terminal page.
    pub next_cursor: Option<MirrorTreeInventoryCursor>,
}

impl MirrorTreeInventoryPage {
    /// Rechecks exact source, contiguous positions and terminal completeness.
    ///
    /// # Errors
    /// Returns an error for malformed rows, changed source, gaps or byte bounds.
    pub fn validate(&self, query: &MirrorTreeInventoryQuery, source: &str) -> Result<()> {
        query.validate()?;
        let start = query.cursor.as_ref().map_or(0, |cursor| cursor.next_index);
        ensure!(
            crate::direct_upload::valid_direct_digest(source)
                && query
                    .cursor
                    .as_ref()
                    .is_none_or(|cursor| cursor.source_commitment == source)
                && self.tree_oid == query.tree_oid
                && self.source_commitment == source
                && self.total_entries <= MAX_INVENTORY_ROWS
                && self.start_index == start
                && (start < self.total_entries
                    || (self.total_entries == 0 && start == 0 && query.cursor.is_none())),
            "inventory page changed its source or range"
        );
        let count = (self.total_entries - start).min(MAX_INVENTORY_PAGE_ROWS);
        ensure!(
            self.entries.len() == count,
            "inventory page omits source rows"
        );
        for entry in &self.entries {
            entry.tree_entry()?;
        }
        ensure!(
            self.entries
                .windows(2)
                .all(|rows| rows[0].name < rows[1].name),
            "inventory rows are not strictly ordered"
        );
        let end = start + count;
        let expected = (end < self.total_entries).then(|| MirrorTreeInventoryCursor {
            tree_oid: self.tree_oid.clone(),
            source_commitment: source.into(),
            next_index: end,
        });
        ensure!(
            self.next_cursor == expected,
            "inventory continuation hides or invents rows"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_INVENTORY_PAGE_BYTES,
            "inventory page exceeds its semantic output bound"
        );
        Ok(())
    }
}

/// Carries complete pair commitments and one present or absent tree page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTreeInventoryProjection {
    /// Complete verified pair, with no object-content selections.
    pub source: MirrorTreeInventoryCommitment,
    /// Exact selected OID, including for verified absence.
    pub tree_oid: String,
    /// Present verified decoded size, absent only after complete pair validation.
    pub object_size: Option<u64>,
    /// Exact bounded page, absent only when the tree is absent from the pair.
    pub page: Option<MirrorTreeInventoryPage>,
}

impl MirrorTreeInventoryProjection {
    /// Validates the complete commitment and exact page correlation.
    ///
    /// # Errors
    /// Returns an error for changed source, oversized tree or malformed page.
    pub fn validate(&self, query: &MirrorTreeInventoryQuery) -> Result<()> {
        query.validate()?;
        match (&query.source, &self.source) {
            (
                MirrorTreeInventorySource::Pack { inspection },
                MirrorTreeInventoryCommitment::Pack { pair },
            ) => pair.validate(&inspection.index_path, &[])?,
            (
                MirrorTreeInventorySource::Loose { .. },
                MirrorTreeInventoryCommitment::Loose { object },
            ) => {
                let oid = aos_registry_surface::object::Oid::from_hex(&query.tree_oid)?;
                ensure!(
                    object.path == oid.loose_path()
                        && object.size <= 8 * 1024 * 1024
                        && self.object_size.is_some()
                        && crate::direct_upload::valid_direct_digest(&object.sha256)
                        && crate::surface_write::strong_if_match_etag(&object.etag).is_ok(),
                    "loose inventory source commitment is invalid"
                );
            }
            _ => anyhow::bail!("inventory changed selected representation"),
        }
        ensure!(
            self.tree_oid == query.tree_oid && self.object_size.is_some() == self.page.is_some(),
            "inventory projection changes selected identity"
        );
        if let (Some(size), Some(page)) = (self.object_size, &self.page) {
            ensure!(
                size <= 4 * 1024 * 1024,
                "inventory tree exceeds the qualified parser bound"
            );
            page.validate(query, &self.source.source_commitment()?)?;
        } else {
            ensure!(
                query.cursor.is_none(),
                "absent tree cannot resume a positive inventory"
            );
        }
        Ok(())
    }
}

/// Produces bounded semantic pages from a fully verified borrowed tree.
///
/// Complete source verification must precede this call. The tree OID is independently
/// checked again; the output contains no raw framing or decoder state.
///
/// # Errors
/// Returns an error for invalid tree identity, entries or aggregate cache size.
pub fn project_pages(
    tree_oid: &str,
    content: &[u8],
    source: &str,
) -> Result<Vec<MirrorTreeInventoryPage>> {
    ensure!(
        content.len() <= 4 * 1024 * 1024
            && crate::direct_upload::valid_direct_digest(source)
            && object::hash_object(ObjectKind::Tree, content).to_hex() == tree_oid,
        "inventory source tree is invalid"
    );
    let mut entries = object::parse_tree(content)?;
    ensure!(
        entries.len() <= MAX_INVENTORY_ROWS,
        "inventory tree has too many entries"
    );
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    ensure!(
        entries.windows(2).all(|rows| rows[0].name != rows[1].name),
        "duplicate inventory name"
    );
    let total_entries = entries.len();
    let mut rows = Vec::with_capacity(total_entries);
    for entry in entries {
        let kind = match entry.mode.as_str() {
            "40000" => GitTreeEntryKind::Tree,
            "100644" => GitTreeEntryKind::Blob,
            "100755" => GitTreeEntryKind::ExecutableBlob,
            "120000" => GitTreeEntryKind::Symlink,
            "160000" => GitTreeEntryKind::Commit,
            _ => anyhow::bail!("unsupported inventory tree mode"),
        };
        let row = GitTreeEntryProjection {
            name: entry.name,
            kind,
            oid: entry.oid.to_hex(),
        };
        row.tree_entry()?;
        rows.push(row);
    }
    let mut pages = Vec::new();
    let mut encoded_bytes = 0_usize;
    // An empty tree still has one explicit terminal page.
    for start in (0..total_entries.max(1)).step_by(MAX_INVENTORY_PAGE_ROWS) {
        let end = (start + MAX_INVENTORY_PAGE_ROWS).min(total_entries);
        let page = MirrorTreeInventoryPage {
            tree_oid: tree_oid.into(),
            source_commitment: source.into(),
            total_entries,
            start_index: start,
            entries: rows[start..end].to_vec(),
            next_cursor: (end < total_entries).then(|| MirrorTreeInventoryCursor {
                tree_oid: tree_oid.into(),
                source_commitment: source.into(),
                next_index: end,
            }),
        };
        let bytes = serde_json::to_vec(&page)?.len();
        ensure!(
            bytes <= MAX_INVENTORY_PAGE_BYTES,
            "inventory row page is too large"
        );
        encoded_bytes = encoded_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("inventory cache accounting overflow"))?;
        ensure!(
            encoded_bytes <= MAX_INVENTORY_CACHE_BYTES,
            "inventory semantic cache is too large"
        );
        pages.push(page);
    }
    Ok(pages)
}

#[cfg(test)]
mod tests;
