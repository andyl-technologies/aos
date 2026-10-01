//! Closed upstream Git pack inspection and bounded selected-content results.
//!
//! Native selects the source configuration and OIDs. Worker verifies the entire
//! pack/index pair beside storage before returning encoded commitments and
//! selected decoded content. Neither encoded source body is a result field.
//!
//! ```text
//! approved HTTPS source + canonical index path + <=8 OIDs/ranges
//!   -> encoded SHA256/size/ETag commitments + <=128KiB decoded projection
//! ```

use anyhow::{ensure, Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::direct_upload::valid_direct_digest;

/// Native-selected original for one immutable upstream inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackInspection {
    /// Registry selecting the upstream trust policy.
    pub registry_id: i64,
    /// Exact current registry configuration version.
    pub registry_resource_version: i64,
    /// Exact current source and trust-policy version.
    pub mirror_resource_version: i64,
    /// Approved HTTPS base, excluding credentials, query and fragment.
    pub upstream_base: String,
    /// Canonical immutable SHA-256 index path.
    pub index_path: String,
    /// Actual qualified managed provider and workflow profile commitment.
    pub protected_profile_digest: String,
    /// Strictly ordered unique OIDs and bounded content ranges.
    pub selections: Vec<MirrorPackSelection>,
}

impl MirrorPackInspection {
    /// Checks the complete source selection before any read is dispatched.
    ///
    /// URL validation supplies the repository's pure URL policy; deployments
    /// retain their platform Fetch or configured egress-router policy.
    ///
    /// # Errors
    /// Returns an error for malformed identity, unsafe source, noncanonical pack
    /// path, or an oversized, unsorted or invalid selection.
    pub fn validate(&self) -> Result<()> {
        let source = url::Url::parse(&self.upstream_base)?;
        ensure!(
            self.registry_id > 0
                && self.registry_resource_version > 0
                && self.mirror_resource_version > 0
                && valid_direct_digest(&self.protected_profile_digest)
                && source.scheme() == "https"
                && source.username().is_empty()
                && source.password().is_none()
                && source.query().is_none()
                && source.fragment().is_none(),
            "pack inspection source is invalid"
        );
        crate::url_guard::is_safe_remote_url(&self.upstream_base)?;
        ensure!(
            self.index_path.len() <= 512
                && aos_registry_surface::pack_index::companion_pack_path(&self.index_path)
                    .is_some(),
            "pack inspection index path is not canonical"
        );
        validate_selections(&self.selections)
    }
}

/// A half-open range in fully verified decoded Git object content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorPackRange {
    /// Inclusive byte offset.
    pub start: u64,
    /// Exclusive byte offset.
    pub end: u64,
}

/// One exact Git object selection, with an optional bounded content range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorPackSelection {
    /// Full lowercase SHA-256 Git OID.
    pub oid: String,
    /// `None` selects the whole object within the result limit.
    pub range: Option<MirrorPackRange>,
}

/// Exact named-entry query for a tree within one canonical stored pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackTreeQuery {
    /// Canonical stored index path under the selected placement.
    pub index_path: String,
    /// Full verified tree OID.
    pub oid: String,
    /// Strictly ordered exact component names, never a generic predicate.
    pub names: Vec<String>,
    /// Original source/predicate continuation, if a later page is requested.
    pub cursor: Option<crate::tree_projection::GitTreeCursor>,
    /// Current independently qualified managed profile commitment.
    pub protected_profile_digest: String,
}

impl MirrorPackTreeQuery {
    /// Validates bounded identity and the exact name predicate before reads.
    ///
    /// # Errors
    /// Returns an error for malformed paths, profile, OID, names or continuation.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.index_path.len() <= 512
                && aos_registry_surface::pack_index::companion_pack_path(&self.index_path)
                    .is_some()
                && valid_direct_digest(&self.protected_profile_digest),
            "pack tree query source is invalid"
        );
        crate::tree_projection::validate_request(&self.oid, &self.names, self.cursor.as_ref())
    }
}

/// Bounded selected rows authenticated by the exact verified pack/index source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackTreeProjection {
    /// Full pair commitments; selected object bytes and missing OIDs are empty.
    pub pair: MirrorPackProjection,
    /// Exact requested tree OID, including for a verified absent selection.
    pub tree_oid: String,
    /// Present verified tree length, absent only after full pair verification.
    pub object_size: Option<u64>,
    /// At most 16KiB name/kind/OID rows; no raw decoded tree is returned.
    pub page: Option<crate::tree_projection::GitTreeEntriesPage>,
}

impl MirrorPackTreeProjection {
    /// Correlates exact source commitments, absent/present state and page bounds.
    ///
    /// # Errors
    /// Returns an error for a changed source/tree/predicate or malformed output.
    pub fn validate(&self, query: &MirrorPackTreeQuery) -> Result<()> {
        query.validate()?;
        self.pair.validate(&query.index_path, &[])?;
        ensure!(
            self.tree_oid == query.oid && self.object_size.is_some() == self.page.is_some(),
            "pack tree result changed its selected identity"
        );
        if let (Some(size), Some(page)) = (self.object_size, &self.page) {
            ensure!(
                size <= 4 * 1024 * 1024,
                "pack tree exceeds decoded object bound"
            );
            page.validate(
                &query.oid,
                &query.names,
                query.cursor.as_ref(),
                &self.pair.source_commitment()?,
            )?;
        }
        Ok(())
    }
}

/// Actual encoded source commitment from the same inspected response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorPackSource {
    /// Canonical surface-relative pack or index path.
    pub path: String,
    /// Independently computed SHA-256 of the complete encoded body.
    pub sha256: String,
    /// Actual encoded source bytes consumed.
    pub size: u64,
    /// Strong ETag observed on that exact response.
    pub etag: String,
}

/// Bounded content selected after whole-object Git identity verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackedObject {
    /// Full independently verified Git object OID.
    pub oid: String,
    /// Closed Git kind: `commit`, `tree`, `tag` or `blob`.
    pub kind: String,
    /// Full decoded content size before selection.
    pub object_size: u64,
    /// Exact returned range, including for a whole-object selection.
    pub range: MirrorPackRange,
    /// Standard-base64 selected decoded bytes, never encoded pack bytes.
    pub content_base64: String,
}

/// Whole-pair commitments and bounded fields returned by storage-side inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorPackProjection {
    /// Exact encoded pack source commitment.
    pub pack: MirrorPackSource,
    /// Exact encoded index source commitment.
    pub index: MirrorPackSource,
    /// Canonical pack path identity, excluding its checksum trailer.
    pub pack_trailer_sha256: String,
    /// Selected objects in strict request OID order.
    pub objects: Vec<MirrorPackedObject>,
    /// Requested OIDs absent from the completely verified pair, in request order.
    pub missing_oids: Vec<String>,
    /// Actual packed entry bytes inflated by the parser.
    pub inflated_entry_bytes: u64,
    /// Actual peak simultaneously live decoded graph bytes, excluding overhead.
    pub peak_decoded_graph_bytes: u64,
}

impl MirrorPackProjection {
    /// Commits only the exact pair source, independently of the selected fields.
    ///
    /// # Errors
    /// Returns an error if the typed source commitment cannot be encoded.
    pub fn source_commitment(&self) -> Result<String> {
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"aos.storage.verified-git-pair-source.v1\0");
        hash.update(serde_json::to_vec(&(
            &self.pack,
            &self.index,
            &self.pack_trailer_sha256,
        ))?);
        Ok(hex::encode(hash.finalize()))
    }

    /// Projects a fully verified explicit presence partition without source bodies.
    ///
    /// # Errors
    /// Returns an error for invalid source ETags or an oversized result envelope.
    pub fn from_available(
        available: aos_registry_surface::pack_index::projection::AvailablePair,
        pack_etag: String,
        index_etag: String,
    ) -> Result<Self> {
        let mut projection = Self::from_verified(available.pair, pack_etag, index_etag)?;
        projection.missing_oids = available
            .missing_oids
            .iter()
            .map(|oid| oid.to_hex())
            .collect();
        ensure!(
            serde_json::to_vec(&projection)?.len() <= 240 * 1024,
            "pack projection exceeds its bounded result envelope"
        );
        Ok(projection)
    }

    /// Projects only commitments and selected decoded fields from a verified pair.
    ///
    /// # Errors
    /// Returns an error for invalid same-response ETags or an oversized result.
    pub fn from_verified(
        pair: aos_registry_surface::pack_index::projection::VerifiedPair,
        pack_etag: String,
        index_etag: String,
    ) -> Result<Self> {
        crate::surface_write::strong_if_match_etag(&pack_etag)?;
        crate::surface_write::strong_if_match_etag(&index_etag)?;
        let projection = Self {
            pack: MirrorPackSource {
                path: pair.pack_path,
                sha256: hex::encode(pair.pack.sha256),
                size: pair.pack.size,
                etag: pack_etag,
            },
            index: MirrorPackSource {
                path: pair.index_path,
                sha256: hex::encode(pair.index.sha256),
                size: pair.index.size,
                etag: index_etag,
            },
            pack_trailer_sha256: hex::encode(pair.pack_trailer_sha256),
            objects: pair
                .objects
                .into_iter()
                .map(|object| MirrorPackedObject {
                    oid: object.oid.to_hex(),
                    kind: object.kind.as_str().into(),
                    object_size: object.object_size,
                    range: MirrorPackRange {
                        start: object.range.start,
                        end: object.range.end,
                    },
                    content_base64: base64::engine::general_purpose::STANDARD
                        .encode(object.content),
                })
                .collect(),
            missing_oids: Vec::new(),
            inflated_entry_bytes: pair.inflated_entry_bytes,
            peak_decoded_graph_bytes: pair.peak_decoded_graph_bytes,
        };
        ensure!(
            serde_json::to_vec(&projection)?.len() <= 240 * 1024,
            "pack projection exceeds its bounded result envelope"
        );
        Ok(projection)
    }

    /// Rechecks exact source, selection, output and full-object identity bounds.
    ///
    /// A fragment is authenticated storage-local output from a verified whole
    /// object; the fragment alone cannot rehash its whole-object OID.
    ///
    /// # Errors
    /// Returns an error for changed paths, malformed commitments, invalid source
    /// identity, oversized output or a result that differs from the selection.
    pub fn validate(&self, index_path: &str, selections: &[MirrorPackSelection]) -> Result<()> {
        use aos_registry_surface::pack_index::projection::MAX_SELECTED_CONTENT_BYTES;

        validate_selections(selections)?;
        let pack_path = aos_registry_surface::pack_index::companion_pack_path(index_path)
            .context("pack projection index path is not canonical")?;
        let path_digest = index_path
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_prefix("pack-"))
            .and_then(|name| name.strip_suffix(".idx"))
            .context("pack index filename is not canonical")?;
        ensure!(
            self.index.path == index_path
                && self.pack.path == pack_path
                && self.pack_trailer_sha256 == path_digest
                && self.pack.size <= 8 * 1024 * 1024
                && self.index.size <= 4 * 1024 * 1024
                && self.inflated_entry_bytes <= 12 * 1024 * 1024
                && self.peak_decoded_graph_bytes <= 12 * 1024 * 1024
                && self.objects.len() + self.missing_oids.len() == selections.len()
                && self
                    .objects
                    .windows(2)
                    .all(|pair| pair[0].oid < pair[1].oid)
                && self.missing_oids.windows(2).all(|pair| pair[0] < pair[1]),
            "pack projection identity or bounds differ"
        );
        for source in [&self.pack, &self.index] {
            ensure!(
                valid_direct_digest(&source.sha256),
                "pack source digest is invalid"
            );
            crate::surface_write::strong_if_match_etag(&source.etag)?;
        }
        let mut returned_bytes = 0_usize;
        let mut objects = self.objects.iter().peekable();
        let mut missing = self.missing_oids.iter().peekable();
        for selection in selections {
            if missing.peek().is_some_and(|oid| **oid == selection.oid) {
                ensure!(
                    !objects
                        .peek()
                        .is_some_and(|object| object.oid == selection.oid),
                    "pack projection contains overlapping presence"
                );
                missing.next();
                continue;
            }
            let object = objects
                .next()
                .context("pack projection omitted a selected presence")?;
            let kind = match object.kind.as_str() {
                "commit" => aos_registry_surface::object::ObjectKind::Commit,
                "tree" => aos_registry_surface::object::ObjectKind::Tree,
                "tag" => aos_registry_surface::object::ObjectKind::Tag,
                "blob" => aos_registry_surface::object::ObjectKind::Blob,
                _ => anyhow::bail!("pack projection kind is invalid"),
            };
            let expected_range = selection.range.unwrap_or(MirrorPackRange {
                start: 0,
                end: object.object_size,
            });
            ensure!(
                object.oid == selection.oid
                    && object.object_size <= 4 * 1024 * 1024
                    && object.range == expected_range
                    && object.range.start <= object.range.end
                    && object.range.end <= object.object_size
                    && object.content_base64.len() <= MAX_SELECTED_CONTENT_BYTES.div_ceil(3) * 4,
                "pack projection selection differs"
            );
            let bytes = base64::engine::general_purpose::STANDARD.decode(&object.content_base64)?;
            ensure!(
                base64::engine::general_purpose::STANDARD.encode(&bytes) == object.content_base64
                    && u64::try_from(bytes.len())? == object.range.end - object.range.start,
                "pack projection content differs from its range"
            );
            returned_bytes = returned_bytes
                .checked_add(bytes.len())
                .context("pack projection output size overflow")?;
            ensure!(
                returned_bytes <= MAX_SELECTED_CONTENT_BYTES,
                "pack projection output exceeds its content bound"
            );
            if object.range.start == 0 && object.range.end == object.object_size {
                ensure!(
                    aos_registry_surface::object::hash_object(kind, &bytes).to_hex() == object.oid,
                    "pack projection whole-object OID differs"
                );
            }
        }
        ensure!(
            objects.next().is_none() && missing.next().is_none(),
            "pack projection reports an unrequested presence"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= 240 * 1024,
            "pack projection exceeds its bounded result envelope"
        );
        Ok(())
    }
}

pub(crate) fn validate_selections(selections: &[MirrorPackSelection]) -> Result<()> {
    ensure!(
        selections.len() <= 8 && selections.windows(2).all(|pair| pair[0].oid < pair[1].oid),
        "pack selections are oversized or not strictly ordered"
    );
    let mut range_bytes = 0_u64;
    for selection in selections {
        ensure!(
            valid_direct_digest(&selection.oid),
            "pack selection OID is invalid"
        );
        if let Some(range) = selection.range {
            ensure!(
                range.start <= range.end && range.end <= 4 * 1024 * 1024,
                "pack selection range is invalid"
            );
            range_bytes = range_bytes
                .checked_add(range.end - range.start)
                .context("pack selection range size overflow")?;
        }
    }
    ensure!(
        range_bytes <= 128 * 1024,
        "pack selection ranges exceed the result bound"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

impl crate::db::Database {
    /// Lists bounded canonical pack candidates from the logical catalogue.
    ///
    /// These names select reads, and do not establish provider presence or Git
    /// validity. The executor independently verifies every selected pair.
    ///
    /// # Errors
    /// Returns an error for database failure or more than 128 candidate pairs.
    pub async fn mirror_git_pack_candidates(
        &self,
        surface: crate::db::SurfaceTarget,
    ) -> Result<Vec<String>> {
        let (registry, cache) = match surface {
            crate::db::SurfaceTarget::Registry(id) => (Some(id), None),
            crate::db::SurfaceTarget::BinaryCache(id) => (None, Some(id)),
        };
        let rows = self
            .backend
            .query(
                "SELECT object_key FROM surface_objects
             WHERE (registry_id = ?1 OR cache_id = ?2)
               AND lifecycle_state = 'active'
               AND (object_key LIKE 'objects/pack/pack-%.idx'
                    OR object_key LIKE '%/objects/pack/pack-%.idx')
             ORDER BY object_key LIMIT 129",
                &[
                    registry
                        .map(crate::value::Value::Int)
                        .unwrap_or(crate::value::Value::Null),
                    cache
                        .map(crate::value::Value::Int)
                        .unwrap_or(crate::value::Value::Null),
                ],
            )
            .await?;
        ensure!(
            rows.len() <= 128,
            "pack lookup exceeds its 128-pair catalogue bound"
        );
        rows.iter()
            .map(|row| {
                let path: String = row.get(0)?;
                ensure!(
                    path.len() <= 512
                        && aos_registry_surface::pack_index::companion_pack_path(&path).is_some(),
                    "catalogue pack path is not canonical"
                );
                Ok(path)
            })
            .collect()
    }
}
