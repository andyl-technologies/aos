//! Authenticated evidence of a completed installed immutable-version read.
//!
//! This is neither a permanent producer closure nor a lease. The Worker source
//! guard selects the actual provider version and pins it through conditional
//! reads; Native separately checks the current accepted Read profile and scope.
//!
//! ```text
//! evidence = {version: 1, producer_profile_digest, configured_domain_digest,
//!             scope, source: {key, size, etag, provider_version},
//!             range: null | [inclusive_start, inclusive_end], metadata_only?: true, sha256}
//! ```

use crate::{
    storage_authority::control::StorageAuthorityObjectScope,
    storage_work::{StorageObjectIdentity, StorageWorkPlan},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Describes exact bytes consumed from a genuine installed provider version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedInspectionSource {
    /// Closed evidence format; independent of permanent guard receipts.
    pub version: u32,
    /// Actual accepted producer profile, not a caller-selected capability.
    pub producer_profile_digest: String,
    /// Exact installed versioned provider/cohort configuration commitment.
    pub configured_domain_digest: String,
    /// Independently derived physical Read scope.
    pub scope: StorageAuthorityObjectScope,
    /// Actual immutable provider identity used by every conditional request.
    pub source: StorageObjectIdentity,
    /// Exact consumed inclusive interval, absent for a complete encoded body.
    pub range: Option<(u64, u64)>,
    /// True only for a metadata-only HEAD with zero consumed source bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub metadata_only: bool,
    /// Independently computed SHA-256 of exactly the consumed bytes.
    pub sha256: String,
}

impl VersionedInspectionSource {
    /// Checks shape without authenticating a Worker result or authorizing reads.
    ///
    /// # Errors
    /// Refuses null/missing versions, weak tags, excessive or inconsistent ranges,
    /// malformed commitments or an invalid physical scope.
    pub fn validate(&self) -> Result<()> {
        self.scope.guard_name()?;
        crate::surface_write::strong_if_match_etag(&self.source.etag)?;
        ensure!(
            self.version == 1
                && crate::direct_upload::valid_direct_digest(&self.producer_profile_digest)
                && crate::direct_upload::valid_direct_digest(&self.configured_domain_digest)
                && crate::direct_upload::valid_direct_digest(&self.sha256)
                && self
                    .source
                    .provider_version
                    .as_deref()
                    .is_some_and(|version| version != "null"
                        && crate::storage_work::valid_provider_version(version))
                && self.source.size <= crate::storage_work::MAX_VERIFY_SOURCE_BYTES,
            "versioned inspection identity malformed"
        );
        if self.metadata_only {
            ensure!(
                self.range.is_none()
                    && self.sha256
                        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "metadata-only source fabricated body evidence"
            );
        }
        if let Some((start, end)) = self.range {
            ensure!(
                start <= end
                    && end < self.source.size
                    && end - start < crate::direct_upload::MAX_DIRECT_PART_BYTES,
                "versioned inspection interval differs"
            );
        }
        Ok(())
    }

    /// Correlates evidence with the exact independently selected physical key.
    ///
    /// # Errors
    /// Refuses another plan path, binding prefix or observed identity.
    pub fn validate_identity(
        &self,
        plan: &StorageWorkPlan,
        path: &str,
        binding_prefix: &str,
        source: &StorageObjectIdentity,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            source == &self.source
                && source.key == plan.object_key(path)?
                && self.scope.full_key == crate::keymap::r2_key(binding_prefix, &source.key),
            "versioned inspection physical identity differs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> VersionedInspectionSource {
        let guarded = super::super::tests::fixture();
        VersionedInspectionSource {
            version: 1,
            producer_profile_digest: "a".repeat(64),
            configured_domain_digest: "b".repeat(64),
            scope: guarded.scope,
            source: StorageObjectIdentity {
                key: "placement/object".into(),
                size: 8,
                etag: "\"actual-tag\"".into(),
                provider_version: Some("actual-provider-version".into()),
            },
            range: None,
            metadata_only: false,
            sha256: "c".repeat(64),
        }
    }

    #[test]
    fn versioned_evidence_has_no_closure_and_rejects_null_version_or_metadata_body_claim() {
        let source = source();
        source.validate().unwrap();
        assert!(
            serde_json::to_value(&source)
                .unwrap()
                .get("closure")
                .is_none()
        );
        for version in [None, Some("null".into()), Some("".into())] {
            let mut changed = source.clone();
            changed.source.provider_version = version;
            assert!(changed.validate().is_err());
        }
        let mut changed = source.clone();
        changed.metadata_only = true;
        assert!(changed.validate().is_err());
        changed.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
        changed.validate().unwrap();
        changed.range = Some((0, 7));
        assert!(changed.validate().is_err());
    }

    #[test]
    fn absent_new_result_field_keeps_exact_original_signed_bytes() {
        let original = br#"{"plan_id":"original","placement_id":1,"placement_resource_version":2,"binding_id":3,"binding_resource_version":4,"source_bytes":0,"outcome":{"kind":"not_found"}}"#;
        let result: crate::storage_work::StorageWorkResult =
            serde_json::from_slice(original).unwrap();
        assert!(result.versioned_sources.is_empty());
        assert_eq!(serde_json::to_vec(&result).unwrap(), original);
        let key = crate::storage_work::StorageWorkKey::new([7; 32]).unwrap();
        assert_eq!(
            key.sign_body(original).unwrap(),
            "87c88bdd32844ec8ea81800b2609104b27ef88ee5b9a129006484cb84592ab3d"
        );
        assert_eq!(
            key.sign_body(&serde_json::to_vec(&result).unwrap())
                .unwrap(),
            "87c88bdd32844ec8ea81800b2609104b27ef88ee5b9a129006484cb84592ab3d"
        );
    }

    #[test]
    fn versioned_pack_mode_and_both_versions_bind_absent_tree_cursor() {
        use crate::mirror_inspection::{
            MirrorPackProjection, MirrorPackSource, MirrorPackTreeProjection, MirrorPackTreeQuery,
        };
        let path = format!("objects/pack/pack-{}.idx", "a".repeat(64));
        let pair = MirrorPackProjection {
            pack: MirrorPackSource {
                provider_version: None,
                guarded_source: None,
                path: path.replace(".idx", ".pack"),
                size: 8,
                etag: "\"pack\"".into(),
                sha256: "b".repeat(64),
            },
            index: MirrorPackSource {
                provider_version: None,
                guarded_source: None,
                path: path.clone(),
                size: 8,
                etag: "\"index\"".into(),
                sha256: "c".repeat(64),
            },
            pack_trailer_sha256: "a".repeat(64),
            objects: vec![],
            missing_oids: vec![],
            inflated_entry_bytes: 0,
            peak_decoded_graph_bytes: 0,
        };
        let old = pair.source_commitment().unwrap();
        assert!(
            serde_json::to_value(&pair).unwrap()["pack"]
                .get("provider_version")
                .is_none()
        );
        let mut pair = pair;
        pair.pack.provider_version = Some("pack-v1".into());
        assert!(pair.source_commitment().is_err());
        pair.index.provider_version = Some("index-v1".into());
        let first = pair.source_commitment().unwrap();
        assert_ne!(old, first);
        let query = MirrorPackTreeQuery {
            index_path: path,
            oid: "e".repeat(64),
            names: vec!["entry".into(), "next".into()],
            protected_profile_digest: "f".repeat(64),
            cursor: Some(crate::tree_projection::GitTreeCursor {
                tree_oid: "e".repeat(64),
                selection_digest: crate::tree_projection::selection_digest(&[
                    "entry".into(),
                    "next".into(),
                ])
                .unwrap(),
                source_commitment: first.clone(),
                next_index: 1,
            }),
        };
        let projection = MirrorPackTreeProjection {
            pair: pair.clone(),
            tree_oid: query.oid.clone(),
            object_size: None,
            page: None,
        };
        projection.validate(&query).unwrap();
        pair.index.provider_version = Some("index-v2".into());
        assert_ne!(first, pair.source_commitment().unwrap());
        let changed = MirrorPackTreeProjection { pair, ..projection };
        assert!(changed.validate(&query).is_err());
    }
}
