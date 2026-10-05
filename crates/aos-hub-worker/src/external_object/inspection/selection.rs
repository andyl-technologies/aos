//! Exact source derivation from existing typed inspection plans.
//!
//! ```text
//! selector = {path, maximum_bytes, expected_sha256?}
//! ```
//!
//! A selector cannot expand the signed operation's path or format bound. The
//! documentation NAR is further pinned by its signed complete content hash.

use anyhow::{Result, ensure};
use aos_hub_core::storage_work::{MAX_METADATA_BYTES, StorageWorkOperation, StorageWorkPlan};
use aos_registry_surface::{object, object_bundle};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Selection {
    pub path: String,
    pub maximum_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
}

impl Selection {
    pub(in crate::external_object) fn from_plan(
        plan: &StorageWorkPlan,
        path: &str,
    ) -> Result<Self> {
        plan.object_key(path)?;
        let git = |oids: &[String]| -> Result<u64> {
            for oid in oids {
                let selected = object::Oid::from_hex(oid)?;
                if path == selected.loose_path() {
                    return Ok(object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES);
                }
                if path == object_bundle::shard_path(&oid[..2])? {
                    return Ok(object_bundle::MAX_BUNDLE_BYTES as u64);
                }
            }
            anyhow::bail!("inspection source is not selected by a Git OID")
        };
        let (maximum_bytes, expected_sha256) = match &plan.operation {
            StorageWorkOperation::Head { path: selected } => {
                ensure!(selected == path, "protected HEAD path differs");
                let expected = if aos_hub_core::storage_work::admitted_oci_blob_path(path) {
                    path.rsplit('/').next().map(str::to_owned)
                } else {
                    None
                };
                (
                    aos_hub_core::storage_work::MAX_VERIFY_SOURCE_BYTES,
                    expected,
                )
            }
            StorageWorkOperation::HashOciRange {
                path: selected,
                total,
                strong_etag,
                expected_provider_version,
                guarded_source,
                ..
            } => {
                ensure!(selected == path, "inventory selected path differs");
                if let Some(version) = expected_provider_version {
                    ensure!(
                        version != "null"
                            && aos_hub_core::storage_work::valid_provider_version(version)
                            && guarded_source.is_none(),
                        "versioned inventory cannot adopt a closure"
                    );
                    aos_hub_core::surface_write::strong_if_match_etag(strong_etag)?;
                    (*total, None)
                } else {
                    let guarded = guarded_source.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("protected inventory source closure absent")
                    })?;
                    guarded.validate_for(&guarded.scope.full_key, *total, strong_etag)?;
                    (*total, Some(guarded.closure.sha256.clone()))
                }
            }
            StorageWorkOperation::InspectMetadata { path: selected } => {
                ensure!(selected == path, "metadata path differs");
                (MAX_METADATA_BYTES as u64, None)
            }
            StorageWorkOperation::InspectMetadataObjects { paths, cursor } => {
                ensure!(
                    paths
                        .get(*cursor..)
                        .ok_or_else(|| anyhow::anyhow!("metadata cursor differs"))?
                        .iter()
                        .any(|selected| selected == path),
                    "metadata batch path differs"
                );
                (MAX_METADATA_BYTES as u64, None)
            }
            StorageWorkOperation::InspectGitObject { oid }
            | StorageWorkOperation::FilterGitTreeEntries { oid, .. } => {
                (git(std::slice::from_ref(oid))?, None)
            }
            StorageWorkOperation::InspectGitObjects { oids } => (git(oids)?, None),
            StorageWorkOperation::InspectDocumentation { artifact, .. }
            | StorageWorkOperation::InspectDocumentationContent { artifact, .. } => {
                let narinfo = format!(
                    "{}.narinfo",
                    aos_registry_surface::store::store_path_hash(&artifact.store_path)?
                );
                if path == narinfo {
                    (64 * 1024, None)
                } else {
                    ensure!(
                        path.starts_with("nar/") && path.ends_with(".nar"),
                        "documentation source is not a canonical NAR"
                    );
                    ensure!(artifact.nar_size <= aos_hub_core::storage_work::protected_inspection::MAX_DOCUMENT_NAR_BYTES as u64, "documentation NAR exceeds format bound");
                    (
                        artifact.nar_size,
                        Some(aos_registry_surface::store::canonical_digest_hex(
                            &artifact.nar_hash,
                        )?),
                    )
                }
            }
            StorageWorkOperation::InspectOciRange { path: selected, .. } => {
                ensure!(selected == path, "OCI range path differs");
                let hash = path
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("OCI digest absent"))?;
                (
                    aos_hub_core::storage_work::MAX_VERIFY_SOURCE_BYTES,
                    Some(hash.into()),
                )
            }
            StorageWorkOperation::InspectStoredGitPack { index_path, .. } => {
                (pack_bound(index_path, path)?, None)
            }
            StorageWorkOperation::FilterStoredGitPackTree { query } => {
                (pack_bound(&query.index_path, path)?, None)
            }
            _ => anyhow::bail!("not an admitted typed protected inspection"),
        };
        Ok(Self {
            path: path.into(),
            maximum_bytes,
            expected_sha256,
        })
    }

    pub(in crate::external_object) fn validate_scope(
        &self,
        plan: &StorageWorkPlan,
        binding_prefix: &str,
        scope: &aos_hub_core::storage_authority::control::StorageAuthorityObjectScope,
    ) -> Result<()> {
        self.validate(plan)?;
        ensure!(
            scope.full_key
                == aos_hub_core::keymap::r2_key(binding_prefix, &plan.object_key(&self.path)?),
            "typed inspection selected another physical key"
        );
        Ok(())
    }

    pub(in crate::external_object) fn validate(&self, plan: &StorageWorkPlan) -> Result<()> {
        plan.validate_observation_shape(&plan.deployment_id)?;
        ensure!(
            *self == Self::from_plan(plan, &self.path)?,
            "typed inspection selector changed"
        );
        Ok(())
    }
}

fn pack_bound(index: &str, path: &str) -> Result<u64> {
    if path == index {
        return Ok(4 * 1024 * 1024);
    }
    ensure!(
        Some(path) == aos_registry_surface::pack_index::companion_pack_path(index).as_deref(),
        "pack pair path differs"
    );
    Ok(8 * 1024 * 1024)
}
