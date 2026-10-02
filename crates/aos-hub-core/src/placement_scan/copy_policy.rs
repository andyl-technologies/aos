//! Catalogue selection for a currently authenticated protected copy profile.
//!
//! Physical keys outside the logical catalogue remain counted unknown. They
//! cannot acquire source authority from discovery or matching LIST metadata.
//! Every catalogue object uses the claimed adapter, including retained replay;
//! the parent controller then performs its normal full destination inventory.

use super::*;
use crate::fetch::SurfaceListPage;
use crate::surface_write::PlacementCopyPolicy;

impl PlacementScanController {
    pub(super) async fn copy_catalogue_objects(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        fetch: &dyn SurfaceFetch,
        writes: &dyn SurfaceWriteProvider,
        surface: SurfaceTarget,
        catalogue: Vec<SurfaceObjectRecord>,
        first_page: SurfaceListPage,
        page_limit: usize,
        max_pages: usize,
        policy: &PlacementCopyPolicy,
        policy_path: &str,
    ) -> Result<serde_json::Value> {
        let known = catalogue.iter().map(|object| object.object_key.as_str())
            .collect::<BTreeSet<_>>();
        for object in &catalogue {
            anyhow::ensure!(object.content_hash.is_some()
                && object.size.is_some_and(|size| size >= 0),
                "protected placement copy requires every current catalogue hash and size");
        }

        let mut cursor = None;
        let mut page = Some(first_page);
        let mut prior_path: Option<String> = None;
        let mut budget = SurfaceListingBudget::default();
        let mut evidence = BTreeMap::new();
        let mut unknown_objects = 0_i64;
        let mut unknown_sample = Vec::new();
        for page_number in 1..=max_pages {
            let current = match page.take() {
                Some(page) => page,
                None => fetch.list_page(cursor.as_deref(), page_limit).await?,
            };
            current.validate(page_limit, cursor.as_deref())?;
            for path in current.paths {
                anyhow::ensure!(prior_path.as_ref().is_none_or(|prior| prior < &path),
                    "protected copy source returned keys out of global order");
                budget.record(&path)?;
                prior_path = Some(path.clone());
                if known.contains(path.as_str()) {
                    if let Some(value) = current.evidence.get(&path) {
                        evidence.insert(path, value.clone());
                    }
                } else {
                    unknown_objects = unknown_objects.checked_add(1)
                        .context("protected copy unknown count overflow")?;
                    if unknown_sample.len() < PLACEMENT_SCAN_ISSUE_SAMPLE_LIMIT {
                        unknown_sample.push(path);
                    }
                }
            }
            cursor = current.next_cursor;
            if cursor.is_none() {
                break;
            }
            if page_number == max_pages {
                bail!("protected placement copy exceeded the page limit");
            }
        }

        let mut copied_bytes = 0_u64;
        for object in &catalogue {
            // The adapter checks the pinned installed profile in its existing
            // authenticated per-object metadata exchange before effects/replay.
            let size = writes.copy_placement_object_with_policy(operation, claim_token,
                source, destination, &object.object_key,
                evidence.get(&object.object_key), Some(policy)).await?
                .context("protected placement copy refuses a Native body fallback")?;
            anyhow::ensure!(u64::try_from(object.size.context("trusted size disappeared")?)? == size,
                "protected copy receipt differs from trusted catalogue size");
            copied_bytes = copied_bytes.checked_add(size)
                .context("protected placement copy byte count overflow")?;
        }

        anyhow::ensure!(writes.placement_copy_policy(operation, claim_token, source,
            destination, policy_path).await?.as_ref() == Some(policy),
            "installed protected placement copy policy changed");
        anyhow::ensure!(self.db.list_active_surface_objects(surface).await? == catalogue,
            "logical catalogue changed during protected placement copy");
        Ok(serde_json::json!({
            "source": source.name,
            "destination": destination.name,
            "copiedObjects": catalogue.len(),
            "copiedBytes": copied_bytes,
            "reusedObjects": 0,
            "unknownSourceObjects": unknown_objects,
            "unknownSourceSample": unknown_sample,
            "catalogueOnly": true,
            "profileDigest": policy.profile_digest,
        }))
    }
}
