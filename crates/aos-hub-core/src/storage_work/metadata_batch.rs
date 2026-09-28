//! Ordered, bounded pages of storage-local registry metadata observations.
//!
//! Missing objects occupy their own positions so a partial reply cannot hide a
//! channel partition. A page carries an exact prefix of the requested paths:
//!
//! ```json
//! {"objects":[{"path":"channels/main/00","document":null}],"next_cursor":1}
//! ```
//!
//! Parallel inspection may read documents beyond the returned prefix. The
//! result counts those source reads; subsequent pages retain bounded replies.

use anyhow::{Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{
    StorageObjectIdentity, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan,
    StorageWorkResult, MAX_METADATA_BYTES, MAX_METADATA_INSPECTION_BATCH, MAX_RESULT_BYTES,
};

/// One exact metadata body and its provider snapshot identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMetadataDocument {
    /// Exact source object observed while reading the document.
    pub source: StorageObjectIdentity,
    /// Standard-base64 exact document bytes, bounded by the metadata limit.
    pub content_base64: String,
}

/// One observation at a specified position in a metadata batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMetadataObject {
    /// Surface-relative path at this position in the issued plan.
    pub path: String,
    /// Exact bounded document, or `None` for definite absence.
    pub document: Option<StorageMetadataDocument>,
}

/// One ordered prefix of the remaining metadata paths in a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMetadataPage {
    /// Explicit present or absent observations, in request order.
    pub objects: Vec<StorageMetadataObject>,
    /// First unreturned path, or `None` when every path has been observed.
    pub next_cursor: Option<usize>,
}

impl StorageMetadataPage {
    /// Validates ordering, continuation, source identities, and body limits.
    ///
    /// Each page must advance the cursor and account for every position in its
    /// prefix. Native still verifies each returned document's signature.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported plan, an incomplete or reordered
    /// prefix, inconsistent source identity, malformed body, or byte overflow.
    pub fn validate(&self, plan: &StorageWorkPlan, source_bytes: u64) -> Result<()> {
        let (paths, cursor) = batch_selector(plan)?;
        let end = cursor
            .checked_add(self.objects.len())
            .context("metadata page cursor overflowed")?;
        anyhow::ensure!(
            !self.objects.is_empty()
                && end <= paths.len()
                && self.next_cursor == (end < paths.len()).then_some(end),
            "storage metadata page has an invalid continuation or empty prefix"
        );

        let mut returned_bytes = 0_u64;
        for (path, object) in paths[cursor..end].iter().zip(&self.objects) {
            returned_bytes = returned_bytes
                .checked_add(validate_object(plan, path, object)?)
                .context("metadata page byte count overflowed")?;
        }

        let maximum_source_bytes = (paths.len() - cursor) as u64 * MAX_METADATA_BYTES as u64;
        anyhow::ensure!(
            returned_bytes <= MAX_METADATA_BYTES as u64
                && source_bytes >= returned_bytes
                && source_bytes <= maximum_source_bytes
                && (self.next_cursor.is_some() || source_bytes == returned_bytes),
            "storage metadata page exceeds its body or source byte budget"
        );
        Ok(())
    }
}

/// Packs a bounded metadata response from all remaining ordered observations.
///
/// Documents are inspected in parallel beside storage. The response retains a
/// contiguous prefix within both the decoded-body and serialized-result budgets;
/// even a maximum-sized single document remains representable. Source bytes
/// include all observed bodies, including any deferred to the next page.
///
/// # Errors
///
/// Returns an error for an unsupported plan, wrong observation count or order,
/// invalid document identity, byte overflow, or an unrepresentable first entry.
pub fn paged_metadata_result(
    plan: &StorageWorkPlan,
    objects: Vec<StorageMetadataObject>,
) -> Result<StorageWorkResult> {
    let (paths, cursor) = batch_selector(plan)?;
    anyhow::ensure!(
        objects.len() == paths.len() - cursor,
        "metadata inspection omitted requested observations"
    );
    let source_bytes =
        paths[cursor..]
            .iter()
            .zip(&objects)
            .try_fold(0_u64, |sum, (path, object)| {
                sum.checked_add(validate_object(plan, path, object)?)
                    .context("metadata inspection source byte count overflowed")
            })?;
    let mut page = StorageMetadataPage {
        objects: Vec::new(),
        next_cursor: Some(cursor),
    };
    let mut decoded_bytes = 0_u64;
    for object in objects {
        let next_bytes = decoded_bytes
            .checked_add(
                object
                    .document
                    .as_ref()
                    .map_or(0, |document| document.source.size),
            )
            .context("metadata page body byte count overflowed")?;
        if next_bytes > MAX_METADATA_BYTES as u64 {
            break;
        }
        page.objects.push(object);
        let end = cursor + page.objects.len();
        page.next_cursor = (end < paths.len()).then_some(end);
        let candidate = result_for_page(plan, &page, source_bytes);
        if serde_json::to_vec(&candidate)?.len() > MAX_RESULT_BYTES {
            page.objects.pop();
            let end = cursor + page.objects.len();
            page.next_cursor = (end < paths.len()).then_some(end);
            break;
        }
        decoded_bytes = next_bytes;
    }
    page.validate(plan, source_bytes)?;
    Ok(result_for_page(plan, &page, source_bytes))
}

fn batch_selector(plan: &StorageWorkPlan) -> Result<(&[String], usize)> {
    let StorageWorkOperation::InspectMetadataObjects { paths, cursor } = &plan.operation else {
        anyhow::bail!("metadata paging requires an ordered metadata inspection plan");
    };
    anyhow::ensure!(
        !paths.is_empty()
            && paths.len() <= MAX_METADATA_INSPECTION_BATCH
            && *cursor < paths.len()
            && paths.iter().all(|path| {
                super::valid_relative_path(path, false) && super::admitted_metadata_path(path)
            })
            && paths.windows(2).all(|pair| pair[0] < pair[1]),
        "metadata inspection has an invalid path set or cursor"
    );
    Ok((paths, *cursor))
}

fn validate_object(
    plan: &StorageWorkPlan,
    path: &str,
    object: &StorageMetadataObject,
) -> Result<u64> {
    anyhow::ensure!(
        object.path == path,
        "storage metadata page reordered its paths"
    );
    let Some(document) = &object.document else {
        return Ok(0);
    };
    crate::surface_write::strong_if_match_etag(&document.source.etag)?;
    anyhow::ensure!(
        document.source.key == plan.object_key(path)?
            && document.source.size <= MAX_METADATA_BYTES as u64,
        "storage metadata page names another or oversized object"
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&document.content_base64)
        .context("decoding storage metadata page document")?;
    anyhow::ensure!(
        bytes.len() as u64 == document.source.size,
        "storage metadata page body disagrees with its source size"
    );
    Ok(document.source.size)
}

fn result_for_page(
    plan: &StorageWorkPlan,
    page: &StorageMetadataPage,
    source_bytes: u64,
) -> StorageWorkResult {
    StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome: StorageWorkOutcome::MetadataObjects { page: page.clone() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(paths: &[&str], cursor: usize) -> StorageWorkPlan {
        StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "metadata-test".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 1,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 4,
            binding_kind: "deployment_r2".into(),
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "tenant".into(),
            operation: StorageWorkOperation::InspectMetadataObjects {
                paths: paths.iter().map(|path| (*path).into()).collect(),
                cursor,
            },
        }
    }

    fn observation(
        plan: &StorageWorkPlan,
        path: &str,
        bytes: Option<Vec<u8>>,
    ) -> StorageMetadataObject {
        StorageMetadataObject {
            path: path.into(),
            document: bytes.map(|bytes| StorageMetadataDocument {
                source: StorageObjectIdentity {
                    provider_version: None,
                    key: plan.object_key(path).unwrap(),
                    size: bytes.len() as u64,
                    etag: "\"snapshot\"".into(),
                },
                content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            }),
        }
    }

    fn page(result: &StorageWorkResult) -> &StorageMetadataPage {
        let StorageWorkOutcome::MetadataObjects { page } = &result.outcome else {
            panic!("expected a metadata page");
        };
        page
    }

    #[test]
    fn maximum_documents_paginate_without_losing_absent_positions() {
        let paths = [
            "channels/main/00",
            "channels/main/01",
            "channels/main/02",
            "channels/main/03",
        ];
        let first_plan = plan(&paths, 0);
        let objects = vec![
            observation(&first_plan, paths[0], None),
            observation(&first_plan, paths[1], Some(vec![1; MAX_METADATA_BYTES])),
            observation(&first_plan, paths[2], Some(vec![2; MAX_METADATA_BYTES])),
            observation(&first_plan, paths[3], None),
        ];

        let first = paged_metadata_result(&first_plan, objects.clone()).unwrap();

        assert_eq!(page(&first).objects, objects[..2]);
        assert_eq!(page(&first).next_cursor, Some(2));
        assert_eq!(first.source_bytes, 2 * MAX_METADATA_BYTES as u64);
        assert!(serde_json::to_vec(&first).unwrap().len() <= MAX_RESULT_BYTES);

        let second_plan = plan(&paths, 2);
        let second = paged_metadata_result(&second_plan, objects[2..].to_vec()).unwrap();

        assert_eq!(page(&second).objects, objects[2..]);
        assert_eq!(page(&second).next_cursor, None);
        assert_eq!(second.source_bytes, MAX_METADATA_BYTES as u64);
        assert!(serde_json::to_vec(&second).unwrap().len() <= MAX_RESULT_BYTES);
        let combined = page(&first)
            .objects
            .iter()
            .chain(&page(&second).objects)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(combined, objects);
    }

    #[test]
    fn serialized_identity_overhead_also_triggers_pagination() {
        let paths = (0..32)
            .map(|index| format!("channels/{}/{index:02x}", "x".repeat(2000)))
            .collect::<Vec<_>>();
        let requested = paths.iter().map(String::as_str).collect::<Vec<_>>();
        let plan = plan(&requested, 0);
        let objects = paths
            .iter()
            .map(|path| {
                let mut object = observation(&plan, path, Some(vec![9; 2048]));
                object.document.as_mut().unwrap().source.etag = format!("\"{}\"", "e".repeat(2048));
                object
            })
            .collect::<Vec<_>>();

        let result = paged_metadata_result(&plan, objects).unwrap();

        assert!(page(&result).objects.len() < 32);
        assert_eq!(page(&result).next_cursor, Some(page(&result).objects.len()));
        assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESULT_BYTES);
    }

    #[test]
    fn validation_rejects_incomplete_reordered_or_forged_observations() {
        let plan = plan(&["HEAD", "info/refs"], 0);
        let objects = vec![
            observation(&plan, "HEAD", Some(b"ref: refs/heads/main".to_vec())),
            observation(&plan, "info/refs", None),
        ];
        let result = paged_metadata_result(&plan, objects).unwrap();
        let valid = page(&result);

        let mut changed = valid.clone();
        changed.objects.pop();
        assert!(changed.validate(&plan, result.source_bytes).is_err());

        let mut changed = valid.clone();
        changed.objects.swap(0, 1);
        assert!(changed.validate(&plan, result.source_bytes).is_err());

        let mut changed = valid.clone();
        changed.next_cursor = Some(0);
        assert!(changed.validate(&plan, result.source_bytes).is_err());

        let mut changed = valid.clone();
        changed.objects[0].document.as_mut().unwrap().source.key = "other/HEAD".into();
        assert!(changed.validate(&plan, result.source_bytes).is_err());

        let mut changed = valid.clone();
        changed.objects[0].document.as_mut().unwrap().content_base64 = "AA==".into();
        assert!(changed.validate(&plan, result.source_bytes).is_err());
        assert!(valid.validate(&plan, result.source_bytes + 1).is_err());
    }

    #[test]
    fn plan_rejects_bulk_paths_duplicates_and_invalid_cursors() {
        for (paths, cursor) in [
            (vec!["HEAD", "info/refs"], 2),
            (vec!["HEAD", "HEAD"], 0),
            (vec!["info/refs", "HEAD"], 0),
            (vec!["nar/bulk.nar"], 0),
            (vec!["channels/main/../private"], 0),
            (Vec::new(), 0),
        ] {
            assert!(plan(&paths, cursor).validate("metadata-test", 101).is_err());
        }
        let paths = vec!["HEAD"; MAX_METADATA_INSPECTION_BATCH + 1];
        assert!(plan(&paths, 0).validate("metadata-test", 101).is_err());
        assert!(plan(&["HEAD", "info/refs"], 0)
            .validate("metadata-test", 101)
            .is_ok());
    }
}
