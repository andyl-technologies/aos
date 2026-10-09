//! Validated candidate review and publication action rules for the browser.
//!
//! The browser reviews the same portable revision as producers and the Hub.
//! A revision replacement preserves stage identity and advances exactly once;
//! availability and authorization are rechecked by the API on every action.

use aos_hub_api::StagedRelease;
use aos_registry_format::staging::wire::{MAX_DECODED_REVISION_BYTES, decode_revision};
use aos_registry_format::staging::{StageObject, StageRecord, StageRevision};

/// Maximum artifact rows rendered at once in candidate reviews.
pub(crate) const INVENTORY_PAGE_SIZE: usize = 50;

/// Names an artifact category in the candidate review vocabulary.
pub(crate) fn artifact_label(kind: &str) -> String {
    match kind {
        "image" | "system_image" => "Image".into(),
        "package" | "nar" | "narinfo" => "Package".into(),
        "container" | "oci_blob" | "oci_manifest" => "Container".into(),
        "registry" | "registry_metadata" | "git_object" => "Registry metadata".into(),
        "tuf_metadata" => "Release metadata".into(),
        _ => kind.replace('_', " "),
    }
}

/// One bounded window of artifact indices matching a review filter.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InventoryPage {
    /// Indices of at most fifty matching artifacts in the exact inventory.
    pub indices: Vec<usize>,
    /// Total number of matching artifacts.
    pub matched: usize,
    /// Number of pages, with one empty page when no artifacts match.
    pub pages: usize,
}

/// Selects a bounded artifact window without constructing all matching rows.
pub(crate) fn inventory_page(inventory: &[StageObject], query: &str, page: usize) -> InventoryPage {
    let query = query.trim().to_lowercase();
    let start = page.saturating_mul(INVENTORY_PAGE_SIZE);
    let end = start.saturating_add(INVENTORY_PAGE_SIZE);
    let mut indices = Vec::with_capacity(INVENTORY_PAGE_SIZE);
    let mut matched = 0;

    for (index, object) in inventory.iter().enumerate() {
        if !query.is_empty()
            && !object.path.to_lowercase().contains(&query)
            && !object.kind.to_lowercase().contains(&query)
            && !artifact_label(&object.kind).to_lowercase().contains(&query)
        {
            continue;
        }
        if (start..end).contains(&matched) {
            indices.push(index);
        }
        matched += 1;
    }

    InventoryPage {
        indices,
        matched,
        pages: matched.div_ceil(INVENTORY_PAGE_SIZE).max(1),
    }
}

/// Builds a resume command using the maintainer's local registry selector.
pub(crate) fn resume_command(revision: &StageRevision, local_registry: &str) -> String {
    let selector = if local_registry.trim().is_empty() {
        "YOUR-CONFIGURED-REGISTRY"
    } else {
        local_registry.trim()
    };
    format!(
        "apr release {} --stage {} --stage-revision {} --resume --registry {}",
        shell_argument(&revision.release_id),
        shell_argument(&revision.id),
        revision.revision,
        shell_argument(selector),
    )
}

/// Quotes values containing shell syntax while leaving simple selectors legible.
fn shell_argument(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./+-".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Validates that a full stage response describes one exact candidate revision.
///
/// # Errors
///
/// Returns an error when the candidate is invalid or its identity differs from
/// the stage metadata used for publication and revision updates.
pub(crate) fn review_stage(stage: &StagedRelease) -> Result<StageRevision, String> {
    let revision = decode_revision(&stage.revision_json, &stage.revision_gzip)
        .map_err(|error| format!("Cannot read this candidate: {error}"))?;
    revision
        .validate()
        .map_err(|error| format!("Cannot review this candidate: {error}"))?;
    if stage.stage_id != revision.id
        || stage.registry != revision.registry
        || stage.revision != revision.revision
        || stage.release_id != revision.release_id
        || stage.source_branch != revision.source_branch
        || stage.commit != revision.commit
        || stage.inventory_digest != revision.inventory_digest
        || stage.object_count != revision.inventory.len() as u64
    {
        return Err("The stage metadata does not match its candidate revision. Refresh the list and review it again.".into());
    }

    Ok(revision)
}

/// Parses and validates an exact candidate revision for a create or update form.
///
/// # Errors
///
/// Returns an error for invalid candidate bytes, a different registry or stage,
/// or a revision that does not advance the current candidate exactly once.
pub(crate) fn review_revision(
    json: &str,
    registry: &str,
    current: Option<&StageRevision>,
) -> Result<StageRevision, String> {
    if json.len() > MAX_DECODED_REVISION_BYTES {
        return Err("The candidate file exceeds the 32 MiB limit.".into());
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum CandidateFile {
        Revision(StageRevision),
        Record(StageRecord),
    }

    let file: CandidateFile = serde_json::from_str(json)
        .map_err(|error| format!("Cannot read the candidate file: {error}"))?;
    // Producers export their local lifecycle too; only the Hub may assign it.
    let revision = match file {
        CandidateFile::Revision(revision) => revision,
        CandidateFile::Record(record) => record.revision,
    };
    revision
        .validate()
        .map_err(|error| format!("Invalid candidate: {error}"))?;
    if revision.registry != registry {
        return Err("The candidate belongs to a different registry.".into());
    }
    let expected_revision = match current {
        Some(current) => {
            if revision.id != current.id {
                return Err("An update must keep the same stage ID.".into());
            }
            current.revision.checked_add(1)
        }
        None => Some(1),
    };
    if expected_revision != Some(revision.revision) {
        return Err("The candidate must be the next revision of this stage.".into());
    }
    Ok(revision)
}

/// Returns whether a stage can still select a different candidate revision.
pub(crate) fn can_edit(stage: &StagedRelease) -> bool {
    matches!(stage.state.as_str(), "draft" | "ready")
}

/// Returns whether publication can begin or continue for this exact stage.
pub(crate) fn can_finalize(stage: &StagedRelease) -> bool {
    !stage.publication_id.is_empty()
        && (stage.state == "releasing"
            || (stage.state == "ready"
                && stage.missing_paths.is_empty()
                && stage.missing_object_count == 0))
}

/// Returns bounded progress even when availability changes between reads.
pub(crate) fn progress_percent(stage: &StagedRelease) -> u64 {
    if stage.total_bytes == 0 {
        return if stage.missing_paths.is_empty() && stage.missing_object_count == 0 {
            100
        } else {
            0
        };
    }
    ((u128::from(stage.uploaded_bytes.min(stage.total_bytes)) * 100)
        / u128::from(stage.total_bytes)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_format::staging::{STAGE_SCHEMA, StageObject, inventory_digest};

    fn revision() -> StageRevision {
        let inventory = vec![StageObject {
            path: "nar/example.nar.zst".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            byte_size: 100,
            kind: "package".into(),
            media_type: "application/octet-stream".into(),
        }];
        StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "candidate".into(),
            registry: "example/main".into(),
            revision: 1,
            release_id: "1.2.3".into(),
            source_branch: "maintainer/candidate".into(),
            commit: "a".repeat(40),
            inventory_digest: inventory_digest(&inventory).unwrap(),
            inventory,
            container: None,
            publication: Vec::new(),
            store_roots: Vec::new(),
        }
    }

    #[test]
    fn review_rejects_wrong_identity_stale_revision_and_changed_inventory() {
        let original = revision();
        let json = serde_json::to_string(&original).unwrap();
        assert!(review_revision(&json, "example/main", None).is_ok());
        assert!(review_revision(&json, "other/main", None).is_err());
        assert!(review_revision(&json, "example/main", Some(&original)).is_err());

        let record = StageRecord {
            revision: original.clone(),
            state: aos_registry_format::staging::StageState::Released,
            released_version: Some(original.release_id.clone()),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            review_revision(&json, "example/main", None).unwrap(),
            original
        );

        let mut next = original.clone();
        next.revision = 2;
        next.commit = "b".repeat(40);
        let json = serde_json::to_string(&next).unwrap();
        assert!(review_revision(&json, "example/main", Some(&original)).is_ok());
        next.inventory[0].byte_size += 1;
        let json = serde_json::to_string(&next).unwrap();
        assert!(review_revision(&json, "example/main", Some(&original)).is_err());
    }

    #[test]
    fn stage_review_binds_actions_to_the_exact_response_identity() {
        let revision = revision();
        let mut stage = StagedRelease {
            registry: revision.registry.clone(),
            stage_id: revision.id.clone(),
            revision_json: serde_json::to_string(&revision).unwrap(),
            revision: revision.revision,
            release_id: revision.release_id.clone(),
            source_branch: revision.source_branch.clone(),
            commit: revision.commit.clone(),
            inventory_digest: revision.inventory_digest.clone(),
            object_count: revision.inventory.len() as u64,
            ..Default::default()
        };
        assert!(review_stage(&stage).is_ok());
        stage.revision_gzip =
            aos_registry_format::staging::wire::encode_revision(&revision).unwrap();
        assert!(review_stage(&stage).is_err());
        stage.revision_json.clear();
        assert!(review_stage(&stage).is_ok());
        stage.stage_id = "different-candidate".into();
        assert!(review_stage(&stage).is_err());
        stage.stage_id = revision.id;
        stage.revision += 1;
        assert!(review_stage(&stage).is_err());
        stage.revision = revision.revision;
        stage.commit = "b".repeat(40);
        assert!(review_stage(&stage).is_err());
    }

    #[test]
    fn large_inventory_reviews_render_a_bounded_filtered_window() {
        let object = revision().inventory.remove(0);
        let inventory = (0..50_000)
            .map(|index| StageObject {
                path: format!("nar/package-{index:05}.nar.zst"),
                ..object.clone()
            })
            .collect::<Vec<_>>();
        let first = inventory_page(&inventory, "package", 0);
        assert_eq!(first.matched, 50_000);
        assert_eq!(first.indices, (0..50).collect::<Vec<_>>());
        let last = inventory_page(&inventory, "package", 999);
        assert_eq!(last.indices, (49_950..50_000).collect::<Vec<_>>());
        let filtered = inventory_page(&inventory, "PACKAGE-00001", 0);
        assert_eq!(filtered.indices, vec![1]);
        assert_eq!(filtered.pages, 1);
    }

    #[test]
    fn resume_commands_require_a_local_selector_and_quote_shell_syntax() {
        let revision = revision();
        assert!(resume_command(&revision, "").ends_with("--registry YOUR-CONFIGURED-REGISTRY"));
        assert!(resume_command(&revision, "main-local").ends_with("--registry main-local"));
        assert!(
            resume_command(&revision, "main'; echo injected")
                .ends_with("--registry 'main'\\''; echo injected'")
        );
    }

    #[test]
    fn publication_actions_fail_closed_for_incomplete_or_terminal_stages() {
        let mut stage = StagedRelease {
            state: "ready".into(),
            publication_id: "publication".into(),
            ..Default::default()
        };
        assert!(can_edit(&stage));
        assert!(can_finalize(&stage));
        stage.missing_paths.push("nar/missing".into());
        assert!(!can_finalize(&stage));
        stage.state = "releasing".into();
        assert!(!can_edit(&stage));
        assert!(can_finalize(&stage));
        for state in ["released", "discarded", "unknown"] {
            stage.state = state.into();
            assert!(!can_edit(&stage));
            assert!(!can_finalize(&stage));
        }
    }

    #[test]
    fn progress_avoids_rounding_overflow_and_bounds_stale_counters() {
        let mut stage = StagedRelease {
            total_bytes: u64::MAX,
            uploaded_bytes: u64::MAX,
            ..Default::default()
        };
        assert_eq!(progress_percent(&stage), 100);
        stage.total_bytes = 100;
        stage.uploaded_bytes = 35;
        assert_eq!(progress_percent(&stage), 35);
        stage.uploaded_bytes = 101;
        assert_eq!(progress_percent(&stage), 100);
        stage.total_bytes = 0;
        stage.missing_paths.push("nar/missing".into());
        assert_eq!(progress_percent(&stage), 0);
        stage.missing_paths.clear();
        stage.missing_object_count = 1;
        assert_eq!(progress_percent(&stage), 0);
    }
}
