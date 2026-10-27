//! Shares exact historical Cache project selection and head commitments.
//!
//! Complete historical inventory DATA determines the same denial-only
//! comparisons and digest as Native callers. It creates no physical original,
//! currentness, financial admission, role proof or effect authority.

use super::{PhysicalPartitionId, recovery::CacheRecoveryInventoryDataV1};
use aos_sandbox_model::model::CacheDomainKind;
use aos_sandbox_model::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

/// Refuses absent, ambiguous or unavailable historical project state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Cache historical project selection differs")]
pub struct CacheCurrentSelectionDataErrorV1;

/// Carries one historical project/partition/replay-head observation as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentProjectPhysicalCacheHeadDataV1 {
    /// Exact selected project comparison identity.
    pub project: ProjectId,
    /// Exact selected physical partition comparison identity.
    pub partition: PhysicalPartitionId,
    /// Same complete inventory and Replay-authority commitment.
    pub head: ObjectDigest,
}

/// Selects exactly one already-compared historical candidate.
///
/// # Errors
/// Rejects an absent or ambiguous candidate set.
pub fn unique_project_physical_cache_head(
    candidates: impl IntoIterator<Item = CurrentProjectPhysicalCacheHeadDataV1>,
) -> Result<CurrentProjectPhysicalCacheHeadDataV1, CacheCurrentSelectionDataErrorV1> {
    let mut candidates = candidates.into_iter();
    let head = candidates.next().ok_or(CacheCurrentSelectionDataErrorV1)?;
    if candidates.next().is_some() {
        return Err(CacheCurrentSelectionDataErrorV1.into());
    }
    Ok(head)
}

/// Selects one exact project partition from complete historical inventories.
///
/// # Errors
/// Rejects absent/ambiguous partitions, poison, outstanding work or wrong quotas.
pub fn select_project_physical_cache_head<'inventory>(
    project: ProjectId,
    inventories: impl IntoIterator<Item = &'inventory CacheRecoveryInventoryDataV1>,
) -> Result<CurrentProjectPhysicalCacheHeadDataV1, CacheCurrentSelectionDataErrorV1> {
    let mut candidates = Vec::new();
    for inventory in inventories {
        let partition = inventory.global.node_quota.partition;
        let disclosure = partition.disclosure();
        if disclosure.kind() != CacheDomainKind::Project
            || disclosure.domain_id().as_bytes() != project.as_bytes()
        {
            continue;
        }
        if inventory.authority_poisoned
            || inventory.global.poison.is_some()
            || !inventory.work.is_empty()
            || inventory
                .global
                .project_quotas
                .iter()
                .filter(|quota| quota.project == project && quota.partition == partition)
                .count()
                != 1
        {
            return Err(CacheCurrentSelectionDataErrorV1.into());
        }

        let head = project_physical_cache_head_digest(
            project,
            partition,
            inventory.protected_replay_binding(),
        );
        candidates.push(CurrentProjectPhysicalCacheHeadDataV1 {
            project,
            partition,
            head,
        });
    }
    unique_project_physical_cache_head(candidates)
}

/// Commits the same project, physical partition and complete replay binding.
#[must_use]
pub fn project_physical_cache_head_digest(
    project: ProjectId,
    partition: PhysicalPartitionId,
    replay_binding: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.cache.project-physical-head.v1\0")
            .chain_update(project.as_bytes())
            .chain_update(partition.digest().as_bytes())
            .chain_update(replay_binding.as_bytes())
            .finalize()
            .into(),
    )
}
