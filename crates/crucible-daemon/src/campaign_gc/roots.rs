//! Shared authoritative logical-root inventory for GC plan and apply.

use std::collections::BTreeSet;

use crucible_campaign::{
    CampaignArchiveManifestId, CampaignFactId, CampaignName, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshotId, ConfigurationId, PinRetention,
};
use crucible_cas::content_store::{ContentId, RefInventoryFence, RefInventorySummary, StoreError};
use crucible_cas::owned_decode::DecodeBudget;

use crate::exact_pin_retention::load_checkpoint_for_configuration;
use crate::{ExactCheckpointStore, ExactPinRetentionError, ExactPinRetentionFence};

use super::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES;

#[cfg(test)]
pub(in crate::campaign_gc) mod admission_tests;

pub(super) enum CampaignGcRootInventoryError {
    Ref(StoreError),
    Campaign(CampaignRepositoryError),
    ExactPin(ExactPinRetentionError),
    InvalidCampaignRef {
        name: String,
    },
    InvalidArchiveRef {
        name: String,
    },
    MissingExactPinMaterialization {
        campaign: CampaignName,
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
    },
    Limit,
    Admission(StoreError),
}

pub(super) fn inventory_authoritative_refs(
    repository: &CampaignRepository,
    fence: &mut dyn RefInventoryFence,
    exact_fence: &mut Option<Box<dyn ExactPinRetentionFence + '_>>,
    roots: &mut RootAccumulator<'_>,
    operation: &super::CampaignGcOperationContext<'_>,
) -> Result<RefInventorySummary, CampaignGcRootInventoryError> {
    let mut semantic_error = None;
    let mut archives = Vec::new();
    let summary = fence.visit_refs(&mut |record| {
        operation.check()?;
        if semantic_error.is_some() {
            return Err(StoreError::InvalidComposition {
                reason: "campaign GC exact-pin inventory already failed",
            });
        }
        if let Some(name) = record.name().as_str().strip_prefix("archives/") {
            if name.is_empty() {
                semantic_error = Some(CampaignGcRootInventoryError::InvalidArchiveRef {
                    name: record.name().as_str().to_owned(),
                });
                return Err(StoreError::InvalidComposition {
                    reason: "campaign GC archive ref is invalid",
                });
            }
            let archive = match CampaignArchiveManifestId::parse(&format!(
                "crucible.campaign.archive-manifest@{}",
                record.target()
            )) {
                Ok(archive) => archive,
                Err(_) => {
                    semantic_error = Some(CampaignGcRootInventoryError::InvalidArchiveRef {
                        name: record.name().as_str().to_owned(),
                    });
                    return Err(StoreError::InvalidComposition {
                        reason: "campaign GC archive ref target is not a manifest",
                    });
                }
            };
            if archives.len() >= MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
                semantic_error = Some(CampaignGcRootInventoryError::Limit);
                return Err(StoreError::Quota);
            }
            reserve_archive_slot(&mut archives, roots.original)
                .map_err(|error| preserve_root_admission(error, &mut semantic_error))?;
            archives.push(archive);
            return Ok(());
        }
        let Some(name) = record.name().as_str().strip_prefix("campaigns/") else {
            roots
                .insert(record.target())
                .map_err(|error| preserve_root_admission(error, &mut semantic_error))?;
            return Ok(());
        };
        roots
            .insert(record.target())
            .map_err(|error| preserve_root_admission(error, &mut semantic_error))?;
        let campaign = match CampaignName::new(name) {
            Ok(campaign) => campaign,
            Err(_) => {
                semantic_error = Some(CampaignGcRootInventoryError::InvalidCampaignRef {
                    name: record.name().as_str().to_owned(),
                });
                return Err(StoreError::InvalidComposition {
                    reason: "campaign GC authoritative campaign ref is invalid",
                });
            }
        };
        let snapshot = match CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            record.target()
        )) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                semantic_error = Some(CampaignGcRootInventoryError::InvalidCampaignRef {
                    name: record.name().as_str().to_owned(),
                });
                return Err(StoreError::InvalidComposition {
                    reason: "campaign GC campaign ref target is not a snapshot",
                });
            }
        };
        let result = repository.visit_pin_retention_roots_at(snapshot, &mut |pin| {
            if semantic_error.is_some() || pin.retention() != PinRetention::Exact {
                return;
            }
            let configuration = pin.request().change.configuration();
            let selection = match exact_fence.as_deref_mut() {
                Some(exact) => match exact.selection(&campaign, configuration) {
                    Ok(selection) => selection,
                    Err(source) => {
                        semantic_error = Some(CampaignGcRootInventoryError::ExactPin(source));
                        return;
                    }
                },
                None => None,
            };
            match selection {
                Some(selection)
                    if selection.campaign() == &campaign
                        && selection.configuration() == configuration
                        && selection.pin_fact() == pin.fact() =>
                {
                    let closure = (|| -> Result<_, ExactPinRetentionError> {
                        // GC must retain checkpoints published under any owner's byte policy.
                        // The loader's format bounds still cap metadata and object count.
                        let backend = repository.blob_backend();
                        let resources = backend
                            .metadata_resources()
                            .map_err(crate::ExactCheckpointStoreError::from)?;
                        let checkpoints = ExactCheckpointStore::new(
                            backend,
                            u64::MAX,
                            repository.ram_retention_authority(),
                        )?
                        .with_ram_root_resources(resources);
                        // The fenced ref inventory already authenticated the current pin.
                        // Re-reading it here would wait on the same ref fence.
                        load_checkpoint_for_configuration(
                            &checkpoints,
                            selection.checkpoint(),
                            configuration,
                        )?;
                        Ok([selection.checkpoint().content_id()])
                    })();
                    match closure {
                        Ok(ids) => {
                            for id in ids {
                                if let Err(error) = roots.insert(id) {
                                    semantic_error = Some(error.into_inventory_error());
                                    break;
                                }
                            }
                        }
                        Err(source) => {
                            semantic_error = Some(CampaignGcRootInventoryError::ExactPin(source));
                        }
                    }
                }
                _ => {
                    semantic_error = Some(
                        CampaignGcRootInventoryError::MissingExactPinMaterialization {
                            campaign: campaign.clone(),
                            configuration,
                            pin_fact: pin.fact(),
                        },
                    );
                }
            }
        });
        if semantic_error.is_none()
            && let Err(source) = result
        {
            semantic_error = Some(CampaignGcRootInventoryError::Campaign(source));
        }
        if semantic_error.is_some() {
            return Err(StoreError::InvalidComposition {
                reason: "campaign GC exact-pin inventory failed",
            });
        }
        Ok(())
    });
    if let Some(source) = semantic_error {
        return Err(source);
    }
    let summary = summary.map_err(CampaignGcRootInventoryError::Ref)?;
    for archive in archives {
        let inspection = repository
            .inspect_campaign_archive_for_gc_with_boundary(archive, fence, &mut || {
                operation.check().map_err(Into::into)
            })
            .map_err(CampaignGcRootInventoryError::Campaign)?;
        for root in inspection.manifest().ram_roots() {
            operation
                .check()
                .map_err(CampaignGcRootInventoryError::Ref)?;
            roots
                .insert(*root)
                .map_err(RootInsertionError::into_inventory_error)?;
        }
        for id in inspection.retained_objects() {
            operation
                .check()
                .map_err(CampaignGcRootInventoryError::Ref)?;
            roots
                .insert_direct(*id)
                .map_err(RootInsertionError::into_inventory_error)?;
        }
    }
    Ok(summary)
}

fn reserve_archive_slot(
    archives: &mut Vec<CampaignArchiveManifestId>,
    original: &DecodeBudget,
) -> Result<(), RootInsertionError> {
    if archives.len() < archives.capacity() {
        return Ok(());
    }
    let capacity = archives
        .capacity()
        .checked_mul(2)
        .map(|count| count.clamp(4, MAX_CAMPAIGN_GC_MANIFEST_ENTRIES))
        .filter(|count| *count > archives.len())
        .ok_or(RootInsertionError::Limit)?;
    let admission = |source| {
        RootInsertionError::Admission(StoreError::DecodeAdmission {
            source,
            custody: Some(original.custody()),
        })
    };

    // Retained earlier charges cover the old buffer while the full new body
    // moves. Collection stays separate from inspection under the ref fence.
    original
        .charge_array::<CampaignArchiveManifestId>(capacity)
        .map_err(admission)?;
    archives
        .try_reserve_exact(capacity - archives.len())
        .map_err(|source| {
            admission(crucible_cas::owned_decode::DecodeAdmissionError::new(
                source,
            ))
        })
}

// One batch pays the initial node and split ancestry as well as occupied slots.
const ROOT_ADMISSION_BATCH: usize = 256;

pub(super) struct RootAccumulator<'original> {
    pub(super) unique: BTreeSet<ContentId>,
    pub(super) ordinary: BTreeSet<ContentId>,
    pub(super) direct: BTreeSet<ContentId>,
    pub(super) pending_write_back: BTreeSet<ContentId>,
    observed: usize,
    admitted_unique: usize,
    original: &'original DecodeBudget,
}

impl<'original> RootAccumulator<'original> {
    pub(super) fn new(original: &'original DecodeBudget) -> Self {
        Self {
            unique: BTreeSet::new(),
            ordinary: BTreeSet::new(),
            direct: BTreeSet::new(),
            pending_write_back: BTreeSet::new(),
            observed: 0,
            admitted_unique: 0,
            original,
        }
    }

    pub(super) fn insert(&mut self, root: ContentId) -> Result<(), RootInsertionError> {
        self.prepare_insert(root)?;
        self.unique.insert(root);
        self.ordinary.insert(root);
        Ok(())
    }

    pub(super) fn insert_direct(&mut self, root: ContentId) -> Result<(), RootInsertionError> {
        self.prepare_insert(root)?;
        self.unique.insert(root);
        self.direct.insert(root);
        Ok(())
    }

    pub(super) fn insert_pending_write_back(
        &mut self,
        root: ContentId,
    ) -> Result<(), RootInsertionError> {
        self.insert_direct(root)?;
        self.pending_write_back.insert(root);
        Ok(())
    }

    fn prepare_insert(&mut self, root: ContentId) -> Result<(), RootInsertionError> {
        self.observed = self
            .observed
            .checked_add(1)
            .ok_or(RootInsertionError::Limit)?;
        if self.observed > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(RootInsertionError::Limit);
        }
        if self.unique.len() < self.admitted_unique || self.unique.contains(&root) {
            return Ok(());
        }

        let next = self
            .admitted_unique
            .checked_add(ROOT_ADMISSION_BATCH)
            .map(|count| count.min(MAX_CAMPAIGN_GC_MANIFEST_ENTRIES))
            .ok_or(RootInsertionError::Limit)?;
        let slot = std::mem::size_of::<ContentId>() + 4 * std::mem::size_of::<usize>();
        let bytes = (next - self.admitted_unique)
            .checked_mul(4)
            .and_then(|count| count.checked_mul(3))
            .and_then(|count| count.checked_mul(slot))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| RootInsertionError::Admission(StoreError::Quota))?;

        // The original ledger also prepays its receipt-vector growth. Each
        // unique-key batch covers all four trees, including category changes.
        self.original.charge_bytes(bytes).map_err(|source| {
            RootInsertionError::Admission(StoreError::DecodeAdmission {
                source,
                custody: Some(self.original.custody()),
            })
        })?;
        self.admitted_unique = next;
        Ok(())
    }
}

impl Drop for RootAccumulator<'_> {
    fn drop(&mut self) {
        // Drop checking keeps the original borrow alive through all tree frees.
    }
}

#[derive(Debug)]
pub(super) enum RootInsertionError {
    Limit,
    Admission(StoreError),
}

impl RootInsertionError {
    pub(super) fn into_store_error(self) -> StoreError {
        match self {
            Self::Limit => StoreError::Quota,
            Self::Admission(source) => source,
        }
    }

    fn into_inventory_error(self) -> CampaignGcRootInventoryError {
        match self {
            Self::Limit => CampaignGcRootInventoryError::Limit,
            Self::Admission(source) => CampaignGcRootInventoryError::Admission(source),
        }
    }
}

fn preserve_root_admission(
    error: RootInsertionError,
    first: &mut Option<CampaignGcRootInventoryError>,
) -> StoreError {
    if let RootInsertionError::Admission(source) = error
        && first.is_none()
    {
        *first = Some(CampaignGcRootInventoryError::Admission(source));
    }
    StoreError::Quota
}
