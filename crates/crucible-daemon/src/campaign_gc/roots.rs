//! Shared authoritative logical-root inventory for GC plan and apply.

use std::collections::BTreeSet;

use crucible_campaign::{
    CampaignArchiveManifestId, CampaignFactId, CampaignName, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshotId, ConfigurationId, PinRetention,
};
use crucible_cas::content_store::{ContentId, RefInventoryFence, RefInventorySummary, StoreError};

use crate::{ExactPinRetentionError, ExactPinRetentionFence};

use super::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES;

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
}

pub(super) fn inventory_authoritative_refs(
    repository: &CampaignRepository,
    fence: &mut dyn RefInventoryFence,
    exact_fence: &mut Option<Box<dyn ExactPinRetentionFence + '_>>,
    roots: &mut RootAccumulator,
) -> Result<RefInventorySummary, CampaignGcRootInventoryError> {
    let mut semantic_error = None;
    let summary = fence.visit_refs(&mut |record| {
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
            let inspection = match repository.inspect_campaign_archive(archive) {
                Ok(inspection) => inspection,
                Err(source) => {
                    semantic_error = Some(CampaignGcRootInventoryError::Campaign(source));
                    return Err(StoreError::InvalidComposition {
                        reason: "campaign GC archive inventory failed",
                    });
                }
            };
            for id in inspection.retained_objects() {
                if roots.insert_direct(*id).is_err() {
                    semantic_error = Some(CampaignGcRootInventoryError::Limit);
                    return Err(StoreError::Quota);
                }
            }
            return Ok(());
        }
        let Some(name) = record.name().as_str().strip_prefix("campaigns/") else {
            roots
                .insert(record.target())
                .map_err(|()| StoreError::Quota)?;
            return Ok(());
        };
        roots
            .insert(record.target())
            .map_err(|()| StoreError::Quota)?;
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
                    if roots.insert(selection.checkpoint().content_id()).is_err() {
                        semantic_error = Some(CampaignGcRootInventoryError::Limit);
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
        if let Err(source) = result {
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
    summary.map_err(CampaignGcRootInventoryError::Ref)
}

#[derive(Default)]
pub(super) struct RootAccumulator {
    pub(super) unique: BTreeSet<ContentId>,
    pub(super) ordinary: BTreeSet<ContentId>,
    pub(super) direct: BTreeSet<ContentId>,
    observed: usize,
}

impl RootAccumulator {
    pub(super) fn insert(&mut self, root: ContentId) -> Result<(), ()> {
        self.observed = self.observed.checked_add(1).ok_or(())?;
        if self.observed > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(());
        }
        self.unique.insert(root);
        self.ordinary.insert(root);
        Ok(())
    }

    pub(super) fn insert_direct(&mut self, root: ContentId) -> Result<(), ()> {
        self.observed = self.observed.checked_add(1).ok_or(())?;
        if self.observed > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(());
        }
        self.unique.insert(root);
        self.direct.insert(root);
        Ok(())
    }
}
