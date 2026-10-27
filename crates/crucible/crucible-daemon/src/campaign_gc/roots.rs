//! Shared authoritative logical-root inventory and reachability for GC plan
//! and apply.
//!
//! Roots are classified as they are inventoried: ordinary roots are traversed
//! as complete campaign closures, direct roots are retained as single objects,
//! and pending write-back roots are direct roots that also protect their cache
//! copies. [`RootAccumulator`] spills every insertion to one external sort as
//! a tagged record, so a single ordered pass yields the root manifest and the
//! sorted ordinary, direct, and pending-write-back sets:
//!
//! ```text
//! root record (38 bytes): id record || class:u8
//!   class 0 ordinary, 1 direct, 2 pending write-back
//! ```
//!
//! [`authenticated_reachable`] then streams the repository's authenticated
//! closure of the ordinary roots, together with the direct roots, into one
//! sorted, deduplicated reachable set on disk.

use std::io;
use std::sync::Arc;

use crucible_campaign::{
    CampaignArchiveManifestId, CampaignFactId, CampaignName, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshotId, ConfigurationId, PinRetention,
};
use crucible_store::content_store::{
    ContentId, RefInventoryFence, RefInventorySummary, StoreError,
};

use crate::exact_pin_retention::load_checkpoint_for_configuration;
use crate::{ExactCheckpointStore, ExactPinRetentionError, ExactPinRetentionFence};

use super::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES;
use super::manifest::{
    CampaignGcManifestError, CampaignGcRootManifest, CampaignGcRootManifestWriter,
};
use super::spill::{
    ExternalSorter, GcWorkDirectory, ID_RECORD_BYTES, IdRecord, RUN_RECORDS, RecordReader,
    SpillFile, SpillWriter, decode_id, encode_id,
};

const ROOT_RECORD_BYTES: usize = ID_RECORD_BYTES + 1;
const ROOT_ORDINARY: u8 = 0;
const ROOT_DIRECT: u8 = 1;
const ROOT_PENDING_WRITE_BACK: u8 = 2;

pub(super) enum CampaignGcRootInventoryError {
    Spill(io::Error),
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

impl From<CampaignRepositoryError> for CampaignGcRootInventoryError {
    fn from(source: CampaignRepositoryError) -> Self {
        Self::Campaign(source)
    }
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
            let retained = repository.visit_campaign_archive_retained_objects(
                &inspection,
                |id| -> Result<(), CampaignGcRootInventoryError> {
                    roots
                        .insert_direct(id)
                        .map_err(|_| CampaignGcRootInventoryError::Limit)
                },
            );
            return match retained {
                Ok(()) => Ok(()),
                Err(error) => {
                    let store_error = match error {
                        CampaignGcRootInventoryError::Limit => StoreError::Quota,
                        _ => StoreError::InvalidComposition {
                            reason: "campaign GC archive inventory failed",
                        },
                    };
                    semantic_error = Some(error);
                    Err(store_error)
                }
            };
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
                    let closure = (|| -> Result<_, ExactPinRetentionError> {
                        // GC must retain checkpoints published under any owner's byte policy.
                        // The loader's format bounds still cap metadata and object count.
                        let checkpoints =
                            ExactCheckpointStore::new(repository.blob_backend(), u64::MAX)?;
                        // The fenced ref inventory already authenticated the current pin.
                        // Re-reading it here would wait on the same ref fence.
                        load_checkpoint_for_configuration(
                            &checkpoints,
                            selection.checkpoint(),
                            configuration,
                        )?;
                        Ok(checkpoints
                            .authenticated_production_closure_ids(selection.checkpoint())?)
                    })();
                    match closure {
                        Ok(ids) => {
                            for id in ids {
                                if roots.insert_direct(id).is_err() {
                                    semantic_error = Some(CampaignGcRootInventoryError::Limit);
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
    if let Some(source) = roots.take_spill_error() {
        return Err(CampaignGcRootInventoryError::Spill(source));
    }
    if let Some(source) = semantic_error {
        return Err(source);
    }
    summary.map_err(CampaignGcRootInventoryError::Ref)
}

/// Spilling accumulator for every classified logical root.
///
/// Insertion fails once the observed roots exceed the manifest bound or a
/// spill write fails. Visitors report that as their own limit error, so
/// callers check [`RootAccumulator::take_spill_error`] first to surface the
/// storage failure instead.
pub(super) struct RootAccumulator {
    sorter: ExternalSorter<ROOT_RECORD_BYTES>,
    observed: usize,
    spill_error: Option<io::Error>,
}

impl RootAccumulator {
    pub(super) fn new(directory: &Arc<GcWorkDirectory>) -> Self {
        Self {
            sorter: ExternalSorter::new(directory, "roots", RUN_RECORDS),
            observed: 0,
            spill_error: None,
        }
    }

    pub(super) fn insert(&mut self, root: ContentId) -> Result<(), ()> {
        self.push(root, ROOT_ORDINARY)
    }

    pub(super) fn insert_direct(&mut self, root: ContentId) -> Result<(), ()> {
        self.push(root, ROOT_DIRECT)
    }

    pub(super) fn insert_pending_write_back(&mut self, root: ContentId) -> Result<(), ()> {
        self.push(root, ROOT_PENDING_WRITE_BACK)
    }

    /// Returns the first spill failure, which takes precedence over the
    /// limit error a visitor reported for it.
    pub(super) fn take_spill_error(&mut self) -> Option<io::Error> {
        self.spill_error.take()
    }

    /// Sorts every root and writes the manifest and the classified sets.
    pub(super) fn finish(
        mut self,
        directory: &Arc<GcWorkDirectory>,
    ) -> Result<ClassifiedRoots, RootClassificationError> {
        if let Some(source) = self.spill_error.take() {
            return Err(RootClassificationError::Spill(source));
        }
        let sorted = self.sorter.finish()?;
        let mut records = sorted.reader::<ROOT_RECORD_BYTES>()?;

        let mut manifest = CampaignGcRootManifestWriter::create(directory)?;
        let mut ordinary = SpillWriter::<ID_RECORD_BYTES>::create(directory, "ordinary-roots")?;
        let mut direct = SpillWriter::<ID_RECORD_BYTES>::create(directory, "direct-roots")?;
        let mut pending = SpillWriter::<ID_RECORD_BYTES>::create(directory, "pending-roots")?;

        // Records sort by identity and then class, so each identity's classes
        // arrive together and in tag order.
        let mut current: Option<RootClasses> = None;
        while let Some(record) = records.next_record()? {
            let (id, class) = split_root_record(&record);
            match current.as_mut() {
                Some(classes) if classes.id == id => classes.add(class),
                _ => {
                    if let Some(classes) = current.take() {
                        classes.write(&mut manifest, &mut ordinary, &mut direct, &mut pending)?;
                    }
                    let mut classes = RootClasses::new(id);
                    classes.add(class);
                    current = Some(classes);
                }
            }
        }
        if let Some(classes) = current {
            classes.write(&mut manifest, &mut ordinary, &mut direct, &mut pending)?;
        }

        Ok(ClassifiedRoots {
            manifest: manifest.finish()?,
            ordinary: ordinary.finish()?,
            direct: direct.finish()?,
            pending_write_back: pending.finish()?,
        })
    }

    fn push(&mut self, root: ContentId, class: u8) -> Result<(), ()> {
        if self.spill_error.is_some() {
            return Err(());
        }
        self.observed = self.observed.checked_add(1).ok_or(())?;
        if self.observed > MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(());
        }
        let mut record = [0_u8; ROOT_RECORD_BYTES];
        record[..ID_RECORD_BYTES].copy_from_slice(&encode_id(root));
        record[ID_RECORD_BYTES] = class;
        self.sorter.push(record).map_err(|source| {
            self.spill_error = Some(source);
        })
    }
}

fn split_root_record(record: &[u8; ROOT_RECORD_BYTES]) -> (IdRecord, u8) {
    let mut id = [0_u8; ID_RECORD_BYTES];
    id.copy_from_slice(&record[..ID_RECORD_BYTES]);
    (id, record[ID_RECORD_BYTES])
}

/// Every class recorded for one root identity.
struct RootClasses {
    id: IdRecord,
    ordinary: bool,
    direct: bool,
    pending_write_back: bool,
}

impl RootClasses {
    const fn new(id: IdRecord) -> Self {
        Self {
            id,
            ordinary: false,
            direct: false,
            pending_write_back: false,
        }
    }

    fn add(&mut self, class: u8) {
        match class {
            ROOT_ORDINARY => self.ordinary = true,
            ROOT_PENDING_WRITE_BACK => {
                // A pending write-back root is retained directly as well.
                self.direct = true;
                self.pending_write_back = true;
            }
            _ => self.direct = true,
        }
    }

    fn write(
        &self,
        manifest: &mut CampaignGcRootManifestWriter,
        ordinary: &mut SpillWriter<ID_RECORD_BYTES>,
        direct: &mut SpillWriter<ID_RECORD_BYTES>,
        pending: &mut SpillWriter<ID_RECORD_BYTES>,
    ) -> Result<(), RootClassificationError> {
        manifest.push(decode_id(&self.id)?)?;
        if self.ordinary {
            ordinary.push(&self.id)?;
        }
        if self.direct {
            direct.push(&self.id)?;
        }
        if self.pending_write_back {
            pending.push(&self.id)?;
        }
        Ok(())
    }
}

/// Root manifest and sorted classified root sets for one inventory.
pub(super) struct ClassifiedRoots {
    pub(super) manifest: CampaignGcRootManifest,
    pub(super) ordinary: SpillFile,
    pub(super) direct: SpillFile,
    pub(super) pending_write_back: SpillFile,
}

/// Failure to classify or spill an accumulated root inventory.
pub(super) enum RootClassificationError {
    Spill(io::Error),
    Manifest(CampaignGcManifestError),
}

impl From<io::Error> for RootClassificationError {
    fn from(source: io::Error) -> Self {
        Self::Spill(source)
    }
}

impl From<CampaignGcManifestError> for RootClassificationError {
    fn from(source: CampaignGcManifestError) -> Self {
        Self::Manifest(source)
    }
}

/// Failure to build the authenticated reachable set.
pub(super) enum ReachabilityError {
    Spill(io::Error),
    Campaign(CampaignRepositoryError),
}

impl From<io::Error> for ReachabilityError {
    fn from(source: io::Error) -> Self {
        Self::Spill(source)
    }
}

/// Builds the sorted, deduplicated set of every reachable logical object.
///
/// The repository authenticates the union of the ordinary roots' closures and
/// streams each object into an external sort; direct roots join the set
/// without traversal. The result holds one id record per reachable object.
pub(super) fn authenticated_reachable(
    repository: &CampaignRepository,
    roots: &ClassifiedRoots,
    directory: &Arc<GcWorkDirectory>,
) -> Result<SpillFile, ReachabilityError> {
    let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(directory, "reachable", RUN_RECORDS);
    let mut root_error = None;
    let mut spill_error = None;
    let traversal = repository.visit_authenticated_closure_ids(
        SpilledIds {
            reader: roots.ordinary.reader()?,
            error: &mut root_error,
        },
        &mut |id| {
            if spill_error.is_none()
                && let Err(source) = sorter.push(encode_id(id))
            {
                spill_error = Some(source);
            }
        },
    );
    // A short root read makes the traversal result meaningless, so storage
    // failures take precedence over whatever the traversal reported.
    if let Some(source) = root_error.or(spill_error) {
        return Err(ReachabilityError::Spill(source));
    }
    traversal.map_err(ReachabilityError::Campaign)?;

    let mut direct = roots.direct.reader::<ID_RECORD_BYTES>()?;
    while let Some(record) = direct.next_record()? {
        sorter.push(record)?;
    }
    Ok(sorter.finish()?)
}

/// Iterator over a spilled id file that records its first read failure.
struct SpilledIds<'a> {
    reader: RecordReader<ID_RECORD_BYTES>,
    error: &'a mut Option<io::Error>,
}

impl Iterator for SpilledIds<'_> {
    type Item = ContentId;

    fn next(&mut self) -> Option<ContentId> {
        if self.error.is_some() {
            return None;
        }
        let decoded = self
            .reader
            .next_record()
            .and_then(|record| record.map(|record| decode_id(&record)).transpose());
        match decoded {
            Ok(id) => id,
            Err(source) => {
                *self.error = Some(source);
                None
            }
        }
    }
}
