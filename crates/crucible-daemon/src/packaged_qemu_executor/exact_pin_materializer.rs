//! Packaged exact-pin materialization owner.
//!
//! The owner authenticates the bounded durable checkpoint catalog once before
//! executor admission, receives every later durable paused root through a
//! bounded channel, and periodically reprojects current semantic exact pins.
//! Repository and checkpoint I/O therefore never run under the supervisor
//! actor, while a pin created after its checkpoint still gains a durable
//! materialization record before stopped-owner GC.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_campaign::{
    CampaignHash, CampaignName, CampaignRepository, CampaignRepositoryError, ConfigurationId,
    ExactCheckpointId, PinRetention,
};

use crate::executor_pool::PausedCheckpointObserver;
use crate::{
    AssignmentLedger, DirectoryAssignmentLedger, DirectoryExactPinMaterializationStore,
    ExactCheckpointStore, ExactCheckpointStoreError, ExactPinMaterializationSelection,
    ExactPinRetentionAdmin, ExactPinRetentionError, MAX_LOCAL_EXECUTOR_WORKERS,
};

/// Maximum distinct durable roots retained by one packaged materializer.
pub(crate) const MAX_PACKAGED_EXACT_PIN_CHECKPOINTS: usize = 65_536;
/// Maximum current exact pins reconciled in one bounded projection pass.
pub(crate) const MAX_PACKAGED_EXACT_PINS_PER_PASS: usize = 65_536;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_TIMEOUT: Duration = Duration::from_millis(250);

pub(crate) struct PreparedPackagedExactPinMaterializer {
    repository: Arc<CampaignRepository>,
    checkpoints: Arc<ExactCheckpointStore>,
    campaigns: BTreeSet<CampaignName>,
    selections: DirectoryExactPinMaterializationStore,
    catalog: BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    catalog_roots: BTreeMap<ExactCheckpointId, ConfigurationId>,
    sender: SyncSender<MaterializerCommand>,
    receiver: Receiver<MaterializerCommand>,
}

pub(crate) struct PackagedExactPinMaterializerOwner {
    shutdown: Arc<AtomicBool>,
    sender: SyncSender<MaterializerCommand>,
    thread: Option<JoinHandle<Result<(), PackagedExactPinMaterializerError>>>,
}

#[derive(Clone)]
pub(crate) struct PackagedExactPinStatusHandle {
    sender: SyncSender<MaterializerCommand>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackagedExactPinStatus {
    pub(crate) generation: CampaignHash,
    pub(crate) selected_roots: BTreeSet<ExactCheckpointId>,
}

struct PackagedExactPinObserver {
    sender: SyncSender<MaterializerCommand>,
}

enum MaterializerCommand {
    Checkpoint(ExactCheckpointId),
    Replacement {
        source: ExactCheckpointId,
        promoted: ExactCheckpointId,
    },
    Reconcile(SyncSender<()>),
    Status {
        campaign: CampaignName,
        snapshot: crucible_campaign::CampaignSnapshotId,
        response: SyncSender<Result<PackagedExactPinStatus, PackagedExactPinMaterializerError>>,
    },
    Shutdown,
}

impl PausedCheckpointObserver for PackagedExactPinObserver {
    fn checkpoint_paused(&self, checkpoint: ExactCheckpointId) -> Result<(), ()> {
        self.sender
            .send(MaterializerCommand::Checkpoint(checkpoint))
            .map_err(|_| ())
    }

    fn checkpoint_promoted(
        &self,
        source: ExactCheckpointId,
        promoted: ExactCheckpointId,
    ) -> Result<(), ()> {
        self.sender
            .send(MaterializerCommand::Replacement { source, promoted })
            .map_err(|_| ())
    }
}

pub(crate) fn prepare_packaged_exact_pin_materializer(
    repository: Arc<CampaignRepository>,
    checkpoints: Arc<ExactCheckpointStore>,
    campaigns: BTreeSet<CampaignName>,
    ledger: &DirectoryAssignmentLedger,
    selection_root: &Path,
) -> Result<
    (
        PreparedPackagedExactPinMaterializer,
        Arc<dyn PausedCheckpointObserver>,
    ),
    PackagedExactPinMaterializerError,
> {
    let mut roots = BTreeSet::new();
    let mut overflow = false;
    ledger.visit_checkpoint_roots(&mut |checkpoint| {
        if roots.len() >= MAX_PACKAGED_EXACT_PIN_CHECKPOINTS && !roots.contains(&checkpoint) {
            overflow = true;
            return;
        }
        roots.insert(checkpoint);
    })?;
    if overflow {
        return Err(PackagedExactPinMaterializerError::CheckpointLimit);
    }

    let mut catalog = BTreeMap::new();
    let mut catalog_roots = BTreeMap::new();
    for checkpoint in roots {
        insert_checkpoint(&checkpoints, &mut catalog, &mut catalog_roots, checkpoint)?;
    }
    let mut selections = DirectoryExactPinMaterializationStore::open(selection_root)?;
    reconcile_exact_pins(
        &repository,
        &checkpoints,
        &campaigns,
        &catalog,
        &mut selections,
    )?;

    let (sender, receiver) = sync_channel(MAX_LOCAL_EXECUTOR_WORKERS);
    Ok((
        PreparedPackagedExactPinMaterializer {
            repository,
            checkpoints,
            campaigns,
            selections,
            catalog,
            catalog_roots,
            sender: sender.clone(),
            receiver,
        },
        Arc::new(PackagedExactPinObserver { sender }),
    ))
}

impl PreparedPackagedExactPinMaterializer {
    pub(crate) fn start(
        self,
        terminal_shutdown: impl Fn() + Send + Sync + 'static,
    ) -> Result<PackagedExactPinMaterializerOwner, PackagedExactPinMaterializerError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let sender = self.sender.clone();
        let terminal_shutdown = Arc::new(terminal_shutdown);
        let thread = thread::Builder::new()
            .name(String::from("crucible-exact-pin-materializer"))
            .spawn(move || {
                let result = self.run();
                if result.is_err() {
                    terminal_shutdown();
                }
                result
            })
            .map_err(|source| PackagedExactPinMaterializerError::Spawn { source })?;
        let owner = PackagedExactPinMaterializerOwner {
            shutdown,
            sender,
            thread: Some(thread),
        };
        if owner.reconcile_now().is_err() {
            return match owner.join() {
                Err(source) => Err(source),
                Ok(()) => Err(PackagedExactPinMaterializerError::OwnerUnavailable),
            };
        }
        Ok(owner)
    }

    fn run(mut self) -> Result<(), PackagedExactPinMaterializerError> {
        loop {
            match self.receiver.recv_timeout(RECONCILE_INTERVAL) {
                Ok(MaterializerCommand::Checkpoint(checkpoint)) => {
                    insert_checkpoint(
                        &self.checkpoints,
                        &mut self.catalog,
                        &mut self.catalog_roots,
                        checkpoint,
                    )?;
                }
                Ok(MaterializerCommand::Replacement { source, promoted }) => {
                    replace_checkpoint(
                        &self.checkpoints,
                        &mut self.catalog,
                        &mut self.catalog_roots,
                        source,
                        promoted,
                    )?;
                }
                Ok(MaterializerCommand::Reconcile(acknowledged)) => {
                    reconcile_exact_pins(
                        &self.repository,
                        &self.checkpoints,
                        &self.campaigns,
                        &self.catalog,
                        &mut self.selections,
                    )?;
                    let _ = acknowledged.send(());
                    continue;
                }
                Ok(MaterializerCommand::Status {
                    campaign,
                    snapshot,
                    response,
                }) => {
                    let status = reconcile_exact_pins(
                        &self.repository,
                        &self.checkpoints,
                        &self.campaigns,
                        &self.catalog,
                        &mut self.selections,
                    )
                    .and_then(|()| {
                        materialization_status(
                            &self.repository,
                            &campaign,
                            snapshot,
                            &mut self.selections,
                        )
                    });
                    let _ = response.try_send(status);
                    continue;
                }
                Ok(MaterializerCommand::Shutdown) => {
                    reconcile_exact_pins(
                        &self.repository,
                        &self.checkpoints,
                        &self.campaigns,
                        &self.catalog,
                        &mut self.selections,
                    )?;
                    return Ok(());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
            reconcile_exact_pins(
                &self.repository,
                &self.checkpoints,
                &self.campaigns,
                &self.catalog,
                &mut self.selections,
            )?;
        }
    }
}

impl PackagedExactPinMaterializerOwner {
    pub(crate) fn status_handle(&self) -> PackagedExactPinStatusHandle {
        PackagedExactPinStatusHandle {
            sender: self.sender.clone(),
        }
    }

    pub(crate) fn request_shutdown(&self) {
        if self
            .shutdown
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let _ = self.sender.send(MaterializerCommand::Shutdown);
        }
    }

    pub(crate) fn reconcile_now(&self) -> Result<(), PackagedExactPinMaterializerError> {
        let (acknowledged, completed) = sync_channel(0);
        self.sender
            .send(MaterializerCommand::Reconcile(acknowledged))
            .map_err(|_| PackagedExactPinMaterializerError::OwnerUnavailable)?;
        completed
            .recv()
            .map_err(|_| PackagedExactPinMaterializerError::OwnerUnavailable)
    }

    pub(crate) fn join(mut self) -> Result<(), PackagedExactPinMaterializerError> {
        self.request_shutdown();
        self.join_inner()
    }

    fn join_inner(&mut self) -> Result<(), PackagedExactPinMaterializerError> {
        let Some(thread) = self.thread.take() else {
            return Err(PackagedExactPinMaterializerError::OwnerUnavailable);
        };
        thread
            .join()
            .map_err(|_| PackagedExactPinMaterializerError::ThreadPanicked)?
    }
}

impl PackagedExactPinStatusHandle {
    pub(crate) fn status(
        &self,
        campaign: &CampaignName,
        snapshot: crucible_campaign::CampaignSnapshotId,
    ) -> Result<PackagedExactPinStatus, PackagedExactPinMaterializerError> {
        let (response, completed) = sync_channel(1);
        self.sender
            .try_send(MaterializerCommand::Status {
                campaign: campaign.clone(),
                snapshot,
                response,
            })
            .map_err(|_| PackagedExactPinMaterializerError::StatusUnavailable)?;
        completed
            .recv_timeout(STATUS_TIMEOUT)
            .map_err(|_| PackagedExactPinMaterializerError::StatusUnavailable)?
    }
}

impl Drop for PackagedExactPinMaterializerOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_inner();
    }
}

fn insert_checkpoint(
    checkpoints: &ExactCheckpointStore,
    catalog: &mut BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    catalog_roots: &mut BTreeMap<ExactCheckpointId, ConfigurationId>,
    checkpoint: ExactCheckpointId,
) -> Result<(), PackagedExactPinMaterializerError> {
    let loaded = checkpoints.load_attempt_checkpoint(checkpoint)?;
    let configuration =
        ConfigurationId::from_hash(CampaignHash::from_bytes(loaded.configuration().bytes));
    insert_authenticated_checkpoint(catalog, catalog_roots, configuration, checkpoint)
}

fn insert_authenticated_checkpoint(
    catalog: &mut BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    catalog_roots: &mut BTreeMap<ExactCheckpointId, ConfigurationId>,
    configuration: ConfigurationId,
    checkpoint: ExactCheckpointId,
) -> Result<(), PackagedExactPinMaterializerError> {
    if let Some(current) = catalog_roots.get(&checkpoint) {
        return if *current == configuration {
            Ok(())
        } else {
            Err(PackagedExactPinMaterializerError::CatalogInvariant)
        };
    }
    if catalog_roots.len() >= MAX_PACKAGED_EXACT_PIN_CHECKPOINTS {
        return Err(PackagedExactPinMaterializerError::CheckpointLimit);
    }
    let roots = catalog.entry(configuration).or_default();
    if !roots.insert(checkpoint) {
        return Err(PackagedExactPinMaterializerError::CatalogInvariant);
    }
    catalog_roots.insert(checkpoint, configuration);
    Ok(())
}

fn replace_checkpoint(
    checkpoints: &ExactCheckpointStore,
    catalog: &mut BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    catalog_roots: &mut BTreeMap<ExactCheckpointId, ConfigurationId>,
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
) -> Result<(), PackagedExactPinMaterializerError> {
    let loaded = checkpoints.load_attempt_checkpoint(promoted)?;
    let configuration =
        ConfigurationId::from_hash(CampaignHash::from_bytes(loaded.configuration().bytes));
    if source == promoted {
        return Err(PackagedExactPinMaterializerError::CatalogInvariant);
    }
    let source_configuration = catalog_roots
        .get(&source)
        .copied()
        .ok_or(PackagedExactPinMaterializerError::UnknownPromotionSource { checkpoint: source })?;
    if source_configuration != configuration {
        return Err(
            PackagedExactPinMaterializerError::PromotionConfigurationMismatch {
                source_configuration,
                promoted: configuration,
            },
        );
    }
    let roots = catalog
        .get_mut(&configuration)
        .ok_or(PackagedExactPinMaterializerError::CatalogInvariant)?;
    if !roots.remove(&source) {
        return Err(PackagedExactPinMaterializerError::CatalogInvariant);
    }
    let remove_configuration = roots.is_empty();
    if remove_configuration {
        catalog.remove(&configuration);
    }
    catalog_roots.remove(&source);
    insert_authenticated_checkpoint(catalog, catalog_roots, configuration, promoted)
}

fn reconcile_exact_pins(
    repository: &CampaignRepository,
    checkpoints: &ExactCheckpointStore,
    campaigns: &BTreeSet<CampaignName>,
    catalog: &BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    selections: &mut DirectoryExactPinMaterializationStore,
) -> Result<(), PackagedExactPinMaterializerError> {
    let mut pending = Vec::new();
    let mut exact_pin_count = 0_usize;
    for campaign in campaigns {
        let mut overflow = false;
        repository.visit_pin_retention_roots(campaign.as_str(), &mut |pin| {
            if pin.retention() != PinRetention::Exact {
                return;
            }
            if exact_pin_count >= MAX_PACKAGED_EXACT_PINS_PER_PASS {
                overflow = true;
                return;
            }
            exact_pin_count += 1;
            let configuration = pin.request().change.configuration();
            let Some(checkpoint) = catalog
                .get(&configuration)
                .and_then(|roots| roots.first().copied())
            else {
                return;
            };
            pending.push((campaign.clone(), configuration, checkpoint));
        })?;
        if overflow {
            return Err(PackagedExactPinMaterializerError::PinLimit);
        }
    }

    for (campaign, configuration, checkpoint) in pending {
        match ExactPinMaterializationSelection::prepare(
            repository,
            checkpoints,
            &campaign,
            configuration,
            checkpoint,
        ) {
            Ok(selection) => {
                selections.select(selection)?;
            }
            Err(ExactPinRetentionError::PinNotExact { .. }) => {}
            Err(source) => return Err(source.into()),
        }
    }
    Ok(())
}

pub(super) fn materialization_status(
    repository: &CampaignRepository,
    campaign: &CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    selections: &mut DirectoryExactPinMaterializationStore,
) -> Result<PackagedExactPinStatus, PackagedExactPinMaterializerError> {
    if repository.head(campaign.as_str())?.snapshot_id() != snapshot {
        return Err(PackagedExactPinMaterializerError::StatusSnapshotChanged);
    }

    let mut exact_pins = Vec::new();
    let mut exact_pin_count = 0_usize;
    let mut overflow = false;
    repository.visit_pin_retention_roots(campaign.as_str(), &mut |pin| {
        if pin.retention() != PinRetention::Exact {
            return;
        }
        if exact_pin_count >= MAX_PACKAGED_EXACT_PINS_PER_PASS {
            overflow = true;
            return;
        }
        exact_pin_count += 1;
        exact_pins.push((pin.request().change.configuration(), pin.fact()));
    })?;
    if overflow {
        return Err(PackagedExactPinMaterializerError::PinLimit);
    }
    if repository.head(campaign.as_str())?.snapshot_id() != snapshot {
        return Err(PackagedExactPinMaterializerError::StatusSnapshotChanged);
    }

    let mut selected_roots = BTreeSet::new();
    let mut fence = selections.acquire_exact_pin_retention_fence()?;
    for (configuration, pin_fact) in exact_pins {
        if let Some(selection) = fence.selection(campaign, configuration)?
            && selection.pin_fact() == pin_fact
        {
            selected_roots.insert(selection.checkpoint());
        }
    }

    let mut generation_material = Vec::new();
    append_generation_text(&mut generation_material, &snapshot.to_string());
    for checkpoint in &selected_roots {
        append_generation_text(&mut generation_material, &checkpoint.to_string());
    }
    Ok(PackagedExactPinStatus {
        generation: CampaignHash::derive(
            "crucible.executor.packaged-materialization-status.v1",
            &generation_material,
        ),
        selected_roots,
    })
}

fn append_generation_text(material: &mut Vec<u8>, value: &str) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value.as_bytes());
}

/// Failure to retain operational exact checkpoints for current semantic pins.
#[derive(Debug, thiserror::Error)]
pub enum PackagedExactPinMaterializerError {
    /// The durable assignment ledger named too many distinct checkpoint roots.
    #[error("packaged exact-pin checkpoint catalog exceeds 65,536 roots")]
    CheckpointLimit,
    /// One current semantic projection contained too many exact pins.
    #[error("packaged exact-pin projection exceeds 65,536 selections")]
    PinLimit,
    /// The bounded status queue or response deadline was exhausted.
    #[error("packaged exact-pin status is temporarily unavailable")]
    StatusUnavailable,
    /// The requested campaign head changed during materialization inventory.
    #[error("packaged exact-pin status snapshot changed during inventory")]
    StatusSnapshotChanged,
    /// A promotion completion named a source absent from the authenticated catalog.
    #[error(
        "packaged exact-pin promotion source {checkpoint} is absent from the checkpoint catalog"
    )]
    UnknownPromotionSource {
        /// Raw source root reported by the promotion owner.
        checkpoint: ExactCheckpointId,
    },
    /// A promotion replacement materialized a different configuration.
    #[error(
        "packaged exact-pin promotion changed configuration from {source_configuration} to {promoted}"
    )]
    PromotionConfigurationMismatch {
        /// Configuration authenticated from the raw source catalog entry.
        source_configuration: ConfigurationId,
        /// Configuration authenticated from the promoted replacement root.
        promoted: ConfigurationId,
    },
    /// The two bounded catalog indexes disagreed.
    #[error("packaged exact-pin checkpoint catalog invariant failed")]
    CatalogInvariant,
    /// Assignment-ledger inventory failed.
    #[error(transparent)]
    Assignment(#[from] crate::AssignmentLedgerError),
    /// Campaign pin projection failed authentication.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// An exact checkpoint failed authentication.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Durable exact-pin selection failed.
    #[error(transparent)]
    Retention(#[from] ExactPinRetentionError),
    /// The fixed materializer thread could not be created.
    #[error("packaged exact-pin materializer thread could not be created")]
    Spawn {
        /// Underlying operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// The materializer owner was already joined.
    #[error("packaged exact-pin materializer owner is unavailable")]
    OwnerUnavailable,
    /// The materializer thread escaped through an invariant panic.
    #[error("packaged exact-pin materializer thread panicked")]
    ThreadPanicked,
}
