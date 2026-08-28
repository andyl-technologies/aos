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
    ExactPinRetentionError, MAX_LOCAL_EXECUTOR_WORKERS,
};

/// Maximum distinct durable roots retained by one packaged materializer.
pub(crate) const MAX_PACKAGED_EXACT_PIN_CHECKPOINTS: usize = 65_536;
/// Maximum current exact pins reconciled in one bounded projection pass.
pub(crate) const MAX_PACKAGED_EXACT_PINS_PER_PASS: usize = 65_536;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct PreparedPackagedExactPinMaterializer {
    repository: Arc<CampaignRepository>,
    checkpoints: Arc<ExactCheckpointStore>,
    campaigns: BTreeSet<CampaignName>,
    selections: DirectoryExactPinMaterializationStore,
    catalog: BTreeMap<ConfigurationId, ExactCheckpointId>,
    sender: SyncSender<MaterializerCommand>,
    receiver: Receiver<MaterializerCommand>,
}

pub(crate) struct PackagedExactPinMaterializerOwner {
    shutdown: Arc<AtomicBool>,
    sender: SyncSender<MaterializerCommand>,
    thread: Option<JoinHandle<Result<(), PackagedExactPinMaterializerError>>>,
}

struct PackagedExactPinObserver {
    sender: SyncSender<MaterializerCommand>,
}

enum MaterializerCommand {
    Checkpoint(ExactCheckpointId),
    Reconcile(SyncSender<()>),
    Shutdown,
}

impl PausedCheckpointObserver for PackagedExactPinObserver {
    fn checkpoint_paused(&self, checkpoint: ExactCheckpointId) -> Result<(), ()> {
        self.sender
            .send(MaterializerCommand::Checkpoint(checkpoint))
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
    for checkpoint in roots {
        insert_checkpoint(&checkpoints, &mut catalog, checkpoint)?;
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
                    insert_checkpoint(&self.checkpoints, &mut self.catalog, checkpoint)?;
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

impl Drop for PackagedExactPinMaterializerOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_inner();
    }
}

fn insert_checkpoint(
    checkpoints: &ExactCheckpointStore,
    catalog: &mut BTreeMap<ConfigurationId, ExactCheckpointId>,
    checkpoint: ExactCheckpointId,
) -> Result<(), PackagedExactPinMaterializerError> {
    let loaded = checkpoints.load(checkpoint)?;
    let configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
        loaded.snapshot().checkpoint().configuration.bytes,
    ));
    if !catalog.contains_key(&configuration) && catalog.len() >= MAX_PACKAGED_EXACT_PIN_CHECKPOINTS
    {
        return Err(PackagedExactPinMaterializerError::CheckpointLimit);
    }
    catalog
        .entry(configuration)
        .and_modify(|current| *current = (*current).min(checkpoint))
        .or_insert(checkpoint);
    Ok(())
}

fn reconcile_exact_pins(
    repository: &CampaignRepository,
    checkpoints: &ExactCheckpointStore,
    campaigns: &BTreeSet<CampaignName>,
    catalog: &BTreeMap<ConfigurationId, ExactCheckpointId>,
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
            let Some(checkpoint) = catalog.get(&configuration).copied() else {
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

/// Failure to retain operational exact checkpoints for current semantic pins.
#[derive(Debug, thiserror::Error)]
pub enum PackagedExactPinMaterializerError {
    /// The durable assignment ledger named too many distinct checkpoint roots.
    #[error("packaged exact-pin checkpoint catalog exceeds 65,536 roots")]
    CheckpointLimit,
    /// One current semantic projection contained too many exact pins.
    #[error("packaged exact-pin projection exceeds 65,536 selections")]
    PinLimit,
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
