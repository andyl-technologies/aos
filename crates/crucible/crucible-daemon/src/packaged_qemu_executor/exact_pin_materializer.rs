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
    AuthenticatedFindingExactCheckpoint, CampaignExecutorStore, CampaignHash, CampaignName,
    CampaignRepository, CampaignRepositoryError, ConfigurationId, ExactCheckpointId,
    ExecutorExactCatalogAllocationCustody, ExecutorExactRetentionCatalog,
    ExecutorExactRetentionCatalogCustody, ExecutorExactRetentionOwnerLease,
    FindingExactCheckpointAuthenticationError, FindingExactCheckpointAuthenticator, PinRetention,
    ScenarioArtifactId, ScenarioDefId,
};
use crucible_store::content_store::{BlobHandle, ContentId};

use crate::automatic_finding_runner::{
    FindingExactCandidateInventory, FindingExactCandidateInventoryError,
    FindingExactRetentionSource, FindingTerminalCheckpointIdentity, exact_findings_enabled,
    publish_authenticated_terminal_checkpoint,
};
use crate::exact_checkpoint_store::ExactFindingCheckpointAuthenticator;
use crate::executor_pool::PausedCheckpointObserver;
use crate::{
    AssignmentLedger, DirectoryAssignmentLedger, DirectoryExactPinMaterializationStore,
    ExactCheckpointStore, ExactCheckpointStoreError, ExactPinMaterializationSelection,
    ExactPinRetentionAdmin, ExactPinRetentionError, MAX_LOCAL_EXECUTOR_WORKERS,
};

pub(super) mod original_retirement;

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
    incomplete_configurations: BTreeSet<ConfigurationId>,
    globally_incomplete: bool,
    owner: CampaignHash,
    _owner_lease: ExecutorExactRetentionOwnerLease,
    _durable_catalog_custody: ExecutorExactRetentionCatalogCustody,
    sender: SyncSender<MaterializerCommand>,
    receiver: Receiver<MaterializerCommand>,
    // Declared after all catalog maps so their allocation credit closes last.
    _catalog_allocation_custody: Option<ExecutorExactCatalogAllocationCustody>,
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct PackagedDurableCatalogTestHandle {
    sender: SyncSender<MaterializerCommand>,
}

#[cfg(test)]
pub(super) struct PackagedDurableCatalogTestLease(PackagedDurableCatalog);

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

struct PackagedDurableCatalog {
    catalog: ExecutorExactRetentionCatalog,
    _scratch: Option<crucible_store::owned_decode::DecodeScratch>,
    // This field remains last so the materializer resumes only after the
    // snapshot and its allocation custody have both been released.
    _release: PackagedDurableCatalogRelease,
}

struct PackagedDurableCatalogRelease(Option<SyncSender<()>>);

impl Drop for PackagedDurableCatalogRelease {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
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
    FindingCandidates {
        configuration: ConfigurationId,
        maximum_candidates: usize,
        response:
            SyncSender<Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError>>,
    },
    FindingTerminalCheckpoint {
        checkpoint: ExactCheckpointId,
        response: SyncSender<Result<(), FindingExactCandidateInventoryError>>,
    },
    DurableCatalog {
        response: SyncSender<Result<PackagedDurableCatalog, FindingExactCandidateInventoryError>>,
    },
    InvalidateCatalog(SyncSender<()>),
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
    store_namespace: CampaignHash,
    ledger: &DirectoryAssignmentLedger,
    selection_root: &Path,
) -> Result<
    (
        PreparedPackagedExactPinMaterializer,
        Arc<dyn PausedCheckpointObserver>,
    ),
    PackagedExactPinMaterializerError,
> {
    let owner = ledger.exact_catalog_owner(store_namespace)?;
    let owner_lease = repository.claim_executor_exact_catalog_owner(owner)?;
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let durable_catalog_custody = store.load_exact_catalog(owner)?;
    let durable_catalog = durable_catalog_custody.catalog();
    let incomplete_configuration_count = durable_catalog
        .map(|catalog| catalog.incomplete_configurations().len())
        .unwrap_or_default();
    let globally_incomplete =
        durable_catalog.is_some_and(ExecutorExactRetentionCatalog::globally_incomplete);
    let mut catalog_allocation_custody = None;
    if let Some(catalog) = durable_catalog {
        let entries =
            catalog_allocation_entries(catalog.entries().len(), incomplete_configuration_count)
                .ok_or(PackagedExactPinMaterializerError::CheckpointLimit)?;
        if entries != 0 {
            store.ensure_exact_catalog_custody(&mut catalog_allocation_custody, entries)?;
        }
    }
    let incomplete_configurations = durable_catalog
        .map(|catalog| catalog.incomplete_configurations().clone())
        .unwrap_or_default();
    let mut roots = BTreeSet::new();
    let mut overflow = false;
    let mut custody_error = None;
    ledger.visit_checkpoint_roots(&mut |checkpoint| {
        if custody_error.is_some() {
            return;
        }
        if roots.len() >= MAX_PACKAGED_EXACT_PIN_CHECKPOINTS && !roots.contains(&checkpoint) {
            overflow = true;
            return;
        }
        if !roots.contains(&checkpoint) {
            let Some(required_entries) =
                catalog_allocation_entries(roots.len() + 1, incomplete_configurations.len())
            else {
                overflow = true;
                return;
            };
            if let Err(error) = store
                .ensure_exact_catalog_custody(&mut catalog_allocation_custody, required_entries)
            {
                custody_error = Some(error);
                return;
            }
        }
        roots.insert(checkpoint);
    })?;
    if let Some(error) = custody_error {
        return Err(error.into());
    }
    if overflow {
        return Err(PackagedExactPinMaterializerError::CheckpointLimit);
    }

    let mut catalog = BTreeMap::new();
    let mut catalog_roots = BTreeMap::new();
    for checkpoint in roots {
        store.ensure_exact_catalog_custody(
            &mut catalog_allocation_custody,
            catalog_allocation_entries(catalog_roots.len() + 1, incomplete_configurations.len())
                .ok_or(PackagedExactPinMaterializerError::CheckpointLimit)?,
        )?;
        insert_checkpoint(&checkpoints, &mut catalog, &mut catalog_roots, checkpoint)?;
    }
    if let Some(retained) = durable_catalog {
        for (checkpoint, _) in retained.entries() {
            if !catalog_roots.contains_key(checkpoint) {
                store.ensure_exact_catalog_custody(
                    &mut catalog_allocation_custody,
                    catalog_allocation_entries(
                        catalog_roots.len() + 1,
                        incomplete_configurations.len(),
                    )
                    .ok_or(PackagedExactPinMaterializerError::CheckpointLimit)?,
                )?;
            }
            insert_checkpoint(&checkpoints, &mut catalog, &mut catalog_roots, *checkpoint)?;
        }
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
            incomplete_configurations,
            globally_incomplete,
            owner,
            _owner_lease: owner_lease,
            _durable_catalog_custody: durable_catalog_custody,
            sender: sender.clone(),
            receiver,
            _catalog_allocation_custody: catalog_allocation_custody,
        },
        Arc::new(PackagedExactPinObserver { sender }),
    ))
}

impl PreparedPackagedExactPinMaterializer {
    pub(super) const fn owner(&self) -> CampaignHash {
        self.owner
    }

    #[cfg(test)]
    pub(super) fn durable_catalog_test_handle(&self) -> PackagedDurableCatalogTestHandle {
        PackagedDurableCatalogTestHandle {
            sender: self.sender.clone(),
        }
    }

    #[cfg(test)]
    pub(super) fn catalog_allocation_admitted_entries(&self) -> usize {
        self._catalog_allocation_custody
            .as_ref()
            .map_or(0, ExecutorExactCatalogAllocationCustody::admitted_entries)
    }

    pub(crate) fn finding_retention_source(&self) -> Arc<dyn FindingExactRetentionSource> {
        Arc::new(PackagedFindingExactRetentionSource {
            sender: self.sender.clone(),
            store: CampaignExecutorStore::new(Arc::clone(&self.repository)),
            checkpoints: Arc::clone(&self.checkpoints),
            owner: self.owner,
            invalidated: AtomicBool::new(false),
        })
    }

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
                    if !self.catalog_roots.contains_key(&checkpoint) {
                        self.ensure_catalog_allocation_custody(self.catalog_roots.len() + 1)?;
                    }
                    insert_checkpoint(
                        &self.checkpoints,
                        &mut self.catalog,
                        &mut self.catalog_roots,
                        checkpoint,
                    )?;
                }
                Ok(MaterializerCommand::Replacement { source, promoted }) => {
                    self.ensure_catalog_allocation_custody(self.catalog_roots.len())?;
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
                Ok(MaterializerCommand::FindingCandidates {
                    configuration,
                    maximum_candidates,
                    response,
                }) => {
                    let result = if self.globally_incomplete
                        || self.incomplete_configurations.contains(&configuration)
                    {
                        Err(FindingExactCandidateInventoryError::LimitExceeded)
                    } else {
                        match self.catalog.get(&configuration) {
                            None => Ok(FindingExactCandidateInventory::empty()),
                            Some(roots) if roots.len() > maximum_candidates => {
                                Err(FindingExactCandidateInventoryError::LimitExceeded)
                            }
                            Some(roots) => CampaignExecutorStore::new(Arc::clone(&self.repository))
                                .reserve_exact_candidate_inventory(roots.len())
                                .map_err(|_| FindingExactCandidateInventoryError::Unavailable)
                                .and_then(|scratch| {
                                    let mut candidates = Vec::new();
                                    candidates.try_reserve_exact(roots.len()).map_err(|_| {
                                        FindingExactCandidateInventoryError::Unavailable
                                    })?;
                                    candidates.extend(roots.iter().copied());
                                    Ok(FindingExactCandidateInventory::admitted(
                                        candidates, scratch,
                                    ))
                                }),
                        }
                    };
                    let _ = response.try_send(result);
                    continue;
                }
                Ok(MaterializerCommand::FindingTerminalCheckpoint {
                    checkpoint,
                    response,
                }) => {
                    let required_entries = self.catalog_roots.len()
                        + usize::from(!self.catalog_roots.contains_key(&checkpoint));
                    if let Err(error) = self.ensure_catalog_allocation_custody(required_entries) {
                        let _ = response
                            .try_send(Err(FindingExactCandidateInventoryError::Unavailable));
                        return Err(error);
                    }
                    let result = insert_checkpoint(
                        &self.checkpoints,
                        &mut self.catalog,
                        &mut self.catalog_roots,
                        checkpoint,
                    );
                    match result {
                        Ok(()) => {
                            let _ = response.try_send(Ok(()));
                            continue;
                        }
                        Err(PackagedExactPinMaterializerError::CheckpointLimit) => {
                            let _ = response
                                .try_send(Err(FindingExactCandidateInventoryError::LimitExceeded));
                            continue;
                        }
                        Err(error) => {
                            let _ = response
                                .try_send(Err(FindingExactCandidateInventoryError::Unavailable));
                            return Err(error);
                        }
                    }
                }
                Ok(MaterializerCommand::DurableCatalog { response }) => {
                    let (release, released) = sync_channel(1);
                    let empty_complete = self.catalog.is_empty()
                        && self.incomplete_configurations.is_empty()
                        && !self.globally_incomplete;
                    let scratch = if empty_complete {
                        Ok(None)
                    } else {
                        projection_entries(&self.catalog, &self.incomplete_configurations).and_then(
                            |entries| {
                                CampaignExecutorStore::new(Arc::clone(&self.repository))
                                    .reserve_exact_catalog_projection(entries)
                                    .map(Some)
                                    .map_err(|_| FindingExactCandidateInventoryError::Unavailable)
                            },
                        )
                    };
                    let result = scratch.and_then(|scratch| {
                        durable_catalog(
                            &self.catalog,
                            &self.incomplete_configurations,
                            self.globally_incomplete,
                        )
                        .map(|catalog| PackagedDurableCatalog {
                            catalog,
                            _scratch: scratch,
                            _release: PackagedDurableCatalogRelease(Some(release)),
                        })
                        .map_err(|_| FindingExactCandidateInventoryError::LimitExceeded)
                    });
                    let wait_for_release = result.is_ok();
                    let _ = response.try_send(result);
                    if wait_for_release {
                        let _ = released.recv();
                    }
                    continue;
                }
                Ok(MaterializerCommand::InvalidateCatalog(acknowledged)) => {
                    self.catalog.clear();
                    self.catalog_roots.clear();
                    self.incomplete_configurations.clear();
                    self.globally_incomplete = true;
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
                    self.repository.retire_executor_exact_catalog(self.owner)?;
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

    fn ensure_catalog_allocation_custody(
        &mut self,
        required_roots: usize,
    ) -> Result<(), PackagedExactPinMaterializerError> {
        let required_entries =
            catalog_allocation_entries(required_roots, self.incomplete_configurations.len())
                .ok_or(PackagedExactPinMaterializerError::CheckpointLimit)?;
        CampaignExecutorStore::new(Arc::clone(&self.repository))
            .ensure_exact_catalog_custody(&mut self._catalog_allocation_custody, required_entries)
            .map_err(Into::into)
    }
}

pub(super) fn catalog_allocation_entries(roots: usize, incomplete: usize) -> Option<usize> {
    roots
        .checked_add(incomplete)
        .filter(|entries| *entries <= MAX_PACKAGED_EXACT_PIN_CHECKPOINTS)
}

#[cfg(test)]
impl PackagedDurableCatalogTestHandle {
    pub(super) fn acquire(&self) -> PackagedDurableCatalogTestLease {
        let (response, completed) = sync_channel(1);
        assert!(
            self.sender
                .send(MaterializerCommand::DurableCatalog { response })
                .is_ok(),
            "running exact-pin materializer accepts catalog request"
        );
        PackagedDurableCatalogTestLease(
            completed
                .recv()
                .expect("running exact-pin materializer returns catalog request")
                .expect("test catalog stays within the authenticated bounds"),
        )
    }
}

#[cfg(test)]
impl PackagedDurableCatalogTestLease {
    pub(super) fn is_empty_complete(&self) -> bool {
        self.0.catalog.is_empty_complete()
    }
}

struct PackagedFindingExactRetentionSource {
    sender: SyncSender<MaterializerCommand>,
    store: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    owner: CampaignHash,
    invalidated: AtomicBool,
}

impl FindingExactRetentionSource for PackagedFindingExactRetentionSource {
    fn candidate_checkpoints(
        &self,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError> {
        if self.invalidated.load(Ordering::Acquire) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        let (response, completed) = sync_channel(1);
        self.sender
            .try_send(MaterializerCommand::FindingCandidates {
                configuration,
                maximum_candidates,
                response,
            })
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        completed
            .recv_timeout(STATUS_TIMEOUT)
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?
    }

    fn exact_findings_enabled(
        &self,
        input: &crate::CrucibleAttemptExecution,
        context: &crate::AttemptExecutionContext,
    ) -> bool {
        exact_findings_enabled(&self.store, input, context)
    }

    fn retain_terminal_checkpoint(
        &self,
        capture: &crate::CapturedAttemptCheckpoint,
        context: &crate::AttemptExecutionContext,
        identity: FindingTerminalCheckpointIdentity,
    ) -> Result<(), FindingExactCandidateInventoryError> {
        if self.invalidated.load(Ordering::Acquire) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        let checkpoint = publish_authenticated_terminal_checkpoint(
            self,
            &self.checkpoints,
            capture,
            context.cancellation(),
            identity,
        )?;
        let (response, completed) = sync_channel(1);
        self.sender
            .try_send(MaterializerCommand::FindingTerminalCheckpoint {
                checkpoint,
                response,
            })
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        loop {
            if context.cancellation().is_canceled() {
                return Err(FindingExactCandidateInventoryError::Unavailable);
            }
            let wait = context
                .remaining_host_watchdog()
                .map_or(STATUS_TIMEOUT, |remaining| remaining.min(STATUS_TIMEOUT));
            if wait.is_zero() {
                return Err(FindingExactCandidateInventoryError::Unavailable);
            }
            match completed.recv_timeout(wait) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(FindingExactCandidateInventoryError::Unavailable);
                }
            }
        }
    }

    fn retain_execution_result(
        &self,
        _input: &crate::CrucibleAttemptExecution,
        context: &crate::AttemptExecutionContext,
        result: &crate::PreparedSemanticAttemptResult,
        gc_exclusion: &crucible_campaign::CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        let (response, completed) = sync_channel(1);
        self.sender
            .try_send(MaterializerCommand::DurableCatalog { response })
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention owner is unavailable",
            })?;
        let mut catalog = completed
            .recv_timeout(STATUS_TIMEOUT)
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention catalog snapshot timed out",
            })?
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention catalog exceeds bounds",
            })?;
        let roots = result
            .finding()
            .map(|finding| finding.bundle().exact_pins().all());
        if roots.is_none_or(BTreeSet::is_empty) && catalog.catalog.is_empty_complete() {
            return Ok(());
        }
        let retained_catalog = std::mem::take(&mut catalog.catalog);
        match (context.diagnostic_execution_id(), roots) {
            (Some(execution), Some(roots)) if !roots.is_empty() => {
                self.store.retain_exact_result_under(
                    gc_exclusion,
                    self.owner,
                    retained_catalog,
                    execution,
                    roots,
                )
            }
            _ => self
                .store
                .replace_exact_catalog_under(gc_exclusion, self.owner, retained_catalog),
        }
    }

    fn retain_execution_catalog(
        &self,
        gc_exclusion: &crucible_campaign::CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        let (response, completed) = sync_channel(1);
        self.sender
            .try_send(MaterializerCommand::DurableCatalog { response })
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention owner is unavailable",
            })?;
        let mut catalog = completed
            .recv_timeout(STATUS_TIMEOUT)
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention catalog snapshot timed out",
            })?
            .map_err(|_| CampaignRepositoryError::Integrity {
                reason: "packaged exact-retention catalog exceeds bounds",
            })?;
        if catalog.catalog.is_empty_complete() {
            return Ok(());
        }
        let retained_catalog = std::mem::take(&mut catalog.catalog);
        self.store
            .replace_exact_catalog_under(gc_exclusion, self.owner, retained_catalog)
    }

    fn abandon_unretained_candidates(&self) {
        self.invalidated.store(true, Ordering::Release);
        let (acknowledged, completed) = sync_channel(0);
        if self
            .sender
            .send(MaterializerCommand::InvalidateCatalog(acknowledged))
            .is_ok()
        {
            let _ = completed.recv();
        }
    }
}

impl FindingExactCheckpointAuthenticator for PackagedFindingExactRetentionSource {
    fn authenticate_finding_assertion_boundary(
        &self,
        checkpoint: ExactCheckpointId,
        boundary: &crucible_campaign::FindingAssertionFailureBoundary,
        trace_bytes: &[u8],
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
    ) -> Result<(), FindingExactCheckpointAuthenticationError> {
        ExactFindingCheckpointAuthenticator::new(&self.store, &self.checkpoints)
            .authenticate_finding_assertion_boundary(
                checkpoint,
                boundary,
                trace_bytes,
                scenario,
                scenario_artifact,
                configuration,
            )
    }

    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        ExactFindingCheckpointAuthenticator::new(&self.store, &self.checkpoints)
            .authenticate_finding_exact_checkpoint(
                checkpoint,
                scenario,
                scenario_artifact,
                configuration,
                maximum_metadata_bytes,
            )
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        ExactFindingCheckpointAuthenticator::new(&self.store, &self.checkpoints)
            .read_finding_exact_checkpoint_object(object)
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

fn projection_entries(
    catalog: &BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    incomplete: &BTreeSet<ConfigurationId>,
) -> Result<usize, FindingExactCandidateInventoryError> {
    let mut entries = 1_usize
        .checked_add(incomplete.len())
        .ok_or(FindingExactCandidateInventoryError::LimitExceeded)?;
    for roots in catalog.values() {
        entries = entries
            .checked_add(
                roots
                    .len()
                    .min(crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize),
            )
            .ok_or(FindingExactCandidateInventoryError::LimitExceeded)?;
    }
    Ok(entries)
}

fn durable_catalog(
    catalog: &BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    retained_incomplete: &BTreeSet<ConfigurationId>,
    globally_incomplete: bool,
) -> Result<ExecutorExactRetentionCatalog, crucible_campaign::CampaignCodecError> {
    let mut entries = Vec::new();
    let mut incomplete = retained_incomplete.clone();
    for (configuration, roots) in catalog {
        if roots.len() > crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize {
            incomplete.insert(*configuration);
        }
        for root in roots
            .iter()
            .take(crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize)
        {
            entries.push((*root, *configuration));
        }
    }
    if globally_incomplete {
        incomplete.clear();
    }
    ExecutorExactRetentionCatalog::new(entries, incomplete, globally_incomplete)
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
