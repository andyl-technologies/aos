//! Durable exact-pin materialization selection for single-host retention.
//!
//! Semantic campaign pins deliberately do not choose an operational QEMU
//! checkpoint. This module owns that separate daemon-side choice and binds it
//! to the exact current pin fact:
//!
//! ```text
//! <root>/writer.lock
//! <root>/records/<key-prefix>/<selection-key>
//! ```
//!
//! A record is a bounded canonical value containing the campaign name,
//! configuration, latest accepted pin fact, and authenticated exact-checkpoint
//! root. The record key is derived from campaign name plus configuration.
//! Replacement is atomic and directory-synced. A lifetime writer lock excludes
//! a second cooperating daemon, while [`ExactPinRetentionFence`] excludes
//! mutation in the owning process during GC plan/apply inventory.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crucible::{Configuration, World};
use crucible_campaign::{
    CampaignCodecError, CampaignFactId, CampaignHash, CampaignName, CampaignRepository,
    CampaignRepositoryError, ConfigurationId, ExactCheckpointId, PinRetention,
};
use crucible_qemu::{
    QemuExactSnapshotPolicy, QemuFailedLaunchChildSource, QemuGuardedNodeRealizationLauncher,
    QemuGuardedThinNodeRealizationLauncher, QemuNodeRealizationExecutor, QemuReplayOracleCheck,
    QemuVmRealizationError, QemuVmRealizationExecutor, QemuVmRealizationStore,
    check_qemu_snapshot_replay_oracle_bound,
};
use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

use crate::{
    ExactCheckpointStore, ExactCheckpointStoreError, LoadedExactCheckpoint,
    QemuAttemptProcessResourceGuard, QemuGuardedReplayOracleSession,
};

/// Registered schema for one durable exact-pin materialization selection.
pub const EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA: &str =
    "crucible.executor.exact-pin-materialization-selection";
/// Canonical schema version for exact-pin materialization selections.
pub const EXACT_PIN_MATERIALIZATION_SELECTION_SCHEMA_VERSION: u32 = 1;
/// Maximum durable selection records in one single-host owner journal.
pub const MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS: u64 = 64_000_000;

const SELECTION_MAGIC: &[u8] = b"crucible.executor.exact-pin-materialization-selection.v1\0";
const SELECTION_KEY_DOMAIN: &str = "crucible.executor.exact-pin-materialization-selection-key.v1";
const SELECTION_CHECKSUM_DOMAIN: &str = "crucible.executor.exact-pin-materialization-selection.v1";
const MAX_SELECTION_RECORD_BYTES: u64 = 4 * 1024;
const RECORDS_DIRECTORY: &str = "records";
const WRITER_LOCK: &str = "writer.lock";

static STAGING_ORDINAL: AtomicU64 = AtomicU64::new(1);

/// One authenticated operational materialization selected for a semantic pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactPinMaterializationSelection {
    campaign: CampaignName,
    configuration: ConfigurationId,
    pin_fact: CampaignFactId,
    checkpoint: ExactCheckpointId,
}

impl ExactPinMaterializationSelection {
    /// Authenticates one exact checkpoint against a current semantic exact pin.
    ///
    /// This read-only preparation intentionally occurs before the selection
    /// journal is mutably borrowed. A composition can therefore follow the GC
    /// lock order (`campaign ref` before `selection journal`) without holding a
    /// journal mutex across repository or checkpoint-store I/O. If the pin
    /// changes before the prepared value is stored, later GC treats the record
    /// as stale rather than rooting it.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError::PinNotExact`] if the configuration is
    /// not currently projected as an exact pin,
    /// [`ExactPinRetentionError::CheckpointConfigurationMismatch`] if the
    /// checkpoint materializes another configuration, or a campaign or
    /// checkpoint-store authentication error.
    pub fn prepare(
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
        campaign: &CampaignName,
        configuration: ConfigurationId,
        checkpoint: ExactCheckpointId,
    ) -> Result<Self, ExactPinRetentionError> {
        Self::prepare_with_checkpoint(repository, checkpoints, campaign, configuration, checkpoint)
            .map(|(selection, _loaded)| selection)
    }

    /// Reauthenticates this durable selection against the current exact pin.
    ///
    /// The returned checkpoint has a fully authenticated root, metadata child,
    /// and bounded reopenable VMState stream. A restore owner must still retain
    /// its campaign resume precondition while turning the immutable selection
    /// into a live execution.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] if the current semantic pin is
    /// absent or changed, the checkpoint materializes another configuration,
    /// or campaign/checkpoint authentication fails.
    pub fn authenticate_current(
        &self,
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
    ) -> Result<LoadedExactCheckpoint, ExactPinRetentionError> {
        let current = current_exact_pin_fact(repository, &self.campaign, self.configuration)?;
        if current != self.pin_fact {
            return Err(ExactPinRetentionError::StaleSelection {
                recorded: self.pin_fact,
                current,
            });
        }
        load_checkpoint_for_configuration(checkpoints, self.checkpoint, self.configuration)
    }

    fn prepare_with_checkpoint(
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
        campaign: &CampaignName,
        configuration: ConfigurationId,
        checkpoint: ExactCheckpointId,
    ) -> Result<(Self, LoadedExactCheckpoint), ExactPinRetentionError> {
        let pin_fact = current_exact_pin_fact(repository, campaign, configuration)?;
        let loaded = load_checkpoint_for_configuration(checkpoints, checkpoint, configuration)?;
        Ok((
            Self {
                campaign: campaign.clone(),
                configuration,
                pin_fact,
                checkpoint,
            },
            loaded,
        ))
    }

    /// Returns the campaign whose current pin projection owns the selection.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact modeled configuration retained by the checkpoint.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the latest accepted exact-pin fact authorizing the selection.
    #[must_use]
    pub const fn pin_fact(&self) -> CampaignFactId {
        self.pin_fact
    }

    /// Returns the complete authenticated exact-checkpoint closure root.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }
}

fn current_exact_pin_fact(
    repository: &CampaignRepository,
    campaign: &CampaignName,
    configuration: ConfigurationId,
) -> Result<CampaignFactId, ExactPinRetentionError> {
    let mut pin_fact = None;
    repository.visit_pin_retention_roots(campaign.as_str(), &mut |record| {
        if record.request().change.configuration() == configuration
            && record.retention() == PinRetention::Exact
        {
            pin_fact = Some(record.fact());
        }
    })?;
    pin_fact.ok_or_else(|| ExactPinRetentionError::PinNotExact {
        campaign: campaign.clone(),
        configuration,
    })
}

fn load_checkpoint_for_configuration(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    configuration: ConfigurationId,
) -> Result<LoadedExactCheckpoint, ExactPinRetentionError> {
    let loaded = checkpoints.load(checkpoint)?;
    let checkpoint_configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
        loaded.snapshot().checkpoint().configuration.bytes,
    ));
    if checkpoint_configuration != configuration {
        return Err(ExactPinRetentionError::CheckpointConfigurationMismatch {
            expected: configuration,
            actual: checkpoint_configuration,
        });
    }
    Ok(loaded)
}

/// Result of one idempotent exact-pin materialization selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactPinSelectionDisposition {
    /// No record existed and this call durably stored the selection.
    Stored,
    /// A prior selection existed and this call durably replaced it.
    Replaced,
    /// The exact same selection was already durable.
    Existing,
}

/// Result of removing one stale or no-longer-required selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactPinSelectionClearDisposition {
    /// One durable selection was removed.
    Removed,
    /// No selection existed for the exact campaign/configuration key.
    Absent,
}

/// Exclusive read authority over one stable exact-pin selection inventory.
pub trait ExactPinRetentionFence {
    /// Loads one exact selection by its semantic campaign/configuration key.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when the record is unreadable,
    /// malformed, corrupt, or stored under a key other than its canonical key.
    fn selection(
        &mut self,
        campaign: &CampaignName,
        configuration: ConfigurationId,
    ) -> Result<Option<ExactPinMaterializationSelection>, ExactPinRetentionError>;
}

/// Separate maintenance capability for exact-pin checkpoint selections.
pub trait ExactPinRetentionAdmin {
    /// Acquires exclusive selection-inventory authority.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when stable inventory authority cannot
    /// be established.
    fn acquire_exact_pin_retention_fence(
        &mut self,
    ) -> Result<Box<dyn ExactPinRetentionFence + '_>, ExactPinRetentionError>;
}

/// Restart-safe single-writer exact-pin materialization journal.
pub struct DirectoryExactPinMaterializationStore {
    root: PathBuf,
    selection_records: u64,
    _writer_lock: File,
}

/// Durable result of replacing one selected raw checkpoint with an oracle match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactPinReplayPromotion {
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
    disposition: ExactPinSelectionDisposition,
}

impl ExactPinReplayPromotion {
    /// Returns the exact checkpoint root compared by the replay oracle.
    #[must_use]
    pub const fn source(self) -> ExactCheckpointId {
        self.source
    }

    /// Returns the new root containing matching replay-oracle evidence.
    #[must_use]
    pub const fn promoted(self) -> ExactCheckpointId {
        self.promoted
    }

    /// Returns how the durable operational selection was updated.
    #[must_use]
    pub const fn disposition(self) -> ExactPinSelectionDisposition {
        self.disposition
    }
}

/// Exact semantic and campaign target for one retained replay-oracle check.
#[derive(Clone, Copy)]
pub struct ExactPinReplayTarget<'a> {
    world: &'a World,
    configuration: &'a Configuration,
    campaign: &'a CampaignName,
    configuration_id: ConfigurationId,
}

impl<'a> ExactPinReplayTarget<'a> {
    /// Binds one modeled configuration to its exact campaign pin key.
    #[must_use]
    pub const fn new(
        world: &'a World,
        configuration: &'a Configuration,
        campaign: &'a CampaignName,
        configuration_id: ConfigurationId,
    ) -> Self {
        Self {
            world,
            configuration,
            campaign,
            configuration_id,
        }
    }
}

/// Executes fat/thin validation and promotes the selected exact root.
pub struct ExactPinReplayValidator<'a, S, E> {
    store: &'a mut S,
    executor: &'a mut E,
    policy: QemuExactSnapshotPolicy,
}

impl<'a, S, E> ExactPinReplayValidator<'a, S, E> {
    /// Creates a validator using production exact-snapshot policy.
    #[must_use]
    pub fn new(store: &'a mut S, executor: &'a mut E) -> Self {
        Self {
            store,
            executor,
            policy: QemuExactSnapshotPolicy::production(),
        }
    }
}

impl<S, E> ExactPinReplayValidator<'_, S, E>
where
    S: QemuVmRealizationStore,
    E: QemuVmRealizationExecutor,
{
    /// Validates and durably promotes the checkpoint selected for `target`.
    ///
    /// The selection fence is held only for the bounded initial lookup. The
    /// immutable checkpoint is authenticated, the fat and thin realizations
    /// are compared without holding operational journal authority, and the
    /// selection owner reauthenticates the source before publishing and
    /// replacing its root.
    ///
    /// The caller owns attempt resource enforcement and mandatory executor
    /// cleanup around this operation. In production, `executor` is therefore
    /// an attempt-scoped guarded QEMU session rather than a raw process adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when selection or checkpoint
    /// authentication fails, either realization path fails, fat/thin state
    /// differs, publication fails, or durable selection replacement fails.
    pub fn validate_and_promote(
        &mut self,
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
        selections: &mut DirectoryExactPinMaterializationStore,
        target: ExactPinReplayTarget<'_>,
    ) -> Result<ExactPinReplayPromotion, ExactPinRetentionError> {
        let selected = {
            let mut fence = selections.acquire_exact_pin_retention_fence()?;
            fence
                .selection(target.campaign, target.configuration_id)?
                .ok_or_else(|| ExactPinRetentionError::MissingSelection {
                    campaign: target.campaign.clone(),
                    configuration: target.configuration_id,
                })?
        };
        let loaded = selected.authenticate_current(repository, checkpoints)?;
        let check = check_qemu_snapshot_replay_oracle_bound(
            target.world,
            target.configuration,
            loaded.snapshot(),
            self.store,
            self.executor,
            self.policy,
        )?;
        selections.promote_replay_oracle_match(
            repository,
            checkpoints,
            target.campaign,
            target.configuration_id,
            check,
        )
    }
}

impl DirectoryExactPinMaterializationStore {
    /// Opens a durable journal and acquires its lifetime single-writer lock.
    ///
    /// The directory must live outside every blob leaf inventoried by campaign
    /// GC. Selection records are operational owner state, not immutable campaign
    /// objects.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when the directory or lock cannot be
    /// created, synchronized, or exclusively acquired.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ExactPinRetentionError> {
        let root = root.into();
        create_directory_durable(&root, "create-selection-root")?;
        create_directory_durable(&root.join(RECORDS_DIRECTORY), "create-selection-records")?;
        let lock_path = root.join(WRITER_LOCK);
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open-selection-writer-lock", &lock_path, source))?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            io_error(
                "lock-selection-writer",
                &lock_path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        sync_directory(&root, "sync-selection-root-on-open")?;
        let selection_records = count_selection_records(&root.join(RECORDS_DIRECTORY))?;
        Ok(Self {
            root,
            selection_records,
            _writer_lock: writer_lock,
        })
    }

    /// Returns the physical operational journal root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Durably stores one previously authenticated exact-pin selection.
    ///
    /// Callers construct `selection` with
    /// [`ExactPinMaterializationSelection::prepare`] before acquiring mutable
    /// journal authority. That split avoids holding the journal lock across
    /// repository or checkpoint-store I/O and preserves the global GC lock
    /// order. Exact replay is read-only except for re-syncing the containing
    /// directory after a prior commit-indeterminate replacement.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] for a record limit, corruption, or
    /// durable persistence failure.
    pub fn select(
        &mut self,
        selection: ExactPinMaterializationSelection,
    ) -> Result<ExactPinSelectionDisposition, ExactPinRetentionError> {
        let path = self.selection_path(&selection.campaign, selection.configuration);
        if let Some(existing) = read_selection(&path, &selection.campaign, selection.configuration)?
        {
            if existing == selection {
                sync_record_parent(&path)?;
                return Ok(ExactPinSelectionDisposition::Existing);
            }
            replace_record(&path, &encode_selection(&selection))?;
            return Ok(ExactPinSelectionDisposition::Replaced);
        }

        if self.selection_records >= MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS {
            return Err(ExactPinRetentionError::SelectionLimit);
        }
        if let Err(source) = replace_record(&path, &encode_selection(&selection)) {
            self.selection_records = count_selection_records(&self.root.join(RECORDS_DIRECTORY))?;
            return Err(source);
        }
        self.selection_records = self
            .selection_records
            .checked_add(1)
            .ok_or(ExactPinRetentionError::SelectionLimit)?;
        Ok(ExactPinSelectionDisposition::Stored)
    }

    /// Runs guarded fat/thin validation, reaps QEMU, and promotes the selection.
    ///
    /// The exact target launcher and independent thin-path launcher share one
    /// attempt-owned resource guard but cannot substitute for one another. The
    /// session is explicitly finished before the first immutable promotion
    /// write. A realization or cleanup failure therefore leaves the raw
    /// selection unchanged and either attests reap or transfers the guard to
    /// quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when selection authentication,
    /// fat/thin realization, cleanup, replay comparison, immutable publication,
    /// or durable selection replacement fails.
    pub fn validate_and_promote_replay_guarded<S, L, G>(
        &mut self,
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
        target: ExactPinReplayTarget<'_>,
        realization_store: &mut S,
        executor: &mut QemuNodeRealizationExecutor<L>,
        guard: G,
    ) -> Result<ExactPinReplayPromotion, ExactPinRetentionError>
    where
        S: QemuVmRealizationStore,
        L: QemuGuardedNodeRealizationLauncher
            + QemuGuardedThinNodeRealizationLauncher
            + QemuFailedLaunchChildSource,
        G: QemuAttemptProcessResourceGuard,
    {
        let selected = {
            let mut fence = self.acquire_exact_pin_retention_fence()?;
            fence
                .selection(target.campaign, target.configuration_id)?
                .ok_or_else(|| ExactPinRetentionError::MissingSelection {
                    campaign: target.campaign.clone(),
                    configuration: target.configuration_id,
                })?
        };
        let loaded = selected.authenticate_current(repository, checkpoints)?;
        let mut session = QemuGuardedReplayOracleSession::new(executor, guard);
        let comparison = check_qemu_snapshot_replay_oracle_bound(
            target.world,
            target.configuration,
            loaded.snapshot(),
            realization_store,
            &mut session,
            QemuExactSnapshotPolicy::production(),
        );
        let cleanup = session.finish();
        let check = match (comparison, cleanup) {
            (_, Err(cleanup)) => return Err(cleanup.into()),
            (Err(comparison), Ok(())) => return Err(comparison.into()),
            (Ok(check), Ok(())) => check,
        };

        self.promote_replay_oracle_match(
            repository,
            checkpoints,
            target.campaign,
            target.configuration_id,
            check,
        )
    }

    /// Publishes a replay-validated replacement for the current exact selection.
    ///
    /// The bound oracle result is applied before any write. The replacement
    /// reuses the source root's authenticated VMState child, publishes new
    /// metadata and root through the ordinary children-before-root protocol,
    /// then durably replaces the operational selection. A semantic pin change
    /// observed after publication rejects selection; the unreachable immutable
    /// promotion remains ordinary GC input.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when no selection exists, the source
    /// selection is stale, the oracle result belongs to another snapshot or is
    /// not a match, publication fails, or the replacement selection cannot be
    /// durably stored.
    pub fn promote_replay_oracle_match(
        &mut self,
        repository: &CampaignRepository,
        checkpoints: &ExactCheckpointStore,
        campaign: &CampaignName,
        configuration: ConfigurationId,
        check: QemuReplayOracleCheck,
    ) -> Result<ExactPinReplayPromotion, ExactPinRetentionError> {
        let source = {
            let mut fence = self.acquire_exact_pin_retention_fence()?;
            fence.selection(campaign, configuration)?.ok_or_else(|| {
                ExactPinRetentionError::MissingSelection {
                    campaign: campaign.clone(),
                    configuration,
                }
            })?
        };
        let loaded = source.authenticate_current(repository, checkpoints)?;
        let capture = loaded.promote_replay_oracle_match(check)?;
        let prepared = checkpoints.prepare_capture(capture)?;
        let publication = checkpoints.publish(&prepared)?;
        let promoted = publication.root();
        let replacement = ExactPinMaterializationSelection::prepare(
            repository,
            checkpoints,
            campaign,
            configuration,
            promoted,
        )?;
        let disposition = self.select(replacement)?;

        Ok(ExactPinReplayPromotion {
            source: source.checkpoint(),
            promoted,
            disposition,
        })
    }

    /// Removes one operational selection without mutating campaign semantics.
    ///
    /// GC already ignores records whose pin fact is not current. This operation
    /// reclaims bounded journal namespace after unpin or replacement workflows.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPinRetentionError`] when an existing record is malformed
    /// or its durable removal cannot be synchronized.
    pub fn clear(
        &mut self,
        campaign: &CampaignName,
        configuration: ConfigurationId,
    ) -> Result<ExactPinSelectionClearDisposition, ExactPinRetentionError> {
        let path = self.selection_path(campaign, configuration);
        if read_selection(&path, campaign, configuration)?.is_none() {
            sync_record_parent(&path)?;
            return Ok(ExactPinSelectionClearDisposition::Absent);
        }
        fs::remove_file(&path)
            .map_err(|source| io_error("remove-selection-record", &path, source))?;
        self.selection_records = self
            .selection_records
            .checked_sub(1)
            .ok_or_else(|| corrupt("selection-record-count-underflow"))?;
        sync_record_parent(&path)?;
        Ok(ExactPinSelectionClearDisposition::Removed)
    }

    fn selection_path(&self, campaign: &CampaignName, configuration: ConfigurationId) -> PathBuf {
        selection_path(&self.root, campaign, configuration)
    }
}

impl ExactPinRetentionAdmin for DirectoryExactPinMaterializationStore {
    fn acquire_exact_pin_retention_fence(
        &mut self,
    ) -> Result<Box<dyn ExactPinRetentionFence + '_>, ExactPinRetentionError> {
        Ok(Box::new(DirectoryExactPinRetentionFence { store: self }))
    }
}

struct DirectoryExactPinRetentionFence<'a> {
    store: &'a DirectoryExactPinMaterializationStore,
}

impl ExactPinRetentionFence for DirectoryExactPinRetentionFence<'_> {
    fn selection(
        &mut self,
        campaign: &CampaignName,
        configuration: ConfigurationId,
    ) -> Result<Option<ExactPinMaterializationSelection>, ExactPinRetentionError> {
        let path = self.store.selection_path(campaign, configuration);
        read_selection(&path, campaign, configuration)
    }
}

/// Failure to authenticate, persist, or inventory exact-pin materialization.
#[derive(Debug, Error)]
pub enum ExactPinRetentionError {
    /// The current semantic projection does not contain the requested exact pin.
    #[error("campaign {campaign:?} configuration {configuration} is not currently exact-pinned")]
    PinNotExact {
        /// Exact campaign name requested by the maintenance owner.
        campaign: CampaignName,
        /// Exact modeled configuration requested by the maintenance owner.
        configuration: ConfigurationId,
    },
    /// No operational checkpoint is selected for this exact pin.
    #[error("campaign {campaign:?} configuration {configuration} has no selected exact checkpoint")]
    MissingSelection {
        /// Exact campaign whose selection was requested.
        campaign: CampaignName,
        /// Exact modeled configuration whose selection was requested.
        configuration: ConfigurationId,
    },
    /// The checkpoint materializes a different modeled configuration.
    #[error("exact checkpoint configuration mismatch: expected {expected}, got {actual}")]
    CheckpointConfigurationMismatch {
        /// Exact semantic pin target.
        expected: ConfigurationId,
        /// Configuration authenticated from checkpoint metadata.
        actual: ConfigurationId,
    },
    /// A durable materialization selection names an earlier exact-pin fact.
    #[error("exact-pin materialization selection is stale: recorded {recorded}, current {current}")]
    StaleSelection {
        /// Pin fact authenticated when the selection was stored.
        recorded: CampaignFactId,
        /// Latest exact-pin fact for the same configuration.
        current: CampaignFactId,
    },
    /// The bounded operational journal has no capacity for another key.
    #[error("exact-pin materialization selection limit exceeded")]
    SelectionLimit,
    /// One durable record or journal path violated its canonical contract.
    #[error("exact-pin materialization journal is corrupt: {reason}")]
    Corrupt {
        /// Stable corruption category.
        reason: &'static str,
    },
    /// Campaign semantic-pin authentication failed.
    #[error(transparent)]
    Campaign(#[from] CampaignRepositoryError),
    /// Exact-checkpoint root or metadata authentication failed.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Replay-oracle evidence was absent, mismatched, or bound elsewhere.
    #[error(transparent)]
    ReplayOracle(#[from] QemuVmRealizationError),
    /// A typed campaign identity in a durable record was malformed.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A durable filesystem operation failed.
    #[error("exact-pin materialization {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact affected path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}

fn selection_path(root: &Path, campaign: &CampaignName, configuration: ConfigurationId) -> PathBuf {
    let key = selection_key(campaign, configuration).to_hex();
    root.join(RECORDS_DIRECTORY).join(&key[..2]).join(key)
}

fn selection_key(campaign: &CampaignName, configuration: ConfigurationId) -> CampaignHash {
    let campaign = campaign.as_str().as_bytes();
    let mut material = Vec::with_capacity(2 + campaign.len() + 32);
    material.extend_from_slice(&(campaign.len() as u16).to_be_bytes());
    material.extend_from_slice(campaign);
    material.extend_from_slice(&configuration.as_hash().as_bytes());
    CampaignHash::derive(SELECTION_KEY_DOMAIN, &material)
}

fn encode_selection(selection: &ExactPinMaterializationSelection) -> Vec<u8> {
    let campaign = selection.campaign.as_str().as_bytes();
    let fact = selection.pin_fact.to_text();
    let checkpoint = selection.checkpoint.to_text();
    let mut bytes = Vec::with_capacity(
        SELECTION_MAGIC.len() + campaign.len() + fact.len() + checkpoint.len() + 104,
    );
    bytes.extend_from_slice(SELECTION_MAGIC);
    push_bounded_string(&mut bytes, campaign);
    bytes.extend_from_slice(&selection.configuration.as_hash().as_bytes());
    push_bounded_string(&mut bytes, fact.as_bytes());
    push_bounded_string(&mut bytes, checkpoint.as_bytes());
    let checksum = CampaignHash::derive(SELECTION_CHECKSUM_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum.as_bytes());
    bytes
}

fn decode_selection(
    bytes: &[u8],
) -> Result<ExactPinMaterializationSelection, ExactPinRetentionError> {
    if bytes.len() as u64 > MAX_SELECTION_RECORD_BYTES
        || bytes.len() < SELECTION_MAGIC.len() + 2 + 32 + 2 + 2 + 32
        || !bytes.starts_with(SELECTION_MAGIC)
    {
        return Err(corrupt("selection-record-shape"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if CampaignHash::derive(SELECTION_CHECKSUM_DOMAIN, body).as_bytes() != checksum {
        return Err(corrupt("selection-record-checksum"));
    }
    let mut cursor = SelectionCursor::new(&body[SELECTION_MAGIC.len()..]);
    let campaign = CampaignName::new(cursor.string()?)?;
    let configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(cursor.fixed()?));
    let pin_fact = CampaignFactId::parse(&cursor.string()?)?;
    let checkpoint = ExactCheckpointId::parse(&cursor.string()?)?;
    if !cursor.is_empty() {
        return Err(corrupt("selection-record-trailing-bytes"));
    }
    Ok(ExactPinMaterializationSelection {
        campaign,
        configuration,
        pin_fact,
        checkpoint,
    })
}

fn read_selection(
    path: &Path,
    campaign: &CampaignName,
    configuration: ConfigurationId,
) -> Result<Option<ExactPinMaterializationSelection>, ExactPinRetentionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(corrupt("selection-record-is-not-file")),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("stat-selection-record", path, source)),
    };
    if metadata.len() > MAX_SELECTION_RECORD_BYTES {
        return Err(corrupt("selection-record-size"));
    }
    let mut file =
        File::open(path).map_err(|source| io_error("open-selection-record", path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_SELECTION_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-selection-record", path, source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_SELECTION_RECORD_BYTES {
        return Err(corrupt("selection-record-length-changed"));
    }
    let selection = decode_selection(&bytes)?;
    if selection.campaign != *campaign
        || selection.configuration != configuration
        || selection_path(
            path.parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or_else(|| corrupt("selection-record-path-depth"))?,
            campaign,
            configuration,
        ) != path
    {
        return Err(corrupt("selection-record-path-identity"));
    }
    Ok(Some(selection))
}

fn replace_record(path: &Path, bytes: &[u8]) -> Result<(), ExactPinRetentionError> {
    if bytes.len() as u64 > MAX_SELECTION_RECORD_BYTES {
        return Err(corrupt("selection-record-size"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| corrupt("selection-record-parent"))?;
    create_directory_durable(parent, "create-selection-record-shard")?;
    let ordinal = STAGING_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(".staging-{}-{ordinal}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(|source| io_error("create-selection-staging", &staging, source))?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&staging);
        return Err(io_error("write-selection-staging", &staging, source));
    }
    fs::rename(&staging, path).map_err(|source| {
        let _ = fs::remove_file(&staging);
        io_error("publish-selection-record", path, source)
    })?;
    sync_directory(parent, "sync-selection-record-parent")
}

fn count_selection_records(root: &Path) -> Result<u64, ExactPinRetentionError> {
    let mut count = 0_u64;
    let shards = fs::read_dir(root)
        .map_err(|source| io_error("read-selection-record-root", root, source))?;
    for shard in shards {
        let shard = shard.map_err(|source| io_error("read-selection-shard", root, source))?;
        let shard_path = shard.path();
        let shard_name = shard
            .file_name()
            .into_string()
            .map_err(|_| corrupt("selection-shard-name"))?;
        if !is_lower_hex(&shard_name, 2)
            || !shard
                .file_type()
                .map_err(|source| io_error("stat-selection-shard", &shard_path, source))?
                .is_dir()
        {
            return Err(corrupt("selection-shard-shape"));
        }
        for record in fs::read_dir(&shard_path)
            .map_err(|source| io_error("read-selection-shard-records", &shard_path, source))?
        {
            let record = record
                .map_err(|source| io_error("read-selection-record-entry", &shard_path, source))?;
            let name = record
                .file_name()
                .into_string()
                .map_err(|_| corrupt("selection-record-name"))?;
            if is_staging_name(&name)
                && record
                    .file_type()
                    .map_err(|source| io_error("stat-selection-staging", &record.path(), source))?
                    .is_file()
            {
                count = count
                    .checked_add(1)
                    .ok_or(ExactPinRetentionError::SelectionLimit)?;
                if count > MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS {
                    return Err(ExactPinRetentionError::SelectionLimit);
                }
                continue;
            }
            if !is_lower_hex(&name, 64)
                || !name.starts_with(&shard_name)
                || !record
                    .file_type()
                    .map_err(|source| io_error("stat-selection-record", &record.path(), source))?
                    .is_file()
            {
                return Err(corrupt("selection-record-entry-shape"));
            }
            count = count
                .checked_add(1)
                .ok_or(ExactPinRetentionError::SelectionLimit)?;
            if count > MAX_EXACT_PIN_MATERIALIZATION_SELECTIONS {
                return Err(ExactPinRetentionError::SelectionLimit);
            }
        }
    }
    Ok(count)
}

fn is_staging_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".staging-") else {
        return false;
    };
    let Some((process, ordinal)) = suffix.split_once('-') else {
        return false;
    };
    !process.is_empty()
        && process.bytes().all(|byte| byte.is_ascii_digit())
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
}

fn push_bounded_string(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_directory_durable(
    path: &Path,
    operation: &'static str,
) -> Result<(), ExactPinRetentionError> {
    fs::create_dir_all(path).map_err(|source| io_error(operation, path, source))?;
    sync_directory(path, operation)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent, operation)?;
    }
    Ok(())
}

fn sync_record_parent(path: &Path) -> Result<(), ExactPinRetentionError> {
    let parent = path
        .parent()
        .ok_or_else(|| corrupt("selection-record-parent"))?;
    sync_directory(parent, "sync-existing-selection-record-parent")
}

fn sync_directory(path: &Path, operation: &'static str) -> Result<(), ExactPinRetentionError> {
    let directory = File::open(path).map_err(|source| io_error(operation, path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> ExactPinRetentionError {
    ExactPinRetentionError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

const fn corrupt(reason: &'static str) -> ExactPinRetentionError {
    ExactPinRetentionError::Corrupt { reason }
}

struct SelectionCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> SelectionCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ExactPinRetentionError> {
        if self.remaining.len() < N {
            return Err(corrupt("selection-record-truncated"));
        }
        let mut value = [0_u8; N];
        value.copy_from_slice(&self.remaining[..N]);
        self.remaining = &self.remaining[N..];
        Ok(value)
    }

    fn string(&mut self) -> Result<String, ExactPinRetentionError> {
        let length = usize::from(u16::from_be_bytes(self.fixed()?));
        if self.remaining.len() < length {
            return Err(corrupt("selection-record-truncated-string"));
        }
        let value = std::str::from_utf8(&self.remaining[..length])
            .map_err(|_| corrupt("selection-record-string-utf8"))?
            .to_owned();
        self.remaining = &self.remaining[length..];
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests;
