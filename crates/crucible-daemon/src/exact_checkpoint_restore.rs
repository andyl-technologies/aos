//! Exact checkpoint restoration into a guarded QEMU run directory.
//!
//! This module joins three independently owned authorities without granting
//! any of them broader mutation capability: a semantic exact pin or durable
//! attempt-resume root, the operational owner that retained it, and the
//! immutable exact-checkpoint store. The VMState child streams into a pinned
//! run-directory transaction; only a complete authenticated copy becomes
//! eligible for guarded launch.

use std::io::{self, Read, Write};
use std::sync::Arc;

use crucible::{Configuration, ContentHash};
use crucible_cas::content_store::{BlobHandle, BlobSource, StoreError};
use crucible_qemu::{
    QemuBakedGenesisRestoreAdmission, QemuCapturedVmState, QemuFailedLaunchChildSource,
    QemuGuardedNodeRealizationLauncher, QemuGuardedThinNodeRealizationLauncher,
    QemuNodeRealizationExecutor, QemuPreparedRunDirectory, QemuSpawnError,
    QemuVmLiveRealizationExecutor, QemuVmRealization, QemuVmRealizationError,
    QemuVmRealizationExecutor, QemuVmRealizationKind, QemuVmRealizationOperation,
    QemuVmReplayRequest, QemuVmSnapshot, QemuVmStateBinding,
};
use thiserror::Error;

use crucible_campaign::{
    CampaignFactId, CampaignName, CampaignRepository, ConfigurationId, ExactCheckpointId,
};

use crate::{
    ExactCheckpointStore, ExactCheckpointStoreError, ExactPinRetentionAdmin,
    ExactPinRetentionError, ExecutionCancellation, LoadedExactCheckpoint,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuExactCheckpointRealization,
};

/// Converts a post-reap QEMU VMState capability into a reopenable CAS source.
///
/// Every opened reader has an independent positional cursor over the same
/// retained inode. The source therefore remains deterministic when immutable
/// publication retries or mirrors it after the run-directory entry is removed.
#[must_use]
pub fn captured_qemu_vmstate_blob(source: QemuCapturedVmState) -> BlobHandle {
    BlobHandle::new(Arc::new(CapturedQemuVmStateSource {
        source: Arc::new(source),
    }))
}

struct CapturedQemuVmStateSource {
    source: Arc<QemuCapturedVmState>,
}

impl BlobSource for CapturedQemuVmStateSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(CapturedQemuVmStateReader {
            source: Arc::clone(&self.source),
            offset: 0,
        }))
    }
}

struct CapturedQemuVmStateReader {
    source: Arc<QemuCapturedVmState>,
    offset: u64,
}

impl Read for CapturedQemuVmStateReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.source.logical_length().saturating_sub(self.offset);
        if remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let maximum = usize::try_from(remaining).unwrap_or(usize::MAX);
        let read_length = buffer.len().min(maximum);
        let read = self
            .source
            .read_at(&mut buffer[..read_length], self.offset)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "captured QEMU VMState ended before its attested length",
            ));
        }
        self.offset = self
            .offset
            .checked_add(u64::try_from(read).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "VMState read length overflow")
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "VMState read offset overflow")
            })?;
        Ok(read)
    }
}

/// One exact checkpoint durably materialized for guarded QEMU restore.
#[derive(Clone, Debug)]
pub struct MaterializedExactCheckpoint {
    checkpoint: ExactCheckpointId,
    pin_fact: CampaignFactId,
    vmstate_binding: QemuVmStateBinding,
    snapshot: QemuVmSnapshot,
}

/// One operational attempt checkpoint durably materialized for guarded resume.
///
/// Unlike [`MaterializedExactCheckpoint`], this value is rooted by the exact
/// resume identity retained in the supervisor ledger rather than by a semantic
/// campaign pin. It still authenticates the same complete immutable root and
/// commits the same root-derived VMState binding before launch.
#[derive(Clone, Debug)]
pub struct MaterializedAttemptCheckpoint {
    checkpoint: ExactCheckpointId,
    vmstate_binding: QemuVmStateBinding,
    snapshot: QemuVmSnapshot,
}

/// Attempt-owned guarded executor for one exact fat/thin replay comparison.
///
/// The session routes the selected fat probe through the exact-root launcher
/// and every cached-ancestor or baked-genesis restore through a disjoint thin-
/// path launcher. It owns the attempt resource guard until the last live QEMU
/// generation is reaped. Any realization failure is conservatively transferred
/// to guard quarantine after first transferring any retained pre-install child
/// authority into that guard.
pub struct QemuGuardedReplayOracleSession<'a, L, G>
where
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    executor: &'a mut QemuNodeRealizationExecutor<L>,
    guard: G,
    realization_failed: bool,
    backend_reaped: bool,
    guard_terminal: bool,
}

impl<'a, L, G> QemuGuardedReplayOracleSession<'a, L, G>
where
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    /// Takes ownership of one installed attempt guard for replay validation.
    #[must_use]
    pub const fn new(executor: &'a mut QemuNodeRealizationExecutor<L>, guard: G) -> Self {
        Self {
            executor,
            guard,
            realization_failed: false,
            backend_reaped: false,
            guard_terminal: false,
        }
    }

    /// Reaps the final thin-path generation and releases its resource guard.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::ReapQuarantined`] when realization or
    /// reap failed and resource ownership was transferred to quarantine. Other
    /// cleanup diagnostics are returned only after reap attestation.
    pub fn finish(mut self) -> Result<(), QemuVmRealizationError> {
        self.cleanup()
    }

    fn observe_realization<T>(
        &mut self,
        result: Result<T, QemuVmRealizationError>,
    ) -> Result<T, QemuVmRealizationError> {
        if result.is_err() {
            self.realization_failed = true;
            if let Some(child) = self.executor.take_failed_launch_child_for_quarantine() {
                self.guard.retain_failed_launch_child(child);
            }
        }
        self.guard.check_operational_boundary()?;
        result
    }

    fn cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.realization_failed && !self.guard_terminal {
            self.guard.quarantine();
            self.guard_terminal = true;
            return Err(QemuVmRealizationError::ReapQuarantined {
                operation: "finish guarded replay-oracle comparison",
                message: String::from(
                    "failed-realization process authority and attempt resources were quarantined",
                ),
            });
        }
        if !self.backend_reaped {
            match QemuVmLiveRealizationExecutor::shutdown_live_backend(self.executor) {
                Ok(_outcome) => self.backend_reaped = true,
                Err(error) => {
                    if !self.guard_terminal {
                        self.guard.quarantine();
                        self.guard_terminal = true;
                    }
                    return Err(QemuVmRealizationError::ReapQuarantined {
                        operation: "finish guarded replay-oracle comparison",
                        message: error.to_string(),
                    });
                }
            }
        }
        if !self.guard_terminal {
            let result = self.guard.finish();
            self.guard_terminal = true;
            result?;
        }
        Ok(())
    }
}

impl<L, G> QemuVmRealizationExecutor for QemuGuardedReplayOracleSession<'_, L, G>
where
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: crucible_qemu::QemuLoadvmCommandAuthorization,
        admission: crucible_qemu::QemuLoadvmRealizationAdmission,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self.executor.load_prepared_thin_snapshot_guarded(
            self.guard.child_process_contract()?,
            config,
            snapshot,
            authorization,
            admission,
        );
        self.observe_realization(result)
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: crucible_qemu::QemuLoadvmCommandAuthorization,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .load_materialized_exact_snapshot_probe_guarded(
                self.guard.child_process_contract()?,
                config,
                snapshot,
                authorization,
            );
        self.observe_realization(result)
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self.executor.load_prepared_baked_genesis_guarded(
            self.guard.child_process_contract()?,
            config,
            admission,
        );
        self.observe_realization(result)
    }

    fn replay_one_quantum(
        &mut self,
        runtime: crucible::RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        self.guard.charge_execution_quantum()?;
        let result = self
            .executor
            .replay_materialized_one_quantum(runtime, request);
        self.observe_realization(result)
    }
}

impl<L, G> Drop for QemuGuardedReplayOracleSession<'_, L, G>
where
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl MaterializedExactCheckpoint {
    /// Returns the complete immutable exact-checkpoint root.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the exact semantic pin fact authorizing materialization.
    #[must_use]
    pub const fn pin_fact(&self) -> CampaignFactId {
        self.pin_fact
    }

    /// Returns the complete-root binding committed with the pinned VMState.
    #[must_use]
    pub const fn vmstate_binding(&self) -> QemuVmStateBinding {
        self.vmstate_binding
    }

    /// Returns the authenticated snapshot metadata bound to the VMState file.
    #[must_use]
    pub const fn snapshot(&self) -> &QemuVmSnapshot {
        &self.snapshot
    }

    /// Consumes the materialization into its authenticated snapshot metadata.
    #[must_use]
    pub fn into_snapshot(self) -> QemuVmSnapshot {
        self.snapshot
    }
}

impl MaterializedAttemptCheckpoint {
    /// Returns the complete immutable exact-checkpoint root.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the complete-root binding committed with the pinned VMState.
    #[must_use]
    pub const fn vmstate_binding(&self) -> QemuVmStateBinding {
        self.vmstate_binding
    }

    /// Returns the authenticated snapshot metadata bound to the VMState file.
    #[must_use]
    pub const fn snapshot(&self) -> &QemuVmSnapshot {
        &self.snapshot
    }

    /// Consumes the materialization into its authenticated snapshot metadata.
    #[must_use]
    pub fn into_snapshot(self) -> QemuVmSnapshot {
        self.snapshot
    }
}

/// Materializes the current selected exact checkpoint into `run_directory`.
///
/// Selection inventory authority is held only for the bounded journal lookup.
/// Campaign and checkpoint authentication, streaming copy, and file sync occur
/// after that fence is released. Cancellation is checked before and after each
/// destination write; a cancellation or any source/destination failure leaves
/// the pinned destination explicitly unready.
///
/// The caller remains responsible for retaining the exact campaign resume
/// precondition until it consumes the returned materialization in guarded QEMU
/// launch. The returned pin fact provides that reconciliation basis.
///
/// # Errors
///
/// Returns [`ExactCheckpointRestoreError`] when cancellation has won, no
/// selection exists, the selection is stale or corrupt, checkpoint closure
/// authentication fails, or the pinned destination cannot be committed.
pub fn materialize_selected_exact_checkpoint<A>(
    repository: &CampaignRepository,
    checkpoints: &ExactCheckpointStore,
    selections: &mut A,
    campaign: &CampaignName,
    configuration: ConfigurationId,
    run_directory: &mut QemuPreparedRunDirectory,
    cancellation: &ExecutionCancellation,
) -> Result<MaterializedExactCheckpoint, ExactCheckpointRestoreError>
where
    A: ExactPinRetentionAdmin + ?Sized,
{
    check_cancellation(cancellation)?;
    let selection = {
        let mut fence = selections.acquire_exact_pin_retention_fence()?;
        fence.selection(campaign, configuration)?.ok_or_else(|| {
            ExactCheckpointRestoreError::MissingSelection {
                campaign: campaign.clone(),
                configuration,
            }
        })?
    };

    check_cancellation(cancellation)?;
    let loaded = selection.authenticate_current(repository, checkpoints)?;
    let (vmstate_binding, snapshot) = materialize_loaded_checkpoint(
        selection.checkpoint(),
        &loaded,
        run_directory,
        cancellation,
    )?;

    Ok(MaterializedExactCheckpoint {
        checkpoint: selection.checkpoint(),
        pin_fact: selection.pin_fact(),
        vmstate_binding,
        snapshot,
    })
}

/// Materializes one supervisor-retained exact root for attempt resume.
///
/// The root is authenticated directly from the immutable checkpoint store.
/// Its checkpoint configuration must equal `initial` or, for a branch attempt,
/// `post_selection`. The VMState child is streamed into the pinned destination
/// and authenticated before the destination becomes eligible for guarded QEMU
/// launch. No semantic pin or selection journal is consulted: the durable
/// supervisor execution origin is the root authority for this operation.
///
/// # Errors
///
/// Returns [`ExactCheckpointRestoreError`] when cancellation wins, the root is
/// unavailable or corrupt, the checkpoint names another configuration, or the
/// pinned destination cannot be committed.
pub fn materialize_attempt_exact_checkpoint(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    run_directory: &mut QemuPreparedRunDirectory,
    cancellation: &ExecutionCancellation,
) -> Result<MaterializedAttemptCheckpoint, ExactCheckpointRestoreError> {
    check_cancellation(cancellation)?;
    let loaded = checkpoints.load(checkpoint)?;
    check_cancellation(cancellation)?;

    let configuration = loaded.snapshot().checkpoint().configuration;
    let configuration_is_allowed = configuration == initial.id()
        || post_selection.is_some_and(|selected| configuration == selected.id());
    if !configuration_is_allowed {
        return Err(
            ExactCheckpointRestoreError::CheckpointConfigurationMismatch {
                checkpoint,
                configuration,
            },
        );
    }

    let (vmstate_binding, snapshot) =
        materialize_loaded_checkpoint(checkpoint, &loaded, run_directory, cancellation)?;
    Ok(MaterializedAttemptCheckpoint {
        checkpoint,
        vmstate_binding,
        snapshot,
    })
}

/// Realizes one materialized exact checkpoint under its attempt process guard.
///
/// The QEMU executor rechecks the paired snapshot and the launcher's selected
/// root binding before guarded spawn. Replay-oracle evidence is admitted inside
/// `crucible-qemu`; this function cannot mint a raw `loadvm` authorization.
/// Cancellation and resource state are checked immediately before and after the
/// blocking realization operation. The caller must still run the session
/// cleanup ladder on every returned error so failed child ownership is reaped
/// or transferred to quarantine.
///
/// # Errors
///
/// Returns [`ExactCheckpointResumeError::Canceled`] when cancellation wins, or
/// [`ExactCheckpointResumeError::Realization`] when replay admission, the
/// selected root, guarded launch, restore, or runtime validation fails.
pub fn realize_materialized_exact_checkpoint_guarded<L, G>(
    executor: &mut QemuNodeRealizationExecutor<L>,
    guard: &mut G,
    configuration: &Configuration,
    materialized: &MaterializedExactCheckpoint,
) -> Result<QemuVmRealization, ExactCheckpointResumeError>
where
    L: QemuGuardedNodeRealizationLauncher,
    G: QemuAttemptProcessResourceGuard,
{
    realize_materialized_snapshot_guarded(executor, guard, configuration, materialized.snapshot())
}

/// Realizes one supervisor-retained attempt materialization under its guard.
/// The returned realization explicitly echoes the immutable root authenticated
/// by `materialized`, allowing the runner to reject cross-root substitution.
///
/// # Errors
///
/// Returns [`ExactCheckpointResumeError::Canceled`] when cancellation wins, or
/// [`ExactCheckpointResumeError::Realization`] when replay admission, guarded
/// launch, restore, or runtime validation fails.
pub fn realize_materialized_attempt_checkpoint_guarded<L, G>(
    executor: &mut QemuNodeRealizationExecutor<L>,
    guard: &mut G,
    configuration: &Configuration,
    materialized: &MaterializedAttemptCheckpoint,
) -> Result<QemuExactCheckpointRealization, ExactCheckpointResumeError>
where
    L: QemuGuardedNodeRealizationLauncher,
    G: QemuAttemptProcessResourceGuard,
{
    let realization = realize_materialized_snapshot_guarded(
        executor,
        guard,
        configuration,
        materialized.snapshot(),
    )?;
    Ok(QemuExactCheckpointRealization::new(
        materialized.checkpoint(),
        realization,
    ))
}

fn materialize_loaded_checkpoint(
    checkpoint: ExactCheckpointId,
    loaded: &LoadedExactCheckpoint,
    run_directory: &mut QemuPreparedRunDirectory,
    cancellation: &ExecutionCancellation,
) -> Result<(QemuVmStateBinding, QemuVmSnapshot), ExactCheckpointRestoreError> {
    check_cancellation(cancellation)?;
    let snapshot = loaded.snapshot().clone();
    let vmstate_binding = restore_binding(checkpoint);
    let mut materialization = run_directory
        .begin_exact_vmstate_materialization(vmstate_binding, loaded.vmstate_bytes())?;
    let copy_result = {
        let mut destination = CancellationCheckedWriter {
            destination: &mut materialization,
            cancellation,
        };
        loaded.copy_vmstate_to(&mut destination)
    };
    if let Err(source) = copy_result {
        if cancellation.is_canceled() {
            return Err(ExactCheckpointRestoreError::Canceled);
        }
        return Err(ExactCheckpointRestoreError::Checkpoint(source));
    }
    check_cancellation(cancellation)?;
    materialization.finish()?;
    run_directory.require_exact_vmstate(vmstate_binding)?;
    check_cancellation(cancellation)?;
    Ok((vmstate_binding, snapshot))
}

fn realize_materialized_snapshot_guarded<L, G>(
    executor: &mut QemuNodeRealizationExecutor<L>,
    guard: &mut G,
    configuration: &Configuration,
    snapshot: &QemuVmSnapshot,
) -> Result<QemuVmRealization, ExactCheckpointResumeError>
where
    L: QemuGuardedNodeRealizationLauncher,
    G: QemuAttemptProcessResourceGuard,
{
    check_resume_boundary(guard)?;
    let runtime = executor.resume_materialized_exact_snapshot_guarded(
        guard.child_process_contract()?,
        configuration,
        snapshot,
    )?;
    check_resume_boundary(guard)?;
    Ok(QemuVmRealization {
        operation: QemuVmRealizationOperation::Resume,
        configuration: configuration.clone(),
        runtime,
        branch: QemuVmRealizationKind::ExactSnapshotLoadvm {
            checkpoint: snapshot.checkpoint().clone(),
        },
    })
}

struct CancellationCheckedWriter<'a, 'b> {
    destination: &'a mut crucible_qemu::QemuVmStateMaterialization<'b>,
    cancellation: &'a ExecutionCancellation,
}

impl Write for CancellationCheckedWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.cancellation.is_canceled() {
            return Err(canceled_io());
        }
        let written = self.destination.write(bytes)?;
        if self.cancellation.is_canceled() {
            return Err(canceled_io());
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.cancellation.is_canceled() {
            return Err(canceled_io());
        }
        self.destination.flush()?;
        if self.cancellation.is_canceled() {
            return Err(canceled_io());
        }
        Ok(())
    }
}

/// Failure while resolving or materializing one retained exact checkpoint.
#[derive(Debug, Error)]
pub enum ExactCheckpointRestoreError {
    /// The attempt was canceled before materialization committed.
    #[error("exact-checkpoint restore materialization was canceled")]
    Canceled,
    /// No durable operational checkpoint was selected for the exact pin.
    #[error("campaign {campaign:?} configuration {configuration} has no selected exact checkpoint")]
    MissingSelection {
        /// Exact campaign being resumed.
        campaign: CampaignName,
        /// Exact pinned configuration being resumed.
        configuration: ConfigurationId,
    },
    /// The retained root belongs to neither legal attempt boundary.
    #[error("exact checkpoint {checkpoint} names foreign configuration {configuration:?}")]
    CheckpointConfigurationMismatch {
        /// Exact root selected by the durable execution origin.
        checkpoint: ExactCheckpointId,
        /// Configuration committed by the checkpoint metadata.
        configuration: ContentHash,
    },
    /// Semantic pin or selection-journal authentication failed.
    #[error(transparent)]
    Selection(#[from] ExactPinRetentionError),
    /// Immutable checkpoint closure authentication or streaming failed.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Pinned run-directory materialization failed.
    #[error(transparent)]
    Spawn(#[from] QemuSpawnError),
}

/// Failure while turning a selected materialization into a guarded live node.
#[derive(Debug, Error)]
pub enum ExactCheckpointResumeError {
    /// Cancellation won before or during guarded realization.
    #[error("exact-checkpoint resume was canceled")]
    Canceled,
    /// QEMU replay admission, launch, restore, or runtime validation failed.
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
}

fn check_cancellation(
    cancellation: &ExecutionCancellation,
) -> Result<(), ExactCheckpointRestoreError> {
    if cancellation.is_canceled() {
        Err(ExactCheckpointRestoreError::Canceled)
    } else {
        Ok(())
    }
}

fn canceled_io() -> io::Error {
    io::Error::other("exact-checkpoint restore materialization was canceled")
}

fn restore_binding(checkpoint: ExactCheckpointId) -> QemuVmStateBinding {
    QemuVmStateBinding::from_exact_checkpoint_root_digest(checkpoint.content_id().digest())
}

fn check_resume_boundary(
    guard: &mut impl QemuAttemptOperationalBoundary,
) -> Result<(), ExactCheckpointResumeError> {
    match guard.check_operational_boundary() {
        Ok(()) => Ok(()),
        Err(QemuVmRealizationError::Canceled { .. }) => Err(ExactCheckpointResumeError::Canceled),
        Err(source) => Err(ExactCheckpointResumeError::Realization(source)),
    }
}

#[cfg(test)]
mod captured_source_tests {
    use super::*;

    #[test]
    fn captured_vmstate_blob_reopens_after_the_named_file_is_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = b"reopenable captured VMState";
        let mut named = tempfile::NamedTempFile::new()?;
        named.write_all(payload)?;
        named.as_file().sync_all()?;
        let source = QemuCapturedVmState::from_unvalidated_test_file(
            named.reopen()?,
            u64::try_from(payload.len())?,
        );
        let blob = captured_qemu_vmstate_blob(source);
        let path = named.path().to_owned();
        drop(named);
        assert!(!path.exists());

        assert_eq!(blob.read_all(1024)?, payload);
        assert_eq!(blob.read_all(1024)?, payload);
        Ok(())
    }
}
