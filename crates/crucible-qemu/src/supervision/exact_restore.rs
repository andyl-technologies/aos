//! Atomic repository-rooted exact-checkpoint launch.
//!
//! This module owns the only operation that turns authenticated checkpoint
//! streams into a live QEMU process. It retains the process contract, prepared
//! directory, execution relation, and every input stream until all bytes have
//! been authenticated and sealed. No writable materialization stage escapes.

use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd as _;

use crucible::{ContentHash, NodeId};

use crate::spawn::{QemuProductionExactRestoreSource, require_exact_restore_not_canceled};
use crate::{
    QemuChildProcessContract, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig,
    QemuLiveNodeStepGateError, QemuNode, QemuPreparedRunDirectory, QemuVmSnapshot,
};

use super::node_step_gate::{
    AtomicExactRestoreAdmission, launch_atomic_exact_restore, resume_restored_exact_node,
};

/// Complete one-shot input for a repository-rooted exact QEMU restore.
#[derive(Debug)]
#[must_use = "an admitted exact restore must be launched or discarded"]
pub struct QemuProductionExactRestoreRequest {
    config: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    process_contract: QemuChildProcessContract,
    snapshot: QemuVmSnapshot,
    node: NodeId,
    router: String,
    crash_detector: String,
    target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
    source: QemuProductionExactRestoreSource,
}

/// Process launch profile bound into one production exact restore request.
pub struct QemuProductionExactRestoreProfile {
    /// Validated live-node process configuration.
    pub config: QemuLiveNodeStepGateConfig,
    /// Prepared directory that owns the child process paths.
    pub run_directory: QemuPreparedRunDirectory,
    /// Authenticated modeled snapshot restored into the child.
    pub snapshot: QemuVmSnapshot,
    /// Modeled node that owns the snapshot.
    pub node: NodeId,
    /// Router identity passed to the child process.
    pub router: String,
    /// Crash-detector identity passed to the child process.
    pub crash_detector: String,
}

impl QemuProductionExactRestoreRequest {
    pub(crate) fn authenticate_replay_basis(
        &self,
        config: &QemuLiveNodeStepGateConfig,
        snapshot: &QemuVmSnapshot,
        node: &NodeId,
    ) -> Result<(), QemuLiveNodeStepGateError> {
        if self.config.run_directory() != config.run_directory()
            || self.node != *node
            || self.snapshot.id() != snapshot.id()
            || self.snapshot.checkpoint().id != snapshot.checkpoint().id
        {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("atomic replay admission differs from its exact request"),
            });
        }
        Ok(())
    }

    /// Admits one complete execution relation and its opaque byte source.
    ///
    /// The process contract is duplicated into this request so the same private
    /// attempt binding protects materialization and launch even when the caller
    /// releases its registry lock.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when the target names another node
    /// or snapshot, the launch profile names another directory, or the process
    /// contract cannot be retained.
    pub fn new(
        profile: QemuProductionExactRestoreProfile,
        process_contract: &QemuChildProcessContract,
        target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
        streams: crucible::exact_checkpoint::ExactCheckpointRestoreStreams,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let QemuProductionExactRestoreProfile {
            config,
            run_directory,
            snapshot,
            node,
            router,
            crash_detector,
        } = profile;
        if config.run_directory() != run_directory.path()
            || target.node() != node.name
            || target.snapshot() != snapshot.id()
        {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "exact restore request differs from its directory, node, or snapshot",
                ),
            });
        }
        let selected_root = ContentHash {
            bytes: target.repository_root().content_id().digest(),
        };
        process_contract
            .require_exact_checkpoint_root(selected_root)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let cancellation = process_contract
            .try_clone_cancellation_event()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        authenticate_immutable_backing(&config, &target, cancellation.as_fd())?;
        let process_contract = process_contract
            .try_clone_for_attempt_generation()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let (root_overlay, device_state, ram_layers) = streams.into_readers();

        Ok(Self {
            config,
            run_directory,
            process_contract,
            snapshot,
            node,
            router,
            crash_detector,
            target,
            source: QemuProductionExactRestoreSource::new(root_overlay, device_state, ram_layers),
        })
    }

    /// Authenticates all bytes, seals descriptors, and launches one exact node.
    ///
    /// No QEMU process is spawned until the overlay, device state, and every
    /// ordered RAM layer match the repository-rooted execution relation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when byte authentication,
    /// descriptor sealing, launch admission, process setup, or restore fails.
    pub fn launch(mut self) -> Result<QemuProductionExactRestoreLaunch, QemuLiveNodeStepGateError> {
        let cancellation = self
            .process_contract
            .try_clone_cancellation_event()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let ram_inputs = self
            .run_directory
            .materialize_production_exact_checkpoint(
                &self.process_contract,
                self.target,
                self.source,
                std::os::fd::AsFd::as_fd(&cancellation),
            )
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let identity =
            QemuLiveNodeIdentity::new(&self.node.name, &self.router, &self.crash_detector);
        let admission = AtomicExactRestoreAdmission::admit(
            &mut self.run_directory,
            &self.process_contract,
            identity,
            &self.snapshot,
            ram_inputs,
            std::os::fd::AsFd::as_fd(&cancellation),
        )?;
        let (node, target) = launch_atomic_exact_restore(&self.config, admission, false)?;

        Ok(QemuProductionExactRestoreLaunch {
            node,
            run_directory: self.run_directory,
            target,
        })
    }
}

fn authenticate_immutable_backing(
    config: &QemuLiveNodeStepGateConfig,
    target: &crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
    cancellation: std::os::fd::BorrowedFd<'_>,
) -> Result<(), QemuLiveNodeStepGateError> {
    let path =
        config
            .root_image()
            .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("exact restore launch has no immutable root image"),
            })?;
    let mut source = File::open(path).map_err(|source| QemuLiveNodeStepGateError::Spawn {
        source: crate::QemuSpawnError::Io {
            operation: "open exact restore immutable root image",
            source,
        },
    })?;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(1024 * 1024).map_err(|_| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("allocate immutable root-image hashing buffer"),
        }
    })?;
    buffer.resize(1024 * 1024, 0);
    let mut hasher = blake3::Hasher::new();
    loop {
        require_exact_restore_not_canceled(cancellation)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let count =
            source
                .read(&mut buffer)
                .map_err(|source| QemuLiveNodeStepGateError::Spawn {
                    source: crate::QemuSpawnError::Io {
                        operation: "hash exact restore immutable root image",
                        source,
                    },
                })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    require_exact_restore_not_canceled(cancellation)
        .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    target
        .authenticate_immutable_backing(ContentHash {
            bytes: *hasher.finalize().as_bytes(),
        })
        .map_err(|_| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "exact restore immutable root image differs from repository-bound backing",
            ),
        })
}

/// Launched exact node with its retained directory and consumed root relation.
#[must_use = "retain the launched node and its run-directory authority"]
pub struct QemuProductionExactRestoreLaunch {
    node: QemuNode,
    run_directory: QemuPreparedRunDirectory,
    target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
}

impl QemuProductionExactRestoreLaunch {
    /// Resumes a fully restored node under its retained exact relation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when QMP does not acknowledge the
    /// running transition or the failed node cannot be synchronously reaped.
    pub fn into_running_node_and_run_directory(
        self,
    ) -> Result<(QemuNode, QemuPreparedRunDirectory), QemuLiveNodeStepGateError> {
        self.into_running_parts()
            .map(|(node, run_directory, _target)| (node, run_directory))
    }

    /// Consumes a lifecycle launch while dropping its replay-only root proof.
    pub fn into_node_and_run_directory(self) -> (QemuNode, QemuPreparedRunDirectory) {
        (self.node, self.run_directory)
    }

    pub(crate) fn into_running_parts(
        self,
    ) -> Result<
        (
            QemuNode,
            QemuPreparedRunDirectory,
            crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
        ),
        QemuLiveNodeStepGateError,
    > {
        let node = resume_restored_exact_node(self.node)?;
        Ok((node, self.run_directory, self.target))
    }
}
