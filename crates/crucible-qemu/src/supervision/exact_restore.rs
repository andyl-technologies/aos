//! Atomic repository-rooted exact-checkpoint launch.
//!
//! This module owns the only operation that turns authenticated checkpoint
//! streams into a live QEMU process. It retains the process contract, prepared
//! directory, execution relation, and every input stream until all bytes have
//! been authenticated and sealed. No writable materialization stage escapes.

use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd as _;
use std::path::Path;

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
    snapshot_object: ContentHash,
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
        let snapshot_object = exact_snapshot_object_identity(&snapshot)?;
        validate_exact_restore_relation(
            config.run_directory(),
            run_directory.path(),
            &node,
            snapshot_object,
            target.node(),
            target.snapshot(),
        )?;
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
            snapshot_object,
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
        self.run_directory
            .prepare_vmstate_container_guarded(
                self.config.qemu_executable(),
                &self.process_contract,
            )
            .map_err(|source| QemuLiveNodeStepGateError::ExactVmstatePreparation { source })?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=vmstate-container-ready");
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
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=ram-inputs-ready");
        let identity =
            QemuLiveNodeIdentity::new(&self.node.name, &self.router, &self.crash_detector);
        let admission = AtomicExactRestoreAdmission::admit(
            &mut self.run_directory,
            &self.process_contract,
            identity,
            &self.snapshot,
            self.snapshot_object,
            ram_inputs,
            std::os::fd::AsFd::as_fd(&cancellation),
        )?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=atomic-admission-ready");
        let (node, target) = launch_atomic_exact_restore(&self.config, admission, false)?;
        eprintln!("CRUCIBLE-PROMOTION-PROBE-TRACE-V1 stage=atomic-restore-complete");

        Ok(QemuProductionExactRestoreLaunch {
            node,
            run_directory: self.run_directory,
            target,
        })
    }
}

fn exact_snapshot_object_identity(
    snapshot: &QemuVmSnapshot,
) -> Result<ContentHash, QemuLiveNodeStepGateError> {
    // Repository targets name the canonical snapshot object, while id() names
    // the snapshot's internal execution state.
    let bytes = snapshot.to_canonical_bytes().map_err(|source| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("encode exact restore snapshot object: {source}"),
        }
    })?;
    Ok(ContentHash::from_bytes(&bytes))
}

fn validate_exact_restore_relation(
    config_directory: &Path,
    prepared_directory: &Path,
    node: &NodeId,
    snapshot_object: ContentHash,
    target_node: &str,
    target_snapshot: ContentHash,
) -> Result<(), QemuLiveNodeStepGateError> {
    if config_directory != prepared_directory
        || target_node != node.name
        || target_snapshot != snapshot_object
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "exact restore request differs from its directory, node, or snapshot",
            ),
        });
    }
    Ok(())
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
    /// Retains a restored node at its authenticated paused boundary for replay comparison.
    ///
    /// The exact probe fingerprints the restored checkpoint before any guest
    /// instruction may execute. Production resume uses `into_running_parts`
    /// only after admitting that checkpoint as the live continuation.
    pub(crate) fn into_paused_parts(
        self,
    ) -> (
        QemuNode,
        QemuPreparedRunDirectory,
        crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
    ) {
        (self.node, self.run_directory, self.target)
    }

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crucible::{Checkpoint, CheckpointKind, Configuration, ScenarioDef, VirtualTime};

    use super::*;

    #[test]
    fn exact_restore_matches_repository_snapshot_object_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let definition = ScenarioDef::from_canonical_material(
            "crucible.test.qemu.exact-restore",
            "snapshot-object-identity",
        );
        let configuration = Configuration::genesis(definition);
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )?;
        let snapshot = QemuVmSnapshot::diskless(checkpoint)?;
        let canonical = snapshot.to_canonical_bytes()?;
        let object_identity = ContentHash::from_bytes(&canonical);
        let node = NodeId {
            name: String::from("guest"),
        };
        let run_directory = Path::new("/exact-restore-generation");

        assert_ne!(snapshot.id(), object_identity);
        assert_eq!(exact_snapshot_object_identity(&snapshot)?, object_identity);
        assert!(
            validate_exact_restore_relation(
                run_directory,
                run_directory,
                &node,
                object_identity,
                "guest",
                object_identity,
            )
            .is_ok()
        );
        for foreign_snapshot in [snapshot.id(), ContentHash::from_bytes(b"other snapshot")] {
            assert!(
                validate_exact_restore_relation(
                    run_directory,
                    run_directory,
                    &node,
                    object_identity,
                    "guest",
                    foreign_snapshot,
                )
                .is_err()
            );
        }
        assert!(
            validate_exact_restore_relation(
                run_directory,
                run_directory,
                &node,
                object_identity,
                "foreign guest",
                object_identity,
            )
            .is_err()
        );
        assert!(
            validate_exact_restore_relation(
                Path::new("/other-generation"),
                run_directory,
                &node,
                object_identity,
                "guest",
                object_identity,
            )
            .is_err()
        );
        Ok(())
    }
}
