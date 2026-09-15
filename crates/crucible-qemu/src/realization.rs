//! QEMU VM realization branch coordination.
//!
//! This module owns the RFC-0010 T-QEMU-6 single `instantiate` path. Lifecycle
//! owners derive the exact requested configuration before calling it. It selects
//! between version-nine exact-checkpoint restore, ancestor replay, and baked-genesis load in
//! the required priority order while keeping the true cold boot inside `bake`.

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, MaterializedState,
    NodeBlobRef, RuntimeState, World,
};
use std::sync::Arc;
use thiserror::Error;

use crucible::exact_checkpoint::ExactCheckpointId;

mod snapshot_codec;
pub use snapshot_codec::QemuVmSnapshotCodecError;
#[cfg(target_os = "linux")]
mod node_executor;
#[cfg(target_os = "linux")]
pub(crate) use node_executor::{QemuHotForkTemplateIdentity, QemuHotForkTemplatePreparer};
#[cfg(target_os = "linux")]
pub use node_executor::{
    QemuReplayValidationExactAdmission, QemuReplayValidationExecutor,
    QemuReplayValidationThinAdmission,
};

/// An exact QEMU VM snapshot cached for one configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmSnapshot {
    /// The checkpoint that owns the cached VM snapshot.
    checkpoint: Arc<Checkpoint>,
    /// Apache-side device continuation captured at the same scheduler boundary.
    host_io: crate::QemuHostIoCheckpoint,
    /// Scheduler-facing Apache node continuation captured at the same boundary.
    node: crate::QemuNodeContinuationCheckpoint,
    live_capture: bool,
    identity: ContentHash,
}

/// One-shot replay-oracle match bound to the complete exact source relation.
///
/// The private source identity prevents a successful fat/thin comparison from
/// being transplanted onto different VMState or Apache continuation metadata.
/// This is a process-local validation capability. Durable publication records
/// it in an exact-root certificate separate from snapshot bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct QemuReplayOracleMatch {
    node: crucible::NodeId,
    source: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
    runtime_hash: ContentHash,
}

impl QemuReplayOracleMatch {
    /// Consumes this match after authenticating its complete source relation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the result belongs to another
    /// snapshot or the concrete comparison was absent or mismatched.
    pub fn into_authenticated_source(
        self,
        repository_root: ExactCheckpointId,
        production_identity: ContentHash,
        target_manifest: ContentHash,
        node: &crucible::NodeId,
        snapshot: &QemuVmSnapshot,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        if node != &self.node
            || self
                .source
                .authenticate_replay_source_relation(
                    repository_root,
                    production_identity,
                    target_manifest,
                    node,
                    snapshot.id(),
                )
                .is_err()
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "replay-oracle evidence",
                message: String::from(
                    "replay-oracle match belongs to a different exact source relation",
                ),
            });
        }
        Ok(self.runtime_hash)
    }
}

impl QemuVmSnapshot {
    /// Builds a snapshot whose QEMU and host-I/O halves share one identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::InvalidCheckpoint`] when the host-I/O
    /// continuation was captured for a different VMState checkpoint.
    pub(crate) fn from_live_capture(
        checkpoint: Arc<Checkpoint>,
        host_io: crate::QemuHostIoCheckpoint,
        node: crate::QemuNodeContinuationCheckpoint,
    ) -> Result<Self, QemuVmRealizationError> {
        if host_io.execution_binding() != checkpoint.id || node.execution_binding() != checkpoint.id
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "paired exact snapshot",
                message: String::from(
                    "host-I/O continuation is bound to another QEMU VMState checkpoint",
                ),
            });
        }
        let identity =
            exact_snapshot_identity(&checkpoint, &host_io, &node, true).map_err(|error| {
                QemuVmRealizationError::InvalidCheckpoint {
                    role: "paired exact snapshot",
                    message: format!("cannot authenticate complete snapshot state: {error}"),
                }
            })?;
        Ok(Self {
            checkpoint,
            host_io,
            node,
            live_capture: true,
            identity,
        })
    }

    /// Returns the materialized scheduler checkpoint paired with this snapshot.
    #[must_use]
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Returns the Apache host-I/O continuation paired with this snapshot.
    #[must_use]
    pub const fn host_io(&self) -> &crate::QemuHostIoCheckpoint {
        &self.host_io
    }

    /// Returns the scheduler-facing node continuation paired with this snapshot.
    #[must_use]
    pub const fn node_continuation(&self) -> &crate::QemuNodeContinuationCheckpoint {
        &self.node
    }

    pub(crate) const fn is_live_capture(&self) -> bool {
        self.live_capture
    }

    /// Returns the aggregate identity binding VMState metadata and Apache state.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.identity
    }

    pub(crate) fn has_valid_identity(&self) -> bool {
        exact_snapshot_identity(
            &self.checkpoint,
            &self.host_io,
            &self.node,
            self.live_capture,
        )
        .is_ok_and(|identity| self.identity == identity)
    }

    /// Builds a paired snapshot for a runtime with no host-serviced block device.
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::InvalidCheckpoint`] if the generated
    /// owner continuations cannot be canonically authenticated.
    #[cfg(any(test, feature = "test-support"))]
    pub fn diskless(checkpoint: Checkpoint) -> Result<Self, QemuVmRealizationError> {
        let host_io = crate::QemuHostIoCheckpoint::without_devices(checkpoint.id);
        let node = crate::QemuNodeContinuationCheckpoint {
            execution_binding: checkpoint.id,
            last_observed_time: checkpoint.virtual_time,
            logical_time_calibration: crate::QemuLogicalTimeCalibration {
                logical_icount: checkpoint.virtual_time.ticks,
                raw_icount: checkpoint.virtual_time.ticks,
            },
            console_observation_boundary: checkpoint.virtual_time,
            pending_preemption: None,
            pending_network_outputs: Vec::new(),
            network_transport: crate::QemuNetworkTransportCheckpoint::empty(),
            next_fault_command_sequence: 2,
            next_fault_event_sequence: 1,
        };
        let identity =
            exact_snapshot_identity(&checkpoint, &host_io, &node, false).map_err(|error| {
                QemuVmRealizationError::InvalidCheckpoint {
                    role: "diskless exact snapshot",
                    message: format!("cannot authenticate generated snapshot state: {error}"),
                }
            })?;
        Ok(Self {
            checkpoint: Arc::new(checkpoint),
            host_io,
            node,
            live_capture: false,
            identity,
        })
    }
}

fn exact_snapshot_identity(
    checkpoint: &Checkpoint,
    host_io: &crate::QemuHostIoCheckpoint,
    node: &crate::QemuNodeContinuationCheckpoint,
    live_capture: bool,
) -> Result<ContentHash, QemuVmSnapshotCodecError> {
    snapshot_codec::canonical_snapshot_identity(checkpoint, host_io, node, live_capture)
}

/// A baked genesis snapshot shared by worlds with identical VM inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuBakedGenesisSnapshot {
    /// The world content address that produced this baked genesis snapshot.
    world_id: ContentHash,
    /// The checkpoint containing the baked ready-point VM state.
    checkpoint: Checkpoint,
    /// The complete QEMU snapshot identity admitted for thin replay.
    source_snapshot: ContentHash,
}

impl QemuBakedGenesisSnapshot {
    /// Binds a baked-genesis checkpoint to its complete source snapshot.
    #[must_use]
    pub fn new(world_id: ContentHash, snapshot: &QemuVmSnapshot) -> Self {
        Self {
            world_id,
            checkpoint: snapshot.checkpoint().clone(),
            source_snapshot: snapshot.id(),
        }
    }
}

/// Validated admission to restore a baked-genesis descriptor checkpoint.
///
/// Values of this type are created only after the baked snapshot has been
/// checked against the requested world. Real QEMU executors can pass this object directly to
/// the Linux node factory without accepting arbitrary fat checkpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QemuBakedGenesisRestoreAdmission<'a> {
    snapshot: &'a QemuBakedGenesisSnapshot,
}

/// Opaque authority for one exact snapshot replay-oracle probe.
///
/// Only the replay-oracle coordinator can create this value. Receiving an
/// admission permits one comparison launch but does not grant production
/// runtime admission.
pub(crate) struct QemuReplayOracleProbeAdmission<'a> {
    snapshot: &'a QemuVmSnapshot,
}

impl<'a> QemuReplayOracleProbeAdmission<'a> {
    const fn new(snapshot: &'a QemuVmSnapshot) -> Self {
        Self { snapshot }
    }

    #[must_use]
    pub(crate) const fn snapshot(&self) -> &'a QemuVmSnapshot {
        self.snapshot
    }
}

impl<'a> QemuBakedGenesisRestoreAdmission<'a> {
    /// Builds a baked-genesis restore admission after validating the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when `snapshot` is not a valid baked
    /// genesis snapshot for `world`.
    pub(crate) fn new(
        snapshot: &'a QemuBakedGenesisSnapshot,
        world: &World,
    ) -> Result<Self, QemuVmRealizationError> {
        validate_baked_genesis_snapshot(snapshot, world)?;
        Ok(Self { snapshot })
    }

    /// Returns the checkpoint whose version-nine descriptors may be restored.
    #[must_use]
    pub(crate) const fn checkpoint(self) -> &'a Checkpoint {
        &self.snapshot.checkpoint
    }
}

/// Replay request passed to the QEMU quantum executor.
pub struct QemuVmReplayRequest {
    from: Configuration,
    to: Configuration,
    decision: Decision,
}

impl QemuVmReplayRequest {
    /// Constructs one canonical replay transition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::InvalidCheckpoint`] when the decision
    /// would violate the scenario model.
    pub fn new(from: Configuration, decision: Decision) -> Result<Self, QemuVmRealizationError> {
        let to = crucible::try_step(&from, decision.clone()).map_err(|source| {
            QemuVmRealizationError::InvalidCheckpoint {
                role: "replay transition target",
                message: format!("decision violates the scenario model: {source}"),
            }
        })?;
        Ok(Self { from, to, decision })
    }

    pub(crate) const fn from(&self) -> &Configuration {
        &self.from
    }

    pub(crate) const fn to(&self) -> &Configuration {
        &self.to
    }

    pub(crate) const fn decision(&self) -> &Decision {
        &self.decision
    }
}

fn validate_snapshot_pair(snapshot: &QemuVmSnapshot) -> Result<(), QemuVmRealizationError> {
    if snapshot.host_io.execution_binding() != snapshot.checkpoint.id {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "paired exact snapshot",
            message: String::from(
                "host-I/O continuation is bound to another QEMU VMState checkpoint",
            ),
        });
    }
    Ok(())
}

fn validate_oracle_runtime_configuration(
    role: &'static str,
    runtime: &RuntimeState,
    expected_configuration: ContentHash,
) -> Result<(), QemuVmRealizationError> {
    if runtime.configuration == expected_configuration {
        Ok(())
    } else {
        Err(QemuVmRealizationError::InvalidCheckpoint {
            role,
            message: format!(
                "runtime configuration {:?} does not match target {:?}",
                runtime.configuration, expected_configuration
            ),
        })
    }
}

fn validate_checkpoint_matches_config(
    checkpoint: &Checkpoint,
    config: &Configuration,
    role: &'static str,
) -> Result<(), QemuVmRealizationError> {
    if checkpoint.configuration == config.id() {
        Ok(())
    } else {
        Err(QemuVmRealizationError::InvalidCheckpoint {
            role,
            message: format!(
                "checkpoint configuration {:?} does not match configuration {:?}",
                checkpoint.configuration,
                config.id()
            ),
        })
    }
}

fn validate_baked_genesis_snapshot(
    snapshot: &QemuBakedGenesisSnapshot,
    world: &World,
) -> Result<(), QemuVmRealizationError> {
    if snapshot.world_id != world.id {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "baked genesis",
            message: format!(
                "baked world {:?} does not match requested world {:?}",
                snapshot.world_id, world.id
            ),
        });
    }
    if snapshot.checkpoint.kind != CheckpointKind::Fat {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "baked genesis",
            message: String::from("baked genesis checkpoint must be fat"),
        });
    }
    validate_exact_checkpoint_state(&snapshot.checkpoint, "baked genesis")?;
    validate_baked_genesis_node_blobs(snapshot, world)?;
    Ok(())
}

fn validate_exact_checkpoint_state(
    checkpoint: &Checkpoint,
    role: &'static str,
) -> Result<(), QemuVmRealizationError> {
    let state =
        checkpoint
            .state
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role,
                message: String::from("fat checkpoint missing materialized state"),
            })?;
    let expected_state = MaterializedState::from_components(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        state.scheduler.clone(),
        state.decision_rng.clone(),
        state.event_log,
    );
    if state.id != expected_state.id {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role,
            message: String::from("materialized state id does not match its components"),
        });
    }
    for (node, blob) in &checkpoint.node_blobs {
        let snapshot = state.vm_snapshots.get(node).ok_or_else(|| {
            QemuVmRealizationError::InvalidCheckpoint {
                role,
                message: format!("materialized state missing VM snapshot for {}", node.name),
            }
        })?;
        if &snapshot.blob != blob {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role,
                message: format!(
                    "materialized VM snapshot for {} does not match checkpoint blob",
                    node.name
                ),
            });
        }
        let expected_icount = checkpoint
            .node_icounts
            .get(node)
            .copied()
            .unwrap_or_default();
        if snapshot.icount != expected_icount {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role,
                message: format!(
                    "materialized VM snapshot icount for {} does not match checkpoint icount",
                    node.name
                ),
            });
        }
    }
    for node in state.vm_snapshots.keys() {
        if !checkpoint.node_blobs.contains_key(node) {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role,
                message: format!(
                    "materialized state has VM snapshot for unknown node {}",
                    node.name
                ),
            });
        }
    }
    Ok(())
}

fn validate_baked_genesis_node_blobs(
    snapshot: &QemuBakedGenesisSnapshot,
    world: &World,
) -> Result<(), QemuVmRealizationError> {
    for node in world.vm_nodes() {
        if !matches!(
            snapshot.checkpoint.node_blob(&node.id),
            Some(NodeBlobRef::Baked(_))
        ) {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "baked genesis",
                message: format!("missing baked node blob for node {}", node.id.name),
            });
        }
    }

    Ok(())
}

/// Errors returned by QEMU VM realization coordination.
#[derive(Debug, Error)]
pub enum QemuVmRealizationError {
    /// A QEMU runtime operation is temporarily unavailable.
    #[error("{operation} executor operation is temporarily unavailable: {message}")]
    ExecutorUnavailable {
        /// Runtime operation being attempted.
        operation: &'static str,
        /// Availability failure detail.
        message: String,
    },
    /// Attempt-scoped realization was canceled at an operational boundary.
    #[error("QEMU realization was canceled before {operation}")]
    Canceled {
        /// Operation that was prevented by cancellation.
        operation: &'static str,
    },
    /// A failed reap transferred the live process and limits to quarantine.
    #[error("{operation} could not attest process reap; enforcement is quarantined: {message}")]
    ReapQuarantined {
        /// Cleanup operation that could not prove reap.
        operation: &'static str,
        /// Diagnostic from the failed kill-and-reap ladder.
        message: String,
    },
    /// A checkpoint-store operation failed.
    #[error("{operation} store operation failed: {message}")]
    Store {
        /// Store operation being attempted.
        operation: &'static str,
        /// Deterministic failure detail.
        message: String,
    },
    /// A QEMU runtime operation failed.
    #[error("{operation} executor operation failed: {message}")]
    Executor {
        /// Runtime operation being attempted.
        operation: &'static str,
        /// Deterministic failure detail.
        message: String,
    },
    /// A cached checkpoint did not match the configuration it claimed to represent.
    #[error("invalid {role} checkpoint: {message}")]
    InvalidCheckpoint {
        /// Checkpoint role being validated.
        role: &'static str,
        /// Deterministic failure detail.
        message: String,
    },
    /// The checkpoint store returned an ancestor outside the target path.
    #[error("invalid cached ancestor: {message}")]
    InvalidAncestor {
        /// Deterministic failure detail.
        message: String,
    },
    /// The exact checkpoint and thin replay produced different runtime fingerprints.
    #[error("QEMU exact-checkpoint replay oracle mismatch: fat={fat_hash:?} thin={thin_hash:?}")]
    ReplayOracleMismatch {
        /// Fingerprint of the probed fat checkpoint.
        fat_hash: ContentHash,
        /// Fingerprint of the thin replay runtime.
        thin_hash: ContentHash,
    },
}

impl PartialEq for QemuVmRealizationError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for QemuVmRealizationError {}
