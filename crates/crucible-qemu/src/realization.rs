//! QEMU VM realization branch coordination.
//!
//! This module owns the RFC-0010 T-QEMU-6 lifecycle rule that `start`,
//! `resume`, and `fork` are all calls to one `instantiate` path. It selects
//! between exact-snapshot `loadvm`, ancestor replay, and baked-genesis load in
//! the required priority order while keeping the true cold boot inside `bake`.

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, EngineError,
    MaterializedState, NodeBlobRef, RuntimeState, ScenarioDef, ScheduleError, World,
};
use thiserror::Error;

use crate::{
    QemuLoadvmCommandAuthorization, QemuLoadvmCommandPurpose, QemuLoadvmRealizationAdmission,
    QemuReplayOracleValidation, QemuSavevmCompletenessPolicy, QemuSavevmPolicyError,
};

mod backend_executor;
pub use backend_executor::QemuBackendRealizationExecutor;
#[cfg(target_os = "linux")]
mod node_executor;
#[cfg(target_os = "linux")]
pub use node_executor::{
    QemuNodeRealizationExecutor, QemuNodeRealizationLauncher, QemuRealizedNodeBackend,
    QemuWarmRestoreNodeLauncher,
};

/// An exact QEMU VM snapshot cached for one configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmSnapshot {
    /// The checkpoint that owns the cached VM snapshot.
    pub checkpoint: Checkpoint,
    /// Replay-oracle evidence for the runtime restored from this snapshot.
    pub replay_oracle_validation: QemuReplayOracleValidation,
}

/// A baked genesis snapshot shared by worlds with identical VM inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuBakedGenesisSnapshot {
    /// The world content address that produced this baked genesis snapshot.
    pub world_id: ContentHash,
    /// The checkpoint containing the baked ready-point VM state.
    pub checkpoint: Checkpoint,
}

impl QemuBakedGenesisSnapshot {
    /// Bakes `world` into a genesis snapshot suitable for QEMU realization.
    ///
    /// This helper keeps model baking behind the `crucible-qemu` boundary for
    /// callers that should only invoke QEMU realization APIs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the model engine rejects the
    /// world or cannot materialize its baked genesis checkpoint.
    pub fn from_model_world(world: &World) -> Result<Self, QemuVmRealizationError> {
        let genesis = crucible::bake(world).map_err(|source| QemuVmRealizationError::Store {
            operation: "bake genesis for QEMU realization",
            message: source.to_string(),
        })?;
        Ok(Self {
            world_id: world.id,
            checkpoint: genesis.checkpoint,
        })
    }
}

/// Validated admission to restore a baked-genesis VMState snapshot.
///
/// Values of this type are created only after the baked snapshot has been
/// checked against the requested world and the QMP `loadvm` token has the
/// baked-genesis purpose. Real QEMU executors can pass this object directly to
/// the Linux node factory without accepting arbitrary fat checkpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuBakedGenesisRestoreAdmission<'a> {
    snapshot: &'a QemuBakedGenesisSnapshot,
    authorization: QemuLoadvmCommandAuthorization,
}

impl<'a> QemuBakedGenesisRestoreAdmission<'a> {
    /// Builds a baked-genesis restore admission after validating the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when `snapshot` is not a valid baked
    /// genesis snapshot for `world` or when `authorization` was not issued for
    /// baked-genesis realization.
    pub(crate) fn new(
        snapshot: &'a QemuBakedGenesisSnapshot,
        world: &World,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<Self, QemuVmRealizationError> {
        validate_baked_genesis_snapshot(snapshot, world)?;
        validate_baked_genesis_authorization(authorization)?;
        Ok(Self {
            snapshot,
            authorization,
        })
    }

    /// Returns the validated baked-genesis snapshot.
    #[must_use]
    pub const fn snapshot(self) -> &'a QemuBakedGenesisSnapshot {
        self.snapshot
    }

    /// Returns the checkpoint whose VMState may be restored.
    #[must_use]
    pub const fn checkpoint(self) -> &'a Checkpoint {
        &self.snapshot.checkpoint
    }

    /// Returns the low-level QMP `loadvm` authorization token.
    #[must_use]
    pub const fn authorization(self) -> QemuLoadvmCommandAuthorization {
        self.authorization
    }

    /// Returns the world identity whose baked genesis was admitted.
    #[must_use]
    pub const fn world_id(self) -> ContentHash {
        self.snapshot.world_id
    }
}

/// A cached ancestor selected for replay toward a target configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuCachedAncestor {
    /// Ancestor configuration on the same schedule path as the target.
    pub configuration: Configuration,
    /// Checkpoint associated with the ancestor configuration.
    pub checkpoint: Checkpoint,
}

/// The operation that requested QEMU VM realization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuVmRealizationOperation {
    /// Realize the genesis configuration for a scenario.
    Start,
    /// Realize the current tip configuration.
    Resume,
    /// Realize a schedule prefix.
    Fork {
        /// Number of decisions retained in the forked prefix.
        prefix_len: usize,
    },
    /// Directly realize an already-built configuration.
    Instantiate,
}

/// The branch that produced a realized runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuVmRealizationKind {
    /// The exact fat snapshot branch was admitted for runtime `loadvm`.
    ExactSnapshotLoadvm {
        /// Checkpoint used for the exact snapshot restore.
        checkpoint: Checkpoint,
    },
    /// A cached ancestor was realized, then the target suffix was replayed.
    AncestorReplay {
        /// Ancestor configuration identity.
        ancestor_configuration: ContentHash,
        /// Number of decisions replayed after realizing the ancestor.
        replayed_decisions: usize,
    },
    /// The target was genesis and was loaded from the baked genesis snapshot.
    BakedGenesisLoad {
        /// Baked genesis checkpoint used as the base runtime.
        checkpoint: Checkpoint,
    },
}

/// A realized QEMU runtime and the branch that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmRealization {
    /// User-facing lifecycle operation that requested realization.
    pub operation: QemuVmRealizationOperation,
    /// Configuration realized by the QEMU runtime.
    pub configuration: Configuration,
    /// Runtime-state handle returned by the QEMU executor.
    pub runtime: RuntimeState,
    /// Realization branch selected for this configuration.
    pub branch: QemuVmRealizationKind,
}

/// Replay request passed to the QEMU quantum executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmReplayRequest {
    /// Configuration the runtime currently denotes.
    pub from: Configuration,
    /// Target configuration after replaying `decision`.
    pub to: Configuration,
    /// One decision replayed in canonical schedule order.
    pub decision: Decision,
}

/// Cache/store callbacks needed by the QEMU realization coordinator.
pub trait QemuVmRealizationStore {
    /// Returns an exact cached snapshot for `config`, when one is available.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the backing checkpoint store
    /// cannot be queried.
    fn exact_snapshot(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError>;

    /// Returns the nearest cached ancestor on `config`'s schedule path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the backing checkpoint store
    /// cannot be queried.
    fn nearest_cached_ancestor(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError>;

    /// Returns the baked genesis snapshot for `world` and `def`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when no baked genesis snapshot exists
    /// or when the backing checkpoint store cannot be queried.
    fn baked_genesis(
        &mut self,
        world: &World,
        def: &ScenarioDef,
    ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError>;
}

/// Loadvm admission policy used by QEMU realization.
pub trait QemuVmLoadvmAdmissionPolicy {
    /// Authorizes loading the trusted baked-genesis ready-point snapshot.
    ///
    /// This does not admit arbitrary exact fat checkpoints; it only supplies
    /// the low-level QMP token needed by the baked-genesis branch.
    fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization;

    /// Authorizes the low-level runtime `loadvm` command.
    fn authorize_loadvm_runtime(self) -> QemuLoadvmCommandAuthorization;

    /// Admits a replay-oracle-validated runtime restored through `loadvm`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSavevmPolicyError`] when replay-oracle evidence is missing
    /// or mismatched.
    fn accept_loadvm_realized_runtime(
        self,
        validation: QemuReplayOracleValidation,
    ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError>;
}

impl QemuVmLoadvmAdmissionPolicy for QemuSavevmCompletenessPolicy {
    fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization {
        self.authorize_baked_genesis_runtime()
    }

    fn authorize_loadvm_runtime(self) -> QemuLoadvmCommandAuthorization {
        self.authorize_loadvm_runtime()
    }

    fn accept_loadvm_realized_runtime(
        self,
        validation: QemuReplayOracleValidation,
    ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
        self.accept_loadvm_realized_runtime(validation)
    }
}

/// QEMU runtime operations used by the realization coordinator.
pub trait QemuVmRealizationExecutor {
    /// Loads an exact snapshot after policy admission authorizes runtime `loadvm`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when launching QEMU, handshaking,
    /// restoring the VM snapshot, or restoring host-owned state fails.
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError>;

    /// Loads an exact snapshot for a replay-oracle probe.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when launching QEMU, handshaking,
    /// restoring the VM snapshot, or restoring host-owned state fails.
    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError>;

    /// Loads a validated baked genesis snapshot without cold-booting.
    ///
    /// The admission object carries both the baked snapshot and the
    /// baked-genesis-specific QMP authorization token.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when launching QEMU, handshaking, or
    /// loading the baked genesis snapshot fails.
    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError>;

    /// Replays one decision using the same quantum-step machinery as live execution.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the replay quantum fails.
    fn replay_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError>;
}

/// The single cold-boot path used only by `bake`.
pub trait QemuVmBakeExecutor {
    /// Cold-boots a world to its deterministic ready point and saves genesis VM state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when QEMU launch, setup, ready-point
    /// execution, or genesis snapshot creation fails.
    fn cold_boot_to_ready_and_savevm(
        &mut self,
        world: &World,
    ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError>;
}

/// Realizes the genesis configuration for `def`.
///
/// This is a convenience wrapper over [`instantiate_qemu_vm`]. It exists to make
/// the public lifecycle API explicit while sharing the single realization path.
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when realization fails.
pub fn start_qemu_vm(
    world: &World,
    def: &ScenarioDef,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    instantiate_qemu_vm_for_operation(
        QemuVmRealizationOperation::Start,
        world,
        Configuration::genesis(def.clone()),
        store,
        executor,
        policy,
    )
}

/// Realizes the current tip configuration.
///
/// This is a convenience wrapper over [`instantiate_qemu_vm`]. It exists to make
/// the public lifecycle API explicit while sharing the single realization path.
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when realization fails.
pub fn resume_qemu_vm(
    world: &World,
    config: &Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    instantiate_qemu_vm_for_operation(
        QemuVmRealizationOperation::Resume,
        world,
        config.clone(),
        store,
        executor,
        policy,
    )
}

/// Realizes a fork prefix of `config`.
///
/// This is a convenience wrapper over [`instantiate_qemu_vm`]. It exists to make
/// the public lifecycle API explicit while sharing the single realization path.
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when `prefix_len` is longer than the
/// source schedule or when realization fails.
pub fn fork_qemu_vm(
    world: &World,
    config: &Configuration,
    prefix_len: usize,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    if prefix_len > config.schedule.len() {
        return Err(QemuVmRealizationError::ForkPrefixOutOfRange {
            prefix_len,
            schedule_len: config.schedule.len(),
        });
    }

    let schedule = config
        .schedule
        .prefix(prefix_len)
        .map_err(QemuVmRealizationError::ForkPrefix)?;
    let fork_config = Configuration {
        def: config.def.clone(),
        schedule,
    };
    instantiate_qemu_vm_for_operation(
        QemuVmRealizationOperation::Fork { prefix_len },
        world,
        fork_config,
        store,
        executor,
        policy,
    )
}

/// Realizes `config` through the single QEMU instantiate path.
///
/// Branch priority is exact fat snapshot, nearest cached ancestor replay, then
/// baked-genesis load plus replay. Exact `loadvm` requires replay-oracle
/// admission through [`QemuSavevmCompletenessPolicy`].
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when branch selection, store access,
/// policy admission, or runtime execution fails.
pub fn instantiate_qemu_vm(
    world: &World,
    config: &Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    instantiate_qemu_vm_for_operation(
        QemuVmRealizationOperation::Instantiate,
        world,
        config.clone(),
        store,
        executor,
        policy,
    )
}

/// Bakes a world by cold-booting once to the deterministic ready point.
///
/// This is the only public QEMU realization function that exposes a cold-boot
/// operation. Hot-loop `start`, `resume`, `fork`, and [`instantiate_qemu_vm`]
/// load baked genesis instead of cold-booting.
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when world ready-point validation, cold
/// boot, setup, ready-point execution, or genesis snapshot creation fails.
pub fn bake_qemu_genesis_vm(
    world: &World,
    executor: &mut impl QemuVmBakeExecutor,
) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
    world
        .validate_ready_point_policies()
        .map_err(|source| QemuVmRealizationError::ReadyPointPolicy { source })?;
    executor.cold_boot_to_ready_and_savevm(world)
}

/// Checks `loadvm(snapshot(config))` against replay from an ancestor.
///
/// The exact snapshot is loaded with [`QemuSavevmCompletenessPolicy`]'s probe
/// authorization, not production runtime admission. The thin side uses the
/// ordinary instantiate/replay machinery and excludes the target exact snapshot
/// from branch selection.
///
/// # Errors
///
/// Returns [`QemuVmRealizationError`] when the exact snapshot is missing or
/// invalid, when either realization path fails, or when either runtime claims a
/// configuration other than `config`.
pub fn check_qemu_replay_oracle(
    world: &World,
    config: &Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: QemuSavevmCompletenessPolicy,
) -> Result<QemuReplayOracleValidation, QemuVmRealizationError> {
    let snapshot =
        store
            .exact_snapshot(config)?
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "replay oracle",
                message: String::from("exact snapshot required for replay-oracle check"),
            })?;
    validate_checkpoint_matches_config(&snapshot.checkpoint, config, "exact snapshot")?;
    if snapshot.checkpoint.kind != CheckpointKind::Fat {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "exact snapshot",
            message: String::from("replay oracle requires a fat exact snapshot"),
        });
    }
    validate_checkpoint_loadvm_state(&snapshot.checkpoint, "exact snapshot")?;

    let fat_runtime = executor.load_exact_snapshot_for_replay_oracle_probe(
        config,
        &snapshot,
        policy.authorize_loadvm_probe(),
    )?;
    validate_oracle_runtime_configuration("loadvm snapshot", &fat_runtime, config.id())?;
    let thin_runtime =
        realize_qemu_replay_oracle_thin_path(world, config.clone(), store, executor, policy)?;
    validate_oracle_runtime_configuration("thin replay", &thin_runtime, config.id())?;

    if fat_runtime.id == thin_runtime.id {
        Ok(QemuReplayOracleValidation::Match {
            runtime_hash: fat_runtime.id,
        })
    } else {
        Ok(QemuReplayOracleValidation::Mismatch {
            fat_hash: fat_runtime.id,
            thin_hash: thin_runtime.id,
        })
    }
}

fn instantiate_qemu_vm_for_operation(
    operation: QemuVmRealizationOperation,
    world: &World,
    config: Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    let realized = instantiate_qemu_vm_inner(world, config, store, executor, policy)?;
    Ok(QemuVmRealization {
        operation,
        ..realized
    })
}

fn instantiate_qemu_vm_inner(
    world: &World,
    config: Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: impl QemuVmLoadvmAdmissionPolicy + Copy,
) -> Result<QemuVmRealization, QemuVmRealizationError> {
    if let Some(snapshot) = store.exact_snapshot(&config)? {
        validate_checkpoint_matches_config(&snapshot.checkpoint, &config, "exact snapshot")?;
        if snapshot.checkpoint.kind == CheckpointKind::Fat {
            validate_checkpoint_loadvm_state(&snapshot.checkpoint, "exact snapshot")?;
            let authorization = policy.authorize_loadvm_runtime();
            let admission = policy
                .accept_loadvm_realized_runtime(snapshot.replay_oracle_validation)
                .map_err(|source| QemuVmRealizationError::SavevmPolicy { source })?;
            let runtime =
                executor.load_exact_snapshot(&config, &snapshot, authorization, admission)?;
            validate_runtime_matches_admission(&runtime, admission)?;
            return Ok(QemuVmRealization {
                operation: QemuVmRealizationOperation::Instantiate,
                configuration: config,
                runtime,
                branch: QemuVmRealizationKind::ExactSnapshotLoadvm {
                    checkpoint: snapshot.checkpoint,
                },
            });
        }
    }

    if let Some(ancestor) = store.nearest_cached_ancestor(&config)? {
        validate_checkpoint_matches_config(
            &ancestor.checkpoint,
            &ancestor.configuration,
            "cached ancestor",
        )?;
        let suffix = proper_ancestor_suffix(&ancestor.configuration, &config)?;
        let realized_ancestor = instantiate_qemu_vm_inner(
            world,
            ancestor.configuration.clone(),
            store,
            executor,
            policy,
        )?;
        let replayed_decisions = suffix.len();
        let runtime = replay_decisions(
            realized_ancestor.runtime,
            ancestor.configuration.clone(),
            config.clone(),
            suffix,
            executor,
        )?;
        return Ok(QemuVmRealization {
            operation: QemuVmRealizationOperation::Instantiate,
            configuration: config,
            runtime,
            branch: QemuVmRealizationKind::AncestorReplay {
                ancestor_configuration: ancestor.configuration.id(),
                replayed_decisions,
            },
        });
    }

    if config.is_genesis() {
        let snapshot = store.baked_genesis(world, &config.def)?;
        let admission = QemuBakedGenesisRestoreAdmission::new(
            &snapshot,
            world,
            policy.authorize_baked_genesis_runtime(),
        )?;
        let runtime = executor.load_baked_genesis(&config, admission)?;
        return Ok(QemuVmRealization {
            operation: QemuVmRealizationOperation::Instantiate,
            configuration: config,
            runtime,
            branch: QemuVmRealizationKind::BakedGenesisLoad {
                checkpoint: snapshot.checkpoint,
            },
        });
    }

    let genesis = Configuration::genesis(config.def.clone());
    let suffix = schedule_suffix(&genesis, &config)?;
    let realized_genesis =
        instantiate_qemu_vm_inner(world, genesis.clone(), store, executor, policy)?;
    let replayed_decisions = suffix.len();
    let runtime = replay_decisions(
        realized_genesis.runtime,
        genesis.clone(),
        config.clone(),
        suffix,
        executor,
    )?;
    Ok(QemuVmRealization {
        operation: QemuVmRealizationOperation::Instantiate,
        configuration: config,
        runtime,
        branch: QemuVmRealizationKind::AncestorReplay {
            ancestor_configuration: genesis.id(),
            replayed_decisions,
        },
    })
}

fn replay_decisions(
    mut runtime: RuntimeState,
    from: Configuration,
    to: Configuration,
    suffix: Vec<Decision>,
    executor: &mut impl QemuVmRealizationExecutor,
) -> Result<RuntimeState, QemuVmRealizationError> {
    let mut current = from;
    for decision in suffix {
        let next = crucible::step(&current, decision.clone());
        runtime = executor.replay_one_quantum(
            runtime,
            QemuVmReplayRequest {
                from: current,
                to: next.clone(),
                decision,
            },
        )?;
        current = next;
    }

    if current == to {
        Ok(runtime)
    } else {
        Err(QemuVmRealizationError::InvalidAncestor {
            message: String::from("replay suffix did not reach target configuration"),
        })
    }
}

fn realize_qemu_replay_oracle_thin_path(
    world: &World,
    config: Configuration,
    store: &mut impl QemuVmRealizationStore,
    executor: &mut impl QemuVmRealizationExecutor,
    policy: QemuSavevmCompletenessPolicy,
) -> Result<RuntimeState, QemuVmRealizationError> {
    if let Some(ancestor) = store.nearest_cached_ancestor(&config)? {
        validate_checkpoint_matches_config(
            &ancestor.checkpoint,
            &ancestor.configuration,
            "cached ancestor",
        )?;
        let suffix = proper_ancestor_suffix(&ancestor.configuration, &config)?;
        let realized_ancestor = instantiate_qemu_vm_inner(
            world,
            ancestor.configuration.clone(),
            store,
            executor,
            policy,
        )?;
        return replay_decisions(
            realized_ancestor.runtime,
            ancestor.configuration,
            config,
            suffix,
            executor,
        );
    }

    if config.is_genesis() {
        let snapshot = store.baked_genesis(world, &config.def)?;
        let admission = QemuBakedGenesisRestoreAdmission::new(
            &snapshot,
            world,
            policy.authorize_baked_genesis_runtime(),
        )?;
        return executor.load_baked_genesis(&config, admission);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let suffix = schedule_suffix(&genesis, &config)?;
    let realized_genesis =
        instantiate_qemu_vm_inner(world, genesis.clone(), store, executor, policy)?;
    replay_decisions(realized_genesis.runtime, genesis, config, suffix, executor)
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
    validate_checkpoint_loadvm_state(&snapshot.checkpoint, "baked genesis")?;
    validate_baked_genesis_node_blobs(snapshot, world)?;
    Ok(())
}

fn validate_checkpoint_loadvm_state(
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

fn validate_runtime_matches_admission(
    runtime: &RuntimeState,
    admission: QemuLoadvmRealizationAdmission,
) -> Result<(), QemuVmRealizationError> {
    let admitted_runtime_hash = admission.runtime_hash();
    if runtime.id == admitted_runtime_hash {
        Ok(())
    } else {
        Err(QemuVmRealizationError::RuntimeContentMismatch {
            expected: admitted_runtime_hash,
            actual: runtime.id,
        })
    }
}

fn validate_baked_genesis_authorization(
    authorization: QemuLoadvmCommandAuthorization,
) -> Result<(), QemuVmRealizationError> {
    let purpose = authorization.purpose();
    if purpose == QemuLoadvmCommandPurpose::BakedGenesisRealization {
        Ok(())
    } else {
        Err(QemuVmRealizationError::InvalidLoadvmAuthorization {
            operation: "restore baked genesis",
            purpose,
        })
    }
}

fn proper_ancestor_suffix(
    ancestor: &Configuration,
    target: &Configuration,
) -> Result<Vec<Decision>, QemuVmRealizationError> {
    if ancestor.schedule.len() >= target.schedule.len() {
        return Err(QemuVmRealizationError::InvalidAncestor {
            message: format!(
                "ancestor schedule length {} is not shorter than target length {}",
                ancestor.schedule.len(),
                target.schedule.len()
            ),
        });
    }

    schedule_suffix(ancestor, target)
}

fn schedule_suffix(
    ancestor: &Configuration,
    target: &Configuration,
) -> Result<Vec<Decision>, QemuVmRealizationError> {
    if ancestor.def != target.def {
        return Err(QemuVmRealizationError::InvalidAncestor {
            message: String::from("ancestor scenario does not match target scenario"),
        });
    }

    let ancestor_len = ancestor.schedule.len();
    let prefix = target
        .schedule
        .prefix(ancestor_len)
        .map_err(QemuVmRealizationError::AncestorPrefix)?;
    if prefix != ancestor.schedule {
        return Err(QemuVmRealizationError::InvalidAncestor {
            message: String::from("ancestor schedule is not a target prefix"),
        });
    }

    Ok(target.schedule.decisions()[ancestor_len..].to_vec())
}

/// Errors returned by QEMU VM realization coordination.
#[derive(Debug, Error)]
pub enum QemuVmRealizationError {
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
    /// A fork prefix was longer than the source configuration schedule.
    #[error("invalid fork prefix: {0}")]
    ForkPrefix(ScheduleError),
    /// A fork prefix was longer than the source configuration schedule.
    #[error("fork prefix length {prefix_len} exceeds schedule length {schedule_len}")]
    ForkPrefixOutOfRange {
        /// Requested fork prefix length.
        prefix_len: usize,
        /// Source configuration schedule length.
        schedule_len: usize,
    },
    /// An ancestor prefix computation failed.
    #[error("invalid ancestor prefix: {0}")]
    AncestorPrefix(ScheduleError),
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
    /// A restored `loadvm` runtime did not match replay-oracle admission.
    #[error("loadvm runtime content mismatch: expected {expected:?}, actual {actual:?}")]
    RuntimeContentMismatch {
        /// Replay-oracle-admitted runtime hash.
        expected: ContentHash,
        /// Runtime hash returned by the executor.
        actual: ContentHash,
    },
    /// The savevm/loadvm policy rejected the realization branch.
    #[error("savevm/loadvm policy rejected runtime realization: {source}")]
    SavevmPolicy {
        /// Underlying policy error.
        source: QemuSavevmPolicyError,
    },
    /// A low-level `loadvm` token had the wrong purpose for the selected branch.
    #[error("invalid QEMU loadvm authorization for {operation}: got {purpose:?}")]
    InvalidLoadvmAuthorization {
        /// Runtime operation being attempted.
        operation: &'static str,
        /// Purpose attached to the rejected authorization token.
        purpose: QemuLoadvmCommandPurpose,
    },
    /// A world has invalid ready-point policy configuration.
    #[error("invalid world ready-point configuration: {source}")]
    ReadyPointPolicy {
        /// Underlying model validation error.
        source: EngineError,
    },
}

impl PartialEq for QemuVmRealizationError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for QemuVmRealizationError {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crucible::{
        NodeBlobRef, NodeId, NodeTemplate, ReadyPoint, RngDecision, RngStreamId, Schedule,
        WhiteBoxPolicy, WorldNode,
    };

    use super::*;
    use crate::QemuLoadvmCommandPurpose;

    type SharedLog = Rc<RefCell<Vec<RealizationCall>>>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RealizationCall {
        ExactSnapshot(ContentHash),
        NearestAncestor(ContentHash),
        BakedGenesis(ContentHash),
        LoadExact {
            config: ContentHash,
            authorization: QemuLoadvmCommandPurpose,
        },
        LoadBaked {
            config: ContentHash,
            authorization: QemuLoadvmCommandPurpose,
        },
        Replay {
            from_len: usize,
            to_len: usize,
            value: u64,
        },
        ColdBootBake(ContentHash),
    }

    struct ScriptedStore {
        log: SharedLog,
        exact_snapshots: Vec<(ContentHash, QemuVmSnapshot)>,
        ancestors: Vec<(ContentHash, QemuCachedAncestor)>,
        baked: QemuBakedGenesisSnapshot,
    }

    struct ScriptedExecutor {
        log: SharedLog,
        exact_runtime_override: Option<ContentHash>,
    }

    #[derive(Clone, Copy)]
    struct ScriptedLoadvmPolicy;

    impl QemuVmRealizationStore for ScriptedStore {
        fn exact_snapshot(
            &mut self,
            config: &Configuration,
        ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::ExactSnapshot(config.id()));
            Ok(self
                .exact_snapshots
                .iter()
                .find(|(id, _)| *id == config.id())
                .map(|(_, snapshot)| snapshot.clone()))
        }

        fn nearest_cached_ancestor(
            &mut self,
            config: &Configuration,
        ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::NearestAncestor(config.id()));
            Ok(self
                .ancestors
                .iter()
                .find(|(id, _)| *id == config.id())
                .map(|(_, ancestor)| ancestor.clone()))
        }

        fn baked_genesis(
            &mut self,
            world: &World,
            _def: &ScenarioDef,
        ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::BakedGenesis(world.id));
            Ok(self.baked.clone())
        }
    }

    impl QemuVmLoadvmAdmissionPolicy for ScriptedLoadvmPolicy {
        fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization {
            QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test()
        }

        fn authorize_loadvm_runtime(self) -> QemuLoadvmCommandAuthorization {
            QemuLoadvmCommandAuthorization::runtime_realization_for_test()
        }

        fn accept_loadvm_realized_runtime(
            self,
            validation: QemuReplayOracleValidation,
        ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
            crate::savevm_policy::validate_loadvm_realized_runtime(validation)
        }
    }

    impl QemuVmRealizationExecutor for ScriptedExecutor {
        fn load_exact_snapshot(
            &mut self,
            config: &Configuration,
            snapshot: &QemuVmSnapshot,
            authorization: QemuLoadvmCommandAuthorization,
            admission: QemuLoadvmRealizationAdmission,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            self.log.borrow_mut().push(RealizationCall::LoadExact {
                config: config.id(),
                authorization: authorization.purpose(),
            });
            Ok(RuntimeState {
                id: match self.exact_runtime_override {
                    Some(hash) => hash,
                    None => admission.runtime_hash(),
                },
                configuration: config.id(),
                node_blobs: snapshot.checkpoint.node_blobs.clone(),
                node_icounts: snapshot.checkpoint.node_icounts.clone(),
                scheduler: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.scheduler.clone())
                    .unwrap_or_else(crucible::SchedulerState::empty),
                event_log: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.event_log)
                    .unwrap_or_default(),
            })
        }

        fn load_exact_snapshot_for_replay_oracle_probe(
            &mut self,
            config: &Configuration,
            snapshot: &QemuVmSnapshot,
            authorization: QemuLoadvmCommandAuthorization,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            self.log.borrow_mut().push(RealizationCall::LoadExact {
                config: config.id(),
                authorization: authorization.purpose(),
            });
            Ok(RuntimeState {
                id: match self.exact_runtime_override {
                    Some(hash) => hash,
                    None => config.id(),
                },
                configuration: config.id(),
                node_blobs: snapshot.checkpoint.node_blobs.clone(),
                node_icounts: snapshot.checkpoint.node_icounts.clone(),
                scheduler: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.scheduler.clone())
                    .unwrap_or_else(crucible::SchedulerState::empty),
                event_log: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.event_log)
                    .unwrap_or_default(),
            })
        }

        fn load_baked_genesis(
            &mut self,
            config: &Configuration,
            admission: QemuBakedGenesisRestoreAdmission<'_>,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            let snapshot = admission.snapshot();
            self.log.borrow_mut().push(RealizationCall::LoadBaked {
                config: config.id(),
                authorization: admission.authorization().purpose(),
            });
            Ok(RuntimeState {
                id: snapshot.checkpoint.id,
                configuration: config.id(),
                node_blobs: snapshot.checkpoint.node_blobs.clone(),
                node_icounts: snapshot.checkpoint.node_icounts.clone(),
                scheduler: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.scheduler.clone())
                    .unwrap_or_else(crucible::SchedulerState::empty),
                event_log: snapshot
                    .checkpoint
                    .state
                    .as_ref()
                    .map(|state| state.event_log)
                    .unwrap_or_default(),
            })
        }

        fn replay_one_quantum(
            &mut self,
            runtime: RuntimeState,
            request: QemuVmReplayRequest,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            self.log.borrow_mut().push(RealizationCall::Replay {
                from_len: request.from.schedule.len(),
                to_len: request.to.schedule.len(),
                value: decision_value(&request.decision),
            });
            let mut scheduler = runtime.scheduler;
            scheduler.apply_decision(&request.decision);
            Ok(RuntimeState {
                id: request.to.id(),
                configuration: request.to.id(),
                node_blobs: runtime.node_blobs,
                node_icounts: runtime.node_icounts,
                scheduler,
                event_log: runtime.event_log,
            })
        }
    }

    impl QemuVmBakeExecutor for ScriptedExecutor {
        fn cold_boot_to_ready_and_savevm(
            &mut self,
            world: &World,
        ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::ColdBootBake(world.id));
            Ok(QemuBakedGenesisSnapshot {
                world_id: world.id,
                checkpoint: Checkpoint::with_node_blobs(
                    hash("checkpoint", "baked-genesis"),
                    hash("configuration", "baked-by-executor"),
                    CheckpointKind::Fat,
                    qemu_baked_node_blobs(world),
                ),
            })
        }
    }

    #[test]
    fn qemu_start_resume_and_fork_share_instantiate_path() -> Result<(), QemuVmRealizationError> {
        let world = world("shared-instantiate");
        let def = scenario("shared-instantiate");
        let tip = config_with_decisions(def.clone(), 2);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        let mut executor = scripted_executor(Rc::clone(&log));

        let start = start_qemu_vm(
            &world,
            &def,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;
        let resume = resume_qemu_vm(
            &world,
            &tip,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;
        let fork = fork_qemu_vm(
            &world,
            &tip,
            1,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(start.operation, QemuVmRealizationOperation::Start);
        assert_eq!(resume.operation, QemuVmRealizationOperation::Resume);
        assert_eq!(
            fork.operation,
            QemuVmRealizationOperation::Fork { prefix_len: 1 }
        );
        assert_eq!(start.configuration, Configuration::genesis(def.clone()));
        assert_eq!(resume.configuration, tip);
        assert_eq!(fork.configuration, config_with_decisions(def, 1));
        assert_eq!(
            logged(&log)
                .iter()
                .filter(|call| matches!(call, RealizationCall::ColdBootBake(_)))
                .count(),
            0
        );

        Ok(())
    }

    #[test]
    fn qemu_lifecycle_wrappers_match_direct_instantiate() -> Result<(), QemuVmRealizationError> {
        let world = world("direct-lifecycle");
        let def = scenario("direct-lifecycle");
        let tip = config_with_decisions(def.clone(), 3);
        let fork_prefix = Configuration {
            def: def.clone(),
            schedule: tip
                .schedule
                .prefix(1)
                .map_err(QemuVmRealizationError::ForkPrefix)?,
        };
        let mut start_store = scripted_store(shared_log(), &world, &def);
        let mut start_executor = scripted_executor(shared_log());
        let mut resume_store = scripted_store(shared_log(), &world, &def);
        let mut resume_executor = scripted_executor(shared_log());
        let mut fork_store = scripted_store(shared_log(), &world, &def);
        let mut fork_executor = scripted_executor(shared_log());

        let start = start_qemu_vm(
            &world,
            &def,
            &mut start_store,
            &mut start_executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;
        let direct_start =
            direct_instantiate_for_test(&world, &def, &Configuration::genesis(def.clone()))?;
        let resume = resume_qemu_vm(
            &world,
            &tip,
            &mut resume_store,
            &mut resume_executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;
        let direct_resume = direct_instantiate_for_test(&world, &def, &tip)?;
        let fork = fork_qemu_vm(
            &world,
            &tip,
            1,
            &mut fork_store,
            &mut fork_executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;
        let direct_fork = direct_instantiate_for_test(&world, &def, &fork_prefix)?;

        assert_same_realization(&start, &direct_start);
        assert_same_realization(&resume, &direct_resume);
        assert_same_realization(&fork, &direct_fork);
        assert_eq!(start.operation, QemuVmRealizationOperation::Start);
        assert_eq!(resume.operation, QemuVmRealizationOperation::Resume);
        assert_eq!(
            fork.operation,
            QemuVmRealizationOperation::Fork { prefix_len: 1 }
        );

        Ok(())
    }

    #[test]
    fn qemu_instantiate_replays_from_nearest_cached_ancestor() -> Result<(), QemuVmRealizationError>
    {
        let world = world("ancestor-replay");
        let def = scenario("ancestor-replay");
        let ancestor = config_with_decisions(def.clone(), 2);
        let target = config_with_decisions(def.clone(), 4);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.ancestors.push((
            target.id(),
            QemuCachedAncestor {
                configuration: ancestor.clone(),
                checkpoint: checkpoint_for_config("ancestor", &ancestor, CheckpointKind::Thin),
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let realized = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(
            realized.branch,
            QemuVmRealizationKind::AncestorReplay {
                ancestor_configuration: ancestor.id(),
                replayed_decisions: 2,
            }
        );
        assert_eq!(
            logged(&log)
                .iter()
                .filter(|call| matches!(
                    call,
                    RealizationCall::Replay {
                        from_len: 2,
                        to_len: 3,
                        value: 2
                    } | RealizationCall::Replay {
                        from_len: 3,
                        to_len: 4,
                        value: 3
                    }
                ))
                .count(),
            2
        );

        Ok(())
    }

    #[test]
    fn qemu_instantiate_loads_baked_genesis_for_genesis_without_cold_boot()
    -> Result<(), QemuVmRealizationError> {
        let world = world("genesis-base");
        let def = scenario("genesis-base");
        let genesis = Configuration::genesis(def.clone());
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        let mut executor = scripted_executor(Rc::clone(&log));

        let realized = instantiate_qemu_vm(
            &world,
            &genesis,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(
            realized.branch,
            QemuVmRealizationKind::BakedGenesisLoad {
                checkpoint: store.baked.checkpoint.clone(),
            }
        );
        assert!(logged(&log).contains(&RealizationCall::BakedGenesis(world.id)));
        assert!(logged(&log).contains(&RealizationCall::LoadBaked {
            config: genesis.id(),
            authorization: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }));
        assert!(
            !logged(&log)
                .iter()
                .any(|call| matches!(call, RealizationCall::ColdBootBake(_)))
        );

        Ok(())
    }

    #[test]
    fn qemu_baked_genesis_rejects_runtime_loadvm_authorization() {
        let world = world("baked-auth-rejects-runtime");
        let def = scenario("baked-auth-rejects-runtime");
        let log = shared_log();
        let store = scripted_store(Rc::clone(&log), &world, &def);

        let error = match QemuBakedGenesisRestoreAdmission::new(
            &store.baked,
            &world,
            QemuLoadvmCommandAuthorization::runtime_realization_for_test(),
        ) {
            Ok(_) => panic!("runtime loadvm token should not admit baked genesis restore"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            QemuVmRealizationError::InvalidLoadvmAuthorization {
                operation: "restore baked genesis",
                purpose: QemuLoadvmCommandPurpose::RuntimeRealization
            }
        ));
    }

    #[test]
    fn qemu_exact_snapshot_loadvm_is_the_default_complete_realization_path()
    -> Result<(), QemuVmRealizationError> {
        let world = world("loadvm-complete");
        let def = scenario("loadvm-complete");
        let target = config_with_decisions(def.clone(), 1);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::Match {
                    runtime_hash: hash("runtime", "exact-fat"),
                },
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let realized = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert!(matches!(
            realized.branch,
            QemuVmRealizationKind::ExactSnapshotLoadvm { .. }
        ));
        assert!(logged(&log).iter().any(|call| matches!(
            call,
            RealizationCall::LoadExact {
                authorization: QemuLoadvmCommandPurpose::RuntimeRealization,
                ..
            }
        )));

        Ok(())
    }

    #[test]
    fn qemu_exact_snapshot_loadvm_requires_replay_oracle_admission()
    -> Result<(), QemuVmRealizationError> {
        let world = world("loadvm-admitted");
        let def = scenario("loadvm-admitted");
        let target = config_with_decisions(def.clone(), 1);
        let runtime_hash = hash("runtime", "admitted");
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        let checkpoint = checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint.clone(),
                replay_oracle_validation: QemuReplayOracleValidation::Match { runtime_hash },
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let realized = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        )?;

        assert_eq!(
            realized.branch,
            QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint }
        );
        assert_eq!(realized.runtime.id, runtime_hash);
        assert!(logged(&log).contains(&RealizationCall::LoadExact {
            config: target.id(),
            authorization: QemuLoadvmCommandPurpose::RuntimeRealization,
        }));
        assert!(
            !logged(&log)
                .iter()
                .any(|call| matches!(call, RealizationCall::Replay { .. }))
        );

        Ok(())
    }

    #[test]
    fn qemu_replay_oracle_matches_loadvm_snapshot_to_replay_from_ancestor()
    -> Result<(), QemuVmRealizationError> {
        let world = world("oracle-match");
        let def = scenario("oracle-match");
        let target = config_with_decisions(def.clone(), 1);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("oracle-exact", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::NotRun,
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let validation = check_qemu_replay_oracle(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(
            validation,
            QemuReplayOracleValidation::Match {
                runtime_hash: target.id(),
            }
        );
        assert!(logged(&log).contains(&RealizationCall::LoadExact {
            config: target.id(),
            authorization: QemuLoadvmCommandPurpose::SnapshotCompletenessProbe,
        }));
        assert!(logged(&log).contains(&RealizationCall::BakedGenesis(world.id)));
        assert!(logged(&log).contains(&RealizationCall::LoadBaked {
            config: Configuration::genesis(def).id(),
            authorization: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }));
        assert!(logged(&log).contains(&RealizationCall::Replay {
            from_len: 0,
            to_len: 1,
            value: 0,
        }));

        Ok(())
    }

    #[test]
    fn qemu_replay_oracle_rejects_incomplete_materialized_state_probe() {
        let world = world("oracle-incomplete-state");
        let def = scenario("oracle-incomplete-state");
        let target = config_with_decisions(def.clone(), 1);
        let log = shared_log();
        let mut checkpoint = checkpoint_for_config("oracle-exact", &target, CheckpointKind::Fat);
        checkpoint.state = None;
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint,
                replay_oracle_validation: QemuReplayOracleValidation::NotRun,
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let result = check_qemu_replay_oracle(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "exact snapshot",
                ..
            })
        ));
        assert_eq!(
            logged(&log),
            vec![RealizationCall::ExactSnapshot(target.id())]
        );
    }

    #[test]
    fn qemu_replay_oracle_reports_loadvm_replay_mismatch() -> Result<(), QemuVmRealizationError> {
        let world = world("oracle-mismatch");
        let def = scenario("oracle-mismatch");
        let target = config_with_decisions(def.clone(), 1);
        let fat_hash = hash("runtime", "oracle-mismatch");
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("oracle-exact", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::NotRun,
            },
        ));
        let mut executor = ScriptedExecutor {
            log,
            exact_runtime_override: Some(fat_hash),
        };

        let validation = check_qemu_replay_oracle(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(
            validation,
            QemuReplayOracleValidation::Mismatch {
                fat_hash,
                thin_hash: target.id(),
            }
        );

        Ok(())
    }

    #[test]
    fn qemu_exact_snapshot_rejects_unvalidated_loadvm_runtime() {
        let world = world("loadvm-not-run");
        let def = scenario("loadvm-not-run");
        let target = config_with_decisions(def.clone(), 1);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::NotRun,
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::SavevmPolicy {
                source: QemuSavevmPolicyError::ReplayOracleValidationRequired
            })
        ));
        assert_eq!(
            logged(&log),
            vec![RealizationCall::ExactSnapshot(target.id())]
        );
    }

    #[test]
    fn qemu_exact_snapshot_rejects_incomplete_materialized_state() {
        let world = world("loadvm-incomplete-state");
        let def = scenario("loadvm-incomplete-state");
        let target = config_with_decisions(def.clone(), 1);
        let log = shared_log();
        let mut checkpoint = checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat);
        checkpoint.state = None;
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint,
                replay_oracle_validation: QemuReplayOracleValidation::Match {
                    runtime_hash: target.id(),
                },
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "exact snapshot",
                ..
            })
        ));
        assert_eq!(
            logged(&log),
            vec![RealizationCall::ExactSnapshot(target.id())]
        );
    }

    #[test]
    fn qemu_exact_snapshot_rejects_mismatched_replay_oracle() {
        let world = world("loadvm-mismatch");
        let def = scenario("loadvm-mismatch");
        let target = config_with_decisions(def.clone(), 1);
        let fat_hash = hash("runtime", "fat");
        let thin_hash = hash("runtime", "thin");
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::Mismatch {
                    fat_hash,
                    thin_hash,
                },
            },
        ));
        let mut executor = scripted_executor(Rc::clone(&log));

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::SavevmPolicy {
                source: QemuSavevmPolicyError::ReplayOracleMismatch {
                    fat_hash: actual_fat,
                    thin_hash: actual_thin,
                }
            }) if actual_fat == fat_hash && actual_thin == thin_hash
        ));
        assert_eq!(
            logged(&log),
            vec![RealizationCall::ExactSnapshot(target.id())]
        );
    }

    #[test]
    fn qemu_exact_snapshot_rejects_wrong_configuration_checkpoint() {
        let world = world("wrong-exact");
        let def = scenario("wrong-exact");
        let target = config_with_decisions(def.clone(), 1);
        let wrong = config_with_decisions(def.clone(), 2);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("wrong-exact", &wrong, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::Match {
                    runtime_hash: hash("runtime", "wrong-exact"),
                },
            },
        ));
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "exact snapshot",
                ..
            })
        ));
    }

    #[test]
    fn qemu_loadvm_runtime_must_match_replay_oracle_admission() {
        let world = world("runtime-mismatch");
        let def = scenario("runtime-mismatch");
        let target = config_with_decisions(def.clone(), 1);
        let admitted = hash("runtime", "admitted");
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.exact_snapshots.push((
            target.id(),
            QemuVmSnapshot {
                checkpoint: checkpoint_for_config("exact-fat", &target, CheckpointKind::Fat),
                replay_oracle_validation: QemuReplayOracleValidation::Match {
                    runtime_hash: admitted,
                },
            },
        ));
        let mut executor = ScriptedExecutor {
            log,
            exact_runtime_override: Some(hash("runtime", "actual")),
        };

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            ScriptedLoadvmPolicy,
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::RuntimeContentMismatch { expected, .. })
                if expected == admitted
        ));
    }

    #[test]
    fn qemu_bake_is_the_only_cold_boot_entry_point() -> Result<(), QemuVmRealizationError> {
        let world = world("cold-boot");
        let log = shared_log();
        let mut executor = scripted_executor(Rc::clone(&log));

        let baked = bake_qemu_genesis_vm(&world, &mut executor)?;

        assert_eq!(baked.world_id, world.id);
        assert_eq!(logged(&log), vec![RealizationCall::ColdBootBake(world.id)]);

        Ok(())
    }

    #[test]
    fn qemu_bake_records_baked_node_blob_refs() -> Result<(), QemuVmRealizationError> {
        let node = NodeId {
            name: String::from("qemu"),
        };
        let world = match World::from_nodes(vec![WorldNode {
            id: node.clone(),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::ConsoleMarker {
                marker: String::from("ready"),
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]) {
            Ok(world) => world,
            Err(error) => panic!("test world should be valid: {error}"),
        };
        let log = shared_log();
        let mut executor = scripted_executor(Rc::clone(&log));

        let baked = bake_qemu_genesis_vm(&world, &mut executor)?;

        assert!(matches!(
            baked.checkpoint.node_blob(&node),
            Some(NodeBlobRef::Baked(_))
        ));
        assert_eq!(baked.checkpoint.node_blobs.len(), 1);
        assert_eq!(logged(&log), vec![RealizationCall::ColdBootBake(world.id)]);
        Ok(())
    }

    #[test]
    fn qemu_bake_rejects_agent_signal_without_white_box_opt_in() {
        let error = match World::from_recorded_parts(
            hash("world", "qemu-invalid-agent-ready"),
            vec![WorldNode {
                id: NodeId {
                    name: String::from("agent"),
                },
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::AgentSignal,
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            }],
            Vec::new(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("invalid agent-signal ready point should not build a world"),
        };

        assert!(matches!(
            error,
            EngineError::WhiteBoxReadyPointWithoutOptIn { .. }
        ));
    }

    #[test]
    fn qemu_instantiate_rejects_non_prefix_cached_ancestor() {
        let world = world("non-prefix");
        let def = scenario("non-prefix");
        let target = config_with_decision_values(def.clone(), &[0, 1]);
        let invalid = config_with_decision_values(def.clone(), &[9]);
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.ancestors.push((
            target.id(),
            QemuCachedAncestor {
                configuration: invalid.clone(),
                checkpoint: checkpoint_for_config("invalid", &invalid, CheckpointKind::Thin),
            },
        ));
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidAncestor { .. })
        ));
    }

    #[test]
    fn qemu_instantiate_rejects_cached_ancestor_checkpoint_mismatch() {
        let world = world("ancestor-checkpoint-mismatch");
        let def = scenario("ancestor-checkpoint-mismatch");
        let ancestor = config_with_decisions(def.clone(), 1);
        let target = config_with_decisions(def.clone(), 2);
        let wrong = Configuration::genesis(scenario("other"));
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.ancestors.push((
            target.id(),
            QemuCachedAncestor {
                configuration: ancestor,
                checkpoint: checkpoint_for_config("wrong", &wrong, CheckpointKind::Thin),
            },
        ));
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "cached ancestor",
                ..
            })
        ));
    }

    #[test]
    fn qemu_instantiate_rejects_stale_baked_genesis_world() {
        let world = world("requested-world");
        let def = scenario("requested-world");
        let genesis = Configuration::genesis(def.clone());
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.baked.world_id = hash("world", "stale-world");
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &genesis,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "baked genesis",
                ..
            })
        ));
    }

    #[test]
    fn qemu_instantiate_rejects_thin_baked_genesis_checkpoint() {
        let world = world("thin-baked-genesis");
        let def = scenario("thin-baked-genesis");
        let genesis = Configuration::genesis(def.clone());
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.baked.checkpoint =
            checkpoint_for_config("thin-baked-genesis", &genesis, CheckpointKind::Thin);
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &genesis,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "baked genesis",
                ..
            })
        ));
    }

    #[test]
    fn qemu_instantiate_rejects_baked_genesis_missing_node_blob() {
        let world = match World::from_nodes(vec![WorldNode {
            id: NodeId {
                name: String::from("qemu"),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: crucible::Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]) {
            Ok(world) => world,
            Err(error) => panic!("test world should be valid: {error}"),
        };
        let def = scenario("missing-baked-node-blob");
        let genesis = Configuration::genesis(def.clone());
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &def);
        store.baked.checkpoint = Checkpoint::new(
            hash("checkpoint", "empty-baked-genesis"),
            genesis.id(),
            CheckpointKind::Fat,
        );
        let mut executor = scripted_executor(log);

        let result = instantiate_qemu_vm(
            &world,
            &genesis,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        );

        assert!(matches!(
            result,
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "baked genesis",
                ..
            })
        ));
    }

    #[test]
    fn qemu_baked_genesis_snapshot_is_shared_across_same_world_scenarios()
    -> Result<(), QemuVmRealizationError> {
        let world = world("shared-baked-world");
        let baked_def = scenario("baked-scenario");
        let requested_def = scenario("requested-scenario");
        let requested_genesis = Configuration::genesis(requested_def.clone());
        let baked_genesis = Configuration::genesis(baked_def.clone());
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), &world, &baked_def);
        store.baked.checkpoint =
            checkpoint_for_config("shared-world-genesis", &baked_genesis, CheckpointKind::Fat);
        let mut executor = scripted_executor(Rc::clone(&log));

        let realized = instantiate_qemu_vm(
            &world,
            &requested_genesis,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )?;

        assert_eq!(
            realized.branch,
            QemuVmRealizationKind::BakedGenesisLoad {
                checkpoint: store.baked.checkpoint.clone(),
            }
        );
        assert!(logged(&log).contains(&RealizationCall::BakedGenesis(world.id)));
        assert!(logged(&log).contains(&RealizationCall::LoadBaked {
            config: requested_genesis.id(),
            authorization: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }));

        Ok(())
    }

    #[test]
    fn qemu_fork_accepts_tip_and_rejects_out_of_range_prefixes() {
        let world = world("fork-prefix-bounds");
        let def = scenario("fork-prefix-bounds");
        let tip = config_with_decisions(def.clone(), 2);
        let tip_log = shared_log();
        let mut tip_store = scripted_store(Rc::clone(&tip_log), &world, &def);
        let mut tip_executor = scripted_executor(tip_log);

        let tip_fork = fork_qemu_vm(
            &world,
            &tip,
            2,
            &mut tip_store,
            &mut tip_executor,
            QemuSavevmCompletenessPolicy::default(),
        );
        let out_of_range = fork_qemu_vm(
            &world,
            &tip,
            3,
            &mut scripted_store(shared_log(), &world, &def),
            &mut scripted_executor(shared_log()),
            QemuSavevmCompletenessPolicy::default(),
        );

        match tip_fork {
            Ok(realized) => {
                assert_eq!(realized.configuration, tip);
                assert_eq!(
                    realized.operation,
                    QemuVmRealizationOperation::Fork { prefix_len: 2 }
                );
            }
            Err(error) => panic!("tip fork should instantiate the tip configuration: {error}"),
        }
        assert!(matches!(
            out_of_range,
            Err(QemuVmRealizationError::ForkPrefixOutOfRange {
                prefix_len: 3,
                schedule_len: 2,
            })
        ));
    }

    fn scripted_store(log: SharedLog, world: &World, def: &ScenarioDef) -> ScriptedStore {
        let genesis = Configuration::genesis(def.clone());
        ScriptedStore {
            log,
            exact_snapshots: Vec::new(),
            ancestors: Vec::new(),
            baked: QemuBakedGenesisSnapshot {
                world_id: world.id,
                checkpoint: Checkpoint::with_node_blobs(
                    hash("checkpoint", "baked-genesis"),
                    genesis.id(),
                    CheckpointKind::Fat,
                    qemu_baked_node_blobs(world),
                ),
            },
        }
    }

    fn scripted_executor(log: SharedLog) -> ScriptedExecutor {
        ScriptedExecutor {
            log,
            exact_runtime_override: None,
        }
    }

    fn shared_log() -> SharedLog {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn logged(log: &SharedLog) -> Vec<RealizationCall> {
        log.borrow().clone()
    }

    fn direct_instantiate_for_test(
        world: &World,
        def: &ScenarioDef,
        config: &Configuration,
    ) -> Result<QemuVmRealization, QemuVmRealizationError> {
        let log = shared_log();
        let mut store = scripted_store(Rc::clone(&log), world, def);
        let mut executor = scripted_executor(log);
        instantiate_qemu_vm(
            world,
            config,
            &mut store,
            &mut executor,
            QemuSavevmCompletenessPolicy::default(),
        )
    }

    fn assert_same_realization(actual: &QemuVmRealization, expected: &QemuVmRealization) {
        assert_eq!(actual.configuration, expected.configuration);
        assert_eq!(actual.runtime, expected.runtime);
        assert_eq!(actual.branch, expected.branch);
    }

    fn world(name: &str) -> World {
        World::from_content_hash(hash("world", name))
    }

    fn qemu_baked_node_blobs(world: &World) -> std::collections::BTreeMap<NodeId, NodeBlobRef> {
        world
            .vm_nodes()
            .iter()
            .map(|node| {
                let blob = hash(
                    "qemu-test-baked-node-blob",
                    &format!("world={:?}\nnode={}", world.id.bytes, node.id.name),
                );
                (node.id.clone(), NodeBlobRef::baked(blob))
            })
            .collect()
    }

    fn scenario(name: &str) -> ScenarioDef {
        ScenarioDef::from_canonical_material("crucible.test.qemu.scenario", name)
    }

    fn config_with_decisions(def: ScenarioDef, count: usize) -> Configuration {
        let values = (0..count).map(|index| index as u64).collect::<Vec<_>>();
        config_with_decision_values(def, &values)
    }

    fn config_with_decision_values(def: ScenarioDef, values: &[u64]) -> Configuration {
        let mut schedule = Schedule::empty();
        for value in values {
            schedule = schedule.appended(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name(format!("stream-{value}")),
                value: *value,
            }));
        }
        Configuration { def, schedule }
    }

    fn checkpoint_for_config(
        name: &str,
        config: &Configuration,
        kind: CheckpointKind,
    ) -> Checkpoint {
        let id = hash("checkpoint", name);
        Checkpoint::with_node_blobs(id, config.id(), kind, qemu_materialized_node_blobs(config))
    }

    fn qemu_materialized_node_blobs(
        config: &Configuration,
    ) -> std::collections::BTreeMap<NodeId, NodeBlobRef> {
        let parent = hash(
            "qemu-test-node-blob-parent",
            &format!("scenario={:?}", config.def.id().bytes),
        );
        let delta = hash(
            "qemu-test-node-blob-delta",
            &format!("config={:?}", config.id().bytes),
        );
        let resolved = hash(
            "qemu-test-node-blob-resolved",
            &format!("config={:?}", config.id().bytes),
        );
        std::collections::BTreeMap::from([(
            NodeId {
                name: String::from("qemu"),
            },
            NodeBlobRef::cow_delta(parent, delta, resolved),
        )])
    }

    fn decision_value(decision: &Decision) -> u64 {
        match decision {
            Decision::RngDraw(draw) => draw.value,
            _ => 0,
        }
    }

    fn hash(domain: &str, material: &str) -> ContentHash {
        ContentHash::from_canonical_material(domain, material)
    }
}
