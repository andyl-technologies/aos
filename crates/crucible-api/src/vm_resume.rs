//! API-owned local VM resume realization bridge.
//!
//! The CLI can only reach engine behavior through the API or session boundary.
//! This module owns the process-local bridge that turns session savepoint
//! evidence into stable machine-readable resume proof fields while delegating
//! branch choice and replay execution to the VM realization coordinator.

use crucible::{
    Checkpoint, Configuration, ContentAddressedBlobRef, ContentHash, ScenarioDef, ScenarioDefForm,
};
use crucible_qemu::{
    QemuBackendRealizationExecutor, QemuBakedGenesisSnapshot, QemuCachedAncestor,
    QemuReplayOracleValidation, QemuSavevmCompletenessPolicy, QemuVmRealization,
    QemuVmRealizationError, QemuVmRealizationKind, QemuVmRealizationOperation,
    QemuVmRealizationStore, QemuVmSnapshot, resume_qemu_vm,
};
use crucible_session::validation::{ResumeRealizationError, realize_resume_from_savepoint};
use thiserror::Error;

/// Errors returned while deriving a process-local VM resume realization proof.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VmResumeRealizationError {
    /// The source savepoint is not on the target resume path.
    #[error(transparent)]
    Resume(#[from] ResumeRealizationError),
    /// The VM realization coordinator rejected the resume path.
    #[error("VM resume realization failed: {message}")]
    Realization {
        /// Deterministic failure detail.
        message: String,
    },
}

/// Stable proof fields emitted for model-checkpoint VM resume realization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCheckpointVmResumeRealizationProof {
    operation: &'static str,
    executor: &'static str,
    branch: &'static str,
    configuration: ContentHash,
    runtime_state: ContentHash,
    ancestor_configuration: Option<ContentHash>,
    checkpoint: Option<ContentHash>,
    replayed_decisions: usize,
}

impl ModelCheckpointVmResumeRealizationProof {
    /// Returns the machine-readable summary fields for stdout and canonical logs.
    #[must_use]
    pub fn field_summary(&self) -> String {
        format!(
            "materialization=qemu-vm-realization operation={} executor={} branch={} checkpoint={} ancestor_configuration={} replayed_decisions={} configuration={} runtime={}",
            self.operation,
            self.executor,
            self.branch,
            format_optional_content_hash_ref(self.checkpoint),
            format_optional_content_hash_ref(self.ancestor_configuration),
            self.replayed_decisions,
            format_content_hash_ref(self.configuration),
            format_content_hash_ref(self.runtime_state),
        )
    }

    fn from_realization(realization: &QemuVmRealization) -> Self {
        let operation = match realization.operation {
            QemuVmRealizationOperation::Resume => "resume",
            QemuVmRealizationOperation::Start => "start",
            QemuVmRealizationOperation::Fork { .. } => "fork",
            QemuVmRealizationOperation::Instantiate => "instantiate",
        };
        let (branch, checkpoint, ancestor_configuration, replayed_decisions) =
            match &realization.branch {
                QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint } => {
                    ("exact-snapshot-loadvm", Some(checkpoint.id), None, 0)
                }
                QemuVmRealizationKind::AncestorReplay {
                    ancestor_configuration,
                    replayed_decisions,
                } => (
                    "ancestor-replay",
                    None,
                    Some(*ancestor_configuration),
                    *replayed_decisions,
                ),
                QemuVmRealizationKind::BakedGenesisLoad { checkpoint } => {
                    ("baked-genesis-load", Some(checkpoint.id), None, 0)
                }
            };
        Self {
            operation,
            executor: "model-checkpoint",
            branch,
            configuration: realization.configuration.id(),
            runtime_state: realization.runtime.id,
            ancestor_configuration,
            checkpoint,
            replayed_decisions,
        }
    }
}

struct ApiVmResumeRealizationStore<'a> {
    source_configuration: &'a Configuration,
    source_checkpoint: &'a Checkpoint,
    baked_genesis: QemuBakedGenesisSnapshot,
}

impl<'a> ApiVmResumeRealizationStore<'a> {
    fn source_is_proper_ancestor_of(&self, config: &Configuration) -> bool {
        self.source_configuration.schedule.len() < config.schedule.len()
            && config
                .schedule
                .prefix(self.source_configuration.schedule.len())
                .is_ok_and(|prefix| prefix == self.source_configuration.schedule)
    }
}

impl<'a> QemuVmRealizationStore for ApiVmResumeRealizationStore<'a> {
    fn exact_snapshot(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
        if *config == *self.source_configuration {
            Ok(Some(QemuVmSnapshot {
                checkpoint: self.source_checkpoint.clone(),
                replay_oracle_validation: QemuReplayOracleValidation::NotRun,
            }))
        } else {
            Ok(None)
        }
    }

    fn nearest_cached_ancestor(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError> {
        if self.source_is_proper_ancestor_of(config) {
            Ok(Some(QemuCachedAncestor {
                configuration: self.source_configuration.clone(),
                checkpoint: self.source_checkpoint.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    fn baked_genesis(
        &mut self,
        world: &crucible::World,
        _def: &ScenarioDef,
    ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
        if world.id == self.baked_genesis.world_id {
            Ok(self.baked_genesis.clone())
        } else {
            Err(QemuVmRealizationError::Store {
                operation: "load API baked genesis",
                message: String::from("stored baked genesis belongs to a different world"),
            })
        }
    }
}

/// Realizes a process-local VM resume proof through the VM coordinator.
///
/// The current process-level CLI path uses an explicitly seeded
/// model-checkpoint executor for coordinator coverage. Exact runtime load
/// admission remains reserved for a concrete VM executor.
///
/// # Errors
///
/// Returns [`VmResumeRealizationError`] when the source checkpoint is not on
/// the target resume path or when coordinator branch selection or replay fails.
pub fn realize_model_checkpoint_vm_resume_from_savepoint(
    scenario: &ScenarioDefForm,
    source_configuration: &Configuration,
    source_checkpoint: &Checkpoint,
    target: &Configuration,
) -> Result<ModelCheckpointVmResumeRealizationProof, VmResumeRealizationError> {
    realize_resume_from_savepoint(source_configuration, source_checkpoint, target)?;
    let baked_genesis =
        QemuBakedGenesisSnapshot::from_model_world(scenario.world()).map_err(|error| {
            VmResumeRealizationError::Realization {
                message: error.to_string(),
            }
        })?;
    let restorable_checkpoints = [source_checkpoint.clone(), baked_genesis.checkpoint.clone()];
    let backend = crucible::SimBackend::from_restorable_checkpoints(&restorable_checkpoints);
    let mut store = ApiVmResumeRealizationStore {
        source_configuration,
        source_checkpoint,
        baked_genesis,
    };
    let mut executor = QemuBackendRealizationExecutor::new(backend);
    let realization = resume_qemu_vm(
        scenario.world(),
        target,
        &mut store,
        &mut executor,
        QemuSavevmCompletenessPolicy::default(),
    )
    .map_err(|error| VmResumeRealizationError::Realization {
        message: error.to_string(),
    })?;
    Ok(ModelCheckpointVmResumeRealizationProof::from_realization(
        &realization,
    ))
}

fn format_content_hash_ref(hash: ContentHash) -> String {
    ContentAddressedBlobRef::from_hash(hash).to_uri()
}

fn format_optional_content_hash_ref(hash: Option<ContentHash>) -> String {
    hash.map(format_content_hash_ref)
        .unwrap_or_else(|| String::from("none"))
}
