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
    QemuVmRealizationError, QemuVmRealizationExecutor, QemuVmRealizationKind,
    QemuVmRealizationOperation, QemuVmRealizationStore, QemuVmSnapshot, resume_qemu_vm,
};
use crucible_session::validation::{ResumeRealizationError, realize_resume_from_savepoint};
use thiserror::Error;

/// Guest architecture accepted by the production plugin-installation probe.
pub use crucible_qemu::LivePluginGuestArchitecture as ProductionGuestArchitecture;
/// Configuration for the production plugin-installation probe.
pub use crucible_qemu::LivePluginInstallGateConfig as ProductionPluginInstallConfig;
/// Failure returned by the production plugin-installation probe.
pub use crucible_qemu::LivePluginInstallGateError as ProductionPluginInstallError;
/// Observed evidence returned by the production plugin-installation probe.
pub use crucible_qemu::LivePluginInstallReport as ProductionPluginInstallReport;
/// Seeded live app-random launch configuration.
pub(crate) use crucible_qemu::QemuLaunchAppRandomConfig as ProductionAppRandomConfig;
/// Production plugin feature switch pinned into launch identity.
pub use crucible_qemu::QemuLaunchPluginSwitch as ProductionPluginSwitch;
/// Root-image format pinned into production launch identity.
pub use crucible_qemu::QemuRootImageFormat as ProductionRootImageFormat;
/// Runs the bounded production plugin-installation probe.
pub use crucible_qemu::run_live_plugin_install_gate as run_production_plugin_install_gate;
pub(crate) use crucible_qemu::{
    DEFAULT_ROOT_OVERLAY_FILE_NAME as PRODUCTION_ROOT_OVERLAY_FILE_NAME,
    QemuGdbstubChannelConfig as ProductionGdbstubChannelConfig,
    QemuLiveNodeStepGateConfig as ProductionLiveNodeStepGateConfig, QemuNode as ProductionLiveNode,
    QemuNodeSet as ProductionNodeSet, launch_qemu_live_node as launch_production_live_node,
};

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

/// Stable proof fields emitted for VM resume realization.
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

    fn from_realization(realization: &QemuVmRealization, executor: &'static str) -> Self {
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
            executor,
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
    let baked_genesis =
        QemuBakedGenesisSnapshot::from_model_world(scenario.world()).map_err(|error| {
            VmResumeRealizationError::Realization {
                message: error.to_string(),
            }
        })?;
    let restorable_checkpoints = [source_checkpoint.clone(), baked_genesis.checkpoint.clone()];
    let backend = crucible::SimBackend::from_restorable_checkpoints(&restorable_checkpoints);
    let mut executor = QemuBackendRealizationExecutor::new(backend);
    realize_qemu_vm_resume_from_savepoint_with_executor(
        scenario,
        source_configuration,
        source_checkpoint,
        target,
        baked_genesis,
        "model-checkpoint",
        &mut executor,
    )
}

/// Realizes a process-local VM resume proof through a caller-owned QEMU executor.
///
/// This crate-internal entry point lets the model-checkpoint resume path select
/// the concrete runtime executor while reusing the API-owned savepoint
/// validation and QEMU coordinator store shape. The `executor` argument may be a
/// test/model backend adapter or a concrete QEMU node executor; the emitted
/// proof records `executor_label` verbatim.
///
/// It is deliberately not part of the public `crucible-api` surface: the QEMU
/// executor seam stays behind the crate boundary so that the versioned API
/// re-exports only the backend-agnostic
/// [`realize_model_checkpoint_vm_resume_from_savepoint`] entry point.
///
/// # Errors
///
/// Returns [`VmResumeRealizationError`] when the source checkpoint is not on
/// the target resume path or when coordinator branch selection or replay fails.
pub(crate) fn realize_qemu_vm_resume_from_savepoint_with_executor(
    scenario: &ScenarioDefForm,
    source_configuration: &Configuration,
    source_checkpoint: &Checkpoint,
    target: &Configuration,
    baked_genesis: QemuBakedGenesisSnapshot,
    executor_label: &'static str,
    executor: &mut impl QemuVmRealizationExecutor,
) -> Result<ModelCheckpointVmResumeRealizationProof, VmResumeRealizationError> {
    realize_resume_from_savepoint(source_configuration, source_checkpoint, target)?;
    let mut store = ApiVmResumeRealizationStore {
        source_configuration,
        source_checkpoint,
        baked_genesis,
    };
    let realization = resume_qemu_vm(
        scenario.world(),
        target,
        &mut store,
        executor,
        QemuSavevmCompletenessPolicy::default(),
    )
    .map_err(|error| VmResumeRealizationError::Realization {
        message: error.to_string(),
    })?;
    Ok(ModelCheckpointVmResumeRealizationProof::from_realization(
        &realization,
        executor_label,
    ))
}

fn format_content_hash_ref(hash: ContentHash) -> String {
    ContentAddressedBlobRef::from_hash(hash).to_uri()
}

fn format_optional_content_hash_ref(hash: Option<ContentHash>) -> String {
    hash.map(format_content_hash_ref)
        .unwrap_or_else(|| String::from("none"))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use crucible::{
        CheckpointKind, Decision, EventLogOffset, Icount, MaterializedState, NodeBlobRef, NodeId,
        NodeTemplate, Plan, Properties, ReadyPoint, RngDecision, RngStreamId, RuntimeState,
        SchedulerState, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
    };
    use crucible_qemu::{
        QemuBakedGenesisRestoreAdmission, QemuLoadvmCommandAuthorization,
        QemuLoadvmRealizationAdmission, QemuVmReplayRequest, QemuVmSnapshot,
    };

    use super::*;

    #[derive(Default)]
    struct ScriptedExecutor {
        baked_loads: usize,
        replayed_decisions: usize,
    }

    impl QemuVmRealizationExecutor for ScriptedExecutor {
        fn load_exact_snapshot(
            &mut self,
            _config: &Configuration,
            _snapshot: &QemuVmSnapshot,
            _authorization: QemuLoadvmCommandAuthorization,
            _admission: QemuLoadvmRealizationAdmission,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            Err(QemuVmRealizationError::Executor {
                operation: "test exact snapshot",
                message: String::from("default policy should not load exact snapshots"),
            })
        }

        fn load_exact_snapshot_for_replay_oracle_probe(
            &mut self,
            _config: &Configuration,
            _snapshot: &QemuVmSnapshot,
            _authorization: QemuLoadvmCommandAuthorization,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            Err(QemuVmRealizationError::Executor {
                operation: "test exact snapshot probe",
                message: String::from("resume proof should not run replay-oracle probes"),
            })
        }

        fn load_baked_genesis(
            &mut self,
            config: &Configuration,
            admission: QemuBakedGenesisRestoreAdmission<'_>,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            self.baked_loads += 1;
            Ok(runtime_for_config(
                config,
                hash("runtime", "baked-genesis"),
                admission.checkpoint(),
            ))
        }

        fn replay_one_quantum(
            &mut self,
            _runtime: RuntimeState,
            request: QemuVmReplayRequest,
        ) -> Result<RuntimeState, QemuVmRealizationError> {
            self.replayed_decisions += 1;
            let checkpoint = runtime_checkpoint_for_config(
                "target",
                &request.to,
                Icount {
                    retired: self.replayed_decisions as u64,
                },
            );
            Ok(runtime_for_config(
                &request.to,
                hash("runtime", "replayed-target"),
                &checkpoint,
            ))
        }
    }

    #[test]
    fn qemu_resume_proof_uses_caller_supplied_executor() -> Result<(), VmResumeRealizationError> {
        let scenario = scenario_form();
        let source = Configuration::genesis(scenario.scenario_def());
        let target = Configuration {
            def: source.def.clone(),
            schedule: source.schedule.appended(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("api-vm-resume"),
                value: 7,
            })),
        };
        let source_checkpoint = checkpoint_for_config("source", &source, Icount { retired: 0 });
        let baked_genesis =
            QemuBakedGenesisSnapshot::from_model_world(scenario.world()).map_err(|error| {
                VmResumeRealizationError::Realization {
                    message: error.to_string(),
                }
            })?;
        let mut executor = ScriptedExecutor::default();

        let proof = realize_qemu_vm_resume_from_savepoint_with_executor(
            &scenario,
            &source,
            &source_checkpoint,
            &target,
            baked_genesis,
            "scripted-node",
            &mut executor,
        )?;

        assert_eq!(executor.baked_loads, 1);
        assert_eq!(executor.replayed_decisions, 1);
        let summary = proof.field_summary();
        assert!(summary.contains("executor=scripted-node"));
        assert!(summary.contains("branch=ancestor-replay"));
        assert!(summary.contains("replayed_decisions=1"));
        assert!(summary.contains(&format!(
            "configuration={}",
            format_content_hash_ref(target.id())
        )));
        Ok(())
    }

    fn scenario_form() -> ScenarioDefForm {
        let world = World::from_nodes(vec![WorldNode {
            id: node_id(),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])
        .expect("test world should be valid");
        ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(10),
        )
        .expect("test scenario form should be valid")
    }

    fn checkpoint_for_config(name: &str, config: &Configuration, icount: Icount) -> Checkpoint {
        let node_blobs = BTreeMap::from([(node_id(), NodeBlobRef::baked(hash("node-blob", name)))]);
        Checkpoint::from_recorded_configuration(
            config,
            None,
            Default::default(),
            BTreeMap::from([(node_id(), icount)]),
            CheckpointKind::Fat,
            node_blobs,
        )
        .map(|checkpoint| {
            let state = MaterializedState::from_checkpoint_parts(
                &checkpoint.node_icounts,
                &checkpoint.node_blobs,
            );
            checkpoint.with_materialized_state(Some(state))
        })
        .expect("test checkpoint should match its configuration")
    }

    fn runtime_checkpoint_for_config(
        name: &str,
        config: &Configuration,
        icount: Icount,
    ) -> Checkpoint {
        let mut checkpoint = Checkpoint::with_node_blobs(
            hash("runtime-checkpoint", name),
            config.id(),
            CheckpointKind::Fat,
            BTreeMap::from([(node_id(), NodeBlobRef::baked(hash("node-blob", name)))]),
        );
        checkpoint.node_icounts.insert(node_id(), icount);
        let state = MaterializedState::from_checkpoint_parts(
            &checkpoint.node_icounts,
            &checkpoint.node_blobs,
        );
        checkpoint.with_materialized_state(Some(state))
    }

    fn runtime_for_config(
        config: &Configuration,
        runtime_id: ContentHash,
        checkpoint: &Checkpoint,
    ) -> RuntimeState {
        RuntimeState {
            id: runtime_id,
            configuration: config.id(),
            node_blobs: checkpoint.node_blobs.clone(),
            node_icounts: checkpoint.node_icounts.clone(),
            scheduler: SchedulerState::from_schedule(&config.schedule),
            event_log: EventLogOffset::default(),
        }
    }

    fn node_id() -> NodeId {
        NodeId {
            name: String::from("api-vm"),
        }
    }

    fn hash(domain: &str, material: &str) -> ContentHash {
        ContentHash::from_canonical_material(domain, material)
    }
}
