//! Guarded exact and thin replay validation admissions.
//!
//! This module owns materialized-input validation and the one-shot launch
//! authority retained until a concrete replay-oracle comparison succeeds.

use super::*;

/// Prepares a fresh operational RAM registration immediately before a replay launch.
///
/// Both replay legs share this authority while the executor runs at most one
/// native node at a time. Implementations retain the original service cap and
/// refuse preparation until the preceding node has completed physical cleanup.
pub trait QemuReplayValidationRegistrationPreparation: Send + Sync {
    /// Returns the live service supervisor sharing the original outer cap.
    fn supervisor(&self) -> crucible_linux_resource::host_supervision::HostOperationSupervisor;

    /// Admits the next node's operational allocation without changing replay inputs.
    ///
    /// # Errors
    ///
    /// Returns an error when the original owner, capacity, or cleanup ordering
    /// does not authorize a new native allocation.
    fn prepare(
        &self,
        config: &QemuLiveNodeStepGateConfig,
        node: &NodeId,
    ) -> Result<crate::ram_control::RamControlRegistration, QemuVmRealizationError>;
}

/// Validated exact-target admission for one replay-oracle comparison.
pub struct QemuReplayValidationExactAdmission {
    config: QemuLiveNodeStepGateConfig,
    run_directory: Option<QemuPreparedRunDirectory>,
    snapshot: ContentHash,
    checkpoint: ContentHash,
    modeled_node: NodeId,
    #[cfg(target_os = "linux")]
    request: Option<QemuProductionExactRestoreRequest>,
    #[cfg(target_os = "linux")]
    target: Option<crucible::exact_checkpoint::ExactCheckpointVerifiedNode>,
    failed_child: Option<crate::QemuNodeChild>,
    registration_preparation: Option<Arc<dyn QemuReplayValidationRegistrationPreparation>>,
}

/// Validated thin-target admission for one replay-oracle comparison.
pub struct QemuReplayValidationThinAdmission {
    config: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    checkpoint: ContentHash,
    snapshot: ContentHash,
    modeled_node: NodeId,
    identity: OwnedLiveNodeIdentity,
    failed_child: Option<crate::QemuNodeChild>,
    registration_preparation: Option<Arc<dyn QemuReplayValidationRegistrationPreparation>>,
}

struct OwnedLiveNodeIdentity {
    node: String,
    router: String,
    crash_detector: String,
}

impl OwnedLiveNodeIdentity {
    fn borrowed(&self) -> QemuLiveNodeIdentity<'_> {
        QemuLiveNodeIdentity::new(&self.node, &self.router, &self.crash_detector)
    }
}

pub(super) struct QemuReplayValidationNodeLauncher {
    exact: QemuReplayValidationExactAdmission,
    thin: QemuReplayValidationThinAdmission,
}

impl QemuReplayValidationExactAdmission {
    /// Admits one authenticated paged exact target for replay validation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] unless the profile names the prepared
    /// directory and the sealed descriptor set matches the supplied snapshot.
    #[cfg(target_os = "linux")]
    pub fn admit_atomic(
        config: QemuLiveNodeStepGateConfig,
        request: QemuProductionExactRestoreRequest,
        snapshot: &QemuVmSnapshot,
        node: NodeId,
    ) -> Result<Self, QemuVmRealizationError> {
        request
            .authenticate_replay_basis(&config, snapshot, &node)
            .map_err(|error| QemuVmRealizationError::InvalidCheckpoint {
                role: "atomic exact replay admission",
                message: error.to_string(),
            })?;
        Ok(Self {
            config,
            run_directory: None,
            snapshot: snapshot.id(),
            checkpoint: snapshot.checkpoint().id,
            modeled_node: node,
            request: Some(request),
            target: None,
            failed_child: None,
            registration_preparation: None,
        })
    }

    /// Defers operational admission until the executor launches this exact leg.
    #[must_use]
    pub fn with_registration_preparation(
        mut self,
        preparation: Arc<dyn QemuReplayValidationRegistrationPreparation>,
    ) -> Self {
        self.registration_preparation = Some(preparation);
        self
    }

    fn launch_prepared_exact_node(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        checkpoint: &Checkpoint,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if snapshot.id() != self.snapshot || checkpoint.id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded exact-profile checkpoint restore",
                message: String::from(
                    "snapshot metadata does not match the materialized exact target",
                ),
            });
        }
        let mut request =
            self.request
                .take()
                .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                    role: "atomic exact replay admission",
                    message: String::from("exact replay request was already consumed"),
                })?;
        if let Some(preparation) = &self.registration_preparation {
            let registration = preparation.prepare(&self.config, &self.modeled_node)?;
            request = request.with_replay_ram_registration(registration, preparation.supervisor());
        }
        let result = request
            .launch()
            .map(QemuProductionExactRestoreLaunch::into_paused_parts);
        let result = result.map(|(node, run_directory, target)| {
            self.run_directory = Some(run_directory);
            self.target = Some(target);
            node
        });
        retain_profile_restore_result(result, &mut self.failed_child, config)
    }
}

impl QemuReplayValidationThinAdmission {
    /// Admits one fresh baked-genesis leg for replay validation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] unless the profile names the prepared
    /// directory is the fresh profile for the supplied modeled snapshot.
    #[cfg(target_os = "linux")]
    pub fn admit(
        config: QemuLiveNodeStepGateConfig,
        run_directory: QemuPreparedRunDirectory,
        snapshot: &QemuVmSnapshot,
        node: NodeId,
        crash_detector: impl Into<String>,
    ) -> Result<Self, QemuVmRealizationError> {
        if config.run_directory() != run_directory.path() {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "fresh thin replay profile",
                message: String::from("launch profile names another prepared run directory"),
            });
        }
        Ok(Self {
            config,
            run_directory,
            checkpoint: snapshot.checkpoint().id,
            snapshot: snapshot.id(),
            modeled_node: node.clone(),
            identity: OwnedLiveNodeIdentity {
                node: node.name,
                router: String::from("crucible-router"),
                crash_detector: crash_detector.into(),
            },
            failed_child: None,
            registration_preparation: None,
        })
    }

    /// Defers operational admission until the preceding replay leg is cleaned.
    #[must_use]
    pub fn with_registration_preparation(
        mut self,
        preparation: Arc<dyn QemuReplayValidationRegistrationPreparation>,
    ) -> Self {
        self.registration_preparation = Some(preparation);
        self
    }

    fn launch_prepared_thin_node(
        &mut self,
        config: &Configuration,
        restore: QemuNodeCheckpointAssertion<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        require_no_failed_launch_child(&self.failed_child)?;
        if restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded thin-profile checkpoint restore",
                message: String::from(
                    "restore checkpoint does not match the materialized thin target",
                ),
            });
        }
        let mut launch_config = self.config.clone();
        if let Some(preparation) = &self.registration_preparation {
            let registration = preparation.prepare(&launch_config, &self.modeled_node)?;
            launch_config = launch_config
                .with_ram_control_registration(registration)
                .with_host_operation_supervisor(preparation.supervisor());
        }
        let launch = QemuProductionFreshLaunchAdmission::admit(
            &launch_config,
            &self.run_directory,
            process_contract,
            self.identity.borrowed(),
        );
        let result =
            launch.and_then(|launch| launch_qemu_production_fresh_node(&launch_config, launch));
        retain_profile_restore_result(result, &mut self.failed_child, config)
    }
}

impl QemuReplayValidationNodeLauncher {
    pub(super) fn new(
        exact: QemuReplayValidationExactAdmission,
        thin: QemuReplayValidationThinAdmission,
    ) -> Result<Self, QemuVmRealizationError> {
        validate_admitted_nodes(&exact.modeled_node, &thin.modeled_node)?;
        validate_replay_profiles(&exact.config, &thin.config)?;
        Ok(Self { exact, thin })
    }

    pub(super) const fn exact_snapshot(&self) -> ContentHash {
        self.exact.snapshot
    }

    pub(super) const fn thin_snapshot(&self) -> ContentHash {
        self.thin.snapshot
    }

    pub(super) fn take_exact_target(
        &mut self,
    ) -> Option<crucible::exact_checkpoint::ExactCheckpointVerifiedNode> {
        self.exact.target.take()
    }

    pub(super) fn into_executor(self) -> QemuReplayValidationExecutor {
        let node = self.exact.modeled_node.clone();
        QemuReplayValidationExecutor {
            node,
            launcher: self,
            active_node: None,
            active_configuration: None,
            active_runtime_id: None,
            event_log: EventLog::new(),
            authority: Arc::new(QemuReplayObservationAuthority),
            next_generation: 0,
            exact_observation_generation: None,
            thin_observation_generation: None,
        }
    }
}

impl QemuFailedLaunchChildSource for QemuReplayValidationExactAdmission {
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl QemuFailedLaunchChildSource for QemuReplayValidationThinAdmission {
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.failed_child.take()
    }
}

impl QemuFailedLaunchChildSource for QemuReplayValidationNodeLauncher {
    fn take_failed_launch_child(&mut self) -> Option<crate::QemuNodeChild> {
        self.exact
            .take_failed_launch_child()
            .or_else(|| self.thin.take_failed_launch_child())
    }
}

impl QemuGuardedNodeRealizationLauncherOps for QemuReplayValidationExactAdmission {
    fn launch_materialized_probe_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuGuardedProbeRestoreAdmission<'_>,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        self.launch_prepared_exact_node(config, snapshot, restore.checkpoint())
    }
}

impl QemuGuardedThinNodeRealizationLauncherOps for QemuReplayValidationThinAdmission {
    fn launch_baked_genesis_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuGuardedBakedRestoreAdmission<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        self.launch_prepared_thin_node(config, restore.into_basis(), process_contract)
    }
}

impl QemuGuardedNodeRealizationLauncherOps for QemuReplayValidationNodeLauncher {
    fn launch_materialized_probe_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuGuardedProbeRestoreAdmission<'_>,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        self.exact
            .launch_materialized_probe_node_guarded(config, snapshot, restore)
    }
}

impl QemuGuardedThinNodeRealizationLauncherOps for QemuReplayValidationNodeLauncher {
    fn launch_baked_genesis_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuGuardedBakedRestoreAdmission<'_>,
        process_contract: &QemuChildProcessContract,
    ) -> Result<QemuNode, QemuVmRealizationError> {
        self.thin
            .launch_baked_genesis_node_guarded(config, restore, process_contract)
    }
}
