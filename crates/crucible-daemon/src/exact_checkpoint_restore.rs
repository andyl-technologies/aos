//! Exact checkpoint restoration into a guarded QEMU run directory.
//!
//! This module joins three independently owned authorities without granting
//! any of them broader mutation capability: a semantic exact pin or durable
//! attempt-resume root, the operational owner that retained it, and the
//! immutable exact-checkpoint store. Runtime restore accepts only version-nine
//! production closures and consumes sealed RAM and device-state descriptors
//! through the production lifecycle.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crucible::{
    Configuration, ContentHash, Decision, NodeId, ScenarioDefForm, SingleSchedulerCheckpoint,
};
use crucible_api::{
    DecodedProductionExactCheckpoint, LifecycleApiError, ProductionExactCheckpointClosure,
    ProductionExactCheckpointResumeBasis, ProductionVmExactNodeRestoreAdmissions,
    open_exact_checkpoint_closure,
};
use crucible_qemu::{
    QemuBakedGenesisSnapshot, QemuReplayOracleMatch, QemuReplayValidationExecutor,
    QemuVmRealizationError, QemuVmReplayRequest, QemuVmSnapshot,
};
use thiserror::Error;

use crucible_campaign::ExactCheckpointId;

use crate::{
    ExactCheckpointStore, ExactCheckpointStoreError, ExecutionCancellation,
    PreparedProductionExactCheckpoint, QemuAttemptProcessResourceGuard,
};

/// Installed and semantically bound production continuation proof.
///
/// The value proves that the complete portable closure was authenticated under
/// the admitted scenario and that its restored schedule continues the exact
/// effective attempt start without introducing another campaign branch edge.
/// It grants no process-launch or replay-oracle authority.
pub(crate) struct InstalledProductionAttemptCheckpoint {
    checkpoint: ExactCheckpointId,
    closure: ProductionExactCheckpointClosure,
    configuration: Configuration,
    scheduler: SingleSchedulerCheckpoint,
    decoded: Option<DecodedProductionExactCheckpoint>,
}

/// Repository-authenticated resume state retained until atomic QEMU launch.
pub(crate) struct AuthenticatedProductionAttemptResume {
    production_identity: ContentHash,
    decoded: DecodedProductionExactCheckpoint,
}

impl AuthenticatedProductionAttemptResume {
    pub(crate) fn configuration(&self) -> &Configuration {
        self.decoded.configuration()
    }

    pub(crate) fn into_decoded(self) -> DecodedProductionExactCheckpoint {
        self.decoded
    }
}

/// Authenticated production boundary that grants no launch capability.
///
/// Boundary inspection temporarily claims the live replay promotion while it
/// validates the complete closure, then releases that claim before returning
/// this value. Process launch must reauthenticate and consume the claim.
pub(crate) struct AuthenticatedProductionAttemptBoundary {
    production_identity: ContentHash,
    configuration: Configuration,
    scheduler: SingleSchedulerCheckpoint,
}

impl AuthenticatedProductionAttemptBoundary {
    pub(crate) const fn production_identity(&self) -> ContentHash {
        self.production_identity
    }

    pub(crate) const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    pub(crate) const fn scheduler(&self) -> &SingleSchedulerCheckpoint {
        &self.scheduler
    }
}

/// No-write campaign-root replacement for one installed production attempt.
#[derive(Debug)]
pub(crate) struct PreparedProductionAttemptReplayOraclePromotion {
    source: ExactCheckpointId,
    replacement: PreparedProductionExactCheckpoint,
}

impl PreparedProductionAttemptReplayOraclePromotion {
    /// Returns the raw attempt root retained throughout promotion.
    #[must_use]
    pub(crate) const fn source(&self) -> ExactCheckpointId {
        self.source
    }

    /// Returns the derived promoted root that must be staged before writes.
    #[must_use]
    pub(crate) const fn promoted(&self) -> ExactCheckpointId {
        self.replacement.root()
    }

    pub(crate) const fn replacement(&self) -> &PreparedProductionExactCheckpoint {
        &self.replacement
    }
}

impl InstalledProductionAttemptCheckpoint {
    /// Returns the exact campaign-CAS root that supplied this continuation.
    #[must_use]
    pub(crate) const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the installed native production closure.
    #[must_use]
    pub(crate) const fn closure(&self) -> &ProductionExactCheckpointClosure {
        &self.closure
    }

    /// Returns the exact restored modeled configuration.
    #[must_use]
    pub(crate) const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the complete restored scheduler continuation.
    #[must_use]
    pub(crate) const fn scheduler(&self) -> &SingleSchedulerCheckpoint {
        &self.scheduler
    }

    pub(crate) fn take_node_restore_admissions(
        &mut self,
    ) -> Option<ProductionVmExactNodeRestoreAdmissions> {
        self.decoded
            .take()
            .map(DecodedProductionExactCheckpoint::into_node_restore_admissions)
    }
}

/// Attempt-owned guarded executor for one exact fat/thin replay comparison.
///
/// The session routes the selected fat probe through the exact-root launcher
/// and every cached-ancestor or baked-genesis restore through a disjoint thin-
/// path launcher. It borrows the promotion's aggregate attempt guard while the
/// current node is active. Any realization failure transfers that aggregate
/// authority to quarantine after retaining any pre-install child.
pub(crate) struct QemuGuardedReplayOracleSession<'a, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    executor: &'a mut QemuReplayValidationExecutor,
    guard: &'a mut G,
    realization_failed: bool,
    backend_reaped: bool,
    guard_terminal: bool,
}

impl<'a, G> QemuGuardedReplayOracleSession<'a, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Borrows one aggregate attempt guard for node-local replay validation.
    #[must_use]
    pub(crate) const fn new(
        executor: &'a mut QemuReplayValidationExecutor,
        guard: &'a mut G,
    ) -> Self {
        Self {
            executor,
            guard,
            realization_failed: false,
            backend_reaped: false,
            guard_terminal: false,
        }
    }

    /// Reaps the final thin-path generation while retaining the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::ReapQuarantined`] when realization or
    /// reap failed and resource ownership was transferred to quarantine. Other
    /// cleanup diagnostics are returned only after reap attestation.
    pub(crate) fn finish(mut self) -> Result<(), QemuVmRealizationError> {
        self.cleanup()
    }

    /// Compares one authenticated fat snapshot with replay from baked genesis.
    ///
    /// Runtime observations stay opaque outside `crucible-qemu`; this session
    /// may sequence guarded operations but cannot manufacture comparison
    /// evidence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when either guarded realization,
    /// replay quantum, or final source-bound comparison fails.
    pub(crate) fn check_snapshot_replay_oracle(
        &mut self,
        world: &crucible::World,
        configuration: &Configuration,
        snapshot: &QemuVmSnapshot,
        baked: &QemuBakedGenesisSnapshot,
    ) -> Result<QemuReplayOracleMatch, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .load_materialized_exact_snapshot_probe_guarded(configuration, snapshot);
        let fat = self.observe_realization(result)?;

        let genesis = Configuration::genesis(configuration.def.clone());
        self.guard.check_operational_boundary()?;
        let process_contract = self.guard.child_process_contract()?;
        let result = self.executor.load_prepared_baked_genesis_guarded(
            process_contract,
            &genesis,
            world,
            baked,
        );
        let mut thin = self.observe_realization(result)?;

        let mut current = genesis;
        for decision in configuration.schedule.decisions() {
            let next = crucible::try_step(&current, decision.clone()).map_err(|source| {
                QemuVmRealizationError::InvalidCheckpoint {
                    role: "baked-genesis replay target",
                    message: format!("decision violates the scenario model: {source}"),
                }
            })?;
            self.guard.check_operational_boundary()?;
            self.guard.charge_execution_quantum()?;
            let result = self.executor.replay_materialized_one_quantum(
                thin,
                QemuVmReplayRequest::new(current, decision.clone())?,
            );
            thin = self.observe_realization(result)?;
            current = next;
        }
        if &current != configuration {
            return Err(QemuVmRealizationError::InvalidAncestor {
                message: String::from("baked-genesis replay did not reach target configuration"),
            });
        }

        self.executor
            .finish_replay_oracle_comparison(snapshot, configuration, fat, thin)
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
            match self.executor.shutdown_active_node() {
                Ok(()) => self.backend_reaped = true,
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
        Ok(())
    }
}

impl<G> Drop for QemuGuardedReplayOracleSession<'_, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Installs and binds one version-nine production checkpoint for attempt resume.
///
/// `initial` is the authenticated pre-selection configuration. A branch
/// attempt supplies `post_selection`, which becomes its effective modeled
/// start; a discovery attempt omits it. The restored production schedule must
/// retain that effective start as an exact prefix. Any later campaign-branch
/// selection is rejected because it belongs to a different semantic attempt,
/// while ordinary scheduler decisions and scenario-authenticated model samples
/// may extend the prefix.
///
/// This operation authenticates the campaign-CAS root, streams the complete
/// portable closure into the private production run-state store, reruns the
/// complete scenario-aware restore validator, and returns only a modeled
/// continuation proof. It does not launch QEMU and does not establish the
/// source-bound replay-oracle evidence required for production resume.
///
/// # Errors
///
/// Returns [`ProductionAttemptCheckpointRestoreError::Canceled`] when
/// cancellation wins, or an exact store, semantic-installation, scenario,
/// identity, configuration, or attempt-prefix error otherwise.
pub(crate) fn install_attempt_production_exact_checkpoint(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    source: &ScenarioDefForm,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    run_state_root: &Path,
    cancellation: &ExecutionCancellation,
) -> Result<InstalledProductionAttemptCheckpoint, ProductionAttemptCheckpointRestoreError> {
    install_attempt_production_exact_checkpoint_inner(AttemptCheckpointInstallation {
        checkpoints,
        checkpoint,
        source,
        initial,
        post_selection,
        run_state_root,
        cancellation,
    })
}

/// Installs one resume-eligible version-nine production checkpoint.
///
/// This applies the complete attempt-prefix and scenario checks from
/// [`install_attempt_production_exact_checkpoint`] and additionally requires
/// every live-node snapshot to carry source-bound `Match` replay-oracle
/// evidence. A raw closure is rejected during no-write native
/// admission and can never reach guarded process launch.
///
/// # Errors
///
/// Returns [`ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady`]
/// for a raw or partially promoted closure, or any error documented by
/// [`install_attempt_production_exact_checkpoint`].
pub(crate) fn install_attempt_production_resume_checkpoint(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    source: &ScenarioDefForm,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    cancellation: &ExecutionCancellation,
) -> Result<AuthenticatedProductionAttemptResume, ProductionAttemptCheckpointRestoreError> {
    let (resume, replay_claim) = authenticate_attempt_production_resume_checkpoint_inner(
        checkpoints,
        checkpoint,
        source,
        initial,
        post_selection,
        cancellation,
    )?;
    replay_claim.commit().map_err(map_production_store_error)?;
    Ok(resume)
}

/// Authenticates a resume boundary without consuming its launch authority.
///
/// The complete promoted closure and attempt continuation receive the same
/// validation as [`install_attempt_production_resume_checkpoint`]. The live
/// promotion claim is released before this function returns, so the eventual
/// launch must repeat authentication and atomically consume it.
///
/// # Errors
///
/// Returns the errors documented by
/// [`install_attempt_production_resume_checkpoint`].
pub(crate) fn authenticate_attempt_production_resume_boundary(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    source: &ScenarioDefForm,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    cancellation: &ExecutionCancellation,
) -> Result<AuthenticatedProductionAttemptBoundary, ProductionAttemptCheckpointRestoreError> {
    let (resume, replay_claim) = authenticate_attempt_production_resume_checkpoint_inner(
        checkpoints,
        checkpoint,
        source,
        initial,
        post_selection,
        cancellation,
    )?;
    let boundary = AuthenticatedProductionAttemptBoundary {
        production_identity: resume.production_identity,
        configuration: resume.decoded.configuration().clone(),
        scheduler: resume.decoded.scheduler().clone(),
    };
    drop(replay_claim);

    Ok(boundary)
}

fn authenticate_attempt_production_resume_checkpoint_inner<'a>(
    checkpoints: &'a ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    source: &ScenarioDefForm,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    cancellation: &ExecutionCancellation,
) -> Result<
    (
        AuthenticatedProductionAttemptResume,
        crate::exact_checkpoint_store::LiveReplayPromotionClaim<'a>,
    ),
    ProductionAttemptCheckpointRestoreError,
> {
    check_production_cancellation(cancellation)?;
    let effective_start = post_selection.unwrap_or(initial);
    let scenario = source.scenario_def();
    if initial.def != scenario || post_selection.is_some_and(|selected| selected.def != scenario) {
        return Err(ProductionAttemptCheckpointRestoreError::AttemptScenarioMismatch);
    }
    if let Some(selected) = post_selection {
        validate_production_post_selection(initial, selected)?;
    }

    let loaded = Arc::new(
        checkpoints
            .load_production_closure_with_cancellation(checkpoint, cancellation)
            .map_err(map_production_store_error)?,
    );
    if loaded.scenario() != scenario.id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch {
                checkpoint,
                scenario: loaded.scenario(),
            },
        );
    }
    let replay_claim =
        authenticate_loaded_replay_oracle_promotion(checkpoints, &loaded, cancellation)?;
    let decoded = loaded
        .decode_semantic_checkpoint(source, cancellation)
        .map_err(map_production_store_error)?;
    if decoded.configuration().id() != loaded.configuration() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointConfigurationMismatch {
                checkpoint,
                configuration: loaded.configuration(),
            },
        );
    }
    validate_production_attempt_continuation(effective_start, decoded.configuration(), checkpoint)?;
    Ok((
        AuthenticatedProductionAttemptResume {
            production_identity: loaded.production_identity(),
            decoded,
        },
        replay_claim,
    ))
}

struct AttemptCheckpointInstallation<'a> {
    checkpoints: &'a ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    source: &'a ScenarioDefForm,
    initial: &'a Configuration,
    post_selection: Option<&'a Configuration>,
    run_state_root: &'a Path,
    cancellation: &'a ExecutionCancellation,
}

fn authenticate_loaded_replay_oracle_promotion<'a>(
    checkpoints: &'a ExactCheckpointStore,
    promoted: &crate::LoadedProductionExactCheckpoint,
    cancellation: &ExecutionCancellation,
) -> Result<
    crate::exact_checkpoint_store::LiveReplayPromotionClaim<'a>,
    ProductionAttemptCheckpointRestoreError,
> {
    let promoted_checkpoint = promoted.root();
    let evidence_id = promoted.promotion_evidence_id().ok_or(
        ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint: promoted_checkpoint,
        },
    )?;
    let raw_checkpoint = promoted.promotion_source().ok_or(
        ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint: promoted_checkpoint,
        },
    )?;
    if raw_checkpoint == promoted_checkpoint {
        return Err(
            ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: promoted_checkpoint,
            },
        );
    }
    let raw = checkpoints
        .load_production_closure_with_cancellation(raw_checkpoint, cancellation)
        .map_err(map_production_store_error)?;
    let _evidence = promoted.promotion_evidence().ok_or(
        ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint: promoted_checkpoint,
        },
    )?;
    promoted
        .authenticate_replay_oracle_promotion(&raw)
        .map_err(map_production_store_error)?;
    checkpoints
        .acquire_live_replay_promotion(promoted_checkpoint, evidence_id)
        .map_err(map_production_store_error)?
        .ok_or(
            ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: promoted_checkpoint,
            },
        )
}

fn install_attempt_production_exact_checkpoint_inner(
    installation: AttemptCheckpointInstallation<'_>,
) -> Result<InstalledProductionAttemptCheckpoint, ProductionAttemptCheckpointRestoreError> {
    let AttemptCheckpointInstallation {
        checkpoints,
        checkpoint,
        source,
        initial,
        post_selection,
        run_state_root,
        cancellation,
    } = installation;
    check_production_cancellation(cancellation)?;
    let effective_start = post_selection.unwrap_or(initial);
    let scenario = source.scenario_def();
    if initial.def != scenario || post_selection.is_some_and(|selected| selected.def != scenario) {
        return Err(ProductionAttemptCheckpointRestoreError::AttemptScenarioMismatch);
    }
    if let Some(selected) = post_selection {
        validate_production_post_selection(initial, selected)?;
    }

    let loaded = Arc::new(
        checkpoints
            .load_production_closure_with_cancellation(checkpoint, cancellation)
            .map_err(map_production_store_error)?,
    );
    if loaded.scenario() != scenario.id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch {
                checkpoint,
                scenario: loaded.scenario(),
            },
        );
    }
    check_production_cancellation(cancellation)?;

    let closure =
        open_exact_checkpoint_closure(run_state_root, source, loaded.production_identity())
            .map_err(map_production_lifecycle_error)?;
    let mut boundary = || production_restore_boundary(cancellation);
    let basis = closure
        .authenticate_resume_basis_with_boundary(&mut boundary)
        .map_err(map_production_lifecycle_error)?;
    validate_production_resume_basis(
        &basis,
        loaded.production_identity(),
        loaded.configuration(),
        effective_start,
        checkpoint,
    )?;
    if closure.identity() != loaded.production_identity() {
        return Err(
            ProductionAttemptCheckpointRestoreError::ClosureIdentityMismatch { checkpoint },
        );
    }
    let decoded = loaded
        .decode_semantic_checkpoint(source, cancellation)
        .map_err(map_production_store_error)?;
    if decoded.configuration().id() != loaded.configuration() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointConfigurationMismatch {
                checkpoint,
                configuration: loaded.configuration(),
            },
        );
    }
    let (configuration, scheduler) = basis.into_parts();
    Ok(InstalledProductionAttemptCheckpoint {
        checkpoint,
        closure,
        configuration,
        scheduler,
        decoded: Some(decoded),
    })
}

/// Reauthenticates one durable replay-oracle root replacement.
///
/// The raw and promoted campaign-CAS roots are loaded independently and must
/// name the submitted scenario. Both complete portable closures then pass the
/// no-write production validator, which proves an exact source-to-certificate
/// transition for every live-node snapshot and forbids every other modeled or
/// artifact change. This is the restart boundary used before a staged ledger
/// pair can advance to its promoted resume root.
///
/// # Errors
///
/// Returns [`ProductionAttemptCheckpointRestoreError::Canceled`] when
/// cancellation wins, or an exact-store, scenario, semantic-closure, or
/// replay-oracle relationship error otherwise.
pub(crate) fn acquire_production_exact_checkpoint_replay_oracle_promotion<'a>(
    checkpoints: &'a ExactCheckpointStore,
    raw: ExactCheckpointId,
    promoted: ExactCheckpointId,
    source: &ScenarioDefForm,
    cancellation: &ExecutionCancellation,
) -> Result<
    crate::exact_checkpoint_store::LiveReplayPromotionClaim<'a>,
    ProductionAttemptCheckpointRestoreError,
> {
    check_production_cancellation(cancellation)?;
    let raw_closure = checkpoints
        .load_production_closure_with_cancellation(raw, cancellation)
        .map_err(map_production_store_error)?;
    if raw_closure.scenario() != source.scenario_def().id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch {
                checkpoint: raw,
                scenario: raw_closure.scenario(),
            },
        );
    }
    let promoted_closure = checkpoints
        .load_production_closure_with_cancellation(promoted, cancellation)
        .map_err(map_production_store_error)?;
    if promoted_closure.scenario() != source.scenario_def().id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch {
                checkpoint: promoted,
                scenario: promoted_closure.scenario(),
            },
        );
    }
    if promoted_closure.promotion_source() != Some(raw) {
        return Err(
            ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: promoted,
            },
        );
    }
    let _evidence = promoted_closure.promotion_evidence().ok_or(
        ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint: promoted,
        },
    )?;

    promoted_closure
        .authenticate_replay_oracle_promotion(&raw_closure)
        .map_err(map_production_store_error)?;
    let evidence_id = promoted_closure.promotion_evidence_id().ok_or(
        ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint: promoted,
        },
    )?;
    checkpoints
        .acquire_live_replay_promotion(promoted, evidence_id)
        .map_err(
            |_| ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: promoted,
            },
        )?
        .ok_or(
            ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: promoted,
            },
        )
}

/// Prepares one attempt-bound production replay-oracle root without writes.
///
/// The installed closure must come from `raw`. `matches` must contain exactly
/// one source-bound matching result for every live production node. The native
/// validator derives the promoted closure lazily, and the campaign store then
/// prepares its complete root/index/object graph without publishing it. The
/// returned root is therefore safe to stage in the operational ledger before
/// the first immutable write.
///
/// # Errors
///
/// Returns [`ProductionAttemptCheckpointRestoreError::Canceled`] when
/// cancellation wins, or an installed-root mismatch, native promotion,
/// immutable-store, identity, scenario, or configuration error otherwise.
pub(crate) fn prepare_attempt_production_replay_oracle_promotion(
    checkpoints: &ExactCheckpointStore,
    raw: ExactCheckpointId,
    installed: &InstalledProductionAttemptCheckpoint,
    matches: BTreeMap<NodeId, QemuReplayOracleMatch>,
    cancellation: &ExecutionCancellation,
) -> Result<PreparedProductionAttemptReplayOraclePromotion, ProductionAttemptCheckpointRestoreError>
{
    check_production_cancellation(cancellation)?;
    if installed.checkpoint() != raw {
        return Err(
            ProductionAttemptCheckpointRestoreError::ClosureIdentityMismatch { checkpoint: raw },
        );
    }
    let mut boundary = || production_restore_boundary(cancellation);
    let promotion = installed
        .closure()
        .prepare_replay_oracle_promotion_with_boundary(raw, matches, &mut boundary)
        .map_err(map_production_lifecycle_error)?;
    if promotion.source() != installed.closure().identity() {
        return Err(
            ProductionAttemptCheckpointRestoreError::ClosureIdentityMismatch { checkpoint: raw },
        );
    }
    let replacement = checkpoints
        .prepare_production_replay_oracle_promotion_with_cancellation(
            raw,
            installed.closure().clone(),
            promotion,
            cancellation,
        )
        .map_err(map_production_store_error)?;
    if replacement.scenario() != installed.configuration().def.id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch {
                checkpoint: replacement.root(),
                scenario: replacement.scenario(),
            },
        );
    }
    if replacement.configuration() != installed.configuration().id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointConfigurationMismatch {
                checkpoint: replacement.root(),
                configuration: replacement.configuration(),
            },
        );
    }
    Ok(PreparedProductionAttemptReplayOraclePromotion {
        source: raw,
        replacement,
    })
}

/// Failure while installing and binding a production attempt continuation.
#[derive(Debug, Error)]
pub(crate) enum ProductionAttemptCheckpointRestoreError {
    /// Cancellation won during bounded root loading or semantic installation.
    #[error("production exact-checkpoint installation was canceled")]
    Canceled,
    /// The attempt start and submitted scenario form disagree.
    #[error("production exact-checkpoint attempt start belongs to another scenario")]
    AttemptScenarioMismatch,
    /// The supplied branch post-selection boundary is not the exact next edge.
    #[error("production exact-checkpoint post-selection boundary is not one branch edge")]
    AttemptSelectionMismatch,
    /// The version-nine root names another scenario.
    #[error("production exact checkpoint {checkpoint} names foreign scenario {scenario:?}")]
    CheckpointScenarioMismatch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
        /// Scenario identity declared by the root.
        scenario: ContentHash,
    },
    /// The installed native closure identity differs from the campaign root.
    #[error("production exact checkpoint {checkpoint} installed another native closure")]
    ClosureIdentityMismatch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
    },
    /// The restored configuration differs from the campaign root declaration.
    #[error(
        "production exact checkpoint {checkpoint} restored another configuration than {configuration:?}"
    )]
    CheckpointConfigurationMismatch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
        /// Configuration identity declared by the root.
        configuration: ContentHash,
    },
    /// The restored schedule does not continue the exact attempt start.
    #[error("production exact checkpoint {checkpoint} is not a continuation of this attempt")]
    AttemptPrefixMismatch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
    },
    /// A materialized-start capture root contains a later attempt configuration.
    #[error("production exact checkpoint {checkpoint} is not the materialized attempt start")]
    MaterializedStartMismatch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
    },
    /// The restored suffix contains another campaign branch edge.
    #[error("production exact checkpoint {checkpoint} crosses another campaign branch edge")]
    NestedCampaignBranch {
        /// Exact campaign-CAS root being installed.
        checkpoint: ExactCheckpointId,
    },
    /// At least one live snapshot lacks source-bound matching replay evidence.
    #[error("production exact checkpoint {checkpoint} is not replay-oracle ready")]
    ReplayOracleNotReady {
        /// Exact raw or partially promoted campaign-CAS root.
        checkpoint: ExactCheckpointId,
    },
    /// Immutable version-nine root authentication failed.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Complete scenario-aware native installation failed.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleApiError),
}

/// Requires a capture root to denote the exact materialized attempt start.
pub(crate) fn validate_materialized_start_configuration(
    checkpoint: ExactCheckpointId,
    materialized_start: &Configuration,
    restored: ContentHash,
) -> Result<(), ProductionAttemptCheckpointRestoreError> {
    if restored != materialized_start.id() {
        return Err(
            ProductionAttemptCheckpointRestoreError::MaterializedStartMismatch { checkpoint },
        );
    }

    Ok(())
}

fn validate_production_attempt_continuation(
    effective_start: &Configuration,
    restored: &Configuration,
    checkpoint: ExactCheckpointId,
) -> Result<(), ProductionAttemptCheckpointRestoreError> {
    let prefix = effective_start.schedule.decisions();
    let decisions = restored.schedule.decisions();
    if effective_start.def != restored.def || !decisions.starts_with(prefix) {
        return Err(ProductionAttemptCheckpointRestoreError::AttemptPrefixMismatch { checkpoint });
    }
    if decisions[prefix.len()..].iter().any(|decision| {
        matches!(decision, Decision::Selection(selection) if selection.is_campaign_branch())
    }) {
        return Err(ProductionAttemptCheckpointRestoreError::NestedCampaignBranch {
            checkpoint,
        });
    }
    Ok(())
}

fn validate_production_resume_basis(
    basis: &ProductionExactCheckpointResumeBasis,
    expected_identity: ContentHash,
    expected_configuration: ContentHash,
    effective_start: &Configuration,
    checkpoint: ExactCheckpointId,
) -> Result<(), ProductionAttemptCheckpointRestoreError> {
    if basis.identity() != expected_identity {
        return Err(
            ProductionAttemptCheckpointRestoreError::ClosureIdentityMismatch { checkpoint },
        );
    }
    if basis.configuration().id() != expected_configuration {
        return Err(
            ProductionAttemptCheckpointRestoreError::CheckpointConfigurationMismatch {
                checkpoint,
                configuration: expected_configuration,
            },
        );
    }
    validate_production_attempt_continuation(effective_start, basis.configuration(), checkpoint)
}

fn validate_production_post_selection(
    initial: &Configuration,
    selected: &Configuration,
) -> Result<(), ProductionAttemptCheckpointRestoreError> {
    let prefix = initial.schedule.decisions();
    let decisions = selected.schedule.decisions();
    let expected_length = prefix
        .len()
        .checked_add(1)
        .ok_or(ProductionAttemptCheckpointRestoreError::AttemptSelectionMismatch)?;
    if initial.def != selected.def
        || decisions.len() != expected_length
        || !decisions.starts_with(prefix)
        || !matches!(
            decisions.last(),
            Some(Decision::Selection(selection)) if selection.is_campaign_branch()
        )
    {
        return Err(ProductionAttemptCheckpointRestoreError::AttemptSelectionMismatch);
    }
    Ok(())
}

fn check_production_cancellation(
    cancellation: &ExecutionCancellation,
) -> Result<(), ProductionAttemptCheckpointRestoreError> {
    if cancellation.is_canceled() {
        Err(ProductionAttemptCheckpointRestoreError::Canceled)
    } else {
        Ok(())
    }
}

fn production_restore_boundary(
    cancellation: &ExecutionCancellation,
) -> Result<(), LifecycleApiError> {
    if cancellation.is_canceled() {
        Err(LifecycleApiError::AttemptOperational {
            class: crucible::SchedulerOperationalFailureClass::Canceled,
            message: String::from("production exact-checkpoint installation canceled"),
        })
    } else {
        Ok(())
    }
}

fn map_production_store_error(
    error: ExactCheckpointStoreError,
) -> ProductionAttemptCheckpointRestoreError {
    match error {
        ExactCheckpointStoreError::Canceled => ProductionAttemptCheckpointRestoreError::Canceled,
        error => ProductionAttemptCheckpointRestoreError::Checkpoint(error),
    }
}

fn map_production_lifecycle_error(
    error: LifecycleApiError,
) -> ProductionAttemptCheckpointRestoreError {
    match error {
        LifecycleApiError::AttemptOperational {
            class: crucible::SchedulerOperationalFailureClass::Canceled,
            ..
        } => ProductionAttemptCheckpointRestoreError::Canceled,
        error => ProductionAttemptCheckpointRestoreError::Lifecycle(error),
    }
}

#[cfg(test)]
mod captured_source_tests {
    use super::*;

    use crucible::{RngDecision, RngStreamId, Schedule};
    use crucible_cas::content_store::{ContentId, ObjectKind};

    #[test]
    fn production_resume_basis_requires_the_exact_attempt_prefix() {
        let scenario = crucible::happy_path_scenario()
            .unwrap_or_else(|error| panic!("build production resume scenario: {error}"))
            .scenario
            .scenario_def();
        let first = Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resume-prefix"),
            value: 1,
        });
        let second = Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("resume-suffix"),
            value: 2,
        });
        let start = Configuration {
            def: scenario.clone(),
            schedule: Schedule::from_decisions([first.clone()]),
        };
        let restored = Configuration {
            def: scenario.clone(),
            schedule: Schedule::from_decisions([first, second.clone()]),
        };
        let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            4,
            b"production attempt continuation",
        ))
        .unwrap_or_else(|error| panic!("build production exact root: {error}"));

        assert!(validate_production_attempt_continuation(&start, &restored, checkpoint).is_ok());
        assert!(validate_materialized_start_configuration(checkpoint, &start, start.id()).is_ok());
        assert!(matches!(
            validate_materialized_start_configuration(checkpoint, &start, restored.id()),
            Err(ProductionAttemptCheckpointRestoreError::MaterializedStartMismatch {
                checkpoint: observed
            }) if observed == checkpoint
        ));

        let foreign = Configuration {
            def: scenario,
            schedule: Schedule::from_decisions([second]),
        };
        assert!(matches!(
            validate_production_attempt_continuation(&start, &foreign, checkpoint),
            Err(ProductionAttemptCheckpointRestoreError::AttemptPrefixMismatch {
                checkpoint: observed
            }) if observed == checkpoint
        ));
        assert!(matches!(
            validate_production_post_selection(&start, &restored),
            Err(ProductionAttemptCheckpointRestoreError::AttemptSelectionMismatch)
        ));
    }
}
