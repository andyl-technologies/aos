//! Authenticated packaged bases and production QEMU source-world capture.
//!
//! A source factory first authenticates one lineage, its exact scenario
//! artifact, and its canonical genesis configuration through the narrow
//! campaign executor store. The expected executor profile must equal the
//! lineage-derived profile before any QEMU lifecycle starts. Only that fixed
//! factory can mint [`AuthenticatedCanonicalQemuHotForkSource`], so managed
//! admission never accepts a caller-authored key or compatibility label.

use crucible::{Configuration, ScenarioDefForm};
use crucible_api::vm_lifecycle::{
    ProductionVmHotForkSourceWorld, ProductionVmHotForkSourceWorldPreparationFailure,
};
use crucible_campaign::{
    CampaignExecutorStore, CampaignLineage, CampaignLineageId, CampaignRepositoryError,
    ConfigurationArtifactId, ExecutorCompatibilityProfile, ScenarioArtifactId,
};
use thiserror::Error;

use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CrucibleArtifactError,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleError,
    QemuAttemptProductionVmLifecycleFactory, QemuAttemptResourceGuardFactory,
    QemuFreshAttemptLifecycleFactory, QemuHotForkSourceWorldKey,
    decode_crucible_configuration_artifact_with_selections, decode_crucible_scenario_artifact,
};

/// Repository-authenticated fixed source basis for one packaged lineage.
#[derive(Clone)]
pub struct AuthenticatedQemuHotForkSourceBasis {
    lineage_id: CampaignLineageId,
    lineage: CampaignLineage,
    scenario_artifact: ScenarioArtifactId,
    source_artifact: ConfigurationArtifactId,
    scenario: ScenarioDefForm,
    source: Configuration,
}

impl AuthenticatedQemuHotForkSourceBasis {
    /// Loads and authenticates one exact canonical-genesis source basis.
    ///
    /// The expected profile is normally the already-authenticated common
    /// packaged-executor profile. Comparing it with the lineage-derived value
    /// prevents a source factory from being rebound to a caller-authored QEMU
    /// build or protocol label.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedQemuHotForkSourceBasisError`] when repository
    /// records are unavailable, artifacts fail semantic decoding, the lineage
    /// has another profile, or its named genesis is not canonical genesis.
    pub fn authenticate(
        store: &CampaignExecutorStore,
        lineage: CampaignLineageId,
        expected_profile: &ExecutorCompatibilityProfile,
    ) -> Result<Self, AuthenticatedQemuHotForkSourceBasisError> {
        let lineage_id = lineage;
        let lineage = store.load_lineage(lineage_id)?;
        let actual_profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
        if &actual_profile != expected_profile {
            return Err(AuthenticatedQemuHotForkSourceBasisError::ProfileMismatch {
                expected: Box::new(expected_profile.clone()),
                actual: Box::new(actual_profile),
            });
        }

        let scenario_artifact = store.load_scenario_artifact(lineage.scenario_content())?;
        let scenario = decode_crucible_scenario_artifact(&scenario_artifact)?;
        let source_artifact = store.load_configuration_artifact(lineage.genesis_content())?;
        let source = decode_crucible_configuration_artifact_with_selections(
            &scenario,
            &scenario_artifact,
            &source_artifact,
            store,
        )?;
        let canonical_genesis = Configuration::genesis(scenario.scenario_def());
        if source != canonical_genesis {
            return Err(AuthenticatedQemuHotForkSourceBasisError::NonCanonicalGenesis);
        }

        Ok(Self {
            lineage_id,
            scenario_artifact: lineage.scenario_content(),
            source_artifact: lineage.genesis_content(),
            lineage,
            scenario,
            source,
        })
    }

    /// Returns the authenticated lineage identity.
    #[must_use]
    pub const fn lineage_id(&self) -> CampaignLineageId {
        self.lineage_id
    }

    /// Returns the authenticated lineage.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the exact scenario artifact used to launch the source.
    #[must_use]
    pub const fn scenario_artifact(&self) -> ScenarioArtifactId {
        self.scenario_artifact
    }

    /// Returns the durable thin fallback for this canonical source.
    #[must_use]
    pub const fn source_artifact(&self) -> ConfigurationArtifactId {
        self.source_artifact
    }

    /// Returns the decoded authenticated scenario form.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the canonical source configuration.
    #[must_use]
    pub const fn source(&self) -> &Configuration {
        &self.source
    }

    /// Returns the authenticated executor compatibility profile.
    #[must_use]
    pub fn profile(&self) -> ExecutorCompatibilityProfile {
        ExecutorCompatibilityProfile::from_lineage(&self.lineage)
    }

    fn key(&self) -> QemuHotForkSourceWorldKey {
        QemuHotForkSourceWorldKey::new(
            self.lineage_id,
            self.source.def.id(),
            self.source.id(),
            ExecutorCompatibilityProfile::from_lineage(&self.lineage),
        )
    }
}

/// Production lifecycle factory fixed to one authenticated source basis.
pub struct ProductionQemuHotForkSourceFactory<R> {
    basis: AuthenticatedQemuHotForkSourceBasis,
    lifecycles: QemuAttemptProductionVmLifecycleFactory<R>,
}

impl<R> ProductionQemuHotForkSourceFactory<R> {
    /// Binds packaged lifecycle launch authority to one authenticated basis.
    ///
    /// The constructor remains crate-private so only the packaged composition
    /// that authenticates deployment identity may mint source tokens.
    pub(crate) fn new(
        basis: AuthenticatedQemuHotForkSourceBasis,
        lifecycles: QemuAttemptProductionVmLifecycleFactory<R>,
        deployed_qemu_build: &str,
    ) -> Result<Self, AuthenticatedQemuHotForkSourceBasisError> {
        let expected = basis.profile().qemu_build().to_owned();
        if deployed_qemu_build != expected {
            return Err(
                AuthenticatedQemuHotForkSourceBasisError::QemuBuildMismatch {
                    expected,
                    actual: deployed_qemu_build.to_owned(),
                },
            );
        }

        Ok(Self { basis, lifecycles })
    }

    /// Returns the immutable authenticated basis.
    #[must_use]
    pub const fn basis(&self) -> &AuthenticatedQemuHotForkSourceBasis {
        &self.basis
    }
}

impl<R> ProductionQemuHotForkSourceFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Launches and prepares one canonical production source world.
    ///
    /// The token's key is derived only from the fixed authenticated basis. The
    /// caller never supplies a lineage, configuration, or compatibility
    /// profile at the source-authority boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionQemuHotForkSourceCaptureError`] when guarded source
    /// startup or atomic source-world preparation fails. Preparation failures
    /// retain the lifecycle until it can be recovered or quarantined.
    pub fn capture(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<AuthenticatedCanonicalQemuHotForkSource, ProductionQemuHotForkSourceCaptureError>
    {
        let scenario = self.basis.scenario.scenario_def();
        let signal_fault_replay =
            crucible::SignalFaultCampaignReplayPlan::empty(self.basis.source.clone());
        let lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                &self.basis.scenario,
                &self.basis.source,
                &signal_fault_replay,
                context,
            )
            .map_err(|source| ProductionQemuHotForkSourceCaptureError::Start(Box::new(source)))?;
        let source = lifecycle
            .prepare_hot_fork_source_world()
            .map_err(|source| {
                ProductionQemuHotForkSourceCaptureError::Preparation(Box::new(source))
            })?;

        Ok(AuthenticatedCanonicalQemuHotForkSource {
            key: self.basis.key(),
            source,
        })
    }
}

/// Canonical source accepted by managed admission after factory authentication.
#[must_use = "admit the authenticated source or retain its complete authority"]
pub struct AuthenticatedCanonicalQemuHotForkSource {
    key: QemuHotForkSourceWorldKey,
    source: ProductionVmHotForkSourceWorld,
}

impl AuthenticatedCanonicalQemuHotForkSource {
    pub(crate) fn into_parts(self) -> (QemuHotForkSourceWorldKey, ProductionVmHotForkSourceWorld) {
        (self.key, self.source)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        key: QemuHotForkSourceWorldKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Self {
        Self { key, source }
    }
}

/// Failure while authenticating a fixed packaged source basis.
#[derive(Debug, Error)]
pub enum AuthenticatedQemuHotForkSourceBasisError {
    /// An immutable campaign record was missing or inconsistent.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Scenario or configuration bytes failed semantic authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The lineage-derived profile differs from the packaged fixed profile.
    #[error("source lineage compatibility profile differs from the packaged executor basis")]
    ProfileMismatch {
        /// Profile fixed by the authenticated packaged campaign set.
        expected: Box<ExecutorCompatibilityProfile>,
        /// Profile derived from the candidate lineage.
        actual: Box<ExecutorCompatibilityProfile>,
    },
    /// The packaged lifecycle launches another QEMU build.
    #[error("deployed QEMU build `{actual}` differs from authenticated lineage build `{expected}`")]
    QemuBuildMismatch {
        /// Build identity authenticated by the lineage.
        expected: String,
        /// Build identity bound to the packaged lifecycle deployment.
        actual: String,
    },
    /// The lineage's named source contains a nonempty decision schedule.
    #[error("source lineage does not name canonical scenario genesis")]
    NonCanonicalGenesis,
}

/// Failure while launching or preparing a production source world.
#[derive(Debug, Error)]
pub enum ProductionQemuHotForkSourceCaptureError {
    /// Guarded production lifecycle startup failed.
    #[error("start canonical production hot-fork source")]
    Start(#[source] Box<AttemptWorkerFailure<QemuAttemptProductionVmLifecycleError>>),
    /// Atomic source-world preparation failed while retaining its lifecycle.
    #[error("prepare canonical production hot-fork source")]
    Preparation(#[source] Box<ProductionVmHotForkSourceWorldPreparationFailure>),
}

#[cfg(test)]
#[path = "qemu_hot_fork_source_capture/tests.rs"]
mod tests;
