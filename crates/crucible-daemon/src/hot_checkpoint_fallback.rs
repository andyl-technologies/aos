//! Authenticated exact/thin fallback composition for retained hot checkpoints.
//!
//! The hot-checkpoint manager records an exact immutable fallback identity,
//! while this module authenticates that identity against the narrow campaign
//! executor store, exact-checkpoint store, and native baked-genesis catalog.
//! [`AuthenticatedHotCheckpointDemotionSink`] then repeats authentication at
//! the actual source-release boundary before delegating irreversible teardown.

use std::sync::Arc;

// crucible-lint: allow host-nondeterminism-state -- immutable decoded configurations are authenticated by content identity, never changed using host observations.
use crucible::{BackendError, Configuration, ContentHash};
use crucible_campaign::{
    CampaignExecutorStore, CampaignHash, CampaignRepositoryError, ConfigurationId, ScenarioDefId,
};
use crucible_qemu::{QemuNode, QemuPreparedHotForkTemplate, QemuVmRealizationError};
use thiserror::Error;

use crate::{
    CrucibleArtifactError, ExactCheckpointStore, ExactCheckpointStoreError,
    FixedQemuHotForkTemplateFactory, HotCheckpointFallback, HotCheckpointPlannedDemotion,
    HotCheckpointTemplateDemotionFailure, HotCheckpointTemplateDemotionSink,
    ProductionBakedGenesisReplayCatalogFactory, QemuAttemptResourceGuardFactory,
    QemuHotForkFactoryQuarantine, QemuHotForkPooledLifecycle, QemuHotForkTemplateKey,
    QemuHotForkTemplateLauncher, decode_crucible_configuration_artifact_with_selections,
    decode_crucible_scenario_artifact,
};

mod sealed {
    pub trait QemuHotCheckpointThinFallbackCatalog {}
}

/// Read-only native-base capability accepted by fallback authentication.
///
/// The trait is sealed so production callers cannot substitute self-asserted
/// availability for the authenticated baked-genesis catalog. Test fakes may
/// implement it only inside this crate.
pub trait QemuHotCheckpointThinFallbackCatalog:
    sealed::QemuHotCheckpointThinFallbackCatalog
{
    /// Authenticates one exact World/scenario native replay basis.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the catalog has no exact basis
    /// or its retained native closure is no longer usable.
    fn require_thin_basis(
        &self,
        world: ContentHash,
        scenario: ContentHash,
    ) -> Result<(), QemuVmRealizationError>;
}

impl<R> sealed::QemuHotCheckpointThinFallbackCatalog
    for ProductionBakedGenesisReplayCatalogFactory<R>
{
}

impl<R> QemuHotCheckpointThinFallbackCatalog for ProductionBakedGenesisReplayCatalogFactory<R> {
    fn require_thin_basis(
        &self,
        world: ContentHash,
        scenario: ContentHash,
    ) -> Result<(), QemuVmRealizationError> {
        self.require_basis(world, scenario)
    }
}

/// Read-only authentication required before hot-source release.
pub trait HotCheckpointFallbackAuthenticator {
    /// Authentication or availability failure.
    type Error;

    /// Authenticates the exact fallback against one retained source key.
    ///
    /// # Errors
    ///
    /// Returns the stable authentication diagnostic without changing source
    /// ownership or fallback retention.
    fn authenticate_fallback(
        &self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error>;
}

/// Repository-backed exact/thin fallback authenticator.
///
/// This capability can load campaign and checkpoint objects but cannot mutate
/// campaign refs, publish observations, allocate QEMU resources, or release a
/// retained hot source.
pub struct QemuHotCheckpointFallbackAuthenticator<B>
where
    B: QemuHotCheckpointThinFallbackCatalog,
{
    campaign: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    thin_bases: B,
}

impl<B> QemuHotCheckpointFallbackAuthenticator<B>
where
    B: QemuHotCheckpointThinFallbackCatalog,
{
    /// Binds the narrow campaign, exact-checkpoint, and thin-base capabilities.
    #[must_use]
    pub const fn new(
        campaign: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        thin_bases: B,
    ) -> Self {
        Self {
            campaign,
            checkpoints,
            thin_bases,
        }
    }

    /// Returns the narrow campaign-record reader.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignExecutorStore {
        &self.campaign
    }

    /// Returns the immutable exact-checkpoint store.
    #[must_use]
    pub fn checkpoints(&self) -> &ExactCheckpointStore {
        &self.checkpoints
    }

    /// Returns the authenticated thin-base catalog.
    #[must_use]
    pub const fn thin_bases(&self) -> &B {
        &self.thin_bases
    }

    fn authenticate_exact(
        &self,
        key: QemuHotForkTemplateKey,
        checkpoint: crucible_campaign::ExactCheckpointId,
    ) -> Result<(), QemuHotCheckpointFallbackAuthenticationError> {
        let lineage = self.campaign.load_lineage(key.lineage())?;
        let loaded = self.checkpoints.load_attempt_checkpoint(checkpoint)?;
        if loaded.configuration() != key.configuration() {
            return Err(
                QemuHotCheckpointFallbackAuthenticationError::ConfigurationMismatch {
                    expected: key.configuration(),
                    actual: loaded.configuration(),
                },
            );
        }
        let actual_scenario =
            ScenarioDefId::from_hash(CampaignHash::from_bytes(loaded.scenario().bytes));
        if actual_scenario != lineage.scenario() {
            return Err(
                QemuHotCheckpointFallbackAuthenticationError::ScenarioMismatch {
                    expected: lineage.scenario(),
                    actual: actual_scenario,
                },
            );
        }
        if loaded
            .as_single_node()
            .is_some_and(|single| single.scheduler().is_none())
        {
            return Err(QemuHotCheckpointFallbackAuthenticationError::MissingCampaignContinuation);
        }
        Ok(())
    }

    fn authenticate_thin(
        &self,
        key: QemuHotForkTemplateKey,
        configuration: crucible_campaign::ConfigurationArtifactId,
    ) -> Result<(), QemuHotCheckpointFallbackAuthenticationError> {
        let lineage = self.campaign.load_lineage(key.lineage())?;
        let scenario_artifact = self
            .campaign
            .load_scenario_artifact(lineage.scenario_content())?;
        let configuration_artifact = self.campaign.load_configuration_artifact(configuration)?;
        if configuration_artifact.scenario() != lineage.scenario()
            || configuration_artifact.scenario_artifact() != lineage.scenario_content()
        {
            return Err(QemuHotCheckpointFallbackAuthenticationError::ThinLineageMismatch);
        }
        let expected_configuration =
            ConfigurationId::from_hash(CampaignHash::from_bytes(key.configuration().bytes));
        if configuration_artifact.configuration() != expected_configuration {
            return Err(
                QemuHotCheckpointFallbackAuthenticationError::ConfigurationMismatch {
                    expected: key.configuration(),
                    actual: ContentHash {
                        bytes: configuration_artifact.configuration().as_hash().as_bytes(),
                    },
                },
            );
        }

        let scenario = decode_crucible_scenario_artifact(&scenario_artifact)?;
        let decoded = decode_crucible_configuration_artifact_with_selections(
            &scenario,
            &scenario_artifact,
            &configuration_artifact,
            &self.campaign,
        )?;
        require_decoded_configuration(key, &decoded)?;
        self.thin_bases
            .require_thin_basis(scenario.world().id, decoded.def.id())?;
        Ok(())
    }
}

impl<B> HotCheckpointFallbackAuthenticator for QemuHotCheckpointFallbackAuthenticator<B>
where
    B: QemuHotCheckpointThinFallbackCatalog,
{
    type Error = QemuHotCheckpointFallbackAuthenticationError;

    fn authenticate_fallback(
        &self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        match fallback {
            HotCheckpointFallback::Exact(checkpoint) => self.authenticate_exact(key, checkpoint),
            HotCheckpointFallback::Thin(configuration) => {
                self.authenticate_thin(key, configuration)
            }
        }
    }
}

fn require_decoded_configuration(
    key: QemuHotForkTemplateKey,
    // crucible-lint: allow host-nondeterminism-state -- only compares the authenticated immutable identity with the retained source; no modeled mutation is permitted.
    configuration: &Configuration,
) -> Result<(), QemuHotCheckpointFallbackAuthenticationError> {
    if configuration.id() != key.configuration() {
        return Err(
            QemuHotCheckpointFallbackAuthenticationError::ConfigurationMismatch {
                expected: key.configuration(),
                actual: configuration.id(),
            },
        );
    }
    Ok(())
}

/// Failure to authenticate one exact/thin hot-checkpoint fallback.
#[derive(Debug, Error)]
pub enum QemuHotCheckpointFallbackAuthenticationError {
    /// Campaign lineage or artifact authentication failed.
    #[error("hot-checkpoint fallback campaign authentication failed")]
    Campaign(#[from] CampaignRepositoryError),
    /// Exact-checkpoint closure authentication failed.
    #[error("hot-checkpoint exact fallback authentication failed")]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// Crucible artifact decoding or selection resolution failed.
    #[error("hot-checkpoint thin fallback artifact authentication failed")]
    Artifact(#[from] CrucibleArtifactError),
    /// The fallback materializes another exact configuration.
    #[error("hot-checkpoint fallback configuration differs from its retained source")]
    ConfigurationMismatch {
        /// Configuration named by the retained source key.
        expected: ContentHash,
        /// Configuration authenticated from the fallback.
        actual: ContentHash,
    },
    /// The exact checkpoint belongs to another scenario lineage.
    #[error("hot-checkpoint exact fallback scenario differs from its retained lineage")]
    ScenarioMismatch {
        /// Scenario named by the retained lineage.
        expected: ScenarioDefId,
        /// Scenario authenticated from the checkpoint.
        actual: ScenarioDefId,
    },
    /// The thin configuration names another lineage artifact.
    #[error("hot-checkpoint thin fallback differs from its retained lineage")]
    ThinLineageMismatch,
    /// A compatibility exact root has no complete campaign scheduler state.
    #[error("hot-checkpoint exact fallback has no complete campaign continuation")]
    MissingCampaignContinuation,
    /// The native baked-genesis catalog cannot realize the thin fallback.
    #[error("hot-checkpoint thin fallback has no authenticated native replay base")]
    ThinBase(#[from] QemuVmRealizationError),
}

/// Irreversible source-release operation used after fallback authentication.
pub trait HotCheckpointSourceDemoter<F> {
    /// Source teardown, reap, or resource-release failure.
    type Error;

    /// Reaps one exact retired source while retaining its authority on error.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointTemplateDemotionFailure`] with the source factory
    /// whenever reap or resource release cannot be attested.
    fn demote_source(
        &mut self,
        factory: F,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<F, Self::Error>>;
}

/// Concrete retirement adapter for one idle fixed real-QEMU source.
///
/// The adapter consumes the source from its fixed factory, drains final
/// observations, and requires an attested backend reap. Failed shutdown never
/// repopulates the reusable slot: the factory receives the exact mutated source
/// in its terminal quarantine before ownership returns to the manager.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuFixedHotCheckpointSourceDemoter;

impl<R, X, Q> HotCheckpointSourceDemoter<FixedQemuHotForkTemplateFactory<R, X, Q>>
    for QemuFixedHotCheckpointSourceDemoter
where
    R: QemuAttemptResourceGuardFactory,
    X: QemuHotForkTemplateLauncher<R::Guard, Template = QemuPreparedHotForkTemplate<QemuNode>>,
    Q: QemuHotForkFactoryQuarantine<
            QemuPreparedHotForkTemplate<QemuNode>,
            QemuHotForkPooledLifecycle<X::Lifecycle>,
        >,
{
    type Error = QemuFixedHotCheckpointSourceDemotionError;

    fn demote_source(
        &mut self,
        mut factory: FixedQemuHotForkTemplateFactory<R, X, Q>,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<
        (),
        HotCheckpointTemplateDemotionFailure<FixedQemuHotForkTemplateFactory<R, X, Q>, Self::Error>,
    > {
        let expected = plan.slot().template_key();
        let actual = factory.template_key();
        if actual != expected {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                QemuFixedHotCheckpointSourceDemotionError::TemplateKeyMismatch { expected, actual },
            ));
        }

        let Some(bound) = factory.take_idle_template() else {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                QemuFixedHotCheckpointSourceDemotionError::TemplateUnavailable,
            ));
        };
        let retained_key = bound.key();
        if retained_key != expected {
            factory.quarantine_failed_demotion(bound);
            return Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                QemuFixedHotCheckpointSourceDemotionError::TemplateKeyMismatch {
                    expected,
                    actual: retained_key,
                },
            ));
        }
        let (key, source) = bound.into_parts();
        match source.shutdown_for_demotion() {
            Ok(()) => Ok(()),
            Err(failure) => {
                let (template, source) = failure.into_parts();
                factory.quarantine_failed_demotion_source(key, template);
                Err(HotCheckpointTemplateDemotionFailure::new(
                    factory,
                    QemuFixedHotCheckpointSourceDemotionError::Shutdown(source),
                ))
            }
        }
    }
}

/// Failure to retire one fixed real-QEMU hot source.
#[derive(Debug, Error)]
pub enum QemuFixedHotCheckpointSourceDemotionError {
    /// The manager attempted to retire a factory from another exact slot.
    #[error("retained hot-checkpoint source key differs from its demotion plan")]
    TemplateKeyMismatch {
        /// Key named by the authenticated demotion plan.
        expected: QemuHotForkTemplateKey,
        /// Key retained by the fixed source factory.
        actual: QemuHotForkTemplateKey,
    },
    /// The fixed source is active or was already quarantined.
    #[error("fixed hot-checkpoint source is not idle for demotion")]
    TemplateUnavailable,
    /// Final event draining or source shutdown/reap failed.
    #[error("fixed hot-checkpoint source shutdown failed: {0}")]
    Shutdown(BackendError),
}

/// Demotion sink that enforces fallback authentication before source teardown.
pub struct AuthenticatedHotCheckpointDemotionSink<A, S> {
    authenticator: A,
    source: S,
}

impl<A, S> AuthenticatedHotCheckpointDemotionSink<A, S> {
    /// Composes exact fallback authentication with irreversible source teardown.
    #[must_use]
    pub const fn new(authenticator: A, source: S) -> Self {
        Self {
            authenticator,
            source,
        }
    }

    /// Returns the fallback authenticator.
    #[must_use]
    pub const fn authenticator(&self) -> &A {
        &self.authenticator
    }

    /// Returns the source demoter.
    #[must_use]
    pub const fn source_demoter(&self) -> &S {
        &self.source
    }
}

impl<F, A, S> HotCheckpointTemplateDemotionSink<F> for AuthenticatedHotCheckpointDemotionSink<A, S>
where
    A: HotCheckpointFallbackAuthenticator,
    S: HotCheckpointSourceDemoter<F>,
{
    type Error = AuthenticatedHotCheckpointDemotionError<A::Error, S::Error>;

    fn validate_fallback(
        &mut self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        self.authenticator
            .authenticate_fallback(key, fallback)
            .map_err(AuthenticatedHotCheckpointDemotionError::Fallback)
    }

    fn demote(
        &mut self,
        factory: F,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<F, Self::Error>> {
        if let Err(source) = self
            .authenticator
            .authenticate_fallback(plan.slot().template_key(), plan.fallback())
        {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                AuthenticatedHotCheckpointDemotionError::Fallback(source),
            ));
        }
        self.source.demote_source(factory, plan).map_err(|failure| {
            let (factory, source) = failure.into_parts();
            HotCheckpointTemplateDemotionFailure::new(
                factory,
                AuthenticatedHotCheckpointDemotionError::Source(source),
            )
        })
    }
}

/// Failure before or during authenticated hot-source demotion.
#[derive(Debug, Error)]
pub enum AuthenticatedHotCheckpointDemotionError<A, S> {
    /// The exact fallback identity was unavailable or inconsistent.
    #[error("hot-checkpoint fallback authentication failed")]
    Fallback(A),
    /// The source could not be reaped or its resources released.
    #[error("hot-checkpoint source demotion failed")]
    Source(S),
}

#[cfg(test)]
mod tests;
