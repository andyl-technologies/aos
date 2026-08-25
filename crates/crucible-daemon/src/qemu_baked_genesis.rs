//! Authenticated native baked-genesis checkpoints for production replay.
//!
//! A concrete replay-oracle worker needs an independently captured thin base
//! before it can compare a newly paused fat checkpoint. This module turns the
//! ordinary guarded fresh-lifecycle capture into that native, read-only
//! capability. It deliberately does not publish a campaign root or advertise
//! exact restore; the packaged replay factory remains responsible for
//! materializing these artifacts under its disjoint thin binding.

use std::collections::BTreeSet;

use crucible::{Configuration, ContentHash, NodeId, ScenarioDefForm};
use crucible_api::{
    LifecycleApiError, ProductionExactCheckpointClosure, ProductionExactCheckpointReplayTargets,
};
use thiserror::Error;

use crate::{
    AttemptExecutionContext, CapturedAttemptCheckpoint, QemuFreshAttemptLifecycleFactory,
    QemuFreshGenesisCheckpointError, capture_fresh_genesis_checkpoint_candidate,
};

/// One completely authenticated native baked-genesis checkpoint closure.
///
/// The capability retains the production lifecycle's bounded native closure,
/// not a second unversioned cache format. It exposes no mutation or campaign-ref
/// authority. Every replay cursor reauthenticates the closure before returning
/// its first node target.
#[derive(Clone)]
pub struct ProductionBakedGenesisCheckpoint {
    world: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    closure: ProductionExactCheckpointClosure,
}

impl std::fmt::Debug for ProductionBakedGenesisCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionBakedGenesisCheckpoint")
            .field("world", &self.world)
            .field("scenario", &self.scenario)
            .field("configuration", &self.configuration)
            .field("closure", &self.closure.identity())
            .finish_non_exhaustive()
    }
}

/// Rejection while admitting a fresh capture as baked-genesis authority.
#[derive(Debug, Error)]
pub enum ProductionBakedGenesisCheckpointError {
    /// A compatibility single-node capture cannot back production replay.
    #[error("baked genesis requires a version-four production checkpoint closure")]
    CompatibilityCapture,
    /// The native closure failed complete production authentication.
    #[error(transparent)]
    Closure(#[from] LifecycleApiError),
    /// The closure names another scenario or a non-genesis configuration.
    #[error("baked-genesis closure does not authenticate the exact scenario genesis")]
    SemanticBasisMismatch,
    /// The fresh closure omitted one World VM or named a foreign/duplicate VM.
    #[error("baked-genesis closure live-node set does not equal the scenario World")]
    NodeSetMismatch,
}

/// Failure while capturing and admitting one production baked genesis.
#[derive(Debug, Error)]
pub enum ProductionBakedGenesisCaptureError<E> {
    /// Guarded fresh-lifecycle capture or teardown failed.
    #[error(transparent)]
    Capture(#[from] QemuFreshGenesisCheckpointError<E>),
    /// The completed capture did not satisfy baked-genesis admission.
    #[error(transparent)]
    Admission(#[from] ProductionBakedGenesisCheckpointError),
}

impl ProductionBakedGenesisCheckpoint {
    /// Admits one fresh exact capture as a native baked-genesis checkpoint.
    ///
    /// Admission requires the version-four production variant, complete closure
    /// authentication, exact scenario genesis, and exactly one live target for
    /// every VM in the World. No destination or campaign store is written.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBakedGenesisCheckpointError`] when the capture uses
    /// the legacy single-node format or any closure, semantic-basis, or node-set
    /// invariant fails.
    pub fn admit(
        source: &ScenarioDefForm,
        capture: CapturedAttemptCheckpoint,
    ) -> Result<Self, ProductionBakedGenesisCheckpointError> {
        let CapturedAttemptCheckpoint::Production(closure) = capture else {
            return Err(ProductionBakedGenesisCheckpointError::CompatibilityCapture);
        };
        let closure = *closure;
        let scenario = source.scenario_def();
        let genesis = Configuration::genesis(scenario.clone());
        if closure.scenario() != scenario.id() || closure.configuration() != genesis.id() {
            return Err(ProductionBakedGenesisCheckpointError::SemanticBasisMismatch);
        }

        let mut expected = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| node.id.clone())
            .collect::<BTreeSet<NodeId>>();
        if expected.is_empty() || expected.len() > crate::MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
        }
        let mut targets = closure.replay_oracle_targets()?;
        while let Some(target) = targets.next_target()? {
            if !expected.remove(target.node())
                || target.snapshot().checkpoint().configuration != genesis.id()
            {
                return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
            }
        }
        if !expected.is_empty() {
            return Err(ProductionBakedGenesisCheckpointError::NodeSetMismatch);
        }

        Ok(Self {
            world: source.world().id,
            scenario: scenario.id(),
            configuration: genesis.id(),
            closure,
        })
    }

    /// Returns the exact World identity whose ready boundary was captured.
    #[must_use]
    pub const fn world(&self) -> ContentHash {
        self.world
    }

    /// Returns the authenticated scenario identity.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact genesis configuration identity.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the native closure identity retained by this capability.
    #[must_use]
    pub const fn closure_identity(&self) -> ContentHash {
        self.closure.identity()
    }

    /// Authenticates a bounded cursor over baked targets in World node order.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the retained native closure became
    /// unavailable, corrupt, or inconsistent after admission.
    pub fn replay_targets(
        &self,
    ) -> Result<ProductionExactCheckpointReplayTargets<'_>, LifecycleApiError> {
        self.closure.replay_oracle_targets()
    }

    /// Consumes the baked capability into its read-only production closure.
    #[must_use]
    pub fn into_closure(self) -> ProductionExactCheckpointClosure {
        self.closure
    }
}

/// Captures and admits one production baked-genesis checkpoint.
///
/// The helper composes the guarded fresh-lifecycle capture with complete native
/// closure admission. It performs no modeled quantum and returns only after the
/// QEMU lifecycle has been torn down.
///
/// # Errors
///
/// Returns [`ProductionBakedGenesisCaptureError`] when lifecycle startup,
/// capture, teardown, or complete baked-genesis admission fails.
pub fn capture_production_baked_genesis<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<ProductionBakedGenesisCheckpoint, ProductionBakedGenesisCaptureError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let capture = capture_fresh_genesis_checkpoint_candidate(factory, source, context)?;
    ProductionBakedGenesisCheckpoint::admit(source, capture).map_err(Into::into)
}
