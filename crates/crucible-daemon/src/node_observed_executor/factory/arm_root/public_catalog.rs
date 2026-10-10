//! Compiles the fixed Root/Clock selection before genuine native preparation.
//!
//! Immutable installed artifacts define the scenario. Current opaque native
//! qualification and complete original public readiness remain mandatory before
//! activation; metadata selection never provides those authorities.

use std::rc::Rc;

use crucible_campaign::ExecutionId;

use super::super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, measure_executable, refused,
};
use super::{
    custody::RootCustodyQueue, factory::RootNativeFactory, installed::RootInstalledEngine,
    profile::RootWorldProfile, publication::RootPublisher, retirement::RootRetirementScope,
};
use crate::node_scenario::NodeScenario;

/// Owns the original inactive Root/Clock realization and its installed capture policy.
pub struct InstalledPreparedRootWorld {
    /// Retains both actual native owners beneath their pre-reserved runtime slot.
    pub world: InstalledPreparedWorld,
    /// Retains independently installed immutable policy, separate from live authority.
    pub preservation: InstalledRootPreservation,
}

/// Retains the installed Root codec without minting native capture or execution seals.
pub struct InstalledRootPreservation {
    pub(super) factory: Rc<RootNativeFactory>,
    target: crucible::node_contract::ActivationRecord,
    retirement: RootRetirementScope,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledRootPreservation {
    /// Returns the source-installed factory with its original owning native lease.
    pub fn factory(&self) -> Rc<dyn crucible::node_state::NativeWorldFactory> {
        self.factory.clone()
    }

    /// Couples initial publication to this actual inactive owner reservation.
    ///
    /// # Errors
    /// Refuses an unavailable original reservation or another activation target.
    pub fn publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Result<Box<dyn crucible::node_contract::ActivationPublisher>, NodeObservedError> {
        let queue = self.factory.native_queue();
        queue.publication_knowledge(&self.target)?;
        Ok(Box::new(RootPublisher::for_prepared(
            stored,
            queue,
            self.target.clone(),
        )))
    }

    /// Consumes the same active runtime beneath its original containment scopes.
    ///
    /// # Errors
    /// Returns the original runtime and preservation handle for a foreign graph,
    /// activation or opaque runtime authority. Successful containment grants no
    /// continuation, publication or namespace release permission.
    pub fn begin_retirement(
        self,
        mut runtime: crucible::node_contract::NodeRuntime,
        graph: &crucible::node_admission::AdmittedGraph,
        activation: &crucible::node_contract::WorldActivation,
    ) -> Result<super::InstalledRootRetirement, Box<RootInitialRetirementFailure>> {
        let validate = (|| {
            if activation.record() != &self.target {
                return Err(refused("Root retirement names another original activation"));
            }
            self.factory
                .check_graph(graph)
                .map_err(|error| refused(&error.to_string()))?;
            runtime
                .scheduler(graph, activation)
                .map_err(|error| refused(&error.to_string()))?;
            Ok(())
        })();
        if let Err(error) = validate {
            return Err(Box::new(RootInitialRetirementFailure {
                error,
                runtime,
                preservation: self,
            }));
        }
        let quarantine = runtime.into_quarantine();
        Ok(self.retirement.begin(self.factory, Some(quarantine)))
    }

    /// Returns bounded immutable bytes and independently recognized dependency rows.
    pub fn immutable(&self) -> Box<dyn crucible::node_state::CaptureEvidence> {
        Box::new(self.factory.immutable())
    }
}

/// Retains the same active world after a retirement authority mismatch.
pub struct RootInitialRetirementFailure {
    /// Describes the rejected original activation or runtime association.
    pub error: NodeObservedError,
    /// Owns the unchanged original runtime and its pre-reserved supervisor slot.
    pub runtime: crucible::node_contract::NodeRuntime,
    /// Retains the same installed factory and pinned original namespace.
    pub preservation: InstalledRootPreservation,
}

fn validate_selection(selections: &[InstalledNodeSelection]) -> Result<(), NodeObservedError> {
    let [clock, root] = selections else {
        return Err(refused(
            "Root selection requires exactly its Clock and Root owners",
        ));
    };
    if clock.node.as_str() != "clock"
        || clock.owner.as_str() != "owner/clock"
        || !matches!(clock.kind, InstalledNodeKind::HostClock)
        || root.node.as_str() != "root"
        || root.owner.as_str() != "owner/root"
        || !matches!(root.kind, InstalledNodeKind::Gem5ArmRoot)
    {
        return Err(refused(
            "Root selection differs from its fixed source-owned roster",
        ));
    }
    Ok(())
}

pub(in super::super) fn scenario(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
) -> Result<NodeScenario, NodeObservedError> {
    validate_selection(selections)?;
    if measure_executable(&catalog.host_executable)? != catalog.host_identity {
        return Err(refused(
            "installed Root catalog host changed before selection",
        ));
    }
    Ok(RootWorldProfile::build_installed(&catalog.host_identity)?.scenario)
}

pub(in super::super) fn prepare_native(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    _execution: ExecutionId,
) -> Result<InstalledPreparedRootWorld, NodeObservedError> {
    let selected = scenario(catalog, selections)?;
    if selected.canonical_bytes()? != authored.canonical_bytes()? {
        return Err(refused(
            "authored Root world differs from its independently installed selection",
        ));
    }
    let engine =
        RootInstalledEngine::with_runtime(catalog.socket_parent.clone(), catalog.custody.clone())?;
    let live = engine.prepare_initial()?;
    if live.profile.scenario.canonical_bytes()? != selected.canonical_bytes()? {
        return Err(refused(
            "actual Root preparation changed its admitted immutable selection",
        ));
    }
    let factory = Rc::new(RootNativeFactory::for_live(&live, engine.native.clone()));
    let retirement = RootRetirementScope::new(
        live.target.clone(),
        &live.namespace,
        engine.native.clone(),
        engine.runtime.clone(),
    )?;
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("Root graph retained unexpected preparation aliases"))?;
    Ok(InstalledPreparedRootWorld {
        world: InstalledPreparedWorld {
            scenario: live.profile.scenario.clone(),
            graph,
            realization: live.realization,
        },
        preservation: InstalledRootPreservation {
            factory,
            target: live.target,
            retirement,
            #[cfg(test)]
            namespace: live.namespace,
        },
    })
}

pub(in super::super) fn publisher(
    stored: crate::node_observed_executor::StoredWorldActivationPublisher,
) -> Result<Box<dyn crucible::node_contract::ActivationPublisher>, NodeObservedError> {
    Ok(Box::new(RootPublisher::for_initial(
        stored,
        RootCustodyQueue::installed()?,
    )))
}

/// Owns an inactive installed Root restore plan with its original signed backing.
pub struct InstalledRootRestore {
    /// Retains the independently admitted fresh graph and complete owner roster.
    pub graph: Rc<crucible::node_admission::AdmittedGraph>,
    /// Retains the fresh target identity without providing an activation token.
    pub target: crucible::node_contract::ActivationRecord,
    archive: crucible::node_state::NativeArchiveRecord,
    pub(super) factory: Rc<RootNativeFactory>,
    native: RootCustodyQueue,
    custody: crucible::node_contract::RuntimeCustodyQueue,
    retirement: RootRetirementScope,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledRootRestore {
    /// Consumes the original restored wrapper before polling retained reclamation.
    ///
    /// # Errors
    /// Returns both owning values unchanged when the restored activation differs
    /// from this reserved target. Successful transfer preserves runtime/staging
    /// Drop custody and does not certify that cleanup has completed.
    pub fn begin_retirement(
        self,
        restored: crucible::node_state::RestoredWorld,
    ) -> Result<super::InstalledRootRetirement, Box<RootRestoredRetirementFailure>> {
        if restored.activation().record() != &self.target {
            return Err(Box::new(RootRestoredRetirementFailure {
                error: refused("Root retirement names another restored activation"),
                restored,
                restore: self,
            }));
        }
        // The complete owning wrapper transfers its actual runtime and staging
        // obligations to the supervisors; no NodeRuntime is extracted or cloned.
        drop(restored);
        Ok(self.retirement.begin(self.factory, None))
    }

    /// Returns the installed policy that independently authenticates the original source.
    pub fn factory(&self) -> Rc<dyn crucible::node_state::NativeWorldFactory> {
        self.factory.clone()
    }

    /// Creates a driver beneath the already retained original native image lease.
    ///
    /// # Errors
    /// Refuses a changed source/world binding or unsupported selected semantics.
    pub fn driver(
        &self,
    ) -> Result<crucible::node_state::NativeWorldRestoreDriver, crucible::node_state::StateError>
    {
        crucible::node_state::NativeWorldRestoreDriver::new(
            self.graph.clone(),
            self.archive.clone(),
            self.factory.clone(),
            self.custody.clone(),
        )
    }

    /// Couples complete durable publication to the original signed preparation ancestry.
    ///
    /// # Errors
    /// Refuses missing or mismatched source preparation/coordinator bodies.
    pub fn publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Result<Box<dyn crucible::node_contract::ActivationPublisher>, NodeObservedError> {
        Ok(Box::new(RootPublisher::for_restore(
            stored,
            self.native.clone(),
            &self.archive,
            &self.target,
        )?))
    }
}

/// Retains the same restored world after a retirement target mismatch.
pub struct RootRestoredRetirementFailure {
    /// Describes the rejected original restore target association.
    pub error: NodeObservedError,
    /// Owns the original restored runtime and native staging capsule.
    pub restored: crucible::node_state::RestoredWorld,
    /// Retains the original installed source, target and retirement scopes.
    pub restore: InstalledRootRestore,
}

pub(in super::super) fn prepare_restore(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    archive: crucible::node_state::NativeArchiveRecord,
) -> Result<InstalledRootRestore, NodeObservedError> {
    let expected = scenario(catalog, selections)?;
    if expected.world.identity()? != archive.manifest().world_binding_hash {
        return Err(refused(
            "Root restore source differs from ordinary installed selection",
        ));
    }
    let engine =
        RootInstalledEngine::with_runtime(catalog.socket_parent.clone(), catalog.custody.clone())?;
    let plan = engine.prepare_cold(archive.clone())?;
    let graph = plan.graph.clone();
    let target = plan.target.clone();
    #[cfg(test)]
    let namespace = plan.namespace.clone();
    let retirement = RootRetirementScope::new(
        target.clone(),
        &plan.namespace,
        engine.native.clone(),
        engine.runtime.clone(),
    )?;
    let factory = Rc::new(RootNativeFactory::for_cold(plan, engine.native.clone()));
    Ok(InstalledRootRestore {
        graph,
        target,
        archive,
        factory,
        native: engine.native,
        custody: engine.runtime,
        retirement,
        #[cfg(test)]
        namespace,
    })
}

impl std::fmt::Debug for RootInitialRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootInitialRetirementFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RootRestoredRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootRestoredRetirementFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
