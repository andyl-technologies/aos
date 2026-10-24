//! Compiles the fixed X86Root/Clock selection before genuine native preparation.
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
    custody::X86RootCustodyQueue, factory::X86RootNativeFactory, installed::X86RootInstalledEngine,
    profile::X86RootWorldProfile, publication::X86RootPublisher,
    retirement::X86RootRetirementScope,
};
use crate::node_scenario::NodeScenario;

/// Owns the original inactive X86Root/Clock realization and its installed capture policy.
pub struct InstalledPreparedX86RootWorld {
    /// Retains both actual native owners beneath their pre-reserved runtime slot.
    pub world: InstalledPreparedWorld,
    /// Retains independently installed immutable policy, separate from live authority.
    pub preservation: InstalledX86RootPreservation,
}

/// Retains the installed X86Root codec without minting native capture or execution seals.
pub struct InstalledX86RootPreservation {
    pub(super) factory: Rc<X86RootNativeFactory>,
    target: crucible_engine::node_contract::ActivationRecord,
    retirement: X86RootRetirementScope,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledX86RootPreservation {
    /// Reads this retained target's native cleanup state without advancing it.
    ///
    /// The snapshot grants no reclamation or namespace-release authority. It
    /// neither probes a caller PID nor polls, commands, or reaps the native peer.
    ///
    /// # Errors
    /// Refuses an absent original queue entry; the same owning handle is retained.
    pub fn cleanup_status(
        &self,
    ) -> Result<super::InstalledX86RootCleanupStatus, NodeObservedError> {
        self.retirement.cleanup_status()
    }

    /// Returns the source-installed factory with its original owning native lease.
    pub fn factory(&self) -> Rc<dyn crucible_engine::node_state::NativeWorldFactory> {
        self.factory.clone()
    }

    /// Couples initial publication to this actual inactive owner reservation.
    ///
    /// # Errors
    /// Refuses an unavailable original reservation or another activation target.
    pub fn publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Result<Box<dyn crucible_engine::node_contract::ActivationPublisher>, NodeObservedError>
    {
        let queue = self.factory.native_queue();
        queue.publication_knowledge(&self.target)?;
        Ok(Box::new(X86RootPublisher::for_prepared(
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
        mut runtime: crucible_engine::node_contract::NodeRuntime,
        graph: &crucible_engine::node_admission::AdmittedGraph,
        activation: &crucible_engine::node_contract::WorldActivation,
    ) -> Result<super::InstalledX86RootRetirement, Box<X86RootInitialRetirementFailure>> {
        let validate = (|| {
            if activation.record() != &self.target {
                return Err(refused(
                    "X86Root retirement names another original activation",
                ));
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
            return Err(Box::new(X86RootInitialRetirementFailure {
                error,
                runtime,
                preservation: self,
            }));
        }
        let quarantine = runtime.into_quarantine();
        Ok(self.retirement.begin(self.factory, Some(quarantine)))
    }

    /// Returns bounded immutable bytes and independently recognized dependency rows.
    pub fn immutable(&self) -> Box<dyn crucible_engine::node_state::CaptureEvidence> {
        Box::new(self.factory.immutable())
    }
}

/// Retains the same active world after a retirement authority mismatch.
pub struct X86RootInitialRetirementFailure {
    /// Describes the rejected original activation or runtime association.
    pub error: NodeObservedError,
    /// Owns the unchanged original runtime and its pre-reserved supervisor slot.
    pub runtime: crucible_engine::node_contract::NodeRuntime,
    /// Retains the same installed factory and pinned original namespace.
    pub preservation: InstalledX86RootPreservation,
}

fn validate_selection(selections: &[InstalledNodeSelection]) -> Result<(), NodeObservedError> {
    let [clock, root] = selections else {
        return Err(refused(
            "X86Root selection requires exactly its Clock and X86Root owners",
        ));
    };
    if clock.node.as_str() != "clock"
        || clock.owner.as_str() != "owner/clock"
        || !matches!(clock.kind, InstalledNodeKind::HostClock)
        || root.node.as_str() != "root"
        || root.owner.as_str() != "owner/root"
        || !matches!(root.kind, InstalledNodeKind::Gem5X86Root)
    {
        return Err(refused(
            "X86Root selection differs from its fixed source-owned roster",
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
            "installed X86Root catalog host changed before selection",
        ));
    }
    Ok(X86RootWorldProfile::build_installed(&catalog.host_identity)?.scenario)
}

pub(in super::super) fn prepare_native(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    _execution: ExecutionId,
) -> Result<InstalledPreparedX86RootWorld, NodeObservedError> {
    let selected = scenario(catalog, selections)?;
    if selected.canonical_bytes()? != authored.canonical_bytes()? {
        return Err(refused(
            "authored X86Root world differs from its independently installed selection",
        ));
    }
    let engine = X86RootInstalledEngine::with_runtime(
        catalog.socket_parent.clone(),
        catalog.custody.clone(),
    )?;
    let live = engine.prepare_initial()?;
    if live.profile.scenario.canonical_bytes()? != selected.canonical_bytes()? {
        return Err(refused(
            "actual X86Root preparation changed its admitted immutable selection",
        ));
    }
    let factory = Rc::new(X86RootNativeFactory::for_live(&live, engine.native.clone()));
    let retirement = X86RootRetirementScope::new(
        live.target.clone(),
        &live.namespace,
        engine.native.clone(),
        engine.runtime.clone(),
    )?;
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("X86Root graph retained unexpected preparation aliases"))?;
    Ok(InstalledPreparedX86RootWorld {
        world: InstalledPreparedWorld {
            scenario: live.profile.scenario.clone(),
            graph,
            realization: live.realization,
        },
        preservation: InstalledX86RootPreservation {
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
) -> Result<Box<dyn crucible_engine::node_contract::ActivationPublisher>, NodeObservedError> {
    Ok(Box::new(X86RootPublisher::for_initial(
        stored,
        X86RootCustodyQueue::installed()?,
    )))
}

/// Owns an inactive installed X86Root restore plan with its original signed backing.
pub struct InstalledX86RootRestore {
    /// Retains the independently admitted fresh graph and complete owner roster.
    pub graph: Rc<crucible_engine::node_admission::AdmittedGraph>,
    /// Retains the fresh target identity without providing an activation token.
    pub target: crucible_engine::node_contract::ActivationRecord,
    archive: crucible_engine::node_state::NativeArchiveRecord,
    pub(super) factory: Rc<X86RootNativeFactory>,
    native: X86RootCustodyQueue,
    custody: crucible_engine::node_contract::RuntimeCustodyQueue,
    retirement: X86RootRetirementScope,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledX86RootRestore {
    /// Reads this retained target's native cleanup state without advancing it.
    ///
    /// The snapshot grants no reclamation or namespace-release authority. It
    /// neither probes a caller PID nor polls, commands, or reaps the native peer.
    ///
    /// # Errors
    /// Refuses an absent original queue entry; the same owning handle is retained.
    pub fn cleanup_status(
        &self,
    ) -> Result<super::InstalledX86RootCleanupStatus, NodeObservedError> {
        self.retirement.cleanup_status()
    }

    /// Consumes the original restored wrapper before polling retained reclamation.
    ///
    /// # Errors
    /// Returns both owning values unchanged when the restored activation differs
    /// from this reserved target. Successful transfer preserves runtime/staging
    /// Drop custody and does not certify that cleanup has completed.
    pub fn begin_retirement(
        self,
        restored: crucible_engine::node_state::RestoredWorld,
    ) -> Result<super::InstalledX86RootRetirement, Box<X86RootRestoredRetirementFailure>> {
        if restored.activation().record() != &self.target {
            return Err(Box::new(X86RootRestoredRetirementFailure {
                error: refused("X86Root retirement names another restored activation"),
                restored,
                restore: self,
            }));
        }
        // The complete owning wrapper transfers its actual runtime and staging
        // obligations to the supervisors; no NodeRuntime is extracted or cloned.
        drop(restored);
        Ok(self.retirement.begin(self.factory, None))
    }

    /// Consumes a restore plan whose exact original cold lease has not entered staging.
    ///
    /// No missing-world or missing-activation observation grants this path. The
    /// installed factory must still own the original unused reservation, signed
    /// image backing and pinned target. Successful transfer disables staging and
    /// retains that lease until authentic runtime cleanup and namespace release.
    ///
    /// # Errors
    /// Returns this same owning plan when the target changed, the lease entered
    /// staging or is borrowed, publication began, or native custody was allocated.
    pub fn begin_unstarted_retirement(
        self,
    ) -> Result<super::InstalledX86RootRetirement, Box<X86RootUnstartedRetirementFailure>> {
        if self.target != self.retirement.target {
            return Err(Box::new(X86RootUnstartedRetirementFailure {
                error: refused("X86Root unstarted retirement target differs from original scope"),
                restore: self,
            }));
        }
        let original = match self.factory.take_unstarted(
            &self.retirement.target,
            &self.archive,
            self.retirement.namespace(),
        ) {
            Ok(original) => original,
            Err(error) => {
                return Err(Box::new(X86RootUnstartedRetirementFailure {
                    error,
                    restore: self,
                }));
            }
        };
        Ok(self.retirement.begin_unstarted(self.factory, original))
    }

    /// Returns the installed policy that independently authenticates the original source.
    pub fn factory(&self) -> Rc<dyn crucible_engine::node_state::NativeWorldFactory> {
        self.factory.clone()
    }

    /// Creates a driver beneath the already retained original native image lease.
    ///
    /// # Errors
    /// Refuses a changed source/world binding or unsupported selected semantics.
    pub fn driver(
        &self,
    ) -> Result<
        crucible_engine::node_state::NativeWorldRestoreDriver,
        crucible_engine::node_state::StateError,
    > {
        crucible_engine::node_state::NativeWorldRestoreDriver::new(
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
    ) -> Result<Box<dyn crucible_engine::node_contract::ActivationPublisher>, NodeObservedError>
    {
        Ok(Box::new(X86RootPublisher::for_restore(
            stored,
            self.native.clone(),
            &self.archive,
            &self.target,
        )?))
    }
}

/// Retains the original restore plan when unused-lease retirement is refused.
pub struct X86RootUnstartedRetirementFailure {
    /// Describes the unmet original target, lease or custody precondition.
    pub error: NodeObservedError,
    /// Owns the same signed image backing, factory, queues and namespace pin.
    pub restore: InstalledX86RootRestore,
}

/// Retains the same restored world after a retirement target mismatch.
pub struct X86RootRestoredRetirementFailure {
    /// Describes the rejected original restore target association.
    pub error: NodeObservedError,
    /// Owns the original restored runtime and native staging capsule.
    pub restored: crucible_engine::node_state::RestoredWorld,
    /// Retains the original installed source, target and retirement scopes.
    pub restore: InstalledX86RootRestore,
}

pub(in super::super) fn prepare_restore(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    archive: crucible_engine::node_state::NativeArchiveRecord,
) -> Result<InstalledX86RootRestore, NodeObservedError> {
    let expected = scenario(catalog, selections)?;
    if expected.world.identity()? != archive.manifest().world_binding_hash {
        return Err(refused(
            "X86Root restore source differs from ordinary installed selection",
        ));
    }
    let engine = X86RootInstalledEngine::with_runtime(
        catalog.socket_parent.clone(),
        catalog.custody.clone(),
    )?;
    let plan = engine.prepare_cold(archive.clone())?;
    let graph = plan.graph.clone();
    let target = plan.target.clone();
    #[cfg(test)]
    let namespace = plan.namespace.clone();
    let retirement = X86RootRetirementScope::new(
        target.clone(),
        &plan.namespace,
        engine.native.clone(),
        engine.runtime.clone(),
    )?;
    let factory = Rc::new(X86RootNativeFactory::for_cold(plan, engine.native.clone()));
    Ok(InstalledX86RootRestore {
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

impl std::fmt::Debug for X86RootInitialRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X86RootInitialRetirementFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for X86RootRestoredRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X86RootRestoredRetirementFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for X86RootUnstartedRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X86RootUnstartedRetirementFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
