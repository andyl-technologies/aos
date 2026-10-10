//! Prepares the distinct complete four-owner native preservation selection.
//!
//! The existing live composition and two-owner preservation interfaces remain
//! separate. Every graph is regenerated from independently installed CPU and
//! Host source policies; native admission and the complete activation barrier
//! are mandatory for both initial and restored execution.

use std::rc::Rc;

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::ActivationRecord,
    node_state::{CaptureEvidence, NativeArchiveRecord, NativeWorldFactory},
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::Id;

use super::super::{
    InstalledGem5ClosedProfile, InstalledNodeCatalog, InstalledNodeSelection,
    InstalledPreparedWorld, NodeObservedError, execution_text, refused,
};
use super::{
    host_group::{factory::IndependentNativeFactory, profile::IndependentGroupProfile},
    installed::InstalledMixedEngine,
};
use crate::node_scenario::NodeScenario;

/// Owns all inactive original owners and the independently installed capture reader.
pub struct InstalledPreparedIndependentNativeWorld {
    /// Retains the complete inactive graph and one owning all-owner realization.
    pub world: InstalledPreparedWorld,
    /// Retains immutable source policy without granting capture or execution.
    pub preservation: InstalledIndependentNativePreservation,
}

/// Retains the exact full-world installed policy and actual reserved native custody.
pub struct InstalledIndependentNativePreservation {
    factory: Rc<IndependentNativeFactory>,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledIndependentNativePreservation {
    /// Returns the selected reader; native restoration and activation remain mandatory.
    pub fn factory(&self) -> Rc<dyn NativeWorldFactory> {
        self.factory.clone()
    }

    /// Returns installed immutable closure without creating native capture proofs.
    pub fn immutable(&self) -> Box<dyn CaptureEvidence> {
        Box::new(self.factory.immutable())
    }

    /// Retains original coordinator context while publishing actual fresh owners.
    ///
    /// The returned publisher cannot synthesize node preparation or Ready. The
    /// complete staged native restoration must supply those original resources.
    ///
    /// # Errors
    /// Refuses another installed source world, native owner family or target.
    pub fn restored_publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
        source: &NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<impl crucible::node_contract::ActivationPublisher, NodeObservedError> {
        self.factory.restored_publisher(stored, source, target)
    }
}

/// Retains one fresh graph, target and inactive original source-image reservation.
pub struct InstalledIndependentNativeRestore {
    /// Borrows the independently admitted complete fresh four-owner graph.
    pub graph: Rc<AdmittedGraph>,
    /// Names the fresh locally owned target; this record grants no permission.
    pub target: ActivationRecord,
    /// Retains the actual inactive archive lease and complete installed policy.
    pub preservation: InstalledIndependentNativePreservation,
}

impl InstalledNodeCatalog {
    /// Regenerates the distinct complete x86 CPU/Clock and Script/Block scenario.
    ///
    /// # Errors
    /// Refuses another roster, backend or facet, unavailable independently
    /// installed artifacts, incompatible graph geometry or source identity.
    pub fn independent_native_scenario(
        &self,
        selections: &[InstalledNodeSelection],
    ) -> Result<NodeScenario, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        Ok(IndependentGroupProfile::build_preserving(
            InstalledGem5ClosedProfile::built_in()?,
            self,
            selections,
        )?
        .scenario)
    }

    /// Prepares every inactive owner before the one complete native activation.
    ///
    /// The original CPU must pass its installed process-image/native closure
    /// qualifier. Host preparation and native9 custody remain separate from the
    /// existing live-only profile and cannot increase its declared guarantees.
    ///
    /// # Errors
    /// Refuses changed authored demands or source identities, unsupported owners,
    /// insufficient original credits, native preparation or closure qualification.
    pub fn prepare_independent_native_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedIndependentNativeWorld, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let expected = self.independent_native_scenario(selections)?;
        if scenario.canonical_bytes()? != expected.canonical_bytes()? {
            return Err(refused(
                "independent authored preserving world differs from installed source",
            ));
        }
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let activation = Id::new(format!("activation/{}", execution_text(execution)))?;
        let live =
            engine.prepare_independent_preserving_group(self, selections, &expected, activation)?;
        let factory = Rc::new(IndependentNativeFactory::for_live(
            &live,
            engine.native.clone(),
        ));
        let graph = Rc::try_unwrap(live.graph)
            .map_err(|_| refused("independent prepared graph retained unexpected owner aliases"))?;
        Ok(InstalledPreparedIndependentNativeWorld {
            world: InstalledPreparedWorld {
                scenario: live.profile.scenario.clone(),
                graph,
                realization: live.realization,
            },
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace: live.namespace,
            },
        })
    }

    /// Reserves a fresh complete source-backed world without allocating a CPU child.
    ///
    /// Original Script/base pathnames may be gone. Their exact independently
    /// enrolled identities must remain; signed archive bytes cannot install a
    /// different source policy. Generic staging must still authenticate the whole
    /// source, reconstruct and qualify actual native owners, and publish one
    /// complete fresh barrier before executing any restored work.
    ///
    /// # Errors
    /// Refuses unavailable independent enrollment, changed signed world, missing
    /// original bodies, stale target identities or exhausted inactive custody.
    pub fn prepare_independent_native_restore(
        &self,
        selections: &[InstalledNodeSelection],
        source: NativeArchiveRecord,
    ) -> Result<InstalledIndependentNativeRestore, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let plan = engine.prepare_independent_cold_group(self, selections, source)?;
        let graph = plan.graph.clone();
        let target = plan.target.clone();
        #[cfg(test)]
        let namespace = plan.namespace.clone();
        let factory = Rc::new(IndependentNativeFactory::for_cold(
            plan,
            engine.native.clone(),
        ));
        Ok(InstalledIndependentNativeRestore {
            graph,
            target,
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace,
            },
        })
    }
}
