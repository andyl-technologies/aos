//! Owns complete capture under the same opaque collecting plan and runtime.
//!
//! No ordinary graph/runtime escapes. Source-specific collection authorization,
//! installed complete factory, unchanged-cut geometry and original native tickets
//! are independent requirements; every unsupported implementation refuses.

use super::*;
use crate::node_state::{
    CaptureEvidence, NativeArchive, NativeArchiveRecord, NativeWorldFactory, StateError,
    StateRequirements,
};
use crucible_node_contract::Position;

/// Borrows complete capture inputs without exposing ordinary collection internals.
///
/// Coordinates and requirements are data. Only this runtime's original plan and
/// actual installed native/host factory can authorize their unchanged capture.
pub struct CollectingOriginalLineageCaptureRequest<'a> {
    /// Borrows the local source-bound archive signer and finite storage limits.
    pub archive: &'a NativeArchive,
    /// Names the unchanged full semantic cut authenticated by all four owners.
    pub cut: Position,
    /// Names the captured original event ordinal, independently checked by source.
    pub ordinal: U64,
    /// Consumes a lifetime original capture identity without resetting grants.
    pub capture_id: Id,
    /// Retains explicit conditional preservation and durable-restart requirements.
    pub requirements: StateRequirements,
    /// Borrows the complete independently retained immutable source closure.
    pub immutable: &'a dyn CaptureEvidence,
    /// Borrows the actual installed complete native/host source factory.
    pub factory: &'a dyn NativeWorldFactory,
    /// Bounds original payload, inventory and native lineage occurrences.
    pub lineage_limits: OriginalInputLineageLimits,
}

pub(crate) struct OriginalCollectingCaptureScope {
    graph: Rc<ConformanceGraph>,
    source: Rc<super::super::HostSchedulingSource>,
    activation: WorldActivation,
    capture_id: Id,
}

impl OriginalCollectingCaptureScope {
    pub(crate) fn same_graph(&self, graph: &Rc<ConformanceGraph>) -> bool {
        Rc::ptr_eq(&self.graph, graph)
    }

    pub(crate) fn plan(&self) -> &crate::node_admission::InstalledConformancePlan {
        self.graph.plan()
    }

    pub(crate) fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    pub(crate) fn source(&self) -> &super::super::HostSchedulingSource {
        &self.source
    }

    pub(crate) fn authenticate(
        &self,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        capture_id: &Id,
        factory: &dyn NativeWorldFactory,
    ) -> Result<(), StateError> {
        if capture_id != &self.capture_id
            || runtime.source_activation.activation_id != self.activation.record().activation_id
            || runtime.source_activation.world_binding_hash
                != self.activation.record().world_binding_hash
        {
            return Err(crate::node_state::schema(RuntimeError::ForeignAuthority));
        }
        self.graph
            .authenticate_complete_capture(&self.source, runtime, scheduling, capture_id)
            .map_err(|error| {
                crate::node_state::schema(RuntimeError::SchedulerRefused(error.message))
            })?;
        factory.authenticate_complete_collecting_capture(
            self.graph.plan(),
            &self.source,
            &self.graph.graph,
            runtime,
            scheduling,
        )?;
        self.source
            .authenticate_current()
            .map_err(|error| crate::node_state::schema(error.reason))?;
        self.graph.authenticate_current_scope().map_err(|error| {
            crate::node_state::schema(RuntimeError::SchedulerRefused(error.message))
        })
    }

    pub(crate) fn provenance(&self) -> serde_json::Value {
        let plan = self.graph.plan().evidence();
        serde_json::json!({
            "schema":"source-owned.collecting-complete-capture/1",
            "plan":plan.plan_ref,"refused":plan.refused_ref,
            "sources":plan.sources,"world":plan.world,
            "ordinary_acceptance":false,
        })
    }
}

impl ConformanceRuntime {
    /// Captures complete original state solely under its actual collecting custody.
    ///
    /// The same graph, runtime, host source and opaque activation stay retained.
    /// No modeled grant is created, and the signed provenance retains the exact
    /// Refused plan instead of implying ordinary behavioral acceptance.
    ///
    /// # Errors
    /// Defaults to source/factory refusal. Refuses absent exact host/activation,
    /// foreign or stale current custody, incomplete native geometry, exhausted
    /// finite credit or uncertain capture. Original tickets stay in this runtime.
    pub fn capture_complete_original_lineage(
        &mut self,
        request: CollectingOriginalLineageCaptureRequest<'_>,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.current().map_err(crate::node_state::schema)?;
        let source = Rc::clone(
            self.exact_inputs
                .as_ref()
                .ok_or_else(|| crate::node_state::schema(RuntimeError::UnsupportedFacet))?,
        );
        source
            .authenticate_complete_preparation_source(source.world())
            .map_err(|error| crate::node_state::schema(error.reason))?;
        source
            .authenticate_current()
            .map_err(|error| crate::node_state::schema(error.reason))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| crate::node_state::schema(RuntimeError::NotActivated))?
            .clone();
        let scope = OriginalCollectingCaptureScope {
            graph: Rc::clone(&self.graph),
            source,
            activation: activation.clone(),
            capture_id: request.capture_id.clone(),
        };
        self.runtime
            .authenticate_complete_capture_purpose(Some(&scope))
            .map_err(crate::node_state::schema)?;
        request
            .archive
            .capture_complete_original_lineage_world_scoped(
                crate::node_state::OriginalLineageCaptureRequest {
                    graph: &self.graph.graph,
                    runtime: &mut self.runtime,
                    activation: &activation,
                    cut: request.cut,
                    ordinal: request.ordinal,
                    capture_id: request.capture_id,
                    requirements: request.requirements,
                    immutable: request.immutable,
                    factory: request.factory,
                    lineage_limits: request.lineage_limits,
                },
                Some(&scope),
            )
    }
}

/// Retains a complete archive solely for fresh collecting-world restoration.
///
/// The signed historical Refused plan stays distinct from the actual new opaque
/// plan and genuine fresh native preparation. This handle exposes no ordinary
/// runtime/graph or accepted qualifier conversion.
pub struct CollectingCompleteRestorationSource {
    original: crate::node_state::CompleteOriginalRestorationSource,
}

impl CollectingCompleteRestorationSource {
    /// Issues the single source-owned Host2 archive ticket without cloning bodies.
    ///
    /// # Errors
    /// Refuses foreign creation custody or a previous ticket transfer. Native
    /// target/context installation remains an independent requirement.
    pub fn take_host_ticket(
        &self,
    ) -> Result<crate::node_state::CompleteOriginalHostTicket, RuntimeError> {
        self.original.take_host_ticket()
    }
}

impl ConformanceRuntime {
    /// Prepares complete historical source under a genuine fresh collecting plan.
    ///
    /// The concrete factory must authenticate held fresh native registrations and
    /// historical complete codecs before this method issues the Host2 source.
    /// New Host source and private Runtime7 context are checked later before Arm.
    ///
    /// # Errors
    /// Defaults to refusal; rejects missing collecting provenance, changed
    /// original plan/audit/source/world, unsupported fresh adopter or finite excess.
    pub fn prepare_complete_original_restoration_source(
        graph: &ConformanceGraph,
        archive: NativeArchiveRecord,
        factory: &dyn NativeWorldFactory,
        limits: super::super::HostSchedulingContinuationLimits,
    ) -> Result<CollectingCompleteRestorationSource, StateError> {
        graph.reauthenticate().map_err(|error| {
            crate::node_state::schema(RuntimeError::SchedulerRefused(error.message))
        })?;
        let historical = archive
            .collecting_complete_capture_provenance()?
            .ok_or_else(|| crate::node_state::schema(RuntimeError::ForeignAuthority))?;
        let plan = graph.plan().evidence();
        if historical.plan != *plan.plan_ref
            || historical.refused != *plan.refused_ref
            || historical.sources != plan.sources
            || historical.world != *plan.world
        {
            return Err(crate::node_state::schema(RuntimeError::ForeignAuthority));
        }
        factory.authenticate_complete_collecting_restoration_source(
            graph.plan(),
            &graph.graph,
            &archive,
            &historical,
        )?;
        graph.authenticate_current_scope().map_err(|error| {
            crate::node_state::schema(RuntimeError::SchedulerRefused(error.message))
        })?;
        let source = archive.into_complete_original_restoration_source_scoped(
            &graph.graph,
            factory,
            limits,
            Some(graph.plan().retained()),
        )?;
        Ok(CollectingCompleteRestorationSource { original: source })
    }
}

impl ConformanceRuntime {
    /// Prepares exact historical journals beneath this same fresh collecting runtime.
    ///
    /// The source retains its actual fresh plan; private runtime/plan identity is
    /// checked before binding or any native restoration callback. Missing source
    /// adopter and target mechanisms retain their default refusals.
    ///
    /// # Errors
    /// Refuses foreign/reused target, stale source/native custody, incomplete
    /// original journals or exhausted finite credit. Failure retains this capsule.
    pub fn prepare_complete_original_lineage_restoration<'a>(
        &mut self,
        source: &'a CollectingCompleteRestorationSource,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        target: &ActivationRecord,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: OriginalLineageRestorationLimits,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        self.current()?;
        self.runtime.prepare_complete_original_lineage_restoration(
            &source.original,
            scheduling,
            target,
            verifier,
            limits,
        )
    }
}
