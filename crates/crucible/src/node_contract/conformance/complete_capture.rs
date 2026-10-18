//! Owns complete capture under the same opaque collecting plan and runtime.
//!
//! No ordinary graph/runtime escapes. Source-specific collection authorization,
//! installed complete factory, unchanged-cut geometry and original native tickets
//! are independent requirements; every unsupported implementation refuses.

use super::*;
use crate::node_admission::InstalledConformancePlan;
use crate::node_state::{
    CaptureEvidence, NativeArchive, NativeArchiveRecord, NativeWorldFactory, StateError,
    StateRequirements,
};
use crucible_node_contract::Position;

#[path = "complete_capture/construction.rs"]
mod construction;

#[path = "complete_capture/restored_source.rs"]
mod restored_source;

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
        self.capture_complete_original_lineage_with_prepared_data(
            request,
            None::<
                fn(
                    &crate::node_contract::NodeRuntime,
                    &crate::node_contract::HostSchedulingSource,
                    &crate::node_scheduling::InputPayload,
                    &crate::node_scheduling::InputPayload,
                ) -> Result<(), RuntimeError>,
            >,
        )
    }

    pub(crate) fn capture_complete_original_lineage_with_prepared_data(
        &mut self,
        request: CollectingOriginalLineageCaptureRequest<'_>,
        prepared: Option<
            impl FnOnce(
                &crate::node_contract::NodeRuntime,
                &crate::node_contract::HostSchedulingSource,
                &crate::node_scheduling::InputPayload,
                &crate::node_scheduling::InputPayload,
            ) -> Result<(), RuntimeError>,
        >,
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
            .capture_complete_original_lineage_world_prepared_data(
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
                prepared,
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
    /// Binds this verified source once to its actual fresh collecting target.
    ///
    /// All three native tickets and the Host2 ticket must already have been
    /// issued. Their real owning adopters check transfers independently. The
    /// target graph authenticates its own actual
    /// installed authority and archive-ticketed host. Matching historical plan
    /// bytes are compatibility data, never a substitute for those fresh checks.
    /// A refused first attempt remains spent; no ticket or binding is renewed.
    ///
    /// # Errors
    /// Refuses foreign creation custody, missing tickets, reused target binding,
    /// another archive/host, revoked graph or changed historical plan selection.
    pub fn bind_original_target_plan(
        &self,
        graph: &ConformanceGraph,
        host: &Rc<super::super::HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        self.original.inner.bind_collecting_target(graph, host)
    }

    /// Transfers one original native-owner ticket before target binding starts.
    ///
    /// This forwards to the same signed source allocation. It does not create
    /// fresh process custody, install a model or authorize a restoration MAC.
    ///
    /// # Errors
    /// Refuses foreign creator custody, a host/unknown owner, repeated issuance
    /// or any target-binding attempt, including a failed earlier attempt.
    pub fn take_native_ticket(
        &self,
        owner: &Id,
    ) -> Result<crate::node_state::CompleteOriginalNativeTicket, RuntimeError> {
        self.original.take_native_ticket(owner)
    }

    /// Borrows the verified source beneath its exact installed collecting graph.
    ///
    /// The borrow retains the original signed backing and private source
    /// identity. Portable equal plan documents cannot substitute another plan.
    /// This loan grants no native installation or preparation permission.
    ///
    /// # Errors
    /// Refuses foreign creation custody, another original plan or revoked graph
    /// authority. The source's own ticket/context gates remain independent.
    pub fn original_source_data(
        &self,
        graph: &ConformanceGraph,
    ) -> Result<&crate::node_state::CompleteOriginalRestorationSource, RuntimeError> {
        self.original.inner.authenticate_birth()?;
        graph
            .reauthenticate()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        if !self
            .original
            .inner
            .collecting_plan()?
            .is_some_and(|plan| plan.same_original(graph.plan()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.original.inner.authenticate_birth()?;
        Ok(&self.original)
    }

    /// Borrows the same collecting archive for an inactive restoration quote.
    ///
    /// This uses the actual live runtime, scheduler, plan and activation identity
    /// without graph/world callbacks, formatting or reconstruction. An unbound
    /// runtime remains unbound DATA; this loan issues no transaction or context.
    ///
    /// # Errors
    /// Refuses another original plan/source/runtime/activation or revoked custody.
    pub fn original_restoration_source_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<&crate::node_state::CompleteOriginalRestorationSource, RuntimeError> {
        runtime.authenticate_original_restoration_target_data(&self.original, plan, activation)?;
        Ok(&self.original)
    }

    /// Compares actual collecting archive allocations without constructing a right.
    ///
    /// # Errors
    /// Refuses a foreign creator or another source allocation, even with equal bytes.
    pub fn authenticate_same_original_source_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
    ) -> Result<(), RuntimeError> {
        self.original.inner.authenticate_birth()?;
        source.inner.authenticate_birth()?;
        if !Rc::ptr_eq(&self.original.inner, &source.inner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Prepares the actual archive-ticketed Host2 node under this same plan.
    ///
    /// The selected host source must already retain this source's one-shot
    /// ticket and belong to the actual graph's original authority. Its private
    /// node anchor is allocated once; no Ready or restored activation is issued.
    ///
    /// # Errors
    /// Refuses a foreign source/plan/host, changed target selection or repeated
    /// host preparation. A successful node must stay retained through failure.
    pub fn prepare_original_host_node(
        &self,
        graph: &ConformanceGraph,
        source: &Rc<super::super::HostSchedulingSource>,
        target: &ActivationRecord,
    ) -> Result<super::super::PreparedHostSchedulingNode, RuntimeError> {
        let archive = self.original_source_data(graph)?;
        graph
            .authenticate_exact_input_scope(source)
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        source
            .prepare_complete_collecting_restoration_node(
                &graph.graph,
                target,
                archive,
                graph.plan(),
            )
            .map_err(|error| RuntimeError::SchedulerRefused(error.reason))
    }

    /// Authenticates this exact unbound source and its actual restored Host.
    ///
    /// This is an origin/identity phase check; it observes no native liveness,
    /// performs no hashing and grants no report, preparation or installation.
    ///
    /// # Errors
    /// Refuses foreign creation, a bound/spent source, missing tickets or another
    /// archive-backed Host allocation, including an attached or prepared node.
    pub fn authenticate_original_prebirth_host_data(
        &self,
        host: &Rc<super::super::HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        self.original.authenticate_original_prebirth_host_data(host)
    }

    /// Counts the actual verified prebirth archive and same restored Host owners.
    ///
    /// The existing source backing is counted once, while the Host's independent
    /// cloned metadata and actual Rc/header are additional owners. Inline caller
    /// capsule and native-ticket handles, code factory/graph and Source3 remain
    /// separate. This observes data and grants no native or restoration rights.
    ///
    /// # Errors
    /// Refuses another original Host/source, a spent preparation phase, unknown
    /// retained backing, checked overflow or the requested-storage maximum.
    pub fn retained_original_prebirth_storage_data(
        &self,
        host: &Rc<super::super::HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original
            .retained_original_prebirth_storage_data(host, maximum)
    }

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
    /// Verifies historical complete source using its distinct installed code graph.
    ///
    /// No live ConformanceGraph or code-native Child is required. The opaque code
    /// graph retains full structural validation; the actual selected-load receipt
    /// and all source/native/common/Host codecs are verified before ticket issue.
    /// Source remains explicitly unbound until actual fresh graph preparation.
    ///
    /// # Errors
    /// Refuses foreign code/plan, absent signed-load origin, changed collecting
    /// provenance, unsupported cold codecs or exhausted finite storage.
    pub fn prepare_complete_original_archive_code_source(
        graph: &crate::node_admission::CompleteArchiveCodeGraph,
        archive: NativeArchiveRecord,
        factory: &dyn NativeWorldFactory,
        limits: super::super::HostSchedulingContinuationLimits,
    ) -> Result<CollectingCompleteRestorationSource, StateError> {
        archive
            .authenticate_complete_load_admission()
            .map_err(crate::node_state::schema)?;
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
        graph.authenticate_archive_source(factory, &archive, &historical)?;
        let source = archive.into_complete_original_restoration_source_scoped(
            &graph.graph,
            factory,
            limits,
            Some(graph.plan().retained()),
        )?;
        graph
            .plan()
            .reauthenticate()
            .map_err(crate::node_state::schema)?;
        Ok(CollectingCompleteRestorationSource { original: source })
    }

    /// Prepares complete historical source under a genuine fresh collecting plan.
    ///
    /// The actual installed code factory authenticates historical complete
    /// codecs under its code-selection graph before this issues an explicitly
    /// unbound source. Its tickets construct the actual fresh owners, then
    /// `bind_original_target_plan` binds their distinct graph. Genuine whole
    /// preparation and completed native restoration remain mandatory before Arm.
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
        archive
            .authenticate_complete_load_admission()
            .map_err(crate::node_state::schema)?;
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
        factory.authenticate_complete_collecting_archive_code_source(
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

#[path = "complete_capture/prebirth_collection17.rs"]
mod prebirth_collection17;
