//! Installs only historical archive-code validation before any native launch.
//!
//! This wrapper shares the existing complete cold verifier and typed codecs. It
//! implements no live Capture, native restoration, staging, geometry or Ready
//! gate. Its private inner owner never enrolls as the scene's live factory.

mod precredit;

mod restored_source;

use super::*;
use crucible_engine::node_admission::{
    AdmissionLimits, CompleteArchiveCodeGraph, admit_complete_archive_code_graph,
};
use crucible_engine::node_contract::{
    CollectingCompleteRestorationSource, HostSchedulingContinuationLimits,
};
use crucible_engine::node_state::{
    CollectingCompleteCaptureProvenance, CompleteOriginalArchiveValidation,
};
use crucible_node_format::canonical;

/// Retains actual installed code solely for complete historical archive verification.
///
/// The installer authenticates real original authority, Source3/Host selection,
/// measured files and finite cold limits. It invokes no post-Hello support check
/// and creates no native actor. Every live NativeWorldFactory hook remains
/// explicitly refusing; no inner factory/ordinary graph conversion is exposed.
#[must_use = "retain installed code ownership through historical validation"]
pub struct PacketCompleteArchiveCodeFactory {
    // The sibling prebirth capsule needs this original owner; it is never public.
    pub(super) inner: Rc<PacketCompleteCaptureFactory>,
    graph: RefCell<Option<std::rc::Weak<CompleteArchiveCodeGraph>>>,
}

impl PacketCompleteArchiveCodeFactory {
    /// Installs the concrete original historical-code factory without Child.
    ///
    /// # Errors
    /// Refuses foreign actual authority/plan/source, changed measured code or
    /// zero finite limits. This does not admit later startup/query allocations.
    pub fn install(
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: Rc<InstalledConformancePlan>,
        limits: NativeArchiveLimits,
    ) -> Result<Rc<Self>, StateError> {
        authority.current().map_err(error)?;
        plan.authenticate_authority(authority.as_ref())
            .map_err(error)?;
        if limits.state.maximum_record_bytes == 0
            || limits.state.maximum_content_objects == 0
            || limits.state.maximum_total_content_bytes == 0
            || limits.native.maximum_record_bytes == 0
            || limits.native.maximum_objects == 0
            || limits.native.maximum_total_record_bytes == 0
        {
            return Err(refused(
                "archive code factory has no finite cold storage limits",
            ));
        }
        let host = Rc::clone(authority.host_source());
        host.authenticate_complete_preparation_source(host.world())
            .map_err(operation_failure)?;
        let inner = Rc::new(PacketCompleteCaptureFactory {
            authority,
            plan,
            host,
            limits,
            records: RefCell::new(None),
            process: std::process::id(),
            thread: std::thread::current().id(),
            actor_storage_loan: RefCell::new(None),
            dependency_storage: RefCell::new(None),
        });
        inner.current()?;
        Ok(Rc::new(Self {
            inner,
            graph: RefCell::new(None),
        }))
    }

    pub(super) fn authenticate_code_owner(&self) -> Result<(), StateError> {
        self.inner.current()
    }

    /// Validates all structural graph rules through the existing Core codecs.
    ///
    /// The result is opaque archive-code data, with no live/ordinary conversion.
    /// No Source native-currentness or original scene/Hello callback is invoked.
    ///
    /// # Errors
    /// Refuses foreign original request, unsupported extensions/capabilities,
    /// inconsistent typed graph/ownership/causality or finite admission excess.
    pub fn admit_original_code_graph(
        &self,
        request: AdmissionRequest<'_>,
        limits: AdmissionLimits,
    ) -> Result<Rc<CompleteArchiveCodeGraph>, crucible_engine::node_admission::AdmissionError> {
        use crucible_engine::node_admission::{
            AdmissionCode, AdmissionStage, AdmissionSubject, EffectCertainty,
        };
        let unavailable = |observed: String| crucible_engine::node_admission::AdmissionError {
            stage: AdmissionStage::Authenticate,
            subject: AdmissionSubject::World,
            code: AdmissionCode::QualificationUnavailable,
            required: "one original archive code graph".into(),
            observed,
            effects: EffectCertainty::Absent,
        };
        self.authenticate_code_owner()
            .map_err(|error| unavailable(error.to_string()))?;
        let mut slot = self
            .graph
            .try_borrow_mut()
            .map_err(|_| unavailable("original code graph is busy".into()))?;
        if slot.is_some() {
            return Err(unavailable(
                "original code graph is already registered".into(),
            ));
        }
        let graph = Rc::new(admit_complete_archive_code_graph(
            request,
            &self.inner.plan,
            self,
            limits,
        )?);
        *slot = Some(Rc::downgrade(&graph));
        Ok(graph)
    }

    /// Verifies an actual selected signed archive and retains its unbound source.
    ///
    /// Core reauthenticates the actual load receipt and full typed closure with
    /// the existing cold verifier. A fresh native target must independently bind
    /// that source later; metadata never installs a model or renews old authority.
    ///
    /// # Errors
    /// Refuses foreign installed code/graph, unsupported historical codecs,
    /// changed signed source identities or exhausted complete decode limits.
    pub fn prepare_original_restoration_source(
        &self,
        graph: &CompleteArchiveCodeGraph,
        archive: NativeArchiveRecord,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<CollectingCompleteRestorationSource, StateError> {
        self.authenticate_code_owner()?;
        let retained = self.original_code_graph()?;
        if !std::ptr::eq(retained.as_ref(), graph) {
            return Err(refused("foreign archive code graph owner"));
        }
        ConformanceRuntime::prepare_complete_original_archive_code_source(
            graph, archive, self, limits,
        )
    }

    /// Counts this same code factory and actual prebirth authority/source owners.
    ///
    /// This includes both wrapper/inner shared roots, original authority, Host
    /// metadata, graph policy/measured files, plan backing and all actual Source3
    /// code allocations. The separately owned opaque code graph is not followed.
    /// Repeated shared views conservatively overcharge; no equal-data refund is
    /// taken. This observes requested storage, never native or physical peak.
    ///
    /// # Errors
    /// Refuses foreign/revoked code ownership, any Source birth/launch/native
    /// attempt, unresolved actual backing or finite requested-storage excess.
    pub fn retained_requested_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, StateError> {
        self.authenticate_code_owner()?;
        let bytes = self.retained_report_startup_code_storage_data(maximum)?;
        self.authenticate_code_owner()?;
        Ok(bytes)
    }

    pub(super) fn authenticate_retained_code_origin_data(&self) -> Result<(), StateError> {
        self.inner.authenticate_storage_origin()?;
        self.inner
            .authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(error)
    }

    pub(super) fn retained_report_startup_code_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, StateError> {
        self.authenticate_retained_code_origin_data()?;
        let mut counter = super::super::retained::Counter::new(maximum);
        counter.rc(self).map_err(error)?;
        if let Some(graph) = self.graph.try_borrow().map_err(error)?.as_ref() {
            counter.weak(graph).map_err(error)?;
        }
        counter
            .add(
                self.inner
                    .actual_archive_daemon_requested_storage(counter.remaining(), false)?,
            )
            .map_err(error)?;
        for source in &self.inner.authority.roster().sources {
            counter
                .add(
                    source
                        .original_complete_code_retained_storage_data(counter.remaining())
                        .map_err(operation_failure)?,
                )
                .map_err(error)?;
            if let Some(group) = source
                .original_effect_receiver_retained_storage_data(counter.remaining())
                .map_err(operation_failure)?
            {
                counter.add(group).map_err(error)?;
            }
        }
        self.authenticate_retained_code_origin_data()?;
        Ok(counter.bytes())
    }

    /// Returns the compiled counters and full read buffer used by the factory walk.
    ///
    /// The caller admits these declared counters and one complete streaming
    /// buffer before the walk, including its original currentness fences.
    /// Source/SDK observation scratch, the opaque code-graph counter,
    /// compiler frames and allocator physical peak are separate terms.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow in the compiled counter extent.
    pub fn retained_requested_storage_scratch_bytes() -> Result<usize, StateError> {
        std::mem::size_of::<super::super::retained::Counter>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(PacketFixtureMeasurements::streaming_scratch_bytes())
            })
            .ok_or_else(|| refused("archive code factory counter storage overflow"))
    }

    fn original_code_graph(&self) -> Result<Rc<CompleteArchiveCodeGraph>, StateError> {
        self.authenticate_code_owner()?;
        self.graph
            .try_borrow()
            .map_err(error)?
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| refused("original archive code graph owner expired"))
    }

    pub(super) fn authenticate_cold_code_graph(
        &self,
        inner: &PacketCompleteCaptureFactory,
        graph: &Rc<CompleteArchiveCodeGraph>,
        original: &AdmittedGraph,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        if !std::ptr::eq(self.inner.as_ref(), inner)
            || !Rc::ptr_eq(&self.original_code_graph()?, graph)
        {
            return Err(refused(
                "archive codec callback crossed its original code owner",
            ));
        }
        graph
            .authenticate_original_graph_data(original)
            .map_err(error)
    }

    pub(super) fn cold_additional_requested_storage_data(
        &self,
        graph: &Rc<CompleteArchiveCodeGraph>,
        maximum: usize,
    ) -> Result<usize, StateError> {
        self.authenticate_code_owner()?;
        if !Rc::ptr_eq(&self.original_code_graph()?, graph) {
            return Err(refused("archive code graph owner differs"));
        }
        let mut counter = super::super::retained::Counter::new(maximum);
        // The common verifier counts the inner factory, authority and Source3.
        // These are the additional actual outer wrapper/graph owners plus both
        // simultaneously declared observer counters, never compiler frames.
        counter
            .add(std::mem::size_of::<super::super::retained::Counter>())
            .map_err(error)?;
        counter
            .add(CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes())
            .map_err(error)?;
        counter
            .shared_header(
                std::ptr::from_ref(self).cast(),
                std::mem::size_of::<Self>(),
                std::mem::align_of::<Self>(),
            )
            .map_err(error)?;
        counter.rc(graph).map_err(error)?;
        // The borrowed graph observer includes its root, which this same
        // counter has already charged through the actual Rc allocation.
        let allowance = counter
            .remaining()
            .checked_add(std::mem::size_of_val(graph.as_ref()))
            .ok_or_else(|| refused("archive code graph observer allowance overflow"))?;
        let graph_bytes = graph
            .retained_requested_storage_excluding_authority_data(allowance)
            .map_err(error)?;
        counter
            .add(
                graph_bytes
                    .checked_sub(std::mem::size_of_val(graph.as_ref()))
                    .ok_or_else(|| refused("archive code graph root storage differs"))?,
            )
            .map_err(error)?;
        self.authenticate_code_owner()?;
        Ok(counter.bytes())
    }

    fn authenticate_plan(&self, plan: &InstalledConformancePlan) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        plan.authenticate_authority(self.inner.authority.as_ref())
            .map_err(error)
    }
}

impl NativeWorldFactory for PacketCompleteArchiveCodeFactory {
    fn authenticate_complete_restored_settled_archive(
        &self,
        scope: crucible_engine::node_state::CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        if scope.original_write_runtime_data()?.is_some() {
            return Err(refused(
                "archive code factory cannot validate a current17 writer",
            ));
        }
        let graph = self.original_code_graph()?;
        self.inner.authenticate_restored17_archive_data(
            scope,
            super::restored17_validation::FactoryPurpose17::ArchiveCode {
                factory: self,
                graph: &graph,
            },
        )
    }

    fn authenticate_source(
        &self,
        _: &AdmittedGraph,
        _: &CapturedOwner,
        _: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "archive code factory cannot authenticate a live native source",
        ))
    }

    fn authenticate_coordinator(
        &self,
        _: &AdmittedGraph,
        _: &RuntimeSnapshot,
        _: &SchedulingSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        Err(refused(
            "archive code factory cannot authenticate a live coordinator",
        ))
    }

    fn reservation(
        &self,
        _: &AdmittedGraph,
        _: &CapturedOwner,
        _: &AuthenticatedNativeSource<'_>,
        _: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError> {
        Err(refused(
            "archive code factory cannot reserve ordinary restoration",
        ))
    }

    fn empty_staging(
        &self,
        _: Rc<AdmittedGraph>,
        _: NativeArchiveRecord,
        _: &ActivationRecord,
        _: RestoreReservations,
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        Err(refused(
            "archive code factory cannot construct ordinary staging",
        ))
    }

    fn authenticate_complete_archive_code_request(
        &self,
        plan: &InstalledConformancePlan,
        request: AdmissionRequest<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_plan(plan)?;
        if request.world != self.inner.authority.world()
            || request.descriptors.len() != 4
            || request.bindings.len() != 4
            || request.owners.len() != 4
            || canonical::json_hash("cnp.admission-requirements.v1", request.requirements)
                .map_err(error)?
                != *self.inner.authority.requirements_identity()
        {
            return Err(refused("archive code request differs from installed world"));
        }
        for (member, source) in self.inner.authority.roster().sources.iter().enumerate() {
            let selected = source.installation();
            if request.descriptors[member] != selected.descriptor
                || request.bindings[member] != selected.binding
                || request.owners[member] != selected.owner
            {
                return Err(refused("archive code native selection differs"));
            }
        }
        let host = self.inner.host.selection();
        if request.descriptors[3] != host.descriptor
            || request.bindings[3] != host.binding
            || request.owners[3] != host.owner
        {
            return Err(refused("archive code Host selection differs"));
        }
        self.authenticate_plan(plan)
    }

    fn authenticate_complete_archive_code_claim(
        &self,
        plan: &InstalledConformancePlan,
        claim: QualificationClaim<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_plan(plan)?;
        match claim {
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                let selected = self
                    .inner
                    .authority
                    .roster()
                    .sources
                    .iter()
                    .map(|source| &source.installation().binding)
                    .chain(std::iter::once(&self.inner.host.selection().binding))
                    .find(|selected| &selected.compatibility == binding)
                    .ok_or_else(|| refused("archive code Node selection is absent"))?;
                if &selected.compatibility.identity().map_err(error)? != binding_hash
                    || qualification_refs != selected.compatibility.qualification_refs
                {
                    return Err(refused("archive code Node identity differs"));
                }
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                let (proof, _) = self
                    .inner
                    .authority
                    .capture_graph_policy()
                    .capture_static_references();
                let selected = self
                    .inner
                    .authority
                    .roster()
                    .sources
                    .iter()
                    .any(|source| &source.installation().owner.owner.id == capture_owner_id)
                    || &self.inner.host.selection().owner.owner.id == capture_owner_id;
                if world_binding_hash != self.inner.host.world()
                    || procedure_ref != proof
                    || !selected
                {
                    return Err(refused("archive code preservation selection differs"));
                }
            }
            _ => return Err(refused("unsupported archive code claim role")),
        }
        self.authenticate_plan(plan)
    }

    fn authenticate_complete_collecting_archive_code_source(
        &self,
        plan: &InstalledConformancePlan,
        graph: &AdmittedGraph,
        archive: &NativeArchiveRecord,
        scope: &CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        self.inner
            .authenticate_original_archive_code_source(plan, graph, archive, scope)
    }

    fn authenticate_complete_original_lineage_archive(
        &self,
        scope: CompleteOriginalArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        if scope.original_write_runtime_data()?.is_some() {
            return Err(refused(
                "archive code factory cannot validate a live capture writer",
            ));
        }
        let graph = self.original_code_graph()?;
        self.inner
            .authenticate_original_complete_archive_code(scope, self, &graph)
    }
}

#[path = "archive_code/template18.rs"]
mod template18;
