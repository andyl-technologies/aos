//! Binds complete collecting capture to the original installed four-owner scene.
//!
//! The factory retains the actual source roster, Host2 source and opaque refused
//! plan. Core owns runtime/node preflight seals and tickets. This factory checks
//! their source-selected rows; it cannot manufacture a row or native permission.

use std::{cell::RefCell, mem::size_of, rc::Rc};

mod archive_code;
mod archive_validation;
mod dependencies;
mod host17;
mod imported17;
mod key;
mod restoration_prebirth;
mod restoration_source;
mod restored17_validation;
pub use archive_code::PacketCompleteArchiveCodeFactory;
pub use restoration_prebirth::PacketCompleteRestorationPrebirth;
mod construction;
mod restoration_storage;
mod retained;

use crucible::{
    node_adapters::cnp::CnpSemanticSource,
    node_admission::{
        AdmissionRequest, AdmittedGraph, InstalledConformancePlan, QualificationClaim,
    },
    node_contract::{
        ActivationRecord, CollectingOriginalLineageCaptureRequest, ConformanceRuntime,
        HostSchedulingSource, NativeStateKey, OriginalInputLineageLimits,
        OriginalLineageRuntimeRecord, PreparedCompleteOriginalCapturePreflight, RuntimeSnapshot,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, CaptureEvidence, CompleteOriginalCaptureFactoryStorage,
        CompleteOriginalCaptureGeometry, CompleteOriginalOwnerCaptureGeometry, NativeArchive,
        NativeArchiveLimits, NativeArchiveRecord, NativeCoordinatorCaptureProof,
        NativeOwnerCaptureProof, NativeRestoreStaging, NativeWorldFactory, RestoreReservations,
        StateError, StateRequirements, VerifiedStateContent, admitted_graph_records_storage,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner, ContentRef, Id, Position, U64};
use crucible_node_provider::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE;

use super::super::fixture::PacketFixtureMeasurements;
use super::capture_records::{error, operation_failure, refused};
use super::{
    InstalledPacketCompleteCollectionAuthority, capture_records::PacketCompleteCaptureRecords,
};

/// Retains the original complete source installation and its opaque collection plan.
///
/// Installation is not Ready or ordinary behavioral acceptance. Source-owned
/// mechanism checks, each owning node's readonly preflight, the core's unchanged
/// cut ticket, and actual native callbacks are independent capture requirements.
#[must_use = "retain the factory with the original world and failed capture custody"]
pub struct PacketCompleteCaptureFactory {
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    host: Rc<HostSchedulingSource>,
    limits: NativeArchiveLimits,
    records: RefCell<Option<PacketCompleteCaptureRecords>>,
    process: u32,
    thread: std::thread::ThreadId,
    actor_storage_loan: RefCell<Option<retained::ActorStorageLoanState>>,
    dependency_storage: RefCell<Option<dependencies::OriginalDependencyStorageScope>>,
}

impl PacketCompleteCaptureFactory {
    /// Retains the actual installed sources and a plan issued by that authority.
    ///
    /// This performs no native request, host attachment, graph conversion or
    /// source installation. Later source checks authenticate the actual selected
    /// mechanism rather than interpreting portable metadata as permission.
    ///
    /// # Errors
    /// Refuses a foreign opaque plan, source revision or invalid finite limits.
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
            return Err(refused("complete factory has no finite capture credit"));
        }
        let host = Rc::clone(authority.host_source());
        host.authenticate_complete_preparation_source(host.world())
            .map_err(operation_failure)?;
        authority.current().map_err(error)?;
        let original = Rc::new(Self {
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
        original.authenticate_preparation()?;
        original.authority.bind_capture_factory(&original)?;
        Ok(original)
    }

    /// Captures through the same collecting runtime without exposing its graph.
    ///
    /// The caller keeps the original runtime, factory and archive outside any
    /// unwind guard. Refusal and callback panic leave administrative tickets and
    /// partial native results in that same runtime; this method never retries a
    /// capture, replays a modeled operation or replaces a failed capsule.
    ///
    /// # Errors
    /// Refuses foreign or stale source custody, unsupported complete mechanism,
    /// changed cuts or insufficient core/native/immutable closure credit.
    pub fn capture_original_world(
        &self,
        runtime: &mut ConformanceRuntime,
        request: PacketCompleteWorldCapture<'_>,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.current()?;
        self.enter_actor_storage_loan()?;
        runtime.capture_complete_original_lineage(CollectingOriginalLineageCaptureRequest {
            archive: request.archive,
            cut: request.cut,
            ordinal: request.ordinal,
            capture_id: request.capture_id,
            requirements: request.requirements,
            immutable: self,
            factory: self,
            lineage_limits: request.lineage_limits,
        })
    }

    pub(super) fn authenticate_authority_object(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
    ) -> Result<(), StateError> {
        if !std::ptr::eq(authority, self.authority.as_ref()) {
            return Err(refused(
                "complete factory was issued by another original authority",
            ));
        }
        self.current()
    }

    pub(super) fn authenticate_preparation(&self) -> Result<(), StateError> {
        self.current()?;
        for source in &self.authority.roster().sources {
            source
                .authenticate_original_complete_capture_preparation_support()
                .map_err(operation_failure)?;
        }
        self.current()
    }

    pub(super) fn authenticate_capture_profile(
        &self,
        claim: QualificationClaim<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_preparation()?;
        let QualificationClaim::Capture {
            world_binding_hash,
            capture_owner_id,
            procedure_ref,
        } = claim
        else {
            return Err(refused(
                "complete dormant profile requires the original Capture claim",
            ));
        };
        let (proof, _) = self
            .authority
            .capture_graph_policy()
            .capture_static_references();
        let selected = self
            .authority
            .roster()
            .sources
            .iter()
            .any(|source| &source.installation().owner.owner.id == capture_owner_id)
            || &self.host.selection().owner.owner.id == capture_owner_id;
        if world_binding_hash != self.host.world() || procedure_ref != proof || !selected {
            return Err(refused(
                "complete dormant owner or procedure differs from original scene",
            ));
        }
        self.authenticate_preparation()
    }

    pub(super) fn authenticate_collecting_request(
        &self,
        request: AdmissionRequest<'_>,
        source: &HostSchedulingSource,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        self.authenticate_preparation()?;
        if !std::ptr::eq(source, self.host.as_ref())
            || request.world != self.authority.world()
            || request.descriptors.len() != 4
            || request.bindings.len() != 4
            || request.owners.len() != 4
        {
            return Err(refused(
                "complete collecting request is not the original whole scene",
            ));
        }
        for native in &self.authority.roster().sources {
            let installed = native.installation();
            if !request.descriptors.contains(&installed.descriptor)
                || !request.bindings.contains(&installed.binding)
                || !request.owners.contains(&installed.owner)
            {
                return Err(refused(
                    "complete collecting request replaced a native original",
                ));
            }
            native
                .authenticate_original_complete_capture_support()
                .map_err(operation_failure)?;
        }
        let host = self.host.selection();
        if !request.descriptors.contains(&host.descriptor)
            || !request.bindings.contains(&host.binding)
            || !request.owners.contains(&host.owner)
        {
            return Err(refused(
                "complete collecting request replaced the original host",
            ));
        }
        self.authenticate_common_data(runtime, scheduling)?;
        self.host
            .authenticate_current()
            .map_err(operation_failure)?;
        self.current()
    }

    pub(super) fn current(&self) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        self.authority.current().map_err(error)?;
        self.plan
            .authenticate_authority(self.authority.as_ref())
            .map_err(error)?;
        if !Rc::ptr_eq(&self.host, self.authority.host_source()) {
            return Err(refused("complete factory Host2 source was replaced"));
        }
        self.host
            .authenticate_complete_preparation_source(self.host.world())
            .map_err(operation_failure)
    }

    fn authenticate_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        self.current()?;
        self.authenticate_archive_graph_data(graph)?;
        self.current()
    }

    fn authenticate_archive_graph_data(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        self.authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(error)?;
        if graph.world() != self.authority.world()
            || graph.world_binding_hash() != self.host.world()
            || !graph.selected_extensions().is_empty()
            || graph.node_ids().count() != 4
            || graph.ownership_policy().capture_owners.len() != 4
        {
            return Err(refused(
                "complete factory graph differs from original four-owner scene",
            ));
        }
        for source in &self.authority.roster().sources {
            let installed = source.installation();
            if graph.descriptor(&installed.descriptor.id) != Some(&installed.descriptor)
                || graph.binding(&installed.descriptor.id) != Some(&installed.binding)
            {
                return Err(refused("complete factory native installation differs"));
            }
        }
        let host = self.host.selection();
        if graph.descriptor(&host.descriptor.id) != Some(&host.descriptor)
            || graph.binding(&host.descriptor.id) != Some(&host.binding)
        {
            return Err(refused("complete factory host installation differs"));
        }
        self.authenticate_storage_origin()
    }

    fn authenticate_live(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        self.authenticate_graph(graph)?;
        self.authority
            .capture_graph_policy()
            .authenticate_original_participants()
            .map_err(error)?;
        for source in &self.authority.roster().sources {
            // The source reads its actual original SDK/native mechanism and
            // selected banks. Metadata labels and these checks alone cannot
            // replace the later same-node preflight or ticketed native action.
            source
                .authenticate_original_complete_capture_support()
                .map_err(operation_failure)?;
        }
        self.host
            .authenticate_current()
            .map_err(operation_failure)?;
        self.authenticate_common_data(runtime, scheduling)?;
        self.current()
    }

    fn authenticate_common_data(
        &self,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        self.authenticate_archive_common_data(runtime, scheduling)?;
        self.current()
    }

    fn authenticate_archive_common_data(
        &self,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        if runtime.schema_version != 7
            || scheduling.schema_version != 1
            || runtime.source_activation.world_binding_hash != *self.host.world()
            || scheduling.world_binding_hash != *self.host.world()
            || runtime.source_activation.activation_id != scheduling.source_activation_id
            || runtime.source_activation.generation != scheduling.source_generation
            || runtime.source_activation.boundary != scheduling.source_boundary
            || runtime.capture_cut != scheduling.capture_cut
            || runtime.capture_ordinal != scheduling.capture_ordinal
            || runtime.owners.len() != 4
            || runtime.source_activation.owners.len() != 4
            || scheduling.source_owners.len() != 4
        {
            return Err(refused(
                "complete factory runtime and scheduler scope differ",
            ));
        }
        for native in &self.authority.roster().sources {
            let installed = native.installation();
            let authority = &installed.binding.authority;
            if runtime
                .source_activation
                .owners
                .iter()
                .filter(|owner| {
                    owner.owner == installed.owner.owner.id
                        && owner.incarnation == authority.incarnation_id
                        && owner.generation == authority.owner_generation
                })
                .count()
                != 1
            {
                return Err(refused(
                    "complete runtime native incarnation is not original",
                ));
            }
        }
        let host = self.host.selection();
        if runtime
            .source_activation
            .owners
            .iter()
            .filter(|owner| {
                owner.owner == host.owner.owner.id
                    && owner.incarnation == host.binding.authority.incarnation_id
                    && owner.generation == host.binding.authority.owner_generation
            })
            .count()
            != 1
        {
            return Err(refused("complete runtime host incarnation is not original"));
        }
        for (actual, expected) in runtime.owners.iter().zip(&runtime.source_activation.owners) {
            if actual.identity != *expected {
                return Err(refused(
                    "complete factory retained runtime owner incarnation differs",
                ));
            }
        }
        for (actual, expected) in scheduling
            .source_owners
            .iter()
            .zip(&runtime.source_activation.owners)
        {
            if actual.owner != expected.owner
                || actual.incarnation != expected.incarnation
                || actual.generation != expected.generation
            {
                return Err(refused(
                    "complete factory scheduler owner incarnation differs",
                ));
            }
        }
        self.authenticate_storage_origin()
    }

    fn prepare_records(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        let mut records = self.records.try_borrow_mut().map_err(error)?;
        if records.is_none() {
            *records = Some(PacketCompleteCaptureRecords::from_graph(
                Rc::clone(&self.authority),
                graph,
                self.limits.state,
            )?);
        }
        Ok(())
    }

    fn authenticate_key(&self, participant: &Id, key: &NativeStateKey) -> Result<(), StateError> {
        let host = self.host.selection();
        let (implementation, profile, schema_id, schema_version, formats) =
            if participant == &host.descriptor.id {
                (
                    &host.binding.compatibility.implementation.implementation_id,
                    "source-owned.host-scheduling-original-lineage/2",
                    if self.selected_host_capture17_data()? {
                        "source-owned.host-scheduling-continuation/17"
                    } else {
                        "source-owned.host-scheduling-continuation/2"
                    },
                    if self.selected_host_capture17_data()? {
                        17
                    } else {
                        2
                    },
                    &host.binding.compatibility.implementation.formats,
                )
            } else {
                let selected = self
                    .authority
                    .roster()
                    .sources
                    .iter()
                    .find(|source| &source.installation().descriptor.id == participant)
                    .ok_or_else(|| refused("complete preflight participant is not original"))?;
                let installed = selected.installation();
                let schema = selected
                    .original_complete_native_snapshot_schema_data()
                    .map_err(operation_failure)?;
                (
                    &installed
                        .binding
                        .compatibility
                        .implementation
                        .implementation_id,
                    PACKET_COMPLETE_LINEAGE_PROFILE,
                    schema.id.as_str(),
                    schema.version,
                    &installed.binding.compatibility.implementation.formats,
                )
            };
        // authenticate_live has already authenticated the selected legacy Source or
        // genuine Host2 mechanism. Compare the entire returned schema against
        // that same retained installed format; do not serialize a second schema
        // definition or infer a native right from its identifier.
        if &key.implementation != implementation
            || key.profile.as_str() != profile
            || !key::matches_installed_schema_data(&key.schema, formats, schema_id, schema_version)
        {
            return Err(refused("complete preflight installed native key differs"));
        }
        Ok(())
    }
}

/// Borrows one actual unchanged-cut collecting capture request.
pub struct PacketCompleteWorldCapture<'a> {
    /// Borrows the installed local signer and its original finite archive limits.
    pub archive: &'a NativeArchive,
    /// Retains the actual common full-position cut.
    pub cut: Position,
    /// Retains the actual common event ordinal.
    pub ordinal: U64,
    /// Moves one lifetime original administrative capture identity.
    pub capture_id: Id,
    /// Moves the exact selected preservation and restart requirements.
    pub requirements: StateRequirements,
    /// Bounds all original payload and lineage occurrences.
    pub lineage_limits: OriginalInputLineageLimits,
}

impl NativeWorldFactory for PacketCompleteCaptureFactory {
    fn authenticate_complete_restored_settled_archive(
        &self,
        scope: crucible::node_state::CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_restored17_archive_data(
            scope,
            restored17_validation::FactoryPurpose17::OriginalWrite,
        )
    }

    fn complete_restored_capture_imported_closure_geometry_data(
        &self,
        scope: &crucible::node_contract::RestoredCollectingCaptureScope17<'_>,
    ) -> Result<crucible::node_state::ImportedClosureGeometry17, StateError> {
        self.imported17_geometry(scope, false)
    }

    fn complete_restored_capture_completed_imported_closure_geometry_data(
        &self,
        scope: &crucible::node_contract::RestoredCollectingCaptureScope17<'_>,
    ) -> Result<crucible::node_state::ImportedClosureGeometry17, StateError> {
        self.imported17_geometry(scope, true)
    }

    fn visit_complete_restored_capture_imported_objects_data(
        &self,
        scope: &crucible::node_contract::RestoredCollectingCaptureScope17<'_>,
        inspect: &mut dyn FnMut(&ContentRef, &[u8], &[ContentRef]) -> Result<(), StateError>,
    ) -> Result<(), StateError> {
        self.visit_imported17_objects(scope, inspect)
    }

    fn authenticate_complete_original_lineage_archive(
        &self,
        scope: crucible::node_state::CompleteOriginalArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_original_complete_archive(scope)
    }

    fn complete_original_capture_dependency_storage(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        runtime_object: &crucible::node_scheduling::InputPayload,
        limits: NativeArchiveLimits,
    ) -> Result<crucible::node_state::CompleteOriginalCaptureDependencyStorage, StateError> {
        self.original_dependency_storage(graph, runtime, scheduling, runtime_object, limits)
    }

    fn complete_original_capture_factory_storage(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureFactoryStorage, StateError> {
        self.authenticate_live(graph, runtime, scheduling)?;
        let projected = admitted_graph_records_storage(graph, limits.state)?;
        // The actual cached declaration selects this additional borrowed walk.
        // Its controls are admitted with factory preparation before the writer
        // asks the Scope for the retained imported-closure rows.
        let imported_counter = if self.selected_host_capture17_data()? {
            imported17::counter_scratch_data()
        } else {
            0
        };
        // This loan exists only during the same actor's synchronous capture.
        // Its immutable grant/scene references remain held by the caller while
        // Core separately owns and accounts the actual runtime.
        let daemon =
            self.actual_daemon_requested_storage(limits.state.maximum_total_content_bytes)?;
        let records = self.records.try_borrow().map_err(error)?;
        let actual_cache = records
            .as_ref()
            .map(PacketCompleteCaptureRecords::retained_bytes)
            .transpose()?
            .unwrap_or(0);
        let (_, runtime_rows) = super::capture_records::runtime_row_demand(runtime, limits.state)?;
        let future_retained = projected
            .retained_bytes
            .checked_add(runtime_rows)
            .ok_or_else(|| refused("complete factory source rows overflow"))?;
        let retained = future_retained
            .max(actual_cache)
            .checked_add(daemon)
            .ok_or_else(|| refused("complete factory requested storage overflow"))?;
        Ok(CompleteOriginalCaptureFactoryStorage {
            actual_retained_bytes: actual_cache
                .checked_add(daemon)
                .ok_or_else(|| refused("complete factory actual storage overflow"))?,
            maximum_retained_bytes: retained,
            maximum_transient_bytes: projected
                .transient_bytes
                // Known observer roots are charged explicitly. Compiler-generated
                // traversal frames/unwind and allocator rounding remain separate
                // source/qualification obligations; this is not a stack bound.
                .checked_add(dependencies::requested_scratch_bytes())
                .and_then(|bytes| bytes.checked_add(imported_counter))
                .and_then(|bytes| bytes.checked_add(crucible::node_adapters::cnp::PacketCompleteSemanticSource::original_complete_native_snapshot_schema_counter_scratch_data()))
                // Full streamed-file scratch can coexist with the retained
                // owners above; repeated synchronous checks share one slot.
                .and_then(|bytes| bytes.checked_add(PacketFixtureMeasurements::streaming_scratch_bytes()))
                .and_then(|bytes| bytes.checked_add(size_of::<super::retained::Counter>()))
                .and_then(|bytes| bytes.checked_add(size_of::<super::retained::Counter>()))
                .and_then(|bytes| bytes.checked_add(size_of::<crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts>()))
                .and_then(|bytes| bytes.checked_add(crucible_node_provider::retained_metadata::original_metadata_observer_layout_bytes()))
                .and_then(|bytes| {
                    projected
                        .record_count
                        .checked_mul(size_of::<super::capture_records::Row>())
                        .and_then(|rows| bytes.checked_add(rows))
                })
                // The actual previous cache coexists with its replacement.
                .and_then(|bytes| bytes.checked_add(actual_cache))
                .ok_or_else(|| refused("complete factory move projection overflow"))?,
        })
    }

    fn authenticate_complete_original_lineage_capture(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        self.authenticate_live(graph, runtime, scheduling)?;
        self.prepare_records(graph)?;
        self.records
            .try_borrow_mut()
            .map_err(error)?
            .as_mut()
            .ok_or_else(|| refused("complete runtime adjacency destination absent"))?
            .bind_runtime(runtime)?;
        self.authenticate_live(graph, runtime, scheduling)
    }

    fn authenticate_complete_collecting_archive_code_source(
        &self,
        plan: &InstalledConformancePlan,
        graph: &AdmittedGraph,
        archive: &NativeArchiveRecord,
        scope: &crucible::node_state::CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        self.authenticate_original_archive_code_source(plan, graph, archive, scope)
    }

    fn authenticate_complete_collecting_capture(
        &self,
        plan: &InstalledConformancePlan,
        source: &HostSchedulingSource,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        plan.authenticate_authority(self.authority.as_ref())
            .map_err(error)?;
        if !std::ptr::eq(source, self.host.as_ref()) {
            return Err(refused(
                "complete collecting factory received a foreign Host2 source",
            ));
        }
        self.authenticate_live(graph, runtime, scheduling)
    }

    fn complete_original_lineage_capture_geometry_from_preflight(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        preflight: &PreparedCompleteOriginalCapturePreflight,
        limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureGeometry, StateError> {
        self.authenticate_live(graph, runtime, scheduling)?;
        self.prepare_records(graph)?;
        let records = self.records.try_borrow().map_err(error)?;
        let _original_records = records
            .as_ref()
            .ok_or_else(|| refused("complete immutable records absent"))?;
        let mut owners = Vec::new();
        owners.try_reserve_exact(4).map_err(error)?;
        for (row, expected) in preflight
            .owners()
            .iter()
            .zip(&graph.ownership_policy().capture_owners)
        {
            let [participant] = row.geometry.participants.as_slice() else {
                return Err(refused(
                    "complete preflight does not retain one original participant",
                ));
            };
            if row.geometry.owner != expected.owner_id {
                return Err(refused("complete preflight key or original owner differs"));
            }
            self.authenticate_key(participant, &row.key)?;
            owners.push(copy_geometry(&row.geometry)?);
        }
        // Core binds exact equality with every original owning-node row.
        // Factory-owned cache/scratch has its separate admitted storage term.
        let geometry = CompleteOriginalCaptureGeometry { owners };
        geometry.validate(
            graph,
            limits.native,
            limits.state,
            limits.state.maximum_dependency_edges,
        )?;
        self.authenticate_live(graph, runtime, scheduling)?;
        Ok(geometry)
    }

    fn original_lineage_capture_immutable_roots(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        _maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.authenticate_live(graph, runtime, scheduling)?;
        // All installed source artifacts and contracts are direct descendants
        // of core's required graph roots, reconstructed by capture_records.
        Ok(Vec::new())
    }

    fn original_lineage_capture_dependencies(
        &self,
        graph: &AdmittedGraph,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.authenticate_graph(graph)?;
        if let Some(dependencies) = self.original_born_dependencies(reference, bytes, maximum)? {
            return Ok(dependencies);
        }
        let records = self.records.try_borrow().map_err(error)?;
        records
            .as_ref()
            .ok_or_else(|| refused("complete source records were not prepared"))?
            .dependencies(reference, bytes, maximum)
    }

    fn authenticate_source(
        &self,
        _: &AdmittedGraph,
        _: &CapturedOwner,
        _: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        Err(refused(
            "complete collecting factory requires Runtime7 original-source validation",
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
            "complete collecting factory requires joint Runtime7 administrative validation",
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
            "complete restoration requires source-verified index3 and fresh native holds",
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
            "complete restoration cannot use the legacy staging route",
        ))
    }
}

impl CaptureEvidence for PacketCompleteCaptureFactory {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.current()?;
        let records = self.records.try_borrow().map_err(error)?;
        records
            .as_ref()
            .ok_or_else(|| refused("complete immutable records were not prepared"))?
            .content(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.current()?;
        let records = self.records.try_borrow().map_err(error)?;
        records
            .as_ref()
            .ok_or_else(|| refused("complete immutable records were not prepared"))?
            .dependencies(reference, bytes, maximum)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refused(
            "complete owners require the installed joint original archive codec",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refused(
            "complete coordinator requires Runtime7 and the original administrative ledger",
        ))
    }
}

fn copy_geometry(
    row: &CompleteOriginalOwnerCaptureGeometry,
) -> Result<CompleteOriginalOwnerCaptureGeometry, StateError> {
    let [participant] = row.participants.as_slice() else {
        return Err(refused("complete geometry participant count differs"));
    };
    let mut participants = Vec::new();
    participants.try_reserve_exact(1).map_err(error)?;
    participants.push(participant.clone());
    Ok(CompleteOriginalOwnerCaptureGeometry {
        owner: row.owner.clone(),
        participants,
        maximum_record_bytes: row.maximum_record_bytes,
        maximum_objects: row.maximum_objects,
        maximum_retained_bytes: row.maximum_retained_bytes,
        maximum_dependency_edges: row.maximum_dependency_edges,
        maximum_transient_bytes: row.maximum_transient_bytes,
    })
}
