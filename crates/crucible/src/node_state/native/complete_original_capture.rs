//! Persists closed native-five plus genuine host-two original capture without modeled grants.
//!
//! All owner bodies stay in the same runtime ticket through codec or disk failure.
//! The mandatory core journal is independent of unchanged Runtime7/Coordinator7.
//! This route remains unsupported until installed source validators and native
//! snapshot/adopter implementations qualify the complete selected closure.

use super::super::{
    CaptureEvidence, StateError, StateRequirements, StateRestoreMode, VerifiedStateContent,
    closure::{ContentInventoryEdition, bounded_record, core_references, verify_complete_closure},
    schema,
    validation::required_immutable_refs,
};
use super::capture::Objects;
use super::lineage_capture::{OwnerReceipt, SignedRows, remaining_native};
use super::lineage_source::OriginalLineageCoordinator;
use super::storage::Index;
use super::*;
use crate::node_contract::OriginalInputLineageLimits;
use crucible_node_contract::{
    CaptureManifest, CaptureRepresentation, CapturedOwner, Id, canonical,
};

#[path = "complete_original_capture/profile.rs"]
mod profile;

#[path = "complete_original_capture/restored17.rs"]
mod restored17;
pub use restored17::{ImportedClosureGeometry17, imported_closure17_counter_scratch_data};

impl NativeArchive {
    /// Captures and signs exact Runtime7 conditional model journals at an unchanged cut.
    ///
    /// Known immutable, original-body and portable obligations consume finite
    /// credits before any native capture callback. Unsupported source policies,
    /// physical artifacts and combined runtime/scheduler editions refuse.
    ///
    /// # Errors
    /// Refuses unsupported preservation, moving cuts, incomplete original native
    /// custody, unknown body dependencies, absent installed policy or finite excess.
    pub fn capture_complete_original_lineage_world(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.capture_complete_original_lineage_world_scoped(request, None)
    }

    pub(crate) fn capture_complete_original_lineage_world_scoped(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
        collecting: Option<&crate::node_contract::OriginalCollectingCaptureScope>,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.capture_complete_original_lineage_world_prepared_data(
            request,
            collecting,
            None::<
                fn(
                    &crate::node_contract::NodeRuntime,
                    &crate::node_contract::HostSchedulingSource,
                    &crate::node_scheduling::InputPayload,
                    &crate::node_scheduling::InputPayload,
                ) -> Result<(), crate::node_contract::RuntimeError>,
            >,
        )
    }

    pub(crate) fn capture_complete_original_lineage_world_prepared_data(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
        collecting: Option<&crate::node_contract::OriginalCollectingCaptureScope>,
        prepared: Option<
            impl FnOnce(
                &crate::node_contract::NodeRuntime,
                &crate::node_contract::HostSchedulingSource,
                &crate::node_scheduling::InputPayload,
                &crate::node_scheduling::InputPayload,
            ) -> Result<(), crate::node_contract::RuntimeError>,
        >,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.capture_complete_lineage_world_family_data(request, collecting, prepared, None, None)?
            .ok_or_else(|| refused("original capture returned no durable archive"))
    }

    // The legacy branch owns its original snapshots. The distinct current17
    // branch borrows the actual Window checkpoints and its one-use Host producer.
    fn capture_complete_lineage_world_family_data(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
        collecting: Option<&crate::node_contract::OriginalCollectingCaptureScope>,
        prepared: Option<
            impl FnOnce(
                &crate::node_contract::NodeRuntime,
                &crate::node_contract::HostSchedulingSource,
                &crate::node_scheduling::InputPayload,
                &crate::node_scheduling::InputPayload,
            ) -> Result<(), crate::node_contract::RuntimeError>,
        >,
        mut restored: Option<restored17::RestoredCaptureInputs17<'_, '_>>,
        completed: Option<&mut Option<NativeArchiveRecord>>,
    ) -> Result<Option<NativeArchiveRecord>, StateError> {
        let OriginalLineageCaptureRequest {
            graph,
            runtime,
            activation,
            cut,
            ordinal,
            capture_id,
            requirements,
            immutable,
            factory,
            lineage_limits,
        } = request;
        restored17::authenticate_purpose(runtime, collecting, restored.as_ref())?;
        // Admit the original incoming owners before snapshot preparation or
        // source callbacks. They survive by move/retention through persistence.
        let request_storage = super::core_future_metadata::original_request_storage(
            &capture_id,
            &requirements,
            self.limits.state.maximum_total_content_bytes,
        )
        .map_err(schema)?;
        if requirements.restore_mode != StateRestoreMode::DurableRestart
            || !requirements.exact_model_continuation
            || requirements.preservation_contract.as_str()
                != "source-owned.packet-complete-original-lineage/5"
            || requirements.deterministic
                && graph.world_repeatability() != crucible_node_contract::Repeatability::Qualified
        {
            return Err(refused(
                "unsupported complete conditional lineage preservation requirements",
            ));
        }
        if !graph.selected_extensions().is_empty() {
            return Err(refused(
                "complete original archive has no selected-extension codec",
            ));
        }
        let selected = extensions::archive::prepare_capture(graph, factory, self.limits.state)?;
        let graph_refs = selected
            .as_ref()
            .map(|selected| {
                extensions::graph_refs::immutable_refs(graph, selected, self.limits.state)
            })
            .transpose()?;
        let immutable = extensions::evidence::SelectionEvidence {
            base: immutable,
            selected: selected.as_ref(),
        };
        let owned_scheduler;
        let scheduler = if let Some(current) = &restored {
            current.authenticate_request(
                graph,
                runtime,
                activation,
                &capture_id,
                cut,
                ordinal,
                factory,
            )?;
            current.scheduling
        } else {
            owned_scheduler = runtime
                .original_lineage_scheduler_snapshot(activation, cut, ordinal)
                .map_err(schema)?;
            &owned_scheduler
        };
        if scheduler.schema_version != 1
            || scheduler.original_epochs.is_some()
            || !scheduler.external_closed_prefixes.is_empty()
        {
            return Err(refused(
                "complete packet-five capture does not qualify combined scheduler editions or external ingress",
            ));
        }
        let owned_source;
        let source = if let Some(current) = &restored {
            current.runtime
        } else {
            owned_source = runtime
                .original_lineage_runtime_snapshot(
                    cut,
                    ordinal,
                    lineage_limits,
                    self.limits.state.maximum_record_bytes,
                )
                .map_err(schema)?;
            &owned_source
        };
        // These actual decoded snapshots already coexist before any native
        // loan/effect. Admit their owned banks now; the complete future peak
        // remains a separate named reservation, not this minimum check.
        let known_snapshot_storage =
            crate::node_contract::NodeRuntime::capture_runtime_record_storage(&source)
                .map_err(schema)?
                .checked_add(
                    crate::node_contract::NodeRuntime::capture_scheduling_record_storage(
                        &scheduler,
                    )
                    .map_err(schema)?,
                )
                .ok_or_else(|| refused("known core snapshot storage overflow"))?;
        if known_snapshot_storage > self.limits.state.maximum_total_content_bytes {
            return Err(refused(
                "known core snapshots exhaust complete content budget",
            ));
        }
        // Admit the installed factory's separate banks before it creates its
        // canonical source cache. These do not change any owning-node row.
        let factory_storage = factory.complete_original_capture_factory_storage(
            graph,
            &source,
            &scheduler,
            self.limits,
        )?;
        factory_storage.validate(self.limits)?;
        let factory_peak = factory_storage.peak()?;
        known_snapshot_storage
            .checked_add(request_storage)
            .and_then(|total| total.checked_add(factory_peak))
            .filter(|total| {
                *total <= self.limits.state.maximum_total_content_bytes
                    && *total <= self.limits.native.maximum_total_record_bytes
            })
            .ok_or_else(|| refused("complete factory preparation exceeds remaining credit"))?;
        factory.authenticate_complete_original_lineage_capture(graph, &source, &scheduler)?;
        let actual_factory = factory.complete_original_capture_factory_storage(
            graph,
            &source,
            &scheduler,
            self.limits,
        )?;
        actual_factory.validate(self.limits)?;
        if actual_factory.actual_retained_bytes > factory_storage.maximum_retained_bytes
            || actual_factory.maximum_retained_bytes > factory_storage.maximum_retained_bytes
            || actual_factory.maximum_transient_bytes > factory_storage.maximum_transient_bytes
        {
            return Err(refused(
                "complete factory exceeded its original admitted banks",
            ));
        }
        if let Some(scope) = collecting {
            scope.authenticate(&source, &scheduler, &capture_id, factory)?;
        }

        let immutable_refs = if let Some(refs) = &graph_refs {
            refs.verify(graph, self.limits.state)?;
            refs.roots().to_vec()
        } else {
            required_immutable_refs(graph, self.limits.state)?
        };
        let additional_maximum = self
            .limits
            .state
            .maximum_content_objects
            .checked_sub(immutable_refs.len())
            .ok_or_else(|| refused("lineage immutable root credit exhausted"))?;
        let additional_roots = factory.original_lineage_capture_immutable_roots(
            graph,
            &source,
            &scheduler,
            additional_maximum,
        )?;
        let immutable_refs =
            super::lineage_roots::combine(immutable_refs, additional_roots, self.limits.state)?;
        let mut immutable_limits = self.limits.state;
        immutable_limits.maximum_total_content_bytes = self
            .limits
            .state
            .maximum_total_content_bytes
            .checked_sub(known_snapshot_storage)
            .and_then(|remaining| remaining.checked_sub(request_storage))
            .and_then(|remaining| remaining.checked_sub(factory_peak))
            .ok_or_else(|| refused("complete immutable reader has no remaining factory credit"))?;
        immutable_limits.maximum_content_bytes = immutable_limits
            .maximum_content_bytes
            .min(immutable_limits.maximum_total_content_bytes);
        let content =
            verify_complete_closure(immutable_refs.clone(), &immutable, immutable_limits)?;
        let owned_runtime_object;
        let owned_scheduler_object;
        let owned_coordinator_object;
        let (runtime_object, scheduler_object, coordinator_object) = if let Some(current) =
            &restored
        {
            (
                current.runtime_object,
                current.scheduling_object,
                current.coordinator_object,
            )
        } else {
            owned_runtime_object = self.lineage_record(source, ORIGINAL_LINEAGE_RUNTIME_MEDIA)?;
            owned_scheduler_object = self.lineage_record(scheduler, "application/json")?;
            let coordinator = OriginalLineageCoordinator {
                schema_version: 7,
                runtime: owned_runtime_object.reference.clone(),
                scheduler: owned_scheduler_object.reference.clone(),
                world_repeatability: graph.world_repeatability(),
            };
            owned_coordinator_object =
                self.lineage_record(&coordinator, ORIGINAL_LINEAGE_COORDINATOR_MEDIA)?;
            (
                &owned_runtime_object,
                &owned_scheduler_object,
                &owned_coordinator_object,
            )
        };
        let inventory_credit = super::lineage_inventory::credit(&source.inputs, self.limits.state)?;
        let inventory_storage = super::lineage_inventory::complete_requested_storage(
            &source.inputs,
            self.limits.state,
        )?;
        let body_geometry = runtime.original_lineage_capture_objects().try_fold(
            (0usize, 0usize),
            |(count, bytes), object| {
                Ok::<_, StateError>((
                    count
                        .checked_add(1)
                        .ok_or_else(|| refused("lineage body count overflow"))?,
                    bytes
                        .checked_add(object.bytes.len())
                        .ok_or_else(|| refused("lineage body byte count overflow"))?,
                ))
            },
        )?;
        let historical = super::historical_capture::HistoricalCaptureClosure::prepare(
            runtime,
            self.limits.state,
        )?;
        let history_geometry = historical.geometry();
        let body_geometry = (
            body_geometry
                .0
                .checked_add(inventory_credit.objects)
                .and_then(|objects| objects.checked_add(history_geometry.0))
                .ok_or_else(|| refused("lineage input inventory count overflow"))?,
            body_geometry
                .1
                .checked_add(inventory_credit.bytes)
                .and_then(|bytes| bytes.checked_add(history_geometry.1))
                .ok_or_else(|| refused("lineage input inventory byte count overflow"))?,
        );
        let mut native_limits = remaining_native(
            graph,
            &content,
            [&runtime_object, &scheduler_object, &coordinator_object],
            &scheduler,
            body_geometry,
            self.limits,
        )?;
        // Reserve the distinct core administrative journal before any owner effect.
        native_limits.maximum_total_record_bytes = native_limits
            .maximum_total_record_bytes
            .checked_sub(self.limits.state.maximum_record_bytes)
            .ok_or_else(|| {
                refused("administrative journal exhausts complete capture byte credit")
            })?;
        native_limits.maximum_objects =
            native_limits
                .maximum_objects
                .checked_sub(1)
                .ok_or_else(|| {
                    refused("administrative journal exhausts complete capture role credit")
                })?;
        let inventories = super::lineage_inventory::prepare(&source.inputs, &inventory_credit)?;
        let mut objects = Objects::new(self, ContentInventoryEdition::Typed);
        historical.enroll(&mut objects, self.limits.state)?;
        drop(historical);

        for (reference, bytes) in content.entries() {
            objects.insert(
                reference.clone(),
                bytes,
                immutable.dependencies(
                    reference,
                    bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        if let Some(plan) = collecting
            .map(|scope| scope.plan())
            .or_else(|| restored.as_ref().map(|current| current.scope.plan_data()))
        {
            let evidence = plan.evidence();
            objects.insert(
                evidence.plan_ref.clone(),
                evidence.plan_bytes,
                evidence.sources.to_vec(),
            )?;
            let mut dependencies = evidence.sources.to_vec();
            dependencies.push(evidence.plan_ref.clone());
            dependencies.sort();
            dependencies.dedup();
            objects.insert(
                evidence.refused_ref.clone(),
                evidence.refused_bytes,
                dependencies,
            )?;
        }
        for object in runtime.original_lineage_capture_objects() {
            objects.insert(
                object.reference.clone(),
                &object.bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &object.reference,
                    &object.bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        for object in &scheduler.payload_objects {
            objects.insert(
                object.reference.clone(),
                &object.bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &object.reference,
                    &object.bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
        }
        for inventory in &inventories {
            let mut dependencies = factory.original_lineage_capture_dependencies(
                graph,
                &inventory.body.reference,
                &inventory.body.bytes,
                self.limits.state.maximum_content_objects,
            )?;
            dependencies.sort();
            dependencies.dedup();
            if dependencies != inventory.dependencies {
                return Err(refused(
                    "installed input inventory dependency codec changed",
                ));
            }
            objects.insert(
                inventory.body.reference.clone(),
                &inventory.body.bytes,
                dependencies,
            )?;
        }
        objects.insert(
            runtime_object.reference.clone(),
            &runtime_object.bytes,
            core_references(&source, self.limits.state.maximum_record_bytes)?,
        )?;
        objects.insert(
            scheduler_object.reference.clone(),
            &scheduler_object.bytes,
            core_references(&scheduler, self.limits.state.maximum_record_bytes)?,
        )?;
        objects.insert(
            coordinator_object.reference.clone(),
            &coordinator_object.bytes,
            if let Some(current) = &restored {
                core_references(current.coordinator, self.limits.state.maximum_record_bytes)?
            } else {
                vec![
                    runtime_object.reference.clone(),
                    scheduler_object.reference.clone(),
                ]
            },
        )?;

        // All known typed rows, including every original inventory occurrence,
        // consume aggregate dependency credit before owning native callbacks.
        objects.check_dependency_credit()?;
        // Count the borrowed whole Host2 representation before creating its
        // first producer copy. This minimum covers current known banks only;
        // the source-selected whole capture peak remains independently required.
        let preflight = if let Some(current) = &restored {
            runtime
                .preflight_complete_restored_capture17_data(
                    graph,
                    activation,
                    source,
                    runtime_object,
                    (scheduler, lineage_limits),
                    NativeArchiveLimits {
                        native: native_limits,
                        state: self.limits.state,
                    },
                    current.scope,
                    std::rc::Rc::clone(current.host),
                )
                .map_err(schema)?
        } else {
            runtime
                .precharge_original_host_capture(
                    graph,
                    source,
                    scheduler,
                    runtime_object,
                    self.limits.state.maximum_total_content_bytes,
                )
                .map_err(schema)?;
            runtime
                .preflight_complete_original_capture(
                    graph,
                    activation,
                    source,
                    runtime_object,
                    (scheduler, lineage_limits),
                    NativeArchiveLimits {
                        native: native_limits,
                        state: self.limits.state,
                    },
                )
                .map_err(schema)?
        };
        // Source born-row plans require the actual owning-node loan and this
        // encoded Runtime7 identity. They cannot be demanded by the earlier
        // factory-cache callback, which precedes that loan and body creation.
        let dependency_limits = NativeArchiveLimits {
            native: native_limits,
            state: self.limits.state,
        };
        let dependency_storage = factory.complete_original_capture_dependency_storage(
            graph,
            &source,
            &scheduler,
            &runtime_object,
            dependency_limits,
        )?;
        dependency_storage.validate(dependency_limits)?;
        let dependency_peak = dependency_storage.peak()?;
        // This closed edition projects empty key-extension maps. Selected world
        // extensions alone do not imply that a source's native schema is closed.
        for owner in preflight.owners() {
            if !owner.key.schema.extensions.is_empty() {
                return Err(refused(
                    "complete source key has unsupported schema extensions",
                ));
            }
        }
        let geometry = factory.complete_original_lineage_capture_geometry_from_preflight(
            graph,
            &source,
            &scheduler,
            &preflight,
            NativeArchiveLimits {
                native: native_limits,
                state: self.limits.state,
            },
        )?;
        let restored_storage = restored
            .as_ref()
            .map(|current| {
                let imported = factory
                    .complete_restored_capture_imported_closure_geometry_data(current.scope)?;
                let imported = restored17::ImportedClosureStorage17::quote(imported, self.limits)?;
                Ok::<_, StateError>(imported)
            })
            .transpose()?;
        // This is a new independent constructor row for the final comparison
        // copies. It consumes neither the Window checkpoint construction credit
        // nor any of the six Source ticket-validation windows.
        let final_snapshot_comparison = if restored.is_some() {
            let row = runtime
                .original_restored_capture_runtime_construction_data(
                    activation,
                    cut,
                    ordinal,
                    self.limits.state.maximum_record_bytes,
                    self.limits
                        .state
                        .maximum_total_content_bytes
                        .min(self.limits.native.maximum_total_record_bytes),
                )
                .map_err(schema)?;
            row.checkpoint_inputs_construction_requested_bytes_data()
                .checked_add(row.counter_scratch_bytes_data())
                .ok_or_else(|| refused("final current17 snapshot comparison row overflow"))?
        } else {
            0
        };
        if let Some(imported) = &restored_storage {
            native_limits.maximum_total_record_bytes = native_limits
                .maximum_total_record_bytes
                .checked_sub(imported.bytes())
                .ok_or_else(|| refused("imported closure exhausts native record credit"))?;
            native_limits.maximum_objects = native_limits
                .maximum_objects
                .checked_sub(imported.objects())
                .ok_or_else(|| refused("imported closure exhausts native object credit"))?;
        }
        let prior_admin = runtime
            .original_capture_journal_with_limit(self.limits.state.maximum_record_bytes)
            .map_err(schema)?;
        let prior_edges =
            core_references(&prior_admin, self.limits.state.maximum_record_bytes)?.len();
        let source_roles = geometry
            .owners
            .iter()
            .try_fold(0usize, |count, row| count.checked_add(row.maximum_objects))
            .ok_or_else(|| refused("capture geometry receipt edge overflow"))?;
        // Four owner receipts, the new admin row and provenance are constructed
        // by core after capture; their future edges are charged before dispatch.
        let core_edges = prior_edges
            .checked_add(source_roles)
            .and_then(|edges| edges.checked_add(14))
            .ok_or_else(|| refused("capture geometry core edge overflow"))?;
        let remaining_edges = objects
            .remaining_dependency_credit()?
            .checked_sub(core_edges)
            .and_then(|edges| {
                edges.checked_sub(
                    restored_storage
                        .as_ref()
                        .map(|row| row.edges())
                        .unwrap_or(0),
                )
            })
            .ok_or_else(|| refused("capture geometry exhausts future core edge credit"))?;
        geometry.validate(graph, native_limits, self.limits.state, remaining_edges)?;
        let (known_objects, known_edges) = objects.complete_geometry_counts()?;
        let (imported_objects, imported_edges) = restored_storage
            .as_ref()
            .map(|imported| (imported.objects(), imported.edges()))
            .unwrap_or((0, 0));
        let projected_objects = known_objects
            .checked_add(imported_objects)
            .and_then(|objects| objects.checked_add(source_roles))
            .and_then(|objects| objects.checked_add(8))
            .ok_or_else(|| refused("complete future core object count overflow"))?;
        let projected_edges = geometry
            .owners
            .iter()
            .try_fold(known_edges, |edges, row| {
                edges.checked_add(row.maximum_dependency_edges)
            })
            .and_then(|edges| edges.checked_add(core_edges))
            .and_then(|edges| edges.checked_add(imported_edges))
            .ok_or_else(|| refused("complete future core edge count overflow"))?;
        let core_metadata = super::core_future_metadata::CoreCaptureMetadataPeak::prepare(
            super::core_future_metadata::CoreCaptureMetadataGeometry {
                graph,
                runtime: &source,
                scheduling: &scheduler,
                runtime_bytes: &runtime_object.bytes,
                scheduling_bytes: &scheduler_object.bytes,
                lineage: lineage_limits,
                owners: &geometry,
                objects: projected_objects,
                edges: projected_edges,
                record_bytes: self.limits.state.maximum_record_bytes,
                maximum: self.limits.state.maximum_total_content_bytes,
            },
        )
        .map_err(schema)?;
        // A complete final sum, not a text-to-heap multiplier. This minimum
        // leaves the separately blocked source/attempt/future-byte peak intact.
        let future_content_banks = super::core_future_metadata::projected_future_content_banks(
            objects
                .complete_disk_bytes()
                .checked_add(
                    restored_storage
                        .as_ref()
                        .map(|row| row.bytes())
                        .unwrap_or(0),
                )
                .ok_or_else(|| refused("future imported content bytes overflow"))?,
            objects.complete_largest_object()?.max(
                restored_storage
                    .as_ref()
                    .map(|row| row.largest())
                    .unwrap_or(0),
            ),
            core_metadata.future_body_bounds(),
            &geometry,
            self.limits.state,
        )
        .map_err(schema)?;
        let known_immutable_banks = content.capture_owned_storage().map_err(schema)?;
        let mut current_core = known_snapshot_storage
            .checked_add(factory_peak)
            .and_then(|bytes| bytes.checked_add(dependency_peak))
            .and_then(|bytes| bytes.checked_add(request_storage))
            .and_then(|bytes| bytes.checked_add(known_immutable_banks))
            .ok_or_else(|| refused("complete current core peak overflow"))?;
        for object in [&runtime_object, &scheduler_object, &coordinator_object] {
            current_core = current_core
                .checked_add(object.bytes.capacity())
                .and_then(|bytes| {
                    bytes.checked_add(
                        crate::node_contract::NodeRuntime::capture_reference_storage(
                            &object.reference,
                        )
                        .ok()?,
                    )
                })
                .ok_or_else(|| refused("complete current encoded bank overflow"))?;
        }
        current_core = current_core
            .checked_add(objects.complete_owned_storage()?)
            .and_then(|bytes| {
                bytes.checked_add(
                    immutable_refs
                        .capacity()
                        .checked_mul(std::mem::size_of::<crucible_node_contract::ContentRef>())?,
                )
            })
            .ok_or_else(|| refused("complete current object/root metadata overflow"))?;
        for reference in &immutable_refs {
            current_core = current_core
                .checked_add(
                    crate::node_contract::NodeRuntime::capture_reference_storage(reference)
                        .map_err(schema)?,
                )
                .ok_or_else(|| refused("complete immutable reference strings overflow"))?;
        }
        current_core = current_core
            .checked_add(
                crate::node_contract::NodeRuntime::capture_admin_storage(&prior_admin)
                    .map_err(schema)?,
            )
            .ok_or_else(|| refused("complete prior administrative records overflow"))?;
        // The archive directory backing remains live through all sequential IO.
        current_core =
            current_core
                .checked_add(
                    crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                        std::fs::File,
                    >(),
                )
                .ok_or_else(|| refused("complete archive directory owner overflow"))?;
        let mut planned_geometry = geometry
            .owners
            .capacity()
            .checked_mul(std::mem::size_of::<
                super::CompleteOriginalOwnerCaptureGeometry,
            >())
            .ok_or_else(|| refused("complete planned geometry bank overflow"))?;
        for row in &geometry.owners {
            planned_geometry = planned_geometry
                .checked_add(
                    crate::node_contract::NodeRuntime::capture_owner_geometry_storage(row)
                        .map_err(schema)?,
                )
                .ok_or_else(|| refused("complete planned geometry metadata overflow"))?;
        }
        // The inline seal includes the fixed named-budget fields and borrowed
        // source handles; its independently owned banks are counted below.
        planned_geometry = planned_geometry
            .checked_add(std::mem::size_of::<
                crate::node_contract::PreparedCompleteOriginalCaptureGeometry,
            >())
            .ok_or_else(|| refused("complete planned seal header overflow"))?;
        // Sealing clones these logical contents into independently owned banks.
        planned_geometry = planned_geometry
            .checked_add(capture_id.as_str().len())
            .and_then(|bytes| {
                bytes.checked_add(
                    crate::node_contract::NodeRuntime::capture_reference_storage(
                        &runtime_object.reference,
                    )
                    .ok()?,
                )
            })
            .ok_or_else(|| refused("complete planned seal identity banks overflow"))?;
        let selected_sources = geometry.owners.iter().try_fold(0usize, |bytes, row| {
            bytes
                .checked_add(row.maximum_retained_bytes)
                .and_then(|bytes| bytes.checked_add(row.maximum_transient_bytes))
                .ok_or_else(|| refused("complete selected source peak overflow"))
        })?;
        if let Some(imported) = &restored_storage {
            current_core = current_core
                .checked_add(restored17::writer_counter_scratch_data())
                .and_then(|bytes| bytes.checked_add(final_snapshot_comparison))
                .and_then(|bytes| bytes.checked_add(imported.peak().ok()?))
                .ok_or_else(|| refused("restored capture import peak overflow"))?;
        }
        let named_peak = super::core_future_metadata::CompleteCaptureAllocationPeak {
            current_core,
            original_payloads: runtime.capture_original_payload_storage().map_err(schema)?,
            cached_preflight: preflight.capture_owned_storage().map_err(schema)?,
            registered_history: runtime
                .capture_registered_attempt_storage()
                .map_err(schema)?,
            planned_geometry,
            attempt_construction: runtime
                .capture_requested_attempt_storage(
                    graph,
                    activation,
                    &capture_id,
                    &source,
                    &runtime_object,
                    self.limits.state.maximum_total_content_bytes,
                )
                .map_err(schema)?,
            inventory_preparation: inventory_storage,
            future_metadata: core_metadata.total().map_err(schema)?,
            future_content: future_content_banks,
            selected_sources,
        };
        // These writer terms coexist with the separately observed actual live
        // runtime below. Owning Source preflight still qualifies the remote
        // native rows and complete selected codec before geometry is available.
        named_peak
            .admit(self.limits.state.maximum_total_content_bytes)
            .map_err(schema)?;
        // The same named total must also fit the remaining native record credit.
        // Retain it in the original geometry instead of accepting a parsed total.
        let allocation_budget = named_peak
            .issue_budget(
                runtime,
                native_limits.maximum_total_record_bytes,
                self.limits.state.maximum_total_content_bytes,
            )
            .map_err(schema)?;

        native_limits.maximum_record_bytes = geometry
            .owners
            .iter()
            .map(|row| row.maximum_record_bytes)
            .max()
            .ok_or_else(|| refused("capture geometry owner roster absent"))?;
        factory.authenticate_complete_original_lineage_capture(graph, &source, &scheduler)?;
        if let Some(scope) = collecting {
            scope.authenticate(&source, &scheduler, &capture_id, factory)?;
        }

        // The factory check can inspect shared Source owners. Recheck the same
        // live runtime after that callback, before sealing or issuing a ticket;
        // changed ownership cannot spend an earlier smaller observation.
        allocation_budget
            .authenticate_runtime(runtime)
            .map_err(schema)?;
        let geometry = runtime
            .prepare_complete_capture_geometry_with_preflight(
                activation,
                &capture_id,
                &runtime_object,
                geometry,
                native_limits,
                (preflight, allocation_budget),
            )
            .map_err(schema)?;
        let expected_scheduling = &scheduler;
        let expected_runtime = &runtime_object;
        let scheduling_object = &scheduler_object;
        let prepared = prepared.map(|prepared| {
            move |current: &crate::node_contract::NodeRuntime,
                  host: &crate::node_contract::HostSchedulingSource,
                  prepared_scheduling: &crate::node_scheduling::SchedulingSnapshot,
                  prepared_runtime: &crate::node_scheduling::InputPayload| {
                if prepared_scheduling != *expected_scheduling
                    || prepared_runtime.reference != expected_runtime.reference
                    || prepared_runtime.bytes != expected_runtime.bytes
                {
                    return Err(crate::node_contract::RuntimeError::ForeignAuthority);
                }
                // These exact objects are enrolled by this same archive writer.
                prepared(current, host, prepared_runtime, scheduling_object)
            }
        });
        let capture_request = crate::node_contract::TicketedOriginalLineageCaptureRequest {
            graph,
            activation,
            capture_id: capture_id.clone(),
            source,
            runtime_object,
            lineage_limits,
            limits: native_limits,
            geometry: &geometry,
        };
        let captures = if let Some(current) = &mut restored {
            runtime
                .capture_installed_restored_lineage17_data(
                    capture_request,
                    current.scope,
                    current.after_owner,
                )
                .map_err(schema)?
        } else {
            runtime
                .capture_installed_original_lineage_with_prepared_host_data(
                    capture_request,
                    prepared,
                )
                .map_err(schema)?
        };
        restored17::authenticate_purpose(runtime, collecting, restored.as_ref())?;
        if let Some(scope) = collecting {
            scope.authenticate(&source, &scheduler, &capture_id, factory)?;
        }
        // The same source-side plans and factory association remain bounded
        // after producer effects, before the first returned dependency row is
        // allocated. Actual Source output already checked its born capacities.
        let observed_dependencies = factory.complete_original_capture_dependency_storage(
            graph,
            &source,
            &scheduler,
            &runtime_object,
            dependency_limits,
        )?;
        observed_dependencies.validate(dependency_limits)?;
        dependency_storage.authenticate_bound(&observed_dependencies)?;
        if let (Some(current), Some(imported)) = (restored.as_ref(), &restored_storage) {
            imported.enroll(factory, current.scope, &mut objects)?;
        }
        let captured_bodies = captures.read().map_err(schema)?;
        let mut states = Vec::new();
        let mut owners = Vec::new();
        states
            .try_reserve_exact(4)
            .map_err(|_| refused("lineage owner reservation failed"))?;
        owners
            .try_reserve_exact(4)
            .map_err(|_| refused("lineage owner receipt reservation failed"))?;
        for original in captured_bodies.owners() {
            let captured = original.native();
            if !captured.artifacts().is_empty() {
                return Err(refused(
                    "physical image custody is unsupported by complete packet-five capture",
                ));
            }
            let mut evidence = Vec::new();
            evidence
                .try_reserve_exact(captured.evidence().len())
                .map_err(|_| refused("lineage evidence reservation failed"))?;
            for object in captured.evidence() {
                evidence.push(object.reference.clone());
                if object.reference == runtime_object.reference {
                    continue;
                }
                objects.insert(
                    object.reference.clone(),
                    &object.bytes,
                    factory.original_lineage_capture_dependencies(
                        graph,
                        &object.reference,
                        &object.bytes,
                        self.limits.state.maximum_content_objects,
                    )?,
                )?;
            }
            // The local settled journal points to the pending native snapshot.
            // Snapshot dependencies therefore come from its exact source codec,
            // never from the complete owner evidence list (which would cycle).
            let journal = original.journal();
            objects.insert(
                journal.reference.clone(),
                &journal.bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &journal.reference,
                    &journal.bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
            evidence.push(journal.reference.clone());
            evidence.sort();
            evidence.dedup();
            objects.insert(
                captured.state().reference.clone(),
                &captured.state().bytes,
                factory.original_lineage_capture_dependencies(
                    graph,
                    &captured.state().reference,
                    &captured.state().bytes,
                    self.limits.state.maximum_content_objects,
                )?,
            )?;
            let native = NativeOwnerState {
                owner: captured.owner().clone(),
                participants: captured.participants().to_vec(),
                key: captured.key().clone(),
                cut,
                state: captured.state().reference.clone(),
                evidence,
                artifacts: Vec::new(),
            };
            let domains: Vec<_> = graph
                .ownership_policy()
                .domains
                .iter()
                .filter(|domain| domain.capture_owner_id == native.owner)
                .map(|domain| domain.id.clone())
                .collect();
            let policy = graph
                .ownership_policy()
                .capture_owners
                .iter()
                .find(|owner| owner.owner_id == native.owner)
                .ok_or_else(|| refused("lineage capture owner absent"))?;
            let receipt = OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash("crucible.native-owner-inventory.v1", &native)
                    .map_err(schema)?,
                coordinator: &coordinator_object.reference,
                cut,
                ordinal,
                domains: &domains,
            };
            let mut dependencies = native.evidence.clone();
            dependencies.extend([native.state.clone(), coordinator_object.reference.clone()]);
            let receipt_ref = objects.record(&receipt, dependencies)?;
            let mut binding_hashes = native
                .participants
                .iter()
                .map(|node| {
                    graph
                        .binding(node)
                        .ok_or_else(|| refused("lineage participant binding absent"))?
                        .identity()
                        .map_err(schema)
                })
                .collect::<Result<Vec<_>, _>>()?;
            binding_hashes.sort();
            owners.push(CapturedOwner {
                capture_owner_id: native.owner.clone(),
                participant_ids: native.participants.clone(),
                state_domain_ids: domains,
                binding_hashes,
                state_schema: native.key.schema.clone(),
                representation: CaptureRepresentation::Durable,
                state_ref: Some(native.state.clone()),
                retained_source_ref: None,
                dependencies: policy.dependencies.clone(),
                capture_receipt: receipt_ref,
                extensions: Default::default(),
            });
            states.push(native);
        }
        if restored.is_some() {
            // All native body copies are now enrolled. Release the private
            // Runtime capture read before terminal phases call the full observer.
            drop(captured_bodies);
        }
        owners.sort_by(|left, right| left.capture_owner_id.cmp(&right.capture_owner_id));
        states.sort_by(|left, right| left.owner.cmp(&right.owner));
        let admin = runtime
            .original_capture_journal_with_limit(self.limits.state.maximum_record_bytes)
            .map_err(schema)?;
        let admin_object =
            self.lineage_record(&admin, super::complete_original_index::JOURNAL_MEDIA)?;
        objects.insert(
            admin_object.reference.clone(),
            &admin_object.bytes,
            core_references(&admin, self.limits.state.maximum_record_bytes)?,
        )?;
        let guarantees_ref = objects.record(&serde_json::json!({
            "schema_version":1,"world_repeatability":graph.world_repeatability(),
            "exact_model_continuation":true,"preservation_contract":requirements.preservation_contract,
        }), vec![])?;
        let selected_ref = selected
            .as_ref()
            .map(|selected| selected.record.reference.clone());
        let mut provenance = serde_json::json!({
            "schema_version":1,"source_activation":source.source_activation,"cut":cut,"ordinal":ordinal,
            "native_archive":{"schema_version":3,"content_inventory":2,"original_capture_journal":admin_object.reference},
        });
        let mut provenance_dependencies = vec![admin_object.reference.clone()];
        if let Some(plan) = collecting
            .map(|scope| scope.plan())
            .or_else(|| restored.as_ref().map(|current| current.scope.plan_data()))
        {
            let evidence = plan.evidence();
            provenance["collecting_capture"] = if let Some(scope) = collecting {
                scope.provenance()
            } else {
                restored17::collecting_provenance(plan)
            };
            provenance_dependencies
                .extend([evidence.plan_ref.clone(), evidence.refused_ref.clone()]);
            provenance_dependencies.extend(evidence.sources.iter().cloned());
            provenance_dependencies.sort();
            provenance_dependencies.dedup();
        }
        let provenance_ref = objects.record(&provenance, provenance_dependencies)?;
        let manifest = CaptureManifest {
            schema_version: 1,
            capture_id,
            world_binding_hash: graph.world_binding_hash().clone(),
            scenario_ref: graph.world().scenario_ref.clone(),
            preservation_contract: requirements.preservation_contract,
            cut,
            event_ordinal: ordinal,
            ordering_profile: graph.world().ordering_profile.clone(),
            guarantees_ref,
            coordinator_state_ref: coordinator_object.reference.clone(),
            owners,
            immutable_refs,
            provenance_ref,
            extensions: Default::default(),
        };
        // Current17 funded these two comparison constructors independently in
        // final_snapshot_comparison before any owner effect. The original path
        // keeps its existing construction and accounting behavior.
        if runtime
            .original_lineage_runtime_snapshot(
                cut,
                ordinal,
                lineage_limits,
                self.limits.state.maximum_record_bytes,
            )
            .map_err(schema)?
            != *source
            || runtime
                .original_lineage_scheduler_snapshot(activation, cut, ordinal)
                .map_err(schema)?
                != *scheduler
        {
            return Err(refused(
                "conditional native/runtime state changed during capture",
            ));
        }
        let artifact = objects.record(
            &manifest,
            core_references(&manifest, self.limits.state.maximum_record_bytes)?,
        )?;
        let index = Index {
            original_capture_journal: Some(admin_object.reference),
            schema_version: 3,
            selected_extensions: selected_ref,
            artifact,
            objects: objects.finish(),
            owners: states,
        };
        let mut pending_record = None;
        let legacy_record;
        let record = if let Some(current) = &restored {
            pending_record = Some(self.pending_restored_write17_record_data(
                index.clone(),
                manifest.clone(),
                runtime,
                &captures,
                current.scope,
                current.host,
            )?);
            pending_record
                .as_ref()
                .ok_or_else(|| refused("pending current17 writer record absent"))?
                .record_data()
        } else {
            legacy_record = self.record(index.clone())?;
            &legacy_record
        };
        {
            // Only this actual pre-sign writer can lend OriginalWrite purpose.
            // Source validation still precedes signing/persistence; this witness
            // is neither a load receipt nor native/source acceptance.
            let origin = super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin::original_write(
                self, &record, &captures, runtime,
            )?;
            if let Some(current) = &mut restored {
                let admission = restored17::WriterTerminalAdmission17::new(
                    current.scope,
                    runtime,
                    &captures,
                    &record,
                    &mut *current.after_owner,
                );
                record.authenticate_restored_settled_before_signing_data(
                    graph,
                    factory,
                    lineage_limits,
                    &origin,
                    &admission,
                    named_peak.total().map_err(schema)?,
                )?;
                current
                    .scope
                    .require_terminal_validation_completed_data(runtime, &captures, &record)
                    .map_err(schema)?;
            } else {
                record.complete_original_lineage_content_with_origin(
                    graph,
                    factory,
                    lineage_limits,
                    &origin,
                )?;
            }
        }
        // The same world remains held on every verification or persistence
        // failure. Release neither drops original bodies nor renews lifetime IDs.
        restored17::authenticate_purpose(runtime, collecting, restored.as_ref())?;
        if let Some(scope) = collecting {
            scope.authenticate(&source, &scheduler, &manifest.capture_id, factory)?;
        }
        let durable = if let Some(current) = &restored {
            pending_record
                .take()
                .ok_or_else(|| refused("pending current17 writer capsule absent"))?
                .persist_data(runtime, &captures, current.scope, current.host)?
        } else {
            self.persist(index)?
        };
        if let Some(completed) = completed {
            // Retain the actual committed record before releasing its ticket.
            // A subsequent failure cannot make committed custody disappear.
            *completed = Some(durable);
            let durable = completed
                .as_ref()
                .ok_or_else(|| refused("durable archive output absent"))?;
            captures
                .release_persisted_archive(runtime, durable)
                .map_err(schema)?;
            Ok(None)
        } else {
            captures
                .release_persisted_archive(runtime, &durable)
                .map_err(schema)?;
            Ok(Some(durable))
        }
    }
}

/// Borrows a complete signed source for its installed backend-specific verifier.
///
/// These references are facts, not restoration authority. The installed source
/// validates every native snapshot, original capture request/response prefix,
/// and actual host closure before this archive may be signed or adopted.
pub struct CompleteOriginalArchiveValidation<'a> {
    restoration_data:
        &'a std::cell::RefCell<[Option<super::CompleteOriginalNativeRestorationData>; 4]>,
    lineage_limits: OriginalInputLineageLimits,

    /// Borrows the exact admitted original world and source-selected bindings.
    pub graph: &'a crate::node_admission::AdmittedGraph,
    /// Borrows the independently authenticated index-three source.
    pub archive: &'a NativeArchiveRecord,
    /// Borrows complete unchanged-cut original Runtime7 data.
    pub runtime: &'a crate::node_contract::OriginalLineageRuntimeRecord,
    /// Borrows the same original scheduler queues, credits and frontiers.
    pub scheduling: &'a crate::node_scheduling::SchedulingSnapshot,
    /// Borrows complete lifetime administrative history, without ID renewal.
    pub administrative: &'a crate::node_contract::RuntimeOriginalCaptureJournal,
    /// Borrows the exact verified bounded typed dependency closure.
    pub content: &'a VerifiedStateContent,
    pub(super) validation_origin:
        &'a super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<
            'a,
        >,
}

impl CompleteOriginalArchiveValidation<'_> {
    /// Retains validated native reconstruction DATA for this exact archive owner.
    ///
    /// The Source-specific factory calls this after its genuine cold-owner
    /// reconstruction and semantic checks. The fixed output contains no heap
    /// bank or grant; it preserves actual detailed demand that would otherwise
    /// disappear with the temporary cold decoder. Only the same original owner
    /// row may populate a slot, once. Historical data never creates live rights.
    ///
    /// # Errors
    /// Refuses a foreign owner row, occupied/busy output or changed source origin.
    pub fn retain_original_native_restoration_data(
        &self,
        owner: &super::NativeOwnerState,
        data: super::ValidatedCompleteNativeRestorationData<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.validation_origin
            .authenticate(self.archive)
            .map_err(|_| crate::node_contract::RuntimeError::ForeignAuthority)?;
        let data = data.into_original_data(owner, self.content)?;
        let index = self
            .archive
            .owners()
            .iter()
            .position(|actual| std::ptr::eq(actual, owner))
            .ok_or(crate::node_contract::RuntimeError::ForeignAuthority)?;
        let mut output = self
            .restoration_data
            .try_borrow_mut()
            .map_err(|_| crate::node_contract::RuntimeError::OwnerBusy)?;
        let slot = output
            .get_mut(index)
            .ok_or(crate::node_contract::RuntimeError::ForeignAuthority)?;
        if slot.is_some() {
            return Err(crate::node_contract::RuntimeError::DuplicateOperation);
        }
        *slot = Some(data);
        Ok(())
    }

    /// Returns the unchanged lineage bounds admitted by this Core validation call.
    ///
    /// These limits describe historical input lookup and create no source,
    /// Capture, allocation or fresh-restoration permission.
    pub fn lineage_limits(&self) -> OriginalInputLineageLimits {
        self.lineage_limits
    }
}

impl NativeArchiveRecord {
    /// Authenticates a closed complete-world archive under its installed native codecs.
    ///
    /// This method preserves the separate default-refusing backend/source gate.
    /// Archive grammar, hashes and state keys alone never establish complete
    /// native restoration or permission to issue fresh readiness. This historical
    /// entry requires the actual selected-load accounting receipt. Only the same
    /// active writer uses the distinct private pre-sign validation origin.
    ///
    /// # Errors
    /// Refuses another graph, missing original history or dependency roles,
    /// changed native owner receipts, moving cuts, unsupported installed codecs
    /// or exhausted metadata/content credits.
    pub fn complete_original_lineage_content(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
    ) -> Result<VerifiedStateContent, StateError> {
        let origin = super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin::selected_load(self)?;
        self.complete_original_lineage_content_with_origin(graph, factory, limits, &origin)
    }

    pub(super) fn complete_original_lineage_content_with_restoration_data(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
    ) -> Result<
        (
            VerifiedStateContent,
            [Option<super::CompleteOriginalNativeRestorationData>; 4],
        ),
        StateError,
    > {
        let origin = super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin::selected_load(self)?;
        self.complete_original_lineage_content_and_restoration_data_with_origin(
            graph, factory, limits, &origin,
        )
    }

    fn complete_original_lineage_content_with_origin(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
        origin: &super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<'_>,
    ) -> Result<VerifiedStateContent, StateError> {
        self.complete_original_lineage_content_and_restoration_data_with_origin(
            graph, factory, limits, origin,
        )
        .map(|(content, _)| content)
    }

    fn complete_original_lineage_content_and_restoration_data_with_origin(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
        origin: &super::storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<'_>,
    ) -> Result<
        (
            VerifiedStateContent,
            [Option<super::CompleteOriginalNativeRestorationData>; 4],
        ),
        StateError,
    > {
        origin.authenticate(self)?;
        let administrative = self.original_capture_journal()?;
        if !graph.selected_extensions().is_empty()
            || self.manifest().world_binding_hash != *graph.world_binding_hash()
            || self.owners().len() != 4
            || self.manifest().owners.len() != 4
        {
            return Err(refused("unsupported complete original source world"));
        }
        super::super::validation::validate_manifest(
            graph,
            self.manifest(),
            &StateRequirements {
                preservation_contract: Id::new("source-owned.packet-complete-original-lineage/5")
                    .map_err(schema)?,
                exact_model_continuation: true,
                deterministic: false,
                restore_mode: StateRestoreMode::DurableRestart,
            },
            self.limits.state,
        )?;
        let content = verify_complete_closure(
            vec![self.artifact().clone()],
            &SignedRows(self),
            self.limits.state,
        )?;
        if content.object_count() != self.index.objects.len() {
            return Err(refused("complete original index has unowned typed roles"));
        }
        for root in required_immutable_refs(graph, self.limits.state)? {
            if !self.manifest().immutable_refs.contains(&root) {
                return Err(refused(
                    "complete original manifest omits admitted immutable role",
                ));
            }
        }
        let coordinator_bytes = content
            .get(&self.manifest().coordinator_state_ref)
            .ok_or_else(|| refused("complete original coordinator is absent"))?;
        let coordinator: OriginalLineageCoordinator =
            decode_record(coordinator_bytes, self.limits.state.maximum_record_bytes)?;
        let runtime_bytes = content
            .get(&coordinator.runtime)
            .ok_or_else(|| refused("complete original Runtime7 is absent"))?;
        let runtime: crate::node_contract::OriginalLineageRuntimeRecord =
            decode_record(runtime_bytes, self.limits.state.maximum_record_bytes)?;
        runtime
            .validate_metadata(limits, self.limits.state.maximum_record_bytes)
            .map_err(schema)?;
        let scheduling_bytes = content
            .get(&coordinator.scheduler)
            .ok_or_else(|| refused("complete original scheduler is absent"))?;
        let scheduling: crate::node_scheduling::SchedulingSnapshot =
            decode_record(scheduling_bytes, self.limits.state.maximum_record_bytes)?;
        if runtime.capture_cut != self.manifest().cut
            || runtime.capture_ordinal != self.manifest().event_ordinal
            || scheduling.capture_cut != runtime.capture_cut
            || scheduling.capture_ordinal != runtime.capture_ordinal
            || scheduling.world_binding_hash != self.manifest().world_binding_hash
        {
            return Err(refused(
                "complete original source changes capture coordinates or world",
            ));
        }
        self.validate_complete_original_owner_receipts(graph, &content)?;
        let restoration_data = std::cell::RefCell::new([None; 4]);
        factory.authenticate_complete_original_lineage_archive(
            CompleteOriginalArchiveValidation {
                restoration_data: &restoration_data,
                lineage_limits: limits,
                graph,
                archive: self,
                runtime: &runtime,
                scheduling: &scheduling,
                administrative: &administrative,
                content: &content,
                validation_origin: origin,
            },
        )?;
        origin.authenticate(self)?;
        Ok((content, restoration_data.into_inner()))
    }
}

impl NativeArchiveRecord {
    pub(super) fn validate_complete_original_owner_receipts(
        &self,
        graph: &AdmittedGraph,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        for (native, captured) in self.owners().iter().zip(&self.manifest.owners) {
            if native.owner != captured.capture_owner_id
                || native.participants != captured.participant_ids
                || native.cut != self.manifest.cut
                || Some(&native.state) != captured.state_ref.as_ref()
                || native.key.schema != captured.state_schema
                || captured.retained_source_ref.is_some()
                || native
                    .evidence
                    .iter()
                    .any(|reference| content.get(reference).is_none())
            {
                return Err(refused("lineage native and manifest owner scopes differ"));
            }
            for participant in &native.participants {
                let binding = graph
                    .binding(participant)
                    .ok_or_else(|| refused("lineage binding absent"))?;
                if !profile::matches_selected_complete_state_profile(
                    &native.key,
                    &binding.compatibility,
                ) {
                    return Err(refused(
                        "lineage owner crossed selected implementation/profile",
                    ));
                }
            }
            let receipt = OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash("crucible.native-owner-inventory.v1", native)
                    .map_err(schema)?,
                coordinator: &self.manifest.coordinator_state_ref,
                cut: self.manifest.cut,
                ordinal: self.manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            bounded_record(&receipt, self.limits.state.maximum_record_bytes)?;
            let expected =
                canonical::canonical_json(&serde_json::to_value(receipt).map_err(schema)?)
                    .map_err(schema)?;
            let bytes = content
                .get(&captured.capture_receipt)
                .ok_or_else(|| refused("lineage owner receipt absent"))?;
            let mut dependencies = native.evidence.clone();
            dependencies.extend([
                native.state.clone(),
                self.manifest.coordinator_state_ref.clone(),
            ]);
            dependencies.sort();
            dependencies.dedup();
            let row = self
                .index
                .objects
                .iter()
                .find(|row| row.reference == captured.capture_receipt)
                .ok_or_else(|| refused("lineage owner receipt row absent"))?;
            if bytes != expected || row.dependencies != dependencies {
                return Err(refused(
                    "lineage original owner receipt or adjacency differs",
                ));
            }
        }
        Ok(())
    }
}
