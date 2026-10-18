//! Performs strict current17 loading under retained attempt and finite phase credit.

use super::*;
use crate::node_contract::{
    HostSchedulingContinuationLimits, SavedRuntimeResult,
    authenticate_host_scheduling_restored_continuation_schema17_data,
};
use crate::node_state::{
    StateRequirements, StateRestoreMode, closure::bounded_record, schema,
    validation::required_immutable_refs,
};
use crucible_node_contract::{Id, canonical};

impl NativeArchiveRecord {
    // Pure terminal DATA cannot escape into a fresh Source or live grant. All
    // Runtime/native once owners, actual outputs and failed Window phase remain
    // retained independently when this local decoder is dropped on refusal.
    pub(in crate::node_state::native) fn authenticate_restored_settled_before_signing_data(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        lineage: OriginalInputLineageLimits,
        origin: &storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<'_>,
        admission: &dyn RestoredArchive17ValidationAdmission,
        additional: usize,
    ) -> Result<(), StateError> {
        origin.authenticate(self)?;
        if origin.original_write_runtime_data(self)?.is_none() {
            return Err(refused(
                "terminal current17 verifier requires actual pending writer custody",
            ));
        }
        let cursor = terminal_construction::Cursor::new(admission);
        cursor.begin(
            RestoredArchive17ValidationStage::MetadataDag,
            std::mem::size_of::<CompleteRestoredSettledArchiveValidationAttempt>(),
        )?;
        let (retained, transient) = terminal_construction::metadata_geometry(self, graph, lineage)?;
        cursor.construct(
            RestoredArchive17ValidationStage::MetadataDag,
            retained,
            transient,
        )?;
        let mut attempt = CompleteRestoredSettledArchiveValidationAttempt::new(self, lineage);
        let result = self.validate_restored_settled_into(
            graph,
            factory,
            lineage,
            additional,
            origin,
            &mut attempt,
            Some(&cursor),
        );
        if result.is_err() {
            attempt.stage.set(ValidationStage::Failed);
        }
        result
    }

    /// Retains and validates the current17 family before any fresh reconstruction.
    ///
    /// The caller retains this exact archive occurrence and the output attempt
    /// throughout the call and any refusal. No native owner, Source, ticket or
    /// target World is created here; only the same completed validated facts may
    /// later move into the actual source constructor.
    ///
    /// # Errors
    /// Refuses an unauthenticated/foreign archive, a reused attempt, incomplete
    /// closure, another family, malformed current data, factory refusal or finite
    /// storage excess. Initialized partials remain in `attempt` on every error.
    pub fn complete_restored_settled_content_with_restoration_data_into(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        limits: OriginalInputLineageLimits,
        additional_retained_bytes: usize,
        attempt: &mut Option<CompleteRestoredSettledArchiveValidationAttempt>,
    ) -> Result<(), StateError> {
        if attempt.is_some() {
            return Err(refused("settled17 validation attempt is already spent"));
        }
        *attempt = Some(CompleteRestoredSettledArchiveValidationAttempt::new(
            self, limits,
        ));
        let owner = attempt
            .as_mut()
            .ok_or_else(|| refused("settled17 validation owner absent"))?;
        let origin = storage::complete_original_validation_origin::CompleteArchiveValidationOrigin::selected_load(self)?;
        let result = self.validate_restored_settled_into(
            graph,
            factory,
            limits,
            additional_retained_bytes,
            &origin,
            owner,
            None,
        );
        if result.is_err() {
            owner.stage.set(ValidationStage::Failed);
        }
        result
    }

    fn validate_restored_settled_into(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        lineage: OriginalInputLineageLimits,
        additional_retained_bytes: usize,
        origin: &storage::complete_original_validation_origin::CompleteArchiveValidationOrigin<'_>,
        owner: &mut CompleteRestoredSettledArchiveValidationAttempt,
        terminal: Option<&terminal_construction::Cursor<'_>>,
    ) -> Result<(), StateError> {
        owner.authenticate(self)?;
        origin.authenticate(self)?;
        if self.manifest().coordinator_state_ref.media_type
            != crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
            || !graph.selected_extensions().is_empty()
            || self.manifest().world_binding_hash != *graph.world_binding_hash()
            || self.owners().len() != 4 || self.manifest().owners.len() != 4
        {
            return Err(refused("settled17 archive world or owner roster differs"));
        }
        if terminal.is_some() {
            // A pending write capsule deliberately performs no early parser or
            // inventory allocation. This real Metadata phase owns those checks.
            storage::validate_index(&self.index, self.limits)?;
        }
        crate::node_state::validation::validate_manifest(
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
        admit(self, owner, additional_retained_bytes, fixed_scratch())?;
        self.authenticate_restored_metadata_dag_into(owner, additional_retained_bytes)?;
        if let Some(cursor) = terminal {
            cursor.finish(RestoredArchive17ValidationStage::MetadataDag, self, owner)?;
            cursor.begin(RestoredArchive17ValidationStage::ContentClosure, 20)?;
            let (retained, transient) = terminal_construction::closure_geometry(self)?;
            cursor.construct(
                RestoredArchive17ValidationStage::ContentClosure,
                retained,
                transient,
            )?;
        }
        let mut maximum_adjacency = 0usize;
        for row in &self.index.objects {
            let mut requested = row
                .dependencies
                .len()
                .checked_mul(std::mem::size_of::<ContentRef>())
                .ok_or_else(|| refused("settled17 signed adjacency extent overflow"))?;
            for reference in &row.dependencies {
                requested = requested
                    .checked_add(NodeRuntime::capture_reference_storage(reference).map_err(schema)?)
                    .ok_or_else(|| refused("settled17 signed adjacency backing overflow"))?;
            }
            maximum_adjacency = maximum_adjacency.max(requested);
        }
        let outside_closure = self
            .capture_owned_storage()
            .map_err(schema)?
            .checked_add(owner.retained_requested_storage_data().map_err(schema)?)
            .and_then(|bytes| {
                bytes.checked_sub(owner.closure.retained_requested_storage_data().ok()?)
            })
            .and_then(|bytes| bytes.checked_add(additional_retained_bytes))
            .and_then(|bytes| bytes.checked_add(fixed_scratch()))
            .ok_or_else(|| refused("settled17 closure enclosing owner overflow"))?;
        let mut closure_limits = self.limits.state;
        closure_limits.maximum_total_content_bytes = closure_limits
            .maximum_total_content_bytes
            .min(self.limits.native.maximum_total_record_bytes);
        owner.closure.verify_into(
            self.artifact(),
            &lineage_capture::SignedRows(self),
            closure_limits,
            outside_closure,
            maximum_adjacency,
        )?;
        owner.content = Some(owner.closure.take_verified_data()?);
        if terminal.is_some() {
            // The writer-private capsule retained the actual typed Manifest.
            // Join its entire canonical body to the verified immutable object
            // before any Source/parent collector can consume this archive.
            let literal = owner
                .content
                .as_ref()
                .and_then(|content| content.get(self.artifact()))
                .ok_or_else(|| refused("terminal Manifest immutable body absent"))?;
            let value = serde_json::to_value(self.manifest()).map_err(schema)?;
            let encoded = canonical::canonical_json(&value).map_err(schema)?;
            if encoded.as_slice() != literal {
                return Err(refused(
                    "terminal Manifest typed record differs from actual immutable bytes",
                ));
            }
        }
        if let Some(cursor) = terminal {
            cursor.finish(
                RestoredArchive17ValidationStage::ContentClosure,
                self,
                owner,
            )?;
            cursor.begin(RestoredArchive17ValidationStage::Administrative, 20)?;
            let content = owner
                .content
                .as_ref()
                .ok_or_else(|| refused("terminal verified content absent"))?;
            let reference = self
                .index
                .original_capture_journal
                .as_ref()
                .ok_or_else(|| refused("terminal administrative role absent"))?;
            let bytes = content
                .get(reference)
                .ok_or_else(|| refused("terminal administrative body absent"))?;
            let (retained, transient) = terminal_construction::administrative_geometry(
                self, bytes, content, lineage, graph,
            )?;
            cursor.construct(
                RestoredArchive17ValidationStage::Administrative,
                retained,
                transient,
            )?;
        }
        owner.stage.set(ValidationStage::Content);
        let content = owner
            .content
            .as_ref()
            .ok_or_else(|| refused("settled17 content absent"))?;
        if content.object_count() != self.index.objects.len() {
            return Err(refused("settled17 index has unowned typed metadata roles"));
        }
        for root in required_immutable_refs(graph, self.limits.state)? {
            if !self.manifest().immutable_refs.contains(&root) {
                return Err(refused("settled17 manifest omits selected immutable role"));
            }
        }
        owner.administrative = Some(complete_original_index::authenticate_admitted(
            self,
            owner
                .retained_requested_storage_data()
                .map_err(schema)?
                .checked_add(additional_retained_bytes)
                .ok_or_else(|| refused("settled17 administrative retained overflow"))?,
            self.limits.state.maximum_total_content_bytes,
        )?);

        if let Some(cursor) = terminal {
            cursor.finish(
                RestoredArchive17ValidationStage::Administrative,
                self,
                owner,
            )?;
            cursor.begin(RestoredArchive17ValidationStage::Coordinator, 20)?;
            let content = owner
                .content
                .as_ref()
                .ok_or_else(|| refused("terminal verified content absent"))?;
            let bytes = content
                .get(&self.manifest().coordinator_state_ref)
                .ok_or_else(|| refused("terminal coordinator body absent"))?;
            let row = CoordinatorCommitmentCheckpoint17::prospective_storage_data(
                bytes.len(),
                maximum(self),
            )
            .map_err(schema)?;
            let references =
                NodeRuntime::capture_reference_storage(&self.manifest().coordinator_state_ref)
                    .map_err(schema)?;
            // Runtime fullref lives in the parsed checkpoint; add the complete
            // typed row's retained bound for its independent clone as well.
            cursor.construct(
                RestoredArchive17ValidationStage::Coordinator,
                terminal_construction::add(
                    row.retained_requested_bytes_data(),
                    terminal_construction::add(references, row.retained_requested_bytes_data())?,
                )?,
                row.maximum_simultaneous_transient_bytes_data(),
            )?;
        }
        let content = owner
            .content
            .as_ref()
            .ok_or_else(|| refused("settled17 content absent"))?;
        let coordinator_bytes = content
            .get(&self.manifest().coordinator_state_ref)
            .ok_or_else(|| refused("settled17 coordinator object absent"))?;
        admit_decode(
            self,
            owner,
            coordinator_bytes,
            additional_retained_bytes,
            false,
        )?;
        let checkpoint_credit = CoordinatorCommitmentCheckpoint17::prospective_storage_data(
            coordinator_bytes.len(),
            self.limits
                .state
                .maximum_total_content_bytes
                .min(self.limits.native.maximum_total_record_bytes),
        )
        .map_err(schema)?;
        admit(
            self,
            owner,
            additional_retained_bytes,
            checkpoint_credit.requested_bytes_data(),
        )?;
        owner.coordinator = Some(decode_record(
            coordinator_bytes,
            self.limits.state.maximum_record_bytes,
        )?);
        let coordinator = owner
            .coordinator
            .as_ref()
            .ok_or_else(|| refused("settled17 coordinator absent"))?;
        coordinator
            .authenticate_structure_data(
                &coordinator.safe_point.runtime,
                self.manifest().cut,
                self.manifest().event_ordinal,
            )
            .map_err(schema)?;
        coordinator.authenticate_prefix_data().map_err(schema)?;
        if terminal.is_none() {
            self.authenticate_coordinator_ancestry17_data(owner, additional_retained_bytes)?;
        }

        let coordinator = owner
            .coordinator
            .as_ref()
            .ok_or_else(|| refused("settled17 coordinator absent after ancestry validation"))?;
        let reference_storage =
            NodeRuntime::capture_reference_storage(&coordinator.safe_point.runtime)
                .map_err(schema)?
                .checked_add(
                    NodeRuntime::capture_reference_storage(&self.manifest().coordinator_state_ref)
                        .map_err(schema)?,
                )
                .ok_or_else(|| refused("settled17 coordinator reference backing overflow"))?;
        admit(self, owner, additional_retained_bytes, reference_storage)?;
        owner.runtime_reference = Some(coordinator.safe_point.runtime.clone());
        owner.checkpoint_reference = Some(self.manifest().coordinator_state_ref.clone());
        if let Some(cursor) = terminal {
            cursor.finish(RestoredArchive17ValidationStage::Coordinator, self, owner)?;
            cursor.begin(RestoredArchive17ValidationStage::CoordinatorAncestry, 20)?;
            let (retained, transient) =
                terminal_construction::coordinator_ancestry_geometry(self, owner)?;
            cursor.construct(
                RestoredArchive17ValidationStage::CoordinatorAncestry,
                retained,
                transient,
            )?;
        }
        if terminal.is_some() {
            self.authenticate_coordinator_ancestry17_data(owner, additional_retained_bytes)?;
        }
        if let Some(cursor) = terminal {
            cursor.finish(
                RestoredArchive17ValidationStage::CoordinatorAncestry,
                self,
                owner,
            )?;
            cursor.begin(RestoredArchive17ValidationStage::Host, 20)?;
        }

        let mut hosts = self.owners().iter().filter(|row| {
            row.key.implementation.as_str() == "source-owned.host-scheduling-owner/2"
        });
        let host_owner = hosts
            .next()
            .ok_or_else(|| refused("settled17 Host owner absent"))?;
        if hosts.next().is_some() || !host_owner.artifacts.is_empty() {
            return Err(refused("settled17 Host owner roster differs"));
        }
        authenticate_host_scheduling_restored_continuation_schema17_data(&host_owner.key.schema)
            .map_err(schema)?;
        let content = owner
            .content
            .as_ref()
            .ok_or_else(|| refused("settled17 content absent"))?;
        let host_bytes = content
            .get(&host_owner.state)
            .ok_or_else(|| refused("settled17 Host body absent"))?;
        if let Some(cursor) = terminal {
            let (retained, transient) =
                terminal_construction::decode_geometry(host_bytes, maximum(self), true, lineage)?;
            cursor.construct(RestoredArchive17ValidationStage::Host, retained, transient)?;
        }
        admit_decode(self, owner, host_bytes, additional_retained_bytes, true)?;
        owner.host = Some(
            HostSchedulingRestoredContinuationRecord17::decode(
                host_bytes,
                HostSchedulingContinuationLimits {
                    maximum_record_bytes: self
                        .limits
                        .state
                        .maximum_record_bytes
                        .min(self.limits.native.maximum_record_bytes),
                    lineage,
                },
            )
            .map_err(schema)?,
        );
        owner.stage.set(ValidationStage::Host);
        if let Some(cursor) = terminal {
            cursor.finish(RestoredArchive17ValidationStage::Host, self, owner)?;
        }
        let host = owner
            .host
            .as_ref()
            .ok_or_else(|| refused("settled17 Host record absent"))?;
        let content = owner
            .content
            .as_ref()
            .ok_or_else(|| refused("settled17 content absent"))?;
        let admin = owner
            .administrative
            .as_ref()
            .ok_or_else(|| refused("settled17 administrative record absent"))?;
        let current = admin
            .attempts
            .last()
            .ok_or_else(|| refused("settled17 administrative cut absent"))?;
        if host.runtime.source_activation != current.source_activation
            || host.runtime.capture_cut != current.cut
            || host.runtime.capture_ordinal != current.ordinal
            || host_owner.owner != host.source.owner.owner.id
            || host_owner.participants.as_slice()
                != std::slice::from_ref(&host.source.descriptor.id)
            || host.runtime.capture_cut != self.manifest().cut
            || host.runtime.capture_ordinal != self.manifest().event_ordinal
            || host
                .runtime
                .operations
                .iter()
                .any(|operation| !matches!(operation.result, SavedRuntimeResult::Acknowledged(_)))
        {
            return Err(refused(
                "settled17 current Host or administrative scope differs",
            ));
        }
        authenticate_host_graph(host, graph, content)?;
        let coordinator = owner
            .coordinator
            .as_ref()
            .ok_or_else(|| refused("settled17 coordinator absent"))?;
        authenticate_serialized_body(
            self,
            owner,
            &host.runtime,
            &coordinator.safe_point.runtime,
            additional_retained_bytes,
            terminal,
            RestoredArchive17ValidationStage::RuntimeIdentity,
        )?;
        authenticate_serialized_body(
            self,
            owner,
            &host.scheduling,
            &coordinator.safe_point.scheduling,
            additional_retained_bytes,
            terminal,
            RestoredArchive17ValidationStage::SchedulingIdentity,
        )?;
        if coordinator.activation.activation_id != host.runtime.source_activation.activation_id
            || coordinator.activation.world_generation != host.runtime.source_activation.generation
            || coordinator.activation.world_binding
                != host.runtime.source_activation.world_binding_hash
            || coordinator.activation.boundary != host.runtime.source_activation.boundary
        {
            return Err(refused(
                "settled17 checkpoint activation differs from current Runtime",
            ));
        }
        for object in &host.objects {
            if content.get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(refused("settled17 Host original body differs from closure"));
            }
        }
        if let Some(cursor) = terminal {
            cursor.begin(RestoredArchive17ValidationStage::OwnerReceipts, 20)?;
            let work = self.restored_settled_owner_receipt_construction_data(graph)?;
            cursor.construct(RestoredArchive17ValidationStage::OwnerReceipts, 0, work)?;
        }
        self.validate_restored_settled_owner_receipts(graph, owner, additional_retained_bytes)?;
        if let Some(cursor) = terminal {
            cursor.finish(RestoredArchive17ValidationStage::OwnerReceipts, self, owner)?;
        }
        admit(self, owner, additional_retained_bytes, 0)?;
        let terminal_prefix_retained_bytes = if terminal.is_some() {
            owner
                .retained_requested_storage_data()
                .map_err(schema)?
                .checked_add(self.capture_owned_storage().map_err(schema)?)
                .and_then(|bytes| {
                    bytes.checked_add(std::mem::size_of::<
                        CompleteRestoredSettledArchiveValidation<'_>,
                    >())
                })
                .ok_or_else(|| refused("terminal Core prefix census overflow"))?
        } else {
            0
        };
        factory.authenticate_complete_restored_settled_archive(
            CompleteRestoredSettledArchiveValidation {
                restoration_data: &owner.restoration_data,
                collection: &owner.collection,
                collection_phase: &owner.collection_phase,
                lineage_limits: lineage,
                terminal_admission: terminal
                    .map(|cursor| cursor as &dyn RestoredArchive17ValidationAdmission),
                terminal_prefix_retained_bytes,
                validation_origin: origin,
                graph,
                archive: self,
                host,
                runtime: &host.runtime,
                scheduling: &host.scheduling,
                administrative: admin,
                content,
                checkpoint_reference: owner
                    .checkpoint_reference
                    .as_ref()
                    .ok_or_else(|| refused("settled17 checkpoint reference absent"))?,
                checkpoint: coordinator,
                coordinator_ancestry: &owner.coordinator_ancestry,
            },
        )?;
        if let Some(cursor) = terminal {
            cursor.begin(RestoredArchive17ValidationStage::FinalConjunction, 0)?;
            cursor.construct(RestoredArchive17ValidationStage::FinalConjunction, 0, 0)?;
        }
        origin.authenticate(self)?;
        let cached = owner
            .restoration_data
            .try_borrow()
            .map_err(|_| refused("settled17 reconstruction cache busy"))?;
        for (index, native) in self.owners().iter().enumerate() {
            if (native.key.implementation.as_str() == "source-owned.packet-native/5")
                != cached[index].is_some()
            {
                return Err(refused("settled17 native reconstruction DATA incomplete"));
            }
        }
        drop(cached);
        owner
            .collection
            .try_borrow()
            .map_err(|_| refused("settled17 decoded owner collection is busy"))?
            .as_ref()
            .ok_or_else(|| refused("settled17 decoded owner collection absent"))?
            .authenticate_completed_data(self)
            .map_err(schema)?;
        owner.stage.set(ValidationStage::Verified);
        if let Some(cursor) = terminal {
            cursor.finish(
                RestoredArchive17ValidationStage::FinalConjunction,
                self,
                owner,
            )?;
        }
        Ok(())
    }
}

pub(super) fn admit(
    archive: &NativeArchiveRecord,
    attempt: &CompleteRestoredSettledArchiveValidationAttempt,
    additional: usize,
    temporary: usize,
) -> Result<(), StateError> {
    let retained = archive
        .capture_owned_storage()
        .map_err(schema)?
        .checked_add(attempt.retained_requested_storage_data().map_err(schema)?)
        .and_then(|bytes| bytes.checked_add(additional))
        .ok_or_else(|| refused("settled17 named owner overflow"))?;
    storage::admit(
        retained,
        temporary,
        archive
            .limits
            .state
            .maximum_total_content_bytes
            .min(archive.limits.native.maximum_total_record_bytes),
    )
}

fn admit_decode(
    archive: &NativeArchiveRecord,
    attempt: &CompleteRestoredSettledArchiveValidationAttempt,
    bytes: &[u8],
    additional: usize,
    host: bool,
) -> Result<(), StateError> {
    if bytes.len() > archive.limits.state.maximum_record_bytes
        || bytes.len() > archive.limits.native.maximum_record_bytes
    {
        return Err(refused("settled17 component exceeds record credit"));
    }
    let maximum = archive
        .limits
        .state
        .maximum_total_content_bytes
        .min(archive.limits.native.maximum_total_record_bytes);
    let decode = if host {
        core_decode_credit::preflight_restored_host17(bytes, maximum)
    } else {
        core_decode_credit::preflight_archive(bytes, maximum)
    }
    .map_err(schema)?;
    let validation = core_decode_credit::validation_storage(
        &decode,
        HostSchedulingContinuationLimits {
            maximum_record_bytes: bytes.len(),
            lineage: OriginalInputLineageLimits::default(),
        },
    )
    .map_err(schema)?;
    admit(
        archive,
        attempt,
        additional,
        decode
            .total()
            .map_err(schema)?
            .checked_add(validation)
            .and_then(|bytes| bytes.checked_add(fixed_scratch()))
            .ok_or_else(|| refused("settled17 decoder work overflow"))?,
    )
}

fn authenticate_serialized_body(
    archive: &NativeArchiveRecord,
    attempt: &CompleteRestoredSettledArchiveValidationAttempt,
    value: &impl serde::Serialize,
    reference: &ContentRef,
    additional: usize,
    terminal: Option<&terminal_construction::Cursor<'_>>,
    stage: RestoredArchive17ValidationStage,
) -> Result<(), StateError> {
    if let Some(cursor) = terminal {
        cursor.begin(stage, 20)?;
    }
    let maximum = archive
        .limits
        .state
        .maximum_total_content_bytes
        .min(archive.limits.native.maximum_total_record_bytes);
    let serialization =
        NodeRuntime::capture_serialization_storage(value, maximum).map_err(schema)?;
    let encoded = NodeRuntime::capture_encoded_output_storage(value, maximum).map_err(schema)?;
    if let Some(cursor) = terminal {
        cursor.construct(
            stage,
            0,
            terminal_construction::add(serialization, encoded)?,
        )?;
    }
    admit(
        archive,
        attempt,
        additional,
        serialization
            .checked_add(encoded)
            .and_then(|bytes| bytes.checked_add(fixed_scratch()))
            .ok_or_else(|| refused("settled17 current record verification overflow"))?,
    )?;
    let bytes =
        canonical::canonical_json(&serde_json::to_value(value).map_err(schema)?).map_err(schema)?;
    let content = attempt
        .content
        .as_ref()
        .ok_or_else(|| refused("settled17 content absent"))?;
    if content.get(reference) != Some(bytes.as_slice()) {
        return Err(refused(
            "settled17 current record differs from signed object",
        ));
    }
    reference.verify(&bytes).map_err(schema)?;
    if let Some(cursor) = terminal {
        cursor.finish(stage, archive, attempt)?;
    }
    Ok(())
}

fn authenticate_host_graph(
    host: &HostSchedulingRestoredContinuationRecord17,
    graph: &crate::node_admission::AdmittedGraph,
    content: &crate::node_state::VerifiedStateContent,
) -> Result<(), StateError> {
    if graph.descriptor(&host.source.descriptor.id) != Some(&host.source.descriptor)
        || graph.binding(&host.source.descriptor.id) != Some(&host.source.binding)
        || graph.owner(&host.source.owner.owner.id) != Some(&host.source.owner)
        || graph.operating_policy(&host.source.descriptor.id) != Some(&host.source.operating_policy)
        || graph.guarantees(&host.source.descriptor.id) != Some(&host.source.guarantees)
    {
        return Err(refused(
            "settled17 Host selection differs from actual historical graph",
        ));
    }
    let mut semantic = host.ancestry.first_semantic.iter();
    for node in graph
        .node_ids()
        .filter(|node| *node != &host.source.descriptor.id)
    {
        let row = semantic
            .next()
            .ok_or_else(|| refused("settled17 semantic ancestry row absent"))?;
        if &row.node != node || content.get(&row.object).is_none() {
            return Err(refused("settled17 semantic ancestry roster differs"));
        }
    }
    if semantic.next().is_some()
        || content.get(&host.ancestry.parent_archive_index).is_none()
        || content.get(&host.ancestry.first_host).is_none()
    {
        return Err(refused("settled17 immutable ancestry closure incomplete"));
    }
    Ok(())
}

pub(super) fn fixed_scratch() -> usize {
    std::mem::size_of::<CompleteRestoredSettledArchiveValidation<'static>>()
        + NodeRuntime::capture_serialization_counter_scratch_data()
        + core_decode_credit::scanner_storage()
        + complete_restored_settled_archive_validation_counter_scratch_data()
        + crucible_node_provider::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
        + std::mem::size_of::<crucible_node_contract::HashRef>()
        + 64 + "blake3-256".len() + "cnp.blob.v1".len()
}

fn maximum(archive: &NativeArchiveRecord) -> usize {
    archive
        .limits
        .state
        .maximum_total_content_bytes
        .min(archive.limits.native.maximum_total_record_bytes)
}
