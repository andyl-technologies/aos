//! Prices the actual Core prefix of the pure current17 terminal verifier.
//!
//! Each row covers all still-live prior cache owners and the next constructor.
//! Quote work is independently admitted before scanner/metadata entry. The
//! cursor forwards Source/parent phases and saves their actual finished census;
//! the final conjunction therefore never walks an unadmitted cache to seed work.

use super::*;
use crate::node_state::schema;
use crucible_node_contract::{HashRef, Id};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

pub(super) struct Cursor<'a> {
    admission: &'a dyn RestoredArchive17ValidationAdmission,
    retained: Cell<usize>,
}

impl<'a> Cursor<'a> {
    pub(super) fn new(admission: &'a dyn RestoredArchive17ValidationAdmission) -> Self {
        Self {
            admission,
            retained: Cell::new(0),
        }
    }

    pub(super) fn begin(
        &self,
        stage: RestoredArchive17ValidationStage,
        quote_transient: usize,
    ) -> Result<(), StateError> {
        self.begin_stage_data(RestoredArchive17ValidationPrewalkData::new_data(
            RestoredArchive17ValidationStep::ordinary_data(stage)?,
            self.retained.get(),
            quote_transient,
            scratch(),
        )?)
    }

    pub(super) fn construct(
        &self,
        stage: RestoredArchive17ValidationStage,
        retained: usize,
        transient: usize,
    ) -> Result<(), StateError> {
        self.construct_stage_data(RestoredArchive17ValidationConstructionData::new_data(
            RestoredArchive17ValidationStep::ordinary_data(stage)?,
            self.retained.get(),
            retained,
            transient,
            scratch(),
        )?)
    }

    pub(super) fn finish(
        &self,
        stage: RestoredArchive17ValidationStage,
        archive: &NativeArchiveRecord,
        owner: &CompleteRestoredSettledArchiveValidationAttempt,
    ) -> Result<(), StateError> {
        let actual = add(
            archive.capture_owned_storage().map_err(schema)?,
            owner.retained_requested_storage_data().map_err(schema)?,
        )?;
        self.finish_stage_data(
            RestoredArchive17ValidationStep::ordinary_data(stage)?,
            actual,
        )
    }
}

impl RestoredArchive17ValidationAdmission for Cursor<'_> {
    fn begin_stage_data(
        &self,
        row: RestoredArchive17ValidationPrewalkData,
    ) -> Result<(), StateError> {
        self.admission.begin_stage_data(row)
    }
    fn construct_stage_data(
        &self,
        row: RestoredArchive17ValidationConstructionData,
    ) -> Result<(), StateError> {
        self.admission.construct_stage_data(row)
    }
    fn finish_stage_data(
        &self,
        step: RestoredArchive17ValidationStep,
        actual: usize,
    ) -> Result<(), StateError> {
        self.admission.finish_stage_data(step, actual)?;
        self.retained.set(actual);
        Ok(())
    }
}

pub(super) fn scratch() -> usize {
    validation::fixed_scratch()
        + storage::fixed_storage()
        + size_of::<Cursor<'_>>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<Result<RestoredArchive17ValidationConstructionData, StateError>>()
        + size_of::<[usize; 12]>()
        + size_of::<std::slice::Iter<'_, storage::Object>>()
        + size_of::<std::slice::Iter<'_, ContentRef>>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<BTreeSet<ContentRef>>()
        + size_of::<BTreeMap<HashRef, ContentRef>>()
        + size_of::<BTreeSet<Id>>()
        + size_of::<BTreeSet<&Id>>()
        + size_of::<Result<usize, RuntimeError>>()
        + crucible_node_provider::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}

pub(super) fn metadata_geometry(
    archive: &NativeArchiveRecord,
    graph: &crate::node_admission::AdmittedGraph,
    lineage: OriginalInputLineageLimits,
) -> Result<(usize, usize), StateError> {
    let rows = archive.index.objects.len();
    let depth = archive
        .limits
        .state
        .maximum_dependency_depth
        .checked_add(1)
        .ok_or_else(|| refused("terminal DAG depth overflow"))?
        .min(rows);
    let work = add(
        rows,
        add(
            multiply(rows, size_of::<usize>())?,
            multiply(depth, size_of::<dag::Frame>())?,
        )?,
    )?;
    // The quote's real empty decoder has no native/Source/once effect. Its exact
    // root and empty-map census execute within the separately funded prewalk T.
    let empty = CompleteRestoredSettledArchiveValidationAttempt::new(archive, lineage);
    let retained = add(
        add(
            empty.retained_requested_storage_data().map_err(schema)?,
            archive.capture_owned_storage().map_err(schema)?,
        )?,
        work,
    )?;
    let manifest = archive.manifest();
    let mut manifest_work = multiply(
        NodeRuntime::capture_manifest_storage(manifest).map_err(schema)?,
        2,
    )?;
    // validate_manifest owns expected/actual IDs, per-owner domain/hash Vecs and
    // the seen-domain BTreeSet. Cloned key validation keeps two adjacent keys.
    for owner in graph.owners() {
        manifest_work = add(
            manifest_work,
            add(size_of::<Id>(), owner.owner.id.allocated_capacity())?,
        )?;
        manifest_work = add(
            manifest_work,
            multiply(owner.node_bindings.len(), size_of::<HashRef>())?,
        )?;
        for binding in &owner.node_bindings {
            manifest_work = add(
                manifest_work,
                NodeRuntime::capture_hash_storage(&binding.binding_hash).map_err(schema)?,
            )?;
        }
    }
    for owner in &manifest.owners {
        manifest_work = add(
            manifest_work,
            add(size_of::<Id>(), owner.capture_owner_id.allocated_capacity())?,
        )?;
    }
    for domain in &graph.ownership_policy().domains {
        manifest_work = add(
            manifest_work,
            add(
                NodeRuntime::capture_map_node_storage::<Id, ()>(),
                add(
                    size_of::<Id>(),
                    multiply(domain.id.allocated_capacity(), 2)?,
                )?,
            )?,
        )?;
    }
    // validate_index owns its full-reference and hash maps beside the pending
    // record. These actual temporary clones are distinct from retained DAG work.
    let mut index_work = 0usize;
    for row in &archive.index.objects {
        index_work = add(
            index_work,
            NodeRuntime::capture_map_node_storage::<ContentRef, ()>(),
        )?;
        index_work = add(
            index_work,
            NodeRuntime::capture_map_node_storage::<HashRef, ContentRef>(),
        )?;
        index_work = add(
            index_work,
            multiply(
                NodeRuntime::capture_reference_storage(&row.reference).map_err(schema)?,
                2,
            )?,
        )?;
        index_work = add(
            index_work,
            NodeRuntime::capture_hash_storage(&row.reference.hash).map_err(schema)?,
        )?;
    }
    for owner in &archive.index.owners {
        index_work = add(
            index_work,
            NodeRuntime::capture_map_node_storage::<Id, ()>(),
        )?;
        index_work = add(index_work, owner.owner.allocated_capacity())?;
        // The selected four-owner codec inventory uses borrowed participants.
        index_work = add(
            index_work,
            NodeRuntime::capture_map_node_storage::<&Id, ()>(),
        )?;
    }
    Ok((
        retained,
        add(
            add(manifest_work, index_work)?,
            size_of::<CompleteRestoredSettledArchiveValidationAttempt>(),
        )?,
    ))
}

pub(super) fn closure_geometry(
    archive: &NativeArchiveRecord,
) -> Result<(usize, usize), StateError> {
    let rows = &archive.index.objects;
    let mut bodies = 0usize;
    let mut refs = 0usize;
    let mut hashes = 0usize;
    let mut largest = 0usize;
    let mut adjacency = 0usize;
    for row in rows {
        let length = usize::try_from(row.reference.length.get()).map_err(schema)?;
        bodies = add(bodies, length)?;
        refs = add(
            refs,
            NodeRuntime::capture_reference_storage(&row.reference).map_err(schema)?,
        )?;
        hashes = add(
            hashes,
            NodeRuntime::capture_hash_storage(&row.reference.hash).map_err(schema)?,
        )?;
        largest = largest.max(length);
        let mut current = multiply(row.dependencies.len(), size_of::<ContentRef>())?;
        for reference in &row.dependencies {
            current = add(
                current,
                NodeRuntime::capture_reference_storage(reference).map_err(schema)?,
            )?;
        }
        adjacency = adjacency.max(current);
    }
    let count = rows.len().max(1);
    // Returned verified maps, the retained queued set, and the fullref table are
    // independent actual owners; fullref equality earns no allocation discount.
    let nodes = add(
        NodeRuntime::capture_map_node_storage::<HashRef, (ContentRef, Vec<u8>)>(),
        add(
            multiply(NodeRuntime::capture_map_node_storage::<ContentRef, ()>(), 2)?,
            NodeRuntime::capture_map_node_storage::<HashRef, ContentRef>(),
        )?,
    )?;
    let pending = multiply(
        multiply(rows.len(), 2)?.max(4),
        size_of::<(ContentRef, usize)>(),
    )?;
    // Named copies: queued1, fullref table1, pending before/after growth2,
    // current1, returned object/reference maps2, and current child clone1.
    let references = add(multiply(refs, 8)?, multiply(hashes, 2)?)?;
    let retained = add(
        add(add(multiply(count, nodes)?, pending)?, references)?,
        add(add(bodies, largest)?, adjacency)?,
    )?;
    // read_file reserves the observed length and permits one changed-file byte.
    // Its old/new grow buffers coexist only on refusal, independently of the
    // retained successful body. Store hash/filename controls use their defining
    // closed projection rather than a body-length-to-heap multiplier.
    let read = add(multiply(add(largest, 1)?, 3)?, 8)?;
    let manifest_literal =
        NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
            archive.manifest(),
            size_of::<crucible_node_contract::CaptureManifest>(),
            archive
                .limits
                .state
                .maximum_total_content_bytes
                .min(archive.limits.native.maximum_total_record_bytes),
        )
        .map_err(schema)?
        .0;
    let transient = add(
        add(add(read, adjacency)?, manifest_literal)?,
        super::super::core_future_metadata::projected_archive_io_storage().map_err(schema)?,
    )?;
    Ok((retained, transient))
}

pub(super) fn administrative_geometry(
    archive: &NativeArchiveRecord,
    bytes: &[u8],
    content: &crate::node_state::VerifiedStateContent,
    lineage: OriginalInputLineageLimits,
    graph: &crate::node_admission::AdmittedGraph,
) -> Result<(usize, usize), StateError> {
    let maximum = archive
        .limits
        .state
        .maximum_total_content_bytes
        .min(archive.limits.native.maximum_total_record_bytes);
    let (retained, journal_parse) = decode_geometry(bytes, maximum, false, lineage)?;
    let coordinator = content
        .get(&archive.manifest().coordinator_state_ref)
        .ok_or_else(|| refused("terminal administrative coordinator bytes absent"))?;
    let coordinator =
        CoordinatorCommitmentCheckpoint17::prospective_storage_data(coordinator.len(), maximum)
            .map_err(schema)?;
    // The defining journal grammar has at most64 attempted captures, each with
    // one Runtime reference and two settlements for exactly4 owners. This is
    // its existing nonrenewing grammar ceiling, never a new scenario policy.
    let reference_nodes = multiply(
        1 + 64 * (1 + 2 * 4),
        NodeRuntime::capture_map_node_storage::<&ContentRef, ()>(),
    )?;
    let identity_nodes = multiply(64 + 5, NodeRuntime::capture_map_node_storage::<&Id, ()>())?;
    let raw = add(
        add(bytes.len(), 1)?,
        add(
            usize::try_from(archive.manifest().coordinator_state_ref.length.get())
                .map_err(schema)?,
            1,
        )?,
    )?;
    let temporary = add(
        journal_parse,
        add(
            coordinator.requested_bytes_data(),
            add(reference_nodes, identity_nodes)?,
        )?,
    )?;
    let read = add(multiply(raw, 3)?, storage::fixed_storage())?;
    // The real extractor constructs a separate DOM for each actual graph role,
    // plus traversal and combined output Vec growth. Deduplicated manifest roots
    // cannot bound these pre-dedup occurrence banks or the original graph DOMs.
    let roots = required_roots_geometry(graph, maximum)?;
    Ok((retained, add(add(temporary, read)?, roots)?))
}

pub(super) fn coordinator_ancestry_geometry(
    archive: &NativeArchiveRecord,
    attempt: &CompleteRestoredSettledArchiveValidationAttempt,
) -> Result<(usize, usize), StateError> {
    let content = attempt
        .content
        .as_ref()
        .ok_or_else(|| refused("terminal coordinator closure absent"))?;
    let maximum = archive
        .limits
        .state
        .maximum_total_content_bytes
        .min(archive.limits.native.maximum_total_record_bytes);
    let mut retained = multiply(
        archive.index.objects.len(),
        size_of::<CoordinatorCommitmentCheckpoint17>(),
    )?;
    let mut transient = coordinator_ancestry17::counter_scratch_data();
    for object in &archive.index.objects {
        if object.reference.media_type != crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA { continue; }
        let bytes = content
            .get(&object.reference)
            .ok_or_else(|| refused("terminal coordinator ancestor bytes absent"))?;
        let row = CoordinatorCommitmentCheckpoint17::prospective_storage_data(bytes.len(), maximum)
            .map_err(schema)?;
        // Every actual signed-role body is independently priced, including
        // malformed/unreachable rows that the final closure later refuses.
        retained = add(retained, row.retained_requested_bytes_data())?;
        transient = transient.max(add(
            row.maximum_simultaneous_transient_bytes_data(),
            row.counter_scratch_bytes_data(),
        )?);
    }
    Ok((retained, transient))
}

pub(super) fn decode_geometry(
    bytes: &[u8],
    maximum: usize,
    host: bool,
    lineage: OriginalInputLineageLimits,
) -> Result<(usize, usize), StateError> {
    let decode = if host {
        core_decode_credit::preflight_restored_host17(bytes, maximum)
    } else {
        core_decode_credit::preflight_archive(bytes, maximum)
    }
    .map_err(schema)?;
    let root = if host {
        size_of::<HostSchedulingRestoredContinuationRecord17>()
    } else {
        size_of::<RuntimeOriginalCaptureJournal>()
    };
    let retained = add(root, add(decode.typed_containers, decode.parser_strings)?)?;
    let validation = core_decode_credit::validation_storage(
        &decode,
        crate::node_contract::HostSchedulingContinuationLimits {
            maximum_record_bytes: bytes.len(),
            lineage,
        },
    )
    .map_err(schema)?;
    Ok((retained, add(decode.total().map_err(schema)?, validation)?))
}

pub(super) fn add(left: usize, right: usize) -> Result<usize, StateError> {
    left.checked_add(right)
        .ok_or_else(|| refused("terminal Core construction overflow"))
}

pub(super) fn multiply(left: usize, right: usize) -> Result<usize, StateError> {
    left.checked_mul(right)
        .ok_or_else(|| refused("terminal Core layout overflow"))
}

fn required_roots_geometry(
    graph: &crate::node_admission::AdmittedGraph,
    maximum: usize,
) -> Result<usize, StateError> {
    fn role(value: &impl serde::Serialize, maximum: usize) -> Result<usize, StateError> {
        let (construction, encoded) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                value,
                size_of::<ContentRef>(),
                maximum,
            )
            .map_err(schema)?;
        let extent = crucible_node_provider::retained_metadata::serialization_storage::original_json_value_storage_extent_data(encoded).map_err(schema)?;
        // The defining lexical bound is used only for actual traversal/ref Vec
        // slots. Typed/string/DOM backing comes from serializer events above.
        let slots = multiply(
            multiply(extent.maximum_value_nodes, 4)?,
            add(size_of::<&serde_json::Value>(), size_of::<ContentRef>())?,
        )?;
        add(construction, slots)
    }
    let mut total = role(graph.world(), maximum)?;
    for owner in graph.owners() {
        total = add(total, role(owner, maximum)?)?;
    }
    for node in graph.node_ids() {
        total = add(
            total,
            role(
                &graph
                    .binding(node)
                    .ok_or_else(|| refused("terminal graph binding absent"))?
                    .compatibility,
                maximum,
            )?,
        )?;
        total = add(
            total,
            role(
                graph
                    .descriptor(node)
                    .ok_or_else(|| refused("terminal graph descriptor absent"))?,
                maximum,
            )?,
        )?;
    }
    total = add(total, role(graph.ownership_policy(), maximum)?)?;
    add(total, role(graph.coordinator_policy(), maximum)?)
}
