//! Joins actual current17 checkpoints and enrolls the signed imported closure.
//!
//! The Window lends the real prepared Host producer and checkpoint owners. The
//! legacy writer retains its own separate Host2 path. Neither a numeric quote
//! nor a successful visitor creates currentness, capture or signing permission.

use super::*;
use crate::node_contract::{
    NodeRuntime, OriginalLineageRuntimeRecord, PreparedRestoredHost17Capture,
    RestoredCollectingCaptureScope17, RuntimeError, WorldActivation,
};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};
use crucible_node_format::{ContentRef, HashRef, Position, U64};
use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;
use std::{mem::size_of, rc::Rc};

pub(super) struct RestoredCaptureInputs17<'a, 'scope> {
    pub(super) scope: &'a RestoredCollectingCaptureScope17<'scope>,
    pub(super) runtime: &'a OriginalLineageRuntimeRecord,
    pub(super) scheduling: &'a SchedulingSnapshot,
    pub(super) runtime_object: &'a InputPayload,
    pub(super) scheduling_object: &'a InputPayload,
    pub(super) coordinator: &'a CoordinatorCommitmentCheckpoint17,
    pub(super) coordinator_object: &'a InputPayload,
    pub(super) host: &'a Rc<PreparedRestoredHost17Capture>,
    pub(super) after_owner: &'a mut dyn FnMut(&NodeRuntime) -> Result<(), RuntimeError>,
}

impl RestoredCaptureInputs17<'_, '_> {
    pub(super) fn authenticate_request(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        capture_id: &Id,
        cut: Position,
        ordinal: U64,
        factory: &dyn NativeWorldFactory,
    ) -> Result<(), StateError> {
        self.scope
            .authenticate_runtime_data(runtime)
            .map_err(schema)?;
        if !world.same_authority(self.scope.world_data())
            || self.scope.capture_id_data() != capture_id
            || self.runtime.capture_cut != cut
            || self.runtime.capture_ordinal != ordinal
            || self.coordinator.safe_point.runtime != self.runtime_object.reference
            || self.coordinator.safe_point.scheduling != self.scheduling_object.reference
            || self.coordinator_object.reference.media_type
                != crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
        {
            return Err(refused("current17 writer checkpoint or capture identity differs"));
        }
        self.coordinator
            .authenticate_structure_data(&self.runtime_object.reference, cut, ordinal)
            .map_err(schema)?;
        self.coordinator
            .authenticate_prefix_data()
            .map_err(schema)?;
        self.host
            .authenticate_runtime_data(runtime, world, self.runtime_object)
            .map_err(schema)?;
        self.host
            .with_scheduling_data(runtime, world, self.runtime_object, |host, scheduling| {
                if !std::ptr::eq(host, self.scope.host_data()) || scheduling != self.scheduling {
                    return Err(RuntimeError::ForeignAuthority);
                }
                Ok(())
            })
            .map_err(schema)?;
        factory.authenticate_complete_collecting_capture(
            self.scope.plan_data(),
            self.scope.host_data(),
            graph,
            self.runtime,
            self.scheduling,
        )?;
        self.scope
            .authenticate_runtime_data(runtime)
            .map_err(schema)
    }
}

pub(super) fn authenticate_purpose(
    runtime: &mut NodeRuntime,
    collecting: Option<&crate::node_contract::OriginalCollectingCaptureScope>,
    restored: Option<&RestoredCaptureInputs17<'_, '_>>,
) -> Result<(), StateError> {
    if let Some(current) = restored {
        if collecting.is_some() {
            return Err(refused(
                "current17 writer cannot borrow an original15 scope",
            ));
        }
        runtime
            .authenticate_complete_restoration_purpose(Some(current.scope.plan_data()))
            .map_err(schema)?;
        current
            .scope
            .authenticate_runtime_data(runtime)
            .map_err(schema)
    } else {
        runtime
            .authenticate_complete_capture_purpose(collecting)
            .map_err(schema)
    }
}

pub(super) fn collecting_provenance(
    plan: &crate::node_admission::InstalledConformancePlan,
) -> serde_json::Value {
    let evidence = plan.evidence();
    serde_json::json!({
        "schema":"source-owned.collecting-complete-capture/1",
        "plan":evidence.plan_ref,"refused":evidence.refused_ref,
        "sources":evidence.sources,"world":evidence.world,
        "ordinary_acceptance":false,
    })
}

impl NativeArchive {
    /// Captures current17 under the actual Window's one-use prepared Host loan.
    ///
    /// The caller performs the genuine full observation after every Source
    /// claim has dropped. This method retains the durable output before any
    /// later ticket-release failure. It never converts an original15 scope,
    /// fabricates a checkpoint or selects current17 from an absent capability.
    ///
    /// # Errors
    /// Refuses an occupied output, foreign scope/checkpoint, unsupported complete
    /// terminal construction quote, failed owner, incomplete dependency closure
    /// or persistence failure. Actual once owners and committed output remain.
    pub(crate) fn capture_complete_restored_settled_world_into(
        &self,
        request: OriginalLineageCaptureRequest<'_>,
        scope: &RestoredCollectingCaptureScope17<'_>,
        completed: &mut Option<NativeArchiveRecord>,
        after_owner: &mut dyn FnMut(&NodeRuntime) -> Result<(), RuntimeError>,
    ) -> Result<(), StateError> {
        if completed.is_some() {
            return Err(refused(
                "current17 durable archive output is already occupied",
            ));
        }
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
        let mut failure = None;
        let outcome = scope.with_prepared_checkpoint_data(
            runtime,
            |runtime,
             source,
             scheduling,
             runtime_object,
             scheduling_object,
             coordinator,
             coordinator_object,
             host| {
                let result = self.capture_complete_lineage_world_family_data(
                    OriginalLineageCaptureRequest {
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
                    },
                    None,
                    None::<
                        fn(
                            &NodeRuntime,
                            &crate::node_contract::HostSchedulingSource,
                            &InputPayload,
                            &InputPayload,
                        ) -> Result<(), RuntimeError>,
                    >,
                    Some(RestoredCaptureInputs17 {
                        scope,
                        runtime: source,
                        scheduling,
                        runtime_object,
                        scheduling_object,
                        coordinator,
                        coordinator_object,
                        host,
                        after_owner,
                    }),
                    Some(completed),
                );
                match result {
                    Ok(None) => Ok(()),
                    Ok(Some(_)) => Err(RuntimeError::ForeignAuthority),
                    Err(error) => {
                        // The Window must observe a real callback failure. Wrapping
                        // this StateError in Ok would incorrectly mark the phase spent.
                        failure = Some(error);
                        Err(RuntimeError::ForeignAuthority)
                    }
                }
            },
        );
        if let Some(error) = failure {
            return Err(error);
        }
        outcome.map_err(schema)
    }
}

/// Reports actual signed imported-closure axes from three admitted Source rows.
///
/// The tuple order is objects, body bytes, full-reference backing, edges,
/// adjacency backing, largest body, returned-row bytes and row-plus-hash bytes.
/// These values are DATA; the actual Scope and completed Source visitor remain
/// independently mandatory. Duplicate shared objects receive no credit refund.
pub type ImportedClosureGeometry17 = [(usize, usize, usize, usize, usize, usize, usize, usize); 3];

/// Names the actual Scope, Source lender and imported-row fixed controls.
///
/// The factory admits this separate counter before asking for the early
/// borrowed Source rows. Destination copies and streamed-file work remain
/// independently funded by the returned actual closure geometry.
pub fn imported_closure17_counter_scratch_data() -> usize {
    RestoredCollectingCaptureScope17::launch_operand_counter_scratch_data()
        + NodeRuntime::original_restored_capture_runtime_counter_scratch_data()
        + crate::node_adapters::cnp::PacketCompleteSemanticSource::original_capture17_imported_closure_counter_scratch_data()
        + size_of::<ImportedClosureStorage17>()
        + size_of::<ImportedClosureCursor17>()
        + size_of::<ImportedClosureGeometry17>()
        + size_of::<Result<ImportedClosureGeometry17, StateError>>()
        + size_of::<Result<ImportedClosureStorage17, StateError>>()
        + size_of::<std::slice::Iter<'_, (usize, usize, usize, usize, usize, usize, usize, usize)>>()
}

pub(super) struct ImportedClosureStorage17 {
    rows: ImportedClosureGeometry17,
    objects: usize,
    edges: usize,
    bytes: usize,
    largest: usize,
    peak: usize,
}

impl ImportedClosureStorage17 {
    pub(super) fn quote(
        rows: ImportedClosureGeometry17,
        limits: NativeArchiveLimits,
    ) -> Result<Self, StateError> {
        let mut objects = 0usize;
        let mut edges = 0usize;
        let mut bytes = 0usize;
        let mut refs = 0usize;
        let mut adjacency = 0usize;
        let mut largest = 0usize;
        let mut lookup = 0usize;
        for &(count, body, references, links, rows, maximum_body, returned, hashed) in &rows {
            if count == 0
                || maximum_body > body
                || returned > hashed
                || count > limits.state.maximum_content_objects
                || links > limits.state.maximum_dependency_edges
                || maximum_body > limits.state.maximum_content_bytes
            {
                return Err(refused("imported current17 closure geometry differs"));
            }
            objects = add(objects, count)?;
            edges = add(edges, links)?;
            bytes = add(bytes, body)?;
            refs = add(refs, references)?;
            adjacency = add(adjacency, rows)?;
            largest = largest.max(maximum_body);
            lookup = lookup.max(hashed);
        }
        let nodes = add(
            NodeRuntime::capture_map_node_storage::<ContentRef, super::super::storage::Object>(),
            NodeRuntime::capture_map_node_storage::<HashRef, ContentRef>(),
        )?;
        // Three full refs plus the separate hash key coexist in Objects. The
        // finished Index and its pending-record clone own two additional refs
        // and independent adjacency banks beside the original map allocations.
        let retained = add(
            multiply(
                objects,
                add(
                    nodes,
                    multiply(2, size_of::<super::super::storage::Object>())?,
                )?,
            )?,
            add(multiply(refs, 5)?, multiply(adjacency, 2)?)?,
        )?;
        let scratch = add(
            size_of::<Self>(),
            add(
                size_of::<ImportedClosureGeometry17>(),
                add(
                    size_of::<Option<StateError>>(),
                    add(
                        size_of::<Result<(), RuntimeError>>(),
                        size_of::<ImportedClosureCursor17>(),
                    )?,
                )?,
            )?,
        )?;
        // The defining archive IO projection names the real artifact owner,
        // filename banks, streamed hash buffer and digest; it is charged again
        // here independently of Source's retained original-body custody.
        let transient = add(
            lookup,
            super::super::core_future_metadata::projected_archive_io_storage().map_err(schema)?,
        )?;
        let peak = add(retained, add(transient, scratch)?)?;
        if objects > limits.state.maximum_content_objects
            || edges > limits.state.maximum_dependency_edges
            || bytes > limits.state.maximum_total_content_bytes
            || peak > limits.state.maximum_total_content_bytes
            || peak > limits.native.maximum_total_record_bytes
        {
            return Err(refused(
                "imported current17 closure exceeds finite archive credit",
            ));
        }
        Ok(Self {
            rows,
            objects,
            edges,
            bytes,
            largest,
            peak,
        })
    }

    pub(super) fn peak(&self) -> Result<usize, StateError> {
        Ok(self.peak)
    }
    pub(super) fn objects(&self) -> usize {
        self.objects
    }
    pub(super) fn edges(&self) -> usize {
        self.edges
    }
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(super) fn largest(&self) -> usize {
        self.largest
    }

    pub(super) fn enroll(
        &self,
        factory: &dyn NativeWorldFactory,
        scope: &RestoredCollectingCaptureScope17<'_>,
        objects: &mut Objects<'_>,
    ) -> Result<(), StateError> {
        let observed =
            factory.complete_restored_capture_completed_imported_closure_geometry_data(scope)?;
        for (bound, observed) in self.rows.iter().zip(&observed) {
            let bound = [
                bound.0, bound.1, bound.2, bound.3, bound.4, bound.5, bound.6, bound.7,
            ];
            let observed = [
                observed.0, observed.1, observed.2, observed.3, observed.4, observed.5, observed.6,
                observed.7,
            ];
            if observed
                .iter()
                .zip(bound)
                .any(|(actual, maximum)| *actual > maximum)
            {
                return Err(refused("completed imported current17 closure widened"));
            }
        }
        let mut cursor = ImportedClosureCursor17::new(self.rows, observed)?;
        factory.visit_complete_restored_capture_imported_objects_data(
            scope,
            &mut |reference, bytes, dependencies| {
                // Check every actual occurrence before allocating its independent
                // reference and adjacency copy, including the parent Index root.
                cursor.observe(reference, bytes, dependencies)?;
                objects.insert(reference.clone(), bytes, dependencies.to_vec())
            },
        )?;
        cursor.finish()?;
        objects.check_dependency_credit()
    }
}

/// Counts the streamed occurrences before any independently owned copy.
struct ImportedClosureCursor17 {
    bounds: [usize; 8],
    expected: [usize; 8],
    actual: [usize; 8],
}

impl ImportedClosureCursor17 {
    fn new(
        bounds: ImportedClosureGeometry17,
        expected: ImportedClosureGeometry17,
    ) -> Result<Self, StateError> {
        Ok(Self {
            bounds: Self::aggregate(bounds)?,
            expected: Self::aggregate(expected)?,
            actual: [0; 8],
        })
    }

    fn aggregate(rows: ImportedClosureGeometry17) -> Result<[usize; 8], StateError> {
        let mut result = [0usize; 8];
        for row in rows {
            let row = [row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7];
            for axis in 0..5 {
                result[axis] = add(result[axis], row[axis])?;
            }
            for axis in 5..8 {
                result[axis] = result[axis].max(row[axis]);
            }
        }
        Ok(result)
    }

    fn observe(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
        dependencies: &[ContentRef],
    ) -> Result<(), StateError> {
        if reference.length.get() != u64::try_from(bytes.len()).map_err(schema)? {
            return Err(refused(
                "imported body differs from its declared full-reference length",
            ));
        }
        let mut row = multiply(dependencies.len(), size_of::<ContentRef>())?;
        for dependency in dependencies {
            row = add(
                row,
                NodeRuntime::capture_reference_storage(dependency).map_err(schema)?,
            )?;
        }
        let hashed = add(
            row,
            NodeRuntime::capture_hash_storage(&reference.hash).map_err(schema)?,
        )?;
        let actual = [
            add(self.actual[0], 1)?,
            add(self.actual[1], bytes.len())?,
            add(
                self.actual[2],
                NodeRuntime::capture_reference_storage(reference).map_err(schema)?,
            )?,
            add(self.actual[3], dependencies.len())?,
            add(self.actual[4], row)?,
            self.actual[5].max(bytes.len()),
            self.actual[6].max(row),
            self.actual[7].max(hashed),
        ];
        if actual
            .iter()
            .zip(self.bounds)
            .any(|(actual, bound)| *actual > bound)
            || actual
                .iter()
                .zip(self.expected)
                .any(|(actual, expected)| *actual > expected)
        {
            return Err(refused(
                "actual imported closure exceeds its admitted occurrence row",
            ));
        }
        self.actual = actual;
        Ok(())
    }

    fn finish(self) -> Result<(), StateError> {
        if self.actual != self.expected {
            return Err(refused(
                "actual imported visitor omitted its declared signed occurrences",
            ));
        }
        Ok(())
    }
}

fn add(left: usize, right: usize) -> Result<usize, StateError> {
    left.checked_add(right)
        .ok_or_else(|| refused("current17 imported closure arithmetic overflow"))
}

fn multiply(left: usize, right: usize) -> Result<usize, StateError> {
    left.checked_mul(right)
        .ok_or_else(|| refused("current17 imported closure layout overflow"))
}

/// Borrows actual live custody for a finite pure terminal parser sequence.
///
/// The callback Cell contains only a local observer control, not a Source,
/// native owner or Window bank loan. It is emptied before invoking the genuine
/// full observer, so no RefMut survives through reobservation.
pub(super) struct WriterTerminalAdmission17<'a, 'scope> {
    scope: &'a RestoredCollectingCaptureScope17<'scope>,
    runtime: &'a NodeRuntime,
    capture: &'a crate::node_contract::OriginalLineageWorldCapture,
    archive: &'a NativeArchiveRecord,
    observer: std::cell::Cell<Option<&'a mut dyn FnMut(&NodeRuntime) -> Result<(), RuntimeError>>>,
}

impl<'a, 'scope> WriterTerminalAdmission17<'a, 'scope> {
    pub(super) fn new(
        scope: &'a RestoredCollectingCaptureScope17<'scope>,
        runtime: &'a NodeRuntime,
        capture: &'a crate::node_contract::OriginalLineageWorldCapture,
        archive: &'a NativeArchiveRecord,
        observer: &'a mut dyn FnMut(&NodeRuntime) -> Result<(), RuntimeError>,
    ) -> Self {
        Self {
            scope,
            runtime,
            capture,
            archive,
            observer: std::cell::Cell::new(Some(observer)),
        }
    }

    fn observe(&self) -> Result<(), StateError> {
        let observer = self
            .observer
            .take()
            .ok_or_else(|| refused("terminal full observer is already borrowed"))?;
        let result = observer(self.runtime);
        self.observer.set(Some(observer));
        result.map_err(schema)
    }
}

impl super::super::RestoredArchive17ValidationAdmission for WriterTerminalAdmission17<'_, '_> {
    fn begin_stage_data(
        &self,
        prewalk: super::super::RestoredArchive17ValidationPrewalkData,
    ) -> Result<(), StateError> {
        self.scope
            .retain_terminal_validation_prewalk_data(
                self.runtime,
                self.capture,
                self.archive,
                prewalk,
            )
            .map_err(schema)?;
        self.observe()?;
        self.scope
            .append_terminal_validation_phase_data(self.runtime, self.capture, self.archive)
            .map_err(schema)?;
        self.observe()
    }

    fn construct_stage_data(
        &self,
        row: super::super::RestoredArchive17ValidationConstructionData,
    ) -> Result<(), StateError> {
        self.scope
            .retain_terminal_validation_row_data(self.runtime, self.capture, self.archive, row)
            .map_err(schema)?;
        self.observe()?;
        self.scope
            .begin_terminal_validation_constructor_data(
                self.runtime,
                self.capture,
                self.archive,
                row.step_data(),
            )
            .map_err(schema)
    }

    fn finish_stage_data(
        &self,
        step: super::super::RestoredArchive17ValidationStep,
        actual_cache_retained: usize,
    ) -> Result<(), StateError> {
        self.scope
            .finish_terminal_validation_stage_data(
                self.runtime,
                self.capture,
                self.archive,
                step,
                actual_cache_retained,
            )
            .map_err(schema)?;
        self.observe()
    }
}

pub(super) fn writer_counter_scratch_data() -> usize {
    size_of::<WriterTerminalAdmission17<'_, '_>>()
        + size_of::<super::super::storage::PendingRestoredArchive17<'_>>()
        + size_of::<Option<super::super::storage::PendingRestoredArchive17<'_>>>()
        + size_of::<Result<super::super::storage::PendingRestoredArchive17<'_>, StateError>>()
        + size_of::<RestoredCaptureInputs17<'_, '_>>()
        + size_of::<Option<StateError>>()
        + size_of::<Option<&mut dyn FnMut(&NodeRuntime) -> Result<(), RuntimeError>>>()
        + size_of::<Result<(), RuntimeError>>()
        + crate::node_contract::OriginalLineageWorldCapture::restored_terminal_counter_scratch_data()
        + RestoredCollectingCaptureScope17::launch_operand_counter_scratch_data()
        + crate::node_contract::host_scheduling_restored_continuation_schema17_counter_scratch_data()
        + crucible_node_transport::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_occurrences_are_bounded_before_owned_copies() {
        let body = b"immutable body";
        let reference =
            crucible_node_format::canonical::content_ref(body, "application/json").unwrap();
        let backing = NodeRuntime::capture_reference_storage(&reference).unwrap();
        let hashed = NodeRuntime::capture_hash_storage(&reference.hash).unwrap();
        let row = (1, body.len(), backing, 0, 0, body.len(), 0, hashed);
        let mut cursor = ImportedClosureCursor17::new([row; 3], [row; 3]).unwrap();
        for _ in 0..3 {
            cursor.observe(&reference, body, &[]).unwrap();
        }
        let admitted = cursor.actual;
        assert!(cursor.observe(&reference, body, &[]).is_err());
        assert_eq!(cursor.actual, admitted);
        cursor.finish().unwrap();
    }

    #[test]
    fn imported_visitor_cannot_omit_rows_or_widen_body_or_adjacency() {
        let body = b"immutable body";
        let reference =
            crucible_node_format::canonical::content_ref(body, "application/json").unwrap();
        let backing = NodeRuntime::capture_reference_storage(&reference).unwrap();
        let hashed = NodeRuntime::capture_hash_storage(&reference.hash).unwrap();
        let row = (1, body.len(), backing, 0, 0, body.len(), 0, hashed);
        let mut cursor = ImportedClosureCursor17::new([row; 3], [row; 3]).unwrap();
        assert!(
            cursor
                .observe(&reference, b"different length", &[])
                .is_err()
        );
        assert!(
            cursor
                .observe(&reference, body, std::slice::from_ref(&reference))
                .is_err()
        );
        cursor.observe(&reference, body, &[]).unwrap();
        assert!(cursor.finish().is_err());
    }
}
