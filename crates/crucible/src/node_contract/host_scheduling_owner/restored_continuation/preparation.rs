//! Retains the genuine prepared Host17 producer before native owner dispatch.
//!
//! The same Source, opaque World, actual Runtime and admitted coordinator boundary
//! construct this capsule. Its snapshot moves once through the separate current17
//! owner ticket. Historical Host17 records cannot construct a prepared capsule.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{
    NativeStateKey, NodeRuntime, OriginalRestoredCoordinatorBoundary17, WorldActivation,
};
use crate::node_state::CompleteOriginalHostTicket;
use crucible_node_contract::U64;
use serde::{Serializer, ser::SerializeSeq};
use std::mem::size_of;

/// Reports independent Host17 constructor owners and temporary work as DATA.
pub(crate) struct RestoredHost17CaptureConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    encoded_upper: usize,
}

impl RestoredHost17CaptureConstructionData {
    pub(crate) fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    pub(crate) fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    pub(crate) fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn maximum_encoded_host_bytes_data(&self) -> usize {
        self.encoded_upper
    }

    /// Names known scalar formatter work admitted before any counting serializer.
    pub(crate) fn counter_transient_bytes_data() -> usize {
        CompleteOriginalHostTicket::restored_capture_ancestry17_index_counter_transient_data()
    }

    /// Names actual metadata, borrowed root and schema-check controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<&NodeRuntime>()
            + size_of::<&crate::node_admission::AdmittedGraph>()
            + size_of::<&HostSchedulingSource>()
            + size_of::<Option<Rc<HostSchedulingSource>>>()
            + size_of::<Result<Rc<HostSchedulingSource>, RuntimeError>>()
            + size_of::<crate::node_contract::HostSchedulingNodeWitness<'static>>()
            + size_of::<BorrowedHost17<'static>>()
            + size_of::<std::cell::Ref<'static, Option<HostSchedulingRestoredContinuation17>>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, Option<HostSchedulingRestoredContinuation17>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<HostSchedulingObservation<'static>>()
            + size_of::<Result<HostSchedulingObservation<'static>, RuntimeError>>()
            + size_of::<ProjectedIndexReference17>()
            + size_of::<[usize; 16]>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + CompleteOriginalHostTicket::restored_capture_ancestry17_counter_scratch_data()
            + CompleteOriginalHostTicket::restored_capture_ancestry17_index_counter_scratch_data()
            + host_scheduling_restored_continuation_schema17_counter_scratch_data()
    }

    /// Prices genuine current construction beside already retained checkpoints.
    ///
    /// The caller supplies the same defining Window checkpoint records and
    /// independently admits the fixed counter and known formatter term first.
    /// Neither these record loans nor the returned row issue a Capture ticket.
    /// The constructor and writer separately join full actual current objects.
    ///
    /// # Errors
    /// Refuses foreign/stale live custody, another current cut, missing explicit
    /// immutable schema17 support, malformed ancestry, layout overflow or limits.
    pub(crate) fn quote_data(
        observation: &HostSchedulingObservation<'_>,
        world: &WorldActivation,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        checkpoint_runtime: &OriginalLineageRuntimeRecord,
        checkpoint_scheduling: &SchedulingSnapshot,
        runtime_object: &InputPayload,
        limits: HostSchedulingContinuationLimits,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        let runtime = observation.runtime;
        let source = observation.source;
        boundary.authenticate_runtime_data(runtime, world, source)?;
        validation::validate_limits(limits)?;
        let schema = selected_schema17(source)?;
        if checkpoint_runtime.capture_cut != boundary.cut_data()
            || checkpoint_runtime.capture_ordinal != boundary.ordinal_data()
            || checkpoint_scheduling.capture_cut != boundary.cut_data()
            || checkpoint_scheduling.capture_ordinal != boundary.ordinal_data()
            || checkpoint_runtime.source_activation.generation != world.record().generation
            || checkpoint_runtime.source_activation.activation_id != world.record().activation_id
            || checkpoint_runtime.source_activation.world_binding_hash
                != world.record().world_binding_hash
            || checkpoint_runtime.source_activation.owners != world.record().owners
            || checkpoint_runtime.source_activation.boundary != world.record().boundary
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let archive = source
            .archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let index = archive.restored_capture_ancestry17_index_construction_data(
            limits.maximum_record_bytes,
            maximum,
        )?;
        let row =
            archive.with_restored_capture_first_roles17_data(|first_host, first_semantic| {
                let borrowed = BorrowedHost17 {
                    schema_version: 17,
                    source: source.selection(),
                    runtime: checkpoint_runtime,
                    scheduling: checkpoint_scheduling,
                    objects: BorrowedObjects17(runtime),
                    ancestry: BorrowedAncestry17 {
                        parent_archive_index: ProjectedIndexReference17::maximum_data(),
                        first_host,
                        first_semantic: first_semantic
                            .map(|(node, object)| BorrowedSemantic17 { node, object }),
                    },
                    admission_policy: runtime.host_restored17_runtime_limits_data().into(),
                };
                let serialized = NodeRuntime::capture_serialization_storage(&borrowed, maximum)?;
                let encoded = NodeRuntime::capture_encoded_output_storage(&borrowed, maximum)?;
                // Report wire extent from the same actual borrowed serializer
                // events, never by treating requested bank capacity as wire bytes.
                // The unit decode slot is used only for this nonowning count; its
                // construction axis does not price any actual typed decoder.
                let (_, encoded_upper) =
                    NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                        &borrowed, 1, maximum,
                    )?;
                // Existing snapshot constructor rows are derived from actual live
                // borrowed owners, independently of checkpoint DATA parameters.
                let runtime_work = runtime.host_restored17_runtime_snapshot_construction_data(
                    boundary.cut_data(),
                    boundary.ordinal_data(),
                    maximum,
                )?;
                let scheduling_work = runtime
                    .host_restored17_scheduler_snapshot_construction_data(
                        boundary.cut_data(),
                        boundary.ordinal_data(),
                        maximum,
                    )?;
                let mut typed = checked_sum(&[
                    NodeRuntime::capture_host_selection_storage(source.selection())?,
                    NodeRuntime::capture_runtime_record_storage(checkpoint_runtime)?,
                    NodeRuntime::capture_scheduling_record_storage(checkpoint_scheduling)?,
                    first_host.owned_storage()?,
                    projected_index_backing(),
                ])?;
                let count = runtime.original_lineage_capture_objects().count();
                typed = checked_sum(&[
                    typed,
                    count
                        .checked_mul(size_of::<InputPayload>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                ])?;
                for object in runtime.original_lineage_capture_objects() {
                    typed = checked_sum(&[
                        typed,
                        object.reference.owned_storage()?,
                        object.bytes.capacity(),
                    ])?;
                }
                for (node, object) in first_semantic {
                    typed = checked_sum(&[typed, node.owned_storage()?, object.owned_storage()?])?;
                }
                let prepared = checked_sum(&[
                    NodeRuntime::capture_shared_allocation_storage::<PreparedRestoredHost17Capture>(
                    ),
                    world.record().owned_storage()?,
                    schema.owned_storage()?,
                    source
                        .selection()
                        .binding
                        .compatibility
                        .implementation
                        .implementation_id
                        .owned_storage()?,
                    source
                        .selection()
                        .binding
                        .compatibility
                        .operating_contract
                        .facets[0]
                        .id
                        .owned_storage()?,
                    runtime_object.reference.owned_storage()?,
                ])?;
                let dependencies = source.restored_capture_dependency_construction17_data(
                    &runtime_object.reference,
                    runtime
                        .original_lineage_capture_objects()
                        .map(|object| &object.reference),
                    first_host,
                    first_semantic,
                    projected_index_backing(),
                    maximum,
                )?;
                let retained = checked_sum(&[
                    dependencies,
                    size_of::<HostSchedulingRestoredCaptureAttempt17>(),
                    size_of::<HostSchedulingRestoredContinuation17>(),
                    typed,
                    encoded,
                    prepared,
                    index.0,
                ])?;
                // Validator clones are priced separately from retained DTOs and
                // from both actual snapshot constructors. Host encoding's DOM and
                // canonical work also coexist with the once-owned typed record.
                let transient = checked_sum(&[
                    runtime_work,
                    scheduling_work,
                    typed,
                    serialized,
                    serialized,
                    encoded,
                    index.1,
                    "blake3-256".len() + "cnp.blob.v1".len() + 64,
                    Self::counter_transient_bytes_data(),
                ])?;
                let scratch = checked_sum(&[Self::counter_scratch_data(), index.2])?;
                if checked_sum(&[retained, transient, scratch])? > maximum {
                    return Err(RuntimeError::ResourceLimit);
                }
                Ok(Self {
                    retained,
                    transient,
                    scratch,
                    encoded_upper,
                })
            })?;
        boundary.authenticate_runtime_data(runtime, world, source)?;
        Ok(row)
    }
}

/// Retains an actual current producer for one genuinely scoped owner ticket.
///
/// Private construction consumes the real completed Host17 writer output. It
/// cannot be instantiated from a decoded historical record or DTO equality.
pub(crate) struct PreparedRestoredHost17Capture {
    source: Rc<HostSchedulingSource>,
    world: WorldActivation,
    runtime: *const NodeRuntime,
    runtime_object: ContentRef,
    key: NativeStateKey,
    snapshot: RefCell<Option<HostSchedulingRestoredContinuation17>>,
}

impl PreparedRestoredHost17Capture {
    /// Counts actual capsule backing without counting unrelated shared owners.
    ///
    /// The same Source and World authority handles remain actual prior owners;
    /// this includes the new World record clone, key/ref banks and snapshot.
    ///
    /// # Errors
    /// Refuses busy private custody or requested-layout overflow.
    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let Self {
            source: _,
            world,
            runtime: _,
            runtime_object,
            key,
            snapshot,
        } = self;
        let snapshot = snapshot.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        checked_sum(&[
            NodeRuntime::capture_shared_allocation_storage::<Self>(),
            world.record().owned_storage()?,
            runtime_object.owned_storage()?,
            NodeRuntime::capture_native_key_storage(key)?,
            snapshot
                .as_ref()
                .map(|snapshot| {
                    snapshot
                        .retained_requested_storage_data()?
                        .checked_sub(size_of::<HostSchedulingRestoredContinuation17>())
                        .ok_or(RuntimeError::ResourceLimit)
                })
                .transpose()?
                .unwrap_or(0),
        ])
    }

    /// Authenticates the same concrete current producer without consuming it.
    ///
    /// # Errors
    /// Refuses another Runtime, World, Host, prepared Runtime reference or source.
    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        runtime_object: &InputPayload,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime)
            || !self.world.same_authority(world)
            || self.runtime_object != runtime_object.reference
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(world)?;
        runtime.authenticate_host_scheduling_source(&self.source)?;
        self.source
            .authenticate_current()
            .map_err(failure_runtime)?;
        selected_schema17(&self.source)?;
        Ok(())
    }

    /// Lends the same prepared scheduler without transferring its producer.
    ///
    /// Both outcomes recheck actual Runtime, World and Source custody after the
    /// borrowed slot is released. The enclosing Window supplies its independent
    /// full observation outside this private loan.
    ///
    /// # Errors
    /// Refuses foreign or stale live custody, a consumed producer or a busy slot.
    pub(crate) fn with_scheduling_data<R>(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        runtime_object: &InputPayload,
        inspect: impl FnOnce(&HostSchedulingSource, &SchedulingSnapshot) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.authenticate_runtime_data(runtime, world, runtime_object)?;
        let result = {
            let snapshot = self
                .snapshot
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let snapshot = snapshot
                .as_ref()
                .ok_or(RuntimeError::OutstandingObligations)?;
            if &snapshot.record_data().source != self.source.selection() {
                return Err(RuntimeError::ForeignAuthority);
            }
            inspect(&self.source, &snapshot.record_data().scheduling)
        };
        self.authenticate_runtime_data(runtime, world, runtime_object)?;
        result
    }

    /// Moves the genuine snapshot once into its same-source owner ticket.
    ///
    /// Every fallible identity check precedes the move. The consuming owner must
    /// install the returned producer before any later fallible work, preserving
    /// the spent occurrence on refusal.
    ///
    /// # Errors
    /// Refuses another Host, World, owner identity or Runtime object, changed
    /// checkpoint DATA, busy custody or an already consumed producer.
    pub(crate) fn take_data(
        &self,
        source: &HostSchedulingSource,
        owner: &OwnerIdentity,
        world: &WorldActivation,
        runtime_record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
    ) -> Result<HostSchedulingRestoredContinuation17, RuntimeError> {
        source.authenticate_current().map_err(failure_runtime)?;
        if !std::ptr::eq(self.source.as_ref(), source)
            || !self.world.same_authority(world)
            || self.runtime_object != runtime_object.reference
            || source.selection().owner.owner.id != owner.owner
            || source.selection().binding.authority.incarnation_id != owner.incarnation
            || source.selection().binding.authority.owner_generation != owner.generation
            || source.world() != &world.record().world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut snapshot = self
            .snapshot
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let record = snapshot
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?
            .record_data();
        if &record.runtime != runtime_record || &record.source != source.selection() {
            return Err(RuntimeError::ForeignAuthority);
        }
        source.authenticate_current().map_err(failure_runtime)?;
        snapshot.take().ok_or(RuntimeError::OutstandingObligations)
    }

    /// Checks the actual attached owner without an invented runtime payload loan.
    ///
    /// # Errors
    /// Refuses another Runtime, stale World or missing same-source attachment.
    pub(crate) fn authenticate_runtime_owner_data(
        &self,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(&self.world)?;
        runtime.authenticate_host_scheduling_source(&self.source)?;
        self.source
            .authenticate_current()
            .map_err(failure_runtime)?;
        selected_schema17(&self.source)?;
        Ok(())
    }

    pub(crate) fn authenticate_host_data(
        &self,
        host: &HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.source.as_ref(), host) {
            return Err(RuntimeError::ForeignAuthority);
        }
        host.authenticate_current().map_err(failure_runtime)
    }

    /// Checks that the actual one-use producer has left this retained capsule.
    ///
    /// This is a local custody fact, not proof of native, Source or archive
    /// completion. The Window additionally requires the real writer result and
    /// the full all-owner conjunction before publishing its completed phase.
    ///
    /// # Errors
    /// Refuses a busy capsule or an actual producer still retained in its slot.
    pub(crate) fn authenticate_spent_data(&self) -> Result<(), RuntimeError> {
        let snapshot = self
            .snapshot
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if snapshot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn key_data(&self) -> &NativeStateKey {
        &self.key
    }

    pub(crate) fn with_snapshot_data<R>(
        &self,
        inspect: impl FnOnce(&HostSchedulingRestoredContinuation17) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let snapshot = self
            .snapshot
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        inspect(
            snapshot
                .as_ref()
                .ok_or(RuntimeError::OutstandingObligations)?,
        )
    }
}

impl NodeRuntime {
    /// Borrows the genuine attached Host observation from the actual Runtime.
    ///
    /// This local constructor performs no whole-Window census or admission. The
    /// enclosing phase separately authenticates its real World and boundary and
    /// performs full observation only after all mutable bank loans are released.
    ///
    /// # Errors
    /// Refuses a foreign, inactive, revoked or busy Host attachment.
    pub(crate) fn restored_host17_observation_data<'a>(
        &'a self,
        source: &'a HostSchedulingSource,
    ) -> Result<HostSchedulingObservation<'a>, RuntimeError> {
        HostSchedulingObservation::new(self, source)
    }

    /// Retains the genuine completed Host17 producer beneath its actual Source.
    ///
    /// The enclosing Window owns the once phase, independently admitted row and
    /// partial slots. It authenticates the full scope before its private mutable
    /// loan and genuinely reobserves the whole graph after releasing that loan.
    /// This constructor therefore checks actual local owners and coordinator
    /// custody without reentering the Window's full mutable-bank census.
    ///
    /// # Errors
    /// Refuses repeated or absent output, another actual current Host/World,
    /// checkpoint disagreement, unsupported advertised format, or storage excess.
    pub(crate) fn prepare_restored_host17_capture_into_data(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        host: &HostSchedulingSource,
        world: &WorldActivation,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        checkpoint_runtime: &OriginalLineageRuntimeRecord,
        checkpoint_scheduling: &SchedulingSnapshot,
        runtime_object: &InputPayload,
        maximum: usize,
        output: &mut Option<HostSchedulingRestoredContinuation17>,
        prepared: &mut Option<Rc<PreparedRestoredHost17Capture>>,
    ) -> Result<(), RuntimeError> {
        if prepared.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        boundary.authenticate_runtime_data(self, world, host)?;
        let snapshot = output
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        if snapshot.record_data().source != *host.selection()
            || snapshot.record_data().runtime != *checkpoint_runtime
            || snapshot.record_data().scheduling != *checkpoint_scheduling
            || graph.world_binding_hash() != &world.record().world_binding_hash
            || graph.descriptor(&host.selection().descriptor.id)
                != Some(&host.selection().descriptor)
            || graph.binding(&host.selection().descriptor.id) != Some(&host.selection().binding)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual = self.retained_restored_host_source17_data(graph, host)?;
        let schema = selected_schema17(&actual)?;
        let key = NativeStateKey {
            implementation: actual
                .selection()
                .binding
                .compatibility
                .implementation
                .implementation_id
                .clone(),
            profile: actual
                .selection()
                .binding
                .compatibility
                .operating_contract
                .facets[0]
                .id
                .clone(),
            schema: schema.clone(),
        };
        let owner = PreparedRestoredHost17Capture {
            source: actual,
            world: world.clone(),
            runtime: self,
            runtime_object: runtime_object.reference.clone(),
            key,
            snapshot: RefCell::new(None),
        };
        // Install the actual capsule before a later check can refuse. Its empty
        // private snapshot cannot pass a preflight or lend an owner continuation.
        *prepared = Some(Rc::new(owner));
        let owner = prepared.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        *owner
            .snapshot
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)? = output.take();
        owner.with_snapshot_data(|snapshot| {
            host.prepare_restored_capture_dependency_plan17_data(snapshot, runtime_object, maximum)
        })?;
        if owner.retained_requested_storage_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        boundary.authenticate_runtime_data(self, world, host)?;
        owner.authenticate_runtime_data(self, world, runtime_object)
    }
}

#[derive(Serialize)]
struct ProjectedIndexHash17 {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}
#[derive(Serialize)]
struct ProjectedIndexReference17 {
    hash: ProjectedIndexHash17,
    length: U64,
    media_type: &'static str,
}
impl ProjectedIndexReference17 {
    fn maximum_data() -> Self {
        Self {
            hash: ProjectedIndexHash17 {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            },
            length: U64::new(u64::MAX),
            media_type: "application/vnd.crucible.native-signed-index-body.v3+json",
        }
    }
}
#[derive(Serialize)]
struct BorrowedSemantic17<'a> {
    node: &'a Id,
    object: &'a ContentRef,
}
#[derive(Serialize)]
struct BorrowedAncestry17<'a> {
    parent_archive_index: ProjectedIndexReference17,
    first_host: &'a ContentRef,
    first_semantic: [BorrowedSemantic17<'a>; 3],
}
struct BorrowedObjects17<'a>(&'a NodeRuntime);
impl Serialize for BorrowedObjects17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence =
            serializer.serialize_seq(Some(self.0.original_lineage_capture_objects().count()))?;
        for object in self.0.original_lineage_capture_objects() {
            sequence.serialize_element(object)?;
        }
        sequence.end()
    }
}
#[derive(Serialize)]
struct BorrowedHost17<'a> {
    schema_version: u16,
    source: &'a HostSchedulingSelection,
    runtime: &'a OriginalLineageRuntimeRecord,
    scheduling: &'a SchedulingSnapshot,
    objects: BorrowedObjects17<'a>,
    ancestry: BorrowedAncestry17<'a>,
    admission_policy: RestoredHostAdmissionPolicy17,
}
fn projected_index_backing() -> usize {
    "blake3-256".len()
        + "cnp.blob.v1".len()
        + 64
        + "application/vnd.crucible.native-signed-index-body.v3+json".len()
}
fn selected_schema17(source: &HostSchedulingSource) -> Result<&SchemaRef, RuntimeError> {
    let mut schemas = source
        .selection()
        .binding
        .compatibility
        .implementation
        .formats
        .iter()
        .filter(|schema| schema.id.as_str() == "source-owned.host-scheduling-continuation/17");
    let schema = schemas.next().ok_or(RuntimeError::UnsupportedFacet)?;
    if schemas.next().is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    authenticate_host_scheduling_restored_continuation_schema17_data(schema)?;
    if source
        .selection()
        .binding
        .compatibility
        .operating_contract
        .facets
        .len()
        != 1
        || source
            .selection()
            .binding
            .compatibility
            .operating_contract
            .facets[0]
            .id
            .as_str()
            != "source-owned.host-scheduling-original-lineage/2"
        || source
            .selection()
            .binding
            .compatibility
            .operating_contract
            .facets[0]
            .version
            != 2
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(schema)
}
fn checked_sum(terms: &[usize]) -> Result<usize, RuntimeError> {
    terms.iter().try_fold(0usize, |sum, term| {
        sum.checked_add(*term).ok_or(RuntimeError::ResourceLimit)
    })
}
fn failure_runtime(error: OperationFailure) -> RuntimeError {
    RuntimeError::SchedulerRefused(error.reason)
}

#[cfg(test)]
mod geometry_controls {
    use super::*;

    #[test]
    fn projected_index_reference_bounds_its_fixed_producer_wire_shape() {
        // These are accounting projections, not signed Index objects or capture
        // permission. The actual identity producer uses this exact fixed media.
        let projected = serde_json::to_value(ProjectedIndexReference17::maximum_data()).unwrap();
        let bound = canonical::canonical_json(&projected).unwrap().len();
        for length in [0, 9, 10, u32::MAX as u64, u64::MAX] {
            let reference = ContentRef {
                hash: crucible_node_contract::HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.blob.v1".into(),
                    digest: "a".repeat(64),
                },
                length: U64::new(length),
                media_type: "application/vnd.crucible.native-signed-index-body.v3+json".into(),
            };
            let encoded =
                canonical::canonical_json(&serde_json::to_value(reference).unwrap()).unwrap();
            assert!(encoded.len() <= bound);
        }
    }

    #[test]
    fn checked_constructor_axes_reject_overflow_and_preserve_exact_zero() {
        assert_eq!(checked_sum(&[]), Ok(0));
        assert_eq!(checked_sum(&[usize::MAX, 0]), Ok(usize::MAX));
        assert_eq!(
            checked_sum(&[usize::MAX, 1]),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(RestoredHost17CaptureConstructionData::counter_transient_bytes_data() >= 20);
    }
}
