//! The evaluator-heap error type.
//!
//! One exhaustive [`EvalHeapError`] enum plus its constructor helpers and
//! conversions, moved verbatim from `heap/mod.rs` under the RFC-0007 §2
//! file-size cap. Like `tree_walk/error_kind.rs`, the enum is a single
//! indivisible parity-relevant surface (§4 — merging or renaming a variant is
//! a parity event), so the §2 "a cohesive unit beats a contrived split"
//! exception applies and the file is allowlisted rather than fragmented.

use super::*;

/// A typed evaluator-heap operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalHeapError {
    /// The runtime allocator could not allocate an opaque handle.
    #[error("evaluator heap allocation error: {0}")]
    Arena(#[from] ArenaError),
    /// The heap side table length overflowed.
    #[error("evaluator heap record length overflow")]
    RecordLengthOverflow,
    /// The heap side table could not reserve space for another object.
    #[error("evaluator heap failed to reserve {records} object records")]
    RecordAllocationFailed {
        /// The requested record capacity.
        records: usize,
    },
    /// Inline capture values were handed to a heap placement without tails.
    #[error("inline flat capture requires the serial flat closure store")]
    InlineCapturePlacementUnsupported,
    /// Lexical regions do not yet scan typed-head work slots as retained edges.
    #[error("worker regions are unsupported while typed thunk heads are enabled")]
    TypedThunkHeadsRegionUnsupported,
    /// The evaluator heap cons table length overflowed.
    #[error("evaluator heap cons table length overflow")]
    ConsTableLengthOverflow,
    /// The evaluator heap cons table could not reserve space for another entry.
    #[error("evaluator heap failed to reserve {entries} cons-table entries")]
    ConsTableAllocationFailed {
        /// The requested cons-table entry count.
        entries: usize,
    },
    /// A runtime value failed a checked heap-value operation.
    #[error("heap value operation failed: {0}")]
    Value(#[from] ValueError),
    /// A Candidate-C boxed-scalar store operation failed (variant carrier only).
    ///
    /// Carries the store error's rendered message so this enum keeps its
    /// `Clone`/`Eq` derives (the scalar error type is `Debug + Error` only).
    #[cfg(feature = "candidate_c_value")]
    #[error("candidate-c scalar store error: {message}")]
    CandidateCScalar {
        /// The rendered scalar-store error.
        message: String,
    },
    /// An attrset operation failed while rewriting a checked heap field.
    #[error("heap attrset operation failed: {0}")]
    Attr(#[from] AttrError),
    /// A packed immutable collection coordinate or lane was malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    #[error("packed heap collection operation failed: {message}")]
    PackedCollection {
        /// Rendered packed-lane error without exposing the private lane API.
        message: String,
    },
    /// A packed boxed-scalar coordinate or lane was malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    #[error("packed heap scalar operation failed: {message}")]
    PackedScalar {
        /// Rendered packed-lane error without exposing the private lane API.
        message: String,
    },
    /// A packed string or path coordinate or lane was malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    #[error("packed heap string/path operation failed: {message}")]
    PackedString {
        /// Rendered packed-lane error without exposing the private lane API.
        message: String,
    },
    /// An active packed thunk lane operation failed.
    #[cfg(feature = "active_packed_thunk_probe")]
    #[error("active packed thunk operation failed: {message}")]
    ActivePackedThunk {
        /// Rendered packed-lane error without exposing the private lane API.
        message: String,
    },
    /// A heap pointer did not belong to this evaluator heap.
    #[error("unknown heap pointer for {tag:?}: 0x{address:x}")]
    UnknownPointer {
        /// The expected runtime value tag.
        tag: ValueTag,
        /// The unrecognized pointer address.
        address: usize,
    },
    /// A heap pointer belonged to this heap but referenced another typed object.
    #[error("heap record type mismatch at 0x{address:x}: expected {expected:?}, got {actual:?}")]
    RecordTypeMismatch {
        /// The expected runtime value tag.
        expected: ValueTag,
        /// The actual typed record tag.
        actual: ValueTag,
        /// The pointer address shared by the runtime value and heap record.
        address: usize,
    },
    /// A released thunk's deferred work was read after capture shedding.
    ///
    /// `AOS_NIX_GC=sweep` sheds a forced thunk's captures at publish time
    /// ([`EvalThunkKind::Released`]); any later attempt to read the deferred
    /// work is an evaluator bug that must fail loudly instead of guessing.
    #[error("released thunk deferred work read after capture shedding at 0x{address:x}")]
    ReleasedThunkWork {
        /// The thunk record address whose released work was read.
        address: usize,
    },
    /// A capture-shedding request targeted a thunk that is not shed-eligible.
    #[error("capture shedding rejected at 0x{address:x}: {reason}")]
    ShedRejected {
        /// The thunk record address that was not shed-eligible.
        address: usize,
        /// Why the record cannot be shed.
        reason: &'static str,
    },
    /// A worker-region pop was requested after the Tier-B sweep retired records.
    ///
    /// Region pops rewind the bump arena and may reuse truncated addresses,
    /// which is only sound while retirement has never removed a non-tail
    /// record. The two reclaimers are mutually exclusive within one heap.
    #[error("worker-region pop rejected: {retired} records were retired by the Tier-B sweep")]
    RegionPopAfterSweep {
        /// The running total of records retired by the sweep.
        retired: u64,
    },
    /// A heap record already carries a different canonical value hash.
    #[error("heap value hash mismatch: existing {existing:?}, attempted {attempted:?}")]
    ValueHashMismatch {
        /// The hash already cached on the heap record.
        existing: ValueHash,
        /// The hash the caller attempted to cache.
        attempted: ValueHash,
    },
    /// The worker allocator cannot be reset while worker records remain live.
    #[error(
        "worker allocator reset rejected while {records} worker-domain heap records remain live"
    )]
    WorkerResetLiveRecords {
        /// The number of worker-domain records still registered in the heap.
        records: usize,
    },
    /// A Tier-B admission plan no longer matches current arena accounting.
    #[error(
        "Tier-B admission plan is stale for {domain} arena: expected {expected:?}, actual {actual:?}"
    )]
    TierBAdmissionStaleArenaStats {
        /// The arena domain whose accounting changed.
        domain: &'static str,
        /// The arena accounting captured by the admission plan.
        expected: ArenaStats,
        /// The current arena accounting.
        actual: ArenaStats,
    },
    /// A Tier-B admission plan no longer matches the heap record count.
    #[error(
        "Tier-B admission plan is stale: record count was {expected_records}, now {actual_records}"
    )]
    TierBAdmissionStaleRecordCount {
        /// The typed heap record count captured by the plan.
        expected_records: usize,
        /// The current typed heap record count.
        actual_records: usize,
    },
    /// A Tier-B admission plan no longer matches the record at an index.
    #[error(
        "Tier-B admission plan record {index} address is stale: expected 0x{expected:x}, actual 0x{actual:x}",
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    TierBAdmissionStaleRecordAddress {
        /// The heap-record index whose address changed.
        index: usize,
        /// The heap address captured by the plan.
        expected: GcHeapAddress,
        /// The current heap address at the same index.
        actual: GcHeapAddress,
    },
    /// A Tier-B admission plan no longer matches a record's allocation domain.
    #[error(
        "Tier-B admission plan record {index} at 0x{address:x} allocation domain changed: expected {expected:?}, actual {actual:?}",
        address = address.address_bits()
    )]
    TierBAdmissionStaleRecordDomain {
        /// The heap-record index whose allocation domain changed.
        index: usize,
        /// The heap address of the record.
        address: GcHeapAddress,
        /// The allocation domain captured by the plan.
        expected: HeapAllocationDomain,
        /// The current allocation domain.
        actual: HeapAllocationDomain,
    },
    /// A Tier-B admission plan no longer matches a record's generation.
    #[error(
        "Tier-B admission plan record {index} at 0x{address:x} generation changed: expected {expected:?}, actual {actual:?}",
        address = address.address_bits()
    )]
    TierBAdmissionStaleRecordGeneration {
        /// The heap-record index whose generation changed.
        index: usize,
        /// The heap address of the record.
        address: GcHeapAddress,
        /// The generation captured by the plan.
        expected: HeapGeneration,
        /// The current generation.
        actual: HeapGeneration,
    },
    /// A worker-region marker referred to more records than the heap currently
    /// contains.
    #[error(
        "worker region pop marker is stale: {reason}; marker record count was {marker_records}, current record count is {current_records}"
    )]
    WorkerRegionPopStaleMark {
        /// The stale marker condition that failed.
        reason: &'static str,
        /// The typed heap record count captured by the marker.
        marker_records: usize,
        /// The current typed heap record count.
        current_records: usize,
    },
    /// The worker-region mark stack length overflowed.
    #[error("worker region mark stack length overflow")]
    WorkerRegionMarkLengthOverflow,
    /// The worker-region mark stack could not reserve another marker.
    #[error("evaluator heap failed to reserve {marks} worker region marks")]
    WorkerRegionMarkAllocationFailed {
        /// The requested mark capacity.
        marks: usize,
    },
    /// The worker-region mark id space was exhausted.
    #[error("worker region mark id space exhausted")]
    WorkerRegionMarkIdExhausted,
    /// A worker-region pop would reclaim non-worker records.
    #[error("worker region pop rejected while {records} non-worker records exist above the marker")]
    WorkerRegionPopNonWorkerRecords {
        /// The number of non-worker records allocated above the marker.
        records: usize,
    },
    /// A retained heap record still references an object above the region
    /// marker.
    #[error(
        "worker region pop rejected because retained object 0x{source_address:x} field {edge_source:?} points at reclaimed object 0x{target_address:x}",
        source_address = source_address.address_bits(),
        target_address = target_address.address_bits()
    )]
    WorkerRegionPopRetainedEdge {
        /// The retained source object containing the edge.
        source_address: GcHeapAddress,
        /// The precise source label on the retained object.
        edge_source: HeapEdgeSource,
        /// The worker object above the marker that would be reclaimed.
        target_address: GcHeapAddress,
    },
    /// A thunk-resolution write barrier was requested for a non-thunk source.
    #[error("thunk resolve write barrier source must be a thunk, found {actual:?}")]
    ThunkResolveBarrierSourceNotThunk {
        /// The runtime tag supplied as the source object.
        actual: ValueTag,
    },
    /// Lexical environment access failed during precise root scanning.
    #[error("heap root scan environment error: {0}")]
    Environment(#[from] EvalEnvError),
    /// Thunk state access failed during precise root scanning.
    #[error("heap root scan thunk error: {0}")]
    Thunk(#[from] ForceError),
    /// Parallel thunk payload access failed during precise root scanning.
    #[error("heap root scan parallel thunk payload error: {0}")]
    ParallelThunkPayload(#[from] ParallelThunkPayloadError),
    /// Precise root scanning overflowed a side table length.
    #[error("heap root scan {table} length overflow")]
    RootScanLengthOverflow {
        /// The scanner side table being grown.
        table: &'static str,
    },
    /// Precise root scanning could not reserve side table storage.
    #[error("heap root scan failed to reserve {entries} {table} entries")]
    RootScanAllocationFailed {
        /// The scanner side table being grown.
        table: &'static str,
        /// The requested side table capacity.
        entries: usize,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// record.
    #[error("collector-poll heap graph is stale for 0x{address:x}", address = address.address_bits())]
    CollectorPollScanStaleObject {
        /// The object whose current outgoing edges differ from the snapshot.
        address: GcHeapAddress,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// allocation state.
    #[error(
        "collector-poll heap graph snapshot is stale: {reason}; record count was {expected_records}, now {actual_records}"
    )]
    CollectorPollScanStaleHeapSnapshot {
        /// The stale snapshot condition that failed.
        reason: &'static str,
        /// The typed heap record count captured by the scan.
        expected_records: usize,
        /// The current typed heap record count.
        actual_records: usize,
    },
    /// A remembered-set edge referenced an address outside this evaluator heap.
    #[error("collector-poll remembered-set {role} address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollRememberedEdgeAddress {
        /// Whether the unknown address was the edge source or target.
        role: &'static str,
        /// The unrecognized remembered-set address.
        address: GcHeapAddress,
    },
    /// A remembered-set edge did not describe an old/permanent-to-young edge in
    /// the current oracle heap.
    #[error(
        "collector-poll remembered-set edge is not old/permanent-to-young: 0x{source:x} ({source_generation:?}) -> 0x{target:x} ({target_generation:?})",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    InvalidCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The current generation of the source record.
        source_generation: HeapGeneration,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
        /// The current generation of the target record.
        target_generation: HeapGeneration,
    },
    /// A visible permanent-to-young edge was absent from the supplied
    /// remembered-set snapshot.
    #[error(
        "collector-poll minor-GC plan is missing remembered permanent-to-young edge: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    MissingCollectorPollRememberedEdge {
        /// The permanent source object containing the young reference.
        source_address: GcHeapAddress,
        /// The young target object that must be remembered.
        target_address: GcHeapAddress,
    },
    /// A remembered-set edge's source card was absent from the supplied
    /// card-table snapshot.
    #[error(
        "collector-poll remembered-set edge source card {card_index} is not dirty: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    MissingCollectorPollDirtyCard {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
        /// The source card index expected in the dirty-card snapshot.
        card_index: usize,
    },
    /// A remembered-set edge no longer matches any concrete source field.
    #[error(
        "collector-poll remembered-set edge has no current source field: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    StaleCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
    },
    /// A planned minor-GC survivor no longer belongs to this evaluator heap.
    #[error("collector-poll minor-GC survivor address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollSurvivorAddress {
        /// The unrecognized survivor address.
        address: GcHeapAddress,
    },
    /// A planned object-generation write points at no destination heap record.
    #[error(
        "collector-poll minor-GC object-generation destination does not belong to this heap: 0x{destination:x}",
        destination = destination.address_bits()
    )]
    UnknownCollectorPollObjectGenerationDestination {
        /// The destination address that should receive generation metadata.
        destination: GcHeapAddress,
    },
    /// A planned object-generation write would rewrite the from-space source
    /// record as its own relocated destination.
    #[error(
        "collector-poll minor-GC object-generation write for 0x{source_address:x} uses its source as destination",
        source_address = source_address.address_bits()
    )]
    CollectorPollObjectGenerationWriteDestinationIsSource {
        /// The duplicated from-space source and destination address.
        source_address: GcHeapAddress,
    },
    /// A planned object-generation write appears more than once for one source.
    #[error(
        "collector-poll minor-GC object-generation write for 0x{source_address:x} appears more than once at index {index}",
        source_address = source_address.address_bits()
    )]
    CollectorPollObjectGenerationWriteDuplicateSource {
        /// The duplicated write index.
        index: usize,
        /// The duplicated from-space source address.
        source_address: GcHeapAddress,
    },
    /// Multiple object-generation writes target one destination record.
    #[error(
        "collector-poll minor-GC object-generation destination 0x{destination:x} for source 0x{source_address:x} conflicts with source 0x{existing_source_address:x} at index {index}",
        destination = destination.address_bits(),
        source_address = source_address.address_bits(),
        existing_source_address = existing_source_address.address_bits()
    )]
    CollectorPollObjectGenerationWriteDuplicateDestination {
        /// The duplicated write index.
        index: usize,
        /// The source address currently being validated.
        source_address: GcHeapAddress,
        /// The earlier source address targeting the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicated destination address.
        destination: GcHeapAddress,
    },
    /// A planned object-generation write targets a from-space survivor source.
    #[error(
        "collector-poll minor-GC object-generation destination 0x{destination:x} for source 0x{source_address:x} overlaps survivor source 0x{existing_source_address:x}, detected at index {index}",
        destination = destination.address_bits(),
        source_address = source_address.address_bits(),
        existing_source_address = existing_source_address.address_bits()
    )]
    CollectorPollObjectGenerationWriteDestinationOverlapsSource {
        /// The request index where the overlap was detected.
        index: usize,
        /// The source address whose destination overlaps a survivor source.
        source_address: GcHeapAddress,
        /// The survivor source address that overlaps a destination.
        existing_source_address: GcHeapAddress,
        /// The destination address that overlaps a survivor source.
        destination: GcHeapAddress,
    },
    /// A planned object-generation write's destination generation disagrees
    /// with its survivor action.
    #[error(
        "collector-poll minor-GC object-generation write for 0x{source_address:x} -> 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    CollectorPollObjectGenerationWriteGenerationMismatch {
        /// The from-space source address.
        source_address: GcHeapAddress,
        /// The destination address.
        destination: GcHeapAddress,
        /// The generation implied by the survivor action.
        expected: HeapGeneration,
        /// The generation carried by the object-copy request.
        actual: HeapGeneration,
        /// The survivor action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A collector-poll commit application did not receive one reference value
    /// per copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference buffer length {actual} does not match copied slot count {expected}"
    )]
    CollectorPollCommitReferenceSlotLengthMismatch {
        /// The copied allocation-poll reference-slot count.
        expected: usize,
        /// The caller-supplied reference buffer length.
        actual: usize,
    },
    /// A collector-poll commit application found a reference value that no
    /// longer matches the copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference slot {index} expected {expected:?}, found {actual:?}"
    )]
    CollectorPollCommitReferenceSlotMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The reference value captured with the poll plan.
        expected: ResolvedValueGeneration,
        /// The caller-supplied reference value.
        actual: ResolvedValueGeneration,
    },
    /// Boundary live remembered-set publication saw an unexpected source epoch.
    #[error(
        "boundary minor-GC live remembered-set source epoch {actual} does not match outcome epoch {expected}"
    )]
    BoundaryMinorGcLiveRememberedSetSourceEpochMismatch {
        /// The epoch held by the outcome-owned remembered set.
        expected: RememberedSetEpoch,
        /// The source epoch consumed by the boundary commit application.
        actual: RememberedSetEpoch,
    },
    /// Boundary live remembered-set publication saw an unexpected next epoch.
    #[error(
        "boundary minor-GC live remembered-set next epoch {actual} does not match expected next epoch {expected}"
    )]
    BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
        /// The epoch expected for merged live remembered-set publication.
        expected: RememberedSetEpoch,
        /// The next epoch published by the boundary commit application.
        actual: RememberedSetEpoch,
    },
    /// Boundary sibling dry-runs disagreed about an overlapping relocation.
    #[error(
        "boundary minor-GC live remembered-set merge relocation mismatch for source {source_address:?}: expected {expected:?}, found {actual:?}"
    )]
    BoundaryMinorGcLiveRememberedSetRelocationMismatch {
        /// The from-space survivor address present in both sibling applications.
        source_address: GcHeapAddress,
        /// The first relocation value recorded for the source.
        expected: ResolvedValueGeneration,
        /// The sibling relocation value recorded for the source.
        actual: ResolvedValueGeneration,
    },
    /// Boundary sibling dry-runs mapped different sources to one destination.
    #[error(
        "boundary minor-GC live remembered-set merge destination collision for {destination:?}: source {source_address:?} conflicts with {existing_source_address:?}"
    )]
    BoundaryMinorGcLiveRememberedSetDestinationCollision {
        /// The from-space survivor address currently being validated.
        source_address: GcHeapAddress,
        /// The earlier from-space survivor address that uses the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicate relocation value.
        destination: ResolvedValueGeneration,
    },
    /// Boundary sibling dry-runs mapped a survivor into from-space.
    #[error(
        "boundary minor-GC live remembered-set merge destination {destination:?} collides with live source {source_address:?}"
    )]
    BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
        /// The from-space survivor address also used as a destination.
        source_address: GcHeapAddress,
        /// The relocation value whose address collides with the source set.
        destination: ResolvedValueGeneration,
    },
    /// An existing-destination boundary commit found a dirty live card table
    /// after metadata publication should have cleared it.
    #[error(
        "boundary minor-GC existing-destination commit expected a clean live card table after metadata publication, found {dirty_cards} dirty cards"
    )]
    BoundaryMinorGcExistingDestinationCommitDirtyCardTable {
        /// The number of dirty-card markers still present.
        dirty_cards: usize,
    },
    /// An existing-destination boundary commit found that its already-published
    /// remembered set does not cover an installed direct heap-field writeback.
    #[error(
        "boundary minor-GC existing-destination commit published remembered set is missing direct writeback edge 0x{source_address:x} -> 0x{target_address:x}",
        source_address = source_address.address_bits(),
        target_address = target_address.address_bits()
    )]
    BoundaryMinorGcExistingDestinationCommitMissingRememberedEdge {
        /// The old or permanent source object whose field will be rewritten.
        source_address: GcHeapAddress,
        /// The young replacement destination required by the installed writeback.
        target_address: GcHeapAddress,
    },
    /// An existing-destination boundary commit had writeback metadata but no
    /// remembered-set publication recorded with that metadata.
    #[error(
        "boundary minor-GC existing-destination commit has {bindings} writeback destination bindings but no recorded remembered-set publication"
    )]
    BoundaryMinorGcExistingDestinationCommitMissingRememberedSetPublication {
        /// The number of installed writeback destination bindings.
        bindings: usize,
    },
    /// An existing-destination boundary commit found a live remembered set that
    /// no longer matches the publication recorded with its writeback metadata.
    #[error(
        "boundary minor-GC existing-destination commit remembered-set publication mismatch: expected epoch {expected_epoch:?} with {expected_edges} edges, found epoch {actual_epoch:?} with {actual_edges} edges"
    )]
    BoundaryMinorGcExistingDestinationCommitRememberedSetPublicationMismatch {
        /// The remembered-set epoch recorded with the writeback metadata.
        expected_epoch: RememberedSetEpoch,
        /// The currently published remembered-set epoch.
        actual_epoch: RememberedSetEpoch,
        /// The remembered-edge count recorded with the writeback metadata.
        expected_edges: usize,
        /// The currently published remembered-edge count.
        actual_edges: usize,
    },
    /// Boundary live destination-byte snapshots have already been installed.
    #[error(
        "boundary minor-GC live destination storage already contains {existing} object snapshots"
    )]
    BoundaryMinorGcLiveDestinationStorageAlreadyInstalled {
        /// The number of previously installed destination object snapshots.
        existing: usize,
    },
    /// Boundary live object-generation metadata has already been installed.
    #[error("boundary minor-GC live object generations already contain {existing} object records")]
    BoundaryMinorGcLiveObjectGenerationsAlreadyInstalled {
        /// The number of previously installed object-generation records.
        existing: usize,
    },
    /// Boundary live reference-writeback metadata has already been installed.
    #[error(
        "boundary minor-GC live reference writebacks already contain {existing} rewritten slots"
    )]
    BoundaryMinorGcLiveReferenceWritebacksAlreadyInstalled {
        /// The number of previously installed reference-writeback slots.
        existing: usize,
    },
    /// Boundary live forwarding destination bindings have already been installed.
    #[error(
        "boundary minor-GC live forwarding destination bindings already contain {existing} binding records"
    )]
    BoundaryMinorGcLiveForwardingDestinationBindingsAlreadyInstalled {
        /// The number of previously installed forwarding destination bindings.
        existing: usize,
    },
    /// Boundary live writeback destination bindings have already been installed.
    #[error(
        "boundary minor-GC live writeback destination bindings already contain {existing} binding records"
    )]
    BoundaryMinorGcLiveWritebackDestinationBindingsAlreadyInstalled {
        /// The number of previously installed writeback destination bindings.
        existing: usize,
    },
    /// Boundary sibling dry-runs disagreed about one destination byte snapshot.
    #[error(
        "boundary minor-GC live destination storage object mismatch for source 0x{source_address:x}: expected {expected:?}, found {actual:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcLiveDestinationStorageObjectMismatch {
        /// The from-space survivor address present in both sibling applications.
        source_address: GcHeapAddress,
        /// The first byte-copy request recorded for the source.
        expected: AllocationCollectorPollObjectByteCopyRequest,
        /// The sibling byte-copy request recorded for the source.
        actual: AllocationCollectorPollObjectByteCopyRequest,
    },
    /// Boundary sibling dry-runs mapped different sources to one byte snapshot.
    #[error(
        "boundary minor-GC live destination storage destination collision for 0x{destination_address:x}: source 0x{source_address:x} conflicts with 0x{existing_source_address:x}",
        destination_address = destination_address.address_bits(),
        source_address = source_address.address_bits(),
        existing_source_address = existing_source_address.address_bits()
    )]
    BoundaryMinorGcLiveDestinationStorageDestinationCollision {
        /// The from-space survivor address currently being validated.
        source_address: GcHeapAddress,
        /// The earlier from-space survivor address that uses the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicate destination object address.
        destination_address: GcHeapAddress,
    },
    /// An object-generation write plan has no installed destination-byte snapshot.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} -> 0x{destination:x}/{generation:?}/{action:?} has no installed destination snapshot",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteMissingDestination {
        /// The from-space survivor source object.
        source_address: GcHeapAddress,
        /// The destination address carried by the object-generation record.
        destination: GcHeapAddress,
        /// The copy or promotion action carried by the object-generation record.
        action: MinorGcSurvivorAction,
        /// The generation carried by the object-generation record.
        generation: HeapGeneration,
    },
    /// An object-generation write plan found stale destination-byte metadata.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} expected {expected:?}/{expected_generation:?}, found {actual:?}/{actual_generation:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteBindingMismatch {
        /// The from-space survivor whose metadata disagreed.
        source_address: GcHeapAddress,
        /// The byte-copy request carried by the object-generation record.
        expected: AllocationCollectorPollObjectByteCopyRequest,
        /// The generation carried by the object-generation record.
        expected_generation: HeapGeneration,
        /// The byte-copy request carried by the installed destination snapshot.
        actual: AllocationCollectorPollObjectByteCopyRequest,
        /// The generation implied by the installed destination snapshot.
        actual_generation: HeapGeneration,
    },
    /// An object-generation write plan found duplicated generation metadata.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} appears more than once at index {index}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteDuplicateSource {
        /// The duplicated generation-record index.
        index: usize,
        /// The duplicated from-space survivor source object.
        source_address: GcHeapAddress,
    },
    /// An object-generation write plan found duplicated destination metadata.
    #[error(
        "boundary minor-GC object-generation write destination 0x{destination:x} for source 0x{source_address:x} conflicts with source 0x{existing_source_address:x} at index {index}",
        destination = destination.address_bits(),
        source_address = source_address.address_bits(),
        existing_source_address = existing_source_address.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteDuplicateDestination {
        /// The duplicated generation-record index.
        index: usize,
        /// The from-space survivor currently being validated.
        source_address: GcHeapAddress,
        /// The earlier from-space survivor that uses the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicated destination object address.
        destination: GcHeapAddress,
    },
    /// An object-generation write plan found duplicated destination snapshot metadata.
    #[error(
        "boundary minor-GC object-generation destination snapshot for source 0x{source_address:x} appears more than once at index {index}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteDuplicateDestinationSource {
        /// The duplicated destination snapshot index.
        index: usize,
        /// The duplicated from-space survivor source object.
        source_address: GcHeapAddress,
    },
    /// An object-generation record's request belongs to another source.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} carries request source 0x{request_source:x}",
        source_address = source_address.address_bits(),
        request_source = request_source.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteRequestSourceMismatch {
        /// The source carried by the object-generation record.
        source_address: GcHeapAddress,
        /// The source carried by the byte-copy request.
        request_source: GcHeapAddress,
    },
    /// An object-generation record's request points at another destination.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} expected request destination 0x{generation_destination:x}, found 0x{request_destination:x}",
        source_address = source_address.address_bits(),
        generation_destination = generation_destination.address_bits(),
        request_destination = request_destination.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteRequestDestinationMismatch {
        /// The source carried by the object-generation record.
        source_address: GcHeapAddress,
        /// The destination carried by the object-generation record.
        generation_destination: GcHeapAddress,
        /// The destination carried by the byte-copy request.
        request_destination: GcHeapAddress,
    },
    /// An object-generation record's action disagrees with its request.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} -> 0x{destination:x} has action {generation_action:?}, request has {request_action:?}",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteRequestActionMismatch {
        /// The source carried by the object-generation record.
        source_address: GcHeapAddress,
        /// The destination carried by the object-generation record.
        destination: GcHeapAddress,
        /// The action carried by the object-generation record.
        generation_action: MinorGcSurvivorAction,
        /// The action carried by the byte-copy request.
        request_action: MinorGcSurvivorAction,
    },
    /// An object-generation record's generation disagrees with its action.
    #[error(
        "boundary minor-GC object-generation write for 0x{source_address:x} -> 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteGenerationMismatch {
        /// The source carried by the object-generation record.
        source_address: GcHeapAddress,
        /// The destination carried by the object-generation record.
        destination: GcHeapAddress,
        /// The generation implied by the destination action.
        expected: HeapGeneration,
        /// The generation carried by the object-generation record.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A destination-byte snapshot has no installed object-generation record.
    #[error(
        "boundary minor-GC destination snapshot for 0x{source_address:x} -> 0x{destination:x}/{generation:?}/{action:?} has no installed object-generation record",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcObjectGenerationWriteUnboundDestination {
        /// The from-space survivor source object.
        source_address: GcHeapAddress,
        /// The destination address carried by the destination snapshot.
        destination: GcHeapAddress,
        /// The copy or promotion action carried by the destination snapshot.
        action: MinorGcSurvivorAction,
        /// The generation implied by the destination snapshot.
        generation: HeapGeneration,
    },
    /// A live root writeback points at no installed destination-byte snapshot.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} points at missing destination 0x{destination:x}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackDestinationMissing {
        /// The copied root source whose replacement needs destination bytes.
        root_source: EvalRootSource,
        /// The replacement destination address without an installed snapshot.
        destination: GcHeapAddress,
    },
    /// A live root writeback's typed replacement disagrees with its destination metadata.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} expected destination 0x{expected_destination:x}, found typed {actual_tag:?}/0x{actual_payload:016x}",
        expected_destination = expected_destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackDestinationMismatch {
        /// The copied root source whose replacement metadata disagreed.
        root_source: EvalRootSource,
        /// The destination address carried by the generation-style root slot.
        expected_destination: GcHeapAddress,
        /// The tag carried by the typed root slot.
        actual_tag: ValueTag,
        /// The raw typed-slot payload bits.
        actual_payload: u64,
    },
    /// A live root writeback's generation disagrees with its destination action.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} destination 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackGenerationMismatch {
        /// The copied root source whose destination generation disagreed.
        root_source: EvalRootSource,
        /// The replacement destination address.
        destination: GcHeapAddress,
        /// The generation implied by the destination action.
        expected: HeapGeneration,
        /// The generation carried by the generation-style root slot.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A root-writeback write plan has no installed destination binding.
    #[error(
        "boundary minor-GC root writeback write for {allocation_domain:?} {root_source:?} -> 0x{destination:x}/{generation:?}/{replacement_tag:?} has no installed destination binding",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackWriteMissingBinding {
        /// The allocator domain assigned to the root writeback.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source whose replacement needs a binding.
        root_source: EvalRootSource,
        /// The tag carried by the typed root replacement.
        replacement_tag: ValueTag,
        /// The replacement destination address.
        destination: GcHeapAddress,
        /// The generation carried by the generation-style root slot.
        generation: HeapGeneration,
    },
    /// A root-writeback write plan found stale destination-binding metadata.
    #[error(
        "boundary minor-GC root writeback write for {allocation_domain:?} {root_source:?} expected {expected_tag:?}/0x{expected_destination:x}/{expected_generation:?}, found {actual_tag:?}/0x{actual_destination:x}/{actual_generation:?}",
        expected_destination = expected_destination.address_bits(),
        actual_destination = actual_destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackWriteBindingMismatch {
        /// The allocator domain assigned to the root writeback.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source whose binding disagreed.
        root_source: EvalRootSource,
        /// The tag carried by the installed root writeback.
        expected_tag: ValueTag,
        /// The destination carried by the installed root writeback.
        expected_destination: GcHeapAddress,
        /// The generation carried by the installed root writeback.
        expected_generation: HeapGeneration,
        /// The tag carried by the installed destination binding.
        actual_tag: ValueTag,
        /// The destination carried by the installed destination binding.
        actual_destination: GcHeapAddress,
        /// The generation carried by the installed destination binding.
        actual_generation: HeapGeneration,
    },
    /// A root-writeback write plan found duplicated live writeback metadata.
    #[error(
        "boundary minor-GC root writeback write for {allocation_domain:?} {root_source:?} appears more than once at index {index}"
    )]
    BoundaryMinorGcRootWritebackWriteDuplicateSource {
        /// The duplicated source index.
        index: usize,
        /// The allocator domain assigned to the root writeback.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source that appears more than once.
        root_source: EvalRootSource,
    },
    /// A root-writeback write plan found duplicated destination-binding metadata.
    #[error(
        "boundary minor-GC root writeback binding for {allocation_domain:?} {root_source:?} appears more than once at index {index}"
    )]
    BoundaryMinorGcRootWritebackWriteDuplicateBinding {
        /// The duplicated binding index.
        index: usize,
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source recorded by the destination binding.
        root_source: EvalRootSource,
    },
    /// A root-writeback destination binding's request points at a different destination.
    #[error(
        "boundary minor-GC root writeback binding for {allocation_domain:?} {root_source:?} expected request destination 0x{binding_destination:x}, found 0x{request_destination:x}",
        binding_destination = binding_destination.address_bits(),
        request_destination = request_destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackWriteRequestDestinationMismatch {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source recorded by the destination binding.
        root_source: EvalRootSource,
        /// The destination carried by the installed destination binding.
        binding_destination: GcHeapAddress,
        /// The destination carried by the binding's byte-copy request.
        request_destination: GcHeapAddress,
    },
    /// A root-writeback destination binding has no installed live writeback.
    #[error(
        "boundary minor-GC root writeback binding for {allocation_domain:?} {root_source:?} -> 0x{destination:x}/{generation:?}/{replacement_tag:?} has no installed live writeback",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackWriteUnboundBinding {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The copied root source recorded by the destination binding.
        root_source: EvalRootSource,
        /// The tag carried by the destination binding.
        replacement_tag: ValueTag,
        /// The replacement destination address carried by the binding.
        destination: GcHeapAddress,
        /// The generation carried by the destination binding.
        generation: HeapGeneration,
    },
    /// A boundary outcome-root writer was asked to mutate a root it does not own.
    #[error(
        "boundary minor-GC outcome root writeback cannot write unsupported root source {root_source:?}"
    )]
    BoundaryMinorGcOutcomeRootWritebackUnsupportedSource {
        /// The root source that is not owned by the evaluation outcome value.
        root_source: EvalRootSource,
    },
    /// A boundary outcome-root writer was asked to rewrite one physical slot twice.
    #[error(
        "boundary minor-GC outcome root writeback cannot write duplicate value-stack slot 0 at index {index} from {root_source:?}"
    )]
    BoundaryMinorGcOutcomeRootWritebackDuplicateValueStackRoot {
        /// The duplicated write index in the validated root-writeback plan.
        index: usize,
        /// The root source that duplicates the outcome-owned slot.
        root_source: EvalRootSource,
    },
    /// The source object for an outcome root writeback is no longer young.
    #[error(
        "boundary minor-GC outcome root writeback for {root_source:?} source 0x{source_address:x} has generation {actual:?}, expected {expected:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcOutcomeRootWritebackSourceGenerationMismatch {
        /// The outcome-owned root source being rewritten.
        root_source: EvalRootSource,
        /// The from-space object expected in the outcome root.
        source_address: GcHeapAddress,
        /// The generation required for a minor-GC source.
        expected: HeapGeneration,
        /// The current heap-record generation for the source object.
        actual: HeapGeneration,
    },
    /// The destination object for an outcome root writeback has the wrong generation.
    #[error(
        "boundary minor-GC outcome root writeback for {root_source:?} destination 0x{destination:x} has generation {actual:?}, expected {expected:?}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcOutcomeRootWritebackDestinationGenerationMismatch {
        /// The outcome-owned root source being rewritten.
        root_source: EvalRootSource,
        /// The destination object written into the outcome root.
        destination: GcHeapAddress,
        /// The generation carried by the validated root writeback.
        expected: HeapGeneration,
        /// The current heap-record generation for the destination object.
        actual: HeapGeneration,
    },
    /// Destination-record reservation cannot reserve this young heap object.
    #[error(
        "collector-poll minor-GC destination reservation for source 0x{source_address:x} cannot reserve a {tag:?} record",
        source_address = source_address.address_bits()
    )]
    CollectorPollMinorGcDestinationReservationUnsupported {
        /// The young source object that needs a destination record.
        source_address: GcHeapAddress,
        /// The source object's heap tag.
        tag: ValueTag,
    },
    /// A planned survivor has no reserved destination record.
    #[error(
        "collector-poll minor-GC survivor 0x{source_address:x} has no reserved destination record",
        source_address = source_address.address_bits()
    )]
    CollectorPollMinorGcDestinationReservationMissing {
        /// The planned survivor source object.
        source_address: GcHeapAddress,
    },
    /// A minor-GC object-body write plan references a destination outside the heap.
    #[error(
        "collector-poll object-body write destination 0x{destination:x} does not belong to this heap",
        destination = destination.address_bits()
    )]
    UnknownCollectorPollObjectBodyDestination {
        /// The destination address that should already resolve to a heap record.
        destination: GcHeapAddress,
    },
    /// A minor-GC object-body write's destination record has stale layout metadata.
    #[error(
        "collector-poll object-body write layout mismatch at 0x{address:x}: expected {expected_size} bytes/{expected_align} align, got {actual_size} bytes/{actual_align} align",
        address = address.address_bits()
    )]
    CollectorPollObjectBodyWriteLayoutMismatch {
        /// The source or destination object address whose side-table layout failed validation.
        address: GcHeapAddress,
        /// The byte size captured by the object-copy request.
        expected_size: usize,
        /// The byte size currently stored on the heap record.
        actual_size: usize,
        /// The alignment captured by the object-copy request.
        expected_align: usize,
        /// The alignment currently stored on the heap record.
        actual_align: usize,
    },
    /// A minor-GC object-body write has not been applied for a destination record.
    #[error(
        "collector-poll object-body binding mismatch for source 0x{source_address:x} -> destination 0x{destination:x}: {reason}",
        source_address = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    CollectorPollObjectBodyWriteBindingMismatch {
        /// The planned from-space source object.
        source_address: GcHeapAddress,
        /// The planned destination object.
        destination: GcHeapAddress,
        /// The validation condition that failed.
        reason: &'static str,
    },
    /// A reference writeback could not be matched to an object-copy request.
    #[error(
        "collector-poll reference writeback {index} has no object-copy request for {expected:?} -> {replacement:?}"
    )]
    CollectorPollReferenceWritebackObjectCopyRequestMissing {
        /// The reference-writeback slot index.
        index: usize,
        /// The expected from-space value for the root or field.
        expected: ResolvedValueGeneration,
        /// The relocated replacement value for the root or field.
        replacement: ResolvedValueGeneration,
    },
    /// A destination byte-copy request disagrees with its own survivor action.
    #[error(
        "boundary minor-GC destination request for 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationActionGenerationMismatch {
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The generation implied by the survivor action.
        expected: HeapGeneration,
        /// The generation carried by the destination request.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A destination byte-copy snapshot does not match its request length.
    #[error(
        "boundary minor-GC destination snapshot for 0x{destination:x} has {actual} bytes, expected {expected}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationPayloadSizeMismatch {
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The byte length requested by the object-copy metadata.
        expected: usize,
        /// The installed byte-snapshot length.
        actual: usize,
    },
    /// A forwarding value points at no installed destination-byte snapshot.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} points at missing destination payload",
        source = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationMissing {
        /// The from-space source whose forwarding value lacks destination bytes.
        source_address: GcHeapAddress,
    },
    /// A destination-byte snapshot has no matching forwarding value.
    #[error(
        "boundary minor-GC destination payload for source 0x{source:x} -> 0x{destination:x} has no forwarding value",
        source = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationForwardingMissing {
        /// The from-space source object.
        source_address: GcHeapAddress,
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
    },
    /// A forwarding value is not heap-backed destination metadata.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} is not heap destination metadata: {actual:?}",
        source = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationNonHeap {
        /// The from-space source whose forwarding metadata is invalid.
        source_address: GcHeapAddress,
        /// The non-heap forwarding metadata.
        actual: ResolvedValueGeneration,
    },
    /// A forwarding value disagrees with its destination-byte snapshot.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} expected destination 0x{expected:x}, found 0x{actual:x}",
        source = source_address.address_bits(),
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationMismatch {
        /// The from-space source whose forwarding destination disagreed.
        source_address: GcHeapAddress,
        /// The destination address installed with copied bytes.
        expected: GcHeapAddress,
        /// The destination address carried by forwarding metadata.
        actual: GcHeapAddress,
    },
    /// A forwarding value's generation disagrees with its destination action.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} destination 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        source = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcForwardingGenerationMismatch {
        /// The from-space source whose forwarding generation disagreed.
        source_address: GcHeapAddress,
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The generation implied by the destination action.
        expected: HeapGeneration,
        /// The generation carried by forwarding metadata.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A heap-field writeback replacement is not heap-backed metadata.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} replacement is not heap metadata: {value:?}",
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The non-heap replacement metadata.
        value: ResolvedValueGeneration,
    },
    /// A heap-field writeback replacement points at no destination-byte snapshot.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} points at missing replacement destination 0x{replacement:x}",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementMissing {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address without an installed snapshot.
        replacement: GcHeapAddress,
    },
    /// A heap-field writeback replacement generation disagrees with its copy action.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} replacement 0x{replacement:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The generation implied by the replacement copy action.
        expected: HeapGeneration,
        /// The generation carried by the replacement metadata.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A copied nursery-field writeback object has no destination-byte snapshot.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{validation_object:x}[{field_index}] {field_source:?} targets missing writeback object 0x{writeback_object:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackObjectMissing {
        /// The from-space object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The relocated object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A copied nursery-field writeback object snapshot belongs to another source.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{validation_object:x}[{field_index}] {field_source:?} targets destination 0x{writeback_object:x} from source 0x{actual_source:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits(),
        actual_source = actual_source.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
        /// The from-space object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The relocated object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The source address recorded by the installed destination snapshot.
        actual_source: GcHeapAddress,
    },
    /// A heap-field writeback write plan has no installed destination binding.
    #[error(
        "boundary minor-GC heap-field writeback write for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} -> 0x{replacement:x}/{generation:?} has no installed destination binding",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteMissingBinding {
        /// The allocator domain assigned to the heap-field source.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The replacement generation.
        generation: HeapGeneration,
    },
    /// A heap-field writeback write plan found stale destination-binding metadata.
    #[error(
        "boundary minor-GC heap-field writeback write for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} expected 0x{expected_replacement:x}/{expected_generation:?}, found 0x{actual_replacement:x}/{actual_generation:?}",
        writeback_object = writeback_object.address_bits(),
        expected_replacement = expected_replacement.address_bits(),
        actual_replacement = actual_replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteBindingMismatch {
        /// The allocator domain assigned to the heap-field source.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination carried by the live writeback.
        expected_replacement: GcHeapAddress,
        /// The replacement generation carried by the live writeback.
        expected_generation: HeapGeneration,
        /// The replacement destination carried by the installed binding.
        actual_replacement: GcHeapAddress,
        /// The replacement generation carried by the installed binding.
        actual_generation: HeapGeneration,
    },
    /// A heap-field writeback write plan found duplicated live writeback metadata.
    #[error(
        "boundary minor-GC heap-field writeback write for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} appears more than once at index {index}",
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
        /// The duplicated source index.
        index: usize,
        /// The allocator domain assigned to the heap-field source.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A heap-field writeback write plan found duplicated destination-binding metadata.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} appears more than once at index {index}",
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteDuplicateBinding {
        /// The duplicated binding index.
        index: usize,
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A heap-field writeback destination binding's request points at another replacement.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} expected replacement request destination 0x{binding_replacement:x}, found 0x{request_destination:x}",
        writeback_object = writeback_object.address_bits(),
        binding_replacement = binding_replacement.address_bits(),
        request_destination = request_destination.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination carried by the installed binding.
        binding_replacement: GcHeapAddress,
        /// The destination carried by the binding's replacement request.
        request_destination: GcHeapAddress,
    },
    /// A heap-field writeback destination binding has malformed writeback-object metadata.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{validation_object:x}[{field_index}] {field_source:?} targets 0x{writeback_object:x} with malformed writeback-object metadata",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A heap-field writeback-object request points at another destination.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{validation_object:x}[{field_index}] {field_source:?} expected writeback-object request destination 0x{writeback_object:x}, found 0x{request_destination:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits(),
        request_destination = request_destination.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteObjectRequestDestinationMismatch {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The destination carried by the binding's writeback-object request.
        request_destination: GcHeapAddress,
    },
    /// A heap-field writeback-object request belongs to another source object.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{validation_object:x}[{field_index}] {field_source:?} targets writeback object 0x{writeback_object:x} from source 0x{actual_source:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits(),
        actual_source = actual_source.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The source recorded by the writeback-object request.
        actual_source: GcHeapAddress,
    },
    /// A heap-field destination binding has no installed live writeback.
    #[error(
        "boundary minor-GC heap-field writeback binding for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} -> 0x{replacement:x}/{generation:?} has no installed live writeback",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackWriteUnboundBinding {
        /// The allocator domain recorded by the destination binding.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination carried by the binding.
        replacement: GcHeapAddress,
        /// The replacement generation carried by the binding.
        generation: HeapGeneration,
    },
    /// A live heap-field applicator does not yet support in-place field writes.
    #[error(
        "boundary minor-GC heap-field writeback application for {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?} is not a copied nursery-object field",
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackApplyUnsupportedInPlace {
        /// The allocator domain recorded by the write plan.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A live reference writeback destination aliases a direct heap-field owner.
    #[error(
        "boundary minor-GC live reference writeback destination 0x{destination:x} aliases direct heap-field writeback owner {allocation_domain:?} 0x{writeback_object:x}[{field_index}] {field_source:?}",
        destination = destination.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
        /// The allocator domain recorded by the direct field write.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten in place.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The direct field source label.
        field_source: HeapEdgeSource,
        /// The object-copy destination that aliases the direct field owner.
        destination: GcHeapAddress,
    },
    /// A copied heap-field write targets a field kind that is not record-owned.
    #[error(
        "collector-poll minor-GC copied heap-field write for 0x{writeback_object:x}[{field_index}] {field_source:?} is not a record-owned list, attrset, or primop-argument field",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollCopiedHeapFieldWriteUnsupportedSource {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A direct heap-field write targets a field kind that is not record-owned.
    #[error(
        "collector-poll minor-GC direct heap-field write for 0x{writeback_object:x}[{field_index}] {field_source:?} is not a supported record-owned list, attrset, primop-argument, or lambda capture field",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollDirectHeapFieldWriteUnsupportedSource {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The direct field source label.
        field_source: HeapEdgeSource,
    },
    /// A copied heap-field write found a stale from-space field value.
    #[error(
        "collector-poll minor-GC copied heap-field write for 0x{writeback_object:x}[{field_index}] {field_source:?} expected {expected:?}, found {actual:?}",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollCopiedHeapFieldWriteValueMismatch {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The from-space field value expected before mutation.
        expected: ResolvedValueGeneration,
        /// The current field value.
        actual: ResolvedValueGeneration,
    },
    /// A direct heap-field write found a stale from-space field value.
    #[error(
        "collector-poll minor-GC direct heap-field write for 0x{writeback_object:x}[{field_index}] {field_source:?} expected {expected:?}, found {actual:?}",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollDirectHeapFieldWriteValueMismatch {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The direct field source label.
        field_source: HeapEdgeSource,
        /// The from-space field value expected before mutation.
        expected: ResolvedValueGeneration,
        /// The current field value.
        actual: ResolvedValueGeneration,
    },
    /// A copied heap-field writeback object has not received its destination generation.
    #[error(
        "collector-poll minor-GC copied heap-field writeback object 0x{writeback_object:x} has generation {actual:?}, expected {expected:?}",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollCopiedHeapFieldWriteObjectGenerationMismatch {
        /// The copied heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The generation required by the writeback-object copy request.
        expected: HeapGeneration,
        /// The current heap-record generation.
        actual: HeapGeneration,
    },
    /// A direct heap-field writeback object is not in the expected generation.
    #[error(
        "collector-poll minor-GC direct heap-field writeback object 0x{writeback_object:x} from {allocation_domain:?} has generation {actual:?}, expected {expected:?}",
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
        /// The allocator domain recorded by the write plan.
        allocation_domain: HeapAllocationDomain,
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The generation required for direct in-place mutation.
        expected: HeapGeneration,
        /// The current heap-record generation.
        actual: HeapGeneration,
    },
    /// A direct heap-field replacement would keep an old/permanent-to-young edge live.
    #[error(
        "collector-poll minor-GC direct heap-field replacement 0x{replacement:x} for 0x{writeback_object:x}[{field_index}] {field_source:?} has generation {generation:?}; direct writes currently require promoted-old replacements",
        replacement = replacement.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollDirectHeapFieldWriteYoungReplacementUnsupported {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The direct field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The replacement generation carried by the write plan.
        generation: HeapGeneration,
    },
    /// A copied heap-field replacement object has not received its destination generation.
    #[error(
        "collector-poll minor-GC copied heap-field replacement 0x{replacement:x} for 0x{writeback_object:x}[{field_index}] {field_source:?} has generation {actual:?}, expected {expected:?}",
        replacement = replacement.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollCopiedHeapFieldWriteReplacementGenerationMismatch {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The generation carried by the write plan.
        expected: HeapGeneration,
        /// The current heap-record generation.
        actual: HeapGeneration,
    },
    /// A direct heap-field replacement object has not received its destination generation.
    #[error(
        "collector-poll minor-GC direct heap-field replacement 0x{replacement:x} for 0x{writeback_object:x}[{field_index}] {field_source:?} has generation {actual:?}, expected {expected:?}",
        replacement = replacement.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    CollectorPollDirectHeapFieldWriteReplacementGenerationMismatch {
        /// The heap object whose field would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The direct field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The generation carried by the write plan.
        expected: HeapGeneration,
        /// The current heap-record generation.
        actual: HeapGeneration,
    },
    /// A forwarding-header write plan has no installed forwarding value for a binding.
    #[error(
        "boundary minor-GC forwarding-header write for 0x{source_address:x} is missing live forwarding value {expected:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingHeaderWriteMissingForwarding {
        /// The from-space object whose header would be written.
        source_address: GcHeapAddress,
        /// The forwarding value required by the installed destination binding.
        expected: ResolvedValueGeneration,
    },
    /// A forwarding-header write plan found a stale forwarding value.
    #[error(
        "boundary minor-GC forwarding-header write for 0x{source_address:x} expected live forwarding value {expected:?}, found {actual:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingHeaderWriteForwardingMismatch {
        /// The from-space object whose header would be written.
        source_address: GcHeapAddress,
        /// The forwarding value required by the installed destination binding.
        expected: ResolvedValueGeneration,
        /// The live forwarding value currently installed on the heap record.
        actual: ResolvedValueGeneration,
    },
    /// A live forwarding value has no installed forwarding-destination binding.
    #[error(
        "boundary minor-GC live forwarding value for 0x{source_address:x} has no forwarding-header destination binding: {actual:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingHeaderWriteUnboundForwarding {
        /// The from-space object whose forwarding value is unbound.
        source_address: GcHeapAddress,
        /// The live forwarding value currently installed on the heap record.
        actual: ResolvedValueGeneration,
    },
    /// Existing-destination live commit reference writebacks lack forwarding-header coverage.
    #[error(
        "boundary minor-GC existing-destination commit has {references} reference writebacks but only {forwarding_headers} forwarding-header writes"
    )]
    BoundaryMinorGcExistingDestinationCommitMissingForwardingHeaders {
        /// The number of supported reference writebacks covered by the preflight.
        references: usize,
        /// The number of forwarding headers covered by the preflight.
        forwarding_headers: usize,
    },
    /// A live forwarding installation received an empty forwarding slot.
    #[error(
        "collector-poll minor-GC forwarding slot for 0x{address:x} at index {index} has no forwarded value",
        address = address.address_bits()
    )]
    CollectorPollForwardingSlotEmpty {
        /// The supplied forwarding slot index.
        index: usize,
        /// The source object whose forwarding slot was empty.
        address: GcHeapAddress,
    },
    /// A live forwarding installation received a duplicated source slot.
    #[error(
        "collector-poll minor-GC forwarding slot for 0x{address:x} appears more than once at index {index}",
        address = address.address_bits()
    )]
    CollectorPollForwardingSlotDuplicateSource {
        /// The supplied forwarding slot index.
        index: usize,
        /// The duplicated source object.
        address: GcHeapAddress,
    },
    /// A caller-supplied root value list did not contain one value per copied
    /// root reference slot.
    #[error(
        "collector-poll minor-GC root reference value count {actual} does not match copied root slot count {expected}"
    )]
    CollectorPollRootReferenceValueLengthMismatch {
        /// The copied allocation-poll root-slot count.
        expected: usize,
        /// The caller-supplied root value count.
        actual: usize,
    },
    /// A caller-supplied or installed root value names a different root source.
    #[error(
        "collector-poll minor-GC root reference source {index} mismatch: expected {expected:?}, found {actual:?}"
    )]
    CollectorPollRootReferenceSourceMismatch {
        /// The copied allocation-poll reference slot or root-writeback pair index.
        index: usize,
        /// The copied root source captured by the poll plan.
        expected: EvalRootSource,
        /// The caller-supplied root source.
        actual: EvalRootSource,
    },
    /// A root writeback application did not receive one caller-owned slot per
    /// derived root writeback.
    #[error(
        "collector-poll minor-GC root writeback slot count {actual} does not match root writeback count {expected}"
    )]
    CollectorPollRootWritebackSlotLengthMismatch {
        /// The derived root writeback count.
        expected: usize,
        /// The caller-supplied root writeback slot count.
        actual: usize,
    },
    /// A root-backed writeback was derived from a copied slot without the
    /// heap-value tag needed to reconstruct a typed replacement value later.
    #[error(
        "collector-poll minor-GC root writeback slot {index} for {root_source:?} is missing its copied value tag"
    )]
    CollectorPollRootWritebackMissingValueTag {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The copied root source missing tag metadata.
        root_source: EvalRootSource,
    },
    /// A tagged root-writeback value could not be reconstructed from
    /// heap-backed address metadata.
    #[error(
        "collector-poll minor-GC root writeback value with tag {tag:?} is not heap-backed metadata: {value:?}"
    )]
    CollectorPollRootWritebackNonHeapValue {
        /// The copied heap tag associated with the root writeback.
        tag: ValueTag,
        /// The generation metadata that should have carried a heap address.
        value: ResolvedValueGeneration,
    },
    /// A caller-owned root `Value` slot no longer contains the expected raw
    /// evaluator value.
    #[error(
        "collector-poll minor-GC root value writeback slot {index} value mismatch: expected {expected_tag:?}/0x{expected_payload:016x}, found {actual_tag:?}/0x{actual_payload:016x}"
    )]
    CollectorPollRootValueWritebackSlotMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The tag expected in the caller-owned slot.
        expected_tag: ValueTag,
        /// The payload expected in the caller-owned slot.
        expected_payload: u64,
        /// The actual tag supplied by the caller-owned slot.
        actual_tag: ValueTag,
        /// The actual payload supplied by the caller-owned slot.
        actual_payload: u64,
    },
    /// A live reference buffer cannot be derived for copied root-only slots yet.
    #[error(
        "collector-poll minor-GC reference slot {index} is not heap-field-backed: {root_source:?}"
    )]
    CollectorPollReferenceSlotNotHeapBacked {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The copied root source that still needs external mutable storage.
        root_source: EvalRootSource,
    },
    /// A heap-field-backed reference slot no longer points at the same field.
    #[error(
        "collector-poll minor-GC reference slot {index} source mismatch: expected {expected:?}, found {actual:?}"
    )]
    CollectorPollReferenceSlotSourceMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The precise field source captured by the poll plan.
        expected: HeapEdgeSource,
        /// The current field source at the saved index, if any.
        actual: Option<HeapEdgeSource>,
    },
    /// A heap-field writeback application did not receive one caller-owned slot
    /// per derived heap-field writeback.
    #[error(
        "collector-poll minor-GC heap-field writeback slot count {actual} does not match heap-field writeback count {expected}"
    )]
    CollectorPollHeapFieldWritebackSlotLengthMismatch {
        /// The derived heap-field writeback count.
        expected: usize,
        /// The caller-supplied heap-field writeback slot count.
        actual: usize,
    },
    /// A caller-owned heap-field writeback slot names different objects than the
    /// copied writeback plan.
    #[error(
        "collector-poll minor-GC heap-field writeback slot {index} object mismatch: expected validation 0x{expected_validation_object:x} / writeback 0x{expected_writeback_object:x}, found validation 0x{actual_validation_object:x} / writeback 0x{actual_writeback_object:x}",
        expected_validation_object = expected_validation_object.address_bits(),
        expected_writeback_object = expected_writeback_object.address_bits(),
        actual_validation_object = actual_validation_object.address_bits(),
        actual_writeback_object = actual_writeback_object.address_bits()
    )]
    CollectorPollHeapFieldWritebackSlotObjectMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The heap object used to validate the copied field label.
        expected_validation_object: GcHeapAddress,
        /// The caller-supplied validation object.
        actual_validation_object: GcHeapAddress,
        /// The heap object whose field must be rewritten.
        expected_writeback_object: GcHeapAddress,
        /// The caller-supplied writeback object.
        actual_writeback_object: GcHeapAddress,
    },
    /// A caller-owned heap-field writeback slot names a different field than
    /// the copied writeback plan.
    #[error(
        "collector-poll minor-GC heap-field writeback slot {index} field mismatch: expected field {expected_field_index} {expected_source:?}, found field {actual_field_index} {actual_source:?}"
    )]
    CollectorPollHeapFieldWritebackSlotFieldMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The precise field index captured by the writeback plan.
        expected_field_index: usize,
        /// The caller-supplied field index.
        actual_field_index: usize,
        /// The precise field source captured by the writeback plan.
        expected_source: HeapEdgeSource,
        /// The caller-supplied field source.
        actual_source: HeapEdgeSource,
    },
    /// A heap-field-backed reference slot object no longer belongs to this heap.
    #[error("collector-poll minor-GC reference slot object does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollReferenceSlotAddress {
        /// The unrecognized reference-slot object address.
        address: GcHeapAddress,
    },
    /// A planned object byte-copy source no longer has the copied layout.
    #[error(
        "collector-poll minor-GC object byte-copy layout mismatch for 0x{address:x}: expected {expected_size} bytes/{expected_align}-byte alignment, found {actual_size} bytes/{actual_align}-byte alignment",
        address = address.address_bits()
    )]
    CollectorPollObjectByteCopyLayoutMismatch {
        /// The copied source object address.
        address: GcHeapAddress,
        /// The planned copy size in bytes.
        expected_size: usize,
        /// The current source-record size in bytes.
        actual_size: usize,
        /// The planned copy alignment in bytes.
        expected_align: usize,
        /// The current source-record alignment in bytes.
        actual_align: usize,
    },
    /// The generational minor-GC planner rejected the oracle snapshot.
    #[error("collector-poll minor-GC planning error: {0}")]
    GenerationalGc(#[from] GenerationalGcError),
    /// A parallel-mode shared-arena heap operation failed.
    #[error("shared evaluator heap error: {0}")]
    SharedArena(#[from] SharedHeapError),
    /// A shared-mode heap operation ran on a heap without a shared backend.
    ///
    /// This is an internal invariant violation: shared-mode entry points are
    /// only dispatched when the backend is installed. It is reported as an
    /// error rather than a panic so no invariant break is silently absorbed.
    #[error("shared heap backend missing for a shared-mode heap operation")]
    SharedBackendMissing,
}

impl EvalHeapError {
    // `pub(super)`: constructed throughout the heap module tree (the
    // pre-split private access, made module-explicit by the §2 relocation).
    pub(super) fn unknown(tag: ValueTag, ptr: NonNull<HeapObject>) -> Self {
        Self::UnknownPointer {
            tag,
            address: ptr.as_ptr() as usize,
        }
    }

    // `pub(super)`: see `unknown`.
    pub(super) fn record_type_mismatch(
        expected: ValueTag,
        actual: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Self {
        Self::RecordTypeMismatch {
            expected,
            actual,
            address: ptr.as_ptr() as usize,
        }
    }
}

impl From<HashConsError> for EvalHeapError {
    fn from(error: HashConsError) -> Self {
        match error {
            HashConsError::BucketLengthOverflow => Self::ConsTableLengthOverflow,
            HashConsError::TableAllocationFailed { entries }
            | HashConsError::BucketAllocationFailed { entries } => {
                Self::ConsTableAllocationFailed { entries }
            }
        }
    }
}

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
impl From<packed_collection_lane::PackedCollectionLaneError> for EvalHeapError {
    fn from(error: packed_collection_lane::PackedCollectionLaneError) -> Self {
        Self::PackedCollection {
            message: error.to_string(),
        }
    }
}

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
impl From<packed_scalar_lane::PackedScalarLaneError> for EvalHeapError {
    fn from(error: packed_scalar_lane::PackedScalarLaneError) -> Self {
        Self::PackedScalar {
            message: error.to_string(),
        }
    }
}

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
impl From<packed_string_lane::PackedStringLaneError> for EvalHeapError {
    fn from(error: packed_string_lane::PackedStringLaneError) -> Self {
        Self::PackedString {
            message: error.to_string(),
        }
    }
}
