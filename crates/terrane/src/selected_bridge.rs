//! Carries privately checked native publication across the storage boundary.
//!
//! The backend consumes fixed neutral records while repository verification
//! lives in the descendant producer module. Only that producer can initialize
//! the private capability fields, after checking actual held observations and
//! current authority. Decoded format records have no constructor into this type.

#[path = "guard/selected.rs"]
pub(crate) mod native_guard;

#[path = "gc/source_carry.rs"]
pub(crate) mod native_collection_sources;

// Collector lease verification has its own producer. Decoded lease records
// cannot construct the selected transition or its retained effect context.
/// Verifies selected collector leases before constructing their private handoff.
#[path = "gc/selected.rs"]
pub(crate) mod native_collection;

/// Verifies roots and completed marking before constructing a private checkpoint.
#[path = "gc/selected_checkpoint.rs"]
pub(crate) mod native_collection_checkpoints;

/// Verifies current destination data placement for copied pack retirement.
#[path = "gc/copied_placement.rs"]
pub(crate) mod native_copied_placement;

/// Selects copied retirement only from checked destination barriers and leases.
#[path = "gc/selected_copied_retirement.rs"]
pub(crate) mod native_copied_retirement;

/// Checks selected permanent owners and current local recovery inputs.
#[path = "gc/selected_permanent_local.rs"]
pub(crate) mod native_permanent_local;

// This test-only descendant constructs typed deadline checks for effect mechanics
// without exposing a production callback or authority factory.
#[cfg(all(feature = "std", test))]
#[path = "store/native_effect/final_check_tests.rs"]
pub(crate) mod effect_test_checks;

use crate::bucket::publication::SelectedObservation;
use crate::store::StoreFailure;
use crate::store::native_publication_effects::collection_permanent_local::NativePermanentObservation;
use std::sync::Arc;
use terrane_core::gc::publication::{
    LogicalChange, PublicationProof, PublicationState, SourceLineage,
};

/// Retains genuine request checks for the final selected-slot dispatch.
#[cfg(feature = "send")]
type FinalCheck<'operation> = dyn Fn() -> Result<(), StoreFailure> + Send + Sync + 'operation;

/// Retains genuine request checks without imposing native runtime bounds.
#[cfg(not(feature = "send"))]
type FinalCheck<'operation> = dyn Fn() -> Result<(), StoreFailure> + 'operation;

/// Owns the genuine producer's final check without borrowing its operation.
#[cfg(feature = "send")]
type OwnedCheck = dyn Fn() -> Result<(), StoreFailure> + Send + Sync + 'static;

/// Owns a final check for bindings whose runtime accepts non-Send futures.
#[cfg(not(feature = "send"))]
type OwnedCheck = dyn Fn() -> Result<(), StoreFailure> + 'static;

#[cfg(feature = "send")]
type SharedOwnedCheck = std::sync::Arc<OwnedCheck>;

#[cfg(not(feature = "send"))]
type SharedOwnedCheck = std::rc::Rc<OwnedCheck>;

/// Retains an owned authority refresh constructed only by a genuine producer.
#[derive(Clone)]
pub(crate) struct OwnedFinalCheck {
    check: SharedOwnedCheck,
}

#[cfg(not(feature = "send"))]
use std::rc::Rc as SharedOwned;
#[cfg(feature = "send")]
use std::sync::Arc as SharedOwned;

impl OwnedFinalCheck {
    /// Retains actual collector extraction descriptors beside genuine current authority.
    ///
    /// The closed worker receipt preserves physical source continuity through
    /// subsequent effects and waiter cancellation. It does not supply serving
    /// eligibility, replace complete body verification, or retain stale selected
    /// operation-cache preimages after this producer's own publication.
    pub(crate) fn with_permanent_source(&self, source: &Arc<NativePermanentObservation>) -> Self {
        let current = self.clone();
        let source = Arc::clone(source);
        Self {
            check: SharedOwned::new(move || {
                current.recheck()?;
                source.recheck_source().map_err(native_restore_failure)?;
                current.recheck()
            }),
        }
    }

    /// Refreshes genuine requests against their retained clock, keys and limits.
    ///
    /// # Errors
    /// Preserves current request or deadline rejection from the checked producer.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        (self.check)()
    }
}

/// Preserves the original native restore failure and its I/O cause.
pub(crate) fn native_restore_failure(error: crate::store::NativeEffectFailure) -> StoreFailure {
    match error {
        crate::store::NativeEffectFailure::Rejected(error) => error,
        crate::store::NativeEffectFailure::Io(error) => {
            let kind = match error.kind() {
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem => {
                    crate::store::StoreErrorKind::ReadOnly
                }
                std::io::ErrorKind::StorageFull => crate::store::StoreErrorKind::Capacity,
                std::io::ErrorKind::Unsupported => crate::store::StoreErrorKind::Unsupported,
                _ => crate::store::StoreErrorKind::Unavailable { retry_after: None },
            };
            StoreFailure::with_source(kind, error)
        }
    }
}

/// Binds one privately verified lease transition to its actual held selection.
///
/// Lease publication changes one complete logical value and the consecutive
/// selected revision. It cannot manufacture collection, lineage or permanent
/// retirement authority. Only the descendant collector producer initializes it.
pub(crate) struct CheckedGcLease<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    guard: crate::bucket::publication::receipts::RecordRead,
    next: PublicationState,
    change: LogicalChange,
    effects: GcLeaseEffectContext,
}

/// Retains genuine lease-time checks and every consumed protected control.
///
/// Actual native descriptor receipts keep the controls excluded through each
/// submitted effect and its durability acknowledgment. An empty caller list or
/// decoded configuration cannot construct this context.
pub(crate) struct GcLeaseEffectContext {
    final_check: OwnedFinalCheck,
    controls: Vec<crate::guard::RetainedControls>,
}

impl GcLeaseEffectContext {
    /// Retains the producer's exact owned clock and final lease check.
    pub(crate) fn final_check(&self) -> OwnedFinalCheck {
        self.final_check.clone()
    }

    /// Borrows all actual consumed control receipts retained by the producer.
    pub(crate) fn controls(&self) -> &[crate::guard::RetainedControls] {
        &self.controls
    }
}

impl<'operation, 'held> CheckedGcLease<'operation, 'held> {
    /// Borrows the complete observation checked for this lease operation.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows the exact selected protected Guard bytes and physical incarnation.
    pub(crate) fn guard_record(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.guard
    }

    /// Borrows the exact whole selected successor checked by the producer.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows the single complete lease expectation and replacement.
    pub(crate) fn change(&self) -> &LogicalChange {
        &self.change
    }

    /// Borrows genuine retained inputs for the dedicated lease effect lane.
    pub(crate) fn effect_context(&self) -> &GcLeaseEffectContext {
        &self.effects
    }

    /// Rechecks actual lease time immediately before the selected-slot dispatch.
    ///
    /// # Errors
    /// Preserves current lease expiry, clock continuity or operation rejection
    /// established by the genuine producer's owned check.
    pub(crate) fn recheck_before_slot(&self) -> Result<(), StoreFailure> {
        self.effects.final_check.recheck()
    }
}

/// Binds a checked mark checkpoint to actual whole selected and physical inputs.
///
/// Only the descendant producer initializes these fields. Canonical root, state
/// and mark records remain data; this handoff grants no sweep, restore, deletion
/// or source-preserving availability-loss authority.
pub(crate) struct CheckedGcCheckpoint<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    sources: Vec<&'operation SelectedObservation<'held>>,
    next: PublicationState,
    roots: terrane_core::gc::GcRoots,
    roots_digest: terrane_core::gc::publication::RawDigest,
    previous_roots: Option<Vec<u8>>,
    previous_state: Option<Vec<u8>>,
    publication: GcCheckpointPublication,
    reads: GcCheckpointReads,
    effects: GcCheckpointEffectContext,
}

/// Describes the closed data staged before a collector state selection.
pub(crate) enum GcCheckpointPublication {
    /// Selects the checked root snapshot and its initial marking frontier.
    Begin {
        /// Initial whole state genuinely derived from the checked roots.
        state: terrane_core::gc::GcState,
    },
    /// Stages immutable shard revisions before selecting the next frontier.
    Progress {
        /// Complete state with the checked pointers and remaining frontier.
        state: terrane_core::gc::GcState,
        /// Fixed canonical marks and their exact integrity pointers.
        revisions: Vec<GcMarkRevision>,
    },
    /// Verifies the completed selected shards, then selects sweep phase.
    FinishMark {
        /// Whole state whose marking frontier has been genuinely completed.
        state: terrane_core::gc::GcState,
        /// Optional final marks matching the selected incremental shard contents.
        /// Keeping the immutable revisions selected permits this list to be empty.
        final_marks: Vec<terrane_core::gc::GcMark>,
    },
}

impl GcCheckpointPublication {
    /// Borrows the complete next collector state without establishing authority.
    pub(crate) fn state(&self) -> &terrane_core::gc::GcState {
        match self {
            Self::Begin { state }
            | Self::Progress { state, .. }
            | Self::FinishMark { state, .. } => state,
        }
    }
}

/// Associates one canonical incremental mark with its exact raw digest pointer.
pub(crate) struct GcMarkRevision {
    pointer: terrane_core::gc::CheckpointPointer,
    mark: terrane_core::gc::GcMark,
}

impl GcMarkRevision {
    /// Borrows the canonical shard, revision and raw mark digest.
    pub(crate) fn pointer(&self) -> &terrane_core::gc::CheckpointPointer {
        &self.pointer
    }

    /// Borrows the whole mark whose bytes must match the pointer.
    pub(crate) fn mark(&self) -> &terrane_core::gc::GcMark {
        &self.mark
    }
}

/// Retains actual backend reads separately from selected logical preimages.
pub(crate) struct GcCheckpointReads {
    roots: crate::bucket::publication::receipts::RecordRead,
    state: crate::bucket::publication::receipts::RecordRead,
    marks: Vec<GcMarkRead>,
    inputs: Vec<crate::bucket::publication::receipts::RecordRead>,
}

impl GcCheckpointReads {
    /// Borrows the exact physical root record read, including actual absence.
    pub(crate) fn roots(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.roots
    }

    /// Borrows the exact physical state read without treating it as selection.
    pub(crate) fn state(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.state
    }

    /// Borrows all fixed incremental and final mark observations.
    pub(crate) fn marks(&self) -> &[GcMarkRead] {
        &self.marks
    }

    /// Borrows the actual complete metadata inputs consumed by marking.
    pub(crate) fn inputs(&self) -> &[crate::bucket::publication::receipts::RecordRead] {
        &self.inputs
    }
}

/// Identifies a physical mark observation using only fixed canonical segments.
pub(crate) enum GcMarkRead {
    /// Reads an immutable mark revision identified by its shard and revision.
    Revision {
        /// Canonical shard number in the collection's cycle.
        shard: u8,
        /// Canonical immutable revision number.
        revision: u64,
        /// Actual backend observation at the independently derived path.
        record: crate::bucket::publication::receipts::RecordRead,
    },
    /// Reads a final shard identified by its shard number.
    Final {
        /// Canonical shard number in the collection's cycle.
        shard: u8,
        /// Actual backend observation at the independently derived path.
        record: crate::bucket::publication::receipts::RecordRead,
    },
}

/// Retains the complete lease check and independently verified control owners.
///
/// The producer's owned final check captures its actual clock continuity and
/// shared poisoned-session state. Owner rows correspond one-for-one to actual
/// retained controls; foreign predicates never use the destination's owner UID.
pub(crate) struct GcCheckpointEffectContext {
    lease: terrane_core::gc::GcLease,
    final_check: OwnedFinalCheck,
    control_owners: Vec<GcControlOwner>,
    controls: Vec<crate::guard::RetainedControls>,
}

impl GcCheckpointEffectContext {
    /// Borrows the exact whole current lease verified by the producer.
    pub(crate) fn lease(&self) -> &terrane_core::gc::GcLease {
        &self.lease
    }

    /// Retains the actual owned clock, continuity and poisoned-session check.
    pub(crate) fn final_check(&self) -> OwnedFinalCheck {
        self.final_check.clone()
    }

    /// Borrows independent owner rows in canonical registration order.
    pub(crate) fn control_owners(&self) -> &[GcControlOwner] {
        &self.control_owners
    }

    /// Borrows the genuinely retained receipts paired with each owner row.
    pub(crate) fn controls(&self) -> &[crate::guard::RetainedControls] {
        &self.controls
    }
}

/// Describes independently checked predicates for one retained control owner.
pub(crate) struct GcControlOwner {
    registration: terrane_core::gc::publication::evidence::PhysicalRegistration,
    configured_operator_uid: u32,
    pins: Vec<terrane_core::gc::publication::evidence::RequiredControlPin>,
}

impl GcControlOwner {
    /// Borrows the complete independently verified physical registration.
    pub(crate) fn registration(
        &self,
    ) -> &terrane_core::gc::publication::evidence::PhysicalRegistration {
        &self.registration
    }

    /// Returns this owner's independently configured operator UID.
    pub(crate) fn configured_operator_uid(&self) -> u32 {
        self.configured_operator_uid
    }

    /// Borrows exact checked record pins belonging to this registration.
    pub(crate) fn pins(&self) -> &[terrane_core::gc::publication::evidence::RequiredControlPin] {
        &self.pins
    }
}

impl<'operation, 'held> CheckedGcCheckpoint<'operation, 'held> {
    /// Borrows the complete actual destination observation checked by the producer.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows every actual foreign namespace observation retained by the producer.
    pub(crate) fn sources(&self) -> &[&'operation SelectedObservation<'held>] {
        &self.sources
    }

    /// Borrows the whole predecessor with only its checked revision advanced.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows the complete checked collection snapshot.
    pub(crate) fn roots(&self) -> &terrane_core::gc::GcRoots {
        &self.roots
    }

    /// Returns raw BLAKE3-256 over the exact canonical root bytes.
    pub(crate) fn roots_digest(&self) -> terrane_core::gc::publication::RawDigest {
        self.roots_digest
    }

    /// Borrows the whole selected root preimage, including authoritative absence.
    pub(crate) fn previous_roots(&self) -> Option<&[u8]> {
        self.previous_roots.as_deref()
    }

    /// Borrows the whole selected state preimage, independent of mutable caches.
    pub(crate) fn previous_state(&self) -> Option<&[u8]> {
        self.previous_state.as_deref()
    }

    /// Borrows the closed typed checkpoint data without permitting caller paths.
    pub(crate) fn publication(&self) -> &GcCheckpointPublication {
        &self.publication
    }

    /// Borrows every actual physical observation consumed by this checkpoint.
    pub(crate) fn reads(&self) -> &GcCheckpointReads {
        &self.reads
    }

    /// Borrows the complete lease, owned checks and independently retained controls.
    pub(crate) fn effect_context(&self) -> &GcCheckpointEffectContext {
        &self.effects
    }

    /// Rechecks actual lease time, clock continuity and permanent session poison.
    ///
    /// # Errors
    /// Preserves the genuine producer's expiry, clock discontinuity or poisoned
    /// session rejection immediately before staging, slot dispatch or acknowledgment.
    pub(crate) fn recheck_before_slot(&self) -> Result<(), StoreFailure> {
        self.effects.final_check.recheck()
    }
}

/// Binds one checked transition to its actual retained backend observations.
///
/// The two lifetimes keep both the observation borrow and its underlying held
/// namespace alive through publication and portable-pointer acknowledgment.
/// No field, builder or deserializer permits ordinary callers to mint it.
pub(crate) struct CheckedMutation<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    sources: Vec<&'operation SelectedObservation<'held>>,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    evidence: CheckedEvidence,
    final_check: Box<FinalCheck<'operation>>,
    effect_context: Option<native_guard::GuardEffectContext>,
}

/// Retains one exact old selector and newly checked immutable Guard-carry body.
///
/// Only the held Guard-carry producer initializes these private fields. The
/// bytes are compared data, not a constructor for source or publication authority.
pub(crate) struct GuardCarriedLineage {
    previous: SourceLineage,
    encoded: Vec<u8>,
}

impl GuardCarriedLineage {
    /// Borrows the actual prior selected lineage checked by the held producer.
    pub(crate) fn previous(&self) -> &SourceLineage {
        &self.previous
    }

    /// Borrows the fresh canonical body bound to the new actual Guard snapshot.
    pub(crate) fn lineage(&self) -> &[u8] {
        &self.encoded
    }
}

/// Distinguishes the privately checked kinds of repository publication.
enum CheckedEvidence {
    Guard {
        snapshot: Vec<u8>,
        carried: Vec<GuardCarriedLineage>,
    },
    Candidate {
        snapshot: Vec<u8>,
        lineage: Vec<u8>,
    },
    SourceRequalification {
        snapshot: Vec<u8>,
        lineage: Vec<u8>,
        history_reads: Vec<crate::bucket::publication::receipts::RecordRead>,
    },
    // Tags and notes retain the selected Guard without acquiring branch history
    // or candidate lineage. Their genuine request checks remain in the producer.
    Advisory {
        snapshot: Vec<u8>,
    },
}

impl<'operation, 'held> CheckedMutation<'operation, 'held> {
    /// Borrows actual owned authority and consumed-control inputs, when retained.
    ///
    /// Absence refuses checked physical effects before staging or repair. It
    /// never permits substituting raw publication for a checked operation.
    pub(crate) fn effect_context(&self) -> Option<&native_guard::GuardEffectContext> {
        self.effect_context.as_ref()
    }

    /// Rechecks genuine operation authority immediately before slot dispatch.
    ///
    /// The backend invokes this after every asynchronous staging operation and
    /// before dispatching its final create-once primitive. The producer retains
    /// actual authenticated requests, trusted selected configuration and clock;
    /// backend and protected-control exclusions remain held through acknowledgment.
    /// This synchronous check performs no I/O or recursive lock acquisition.
    ///
    /// # Errors
    /// Rejects expired or retired capability keys, expired tokens, request
    /// caveat failures, or an elapsed operation deadline at the actual clock.
    pub(crate) fn recheck_before_slot(&self) -> Result<(), StoreFailure> {
        (self.final_check)()
    }

    /// Borrows the exact destination observation checked by the producer.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows every actual source observation retained by the producer.
    pub(crate) fn sources(&self) -> &[&'operation SelectedObservation<'held>] {
        &self.sources
    }

    /// Borrows the fixed whole successor, including Guard and lineage selectors.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows the exact whole-value logical mutations checked by the producer.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows the complete independently checked canonical Guard bytes.
    pub(crate) fn guard_snapshot(&self) -> &[u8] {
        match &self.evidence {
            CheckedEvidence::Guard { snapshot, .. }
            | CheckedEvidence::Candidate { snapshot, .. }
            | CheckedEvidence::SourceRequalification { snapshot, .. }
            | CheckedEvidence::Advisory { snapshot } => snapshot,
        }
    }

    /// Borrows completed lineage for candidate or same-head source publication.
    pub(crate) fn lineage(&self) -> Option<&[u8]> {
        match &self.evidence {
            CheckedEvidence::Guard { .. } | CheckedEvidence::Advisory { .. } => None,
            CheckedEvidence::Candidate { lineage, .. }
            | CheckedEvidence::SourceRequalification { lineage, .. } => Some(lineage),
        }
    }

    /// Borrows the sealed Guard producer's complete carried-lineage output list.
    ///
    /// Candidate, same-head source and advisory transitions carry no outputs.
    /// This accessor exposes data only; it cannot initialize private checks.
    pub(crate) fn guard_carried_lineages(&self) -> &[GuardCarriedLineage] {
        match &self.evidence {
            CheckedEvidence::Guard { carried, .. } => carried,
            CheckedEvidence::Candidate { .. }
            | CheckedEvidence::SourceRequalification { .. }
            | CheckedEvidence::Advisory { .. } => &[],
        }
    }

    /// Borrows genuine selected log-chain receipts for same-head requalification.
    ///
    /// Presence selects the private consumer route only. These ordinary read
    /// records supply no source completion, permission or durable acknowledgment.
    pub(crate) fn requalification_history_reads(
        &self,
    ) -> Option<&[crate::bucket::publication::receipts::RecordRead]> {
        match &self.evidence {
            CheckedEvidence::SourceRequalification { history_reads, .. } => Some(history_reads),
            CheckedEvidence::Guard { .. }
            | CheckedEvidence::Candidate { .. }
            | CheckedEvidence::Advisory { .. } => None,
        }
    }

    /// Returns the exact proof selector derived from the fixed checked bytes.
    pub(crate) fn proof(&self) -> PublicationProof {
        match &self.evidence {
            CheckedEvidence::Guard { snapshot, .. } => {
                PublicationProof::Guard(*blake3::hash(snapshot).as_bytes())
            }
            CheckedEvidence::Candidate { lineage, .. }
            | CheckedEvidence::SourceRequalification { lineage, .. } => {
                PublicationProof::Candidate(*blake3::hash(lineage).as_bytes())
            }
            CheckedEvidence::Advisory { .. } => PublicationProof::Raw,
        }
    }
}
