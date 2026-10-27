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

/// Derives opaque own-context histories from actual cycle or current roots.
#[path = "gc/qualified_roots.rs"]
pub(crate) mod native_collection_roots;

/// Owns the closed initial nonburned retirement producer.
#[path = "gc/selected_retirement.rs"]
pub(crate) mod native_collection_retirement;

/// Qualifies exact pre-ownership restoration under independently current held inputs.
#[path = "gc/selected_restore.rs"]
pub(crate) mod native_collection_restore;

/// Qualifies renewed full-D waiting and first protected local ownership only.
#[path = "gc/selected_local_ownership.rs"]
pub(crate) mod native_local_ownership;

/// Requalifies ordinary local ownership before actual unlink and recovery.
#[path = "gc/selected_local_deletion.rs"]
pub(crate) mod native_local_deletion;

/// Retains independently verified root histories without destructive authority.
pub(crate) use native_collection_roots::QualifiedCollectionRoots;

/// Reconciles completed cycle marks with independently verified held current roots.
#[path = "gc/current.rs"]
pub(crate) mod native_current_collection;

// This test-only descendant constructs typed deadline checks for effect mechanics
// without exposing a production callback or authority factory.
#[cfg(all(feature = "std", test, feature = "tokio"))]
#[path = "store/native_effect/final_check_tests.rs"]
pub(crate) mod effect_test_checks;

use crate::bucket::publication::SelectedObservation;
use crate::store::StoreFailure;
use crate::store::native_publication_effects::collection_copied_retirement::NativeBarrier;
use crate::store::native_publication_effects::collection_permanent_local::NativePermanentObservation;
use std::sync::Arc;
use terrane_format::gc::publication::{
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
    /// Retains genuine copied barrier continuity beside current authority.
    ///
    /// Each submitted effect retains the opaque preparation and NEW-barrier
    /// descriptors even if its waiter disappears. Actual elapsed observation
    /// remains on the original clock; this check neither restarts the wait nor
    /// grants ownership from a decoded age or proposed record.
    pub(crate) fn with_copied_barrier(&self, barrier: &NativeBarrier) -> Self {
        let current = self.clone();
        let barrier = barrier.retain();
        Self {
            check: SharedOwned::new(move || {
                current.recheck()?;
                barrier.elapsed().map_err(native_restore_failure)?;
                current.recheck()
            }),
        }
    }

    /// Retains genuine maintenance pairs with linear physical bracketing.
    ///
    /// Forward inventory order preserves each first observation. The reverse
    /// pass checks earlier pairs again after every later pair was observed;
    /// the last pair needs no duplicate observation. The original current
    /// check runs before the first pair and after each observation, preserving
    /// clock, expiry and cancellation refusal without recursively duplicating
    /// previously retained pair checks. Every effect still refreshes its full
    /// Frame and retains all genuine descriptors through acknowledgment.
    pub(crate) fn with_restore_pairs(
        &self,
        pairs: &[crate::store::native_publication_effects::NativeRestorePair],
    ) -> Self {
        if pairs.is_empty() {
            return self.clone();
        }

        let current = self.clone();
        let held: Vec<_> = pairs.iter().map(|pair| pair.held()).collect();
        Self {
            check: SharedOwned::new(move || {
                current.recheck()?;
                for pair in held.iter().chain(held.iter().rev().skip(1)) {
                    pair.recheck().map_err(native_restore_failure)?;
                    current.recheck()?;
                }
                Ok(())
            }),
        }
    }

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

    /// Retains actual maintenance descriptors alongside genuine current authority.
    ///
    /// The one-element prefix preserves the same current-pair-current ordering
    /// as complete collector prefixes and retains the actual native receipt.
    pub(crate) fn with_restore_pair(
        &self,
        pair: &crate::store::native_publication_effects::NativeRestorePair,
    ) -> Self {
        self.with_restore_pairs(std::slice::from_ref(pair))
    }

    /// Retains original candidate-directory continuity during unselected staging.
    ///
    /// Only fresh, unselected progress proposals may use this narrower physical
    /// check. Mutable checkpoint keys still require their genuine absent preimage.
    /// The owning producer must restore complete candidate enumeration before
    /// preselection synchronization and keep it through slot installation and
    /// acknowledgment. Continuity alone proves neither coverage nor absence.
    pub(crate) fn with_permanent_candidate_continuity(
        &self,
        source: &Arc<NativePermanentObservation>,
    ) -> Self {
        let current = self.clone();
        let source = Arc::clone(source);
        Self {
            check: SharedOwned::new(move || {
                current.recheck()?;
                source
                    .recheck_candidate_continuity()
                    .map_err(native_restore_failure)?;
                current.recheck()
            }),
        }
    }

    /// Retains metadata-only continuity from an executor-produced maintenance pair.
    pub(crate) fn restore_continuity(
        pair: &crate::store::native_publication_effects::NativeRestorePair,
    ) -> Self {
        let held = pair.held();
        Self {
            check: SharedOwned::new(move || held.recheck().map_err(native_restore_failure)),
        }
    }

    /// Retains genuine candidate-family traversal beside current authority.
    ///
    /// The opaque native receipt refreshes its complete family enumeration and
    /// retained directory continuity before selecting progress. Selected history
    /// still determines pass coverage; physical evidence alone cannot complete
    /// a pass or grant permission to reclaim an artifact.
    pub(crate) fn with_permanent_traversal(
        &self,
        source: &Arc<NativePermanentObservation>,
    ) -> Self {
        let current = self.clone();
        let source = Arc::clone(source);
        Self {
            check: SharedOwned::new(move || {
                current.recheck()?;
                source
                    .recheck_candidate_walk()
                    .map_err(native_restore_failure)?;
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
    roots: terrane_format::gc::GcRoots,
    roots_digest: terrane_format::gc::publication::RawDigest,
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
        state: terrane_format::gc::GcState,
    },
    /// Stages immutable shard revisions before selecting the next frontier.
    Progress {
        /// Complete state with the checked pointers and remaining frontier.
        state: terrane_format::gc::GcState,
        /// Fixed canonical marks and their exact integrity pointers.
        revisions: Vec<GcMarkRevision>,
    },
    /// Verifies the completed selected shards, then selects sweep phase.
    FinishMark {
        /// Whole state whose marking frontier has been genuinely completed.
        state: terrane_format::gc::GcState,
        /// Optional final marks matching the selected incremental shard contents.
        /// Keeping the immutable revisions selected permits this list to be empty.
        final_marks: Vec<terrane_format::gc::GcMark>,
    },
}

impl GcCheckpointPublication {
    /// Borrows the complete next collector state without establishing authority.
    pub(crate) fn state(&self) -> &terrane_format::gc::GcState {
        match self {
            Self::Begin { state }
            | Self::Progress { state, .. }
            | Self::FinishMark { state, .. } => state,
        }
    }
}

/// Associates one canonical incremental mark with its exact raw digest pointer.
pub(crate) struct GcMarkRevision {
    pointer: terrane_format::gc::CheckpointPointer,
    mark: terrane_format::gc::GcMark,
}

impl GcMarkRevision {
    /// Borrows the canonical shard, revision and raw mark digest.
    pub(crate) fn pointer(&self) -> &terrane_format::gc::CheckpointPointer {
        &self.pointer
    }

    /// Borrows the whole mark whose bytes must match the pointer.
    pub(crate) fn mark(&self) -> &terrane_format::gc::GcMark {
        &self.mark
    }
}

/// Retains actual backend reads separately from selected logical preimages.
pub(crate) struct GcCheckpointReads {
    roots: crate::bucket::publication::receipts::RecordRead,
    state: crate::bucket::publication::receipts::RecordRead,
    marks: Vec<GcMarkRead>,
    inputs: Vec<crate::bucket::publication::receipts::RecordRead>,
    guard: crate::bucket::publication::receipts::RecordRead,
}

impl GcCheckpointReads {
    /// Borrows the exact selected Guard record retained under protected owner checks.
    ///
    /// This input is separate from namespace Payload records and grants no
    /// trust or mutation authority by its decoded bytes alone.
    pub(crate) fn guard(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.guard
    }

    /// Borrows the exact physical root record read, including actual absence.
    pub(crate) fn roots(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.roots
    }

    /// Borrows the exact physical state read without treating it as selection.
    pub(crate) fn state(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.state
    }

    /// Borrows all fixed immutable mark-revision observations.
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
}

/// Retains the complete lease check and independently verified control owners.
///
/// The producer's owned final check captures its actual clock continuity and
/// shared poisoned-session state. Owner rows correspond one-for-one to actual
/// retained controls; foreign predicates never use the destination's owner UID.
pub(crate) struct GcCheckpointEffectContext {
    lease: terrane_format::gc::GcLease,
    final_check: OwnedFinalCheck,
    control_owners: Vec<GcControlOwner>,
    controls: Vec<crate::guard::RetainedControls>,
}

impl GcCheckpointEffectContext {
    /// Borrows the exact whole current lease verified by the producer.
    pub(crate) fn lease(&self) -> &terrane_format::gc::GcLease {
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
    registration: terrane_format::gc::publication::evidence::PhysicalRegistration,
    configured_operator_uid: u32,
    pins: Vec<terrane_format::gc::publication::evidence::RequiredControlPin>,
}

impl GcControlOwner {
    /// Borrows the complete independently verified physical registration.
    pub(crate) fn registration(
        &self,
    ) -> &terrane_format::gc::publication::evidence::PhysicalRegistration {
        &self.registration
    }

    /// Returns this owner's independently configured operator UID.
    pub(crate) fn configured_operator_uid(&self) -> u32 {
        self.configured_operator_uid
    }

    /// Borrows exact checked record pins belonging to this registration.
    pub(crate) fn pins(&self) -> &[terrane_format::gc::publication::evidence::RequiredControlPin] {
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
    pub(crate) fn roots(&self) -> &terrane_format::gc::GcRoots {
        &self.roots
    }

    /// Returns raw BLAKE3-256 over the exact canonical root bytes.
    pub(crate) fn roots_digest(&self) -> terrane_format::gc::publication::RawDigest {
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

/// Retains fresh current-root verification under one actual selected observation.
///
/// This carrier is initialized only by the current qualification descendant.
/// Its untrusted fence bytes name the selected cycle checkpoint; independent
/// fresh traversal remains private operation evidence. It grants no physical
/// age, incarnation, Trash, retirement, restore or deletion authority.
pub(crate) struct CheckedCurrentCollection<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    session: &'operation crate::gc::runner::session::Session,
    fence: terrane_format::gc::retirement::CurrentCollectionFence,
    selected_roots: terrane_format::gc::GcRoots,
    selected_state: terrane_format::gc::GcState,
    #[cfg(all(test, feature = "tokio", unix))]
    current_roots: terrane_format::gc::GcRoots,
    #[cfg(all(test, feature = "tokio", unix))]
    late_roots: terrane_format::gc::GcRoots,
    #[cfg(all(test, feature = "tokio", unix))]
    current_state: terrane_format::gc::GcState,
    #[cfg(all(test, feature = "tokio", unix))]
    cycle_marks: std::collections::BTreeSet<[u8; 32]>,
    #[cfg(all(test, feature = "tokio", unix))]
    current_marks: std::collections::BTreeSet<[u8; 32]>,
    eligibility_marks: std::collections::BTreeSet<[u8; 32]>,
    sources: Option<native_collection_sources::CompletedSources>,
    reads: GcCheckpointReads,
    effects: GcCheckpointEffectContext,
}

impl<'operation, 'held> CheckedCurrentCollection<'operation, 'held> {
    /// Borrows the exact current namespace observation kept alive by the caller.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows the canonical fence data, without selecting or authorizing it.
    pub(crate) fn fence(&self) -> &terrane_format::gc::retirement::CurrentCollectionFence {
        &self.fence
    }

    /// Borrows the independently replay-verified selected cycle roots and state.
    pub(crate) fn selected_checkpoint(
        &self,
    ) -> (&terrane_format::gc::GcRoots, &terrane_format::gc::GcState) {
        (&self.selected_roots, &self.selected_state)
    }

    /// Borrows the conservative fresh roots, later dominated roots and completed frontier.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn fresh_traversal(
        &self,
    ) -> (
        &terrane_format::gc::GcRoots,
        &terrane_format::gc::GcRoots,
        &terrane_format::gc::GcState,
    ) {
        (&self.current_roots, &self.late_roots, &self.current_state)
    }

    /// Borrows cycle and fresh marks separately for inspection, never as caller proof.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn verified_marks(
        &self,
    ) -> (
        &std::collections::BTreeSet<[u8; 32]>,
        &std::collections::BTreeSet<[u8; 32]>,
    ) {
        (&self.cycle_marks, &self.current_marks)
    }

    /// Borrows independently completed source evidence only for retirement.
    pub(crate) fn sources(&self) -> Option<&native_collection_sources::CompletedSources> {
        self.sources.as_ref()
    }

    /// Tests every actual index member against the conservative verified union.
    ///
    /// A true value is a reachability predicate only. The retirement producer
    /// still must bind the executor-qualified native pair to this selected
    /// inventory, qualify its actual backend age and select the exact barrier.
    pub(crate) fn members_unmarked(&self, index: &crate::pack::PackIndexSnapshot) -> bool {
        index
            .entries()
            .iter()
            .all(|entry| !self.eligibility_marks.contains(entry.hash()))
    }

    /// Tests one witness member against independently verified cycle/current marks.
    pub(crate) fn member_unmarked(&self, hash: &[u8; 32]) -> bool {
        !self.eligibility_marks.contains(hash)
    }

    /// Borrows the protected selected Guard read for the worker's exact preimage.
    ///
    /// Consumers capture this record with ProtectedRecord and the actual backend
    /// operator; checkpoint metadata reads below use the separate Payload policy.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn guard_record(&self) -> &crate::bucket::publication::receipts::RecordRead {
        self.reads.guard()
    }

    /// Borrows exact checkpoint, selected log, catalog and traversal read preimages.
    pub(crate) fn reads(&self) -> &GcCheckpointReads {
        &self.reads
    }

    /// Borrows retained consumed controls and the genuine owned Session check.
    pub(crate) fn effect_context(&self) -> &GcCheckpointEffectContext {
        &self.effects
    }

    /// Revalidates the held whole selection and actual collector time before handoff.
    ///
    /// # Errors
    /// Refuses changed logical/control selection, cancellation, clock rollback
    /// or lease expiry. Each worker also retains exact preimages, actual control
    /// exclusions and the owned check; this async check cannot replace them.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.observed.revalidate().await?;
        self.session.recheck()?;
        self.effects.final_check.recheck()
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

/// Retains independently current metadata qualification without old cycle marks.
///
/// Only the actual fresh-current producer initializes this carrier. Its reads,
/// selected Guard and consumed controls remain bound to the live Session.
pub(crate) struct CheckedRestoreCurrent<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    session: &'operation crate::gc::runner::session::Session,
    inputs: Vec<crate::bucket::publication::receipts::RecordRead>,
    guard: crate::bucket::publication::receipts::RecordRead,
    effects: GcCheckpointEffectContext,
}

impl<'operation, 'held> CheckedRestoreCurrent<'operation, 'held> {
    /// Borrows the actual selected namespace held for this complete operation.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows every exact current ref, history, catalog and metadata observation.
    pub(crate) fn inputs(&self) -> &[crate::bucket::publication::receipts::RecordRead] {
        &self.inputs
    }

    /// Borrows the selected Guard separately from payload observations.
    pub(crate) fn guard_record(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.guard
    }

    /// Borrows actual live controls and the owned Session/maintenance-pair check.
    pub(crate) fn effect_context(&self) -> &GcCheckpointEffectContext {
        &self.effects
    }

    /// Rechecks the actual held selection, current lease, clock and controls.
    ///
    /// # Errors
    /// Refuses changed selected state or controls, lost lease, cancellation or clock discontinuity.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.effects.final_check.recheck()?;
        self.observed.revalidate().await?;
        self.session.recheck()?;
        self.effects.final_check.recheck()
    }
}
