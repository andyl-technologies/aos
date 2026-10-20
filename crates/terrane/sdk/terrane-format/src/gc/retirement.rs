//! Owns pure permanent-deletion and copied-placement retirement records.
//!
//! Canonical records represent untrusted data. Physical ownership, current
//! placement authority and completed waits require independent backend checks.
//!
//! D-82 records are disjoint from ordinary local D-78-v1 records (GC-15,
//! GC-29). Permanent owners survive completed and empty reconciliation passes.
//!
//! ```text
//! PermanentDeleteOperation = [2, revision, phase, authorization, owner, pass]
//! CopiedRetirementPreparation = [2, revision, 3 / 4, plan]
//! ```

mod cbor;
pub(crate) mod publication;
mod validation;

#[cfg(test)]
mod tests;

use super::publication::{BackendBinding, PublicationError, PublicationState, RawDigest};
use super::{GcError, GcLease};
use crate::bucket::{RecordError, Tombstone};
use alloc::{string::String, vec::Vec};
use core::fmt;

/// Bounds a single retirement record before allocation (CRATE-4).
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Bounds the observation delta in one event without limiting future events.
pub const MAX_OBSERVATIONS: usize = 4096;

/// Reports a format or represented retirement relationship failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetirementError {
    /// The deterministic CBOR representation is invalid.
    Cbor(crate::cbor::Error),
    /// A publication value is malformed.
    Publication(PublicationError),
    /// A consumed original-control pin is malformed.
    Evidence(super::publication::evidence::EvidenceError),
    /// A whole lease value is malformed.
    Lease(GcError),
    /// A canonical Tombstone is malformed.
    Bucket(RecordError),
    /// A detached-index witness is malformed.
    Index(crate::pack_format::Error),
    /// A field violates the disjoint v2 schema.
    Schema,
    /// Represented fields or transitions disagree.
    Contradiction,
    /// Checked duration, revision or pass arithmetic overflows.
    Exhausted,
}

impl fmt::Display for RetirementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
            Self::Evidence(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::Bucket(error) => error.fmt(formatter),
            Self::Index(error) => error.fmt(formatter),
            Self::Schema => formatter.write_str("invalid permanent retirement record"),
            Self::Contradiction => formatter.write_str("retirement fields contradict each other"),
            Self::Exhausted => formatter.write_str("retirement arithmetic exhausted"),
        }
    }
}

impl core::error::Error for RetirementError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::Evidence(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Bucket(error) => Some(error),
            Self::Index(error) => Some(error),
            _ => None,
        }
    }
}

macro_rules! from_error {
    ($($source:ty => $variant:ident),+ $(,)?) => {$(
        impl From<$source> for RetirementError {
            fn from(error: $source) -> Self { Self::$variant(error) }
        }
    )+};
}

from_error!(crate::cbor::Error => Cbor, PublicationError => Publication,
    super::publication::evidence::EvidenceError => Evidence,
    GcError => Lease, RecordError => Bucket, crate::pack_format::Error => Index);

/// Names an exact immutable record without authenticating its selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPointer {
    /// Registered relative key.
    pub key: String,
    /// Raw BLAKE3 of exact canonical bytes.
    pub digest: RawDigest,
}

/// Names a selected publication slot without proving chain selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipSlot {
    /// Publication revision of the slot.
    pub revision: u64,
    /// Raw digest of the exact slot bytes.
    pub digest: RawDigest,
}

/// Binds a pack to its original collection cycle and fencing epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exclusion {
    /// Permanently retired physical pack identifier.
    pub pack: [u8; 16],
    /// Canonical trash cycle.
    pub cycle: u64,
    /// Original exclusion epoch.
    pub epoch: u64,
}

/// Carries a remote initial artifact's exact key, identity and byte size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteArtifact {
    /// Exact registered logical key.
    pub key: String,
    /// Pack/index domain identity or raw canonical trash digest.
    pub digest: RawDigest,
    /// Exact immutable byte size.
    pub size: u64,
}

/// Carries a claimed committed local NEW barrier journal incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBarrierArtifact {
    /// Exact newly selected destination trash key.
    pub key: String,
    /// Claimed fresh creation-journal nonce.
    pub nonce: [u8; 32],
    /// Exact canonical Tombstone bytes in the kind-2 binding.
    pub tombstone: Vec<u8>,
    /// Opaque claimed regular-file identity, one to 128 bytes.
    pub file_identity: Vec<u8>,
}

/// Distinguishes actual remote and local destination barrier representations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BarrierArtifact {
    /// Exact remote conditional-installation association.
    Remote(RemoteArtifact),
    /// Exact local committed journal association.
    Local(LocalBarrierArtifact),
}

/// Describes ordinary remote first ownership with all three initial artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSweepDeleteAuthorization {
    /// Secure operation nonce matching the operation key.
    pub nonce: [u8; 32],
    /// Claimed actual remote resource and coordination binding.
    pub backend: BackendBinding,
    /// Exact original physical exclusion.
    pub exclusion: Exclusion,
    /// Whole original authorizing lease.
    pub lease: GcLease,
    /// Whole-second deletion window D.
    pub deletion_seconds: u64,
    /// Pack, detached index and original trash, in that order.
    pub artifacts: [RemoteArtifact; 3],
    /// Bounded exact detached-index witness.
    pub witness: Vec<u8>,
    /// Exact canonical original Tombstone bytes.
    pub tombstone: Vec<u8>,
    /// Claimed completed D lower bound in nanoseconds.
    pub deletion_elapsed_nanos: u64,
    /// Exact current collection Fence reference.
    pub fence: RecordPointer,
    /// Whole-second grace window G.
    pub grace_seconds: u64,
    /// Claimed completed G lower bound in nanoseconds.
    pub grace_elapsed_nanos: u64,
}

/// Describes a separate selected copied-placement destination preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopiedRetirementPlan {
    /// Secure operation nonce matching the preparation key.
    pub nonce: [u8; 32],
    /// Actual claimed destination backend, never the source owner.
    pub backend: BackendBinding,
    /// NEW destination exclusion and barrier incarnation.
    pub exclusion: Exclusion,
    /// Whole preparing lease.
    pub lease: GcLease,
    /// Earlier destination fresh-copy genesis slot.
    pub genesis: OwnershipSlot,
    /// Current destination CopiedPlacementFence reference.
    pub fence: RecordPointer,
    /// Canonical NEW Tombstone with zero removed entries.
    pub tombstone: Vec<u8>,
    /// Whole-second grace window G.
    pub grace_seconds: u64,
    /// Whole-second deletion window D.
    pub deletion_seconds: u64,
}

/// Describes preparation progress without granting ownership or elapsed age.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationPhase {
    /// Selected preparation before creating its NEW destination barrier.
    Preparing,
    /// Failed or cancelled preparation retaining the copied burn.
    Abandoned,
}

/// Carries one immutable copied plan and checked preparation revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopiedRetirementPreparation {
    /// Checked operation revision, initially zero.
    pub revision: u64,
    /// Preparation progress, separate from owner phases.
    pub phase: PreparationPhase,
    /// Immutable destination plan.
    pub plan: CopiedRetirementPlan,
}

/// Describes final copied retirement without inventing old artifact witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopiedRetirementAuthorization {
    /// Secure operation nonce matching the preparation and operation key.
    pub nonce: [u8; 32],
    /// Claimed actual destination backend.
    pub backend: BackendBinding,
    /// Exact newly selected destination barrier incarnation.
    pub exclusion: Exclusion,
    /// Whole CURRENT final authorizing lease.
    pub lease: GcLease,
    /// Whole-second deletion window D.
    pub deletion_seconds: u64,
    /// NEW barrier; pack/index positions are encoded as explicit null.
    pub barrier: BarrierArtifact,
    /// Exact canonical NEW Tombstone bytes.
    pub tombstone: Vec<u8>,
    /// Claimed FULL barrier D lower bound in nanoseconds.
    pub deletion_elapsed_nanos: u64,
    /// Current final CopiedPlacementFence reference.
    pub fence: RecordPointer,
    /// Whole-second grace window G.
    pub grace_seconds: u64,
    /// Claimed FULL barrier G lower bound in nanoseconds.
    pub grace_elapsed_nanos: u64,
    /// Earlier destination fresh-copy genesis slot.
    pub genesis: OwnershipSlot,
    /// Earlier selected preparation slot.
    pub preparation: OwnershipSlot,
    /// Optional independently qualified current lineage collection fence.
    pub lineage_fence: Option<RecordPointer>,
}

/// Preserves the disjoint ordinary sweep and copied destination schemas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PermanentDeleteAuthorization {
    /// Ordinary remote sweep with retained detached-index witness.
    Sweep(RemoteSweepDeleteAuthorization),
    /// Copied placement retirement observing only a NEW destination barrier.
    Copied(CopiedRetirementAuthorization),
}

/// Describes permanent progress without a terminal Done phase (GC-15).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    /// Ownership proposal with null future owner/pass pointers.
    Proposed,
    /// Permanent selected owner with exact owner and pass pointers.
    Owned,
    /// Unselected proposal cancelled before ownership.
    Cancelled,
}

/// Carries an immutable authorization and recoverable permanent progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermanentDeleteOperation {
    /// Checked operation revision.
    pub revision: u64,
    /// Proposed, Owned or Cancelled; ownership never completes.
    pub phase: OperationPhase,
    /// Immutable exact initial authorization.
    pub authorization: PermanentDeleteAuthorization,
    /// Exact selecting slot, present only while Owned.
    pub owner: Option<OwnershipSlot>,
    /// Exact selected pass, present only while Owned.
    pub pass: Option<RecordPointer>,
}

/// Distinguishes visibility copied from permanent independently selected ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PermanentOwnerSelection {
    /// Copied burn visibility with pending destination retirement duty.
    CopiedVisibility,
    /// Exact immutable selected owner, without its own selecting slot digest.
    Permanent(RecordPointer),
}

/// Associates one burned pack with its recoverable owner selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermanentBurnOwner {
    /// Permanently retired pack identifier.
    pub pack: [u8; 16],
    /// Visibility-only or exact permanent owner selection.
    pub selection: PermanentOwnerSelection,
}

/// Distinguishes unversioned instances from opaque retained backend handles.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedInstance {
    /// Actual unversioned object or local regular file.
    Unversioned,
    /// Actual retained object version.
    Version(Vec<u8>),
    /// Actual retained deletion marker.
    Marker(Vec<u8>),
}

/// Names a target kind in unsigned fieldwise key-family order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedArtifact {
    /// The exact pack key.
    Pack,
    /// The exact detached-index key.
    Index,
    /// A canonical trash key at its ACTUAL observed cycle.
    Trash(u64),
}

/// Describes an observed request state without granting backend handle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationState {
    /// Selected observation planned for a separately authorized request.
    Planned,
    /// Qualified absence at this observation, never permanent future absence.
    ConfirmedAbsent,
    /// Request outcome or continuity remains uncertain.
    Indeterminate,
    /// Current permission or backend policy defers this duty.
    Deferred,
}

/// Carries one bounded exact target observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestObservation {
    /// Pack, index, or actual canonical trash cycle.
    pub artifact: ObservedArtifact,
    /// Actual instance discriminant and opaque handle.
    pub instance: ObservedInstance,
    /// Current observed request state.
    pub state: ObservationState,
}

/// Describes progress through one key-family scope at an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassCoverage {
    /// Traversal completeness is unknown.
    Unknown,
    /// Candidate traversal completed, without universal absence evidence.
    CandidateTraversalCompleted,
    /// Independently qualified all-version absence at this observation only.
    QualifiedAllVersionAbsenceAtObservation,
}

/// Describes a pass phase while permanent ownership continues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassPhase {
    /// Partial candidate traversal or unresolved Planned work remains.
    Open,
    /// Candidate traversal completed; future passes remain mandatory.
    PassCompleted,
}

/// Carries a bounded permanent reconciliation event (GC-7, GC-15, GC-23).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermanentDeletePass {
    /// Raw digest of the exact immutable initial authorization.
    pub authorization_digest: RawDigest,
    /// Original owner selection slot, never replaced on takeover.
    pub owner: OwnershipSlot,
    /// Next operation revision matching the immutable event key suffix.
    pub revision: u64,
    /// Checked pass number, initially zero.
    pub pass: u64,
    /// Checked event number within this pass, initially zero.
    pub event: u64,
    /// Exact CURRENT predecessor publication slot.
    pub predecessor: OwnershipSlot,
    /// Whole current predecessor state with its OLD pass pointer.
    pub state: PublicationState,
    /// Whole current progress lease, independent of the original owner lease.
    pub lease: GcLease,
    /// Claimed unchanged actual backend binding.
    pub backend: BackendBinding,
    /// Open or completed candidate traversal; neither ends ownership.
    pub phase: PassPhase,
    /// Bounded observation DELTA in unsigned fieldwise unique order.
    pub observations: Vec<RequestObservation>,
    /// Pack, index, and complete trash FAMILY coverage, in that order.
    pub coverage: [PassCoverage; 3],
    /// Fresh event nonce matching the event proposal key and transaction.
    pub nonce: [u8; 32],
    /// Exact current placement fence, REQUIRED for a copied local backend.
    pub placement_fence: Option<RecordPointer>,
}

/// Carries a complete claimed current ref row in a collection fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceRef {
    /// Complete inventoried ref name.
    pub name: String,
    /// Whole canonical current ref bytes or explicit absence.
    pub current: Option<Vec<u8>>,
    /// Retained branch selection, including absent-name history.
    pub selection: super::publication::CommittedSelection,
    /// Whole selected retained log, required for a known selected branch.
    pub log: Option<crate::refs::RefLogRecord>,
}

/// Describes current collection evidence without authenticating root closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentCollectionFence {
    /// Exact canonical selected CAPABILITIES bytes.
    pub capabilities: Vec<u8>,
    /// Exact selected MANIFEST or authoritatively fresh-empty absence claim.
    pub manifest: Option<Vec<u8>>,
    /// Complete claimed inventory rows sorted uniquely by unsigned name bytes.
    pub refs: Vec<FenceRef>,
    /// Raw digest of the selected current Guard snapshot.
    pub guard: RawDigest,
    /// Whole selected predecessor publication state.
    pub state: PublicationState,
    /// Exact selected current root snapshot key and raw digest.
    pub roots: RecordPointer,
    /// Exact selected current mark/placement state key and raw digest.
    pub marks: RecordPointer,
    /// Claimed unchanged actual backend binding.
    pub backend: BackendBinding,
    /// Exact claimed consumed control pins in registered unique fieldwise order.
    pub controls: Vec<super::publication::evidence::RequiredControlPin>,
}

/// Describes copied destination physical placement closure, never foreign authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopiedPlacementFence {
    /// Exact canonical selected destination CAPABILITIES bytes.
    pub capabilities: Vec<u8>,
    /// Exact canonical selected destination MANIFEST bytes.
    pub manifest: Vec<u8>,
    /// Complete claimed current ref and retained history rows.
    pub refs: Vec<FenceRef>,
    /// Actual claimed selected destination Guard digest.
    pub guard: RawDigest,
    /// Whole selected predecessor destination state.
    pub state: PublicationState,
    /// Exact current destination root snapshot pointer.
    pub roots: RecordPointer,
    /// Exact current destination placement traversal pointer.
    pub marks: RecordPointer,
    /// Actual claimed independent destination binding.
    pub backend: BackendBinding,
    /// Exact claimed consumed current destination control pins.
    pub controls: Vec<super::publication::evidence::RequiredControlPin>,
    /// Actual claimed independent destination fresh-copy genesis.
    pub genesis: OwnershipSlot,
    /// Exact selected portable destination projection pointer.
    pub projection: RecordPointer,
}
