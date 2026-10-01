//! Encodes untrusted D-79 publication and portable-projection records.
//!
//! Canonical decoding establishes format consistency only. Physical bindings,
//! administrative freshness, referenced evidence, and selected-chain authority
//! require independent backend checks; none is created by these public values.
//! CAPABILITIES and catalog payloads remain opaque: presence checks do not
//! certify profiles, complete inventory, activation markers, or payload closure.
//! Publication factories must independently validate these exact bytes using
//! the corresponding canonical payload codecs before authority or admission.
//!
//! ```text
//! PublicationCurrent = {0: 1, 1: revision, 2: raw_digest32}
//! PortableCurrent = {0: 1, 1: snapshot_key, 2: raw_digest32}
//! ```

mod cbor;
pub mod evidence;
mod validation;

pub use super::retirement::{PermanentBurnOwner, PermanentOwnerSelection};

use crate::refs::RefRecord;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

/// Carries an untrusted raw BLAKE3 digest, without a content identity domain.
pub type RawDigest = [u8; 32];

/// Reports a publication encoding or internal consistency failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationError {
    /// The deterministic CBOR subset was violated.
    Cbor(crate::cbor::Error),
    /// An embedded whole ref record was rejected.
    Ref(crate::refs::RecordError),
    /// A field has the wrong registered shape.
    Schema,
    /// Fields contradict one another or a represented predecessor.
    Contradiction,
    /// A revision or sequence cannot advance without overflow.
    Exhausted,
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(formatter),
            Self::Ref(error) => error.fmt(formatter),
            Self::Schema => formatter.write_str("publication record violates its schema"),
            Self::Contradiction => formatter.write_str("publication fields contradict each other"),
            Self::Exhausted => formatter.write_str("publication revision or sequence exhausted"),
        }
    }
}

impl core::error::Error for PublicationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Ref(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::cbor::Error> for PublicationError {
    fn from(error: crate::cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<crate::refs::RecordError> for PublicationError {
    fn from(error: crate::refs::RecordError) -> Self {
        Self::Ref(error)
    }
}

/// Names the provider in a remote backend's untrusted binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteProvider {
    /// An S3-compatible provider.
    S3,
    /// A GCS provider.
    Gcs,
}

/// Describes claimed physical binding data without authenticating it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendBinding {
    /// A normalized local root and claimed opened identities.
    Local {
        /// Normalized absolute filesystem bytes, without NUL.
        root: Vec<u8>,
        /// Claimed root device identifier.
        root_device: u64,
        /// Claimed root inode identifier.
        root_inode: u64,
        /// Claimed stable coordination device identifier.
        coordination_device: u64,
        /// Claimed stable coordination inode identifier.
        coordination_inode: u64,
    },
    /// A remote resource and protected coordination namespace.
    Remote {
        /// Configured provider.
        provider: RemoteProvider,
        /// Exact endpoint text.
        endpoint: String,
        /// Exact bucket resource text.
        bucket: String,
        /// Exact resource prefix bytes.
        prefix: Vec<u8>,
        /// Claimed protected resource registration nonce.
        resource_nonce: [u8; 32],
        /// Exact protected coordination key bytes.
        coordination_key: Vec<u8>,
        /// Claimed protected coordination registration nonce.
        coordination_nonce: [u8; 32],
    },
}

/// Describes the recorded activation phase, without granting admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    /// Activation is incomplete and cannot authorize a fresh registration.
    Pending,
    /// Activation records the exact genesis digest.
    Active,
}

/// Records an immutable binding and its activation progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRegistration {
    /// Claimed actual backend binding.
    pub binding: BackendBinding,
    /// Recorded activation phase.
    pub activation: Activation,
    /// Exact genesis slot digest; required in Active, optional in Pending.
    pub genesis: Option<RawDigest>,
}

/// Distinguishes never-selected, exact retained, and unknown branch history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommittedSelection {
    /// No head has ever been selected.
    Never,
    /// Exact whole last-selected head, including its candidate selector.
    Selected(Box<RefRecord>),
    /// Historical selection predates the protocol and remains unknown.
    Unknown,
}

/// Associates a complete branch name with its untrusted retained selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    /// Full branch name in heads, jobs, conflicts, or derived.
    pub name: String,
    /// Exact selection or explicit historical uncertainty.
    pub selection: CommittedSelection,
}

/// Holds portable branch history and its nonauthoritative origin stamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedHistory {
    /// Complete branch rows sorted uniquely by unsigned name bytes.
    pub branches: Vec<HistoryEntry>,
    /// Claimed source backend origin, never private authority.
    pub origin: BackendBinding,
}

/// Binds an exact immutable portable snapshot key to its raw digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableCurrent {
    /// Registered snapshot key, including revision and operation nonce.
    pub key: String,
    /// Raw digest of the exact canonical snapshot bytes.
    pub digest: RawDigest,
}

/// Carries a logical projection value or explicit absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEntry {
    /// Registered logical payload key.
    pub key: String,
    /// Whole selected bytes, or explicit absence.
    pub value: Option<Vec<u8>>,
}

/// Records a complete portable checkpoint or an exact predecessor delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableSnapshot {
    /// Selected source publication revision.
    pub revision: u64,
    /// Nonauthoritative backend origin stamp.
    pub origin: BackendBinding,
    /// Complete checkpoint rows or predecessor delta, sorted uniquely.
    pub projection: Vec<ProjectionEntry>,
    /// Exact predecessor snapshot; absence identifies a full checkpoint.
    pub predecessor: Option<PortableCurrent>,
}

/// Associates a current source ref with an untrusted checked-lineage digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLineage {
    /// Complete source ref name.
    pub name: String,
    /// Raw digest of separately checked lineage bytes.
    pub digest: RawDigest,
}

/// Describes selected publication state without proving chain selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationState {
    /// Transaction revision, beginning at zero.
    pub revision: u64,
    /// Monotone qualified availability-loss generation.
    pub loss_generation: u64,
    /// Current source rows sorted uniquely by unsigned name bytes.
    pub sources: Vec<SourceLineage>,
    /// Claimed unchanged physical backend binding.
    pub binding: BackendBinding,
    /// Complete branch history, including absent names.
    pub branches: Vec<HistoryEntry>,
    /// Selected Guard snapshot digest, or explicit pre-Guard absence.
    pub guard: Option<RawDigest>,
    /// Recoverable permanent owners sorted uniquely by pack ID.
    /// Absence is legacy unknown, while an empty array is explicitly complete.
    pub burn_owners: Option<Vec<PermanentBurnOwner>>,
}

/// Holds the optional nonauthoritative selected-commit cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationCurrent {
    /// Cached selected revision.
    pub revision: u64,
    /// Exact selected commit slot digest.
    pub digest: RawDigest,
}

/// Binds a create-once publication slot to its exact transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationCommit {
    /// Slot revision, beginning at zero.
    pub revision: u64,
    /// Previous slot digest, absent only at genesis zero.
    pub predecessor: Option<RawDigest>,
    /// Registered immutable transaction key with a secure nonce spelling.
    pub transaction_key: String,
    /// Raw digest of exact canonical transaction bytes.
    pub transaction_digest: RawDigest,
}

/// Carries a removed pack's separately checked detached-index witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovedPack {
    /// Physical pack identifier.
    pub pack: [u8; 16],
    /// Detached index identity.
    pub index: RawDigest,
}

/// Describes untrusted publication proof references, never private evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationProof {
    /// Raw mutation with no lineage creation or Guard transition.
    Raw,
    /// Separately privately checked candidate lineage.
    Candidate(RawDigest),
    /// Separately qualified GC preservation and exact witnesses.
    Collection {
        /// Registered exact current Fence key.
        fence_key: String,
        /// Raw digest of Fence bytes.
        fence_digest: RawDigest,
        /// Exact removed pack/index witnesses in their recorded order.
        removed: Vec<RemovedPack>,
        /// Carried source/prior-lineage pairs, sorted uniquely by name.
        carried: Vec<SourceLineage>,
    },
    /// Separately privately checked permanent physical retirement (D-82 case 3).
    PermanentRetirement {
        /// Exact canonical immutable authorization, never private permission.
        authorization: Vec<u8>,
        /// Carried source/prior-lineage pairs, sorted uniquely by name.
        carried: Vec<SourceLineage>,
    },
    /// Separately privately checked Guard installation transition.
    Guard(RawDigest),
}

/// Carries a whole logical compare-and-swap expectation and replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalChange {
    /// Registered logical key, sorted uniquely in a transaction.
    pub key: String,
    /// Whole previous bytes, or explicit prior absence.
    pub expected: Option<Vec<u8>>,
    /// Whole replacement bytes, or explicit new absence.
    pub new: Option<Vec<u8>>,
}

/// Binds an exact predecessor slot revision to its raw digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredecessorSlot {
    /// Exact predecessor revision.
    pub revision: u64,
    /// Raw digest of that immutable slot.
    pub digest: RawDigest,
}

/// Records a proposed selected transaction with no publication capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationTransaction {
    /// Claimed secure operation nonce, associated with its immutable key.
    pub nonce: [u8; 32],
    /// Exact predecessor state; absent only at genesis.
    pub old: Option<PublicationState>,
    /// Exact proposed next state.
    pub new: PublicationState,
    /// Sorted unique whole logical changes.
    pub changes: Vec<LogicalChange>,
    /// Untrusted proof references requiring independent private checks.
    pub proof: PublicationProof,
    /// Exact predecessor slot; absent only at genesis.
    pub predecessor: Option<PredecessorSlot>,
    /// Exact staged immutable portable snapshot.
    pub snapshot: PortableCurrent,
}
