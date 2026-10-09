//! Owns typed domain-ledger DATA without protected writer or effect authority.
//!
//! [`transaction`] owns closed namespace records, Idempotency DATA, limits,
//! native encoding, and bounded preparation. [`capacity`] owns the canonical
//! legacy reservation schema and identities. [`records`] owns schema-bound
//! envelopes, durable members, and borrowed semantic replay. None seals a
//! current cut, grants capacity, or manufactures a postcommit capability.
//! The generic Journal dependency supplies framing and checked mechanics;
//! physical custody and role-specific admission stay with their actual owners.
//! [`public_operation`] owns immutable public-operation metadata, authorization
//! scope DATA, the durable method/state registry and established resource projection.
//! `operation` owns both established Operation record versions and their native
//! Operation/Effect keys, without acquiring live admission or commit authority.
//! [`protected_names`] owns historical physical-name pairs; [`source_project_history`]
//! owns all five canonical Source rows, their terminal tag and complete historical
//! join. Native currentness, signing, protected proofs and writer loans stay upper.
//! [`root_project_history`] owns Root's cancellation, outcome and terminal-floor
//! rows. [`project_source`] separately owns immutable accepted-Create source hash
//! inputs and their commitment, independently of Source's admission history.
//! [`project_admission_metadata`] owns the complete Controller historical row,
//! while native admission and full projection grammar stay with Domain's owners.
//! [`execution_observe_reservation`] owns the complete canonical Observe binding;
//! [`create_q04_history`] owns the closed Q04 historical record family and its
//! shared private codec. Native signing, custody and continuation stay upper.

pub mod capacity;
pub mod create_q04_history;
pub mod execution_observe_reservation;
pub mod operation;
pub mod project_admission_metadata;
pub mod project_source;
pub mod protected_names;
pub mod public_operation;
pub mod records;
pub mod root_project_history;
pub mod source_project_history;
pub mod transaction;

use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::record::RecordError;

/// Reports malformed canonical protected-history DATA without native causes.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedHistoryDataErrorV1 {
    /// A historical fixed record, physical-name claim or row join is malformed.
    #[error("protected history DATA is malformed")]
    Malformed,
}

/// Reports malformed or unrepresentable typed transaction DATA.
#[derive(Debug, thiserror::Error)]
pub enum JournalTransactionDataError {
    /// The stable identity is zero or the record set is empty.
    #[error("transaction identity must be nonzero and records must be nonempty")]
    InvalidTransaction,
    /// The client key is empty or exceeds 128 bytes.
    #[error("idempotency key must contain between 1 and 128 bytes")]
    InvalidIdempotencyKey,
    /// Transaction framing is malformed.
    #[error("malformed journal transaction: {0}")]
    MalformedTransaction(&'static str),
    /// A closed record schema is malformed.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A configured size or count bound was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A logical namespace/key occurs more than once.
    #[error("transaction contains duplicate logical record keys")]
    DuplicateRecordKey,
    /// Aggregate encoded bytes overflow their representation.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// Generic framing retained its original cause.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Generic record decoding retained its original cause.
    #[error(transparent)]
    Record(#[from] RecordError),
}

impl From<aos_sandbox_core::journal_namespace::UnknownRecordNamespace>
    for JournalTransactionDataError
{
    fn from(_: aos_sandbox_core::journal_namespace::UnknownRecordNamespace) -> Self {
        Self::MalformedRecord("unknown record namespace")
    }
}

/// Reports canonical domain DATA or exact successor-shape failures.
#[derive(Debug, thiserror::Error)]
pub enum DomainLedgerDataError {
    /// A key, envelope, revision, predecessor, or payload is noncanonical.
    #[error("protected domain journal record is noncanonical")]
    NonCanonicalRecord,
    /// A successor does not exactly extend the supplied predecessor DATA.
    #[error("protected domain journal compare-and-swap failed")]
    CompareAndSwapFailed,
    /// Typed transaction DATA validation failed.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
}
