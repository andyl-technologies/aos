//! Owns typed domain-ledger DATA without protected writer or effect authority.
//!
//! [`transaction`] owns closed namespace records, Idempotency DATA, limits,
//! native encoding, and bounded preparation. [`capacity`] owns the canonical
//! legacy reservation schema and identities. [`capacity_family`] owns all seven
//! complete codecs, shared accounting and full-state selection. [`records`] owns schema-bound
//! envelopes, durable members, and borrowed semantic replay. None seals a
//! current cut, grants capacity, or manufactures a postcommit capability.
//! The generic Journal dependency supplies framing and checked mechanics;
//! physical custody and role-specific admission stay with their actual owners.
//! [`public_operation`] owns immutable public-operation metadata, authorization
//! scope DATA, the durable method/state registry and established resource projection.
//! `operation` owns both established Operation record versions and their native
//! Operation/Effect keys, without acquiring live admission or commit authority.
//! [`delete_batch`] owns the complete borrowed/owned Delete grammar and auxiliary
//! DATA; Native Journal admission and real COMMIT readback remain upper.
//! [`lifecycle_model`] owns typed resources, dependency edges, both established
//! postorder rules and their shared model errors; current graph admission stays upper.
//! [`ownership_gate`] owns the complete plan/state and V1 historical Gate codec;
//! native activation and current-publication validation stay with Domain.
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
//! [`create_storage_history`] checks initial V1 continuation envelopes only;
//! complete nested phase schemas and Native receiving/currentness stay upper.
//! [`resource_bank`] owns the complete passive account/claim codecs, inclusive
//! replay, co-issuance and terminal history. Native resource loans stay upper.
//! [`controller_history_relation`] owns complete atomic Delete metadata and
//! Controller capacity transfer/settlement comparisons, without Native admission.

pub mod capacity;
pub mod capacity_family;
pub mod controller_history_relation;
pub mod create_q04_history;
pub mod create_storage_history;
pub mod delete_batch;
pub mod effect_history;
pub mod floor_sidecar_geometry;
pub mod execution_observe_reservation;
pub mod execution_no_apply_floor;
pub mod lifecycle_model;
/// Borrows canonical lifecycle auxiliary framing without native authority.
pub mod lifecycle_auxiliary;
/// Retains exact ordinary Stop dispatch packets without effect authority.
pub mod stop_dispatch;
/// Retains fresh Stop cleanup completion comparisons without writer authority.
pub mod stop_completion;
pub mod operation;
pub mod ownership_gate;
pub mod project_admission_metadata;
pub mod project_source;
pub mod protected_names;
pub mod public_operation;
pub mod readonly;
pub mod records;
/// Shares canonical historical provisioning resources without Native authority.
pub mod provisioning_resources;
pub mod resource_bank;
pub mod runtime_authority_history;
pub mod root_project_history;
pub mod source_project_history;
pub mod source_policy_hold;
pub mod cache_policy_hold;
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

/// Contains passive Delete-purpose Root and Source exchange DATA.
pub mod delete_root;

/// Defines undeployed, purpose-specific Root provisioning exchange DATA.
pub mod provisioning_root;
