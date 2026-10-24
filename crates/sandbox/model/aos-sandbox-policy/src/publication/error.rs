//! Preserves portable schema classes and optional native owning causes.
//!
//! Native-enabled Linux builds retain the same Journal cause identity and
//! variant order. Other builds keep transaction failures typed without linking
//! a native journal, constructing a role or losing the original DATA class.

use crate::PolicyModelError;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};
#[cfg(all(feature = "native-journal", target_os = "linux"))]
use crate::native::PolicyNativeJournalErrorV1 as JournalError;

/// Reports malformed domain records, stale plans, and journal failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedDomainJournalErrorV1 {
    /// A key, envelope, revision, predecessor, or payload is noncanonical.
    #[error("protected domain journal record is noncanonical")]
    NonCanonicalRecord,
    /// A successor does not exactly extend the currently materialized value.
    #[error("protected domain journal compare-and-swap failed")]
    CompareAndSwapFailed,
    /// A plan or capability was issued by another adapter instance or snapshot.
    #[error("protected domain journal authority is stale or substituted")]
    StaleAuthority,
    /// Durable recovery found a mixture of predecessor and successor values.
    #[error("protected domain journal recovery found divergent state")]
    DivergentRecovery,
    /// The underlying journal rejected or could not durably perform an action.
    #[error(transparent)]
    #[cfg(all(feature = "native-journal", target_os = "linux"))]
    Journal(#[from] JournalError),
    /// The platform has no supported protected native opener.
    #[cfg(not(all(feature = "native-journal", target_os = "linux")))]
    #[error("protected journal opening requires supported, permitted openat2 resolution")]
    UnsupportedProtectedOpen,
    /// Retains the exact portable transaction class without native custody.
    #[cfg(not(all(feature = "native-journal", target_os = "linux")))]
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
}

impl From<DomainLedgerDataError> for ProtectedDomainJournalErrorV1 {
    fn from(error: DomainLedgerDataError) -> Self {
        match error {
            DomainLedgerDataError::NonCanonicalRecord => Self::NonCanonicalRecord,
            DomainLedgerDataError::CompareAndSwapFailed => Self::CompareAndSwapFailed,
            #[cfg(all(feature = "native-journal", target_os = "linux"))]
            DomainLedgerDataError::Transaction(error) => Self::Journal(JournalError::from(
                aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from(
                    error,
                ),
            )),
            #[cfg(not(all(feature = "native-journal", target_os = "linux")))]
            DomainLedgerDataError::Transaction(error) => Self::Transaction(error),
        }
    }
}

#[cfg(all(feature = "native-journal", target_os = "linux"))]
impl From<JournalTransactionDataError> for ProtectedDomainJournalErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        <Self as From<JournalError>>::from(JournalError::from(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from(error),
        ))
    }
}


/// Reports policy verification, framing, currentness, or durability failures.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCompilerJournalErrorV1 {
    /// Retains a canonical Q04 comparison error outside the old binding classes.
    #[error(transparent)]
    Q04Data(crate::q04_data::PolicyQ04DataErrorV1),
    /// A verifier rejected the exact candidate and prerequisite tuple.
    #[error("compiled policy candidate lacks authenticated publication authority")]
    UnauthenticatedCandidate,
    /// A digest, identity, generation, descriptor, or current head is invalid.
    #[error("compiled policy publication is noncanonical")]
    NonCanonicalPublication,
    /// Canonical compiler serialization failed.
    #[error(transparent)]
    Model(#[from] PolicyModelError),
    /// Protected currentness, CAS, replay, or durability failed.
    #[error(transparent)]
    Journal(#[from] ProtectedDomainJournalErrorV1),
}

impl From<DomainLedgerDataError> for PolicyCompilerJournalErrorV1 {
    fn from(error: DomainLedgerDataError) -> Self {
        Self::from(ProtectedDomainJournalErrorV1::from(error))
    }
}


impl From<crate::q04_data::PolicyQ04DataErrorV1> for PolicyCompilerJournalErrorV1 {
    fn from(error: crate::q04_data::PolicyQ04DataErrorV1) -> Self {
        match error {
            crate::q04_data::PolicyQ04DataErrorV1::UnauthenticatedCandidate => {
                Self::UnauthenticatedCandidate
            }
            crate::q04_data::PolicyQ04DataErrorV1::Transaction(error) => {
                Self::from(DomainLedgerDataError::Transaction(error))
            }
            other => Self::Q04Data(other),
        }
    }
}


impl From<aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1> for PolicyCompilerJournalErrorV1 {
    fn from(error: aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1) -> Self {
        match error {
            aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1::UnauthenticatedCandidate => Self::UnauthenticatedCandidate,
        }
    }
}
