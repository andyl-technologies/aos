//! Preserves the still-upper Domain role errors at the native Policy boundary.
//!
//! Canonical publication/schema bodies live only in Policy. Existing Domain
//! callers still own their actual Journal causes; these cannot be erased or
//! moved into the lower native enum. Flat comparison/model classes map exactly.

use aos_sandbox_policy::PolicyModelError;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use crate::protected_domain_journal::ProtectedDomainJournalErrorV1;

/// Reports policy verification, framing, currentness, or durability failures.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCompilerJournalErrorV1 {
    /// Retains the independently owned Cache retirement failure.
    #[error(transparent)]
    Cache(#[from] aos_sandbox_cache::CacheResidencyProtectedJournalErrorV1),

    /// Retains the portable Q04 packet comparison failure.
    #[error(transparent)]
    Q04Data(aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1),

    /// Retains a distinct lower native owner's complete protected/schema cause.
    #[error(transparent)]
    Native(aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1),

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

impl From<aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1>
    for PolicyCompilerJournalErrorV1
{
    fn from(error: aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1) -> Self {
        use aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1 as NativeError;

        match error {
            #[cfg(not(target_os = "linux"))]
            NativeError::Journal(error) => {
                use aos_sandbox_policy::publication::ProtectedDomainJournalErrorV1 as DataError;

                match error {
                    DataError::NonCanonicalRecord => {
                        Self::Journal(ProtectedDomainJournalErrorV1::NonCanonicalRecord)
                    }
                    DataError::CompareAndSwapFailed => {
                        Self::Journal(ProtectedDomainJournalErrorV1::CompareAndSwapFailed)
                    }
                    DataError::StaleAuthority => {
                        Self::Journal(ProtectedDomainJournalErrorV1::StaleAuthority)
                    }
                    DataError::DivergentRecovery => {
                        Self::Journal(ProtectedDomainJournalErrorV1::DivergentRecovery)
                    }
                    DataError::Transaction(cause) => Self::from(
                        DomainLedgerDataError::Transaction(cause),
                    ),
                    DataError::UnsupportedProtectedOpen => {
                        Self::from(crate::JournalError::UnsupportedProtectedOpen)
                    }
                }
            }
            NativeError::UnauthenticatedCandidate => Self::UnauthenticatedCandidate,
            NativeError::NonCanonicalPublication => Self::NonCanonicalPublication,
            NativeError::Model(cause) => Self::Model(cause),
            cause => Self::Native(cause),
        }
    }
}

impl From<crate::JournalError> for PolicyCompilerJournalErrorV1 {
    fn from(error: crate::JournalError) -> Self {
        Self::Journal(ProtectedDomainJournalErrorV1::Journal(error))
    }
}

impl From<aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1>
    for PolicyCompilerJournalErrorV1
{
    fn from(error: aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1) -> Self {
        Self::from(aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1::from(error))
    }
}

impl From<aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1>
    for PolicyCompilerJournalErrorV1
{
    fn from(error: aos_sandbox_policy::q04_data::PolicyQ04DataErrorV1) -> Self {
        Self::from(aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1::from(error))
    }
}

impl From<aos_sandbox_cache::CacheJournalErrorV1> for PolicyCompilerJournalErrorV1 {
    fn from(error: aos_sandbox_cache::CacheJournalErrorV1) -> Self {
        Self::Cache(aos_sandbox_cache::CacheResidencyProtectedJournalErrorV1::from(error))
    }
}
