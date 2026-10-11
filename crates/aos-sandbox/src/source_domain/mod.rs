//! Owns protected Native Source journal custody and cross-domain transactions.
//!
//! The private fixed-writer child retains the live Source writer, paid opening
//! originals and Q04 loans used by Controller and Runtime callers. The private
//! cross-domain child retains the dormant four-domain join and recovery engine.
//! Shared fixed names, limits and the replay-member bound belong to this owner;
//! lifecycle schemas and accepted lifecycle identities remain Lifecycle-owned.

use crate::journal::JournalLimits;

mod cross_domain;
mod fixed_writer;

pub use cross_domain::{
    CrossDomainSemanticTupleV1,
    CrossDomainJournalSuccessorV1,
    CrossDomainPostcommitRecordV1,
    CrossDomainJournalSnapshotV1,
    PreparedCrossDomainJournalTransactionV1,
    CrossDomainJournalOutcomeUnknownV1,
    CrossDomainPostcommitCapabilityV1,
    ValidatedCrossDomainPostcommitV1,
    AppliedCrossDomainJournalTransactionV1,
    CrossDomainJournalCommitOutcomeV1,
    CrossDomainJournalRecoveryV1,
    ReplayedCrossDomainPostcommitV1,
    ProtectedCrossDomainJournalV1,
};
pub use fixed_writer::ProtectedSourceDomainJournalOwnerV1;
#[cfg(target_os = "linux")]
pub use fixed_writer::ControllerSourceJournalConstructionV1;
#[cfg(target_os = "linux")]
pub(crate) use fixed_writer::OriginalQ04SourceOwnerCutV1;

const MAXIMUM_CROSS_DOMAIN_REPLAY_MEMBERS: usize = 262_144;
pub(crate) const PROTECTED_SOURCE_DOMAIN_ROOT: &str = "/var/lib/aos/sandbox/source-domains";
pub(crate) const PROTECTED_SOURCE_DOMAIN_JOURNAL: &str = "source-domains-v1.journal";

pub(crate) fn source_domain_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 256 * 1024 * 1024,
        maximum_key_bytes: 512,
        maximum_records_per_transaction: 64,
        maximum_transaction_bytes: 1024 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 2 * 1024 * 1024 * 1024,
        // The V8 pending marker must not reduce the existing replay-member bound.
        maximum_materialized_records: MAXIMUM_CROSS_DOMAIN_REPLAY_MEMBERS + 1,
    }
}
