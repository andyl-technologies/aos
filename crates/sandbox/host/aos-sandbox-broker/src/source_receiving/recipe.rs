//! Defines the existing fixed Source native recipe as comparison DATA.

use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

/// Names the existing fixed Source-domain directory.
pub const SOURCE_DOMAIN_DIRECTORY_V1: &str = "/var/lib/aos/sandbox/source-domains";
/// Names the existing fixed Source-domain journal.
pub const SOURCE_DOMAIN_JOURNAL_V1: &str = "source-domains-v1.journal";

/// Returns the unchanged Source-domain native bounds as DATA.
pub fn source_journal_limits_v1() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 256 * 1024 * 1024,
        maximum_key_bytes: 512,
        maximum_records_per_transaction: 64,
        maximum_transaction_bytes: 1024 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 2 * 1024 * 1024 * 1024,
        // Preserve the existing replay-member bound beside the V8 pending row.
        maximum_materialized_records: 262_144 + 1,
    }
}
