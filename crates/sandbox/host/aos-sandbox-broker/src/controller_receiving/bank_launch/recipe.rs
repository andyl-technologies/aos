//! Defines the existing fixed Controller writer recipe as comparison DATA.
//!
//! The actual paired startup constructor alone consumes this recipe. A path or
//! limits value cannot establish native custody, bank enrollment or a role loan.

use std::path::Path;

use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

pub(super) const DIRECTORY: &str = "/var/lib/aos/sandboxd";
pub(super) const NAME: &str = "controller.journal";

pub(super) fn directory() -> &'static Path {
    Path::new(DIRECTORY)
}

/// Returns the existing production Controller native limits as DATA.
#[must_use]
pub fn controller_journal_limits_v1() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 4096,
        maximum_transaction_bytes: 64 * 1024 * 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 128 * 1024 * 1024,
        maximum_materialized_records: 131_072,
    }
}
