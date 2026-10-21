//! Defines the fixed protected Session journal format limits and archive ceilings.
//!
//! These constants and limits are passive schema DATA; actual native owners
//! separately open, admit, replay and retain their original journals.

use aos_sandbox_broker_session_protocol::BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES;
use crate::domain_ledger::transaction::JournalLimits;
use super::historical_checkpoint::MAXIMUM_BYTES as CHECKPOINT_BYTES;
use super::stored_history::VALUE_FIXED_BYTES_V3;

/// Bounds the existing current protocol rows in one protected Session writer.
pub const MAXIMUM_PROTOCOL_RECORDS: usize = 4;

/// Bounds the existing retained Storage group archives.
pub const MAXIMUM_STORAGE_GROUP_ARCHIVES: usize = 16;

/// Bounds the existing retained Storage Inventory archives.
pub const MAXIMUM_STORAGE_INVENTORY_ARCHIVES: usize = 16;

/// Bounds the existing retained Storage Inventory abandonment rows.
pub const MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS: usize = 16;

/// Bounds the existing retained Host argument archives.
pub const MAXIMUM_HOST_ARGUMENT_ARCHIVES: usize = 16;

/// Bounds the existing retained Host terminal archives.
pub const MAXIMUM_HOST_TERMINAL_ARCHIVES: usize = MAXIMUM_HOST_ARGUMENT_ARCHIVES;


/// Names the existing fixed protected Session journal basename.
pub const PROTECTED_SESSION_JOURNAL_V1: &str = "session.journal";

/// Returns the existing compiled protected Session writer and reader limits.
#[must_use]
pub fn protected_session_journal_limits_v1() -> JournalLimits {
    let maximum_record_bytes = BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
        + VALUE_FIXED_BYTES_V3
        + CHECKPOINT_BYTES
        + 1024;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: 24,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 2 * maximum_record_bytes + 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: (MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS
            + MAXIMUM_HOST_ARGUMENT_ARCHIVES
            + MAXIMUM_HOST_TERMINAL_ARCHIVES)
            * maximum_record_bytes,
        maximum_materialized_records: MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS
            + MAXIMUM_HOST_ARGUMENT_ARCHIVES
            + MAXIMUM_HOST_TERMINAL_ARCHIVES,
    }
}
