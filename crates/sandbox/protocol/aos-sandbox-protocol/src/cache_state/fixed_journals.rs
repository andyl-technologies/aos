//! Shares compiled Cache journal names and the existing replay-limit recipes.
//!
//! These values are configuration DATA. They do not open a journal, authenticate
//! a mount, borrow a writer, reserve resources, validate a namespace or grant a
//! signer purpose. The actual role owns its fixed path selection and receiving
//! originals. The ordinary Native constructors use these same five recipes.

use crate::domain_ledger::transaction::JournalLimits;

/// Names the existing Controller-owned bootstrap directory.
pub const CACHE_BOOTSTRAP_DIRECTORY_V1: &str = "/var/lib/aos/sandboxd/cache-residency-authority";
/// Names the existing protected Cache journals directory.
pub const CACHE_JOURNAL_DIRECTORY_V1: &str = "/var/lib/aos/sandbox/cache-residency-journals";
/// Names the exact bootstrap journal.
pub const CACHE_BOOTSTRAP_BASENAME_V1: &str = "bootstrap-v1.journal";
/// Names the exact policy-hold journal.
pub const CACHE_HOLD_BASENAME_V1: &str = "policy-hold.journal";
/// Names the exact state journal.
pub const CACHE_STATE_BASENAME_V1: &str = "state.journal";
/// Names the exact authority journal.
pub const CACHE_AUTHORITY_BASENAME_V1: &str = "authority.journal";
/// Names the exact monotone clock journal.
pub const CACHE_CLOCK_BASENAME_V1: &str = "clock.journal";
/// Bounds the existing bootstrap's complete source-partition inventory.
pub const CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1: usize = 4_096;
/// Names the established HOLD genesis key used in its native framing bound.
pub const CACHE_HOLD_GENESIS_KEY_V1: &[u8] = b"\0aos-cache-policy-hold-genesis-v1\0";
/// Carries the established HOLD genesis value used in its native framing bound.
pub const CACHE_HOLD_GENESIS_V1: &[u8] = b"AOSCPG01";

/// Selects one compiled existing journal recipe without lending role authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheJournalRecipeRoleV1 {
    /// Selects the Controller bootstrap inventory.
    Bootstrap,
    /// Selects the Cache policy freeze and retained Held history.
    Hold,
    /// Selects the complete Cache state history.
    State,
    /// Selects the Cache authority inventory.
    Authority,
    /// Selects the monotone Cache time floor.
    Clock,
}

impl CacheJournalRecipeRoleV1 {
    /// Returns the existing writer directory as nonauthorizing path DATA.
    #[must_use]
    pub const fn writer_directory_v1(self) -> &'static str {
        match self {
            Self::Bootstrap => CACHE_BOOTSTRAP_DIRECTORY_V1,
            _ => CACHE_JOURNAL_DIRECTORY_V1,
        }
    }

    /// Returns the corresponding fixed readonly signer mount target.
    ///
    /// Bootstrap uses the prepared child view; a signer cannot search the
    /// original private Controller parent. Actual mount validation remains
    /// mandatory and is not implied by this string.
    #[must_use]
    pub const fn signer_view_v1(self) -> &'static str {
        match self {
            Self::Bootstrap => "/run/aos/sandbox-cache-signer-controller-journal",
            _ => "/run/aos/sandbox-cache-signer-journals",
        }
    }

    /// Returns the exact existing journal basename.
    #[must_use]
    pub const fn basename_v1(self) -> &'static str {
        match self {
            Self::Bootstrap => CACHE_BOOTSTRAP_BASENAME_V1,
            Self::Hold => CACHE_HOLD_BASENAME_V1,
            Self::State => CACHE_STATE_BASENAME_V1,
            Self::Authority => CACHE_AUTHORITY_BASENAME_V1,
            Self::Clock => CACHE_CLOCK_BASENAME_V1,
        }
    }

    /// Derives the same complete replay bounds used by the actual constructors.
    ///
    /// The HOLD history bound uses its existing native frame widths and physical
    /// cap. It neither guesses a lane count nor increases any journal bound.
    #[must_use]
    pub fn limits_v1(self) -> JournalLimits {
        match self {
            Self::Bootstrap => JournalLimits {
                maximum_journal_bytes: 256 * 1024 * 1024,
                maximum_record_bytes: 16 * 1024 * 1024,
                maximum_transactions: CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1,
                maximum_materialized_bytes: 128 * 1024 * 1024,
                maximum_materialized_records: CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1,
                maximum_records_per_transaction: CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1,
                maximum_transaction_bytes: 128 * 1024 * 1024,
                ..JournalLimits::default()
            },
            Self::State => JournalLimits::default(),
            Self::Authority => JournalLimits {
                maximum_record_bytes: 16 * 1024 * 1024,
                maximum_materialized_records: 16_384,
                ..JournalLimits::default()
            },
            Self::Clock => JournalLimits {
                maximum_journal_bytes: 16 * 1024 * 1024,
                maximum_record_bytes: 4 * 1024,
                maximum_key_bytes: 128,
                maximum_records_per_transaction: 1,
                maximum_transaction_bytes: 8 * 1024,
                maximum_transactions: 262_144,
                maximum_materialized_bytes: 8 * 1024,
                maximum_materialized_records: 1,
            },
            Self::Hold => hold_limits(),
        }
    }
}

fn hold_limits() -> JournalLimits {
    use crate::domain_ledger::create_storage_history::{
        HEAD_BYTES, KEY_BYTES, cache_held::CACHE_HELD_RECORD_BYTES_V1,
    };
    use aos_sandbox_journal::framing::{COMMIT_PAYLOAD_BYTES, HEADER_BYTES};

    let maximum_journal_bytes = 16 * 1024 * 1024;
    let maximum_transactions = 50_000;
    let record_payload = 7 + KEY_BYTES + CACHE_HELD_RECORD_BYTES_V1;
    let head_payload = 7 + KEY_BYTES + HEAD_BYTES;
    let genesis_append = 3 * HEADER_BYTES
        + 4
        + COMMIT_PAYLOAD_BYTES
        + 7
        + CACHE_HOLD_GENESIS_KEY_V1.len()
        + CACHE_HOLD_GENESIS_V1.len();

    // Every history row retains a reached native payload and requires a full
    // key/head frame. The actual closed family has at most three other rows.
    let history_rows = ((maximum_journal_bytes - genesis_append)
        / (HEADER_BYTES + 7 + KEY_BYTES + HEAD_BYTES))
        .min((maximum_transactions - 1) * 2);
    JournalLimits {
        maximum_journal_bytes: maximum_journal_bytes as u64,
        maximum_record_bytes: record_payload,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: record_payload + head_payload,
        maximum_transactions,
        maximum_materialized_bytes: maximum_journal_bytes,
        maximum_materialized_records: 3 + history_rows,
    }
}
