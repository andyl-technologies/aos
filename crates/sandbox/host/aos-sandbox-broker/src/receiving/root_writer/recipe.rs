//! Names the existing closed Root authority and compiler-state storage recipes.

use std::path::Path;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

pub(super) const DIRECTORY: &str = "/var/lib/aos/sandbox/policy-compiler";
pub(super) const AUTHORITY: &str = "authority.journal";
pub(super) const POLICY: &str = "state.journal";

#[derive(Clone, Copy)]
pub(in crate::receiving) enum RootWriterRecipeV1 {
    StartupAuthority,
    CurrentAuthority,
    CurrentPolicy,
}

impl RootWriterRecipeV1 {
    pub(in crate::receiving) fn index(self) -> usize {
        match self {
            Self::StartupAuthority => 0,
            Self::CurrentAuthority => 1,
            Self::CurrentPolicy => 2,
        }
    }

    pub(super) fn directory(self) -> &'static Path {
        Path::new(DIRECTORY)
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::StartupAuthority | Self::CurrentAuthority => AUTHORITY,
            Self::CurrentPolicy => POLICY,
        }
    }

    pub(super) fn allows_creation(self) -> bool {
        matches!(self, Self::StartupAuthority | Self::CurrentPolicy)
    }

    pub(super) fn limits(self) -> JournalLimits {
        match self {
            Self::StartupAuthority | Self::CurrentAuthority => authority_limits(),
            Self::CurrentPolicy => JournalLimits::default(),
        }
    }
}

// These exact existing limits have one body and an immediate upper forward;
// no role caller supplies or widens them. The existing accepted binding/archive
// maxima are 4096/1024, pinned in the accompanying conservation receipt.
pub(super) fn authority_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 4 * 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 256,
        maximum_transaction_bytes: 2 * 1024 * 1024,
        maximum_transactions: 262_144,
        maximum_materialized_bytes: 8 * 1024 * 1024,
        maximum_materialized_records: 3 * 4_096 + 19 + 1_024,
    }
}
