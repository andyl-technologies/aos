//! Owns the independent Root Authority writer, pins and complete native history.
//!
//! Construction composes the same fixed Root opening, full cold replay and
//! independently held administrative originals. Only a completed construction
//! transfers this owner. Per-flight acceptance and final mutation loans remain
//! below this role; a read view, signature or financial handle is not a loan.

mod append_context;
mod append_gate;
mod binding_history;
mod cache_terminal;
mod capacity;
mod currentness;
mod error;
mod forecast;
mod gen1;
mod genesis;
mod history;
mod history_pair;
mod inputs;
mod names;
mod opening;
mod pins;
mod publication_cut;
mod q04;
mod serving;
mod stage;
mod terminal_cut;
mod terminal_check;

use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use super::journal::RootPolicyJournalV1;
use currentness::RootAuthorityCurrentCustodyV1;
use pins::RootAuthorityPinsOriginalV1;

pub(in crate::native) use append_gate::AuthorityAppendGateV1;
pub use append_gate::RootAuthorityQ04AppendFailureV1;
pub(in crate::native) use forecast::AuthorityForecastGateV1;
pub use genesis::{
    CurrentNixRootArchiveAttemptV1, CurrentRootFirstSourceSuccessorFloorV2,
    CurrentRootProjectSuccessorFloorV3, CurrentRootSourceGenesisFloorV1,
    CurrentRootSourceProjectGenesisFloorV3, RootFirstSourceSuccessorOpeningV2,
    RootFirstSuccessorMutationResultsV2, RootGenesisOpeningFailureV1,
    RootProjectGenesisMutationResultsV3, RootSourceGenesisAuthorityV1, RootStrictGenesisFailureV1,
    fixed_root_source_genesis_recovery_available_v1,
};
pub(in crate::native) use genesis::{
    GlobalRootGenesisNativeCutV2, RootGenesisAdvisoryCutV1, RootGenesisCapacityCutDataV1,
    RootProjectGenesisNativeCutV3, RootStrictGenesisNativeCutV1, RootSuccessorAdvisoryCutV1,
    RootSuccessorNativeServerCutV3,
};

pub use binding_history::RootAuthorityQ04HistoryV1;
pub use cache_terminal::{RootAuthorityCacheTerminalErrorV1, RootAuthorityCacheTerminalOutcomeV1};
pub use currentness::RootAuthorityCurrentFailureV1;
pub use error::RootAuthorityErrorV1;
pub use gen1::RootAuthorityGen1LoanV1;
pub use opening::RootAuthorityConstructionOriginalV1;
pub(in crate::native) use publication_cut::RootAuthorityQ04PublicationLoanV1;
pub use q04::RootAuthorityQ04FlightOriginalV1;

/// Retains the actual independent Authority journal and its native pin originals.
///
/// The selected writer is constructed only by the real Root receiver. The
/// underlying ordinary fixed opening remains a distinct physical branch; it
/// cannot replace missing selected finance in this role construction. No caller supplies a journal, map, instance,
/// pins, currentness result or role-success stamp to construct this type.
pub struct RootAuthorityOriginalV1 {
    journal: RootPolicyJournalV1,
    pins: RootAuthorityPinsOriginalV1,
    names: ProtectedJournalNamesV1,
    current: RootAuthorityCurrentCustodyV1,
}

impl RootAuthorityOriginalV1 {
    /// Rechecks the same native writer, independent pins and complete history.
    ///
    /// The actual selected branch pays its fixed observation and every reached
    /// dynamic history plane before growth. Returned failures and unwinding keep the reached
    /// native capture parked in this same resident owner.
    ///
    /// # Errors
    /// Rejects changed names, credentials, role rows, fixed-owner custody or
    /// complete semantic history, retaining the actual native or payer cause.
    pub fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        currentness::require_current_v1(&self.journal, &self.pins, self.names, &self.current)
    }

    /// Borrows a retained native panic-prefix cause without observing again.
    ///
    /// Returned errors refer to this same retained owner; callers keep the owner
    /// resident before independent later posts.
    #[must_use]
    pub fn retained_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.current.failure().or_else(|| self.journal.failure())
    }
}

impl RootAuthorityOriginalV1 {
    pub(in crate::native) fn resolve_held_failure_v1<'error>(
        &'error self,
        cause: &'error RootAuthorityErrorV1,
    ) -> &'error (dyn std::error::Error + 'static) {
        match cause {
            RootAuthorityErrorV1::Currentness(_) => self.current.failure().unwrap_or(cause),
            RootAuthorityErrorV1::Journal(super::PolicyNativeJournalErrorV1::Q04Current(_)) => {
                self.journal.q04_readback_failure_v1().unwrap_or(cause)
            }
            // Only these two resident markers require resolution. An owned
            // unrelated refusal must never become an always-native fallback.
            _ => cause,
        }
    }
}
