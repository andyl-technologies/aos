//! Binds shared mechanical continuation clocks to the existing Domain errors.
//!
//! The native sources, finite source selection, comparison horizon, and failed
//! prefix custody live in Broker. These aliases supply only the two existing
//! diagnostic categories; they create no new observation or purpose grant.

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;

impl aos_sandbox_broker::controller_clock::ContinuationClockErrorV1 for JournalError {
    fn protected_boundary() -> Self {
        Self::ProtectedBoundary
    }

    fn journal_too_large() -> Self {
        Self::JournalTooLarge
    }
}

pub(crate) type RootContinuationHorizonDataV1 =
    aos_sandbox_broker::continuation_clock::RootContinuationHorizonDataV1<JournalError>;

pub(crate) type RootContinuationClockGateV1 =
    aos_sandbox_broker::continuation_clock::RootContinuationClockGateV1<
        SourceGenesisErrorV1,
        JournalError,
    >;
