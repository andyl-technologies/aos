//! Retained ordinary Query custody borrowing three genuine original owners.
//!
//! Query progress never recreates original authorization or renews its clock.
//! Armed boundaries revoke actual Session and retained progress on returned
//! error or unwind. They start from genuine phase11 originals, not their older
//! construction paths; panic-abort and process loss do not run these guards.

use std::cell::Cell;

use aos_sandbox::{
    JournalTransaction, MountOriginalInventoryJournalAuthorityV6,
    OriginalInventoryProtectedReadbackV6, OriginalRootProtectedReadbackV5,
};
use aos_sandbox_protocol::mount_source_acquisition_state as msa;

use super::*;
use crate::carrier::RetainedSourceProviderRecordV5;

mod binding;
mod custody;
mod exchange;
mod request;

use custody::QueryBoundaryV6;

// A call-local grouping of existing borrows, never a public endpoint owner.
type Original<'a> = (
    &'a AuthorizedMountProviderOutcomeV2,
    &'a OriginalNativeReceivedOutcomeV5,
    &'a OriginalRootProtectedReadbackV5,
);
type Writer<'a> = MountOriginalInventoryJournalAuthorityV6<'a>;

/// Retains one Query plan, canonical draft and at-most-once signature attempt.
#[must_use = "Query preparation retains signatures and must remain owned on failure"]
pub struct OriginalInventoryPreparationV6 {
    root: [u8; 32],
    plan: Option<CurrentMountProviderSessionPlanV2>,
    request: Option<InventorySourceRequestV1>,
    draft: Option<msa::SourceProviderQueryAttemptV2>,
    correlations: Option<msa::InventoryCorrelationSetV2>,
    historical: Vec<HistoricalMountInventoryAuthorizationV2>,
    attempted_sign: bool,
    signed: Option<SignedSourceProviderRequestV1>,
    prepared: Option<PreparedMountProviderRequestV2>,
    confirmed: bool,
    failed: Cell<bool>,
}

/// Retains exact reserved, possible-send and actual Sent Query custody.
#[must_use = "Query send progress retains possible-send debt"]
pub struct OriginalInventorySendV6 {
    root: [u8; 32],
    query: [u8; 32],
    reservation: Option<ReservedMountProviderRequestV2>,
    recovery: Option<MountProviderRequestSendRecoveryV2>,
    sent: Option<SentMountProviderRequestV2>,
    attempted: bool,
    observed_boundary: Option<ProviderSendBoundaryV6>,
    carrier_accepted: bool,
    failed: Cell<bool>,
}

/// Retains one actual Query carrier packet and its first verifier anchor.
#[must_use = "Query receipt custody must remain owned on failure"]
pub struct OriginalInventoryReceivedOutcomeV6 {
    root: [u8; 32],
    query: [u8; 32],
    received: Option<RetainedSourceProviderRecordV5>,
    verified: Option<VerifiedMountProviderOutcomeV2>,
    failed: Cell<bool>,
}

impl OriginalInventoryPreparationV6 {
    /// Borrows signed Query preparation and its nonauthorizing owner draft.
    pub fn reservation_data(
        &self,
    ) -> Option<(&PreparedMountProviderRequestV2, &msa::SourceProviderQueryAttemptV2)> {
        if self.failed.get() || self.confirmed {
            None
        } else {
            self.prepared.as_ref().zip(self.draft.as_ref())
        }
    }
}

impl OriginalInventoryReceivedOutcomeV6 {
    /// Borrows verified zero-FD Inventory DATA without releasing packet custody.
    pub fn verified_inventory(&self) -> Option<&VerifiedMountProviderOutcomeV2> {
        if self.failed.get()
            || self.received.as_ref()
                .and_then(|record| record.bound())
                .is_none()
        {
            None
        } else {
            self.verified.as_ref()
        }
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Rechecks the original owners under the actual named current Query cut.
    ///
    /// # Errors
    /// Revokes original and Session effects on any origin or currentness failure.
    #[doc(hidden)]
    pub fn revalidate_original_inventory_continuation_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
    ) -> Result<(), SourceProviderSecurityError> {
        QueryBoundaryV6::new(self, original, ()).run(|session, _| {
            session.require_original_root_closed_for_inventory_v6(writer, original)
        })
    }

    /// Irreversibly revokes Query progress without releasing any owned bytes.
    #[doc(hidden)]
    pub fn invalidate_original_inventory_progress_v6(
        &mut self,
        preparation: Option<&mut OriginalInventoryPreparationV6>,
        send: Option<&mut OriginalInventorySendV6>,
        received: Option<&mut OriginalInventoryReceivedOutcomeV6>,
    ) {
        if let Some(preparation) = preparation {
            preparation.failed.set(true);
        }
        if let Some(send) = send {
            send.failed.set(true);
        }
        if let Some(received) = received {
            received.failed.set(true);
        }

        self.poison(SourceProviderSecurityError::SessionContinuity);
    }

    fn fail_query_v6(&mut self, original: Original<'_>) {
        self.invalidate_original_inventory_continuation_v6(Some(original.1));
    }
}

fn invalid() -> SourceProviderSecurityError {
    SourceProviderSecurityError::SessionContinuity
}
