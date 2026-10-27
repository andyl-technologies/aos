//! Joins earned Target compilation to the same real Authority history.
//!
//! The caller supplies selectors and original packets; only this Work's actual
//! positive compilation receipt and the Flight's strict native gen1 checks can
//! construct native binding history. No supplied suffix or eligibility enters.

use super::RootPolicyPublicationWorkV1;
use crate::native::authority::RootAuthorityQ04FlightOriginalV1;
use crate::q04_data::Q04RootStageRecipeV1;

/// Identifies the actual retained first owner at binding-history admission.
///
/// This diagnostic grants no history eligibility or operation permission. The
/// caller latches it before independently owed posts can add a later failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPolicyHistoryAdmissionFailureV1 {
    /// The same Work retains its earlier compilation or Target refusal.
    PolicyHeld,
    /// The actual Flight retains its original Authority/native refusal.
    AuthorityHeld,
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Admits the same held compiler result to the actual binding-history owner.
    ///
    /// # Errors
    /// Retains the genuine Authority/native error and refuses reentry, missing
    /// positive compiler input, changed original Target rows or foreign packets.
    pub fn admit_root_binding_history_once_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim: &[u8],
        request: &[u8],
        preview: &[u8],
        controller: &[u8],
        source: &[u8],
    ) -> Result<(), RootPolicyHistoryAdmissionFailureV1> {
        if self.history_entered || self.failure_v1().is_some() {
            self.refuse_entry_v1();
            return Err(RootPolicyHistoryAdmissionFailureV1::PolicyHeld);
        }
        self.history_entered = true;
        match flight.admit_q04_history_v1(self, stage, claim, request,
            preview, controller, source)
        {
            Ok(()) => {
                self.history_complete = true;
                Ok(())
            }
            Err(()) => Err(if self.failure_v1().is_some() {
                RootPolicyHistoryAdmissionFailureV1::PolicyHeld
            } else {
                RootPolicyHistoryAdmissionFailureV1::AuthorityHeld
            }),
        }
    }
}

impl RootPolicyPublicationWorkV1<'_> {
    /// Earns Decision eligibility from the same fresh strict publication readback.
    ///
    /// # Errors
    /// Separates this Work's actual held/native observation failure from the
    /// genuine Authority's retained R2/Decision-history admission failure.
    pub fn admit_root_decision_once_v1(
        &mut self,
        flight: &mut RootAuthorityQ04FlightOriginalV1<'_, '_, '_>,
        stage: &Q04RootStageRecipeV1,
        claim: &[u8],
        controller: &[u8],
        source: &[u8],
        cache_uid: u32,
    ) -> Result<(), RootPolicyHistoryAdmissionFailureV1> {
        if self.refresh_publication_for_decision_v1(flight, stage, claim,
            controller, source, cache_uid).is_err()
        {
            return Err(RootPolicyHistoryAdmissionFailureV1::PolicyHeld);
        }
        match flight.admit_q04_decision_v1(self, stage, source) {
            Ok(()) => Ok(()),
            Err(()) => Err(if self.failure_v1().is_some() {
                RootPolicyHistoryAdmissionFailureV1::PolicyHeld
            } else {
                RootPolicyHistoryAdmissionFailureV1::AuthorityHeld
            }),
        }
    }
}
