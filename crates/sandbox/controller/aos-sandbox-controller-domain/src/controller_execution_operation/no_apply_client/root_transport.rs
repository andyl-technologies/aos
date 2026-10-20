//! Funds the real Root connection from the same retained NoApply Source/C18.
//!
//! The Root client reports its cumulative native/model/traffic representation
//! demand before each reached leaf. This monotone invoice cannot create a Root
//! peer, floor, Controller append, role, Source account or disposition token.

use super::*;

impl<'turn, 'source, 'original>
    ControllerExecutionNoApplyClientLoanV2<'turn, 'source, 'original>
{
    /// Admits cumulative Root transport representation on this same Source loan.
    ///
    /// The invoice replaces only the previous Root subtotal. It adds the fixed
    /// retained native base and ALL actual Host IO before checking the same
    /// Source/C18 declaration. Subsequent Host turns include this retained Root
    /// subtotal too; neither direction can reset or borrow the other's credit.
    ///
    /// # Errors
    /// Retains a decreasing invoice, overflow, earlier native failure or actual
    /// Source refusal. Refusal neither updates the paid subtotal nor refunds
    /// any already reached Root or Host representation.
    #[doc(hidden)]
    pub fn admit_root_transport_complete_v2(
        &mut self,
        cumulative: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native()?;
        let result = (|| {
            if self.native.root_demand.componentwise_max(cumulative) != cumulative {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let complete = self.base.checked_add(self.native.io.retained_demand_v2()?)?
                .checked_add(cumulative)?;
            self.require_transport_complete_v2(complete)
        })();
        match result {
            Ok(()) => {
                self.native.root_demand = cumulative;
                Ok(())
            }
            Err(cause) => {
                self.native.root_refusal.get_or_insert(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        }
    }

    /// Borrows the actual opaque profile already held by the genuine C18 loan.
    ///
    /// Its lifetime is the existing external immutable profile borrow, so the
    /// native Root peer engine may use it while reborrowing financial fields.
    /// No mutable Controller journal or Source/native receiver is exposed.
    #[doc(hidden)]
    #[must_use]
    pub fn root_transport_profile_v2(&self) -> &'turn ProductionControllerNormalRootProfileV1 {
        self.profile
    }
}
