//! Joins paid maintenance to the same continuously held authenticated Session.
//!
//! The opaque completed borrower retains the actual receiver and mutable
//! Session association throughout the sole Inventory driver's native window.
//! No Recover custody, old transport horizon or public Journal is substituted.

use super::*;
use crate::handshake::output_registration_continuation::ControllerInventoryClientKernelV1;

impl OperatorRecoverStorageInventoryOriginalV1 {
    /// Observes one fixed inventory under the same actual maintenance interval.
    ///
    /// Each entered query keeps its whole native and SDK failure prefix. Its
    /// independent native post and positive physical disposal are performed by
    /// the existing shared driver before this short borrower is released.
    ///
    /// # Errors
    /// Retains repeated entry, foreign completed Session, original/native
    /// admission, request, signed outcome, full model or disposal refusal.
    pub fn observe_maintenance_once_v2(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        completed: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
        index: usize,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.entered {
            self.reentry
                .get_or_insert(BrokerSessionSecurityError::Currentness);
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        self.entered = true;
        self.shape = Some(ControllerInventoryClientKernelV1::<
            aos_sandbox::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>,
        >::security_shape_v1());
        let shape = match self.shape.as_ref() {
            Some(Ok(shape)) => *shape,
            _ => {
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let method = match loan.inventory_method_data_v2(index) {
            Ok(method) => method,
            Err(cause) => {
                self.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let (receiving, inner) = completed.reborrow_v1();
        let journal = match inner.operator_reconciliation_inventory_journal_v2(method) {
            Ok(journal) => journal,
            Err(cause) => {
                self.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Protected(
                    cause,
                )));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match loan.borrow_inventory_once_v2(index, receiving, journal, shape) {
            Ok(native) => {
                self.admission = Some(Ok(()));
                native
            }
            Err(cause) => {
                self.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                return Err(OutputPreparationClosedV1);
            }
        };
        self.drive_prepaid_kernel_v2(
            ControllerInventoryClientKernelV1::retain_prepaid(native),
            inner,
        )?;
        let answer = self.answer.as_ref().ok_or(OutputPreparationClosedV1)?;
        let journal = inner
            .operator_reconciliation_inventory_journal_v2(method)
            .map_err(|cause| {
                self.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Protected(
                    cause,
                )));
                loan.retain_sdk_refusal_once_v2();
                OutputPreparationClosedV1
            })?;
        loan.retain_inventory_model_once_v2(
            index,
            journal,
            answer.outcome_v1(),
            answer.decoded_model_original_v2(),
        )
        .map_err(|_| OutputPreparationClosedV1)?;
        loan.persist_inventory_snapshot_once_v2(
            index,
            answer.outcome_v1(),
            answer.decoded_model_original_v2(),
        )
        .map_err(|_| OutputPreparationClosedV1)
    }

    /// Borrows the exact signed maintenance outcome after positive disposition.
    #[must_use]
    pub fn maintenance_outcome_data_v2(&self)
        -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1>
    {
        self.maintenance_model_data_v2()?;
        Some(self.answer.as_ref()?.outcome_v1())
    }

    /// Borrows the sole canonical decoder's immutable completed model.
    ///
    /// This is historical DATA; the maintenance owner separately requires its
    /// exact native query, same Session Journal and all independent posts.
    #[must_use]
    pub fn maintenance_model_data_v2(&self)
        -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2>
    {
        if self.reentry.is_some()
            || !matches!(self.final_post, Some(Ok(())))
            || !matches!(self.model_checked, Some(Ok(())))
        {
            return None;
        }
        Some(self.answer.as_ref()?.decoded_model_original_v2())
    }
}
