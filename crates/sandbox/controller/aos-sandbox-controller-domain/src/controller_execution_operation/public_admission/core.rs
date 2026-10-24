//! Borrows C18 only for its exact canonical public Create admission.
//!
//! The compiler's whole immutable plan remains resident before Core assembles
//! its ordinary ordered rows. The private Core recipe identifies that same
//! plan; native append never acquires permission merely from scope presence.

use super::*;
use crate::reconciler::provisioning::CoreCommitRecipeV1;

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn bind_plan_once_v2(
        &mut self,
        controller: &Journal,
        plan: Arc<crate::OperationPlan>,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if self.prefix.plan.is_some() || self.prefix.admission_entered
            || self.prefix.compiler.as_ref().is_none_or(|compiler| !compiler.retains_plan_v2(&plan))
            || plan.require_public_execution_admission_shape_v2().is_err()
        {
            self.prefix.first.get_or_insert(First::Plan);
            return Err(JournalError::ProtectedBoundary);
        }

        self.prefix.plan = Some(plan);
        Ok(())
    }

    pub(crate) fn prepare_admission_v2(
        &mut self,
        controller: &mut Journal,
        transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if self.prefix.admission_entered || self.prefix.admission_transaction.is_some()
            || self.prefix.plan.as_deref() != recipe.admission_plan_v1()
            || self.prefix.plan.is_none()
        {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }

        self.prefix.admission_entered = true;
        self.prefix.admission_geometry = Some((|| {
            let native = controller.append_receiving_demand_v1(
                transaction.records().iter().map(|record| {
                    aos_sandbox_journal::geometry::RecordShape {
                        key_bytes: record.key().len(),
                        value_bytes: record.value().map(<[u8]>::len),
                    }
                }),
            ).map_err(|cause| match cause {
                crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
                crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) =>
                    JournalError::ReceivingAccounting(cause),
            })?;

            // Retain the exact canonical rows before crossing native append.
            // The canonical compiler/encoder peak was prepaid before entry.
            let bytes = transaction.records().iter().try_fold(
                std::mem::size_of::<JournalTransaction>(),
                |bytes, record| bytes.checked_add(std::mem::size_of::<crate::JournalRecord>())?
                    .checked_add(record.key().len())?
                    .checked_add(record.value().map_or(0, <[u8]>::len)),
            ).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let Some(demand) = self.prefix.admission_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            self.prefix.first = Some(First::AdmissionGeometry);
            return Err(JournalError::ProtectedBoundary);
        };

        self.prefix.admission_funding = Some((|| {
            let bank = self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(
                &bank, controller, self.profile.as_ref(),
            )?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(
                &bank, controller, self.profile.as_ref(), Demand::from_demand_v1(complete),
            );
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(self.prefix.admission_funding, Some(Ok(()))) {
            self.prefix.admission_funding_native_selected = self.financial.failure().is_some();
            self.prefix.first = Some(First::AdmissionFunding);
            return Err(JournalError::ProtectedBoundary);
        }

        self.prefix.admission_transaction = Some(transaction.clone());
        Ok(())
    }

    pub(crate) fn require_admission_v2(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if !self.prefix.admission_entered
            || !matches!(self.prefix.admission_funding, Some(Ok(())))
            || self.prefix.plan.is_none()
            || self.prefix.plan.as_deref() != recipe.admission_plan_v1()
            || self.prefix.admission_transaction.as_ref() != Some(transaction)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn retain_admission_append_v2(
        &mut self,
        returned: Result<crate::journal::CommitResult, JournalError>,
    ) -> Result<crate::journal::CommitResult, JournalError> {
        if self.prefix.admission_append.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.prefix.admission_append = Some(returned);
        match self.prefix.admission_append.as_ref() {
            Some(Ok(commit)) => Ok(*commit),
            _ => {
                self.prefix.first.get_or_insert(First::AdmissionAppend);
                Err(JournalError::ProtectedBoundary)
            }
        }
    }
}
