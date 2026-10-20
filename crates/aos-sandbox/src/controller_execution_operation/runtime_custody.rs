//! Moves the same Runtime C18 between public compilation and accepted work.
//!
//! The serial Node caller temporarily installs the whole public scope in its
//! Journal. The transfer state permits no native or effect entry. Every body
//! return restores that same scope before returning custody to Runtime.

use std::sync::{Arc, Mutex};

use super::*;

enum Custody {
    Native(ControllerExecutionOperationOriginalV1),
    Public(Box<ExecutionPublicAdmissionScopeV2>),
    InJournal,
}

/// Retains one actual Runtime C18 across predurable and accepted intervals.
///
/// Construction consumes the previously funded native original. No caller can
/// replace that original, reset its spent history or manufacture acceptance.
#[must_use = "retain the whole C18 custody through all native posts"]
pub struct ControllerExecutionRuntimeCustodyV2 {
    custody: Custody,
}

/// Moves the genuine Runtime original with its installed bank/profile context.
///
/// The final demand describes the concrete Runtime fixed representation; it
/// cannot choose a payer, subdivision, capacity or native admission result.
#[doc(hidden)]
pub type ControllerExecutionPublicCustodyTransferV2 = (
    ControllerExecutionRuntimeCustodyV2,
    Arc<Mutex<ControllerResourceBankOpeningV1>>,
    Arc<ProductionControllerNormalRootProfileV1>,
    Demand,
);

impl ControllerExecutionRuntimeCustodyV2 {
    /// Retains the actual funded Runtime original before either kind of entry.
    #[doc(hidden)]
    pub fn from_original_v2(original: ControllerExecutionOperationOriginalV1) -> Self {
        Self { custody: Custody::Native(original) }
    }

    /// Borrows the original retained failure without replacing its cause.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match &self.custody {
            Custody::Native(original) => original.failure(),
            Custody::Public(scope) => scope.failure_v2(),
            Custody::InJournal => Some(&ResourceReservationErrorV1::Conflict),
        }
    }

    /// Borrows the retained predurable compiler and protected assignment DATA.
    ///
    /// # Errors
    /// Refuses native-only, transferred, retired, failed or unprepared custody.
    /// Success supplies neither native availability nor accepted operation data.
    pub fn preaccept_source_data_v2(&self)
        -> Result<ExecutionPublicPreacceptSourceDataV2<'_>, crate::JournalError>
    {
        match &self.custody {
            Custody::Public(scope) => scope.preaccept_source_data_v2(),
            _ => Err(crate::JournalError::ProtectedBoundary),
        }
    }

    /// Lends the same prepared whole scope to the concrete paired Session SDK.
    ///
    /// The caller keeps both actual Sessions borrowed through initial IO,
    /// canonical admission and accepted bind. This lends no replacement owner,
    /// bank, original deadline, accepted result or effect permission.
    ///
    /// # Errors
    /// Refuses native-only/transferred/retired custody, changed Controller or
    /// missing/failed original compiler and protected assignment preparation.
    #[doc(hidden)]
    pub fn borrow_prepared_public_scope_v2<'owner>(&'owner mut self, controller: &Journal)
        -> Result<&'owner mut ExecutionPublicAdmissionScopeV2, crate::JournalError> {
        match &mut self.custody {
            Custody::Public(scope) => {
                scope.require_current_v2(controller)?;
                scope.preaccept_source_data_v2()?;
                Ok(scope)
            }
            _ => Err(crate::JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn take_public_scope_once_v2(
        &mut self,
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Result<Box<ExecutionPublicAdmissionScopeV2>, ResourceReservationErrorV1> {
        match std::mem::replace(&mut self.custody, Custody::InJournal) {
            Custody::Native(original) => Ok(Box::new(ExecutionPublicAdmissionScopeV2::new(
                original, bank, profile,
            ))),
            Custody::Public(scope) if scope.can_retire_native_v2(&bank, &profile) => {
                // Only the actual positive-disposal route marks a prefix
                // retired. Its native original keeps all previously spent
                // traffic and enters again through the same finite declaration.
                let original = scope.into_retired_native_v2();
                Ok(Box::new(ExecutionPublicAdmissionScopeV2::new(original, bank, profile)))
            }
            prior => {
                self.custody = prior;
                Err(ResourceReservationErrorV1::Conflict)
            }
        }
    }

    pub(crate) fn restore_public_scope_v2(&mut self, scope: Box<ExecutionPublicAdmissionScopeV2>) {
        if !matches!(self.custody, Custody::InJournal) {
            std::process::abort();
        }
        self.custody = Custody::Public(scope);
    }

    /// Borrows the same native original and its protected accepted decoder.
    ///
    /// Public entry resumes the parked interval without another native before.
    /// Its separate upper-prefix obligation must retire before Source disposal.
    /// A positively retired prefix uses the existing ordinary engine thereafter.
    ///
    /// # Errors
    /// Refuses a live transfer, missing exact acceptance, changed original cut,
    /// retained failure, overlap or insufficient genuine declared capacity.
    pub fn begin_once_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        expected: &PublicMutationEffectHistoryV1,
        runtime_fixed: Demand,
    ) -> Result<(
        ControllerExecutionOperationReceivingLoanV1<'owner>,
        Option<ControllerExecutionAdmissionRetirementV2<'owner>>,
    ), ResourceReservationErrorV1> {
        match &mut self.custody {
            Custody::Native(original) => original.begin_once_v1(
                bank, controller, profile, operation, expected, runtime_fixed,
            ).map(|loan| (loan, None)),
            Custody::Public(scope) => {
                if scope.retired {
                    scope.financial.begin_once_v1(
                        bank, controller, profile, operation, expected, runtime_fixed,
                    ).map(|loan| (loan, None))
                } else {
                    scope.resume_accepted_once_v2(
                        bank, controller, profile, operation, expected, runtime_fixed,
                    ).map(|(loan, retirement)| (loan, Some(retirement)))
                }
            }
            Custody::InJournal => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Begins fresh cleanup from this Runtime's actual disposed native C18.
    ///
    /// A public scope lends its same native original only after certified
    /// prefix retirement and actual Source D-positive. A pending, failed or
    /// uncertain public interval cannot enter. The fresh completed Recover
    /// association, native entry and independent historical verification remain
    /// required; no old Apply Source or deadline crosses this boundary.
    ///
    /// # Examples
    ///
    /// A caller cannot assert successful retirement on a pending public scope:
    ///
    /// ```compile_fail
    /// use aos_sandbox::controller_execution_operation::ExecutionPublicAdmissionScopeV2;
    /// fn certify(scope: &mut ExecutionPublicAdmissionScopeV2) {
    ///     scope.retired = true;
    /// }
    /// ```
    ///
    /// A caller cannot bypass uncertain posts by extracting the native owner:
    ///
    /// ```compile_fail
    /// use aos_sandbox::controller_execution_operation::ExecutionPublicAdmissionScopeV2;
    /// fn bypass(scope: &mut ExecutionPublicAdmissionScopeV2) {
    ///     let _native = &mut scope.financial;
    /// }
    /// ```
    ///
    /// # Errors
    /// Refuses uncertified public/transferred custody, failed native entry,
    /// overlap, changed originals or insufficient complete representation.
    pub fn begin_no_apply_cleanup_once_v2<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        completed: &crate::controller_resource_reservation::OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_>,
        target: OperationId,
        runtime: Demand,
    ) -> Result<ControllerExecutionCleanupReceivingLoanV2<'owner>, ResourceReservationErrorV1> {
        match &mut self.custody {
            Custody::Native(original) => original.begin_no_apply_cleanup_once_v2(
                bank, controller, profile, completed, target, runtime,
            ),
            Custody::Public(scope) => scope.borrow_retired_cleanup_native_v2(controller, profile)?
                .begin_no_apply_cleanup_once_v2(bank, controller, profile, completed, target, runtime),
            Custody::InJournal => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Begins the existing paid periodic observation only outside public work.
    ///
    /// # Errors
    /// Refuses a pending public prefix, transfer, failed native original,
    /// overlap or a failed existing periodic native/accepted-source check.
    pub fn begin_periodic_observation_once_v4<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        runtime_fixed: Demand,
    ) -> Result<ControllerExecutionOperationReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        let original = match &mut self.custody {
            Custody::Native(original) => original,
            Custody::Public(scope) if scope.retired => &mut scope.financial,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        original.begin_periodic_observation_once_v4(
            bank, controller, profile, operation, runtime_fixed,
        )
    }
}

impl Drop for ControllerExecutionRuntimeCustodyV2 {
    fn drop(&mut self) {
        if matches!(self.custody, Custody::InJournal) {
            // Returning without the transferred original loses live native
            // custody even if the caller ignored its must-use annotation.
            std::process::abort();
        }
    }
}
