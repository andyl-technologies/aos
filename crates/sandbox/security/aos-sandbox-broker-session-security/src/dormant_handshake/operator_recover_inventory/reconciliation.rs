//! Retains a finite reconciliation query through the sole signed query driver.

use super::*;
use aos_sandbox_controller_domain::OperatorReconciliationObservationLoanV2;
use crate::dormant_handshake::OperatorReconciliationSessionOpenV2;
use crate::handshake::output_registration_continuation::ControllerInventoryClientKernelV1;

/// Retains the same native, signed and decoded originals for one new query.
///
/// Its inert construction creates no Session or grant. Completed data is lent
/// only after the exact cold/native owner and all query afters really succeed.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain every entered query with its actual role and Session"]
pub struct OperatorReconciliationInventoryOriginalV2 {
    original: OperatorRecoverStorageInventoryOriginalV1,
}

impl OperatorReconciliationInventoryOriginalV2 {
    /// Lends the same completed query, decoded model and private Session journal.
    ///
    /// The Domain joins these originals to its retained native query before
    /// returning a proof. No caller-supplied journal or model crosses this port.
    ///
    /// # Errors
    /// Refuses incomplete SDK, native, Source or Session custody, a changed
    /// protected cut, or another query's signed body and decoded model.
    pub fn borrow_completed_inventory_v2<'held>(
        &'held self,
        owner: &'held aos_sandbox_controller_domain::OperatorReconciliationObservationOriginalV2,
        seed: &aos_sandbox_controller_domain::OperatorRecoveredStoppedCreateSeedV1<'_>,
        controller: &aos_sandbox_controller_domain::Journal,
        source: &aos_sandbox_controller_domain::source_domain::ProtectedSourceDomainJournalOwnerV1,
        session: &'held DormantAuthenticatedBrokerSessionV1,
        index: usize,
    ) -> Result<aos_sandbox_controller_domain::OperatorReconciliationInventoryProofV2<'held>, aos_sandbox_controller_domain::OperatorCreateRecoveryClosedV1> {
        let closed = aos_sandbox_controller_domain::OperatorCreateRecoveryClosedV1;
        let outcome = self.outcome_v2().ok_or(closed)?;
        let decoded = self.decoded_model_v2().ok_or(closed)?;
        let journal = session.0.operator_reconciliation_inventory_journal_v2(
            decoded.method_v2()).map_err(|_| closed)?;
        owner.borrow_completed_inventory_v2(seed, controller, source, index,
            journal, outcome, decoded)
    }

    /// Observes the next fixed method of this actual reconciliation endpoint.
    ///
    /// The sole index selects Host3, Network19 or Mount16 from the genuine
    /// role. It selects no payer, request identifier, deadline or journal path.
    ///
    /// # Errors
    /// Retains actual cold association, native financing, signed exchange,
    /// decoder, currentness, final after or positive-disposal refusal.
    pub fn observe_once_v2(&mut self,
        loan: &mut OperatorReconciliationObservationLoanV2<'_, '_, '_, '_>,
        cold: &OperatorReconciliationSessionOpenV2,
        session: &mut DormantAuthenticatedBrokerSessionV1, index: usize,
    ) -> Result<(), OutputPreparationClosedV1> {
        let original = &mut self.original;
        if original.entered {
            original.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        original.entered = true;
        let mut completed = match cold.borrow_completed_kernel_session_v2(&mut session.0) {
            Ok(completed) => { original.cold = Some(Ok(())); completed }
            Err(cause) => {
                original.cold = Some(Err(cause));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        original.shape = Some(ControllerInventoryClientKernelV1::<
            aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>>::security_shape_v1());
        let shape = match original.shape.as_ref() {
            Some(Ok(shape)) => *shape,
            _ => { loan.retain_sdk_refusal_once_v2(); return Err(OutputPreparationClosedV1); }
        };
        let (receiving, inner) = completed.reborrow_v1();
        let method = match loan.inventory_method_data_v2(index) {
            Ok(method) => method,
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let journal = match inner.operator_reconciliation_inventory_journal_v2(method) {
            Ok(journal) => journal,
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Protected(cause)));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match loan.borrow_inventory_once_v2(index, receiving, journal, shape) {
            Ok(native) => { original.admission = Some(Ok(())); native }
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                return Err(OutputPreparationClosedV1);
            }
        };
        original.drive_prepaid_kernel_v2(ControllerInventoryClientKernelV1::retain_prepaid(native), inner)
    }

    /// Borrows the exact signed outcome after real positive query disposal.
    pub fn outcome_v2(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1> {
        self.decoded_model_v2()?;
        Some(self.original.answer.as_ref()?.outcome_v1())
    }

    /// Borrows the immutable sole-decoder model and its original body commitment.
    ///
    /// This historical DATA cannot itself assert current physical absence.
    pub fn decoded_model_v2(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2> {
        if self.original.reentry.is_some() || !matches!(self.original.final_post, Some(Ok(())))
            || !matches!(self.original.model_checked, Some(Ok(()))) { return None; }
        Some(self.original.answer.as_ref()?.decoded_model_original_v2())
    }

    /// Borrows the first actual SDK cause beside its same outer Session.
    pub fn failure_v2<'cause>(&'cause self, session: &'cause DormantAuthenticatedBrokerSessionV1)
        -> Option<&'cause (dyn Error + 'static)> {
        self.original.failure_v1(session)
    }
}


/// Retains the same native, signed and decoded originals for one new query.
///
/// Its inert construction creates no Session or grant. Completed data is lent
/// only after the exact cold/native owner and all query afters really succeed.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain every entered query with its actual role and Session"]
pub struct OperatorStopCleanupInventoryOriginalV1 {
    original: OperatorRecoverStorageInventoryOriginalV1,
}

impl OperatorStopCleanupInventoryOriginalV1 {
    /// Borrows only the same completed native query's sole decoded Host3 model.
    ///
    /// Root and the fresh Source22 owner must independently authorize every
    /// later use. This immutable observation creates no absence or Stop grant.
    ///
    /// # Errors
    /// Refuses failed SDK/query disposition, changed Source or another decoded
    /// body, native Session opening, query nonce or cleanup entropy original.
    pub fn borrow_completed_inventory_data_v1<'held>(
        &'held self,
        loan: &mut aos_sandbox_controller_domain::OperatorStopCleanupObservationLoanV1<'_, '_>,
        source: &aos_sandbox_controller_domain::source_domain::ProtectedSourceDomainJournalOwnerV1,
        session: &DormantAuthenticatedBrokerSessionV1,
    ) -> Result<&'held aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2,
        OutputPreparationClosedV1>
    {
        let outcome = self.outcome_v2().ok_or(OutputPreparationClosedV1)?;
        let decoded = self.decoded_model_v2().ok_or(OutputPreparationClosedV1)?;
        let journal = session.0.operator_reconciliation_inventory_journal_v2(decoded.method_v2())
            .map_err(|_| OutputPreparationClosedV1)?;
        loan.require_completed_inventory_data_v1(source, journal, outcome, decoded)
            .map_err(|_| OutputPreparationClosedV1)?;
        Ok(decoded)
    }

    /// Observes the next fixed method of this actual reconciliation endpoint.
    ///
    /// The sole index selects Host3, Network19 or Mount16 from the genuine
    /// role. It selects no payer, request identifier, deadline or journal path.
    ///
    /// # Errors
    /// Retains actual cold association, native financing, signed exchange,
    /// decoder, currentness, final after or positive-disposal refusal.
    pub fn observe_once_v1(&mut self,
        loan: &mut aos_sandbox_controller_domain::OperatorStopCleanupObservationLoanV1<'_, '_>,
        cold: &crate::dormant_handshake::OperatorStopCleanupSessionOpenV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        let original = &mut self.original;
        if original.entered {
            original.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            loan.retain_sdk_refusal_once_v1();
            return Err(OutputPreparationClosedV1);
        }
        original.entered = true;
        let mut completed = match cold.borrow_completed_kernel_session_v1(&mut session.0) {
            Ok(completed) => { original.cold = Some(Ok(())); completed }
            Err(cause) => {
                original.cold = Some(Err(cause));
                loan.retain_sdk_refusal_once_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        original.shape = Some(ControllerInventoryClientKernelV1::<
            aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>>::security_shape_v1());
        let shape = match original.shape.as_ref() {
            Some(Ok(shape)) => *shape,
            _ => { loan.retain_sdk_refusal_once_v1(); return Err(OutputPreparationClosedV1); }
        };
        let (receiving, inner) = completed.reborrow_v1();
        let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        let journal = match inner.operator_reconciliation_inventory_journal_v2(method) {
            Ok(journal) => journal,
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Protected(cause)));
                loan.retain_sdk_refusal_once_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match loan.borrow_inventory_once_v1(receiving, journal, shape) {
            Ok(native) => { original.admission = Some(Ok(())); native }
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                return Err(OutputPreparationClosedV1);
            }
        };
        original.drive_prepaid_kernel_v2(ControllerInventoryClientKernelV1::retain_prepaid(native), inner)
    }

    /// Borrows the exact signed outcome after real positive query disposal.
    pub fn outcome_v2(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1> {
        self.decoded_model_v2()?;
        Some(self.original.answer.as_ref()?.outcome_v1())
    }

    /// Borrows the immutable sole-decoder model and its original body commitment.
    ///
    /// This historical DATA cannot itself assert current physical absence.
    pub fn decoded_model_v2(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2> {
        if self.original.reentry.is_some() || !matches!(self.original.final_post, Some(Ok(())))
            || !matches!(self.original.model_checked, Some(Ok(()))) { return None; }
        Some(self.original.answer.as_ref()?.decoded_model_original_v2())
    }

    /// Borrows the first actual SDK cause beside its same outer Session.
    pub fn failure_v2<'cause>(&'cause self, session: &'cause DormantAuthenticatedBrokerSessionV1)
        -> Option<&'cause (dyn Error + 'static)> {
        self.original.failure_v1(session)
    }
}


/// Retains one actual Source22 Host3 query through the shared signed IO kernel.
///
/// It creates no Session, absence, Root receipt or effect grant. The Source22
/// ordinal and genuine completed cold receiver select its actual native loan.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the real query beside its current Source22 and Session"]
pub struct OperatorStopCleanupSourceInventoryOriginalV1 {
    original: OperatorRecoverStorageInventoryOriginalV1,
    proof_entered: bool,
    proof_session: Option<Result<(), BrokerSessionSecurityError>>,
    proof_native: Option<aos_sandbox_controller_domain::controller_lifecycle_stop::StopCleanupCompletionErrorV1>,
    proof_closed: Option<OutputPreparationClosedV1>,
}

impl OperatorStopCleanupSourceInventoryOriginalV1 {
    /// Enters the finite real Host3 ordinal under the same paid Source22.
    ///
    /// # Errors
    /// Retains repeated entry, changed cold/Source/current C, financing, native
    /// IO, canonical signature/model, currentness or positive-disposal failure.
    pub fn observe_once_v1(
        &mut self,
        source: &mut aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &mut aos_sandbox_controller_domain::Journal,
        cold: &crate::dormant_handshake::OperatorStopCleanupSourceSessionOpenV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        index: usize,
    ) -> Result<(), OutputPreparationClosedV1> {
        let original = &mut self.original;
        if original.entered {
            original.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            source.retain_cold_sdk_refusal_v1();
            return Err(OutputPreparationClosedV1);
        }
        original.entered = true;
        let mut completed = match cold.borrow_completed_kernel_session_v1(&mut session.0) {
            Ok(completed) => { original.cold = Some(Ok(())); completed }
            Err(cause) => {
                original.cold = Some(Err(cause));
                source.retain_cold_sdk_refusal_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        original.shape = Some(ControllerInventoryClientKernelV1::<
            aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>>::security_shape_v1());
        let shape = match original.shape.as_ref() {
            Some(Ok(shape)) => *shape,
            _ => { source.retain_cold_sdk_refusal_v1(); return Err(OutputPreparationClosedV1); }
        };
        let (receiving, inner) = completed.reborrow_v1();
        let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        let journal = match inner.operator_reconciliation_inventory_journal_v2(method) {
            Ok(journal) => journal,
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Protected(cause)));
                source.retain_cold_sdk_refusal_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match source.borrow_inventory_once_v1(controller, index, receiving, journal, shape) {
            Ok(native) => { original.admission = Some(Ok(())); native }
            Err(cause) => {
                original.admission = Some(Err(OperatorRecoverInventoryBorrowFailureV1::Native(cause)));
                return Err(OutputPreparationClosedV1);
            }
        };
        original.drive_prepaid_kernel_v2(ControllerInventoryClientKernelV1::retain_prepaid(native), inner)
    }

    /// Records the exact native query and sole model on the actual Source22.
    ///
    /// The retained reference is immutable comparison DATA for Root; later A8
    /// evidence still requires the same native financial affinity, actual Root
    /// post-D proof and strict final population/current Source conjunction.
    ///
    /// # Errors
    /// Refuses incomplete SDK/native disposition, another decoded body,
    /// repeated model registration, wrong ordinal or changed Source/Session.
    pub fn bind_completed_inventory_once_v1(
        &self,
        source: &mut aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &aos_sandbox_controller_domain::Journal,
        session: &DormantAuthenticatedBrokerSessionV1,
        index: usize,
    ) -> Result<(), OutputPreparationClosedV1> {
        let outcome = self.outcome_v1().ok_or(OutputPreparationClosedV1)?;
        let decoded = self.decoded_model_v1().ok_or(OutputPreparationClosedV1)?;
        let journal = session.0.operator_reconciliation_inventory_journal_v2(decoded.method_v2())
            .map_err(|_| OutputPreparationClosedV1)?;
        source.require_completed_inventory_model_v1(controller, journal, outcome, decoded, index, false)
            .map_err(|_| OutputPreparationClosedV1)
    }

    /// Joins the actual final Host3 and private Session to the native A8 proof.
    ///
    /// The returned original borrows these same completed SDK/model/Session
    /// owners. Its constructor independently rejoins Source22 financial
    /// affinity, bound final-query horizon, A7 ancestry and true Root48; no
    /// decoded response or retained comparison tuple can construct it alone.
    ///
    /// # Errors
    /// Retains a repeated call, incomplete query, changed private Session,
    /// Source/Root currentness or canonical final-population failure.
    pub fn borrow_stop_cleanup_completion_once_v1<'held>(
        &'held mut self,
        source: &mut aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &aos_sandbox_controller_domain::Journal,
        root: aos_sandbox_controller_domain::normal_root::RootStopCleanupClientCompletedBorrowV1<'held>,
        session: &'held DormantAuthenticatedBrokerSessionV1,
    ) -> Result<aos_sandbox_controller_domain::controller_lifecycle_stop::StopCleanupCompletionOriginalV1<'held>,
        OutputPreparationClosedV1> {
        if self.proof_entered {
            self.proof_closed.get_or_insert(OutputPreparationClosedV1);
            source.retain_cold_sdk_refusal_v1();
            return Err(OutputPreparationClosedV1);
        }
        self.proof_entered = true;
        if self.original.reentry.is_some()
            || !matches!(self.original.final_post, Some(Ok(())))
            || !matches!(self.original.model_checked, Some(Ok(()))) {
            self.proof_closed.get_or_insert(OutputPreparationClosedV1);
            source.retain_cold_sdk_refusal_v1();
            return Err(OutputPreparationClosedV1);
        }
        let answer = match self.original.answer.as_ref() {
            Some(answer) => answer,
            None => {
                self.proof_closed.get_or_insert(OutputPreparationClosedV1);
                source.retain_cold_sdk_refusal_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        let decoded = answer.decoded_model_original_v2();
        let journal = match session.0.operator_reconciliation_inventory_journal_v2(decoded.method_v2()) {
            Ok(journal) => { self.proof_session = Some(Ok(())); journal }
            Err(cause) => {
                self.proof_session = Some(Err(cause));
                source.retain_cold_sdk_refusal_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        match source.borrow_stop_cleanup_completion_once_v1(controller, root, journal,
            answer.outcome_v1(), decoded) {
            Ok(proof) => Ok(proof),
            Err(cause) => {
                self.proof_native = Some(cause);
                source.retain_cold_sdk_refusal_v1();
                Err(OutputPreparationClosedV1)
            }
        }
    }

    /// Borrows the exact immutable signed outcome after positive SDK disposal.
    #[must_use]
    pub fn outcome_v1(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1> {
        self.decoded_model_v1()?;
        Some(self.original.answer.as_ref()?.outcome_v1())
    }

    /// Borrows the sole retained decoded body and its exact packet association.
    #[must_use]
    pub fn decoded_model_v1(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2> {
        if self.original.reentry.is_some() || !matches!(self.original.final_post, Some(Ok(())))
            || !matches!(self.original.model_checked, Some(Ok(()))) { return None; }
        Some(self.original.answer.as_ref()?.decoded_model_original_v2())
    }

    /// Borrows the real first SDK cause beside its same actual Session.
    pub fn failure_v1<'cause>(
        &'cause self,
        session: &'cause DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        self.original.failure_v1(session)
            .or_else(|| self.proof_session.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.proof_native.as_ref().map(|cause| cause as _))
            .or_else(|| self.proof_closed.as_ref().map(|cause| cause as _))
    }
}
