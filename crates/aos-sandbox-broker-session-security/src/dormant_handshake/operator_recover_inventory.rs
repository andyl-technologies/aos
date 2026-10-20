//! Retains the real Recover Inventory18 exchange beside its whole cold Session.
//!
//! The installed caller parks this inert owner before entry. The sole shared
//! Inventory engine borrows the genuine Recover source/C interval; its complete
//! entered request, raw IO, model and independent posts move back here before
//! that short native loan ends. An answer remains historical observation DATA.

use super::*;
mod reconciliation;
mod maintenance;
pub use reconciliation::{OperatorReconciliationInventoryOriginalV2, OperatorStopCleanupInventoryOriginalV1, OperatorStopCleanupSourceInventoryOriginalV1};
/// Retains maintenance queries through the same owning Inventory driver.
#[doc(hidden)]
pub type ControllerCatalogMaintenanceInventoryOriginalV2 = OperatorRecoverStorageInventoryOriginalV1;
use std::error::Error;
use aos_sandbox::{OperatorCreateRecoveryLoanV1, JournalError};
use crate::handshake::output_registration_continuation::{
    OperatorRecoverInventoryClientKernelV1, OperatorRecoverInventoryBorrowFailureV1, ControllerInventoryQueryOriginalsV1,
    DeleteInventoryAnswerOriginalsV1, DeleteInventoryModelV1,
    OutputPreparationClosedV1, StoragePreparationClientProgressV1,
};

/// Retains one authorized Recover's signed Inventory18 query and reached errors.
///
/// Empty construction performs no IO or financial admission. The same whole
/// outer Session remains with its caller through both query outcomes and the
/// independently owed enclosing Source/C posts. It never completes old Apply.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the whole entered query beside its original Recover and Session"]
pub struct OperatorRecoverStorageInventoryOriginalV1 {
    entered: bool,
    cold: Option<Result<(), BrokerSessionSecurityError>>,
    shape: Option<Result<aos_sandbox::DeleteInventorySecurityShapeDataV1, JournalError>>,
    admission: Option<Result<(), OperatorRecoverInventoryBorrowFailureV1>>,
    preparation: Option<Result<(), OutputPreparationClosedV1>>,
    final_post: Option<Result<(), OutputPreparationClosedV1>>,
    retained: Option<ControllerInventoryQueryOriginalsV1>,
    answer: Option<DeleteInventoryAnswerOriginalsV1>,
    model_checked: Option<Result<(), BrokerSessionSecurityError>>,
    reentry: Option<BrokerSessionSecurityError>,
    root_binding: Option<Result<(), BrokerSessionSecurityError>>,
}

impl OperatorRecoverStorageInventoryOriginalV1 {
    /// Lends the actual completed first-local predecessor for residual entry.
    ///
    /// This rejoins the same private Session Journal, captured signed18/model,
    /// complete Recover/Root/Source originals and exact terminal joint4. It
    /// performs no IO, allocation, retirement or authority/enrollment change.
    /// Fresh physical reconciliation and native enrollment remain downstream.
    ///
    /// # Errors
    /// Refuses missing/changed SDK/native custody, another current C/Source cut
    /// or a state outside the single stopped-Create/no-active-resource subset.
    #[doc(hidden)]
    pub fn borrow_first_local_stopped_predecessor_v1<'completed>(
        &'completed self, original: &'completed aos_sandbox::OperatorCreateRecoveryOriginalV1,
        controller: &aos_sandbox::Journal,
        source: &aos_sandbox::source_domain::ProtectedSourceDomainJournalOwnerV1,
        session: &'completed DormantAuthenticatedBrokerSessionV1,
    ) -> Result<aos_sandbox::OperatorRecoveredStoppedCreateSeedV1<'completed>, aos_sandbox::OperatorCreateRecoveryClosedV1> {
        let closed = aos_sandbox::OperatorCreateRecoveryClosedV1;
        let journal = session.0.operator_recover_inventory_journal_v1().map_err(|_| closed)?;
        let outcome = self.outcome_v1().ok_or(closed)?;
        let (inventory, _) = self.inventory_v1().ok_or(closed)?;
        original.borrow_first_local_stopped_predecessor_v1(controller, source, journal, outcome, inventory)
    }

    /// Connects only the completed actual signed18 owner to its same Root flight.
    ///
    /// The private Session Journal stays borrowed from the same outer capsule;
    /// no public Journal/raw outcome adopter is exposed to Runtime.
    ///
    /// # Errors
    /// Refuses incomplete query/Session custody or the real Root exchange. The
    /// caller still parks the whole Root owner before all enclosing posts.
    #[doc(hidden)]
    pub fn observe_root_finality_once_v1(&mut self,
        loan: &mut OperatorCreateRecoveryLoanV1<'_, '_>, controller: &aos_sandbox::Journal,
        session: &DormantAuthenticatedBrokerSessionV1,
        root: &mut aos_sandbox::normal_root::RootFinalityRecoverClientOriginalV1,
    ) -> Result<(), aos_sandbox::normal_root::RootFinalityRecoverClientClosedV1> {
        let closed = aos_sandbox::normal_root::RootFinalityRecoverClientClosedV1;
        if self.root_binding.is_some() || self.outcome_v1().is_none() {
            self.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            loan.retain_storage_sdk_refusal_once_v1();
            return Err(closed);
        }
        let journal = match session.0.operator_recover_inventory_journal_v1() {
            Ok(journal) => { self.root_binding = Some(Ok(())); journal }
            Err(cause) => {
                self.root_binding = Some(Err(cause));
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(closed);
            }
        };
        let outcome = self.outcome_v1().ok_or(closed)?;
        root.observe_once_v1(loan, controller, journal, outcome)
    }

    /// Queries the actual new Inventory18-only Session under its original loan.
    ///
    /// # Errors
    /// Retains failed cold association, admission, request, IO, signed model or
    /// independent final native post. The caller must still perform the paid
    /// enclosing Source-after, C-after and final original-clock observations.
    pub fn observe_once_v1(&mut self, loan: &mut OperatorCreateRecoveryLoanV1<'_, '_>,
        cold: &OperatorRecoverStorageSessionOpenV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.entered {
            self.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            loan.retain_storage_sdk_refusal_once_v1();
            return Err(OutputPreparationClosedV1);
        }
        self.entered = true;
        // No Session is unwrapped or replaced. This actual cold owner rejoins
        // its retained transport cookie, native receiver and endpoint in place.
        let mut completed = match cold.borrow_completed_kernel_session_v1(&mut session.0) {
            Ok(completed) => {
                self.cold = Some(Ok(()));
                completed
            }
            Err(cause) => {
                self.cold = Some(Err(cause));
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        self.shape = Some(OperatorRecoverInventoryClientKernelV1::security_shape_v1());
        let shape = match self.shape.as_ref() {
            Some(Ok(shape)) => *shape,
            _ => {
                loan.retain_storage_sdk_refusal_once_v1();
                return Err(OutputPreparationClosedV1);
            }
        };
        let (receiving, inner) = completed.reborrow_v1();
        let native = match OperatorRecoverInventoryClientKernelV1::borrow_native_once_v1(
            loan, receiving, inner, shape,
        ) {
            Ok(native) => {
                self.admission = Some(Ok(()));
                native
            }
            Err(cause) => {
                self.admission = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        self.drive_prepaid_kernel_v2(OperatorRecoverInventoryClientKernelV1::retain_prepaid(native), inner)
    }

    fn drive_prepaid_kernel_v2(&mut self,
        mut kernel: crate::handshake::output_registration_continuation::ControllerInventoryClientKernelV1<
            aos_sandbox::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>>,
        inner: &mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.preparation = Some(kernel.prepare_once(inner));
        let mut committed = false;
        if matches!(self.preparation, Some(Ok(()))) {
            loop {
                match kernel.advance_once(inner) {
                    StoragePreparationClientProgressV1::Pending
                    | StoragePreparationClientProgressV1::Sent => {}
                    StoragePreparationClientProgressV1::Committed => {
                        committed = true;
                        break;
                    }
                    StoragePreparationClientProgressV1::Closed => break,
                }
            }
        }
        // This is unconditional after entered preparation, including a refused
        // primary. The enclosing Source/C posts have separate owning slots.
        self.final_post = Some(kernel.finish_native_once(inner));
        if committed && matches!(self.final_post, Some(Ok(()))) {
            match kernel.try_finish_positive_once(inner) {
                Ok(answer) => {
                    let method = answer.outcome_v1().request().method();
                    let model_matches = matches!((method, answer.model_v1()),
                        (BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES, DeleteInventoryModelV1::Storage(_, _))
                        | (BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME, DeleteInventoryModelV1::Host(_))
                        | (BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS, DeleteInventoryModelV1::Mount(_))
                        | (BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES, DeleteInventoryModelV1::Network(_)));
                    self.model_checked = Some(if model_matches && answer.decoded_model_original_v2().method_v2() == method {
                        Ok(())
                    } else {
                        Err(BrokerSessionSecurityError::Currentness)
                    });
                    self.answer = Some(answer);
                    if matches!(self.model_checked, Some(Ok(()))) {
                        Ok(())
                    } else {
                        Err(OutputPreparationClosedV1)
                    }
                }
                Err(kernel) => {
                    self.retained = Some(kernel.into_retained_query_v1());
                    Err(OutputPreparationClosedV1)
                }
            }
        } else {
            // Return all SDK originals before the short loan drops. Its actual
            // native state stays inline on the same upper Recover original.
            self.retained = Some(kernel.into_retained_query_v1());
            Err(OutputPreparationClosedV1)
        }
    }

    /// Borrows the complete validated Storage inventory as historical DATA.
    ///
    /// This exposes no Apply completion, lease, native reader or mutation grant.
    #[must_use]
    pub fn inventory_v1(&self) -> Option<(&aos_sandbox_protocol::ValidatedStorageInventory,
        &aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse)> {
        if self.reentry.is_some() || !matches!(self.final_post, Some(Ok(())))
            || !matches!(self.model_checked, Some(Ok(()))) {
            return None;
        }
        match self.answer.as_ref()?.model_v1() {
            DeleteInventoryModelV1::Storage(validated, raw) => Some((validated, raw)),
            _ => None,
        }
    }

    /// Borrows the exact signed request/outcome retained after positive disposal.
    ///
    /// Its request carries the original random ID, immutable deadline and Session
    /// binding. Independent Root verification still reads its own physical files.
    #[must_use]
    pub fn outcome_v1(&self) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1> {
        self.inventory_v1()?;
        Some(self.answer.as_ref()?.outcome_v1())
    }

    /// Borrows the actual verified Inventory18-only negotiated endpoints.
    ///
    /// This historical comparison DATA grants no current Session or cold opener.
    #[must_use]
    pub fn negotiated_endpoints_v1(&self)
        -> Option<&aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1> {
        self.inventory_v1()?;
        self.answer.as_ref()?.recover_transcript_data_v1()
    }

    /// Returns the actual completed native NEXT/device/inode/end and protected cut.
    ///
    /// Both values come from this retained positive observation. They cannot
    /// settle the earlier Apply head or replace independent native Root reads.
    #[must_use]
    pub fn completed_boundary_data_v2(&self)
        -> Option<((u64, u64, u64, u64), (u64, [u8; 32]))> {
        self.inventory_v1()?;
        let answer = self.answer.as_ref()?;
        Some((answer.native_boundary_data_v2(), answer.protected_cut_data_v2()))
    }

    /// Borrows the actual SDK primary while the same whole Session remains held.
    ///
    /// Native-first causes stay on the actual Recover original and are selected
    /// by its existing diagnostic predicate rather than replaced with this view.
    #[must_use]
    pub fn failure_v1<'cause>(&'cause self, session: &'cause DormantAuthenticatedBrokerSessionV1)
        -> Option<&'cause (dyn Error + 'static)> {
        self.cold.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.shape.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.admission.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.retained.as_ref().and_then(|original| original.failure_with_session_v1(&session.0, None)))
            .or_else(|| self.model_checked.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.preparation.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.final_post.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.root_binding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

pub(crate) fn operator_recover_inventory_coordinates_v1(
    session: &handshake::DormantAuthenticatedBrokerSessionV1,
    original: &aos_sandbox::ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>,
) -> Result<DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
    let (request_id, deadline_boottime_nanoseconds, maximum_response_bytes, protocol_version, audience) =
        handshake::operator_recover_inventory_coordinates_v1(session, original)?;
    Ok(DormantBrokerRequestCoordinatesV1 {
        request_id, deadline_boottime_nanoseconds, maximum_response_bytes, protocol_version, audience,
    })
}
