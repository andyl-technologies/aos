//! Retains the actual Core loan and both signed Storage flights in Runtime.
//!
//! The private Journal scope temporarily lends its SAME C23 original. The
//! complete return is attempted before any hook Result is exposed, including
//! association, send, receive, schema, currentness and debit failures.

use super::*;
use aos_sandbox_controller_domain::{CreateProvisioningStorageIoOriginalV1,
    CreateProvisioningStorageIoErrorV1, PreparedAuthorityEffectV1, ReconcilerError};
use aos_sandbox_controller_domain::reconciler::{AuthorityEffectObservationV1, EffectFailure, ValidatedAuthorityEffectReceiptV1};
use aos_sandbox_broker_session_security::controller_composition::{
    OutputPreparationClosedV1 as StorageProvisioningSessionIoClosedV1,
    StorageProvisioningSessionIoOriginalV1,
};

struct ObserveOriginalsV1 {
    taken: Option<Result<CreateProvisioningStorageIoOriginalV1, CreateProvisioningStorageIoErrorV1>>,
    result: Option<Result<AuthorityEffectObservationV1, CreateProvisioningStorageIoErrorV1>>,
    returned: Option<Result<(), CreateProvisioningStorageIoErrorV1>>,
    issued: bool,
}

pub(super) struct StorageIoOriginalsV1 {
    observe: ObserveOriginalsV1,
    pub(super) flights: StorageProvisioningSessionIoOriginalV1,
    taken: Option<Result<CreateProvisioningStorageIoOriginalV1, CreateProvisioningStorageIoErrorV1>>,
    borrowed: Option<Result<(), CreateProvisioningStorageIoErrorV1>>,
    apply: Option<Result<(), StorageProvisioningSessionIoClosedV1>>,
    inventory: Option<Result<(), StorageProvisioningSessionIoClosedV1>>,
    returned: Option<Result<(), CreateProvisioningStorageIoErrorV1>>,
    receipt: Option<Result<ValidatedAuthorityEffectReceiptV1, ReconcilerError>>,
    post_shape: Option<Result<aos_sandbox_controller_domain::StorageProvisioningSessionPostShapeDataV1, ResourceReservationErrorV1>>,
    pub(super) selected_original: bool,
    issued: bool,
}

impl StorageIoOriginalsV1 {
    pub(super) fn new() -> Self {
        Self { observe: ObserveOriginalsV1 { taken: None, result: None, returned: None, issued: false },
            flights: StorageProvisioningSessionIoOriginalV1::new(), taken: None,
            borrowed: None, apply: None, inventory: None, returned: None,
            receipt: None, post_shape: None, selected_original: false, issued: false }
    }

    fn post_shape_v1(&mut self) -> Result<aos_sandbox_controller_domain::StorageProvisioningSessionPostShapeDataV1,
        OriginalCreateProvisioningClosedV1> {
        if self.post_shape.is_none() {
            self.post_shape = Some((|| {
                use aos_sandbox_model::ResourceDimension as D;
                let demand = StorageProvisioningSessionIoOriginalV1::retained_post_receiving_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let allowed = ResourceVector::ZERO.with(D::MemoryBytes, demand.get(D::MemoryBytes))
                    .with(D::OpenFiles, demand.get(D::OpenFiles));
                if demand != allowed { return Err(ResourceReservationErrorV1::Conflict); }
                Ok(aos_sandbox_controller_domain::StorageProvisioningSessionPostShapeDataV1 {
                    receiving_bytes: usize::try_from(demand.get(D::MemoryBytes))
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                    open_files: usize::try_from(demand.get(D::OpenFiles))
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                })
            })());
        }
        self.post_shape.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(OriginalCreateProvisioningClosedV1)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.post_shape.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.observe.taken.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.observe.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.observe.returned.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.taken.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.borrowed.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.flights.failure())
            .or_else(|| self.returned.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.receipt.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}

impl OriginalCreateProvisioningIssuerV1 {
    pub(in crate::controller_service::effects) fn observe_storage_once_v1(&mut self, operation: OperationId, step: u32,
        prepared: &PreparedAuthorityEffectV1, controller: &mut Journal,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        let refused = || EffectFailure::Permanent(
            "the original provisioning dispatch observation is closed".to_owned());
        if !self.in_core || self.storage_io.observe.taken.is_some()
            || self.storage_io.observe.issued {
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first.get_or_insert(First::Closed);
            return Err(refused());
        }
        let io = &mut self.storage_io;
        let post = match io.post_shape_v1() {
            Ok(post) => post,
            Err(_) => {
                self.first.get_or_insert(First::StorageIo);
                return Err(refused());
            }
        };
        io.observe.taken = Some(controller.take_original_provisioning_storage_io_v1(
            operation, step, prepared, post));
        if let Some(Ok(original)) = io.observe.taken.as_mut() {
            io.observe.result = Some(match original.borrow_once_v1(controller, prepared) {
                Ok(mut loan) => loan.observe_unissued_storage_apply_once_v1(prepared),
                Err(cause) => Err(cause),
            });
            io.observe.returned = Some(controller.return_original_provisioning_storage_io_v1(original));
        }
        if !matches!(io.observe.result, Some(Ok(_)))
            || !matches!(io.observe.returned, Some(Ok(()))) {
            io.selected_original = controller.original_provisioning_storage_io_failure_v1().is_some();
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first.get_or_insert(First::StorageIo);
            return Err(refused());
        }
        // Only the actual consumed prior-turn Core proof can yield Absent.
        // Empty in-memory fields and a cold restart never enter that producer.
        io.observe.issued = true;
        match io.observe.result.take() {
            Some(Ok(observation)) => Ok(observation),
            _ => std::process::abort(),
        }
    }

    pub(super) fn apply_storage_once_v1(&mut self, operation: OperationId, step: u32,
        prepared: &PreparedAuthorityEffectV1, sessions: &mut ControllerBrokerSessions,
        controller: &mut Journal,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        let refused = || EffectFailure::Permanent(
            "the original provisioning Storage IO owner retains a refusal".to_owned());
        if !self.in_core || self.storage_io.taken.is_some() || self.storage_io.issued {
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first.get_or_insert(First::Closed);
            return Err(refused());
        }
        let io = &mut self.storage_io;
        let post = match io.post_shape_v1() {
            Ok(post) => post,
            Err(_) => {
                self.first.get_or_insert(First::StorageIo);
                return Err(refused());
            }
        };
        io.taken = Some(controller.take_original_provisioning_storage_io_v1(
            operation, step, prepared, post));
        if let Some(Ok(original)) = io.taken.as_mut() {
            match original.borrow_once_v1(controller, prepared) {
                Ok(mut loan) => {
                    if let Some(storage) = sessions.storage.as_mut() {
                        io.apply = Some(storage.apply_original_provisioning_once_v1(
                            &mut io.flights, &mut loan, prepared));
                        if matches!(io.apply, Some(Ok(()))) {
                            io.inventory = Some(storage.inventory_original_provisioning_once_v1(
                                &mut io.flights, &mut loan, prepared));
                        }
                    }
                    io.borrowed = Some(Ok(()));
                }
                Err(cause) => io.borrowed = Some(Err(cause)),
            }
            // No healthy gate may suppress this handback after a refusal.
            // The returned owner itself retains a failed handback's original.
            io.returned = Some(controller.return_original_provisioning_storage_io_v1(original));
        }
        if !matches!(io.apply, Some(Ok(()))) || !matches!(io.inventory, Some(Ok(())))
            || !matches!(io.returned, Some(Ok(()))) {
            let entry_failed = matches!(io.taken, Some(Err(_)))
                || matches!(io.borrowed, Some(Err(_)));
            io.selected_original = io.flights.has_selected_original_failure_v1()
                || (entry_failed && controller.original_provisioning_storage_io_failure_v1().is_some());
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first.get_or_insert(First::StorageIo);
            return Err(refused());
        }
        io.receipt = Some(match io.flights.completed_apply_outcome_v1() {
            Some(outcome) => prepared.validate_authenticated_outcome(outcome),
            None => Err(ReconcilerError::InvalidExecutorOutput(
                "the original Storage Apply outcome is not complete")),
        });
        if !matches!(io.receipt, Some(Ok(_))) {
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first.get_or_insert(First::StorageIo);
            return Err(refused());
        }
        // The sole validated receipt moves into Core; both authenticated source
        // outcomes/models remain owned in this inline header for Source/Root.
        io.issued = true;
        match io.receipt.take() {
            Some(Ok(receipt)) => Ok(receipt),
            _ => std::process::abort(),
        }
    }
}

impl super::super::ProductionEffectExecutor {
    pub(in crate::controller_service::effects) fn apply_original_provisioning_storage_v1(&mut self,
        operation: OperationId, step: u32, prepared: &PreparedAuthorityEffectV1,
        controller: &mut Journal,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        let mut sessions = self.sessions.lock().map_err(|_| EffectFailure::Permanent(
            "the original provisioning Session owner is unavailable".to_owned()))?;
        self.create_provisioning.apply_storage_once_v1(
            operation, step, prepared, &mut sessions, controller)
    }
}
