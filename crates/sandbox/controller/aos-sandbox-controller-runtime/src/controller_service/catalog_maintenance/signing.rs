//! Keeps Maintenance's existing fixed key and actual returned signature resident.
//!
//! Only the genuine same-F Root borrower enters the shared key expansion.
//! Independent posts run after every reached preparation or signing failure.
//! Positive crypto scratch remains here until the enclosing whole M retirement.

use crate::controller_service::plan_signer::{
    ControllerBrokerPlanSignerError, ControllerBrokerPlanSignerV1,
};
use aos_sandbox_controller_domain::ControllerCatalogMaintenanceSigningBorrowV3;
use aos_sandbox_broker::prepared_plan_signing::{
    PreparedBrokerPlanCompletionErrorV1, PreparedBrokerPlanSigningV1,
};
use aos_sandbox_model::model::SignatureBytes;
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;

type Cause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
enum First {
    Inputs,
    Preparation,
    Key,
    Completion,
    After,
    Reentry,
}

#[derive(Default)]
pub(super) struct MaintenanceStorageSigningOriginalV3 {
    inputs: Option<Result<(), ControllerBrokerPlanSignerError>>,
    key: Option<Result<PreparedBrokerPlanSigningV1, Cause>>,
    signature: Option<SignatureBytes>,
    completion: Option<Result<(), PreparedBrokerPlanCompletionErrorV1>>,
    body: Option<Result<(), Cause>>,
    after: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    first: Option<First>,
    entered: bool,
}

impl MaintenanceStorageSigningOriginalV3 {
    pub(super) fn sign_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceSigningBorrowV3<'_, '_>,
        verifier: &OwnershipAuthorityVerifier,
        signer: &ControllerBrokerPlanSignerV1,
    ) -> Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        self.body = Some((|| -> Result<(), Cause> {
            let (authority, scope) = match signer.create_plan_inputs_v1() {
                Ok(inputs) => {
                    self.inputs = Some(Ok(()));
                    inputs
                }
                Err(error) => {
                    self.inputs = Some(Err(error));
                    self.first = Some(First::Inputs);
                    return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict.into());
                }
            };
            loan.prepare_once_v3(verifier, authority, scope)?;
            self.key = Some(signer.prepare_original_maintenance_storage_plan_v3(loan));
            let key = match self.key.as_mut().and_then(|result| result.as_mut().ok()) {
                Some(key) => key,
                None => {
                    self.first = Some(First::Key);
                    return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict.into());
                }
            };
            let message = key.key_message_loan()?;
            let now = loan.final_signing_clock_once_v3()?;
            self.signature = Some(message.sign());
            let signature = self
                .signature
                .as_ref()
                .ok_or(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict)?;
            let signed = match key.complete_once(signature, now.wall_seconds()) {
                Ok(signed) => {
                    self.completion = Some(Ok(()));
                    signed
                }
                Err(error) => {
                    self.completion = Some(Err(error));
                    self.first = Some(First::Completion);
                    return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict.into());
                }
            };
            loan.retain_signed_once_v3(signed)?;
            Ok(())
        })());
        let body_succeeded = matches!(self.body, Some(Ok(())));
        if !body_succeeded {
            self.first.get_or_insert(First::Preparation);
        }

        // This concrete borrower was entered before the body. Neither a
        // missing fixed input nor key/message/clock/signature refusal skips
        // its two native after destinations or unchanged-cutoff comparison.
        self.after = Some(loan.finish_once_v3(body_succeeded));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_some() {
            return Err(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Inputs => self.inputs.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Key => self
                .key
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            First::Completion => self
                .completion
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Preparation => self
                .body
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            First::After => self.after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry => None,
        }
    }
}
