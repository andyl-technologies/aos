//! Drives the installed original Create with one stack-held Ready and Session.
//!
//! The coordinator owns actual Inventory/B flights. Private child placement
//! lets it borrow the already-resident Storage Session without a new getter,
//! writer, socket factory or reconstruction from a persisted row. Root Use and
//! cross-owner terminal completion remain distinct typed subsequent phases.

use crate::controller_service::ControllerBrokerSessions;
use aos_sandbox::{OriginalCreateStorageReadyV1, CreateStorageReadyClosedV1,
    CreateStorageRootExchangeClosedV1, CreateStorageControllerDriverShapeDataV1,
    CreateStorageInventoryClosedV1, CreateStorageBundleClosedV1, CreateStorageOwnershipProgressV1};
use aos_sandbox_broker_session_security::controller_composition::{
    OriginalStorageInventoryClientFlightV1, OriginalStorageReadyBundleFlightV1,
    OriginalStorageCreatePreparationFlightV1, original_create_storage_use_security_shape_v1,
    StoragePreparationClientProgressV1, CreateStorageReadyBundleClosedV1,
};
use crate::controller_service::plan_signer::{ControllerBrokerPlanSignerV1,
    ControllerBrokerPlanSignerError};
use super::storage_preparation_client::StoragePreparationClientClosedV1;

#[derive(Debug, thiserror::Error)]
#[error("the installed original Create driver retains an unfinished stage")]
pub(in crate::controller_service) struct OriginalCreateStorageDriverClosedV1;

pub(in crate::controller_service) struct OriginalCreateStorageDriverV1 {
    started: bool,
    terminal: bool,
    admission: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    cache: Option<Result<(), CreateStorageReadyClosedV1>>,
    assignment: Option<Result<(), CreateStorageReadyClosedV1>>,
    ownership: Option<Result<CreateStorageOwnershipProgressV1, CreateStorageReadyClosedV1>>,
    client: Option<Result<(), StoragePreparationClientClosedV1>>,
    inventory_borrow: Option<Result<(), CreateStorageInventoryClosedV1>>,
    prepared: Option<bool>,
    sent: Option<StoragePreparationClientProgressV1>,
    received: Option<StoragePreparationClientProgressV1>,
    wait: Option<bool>,
    bundle_borrow: Option<Result<(), CreateStorageBundleClosedV1>>,
    bundle_result: Option<Result<(), CreateStorageReadyBundleClosedV1>>,
    inputs: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    root: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    invitation: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    cache_current: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    current_turn: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    signer_inputs: Option<Result<(), ControllerBrokerPlanSignerError>>,
    use_reserved: Option<bool>,
    reserved_turn: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    use_cache: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    use_current: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    signing_shape: Option<bool>,
    signing_borrow: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    signing_inputs: Option<Result<(), ControllerBrokerPlanSignerError>>,
    signing_prepared: Option<bool>,
    signed: Option<bool>,
    signing_after: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    signing_finished: Option<bool>,
    signed_recorded: Option<bool>,
    signed_exchange: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    dispatch_bound: Option<Result<(), CreateStorageReadyClosedV1>>,
    request_prepared: Option<bool>,
    request_sent: Option<StoragePreparationClientProgressV1>,
    request_received: Option<StoragePreparationClientProgressV1>,
    request_wait: Option<bool>,
    outcome_recorded: Option<bool>,
    outcome_exchange: Option<bool>,
    use_committed: Option<Result<(), CreateStorageReadyClosedV1>>,
    source_released: Option<Result<(), CreateStorageReadyClosedV1>>,
    cache_released: Option<Result<(), CreateStorageReadyClosedV1>>,
    handoff: Option<Result<(), CreateStorageReadyClosedV1>>,
    root_closed: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    ready_finished: Option<Result<(), CreateStorageReadyClosedV1>>,
    preparation: OriginalStorageCreatePreparationFlightV1,
    inventory: OriginalStorageInventoryClientFlightV1,
    bundle: OriginalStorageReadyBundleFlightV1,
    closed: Option<OriginalCreateStorageDriverClosedV1>,
}

impl OriginalCreateStorageDriverV1 {
    pub(in crate::controller_service) fn new() -> Self {
        Self { started: false, terminal: false, admission: None, cache: None,
            assignment: None, ownership: None, client: None, inventory_borrow: None,
            prepared: None, sent: None, received: None, wait: None, bundle_borrow: None,
            bundle_result: None, inputs: None, root: None, invitation: None, cache_current: None, current_turn: None,
            signer_inputs: None, use_reserved: None, reserved_turn: None,
            use_cache: None, use_current: None,
            signing_shape: None, signing_borrow: None, signing_inputs: None,
            signing_prepared: None, signed: None, signing_after: None, signing_finished: None,
            signed_recorded: None, signed_exchange: None, dispatch_bound: None,
            request_prepared: None,
            request_sent: None, request_received: None, request_wait: None,
            outcome_recorded: None, outcome_exchange: None,
            use_committed: None, source_released: None, cache_released: None,
            handoff: None, root_closed: None, ready_finished: None,
            preparation: OriginalStorageCreatePreparationFlightV1::empty(),
            inventory: OriginalStorageInventoryClientFlightV1::empty(),
            bundle: OriginalStorageReadyBundleFlightV1::empty(), closed: None }
    }

    // Only the installed post-terminal caller can borrow this exact retained
    // proposal and signed result. The view is DATA, not fresh Apply authority.
    pub(in crate::controller_service) fn completed_preparation_data_v1<'held>(
        &'held self,
        intake: &aos_sandbox::CreateContinuationIntakeAttemptV1,
        operation: aos_sandbox_core::OperationId,
    ) -> Result<aos_sandbox_broker_session_security::controller_composition::
        CreateStorageCompletedPreparationDataV1<'held>, OriginalCreateStorageDriverClosedV1>
    {
        if !self.terminal || self.closed.is_some()
            || intake.require_original_create_terminal_v1(operation).is_err()
        {
            return Err(OriginalCreateStorageDriverClosedV1);
        }
        let data = self.preparation.completed_preparation_data_v1(&self.bundle)
            .map_err(|_| OriginalCreateStorageDriverClosedV1)?;
        if data.proposed().operation_id() != operation {
            return Err(OriginalCreateStorageDriverClosedV1);
        }
        Ok(data)
    }

    pub(in crate::controller_service) fn completed_ready_bytes_v1(&self,
        intake: &aos_sandbox::CreateContinuationIntakeAttemptV1,
        operation: aos_sandbox_core::OperationId,
    ) -> Result<&[u8], OriginalCreateStorageDriverClosedV1> {
        self.completed_preparation_data_v1(intake, operation)?;
        self.bundle.encoded_bundle_v1().ok_or(OriginalCreateStorageDriverClosedV1)
    }

    pub(in crate::controller_service) fn begin_original_storage_apply_root_once_v1(&self,
        intake: &aos_sandbox::CreateContinuationIntakeAttemptV1,
        operation: aos_sandbox_core::OperationId,
        loan: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        complete: aos_sandbox_core::ResourceVector,
    ) -> Result<aos_sandbox::normal_root::RootStorageApplyClientOriginalV1,
        aos_sandbox::ResourceReservationErrorV1> {
        self.completed_preparation_data_v1(intake, operation)
            .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        self.preparation.begin_original_storage_apply_root_once_v1(
            &self.bundle, loan, controller, complete,
        )
    }

    fn close<T>(&mut self) -> Result<T, OriginalCreateStorageDriverClosedV1> {
        self.closed.get_or_insert(OriginalCreateStorageDriverClosedV1);
        Err(OriginalCreateStorageDriverClosedV1)
    }

    pub(in crate::controller_service) fn failure_with_ready<'cause>(&'cause self,
        sessions: &'cause ControllerBrokerSessions,
        ready: &'cause OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        let native = || ready.failure();
        if matches!(self.admission, Some(Err(_))) || matches!(self.cache, Some(Err(_)))
            || matches!(self.assignment, Some(Err(_))) || matches!(self.ownership, Some(Err(_))) {
            return native().or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.client, Some(Err(_))) {
            return sessions.storage_preparation_client.as_ref()
                .and_then(|attempt| attempt.failure_with_ready(ready))
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.inventory_borrow.is_some() && (matches!(self.inventory_borrow, Some(Err(_)))
            || self.prepared == Some(false) || self.wait == Some(false)
            || matches!(self.sent, Some(StoragePreparationClientProgressV1::Closed))
            || matches!(self.received, Some(StoragePreparationClientProgressV1::Closed))) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_inventory_failure_with_ready(&self.inventory, ready))
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.bundle_borrow, Some(Err(_))) || matches!(self.bundle_result, Some(Err(_))) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_ready_bundle_failure_with_ready(&self.bundle, ready))
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.inputs, Some(Err(_))) || matches!(self.root, Some(Err(_)))
            || matches!(self.invitation, Some(Err(_))) || matches!(self.cache_current, Some(Err(_))) || matches!(self.current_turn, Some(Err(_))) {
            return ready.original_root_exchange_failure()
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if let Some(Err(cause)) = &self.signer_inputs { return Some(cause); }
        if self.use_reserved == Some(false) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.reserved_turn, Some(Err(_))) || matches!(self.use_cache, Some(Err(_)))
            || matches!(self.use_current, Some(Err(_))) {
            return ready.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if let Some(Err(cause)) = &self.signing_inputs { return Some(cause); }
        if matches!(self.signing_borrow, Some(Err(_))) {
            return ready.original_storage_signing_failure_v1().or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.signing_prepared == Some(false) || self.signed == Some(false)
            || matches!(self.signing_after, Some(Err(_))) || self.signing_finished == Some(false) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.signed_recorded == Some(false) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.signed_exchange, Some(Err(_)))
            || matches!(self.dispatch_bound, Some(Err(_)))
        {
            return ready.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.request_prepared == Some(false) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.request_wait == Some(false)
            || matches!(self.request_sent, Some(StoragePreparationClientProgressV1::Closed))
            || matches!(self.request_received, Some(StoragePreparationClientProgressV1::Closed)) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if self.outcome_recorded == Some(false) || self.outcome_exchange == Some(false) {
            return sessions.storage.as_ref().and_then(|storage| storage.0.session
                .original_create_storage_use_failure_with_ready(&self.preparation, ready))
                .or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.use_committed, Some(Err(_))) || matches!(self.source_released, Some(Err(_)))
            || matches!(self.cache_released, Some(Err(_))) || matches!(self.handoff, Some(Err(_))) {
            return ready.storage_use_original_failure_v1().or_else(|| ready.failure())
                .or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        if matches!(self.root_closed, Some(Err(_))) || matches!(self.ready_finished, Some(Err(_))) {
            return ready.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _));
        }
        self.closed.as_ref().map(|cause| cause as _)
    }

    // This is only a prefix of the one installed continuation. Its caller
    // retains the SAME stack Ready afterwards; this cannot finish an Effect.
    pub(in crate::controller_service) fn run_root_ready_prefix_once(&mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>, sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if self.started { return self.close(); }
        self.started = true;
        let Some(bytes) = std::mem::size_of::<Self>().checked_mul(2) else { return self.close(); };
        self.admission = Some(ready.admit_installed_controller_driver_once(CreateStorageControllerDriverShapeDataV1 {
            // The driver retains only inline result/control destinations.
            // Its actual compiled storage is paid above; it creates no names.
            bytes, metadata_cells: 0,
        }));
        if !matches!(self.admission, Some(Ok(()))) { return self.close(); }
        self.cache = Some(ready.produce_cache_held_once());
        if !matches!(self.cache, Some(Ok(()))) { return self.close(); }
        self.assignment = Some(ready.produce_assignment_planned_once());
        if !matches!(self.assignment, Some(Ok(()))) { return self.close(); }
        loop {
            // The native owner retains every uncertain original Begin/Query,
            // checks the same immutable cutoff, and admits each reached next
            // attempt before growth. This does not reconstruct its claim.
            self.ownership = Some(ready.progress_local_ownership_v1());
            match &self.ownership {
                Some(Ok(CreateStorageOwnershipProgressV1::Verified)) => break,
                Some(Ok(CreateStorageOwnershipProgressV1::Pending | CreateStorageOwnershipProgressV1::Unavailable)) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => return self.close(),
            }
        }
        self.client = Some(sessions.run_original_storage_preparation_client_once(ready));
        if !matches!(self.client, Some(Ok(()))) { return self.close(); }
        let Some(storage) = sessions.storage.as_mut() else { return self.close(); };
        let session = &mut storage.0.session;
        {
            let mut original = match ready.borrow_inventory_once() {
                Ok(original) => { self.inventory_borrow = Some(Ok(())); original }
                Err(cause) => { self.inventory_borrow = Some(Err(cause)); return self.close(); }
            };
            self.prepared = Some(session.prepare_original_create_storage_inventory_once(&mut self.inventory, &mut original));
            if self.prepared != Some(true) { return self.close(); }
            loop {
                self.sent = Some(session.send_original_create_storage_inventory_once(&mut self.inventory, &mut original));
                match self.sent {
                    Some(StoragePreparationClientProgressV1::Sent) => break,
                    Some(StoragePreparationClientProgressV1::Pending) => {
                        self.wait = Some(session.wait_original_create_storage_inventory_once(&mut self.inventory, &mut original));
                        if self.wait != Some(true) { return self.close(); }
                    }
                    _ => return self.close(),
                }
            }
            loop {
                self.received = Some(session.receive_original_create_storage_inventory_once(&mut self.inventory, &mut original));
                match self.received {
                    Some(StoragePreparationClientProgressV1::Committed) => break,
                    Some(StoragePreparationClientProgressV1::Pending) => {
                        self.wait = Some(session.wait_original_create_storage_inventory_once(&mut self.inventory, &mut original));
                        if self.wait != Some(true) { return self.close(); }
                    }
                    _ => return self.close(),
                }
            }
            // Security completes the actual authenticated terminal and Native
            // independent posts before this short purpose borrower ends.
        }
        {
            let mut original = match ready.borrow_bundle_encoding_once() {
                Ok(original) => { self.bundle_borrow = Some(Ok(())); original }
                Err(cause) => { self.bundle_borrow = Some(Err(cause)); return self.close(); }
            };
            self.bundle_result = Some(session.encode_original_create_storage_ready_bundle_once(
                &mut self.bundle, &self.inventory, &mut original));
            if !matches!(self.bundle_result, Some(Ok(()))) { return self.close(); }
        }
        let Some(bytes) = self.bundle.encoded_bundle_v1() else { return self.close(); };
        self.inputs = Some(ready.produce_inputs_ready_once(bytes));
        if !matches!(self.inputs, Some(Ok(()))) { return self.close(); }
        self.root = Some(ready.exchange_root_ready_once(bytes));
        if !matches!(self.root, Some(Ok(()))) { return self.close(); }
        self.invitation = Some(ready.await_root_cache_invitation_once(bytes));
        if !matches!(self.invitation, Some(Ok(()))) { return self.close(); }
        self.cache_current = Some(ready.produce_original_cache_current_once(bytes));
        if !matches!(self.cache_current, Some(Ok(()))) { return self.close(); }
        self.current_turn = Some(ready.exchange_root_current_turn_once());
        if !matches!(self.current_turn, Some(Ok(()))) { return self.close(); }
        // The original same Session and complete bytes stay resident. The
        // subsequent genuine U/Prepare/terminal stages continue on
        // this same Ready; reaching this prefix is never Effect completion.
        Ok(())
    }

    // The actual caller continues inside the SAME stack Ready. Success here
    // means only Root8 signing inputs; it cannot complete an Apply or Effect.
    pub(in crate::controller_service) fn run_root_use_prefix_once(&mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
        signer: &ControllerBrokerPlanSignerV1,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if !matches!(self.current_turn, Some(Ok(()))) || self.signer_inputs.is_some() {
            return self.close();
        }
        let (authority, scope) = match signer.create_plan_inputs_v1() {
            Ok(inputs) => { self.signer_inputs = Some(Ok(())); inputs }
            Err(cause) => { self.signer_inputs = Some(Err(cause)); return self.close(); }
        };
        let Some(storage) = sessions.storage.as_mut() else { return self.close(); };
        self.use_reserved = Some(storage.0.session.reserve_original_create_storage_use_once(
            &mut self.preparation, ready, &self.bundle, authority, scope));
        if self.use_reserved != Some(true) { return self.close(); }

        self.reserved_turn = Some(ready.exchange_root_use_reserved_once());
        if !matches!(self.reserved_turn, Some(Ok(()))) { return self.close(); }
        let Some(bytes) = self.bundle.encoded_bundle_v1() else { return self.close(); };
        self.use_cache = Some(ready.produce_use_cache_current_once(bytes));
        if !matches!(self.use_cache, Some(Ok(()))) { return self.close(); }
        self.use_current = Some(ready.exchange_root_use_current_once());
        if !matches!(self.use_current, Some(Ok(()))) { return self.close(); }
        Ok(())
    }

    // Native owns the long original interval. The actual private signer is
    // reached only inside that interval and every entered path finishes After.
    pub(in crate::controller_service) fn run_storage_signing_prefix_once(&mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
        signer: &ControllerBrokerPlanSignerV1,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if !matches!(self.use_current, Some(Ok(()))) || self.signing_shape.is_some() {
            return self.close();
        }
        let shape = original_create_storage_use_security_shape_v1();
        self.signing_shape = Some(shape.is_some());
        let Some(shape) = shape else { return self.close(); };
        let Some(storage) = sessions.storage.as_mut() else { return self.close(); };
        let session = &mut storage.0.session;
        {
            let mut original = match ready.borrow_original_storage_signing_once(shape) {
                Ok(original) => { self.signing_borrow = Some(Ok(())); original }
                Err(cause) => { self.signing_borrow = Some(Err(cause)); return self.close(); }
            };
            // The public inputs remain borrowed from this same retained signer.
            // No private key is expanded by reading this pure association DATA.
            let inputs = signer.create_plan_inputs_v1();
            match inputs {
                Ok((authority, scope)) => {
                    self.signing_inputs = Some(Ok(()));
                    let preparation = session.prepare_original_create_storage_signing_once(
                        &mut self.preparation, &mut original, &self.bundle,
                        &self.inventory, authority, scope);
                    self.signing_prepared = Some(preparation.is_some());
                    if let Some(preparation) = preparation {
                        // The Session installs the whole carrier Result before
                        // any later native/key/clock/signature operation.
                        let carrier = signer.prepare_create_plan_v1(&original, preparation);
                        self.signed = Some(session.sign_original_create_storage_plan_once(
                            &mut self.preparation, &mut original, carrier));
                    }
                }
                Err(cause) => { self.signing_inputs = Some(Err(cause)); }
            }
            // Do not return between borrowing this actual loan and its owed
            // post. Preparation, key/carrier and raw signature refusal all get
            // the same independently owed full Root/Source/Cache/native After.
            self.signing_after = Some(original.finish_after_once());
        }
        // The long mutable loan has ended after its actual post. This check
        // cannot replace an earlier actual Security/key/signature cause.
        self.signing_finished = Some(session.finish_original_create_storage_signing_once(
            &mut self.preparation, ready));
        if !matches!(self.signing_inputs, Some(Ok(()))) || self.signed != Some(true)
            || !matches!(self.signing_after, Some(Ok(()))) || self.signing_finished != Some(true) {
            return self.close();
        }
        Ok(())
    }

    // Each native owner retains its own before/after observations and actual
    // failed prefix. This driver forwards only the same completed owners.
    pub(in crate::controller_service) fn run_root_signed_dispatch_once(
        &mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if self.signing_finished != Some(true) || self.signed_recorded.is_some() {
            return self.close();
        }

        let Some(storage) = sessions.storage.as_mut() else {
            return self.close();
        };
        self.signed_recorded = Some(storage.0.session.record_original_create_storage_signed_once(
            &mut self.preparation,
            ready,
            &self.bundle,
        ));
        if self.signed_recorded != Some(true) {
            return self.close();
        }

        self.signed_exchange = Some(ready.exchange_root_signed_once());
        if !matches!(self.signed_exchange, Some(Ok(()))) {
            return self.close();
        }

        self.dispatch_bound = Some(ready.produce_original_storage_dispatch_bound_once());
        if !matches!(self.dispatch_bound, Some(Ok(()))) {
            return self.close();
        }
        Ok(())
    }

    pub(in crate::controller_service) fn run_storage_request_reservation_once(
        &mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if !matches!(self.dispatch_bound, Some(Ok(()))) || self.request_prepared.is_some() {
            return self.close();
        }

        let Some(storage) = sessions.storage.as_mut() else {
            return self.close();
        };
        // The same Session wrapper owns request preparation/CAS, actual C8
        // and every entered independently owed Root post before returning.
        // This caller retains the original B, Inventory and whole flight.
        self.request_prepared = Some(storage.0.session.prepare_original_create_storage_request_once(
            &mut self.preparation,
            ready,
            &self.bundle,
            &self.inventory,
        ));
        if self.request_prepared != Some(true) {
            return self.close();
        }
        Ok(())
    }

    pub(in crate::controller_service) fn run_storage_request_exchange_once(
        &mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if self.request_prepared != Some(true) || self.request_sent.is_some() || self.closed.is_some() {
            return self.close();
        }

        let Some(storage) = sessions.storage.as_mut() else {
            return self.close();
        };
        let session = &mut storage.0.session;
        loop {
            self.request_sent = Some(session.send_original_create_storage_request_once(
                &mut self.preparation,
                ready,
            ));
            match self.request_sent {
                Some(StoragePreparationClientProgressV1::Sent) => break,
                Some(StoragePreparationClientProgressV1::Pending) => {
                    self.request_wait = Some(session.wait_original_create_storage_request_once(
                        &mut self.preparation,
                        ready,
                    ));
                    if self.request_wait != Some(true) {
                        return self.close();
                    }
                }
                _ => return self.close(),
            }
        }

        loop {
            self.request_received = Some(session.receive_original_create_storage_request_once(
                &mut self.preparation,
                ready,
            ));
            match self.request_received {
                Some(StoragePreparationClientProgressV1::Committed) => break,
                Some(StoragePreparationClientProgressV1::Pending) => {
                    self.request_wait = Some(session.wait_original_create_storage_request_once(
                        &mut self.preparation,
                        ready,
                    ));
                    if self.request_wait != Some(true) {
                        return self.close();
                    }
                }
                _ => return self.close(),
            }
        }
        Ok(())
    }

    // This advances only C9/Root5; U commit and real releases remain separate.
    pub(in crate::controller_service) fn run_storage_outcome_once(
        &mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if !matches!(self.request_received, Some(StoragePreparationClientProgressV1::Committed))
            || self.outcome_recorded.is_some() || self.closed.is_some() {
            return self.close();
        }
        let Some(storage) = sessions.storage.as_mut() else { return self.close(); };
        let session = &mut storage.0.session;
        self.outcome_recorded = Some(session.record_original_create_storage_outcome_once(
            &mut self.preparation, ready,
        ));
        if self.outcome_recorded != Some(true) { return self.close(); }
        self.outcome_exchange = Some(session.exchange_original_create_storage_outcome_once(
            &mut self.preparation, ready,
        ));
        if self.outcome_exchange != Some(true) { return self.close(); }
        Ok(())
    }

    // The same original U, held writers, Root stream and Session flight remain
    // resident. No positive bank commit is rolled back by a later refusal.
    pub(in crate::controller_service) fn run_storage_terminal_once(&mut self,
        ready: &mut OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Result<(), OriginalCreateStorageDriverClosedV1> {
        if self.outcome_exchange != Some(true) || self.use_committed.is_some() || self.closed.is_some() {
            return self.close();
        }
        self.use_committed = Some(ready.commit_original_storage_use_once());
        if !matches!(self.use_committed, Some(Ok(()))) { return self.close(); }

        self.source_released = Some(ready.release_original_storage_source_once());
        if !matches!(self.source_released, Some(Ok(()))) { return self.close(); }
        self.cache_released = Some(ready.release_original_storage_cache_once());
        if !matches!(self.cache_released, Some(Ok(()))) { return self.close(); }

        self.handoff = Some(ready.produce_original_storage_handoff_once());
        if !matches!(self.handoff, Some(Ok(()))) { return self.close(); }
        self.root_closed = Some(ready.exchange_root_releases_once());
        if !matches!(self.root_closed, Some(Ok(()))) { return self.close(); }

        self.ready_finished = Some(ready.finish_original_create_terminal_once());
        if !matches!(self.ready_finished, Some(Ok(()))) { return self.close(); }
        // This is the actual native Ready seal, including C10, strict Root16,
        // final Cache/control posts and the original association crossing.
        self.terminal = true;
        Ok(())
    }
}

impl Drop for OriginalCreateStorageDriverV1 {
    fn drop(&mut self) {
        if self.started && !self.terminal { std::process::abort(); }
    }
}
