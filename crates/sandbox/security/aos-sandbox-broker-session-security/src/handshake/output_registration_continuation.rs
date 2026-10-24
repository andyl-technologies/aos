//! Retains zero-FD preparation and purpose-fixed client flights on their original Sessions.
//!
//! Two fixed whole receive slots retain original record subjects and failures.
//! Endpoint-local heads are checked independently against the same held writer.
//! A failed, cancelled or unwinding loan closes permanently; neither EAGAIN nor
//! EINTR authorizes another attempted preparation action.

use aos_sandbox_api::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1;
use aos_sandbox_api::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
use aos_sandbox_protocol::storage_output_reserve::continuation::{
    AUTHORIZATION_V1, MAXIMUM_PREPARATION_BYTES_V1, NOMINATION_V1,
    decode_preparation_v1, encode_preparation_v1, matches_original_request_v1,
};

use super::{DormantAuthenticatedBrokerSessionV1, HandshakeReceiveProfileV1};
use crate::BrokerSessionSecurityError;

mod fixed_service;
pub use fixed_service::{FixedServiceRequestOriginalV4, FixedServiceRequestClosedV4};
mod fixed_service_response;
pub use fixed_service_response::{FixedServiceResponseOriginalV4, FixedServiceResponseClosedV4, FixedServiceResponseProgressV4};
mod storage_inventory;
mod delete_inventory;
pub use delete_inventory::{DeleteInventoryModelV1, DeleteInventoryAnswerOriginalsV1, DeleteInventoryNegotiatedPreimagesV2};
pub(crate) use delete_inventory::{DeleteInventoryClientKernelV1, ControllerInventoryQueryOriginalsV1, ControllerInventoryClientKernelV1};
mod storage_io;
mod operator_recover_inventory;
pub(crate) use operator_recover_inventory::{OperatorRecoverInventoryClientKernelV1,
    OperatorRecoverInventoryBorrowFailureV1};
mod storage_provisioning;
pub(crate) use storage_provisioning::MaintenanceStorageSessionIoOriginalV3;
pub use storage_provisioning::{HostExecutionNoApplySessionIoOriginalV2, HostExecutionNoApplyClientSessionBorrowV2, ExecutionAvailabilitySessionIoOriginalV2, ExecutionAvailabilityClientSessionBorrowV2, ControllerCatalogMaintenanceSessionIoOriginalV2, DeleteNetworkApplySessionIoOriginalV4, delete_network_apply_security_shape_v4, delete_network_apply_response_maximum_v4, DeleteMountReapSessionIoOriginalV4, delete_mount_reap_security_shape_v4, delete_mount_reap_response_maximum_v4, DeleteStorageApplySessionIoOriginalV3, delete_storage_apply_security_shape_v3, delete_storage_apply_response_maximum_v3, DeleteStoragePreparationSessionIoOriginalV3, delete_storage_preparation_security_shape_v3, delete_storage_preparation_response_maximum_v3, StorageProvisioningSessionIoOriginalV1, StartHostCatalogSessionIoOriginalV2, StartHostCatalogQualifiedSessionBorrowV2, StartResourceProvisioningSessionIoOriginalV4, StartResourceCompletedModelsOriginalV2, StartResourceSessionCompletionDataV2};
mod storage_create;
pub use storage_create::{OriginalStorageCreatePreparationFlightV1, CreateStorageCompletedPreparationDataV1,
    original_create_storage_use_security_shape_v1};
mod ready_bundle;
pub use ready_bundle::{CreateStorageReadyBundleClosedV1, OriginalStorageReadyBundleFlightV1};
pub use storage_inventory::OriginalStorageInventoryClientFlightV1;

#[derive(Clone, Copy)]
enum FailureSite {
    Witness,
    Protected,
    Encode(usize),
    Send(usize),
    Receive(usize),
    Decode(usize),
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OriginalOutputRequestIdentityV1 {
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
}

impl OriginalOutputRequestIdentityV1 {
    fn from_original(request: &AuthenticatedBrokerMethodRequestV1) -> Self {
        Self {
            request_id: request.request_id(),
            signed_request_digest: request.signed_request_digest(),
            session_binding: request.session_binding(),
        }
    }
}

/// Reports a negative preparation refusal while original custody stays resident.
#[derive(Debug, thiserror::Error)]
#[error("original output preparation is closed; its custody remains resident")]
pub struct OutputPreparationClosedV1;

#[derive(Debug, thiserror::Error)]
#[error("original output witness cause requires its resident Session loan")]
struct OutputWitnessUnavailableV1;

/// Owns original transport results separately from the Session it will borrow.
pub struct OutputPreparationCustodyV1 {
    original_request: Option<OriginalOutputRequestIdentityV1>,
    original_head: Option<[u8; 32]>,
    encoded: [Option<Result<Vec<u8>, ProtocolValidationError>>; 2],
    sent: [Option<Result<(), SeqpacketError>>; 2],
    lifecycle_sent: [Option<super::StorageResponseSendAttemptV1>; 2],
    lifecycle_host: bool,
    packets: [OriginalOutputPacketV1; 2],
    decoded: [Option<Result<StorageOutputRegistrationPreparationV1, ProtocolValidationError>>; 2],
    protected_failure: Option<BrokerSessionSecurityError>,
    first_site: Option<FailureSite>,
    postcheck_debt: Option<BrokerSessionSecurityError>,
    witness_postcheck_debt: bool,
    closed: bool,
}

impl OutputPreparationCustodyV1 {
    /// Prices the fixed Client nomination/authorization side-record interval.
    ///
    /// The Client receives one bounded nomination and sends one bounded
    /// authorization. Neither packet is the separately priced terminal. This
    /// passive shape grants no Session, writer, signed plan or resource payment.
    #[must_use]
    pub fn client_receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let maximum = MAXIMUM_PREPARATION_BYTES_V1;
        let wire = u64::try_from(maximum).ok()?;
        // This schema and its sole nested authorization have only singular
        // bytes/scalars. Unknown groups still use the canonical Buffa bound.
        let protobuf = aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(wire, 0).ok()?;
        let (raw, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::host_execution_response_receive_obligations_v1(maximum)?;
        let bytes = protobuf.checked_mul(2)?
            .checked_add(wire.checked_mul(3)?)?
            .checked_add(u64::try_from(raw).ok()?)?
            .checked_add(u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?)?;
        // The decoded nomination coexists with the constructed authorization,
        // its encoder/re-encoder, and the original raw receive observation.
        Some(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::NetworkBytes, wire.checked_mul(2)?)
            .with(D::OutputBytes, wire))
    }

    pub(crate) fn select_lifecycle_host_v1(
        &mut self,
        receiving: &mut crate::recovery::StorageHostClientReceivingV1<'_, '_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        receiving.require_current_v1()?;
        if self.lifecycle_host || self.original_request.is_some() || self.first_site.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.lifecycle_host = true;
        Ok(())
    }

    /// Creates only empty result custody without request or authority admission.
    pub fn empty() -> Self {
        Self {
            original_request: None,
            original_head: None,
            encoded: std::array::from_fn(|_| None),
            sent: std::array::from_fn(|_| None),
            lifecycle_sent: std::array::from_fn(|_| None),
            lifecycle_host: false,
            packets: std::array::from_fn(|_| OriginalOutputPacketV1::empty()),
            decoded: std::array::from_fn(|_| None),
            protected_failure: None,
            first_site: None,
            postcheck_debt: None,
            witness_postcheck_debt: false,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_site? {
            FailureSite::Witness => Some(&OutputWitnessUnavailableV1),
            FailureSite::Protected => self.protected_failure.as_ref().map(|e| e as &dyn std::error::Error),
            FailureSite::Encode(i) => self.encoded.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            FailureSite::Send(i) => self.lifecycle_sent.get(i).and_then(Option::as_ref).and_then(|sent| sent.failure())
                .or_else(|| self.sent.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error)),
            FailureSite::Receive(i) => Some(self.packets.get(i)?.failure().unwrap_or(&OutputPreparationClosedV1)),
            FailureSite::Decode(i) => self.decoded.get(i)?.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            FailureSite::Closed if self.has_postcheck_debt() => None,
            FailureSite::Closed => Some(&OutputPreparationClosedV1),
        }
    }

    pub(crate) fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match self.first_site? {
            FailureSite::Witness => Some(
                session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1),
            ),
            FailureSite::Receive(index) => Some(
                self.packets.get(index)?.failure_with_session(session)
                    .unwrap_or(&OutputPreparationClosedV1),
            ),
            _ => self.failure(),
        }
    }

    pub(crate) fn postcheck_debt_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_postcheck_debt {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        self.postcheck_debt.as_ref().map(|error| error as &dyn std::error::Error)
    }

    /// Observes whether the original retained postcheck debt is present.
    pub fn has_postcheck_debt(&self) -> bool {
        self.witness_postcheck_debt || self.postcheck_debt.is_some()
    }

    /// Borrows the original decoded preparation record for the requested stage.
    pub fn record(&self, stage: u32) -> Option<&StorageOutputRegistrationPreparationV1> {
        let index = stage_index(stage)?;
        self.decoded[index].as_ref()?.as_ref().ok()
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&BrokerSessionSecurityError> {
        self.postcheck_debt.as_ref()
    }

    fn close(&mut self, site: FailureSite) {
        self.closed = true;
        if self.first_site.is_none() {
            self.first_site = Some(site);
        }
    }
}

/// Borrows the real pending writer/socket; Drop never releases or replaces them.
pub struct HeldOutputPreparationV1<'session> {
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    state: &'session mut OutputPreparationCustodyV1,
    completed_turn: bool,
}

impl<'session> HeldOutputPreparationV1<'session> {
    pub(super) fn begin(
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        state: &'session mut OutputPreparationCustodyV1,
    ) -> Self {
        let identity = OriginalOutputRequestIdentityV1::from_original(request);
        if state.original_request.is_some_and(|original| original != identity) {
            state.close(FailureSite::Closed);
        } else {
            state.original_request = Some(identity);
        }
        Self {
            session,
            state,
            completed_turn: false,
        }
    }

    /// Observes the original protected preparation head under its same loan.
    ///
    /// # Errors
    /// Rejects a closed or mismatched request, changed witnesses/journal head, or an unavailable preparation head.
    pub fn original_head(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<[u8; 32], OutputPreparationClosedV1> {
        self.recheck(request)?;
        self.state.original_head.ok_or(OutputPreparationClosedV1)
    }

    pub(crate) fn recheck(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.state.closed || self.state.original_request != Some(OriginalOutputRequestIdentityV1::from_original(request)) {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        if !self.session.revalidate_output_witnesses() {
            self.state.close(FailureSite::Witness);
            return Err(OutputPreparationClosedV1);
        }
        let result = self.session.owner.hold_output_registration_request(
            request, &self.session.transcript, self.session.socket.peer(),
        ).map(|cut| cut.head_commitment());
        match result {
            Ok(head) => {
                if self.state.original_head.is_some_and(|original| original != head) {
                    self.state.protected_failure = Some(BrokerSessionSecurityError::Currentness);
                    self.state.close(FailureSite::Protected);
                    if !self.session.revalidate_output_witnesses() {
                        self.state.witness_postcheck_debt = true;
                    }
                    return Err(OutputPreparationClosedV1);
                }
                self.state.original_head = Some(head);
                if !self.session.revalidate_output_witnesses() {
                    self.state.close(FailureSite::Witness);
                    return Err(OutputPreparationClosedV1);
                }
                Ok(())
            }
            Err(error) => {
                self.state.protected_failure = Some(error);
                self.state.close(FailureSite::Protected);
                if !self.session.revalidate_output_witnesses() {
                    self.state.witness_postcheck_debt = true;
                }
                Err(OutputPreparationClosedV1)
            }
        }
    }

    /// Sends the original preparation record under its existing borrowed custody.
    ///
    /// # Errors
    /// Rejects wrong or repeated stages, request/head mismatches, encoding/send failures, or failed custody bookends.
    pub fn send(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        record: &StorageOutputRegistrationPreparationV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        let Some(index) = stage_index(record.stage) else {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        };
        if self.state.sent[index].is_some() || self.state.lifecycle_sent[index].is_some()
            || !matches_original_request_v1(record, request)
            || !matches!((request.direction(), record.stage),
                (AuthenticatedBrokerRequestDirectionV1::ServerReceive, NOMINATION_V1)
                | (AuthenticatedBrokerRequestDirectionV1::ClientSend, AUTHORIZATION_V1))
            || (record.stage == NOMINATION_V1
                && record.storage_pending_head != self.state.original_head.ok_or(OutputPreparationClosedV1)?)
            || (record.stage == AUTHORIZATION_V1
                && record.controller_pending_head != self.state.original_head.ok_or(OutputPreparationClosedV1)?)
        {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        self.state.encoded[index] = Some(encode_preparation_v1(record));
        if !matches!(&self.state.encoded[index], Some(Ok(_))) {
            self.state.close(FailureSite::Encode(index));
            return Err(OutputPreparationClosedV1);
        }
        self.recheck(request)?;
        let Some(Ok(packet)) = &self.state.encoded[index] else { return Err(OutputPreparationClosedV1); };
        if self.state.lifecycle_host {
            let _ = self.session.send_storage_packet_retaining_v1(packet, &mut self.state.lifecycle_sent[index]);
        } else {
            self.state.sent[index] = Some(self.session.socket.send(packet));
        }
        let sent = if self.state.lifecycle_host {
            self.state.lifecycle_sent[index].as_ref().is_some_and(|attempt| attempt.is_sent())
        } else {
            matches!(self.state.sent[index], Some(Ok(())))
        };
        if !sent {
            self.state.close(FailureSite::Send(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        self.check_after_action(request);
        if self.state.closed {
            Err(OutputPreparationClosedV1)
        } else {
            Ok(())
        }
    }

    /// Receives the original preparation stage into its same retained destination.
    ///
    /// # Errors
    /// Rejects wrong or repeated stages, receive/decode failures, request mismatches, or failed custody bookends.
    pub fn receive(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        stage: u32,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        let Some(index) = stage_index(stage) else {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        };
        if self.state.packets[index].received.is_some()
            || !matches!((request.direction(), stage),
                (AuthenticatedBrokerRequestDirectionV1::ClientSend, NOMINATION_V1)
                | (AuthenticatedBrokerRequestDirectionV1::ServerReceive, AUTHORIZATION_V1))
        {
            self.state.close(FailureSite::Closed);
            return Err(OutputPreparationClosedV1);
        }
        if !self.state.packets[index].receive_storage_preparation_once_v1(self.session, MAXIMUM_PREPARATION_BYTES_V1) {
            self.state.close(FailureSite::Receive(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        let Some(packet) = self.state.packets[index].payload() else { return Err(OutputPreparationClosedV1); };
        self.state.decoded[index] = Some(decode_preparation_v1(packet, stage));
        let Some(Ok(decoded)) = &self.state.decoded[index] else {
            self.state.close(FailureSite::Decode(index));
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        };
        if !matches_original_request_v1(decoded, request) {
            self.state.close(FailureSite::Closed);
            self.check_after_action(request);
            return Err(OutputPreparationClosedV1);
        }
        self.check_after_action(request);
        if self.state.closed {
            Err(OutputPreparationClosedV1)
        } else {
            Ok(())
        }
    }

    fn check_after_action(&mut self, request: &AuthenticatedBrokerMethodRequestV1) {
        if self.state.original_request != Some(OriginalOutputRequestIdentityV1::from_original(request)) {
            self.state.close(FailureSite::Closed);
            return;
        }
        if !self.session.revalidate_output_witnesses() {
            if self.state.postcheck_debt.is_none() {
                self.state.witness_postcheck_debt = true;
            }
            self.state.close(FailureSite::Closed);
        }
        // This independent check still runs after native or witness failure.
        let result = self.session.owner.hold_output_registration_request(
            request, &self.session.transcript, self.session.socket.peer(),
        ).map(|cut| cut.head_commitment());
        let error = match result {
            Ok(head) if self.state.original_head == Some(head) => None,
            Ok(_) => Some(BrokerSessionSecurityError::Currentness),
            Err(error) => Some(error),
        };
        if let Some(error) = error {
            if self.state.postcheck_debt.is_none() {
                self.state.postcheck_debt = Some(error);
            }
            self.state.close(FailureSite::Closed);
        }
        if !self.session.revalidate_output_witnesses() {
            if self.state.postcheck_debt.is_none() {
                self.state.witness_postcheck_debt = true;
            }
            self.state.close(FailureSite::Closed);
        }
    }

    /// Ends only this successful short loan; it does not retire the request.
    ///
    /// # Errors
    /// Rejects a closed or mismatched request, changed witnesses, or a changed protected preparation head.
    pub fn finish_turn(
        mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.recheck(request)?;
        self.completed_turn = true;
        Ok(())
    }

    /// Lends the actual pending Storage writer to the closed same-F query.
    pub(crate) fn query_logical_output_receiving_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> bool {
        let journal = match self.session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(cause) => {
                self.state.protected_failure = Some(cause);
                self.state.close(FailureSite::Protected);
                return false;
            }
        };
        storage.query_original_execution_output_receiving_v1(output, attempt, receiving, journal, &self.session.socket);
        true
    }

    /// Keeps this exact Storage transport borrow through the actual Host domain.
    pub(crate) fn register_logical_output_with_host_receiving_v1(
        &mut self,
        host: &mut crate::DormantAuthenticatedBrokerSessionV1,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> bool {
        let journal = match self.session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(cause) => {
                self.state.protected_failure = Some(cause);
                self.state.close(FailureSite::Protected);
                return false;
            }
        };
        host.register_original_storage_output_with_host_receiving_v1(committed, storage, output,
            attempt, checks, receiving, journal, &self.session.socket);
        true
    }

    pub(crate) fn prepare_capture_host_body_receiving_v3(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> bool {
        let journal = match self.session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(cause) => { self.state.protected_failure = Some(cause); self.state.close(FailureSite::Protected); return false; }
        };
        storage.prepare_original_capture_ongoing_v3(request, header, output, receiving, journal, &self.session.socket);
        true
    }

    pub(crate) fn capture_with_host_receiving_v3(
        &mut self, host: &mut crate::DormantAuthenticatedBrokerSessionV1,
        committed: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        checks: &mut [Option<Result<(), BrokerSessionSecurityError>>; 2],
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> bool {
        let journal = match self.session.owner.retained_storage_journal_v1() {
            Ok(journal) => journal,
            Err(cause) => { self.state.protected_failure = Some(cause); self.state.close(FailureSite::Protected); return false; }
        };
        host.finish_original_capture_with_host_receiving_v3(committed, storage, output,
            request, checks, receiving, journal, &self.session.socket);
        true
    }

    /// Bookends an external domain action even when its resident result failed.
    /// A later currentness error is debt, not a replacement action cause.
    pub(crate) fn finish_action_turn(
        mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.check_after_action(request);
        if self.state.closed {
            return Err(OutputPreparationClosedV1);
        }
        self.completed_turn = true;
        Ok(())
    }
}

impl Drop for HeldOutputPreparationV1<'_> {
    fn drop(&mut self) {
        if !self.completed_turn {
            self.state.close(FailureSite::Closed);
        }
    }
}

fn stage_index(stage: u32) -> Option<usize> {
    match stage {
        NOMINATION_V1 => Some(0),
        AUTHORIZATION_V1 => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_postcheck_debt_does_not_replace_native_send_cause() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.sent = Some(Err(SeqpacketError::WouldBlock));
        flight.witness_postcheck_debt = true;

        let cause = flight.failure().unwrap();

        assert!(matches!(
            cause.downcast_ref::<SeqpacketError>(),
            Some(SeqpacketError::WouldBlock),
        ));
        assert!(flight.has_postcheck_debt());
    }

    #[test]
    fn later_witness_site_is_not_a_global_cause_priority() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.prepared = Some(Err(BrokerSessionSecurityError::Currentness));
        flight.witness_failure_site = Some(ClientWitnessSiteV1::Send);

        let cause = flight.failure().unwrap();

        assert!(matches!(
            cause.downcast_ref::<BrokerSessionSecurityError>(),
            Some(BrokerSessionSecurityError::Currentness),
        ));
    }

    #[test]
    fn witness_only_postcheck_is_debt_not_a_primary_marker() {
        let mut flight = OriginalOutputClientFlightV1::empty();
        flight.witness_postcheck_debt = true;
        flight.closed = true;

        assert!(flight.failure().is_none());
        assert!(flight.has_postcheck_debt());

        let mut preparation = OutputPreparationCustodyV1::empty();
        preparation.witness_postcheck_debt = true;
        preparation.close(FailureSite::Closed);

        assert!(preparation.failure().is_none());
        assert!(preparation.has_postcheck_debt());
    }

    #[test]
    fn preparation_has_exactly_two_fixed_slots_without_unknown_stage_aliases() {
        assert_eq!(stage_index(NOMINATION_V1), Some(0));
        assert_eq!(stage_index(AUTHORIZATION_V1), Some(1));
        assert_eq!(stage_index(0), None);
        assert_eq!(stage_index(3), None);
        assert_eq!(stage_index(u32::MAX), None);
    }
}

/// Owns the same authenticated client request across preparation and terminal CAS.
/// Protocol engines consume a gate/advancement once; they never take/reinsert a
/// Session or replace a failed request. Complete native records stay resident.
pub struct OriginalOutputClientFlightV1 {
    purpose: OriginalClientFlightPurposeV1,
    pub(crate) coordinates: Option<Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError>>,
    prepared: Option<Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError>>,
    initialization: Option<Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>>,
    successor: Option<Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError>>,
    sent: Option<Result<(), SeqpacketError>>,
    storage_sent: Option<super::StorageResponseSendAttemptV1>,
    terminal_packet: OriginalOutputPacketV1,
    terminal: Option<Result<aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1, aos_sandbox_broker_session_protocol::BrokerSessionProjectionError>>,
    admission: Option<Result<crate::ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError>>,
    pub(crate) committed: Option<crate::ProtectedBrokerOutcomeCommitResultV1>,
    inventory_io_post: Option<Result<(), storage_io::StorageIoNativeFailureV1>>,
    inventory_decode: Option<Result<(), storage_io::StorageIoNativeFailureV1>>,
    inventory_outcome: Option<Result<(), storage_io::StorageIoNativeFailureV1>>,
    protected_failure: Option<BrokerSessionSecurityError>,
    pub(crate) postcheck_debt: Option<BrokerSessionSecurityError>,
    witness_failure_site: Option<ClientWitnessSiteV1>,
    witness_postcheck_debt: bool,
    closed: bool,
}

// Selects the closed protocol purpose of one shared retained flight. The
// The legacy public empty constructor always selects Output. Separate closed
// owners select Preparation or D Inventory only after their genuine admission;
// a caller method list or replacement Session cannot select either purpose.
#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalClientFlightPurposeV1 { Output, StorageHost, StoragePreparation, ControllerInventory, ReconciliationInventory(BrokerMethod), StorageProvisioning, StartResourceProvisioning, DeleteStoragePreparation, CatalogMaintenance, MaintenanceStorage, DeleteStorageApply, DeleteNetwork, DeleteMount, ExecutionAvailability, ExecutionNoApply }

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientWitnessSiteV1 {
    Prepare,
    Initialize,
    Append,
    Send,
    Receive,
    Admission,
    Commit,
}

impl OriginalOutputClientFlightV1 {
    /// Creates only empty result custody without request or authority admission.
    pub fn empty() -> Self {
        Self {
            purpose: OriginalClientFlightPurposeV1::Output,
            coordinates: None,
            prepared: None,
            initialization: None,
            successor: None,
            sent: None,
            storage_sent: None,
            terminal_packet: OriginalOutputPacketV1::empty(),
            terminal: None,
            admission: None,
            committed: None,
            inventory_io_post: None,
            inventory_decode: None,
            inventory_outcome: None,
            protected_failure: None,
            postcheck_debt: None,
            witness_failure_site: None,
            witness_postcheck_debt: false,
            closed: false,
        }
    }

    pub(super) fn select_storage_host_once_v1(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.purpose != OriginalClientFlightPurposeV1::Output || self.prepared.is_some()
            || self.closed || !matches!(self.coordinates, Some(Ok(_)))
        { return Err(BrokerSessionSecurityError::Currentness); }
        self.purpose = OriginalClientFlightPurposeV1::StorageHost;
        Ok(())
    }

    /// Borrows the original parked coordinates or their actual preparation error.
    pub fn coordinates(&self) -> Option<&Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError>> {
        self.coordinates.as_ref()
    }

    /// Borrows the parked terminal commit result without releasing flight custody.
    pub fn committed(&self) -> Option<&crate::ProtectedBrokerOutcomeCommitResultV1> {
        self.committed.as_ref()
    }

    /// Borrows the original authenticated request without releasing its flight.
    pub fn request(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        Some(&self.prepared.as_ref()?.as_ref().ok()?.0)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure_inner(None)
    }

    pub(crate) fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.failure_inner(Some(session)).map(|cause| {
            // Resolve only the actual earliest returned indexed marker. A
            // later independent endpoint/floor failure cannot replace an
            // earlier canonical, signature, history or native primary.
            if let Some(returned) = cause.downcast_ref::<BrokerSessionSecurityError>() {
                session.owner.retained_revalidation_failure_for(returned)
                    .or_else(|| session.owner.retained_storage_floor_revalidation_failure_for(returned))
                    .unwrap_or(cause)
            } else { cause }
        })
    }

    fn failure_inner<'a>(
        &'a self,
        session: Option<&'a DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.coordinates { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Prepare, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.prepared { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Initialize, session) {
            return Some(error);
        }
        match &self.initialization {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Append, session) {
            return Some(error);
        }
        match &self.successor {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Send, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.sent { return Some(error); }
        if let Some(error) = self.storage_sent.as_ref().and_then(|sent| sent.failure()) { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Receive, session) {
            return Some(error);
        }
        let packet_failure = match session {
            Some(session) => self.terminal_packet.failure_with_session(session),
            None => self.terminal_packet.failure(),
        };
        if let Some(error) = packet_failure { return Some(error); }
        if let Some(Err(error)) = &self.terminal { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Admission, session) {
            return Some(error);
        }
        if let Some(Err(error)) = &self.admission { return Some(error); }
        if let Some(error) = self.witness_failure_at(ClientWitnessSiteV1::Commit, session) {
            return Some(error);
        }
        if let Some(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) = &self.committed { return Some(error); }
        self.protected_failure.as_ref().map(|error| error as &dyn std::error::Error)
    }

    fn witness_failure_at<'a>(
        &'a self,
        site: ClientWitnessSiteV1,
        session: Option<&'a DormantAuthenticatedBrokerSessionV1>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_failure_site != Some(site) {
            return None;
        }
        Some(session.and_then(DormantAuthenticatedBrokerSessionV1::output_witness_failure)
            .unwrap_or(&OutputWitnessUnavailableV1))
    }

    pub(crate) fn postcheck_debt_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if self.witness_postcheck_debt {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        self.postcheck_debt.as_ref().map(|error| error as &dyn std::error::Error)
    }

    /// Observes whether the original retained postcheck debt is present.
    pub fn has_postcheck_debt(&self) -> bool {
        self.witness_postcheck_debt || self.postcheck_debt.is_some()
    }

    fn check_witness(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        site: ClientWitnessSiteV1,
        post: bool,
    ) -> bool {
        let current = match self.purpose {
            OriginalClientFlightPurposeV1::ControllerInventory | OriginalClientFlightPurposeV1::ReconciliationInventory(_)
                | OriginalClientFlightPurposeV1::DeleteStoragePreparation | OriginalClientFlightPurposeV1::CatalogMaintenance | OriginalClientFlightPurposeV1::MaintenanceStorage
                | OriginalClientFlightPurposeV1::ExecutionAvailability | OriginalClientFlightPurposeV1::ExecutionNoApply | OriginalClientFlightPurposeV1::DeleteStorageApply | OriginalClientFlightPurposeV1::DeleteNetwork | OriginalClientFlightPurposeV1::DeleteMount =>
                session.revalidate_delete_inventory_witnesses_v1(),
            _ => session.revalidate_output_witnesses(),
        };
        if current { return true; }
        if post {
            if self.postcheck_debt.is_none() {
                self.witness_postcheck_debt = true;
            }
        } else if self.witness_failure_site.is_none() {
            self.witness_failure_site = Some(site);
        }
        self.closed = true;
        false
    }

    /// Parks both independent postchecks even when the preceding action failed.
    fn check_after_transition(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        site: ClientWitnessSiteV1,
    ) -> bool {
        let witness_current = self.check_witness(session, site, true);
        let result = session.owner.revalidate_transport(&session.transcript, session.socket.peer());
        if let Err(error) = result {
            if self.postcheck_debt.is_none() {
                self.postcheck_debt = Some(error);
            }
            self.closed = true;
            self.check_witness(session, site, true);
            return false;
        }
        let after = self.check_witness(session, site, true);
        witness_current && after
    }

    pub(crate) fn prepare(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        envelope: BrokerRequestEnvelope,
    ) -> bool {
        self.prepare_engine(session, envelope, None)
    }

    fn prepare_engine(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        envelope: BrokerRequestEnvelope, original_create_maximum: Option<usize>,
    ) -> bool {
        self.prepare_captured_engine_v1(session, envelope, original_create_maximum, None)
    }

    fn prepare_captured_engine_v1(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        envelope: BrokerRequestEnvelope, original_create_maximum: Option<usize>,
        capture: Option<&mut crate::recovery::ClientRequestOriginalsV1>,
    ) -> bool {
        if self.closed || self.prepared.is_some() { self.closed = true; return false; }
        let Some(Ok(coordinates)) = self.coordinates.as_ref() else { self.closed = true; return false; };
        let coordinates = *coordinates;
        let permitted = match self.purpose {
            OriginalClientFlightPurposeV1::Output => matches!(envelope.method.as_known(),
                Some(BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE)),
            OriginalClientFlightPurposeV1::StorageHost =>
                session.owner.retained_storage_host_journal_v1().is_ok()
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT),
            OriginalClientFlightPurposeV1::StoragePreparation =>
                session.is_original_storage_preparation_profile_v1()
                    && matches!(envelope.method.as_known(),
                        Some(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)),
            OriginalClientFlightPurposeV1::DeleteNetwork =>
                session.owner.delete_inventory_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_NETWORK_APPLY),
            OriginalClientFlightPurposeV1::DeleteMount =>
                session.owner.delete_inventory_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1)
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1),
            OriginalClientFlightPurposeV1::DeleteStorageApply =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY),
            OriginalClientFlightPurposeV1::DeleteStoragePreparation =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG),
            OriginalClientFlightPurposeV1::StorageProvisioning =>
                aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript)
                    && matches!(envelope.method.as_known(), Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)),
            OriginalClientFlightPurposeV1::StartResourceProvisioning =>
                aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(&session.transcript)
                    && matches!(envelope.method.as_known(), Some(BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
                        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
                        | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                        | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                        | BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                        | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG)),
            OriginalClientFlightPurposeV1::MaintenanceStorage =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript)
                    && matches!(envelope.method.as_known(), Some(BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)),
            OriginalClientFlightPurposeV1::CatalogMaintenance =>
                session.owner.catalog_maintenance_client_journal_v2().is_ok()
                    && envelope.method.as_known() == Some(BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG),
            OriginalClientFlightPurposeV1::ExecutionNoApply =>
                envelope.method.as_known().is_some_and(|method| session.require_execution_no_apply_client_v2(method).is_ok()),
            OriginalClientFlightPurposeV1::ExecutionAvailability =>
                session.require_execution_availability_client_v2().is_ok_and(|method| envelope.method.as_known() == Some(method)),
            OriginalClientFlightPurposeV1::ReconciliationInventory(expected) =>
                session.owner.reconciliation_inventory_client_journal_v2(expected).is_ok()
                    && envelope.method.as_known() == Some(expected),
            OriginalClientFlightPurposeV1::ControllerInventory => matches!(
                (session.owner.delete_inventory_client_method_v1(), envelope.method.as_known()),
                (Ok(expected), Some(actual)) if expected == actual,
            ),
        };
        if !permitted { self.closed = true; return false; }
        let Some(method) = envelope.method.as_known() else { self.closed = true; return false; };
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Prepare, false) {
            return false;
        }
        let descriptors = usize::from(
            (boundary.flight.purpose == OriginalClientFlightPurposeV1::StartResourceProvisioning
                && matches!(method, BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG))
            || (boundary.flight.purpose == OriginalClientFlightPurposeV1::CatalogMaintenance
                && method == BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG));
        boundary.flight.prepared = Some(match capture {
            Some(capture) => session.prepare_client_request_retaining_v1(envelope, method, descriptors,
                coordinates.request_id(), coordinates.deadline_boottime_nanoseconds(),
                coordinates.maximum_response_bytes(), capture),
            None => session.prepare_client_request(envelope, method, descriptors, coordinates.request_id(),
                coordinates.deadline_boottime_nanoseconds(), coordinates.maximum_response_bytes()),
        });
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Prepare);
        if !after { return false; }
        let Some(Ok((prepared, initialize))) = &boundary.flight.prepared else { return false; };
        if boundary.flight.purpose == OriginalClientFlightPurposeV1::StoragePreparation
            && prepared.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            && prepared.canonical_packet().len() > aos_sandbox_protocol::fixed_storage_inventory_request_packet_bound_v1()
        {
            boundary.flight.protected_failure = Some(BrokerSessionSecurityError::Currentness);
            return false;
        }
        if original_create_maximum.is_some_and(|maximum| prepared.canonical_packet().len() > maximum) {
            boundary.flight.protected_failure = Some(BrokerSessionSecurityError::Currentness);
            return false;
        }
        let Some(Ok((_, initialize))) = &boundary.flight.prepared else { return false; };
        let initialize = *initialize;
        if initialize {
            if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Initialize, false) {
                return false;
            }
            let Some(Ok((request, _))) = &boundary.flight.prepared else { return false; };
            boundary.flight.initialization = Some(session.initialize_authenticated_request(request));
            let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Initialize);
            if !after { return false; }
            if !matches!(&boundary.flight.initialization, Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::Initialized))) { return false; }
        } else {
            if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Append, false) {
                return false;
            }
            let Some(Ok((request, _))) = &boundary.flight.prepared else { return false; };
            boundary.flight.successor = Some(session.append_authenticated_request(request));
            let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Append);
            if !after { return false; }
            if !matches!(&boundary.flight.successor, Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::Committed))) { return false; }
        }
        boundary.completed = true;
        true
    }

    pub(crate) fn send_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        if self.purpose == OriginalClientFlightPurposeV1::StorageHost {
            return self.send_preparation_once_v1(session) == StoragePreparationClientProgressV1::Sent;
        }
        if self.closed || self.sent.is_some() { self.closed = true; return false; }
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Send, false) {
            return false;
        }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        let Some(request) = boundary.flight.request() else { return false; };
        boundary.flight.sent = Some(session.socket.send(request.canonical_packet()));
        // The actual native send error wins over all later currentness debt.
        let after = boundary.flight.recheck_pending(session, true);
        if !matches!(&boundary.flight.sent, Some(Ok(()))) || !after { return false; }
        boundary.completed = true;
        true
    }

    fn send_preparation_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> StoragePreparationClientProgressV1 {
        self.send_preparation_with_content_v4(session, None)
    }

    fn send_preparation_with_content_v4(&mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        content: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> StoragePreparationClientProgressV1 {
        let selected = match self.purpose {
            OriginalClientFlightPurposeV1::StorageHost => session.owner.retained_storage_host_journal_v1().is_ok(),
            OriginalClientFlightPurposeV1::DeleteNetwork =>
                session.owner.delete_inventory_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
                    && self.request().is_some_and(|request| request.method() == BrokerMethod::BROKER_METHOD_NETWORK_APPLY),
            OriginalClientFlightPurposeV1::DeleteMount =>
                session.owner.delete_inventory_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && session.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1)
                    && self.request().is_some_and(|request| request.method() == BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1),
            OriginalClientFlightPurposeV1::DeleteStorageApply =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && self.request().is_some_and(|request| request.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY),
            OriginalClientFlightPurposeV1::DeleteStoragePreparation =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && session.transcript.protocol() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
                    && session.transcript.audience() == aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                    && self.request().is_some_and(|request| request.method() == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG),
            OriginalClientFlightPurposeV1::StoragePreparation =>
                session.is_original_storage_preparation_profile_v1(),
            OriginalClientFlightPurposeV1::ReconciliationInventory(method) =>
                session.owner.reconciliation_inventory_client_journal_v2(method).is_ok(),
            OriginalClientFlightPurposeV1::ControllerInventory =>
                session.owner.delete_inventory_client_method_v1().is_ok(),
            OriginalClientFlightPurposeV1::StorageProvisioning =>
                aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript),
            OriginalClientFlightPurposeV1::StartResourceProvisioning =>
                aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(&session.transcript),
            OriginalClientFlightPurposeV1::MaintenanceStorage =>
                session.owner.retained_storage_client_journal_v1().is_ok()
                    && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript),
            OriginalClientFlightPurposeV1::CatalogMaintenance =>
                session.owner.catalog_maintenance_client_journal_v2().is_ok(),
            OriginalClientFlightPurposeV1::ExecutionNoApply =>
                self.request().is_some_and(|request| session.require_execution_no_apply_client_v2(request.method()).is_ok()),
            OriginalClientFlightPurposeV1::ExecutionAvailability =>
                session.require_execution_availability_client_v2().is_ok_and(|method| self.request().is_some_and(|request| request.method() == method)),
            OriginalClientFlightPurposeV1::Output => false,
        };
        if !selected || self.closed || self.sent.is_some() || self.storage_sent.is_some() {
            self.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        if !self.check_witness(session, ClientWitnessSiteV1::Send, false)
            || !self.recheck_pending(session, false)
        {
            self.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        let Some(Ok((request, _))) = self.prepared.as_ref() else {
            self.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        };
        let expected_content = (self.purpose == OriginalClientFlightPurposeV1::StartResourceProvisioning
            && matches!(request.method(), BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG))
            || (self.purpose == OriginalClientFlightPurposeV1::CatalogMaintenance
                && request.method() == BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG);
        if content.is_some() != expected_content {
            self.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        let _ = session.send_client_packet_retaining_engine_v4(
            request.canonical_packet(), content, &mut self.storage_sent,
        );
        // Native refusal cannot suppress the independent protected/peer posts.
        let after = self.recheck_pending(session, true);
        if after && self.storage_sent.as_ref().is_some_and(|sent| sent.is_sent()) {
            self.sent = Some(Ok(()));
            StoragePreparationClientProgressV1::Sent
        } else if after && self.storage_sent.as_ref().is_some_and(|sent| sent.is_nonconsuming()) {
            StoragePreparationClientProgressV1::Pending
        } else {
            self.closed = true;
            StoragePreparationClientProgressV1::Closed
        }
    }

    pub(crate) fn receive_terminal_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        self.receive_terminal_with_storage_io_v1::<aos_sandbox_controller_domain::OriginalCreateStorageInventoryV1<'_, '_, '_>>(session, None)
    }

    fn receive_terminal_with_storage_io_v1<N: storage_io::NativeStorageIoV1>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        mut inventory: Option<&mut N>,
    ) -> bool {
        self.receive_terminal_engine_v1(session, inventory, None)
    }

    fn receive_terminal_engine_v1<N: storage_io::NativeStorageIoV1>(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        mut inventory: Option<&mut N>,
        capture: Option<&mut aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1>,
    ) -> bool {
        if self.closed || self.terminal_packet.received.is_some() { self.closed = true; return false; }
        let mut boundary = OutputClientBoundaryV1 { flight: self, completed: false };
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Receive, false) {
            return false;
        }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        let Some(request) = boundary.flight.request() else { return false; };
        let Ok(maximum) = usize::try_from(request.maximum_response_bytes()) else { return false; };
        let received = match boundary.flight.purpose {
            OriginalClientFlightPurposeV1::Output | OriginalClientFlightPurposeV1::StorageHost =>
                boundary.flight.terminal_packet.receive_storage_preparation_once_v1(session, maximum),
            OriginalClientFlightPurposeV1::StoragePreparation | OriginalClientFlightPurposeV1::StorageProvisioning | OriginalClientFlightPurposeV1::StartResourceProvisioning | OriginalClientFlightPurposeV1::CatalogMaintenance | OriginalClientFlightPurposeV1::MaintenanceStorage =>
                boundary.flight.terminal_packet.receive_storage_preparation_once_v1(session, maximum),
            OriginalClientFlightPurposeV1::ControllerInventory | OriginalClientFlightPurposeV1::ReconciliationInventory(_)
                | OriginalClientFlightPurposeV1::DeleteStoragePreparation | OriginalClientFlightPurposeV1::DeleteStorageApply | OriginalClientFlightPurposeV1::DeleteNetwork | OriginalClientFlightPurposeV1::DeleteMount | OriginalClientFlightPurposeV1::ExecutionAvailability | OriginalClientFlightPurposeV1::ExecutionNoApply =>
                boundary.flight.terminal_packet.receive_delete_inventory_once_v1(session, maximum),
        };
        let after = boundary.flight.recheck_pending(session, true);
        if (!received || !after) && boundary.flight.failure_with_session(session).is_some() {
            if let Some(original) = inventory.as_deref_mut() { original.mark_sdk_primary_before_post_v1(); }
        }
        let native_after = if let Some(original) = inventory.as_deref_mut() {
            boundary.flight.inventory_io_post = Some(match original.session_journal_v1(&session.owner) {
                Ok(journal) => original.observe_io_post_once(journal, &session.socket, &session.transcript),
                Err(cause) => {
                    if boundary.flight.protected_failure.is_none() {
                        boundary.flight.protected_failure = Some(cause);
                    }
                    Err(N::closed())
                }
            }.map_err(Into::into));
            matches!(boundary.flight.inventory_io_post, Some(Ok(())))
        } else { true };
        if !received || !after || !native_after {
            if after && native_after && matches!(boundary.flight.purpose,
                OriginalClientFlightPurposeV1::StoragePreparation | OriginalClientFlightPurposeV1::ControllerInventory | OriginalClientFlightPurposeV1::ReconciliationInventory(_) | OriginalClientFlightPurposeV1::StorageProvisioning | OriginalClientFlightPurposeV1::StartResourceProvisioning | OriginalClientFlightPurposeV1::DeleteStoragePreparation | OriginalClientFlightPurposeV1::CatalogMaintenance | OriginalClientFlightPurposeV1::MaintenanceStorage | OriginalClientFlightPurposeV1::DeleteStorageApply | OriginalClientFlightPurposeV1::DeleteNetwork | OriginalClientFlightPurposeV1::DeleteMount | OriginalClientFlightPurposeV1::ExecutionAvailability | OriginalClientFlightPurposeV1::ExecutionNoApply)
                && boundary.flight.terminal_packet.is_nonconsuming_v1()
            {
                // Its actual initial recvmsg refusal remains resident until the
                // genuine owning operation finishes its independent posts.
                boundary.completed = true;
            }
            return false;
        }
        if let Some(original) = inventory.as_deref_mut() {
            if original.finish_positive_io_once().is_err() { return false; }
            let Some(packet) = boundary.flight.terminal_packet.payload() else { return false; };
            boundary.flight.inventory_decode = Some(original.admit_response_decode_once(packet).map_err(Into::into));
            if !matches!(boundary.flight.inventory_decode, Some(Ok(()))) { return false; }
        }
        let Some(packet) = boundary.flight.terminal_packet.payload() else { return false; };
        boundary.flight.terminal = Some(aos_sandbox_broker_session_protocol::decode_canonical_response_v1(packet));
        if !matches!(&boundary.flight.terminal, Some(Ok(_))) { return false; }
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Admission, false) {
            return false;
        }
        let Some(Ok(terminal)) = &boundary.flight.terminal else { return false; };
        let Some(request) = boundary.flight.request() else { return false; };
        if let Some(original) = inventory.as_deref_mut() {
            let reserved = match original.session_stored_v1(&session.owner) {
                Ok(stored) => original.admit_outcome_once(stored, request.canonical_packet(), &terminal.message().body),
                Err(cause) => {
                    if boundary.flight.protected_failure.is_none() {
                        boundary.flight.protected_failure = Some(cause);
                    }
                    Err(N::closed())
                }
            };
            boundary.flight.inventory_outcome = Some(reserved.map_err(Into::into));
            if !matches!(boundary.flight.inventory_outcome, Some(Ok(()))) { return false; }
        }
        let Some(Ok(terminal)) = &boundary.flight.terminal else { return false; };
        let Some(request) = boundary.flight.request() else { return false; };
        let (gate, _) = match session.reopen_broker_outcome(request) {
            Ok(gate) => gate,
            Err(error) => {
                boundary.flight.protected_failure = Some(error);
                boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Admission);
                return false;
            }
        };
        boundary.flight.admission = Some(match capture {
            Some(capture) => gate.admit_outcome_retaining_v1(terminal, capture),
            None => gate.admit_outcome(terminal),
        });
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Admission);
        if !after { return false; }
        if !matches!(&boundary.flight.admission, Some(Ok(crate::ProtectedBrokerOutcomeAdmissionV1::New { .. }))) { return false; }
        if !boundary.flight.recheck_pending(session, false) { return false; }
        if !boundary.flight.check_witness(session, ClientWitnessSiteV1::Commit, false) {
            return false;
        }

        // One-way consumption into the sole outcome writer, not temporary
        // custody removal and reinsertion. Every canonical preimage remains.
        let Some(Ok(crate::ProtectedBrokerOutcomeAdmissionV1::New { advancement })) = boundary.flight.admission.take() else { return false; };
        boundary.flight.committed = Some(session.commit_broker_outcome(advancement));
        let after = boundary.flight.check_after_transition(session, ClientWitnessSiteV1::Commit);
        if !after { return false; }
        if !matches!(&boundary.flight.committed, Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_))) { return false; }
        boundary.completed = true;
        true
    }

    fn recheck_pending(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, post: bool) -> bool {
        let site = if self.terminal.is_some() {
            ClientWitnessSiteV1::Commit
        } else if self.sent.is_some() {
            ClientWitnessSiteV1::Receive
        } else {
            ClientWitnessSiteV1::Send
        };
        let witness_current = self.check_witness(session, site, post);
        if !post && !witness_current { return false; }
        let Some(request) = self.request() else { return false; };
        let result = match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => session.owner.hold_capture_candidate_client_request(
                request, &session.transcript, session.socket.peer(),
            ).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => session.owner.hold_output_registration_request(
                request, &session.transcript, session.socket.peer(),
            ).map(|_| ()),
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => session.owner.hold_storage_output_host_readback(
                request, &session.transcript, session.socket.peer(),
            ).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                if self.purpose == OriginalClientFlightPurposeV1::StoragePreparation
                    && session.is_original_storage_preparation_profile_v1() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                if self.purpose == OriginalClientFlightPurposeV1::DeleteStoragePreparation
                    && session.owner.retained_storage_client_journal_v1().is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                if self.purpose == OriginalClientFlightPurposeV1::DeleteNetwork
                    && session.owner.delete_inventory_client_journal_v1().is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                if self.purpose == OriginalClientFlightPurposeV1::DeleteMount
                    && session.owner.delete_inventory_client_journal_v1().is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                if self.purpose == OriginalClientFlightPurposeV1::DeleteStorageApply
                    && session.owner.retained_storage_client_journal_v1().is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                if self.purpose == OriginalClientFlightPurposeV1::StorageProvisioning
                    && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript) =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
                if self.purpose == OriginalClientFlightPurposeV1::StartResourceProvisioning
                    && aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(&session.transcript) =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                if self.purpose == OriginalClientFlightPurposeV1::MaintenanceStorage
                    && session.owner.retained_storage_client_journal_v1().is_ok()
                    && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&session.transcript) =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
                if self.purpose == OriginalClientFlightPurposeV1::CatalogMaintenance
                    && session.owner.catalog_maintenance_client_journal_v2().is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
                if self.purpose == OriginalClientFlightPurposeV1::ExecutionAvailability
                    && session.require_execution_availability_client_v2().ok() == Some(request.method()) =>
                session.reopen_broker_outcome(request).map(|_| ()),
            method if self.purpose == OriginalClientFlightPurposeV1::ExecutionNoApply
                && session.require_execution_no_apply_client_v2(method).is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            method if matches!(self.purpose, OriginalClientFlightPurposeV1::ReconciliationInventory(expected) if expected == method)
                && session.owner.reconciliation_inventory_client_journal_v2(method).is_ok() =>
                session.reopen_broker_outcome(request).map(|_| ()),
            method if self.purpose == OriginalClientFlightPurposeV1::ControllerInventory
                && session.owner.delete_inventory_client_method_v1().ok() == Some(method) =>
                session.reopen_broker_outcome(request).map(|_| ()),
            _ => return false,
        };
        if let Err(error) = result {
            if post {
                if self.postcheck_debt.is_none() { self.postcheck_debt = Some(error); }
            } else if self.protected_failure.is_none() { self.protected_failure = Some(error); }
            self.check_witness(session, site, true);
            return false;
        }
        let after = self.check_witness(session, site, post);
        witness_current && after
    }
}

struct OutputClientBoundaryV1<'flight> {
    flight: &'flight mut OriginalOutputClientFlightV1,
    completed: bool,
}

impl Drop for OutputClientBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed { self.flight.closed = true; }
    }
}

/// Retains the same writer's prepared, committed and transmitted terminal.
/// Successful local transmission never retires the original request.
pub(crate) struct OriginalOutputServerTerminalV1 {
    prepared: Option<Result<crate::ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError>>,
    pub(crate) committed: Option<crate::ProtectedBrokerOutcomeCommitResultV1>,
    before_commit: Option<Result<(), BrokerSessionSecurityError>>,
    before_send: Option<Result<(), BrokerSessionSecurityError>>,
    sent: Option<Result<(), SeqpacketError>>,
    after_send: Option<Result<(), BrokerSessionSecurityError>>,
    closed: bool,
}

impl OriginalOutputServerTerminalV1 {
    pub(crate) fn empty() -> Self {
        Self {
            prepared: None,
            committed: None,
            before_commit: None,
            before_send: None,
            sent: None,
            after_send: None,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.prepared { return Some(error); }
        if let Some(Err(error)) = &self.before_commit { return Some(error); }
        if let Some(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) = &self.committed { return Some(error); }
        if let Some(Err(error)) = &self.before_send { return Some(error); }
        if let Some(Err(error)) = &self.sent { return Some(error); }
        self.closed.then_some(&OutputPreparationClosedV1 as &dyn std::error::Error)
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&BrokerSessionSecurityError> {
        self.after_send.as_ref()?.as_ref().err()
    }

    pub(crate) fn locally_sent(&self) -> bool {
        !self.closed
            && matches!(&self.sent, Some(Ok(())))
            && matches!(&self.after_send, Some(Ok(())))
    }

    pub(crate) fn prepare_and_commit(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        body: &[u8],
    ) {
        self.prepare_and_commit_engine_v4(session, request, body, false);
    }

    fn prepare_fixed_service_once_v4(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1, body: &[u8],
    ) {
        self.prepare_and_commit_engine_v4(session, request, body, true);
    }

    fn prepare_and_commit_engine_v4(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1, body: &[u8], fixed_service: bool,
    ) {
        if self.closed || self.prepared.is_some() {
            self.closed = true;
            return;
        }
        let mut boundary = OutputServerTerminalBoundaryV1 { terminal: self, completed: false };
        let permitted = if fixed_service {
            matches!(request.method(), BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
                | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES)
                && body.len() <= aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
        } else {
            matches!(request.method(), BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT) && body.len() <= 1024
        };
        if !permitted || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || body.is_empty()
        {
            return;
        }
        let message = aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope {
            request_id: request.request_id().to_vec(),
            method: request.method().into(),
            body: body.to_vec(),
            ..Default::default()
        };
        boundary.terminal.prepared = Some(session.prepare_broker_outcome(request, message));
        if !matches!(&boundary.terminal.prepared, Some(Ok(_))) { return; }

        // The same original pending writer is checked after canonical signing
        // and immediately before its existing durable commit engine.
        boundary.terminal.before_commit = Some(if fixed_service {
            session.owner.hold_pending_request(request, &session.transcript, session.socket.peer()).map(|_| ())
        } else {
            session.owner.hold_output_registration_request(request, &session.transcript, session.socket.peer()).map(|_| ())
        });
        if !matches!(&boundary.terminal.before_commit, Some(Ok(()))) { return; }
        let Some(Ok(pending)) = boundary.terminal.prepared.take() else { return; };
        boundary.terminal.committed = Some(session.commit_broker_outcome(pending));
        if !matches!(&boundary.terminal.committed, Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_))) { return; }
        boundary.completed = true;
    }

    pub(crate) fn send_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) {
        if self.closed || self.sent.is_some() { self.closed = true; return; }
        let mut boundary = OutputServerTerminalBoundaryV1 { terminal: self, completed: false };
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &boundary.terminal.committed else { return; };
        let currentness = match committed.storage_output_server_originals_v1() {
            Ok((_, currentness)) => currentness,
            Err(error) => {
                boundary.terminal.before_send = Some(Err(error));
                return;
            }
        };
        boundary.terminal.before_send = Some(session.owner.compare_storage_output_server_terminal_v1(
            currentness, session.socket.peer(),
        ));
        if !matches!(&boundary.terminal.before_send, Some(Ok(()))) { return; }

        boundary.terminal.sent = Some(session.socket.send(committed.exact_packet()));
        boundary.terminal.after_send = Some(session.owner.compare_storage_output_server_terminal_v1(
            currentness, session.socket.peer(),
        ));
        boundary.completed = matches!(&boundary.terminal.sent, Some(Ok(())))
            && matches!(&boundary.terminal.after_send, Some(Ok(())));
    }
}

struct OutputServerTerminalBoundaryV1<'terminal> {
    terminal: &'terminal mut OriginalOutputServerTerminalV1,
    completed: bool,
}

#[derive(Clone, Copy)]
enum FixedServiceRequestSelectorV5 {
    Exact(BrokerMethod),
    Network,
}

/// Keeps the actual initial native record and protected admission beside the
/// original Session. It uses the same parser and request CAS as ordinary receipt.
pub(crate) struct OriginalOutputServerReceiptV1 {
    packet: OriginalOutputPacketV1,
    profile: Option<Result<(), BrokerSessionSecurityError>>,
    fixed_service_metadata: Option<std::io::Result<std::fs::Metadata>>,
    fixed_service_extent: Option<Result<aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1, crate::recovery::FixedServiceReceivingExtentErrorV4>>,
    fixed_service_demand: Option<Result<(), BrokerSessionSecurityError>>,
    fixed_service_method: Option<Result<(), BrokerSessionSecurityError>>,
    fixed_service_expected: Option<FixedServiceRequestSelectorV5>,
    fixed_service_funding_selected: bool,
    clock: Option<Result<u64, BrokerSessionSecurityError>>,
    admission: Option<Result<crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError>>,
    initialization: Option<Result<crate::ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError>>,
    successor: Option<Result<crate::ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError>>,
    before: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    after: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    completed: bool,
    closed: bool,
}

impl OriginalOutputServerReceiptV1 {
    pub(crate) fn empty() -> Self {
        Self {
            packet: OriginalOutputPacketV1::empty(),
            profile: None,
            fixed_service_metadata: None,
            fixed_service_extent: None,
            fixed_service_demand: None,
            fixed_service_method: None,
            fixed_service_expected: None,
            fixed_service_funding_selected: false,
            clock: None,
            admission: None,
            initialization: None,
            successor: None,
            before: None,
            after: None,
            completed: false,
            closed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.before { return Some(error); }
        if let Some(Err(error)) = &self.profile { return Some(error); }
        if let Some(error) = self.packet.failure() { return Some(error); }
        if let Some(Err(error)) = &self.clock { return Some(error); }
        if let Some(Err(error)) = &self.fixed_service_metadata { return Some(error); }
        if let Some(Err(error)) = &self.fixed_service_extent { return Some(error); }
        if let Some(Err(error)) = &self.fixed_service_demand { return Some(error); }
        if let Some(Err(error)) = &self.admission { return Some(error); }
        if let Some(Err(error)) = &self.fixed_service_method { return Some(error); }
        match &self.initialization {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        match &self.successor {
            Some(Err(error)) | Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        // A post-action cutoff failure is an actual retained cause; it must
        // precede the generic closed-status fallback when no action failed.
        if let Some(Err(error)) = &self.after { return Some(error); }
        self.closed.then_some(&OutputPreparationClosedV1 as &dyn std::error::Error)
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&crate::DormantBrokerSessionHandshakeErrorV1> {
        self.after.as_ref()?.as_ref().err()
    }

    pub(crate) fn receive_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1, deadline: u64) {
        self.receive_with_storage_receiving_v1(session, deadline, None, None, None);
    }

    pub(crate) fn receive_storage_prepare_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) {
        self.receive_with_storage_receiving_v1(session, deadline, Some(receiving), None, None);
    }

    pub(crate) fn receive_storage_prepare_replay_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        terminal: &crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) {
        self.receive_with_storage_receiving_v1(
            session, deadline, Some(receiving), Some(terminal), None,
        );
    }

    pub(crate) fn receive_storage_lifecycle_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        request_bound: aos_sandbox_model::ResourceVector,
    ) {
        self.receive_with_storage_receiving_v1(
            session, deadline, None, None, Some((receiving, request_bound)),
        );
    }

    pub(crate) fn recheck_replay_transport_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> bool {
        self.packet.recheck_replay_transport_v1(session)
    }

    pub(crate) fn replay_transport_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.packet.replay_transport_failure_v1()
    }

    fn receive_with_storage_receiving_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        replay_terminal: Option<&crate::ProtectedBrokerOutcomeCommittedAdvancementV1>,
        lifecycle_receiving: Option<(
            &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
            aos_sandbox_model::ResourceVector,
        )>,
    ) {
        self.receive_with_fixed_service_v4(session, Some(deadline), receiving, replay_terminal, lifecycle_receiving, None);
    }

    pub(crate) fn receive_fixed_service_once_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        receiving: &mut aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4<'_>,
        complete_required: &mut aos_sandbox_model::ResourceVector,
        expected: BrokerMethod,
    ) {
        self.fixed_service_expected = Some(FixedServiceRequestSelectorV5::Exact(expected));
        self.receive_with_fixed_service_v4(session, Some(deadline), None, None, None,
            Some((receiving, complete_required)));
    }

    pub(crate) fn receive_inventory_continuation_once_v5(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4<'_>,
        complete_required: &mut aos_sandbox_model::ResourceVector, expected: BrokerMethod,
    ) {
        if !matches!(expected, BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES) {
            self.closed = true;
            return;
        }
        self.fixed_service_expected = Some(FixedServiceRequestSelectorV5::Exact(expected));
        // This closed inventory entrance binds the actual newly authenticated
        // signed request D. None never selects an ordinary/effect deadline.
        self.receive_with_fixed_service_v4(session, None, None, None, None,
            Some((receiving, complete_required)));
    }

    // The finite later Reap uses the SAME protected receive engine, purpose
    // join and actual newly authenticated signed D. Domain admission remains
    // independently restricted to the distinct signed Reap62 verb.
    pub(crate) fn receive_mount_reap_continuation_once_v5(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4<'_>,
        complete_required: &mut aos_sandbox_model::ResourceVector,
    ) {
        self.fixed_service_expected = Some(FixedServiceRequestSelectorV5::Exact(BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1));
        self.receive_with_fixed_service_v4(session, None, None, None, None,
            Some((receiving, complete_required)));
    }

    pub(crate) fn receive_network_request_continuation_once_v5(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4<'_>,
        complete_required: &mut aos_sandbox_model::ResourceVector,
    ) {
        self.fixed_service_expected = Some(FixedServiceRequestSelectorV5::Network);
        self.receive_with_fixed_service_v4(session, None, None, None, None,
            Some((receiving, complete_required)));
    }

    fn receive_with_fixed_service_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        deadline: Option<u64>,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        replay_terminal: Option<&crate::ProtectedBrokerOutcomeCommittedAdvancementV1>,
        lifecycle_receiving: Option<(
            &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
            aos_sandbox_model::ResourceVector,
        )>,
        mut fixed_service: Option<(
            &mut aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4<'_>,
            &mut aos_sandbox_model::ResourceVector,
        )>,
    ) {
        if self.closed || self.before.is_some() { self.closed = true; return; }
        self.closed = true;
        self.before = Some(if fixed_service.is_some() {
            // The actual opening pair is sampled once after bounded receipt,
            // immediately before canonical admission. The selected caller has
            // already prepaid and armed its independent native/paired after.
            if deadline == Some(0) { Err(crate::DormantBrokerSessionHandshakeErrorV1::Deadline) } else { Ok(()) }
        } else { deadline.ok_or(crate::DormantBrokerSessionHandshakeErrorV1::Deadline)
            .and_then(crate::dormant_handshake::check_production_deadline) });
        if !matches!(&self.before, Some(Ok(()))) { return; }
        self.receive_original(session, receiving, replay_terminal, lifecycle_receiving,
            fixed_service.as_mut().map(|(loan, required)| (&mut **loan, &mut **required)), deadline);
        // Selected native and paired afters belong to the prearmed whole
        // interval, after the domain body and response. This local status
        // records receipt completion without sampling another hidden clock.
        self.after = Some(if fixed_service.is_some() { Ok(()) }
            else { deadline.ok_or(crate::DormantBrokerSessionHandshakeErrorV1::Deadline)
            .and_then(crate::dormant_handshake::check_production_deadline) });
        if matches!(&self.after, Some(Ok(()))) && self.actual_admission_complete() {
            self.closed = false;
            self.completed = true;
        }
    }

    fn receive_original(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        mut receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        replay_terminal: Option<&crate::ProtectedBrokerOutcomeCommittedAdvancementV1>,
        mut lifecycle_receiving: Option<(
            &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
            aos_sandbox_model::ResourceVector,
        )>,
        mut fixed_service: Option<(
            &mut aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4<'_>,
            &mut aos_sandbox_model::ResourceVector,
        )>,
        deadline: Option<u64>,
    ) {
        self.profile = Some(if fixed_service.is_some() {
            session.owner.require_fixed_service_server_v4(&session.transcript, session.socket.peer())
        } else {
            match (receiving.as_deref_mut(), lifecycle_receiving.as_mut()) {
                (Some(original), None) => session.owner.require_storage_prepare_server_v2(
                    &session.transcript, session.socket.peer(), original,
                ),
                (None, Some((original, _))) => session.owner.require_storage_lifecycle_server_v2(
                    &session.transcript, session.socket.peer(), original,
                ),
                (None, None) => session.owner.require_original_storage_output_server(
                    &session.transcript, session.socket.peer(),
                ),
                (Some(_), Some(_)) => Err(BrokerSessionSecurityError::Currentness),
            }
        });
        if !matches!(&self.profile, Some(Ok(()))) { return; }
        let maximum = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(session.transcript.protocol());
        let received = if fixed_service.is_some() {
            self.packet.receive_fixed_service_once_v4(session, maximum)
        } else if receiving.is_some() || lifecycle_receiving.is_some() {
            self.packet.receive_storage_preparation_once_v1(session, maximum)
        } else {
            self.packet.receive_once(session, maximum)
        };
        if !received { return; }
        self.clock = Some(if let Some((loan, _)) = fixed_service.as_mut() {
            loan.actual_before_clock_v4().and_then(|sample| {
                if let Some(deadline) = deadline { loan.narrow_deadline_data_v4(deadline, None)?; }
                Ok(sample.boottime_nanoseconds())
            }).map_err(|_| BrokerSessionSecurityError::Currentness)
        } else { super::protected_boottime_nanoseconds() });
        let Some(Ok(now)) = &self.clock else { return; };
        let Some(packet) = self.packet.payload() else { return; };
        let descriptor_count = self.packet.descriptor_count_v4().unwrap_or(0);
        self.admission = Some(if let Some((loan, required)) = fixed_service {
            // The held prefix is measured before the same canonical decoder;
            // all growth is paid under this actual interval's cumulative bound.
            self.fixed_service_extent = Some(session.owner.fixed_service_receiving_extent_v4(
                &mut self.fixed_service_metadata,
            ));
            self.fixed_service_demand = Some((|| {
                let extent = self.fixed_service_extent.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let demand = session.owner.fixed_service_request_demand_v4(extent)?;
                if loan.require_additional_representation_v4(demand).is_err() {
                    self.fixed_service_funding_selected = true;
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                // Retained for the shared old ABI until the public wrapper
                // cuts callers over; the actual loan owns cumulative finance.
                *required = required.checked_add(demand)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                Ok(())
            })());
            if !matches!(self.fixed_service_demand, Some(Ok(()))) { return; }
            let admitted = session.owner.admit_received_request(
                packet, descriptor_count, &session.transcript, session.socket.peer(), *now,
            );
            self.fixed_service_method = Some(match admitted.as_ref() {
                Ok(admission) => {
                    let actual = admission_request_v4(admission);
                    let selected = match self.fixed_service_expected {
                        Some(FixedServiceRequestSelectorV5::Exact(expected)) if expected == actual.method() =>
                            loan.require_method_data_v4(actual.method() as u32),
                        Some(FixedServiceRequestSelectorV5::Network) =>
                            loan.select_authenticated_network_request_once_v5(actual),
                        _ => Err(aos_sandbox_broker::receiving::FixedServiceOperationClosedV4::default()),
                    };
                    selected.and_then(|()| loan.narrow_deadline_data_v4(
                        actual.deadline_boottime_nanoseconds(), None,
                    )).map_err(|_| BrokerSessionSecurityError::Currentness)
                }
                Err(_) => Err(BrokerSessionSecurityError::Currentness),
            });
            // No request/initialization append occurs before the genuine
            // loan's exact private method purpose agrees with authentication.
            admitted
        } else { match (receiving.as_deref_mut(), replay_terminal, lifecycle_receiving.as_mut()) {
            (None, None, Some((receiving, request_bound))) => session.owner.admit_retained_storage_request_v1(
                packet, &session.transcript, &session.socket, *now, receiving, *request_bound,
            ),
            (Some(receiving), Some(terminal), None) => session.owner.admit_storage_prepare_replay_received_request_v1(
                packet, 0, &session.transcript, session.socket.peer(), *now, receiving, terminal,
            ),
            (Some(receiving), None, None) => session.owner.admit_storage_prepare_received_request_v1(
                packet, 0, &session.transcript, session.socket.peer(), *now, receiving,
            ),
            (None, None, None) => session.owner.admit_received_request(
                packet, 0, &session.transcript, session.socket.peer(), *now,
            ),
            _ => Err(BrokerSessionSecurityError::Currentness),
        }});
        if self.fixed_service_method.as_ref().is_some_and(Result::is_err) { return; }
        if let Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { request, requires_initialization })) = &self.admission {
            if *requires_initialization {
                self.initialization = Some(if receiving.is_some() || lifecycle_receiving.is_some() {
                    session.initialize_storage_request_receiving_v2(request, receiving.as_deref_mut(),
                        lifecycle_receiving.as_mut().map(|(source, _)| &mut **source))
                } else {
                    session.initialize_authenticated_request(request)
                });
            } else {
                self.successor = Some(if receiving.is_some() || lifecycle_receiving.is_some() {
                    session.append_storage_request_receiving_v3(request, receiving.as_deref_mut(),
                        lifecycle_receiving.as_mut().map(|(source, _)| &mut **source))
                } else {
                    session.append_authenticated_request(request)
                });
            }
        }
    }

    fn actual_admission_complete(&self) -> bool {
        if self.fixed_service_method.as_ref().is_some_and(Result::is_err) { return false; }
        match &self.admission {
            Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { requires_initialization: true, .. })) =>
                matches!(&self.initialization, Some(Ok(crate::ProtectedBrokerSessionInitializationResultV1::Initialized))),
            Some(Ok(crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { requires_initialization: false, .. })) =>
                matches!(&self.successor, Some(Ok(crate::ProtectedBrokerRequestCommitResultV1::Committed))),
            Some(Ok(_)) => true,
            _ => false,
        }
    }

    pub(crate) fn has_completed_admission_v1(&self) -> bool {
        self.completed && !self.closed
    }

    fn fixed_service_original_failure_selected_v4(&self) -> bool {
        if self.fixed_service_expected.is_none() || self.before.as_ref().is_some_and(Result::is_err)
            || self.profile.as_ref().is_some_and(Result::is_err) || self.packet.failure().is_some()
        { return false; }
        if self.clock.as_ref().is_some_and(Result::is_err) { return true; }
        if self.fixed_service_metadata.as_ref().is_some_and(Result::is_err)
            || self.fixed_service_extent.as_ref().is_some_and(Result::is_err)
        { return false; }
        if self.fixed_service_demand.as_ref().is_some_and(Result::is_err) {
            return self.fixed_service_funding_selected;
        }
        matches!(self.admission, Some(Ok(_)))
            && self.fixed_service_method.as_ref().is_some_and(Result::is_err)
    }

    fn take_network_descriptor_v4(&mut self) -> Option<std::os::fd::OwnedFd> {
        if self.borrowed_authenticated_request_v4()?.method()
            != BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
        { return None; }
        self.packet.take_preparation_descriptor_v4()
    }

    pub(crate) fn borrowed_authenticated_request_v4(&self)
        -> Option<&AuthenticatedBrokerMethodRequestV1>
    {
        if !self.has_completed_admission_v1() { return None; }
        match self.admission.as_ref()?.as_ref().ok()? {
            crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { request, .. } => Some(request),
            // The old exact replay engine retains its actual terminal/pending
            // owner. Neither may re-enter a fresh domain mutation through this
            // comparison getter; selected replay disposition is separate.
            _ => None,
        }
    }

    /// One-way handoff only after the actual resident CAS/postcheck results.
    pub(crate) fn into_admitted_original(&mut self) -> Option<crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1> {
        if !self.completed || self.closed { return None; }
        let Some(Ok(admission)) = self.admission.take() else { return None; };
        Some(admission)
    }
}

fn admission_request_v4(admission: &crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1)
    -> &AuthenticatedBrokerMethodRequestV1 {
    match admission {
        crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::New { request, .. }
        | crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay { request, .. } => request,
        crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay { replay } => replay.request(),
    }
}

impl Drop for OutputServerTerminalBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.terminal.closed = true;
        }
    }
}

enum OriginalReceivedPacketV4 {
    Plain(ReceivedRecord),
    FixedService(aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord),
}

impl OriginalReceivedPacketV4 {
    fn payload(&self) -> &[u8] {
        match self { Self::Plain(record) => record.payload(), Self::FixedService(record) => record.payload() }
    }

    fn subject(&self) -> &aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject {
        match self { Self::Plain(record) => record.subject(), Self::FixedService(record) => record.subject() }
    }

    fn require_original(&self, socket: &mut aos_sandbox_linux::seqpacket::SeqpacketSocket) -> Result<(), RecordBindingError> {
        match self {
            Self::Plain(record) => socket.require_output_registration_received_original_v1(record),
            Self::FixedService(record) => socket.require_fixed_service_descriptor_received_original_v4(record),
        }
    }

    fn descriptor_count(&self) -> usize {
        match self { Self::Plain(_) => 0, Self::FixedService(record) => record.descriptors().len() }
    }
}

/// Retains one whole native packet before binding and subject observations.
pub(crate) struct OriginalOutputPacketV1 {
    received: Option<Result<OriginalReceivedPacketV4, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    subject_current: bool,
    witness_failure: bool,
    replay_binding: Option<Result<(), RecordBindingError>>,
    replay_alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    replay_subject_current: Option<bool>,
}

// This selects only the existing witness comparator, never a payer or role.
// The D arm is chosen solely by the closed clientflight purpose above.
enum PacketSubjectCheckV1 { ExistingEndpoint, RetainedClient }

impl OriginalOutputPacketV1 {
    pub(crate) fn empty() -> Self {
        Self {
            received: None,
            binding: None,
            alive: None,
            subject_current: false,
            witness_failure: false,
            replay_binding: None,
            replay_alive: None,
            replay_subject_current: None,
        }
    }

    pub(crate) fn receive_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
    ) -> bool {
        self.receive_with_profile_v1(session, maximum, HandshakeReceiveProfileV1::Ordinary,
            PacketSubjectCheckV1::ExistingEndpoint)
    }

    fn receive_storage_preparation_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
    ) -> bool {
        self.receive_with_profile_v1(session, maximum, HandshakeReceiveProfileV1::StoragePreparation,
            PacketSubjectCheckV1::ExistingEndpoint)
    }

    fn receive_delete_inventory_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
    ) -> bool {
        self.receive_with_profile_v1(session, maximum, HandshakeReceiveProfileV1::StoragePreparation,
            PacketSubjectCheckV1::RetainedClient)
    }

    fn receive_with_profile_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
        profile: HandshakeReceiveProfileV1,
        subject_check: PacketSubjectCheckV1,
    ) -> bool {
        if self.received.is_some() { return false; }
        self.received = Some(match profile {
            HandshakeReceiveProfileV1::Ordinary => session.socket.receive_retaining(maximum).map(OriginalReceivedPacketV4::Plain),
            HandshakeReceiveProfileV1::StoragePreparation | HandshakeReceiveProfileV1::StorageHost =>
                session.socket.receive_storage_preparation_retaining_v1(maximum).map(OriginalReceivedPacketV4::Plain),
            // This pending-method receiver has only Ordinary and Storage
            // callers. Initial and Start HELLO custody cannot enter this request lane.
            HandshakeReceiveProfileV1::ControllerInitial | HandshakeReceiveProfileV1::StartResource => return false,
        });
        self.validate_received_once_v4(session, subject_check)
    }

    fn receive_fixed_service_once_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        maximum: usize,
    ) -> bool {
        if self.received.is_some() { return false; }
        self.received = Some(session.socket.receive_fixed_service_request_retaining_v4(maximum)
            .map(OriginalReceivedPacketV4::FixedService));
        self.validate_received_once_v4(session, PacketSubjectCheckV1::ExistingEndpoint)
    }

    fn validate_received_once_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        subject_check: PacketSubjectCheckV1,
    ) -> bool {
        let Some(Ok(record)) = &self.received else { return false; };
        self.binding = Some(record.require_original(&mut session.socket));
        if !matches!(self.binding.as_ref(), Some(Ok(()))) { return false; }
        self.alive = Some(record.subject().is_alive());
        if !matches!(self.alive.as_ref(), Some(Ok(true))) { return false; }
        self.subject_current = match subject_check {
            PacketSubjectCheckV1::ExistingEndpoint => session.require_output_subject(record.subject()),
            PacketSubjectCheckV1::RetainedClient => session.require_delete_inventory_subject_v1(record.subject()),
        };
        self.witness_failure = !self.subject_current && session.output_witness_failure().is_some();
        self.subject_current
    }

    fn recheck_replay_transport_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> bool {
        if self.replay_binding.is_some() {
            return false;
        }
        let Some(Ok(record)) = &self.received else {
            return false;
        };
        self.replay_binding = Some(
            record.require_original(&mut session.socket),
        );
        if !matches!(self.replay_binding, Some(Ok(()))) {
            return false;
        }
        self.replay_alive = Some(record.subject().is_alive());
        if !matches!(self.replay_alive, Some(Ok(true))) {
            return false;
        }
        self.replay_subject_current = Some(session.require_output_subject(record.subject()));
        matches!(self.replay_subject_current, Some(true))
    }

    fn replay_transport_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.replay_binding {
            return Some(error);
        }
        if let Some(Err(error)) = &self.replay_alive {
            return Some(error);
        }
        if matches!(self.replay_alive, Some(Ok(false)))
            || matches!(self.replay_subject_current, Some(false))
        {
            return Some(&OutputPreparationClosedV1);
        }
        None
    }

    fn is_nonconsuming_v1(&self) -> bool {
        matches!(self.received.as_ref(), Some(Err(error))
            if error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted())
            && self.binding.is_none() && self.alive.is_none()
            && !self.subject_current && !self.witness_failure
    }

    pub(crate) fn payload(&self) -> Option<&[u8]> {
        if !self.subject_current { return None; }
        Some(self.received.as_ref()?.as_ref().ok()?.payload())
    }

    fn descriptor_count_v4(&self) -> Option<usize> {
        if !self.subject_current { return None; }
        Some(self.received.as_ref()?.as_ref().ok()?.descriptor_count())
    }

    fn take_preparation_descriptor_v4(&mut self) -> Option<std::os::fd::OwnedFd> {
        if !self.subject_current { return None; }
        match self.received.as_mut()?.as_mut().ok()? {
            OriginalReceivedPacketV4::FixedService(record) => record.take_fixed_service_preparation_descriptor_data_v4(),
            OriginalReceivedPacketV4::Plain(_) => None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.received { return Some(error); }
        if let Some(Err(error)) = &self.binding { return Some(error); }
        if let Some(Err(error)) = &self.alive { return Some(error); }
        if self.witness_failure { return Some(&OutputWitnessUnavailableV1); }
        None
    }

    fn failure_with_session<'a>(
        &'a self,
        session: &'a DormantAuthenticatedBrokerSessionV1,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.received { return Some(error); }
        if let Some(Err(error)) = &self.binding { return Some(error); }
        if let Some(Err(error)) = &self.alive { return Some(error); }
        if self.witness_failure {
            return Some(session.output_witness_failure().unwrap_or(&OutputWitnessUnavailableV1));
        }
        None
    }
}

/// Retains one closed Inventory or Prepare request on its original Session.
///
/// Construction creates empty result destinations only. The actual owning
/// Create operation must prepay fixed/request/response/currentness work before
/// entering it. A completed narrow signed transcript remains mandatory, and
/// the wrapper cannot take or replace the Session, request or recovery owner.
pub struct OriginalStoragePreparationClientFlightV1 {
    inner: OriginalOutputClientFlightV1,
    pending: Option<StoragePreparationPendingSiteV1>,
}

/// Reports the resident closed preparation flight's actual transport progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePreparationClientProgressV1 {
    /// The actual initial syscall refused without consuming a record.
    Pending,
    /// The exact original request was fully sent with positive local posts.
    Sent,
    /// The authenticated terminal was durably committed and independently read back.
    Committed,
    /// A fatal or ambiguous result remains resident and cannot be retried.
    Closed,
}

#[derive(Clone, Copy)]
enum StoragePreparationPendingSiteV1 { Send, Receive }

impl OriginalStoragePreparationClientFlightV1 {
    // The closed preparation flight retains fourteen direct Result/cause
    // destinations, five packet Results, two protected sender Results and
    // four native send Results/framing cells. Raw receive/FD/model owners
    // keep their separate shared native and protocol geometry suppliers.
    const fn receiving_control_cells_v1() -> usize {
        14 + 5 + 2 + 4
    }

    /// Constructs empty custody without opening, signing or granting a request.
    #[must_use]
    pub fn empty() -> Self {
        let mut inner = OriginalOutputClientFlightV1::empty();
        inner.purpose = OriginalClientFlightPurposeV1::StoragePreparation;
        Self { inner, pending: None }
    }

    pub(crate) fn inner_mut(&mut self) -> &mut OriginalOutputClientFlightV1 { &mut self.inner }

    pub(crate) fn send_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> StoragePreparationClientProgressV1 {
        self.send_with_content_v4(session, None)
    }

    pub(super) fn send_with_content_v4(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        content: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> StoragePreparationClientProgressV1 {
        if self.pending.is_some() {
            self.inner.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        let result = self.inner.send_preparation_with_content_v4(session, content);
        if result == StoragePreparationClientProgressV1::Pending {
            self.pending = Some(StoragePreparationPendingSiteV1::Send);
        }
        result
    }

    pub(crate) fn receive_once_v1(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> StoragePreparationClientProgressV1 {
        if self.pending.is_some() || !matches!(self.inner.sent, Some(Ok(()))) {
            self.inner.closed = true;
            return StoragePreparationClientProgressV1::Closed;
        }
        if self.inner.receive_terminal_once(session) {
            StoragePreparationClientProgressV1::Committed
        } else if !self.inner.closed && self.inner.terminal_packet.is_nonconsuming_v1() {
            self.pending = Some(StoragePreparationPendingSiteV1::Receive);
            StoragePreparationClientProgressV1::Pending
        } else {
            StoragePreparationClientProgressV1::Closed
        }
    }

    /// Borrows the original signed request while all flight custody stays held.
    #[must_use]
    pub fn request(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> { self.inner.request() }

    /// Borrows the actual terminal commit or its original retained recovery.
    #[must_use]
    pub fn committed(&self) -> Option<&crate::ProtectedBrokerOutcomeCommitResultV1> { self.inner.committed() }

    pub(crate) fn failure_with_session<'a>(&'a self, session: &'a DormantAuthenticatedBrokerSessionV1)
        -> Option<&'a (dyn std::error::Error + 'static)>
    {
        self.inner.failure_with_session(session)
    }
}
