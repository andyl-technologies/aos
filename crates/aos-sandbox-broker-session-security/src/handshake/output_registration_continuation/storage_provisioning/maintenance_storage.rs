//! Runs actual Maintenance31 and fresh18 through the sole captured flight.
//!
//! This finite member owns both complete operations beside the same opaque
//! completed Storage borrower. Its genuine native M lender supplies every
//! request, debit, Session/native and unchanged-cutoff gate. The unsigned
//! envelope and authenticated packet/outcome engines remain shared.

use super::member::common_turns;
use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox::{
    ControllerMaintenanceStorageIoLoanV3, ControllerMaintenanceStorageRequestOriginalV3, Journal,
};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, SeqpacketSocket};
use buffa::Message as _;

pub(crate) struct MaintenanceStorageSessionIoOriginalV3 {
    inner: Option<StorageProvisioningSessionIoOriginalV1>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
}

impl MaintenanceStorageSessionIoOriginalV3 {
    pub(crate) fn new() -> Self {
        Self {
            inner: Some(StorageProvisioningSessionIoOriginalV1::new_kind_v4(
                ProvisioningKindV4::MaintenanceStorage,
            )),
            admission: None,
        }
    }

    pub(crate) fn observe_once_v3(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        completed: &mut crate::dormant_handshake::DormantControllerInitialSessionCompletedBorrowV1<
            '_,
        >,
        prepared: &ControllerMaintenanceStorageRequestOriginalV3,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.admission.is_some() {
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        let (receiving, session) = completed.reborrow_v1();
        let journal = session
            .owner
            .retained_storage_client_journal_v1()
            .map_err(|_| OutputPreparationClosedV1)?;
        let mut native = match loan.borrow_refresh_storage_io_once_v3(
            receiving,
            prepared,
            journal,
            &session.transcript,
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
        let inner = self.inner.as_mut().ok_or(OutputPreparationClosedV1)?;
        inner.run_member_once_v4(session, &mut native, prepared, false)?;
        inner.run_member_once_v4(session, &mut native, prepared, true)
    }

    pub(crate) fn outcomes_v3(
        &self,
    ) -> Option<(
        &AuthenticatedBrokerMethodOutcomeV1,
        &AuthenticatedBrokerMethodOutcomeV1,
        &[u8; 64],
    )> {
        let inner = self.inner.as_ref()?;
        if inner.failure().is_some() {
            return None;
        }
        let native = inner.completed_native.as_ref()?.as_ref().ok()?.as_ref()?;
        Some((
            inner.apply.authenticated(false)?,
            inner.inventory.authenticated(true)?,
            native,
        ))
    }

    pub(crate) fn inventory_model_v3(
        &self,
    ) -> Option<&(ValidatedStorageInventory, InventoryStorageResourcesResponse)> {
        self.outcomes_v3()?;
        self.inner
            .as_ref()?
            .inventory
            .outcome
            .as_ref()?
            .retained_storage_inventory_response_data_v1()
    }

    pub(crate) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.inner
            .as_ref()
            .and_then(StorageProvisioningSessionIoOriginalV1::failure)
            .or_else(|| {
                self.admission
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    pub(crate) fn dispose_after_all_posts_v3(
        &mut self,
        token: aos_sandbox::ControllerMaintenanceStorageSdkDisposalV3<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.outcomes_v3().ok_or(OutputPreparationClosedV1)?;
        drop(self.inner.take());
        token.complete_after_disposal_v3();
        Ok(())
    }
}

impl ProvisioningMemberV4 for ControllerMaintenanceStorageIoLoanV3<'_> {
    type Prepared = ControllerMaintenanceStorageRequestOriginalV3;
    common_turns!();

    fn retain_primary_refusal_v4(&mut self, original_selected: bool) {
        if original_selected {
            self.retain_storage_io_refusal_once_v3();
        } else {
            self.retain_storage_sdk_refusal_once_v3();
        }
    }

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &Self::Prepared) -> bool {
        matches!(kind, ProvisioningKindV4::MaintenanceStorage)
    }

    fn completed_native_data_v2(&self) -> Result<Option<[u8; 64]>, ResourceReservationErrorV1> {
        self.completed_session_native_data_v3()
            .map(|native| Some(*native))
    }

    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        aos_sandbox_linux::seqpacket::SeqpacketSocket::network_preparation_send_receiving_bytes_v4(
        )?
        .checked_add(size_of::<MaintenanceStorageSessionIoOriginalV3>().checked_mul(2)?)
    }

    fn request_packet_bound_v4(&self, prepared: &Self::Prepared, inventory: bool) -> Option<usize> {
        if inventory {
            return Some(
                aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1(),
            );
        }
        let clear = prepared.authorization_data_v3().into_iter().try_fold(
            prepared.request_data_v3().0.len().checked_add(8 * 6)?,
            |total, field| total.checked_add(field.len()),
        )?;
        aos_sandbox_protocol::session::authenticated_request_packet_bound_from_clear_v1(clear)
    }

    fn admit_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: aos_sandbox::StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.admit_storage_io_once_v3(prepared, journal, socket, transcript, shape, inventory)
    }

    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        prepared: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        let inputs = (|| {
            let header = self
                .request_header_data_v3(inventory)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            // M already retains its distinct fresh18 entropy. Reuse the
            // common Storage header/limit fold with supplied coordinates;
            // requesting another generated Inventory ID would lose that owner.
            let coordinates = session.start_resource_provisioning_coordinates_v2(&header, false)?;
            let envelope = if inventory {
                BrokerRequestEnvelope {
                    method: BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES.into(),
                    body: InventoryStorageRequest {
                        header: Some(coordinates.request_header()).into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                    ..Default::default()
                }
            } else {
                let [plan, signature, lease, lease_signature] = prepared.authorization_data_v3();
                BrokerRequestEnvelope {
                    method: BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT.into(),
                    body: prepared.request_data_v3().0.to_vec(),
                    authorization: Some(
                        aos_proto::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1 {
                            broker_plan: plan.to_vec(),
                            broker_plan_signature: signature.to_vec(),
                            ownership_lease: lease.to_vec(),
                            ownership_lease_signature: lease_signature.to_vec(),
                            ..Default::default()
                        },
                    )
                    .into(),
                    ..Default::default()
                }
            };
            Ok((coordinates, envelope))
        })();
        match inputs {
            Ok((coordinates, envelope)) => {
                flight.shared.inner.coordinates = Some(Ok(coordinates));
                flight.unsigned = Some(envelope);
                match flight.unsigned.as_ref() {
                    Some(envelope) => flight.shared.inner.prepare_captured_engine_v1(
                        session,
                        envelope.clone(),
                        Some(maximum_request),
                        match flight.request_originals.as_mut() {
                            Some(capture) => Some(capture.as_mut()),
                            None => return false,
                        },
                    ),
                    None => false,
                }
            }
            Err(cause) => {
                flight.shared.inner.coordinates = Some(Err(cause));
                flight.mark(First::Coordinates);
                false
            }
        }
    }

    fn bind_request_v4(
        &mut self,
        prepared: &Self::Prepared,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bind_storage_request_once_v3(prepared, request)
    }

    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        owner.observe_retained_storage_client_owner_v1(transcript, peer)
    }

    fn finish_terminal_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_storage_terminal_once_v3(prepared, journal, outcome)
    }

    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_storage_terminal_post_once_v3(journal, socket, transcript)
    }
}
