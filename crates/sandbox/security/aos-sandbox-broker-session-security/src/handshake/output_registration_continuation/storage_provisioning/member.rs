//! Seals one shared provisioning flight to actual Create, Start or Delete loans.
//!
//! These implementations delegate genuine native stages and borrow the exact
//! Prepared owner. They contain no Session/payer/authority constructor.

use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox_controller_domain::{
    Journal, PreparedStartResourceRequestOriginalV2, StartResourceProvisioningIoLoanV2,
    StorageProvisioningSessionIoShapeDataV1,
};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

#[derive(Clone, Copy)]
pub(super) enum ProvisioningKindV4 {
    Storage,
    StartStorage,
    Network,
    Mount,
    Host,
    HostCatalog,
    MaintenanceCatalog,
    MaintenanceStorage,
    DeletePreparation,
    DeleteApply,
    DeleteNetwork,
    DeleteMount,
    ExecutionAvailability,
    ExecutionNoApply,
}

pub(super) trait ProvisioningMemberV4:
    NativeStorageIoV1<Failure = ResourceReservationErrorV1>
{
    type Prepared;
    fn retain_primary_refusal_v4(&mut self, _original_selected: bool) {}
    fn flight_owner_inline_bytes_v4() -> Option<usize> {
        size_of::<StorageProvisioningSessionIoOriginalV1>().checked_mul(2)?
            .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(2)?)
    }

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, prepared: &Self::Prepared) -> bool;

    fn completed_native_data_v2(&self) -> Result<Option<[u8; 64]>, ResourceReservationErrorV1> { Ok(None) }

    fn extra_inline_bytes_v4(&self) -> Option<usize>;
    fn request_packet_bound_v4(&self, prepared: &Self::Prepared, inventory: bool) -> Option<usize>;
    fn admit_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1>;
    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        prepared: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool;
    fn begin_request_preparation_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1>;
    fn begin_receive_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1>;
    fn bind_request_v4(
        &mut self,
        prepared: &Self::Prepared,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1>;
    fn admit_predecessor_v4(&mut self, journal: &Journal)
    -> Result<(), ResourceReservationErrorV1>;
    fn prepare_pending_receive_v4<'held>(
        &'held mut self,
        receipt: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<Self::Disposal<'held>, ResourceReservationErrorV1>;
    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1;
    fn compare_predecessor_v4(owner: &mut ProtectedBrokerSessionOwnerV1,
        currentness: &crate::recovery::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity, originals: &mut crate::recovery::OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        owner.compare_atomic_snapshot_predecessor_retaining_v1(currentness, peer, originals)
    }

    fn finish_terminal_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1>;
    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1>;
}

macro_rules! common_turns {
    () => {
        fn begin_request_preparation_v4(
            &mut self,
            journal: &Journal,
            socket: &SeqpacketSocket,
            transcript: &VerifiedBrokerSessionTranscriptV1,
        ) -> Result<(), ResourceReservationErrorV1> {
            self.begin_request_preparation_once(journal, socket, transcript)
        }
        fn begin_receive_v4(
            &mut self,
            journal: &Journal,
            socket: &SeqpacketSocket,
            transcript: &VerifiedBrokerSessionTranscriptV1,
        ) -> Result<(), ResourceReservationErrorV1> {
            self.begin_receive_once(journal, socket, transcript)
        }
        fn admit_predecessor_v4(
            &mut self,
            journal: &Journal,
        ) -> Result<(), ResourceReservationErrorV1> {
            self.admit_retained_predecessor_once(journal)
        }
        fn prepare_pending_receive_v4<'held>(
            &'held mut self,
            receipt: &RetainedSeqpacketReceiveErrorV1,
        ) -> Result<Self::Disposal<'held>, ResourceReservationErrorV1> {
            self.prepare_pending_receive_disposal_once(receipt)
        }
    };
}

pub(super) use common_turns;

impl ProvisioningMemberV4 for CreateProvisioningStorageIoLoanV1<'_> {
    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &Self::Prepared) -> bool {
        matches!(kind, ProvisioningKindV4::Storage)
    }

    type Prepared = PreparedAuthorityEffectV1;
    common_turns!();
    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        size_of::<aos_sandbox_controller_domain::StorageProvisioningWorkspaceOriginalV1<'static>>().checked_mul(2)
    }
    fn request_packet_bound_v4(&self, prepared: &Self::Prepared, inventory: bool) -> Option<usize> {
        if inventory {
            Some(aos_sandbox_protocol::fixed_storage_inventory_request_packet_bound_v1())
        } else {
            aos_sandbox_protocol::session::authenticated_request_packet_bound_from_clear_v1(
                prepared.attempt().packet().len(),
            )
        }
    }
    fn admit_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if inventory {
            self.admit_storage_inventory_io_once_v1(prepared, journal, socket, transcript, shape)
        } else {
            self.admit_storage_apply_io_once_v1(prepared, journal, socket, transcript, shape)
        }
    }
    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        prepared: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        if !inventory {
            flight.durable_request = Some(prepared.broker_request());
        }
        flight.shared.inner.coordinates = Some(if inventory {
            crate::dormant_handshake::storage_provisioning_inventory_coordinates_v1(
                session,
                prepared.attempt().deadline_boottime_nanoseconds(),
            )
        } else {
            match flight
                .durable_request
                .as_ref()
                .and_then(|value| value.as_ref().ok())
            {
                Some(request) => {
                    crate::dormant_handshake::storage_provisioning_apply_coordinates_v1(
                        session, request,
                    )
                }
                None => Err(BrokerSessionSecurityError::Currentness),
            }
        });
        if let Some(Ok(coordinates)) = flight.shared.inner.coordinates.as_ref() {
            let envelope = if inventory {
                Ok(BrokerRequestEnvelope {
                    method: BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES.into(),
                    body: InventoryStorageRequest {
                        header: Some(coordinates.request_header()).into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                    ..Default::default()
                })
            } else {
                flight
                    .durable_request
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .map(|request| request.clone().into_envelope())
                    .ok_or(BrokerSessionSecurityError::Currentness)
            };
            match envelope {
                Ok(envelope) => {
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
                    flight.shared.inner.protected_failure = Some(cause);
                    false
                }
            }
        } else {
            flight.mark(First::Coordinates);
            false
        }
    }
    fn bind_request_v4(
        &mut self,
        prepared: &Self::Prepared,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bind_storage_request_once_v1(prepared, request)
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
        self.finish_storage_terminal_once_v1(prepared, journal, outcome)
    }
    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_storage_terminal_post_once_v1(journal, socket, transcript)
    }
}

impl ProvisioningMemberV4 for StartResourceProvisioningIoLoanV2<'_> {
    fn matches_kind_v2(&self, kind: ProvisioningKindV4, prepared: &Self::Prepared) -> bool {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose;
        let purpose = match kind { ProvisioningKindV4::Network => Purpose::NetworkPrepare,
            ProvisioningKindV4::Mount => Purpose::MountNamespace, ProvisioningKindV4::Host => Purpose::HostLaunch, ProvisioningKindV4::StartStorage => Purpose::StorageGuestRoot, ProvisioningKindV4::Storage | ProvisioningKindV4::HostCatalog | ProvisioningKindV4::DeletePreparation | ProvisioningKindV4::MaintenanceCatalog | ProvisioningKindV4::MaintenanceStorage | ProvisioningKindV4::DeleteApply | ProvisioningKindV4::DeleteNetwork | ProvisioningKindV4::DeleteMount | ProvisioningKindV4::ExecutionAvailability | ProvisioningKindV4::ExecutionNoApply => return false };
        self.purpose_data_v2() == purpose && prepared.purpose_data_v2() == purpose
    }

    fn completed_native_data_v2(&self) -> Result<Option<[u8; 64]>, ResourceReservationErrorV1> {
        self.completed_session_native_data_v2().map(|position| Some(*position))
    }

    type Prepared = PreparedStartResourceRequestOriginalV2;
    common_turns!();
    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        let coordinates = if self.protocol_data_v2() == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host {
            crate::handshake::start_host_coordinates_receiving_bytes_v2()?
        } else { 0 };
        aos_sandbox_linux::seqpacket::SeqpacketSocket::network_preparation_send_receiving_bytes_v4()?
            .checked_add(coordinates)?
            .checked_add(size_of::<StartResourceProvisioningSessionIoOriginalV4>()
                .checked_sub(size_of::<StorageProvisioningSessionIoOriginalV1>())?.checked_mul(2)?)
    }
    fn request_packet_bound_v4(&self, prepared: &Self::Prepared, inventory: bool) -> Option<usize> {
        if inventory {
            return Some(
                aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1(),
            );
        }
        let view = self.borrow_prepared_request_v2(prepared).ok()?;
        let parts = [
            view.request_body_v2().ok()?,
            view.plan_bytes_v2().ok()?,
            view.plan_signature_v2().ok()?,
            view.lease_bytes_v2(),
            view.lease_signature_v2(),
        ];
        // Complete five-byte length varints bound each raw bytes field, the
        // quartet wrapper and one exact descriptor entry without encoding it.
        let clear = parts
            .iter()
            .try_fold(8_usize.checked_mul(6)?, |total, part| {
                total.checked_add(part.len())
            })?;
        aos_sandbox_protocol::session::authenticated_request_packet_bound_from_clear_v1(clear)
    }
    fn admit_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if inventory {
            self.admit_resource_inventory_io_once_v2(prepared, journal, socket, transcript, shape)
        } else {
            self.admit_resource_request_io_once_v2(prepared, journal, socket, transcript, shape)
        }
    }
    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        prepared: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        // The view borrows the genuine prepared model and original lease;
        // no independently obtained artifact or descriptor tuple is accepted.
        let inputs = (|| {
            let view = self
                .borrow_prepared_request_v2(prepared)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let header = view
                .request_header_v2()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let coordinates = crate::dormant_handshake::start_resource_provisioning_coordinates_v2(
                session, header, inventory,
            )?;
            let envelope = if inventory {
                BrokerRequestEnvelope {
                    method: self.method_data_v2(true).into(),
                    body: match self.protocol_data_v2() {
                        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network =>
                            aos_sandbox_api::aos::sandbox::local::v1::InventoryNetworksRequest {
                                header: Some(coordinates.request_header()).into(), ..Default::default()
                            }.encode_to_vec(),
                        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage =>
                            InventoryStorageRequest {
                                header: Some(coordinates.request_header()).into(), ..Default::default()
                            }.encode_to_vec(),
                        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount =>
                            aos_sandbox_api::aos::sandbox::local::v1::InventoryDestinationSlotsRequest {
                                header: Some(coordinates.request_header()).into(), ..Default::default()
                            }.encode_to_vec(),
                        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host =>
                            aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeRequest {
                                header: Some(coordinates.request_header()).into(), ..Default::default()
                            }.encode_to_vec(),
                        _ => return Err(BrokerSessionSecurityError::Currentness),
                    },
                    ..Default::default()
                }
            } else {
                BrokerRequestEnvelope {
                    method: self.method_data_v2(false).into(),
                    body: view.request_body_v2().map_err(|_| BrokerSessionSecurityError::Currentness)?.to_vec(),
                    descriptors: if self.method_data_v2(false) == BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 { vec![aos_sandbox_api::aos::sandbox::local::v1::BrokerDescriptorEntry {
                        index: 0,
                        role: aos_sandbox_api::aos::sandbox::local::v1::BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_NETWORK_PREPARATION_V2.into(),
                        ..Default::default()
                    }] } else { Vec::new() },
                    authorization: Some(aos_sandbox_api::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1 {
                        broker_plan: view.plan_bytes_v2().map_err(|_| BrokerSessionSecurityError::Currentness)?.to_vec(),
                        broker_plan_signature: view.plan_signature_v2().map_err(|_| BrokerSessionSecurityError::Currentness)?.to_vec(),
                        ownership_lease: view.lease_bytes_v2().to_vec(),
                        ownership_lease_signature: view.lease_signature_v2().to_vec(), ..Default::default()
                    }).into(), ..Default::default()
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
        self.bind_resource_request_once_v2(prepared, request)
    }
    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        owner.observe_retained_resource_client_owner_v2(transcript, peer)
    }
    fn finish_terminal_v4(
        &mut self,
        prepared: &Self::Prepared,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_resource_terminal_once_v2(prepared, journal, outcome)
    }
    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_resource_terminal_post_once_v2(journal, socket, transcript)
    }
}

// Finite Delete loans lend the same native stages and captured request engine.
macro_rules! delete_storage_member {
    ($loan:ident, $kind:ident, $request_bound:ident, $admit:ident, $header:ident,
     $coordinates:ident, $envelope:ident, $method:ident, $bind:ident,
     $compare:ident, $finish:ident, $post:ident, $owner_post:ident) => {
        impl ProvisioningMemberV4 for aos_sandbox_controller_domain::$loan<'_> {
            type Prepared = ();
            common_turns!();

            fn flight_owner_inline_bytes_v4() -> Option<usize> {
                match ProvisioningKindV4::$kind {
                    ProvisioningKindV4::DeleteMount => super::delete_mount::inline_bytes_v4(),
                    _ => super::delete_session::inline_bytes_v3(),
                }
            }

            fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &()) -> bool {
                matches!(kind, ProvisioningKindV4::$kind)
            }

            fn extra_inline_bytes_v4(&self) -> Option<usize> {
                Some(0)
            }

            fn request_packet_bound_v4(&self, _: &(), inventory: bool) -> Option<usize> {
                if inventory {
                    None
                } else {
                    self.$request_bound()
                }
            }

            fn admit_v4(
                &mut self,
                _: &(),
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
                shape: StorageProvisioningSessionIoShapeDataV1,
                inventory: bool,
            ) -> Result<(), ResourceReservationErrorV1> {
                if inventory {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                self.$admit(journal, socket, transcript, shape)
            }

            fn prepare_request_v4(
                &mut self,
                flight: &mut ProvisioningFlightV1,
                session: &mut DormantAuthenticatedBrokerSessionV1,
                _: &(),
                inventory: bool,
                maximum_request: usize,
            ) -> bool {
                if inventory {
                    return false;
                }
                let inputs = (|| {
                    let header = self
                        .$header()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let coordinates = crate::dormant_handshake::$coordinates(session, &header)?;
                    let envelope = self
                        .$envelope()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    if envelope.method.as_known() != Some(BrokerMethod::$method)
                        || !envelope.descriptors.is_empty()
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
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
                _: &(),
                request: &AuthenticatedBrokerMethodRequestV1,
            ) -> Result<(), ResourceReservationErrorV1> {
                self.$bind(request)
            }

            fn observe_owner_v4(
                owner: &mut ProtectedBrokerSessionOwnerV1,
                transcript: &VerifiedBrokerSessionTranscriptV1,
                peer: &ConnectionPeerIdentity,
            ) -> RetainedStorageClientOwnerPostV1 {
                owner.$owner_post(transcript, peer)
            }

            fn compare_predecessor_v4(
                owner: &mut ProtectedBrokerSessionOwnerV1,
                currentness: &crate::recovery::ProtectedBrokerOutcomeCurrentnessOwnerV1,
                peer: &ConnectionPeerIdentity,
                originals: &mut crate::recovery::OutcomeCurrentOriginalsV1,
            ) -> Result<(), BrokerSessionSecurityError> {
                owner.$compare(currentness, peer, originals)
            }

            fn finish_terminal_v4(
                &mut self,
                _: &(),
                journal: &Journal,
                outcome: &AuthenticatedBrokerMethodOutcomeV1,
            ) -> Result<(), ResourceReservationErrorV1> {
                self.$finish(journal, outcome)
            }

            fn observe_terminal_post_v4(
                &mut self,
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
            ) -> Result<(), ResourceReservationErrorV1> {
                self.$post(journal, socket, transcript)
            }
        }

    };
}

delete_storage_member!(OriginalDeleteStoragePreparationLoanV3, DeletePreparation,
    preparation_request_bound_v3, admit_preparation_io_once_v3, preparation_header_data_v3,
    delete_storage_preparation_coordinates_v3, preparation_request_envelope_v3,
    BROKER_METHOD_STORAGE_PREPARE_CATALOG, bind_preparation_request_once_v3,
    compare_delete_preparation_retaining_v3, finish_preparation_terminal_once_v3,
    observe_preparation_terminal_post_once_v3, observe_retained_storage_client_owner_v1);

delete_storage_member!(OriginalDeleteStorageApplyLoanV3, DeleteApply,
    apply_request_bound_v3, admit_apply_io_once_v3, apply_header_data_v3,
    delete_storage_apply_coordinates_v3, apply_request_envelope_v3,
    BROKER_METHOD_STORAGE_APPLY, bind_apply_request_once_v3,
    compare_delete_apply_retaining_v3, finish_apply_terminal_once_v3,
    observe_apply_terminal_post_once_v3, observe_retained_storage_client_owner_v1);

delete_storage_member!(OriginalDeleteNetworkApplyLoanV4, DeleteNetwork,
    network_request_bound_v4, admit_network_io_once_v4, network_header_data_v4,
    delete_network_apply_coordinates_v4, network_request_envelope_v4,
    BROKER_METHOD_NETWORK_APPLY, bind_network_request_once_v4,
    compare_delete_network_retaining_v4, finish_network_terminal_once_v4,
    observe_network_terminal_post_once_v4, observe_retained_delete_network_client_owner_v4);
delete_storage_member!(OriginalDeleteMountReapLoanV4, DeleteMount,
    mount_request_bound_v4, admit_mount_io_once_v4, mount_header_data_v4,
    delete_mount_reap_coordinates_v4, mount_request_envelope_v4,
    BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1, bind_mount_request_once_v4,
    compare_delete_mount_retaining_v4, finish_mount_terminal_once_v4,
    observe_mount_terminal_post_once_v4, observe_retained_delete_mount_client_owner_v4);
