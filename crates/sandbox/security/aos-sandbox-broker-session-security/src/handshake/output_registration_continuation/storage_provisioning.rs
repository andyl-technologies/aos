//! Retains actual C23 Apply and fresh Inventory on the same completed Session.
//!
//! Both fixed methods use the existing authenticated client request, IO, schema,
//! outcome writer and currentness kernel. Native C23 holds the exact scoped Core
//! attempt; this owner retains every packet, syscall, typed model and owed post
//! through later Source/Root consumers. Ordinary callers keep their old routes.

use super::storage_inventory::wait::InventoryWaitOriginalsV1;
use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::{
    InventoryStorageRequest, InventoryStorageResourcesResponse, StorageResult,
};
use aos_sandbox_controller_domain::{
    CreateProvisioningStorageIoLoanV1, PreparedAuthorityEffectV1, ResourceReservationErrorV1,
};
use aos_sandbox_protocol::{
    ValidatedStorageInventory,
    authenticated_session::all_methods::{
        AuthenticatedBrokerMethodOutcomeV1,
        outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
    },
};
use buffa::Message as _;
use std::error::Error;
use std::mem::size_of;

mod member;
mod host_catalog;
mod catalog_maintenance;
mod maintenance_storage;
pub(crate) use maintenance_storage::MaintenanceStorageSessionIoOriginalV3;
pub use catalog_maintenance::ControllerCatalogMaintenanceSessionIoOriginalV2;
mod delete_preparation;
mod delete_apply;
mod delete_network;
pub use delete_network::{DeleteNetworkApplySessionIoOriginalV4, delete_network_apply_security_shape_v4, delete_network_apply_response_maximum_v4};
mod delete_mount;
pub use delete_mount::{DeleteMountReapSessionIoOriginalV4, delete_mount_reap_security_shape_v4, delete_mount_reap_response_maximum_v4};
mod delete_session;
pub use delete_apply::{DeleteStorageApplySessionIoOriginalV3, delete_storage_apply_security_shape_v3, delete_storage_apply_response_maximum_v3};
pub use delete_preparation::{DeleteStoragePreparationSessionIoOriginalV3, delete_storage_preparation_security_shape_v3, delete_storage_preparation_response_maximum_v3};
pub use host_catalog::{StartHostCatalogSessionIoOriginalV2, StartHostCatalogQualifiedSessionBorrowV2};
mod start_storage;
mod completed_models;
mod execution_no_apply;
pub use execution_no_apply::{HostExecutionNoApplySessionIoOriginalV2, HostExecutionNoApplyClientSessionBorrowV2};
mod execution_availability;
pub use execution_availability::{ExecutionAvailabilitySessionIoOriginalV2, ExecutionAvailabilityClientSessionBorrowV2};
pub use completed_models::StartResourceCompletedModelsOriginalV2;
use super::storage_io::{NativeStorageIoDisposalV1, NativeStorageIoV1};
use member::{ProvisioningKindV4, ProvisioningMemberV4};

#[derive(Clone, Copy)]
enum First { Fixed, Coordinates, Preparation, Shared, Send, Wait, Receive, Predecessor, Final, Completion, Reentry }

struct ProvisioningFlightV1 {
    kind: ProvisioningKindV4,
    shared: OriginalStoragePreparationClientFlightV1,
    wait: InventoryWaitOriginalsV1<ResourceReservationErrorV1>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    fixed_original_selected: bool,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    request_originals: Option<Box<crate::recovery::ClientRequestOriginalsV1>>,
    preparation_post: Option<Result<(), ResourceReservationErrorV1>>,
    preparation_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    request_binding: Option<Result<(), ResourceReservationErrorV1>>,
    durable_request: Option<Result<aos_sandbox_controller_domain::PreparedAuthorityBrokerRequestV1, aos_sandbox_controller_domain::ReconcilerError>>,
    unsigned: Option<BrokerRequestEnvelope>,
    send_before: Option<Result<(), ResourceReservationErrorV1>>,
    send_after: Option<Result<(), ResourceReservationErrorV1>>,
    receive_before: Option<Result<(), ResourceReservationErrorV1>>,
    outcome: Option<Box<AuthenticatedBrokerMethodOutcomeCaptureV1>>,
    predecessor_admission: Option<Result<(), ResourceReservationErrorV1>>,
    predecessor_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    final_transport: Option<crate::recovery::RetainedStorageClientOwnerPostV1>,
    final_native: Option<Result<(), ResourceReservationErrorV1>>,
    completion: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
    entered: bool,
    completed: bool,
}

impl ProvisioningFlightV1 {
    fn new(kind: ProvisioningKindV4) -> Self {
        let mut shared = OriginalStoragePreparationClientFlightV1::empty();
        shared.inner.purpose = match kind {
            ProvisioningKindV4::Storage => OriginalClientFlightPurposeV1::StorageProvisioning,
            ProvisioningKindV4::MaintenanceCatalog => OriginalClientFlightPurposeV1::CatalogMaintenance,
            ProvisioningKindV4::MaintenanceStorage => OriginalClientFlightPurposeV1::MaintenanceStorage,
            ProvisioningKindV4::DeleteNetwork => OriginalClientFlightPurposeV1::DeleteNetwork,
            ProvisioningKindV4::DeleteMount => OriginalClientFlightPurposeV1::DeleteMount,
            ProvisioningKindV4::DeleteApply => OriginalClientFlightPurposeV1::DeleteStorageApply,
            ProvisioningKindV4::DeletePreparation => OriginalClientFlightPurposeV1::DeleteStoragePreparation,
            ProvisioningKindV4::ExecutionNoApply => OriginalClientFlightPurposeV1::ExecutionNoApply,
            ProvisioningKindV4::ExecutionAvailability => OriginalClientFlightPurposeV1::ExecutionAvailability,
            ProvisioningKindV4::StartStorage | ProvisioningKindV4::Network | ProvisioningKindV4::Mount | ProvisioningKindV4::Host | ProvisioningKindV4::HostCatalog => OriginalClientFlightPurposeV1::StartResourceProvisioning,
        };
        Self {
            kind, shared,
            wait: Default::default(),
            fixed: None,
            fixed_original_selected: matches!(kind, ProvisioningKindV4::Storage),
            preparation: None,
            request_originals: None,
            preparation_post: None,
            preparation_disposal: None,
            request_binding: None,
            durable_request: None,
            unsigned: None,
            send_before: None,
            send_after: None,
            receive_before: None,
            outcome: None,
            predecessor_admission: None,
            predecessor_originals: None,
            predecessor: None,
            final_transport: None,
            final_native: None,
            completion: None,
            first: None,
            entered: false,
            completed: false,
        }
    }

    // Only the shared driver calls this after its genuine typed member has
    // admitted the complete shape. Refusal/post destinations remain inline;
    // diagnostics and all inert constructors never initialize these captures.
    fn initialize_admitted_body_once_v5(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.fixed, Some(Ok(())))
            || self.request_originals.is_some()
            || self.outcome.is_some()
            || self.predecessor_originals.is_some()
        {
            return Err(OutputPreparationClosedV1);
        }

        self.request_originals = Some(Box::new(Default::default()));
        self.outcome = Some(Box::new(Default::default()));
        self.predecessor_originals = Some(Box::new(Default::default()));
        Ok(())
    }

    // Each real capture keeps its own allocation, constructor/return planes
    // and controls. The count comes only from the actual closed owner roster.
    fn body_slots_receiving_bytes_v5(slots: usize) -> Option<usize> {
        fn capture_bytes<T>() -> Option<usize> {
            size_of::<T>()
                .checked_mul(3)?
                .checked_add(size_of::<Box<T>>().checked_mul(2)?)?
                .checked_add(size_of::<std::alloc::Layout>())
        }

        capture_bytes::<crate::recovery::ClientRequestOriginalsV1>()?
            .checked_add(capture_bytes::<AuthenticatedBrokerMethodOutcomeCaptureV1>()?)?
            .checked_add(capture_bytes::<crate::recovery::OutcomeCurrentOriginalsV1>()?)?
            .checked_mul(slots)
    }

    fn mark(&mut self, site: First) {
        self.first.get_or_insert(site);
        self.shared.inner.closed = true;
    }

    fn originals<'held>(
        &self,
        terminal: &'held crate::recovery::ProtectedBrokerOutcomeCommittedAdvancementV1,
        inventory: bool,
    ) -> Result<
        (
            &'held AuthenticatedBrokerMethodOutcomeV1,
            &'held crate::recovery::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        BrokerSessionSecurityError,
    > {
        match self.shared.inner.purpose {
            OriginalClientFlightPurposeV1::DeleteNetwork => terminal.delete_network_originals_v4(),
            OriginalClientFlightPurposeV1::DeleteMount => terminal.delete_mount_originals_v4(),
            OriginalClientFlightPurposeV1::DeleteStorageApply => terminal.delete_storage_apply_originals_v3(),
            OriginalClientFlightPurposeV1::DeleteStoragePreparation => terminal.delete_storage_preparation_originals_v3(),
            OriginalClientFlightPurposeV1::StorageProvisioning => {
                terminal.storage_provisioning_client_originals_v1(inventory)
            }
            OriginalClientFlightPurposeV1::CatalogMaintenance => terminal.catalog_maintenance_client_originals_v2(),
            OriginalClientFlightPurposeV1::MaintenanceStorage => terminal.maintenance_storage_client_originals_v3(inventory),
            OriginalClientFlightPurposeV1::ExecutionNoApply => terminal.execution_no_apply_client_originals_v2(),
            OriginalClientFlightPurposeV1::ExecutionAvailability => terminal.execution_availability_client_originals_v2(),
            OriginalClientFlightPurposeV1::StartResourceProvisioning => {
                if matches!(self.kind, ProvisioningKindV4::HostCatalog) {
                    terminal.start_host_catalog_client_originals_v2()
                } else {
                    terminal.start_resource_provisioning_client_originals_v2(inventory)
                }
            }
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn authenticated(&self, inventory: bool) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        if !self.completed || self.shared.inner.closed {
            return None;
        }
        match self.shared.inner.committed.as_ref()? {
            crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal) => self
                .originals(terminal, inventory)
                .ok()
                .map(|(outcome, _)| outcome),
            _ => None,
        }
    }
}

/// Retains the two exact signed IO flights beside the same installed Session.
///
/// Construction is inert. Only the actual private Core scope's opaque C23 loan
/// can enter either stage; Inventory follows the completed actual Apply owner.
/// Its historical getters lend DATA and never authorize a Source or Core append.
#[doc(hidden)]
#[must_use = "retain both whole flights through native posts and Source/Root disposition"]
pub struct StorageProvisioningSessionIoOriginalV1 {
    apply: ProvisioningFlightV1,
    inventory: ProvisioningFlightV1,
    completed_native: Option<Result<Option<[u8; 64]>, ResourceReservationErrorV1>>,
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Constructs fixed empty destinations without allocation, IO or admission.
    #[must_use]
    pub fn new() -> Self {
        Self::new_kind_v4(ProvisioningKindV4::Storage)
    }

    fn new_kind_v4(kind: ProvisioningKindV4) -> Self {
        Self {
            apply: ProvisioningFlightV1::new(kind),
            inventory: ProvisioningFlightV1::new(kind),
            completed_native: None,
        }
    }

    /// Runs the actual durable method-7 request on its original Apply Session.
    ///
    /// # Errors
    /// Returns a stopping marker while retaining exact native/schema/model
    /// originals; no failed or already entered stage may be replaced.
    pub fn apply_once_v1(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.run_storage_provisioning_apply_once_v1(self, original, prepared)
    }

    /// Runs fresh method-18 Inventory after this same owner's completed Apply.
    ///
    /// # Errors
    /// Refuses failed/missing Apply, changed Session/C23, and any IO/schema/post failure.
    pub fn inventory_once_v1(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.run_storage_provisioning_inventory_once_v1(self, original, prepared)
    }

    pub(crate) fn run_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>,
        prepared: &PreparedAuthorityEffectV1,
        inventory: bool,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.run_member_once_v4(session, original, prepared, inventory)
    }

    fn run_member_once_v4<N: ProvisioningMemberV4>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut N,
        prepared: &N::Prepared,
        inventory: bool,
    ) -> Result<(), OutputPreparationClosedV1> {
        if inventory && self.apply.authenticated(false).is_none() {
            return Err(OutputPreparationClosedV1);
        }
        let flight = if inventory { &mut self.inventory } else { &mut self.apply };
        Self::run_flight_once_v4(flight, session, original, prepared, inventory)?;
        if inventory && matches!(flight.shared.inner.purpose, OriginalClientFlightPurposeV1::StartResourceProvisioning | OriginalClientFlightPurposeV1::MaintenanceStorage) {
            self.completed_native = Some(original.completed_native_data_v2());
            if !matches!(self.completed_native, Some(Ok(_))) { return Err(OutputPreparationClosedV1); }
        }
        Ok(())
    }

    fn run_flight_once_v4<N: ProvisioningMemberV4>(
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut N,
        prepared: &N::Prepared,
        inventory: bool,
    ) -> Result<(), OutputPreparationClosedV1> {
        let shape = Self::shape::<N>(session, original, prepared, inventory);
        if flight.entered {
            flight.mark(First::Reentry);
            return Err(OutputPreparationClosedV1);
        }
        flight.entered = true;
        if !original.matches_kind_v2(flight.kind, prepared) {
            flight.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
            flight.mark(First::Fixed);
            Self::final_posts(flight, session, original);
            return Err(OutputPreparationClosedV1);
        }
        let Some(shape) = shape else {
            flight.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
            flight.mark(First::Fixed);
            if matches!(flight.shared.inner.purpose, OriginalClientFlightPurposeV1::StartResourceProvisioning | OriginalClientFlightPurposeV1::MaintenanceStorage
                | OriginalClientFlightPurposeV1::DeleteStoragePreparation | OriginalClientFlightPurposeV1::DeleteStorageApply | OriginalClientFlightPurposeV1::DeleteNetwork | OriginalClientFlightPurposeV1::DeleteMount
                | OriginalClientFlightPurposeV1::ExecutionAvailability | OriginalClientFlightPurposeV1::ExecutionNoApply) {
                Self::final_posts(flight, session, original);
            }
            return Err(OutputPreparationClosedV1);
        };
        flight.fixed = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => {
                flight.fixed_original_selected = true;
                original.admit_v4(
                prepared,
                journal,
                &session.socket,
                &session.transcript,
                shape,
                inventory,
            )
            },
            Err(cause) => {
                flight.shared.inner.protected_failure = Some(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        });
        if !matches!(flight.fixed, Some(Ok(()))) {
            flight.mark(First::Fixed);
            Self::final_posts(flight, session, original);
            return Err(OutputPreparationClosedV1);
        }
        let primary = match flight.initialize_admitted_body_once_v5() {
            Ok(()) => Self::body::<N>(
                flight,
                session,
                original,
                prepared,
                inventory,
                shape.request_bytes,
            ),
            Err(_) => {
                flight.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
                flight.fixed_original_selected = false;
                flight.mark(First::Fixed);
                false
            }
        };
        if !primary {
            original.retain_primary_refusal_v4(flight.selected_original_failure());
        }
        Self::final_posts(flight, session, original);
        if !primary
            || !flight
                .final_transport
                .as_ref()
                .is_some_and(|post| post.failure().is_none())
            || !matches!(flight.final_native, Some(Ok(())))
        {
            flight.mark(First::Final);
            return Err(OutputPreparationClosedV1);
        }
        let outcome = match flight.shared.inner.committed.as_ref() {
            Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) => flight
                .originals(terminal, inventory)
                .ok()
                .map(|(outcome, _)| outcome),
            _ => None,
        };
        flight.completion = Some(match outcome {
            Some(outcome) => match original.session_journal_v1(&session.owner) {
                Ok(journal) => original.finish_terminal_v4(prepared, journal, outcome),
                Err(cause) => {
                    flight.shared.inner.protected_failure.get_or_insert(cause);
                    Err(ResourceReservationErrorV1::Conflict)
                }
            },
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(flight.completion, Some(Ok(()))) {
            flight.mark(First::Completion);
            return Err(OutputPreparationClosedV1);
        }
        flight.completed = true;
        Ok(())
    }

    fn final_posts<N: ProvisioningMemberV4>(
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut N,
    ) {
        flight.final_transport = Some(N::observe_owner_v4(
            &mut session.owner,
            &session.transcript,
            session.socket.peer(),
        ));
        flight.final_native = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => {
                original.observe_terminal_post_v4(journal, &session.socket, &session.transcript)
            }
            Err(cause) => {
                flight.shared.inner.protected_failure.get_or_insert(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        });
    }

    fn shape<N: ProvisioningMemberV4>(
        session: &DormantAuthenticatedBrokerSessionV1,
        original: &N,
        prepared: &N::Prepared,
        inventory: bool,
    ) -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        Self::shape_data_v4(
            session.transcript.negotiated_maximum_response_bytes() as usize,
            original.request_packet_bound_v4(prepared, inventory)?,
            N::flight_owner_inline_bytes_v4()?, original.extra_inline_bytes_v4()?)
    }

    fn shape_data_v4(negotiated_maximum: usize, request_bytes: usize,
        flight_bytes: usize, extra_bytes: usize,
    ) -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
        let maximum = negotiated_maximum
            .min(aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES);
        if maximum == 0 || request_bytes == 0 { return None; }
        let (native_bytes, native_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::storage_preparation_receive_obligations_v1(maximum)?;
        let (current, _) = crate::recovery::OutcomeCurrentOriginalsV1::receiving_footprint_v1()?;
        let request = crate::recovery::ClientRequestOriginalsV1::receiving_backing_bytes_v1()?;
        let (post, _) =
            crate::recovery::RetainedStorageClientOwnerPostV1::receiving_peer_footprint_v1()?;
        let wait = InventoryWaitOriginalsV1::<ResourceReservationErrorV1>::receiving_construction_bytes_v1()?;
        let retained_endpoint_files = crate::recovery::ClientRequestOriginalsV1::retained_endpoint_open_files_v1()?
            .checked_add(crate::recovery::OutcomeCurrentOriginalsV1::retained_endpoint_open_files_v1()?)?
            .checked_add(crate::recovery::RetainedStorageClientOwnerPostV1::retained_endpoint_open_files_v1()?)?;
        Some(aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1 {
            receiving_bytes: flight_bytes
                .checked_add(extra_bytes)?
                .checked_add(native_bytes)?
                .checked_add(current)?
                .checked_add(wait)?
                .checked_add(request)?
                .checked_add(post)?,
            receive_files: native_files,
            retained_endpoint_files,
            namespace_entries: 0,
            request_bytes,
            response_bytes: maximum,
        })
    }

    fn body<N: ProvisioningMemberV4>(
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut N,
        prepared: &N::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        // No body phase may fall back to an ordinary, nonretaining engine.
        // The sole initializer runs only after the genuine admission above;
        // these captures remain occupied until whole positive disposition.
        if flight.request_originals.is_none()
            || flight.outcome.is_none()
            || flight.predecessor_originals.is_none()
        {
            flight.mark(First::Preparation);
            return false;
        }
        flight.preparation = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => {
                original.begin_request_preparation_v4(journal, &session.socket, &session.transcript)
            }
            Err(cause) => {
                flight.shared.inner.protected_failure = Some(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        });
        let prepared_ok = if matches!(flight.preparation, Some(Ok(()))) {
            original.prepare_request_v4(flight, session, prepared, inventory, maximum_request)
        } else {
            flight.mark(First::Preparation);
            false
        };
        flight.preparation_post = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => {
                original.observe_io_post_once(journal, &session.socket, &session.transcript)
            }
            Err(cause) => {
                flight.shared.inner.protected_failure.get_or_insert(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        });
        if !prepared_ok || !matches!(flight.preparation_post, Some(Ok(()))) {
            flight.mark(First::Preparation);
            return false;
        }
        flight.preparation_disposal = Some(original.finish_positive_io_once());
        if !matches!(flight.preparation_disposal, Some(Ok(()))) {
            flight.mark(First::Preparation);
            return false;
        }
        flight.request_binding = Some(match flight.shared.inner.request() {
            Some(request) => original.bind_request_v4(prepared, request),
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(flight.request_binding, Some(Ok(()))) {
            flight.mark(First::Preparation);
            return false;
        }
        loop {
            match super::storage_io::send_once(
                &mut flight.shared,
                &mut flight.wait,
                &mut flight.send_before,
                &mut flight.send_after,
                session,
                original,
            ) {
                Ok(StoragePreparationClientProgressV1::Sent) => break,
                Ok(StoragePreparationClientProgressV1::Pending) => {
                    if !flight
                        .wait
                        .wait_original_once(session, &mut flight.shared.inner, original)
                    {
                        flight.mark(First::Wait);
                        return false;
                    }
                }
                _ => {
                    flight.mark(First::Send);
                    return false;
                }
            }
        }
        loop {
            flight.receive_before = Some(match original.session_journal_v1(&session.owner) {
                Ok(journal) => {
                    original.begin_receive_v4(journal, &session.socket, &session.transcript)
                }
                Err(cause) => {
                    flight.shared.inner.protected_failure.get_or_insert(cause);
                    Err(ResourceReservationErrorV1::Conflict)
                }
            });
            if !matches!(flight.receive_before, Some(Ok(()))) {
                flight.shared.inner.inventory_io_post = Some(
                    flight
                        .shared
                        .inner
                        .observe_storage_io_post_v1(session, original)
                        .map_err(Into::into),
                );
                flight.mark(First::Receive);
                return false;
            }
            let committed = flight.shared.inner.receive_terminal_engine_v1(
                session,
                Some(original),
                match flight.outcome.as_mut() {
                    Some(capture) => Some(capture.as_mut()),
                    None => return false,
                },
            );
            if flight.shared.inner.inventory_io_post.is_none() {
                flight.shared.inner.inventory_io_post = Some(
                    flight
                        .shared
                        .inner
                        .observe_storage_io_post_v1(session, original)
                        .map_err(Into::into),
                );
            }
            if committed {
                break;
            }
            if !flight.shared.inner.closed
                && flight.shared.inner.terminal_packet.is_nonconsuming_v1()
            {
                let Some(Err(receipt)) = flight.shared.inner.terminal_packet.received.as_ref()
                else {
                    flight.mark(First::Receive);
                    return false;
                };
                let disposal = match original.prepare_pending_receive_v4(receipt) {
                    Ok(disposal) => disposal,
                    Err(_) => {
                        flight.mark(First::Receive);
                        return false;
                    }
                };
                drop(std::mem::replace(
                    &mut flight.shared.inner.terminal_packet,
                    OriginalOutputPacketV1::empty(),
                ));
                disposal.complete_after_receipt_disposal();
                flight.shared.inner.inventory_io_post = None;
                flight.receive_before = None;
                if !flight.wait.arm_receive()
                    || !flight
                        .wait
                        .wait_original_once(session, &mut flight.shared.inner, original)
                {
                    flight.mark(First::Wait);
                    return false;
                }
            } else {
                flight.mark(First::Shared);
                return false;
            }
        }
        flight.predecessor_admission = Some(match original.session_journal_v1(&session.owner) {
            Ok(journal) => original.admit_predecessor_v4(journal),
            Err(cause) => {
                flight.shared.inner.protected_failure.get_or_insert(cause);
                Err(ResourceReservationErrorV1::Conflict)
            }
        });
        if !matches!(flight.predecessor_admission, Some(Ok(()))) {
            flight.mark(First::Predecessor);
            return false;
        }
        if let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) =
            flight.shared.inner.committed.as_ref()
        {
            match flight.originals(terminal, inventory) {
                Ok((_, currentness)) => {
                    flight.predecessor = Some(
                        N::compare_predecessor_v4(
                            &mut session.owner,
                            currentness,
                            session.socket.peer(),
                            match flight.predecessor_originals.as_mut() {
                                Some(capture) => capture.as_mut(),
                                None => return false,
                            },
                        ),
                    );
                }
                Err(cause) => {
                    flight.shared.inner.protected_failure.get_or_insert(cause);
                }
            }
        }
        if !matches!(flight.predecessor, Some(Ok(()))) {
            flight.mark(First::Predecessor);
            return false;
        }
        true
    }

    /// Borrows the original completed authenticated Apply outcome.
    #[must_use]
    pub fn completed_apply_outcome_v1(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.apply.authenticated(false)
    }

    /// Borrows the same parser's complete validated Apply response.
    #[must_use]
    fn completed_apply_result_v1(&self) -> Option<&StorageResult> {
        self.completed_apply_outcome_v1()?;
        self.apply.outcome.as_ref()?.retained_storage_apply_response_data_v1()
    }

    /// Borrows the original fresh authenticated Inventory outcome.
    #[must_use]
    fn completed_inventory_outcome_v1(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.inventory.authenticated(true)
    }

    /// Borrows the same parser's complete semantic and raw Inventory model.
    #[must_use]
    fn completed_inventory_model_v1(
        &self,
    ) -> Option<&(ValidatedStorageInventory, InventoryStorageResourcesResponse)> {
        self.completed_inventory_outcome_v1()?;
        self.inventory
            .outcome
            .as_ref()?
            .retained_storage_inventory_response_data_v1()
    }
}

impl Default for StorageProvisioningSessionIoOriginalV1 {
    fn default() -> Self { Self::new() }
}

impl ProvisioningFlightV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<E: Error + 'static>(slot: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
        }
        let shared = || self.shared.inner.failure().map(|returned| {
            // Only the exact admission marker can select its richer schema
            // cause. An earlier raw packet/crypto/native refusal stays first.
            if let (Some(actual), Some(Err(marker))) =
                (returned.downcast_ref::<BrokerSessionSecurityError>(), self.shared.inner.admission.as_ref()) {
                if std::ptr::eq(actual, marker) {
                    return self.outcome.as_ref().and_then(|capture| capture.cause())
                        .unwrap_or(returned);
                }
            }
            if let (Some(actual), Some(Err(marker))) =
                (returned.downcast_ref::<BrokerSessionSecurityError>(), self.shared.inner.prepared.as_ref()) {
                if std::ptr::eq(actual, marker) {
                    return self.request_originals.as_ref().and_then(|capture| capture.failure())
                        .unwrap_or(returned);
                }
            }
            returned
        });
        let selected = match self.first? {
            First::Fixed => {
                if matches!(self.shared.inner.purpose,
                    OriginalClientFlightPurposeV1::StartResourceProvisioning | OriginalClientFlightPurposeV1::MaintenanceStorage
                        | OriginalClientFlightPurposeV1::CatalogMaintenance
                        | OriginalClientFlightPurposeV1::DeleteStoragePreparation
                        | OriginalClientFlightPurposeV1::DeleteStorageApply | OriginalClientFlightPurposeV1::DeleteNetwork | OriginalClientFlightPurposeV1::DeleteMount | OriginalClientFlightPurposeV1::ExecutionAvailability | OriginalClientFlightPurposeV1::ExecutionNoApply)
                    && !self.fixed_original_selected {
                    shared().or_else(|| cause(&self.fixed))
                } else { cause(&self.fixed) }
            },
            First::Coordinates => self.durable_request.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)).or_else(shared),
            First::Preparation => cause(&self.preparation).or_else(|| {
                self.durable_request.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            }).or_else(shared).or_else(|| cause(&self.preparation_post)).or_else(|| cause(&self.preparation_disposal)).or_else(|| cause(&self.request_binding)),
            First::Shared => shared(),
            First::Send => cause(&self.send_before).or_else(shared).or_else(|| cause(&self.send_after)),
            First::Wait => self.wait.failure_with_native(None).or_else(shared),
            First::Receive => cause(&self.receive_before).or_else(shared),
            First::Predecessor => cause(&self.predecessor_admission)
                .or_else(|| self.predecessor_originals.as_ref().and_then(|capture| capture.failure()))
                .or_else(|| cause(&self.predecessor))
                .or_else(shared),
            First::Final => shared().or_else(|| self.final_transport.as_ref().and_then(|post| post.failure())).or_else(|| cause(&self.final_native)),
            First::Completion => cause(&self.completion).or_else(shared),
            First::Reentry => Some(&OutputPreparationClosedV1 as &(dyn Error + 'static)),
        };
        selected.or(Some(&OutputPreparationClosedV1 as &(dyn Error + 'static)))
    }
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Borrows the selected actual retained syscall, schema, model or post cause.
    ///
    /// Native financial markers resolve through the same C23 scope's original
    /// diagnostic owner; this view never clones that owner's errors or probes.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.apply.failure().or_else(|| self.inventory.failure())
            .or_else(|| self.completed_native.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Borrows the exact completed signed/typed IO beside its actual Session.
    ///
    /// # Errors
    /// Refuses unfinished or failed IO, a substituted Session or another C23.
    pub(crate) fn borrow_workspace_original_v1<'models>(&'models self,
        session: &'models crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>, prepared: &PreparedAuthorityEffectV1,
    ) -> Result<aos_sandbox_controller_domain::StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        session.borrow_storage_provisioning_workspace_v1(self, original, prepared)
    }

    pub(crate) fn borrow_workspace_kernel_v1<'models>(&'models self, session: &'models DormantAuthenticatedBrokerSessionV1,
        original: &mut CreateProvisioningStorageIoLoanV1<'_>, prepared: &PreparedAuthorityEffectV1,
    ) -> Result<aos_sandbox_controller_domain::StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        let apply = self.completed_apply_outcome_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let result = self.completed_apply_result_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let inventory = self.completed_inventory_outcome_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let model = self.completed_inventory_model_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let journal = session.owner.retained_storage_client_journal_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        original.borrow_completed_storage_workspace_v1(prepared, journal, &session.socket, &session.transcript,
            apply, result, inventory, model)
    }
}

impl ProvisioningFlightV1 {
    fn selected_original_failure(&self) -> bool {
        let shared_failure = self.shared.inner.failure();
        match self.first {
            Some(First::Fixed) => self.fixed_original_selected
                && self.fixed.as_ref().is_some_and(Result::is_err),
            Some(First::Preparation) => self.preparation.as_ref().is_some_and(Result::is_err)
                || (shared_failure.is_none() && (self.preparation_post.as_ref().is_some_and(Result::is_err)
                    || self.preparation_disposal.as_ref().is_some_and(Result::is_err)
                    || self.request_binding.as_ref().is_some_and(Result::is_err))),
            Some(First::Send) => self.send_before.as_ref().is_some_and(Result::is_err)
                || (shared_failure.is_none() && self.send_after.as_ref().is_some_and(Result::is_err)),
            Some(First::Receive) => self.receive_before.as_ref().is_some_and(Result::is_err),
            Some(First::Shared) => shared_failure.is_none() && (
                self.shared.inner.inventory_io_post.as_ref().is_some_and(Result::is_err)
                    || self.shared.inner.inventory_decode.as_ref().is_some_and(Result::is_err)
                    || self.shared.inner.inventory_outcome.as_ref().is_some_and(Result::is_err)),
            Some(First::Wait) => self.wait.failure_with_native(None)
                .is_some_and(|cause| cause.is::<ResourceReservationErrorV1>()),
            Some(First::Predecessor) => self.predecessor_admission.as_ref().is_some_and(Result::is_err),
            Some(First::Final) => shared_failure.is_none()
                && self.final_transport.as_ref().is_some_and(|post| post.failure().is_none())
                && self.final_native.as_ref().is_some_and(Result::is_err),
            Some(First::Completion) => self.completion.as_ref().is_some_and(Result::is_err),
            _ => false,
        }
    }
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Identifies only this flight's selected original-native stopping marker.
    ///
    /// Runtime uses this after its actual selected IO hook returned an error to
    /// borrow the same restored Core C23 cause. An earlier raw/socket/schema
    /// cause cannot select a later native post through this diagnostic predicate.
    #[must_use]
    pub fn has_selected_original_failure_v1(&self) -> bool {
        if self.apply.first.is_some() { self.apply.selected_original_failure() }
        else { self.inventory.selected_original_failure() }
    }
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Borrows the completed workspace inside its genuine fresh Source turn.
    ///
    /// The context is minted by the actual current Root/C23 Action after the
    /// Core child completed. It does not recreate the earlier Applying loan.
    /// Both signed outcomes, typed models and native Session stay borrowed for
    /// the returned lender's lifetime.
    ///
    /// # Errors
    /// Refuses incomplete IO, a changed Session or model, or a failed current
    /// Action/Root/C23 association or complete representation admission.
    #[doc(hidden)]
    pub fn borrow_source_workspace_original_v1<'models>(
        &'models self,
        session: &'models crate::DormantAuthenticatedBrokerSessionV1,
        context: &mut aos_sandbox_controller_domain::CreateProvisioningSourceWorkspaceContextV1<'_>,
    ) -> Result<aos_sandbox_controller_domain::StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        session.borrow_storage_provisioning_source_workspace_v1(self, context)
    }

    pub(crate) fn borrow_source_workspace_kernel_v1<'models>(
        &'models self,
        session: &'models DormantAuthenticatedBrokerSessionV1,
        context: &mut aos_sandbox_controller_domain::CreateProvisioningSourceWorkspaceContextV1<'_>,
    ) -> Result<aos_sandbox_controller_domain::StorageProvisioningWorkspaceOriginalV1<'models>, ResourceReservationErrorV1> {
        let apply = self.completed_apply_outcome_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let result = self.completed_apply_result_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let inventory = self.completed_inventory_outcome_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let model = self.completed_inventory_model_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let journal = session.owner.retained_storage_client_journal_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        context.borrow_completed_storage_workspace_v1(journal, &session.socket,
            &session.transcript, apply, result, inventory, model)
    }
}

impl StorageProvisioningSessionIoOriginalV1 {
    /// Bounds the complete independently owed post before the Core IO take.
    ///
    /// This pure supplier includes the actual returned post carriers, retained
    /// peer and dedicated endpoint native backing, the closed floor archive,
    /// and the same-Session association result carriers. It creates no scope,
    /// Session, financial original, permission or selected payer.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_post_receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (peer_bytes, _) = crate::recovery::RetainedStorageClientOwnerPostV1::receiving_peer_footprint_v1()?;
        let endpoint_files = crate::recovery::RetainedStorageClientOwnerPostV1::retained_endpoint_open_files_v1()?;
        let floor = crate::recovery::floor_revalidation_footprint_v1()?;
        let bytes = size_of::<crate::recovery::RetainedStorageClientOwnerPostV1>().checked_mul(2)?
            .checked_add(peer_bytes)?
            .checked_add(floor.inline_bytes)?.checked_add(floor.heap_bytes)?
            .checked_add(aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1::native_post_carrier_bytes_v1()?)?;
        let files = endpoint_files.checked_add(floor.file_descriptors)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?))
    }
}

/// Retains Network63 and its following fresh signed Inventory19 on one new Start Session.
#[must_use = "retain both whole flights through C, Root and source disposition"]
pub struct StartResourceProvisioningSessionIoOriginalV4 {
    inner: StorageProvisioningSessionIoOriginalV1,
    completed_models: Option<StartResourceCompletedModelsOriginalV2>,
}

impl StartResourceProvisioningSessionIoOriginalV4 {
    /// Creates inert destinations without allocation, IO or authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: StorageProvisioningSessionIoOriginalV1::new_kind_v4(ProvisioningKindV4::Network),
            completed_models: None,
        }
    }

    /// Creates only inert destinations for the closed Mount62/Inventory16 pair.
    #[must_use]
    pub fn mount_namespace_v2() -> Self {
        Self { inner: StorageProvisioningSessionIoOriginalV1::new_kind_v4(ProvisioningKindV4::Mount), completed_models: None }
    }

    /// Creates inert destinations for the closed Host1 and fresh Inventory3 pair.
    #[must_use]
    pub fn host_launch_v2() -> Self {
        Self { inner: StorageProvisioningSessionIoOriginalV1::new_kind_v4(ProvisioningKindV4::Host), completed_models: None }
    }

    /// Runs this genuine resource's exact prepared request on its retained Session.
    ///
    /// # Errors
    /// Retains the first schema/native/funding failure and all independently owed posts.
    pub fn prepare_once_v4(
        &mut self,
        session: &mut super::super::StartResourceSessionBorrowV4<'_>,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.inner
            .run_member_once_v4(session.inner, original, prepared, false)
    }

    /// Runs the exact fresh signed Inventory after this owner's completed resource request.
    ///
    /// # Errors
    /// Refuses missing preparation, substituted originals, reentry or an IO/post failure.
    pub fn inventory_once_v4(
        &mut self,
        session: &mut super::super::StartResourceSessionBorrowV4<'_>,
        original: &mut aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_>,
        prepared: &aos_sandbox_controller_domain::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.inner
            .run_member_once_v4(session.inner, original, prepared, true)
    }

    /// Borrows the original completed signed preparation outcome as historical DATA.
    #[must_use]
    pub fn completed_prepare_outcome_v4(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.inner.apply.authenticated(false)
    }

    /// Borrows the same parser's completed preparation response DATA.
    #[must_use]
    pub fn completed_prepare_result_v4(
        &self,
    ) -> Option<&aos_sandbox_api::aos::sandbox::local::v1::NetworkResult> {
        self.completed_prepare_outcome_v4()?;
        self.inner
            .apply
            .outcome
            .as_ref()?
            .retained_network_prepare_response_data_v4()
    }

    /// Borrows the original fresh signed Inventory outcome as historical DATA.
    #[must_use]
    pub fn completed_inventory_outcome_v4(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.inner.inventory.authenticated(true)
    }

    /// Borrows the same canonical decoder's complete validated Inventory DATA.
    #[must_use]
    pub fn completed_inventory_model_v4(
        &self,
    ) -> Option<&aos_sandbox_protocol::ValidatedNetworkInventory> {
        self.completed_inventory_outcome_v4()?;
        self.inner
            .inventory
            .outcome
            .as_ref()?
            .retained_network_inventory_response_data_v4()
    }

    /// Borrows the same sole decoder's actual completed Mount62 resource.
    #[must_use]
    pub fn completed_mount_namespace_result_v2(&self)
        -> Option<&aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1> {
        if !matches!(self.inner.apply.kind, ProvisioningKindV4::Mount) || self.failure().is_some() {
            return None;
        }
        self.completed_prepare_outcome_v4()?;
        self.inner.apply.outcome.as_ref()?.retained_mount_namespace_result_data_v2()
    }

    /// Borrows the same sole decoder's completed Mount62/Inventory16 model.
    ///
    /// This historical DATA is available only on this owner's actual Mount
    /// pair after authenticated IO and all independently owed native posts.
    #[must_use]
    pub fn completed_mount_inventory_model_v2(
        &self,
    ) -> Option<&aos_sandbox_protocol::ValidatedDestinationSlotInventory> {
        if !matches!(self.inner.inventory.kind, ProvisioningKindV4::Mount)
            || self.failure().is_some() {
            return None;
        }
        self.completed_prepare_outcome_v4()?;
        self.completed_inventory_outcome_v4()?;
        self.inner.inventory.outcome.as_ref()?.retained_mount_namespace_inventory_data_v2()
    }

    /// Borrows the sole decoder's full fresh Host runtime inventory DATA.
    ///
    /// This does not grant Host execution or substitute for the real final
    /// Root verifier, Guardian readiness, native posts or physical disposition.
    #[must_use]
    pub fn completed_host_inventory_model_v2(&self)
        -> Option<&aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse> {
        if !matches!(self.inner.inventory.kind, ProvisioningKindV4::Host)
            || self.failure().is_some() { return None; }
        self.completed_prepare_outcome_v4()?;
        self.completed_inventory_outcome_v4()?;
        self.inner.inventory.outcome.as_ref()?.retained_host_inventory_data_v2()
    }

    /// Borrows the actual earliest retained refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.failure().or_else(|| self.completed_models.as_ref()?.failure_v2())
    }

    /// Identifies only an earlier actual native/financial first cause.
    #[must_use]
    pub fn has_selected_original_failure_v4(&self) -> bool {
        self.inner.has_selected_original_failure_v1()
    }

    /// Prices the same compiled final-post destinations before new IO entry.
    #[must_use]
    pub fn retained_post_receiving_demand_v4() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let data = size_of::<StartResourceSessionCompletionDataV2<'static>>().checked_mul(2)?
            .checked_add(size_of::<aos_sandbox_controller_domain::StartResourceUpperDisposalV2<'static>>().checked_mul(2)?)?;
        StorageProvisioningSessionIoOriginalV1::retained_post_receiving_demand_v1()?
            .checked_add(aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2::
                completed_native_post_receiving_demand_v2().ok()?).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(data).ok()?)).ok()
    }

    /// Lends exact retained authenticated packets and the actual final native sample.
    ///
    /// # Errors
    /// Refuses incomplete resource/Inventory IO, any retained post/currentness
    /// error, or an absent actual native position. This is comparison DATA only.
    pub fn completed_exchange_data_v2(&self) -> Result<StartResourceSessionCompletionDataV2<'_>, OutputPreparationClosedV1> {
        if self.failure().is_some() { return Err(OutputPreparationClosedV1); }
        let resource = self.completed_prepare_outcome_v4().ok_or(OutputPreparationClosedV1)?;
        let inventory = self.completed_inventory_outcome_v4().ok_or(OutputPreparationClosedV1)?;
        let native = self.inner.completed_native.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(Option::as_ref).ok_or(OutputPreparationClosedV1)?;
        Ok(StartResourceSessionCompletionDataV2 {
            resource_request: resource.request().canonical_packet(), resource_outcome: resource.canonical_packet(),
            inventory_request: inventory.request().canonical_packet(), inventory_outcome: inventory.canonical_packet(),
            session_native: native,
        })
    }
}

impl Default for StartResourceProvisioningSessionIoOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrows comparison bytes from one genuinely completed pair of resource IO flights.
///
/// No raw Session, Journal, descriptor, crypto key or adopter is exposed.
pub struct StartResourceSessionCompletionDataV2<'held> {
    /// Exact signed resource request retained by the actual native Session.
    pub resource_request: &'held [u8],
    /// Exact complete authenticated resource outcome from that same Session.
    pub resource_outcome: &'held [u8],
    /// Distinct fresh signed Inventory request retained by that same owner.
    pub inventory_request: &'held [u8],
    /// Exact complete authenticated Inventory outcome from that same Session.
    pub inventory_outcome: &'held [u8],
    /// Actual final names48, NEXT8 and observed held native EOF8.
    pub session_native: &'held [u8; 64],
}
