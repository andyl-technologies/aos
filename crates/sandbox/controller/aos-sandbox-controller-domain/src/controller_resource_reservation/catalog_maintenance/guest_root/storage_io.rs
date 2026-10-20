//! Binds real method31 and fresh18 to the same Maintenance and completed Storage.
//!
//! The finite member delegates all native transport, packet, schema, outcome,
//! receiving and terminal stages to the existing shared Session IO kernel.
//! Its private constructor rejoins the actual Root-transferred request and
//! continuously held ordinary receiver. No detached signature admits an effect.

use super::*;
use crate::controller_resource_reservation::create_intake::provisioning::receiving::storage_io::StorageIoStagesV1;
use crate::journal::StorageNativeOpeningOwnerLinkV1;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::seqpacket::{SeqpacketSocket, StorageSeqpacketSessionOriginV1};

pub(in crate::controller_resource_reservation::catalog_maintenance) struct MaintenanceStorageIoOriginalV3
{
    pub(in crate::controller_resource_reservation) stages: StorageIoStagesV1,
    origin: Option<StorageSeqpacketSessionOriginV1>,
    nonce: [u8; 16],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    nonce_comparison: Option<Result<(), ResourceReservationErrorV1>>,
    nonce_primary: bool,
    pub(in crate::controller_resource_reservation::catalog_maintenance) entered: bool,
    sdk_refusal: Option<JournalError>,
    pub(in crate::controller_resource_reservation::catalog_maintenance) disposed: bool,
}

impl MaintenanceStorageIoOriginalV3 {
    pub(in crate::controller_resource_reservation::catalog_maintenance) fn require_outcomes_v3(
        &self,
        resource: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        native: &[u8; 64],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.stages
            .require_completed_storage_outcomes_v3(resource, inventory)?;
        if self.stages.completed_session_native_data_v2()? != native || self.disposed {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn new() -> Self {
        Self {
            stages: Default::default(),
            origin: None,
            nonce: [0; 16],
            entropy: None,
            nonce_comparison: None,
            nonce_primary: false,
            entered: false,
            sdk_refusal: None,
            disposed: false,
        }
    }

    pub(super) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        let nonce = || {
            self.entropy
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| {
                    self.nonce_comparison
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
        };
        if self.nonce_primary {
            return nonce();
        }
        self.stages
            .failure()
            .or_else(nonce)
            .or_else(|| self.sdk_refusal.as_ref().map(|cause| cause as _))
    }
}

/// Borrows the actual signed Maintenance request and original held Storage Session.
#[doc(hidden)]
pub struct ControllerMaintenanceStorageIoLoanV3<'loan> {
    owner: &'loan mut CatalogMaintenanceOriginalV2,
    controller: &'loan Journal,
    source: &'loan ProtectedSourceDomainJournalOwnerV1,
    receiving: &'loan crate::ControllerInitialBrokerSessionReceivingV1,
    prepared: &'loan ControllerMaintenanceStorageRequestOriginalV3,
    journal: StorageNativeOpeningOwnerLinkV1,
    binding: [u8; 32],
    context: [u8; 32],
    resident_base: ResourceVector,
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Borrows both real31/fresh18 stages of the original completed Storage Session.
    ///
    /// # Errors
    /// Retains changed Root/request/receiver, purpose, Session, reentry, geometry
    /// or same-F payment refusal before any new entropy or transport operation.
    #[doc(hidden)]
    pub fn borrow_refresh_storage_io_once_v3<'loan>(
        &'loan mut self,
        receiving: &'loan crate::ControllerInitialBrokerSessionReceivingV1,
        prepared: &'loan ControllerMaintenanceStorageRequestOriginalV3,
        journal: &Journal,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ControllerMaintenanceStorageIoLoanV3<'loan>, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, journal, 2)?;
        if self.owner.purpose != Some(MaintenancePurposeV2::CatalogRefresh)
            || self.owner.guest_root.storage_io.entered
            || !aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(
                transcript,
            )
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner
            .guest_root
            .root
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_transferred_request_v3(prepared)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;

        let witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::<
            JournalError,
        >::receiving_footprint_v1()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
        let memory = witness
            .memory_bytes
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ControllerMaintenanceStorageIoLoanV3<'static>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ControllerMaintenanceStorageSdkDisposalV3<'static>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let files = witness
            .open_files
            .checked_mul(2)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cells = witness
            .metadata_cells
            .checked_mul(2)
            .and_then(|cells| u64::try_from(cells).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = journal.held_names_receiving_demand_v2()?;
        self.reserve_additional_v2(
            names.checked_add(names)?.checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, cells),
            )?,
        )?;
        self.owner.guest_root.storage_io.entered = true;
        let resident_base = self.owner.reached;
        Ok(ControllerMaintenanceStorageIoLoanV3 {
            owner: self.owner,
            controller: self.controller,
            source: self.source,
            receiving,
            prepared,
            journal: journal.held_session_owner_link_v1(),
            binding: transcript.session_binding(),
            context: transcript.protected_context_digest(),
            resident_base,
        })
    }
}

impl ControllerMaintenanceStorageIoLoanV3<'_> {
    pub(in crate::controller_resource_reservation) fn io_stages_v2(
        &mut self,
    ) -> &mut StorageIoStagesV1 {
        &mut self.owner.guest_root.storage_io.stages
    }

    pub(in crate::controller_resource_reservation) fn require_current_native_v2(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner
            .require_current_v2(self.controller, self.source)?;
        if self.owner.guest_root.storage_io.disposed {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner
            .source_projection
            .require_same_projection_v2(self.source.journal_ref_v1())?;
        self.owner
            .guest_root
            .root
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_transferred_request_v3(self.prepared)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }

    pub(in crate::controller_resource_reservation) fn complete_base_native_v2(
        &mut self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        Ok(self
            .resident_base
            .checked_add(
                self.owner
                    .guest_root
                    .storage_io
                    .stages
                    .retained_demand_v1(0)?,
            )?
            .checked_add(incoming)?)
    }

    pub(in crate::controller_resource_reservation) fn require_prepared_complete_native_v2(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        let additional = complete.checked_sub(self.owner.reached)?;
        self.owner
            .reserve_additional_v2(self.controller, self.source, additional)
    }

    pub(in crate::controller_resource_reservation) fn require_session_journal_v2(
        &self,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.journal.matches_journal_v1(journal) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation) fn require_session_association_v2(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), crate::ControllerCatalogMaintenanceSessionCurrentnessErrorV2> {
        use crate::ControllerCatalogMaintenanceSessionCurrentnessErrorV2 as E;
        self.require_session_journal_v2(journal)?;
        if transcript.protocol() != BrokerSessionProtocolV1::Storage
            || transcript.session_binding() != self.binding
            || transcript.protected_context_digest() != self.context
        {
            return Err(ResourceReservationErrorV1::Conflict.into());
        }
        let mut native = None;
        let original = &mut self.owner.guest_root.storage_io;
        let returned = if let Some(origin) = original.origin.as_ref() {
            origin.require_same_socket_retaining_v4(socket, &mut native)
        } else {
            socket
                .capture_storage_session_origin_retaining_v4(&mut native)
                .map(|origin| original.origin = Some(origin))
        };
        match (returned, native) {
            (Ok(()), _) => Ok(()),
            (Err(binding), Some(Err(native))) => Err(E::Native { native, binding }),
            (Err(binding), _) => Err(binding.into()),
        }
    }

    pub(in crate::controller_resource_reservation) fn require_prepared_v3(
        &mut self,
        prepared: &ControllerMaintenanceStorageRequestOriginalV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(prepared, self.prepared) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_native_v2()
    }

    pub(in crate::controller_resource_reservation) fn cutoff_data_v3(&self) -> u64 {
        self.prepared.cutoff_data_v3()
    }

    pub(in crate::controller_resource_reservation) fn prepare_inventory_nonce_once_v3(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = &mut self.owner.guest_root.storage_io;
        if original.entropy.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.entropy = Some(rustix::rand::getrandom(
            &mut original.nonce,
            rustix::rand::GetRandomFlags::empty(),
        ));
        original.nonce_comparison = Some(
            if matches!(original.entropy, Some(Ok(16)))
                && original.nonce != [0; 16]
                && original.nonce != self.prepared.preparation.request_header.request_id
            {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            },
        );
        if !matches!(original.nonce_comparison, Some(Ok(()))) {
            original.nonce_primary = true;
            self.owner.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows exact signed31 or freshly retained18 header DATA after admission.
    ///
    /// # Errors
    /// Refuses changed current custody, unadmitted stage or missing fresh nonce.
    #[doc(hidden)]
    pub fn request_header_data_v3(&mut self, inventory: bool)
    -> Result<aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2, ResourceReservationErrorV1>{
        self.require_current_native_v2()?;
        let mut header = self.prepared.preparation.request_header;
        if inventory {
            if !matches!(
                self.owner.guest_root.storage_io.nonce_comparison,
                Some(Ok(()))
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            header.request_id = self.owner.guest_root.storage_io.nonce;
        }
        Ok(header)
    }

    /// Borrows the actual complete signed31/fresh18 native Session position.
    ///
    /// # Errors
    /// Refuses either incomplete terminal, native posts or changed fixed names.
    #[doc(hidden)]
    pub fn completed_session_native_data_v3(
        &self,
    ) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        self.owner
            .guest_root
            .storage_io
            .stages
            .completed_session_native_data_v2()
    }

    /// Keeps an SDK refusal beside the actual same-M native prefixes.
    #[doc(hidden)]
    pub fn retain_storage_sdk_refusal_once_v3(&mut self) {
        self.owner
            .guest_root
            .storage_io
            .sdk_refusal
            .get_or_insert(JournalError::ProtectedBoundary);
        self.owner.first.get_or_insert(First::Sdk);
    }

    /// Latches an earlier actual lower native/financial refusal before SDK posts.
    #[doc(hidden)]
    pub fn retain_storage_io_refusal_once_v3(&mut self) {
        self.owner.first.get_or_insert(First::GuestRoot);
    }
}

/// Holds the actual same-M owner until its two positive SDK flights are dropped.
#[doc(hidden)]
pub struct ControllerMaintenanceStorageSdkDisposalV3<'owner> {
    owner: &'owner mut CatalogMaintenanceOriginalV2,
    completed: bool,
}

impl ControllerMaintenanceStorageSdkDisposalV3<'_> {
    /// Disposes positive native stages only after physical SDK prefix disposal.
    pub fn complete_after_disposal_v3(mut self) {
        drop(std::mem::take(&mut self.owner.guest_root.storage_io.stages));
        self.owner.guest_root.storage_io.disposed = true;
        self.completed = true;
    }
}

impl Drop for ControllerMaintenanceStorageSdkDisposalV3<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner
                .guest_root
                .storage_io
                .sdk_refusal
                .get_or_insert(JournalError::ProtectedBoundary);
            self.owner.first.get_or_insert(First::GuestRoot);
        }
    }
}

impl CatalogMaintenanceOriginalV2 {
    /// Lends real31/fresh18 disposal after Root ACK, catalog confirmation and all posts.
    ///
    /// # Errors
    /// Retains changed exact request/outcomes/native pair, incomplete fresh
    /// physical proof/Root/Source, unfinished posts or repeated disposition.
    #[doc(hidden)]
    pub fn prepare_storage_sdk_disposal_once_v3<'owner>(
        &'owner mut self,
        controller: &Journal,
        prepared: &ControllerMaintenanceStorageRequestOriginalV3,
        resource: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        native: &[u8; 64],
    ) -> Result<ControllerMaintenanceStorageSdkDisposalV3<'owner>, ResourceReservationErrorV1> {
        self.require_completed_posts_v2(controller)?;
        if self.purpose != Some(MaintenancePurposeV2::CatalogRefresh) || !self.warm.completed_v2() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.guest_root
            .storage_io
            .require_outcomes_v3(resource, inventory, native)?;
        let root = self
            .guest_root
            .root
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        root.require_transferred_request_v3(prepared)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if !root.final_ack_completed_v3() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if root.retire_positive_native_once_v3().is_err() {
            self.first.get_or_insert(First::GuestRoot);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(ControllerMaintenanceStorageSdkDisposalV3 {
            owner: self,
            completed: false,
        })
    }
}
