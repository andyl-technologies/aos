//! Borrows the same paid maintenance for the sole shared Catalog17 flight.
//!
//! This private source constructor carries the real completed ordinary Host
//! receiver and current native turn. The Session remains exclusively held by
//! Security's opaque completed borrower; no generic Session or numeric payer
//! can enter its SDK flight. Independent cookie observations do not depend on
//! healthy financial state once the phase has entered.

use super::queries::CatalogMaintenanceSourceReceivingV2;
mod completion;
pub use completion::{
    ControllerCatalogMaintenanceCatalogDisposalV2, ControllerCatalogMaintenanceCompletionRefusalV2,
};

use super::*;
use crate::ControllerInitialBrokerSessionReceivingV1;
use crate::controller_resource_reservation::create_intake::provisioning::receiving::storage_io::StorageIoStagesV1;
use crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2;
use crate::journal::StorageNativeOpeningOwnerLinkV1;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredential;
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, SeqpacketSocket, StorageSeqpacketSessionOriginV1,
};

/// Owns an independent native cookie refusal without erasing its raw syscall cause.
#[derive(Debug, thiserror::Error)]
#[doc(hidden)]
pub enum ControllerCatalogMaintenanceSessionCurrentnessErrorV2 {
    /// The same held Journal or transcript data failed its actual binding.
    #[error(transparent)]
    Binding(#[from] ResourceReservationErrorV1),
    /// The native cookie sampler failed before its binding projection.
    #[error("catalog maintenance socket cookie failed: {native} ({binding})")]
    Native {
        /// The original kernel error from the single reached cookie sampler.
        #[source]
        native: aos_sandbox_linux::Error,
        /// The same sampler's binding-level projection.
        binding: RecordBindingError,
    },
    /// The actual wrapper or current native cookie changed.
    #[error(transparent)]
    Socket(#[from] RecordBindingError),
}

pub(super) struct CatalogMaintenanceIoOriginalV2 {
    stages: StorageIoStagesV1,
    origin: Option<StorageSeqpacketSessionOriginV1>,
    nonce: [u8; 16],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    nonce_comparison: Option<Result<(), ResourceReservationErrorV1>>,
    nonce_primary: bool,
    completion: Option<completion::CatalogMaintenanceCatalogNativeCompletionV2>,
    completion_entry: Option<Result<(), ResourceReservationErrorV1>>,
    completion_identity: Option<Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>>,
}

impl CatalogMaintenanceIoOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            stages: Default::default(),
            origin: None,
            nonce: [0; 16],
            entropy: None,
            nonce_comparison: None,
            nonce_primary: false,
            completion: None,
            completion_entry: None,
            completion_identity: None,
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        // This latch is set only at the nonce failure boundary after the
        // same stage admitted successfully. Independently owed terminal posts
        // cannot replace that earlier raw entropy/comparison cause.
        if self.nonce_primary {
            return self.nonce_failure_v2();
        }
        // Completion may consume only an earlier entirely positive stage.
        // Its frozen refusal therefore precedes every later attempted reentry
        // on the now-empty stage and cannot be masked by that later marker.
        self.completion
            .as_ref()
            .and_then(|completion| completion.failure_v2())
            .or_else(|| {
                self.completion_entry
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.completion_identity
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.stages.failure())
            .or_else(|| {
                self.entropy
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.nonce_comparison
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    fn nonce_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
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
    }
}

/// Keeps one actual completed Host receiver in its genuine maintenance turn.
#[doc(hidden)]
#[must_use = "retain the entire flight and every independent native post"]
pub struct ControllerCatalogMaintenanceIoLoanV2<'loan> {
    owner: &'loan mut CatalogMaintenanceOriginalV2,
    controller: &'loan Journal,
    source: &'loan ProtectedSourceDomainJournalOwnerV1,
    receiving: &'loan ControllerInitialBrokerSessionReceivingV1,
    catalog: &'loan StartHostCatalogPublicationOriginalV2,
    journal: StorageNativeOpeningOwnerLinkV1,
    binding: [u8; 32],
    context: [u8; 32],
    cutoff: u64,
    resident_base: ResourceVector,
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Borrows the only Catalog17 phase from this same completed Host Session.
    ///
    /// All preconstruction comparisons are passive. Its exact loan carrier is
    /// admitted before construction; the shared SDK supplier must then admit
    /// the complete native/flight shape before the first sampler or entropy read.
    ///
    /// # Errors
    /// Refuses repeated entry, another source/receiver/Journal, changed Host
    /// transcript, expired mechanical interval or financial admission.
    #[doc(hidden)]
    pub fn borrow_catalog_io_once_v2<'loan>(
        &'loan mut self,
        receiving: &'loan ControllerInitialBrokerSessionReceivingV1,
        catalog: &'loan StartHostCatalogPublicationOriginalV2,
        journal: &Journal,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ControllerCatalogMaintenanceIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.require_completed_session_v2(receiving, journal, 0)?;
        if self.owner.catalog_io_entered || transcript.protocol() != BrokerSessionProtocolV1::Host
            || !transcript.negotiated_methods().contains(&aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut source_receiving = CatalogMaintenanceSourceReceivingV2 {
            owner: self.owner,
            source: self.source,
        };
        catalog.require_same_maintenance_source_v2(&mut source_receiving, self.controller)?;
        let bytes = std::mem::size_of::<ControllerCatalogMaintenanceIoLoanV2<'static>>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // The terminal native position opens the held writer's two names
        // and samples its existing descriptions. These are separate from the
        // SDK peer/floor post and stay charged through whole-cycle disposal.
        let witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::<
            JournalError,
        >::receiving_footprint_v1()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
        let terminal = journal.held_names_receiving_demand_v2()?.checked_add(
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(witness.memory_bytes)
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                )
                .with(
                    D::OpenFiles,
                    u64::try_from(witness.open_files)
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(witness.metadata_cells)
                        .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                ),
        )?;
        self.reserve_additional_v2(
            ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .checked_add(terminal)?,
        )?;
        let cutoff = self.original_cutoff_v2()?;
        self.owner.catalog_io_entered = true;
        let resident_base = self.owner.reached;
        Ok(ControllerCatalogMaintenanceIoLoanV2 {
            owner: self.owner,
            controller: self.controller,
            source: self.source,
            receiving,
            catalog,
            journal: journal.held_session_owner_link_v1(),
            binding: transcript.session_binding(),
            context: transcript.protected_context_digest(),
            cutoff,
            resident_base,
        })
    }
}

impl ControllerCatalogMaintenanceIoLoanV2<'_> {
    pub(in crate::controller_resource_reservation) fn failure_native_v2(
        &self,
    ) -> Option<&(dyn Error + 'static)> {
        self.owner.catalog_io.failure_v2()
    }

    pub(in crate::controller_resource_reservation) fn io_stages_v2(
        &mut self,
    ) -> &mut StorageIoStagesV1 {
        &mut self.owner.catalog_io.stages
    }

    // This is a local traffic-retention discriminator on the sole stage owned
    // by this same immutable native identity, never a financial operation ID.
    pub(in crate::controller_resource_reservation) fn native_turn_data_v2(&self) -> u64 {
        0
    }

    pub(in crate::controller_resource_reservation) fn require_current_native_v2(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.catalog_io.completion.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut receiving = CatalogMaintenanceSourceReceivingV2 {
            owner: self.owner,
            source: self.source,
        };
        self.catalog
            .require_same_maintenance_source_v2(&mut receiving, self.controller)
    }

    pub(in crate::controller_resource_reservation) fn complete_base_native_v2(
        &mut self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        // Fixed admission is provisional on the SAME stage. The common
        // engine later supplies its full fixed+variable invoice, then retains
        // that incoming plane exactly once. Reusing reached here would add
        // that same fixed plane a second time before the stage retained it.
        self.resident_base
            .checked_add(self.owner.catalog_io.stages.retained_demand_v1(0)?)?
            .checked_add(incoming)
            .map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation) fn require_prepared_complete_native_v2(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        self.owner.funding = Some((|| {
            let bank = self
                .owner
                .bank
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            bank.require_catalog_maintenance_complete_v2(
                self.owner
                    .native
                    .as_mut()
                    .and_then(|value| value.as_mut().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                self.controller,
                self.owner
                    .profile
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                complete,
            )
        })());
        if !matches!(self.owner.funding, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Funding);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.reached = complete;
        Ok(())
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
    ) -> Result<(), ControllerCatalogMaintenanceSessionCurrentnessErrorV2> {
        self.require_session_journal_v2(journal)?;
        if transcript.protocol() != BrokerSessionProtocolV1::Host
            || transcript.session_binding() != self.binding
            || transcript.protected_context_digest() != self.context
        {
            return Err(ResourceReservationErrorV1::Conflict.into());
        }
        let mut native = None;
        let returned = if let Some(origin) = self.owner.catalog_io.origin.as_ref() {
            origin.require_same_socket_retaining_v4(socket, &mut native)
        } else {
            socket
                .capture_storage_session_origin_retaining_v4(&mut native)
                .map(|origin| {
                    self.owner.catalog_io.origin = Some(origin);
                })
        };
        match (returned, native) {
            (Ok(()), _) => Ok(()),
            (Err(binding), Some(Err(native))) => Err(
                ControllerCatalogMaintenanceSessionCurrentnessErrorV2::Native { native, binding },
            ),
            (Err(binding), _) => Err(binding.into()),
        }
    }

    pub(in crate::controller_resource_reservation) fn protocol_data_v2(
        &self,
    ) -> BrokerSessionProtocolV1 {
        BrokerSessionProtocolV1::Host
    }
    pub(in crate::controller_resource_reservation) fn cutoff_data_v2(&self) -> u64 {
        self.cutoff
    }

    pub(in crate::controller_resource_reservation) fn require_catalog_source_v2(
        &mut self,
        catalog: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.catalog, catalog) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_native_v2()
    }

    pub(in crate::controller_resource_reservation) fn prepare_nonce_once_v2(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.catalog_io.entropy.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.catalog_io.entropy = Some(rustix::rand::getrandom(
            &mut self.owner.catalog_io.nonce,
            rustix::rand::GetRandomFlags::empty(),
        ));
        self.owner.catalog_io.nonce_comparison = Some(
            if matches!(self.owner.catalog_io.entropy, Some(Ok(16)))
                && self.owner.catalog_io.nonce != [0; 16]
            {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            },
        );
        if !matches!(self.owner.catalog_io.nonce_comparison, Some(Ok(()))) {
            self.owner.catalog_io.nonce_primary = true;
            self.owner.first.get_or_insert(First::CatalogIo);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Derives fresh coordinates only after full shared native/flight admission.
    ///
    /// # Errors
    /// Refuses changed current scope, another Session, missing paid entropy or
    /// unsupported negotiated bounds. No new clock, entropy or lease is created.
    #[doc(hidden)]
    pub fn catalog_request_header_data_v2(&mut self, journal: &Journal, _socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2, ResourceReservationErrorV1>{
        self.require_current_native_v2()?;
        self.require_session_journal_v2(journal)?;
        if !matches!(self.owner.catalog_io.nonce_comparison, Some(Ok(())))
            || transcript.session_binding() != self.binding
            || transcript.protected_context_digest() != self.context
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (major, minor) = transcript.protocol_version();
        if major != 1
            || minor != 0
            || transcript.negotiated_maximum_response_bytes() == 0
            || transcript.audience()
                != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
            protocol_major: u32::from(major), protocol_minor: u32::from(minor),
            audience: transcript.audience(), request_id: self.owner.catalog_io.nonce,
            deadline_boottime_nanoseconds: self.cutoff,
            maximum_response_bytes: transcript.negotiated_maximum_response_bytes(),
        })
    }

    pub(in crate::controller_resource_reservation) fn require_publication_request_v2(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        let context = request
            .host_catalog_publication_data_v2()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let draft = self
            .catalog
            .draft_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if request.request_id() != self.owner.catalog_io.nonce
            || request.session_binding() != self.binding
            || context.catalog_generation() != draft.expected_generation()
            || context.catalog_digest() != draft.expected_digest()
            || context.catalog_bytes()
                != u64::try_from(draft.canonical_catalog().len())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
            || context.header().deadline_boottime_nanoseconds() > self.cutoff
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows the same admitted canonical source descriptor without cloning it.
    ///
    /// # Errors
    /// Refuses changed native identity or any earlier failure. The actual sender
    /// independently enters the healthy paid native stage before this DATA view.
    #[doc(hidden)]
    pub fn borrow_catalog_descriptor_v2(
        &self,
    ) -> Result<&SealedReadOnlyCredential, ResourceReservationErrorV1> {
        let identity = self.catalog.maintenance_identity_data_v2()?;
        if self.owner.first.is_some()
            || !self
                .owner
                .native
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .is_some_and(|native| native.matches_identity_data_v2(identity))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.catalog
            .sealed_transfer_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerCatalogMaintenanceIoLoanV2<'_> {
    /// Latches the actual native stage before any enclosing independent posts.
    ///
    /// This diagnostic marker never creates a successful phase. A later Source
    /// or C post cannot replace the already retained sampler or transport cause.
    #[doc(hidden)]
    pub fn retain_catalog_io_refusal_once_v2(&mut self) {
        if self.owner.catalog_io.failure_v2().is_some() {
            self.owner.first.get_or_insert(First::CatalogIo);
        }
    }
}

impl CatalogMaintenanceIoOriginalV2 {
    pub(super) fn require_terminal_v2(
        &self,
        native: &ControllerCatalogMaintenanceReceivingV2,
        source: &StartHostCatalogPublicationOriginalV2,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.completion
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_terminal_v2(native, source, outcome)
    }
}

impl ControllerCatalogMaintenanceIoLoanV2<'_> {
    /// Latches an actual SDK refusal before independently owed native posts.
    #[doc(hidden)]
    pub fn retain_catalog_sdk_refusal_once_v2(&mut self) {
        self.owner
            .sdk_refusal
            .get_or_insert(JournalError::ProtectedBoundary);
        self.owner.first.get_or_insert(First::Sdk);
    }

    /// Selects only the same retained original at this chronological boundary.
    #[doc(hidden)]
    #[must_use]
    pub fn catalog_original_failure_selected_v2(&self) -> bool {
        self.owner.original_failure_selected_v2()
    }
}
