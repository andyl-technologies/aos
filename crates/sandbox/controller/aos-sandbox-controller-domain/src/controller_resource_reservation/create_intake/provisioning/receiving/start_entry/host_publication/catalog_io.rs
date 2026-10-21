//! Lends only the genuine pending-child catalog6 owner to Host publication IO.
//!
//! This borrower uses the existing finite Session IO stages. Its independent
//! socket posts remain reachable after a primary financial or body refusal.
//! The SDK separately requires its privately authenticated opaque Host Session;
//! neither this native association nor a supplied transcript can adopt one.

mod native_completion;
pub use native_completion::{
    StartHostCatalogCompletionRefusalV2, StartHostCatalogDisposalV2,
    StartHostCatalogNativeCompletionV2,
};

use super::super::network_opening::{
    StartResourceSessionAssociationV4, StartResourceSessionCurrentnessErrorV4,
    StartResourceSessionOpeningOriginalV2,
};
use super::*;
use crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_linux_descriptors::credential::SealedReadOnlyCredential;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

#[derive(Default)]
pub(crate) struct StartHostCatalogPostOriginalV2 {
    shape: Option<crate::StartResourceSessionPostShapeDataV2>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    payment: Option<Result<(), ResourceReservationErrorV1>>,
    disposed: bool,
}

impl StartHostCatalogPostOriginalV2 {
    pub(crate) fn retained_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.disposed {
            return Ok(ResourceVector::ZERO);
        }
        match self.geometry.as_ref() {
            Some(Ok(demand)) => Ok(*demand),
            Some(Err(_)) => Err(ResourceReservationErrorV1::Conflict),
            None => Ok(ResourceVector::ZERO),
        }
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.payment
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

/// Borrows the actual catalog source, Host Session and pending-child native turn.
///
/// Its private fields are supplied only by the genuine current Start/Root
/// constructor below. No budget, descriptor, catalog model or status flag can
/// construct this borrower. It never borrows the later HostLaunch IO2 stages.
#[doc(hidden)]
pub struct StartHostCatalogIoLoanV2<'loan> {
    native: &'loan mut StartNativeStateV1,
    identity: &'loan Arc<()>,
    plan: &'loan crate::OperationPlan,
    authorization: &'loan crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1,
    source_journal: &'loan Journal,
    source_origin: &'loan source_origin::StartSourceOriginOriginalV1,
    root: &'loan crate::normal_root::RootStartResourceCurrentTurnV2<'loan>,
    controller: &'loan Journal,
    association: &'loan StartResourceSessionAssociationV4,
    catalog: &'loan StartHostCatalogPublicationOriginalV2,
    resident_base: ResourceVector,
    cutoff: u64,
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Lends method17 only from the same paid pending source and completed Host opener.
    ///
    /// All checks before construction are passive comparisons on the actual
    /// already-held owners. The canonical source has prepaid this concrete
    /// borrower's construction, and the SDK admits its complete flight before
    /// native Session observation or request preparation.
    ///
    /// # Errors
    /// Refuses another phase, Source, child, Host Session, catalog or prior entry.
    #[doc(hidden)]
    pub fn borrow_host_catalog_io_once_v2<'loan>(
        &'loan mut self,
        root: &'loan crate::normal_root::RootStartResourceCurrentTurnV2<'loan>,
        opening: &'loan StartResourceSessionOpeningOriginalV2,
        catalog: &'loan StartHostCatalogPublicationOriginalV2,
        controller: &'loan Journal,
        post: crate::StartResourceSessionPostShapeDataV2,
    ) -> Result<StartHostCatalogIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.require_host_stage_v2(6, controller)?;
        let action = self
            .native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.require_pending_catalog_v2(controller)?;
        root.require_host_publication_owner_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self.plan.operation_id(),
            self.native.native_turn,
            self.native.profile.as_ref(),
        )?;
        catalog.require_same_source_v2(self, controller)?;
        let draft = catalog
            .draft_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if opening.actual_role_v2() != crate::ControllerInitialBrokerSessionRoleV1::Host
            || draft.expected_generation() != action.contract.catalog_generation
            || draft.expected_digest().as_bytes() != &action.contract.catalog_digest
            || self.native.resources.host_catalog_io_entered
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let association = opening
            .completed_session_association_v4()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        association.require_start_v4(
            self.identity,
            self.plan.operation_id(),
            &self.native.profile,
        )?;
        let (_, cutoff) = root.original_opening_horizon_v2()?;
        self.native.resources.host_catalog_io_entered = true;
        self.native.resources.host_catalog_opening_resident = opening
            .held_host_catalog_receiving_demand_v2(
                self.identity,
                self.plan.operation_id(),
                self.native.native_turn,
                &self.native.profile,
            )?;
        self.native.resources.host_catalog_post.shape = Some(post);
        let shape = super::super::super::storage_post::StorageProvisioningSessionPostShapeDataV1 {
            receiving_bytes: post.receiving_bytes,
            open_files: post.open_files,
        };
        self.native.resources.host_catalog_post.geometry = Some(shape.checked_demand_v1());
        let root_demand = root.require_host_publication_owner_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self.plan.operation_id(),
            self.native.native_turn,
            self.native.profile.as_ref(),
        )?;
        self.native.resources.host_catalog_post.payment =
            Some(self.require_complete_v1(controller, root_demand));
        if !matches!(
            self.native.resources.host_catalog_post.payment,
            Some(Ok(()))
        ) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(StartHostCatalogIoLoanV2 {
            native: self.native,
            identity: self.identity,
            plan: self.plan,
            authorization: self.authorization,
            source_journal: self.source,
            source_origin: self.source_origin,
            root,
            controller,
            association,
            catalog,
            resident_base: self.resident_base,
            cutoff,
        })
    }
}

impl StartHostCatalogIoLoanV2<'_> {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn io_stages_v2(
        &mut self,
    ) -> &mut super::super::super::storage_io::StorageIoStagesV1 {
        &mut self.native.resources.host_catalog_io
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn native_turn_data_v2(
        &self,
    ) -> u64 {
        self.native.native_turn
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_current_native_v2(
        &self,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native.require_current_v1(self.controller)?;
        // Moving the actual stage into native completion consumes this loan's
        // positive phase. Its empty former slot must never admit another flight.
        if self.native.resources.host_catalog_completion.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.plan
            .require_accepted_start_data_v1(self.controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.controller
            .require_public_mutation_targets_live_v2(
                self.authorization.project(),
                self.authorization.request().request(),
            )
            .map_err(ResourceReservationErrorV1::Journal)?;
        self.source_origin
            .require_completed_source_affinity_v1(self.source_journal)?;
        let action = self
            .native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.require_pending_catalog_v2(self.controller)?;
        self.root.require_host_publication_owner_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self.plan.operation_id(),
            self.native.native_turn,
            self.native.profile.as_ref(),
        )?;
        self.association.require_start_v4(
            self.identity,
            self.plan.operation_id(),
            &self.native.profile,
        )?;
        self.catalog.require_native_source_v2(
            self.identity,
            self.plan.operation_id(),
            self.controller,
        )
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn complete_base_native_v2(
        &self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        let root = self.root.require_host_publication_owner_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self.plan.operation_id(),
            self.native.native_turn,
            self.native.profile.as_ref(),
        )?;
        self.resident_base
            .checked_add(root)?
            .checked_add(
                self.native
                    .resources
                    .retained_demand_v2(self.native.native_turn)?,
            )?
            .checked_add(incoming)
            .map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_prepared_complete_native_v2(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let native = self
            .native
            .native
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.native
            .bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_complete_v1(
                native.original_mut_v1(),
                self.controller,
                self.native.profile.as_ref(),
                complete,
            )
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_session_association_v2(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), StartResourceSessionCurrentnessErrorV4> {
        // Deliberately independent of healthy financial/current C state.
        self.association
            .require_current_session_v4(journal, socket, transcript)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_session_journal_v2(
        &self,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.association.require_completed_journal_v4(journal)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn protocol_data_v2(
        &self,
    ) -> BrokerSessionProtocolV1 {
        BrokerSessionProtocolV1::Host
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn cutoff_data_v2(
        &self,
    ) -> u64 {
        self.cutoff
    }

    /// Derives only request coordinates from this same source and verified Session.
    ///
    /// The request identity is deterministic, nonsecret and domain separated.
    /// The ordinary retained request engine still performs its full protected
    /// history/sequence/current-context admission before signing. This method
    /// does not read entropy, sample a clock or create a later deadline.
    ///
    /// # Errors
    /// Refuses changed source/Root/Session, zero identity or invalid negotiated bounds.
    #[doc(hidden)]
    pub fn catalog_request_header_data_v2(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    ResourceReservationErrorV1>{
        self.require_current_native_v2()?;
        self.association
            .require_same_session_v4(journal, socket, transcript)?;
        let action = self
            .native
            .host_publication_action
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.start.host-catalog.request.v2\0")
            .chain_update(self.plan.operation_id().as_bytes())
            .chain_update(action.contract.plan.operation_id().as_bytes())
            .chain_update(action.contract.catalog_generation.to_be_bytes())
            .chain_update(action.contract.catalog_digest)
            .chain_update(transcript.session_binding())
            .finalize();
        let mut request_id = [0; 16];
        request_id.copy_from_slice(&digest[..16]);
        let (major, minor) = transcript.protocol_version();
        let maximum_response_bytes = transcript.negotiated_maximum_response_bytes();
        if request_id == [0; 16]
            || self.cutoff == 0
            || maximum_response_bytes == 0
            || transcript.audience()
                != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
            protocol_major: u32::from(major), protocol_minor: u32::from(minor),
            audience: transcript.audience(), request_id,
            deadline_boottime_nanoseconds: self.cutoff, maximum_response_bytes,
        })
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_publication_request_v2(
        &self,
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
        if context.catalog_generation() != draft.expected_generation()
            || context.catalog_bytes()
                != u64::try_from(draft.canonical_catalog().len())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?
            || context.catalog_digest() != draft.expected_digest()
            || context.header().deadline_boottime_nanoseconds() > self.cutoff
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows only this same actual catalog's completed sealed descriptor.
    ///
    /// # Errors
    /// Refuses changed native/Source/Root/private child or source custody.
    #[doc(hidden)]
    pub fn borrow_catalog_descriptor_v2(
        &self,
    ) -> Result<&SealedReadOnlyCredential, ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        self.catalog
            .sealed_transfer_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_catalog_source_v2(
        &self,
        source: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_native_v2()?;
        if !std::ptr::eq(self.catalog, source) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl StartHostCatalogPublicationLoanV2<'_> {
    // A caller-supplied signed outcome is insufficient: the actual same native
    // owner must already hold the complete stage plus both consumed receipts.
    pub(crate) fn require_terminal_for_confirmation_v2(
        &self,
        source: &StartHostCatalogPublicationOriginalV2,
        controller: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller)?;
        let native = self
            .entry
            .native_state
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_native_source_v2(
            &self.contract.identity,
            self.contract.parent,
            controller,
        )?;
        native
            .resources
            .host_catalog_completion
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_terminal_v2(
                &self.contract.identity,
                self.contract.parent,
                source,
                outcome,
            )
    }
}

impl StartHostCatalogIoLoanV2<'_> {
    /// Selects a reached lower-original failure at this exact completion boundary.
    ///
    /// This diagnostic performs no IO and must be latched before later C/Root
    /// posts. A rejected pure stage comparison with no native cause stays local.
    #[doc(hidden)]
    #[must_use]
    pub fn completion_original_failure_selected_v2(&self) -> bool {
        self.native.native_failure_v1().is_some()
            || self
                .native
                .resources
                .host_catalog_completion
                .as_ref()
                .is_some_and(|owner| owner.failure_v2().is_some())
    }
}
