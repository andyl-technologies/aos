//! Lends the same fresh Start native owner to its closed Network63/19 stages.
//!
//! The IO loan is distinct from Create's scoped C23 loan. Its private entry
//! joins the actual completed preparation, Root IO window and native Session
//! association. The SDK additionally requires its opaque completed Session
//! borrower, retaining captured enrolled-key/context authentication there.

use super::*;

mod host_rejoin;
pub use host_rejoin::StartHostSessionRejoinOriginalV2;
use super::resource_state::StartResourceKindV2;
use super::host_root::OriginalStartHostRootLoanV1;
use super::network_opening::{StartResourceSessionAssociationV4, StartResourceSessionCurrentnessErrorV4};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2;
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredential;
use crate::normal_root::RootStartResourceCurrentTurnV2;

/// Names the shared SDK kernel's complete independently owed native post shape.
///
/// This cost DATA is supplied only by the actual Network SDK fixed supplier.
/// It contains no account, resource namespace, traffic or receiving authority.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartResourceSessionPostShapeDataV2 {
    /// Actual post/floor/native byte backing including construction overlap.
    pub receiving_bytes: usize,
    /// Actual independent native descriptors outside the raw receive peak.
    pub open_files: usize,
}

#[derive(Default)]
pub(super) struct StartResourcePostPreparationV2 {
    shape: Option<StartResourceSessionPostShapeDataV2>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    payment: Option<Result<(), ResourceReservationErrorV1>>,
    diagnostic_binding: Option<(u64, NetworkIoDiagnosticBindingV4)>,
    original_native_selected: std::cell::Cell<Option<bool>>,
}

type NetworkIoDiagnosticBindingV4 = (aos_sandbox_core::OperationId, [u8; 32], u64, i64);

impl StartResourcePostPreparationV2 {
    pub(super) fn resident_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        match self.geometry.as_ref() {
            Some(Ok(demand)) => Ok(*demand),
            Some(Err(_)) => Err(CLOSED),
            None => Ok(ResourceVector::ZERO),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

/// Exclusively borrows the genuine current Start and its Network IO stages.
///
/// Callers cannot construct this loan from a vector, generic Session, old
/// Create original or completed Session association alone.
#[doc(hidden)]
pub struct StartResourceProvisioningIoLoanV2<'loan> {
    kind: StartResourceKindV2,
    native: &'loan mut StartNativeStateV1,
    identity: &'loan Arc<()>,
    plan: &'loan crate::OperationPlan,
    authorization: &'loan crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1,
    source: &'loan Journal,
    source_origin: &'loan source_origin::StartSourceOriginOriginalV1,
    root: &'loan RootStartResourceCurrentTurnV2<'loan>,
    controller: &'loan Journal,
    association: StartResourceIoAssociationV2<'loan>,
    prepared: &'loan PreparedStartResourceRequestOriginalV2,
    lease: &'loan SignedOwnershipLease,
    resident_base: ResourceVector,
}

// Only genuine Start entry methods choose these actual resident originals.
// A retained Create association supplies no old payer or completed turn credit.
enum StartResourceIoAssociationV2<'held> {
    Opened(&'held StartResourceSessionAssociationV4),
    RetainedCreate(&'held super::super::CreateProvisioningOriginalsV1),
}

impl StartResourceIoAssociationV2<'_> {
    fn require_start_v2(&self, native: &StartNativeStateV1, identity: &Arc<()>,
        parent: aos_sandbox_core::OperationId, kind: StartResourceKindV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Opened(association) => {
                if kind == StartResourceKindV2::Storage
                    || association.actual_role_v2() != kind.role_v2() { return Err(CLOSED); }
                association.require_start_v4(identity, parent, &native.profile)
            }
            Self::RetainedCreate(previous) => {
                if kind != StartResourceKindV2::Storage
                    || previous.parent != native.create_parent
                    || !Arc::ptr_eq(&previous.bank, &native.bank)
                    || !Arc::ptr_eq(&previous.profile, &native.profile)
                    || !previous.start_entry_entered
                    || !matches!(previous.after, Some(Ok(())))
                    || previous.failure().is_some() { return Err(CLOSED); }
                // This is only the old held representation's positive phase;
                // no old native currentness or financial borrower is reentered.
                previous.client_session.completed_resident_receiving_demand_v1()?;
                Ok(())
            }
        }
    }

    fn observe_session_v2(&self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), StartResourceSessionCurrentnessErrorV4> {
        match self {
            Self::Opened(association) => association.require_current_session_v4(journal, socket, transcript),
            Self::RetainedCreate(previous) => previous.client_session
                .observe_completed_provisioning_session_v2(journal, socket, transcript, Ok(())),
        }
    }

    fn require_journal_v2(&self, journal: &Journal) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Opened(association) => association.require_completed_journal_v4(journal),
            Self::RetainedCreate(previous) => previous.client_session
                .require_completed_journal_v1(journal).map_err(|_| CLOSED),
        }
    }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Lends only the actual current Network IO turn and completed preparation.
    ///
    /// # Errors
    /// Refuses changed Start/Root/Source, foreign completed preparation or a
    /// Session associated with another parent/profile/accepted owner.
    pub fn borrow_network_io_once_v2<'loan>(
        &'loan mut self,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        association: &'loan StartResourceSessionAssociationV4,
        prepared: &'loan PreparedStartResourceRequestOriginalV2,
        controller: &'loan Journal,
        post: StartResourceSessionPostShapeDataV2,
    ) -> Result<StartResourceProvisioningIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_resource_io_once_v2(StartResourceKindV2::Network, root, StartResourceIoAssociationV2::Opened(association), prepared, controller, post)
    }

    // Only the enclosing genuine Entry can eventually lend this purpose after
    // its actual predecessor completion. There is no external selector port.
    pub fn borrow_mount_io_once_v2<'loan>(
        &'loan mut self, root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        association: &'loan StartResourceSessionAssociationV4,
        prepared: &'loan PreparedStartResourceRequestOriginalV2,
        controller: &'loan Journal, post: StartResourceSessionPostShapeDataV2,
    ) -> Result<StartResourceProvisioningIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_resource_io_once_v2(StartResourceKindV2::Mount, root, StartResourceIoAssociationV2::Opened(association), prepared, controller, post)
    }

    /// Lends the actual active-generation2 Host IO turn and retained catalog Session.
    ///
    /// # Errors
    /// Refuses pending publication, a foreign prepared pair, reused IO stage or
    /// another actual Session/Root/native/Source association.
    #[doc(hidden)]
    pub fn borrow_host_io_once_v2<'loan>(
        &'loan mut self, root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        association: &'loan StartResourceSessionAssociationV4,
        prepared: &'loan PreparedStartResourceRequestOriginalV2,
        controller: &'loan Journal, post: StartResourceSessionPostShapeDataV2,
    ) -> Result<StartResourceProvisioningIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.require_host_stage_v2(2, controller)?;
        self.native.require_host_effect_applying_v2(controller)?;
        self.borrow_resource_io_once_v2(StartResourceKindV2::Host, root,
            StartResourceIoAssociationV2::Opened(association), prepared, controller, post)
    }

    /// Rejoins the actual continuously held Create Storage Session for fresh31/18.
    ///
    /// Only the new Start native owner pays. The historical receiver remains
    /// borrowed in place and lends neither its old account nor its once-slots.
    ///
    /// # Errors
    /// Refuses a foreign Create parent, Bank, profile, unfinished held Session,
    /// changed fresh Start/Root/Source, or a reused Storage IO stage.
    #[doc(hidden)]
    pub fn borrow_storage_io_once_v2<'loan>(
        &'loan mut self,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        previous: &'loan super::super::CreateProvisioningOriginalsV1,
        prepared: &'loan PreparedStartResourceRequestOriginalV2,
        controller: &'loan Journal,
        post: StartResourceSessionPostShapeDataV2,
    ) -> Result<StartResourceProvisioningIoLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_resource_io_once_v2(StartResourceKindV2::Storage, root,
            StartResourceIoAssociationV2::RetainedCreate(previous), prepared, controller, post)
    }

    fn borrow_resource_io_once_v2<'loan>(
        &'loan mut self, kind: StartResourceKindV2,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        association: StartResourceIoAssociationV2<'loan>,
        prepared: &'loan PreparedStartResourceRequestOriginalV2,
        controller: &'loan Journal, post: StartResourceSessionPostShapeDataV2,
    ) -> Result<StartResourceProvisioningIoLoanV2<'loan>, ResourceReservationErrorV1> {
        if prepared.purpose_data_v2() != kind.purpose_v2()
            || root.resource_purpose_data_v2()? != kind.purpose_v2() {
            return Err(CLOSED);
        }
        self.require_current_v1(controller)?;
        root.require_io_v2(self, controller)?;
        association.require_start_v2(self.native, self.identity, self.plan.operation_id(), kind)?;
        root.require_io_preparation_v4(prepared, self.plan.operation_id(),
            self.native.native_turn, self.native.profile.as_ref())?;
        let lease = self.fresh_ownership_lease_v1()?;
        if self.native.resources.member_mut_v2(kind).io_loan_entered {
            return Err(CLOSED);
        }
        self.native.resources.member_mut_v2(kind).io_loan_entered = true;
        self.native.resources.member_mut_v2(kind).post.shape = Some(post);
        // The same immutable preparation has already passed the actual Root
        // IO gate. Save only diagnostic DATA before the first debit can fail.
        self.native.resources.member_mut_v2(kind).post.diagnostic_binding = prepared.completed_root_binding_v2()
            .ok().map(|binding| (self.native.native_turn, binding));
        // This uses the same passive lower native-floor law as the shared SDK
        // kernel. It is cost DATA, never a Create original or authority cast.
        let shape = super::super::storage_post::StorageProvisioningSessionPostShapeDataV1 {
            receiving_bytes: post.receiving_bytes,
            open_files: post.open_files,
        };
        self.native.resources.member_mut_v2(kind).post.geometry = Some(shape.checked_demand_v1());
        self.native.resources.member_mut_v2(kind).post.payment = Some((|| {
            let resources = self.native.resources.retained_demand_v2(self.native.native_turn)?;
            let root = root.require_io_preparation_v4(prepared, self.plan.operation_id(),
                self.native.native_turn, self.native.profile.as_ref())?;
            let carriers = size_of::<StartResourceProvisioningIoLoanV2<'static>>()
                .checked_add(size_of::<StartResourcePreparedRequestBorrowV2<'static>>())
                .and_then(|bytes| bytes.checked_mul(2)).ok_or(CLOSED)?;
            let complete = self.resident_base.checked_add(root)?.checked_add(resources)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                    u64::try_from(carriers).map_err(|_| CLOSED)?))?;
            let native = self.native.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(CLOSED)?;
            self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_create_provisioning_complete_v1(native.original_mut_v1(), controller,
                    self.native.profile.as_ref(), complete)
        })());
        if !matches!(self.native.resources.member_mut_v2(kind).post.payment, Some(Ok(()))) {
            self.native.first.get_or_insert(FirstV1::ResourcePost(kind));
            return Err(CLOSED);
        }

        Ok(StartResourceProvisioningIoLoanV2 {
            kind, native: self.native,
            identity: self.identity,
            plan: self.plan,
            authorization: self.authorization,
            source: self.source,
            source_origin: self.source_origin,
            root,
            controller,
            association,
            prepared,
            lease,
            resident_base: self.resident_base,
        })
    }
}

impl<'loan> StartResourceProvisioningIoLoanV2<'loan> {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn request_additional_receiving_demand_v2(&self, request_bytes: usize)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        match self.kind {
            StartResourceKindV2::Network => crate::journal::broker_session_receiving::
                network_prepare_client_request_additional_demand_v2(request_bytes).map_err(|_| CLOSED),
            StartResourceKindV2::Mount => self.prepared.mount_request_receiving_demand_v2(),
            StartResourceKindV2::Storage => PreparedStartResourceRequestOriginalV2::storage_request_receiving_demand_v2(),
            StartResourceKindV2::Host => self.prepared.host_request_receiving_demand_v2(),
        }
    }

    /// Returns the fixed protocol of this genuine resource-specific loan.
    #[doc(hidden)]
    #[must_use]
    pub fn protocol_data_v2(&self) -> aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1 {
        use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1 as Protocol;
        match self.kind { StartResourceKindV2::Network => Protocol::Network,
            StartResourceKindV2::Mount => Protocol::Mount, StartResourceKindV2::Storage => Protocol::Storage,
            StartResourceKindV2::Host => Protocol::Host }
    }

    /// Returns only the exact effect or fresh Inventory method of this loan.
    #[doc(hidden)]
    #[must_use]
    pub fn method_data_v2(&self, inventory: bool) -> aos_proto::aos::sandbox::local::v1::BrokerMethod {
        use aos_proto::aos::sandbox::local::v1::BrokerMethod as Method;
        match (self.kind, inventory) {
            (StartResourceKindV2::Network, false) => Method::BROKER_METHOD_NETWORK_PREPARE_V2,
            (StartResourceKindV2::Network, true) => Method::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            (StartResourceKindV2::Mount, false) => Method::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            (StartResourceKindV2::Mount, true) => Method::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            (StartResourceKindV2::Storage, false) => Method::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
            (StartResourceKindV2::Storage, true) => Method::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            (StartResourceKindV2::Host, false) => Method::BROKER_METHOD_HOST_APPLY_RUNTIME,
            (StartResourceKindV2::Host, true) => Method::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        }
    }

    /// Lends the last actual terminal native position after both finite IO posts.
    ///
    /// # Errors
    /// Refuses incomplete/failing resource or Inventory stages, changed current
    /// Root/Start/Source association, or an absent actual retained native sample.
    #[doc(hidden)]
    pub fn completed_session_native_data_v2(&self) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.native.resources.member_v2(self.kind).io.completed_session_native_data_v2()
    }

    /// Prices the two independent final native posts before either IO stage.
    ///
    /// This supplies Memory and descriptor backing only. The same Session's
    /// rooted names are already retained in its opening/survivor representation.
    ///
    /// # Errors
    /// Refuses checked compiled-layout or fixed native geometry overflow.
    #[doc(hidden)]
    pub fn completed_native_post_receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let names = crate::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("session.journal")?;
        let witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::<crate::JournalError>::
            receiving_footprint_v1().ok_or(CLOSED)?;
        let one = ResourceVector::ZERO
            .with(D::MemoryBytes, names.get(D::MemoryBytes).checked_add(
                u64::try_from(witness.memory_bytes).map_err(|_| CLOSED)?).ok_or(CLOSED)?)
            .with(D::OpenFiles, names.get(D::OpenFiles).checked_add(
                u64::try_from(witness.open_files).map_err(|_| CLOSED)?).ok_or(CLOSED)?);
        // One actual resource terminal and one distinct fresh Inventory terminal.
        one.checked_add(one).map_err(Into::into)
    }

    /// Returns the immutable purpose of this genuine finite native IO loan.
    #[doc(hidden)]
    #[must_use]
    pub fn purpose_data_v2(&self) -> aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 { self.kind.purpose_v2() }

    /// Borrows the real sealed content only for this stage's Network63 purpose.
    ///
    /// Inventory19 returns None from the actual private active-stage state.
    /// The borrowed credential belongs to the immutable prepared owner, so no
    /// FD clone or self-reference is held across a send, wait or native post.
    ///
    /// # Errors
    /// Refuses incomplete/failed stages, changed actual Start/Root/Source or
    /// preparation, and missing completed native sealing.
    pub fn borrow_preparation_content_descriptor_v2(
        &self,
    ) -> Result<Option<&'loan SealedReadOnlyCredential>, ResourceReservationErrorV1> {
        self.require_prepared_v2(self.prepared)?;
        if self.kind != StartResourceKindV2::Network
            || !self.native.resources.member_v2(self.kind).io.network_preparation_active_v2()? {
            return Ok(None);
        }
        self.prepared.sealed_content_v2().map(Some).map_err(|_| CLOSED)
    }


    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn io_stages_v2(&mut self) -> &mut super::super::storage_io::StorageIoStagesV1 {
        &mut self.native.resources.member_mut_v2(self.kind).io
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_session_association_v2(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), StartResourceSessionCurrentnessErrorV4> {
        // This native post deliberately remains independent of C health.
        self.association.observe_session_v2(journal, socket, transcript)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_session_journal_v2(&self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.association.require_journal_v2(journal)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn native_turn_data_v2(&self) -> u64 {
        self.native.native_turn
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn complete_base_native_v2(&self, incoming: ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let root = self.require_current_v2()?;
        self.resident_base.checked_add(root)?
            .checked_add(self.native.resources.retained_demand_v2(self.native.native_turn)?)?
            .checked_add(incoming)
            .map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_complete_native_v2(&mut self, incoming: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        let complete = self.complete_base_native_v2(incoming)?;
        self.require_prepared_complete_native_v2(complete)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_prepared_complete_native_v2(&mut self, complete: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        let native = self.native.native.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(CLOSED)?;
        self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_complete_v1(native.original_mut_v1(), self.controller,
                self.native.profile.as_ref(), complete)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_current_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.native.require_current_v1(self.controller)?;
        self.plan.require_accepted_start_data_v1(self.controller).map_err(|_| CLOSED)?;
        self.controller.require_public_mutation_targets_live_v2(
            self.authorization.project(), self.authorization.request().request(),
        ).map_err(ResourceReservationErrorV1::Journal)?;
        self.source_origin.require_completed_source_affinity_v1(self.source)?;
        self.association.require_start_v2(self.native, self.identity, self.plan.operation_id(), self.kind)?;
        if self.prepared.purpose_data_v2() != self.kind.purpose_v2()
            || self.root.resource_purpose_data_v2()? != self.kind.purpose_v2() { return Err(CLOSED); }
        self.root.require_io_preparation_v4(self.prepared, self.plan.operation_id(),
            self.native.native_turn, self.native.profile.as_ref())
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving)
    fn require_prepared_v2(&self, prepared: &PreparedStartResourceRequestOriginalV2)
        -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.prepared, prepared) {
            return Err(CLOSED);
        }
        self.require_current_v2().map(|_| ())
    }

    /// Borrows exact signed request inputs from this loan's same prepared owner.
    ///
    /// This view neither parses a header again nor accepts external artifact or
    /// FD tuples. Actual send/receive/currentness remains with the closed stages.
    ///
    /// # Errors
    /// Refuses another preparation or changed Start/Root/Source association.
    pub fn borrow_prepared_request_v2<'held>(
        &self,
        prepared: &'held PreparedStartResourceRequestOriginalV2,
    ) -> Result<StartResourcePreparedRequestBorrowV2<'held>, ResourceReservationErrorV1>
    where
        'loan: 'held,
    {
        self.require_prepared_v2(prepared)?;
        Ok(StartResourcePreparedRequestBorrowV2 { prepared, lease: self.lease })
    }
}

/// Borrows the sole normalizer's actual completed signed request and sealed FD.
#[doc(hidden)]
pub struct StartResourcePreparedRequestBorrowV2<'held> {
    prepared: &'held PreparedStartResourceRequestOriginalV2,
    lease: &'held SignedOwnershipLease,
}

impl StartResourcePreparedRequestBorrowV2<'_> {
    /// Borrows exact canonical plan bytes retained by the genuine preparation.
    ///
    /// # Errors
    /// Refuses an incomplete or failed prepared original.
    pub fn plan_bytes_v2(&self) -> Result<&[u8], PreparedStartResourceRequestClosedV2> {
        self.prepared.signed_plan_v2().map(|signed| signed.canonical_plan())
    }

    /// Borrows the exact detached plan signature from that same owner.
    ///
    /// # Errors
    /// Refuses an incomplete or failed prepared original.
    pub fn plan_signature_v2(&self) -> Result<&[u8], PreparedStartResourceRequestClosedV2> {
        self.prepared.signed_plan_v2().map(|signed| signed.canonical_signature())
    }

    /// Borrows the genuine current Start's verified fresh Ownership lease bytes.
    #[must_use]
    pub fn lease_bytes_v2(&self) -> &[u8] {
        self.lease.canonical_lease()
    }

    /// Borrows the exact detached signature of the same verified lease.
    #[must_use]
    pub fn lease_signature_v2(&self) -> &[u8] {
        self.lease.canonical_signature()
    }

    /// Borrows the sole normalizer's exact deadline-injected request body.
    ///
    /// # Errors
    /// Refuses an incomplete or failed prepared original.
    pub fn request_body_v2(&self) -> Result<&[u8], PreparedStartResourceRequestClosedV2> {
        self.prepared.request_body_v2()
    }

    /// Borrows fixed coordinates already decoded by that same normalizer.
    ///
    /// # Errors
    /// Refuses an incomplete or failed prepared original.
    pub fn request_header_v2(&self)
        -> Result<&StartResourceRequestHeaderDataV2, PreparedStartResourceRequestClosedV2> {
        self.prepared.request_header_v2()
    }

    /// Borrows the actual completed sealed credential without cloning its FD.
    ///
    /// # Errors
    /// Refuses incomplete or failed native sealing/construction.
    pub fn sealed_content_v2(&self)
        -> Result<&SealedReadOnlyCredential, PreparedStartResourceRequestClosedV2> {
        self.prepared.sealed_content_v2()
    }
}

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

impl AcceptedStartEntryOriginalV1 {
    fn resource_io_diagnostic_state_v4(
        &self,
        opening: &super::network_opening::StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Option<(&StartNativeStateV1, StartResourceKindV2)> {
        let kind = StartResourceKindV2::from_purpose_v2(prepared.purpose_data_v2()).ok()?;
        let state = self.native_state.as_ref()?;
        let identity = self.identity.as_ref().ok()?;
        let parent = self.body.plan_v1().ok()?.operation_id();
        if kind == StartResourceKindV2::Storage {
            if !matches!(state.resources.storage.retained_create_join, Some(Ok(()))) { return None; }
        } else {
            let association = opening.completed_session_association_v4()?;
            if association.actual_role_v2() != kind.role_v2() { return None; }
            association.require_start_v4(identity, parent, &state.profile).ok()?;
        }
        let binding = prepared.completed_root_binding_v2().ok()?;
        if !state.resources.member_v2(kind).io_loan_entered
            || binding.0 != parent
            || state.resources.member_v2(kind).post.diagnostic_binding != Some((state.native_turn, binding))
            || !matches!(self.resource_entries.member_v2(kind).turn_next[2], Some(Ok(())))
            || !matches!(self.resource_entries.member_v2(kind).turn_before[2], Some(Ok(())))
        {
            return None;
        }
        Some((state, kind))
    }

    /// Freezes the actual failed Network IO owner's diagnostic source.
    ///
    /// The Runtime calls this at a failed loan or SDK body boundary, before
    /// its independently owed C and Root posts. It calls this for an SDK
    /// refusal only when that SDK selected the actual Domain owner. The first
    /// local-versus-native choice is sticky; later posts cannot replace it.
    /// This performs only private identity and retained-result comparisons.
    #[doc(hidden)]
    #[must_use]
    pub fn snapshot_resource_io_failure_v4(
        &self,
        opening: &super::network_opening::StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> bool {
        let Some((state, kind)) = self.resource_io_diagnostic_state_v4(opening, prepared) else {
            return false;
        };
        if state.resources.member_v2(kind).post.original_native_selected.get().is_some() {
            return true;
        }
        let native = state.native_failure_v1().is_some();
        if !native && state.resources.member_v2(kind).io.failure().is_none() && state.resources.member_v2(kind).post.failure().is_none() {
            return false;
        }
        state.resources.member_v2(kind).post.original_native_selected.set(Some(native));
        true
    }

    /// Borrows the frozen actual Network IO cause from the same Start owner.
    ///
    /// This diagnostic does not sample, parse, enter a native scope or require
    /// healthy C. Callers retain their earlier pure SDK error separately.
    #[doc(hidden)]
    #[must_use]
    pub fn resource_io_failure_with_original_v4<'held>(
        &'held self,
        opening: &super::network_opening::StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Option<&'held (dyn Error + 'static)> {
        let Some((state, kind)) = self.resource_io_diagnostic_state_v4(opening, prepared) else {
            return Some(&CLOSED);
        };
        match state.resources.member_v2(kind).post.original_native_selected.get() {
            Some(true) => state.native_failure_v1(),
            Some(false) => state.resources.member_v2(kind).post.failure().or_else(|| state.resources.member_v2(kind).io.failure()),
            None => Some(&CLOSED),
        }
    }

    /// Formats the same frozen Network IO cause, including retained profile detail.
    ///
    /// # Errors
    /// Returns only an error reported by the supplied formatter.
    #[doc(hidden)]
    pub fn fmt_resource_io_failure_v4(
        &self,
        opening: &super::network_opening::StartResourceSessionOpeningOriginalV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if let Some((state, kind)) = self.resource_io_diagnostic_state_v4(opening, prepared) {
            if state.resources.member_v2(kind).post.original_native_selected.get() == Some(true) {
                if let Some(native) = state.native.as_ref().and_then(|result| result.as_ref().ok()) {
                    if let Some(view) = native.original_v1().profile_failure_view_v1() {
                        return formatter.debug_struct("OriginalStartNetworkIoProfileFailure")
                            .field("phase", &view.phase())
                            .field("classification", &view.classification())
                            .field("cause", &view.cause())
                            .field("property", &view.property_failure())
                            .finish();
                    }
                }
            }
        }
        match self.resource_io_failure_with_original_v4(opening, prepared) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start Network IO has no selected failure"),
        }
    }
}


impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Rejoins the original held Storage Session in its fresh Root opening interval.
    ///
    /// This pays only the new comparison and kernel-result destinations. The
    /// actual Session remains accounted by the continuously retained Create
    /// history. No HELLO, old account, writer reopen or old native turn is used.
    ///
    /// # Errors
    /// Retains the first geometry/debit or whole passive/native association refusal.
    #[doc(hidden)]
    pub fn observe_retained_storage_session_once_v2(
        &mut self,
        root: &RootStartResourceCurrentTurnV2<'_>,
        previous: &super::super::CreateProvisioningOriginalsV1,
        controller: &Journal,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        root.require_opening_v2(self, controller)?;
        if root.resource_purpose_data_v2()? != StartResourceKindV2::Storage.purpose_v2()
            || self.native.resources.storage.retained_create_demand.is_some() { return Err(CLOSED); }
        self.native.resources.storage.retained_create_demand = Some((|| {
            let bytes = size_of::<Result<(), StartResourceSessionCurrentnessErrorV4>>()
                .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        self.native.resources.storage.retained_create_funding = Some((|| {
            let root = root.require_opening_owner_v2(self.plan.operation_id(),
                self.native.native_turn, self.native.profile.as_ref())?;
            // The retained comparison plane is already joined by the same
            // resource sum inside require_complete; add Root residency once.
            self.require_complete_v1(controller, root)
        })());
        if !matches!(self.native.resources.storage.retained_create_funding, Some(Ok(()))) {
            let selected = self.native.native_failure_v1().is_some();
            self.native.first.get_or_insert(FirstV1::ResourceSessionJoin(selected));
            return Err(CLOSED);
        }
        let data = StartResourceIoAssociationV2::RetainedCreate(previous)
            .require_start_v2(self.native, self.identity, self.plan.operation_id(), StartResourceKindV2::Storage);
        self.native.resources.storage.retained_create_join = Some(previous.client_session
            .observe_completed_provisioning_session_v2(journal, socket, transcript, data));
        if !matches!(self.native.resources.storage.retained_create_join, Some(Ok(()))) {
            self.native.first.get_or_insert(FirstV1::ResourceSessionJoin(false));
            return Err(CLOSED);
        }
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Records the already-held Storage Session after fresh C and Root opening posts.
    ///
    /// No new Session representation is added: the same actual Create history
    /// already owns and prices it. Fresh31/17 operation and Root models remain
    /// in their separate resource planes until actual positive disposal.
    ///
    /// # Errors
    /// Refuses incomplete actual rejoin/posts, reentry or changed C/Root purpose.
    #[doc(hidden)]
    pub fn retain_completed_storage_session_once_v2(
        &mut self, root: &crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        if state.resources.storage.session_resident.is_some()
            || !matches!(state.resources.storage.retained_create_join, Some(Ok(()))) { return Err(CLOSED); }
        root.require_completed_resource_opening_v4(StartResourceKindV2::Storage.purpose_v2(),
            self, controller, self.body.plan_v1()?.operation_id(), state.native_turn)?;
        self.native_state.as_mut().ok_or(CLOSED)?.resources.storage.session_resident = Some(Ok(ResourceVector::ZERO));
        Ok(())
    }
}
