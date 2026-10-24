//! Lends the genuine active Start and Root Network interval to fixed Session IO.
//!
//! The retained capsule and journal controls belong to this one opening. Native
//! endpoint custody comes from the same current C/Bank/profile/Launch engine.
//! A taken Journal is only an identity join; it never proves HELLO or completed
//! endpoint/floor disposition, and no Session association can be adopted here.

mod completion;
mod disposition;
pub use disposition::StartResourceUpperDisposalV2;
pub use completion::{StartResourceColdCompletionOriginalV4, StartResourceSessionAssociationV4,
    StartResourceHelloDisposalV4, StartResourceHelloDisposalErrorV4, StartResourceSessionCurrentnessErrorV4};

use super::*;
use super::host_root::OriginalStartHostRootLoanV1;
use crate::journal::broker_session_receiving as geometry;
use crate::journal::{ControllerStartResourceSessionCapturedJournalOpenV4,
    ProtectedJournalPreopenReplayExtentV1, StorageNativeOpeningOwnerLinkV1};
use crate::normal_root::RootStartResourceCurrentTurnV2;
use crate::{ControllerInitialBrokerSessionShapeV1,
    ControllerInitialBrokerSessionCaptureShapeV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerStartResourceEndpointOriginalV2;
use aos_sandbox_broker::endpoint_native_files::{ControllerEndpointExecutionOriginalV1,
    ControllerEndpointExecutionCaptureErrorV1, ControllerEndpointNativeCustodyCaptureV1,
    EndpointNativeFileOpenOriginalV1, EndpointNativeFileV1};
use aos_sandbox_linux::self_execution::SelfExecutionObservationV1;

/// Binds a fixed facade to its actual retained Start opening without allocation.
#[doc(hidden)]
#[derive(Clone)]
pub struct StartResourceSessionOpeningOwnerLinkV2 {
    identity: Arc<()>,
    parent: OperationId,
    native_turn: u64,
    role: crate::ControllerInitialBrokerSessionRoleV1,
}

impl StartResourceSessionOpeningOwnerLinkV2 {
    pub(crate) fn same_owner_v2(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
            && self.parent == other.parent && self.native_turn == other.native_turn
            && self.role == other.role
    }
}

#[derive(Clone, Copy)]
enum First { Reentry, Fixed, Prefix, Endpoint, Finish, Completion }

/// Retains the new Start Network opening's real endpoint and journal controls.
///
/// Empty construction grants no native interval, Journal or Session. Its only
/// lender is the actual Start loan inside its live Root Session-opening turn.
#[doc(hidden)]
#[must_use = "retain this owner through SDK and independent C/Root posts"]
pub struct StartResourceSessionOpeningOriginalV2 {
    link: Option<StartResourceSessionOpeningOwnerLinkV2>,
    role: crate::ControllerInitialBrokerSessionRoleV1,
    endpoint: ControllerStartResourceEndpointOriginalV2,
    fixed: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    prefix: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    representation_prepaid: Option<ResourceVector>,
    original_native_selected: std::cell::Cell<Option<bool>>,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    opening: Option<StorageNativeOpeningOwnerLinkV1>,
    preparation_entered: bool,
    replay_entered: bool,
    take_entered: bool,
    finish: Option<Result<(), ResourceReservationErrorV1>>,
    completion: StartResourceColdCompletionOriginalV4,
    first: Option<First>,
}

impl StartResourceSessionOpeningOriginalV2 {
    /// Creates only inline destinations without native work or an account.
    #[must_use]
    pub fn new() -> Self {
        Self::for_role_v2(crate::ControllerInitialBrokerSessionRoleV1::Network)
    }

    /// Creates only inert destinations for the fixed Mount endpoint.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_namespace_v2() -> Self {
        Self::for_role_v2(crate::ControllerInitialBrokerSessionRoleV1::Mount)
    }

    /// Creates only inert Host destinations for the private catalog interval.
    ///
    /// The private pending-child catalog lender is the sole positive issuer;
    /// this constructor does not enter a turn or open a second Session.
    #[doc(hidden)]
    #[must_use]
    pub fn host_catalog_v2() -> Self {
        Self::for_role_v2(crate::ControllerInitialBrokerSessionRoleV1::Host)
    }

    fn for_role_v2(role: crate::ControllerInitialBrokerSessionRoleV1) -> Self {
        let endpoint = match role {
            crate::ControllerInitialBrokerSessionRoleV1::Host => ControllerStartResourceEndpointOriginalV2::host_catalog_v2(),
            crate::ControllerInitialBrokerSessionRoleV1::Mount => ControllerStartResourceEndpointOriginalV2::mount_v2(),
            _ => ControllerStartResourceEndpointOriginalV2::new(),
        };
        Self { link: None, role, endpoint,
            fixed: None, prefix: None, representation_prepaid: None,
            original_native_selected: std::cell::Cell::new(None), extent: None, opening: None,
            preparation_entered: false, replay_entered: false, take_entered: false,
            finish: None, completion: StartResourceColdCompletionOriginalV4::new(), first: None }
    }

    /// Returns the fixed resource selected by this inert destination.
    #[must_use]
    pub fn actual_role_v2(&self) -> crate::ControllerInitialBrokerSessionRoleV1 { self.role }

    /// Borrows the actual earliest cost, native or scheduling refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let Some(first) = self.first else {
            return self.endpoint.failure();
        };
        match first {
            First::Fixed => original_error(&self.fixed).or_else(|| self.endpoint.failure()),
            First::Prefix => original_error(&self.prefix),
            First::Endpoint => self.endpoint.failure(),
            First::Finish => original_error(&self.finish),
            First::Completion => self.completion.failure(),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED))
    }
}

impl Default for StartResourceSessionOpeningOriginalV2 {
    fn default() -> Self { Self::new() }
}

/// Exclusively borrows the genuine new Start and its retained opening original.
///
/// Only the actual Start/Root method constructs this short loan. No amount,
/// profile, raw descriptor or initial-B receiver is accepted as its authority.
#[doc(hidden)]
pub struct StartResourceSessionOpeningLoanV2<'loan> {
    native: &'loan mut StartNativeStateV1,
    plan: &'loan crate::OperationPlan,
    authorization: &'loan crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1,
    source: &'loan Journal,
    source_origin: &'loan source_origin::StartSourceOriginOriginalV1,
    root: &'loan RootStartResourceCurrentTurnV2<'loan>,
    controller: &'loan Journal,
    owner: &'loan mut StartResourceSessionOpeningOriginalV2,
    resident_base: ResourceVector,
    wall_expiry: i64,
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Lends only the actual current Network Session-opening Root purpose.
    ///
    /// # Errors
    /// Refuses changed Start/Source/native/Root association or a reused opening.
    #[doc(hidden)]
    pub fn borrow_network_opening_once_v2<'loan>(
        &'loan mut self,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        owner: &'loan mut StartResourceSessionOpeningOriginalV2,
        controller: &'loan Journal,
    ) -> Result<StartResourceSessionOpeningLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_resource_opening_once_v2(super::resource_state::StartResourceKindV2::Network,
            root, owner, controller)
    }

    pub fn borrow_mount_opening_once_v2<'loan>(
        &'loan mut self,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        owner: &'loan mut StartResourceSessionOpeningOriginalV2,
        controller: &'loan Journal,
    ) -> Result<StartResourceSessionOpeningLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_resource_opening_once_v2(super::resource_state::StartResourceKindV2::Mount,
            root, owner, controller)
    }

    /// Lends the Host opener only inside the genuine pending-child catalog turn.
    ///
    /// The actual Catalog6 loan first supplies this short Start borrower. Both
    /// the pending child and exact Root phase are checked again here before
    /// the sole existing opening constructor binds any endpoint or Journal.
    ///
    /// # Errors
    /// Refuses incomplete child admission/posts, changed Source/native/Root,
    /// active authority, another Host stage or a reused opening original.
    #[doc(hidden)]
    pub fn borrow_host_catalog_opening_once_v2<'loan>(
        &'loan mut self,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        owner: &'loan mut StartResourceSessionOpeningOriginalV2,
        controller: &'loan Journal,
    ) -> Result<StartResourceSessionOpeningLoanV2<'loan>, ResourceReservationErrorV1> {
        self.require_host_stage_v2(6, controller)?;
        self.native.host_publication_action.as_ref().ok_or(CLOSED)?
            .require_pending_catalog_v2(controller)?;
        root.require_host_publication_owner_v2(
            crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
            self.plan.operation_id(), self.native.native_turn, self.native.profile.as_ref(),
        )?;
        self.borrow_fixed_opening_once_v2(
            crate::ControllerInitialBrokerSessionRoleV1::Host,
            aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1::HostLaunch,
            root, owner, controller,
        )
    }

    fn borrow_resource_opening_once_v2<'loan>(
        &'loan mut self,
        kind: super::resource_state::StartResourceKindV2,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        owner: &'loan mut StartResourceSessionOpeningOriginalV2,
        controller: &'loan Journal,
    ) -> Result<StartResourceSessionOpeningLoanV2<'loan>, ResourceReservationErrorV1> {
        self.borrow_fixed_opening_once_v2(kind.role_v2(), kind.purpose_v2(), root, owner, controller)
    }

    fn borrow_fixed_opening_once_v2<'loan>(
        &'loan mut self,
        role: crate::ControllerInitialBrokerSessionRoleV1,
        purpose: aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1,
        root: &'loan RootStartResourceCurrentTurnV2<'loan>,
        owner: &'loan mut StartResourceSessionOpeningOriginalV2,
        controller: &'loan Journal,
    ) -> Result<StartResourceSessionOpeningLoanV2<'loan>, ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        root.require_opening_v2(self, controller)?;
        if owner.role != role || root.resource_purpose_data_v2()? != purpose {
            return Err(CLOSED);
        }
        if owner.link.is_some() || owner.first.is_some() {
            owner.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        let wall_expiry = self.original_wall_expiry_v1()?;
        owner.link = Some(StartResourceSessionOpeningOwnerLinkV2 {
            identity: Arc::clone(self.identity), parent: self.plan.operation_id(),
            native_turn: self.native.native_turn, role: owner.role,
        });
        Ok(StartResourceSessionOpeningLoanV2 {
            native: self.native, plan: self.plan, authorization: self.authorization, source: self.source,
            source_origin: self.source_origin, root, controller, owner,
            resident_base: self.resident_base, wall_expiry,
        })
    }
}

impl StartResourceSessionOpeningLoanV2<'_> {
    /// Returns the fixed purpose selected by the genuine retained Start owner.
    #[must_use]
    pub fn actual_role_v2(&self) -> crate::ControllerInitialBrokerSessionRoleV1 { self.owner.role }

    fn require_current(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.owner.first.is_some() || self.owner.finish.is_some() { return Err(CLOSED); }
        self.native.require_current_v1(self.controller)?;
        self.plan.require_accepted_start_data_v1(self.controller).map_err(|_| CLOSED)?;
        self.controller.require_public_mutation_targets_live_v2(
            self.authorization.project(), self.authorization.request().request(),
        ).map_err(ResourceReservationErrorV1::Journal)?;
        self.source_origin.require_completed_source_affinity_v1(self.source)?;
        if self.owner.role == crate::ControllerInitialBrokerSessionRoleV1::Host {
            self.native.host_publication_action.as_ref().ok_or(CLOSED)?
                .require_pending_catalog_v2(self.controller)?;
            self.root.require_host_publication_owner_v2(
                crate::normal_root::RootHostPublicationTurnKindV2::Catalog,
                self.plan.operation_id(), self.native.native_turn, self.native.profile.as_ref(),
            )?;
        }
        self.root.require_opening_owner_v2(self.plan.operation_id(), self.native.native_turn,
            self.native.profile.as_ref())
    }

    /// Borrows the unchanged Start origin and already tightened Root cutoff.
    ///
    /// # Errors
    /// Refuses a changed current Start/Source/Root opening association.
    pub fn original_horizon_v2(&self)
        -> Result<(aos_sandbox_model::RawPairedClockSample, u64), ResourceReservationErrorV1> {
        self.require_current()?;
        self.root.original_opening_horizon_v2()
    }

    pub(crate) fn owner_link_v2(&self) -> StartResourceSessionOpeningOwnerLinkV2 {
        // The sole private constructor installed this link before lending.
        match self.owner.link.as_ref() {
            Some(link) => link.clone(),
            None => std::process::abort(),
        }
    }

    pub(crate) fn controller_uid_v2(&self) -> Result<u32, ResourceReservationErrorV1> {
        self.require_current()?;
        Ok(rustix::process::geteuid().as_raw())
    }

    /// Admits actual compiled SDK backing before endpoint, floor or HELLO IO.
    ///
    /// # Errors
    /// Retains checked shape, native same-owner or original capacity refusal.
    #[doc(hidden)]
    pub fn admit_actual_capture_shape_once_v2(&mut self, shape: ControllerInitialBrokerSessionShapeV1)
        -> Result<(), ResourceReservationErrorV1> {
        if self.owner.fixed.is_some() { self.owner.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.owner.fixed = Some((|| {
            let root = self.require_current()?;
            let mut demand = geometry::fixed_start_network_client_handshake_receiving_demand_v2(shape.hello)
                .map_err(|_| CLOSED)?
                .checked_add(geometry::handshake_flight_demand(geometry::StorageHandshakeEndpointV1::Client)
                    .map_err(|_| CLOSED)?)?
                .checked_add(geometry::fixed_initialization_demand_v1().map_err(|_| CLOSED)?)?
                .checked_add(ControllerStartResourceSessionCapturedJournalOpenV4::fixed_preparation_demand(self.owner.role)?)?;
            for plane in [shape.endpoint, shape.endpoint_revalidation, shape.floor,
                shape.floor_revalidation, shape.process] {
                demand = demand.checked_add(capture_demand(plane)?)?;
            }
            let own = u64::try_from(size_of::<StartResourceSessionOpeningOriginalV2>()
                .checked_add(size_of::<StartResourceSessionOpeningLoanV2<'static>>())
                .and_then(|bytes| bytes.checked_mul(2)).ok_or(CLOSED)?).map_err(|_| CLOSED)?;
            demand = demand.checked_add(StartResourceColdCompletionOriginalV4::receiving_demand_v4()?)?;
            let complete = self.resident_base.checked_add(root)?
                .checked_add(self.native.resources.retained_demand_v2(self.native.native_turn)?)?
                .checked_add(demand)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, own))?;
            let native = self.native.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
            self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .prepare_start_resource_endpoint_once_v2(&mut self.owner.endpoint, native.original_mut_v1(),
                    self.controller, self.native.profile.as_ref(), complete)?;
            let capsule = ControllerStartResourceEndpointOriginalV2::receiving_demand_v2()?;
            let representation = demand.checked_add(capsule)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, own))?;
            // Only this opening's actual admitted construction/model/native
            // planes bound the later survivor handoff. Root/previous owners
            // and spent HELLO traffic cannot become representation credit.
            self.owner.representation_prepaid = Some(ResourceVector::ZERO
                .with(D::MemoryBytes, representation.get(D::MemoryBytes))
                .with(D::OpenFiles, representation.get(D::OpenFiles))
                .with(D::MetadataEntries, representation.get(D::MetadataEntries)));
            Ok(complete.checked_add(capsule)?)
        })());
        if !matches!(self.owner.fixed, Some(Ok(_))) {
            self.owner.first = Some(First::Fixed);
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Rejoins the genuine active fixed capture before endpoint-dependent work.
    ///
    /// # Errors
    /// Refuses unpaid shape, changed C/native/Root or a prior opening refusal.
    pub fn require_fixed_capture_current_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.require_current()?;
        if !matches!(self.owner.fixed, Some(Ok(_))) { return Err(CLOSED); }
        let native = self.native.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_start_resource_endpoint_current_v2(&mut self.owner.endpoint, native.original_v1(),
                self.controller, self.native.profile.as_ref())
    }

    /// Returns only the node from the actual current enrolled Bank original.
    ///
    /// # Errors
    /// Refuses incomplete fixed funding or changed native association.
    pub fn expected_node_v2(&mut self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        let native = self.native.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .start_resource_endpoint_expected_node_v2(&mut self.owner.endpoint, native.original_v1(),
                self.controller, self.native.profile.as_ref())
    }

    pub(crate) fn enter_journal_preparation_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        if self.owner.preparation_entered { self.owner.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.owner.preparation_entered = true;
        Ok(())
    }

    /// Pays the actual held native prefix and sole shared Session schema.
    ///
    /// # Errors
    /// Retains another facade/extent, checked geometry or original debit refusal.
    pub fn admit_captured_prefix_once_v2(&mut self,
        facade: &ControllerStartResourceSessionCapturedJournalOpenV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.prefix.is_some() || !self.owner.preparation_entered {
            self.owner.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.owner.prefix = Some((|| {
            self.require_fixed_capture_current_v2()?;
            if !facade.receiving_owner_link_v2().is_some_and(|link| link.same_owner_v2(&self.owner_link_v2())) {
                return Err(CLOSED);
            }
            let extent = facade.captured_extent().copied().ok_or(CLOSED)?;
            self.owner.extent = Some(extent);
            let variable = extent.dominant_native_receiving_demand_v1()?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(geometry::schema_demand(&extent).map_err(|_| CLOSED)?)?;
            let complete = self.owner.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(CLOSED)?.checked_add(variable)?;
            let native = self.native.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
            self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_create_provisioning_complete_v1(native.original_mut_v1(), self.controller,
                    self.native.profile.as_ref(), complete)?;
            self.owner.representation_prepaid = Some(self.owner.representation_prepaid
                .ok_or(CLOSED)?.checked_add(variable)?);
            Ok(complete)
        })());
        if !matches!(self.owner.prefix, Some(Ok(_))) { self.owner.first = Some(First::Prefix); return Err(CLOSED); }
        Ok(())
    }

    pub(crate) fn enter_journal_replay_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        if self.owner.replay_entered || !matches!(self.owner.prefix, Some(Ok(_))) {
            self.owner.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.owner.replay_entered = true;
        Ok(())
    }

    pub(crate) fn enter_journal_take_once_v2(&mut self, opening: &StorageNativeOpeningOwnerLinkV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        if self.owner.take_entered || !self.owner.replay_entered || self.owner.opening.is_some() {
            self.owner.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.owner.take_entered = true;
        self.owner.opening = Some(opening.clone());
        Ok(())
    }
}

fn capture_demand(shape: ControllerInitialBrokerSessionCaptureShapeV1)
    -> Result<ResourceVector, ResourceReservationErrorV1> {
    let memory = shape.inline_bytes.checked_add(shape.heap_bytes).ok_or(CLOSED)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| CLOSED)?)
        .with(D::OpenFiles, u64::try_from(shape.open_files).map_err(|_| CLOSED)?)
        .with(D::MetadataEntries, u64::try_from(shape.metadata_cells).map_err(|_| CLOSED)?))
}

fn original_error<T, E: Error + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;


impl StartResourceSessionOpeningLoanV2<'_> {
    /// Captures actual same-C Network self-execution through the shared engine.
    ///
    /// # Errors
    /// Retains native capture or original association refusal without replacement.
    pub fn capture_endpoint_execution_once_v2(&mut self)
        -> Result<ControllerEndpointExecutionOriginalV1, ControllerEndpointExecutionCaptureErrorV1> {
        self.require_fixed_capture_current_v2()
            .map_err(|_| ControllerEndpointExecutionCaptureErrorV1::Unavailable)?;
        let native = self.native.native.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ControllerEndpointExecutionCaptureErrorV1::Unavailable)?;
        let returned = self.native.bank.lock()
            .map_err(|_| ControllerEndpointExecutionCaptureErrorV1::Unavailable)?
            .capture_start_resource_execution_once_v2(&mut self.owner.endpoint, native.original_v1(),
                self.controller, self.native.profile.as_ref());
        if returned.is_err() { self.owner.first.get_or_insert(First::Endpoint); }
        returned
    }

    /// Opens the fixed Network endpoint directory into its actual destination.
    ///
    /// # Errors
    /// Retains native opening and same-owner refusal in their original owners.
    pub fn capture_endpoint_directory_once_v2(&mut self, destination: &mut EndpointNativeFileOpenOriginalV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        let native = self.native.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        let returned = self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .capture_start_resource_directory_once_v2(&mut self.owner.endpoint, native.original_v1(),
                self.controller, self.native.profile.as_ref(), destination);
        if returned.is_err() { self.owner.first.get_or_insert(First::Endpoint); }
        returned
    }

    /// Joins all four actual files to the same native Network custody owner.
    ///
    /// # Errors
    /// Retains execution, native post, file/currentness or custody refusal.
    pub fn capture_endpoint_custody_once_v2(&mut self,
        destination: &mut ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<SelfExecutionObservationV1>, files: [&EndpointNativeFileV1; 4],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        let native = self.native.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        let returned = self.native.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .capture_start_resource_custody_once_v2(&mut self.owner.endpoint, native.original_v1(),
                self.controller, self.native.profile.as_ref(), destination, execution, post, files);
        if returned.is_err() { self.owner.first.get_or_insert(First::Endpoint); }
        returned
    }

    /// Rejoins the same taken main Journal before dependent cold controls.
    ///
    /// # Errors
    /// Refuses a foreign Journal, incomplete take or any prior capture failure.
    pub fn require_opened_journal_v2(&mut self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed_capture_current_v2()?;
        if !self.owner.take_entered || !self.owner.opening.as_ref()
            .is_some_and(|opening| opening.matches_journal_v1(journal)) {
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Retains the live Start native association at the actual SDK return.
    ///
    /// SDK-owned endpoint/floor observations remain independently mandatory.
    /// This method neither performs nor suppresses their after observations,
    /// and it cannot construct completed HELLO/native disposition. Runtime
    /// still unconditionally finishes C and then Root after this short loan.
    ///
    /// # Errors
    /// Retains missing fixed capture, endpoint custody or same-turn refusal.
    pub fn finish_capture_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.finish.is_some() { self.owner.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.owner.finish = Some((|| {
            self.require_fixed_capture_current_v2()?;
            if self.owner.endpoint.completed_custody_v2().is_none() { return Err(CLOSED); }
            Ok(())
        })());
        if !matches!(self.owner.finish, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Finish);
            return Err(CLOSED);
        }
        Ok(())
    }
}

fn matches_resource_transcript_v2(role: crate::ControllerInitialBrokerSessionRoleV1,
    transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
) -> bool {
    use aos_sandbox_broker_session_protocol::profile;
    match role {
        crate::ControllerInitialBrokerSessionRoleV1::Host => profile::is_start_host_catalog_launch_transcript_v2(transcript),
        crate::ControllerInitialBrokerSessionRoleV1::Network => profile::is_network_service_transcript_v5(transcript),
        crate::ControllerInitialBrokerSessionRoleV1::Mount => profile::is_mount_attachment_anchor_transcript_v4(transcript),
        crate::ControllerInitialBrokerSessionRoleV1::Storage => profile::is_storage_lifecycle_transcript_v2(transcript),
        _ => false,
    }
}

impl StartResourceSessionOpeningOriginalV2 {
    // The Catalog IO interval shares opening6 before its outer C/Root posts.
    // Preserve the actual already-admitted opening residency while adding the
    // co-live method17 flight. This reads no native state or operation traffic.
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry)
    fn held_host_catalog_receiving_demand_v2(&self, identity: &Arc<()>,
        parent: OperationId, native_turn: u64,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.actual_role_v2() != crate::ControllerInitialBrokerSessionRoleV1::Host {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let association = self.completed_session_association_v4().ok_or(ResourceReservationErrorV1::Conflict)?;
        association.require_start_v4(identity, parent, profile)?;
        if self.link.as_ref().is_none_or(|link| link.native_turn != native_turn) { return Err(ResourceReservationErrorV1::Conflict); }
        let prepaid = self.representation_prepaid.ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, prepaid.get(D::MemoryBytes))
            .with(D::OpenFiles, prepaid.get(D::OpenFiles))
            .with(D::MetadataEntries, prepaid.get(D::MetadataEntries)))
    }
}
