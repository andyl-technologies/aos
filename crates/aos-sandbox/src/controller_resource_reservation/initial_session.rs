//! Owns the four initial Controller Client receivers under the same original B.
//!
//! Each fixed endpoint has one permanent complete-bound destination in the
//! original baseline ledger. Fixed capture and actual-prefix replay consume
//! distinct once-only full-vector phases before their corresponding growth.
//! Neither a numeric shape nor an opened journal constructs another original.

use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::component_receiving::ComponentReceivingOwnedOperationV1;
use super::ResourceReservationErrorV1;
use crate::journal::broker_session_receiving::{self as geometry, StorageHandshakePrivateFootprintV1};
use crate::normal_root::{
    NormalRootStartupErrorV1,
    ProductionControllerNormalRootProfileV1,
};

pub use aos_sandbox_broker::controller_receiving::ControllerInitialBrokerSessionRoleV1;
use aos_sandbox_broker::controller_receiving::{
    ControllerInitialSessionReceivingOriginalV1, ControllerReceivingOriginalV1,
};

/// Describes the actual retained carriers of one fixed capture engine.
///
/// The owning Security producer derives these widths from its concrete types
/// and shared native suppliers. They reduce the same original allowance;
/// they cannot construct an account, loan, endpoint or permission to observe.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerInitialBrokerSessionCaptureShapeV1 {
    /// Inline owning representation, excluding separately named heap backing.
    pub inline_bytes: usize,
    /// Dominant reached native, path, secret and parser backing bytes.
    pub heap_bytes: usize,
    /// Simultaneous original and failed-partial descriptors.
    pub open_files: usize,
    /// Representation census retained for diagnostics; it is not a namespace debit.
    pub metadata_cells: usize,
}

impl ControllerInitialBrokerSessionCaptureShapeV1 {
    fn demand(self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let count = |value| u64::try_from(value)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable);
        let bytes = self.inline_bytes.checked_add(self.heap_bytes)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, count(bytes)?)
            .with(D::OpenFiles, count(self.open_files)?))
    }
}

/// Describes the complete fixed initial acquisition before growing IO.
///
/// There is no resource vector or payer in this DATA. The genuine bank fixes
/// the role and joins its admitted profile before using these concrete widths.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerInitialBrokerSessionShapeV1 {
    /// Actual private HELLO owners and retained reducer-failure reservoirs.
    pub hello: StorageHandshakePrivateFootprintV1,
    /// Shared endpoint-file, self-execution and independent post capture.
    pub endpoint: ControllerInitialBrokerSessionCaptureShapeV1,
    /// Same endpoint's actual retained revalidation archive.
    pub endpoint_revalidation: ControllerInitialBrokerSessionCaptureShapeV1,
    /// Initial mode, provisioning, confinement and absence capture.
    /// Raw Required-sidecar acquisition, replay and TPM work are separate.
    pub floor: ControllerInitialBrokerSessionCaptureShapeV1,
    /// Same fixed floor's actual retained revalidation archive.
    pub floor_revalidation: ControllerInitialBrokerSessionCaptureShapeV1,
    /// Actual process-evidence originals reached by the selected HELLO.
    pub process: ControllerInitialBrokerSessionCaptureShapeV1,
}

/// Reports a refused or repeated original initial Session stage.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("original Controller initial Session receiving is closed")]
pub struct ControllerInitialBrokerSessionClosedV1;

/// Keeps intrinsic same-bank and once-role identity without a new allocation.
#[derive(Clone)]
pub(crate) struct ControllerInitialBrokerSessionOwnerLinkV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    role: ControllerInitialBrokerSessionRoleV1,
}

impl ControllerInitialBrokerSessionOwnerLinkV1 {
    pub(crate) fn same_owner_v1(&self, other: &Self) -> bool {
        self.role == other.role && Arc::ptr_eq(&self.original, &other.original)
    }
}

mod completed_native;
pub use completed_native::ControllerInitialSessionCompletedNativeBorrowV1;

mod provisioning_link;
mod storage_floor;
mod storage_physical;
pub use storage_physical::ControllerStorageFloorPhysicalReceivingV1;

type ProducerV1 = Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1>;

#[derive(Clone, Copy)]
enum FirstV1 {
    Preparation,
    FixedOperation,
    Before,
    Prefix,
    PrefixOperation,
    EndpointArming,
    EndpointNative,
    EndpointCustody,
    FloorArming,
    ActualShape,
    After,
    StorageFloor,
    Reentry,
}

/// Retains one genuine once-only boot endpoint receiver and its first causes.
///
/// Only the actual enrolled bank constructs this value. Successful handoff
/// does not refund its permanent reservation or rearm the initial endpoint.
/// A failed owner remains resident in the enclosing Controller Session slots.
#[doc(hidden)]
#[must_use = "retain this original beside all partial initial Session owners"]
pub struct ControllerInitialBrokerSessionReceivingV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    role: ControllerInitialBrokerSessionRoleV1,
    recover_cutoff: Option<u64>,
    shape: Option<ControllerInitialBrokerSessionShapeV1>,
    endpoint_arming: Option<Result<(), ResourceReservationErrorV1>>,
    endpoint_native: Option<Result<(), aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1>>,
    endpoint_custody: Option<Result<(), aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1>>,
    floor_arming: Option<Result<(), ResourceReservationErrorV1>>,
    actual_shape: Option<Result<(), ResourceReservationErrorV1>>,
    fixed: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed_operation: Option<ComponentReceivingOwnedOperationV1>,
    before: Option<ProducerV1>,
    before_binding: Option<Result<(), ResourceReservationErrorV1>>,
    after: Option<ProducerV1>,
    after_binding: Option<Result<(), ResourceReservationErrorV1>>,
    receiving: Option<ControllerInitialSessionReceivingOriginalV1>,
    extent: Option<crate::journal::ProtectedJournalPreopenReplayExtentV1>,
    prefix: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    prefix_operation: Option<ComponentReceivingOwnedOperationV1>,
    controller_uid: Option<u32>,
    opening: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    storage_floor: storage_floor::InitialStorageFloorReceivingV1,
    physical_association: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    physical_transfer: Option<Result<(), ResourceReservationErrorV1>>,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    runtime_binding: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    preparation_entered: bool,
    replay_entered: bool,
    take_entered: bool,
    borrowed: bool,
    borrow_entered: bool,
    first: Option<FirstV1>,
}

/// Exclusively borrows the same initial receiver for its closed native stages.
///
/// This loan exposes no account, caller path, UID constructor or grant vector.
#[doc(hidden)]
pub struct ControllerInitialBrokerSessionReceivingLoanV1<'original> {
    owner: &'original mut ControllerInitialBrokerSessionReceivingV1,
}

impl ControllerInitialBrokerSessionReceivingV1 {
    pub(crate) fn require_completed_stop_cleanup_journal_v1(&self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        journal: &crate::Journal, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_stop_cleanup_journal_body_v1(journal, cutoff)?;
        native.require_stop_cleanup_session_original_v1(self.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        Ok(())
    }

    pub(crate) fn require_completed_stop_cleanup_source_journal_v1(&self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        journal: &crate::Journal, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_stop_cleanup_journal_body_v1(journal, cutoff)?;
        native.require_stop_cleanup_source_session_original_v1(self.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        Ok(())
    }

    fn require_completed_stop_cleanup_journal_body_v1(&self,
        journal: &crate::Journal, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.recover_cutoff != Some(cutoff) || self.role != ControllerInitialBrokerSessionRoleV1::Host
            || self.failure().is_some() || !self.take_entered
            || !matches!(self.after, Some(Ok(_))) || !matches!(self.after_binding, Some(Ok(())))
            || !self.opening.as_ref().is_some_and(|opening| opening.matches_journal_v1(journal))
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }

    /// Retains the actual Recover-funded Host identity through Session disposal.
    ///
    /// The existing native receiver selects its own financial branch. Other
    /// valid branches return no Recover retention; Source22 keeps its distinct
    /// Stop cleanup retainer. This lends no query, effect or financial capacity.
    ///
    /// # Errors
    /// Refuses a missing, unclaimed, failed or inactive actual native receiver.
    #[doc(hidden)]
    pub fn retain_recovery_session_native_v1(&self)
        -> Result<Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoverySessionRetentionV1>, ResourceReservationErrorV1>
    {
        self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .retain_recovery_session_native_v1().map_err(Into::into)
    }

    /// Retains the genuine Source22 financial identity in the final Session.
    ///
    /// # Errors
    /// Refuses a missing, failed or already fenced actual initial receiver.
    #[doc(hidden)]
    pub fn retain_stop_cleanup_session_native_v1(&self)
        -> Result<Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSessionRetentionV1>, ResourceReservationErrorV1>
    {
        self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .retain_stop_cleanup_session_native_v1().map_err(Into::into)
    }

    pub(crate) fn require_execution_cleanup_source_v2(&self,
        source: &super::ControllerExecutionSourceScopeV1<'_, '_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let receiving = self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_execution_cold_session_original_v2(receiving).map_err(Into::into)
    }

    pub(crate) fn require_stop_cleanup_source_original_v1(&self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        native.require_stop_cleanup_source_session_original_v1(
            self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?)
            .map_err(Into::into)
    }

    /// Retains the actual Source/C18 identity in the completed native Session.
    ///
    /// # Errors
    /// Refuses a failed or inactive actual initial cold receiver.
    #[doc(hidden)]
    pub fn retain_execution_cold_native_v2(&self)
        -> Result<Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerExecutionColdSessionRetentionV2>, ResourceReservationErrorV1>
    {
        self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .retain_execution_cold_native_v2().map_err(Into::into)
    }

    pub(super) fn new(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> Self {
        Self {
            original,
            profile,
            role,
            recover_cutoff: None,
            shape: None,
            endpoint_arming: None,
            endpoint_native: None,
            endpoint_custody: None,
            floor_arming: None,
            actual_shape: None,
            fixed: None,
            fixed_operation: None,
            before: None,
            before_binding: None,
            after: None,
            after_binding: None,
            receiving: None,
            extent: None,
            prefix: None,
            prefix_operation: None,
            controller_uid: None,
            opening: None,
            storage_floor: storage_floor::InitialStorageFloorReceivingV1::new(),
            physical_association: None,
            physical_transfer: None,
            runtime: None,
            runtime_binding: None,
            preparation_entered: false,
            replay_entered: false,
            take_entered: false,
            borrowed: false,
            borrow_entered: false,
            first: None,
        }
    }

    pub(super) fn fixed_demand(
        role: ControllerInitialBrokerSessionRoleV1,
        shape: ControllerInitialBrokerSessionShapeV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let hello = geometry::fixed_controller_client_handshake_receiving_demand(shape.hello)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let flight = geometry::handshake_flight_demand(geometry::StorageHandshakeEndpointV1::Client)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let initialization = geometry::fixed_initialization_demand_v1()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let native = crate::journal::ControllerBrokerSessionCapturedJournalOpenV1::
            fixed_preparation_demand(role)?;
        let completed_native_bytes = size_of::<ControllerInitialSessionCompletedNativeBorrowV1<'static>>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(size_of::<crate::journal::JournalProtectedNativeResidencyV1<'static>>().checked_mul(3)?))
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(size_of::<Self>().checked_add(completed_native_bytes)
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?)
            .checked_add(ControllerInitialSessionReceivingOriginalV1::receiving_demand_v1()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?)?
            .checked_add(storage_floor::InitialStorageFloorReceivingV1::receiving_temporary_demand_v1()?)?;
        let hello_files = hello.get(D::OpenFiles);
        let main_files = native.get(D::OpenFiles);
        let demand = hello.checked_add(flight)?.checked_add(initialization)?.checked_add(native)?.checked_add(own)?
            .checked_add(shape.endpoint.demand()?)?
            .checked_add(shape.endpoint_revalidation.demand()?)?
            .checked_add(shape.floor.demand()?)?
            .checked_add(shape.floor_revalidation.demand()?)?
            .checked_add(shape.process.demand()?)?;
        let completed_hello = geometry::controller_client_completed_handshake_open_file_bound_v1()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        // The actual initial Client enters main preparation only through the
        // completed Verified HELLO handoff. A failed receive retains its full
        // native prefix and cannot open main. Successful receive staging has
        // already dropped before Cold retains the four-file carrier below.
        let peak = hello_files.max(completed_hello.checked_add(main_files)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?);
        let files = demand.get(D::OpenFiles).checked_sub(hello_files)
            .and_then(|files| files.checked_sub(main_files))
            .and_then(|files| files.checked_add(peak))
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(demand.with(D::OpenFiles, files))
    }

    pub(super) fn prepare_once(&mut self, shape: ControllerInitialBrokerSessionShapeV1) {
        self.prepare_with_receiving_once_v1(shape, None)
    }

    pub(super) fn prepare_recover_once_v1(&mut self, shape: ControllerInitialBrokerSessionShapeV1,
        receiving: ControllerInitialSessionReceivingOriginalV1, cutoff: u64,
    ) {
        self.recover_cutoff = Some(cutoff);
        self.prepare_with_receiving_once_v1(shape, Some(receiving));
    }

    pub(super) fn prepare_recovered_ordinary_once_v2(
        &mut self,
        shape: ControllerInitialBrokerSessionShapeV1,
        receiving: ControllerInitialSessionReceivingOriginalV1,
    ) {
        // The genuine new context supplies this role's funding. Ordinary cold
        // acquisition uses its existing paid mechanical clock; it cannot renew
        // the completed Recover request or select a read-only recovery profile.
        self.prepare_with_receiving_once_v1(shape, Some(receiving));
    }

    fn prepare_with_receiving_once_v1(&mut self, shape: ControllerInitialBrokerSessionShapeV1,
        receiving: Option<ControllerInitialSessionReceivingOriginalV1>,
    ) {
        if self.fixed.is_some() || self.first.is_some() {
            self.first.get_or_insert(FirstV1::Reentry);
            return;
        }
        self.shape = Some(shape);
        // The real C role latch enters before even pure geometry. The lower
        // owner returns no Native receiver, account or positive IO permission.
        self.receiving = Some(match receiving {
            Some(receiving) => receiving,
            None => ControllerInitialSessionReceivingOriginalV1::from_actual_profile_v1(
                Arc::clone(&self.original), self.profile.lower_original_v1(), self.role),
        });
        self.fixed = Some((|| {
            let receiving = self.receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.require_claimed_v1().map_err(ResourceReservationErrorV1::from)?;
            let demand = Self::fixed_demand(self.role, shape)?;
            receiving.debit_initial_session_representation_v1(demand)
                .map_err(ResourceReservationErrorV1::from)?;
            Ok(demand)
        })());
        if !matches!(self.fixed, Some(Ok(_))) {
            // Preserve the old claim's global close after fixed geometry
            // refusal; the actual upper error stays ahead of this close post.
            if let Some(receiving) = self.receiving.as_mut() {
                receiving.fence_after_upper_representation_refusal_v1();
            }
            self.first = Some(FirstV1::Preparation);
        }
    }

    pub(super) fn is_prepared(&self) -> bool {
        matches!(self.fixed, Some(Ok(_))) && self.first.is_none()
            && self.fixed_operation.is_none()
    }

    /// Reports the fixed role retained by the genuine original.
    #[must_use]
    pub const fn role_v1(&self) -> ControllerInitialBrokerSessionRoleV1 {
        self.role
    }

    /// Reports the node retained by the same original enrolled bank.
    ///
    /// # Errors
    /// Refuses absent, closed or unclaimed original endpoint custody.
    pub fn expected_node_v1(&self) -> Result<[u8; 16], ControllerInitialBrokerSessionClosedV1> {
        self.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?
            .expected_node_v1()
            .map_err(|_| ControllerInitialBrokerSessionClosedV1)
    }

    /// Retains the actual Controller reactor as nonauthorizing mechanics.
    ///
    /// The installed caller supplies the same Arc parked by RuntimePreparation.
    /// This never starts IO, pays a receiver or replaces the genuine C/profile,
    /// fixed once-Storage claim and actual Journal associations.
    ///
    /// # Errors
    /// Retains repeated, non-Storage, unprepared or already-entered association.
    #[doc(hidden)]
    pub fn retain_runtime_mechanics_once_v1(&mut self, runtime: Arc<tokio::runtime::Runtime>)
        -> Result<(), ControllerInitialBrokerSessionClosedV1>
    {
        if self.runtime_binding.is_some() || self.runtime.is_some()
            || self.role != ControllerInitialBrokerSessionRoleV1::Storage
            || !self.is_prepared() || self.fixed_operation.is_some() || self.borrowed
        {
            if self.runtime_binding.is_none() {
                self.runtime_binding = Some(Err(ControllerInitialBrokerSessionClosedV1));
            }
            self.first.get_or_insert(FirstV1::StorageFloor);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.runtime_binding = Some(self.receiving.as_ref()
            .ok_or(ControllerInitialBrokerSessionClosedV1)?
            .require_storage_floor_current_v1().map_err(|_| ControllerInitialBrokerSessionClosedV1));
        if !matches!(self.runtime_binding, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::StorageFloor);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.runtime = Some(runtime);
        Ok(())
    }

    /// Consumes the fixed flight before any mode/path/native observation.
    ///
    /// # Errors
    /// Keeps original funding, currentness and incomplete-entry causes resident.
    pub fn begin_capture_once_v1(&mut self) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if !self.is_prepared() || self.borrowed {
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        let Some(Ok(demand)) = self.fixed.as_ref() else {
            return Err(ControllerInitialBrokerSessionClosedV1);
        };
        self.fixed_operation = Some(ComponentReceivingOwnedOperationV1::preflight(*demand, *demand));
        let Some(operation) = self.fixed_operation.as_mut() else {
            return Err(ControllerInitialBrokerSessionClosedV1);
        };
        if operation.consume_once().is_err() {
            self.first = Some(FirstV1::FixedOperation);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }

        self.before = Some(match self.receiving.as_mut() {
            Some(receiving) => receiving.observe_profile_before_once_v1(self.profile.lower_original_v1())
                .map_err(Into::into),
            None => Err(NormalRootStartupErrorV1::Service),
        });
        self.before_binding = Some(match self.before.as_ref() {
            Some(Ok(before)) => self.require_recipient_v1(before.0, before.1),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.before_binding, Some(Ok(()))) {
            self.first = Some(FirstV1::Before);
            // Fixed payment entered both bookends. No primary capture follows
            // this refusal, but the independently available after is still owed.
            let _after = self.finish_capture_once_v1();
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.controller_uid = Some(rustix::process::geteuid().as_raw());
        Ok(())
    }

    /// Borrows only the already-consumed actual per-endpoint receiver.
    ///
    /// # Errors
    /// Refuses incomplete, failed, currently borrowed or already-taken entry.
    pub fn borrow_once_v1(&mut self)
        -> Result<ControllerInitialBrokerSessionReceivingLoanV1<'_>, ControllerInitialBrokerSessionClosedV1>
    {
        if self.first.is_some() || self.borrowed || self.borrow_entered || self.take_entered
            || !matches!(self.before_binding, Some(Ok(())))
            || !self.fixed_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.borrowed = true;
        self.borrow_entered = true;
        Ok(ControllerInitialBrokerSessionReceivingLoanV1 { owner: self })
    }

    /// Runs the independent actual Controller post after either capture outcome.
    ///
    /// This never releases native partials, completes an upper semantic result,
    /// refunds capacity or permits another initial connection.
    ///
    /// # Errors
    /// Retains earlier causes before later profile/currentness refusals.
    pub fn finish_capture_once_v1(&mut self) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.after.is_some() || self.borrowed
            || !self.fixed_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.after = Some(match self.receiving.as_mut() {
            Some(receiving) => receiving.observe_profile_after_once_v1(self.profile.lower_original_v1())
                .map_err(Into::into),
            None => Err(NormalRootStartupErrorV1::Service),
        });
        self.after_binding = Some(match (self.before.as_ref(), self.after.as_ref()) {
            (Some(Ok(before)), Some(Ok(after))) if before == after =>
                self.require_recipient_v1(after.0, after.1),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::After);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    fn require_recipient_v1(&self, recipient: [u8; 16], producer: [u8; 16])
        -> Result<(), ResourceReservationErrorV1>
    {
        self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .require_recipient_v1(recipient, producer).map_err(Into::into)
    }

    /// Borrows the actual original profile's guarded native cause, if selected.
    ///
    /// The returned guard stays alive while its cause is borrowed. Earlier
    /// Native geometry/ledger/shape failures cannot expose a later profile post.
    #[doc(hidden)]
    pub fn profile_failure_view_v1(&self)
        -> Option<crate::normal_root::ControllerProfileFailureViewV1<'_>>
    {
        if !matches!(self.first, Some(FirstV1::Before | FirstV1::After)) {
            return None;
        }
        self.receiving.as_ref()?.profile_failure_view_v1(self.profile.lower_original_v1())
    }

    /// Borrows the actual earliest retained funding, profile or stage cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Preparation => self.receiving.as_ref().and_then(|owner| owner.failure())
                .or_else(|| self.fixed.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::FixedOperation => self.fixed_operation.as_ref()?.failure().map(|cause| cause as &dyn Error),
            FirstV1::Before => self.before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| self.receiving.as_ref().and_then(|owner| owner.failure())
                    .unwrap_or(cause as &dyn Error))
                .or_else(|| self.before_binding.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::Prefix => self.receiving.as_ref().and_then(|owner| owner.failure())
                .or_else(|| self.prefix.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::PrefixOperation => self.prefix_operation.as_ref()?.failure().map(|cause| cause as &dyn Error),
            FirstV1::EndpointCustody => self.receiving.as_ref().and_then(|owner| owner.failure())
                .or_else(|| self.endpoint_custody.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::EndpointNative => self.receiving.as_ref().and_then(|owner| owner.failure())
                .or_else(|| self.endpoint_native.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::EndpointArming => self.endpoint_arming.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error),
            FirstV1::FloorArming => self.floor_arming.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error),
            FirstV1::ActualShape => self.actual_shape.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error),
            FirstV1::After => self.after.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| self.receiving.as_ref().and_then(|owner| owner.failure())
                    .unwrap_or(cause as &dyn Error))
                .or_else(|| self.after_binding.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)),
            FirstV1::StorageFloor => self.receiving.as_ref().and_then(|owner| owner.failure())
                .or_else(|| self.physical_association.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)))
                .or_else(|| self.physical_transfer.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)))
                .or_else(|| self.runtime_binding.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)))
                .or_else(|| self.storage_floor.failure()),
            FirstV1::Reentry => Some(&ControllerInitialBrokerSessionClosedV1),
        }
    }
}

impl ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    /// Reports only this actual private Stop cold financial purpose.
    ///
    /// # Errors
    /// Refuses missing or failed current native custody.
    #[doc(hidden)]
    pub fn is_host_stop_cleanup_data_v1(&self) -> Result<bool, ControllerInitialBrokerSessionClosedV1> {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        Ok(self.owner.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?
            .is_host_stop_cleanup_data_v1())
    }

    /// Selects only the finite actual Source/C18 NoApply cold profile.
    ///
    /// # Errors
    /// Refuses missing, failed or no-longer-current native custody.
    #[doc(hidden)]
    pub fn is_execution_cleanup_cold_data_v2(&self) -> Result<bool, ControllerInitialBrokerSessionClosedV1> {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        Ok(self.owner.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?
            .is_execution_cleanup_cold_data_v2())
    }

    pub(crate) fn require_git_coverage_profile_v1(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        if !matches!(self.owner.role,
            ControllerInitialBrokerSessionRoleV1::Mount | ControllerInitialBrokerSessionRoleV1::Storage)
            || !std::ptr::eq(self.owner.profile.as_ref(), profile)
        {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        Ok(())
    }

    /// Lends the installed ordinary profile selector from this paid receiver.
    ///
    /// Recover and readonly reconciliation preserve their separate profiles.
    /// No external role or method roster can select this provenance.
    ///
    /// # Errors
    /// Refuses a failed fixed phase or a missing/currentness-refused receiver.
    #[doc(hidden)]
    pub fn selected_maintenance_client_role_v2(&self)
        -> Result<Option<ControllerInitialBrokerSessionRoleV1>, ControllerInitialBrokerSessionClosedV1>
    {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        self.owner.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?
            .selected_maintenance_client_role_v2().map_err(|_| ControllerInitialBrokerSessionClosedV1)
    }

    /// Borrows the original authorized Recover horizon for the closed cold profile.
    ///
    /// This DATA is absent for the initial Session purpose. It never constructs
    /// a recovery owner, renews a deadline, or grants an Inventory request.
    #[doc(hidden)]
    #[must_use]
    pub const fn operator_recover_cutoff_data_v1(&self) -> Option<u64> {
        self.owner.recover_cutoff
    }

    /// Reports the role fixed by the same genuine original, as passive DATA.
    #[must_use]
    pub const fn role_v1(&self) -> ControllerInitialBrokerSessionRoleV1 {
        self.owner.role
    }

    /// Gates the shared fixed Client capture before its first native operation.
    ///
    /// # Errors
    /// Refuses another role, unconsumed funding, prior failure or repeated entry.
    pub fn require_fixed_capture_current_v1(
        &self, role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || role != self.owner.role
            || !matches!(self.owner.before_binding, Some(Ok(())))
            || !self.owner.fixed_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        Ok(())
    }

    /// Obtains the actual same-C self guard before fixed endpoint acquisition.
    ///
    /// # Errors
    /// Retains native capture failure or refuses missing genuine fixed entry.
    #[doc(hidden)]
    pub fn capture_endpoint_execution_once_v1(&mut self)
        -> Result<aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
            aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>
    {
        use aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1 as Failure;
        self.require_fixed_capture_current_v1(self.owner.role).map_err(|_| Failure::Unavailable)?;
        let returned = self.owner.receiving.as_mut().ok_or(Failure::Unavailable)?
            .capture_endpoint_execution_once_v1();
        if returned.is_err() {
            self.owner.endpoint_native.get_or_insert(Err(
                aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1::Conflict,
            ));
            self.owner.first.get_or_insert(FirstV1::EndpointNative);
        }
        returned
    }

    /// Captures the fixed directory through this same paid original role.
    ///
    /// The whole native result stays in the actual lower destination. No raw
    /// descriptor, caller path or semantic endpoint is returned.
    ///
    /// # Errors
    /// Refuses absent fixed entry or lower same-C once-role/currentness gates.
    #[doc(hidden)]
    pub fn capture_endpoint_directory_once_v1(
        &mut self,
        destination: &mut aos_sandbox_broker::endpoint_native_files::EndpointNativeFileOpenOriginalV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        self.owner.endpoint_native = Some(match self.owner.receiving.as_mut() {
            Some(receiving) => receiving.capture_endpoint_directory_once_v1(destination),
            None => Err(aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1::Conflict),
        });
        if matches!(self.owner.endpoint_native, Some(Ok(()))) { Ok(()) }
        else {
            self.owner.first.get_or_insert(FirstV1::EndpointNative);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Joins actual same-C native endpoint custody without semantic admission.
    ///
    /// The lower destination physically owns the real guard and same opaque
    /// descriptors. No completion assertion or substitute identity is accepted.
    ///
    /// # Errors
    /// Retains same-original, role, phase or native-custody refusal.
    #[doc(hidden)]
    pub fn capture_endpoint_custody_once_v1(
        &mut self,
        destination: &mut aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
        files: [&aos_sandbox_broker::endpoint_native_files::EndpointNativeFileV1; 4],
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        self.require_fixed_capture_current_v1(self.owner.role)?;
        self.owner.endpoint_custody = Some(match self.owner.receiving.as_mut() {
            Some(receiving) => receiving.capture_endpoint_custody_once_v1(destination, execution, post, files),
            None => Err(aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1::Conflict),
        });
        if matches!(self.owner.endpoint_custody, Some(Ok(()))) { Ok(()) }
        else {
            self.owner.first.get_or_insert(FirstV1::EndpointCustody);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Checks the actual fixed Security recipe before its first capture IO.
    ///
    /// The real upper producer derives this DATA from its concrete types and
    /// lower suppliers. Accepted dimensions cannot be exchanged between named
    /// capture families, and a smaller caller shape cannot grant larger work.
    ///
    /// # Errors
    /// Retains repeated entry, missing fixed payment or actual shape shortfall.
    pub fn admit_actual_capture_shape_once_v1(
        &mut self,
        actual: ControllerInitialBrokerSessionShapeV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.actual_shape.is_some() || self.owner.first.is_some() {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.actual_shape = Some((|| {
            if !self.owner.fixed_operation.as_ref()
                .is_some_and(|phase| phase.is_consumed_current())
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let accepted = self.owner.shape.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let accepted_hello = geometry::fixed_handshake_receiving_demand(accepted.hello)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let actual_hello = geometry::fixed_handshake_receiving_demand(actual.hello)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            accepted_hello.checked_sub(actual_hello)?;
            for (funded, reached) in [
                (accepted.endpoint, actual.endpoint),
                (accepted.endpoint_revalidation, actual.endpoint_revalidation),
                (accepted.floor, actual.floor),
                (accepted.floor_revalidation, actual.floor_revalidation),
                (accepted.process, actual.process),
            ] {
                funded.demand()?.checked_sub(reached.demand()?)?;
            }
            Ok(())
        })());
        if matches!(self.owner.actual_shape, Some(Ok(()))) {
            Ok(())
        } else {
            self.owner.first = Some(FirstV1::ActualShape);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Checks the actual endpoint archive shape before its first allocation.
    ///
    /// # Errors
    /// Retains repeated, underfunded or overflowing actual archive geometry.
    pub fn require_endpoint_revalidation_shape_v1(
        &mut self, actual: ControllerInitialBrokerSessionCaptureShapeV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.endpoint_arming.is_some() || self.owner.first.is_some() {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.endpoint_arming = Some((|| {
            let accepted = self.owner.shape.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?.endpoint_revalidation;
            accepted.demand()?.checked_sub(actual.demand()?)?;
            Ok(())
        })());
        if matches!(self.owner.endpoint_arming, Some(Ok(()))) {
            Ok(())
        } else {
            self.owner.first = Some(FirstV1::EndpointArming);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Checks the actual floor archive shape before its first allocation.
    ///
    /// # Errors
    /// Retains repeated, underfunded or overflowing actual archive geometry.
    pub fn require_floor_revalidation_shape_v1(
        &mut self, actual: ControllerInitialBrokerSessionCaptureShapeV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.floor_arming.is_some() || self.owner.first.is_some() {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.floor_arming = Some((|| {
            let accepted = self.owner.shape.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?.floor_revalidation;
            accepted.demand()?.checked_sub(actual.demand()?)?;
            Ok(())
        })());
        if matches!(self.owner.floor_arming, Some(Ok(()))) {
            Ok(())
        } else {
            self.owner.first = Some(FirstV1::FloorArming);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Reports the node retained by this same enrolled original.
    ///
    /// # Errors
    /// Refuses a closed, missing or unclaimed genuine bank original.
    pub fn expected_node_v1(&self) -> Result<[u8; 16], ControllerInitialBrokerSessionClosedV1> {
        self.owner.expected_node_v1()
    }

    /// Joins the actual final-taken main Journal before dependent floor work.
    ///
    /// # Errors
    /// Refuses another Journal, an incomplete take or a failed receiving phase.
    pub fn require_opened_journal_v1(
        &self,
        journal: &crate::Journal,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || !self.owner.take_entered
            || !self.owner.opening.as_ref()
                .is_some_and(|opening| opening.matches_journal_v1(journal))
        {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        Ok(())
    }

    pub(crate) const fn actual_role_v1(&self) -> ControllerInitialBrokerSessionRoleV1 {
        self.owner.role
    }

    pub(crate) fn owner_link_v1(&self) -> ControllerInitialBrokerSessionOwnerLinkV1 {
        ControllerInitialBrokerSessionOwnerLinkV1 {
            original: Arc::clone(&self.owner.original), role: self.owner.role,
        }
    }

    pub(crate) fn controller_uid_v1(&self) -> Result<u32, ControllerInitialBrokerSessionClosedV1> {
        self.owner.controller_uid.ok_or(ControllerInitialBrokerSessionClosedV1)
    }

    pub(crate) fn enter_journal_preparation_once_v1(
        &mut self, role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || role != self.owner.role || self.owner.preparation_entered
            || !self.owner.fixed_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.preparation_entered = true;
        Ok(())
    }

    /// Pays native replay and complete shared schema before prefix decoding.
    ///
    /// The same held extent is retained before replay closes its accessor. No
    /// caller length, scalar maximum, replacement prefix or resource vector enters.
    ///
    /// # Errors
    /// Retains refused representation arithmetic or the same original B debit.
    pub fn admit_captured_prefix_once_v1(
        &mut self, opening: &crate::journal::ControllerBrokerSessionCapturedJournalOpenV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.prefix.is_some() || !self.owner.preparation_entered || self.owner.first.is_some() {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        let expected_owner = self.owner_link_v1();
        self.owner.prefix = Some((|| {
            // The extent must belong to this exact prepared original, rather
            // than a smaller foreign facade with an otherwise valid prefix.
            if !opening.receiving_owner_link_v1()
                .is_some_and(|actual| actual.same_owner_v1(&expected_owner))
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let extent = opening.captured_extent().copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.owner.extent = Some(extent);
            let native = extent.dominant_native_receiving_demand_v1()?;
            let semantic = extent.dominant_semantic_receiving_demand_v1()?;
            let schema = geometry::schema_demand(&extent)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            // The fixed stage already paid pre-main HELLO/checkpoint models.
            let variable = native.checked_add(semantic)?.checked_add(schema)?;
            let fixed = self.owner.fixed.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            self.owner.receiving.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .debit_initial_session_representation_v1(fixed.checked_add(variable)?)
                .map_err(ResourceReservationErrorV1::from)?;
            Ok(variable)
        })());
        let Some(Ok(variable)) = self.owner.prefix.as_ref() else {
            self.owner.first = Some(FirstV1::Prefix);
            return Err(ControllerInitialBrokerSessionClosedV1);
        };
        self.owner.prefix_operation = Some(ComponentReceivingOwnedOperationV1::preflight(*variable, *variable));
        if !self.owner.prefix_operation.as_mut().is_some_and(|phase| phase.consume_once().is_ok()) {
            self.owner.first = Some(FirstV1::PrefixOperation);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        Ok(())
    }

    pub(crate) fn enter_journal_replay_once_v1(
        &mut self, role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || role != self.owner.role || self.owner.replay_entered
            || !self.owner.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.replay_entered = true;
        Ok(())
    }

    pub(crate) fn enter_journal_take_once_v1(
        &mut self,
        role: ControllerInitialBrokerSessionRoleV1,
        opening: &crate::journal::StorageNativeOpeningOwnerLinkV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.owner.first.is_some() || role != self.owner.role
            || !self.owner.replay_entered || self.owner.take_entered || self.owner.opening.is_some()
            || !self.owner.prefix_operation.as_ref().is_some_and(|phase| phase.is_consumed_current())
        {
            self.owner.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.take_entered = true;
        self.owner.opening = Some(opening.clone());
        Ok(())
    }
}

impl Drop for ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    fn drop(&mut self) {
        // Ending a temporary exclusive borrow does not dispose any native
        // attempt, release the permanent charge or reset the initial role.
        self.owner.borrowed = false;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_capture_backing_overflow_refuses_without_allocation() {
        let shape = ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: usize::MAX,
            heap_bytes: 1,
            open_files: 0,
            metadata_cells: 0,
        };
        assert!(shape.demand().is_err());
    }

    #[test]
    fn archive_shape_cannot_substitute_memory_for_descriptor_capacity() {
        let accepted = ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: 128,
            heap_bytes: 4096,
            open_files: 2,
            metadata_cells: 8,
        };
        let actual = ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: 64,
            heap_bytes: 1024,
            open_files: 3,
            metadata_cells: 4,
        };
        assert!(accepted.demand().unwrap().checked_sub(actual.demand().unwrap()).is_err());
    }
}

impl ControllerInitialBrokerSessionReceivingV1 {
    pub(crate) fn require_completed_recover_journal_v1(&self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        journal: &crate::Journal, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.recover_cutoff != Some(cutoff) || self.role != ControllerInitialBrokerSessionRoleV1::Storage
            || self.failure().is_some() || !self.take_entered
            || !matches!(self.after, Some(Ok(_))) || !matches!(self.after_binding, Some(Ok(())))
            || !self.opening.as_ref().is_some_and(|opening| opening.matches_journal_v1(journal))
        { return Err(ResourceReservationErrorV1::Conflict); }
        native.require_storage_session_original_v1(self.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        Ok(())
    }
}

impl ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    /// Reports only the purpose of this actual residual receiver.
    #[doc(hidden)]
    #[must_use]
    pub fn reconciliation_role_data_v2(&self)
        -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerReconciliationInventoryRoleV2> {
        self.owner.receiving.as_ref()?.reconciliation_role_data_v2()
    }
}

impl ControllerInitialBrokerSessionReceivingV1 {
    pub(crate) fn require_completed_reconciliation_journal_v2(&self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
        journal: &crate::Journal, cutoff: u64,
        role: aos_sandbox_broker::controller_receiving::bank_launch::ControllerReconciliationInventoryRoleV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.recover_cutoff != Some(cutoff) || self.role != role.broker_role_data_v2()
            || self.failure().is_some() || !self.take_entered
            || !matches!(self.after, Some(Ok(_))) || !matches!(self.after_binding, Some(Ok(())))
            || !self.opening.as_ref().is_some_and(|opening| opening.matches_journal_v1(journal)) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.require_reconciliation_inventory_session_original_v2(self.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?, role)?;
        Ok(())
    }
}
