//! Retains the successor's closed, capability-authorized Create reconciliation.
//!
//! This owner pays a new Recover observation on the existing C residual. It
//! never adopts the lost Apply/C23 receiver, changes predecessor bank claims,
//! reissues an effect, or derives authority from a stored receipt. Authorization,
//! current native inventory and final reconciliation remain distinct stages.

pub(in crate::controller_resource_reservation) mod storage;
mod stop_cleanup;
pub use stop_cleanup::OperatorStopCleanupObservationLoanV1;
pub use storage::{OperatorRecoverInventoryLoanV1, OperatorRecoverInventoryDisposalV1,
    OperatorReconciliationInventoryLoanV2, ControllerRecoveryInventoryLoanV2};
mod request;
mod root_inputs;
mod completed_cleanup;
pub use completed_cleanup::{OperatorExecutionNoApplyRecoveryCompletedHandoffV2,
    OperatorStopCleanupRecoveryCompletedHandoffV1};
pub(crate) mod finality;
pub(crate) use request::RequestModelsV1;
mod source;
mod admission;
mod completed_read;
mod reconciliation;
pub use reconciliation::{OperatorReconciliationObservationCustodyV2,
    OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
    OperatorFirstLocalReconciliationCompleteV2, OperatorReconciliationInventoryProofV2,
    OperatorReconciliationObservationEntryRefusalV2, OperatorReconciliationObservationOriginalV2,
    OperatorReconciliationObservationLoanV2, ControllerReconciliationInventoryRoleV2};

mod stopped_predecessor;

pub use stopped_predecessor::OperatorRecoveredStoppedCreateSeedV1;

use std::error::Error;
use std::sync::{Arc, Mutex};

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1;
use aos_sandbox_core::{NodeId, RawPairedClockSample, ResourceDimension as D, ResourceVector};

use super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::cli_model::authorization_adapter::CliAuthorizationAdapterError;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1;
use crate::Journal;

/// Reports a closed or incomplete actual Recover stage.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("original OperatorRecover observation is closed")]
pub struct OperatorCreateRecoveryClosedV1;

#[derive(Clone, Copy)]
enum FirstV1 {
    Native, Funding, Request, Handle, AuthorizationNative, Authorization, AuthorizationReadback, Horizon,
    Clock, Admission, Storage, StopCleanupNonce, StopCleanupObservation, Source, Finality, Body, After, FinalClock, CompletedRead, CompletedHandoff,
}

/// Holds one actual Recover native interval and every entered partial owner.
///
/// Construction is private to the paid command entrance. A cold final record,
/// a request DTO or an interrupted Create receipt cannot construct this owner.
#[doc(hidden)]
#[must_use = "retain the whole Recover attempt through every independently owed post"]
pub struct OperatorCreateRecoveryOriginalV1 {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    runtime: Arc<tokio::runtime::Runtime>,
    native: Result<ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1>,
    fixed: ResourceVector,
    reached: ResourceVector,
    demand: Option<Result<(), ResourceReservationErrorV1>>,
    authorization_native: Option<PublicMutationAuthorizationNativeV1>,
    target: Option<aos_sandbox_core::OperationId>,
    request: Option<Result<request::RequestModelsV1, crate::OperationCompilationError>>,
    handle: Option<Result<aos_sandbox_core::CapabilityId, crate::ControllerServiceError>>,
    floor_entered: bool,
    authorization: Option<Result<PublicMutationAuthorizationV1, CliAuthorizationAdapterError>>,
    authorization_readback: Option<Result<aos_sandbox_protocol::public_api::model::AuthorizationRevisionDigestV1,
        CliAuthorizationAdapterError>>,
    horizon: Option<Result<RecoverHorizonV1, OperatorCreateRecoveryClosedV1>>,
    clock: Option<crate::policy_compiler::provisioning_current::RootContinuationClockGateV1>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    final_clock_native: crate::controller::RetainedControllerProtectedClockAttemptV1,
    final_clock: Option<Result<RawPairedClockSample, crate::JournalError>>,
    final_clock_comparison: Option<Result<(), crate::JournalError>>,
    first: Option<FirstV1>,
    body: Option<Result<(), OperatorCreateRecoveryClosedV1>>,
    storage: storage::OperatorRecoverStorageSessionOriginalV1,
    stop_cleanup_nonce: aos_sandbox_broker::bounded_entropy::RetainedKernelNonceOriginalV1,
    stop_cleanup_observation: stop_cleanup::StopCleanupObservationOriginalV1,
    source: source::SourceObservationV1,
    admission: admission::ObservationAdmissionOriginalV1,
    finality: finality::FinalityOriginalV1,
    completed_read: Option<Box<completed_read::CompletedReadOriginalV1>>,
    completed_read_entry: Option<completed_read::ReadEntryRefusalV1>,
    completed_read_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    cleanup_handoff: completed_cleanup::CompletedHandoffStateV2,
}

// An unpaid entry has reached only the lower financial/native frontier. Keep
// that entire original inline; never allocate the large upper owner on refusal.
pub(crate) enum OperatorRecoverCustodyV2 {
    Entered(Box<OperatorCreateRecoveryOriginalV1>),
    EntryRefused(OperatorRecoverEntryRefusalV2),
}

pub(crate) struct OperatorRecoverEntryRefusalV2 {
    _bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    _profile: Arc<ProductionControllerNormalRootProfileV1>,
    _runtime: Arc<tokio::runtime::Runtime>,
    native: Result<ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1>,
    _fixed: Option<ResourceVector>,
    _reached: ResourceVector,
}

impl OperatorRecoverEntryRefusalV2 {
    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match &self.native {
            Err(cause) => Some(cause),
            Ok(native) => native.failure(),
        }
    }
}

struct RecoverHorizonV1 {
    original: RawPairedClockSample,
    cutoff: u64,
    expires_wall_seconds: i64,
}

impl RecoverHorizonV1 {
    // Bounds only this freshly authorized operation. It never renews an old
    // Apply challenge or supplies effect authority from historical evidence.
    fn from_current_authorization_v1(
        original: RawPairedClockSample,
        expires_wall_seconds: i64,
    ) -> Result<Self, OperatorCreateRecoveryClosedV1> {
        let absolute = original.conservative_expiry_deadline_data_v1(expires_wall_seconds)
            .ok_or(OperatorCreateRecoveryClosedV1)?;
        let fixed = original.boottime_nanoseconds().checked_add(65_000_000_000)
            .ok_or(OperatorCreateRecoveryClosedV1)?;
        Ok(Self { original, cutoff: absolute.min(fixed), expires_wall_seconds })
    }
}

/// Lends only the same authorized Recover receiver and held Controller.
///
/// The cold Storage implementation keeps its own finite persistent progress
/// under this owner. No initial Session slot or Create loan is accepted here.
#[doc(hidden)]
pub struct OperatorCreateRecoveryLoanV1<'owner, 'controller> {
    owner: &'owner mut OperatorCreateRecoveryOriginalV1,
    controller: &'controller Journal,
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Selects the finite purpose from this actual current admitted Recover.
    ///
    /// This comparison DATA selects a concrete driver. Every later Source,
    /// Session, Root grant, clock and native borrower remains independently
    /// required; the tag grants no effect or completed native custody.
    ///
    /// # Errors
    /// Refuses another C/profile, failed or finished native entry, incomplete
    /// authorization or changed protected four-row admission.
    #[doc(hidden)]
    pub fn recovery_purpose_data_v1(&self, controller: &Journal)
        -> Result<aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1,
            ResourceReservationErrorV1> {
        self.require_native_current_v1(controller)?;
        if !matches!(self.authorization, Some(Ok(_)))
            || !matches!(self.authorization_readback, Some(Ok(_)))
            || self.failure_v1().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_observation_current_v1(controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.request.as_ref().and_then(|value| value.as_ref().ok())
            .map(RequestModelsV1::public_recovery_kind_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn begin_native_v1(
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        runtime: Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        reached: ResourceVector,
    ) -> OperatorRecoverCustodyV2 {
        // The same entry pays the heap payload, its constructor/return carrier
        // and compact Journal custody before any upper owner is materialized.
        let fixed = Self::fixed_receiving_demand_v2();
        let native = (|| {
            let complete = fixed.ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(reached)?;
            bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_operator_recover_receiving_v1(controller, &profile, complete)
        })();
        let prepaid = native.as_ref().is_ok_and(|native|
            native.require_prepaid_owed_observation_v1().is_ok());
        if !prepaid {
            return OperatorRecoverCustodyV2::EntryRefused(OperatorRecoverEntryRefusalV2 {
                _bank: bank, _profile: profile, _runtime: runtime, native,
                _fixed: fixed, _reached: reached,
            });
        }
        // Later profile/name failures do not revoke this initial paid receipt.
        // Their complete lower originals and all owed posts stay in this Box.
        OperatorRecoverCustodyV2::Entered(Box::new(Self {
            bank, profile, runtime, native,
            fixed: fixed.unwrap_or(ResourceVector::ZERO), reached, demand: None,
            authorization_native: Some(PublicMutationAuthorizationNativeV1::new()),
            target: None, request: None, handle: None, floor_entered: false,
            authorization: None, authorization_readback: None,
            horizon: None, clock: None, after: None,
            final_clock_native: Default::default(), final_clock: None,
            final_clock_comparison: None, first: None, body: None,
            storage: Default::default(), source: source::SourceObservationV1::new(),
            stop_cleanup_nonce: Default::default(),
            stop_cleanup_observation: Default::default(),
            admission: Default::default(),
            finality: Default::default(),
            completed_read: None, completed_read_entry: None, completed_read_geometry: None,
            cleanup_handoff: Default::default(),
        }))
    }

    fn fixed_receiving_demand_v2() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(aos_sandbox_broker::bounded_entropy::RetainedKernelNonceOriginalV1::construction_bytes_v1()?)?
            .checked_add(std::mem::size_of::<stop_cleanup::StopCleanupObservationReceiptV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<OperatorStopCleanupObservationLoanV1<'static, 'static>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'static>>()
                .checked_mul(3)?)?
            .checked_add(std::mem::size_of::<OperatorStopCleanupRecoveryCompletedHandoffV1<'static>>()
                .checked_mul(3)?)?
            .checked_add(aos_sandbox_protocol::domain_ledger::public_operation::
                metadata_complete_projection_receiving_bytes_v1()?)?
            .checked_add(std::mem::size_of::<Box<Self>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<OperatorRecoverCustodyV2>().checked_mul(2)?)?
            .checked_add(stopped_predecessor::carrier_receiving_bytes_v1()?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    fn require_native_current_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_operator_recover_current_v1(native, controller, &self.profile)
    }

    pub(crate) fn require_complete_v1(&mut self, controller: &Journal, reached: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_native_current_v1(controller)?;
        let complete = self.fixed.checked_add(reached)?;
        let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let result = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_operator_recover_complete_v1(native, controller, &self.profile, complete);
        if result.is_ok() {
            self.reached = reached;
        }
        self.demand = Some(result);
        self.latch_primary_failure_v1();
        match self.demand.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Borrows the actual authorized native interval for the cold Session.
    ///
    /// # Errors
    /// Refuses incomplete authorization, unavailable original expiry, a changed
    /// Controller, any prior failure, or already entered native after posts.
    #[doc(hidden)]
    pub fn borrow_storage_v1<'owner, 'controller>(
        &'owner mut self, controller: &'controller Journal,
    ) -> Result<OperatorCreateRecoveryLoanV1<'owner, 'controller>, ResourceReservationErrorV1> {
        if self.recovery_purpose_data_v1(controller)?
            != aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::MetadataComplete
        { return Err(ResourceReservationErrorV1::Conflict); }
        self.require_native_current_v1(controller)?;
        if !matches!(self.authorization, Some(Ok(_)))
            || !matches!(self.authorization_readback, Some(Ok(_)))
            || !matches!(self.horizon, Some(Ok(_))) || self.failure_v1().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_observation_current_v1(controller).map_err(|_|ResourceReservationErrorV1::Conflict)?;
        Ok(OperatorCreateRecoveryLoanV1 { owner: self, controller })
    }

    /// Runs prearmed C after observations even after a refused body or debit.
    ///
    /// # Errors
    /// Preserves actual entry, lock, independent native post and reentry causes.
    #[doc(hidden)]
    pub fn finish_native_once_v1(&mut self, controller: &mut Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.latch_primary_failure_v1();
        let result = (|| {
            let native = self.native.as_mut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .finish_operator_recover_native_once_v1(native, controller, &self.profile)
        })();
        self.after = Some(result);
        self.latch_primary_failure_v1();
        match self.after.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Borrows the retained refusal without manufacturing a recovered grant.
    #[doc(hidden)]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let selected = self.first.or_else(|| self.primary_source_v1())?;
        match selected {
            FirstV1::CompletedHandoff => self.cleanup_handoff.failure(),
            FirstV1::CompletedRead => self.completed_read.as_deref().and_then(|read| read.failure())
                .or_else(|| self.completed_read_entry.as_ref().and_then(|entry| entry.failure()))
                .or_else(|| self.completed_read_geometry.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FirstV1::Native => self.native.as_ref().err().map(|cause| cause as _)
                .or_else(|| self.native.as_ref().ok().and_then(|native| native.failure())),
            FirstV1::Funding => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Request => self.request.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Handle => self.handle.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::AuthorizationNative => self.authorization_native.as_ref()?.failure(),
            FirstV1::Authorization => self.authorization.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::AuthorizationReadback => self.authorization_readback.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Horizon => self.horizon.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Clock => self.clock.as_ref()?.failure(),
            FirstV1::Admission => self.admission.failure_v1(),
            FirstV1::Storage => self.storage.failure_v1(),
            FirstV1::StopCleanupNonce => self.stop_cleanup_nonce.failure(),
            FirstV1::StopCleanupObservation => self.stop_cleanup_observation.failure(),
            FirstV1::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Source => self.source.failure(),
            FirstV1::Finality => self.finality.failure(),
            FirstV1::After => self.after.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::FinalClock => self.final_clock_native.failure()
                .or_else(|| self.final_clock.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.final_clock_comparison.as_ref()?.as_ref().err().map(|cause| cause as _)),
        }
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    fn primary_source_v1(&self) -> Option<FirstV1> {
        if self.completed_read.as_deref().is_some_and(|read| read.failure().is_some())
            || self.completed_read_entry.as_ref().is_some_and(|entry| entry.failure().is_some())
            || matches!(self.completed_read_geometry, Some(Err(_))) {
            return Some(FirstV1::CompletedRead);
        }
        if self.native.is_err() || self.native.as_ref().is_ok_and(|native| native.failure().is_some()) { return Some(FirstV1::Native); }
        if matches!(self.demand, Some(Err(_))) { return Some(FirstV1::Funding); }
        if matches!(self.request, Some(Err(_))) { return Some(FirstV1::Request); }
        if matches!(self.handle, Some(Err(_))) { return Some(FirstV1::Handle); }
        if self.authorization_native.as_ref().is_some_and(|native| native.failure().is_some()) { return Some(FirstV1::AuthorizationNative); }
        if matches!(self.authorization, Some(Err(_))) { return Some(FirstV1::Authorization); }
        if matches!(self.authorization_readback, Some(Err(_))) { return Some(FirstV1::AuthorizationReadback); }
        if matches!(self.horizon, Some(Err(_))) { return Some(FirstV1::Horizon); }
        if self.clock.as_ref().is_some_and(|clock| clock.failure().is_some()) { return Some(FirstV1::Clock); }
        if self.admission.failure_v1().is_some() { return Some(FirstV1::Admission); }
        if self.storage.failure_v1().is_some() { return Some(FirstV1::Storage); }
        if self.stop_cleanup_nonce.failure().is_some() { return Some(FirstV1::StopCleanupNonce); }
        if self.stop_cleanup_observation.failure().is_some() { return Some(FirstV1::StopCleanupObservation); }
        if self.source.failure().is_some() { return Some(FirstV1::Source); }
        if self.finality.failure().is_some() { return Some(FirstV1::Finality); }
        if matches!(self.body, Some(Err(_))) { return Some(FirstV1::Body); }
        if matches!(self.after, Some(Err(_))) { return Some(FirstV1::After); }
        if self.final_clock_native.failure().is_some()
            || matches!(self.final_clock, Some(Err(_)))
            || matches!(self.final_clock_comparison, Some(Err(_))) { return Some(FirstV1::FinalClock); }
        if self.cleanup_handoff.failure().is_some() { return Some(FirstV1::CompletedHandoff); }
        None
    }

    fn latch_primary_failure_v1(&mut self) {
        if self.first.is_none() { self.first = self.primary_source_v1(); }
    }
}

impl OperatorCreateRecoveryLoanV1<'_, '_> {
    /// Rejoins the same active successor, C writer and authorization attempt.
    ///
    /// # Errors
    /// Refuses changed or failed original custody and incomplete authorization.
    pub fn require_current_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_native_current_v1(self.controller)?;
        if !matches!(self.owner.authorization, Some(Ok(_)))
            || !matches!(self.owner.authorization_readback, Some(Ok(_)))
            || self.owner.failure_v1().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.require_observation_current_v1(self.controller)
            .map_err(|_|ResourceReservationErrorV1::Conflict)?;
        Ok(())
    }

    /// Pays cumulative reached Session representation before further growth.
    ///
    /// The input includes all retained Recover models and actual traffic; the
    /// fixed owning header is joined by the original, never supplied as a grant.
    ///
    /// # Errors
    /// Retains arithmetic, capacity and same-original currentness refusals.
    pub fn require_complete_v1(&mut self, complete: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_current_v1()?;
        self.owner.require_complete_v1(self.controller, complete)
    }

    /// Adds an actual additional resident plane and its reached traffic.
    ///
    /// # Errors
    /// Retains arithmetic, capacity and same-original currentness refusal.
    pub fn reserve_additional_v1(&mut self, additional: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        let complete = self.owner.reached.checked_add(additional)?;
        self.require_complete_v1(complete)
    }

    /// Checks the same protected horizon before the next native frontier.
    ///
    /// # Errors
    /// Retains native clock, provenance, boot, cutoff or wall-expiry refusal.
    pub fn check_frontier_v1(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        let result = self.owner.clock.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .check_next_once_v1().map_err(ResourceReservationErrorV1::Journal);
        self.owner.latch_primary_failure_v1();
        result
    }

    /// Observes an already paid paired after despite an earlier stage refusal.
    ///
    /// The enclosing concrete SDK destination enforces once-only entry. This
    /// port performs no native-finance admission and cannot begin another body.
    ///
    /// # Errors
    /// Retains the same clock, provenance, boot, deadline or wall-expiry refusal.
    #[doc(hidden)]
    pub fn observe_owed_clock_after_once_v1(&mut self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1>
    {
        self.owner.latch_primary_failure_v1();
        self.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .require_prepaid_owed_observation_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let result = self.owner.clock.as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .check_next_once_v1().map_err(ResourceReservationErrorV1::Journal);
        self.owner.latch_primary_failure_v1();
        result
    }

    /// Returns the real enrolled node as comparison DATA.
    ///
    /// # Errors
    /// Refuses changed enrollment or unavailable actual Bank custody.
    pub fn node_v1(&self) -> Result<NodeId, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .operator_recover_node_v1(self.controller, &self.owner.profile)
    }

    /// Returns the original protected authorization deadline without renewal.
    ///
    /// # Errors
    /// Refuses missing or failed protected horizon derivation.
    pub fn original_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.owner.horizon.as_ref().and_then(|value| value.as_ref().ok())
            .map(|horizon| horizon.cutoff).ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the same retained measured profile.
    pub fn profile_v1(&self) -> &Arc<ProductionControllerNormalRootProfileV1> {
        &self.owner.profile
    }

    /// Borrows the startup's existing runtime, without creating another worker.
    pub fn runtime_v1(&self) -> &Arc<tokio::runtime::Runtime> {
        &self.owner.runtime
    }

    /// Borrows the actual original refusal.
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure_v1()
    }
}


impl OperatorCreateRecoveryOriginalV1 {
    pub(crate) fn prepare_floor_once_v1(&mut self, controller: &Journal,
        transaction: &crate::JournalTransaction,
        recipe: &crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), crate::JournalError> {
        if let Some(read) = self.completed_read.as_deref_mut() {
            let result = (|| {
                read.require_current(&self.bank, &self.profile, controller)
                    .map_err(|_| crate::JournalError::ProtectedBoundary)?;
                read.prepare_floor_v1(controller, transaction, recipe)?;
                read.funding = Some(match self.bank.lock() {
                    Ok(bank) => bank.require_operator_recover_complete_v1(
                        read.native.as_mut().map_err(|_| crate::JournalError::ProtectedBoundary)?,
                        controller, &self.profile, read.reached,
                    ),
                    Err(_) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
                });
                if !matches!(read.funding, Some(Ok(()))) {
                    return Err(crate::JournalError::ProtectedBoundary);
                }
                Ok(())
            })();
            read.latch();
            self.latch_primary_failure_v1();
            return result;
        }
        if self.floor_entered || self.target.is_none() || self.authorization.is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.require_native_current_v1(controller)
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        recipe.require_exact_v1(transaction)?;
        let native = controller.append_receiving_demand_v1(transaction.records().iter().map(|record|
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
            })).map_err(|_| crate::JournalError::ProtectedBoundary)?;
        let semantic = controller.create_storage_semantic_append_demand_v1()?;
        let reached = self.reached.checked_add(native)
            .and_then(|demand| demand.checked_add(semantic))
            .map_err(crate::JournalError::ReceivingAccounting)?;
        self.require_complete_v1(controller, reached)
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        self.floor_entered = true;
        Ok(())
    }

    pub(crate) fn require_floor_transition_v1(&self, controller: &Journal)
        -> Result<(), crate::JournalError> {
        if let Some(read) = self.completed_read.as_deref() {
            read.require_current(&self.bank, &self.profile, controller)
                .map_err(|_| crate::JournalError::ProtectedBoundary)?;
            return read.require_floor_transition_v1(controller);
        }
        if !self.floor_entered || self.target.is_none() || self.authorization.is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.require_native_current_v1(controller)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn matches_identity_v1(&self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool {
        self.target == Some(identity.operation())
    }
}


impl OperatorCreateRecoveryOriginalV1 {
    /// Samples the paid original horizon after all reached native after posts.
    ///
    /// No healthy financial or semantic gate suppresses this independent clock
    /// destination after an entered body or native after has refused.
    pub(crate) fn finish_final_clock_once_v1(&mut self) {
        self.latch_primary_failure_v1();
        if self.final_clock.is_none() {
            // This actual admission receipt survives later poison, while a
            // failed first debit cannot create an unpriced native observation.
            let paid = self.native.as_ref().is_ok_and(|native|
                native.require_prepaid_owed_observation_v1().is_ok());
            self.final_clock = Some(if paid {
                self.final_clock_native.observe_once_v1()
            } else {
                Err(crate::JournalError::ProtectedBoundary)
            });
            if let Some(Ok(sample)) = self.final_clock.as_ref() {
                self.final_clock_comparison = Some(self.clock.as_ref()
                    .ok_or(crate::JournalError::ProtectedBoundary)
                    .and_then(|clock| clock.require_final_sample_v1(*sample)));
            }
        }
        self.latch_primary_failure_v1();
    }

    pub(crate) fn retain_observation_result_v1(&mut self,
        result: Result<(), OperatorCreateRecoveryClosedV1>,
    ) {
        if self.body.is_none() { self.body = Some(result); }
        self.latch_primary_failure_v1();
    }
}

#[cfg(test)]
mod custody_layout_tests {
    use super::*;

    #[test]
    fn ordinary_journal_keeps_only_optional_recover_custody_not_its_payload() {
        assert!(std::mem::size_of::<Option<OperatorRecoverCustodyV2>>()
            < std::mem::size_of::<OperatorCreateRecoveryOriginalV1>());
        assert!(std::mem::size_of::<Journal>()
            < std::mem::size_of::<OperatorCreateRecoveryOriginalV1>());

        let fixed = OperatorCreateRecoveryOriginalV1::fixed_receiving_demand_v2().unwrap();
        let paid = usize::try_from(fixed.get(D::MemoryBytes)).unwrap();
        let ordinary_carriers = 2 * std::mem::size_of::<OperatorCreateRecoveryOriginalV1>()
            + 2 * std::mem::size_of::<Box<OperatorCreateRecoveryOriginalV1>>()
            + 2 * std::mem::size_of::<OperatorRecoverCustodyV2>();

        // The bounded nonce's native result slots and the Host comparison/loan
        // carriers are paid before their first materialization as well.
        let cleanup_nonce = aos_sandbox_broker::bounded_entropy::RetainedKernelNonceOriginalV1::
            construction_bytes_v1().unwrap();
        let cleanup_observation = 3 * std::mem::size_of::<stop_cleanup::StopCleanupObservationReceiptV1>();
        let cleanup_loan = 3 * std::mem::size_of::<OperatorStopCleanupObservationLoanV1<'static, 'static>>();

        // Fresh cleanup handoffs and the public metadata projection remain
        // prepaid even though the ordinary Journal stores only small custody.
        let execution_handoff = 3 * std::mem::size_of::<OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'static>>();
        let stop_handoff = 3 * std::mem::size_of::<OperatorStopCleanupRecoveryCompletedHandoffV1<'static>>();
        let metadata_projection = aos_sandbox_protocol::domain_ledger::public_operation::
            metadata_complete_projection_receiving_bytes_v1().unwrap();
        let stopped_predecessor = stopped_predecessor::carrier_receiving_bytes_v1().unwrap();
        let complete = ordinary_carriers + cleanup_nonce + cleanup_observation + cleanup_loan
            + execution_handoff + stop_handoff + metadata_projection + stopped_predecessor;
        assert_eq!(paid, complete);
    }
}
