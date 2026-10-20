//! Retains the genuine public Stop entry on the Controller baseline ledger.
//!
//! Native receiving is purpose-closed and pays the complete accepted graph
//! before decoding it. Successful selection supplies comparison DATA only;
//! Source mutation, signed Host dispatch and terminal residual emission each
//! require their actual later native turn and exact semantic borrowers.

pub(crate) mod source;
mod host;
mod inventory;
mod recovered_seed;
mod cleanup;
pub use cleanup::ControllerHostStopCleanupSourceLoanV1;
pub use cleanup::{StopCleanupCompletionErrorV1, StopCleanupCompletionOriginalV1};
pub use cleanup::StopCleanupSourceAppendOriginalV1;
pub(crate) use cleanup::StopCleanupSourceAppendAuthorizationV1;
pub(crate) use cleanup::StopCleanupControllerAppendContextV1;
pub use cleanup::{ControllerHostStopCleanupCompletionV1, ControllerHostStopCleanupPendingDisposalV1,
    ControllerHostStopCleanupPositiveDisposalV1};
pub(crate) mod terminal;

use std::error::Error;
use std::sync::{Arc, Mutex};

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
use aos_sandbox_core::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;

use crate::controller_resource_reservation::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::{Journal, ReconcilerError};

type Result<T> = std::result::Result<T, ResourceReservationErrorV1>;

#[derive(Clone, Copy)]
enum First { Geometry, Native, Context, After, RecoveredSeed, Reentry }

/// Owns the actual accepted Stop graph and its paid native entry/post results.
///
/// Construction performs no IO. Every reached error remains in this value;
/// neither its context DATA nor completed native receiving grants an effect.
#[must_use]
pub struct ControllerLifecycleStopOriginalV4 {
    operation: OperationId,
    recovered_seed: recovered_seed::RecoveredStopSeedOriginalV3,
    cleanup: Option<Box<cleanup::StopCleanupOriginalV1>>,
    retained_stop_intake: Option<crate::controller_resource_reservation::ControllerOperationIntakeOriginalV1>,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    entered: bool,
    geometry: Option<Result<ResourceVector>>,
    native: Option<Result<ControllerCreateProvisioningReceivingV1>>,
    accepted: Option<std::result::Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    after: Option<Result<()>>,
    first: Option<First>,
    source_turns: [source::StopSourceTurnSlotV4; 6],
    source_preparation: Option<Result<()>>,
    source_resident: Option<ResourceVector>,
    host_turn: source::StopSourceTurnOriginalV4,
    inventory: inventory::StopInventoryChallengeOriginalV5,
    host_entry: Option<Result<()>>,
    host_fixed: Option<Result<()>>,
    host_fee: Option<Result<()>>,
    inventory_fee: Option<Result<()>>,
    host_fee_original: bool,
    host_finish: Option<Result<()>>,
    host_first: Option<host::HostFirstV4>,
    host_models: Option<Result<ResourceVector>>,
    host_complete: Option<ResourceVector>,
    residual_turn: source::StopSourceTurnOriginalV4,
    residual_observation: Option<std::result::Result<crate::lifecycle::LifecycleEffectObservationV1,
        crate::lifecycle::LifecyclePhase6ErrorV1>>,
    residual_result: Option<Result<()>>,
    residual_record: Option<crate::lifecycle::LifecycleRecordDigestV1>,
    residual_complete: Option<ResourceVector>,
    terminal: terminal::StopControllerTerminalOriginalV4,
    host_authority: crate::lifecycle_authority::RuntimeStopAuthorityOriginalV4,
    host_authority_entry: Option<Result<()>>,
    closed: ResourceReservationErrorV1,
}

impl ControllerLifecycleStopOriginalV4 {
    /// Returns the six ordinary Source destinations' full inactive liability.
    ///
    /// The memory includes each backing, returned value, constructor staging,
    /// and allocation-layout carrier. Small handles are already part of this
    /// original's compiled layout.
    /// Source-bearing startup and both actual Source-successor issuance paths
    /// prepay this supplier before constructing their resident owners. Empty
    /// NoRoot/NoNix startup retains its ordinary allocation policy and gains
    /// no Source authority; these six destinations remain unallocated there.
    /// Each ordinary Source turn also pays its existing fixed demand through
    /// the genuine native entry before allocation.
    /// Cleanup leaves these destinations unallocated and never enters them.
    /// No namespace metadata is created by the destination allocations.
    #[must_use]
    pub fn inactive_receiving_footprint_v4() -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<source::StopSourceTurnOriginalV4>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<std::alloc::Layout>())?
            .checked_mul(6)?;
        Some((bytes, 0))
    }

    // Role geometry keeps the old two-copy destination plane and the added
    // Box construction staging even though the inactive header is smaller.
    // It is distinct from startup's resident precharge and cannot be replaced
    // by a later effect debit.
    fn inactive_receiving_demand_v4() -> Result<ResourceVector> {
        let (bytes, _) = Self::inactive_receiving_footprint_v4()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Constructs inert destinations from the actual retained Bank/profile.
    #[must_use]
    pub fn new_v4(operation: OperationId, bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>) -> Self {
        Self { operation, recovered_seed: Default::default(), cleanup: None, retained_stop_intake: None, bank, profile, entered: false, geometry: None, native: None,
            accepted: None, after: None, first: None,
            source_turns: [
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::Admission),
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::BindPlan),
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::InitialProgress),
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::SemanticReadiness),
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::SemanticCommit),
                source::StopSourceTurnSlotV4::new(source::StopSourcePurposeV4::Completing),
            ],
            source_preparation: None, source_resident: None,
            host_turn: source::StopSourceTurnOriginalV4::new(source::StopSourcePurposeV4::HostDispatch),
            inventory: Default::default(),
            host_entry: None, host_fixed: None, host_fee: None, inventory_fee: None, host_fee_original: false, host_finish: None, host_first: None, host_models: None, host_complete: None,
            residual_turn: source::StopSourceTurnOriginalV4::new(source::StopSourcePurposeV4::Residual),
            residual_observation: None, residual_result: None, residual_record: None, residual_complete: None, terminal: terminal::StopControllerTerminalOriginalV4::new(),
            host_authority: crate::lifecycle_authority::RuntimeStopAuthorityOriginalV4::new(),
            host_authority_entry: None, closed: ResourceReservationErrorV1::Conflict }
    }

    /// Pays and retains the exact accepted public Stop before any Source use.
    ///
    /// The actual Runtime header is a concrete layout cost input, never a
    /// receiving purpose or capacity. This same original remains occupied on
    /// refusal. Its native after is attempted independently after every actual
    /// native entry, including accepted-graph refusal.
    ///
    /// # Errors
    /// Retains repeated entry, geometry, original/native, graph or post failure.
    pub fn prepare_accepted_once_v4<T: Sized>(&mut self, controller: &mut Journal) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        self.geometry = Some((|| {
            let models = crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(controller)?;
            let bytes = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<T>().checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(models))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .checked_add(Self::inactive_receiving_demand_v4()?)?)
        })());
        let Some(complete) = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() else {
            self.first = Some(First::Geometry);
            return Err(ResourceReservationErrorV1::Conflict);
        };

        self.native = Some((|| {
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .begin_lifecycle_stop_native_v4(controller, self.profile.as_ref(), complete)
        })());
        if self.native.as_ref().and_then(|value| value.as_ref().ok())
            .is_none_or(|native| native.failure().is_some()) {
            self.first.get_or_insert(First::Native);
        } else {
            self.accepted = Some(crate::reconciler::accepted_stop_effect_from_journal_v4(
                controller, self.operation));
            if !matches!(self.accepted, Some(Ok(Some(_)))) {
                self.first.get_or_insert(First::Context);
            }
        }

        if let Some(native) = self.native.as_mut().and_then(|value| value.as_mut().ok()) {
            self.after = Some((|| {
                self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .finish_lifecycle_stop_native_once_v4(native, controller, self.profile.as_ref())
            })());
            if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        }
        if self.first.is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

    /// Prepares the one accepted Stop's complete ordinary Source cursor.
    ///
    /// Each closed metadata phase pays a distinct native interval and retains
    /// its exact append/readback result. This method never dispatches Host or
    /// exposes a terminal result from the prepared cursor.
    ///
    /// # Errors
    /// Retains reentry, missing accepted Stop, financial/native, Source schema,
    /// exact CAS, independent post or physical positive-disposal refusal.
    pub fn prepare_source_metadata_once_v4(
        &mut self,
        controller: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.source_preparation.is_some() || self.accepted_context_v4().is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source_preparation = Some((|| {
            let mut resident = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            for turn in &mut self.source_turns {
                turn.run_once_v4(self.operation, &self.bank, self.profile.as_ref(),
                    native, resident, controller, source)?;
                let bytes = u64::try_from(turn.resident_bytes_v4()?)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                resident = resident.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
                self.source_resident = Some(resident);
            }
            Ok(())
        })());
        if matches!(self.source_preparation, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Borrows the fully selected pending Stop context as inert DATA.
    #[must_use]
    pub fn accepted_context_v4(&self) -> Option<&PublicMutationEffectHistoryV1> {
        if self.first.is_some() || !matches!(self.after, Some(Ok(()))) { return None; }
        self.accepted.as_ref()?.as_ref().ok()?.as_ref()
    }

    /// Returns the retained earliest native or semantic cause by reference.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        if self.first.is_none() {
            if let Some(native) = self.native.as_ref().and_then(|result| result.as_ref().ok()) {
                for turn in &self.source_turns {
                    if let Some(cause) = turn.failure_v4(native) { return Some(cause); }
                }
                if let Some(cause) = self.inventory.failure() { return Some(cause); }
                if let Some(cause) = self.residual_turn.failure_v4(native) { return Some(cause); }
                if let Some(cause) = self.terminal.failure_v4(native) { return Some(cause); }
                if let Some(Err(cause)) = self.residual_observation.as_ref() { return Some(cause); }
                if let Some(first) = self.host_first {
                    return match first {
                        host::HostFirstV4::Entry | host::HostFirstV4::After | host::HostFirstV4::Dispatch =>
                            self.host_turn.failure_v4(native).or_else(||
                                self.host_entry.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
                                .or_else(|| self.host_finish.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)),
                        host::HostFirstV4::Fee => {
                            if self.host_fee_original {
                                native.failure().or_else(|| self.host_fee.as_ref()?.as_ref().err().map(|e| e as _))
                            } else {
                                self.host_models.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
                                    .or_else(|| self.host_fixed.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
                                    .or_else(|| self.host_fee.as_ref()?.as_ref().err().map(|e| e as _))
                            }
                        }
                        host::HostFirstV4::InventoryFee => {
                            if self.host_fee_original { native.failure().or_else(|| self.inventory_fee.as_ref()?.as_ref().err().map(|e| e as _)) }
                            else { self.inventory_fee.as_ref()?.as_ref().err().map(|e| e as _) }
                        }
                        host::HostFirstV4::Authority => self.host_authority.failure_v4()
                            .or_else(|| self.host_authority_entry.as_ref()?.as_ref().err().map(|e| e as _)),
                    };
                }

            }
            return self.source_preparation.as_ref().and_then(|result| result.as_ref().err())
                .or_else(|| self.host_entry.as_ref().and_then(|result| result.as_ref().err()))
                .or_else(|| self.host_fee.as_ref().and_then(|result| result.as_ref().err()))
                .or_else(|| self.host_finish.as_ref().and_then(|result| result.as_ref().err()))
                .map(|cause| cause as _);
        }
        match self.first? {
            First::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Native => match self.native.as_ref()? {
                Err(cause) => Some(cause),
                Ok(native) => native.failure(),
            },
            First::Context => self.accepted.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn Error + 'static)).or(Some(&self.closed)),
            First::After => self.native.as_ref().and_then(|value| value.as_ref().ok())
                .and_then(|native| native.failure())
                .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::RecoveredSeed => self.recovered_seed.failure(self.native.as_ref().and_then(|value| value.as_ref().ok()))
                .or_else(|| self.native.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static)))
                .or(Some(&self.closed)),
            First::Reentry => Some(&self.closed),
        }
    }
}

impl ControllerLifecycleStopOriginalV4 {
    /// Parks the actual previously paid recovered Stop original for a new turn.
    ///
    /// # Errors
    /// Refuses a previously entered or already occupied upper owner.
    pub fn retain_recovered_stop_intake_once_v6(&mut self,
        intake: aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeOriginalV1,
    ) -> std::result::Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeOriginalV1> {
        if self.entered || self.retained_stop_intake.is_some() { return Err(intake); }
        self.retained_stop_intake = Some(intake);
        Ok(())
    }

    /// Moves the paid recovered original after the genuine healthy terminal.
    ///
    /// # Errors
    /// Refuses incomplete SDK/Source/C terminal, native afters or seed binding.
    pub fn take_healthy_recovered_stop_intake_once_v6(&mut self, controller: &Journal)
        -> Result<Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeOriginalV1>> {
        self.require_healthy_stop_disposal_v5(controller)?;
        let native = self.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .take_completed_recovered_stop_intake_v3(native, controller, self.profile.as_ref())
    }
}
