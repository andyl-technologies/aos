//! Joins declared operation intake to the same Controller writer and launch.
//!
//! Only the paired fixed writer can claim the two image-selected purposes.
//! The purpose's original C retains the permanent reservation and consumed
//! operation. Its upper semantic owner must authenticate the accepted record
//! and retain its own input, result, effect and uncertainty owners. Native
//! completion proves neither acceptance nor Delete or execution authority.

use std::error::Error;
use std::sync::{Arc, MutexGuard};

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank as bank;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::controller_receiving::operation_intake::{
    ControllerOperationIntakesV1, OperationIntakeFundingV2, OperationIntakePurposeV1,
};
use crate::controller_receiving::{ControllerOriginalObservationV1, ControllerReceivingOriginalV1};
use crate::controller_receiving::profile::ControllerSelfProfileOriginalV1;

use super::coordinator::ControllerCoordinatorWriterV1;
use super::identity::ControllerWriterIdentityV1;
use super::launch::ControllerBankLaunchOriginalV1;
use super::writer::ControllerWriterNameSampleV1;
use super::ControllerBankLaunchErrorV1;

mod cold_session;
pub(crate) use cold_session::ControllerExecutionColdSessionBudgetV2;
pub use cold_session::ControllerExecutionColdSessionRetentionV2;

/// Reports only the intrinsic funding branch of a retained native owner.
///
/// This DATA selects a private guard; it grants no readiness or entry. The
/// recovered guard still requires the actual opaque completed association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerOperationIntakeFundingKindDataV2 {
    /// Selects the unchanged initial first-use and reserved-claim guard.
    InitialReservedClaim,
    /// Selects the recovered same-baseline/durable-row/enrollment guard.
    RecoveredBaseline,
}

/// Describes reached upper resident or flight demand without creating payment.
///
/// The genuine purpose owner admits all22 dimensions before upper construction
/// or native work. This DATA cannot construct that owner or select a purpose.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerOperationIntakeDemandDataV1 {
    demand: ResourceVector,
}

impl ControllerOperationIntakeDemandDataV1 {
    /// Returns this passive representation requirement, without admitting work.
    #[must_use]
    pub const fn demand_v1(&self) -> ResourceVector { self.demand }

    /// Carries one actual upper supplier's complete passive requirement.
    #[must_use]
    pub const fn from_demand_v1(demand: ResourceVector) -> Self { Self { demand } }

    /// Prices Delete capacity with its same-C exclusive Source scope reserved.
    ///
    /// This passive requirement uses the exact same resident supplier as the
    /// actual Delete claim. Execution keeps its distinct existing requirement.
    ///
    /// # Errors
    /// Refuses when the configured declaration cannot cover the actual upper,
    /// native C bookends and Source scope before any allocation or native IO.
    pub fn from_declared_delete_remaining_v1(
        declared: ResourceVector,
        upper_resident: Self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        Ok(Self { demand: checked_upper_capacity_v1(
            declared, upper_resident.demand,
            ControllerOperationIntakeOriginalV1::native_source_resident_demand_v1(OperationIntakePurposeV1::Delete)?,
            ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?,
        )? })
    }

    /// Prices upper flight capacity after the same native resident/flight costs.
    ///
    /// All inputs and the result are DATA. The actual fixed C factory still
    /// checks its own canonical claim, original, launch and profile; a supplied
    /// vector cannot authorize construction or reserve another account.
    ///
    /// # Errors
    /// Preserves checked arithmetic refusal when the declared amount cannot
    /// cover upper resident demand and the actual native owners and bookends.
    pub fn from_declared_remaining_v1(
        declared: ResourceVector,
        upper_resident: Self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        let native_resident = ControllerOperationIntakeOriginalV1::native_source_resident_demand_v1(OperationIntakePurposeV1::Execution)?;
        let native_flight = ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?;
        Ok(Self { demand: checked_upper_capacity_v1(
            declared, upper_resident.demand, native_resident, native_flight,
        )? })
    }

}

#[derive(Clone, Copy)]
enum First {
    Arm,
    NamesBefore,
    OriginalBefore,
    NamesAfter,
    OriginalAfter,
    Launch,
    CompleteRequirement,
    PreacceptPreparation,
    Financial,
}

// Keeps the native owner's entry chronology independent of its paid native
// samples. In particular, a refused slot debit must become sticky before the
// caller can recompute a larger complete requirement on a later entry.
struct OperationIntakeEntryV1 {
    first: Option<First>,
    whole_required: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    preaccept_preparation: Option<ControllerBankLaunchErrorV1>,
}

impl OperationIntakeEntryV1 {
    const fn new() -> Self {
        Self { first: None, whole_required: None, preaccept_preparation: None }
    }

    fn prepare_whole_requirement_v1(
        &mut self,
        capacity: ResourceVector,
        initial: ResourceVector,
        native: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.whole_required = Some(initial.checked_add(native)
            .and_then(|required| capacity.checked_sub(required).map(|_| required)));
        if self.whole_required.as_ref().is_none_or(|result| result.is_err()) {
            self.first = Some(First::CompleteRequirement);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    fn begin_slot_once_v1(
        &mut self,
        slot: &mut crate::controller_receiving::operation_intake::OperationIntakeSlotV1,
        required: ResourceVector,
        prepaid_traffic: Option<ResourceVector>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let begun = match prepaid_traffic {
            Some(traffic) => slot.begin_with_traffic_v1(required, traffic),
            None => slot.begin_once(required),
        };
        if let Err(cause) = begun {
            // The actual cause stays in the same guarded slot. Do not set
            // active: no native/profile sample or independently owed post began.
            self.first = Some(First::Financial);
            return Err(cause.into());
        }
        Ok(())
    }

    fn retire_positive_v1(&mut self) {
        self.whole_required = None;
        self.preaccept_preparation = None;
    }
}

/// Retains one declared purpose's intrinsic original and whole native attempts.
///
/// This type has no public constructor, budget accessor, purpose selector or
/// writer factory. Only the same fixed Bank/launch join can issue it. It is
/// deliberately non-Clone: its actual reserved purpose is claimed once.
#[must_use]
pub struct ControllerOperationIntakeOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    purpose: OperationIntakePurposeV1,
    funding: OperationIntakeFundingV2,
    recovered_enrollment: Option<super::create_provisioning::RecoveredEnrollmentAssociationV1>,
    recovered_cleanup: Option<super::create_provisioning::RecoveredStopCleanupAssociationOriginalV1>,
    before: ControllerOriginalObservationV1,
    after: ControllerOriginalObservationV1,
    names_before: ControllerWriterNameSampleV1,
    names_after: ControllerWriterNameSampleV1,
    arm: Option<Result<(), ControllerBankLaunchErrorV1>>,
    names_before_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    before_result: Option<Result<crate::receiving::OriginalEnrollment, crate::controller_receiving::ControllerReceivingErrorV1>>,
    names_after_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    after_result: Option<Result<crate::receiving::OriginalEnrollment, crate::controller_receiving::ControllerReceivingErrorV1>>,
    launch_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    entry: OperationIntakeEntryV1,
    active: bool,
    delete_source_scope_open: bool,
    whole_capacity: ResourceVector,
    whole_declared: bool,
    execution_admission_parked: bool,
}

/// Borrows the actual purpose, same writer, launch and profile through its posts.
#[must_use]
pub struct ControllerOperationIntakeReceivingLoanV1<'owner> {
    owner: &'owner mut ControllerOperationIntakeOriginalV1,
    finished: bool,
    delete_source_scope_entered: bool,
    execution_admission_handoff: bool,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Claims only the image-declared Delete subdivision of this same C.
    ///
    /// # Errors
    /// Refuses absent declaration, foreign profile/launch, missing actual claim,
    /// changed writer or insufficient complete resident/flight capacity.
    pub fn claim_delete_operation_intake_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        self.claim_operation_intake_once(launch, profile, OperationIntakePurposeV1::Delete,
            resident, flight_capacity)
    }

    /// Claims only the image-declared accepted-execution subdivision of this C.
    ///
    /// # Errors
    /// Refuses absent declaration, foreign profile/launch, missing actual claim,
    /// changed writer or insufficient complete resident/flight capacity.
    pub fn claim_execution_operation_intake_once_v1(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        self.claim_operation_intake_once(launch, profile, OperationIntakePurposeV1::Execution,
            resident, flight_capacity)
    }

    /// Permanently funds a fresh Delete intake from this successor's remaining B.
    ///
    /// The completed Recover original and current successor must belong to this
    /// exact C/profile. Old reserved Delete claims are neither read nor reused.
    /// The image declaration is only a maximum; remaining R can refuse entry.
    ///
    /// # Errors
    /// Refuses incomplete Recover, foreign/currentness mismatches, reused slots,
    /// undeclared or excessive capacity, or any permanent baseline debit failure.
    pub fn fund_recovered_delete_operation_intake_once_v2(
        &mut self, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        completed: &super::create_provisioning::ControllerOperatorRecoverReceivingV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        self.fund_recovered_operation_intake_once_v2(launch, profile, completed,
            OperationIntakePurposeV1::Delete, resident, flight_capacity)
    }

    /// Permanently funds a fresh Execution intake on this same recovered baseline.
    ///
    /// No predecessor claim, account, spent traffic or owner highwater is reset.
    /// Upper completion and accepted-operation checks remain separate obligations.
    ///
    /// # Errors
    /// Refuses incomplete Recover, a foreign successor/profile, a reused slot,
    /// excessive declaration or insufficient actual remaining baseline capacity.
    pub fn fund_recovered_execution_operation_intake_once_v2(
        &mut self, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        completed: &super::create_provisioning::ControllerOperatorRecoverReceivingV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        self.fund_recovered_operation_intake_once_v2(launch, profile, completed,
            OperationIntakePurposeV1::Execution, resident, flight_capacity)
    }

    /// Returns remaining arithmetic DATA after the genuine completed Recover join.
    ///
    /// The quote reserves nothing. Each named funding entrance recomputes all
    /// currentness and complete-demand checks against the same original ledger.
    ///
    /// # Errors
    /// Refuses incomplete or foreign Recover/current successor/profile custody.
    pub fn recovered_operation_intake_remaining_data_v2(
        &self, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        completed: &super::create_provisioning::ControllerOperatorRecoverReceivingV1,
    ) -> Result<ControllerOperationIntakeDemandDataV1, ControllerBankLaunchErrorV1> {
        completed.require_completed_original_v1(self, launch, profile)?;
        launch.require_operator_recover_current_v1(self)?;
        Ok(ControllerOperationIntakeDemandDataV1::from_demand_v1(
            self.fixed.original().recovered_operation_remaining_data_v2(profile)?,
        ))
    }

    fn fund_recovered_operation_intake_once_v2(
        &mut self, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        completed: &super::create_provisioning::ControllerOperatorRecoverReceivingV1,
        purpose: OperationIntakePurposeV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        let original = self.fixed.original();
        original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(purpose).require_vacant_recovered_v2()?;
        let mut preparation = FailedBeginGuardV1 { original, purpose, completed: false };
        completed.require_completed_original_v1(self, launch, profile)?;
        launch.require_operator_recover_current_v1(self)?;
        let resident = resident.demand.checked_add(
            ControllerOperationIntakeOriginalV1::native_source_resident_demand_v1(purpose)?,
        )?;
        let flight_capacity = flight_capacity.demand.checked_add(
            ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?,
        )?;
        let complete = resident.checked_add(flight_capacity)?;
        let funded = original.fund_recovered_operation_intake_v2(profile, purpose, complete,
            self.next_sequence(), self.durable_prefix_end_data_v1());
        let funding = original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(purpose).bind_recovered_once_v2(purpose, funded, resident, flight_capacity)?;
        // Actual pool allocation follows the complete permanent debit, using
        // exactly the same slot/profile mechanism as initial reserved funding.
        profile.prepare_operation_intake_pool_once_v1(original, purpose)?;
        preparation.completed = true;
        drop(preparation);
        Ok(ControllerOperationIntakeOriginalV1::new_funded_v2(
            Arc::clone(original), Arc::clone(self.fixed.identity()), purpose, funding, flight_capacity,
        ))
    }

    fn claim_operation_intake_once(
        &mut self,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: OperationIntakePurposeV1,
        resident: ControllerOperationIntakeDemandDataV1,
        flight_capacity: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        // A successor recipient cannot reconstruct lost boot-original D/X
        // custody from its still-Reserved history. Actual transfer/recovery of
        // those live/failed owners needs its own closed protocol first.
        if !launch.is_initial_enrollment() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let original = self.fixed.original();
        let observed = original.operation_intake_enrollment_v1(profile)?;
        launch.require_current_controller_v1(self)?;
        let claim = match purpose {
            OperationIntakePurposeV1::Delete => bank::delete_operation_intake_claim(observed.identity, observed.policy)?,
            OperationIntakePurposeV1::Execution => bank::execution_operation_intake_claim(observed.identity, observed.policy)?,
            OperationIntakePurposeV1::LifecycleStop => return Err(ControllerBankLaunchErrorV1::Conflict),
        }.ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let native_resident = match purpose {
            OperationIntakePurposeV1::Delete =>
                ControllerOperationIntakeOriginalV1::native_source_resident_demand_v1(OperationIntakePurposeV1::Delete)?,
            OperationIntakePurposeV1::Execution =>
                ControllerOperationIntakeOriginalV1::native_source_resident_demand_v1(OperationIntakePurposeV1::Execution)?,
            OperationIntakePurposeV1::LifecycleStop => return Err(ControllerBankLaunchErrorV1::Conflict),
        };
        let resident = resident.demand.checked_add(native_resident)?;
        // This is the actual image-reserved C purpose, not a new account or
        // baseline debit. Both complete requirements precede owner growth.
        let flight_capacity = flight_capacity.demand.checked_add(
            ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?,
        )?;
        original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(purpose).claim_once(purpose, claim, resident, flight_capacity)?;
        let binding = bank::require_exact_claim_record_v1(self.fixed.bank_state_v1()?, claim);
        if let Err(cause) = binding {
            original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
                .slot_mut(purpose).close();
            self.fixed.fence();
            return Err(cause.into());
        }
        if let Err(cause) = profile.prepare_operation_intake_pool_once_v1(original, purpose) {
            original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
                .slot_mut(purpose).close();
            return Err(cause.into());
        }
        Ok(ControllerOperationIntakeOriginalV1::new_funded_v2(
            Arc::clone(original), Arc::clone(self.fixed.identity()), purpose,
            OperationIntakeFundingV2::InitialReservedClaim(claim), flight_capacity,
        ))
    }
}

impl ControllerOperationIntakeOriginalV1 {
    fn new_funded_v2(original: Arc<ControllerReceivingOriginalV1>,
        identity: Arc<ControllerWriterIdentityV1>, purpose: OperationIntakePurposeV1,
        funding: OperationIntakeFundingV2, flight_capacity: ResourceVector,
    ) -> Self {
        Self {
            original, identity, purpose, funding, recovered_enrollment: None, recovered_cleanup: None,
            before: ControllerOriginalObservationV1::new(), after: ControllerOriginalObservationV1::new(),
            names_before: ControllerWriterNameSampleV1::new(), names_after: ControllerWriterNameSampleV1::new(),
            arm: None, names_before_result: None, before_result: None,
            names_after_result: None, after_result: None, launch_result: None,
            entry: OperationIntakeEntryV1::new(), active: false,
            delete_source_scope_open: false,
            whole_capacity: flight_capacity,
            whole_declared: false,
            execution_admission_parked: false,
        }
    }

    fn require_funding_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        match self.funding {
            OperationIntakeFundingV2::InitialReservedClaim(claim) => {
                bank::require_exact_claim_record_v1(writer.fixed.bank_state_v1()?, claim)?;
            }
            OperationIntakeFundingV2::RecoveredLifecycleStop(receipt) => {
                self.require_stop_seed_unpublished_v3(writer, launch, profile)?;
                receipt.record_data_v3().require_replayed_v3(writer.fixed.bank_state_v1()?)?;
            }
            OperationIntakeFundingV2::RecoveredBaseline(receipt) => {
                self.recovered_enrollment.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                    .require_same_v1(&self.original, &self.identity)?;
                launch.require_operator_recover_current_v1(writer)?;
                self.original.require_recovered_operation_funding_v2(profile, receipt)?;
                // A new operation cannot use an in-memory debit alone. Its
                // complete same-C durable subdivision must already be present.
                receipt.record_data_v1().require_replayed_v1(writer.fixed.bank_state_v1()?)?;
            }
        }
        self.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot(self.purpose).require_same_funding_v2(self.funding)?;
        Ok(())
    }

    fn native_resident_demand_v1(purpose: OperationIntakePurposeV1) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let inline = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<FailedBeginGuardV1<'_>>()))
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(inline).map_err(|_| ControllerBankLaunchErrorV1::Conflict)?)
            .checked_add(ControllerSelfProfileOriginalV1::operation_intake_pool_resident_demand_v1(purpose)?)?)
    }

    fn native_source_resident_demand_v1(purpose: OperationIntakePurposeV1) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        // Scope and token contain only thin references to the generic writer;
        // their layout and fixed names samples do not depend on its selection.
        Ok(Self::native_resident_demand_v1(purpose)?.checked_add(
            crate::source_receiving::SourceDeleteScopeV1::<()>::receiving_demand_v1()?,
        )?)
    }

    fn native_flight_demand_v1(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1>
    {
        let observation = ControllerOriginalObservationV1::receiving_demand_v1()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let inline = std::mem::size_of::<ControllerOperationIntakeReceivingLoanV1<'_>>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<ControllerOperationIntakeFailureViewV1<'_>>()))
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(profile.operation_intake_demand_v1()?
            .checked_add(observation)?.checked_add(observation)?
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(inline).map_err(|_| ControllerBankLaunchErrorV1::Conflict)?))?)
    }

    /// Enters a full finite operation before accepted decoding or native IO.
    ///
    /// The passed shape is a requirement, never capacity. The closed upper
    /// compiler/consumer supplies its actual bounded codec/native/output recipe.
    /// All original/profile/name overhead is added by this same native receiver.
    ///
    /// # Errors
    /// Refuses overlap, failed predecessor, foreign original, changed launch,
    /// unavailable actual profile geometry or any full-vector admission failure.
    pub fn borrow_receiving_v1<'owner, P>(
        &'owner mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        demand: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeReceivingLoanV1<'owner>, ControllerBankLaunchErrorV1> {
        if self.purpose == OperationIntakePurposeV1::LifecycleStop {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        if self.active || self.entry.first.is_some() || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original) || !profile.has_same_baseline_original(&self.original)
        {
            self.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
                .slot_mut(self.purpose).close();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let mut preparation = FailedBeginGuardV1 {
            original: &self.original, purpose: self.purpose, completed: false,
        };
        launch.require_current_controller_v1(writer)?;
        self.original.operation_intake_enrollment_v1(profile)?;
        self.require_funding_v2(writer, launch, profile)?;
        let required = demand.demand.checked_add(Self::native_flight_demand_v1(profile)?)?;
        // The full22 owned operation remains consumed before any accepted
        // decode/native entry. Its reserved capacity is distinct from actual
        // finite traffic, prepaid before every reached stage on the same slot.
        let mut slots = self.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let prepaid_traffic = if self.whole_declared {
            Some(*self.entry.whole_required.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?)
        } else {
            None
        };
        self.entry.begin_slot_once_v1(slots.slot_mut(self.purpose), required, prepaid_traffic)?;
        drop(slots);
        self.active = true;
        // A prior positive disposal cleared only its actual transient owners.
        // Permanent resident peak, claim and flight capacity stay unchanged.
        self.arm = Some(writer.fixed.begin_name_sample(&mut self.names_after));
        if self.arm.as_ref().is_some_and(Result::is_err) { self.entry.first = Some(First::Arm); }
        self.names_before_result = Some((|| {
            writer.fixed.begin_name_sample(&mut self.names_before)?;
            writer.fixed.finish_owed_name_sample(&mut self.names_before)
        })());
        if self.entry.first.is_none() && self.names_before_result.as_ref().is_some_and(Result::is_err) {
            self.entry.first = Some(First::NamesBefore);
        }
        self.before_result = Some(self.before.observe_operation_intake_once_v1(
            &self.original, profile, self.purpose, 0,
        ));
        if self.entry.first.is_none() && self.before_result.as_ref().is_some_and(Result::is_err) {
            self.entry.first = Some(First::OriginalBefore);
        }
        if self.entry.first.is_some() { writer.fixed.fence(); }
        preparation.completed = true;
        drop(preparation);
        Ok(ControllerOperationIntakeReceivingLoanV1 {
            owner: self, finished: false, delete_source_scope_entered: false,
            execution_admission_handoff: false,
        })
    }

    /// Borrows only Delete17, consuming its SAME finite full-vector capacity.
    ///
    /// Actual authorization demand is checked before input/model/native growth.
    /// Later held Source/Root extents are complete requirements against this
    /// same consumed capacity; a supplied requirement cannot select capacity.
    ///
    /// # Errors
    /// Refuses another purpose, failed/current/foreign owner or insufficient
    /// initial requirement through the shared private operation engine.
    pub fn borrow_delete_whole_declared_v1<'owner, P>(
        &'owner mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        initial: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeReceivingLoanV1<'owner>, ControllerBankLaunchErrorV1> {
        if self.purpose != OperationIntakePurposeV1::Delete {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.borrow_whole_declared_inner_v1(writer, launch, profile, initial)
    }

    /// Borrows only Execution18, consuming its SAME finite full-vector capacity.
    ///
    /// Actual upper fixed demand is checked before entering any new native
    /// work. Later held extents remain requirements against this already
    /// consumed vector; no caller can choose capacity or create another account.
    ///
    /// # Errors
    /// Refuses another purpose, failed/current/foreign owner or insufficient
    /// initial shape, preserving the original checked arithmetic result.
    pub fn borrow_execution_whole_declared_v1<'owner, P>(
        &'owner mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        initial: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeReceivingLoanV1<'owner>, ControllerBankLaunchErrorV1> {
        if self.purpose != OperationIntakePurposeV1::Execution {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.borrow_whole_declared_inner_v1(writer, launch, profile, initial)
    }

    fn borrow_whole_declared_inner_v1<'owner, P>(
        &'owner mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        initial: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeReceivingLoanV1<'owner>, ControllerBankLaunchErrorV1> {
        if self.active || self.entry.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // Use the original factory's saved complete capacity and the SAME
        // native supplier. This is no public capacity/amount projection.
        // Actual finite traffic starts at whole_required and is extended on
        // this SAME slot before later native/model IO; it is never refunded.
        let native = Self::native_flight_demand_v1(profile)?;
        if self.entry.prepare_whole_requirement_v1(self.whole_capacity, initial.demand, native).is_err() {
            self.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
                .slot_mut(self.purpose).close();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let upper_capacity = self.whole_capacity.checked_sub(native)?;
        self.whole_declared = true;
        self.borrow_receiving_v1(writer, launch, profile,
            ControllerOperationIntakeDemandDataV1 { demand: upper_capacity })
    }

    /// Borrows the actual first native cause retained by this purpose owner.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.entry.first? {
            First::Arm => error(&self.arm),
            First::NamesBefore => self.names_before.failure().or_else(|| error(&self.names_before_result)),
            First::OriginalBefore => self.before.failure().or_else(|| error(&self.before_result)),
            First::NamesAfter => self.names_after.failure().or_else(|| error(&self.names_after_result)),
            First::OriginalAfter => self.after.failure().or_else(|| error(&self.after_result)),
            First::Launch => error(&self.launch_result),
            First::CompleteRequirement => error(&self.entry.whole_required),
            First::PreacceptPreparation => self.entry.preaccept_preparation.as_ref().map(|cause| cause as _),
            First::Financial => None,
        }
    }
}

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    /// Borrows the same original/profile cause through this continuously held loan.
    ///
    /// This is diagnostic custody only. Upper callers select it only for their
    /// actual native-entry/completion marker; it cannot replace an earlier
    /// concrete authorization, decoder, Source or physical body failure.
    #[must_use]
    pub fn failure_view_v1<'scope>(
        &'scope self,
        profile: &'scope ControllerSelfProfileOriginalV1,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'scope>> {
        self.owner.failure_view_v1(profile)
    }

    // Only the actual Source coordinator calls this closed Delete-purpose join.
    // Its two real names observations were reserved by the actual Delete
    // claim before capacity derivation. The persistent Source writer/index
    // debt remains on its separate genuine construction original.
    pub(crate) fn enter_delete_source_scope_v1<P>(
        &mut self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.enter_source_scope_inner_v1(source, writer, launch, profile, OperationIntakePurposeV1::Delete)
    }

    pub(crate) fn enter_execution_source_scope_v1<P>(
        &mut self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.enter_source_scope_inner_v1(source, writer, launch, profile, OperationIntakePurposeV1::Execution)
    }

    fn enter_source_scope_inner_v1<P>(
        &mut self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: OperationIntakePurposeV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_active_v1(writer, launch, profile)?;
        if self.owner.purpose != purpose
            || self.delete_source_scope_entered || self.owner.delete_source_scope_open
            || !source.has_same_original_v1(&self.owner.original)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.delete_source_scope_entered = true;
        self.owner.delete_source_scope_open = true;
        Ok(())
    }

    /// Requires the entered before bookends without granting effect authority.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or finished native interval.
    pub fn require_active_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.owner.require_active_native_inner_v2(writer, launch, profile, self.finished)
    }

    /// Checks the complete reached Delete17 shape before further growth or IO.
    ///
    /// The actual caller includes all simultaneously held authorization,
    /// Source, graph, transport and native owners. This full requirement is
    /// checked against the same declaration already consumed at named entry.
    ///
    /// # Errors
    /// Refuses another purpose/original, completed/failed entry or a complete
    /// requirement beyond that same permanently reserved full-vector capacity.
    pub fn require_delete_complete_v1<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Delete {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_whole_complete_inner_v1(writer, launch, profile, complete)
    }

    /// Checks reached Execution18 representation before each new held-prefix replay.
    ///
    /// The same full22 declaration was consumed once at named entry. This
    /// monotonically checks actual requirements and cannot reset/refund it.
    ///
    /// # Errors
    /// Refuses another purpose/original, completed/failed entry or a complete
    /// reached requirement beyond the SAME permanently reserved capacity.
    pub fn require_execution_complete_v1<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Execution {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_whole_complete_inner_v1(writer, launch, profile, complete)
    }

    fn require_whole_complete_inner_v1<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_active_v1(writer, launch, profile)?;
        if !self.owner.whole_declared {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let native = ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?;
        let previous = *self.owner.entry.whole_required.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        self.owner.entry.whole_required = Some(complete.demand.checked_add(native)
            .map(|required| previous.componentwise_max(required))
            .and_then(|required| self.owner.whole_capacity.checked_sub(required).map(|_| required)));
        if self.owner.entry.whole_required.as_ref().is_none_or(|result| result.is_err()) {
            self.owner.entry.first.get_or_insert(First::CompleteRequirement);
            self.owner.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
                .slot_mut(self.owner.purpose).close();
            writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let required = *self.owner.entry.whole_required.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let traffic = self.owner.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(self.owner.purpose).reserve_complete_traffic_v1(required);
        if let Err(cause) = traffic {
            self.owner.entry.first.get_or_insert(First::CompleteRequirement);
            writer.fixed.fence();
            return Err(cause.into());
        }
        Ok(())
    }

    // Reached preaccept bytes/traffic are added to the actual whole-flight
    // frontier. This is not a new capacity or a replacement per-stage maximum.
    pub(crate) fn reserve_delete_preaccept_additional_v1<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.reserve_delete_preaccept_with_receipt_v2(writer, launch, profile, additional).map(|_| ())
    }

    // Only the closed pending Source consumer retains this checked-demand
    // receipt. It is DATA from the same successful reservation, not a new
    // ledger, available capacity getter, admission or reset.
    pub(crate) fn reserve_delete_preaccept_with_receipt_v2<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeDemandDataV1, ControllerBankLaunchErrorV1> {
        let result = (|| {
            if self.owner.purpose != OperationIntakePurposeV1::Delete
                || !self.delete_source_scope_entered || !self.owner.delete_source_scope_open {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            self.require_active_v1(writer, launch, profile)?;
            let native = ControllerOperationIntakeOriginalV1::native_flight_demand_v1(profile)?;
            let previous = *self.owner.entry.whole_required.as_ref()
                .and_then(|required| required.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let upper = preaccept::additional_preaccept_requirement_v1(
                previous, native, additional.demand,
            );
            let upper = match upper {
                Ok(upper) => upper,
                Err(cause) => {
                    self.owner.entry.whole_required = Some(Err(cause));
                    self.owner.entry.first.get_or_insert(First::CompleteRequirement);
                    return Err(ControllerBankLaunchErrorV1::Conflict);
                }
            };
            // The sole common checker adds the outer native tranche once and
            // pays the positive cumulative traffic delta on the SAME slot.
            self.require_delete_complete_v1(writer, launch, profile,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(upper))?;
            Ok(ControllerOperationIntakeDemandDataV1::from_demand_v1(upper))
        })();
        match result {
            Ok(receipt) => Ok(receipt),
            Err(cause) => Err(self.retain_delete_preaccept_refusal_v1(writer, cause)),
        }
    }

    fn retain_delete_preaccept_refusal_v1<P>(
        &mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        cause: ControllerBankLaunchErrorV1,
    ) -> ControllerBankLaunchErrorV1 {
        if self.owner.purpose != OperationIntakePurposeV1::Delete
            || !self.owner.delete_source_scope_open { return cause; }
        // Store the real earlier error before either closure can refuse.
        if self.owner.entry.preaccept_preparation.is_none() {
            self.owner.entry.preaccept_preparation = Some(cause);
        }
        self.owner.entry.first.get_or_insert(First::PreacceptPreparation);
        if let Ok(mut state) = self.owner.original.operation_intakes.try_lock() {
            state.slot_mut(OperationIntakePurposeV1::Delete).refuse_delete_preaccept_turn_v1();
        }
        writer.fixed.fence();
        ControllerBankLaunchErrorV1::Conflict
    }

    /// Projects this actual Delete funding only under its same current C join.
    ///
    /// The canonical witness remains DATA: it cannot reconstruct the consumed
    /// original, active source scope, or a receiving grant in another process.
    ///
    /// # Errors
    /// Refuses another purpose, absent Source custody or changed original,
    /// profile, Launch, protected funding row, or active financial operation.
    pub fn current_delete_funding_data_v3<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<bank::OperationIntakeFundingDataV1, ControllerBankLaunchErrorV1> {
        if self.owner.purpose != OperationIntakePurposeV1::Delete
            || !self.delete_source_scope_entered || !self.owner.delete_source_scope_open {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_active_v1(writer, launch, profile)?;
        match &self.owner.funding {
            OperationIntakeFundingV2::InitialReservedClaim(claim) =>
                Ok(bank::OperationIntakeFundingDataV1::InitialReservedClaim(*claim)),
            OperationIntakeFundingV2::RecoveredBaseline(receipt) =>
                Ok(bank::OperationIntakeFundingDataV1::RecoveredBaseline(receipt.record_data_v1())),
            OperationIntakeFundingV2::RecoveredLifecycleStop(_) => Err(ControllerBankLaunchErrorV1::Conflict),
        }
    }

    /// Borrows only the same actual held Controller history after paid entry.
    ///
    /// # Errors
    /// Refuses failed or completed native entry before lending history.
    pub fn historical_view_v1<'writer, P>(&self,
        writer: &'writer ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<HistoricalLedgerReadViewV1<'writer>, ControllerBankLaunchErrorV1> {
        self.require_active_v1(writer, launch, profile)?;
        Ok(writer.fixed.historical_view())
    }

    fn require_same_actual_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&self.owner.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.owner.original)
            || !profile.has_same_baseline_original(&self.owner.original)
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        Ok(())
    }

    /// Runs every already-owed native post independently of primary failure.
    ///
    /// The upper caller retains its whole body Result and calls this on both
    /// outcomes. These observations neither clear that Result nor retry effects.
    ///
    /// # Errors
    /// Refuses repeated completion or any retained before/after/launch failure.
    pub fn finish_native_once_v1<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_same_actual_v1(writer, profile)?;
        if self.finished { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.finished = true;
        self.owner.names_after_result = Some(writer.fixed.finish_owed_name_sample(&mut self.owner.names_after));
        if self.owner.entry.first.is_none() && self.owner.names_after_result.as_ref().is_some_and(Result::is_err) {
            self.owner.entry.first = Some(First::NamesAfter);
        }
        self.owner.after_result = Some(self.owner.after.observe_operation_intake_once_v1(
            &self.owner.original, profile, self.owner.purpose, 2,
        ));
        if self.owner.entry.first.is_none() && self.owner.after_result.as_ref().is_some_and(Result::is_err) {
            self.owner.entry.first = Some(First::OriginalAfter);
        }
        self.owner.launch_result = Some((|| {
            launch.require_current_controller_v1(writer)?;
            self.owner.require_funding_v2(writer, launch, profile)
        })());
        if self.owner.entry.first.is_none() && self.owner.launch_result.as_ref().is_some_and(Result::is_err) {
            self.owner.entry.first = Some(First::Launch);
        }
        if self.owner.entry.first.is_some() {
            writer.fixed.fence();
            Err(ControllerBankLaunchErrorV1::Conflict)
        } else { Ok(()) }
    }

    /// Prepares native disposal while every actual upper owner remains resident.
    ///
    /// The trusted upper owner must first finish its semantic, currentness and
    /// effect/Ended obligations, then consume/drop its positive transients before
    /// calling the returned token's infallible completion. This token certifies
    /// no accepted operation or product effect.
    ///
    /// # Errors
    /// Refuses missing posts, native failure, changed owner or earlier disposal.
    pub fn prepare_positive_disposal_v1<'disposal, P>(&'disposal mut self,
        writer: &'disposal ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerOperationIntakeDisposalV1<'disposal>, ControllerBankLaunchErrorV1> {
        if self.owner.delete_source_scope_open {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.prepare_positive_disposal_inner_v1(writer, launch, profile)
    }

    // The proof has no public constructor. Only the positively checked actual
    // Source scope can select this joint completion while retaining its writer.
    pub(crate) fn prepare_delete_source_disposal_v1<'disposal, P>(
        &'disposal mut self,
        writer: &'disposal ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        _proof: crate::source_receiving::delete_scope::SourceDeletePositiveProofV1,
    ) -> Result<ControllerOperationIntakeDisposalV1<'disposal>, ControllerBankLaunchErrorV1> {
        self.prepare_source_disposal_inner_v1(writer, launch, profile, OperationIntakePurposeV1::Delete)
    }

    pub(crate) fn prepare_execution_source_disposal_v1<'disposal, P>(
        &'disposal mut self,
        writer: &'disposal ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        _proof: crate::source_receiving::delete_scope::SourceExecutionPositiveProofV1,
    ) -> Result<ControllerOperationIntakeDisposalV1<'disposal>, ControllerBankLaunchErrorV1> {
        self.prepare_source_disposal_inner_v1(writer, launch, profile, OperationIntakePurposeV1::Execution)
    }

    fn prepare_source_disposal_inner_v1<'disposal, P>(
        &'disposal mut self,
        writer: &'disposal ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: OperationIntakePurposeV1,
    ) -> Result<ControllerOperationIntakeDisposalV1<'disposal>, ControllerBankLaunchErrorV1> {
        if !self.delete_source_scope_entered || !self.owner.delete_source_scope_open
            || self.owner.purpose != purpose
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.prepare_positive_disposal_inner_v1(writer, launch, profile)
    }

    fn prepare_positive_disposal_inner_v1<'disposal, P>(
        &'disposal mut self,
        writer: &'disposal ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerOperationIntakeDisposalV1<'disposal>, ControllerBankLaunchErrorV1> {
        self.require_same_actual_v1(writer, profile)?;
        if !self.finished || self.owner.entry.first.is_some() || !self.owner.active {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_current_controller_v1(writer)?;
        self.owner.require_funding_v2(writer, launch, profile)?;
        let mut state = writer.fixed.original().operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        state.slot_mut(self.owner.purpose).prepare_disposal()?;
        Ok(ControllerOperationIntakeDisposalV1 { state, owner: self.owner })
    }
}

impl Drop for ControllerOperationIntakeReceivingLoanV1<'_> {
    fn drop(&mut self) {
        if self.owner.active && !self.execution_admission_handoff {
            match self.owner.original.operation_intakes.try_lock() {
                Ok(mut state) => state.slot_mut(self.owner.purpose).close(),
                Err(_) => std::process::abort(),
            }
        }
    }
}

/// Exclusively keeps completed native checks through actual upper disposal.
#[must_use]
pub struct ControllerOperationIntakeDisposalV1<'disposal> {
    state: MutexGuard<'disposal, ControllerOperationIntakesV1>,
    owner: &'disposal mut ControllerOperationIntakeOriginalV1,
}

impl ControllerOperationIntakeDisposalV1<'_> {
    /// Completes only after the trusted owner drops its positive transients.
    ///
    /// Performs no IO, allocation, lock, fallible post, refund or accounting reset.
    pub fn complete_after_disposal_v1(mut self) {
        self.owner.names_before.dispose_after_complete_interval();
        self.owner.names_after.dispose_after_complete_interval();
        self.owner.before = ControllerOriginalObservationV1::new();
        self.owner.after = ControllerOriginalObservationV1::new();
        self.owner.names_before = ControllerWriterNameSampleV1::new();
        self.owner.names_after = ControllerWriterNameSampleV1::new();
        self.owner.arm = None;
        self.owner.names_before_result = None;
        self.owner.before_result = None;
        self.owner.names_after_result = None;
        self.owner.after_result = None;
        self.owner.launch_result = None;
        self.state.slot_mut(self.owner.purpose).complete_after_disposal();
        self.owner.delete_source_scope_open = false;
        self.owner.entry.retire_positive_v1();
        self.owner.whole_declared = false;
        self.owner.active = false;
    }
}

impl Drop for ControllerOperationIntakeOriginalV1 {
    fn drop(&mut self) {
        if self.active || self.entry.first.is_some() { std::process::abort(); }
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

enum FailureCause<'scope> {
    Financial(MutexGuard<'scope, ControllerOperationIntakesV1>, OperationIntakePurposeV1),
    Native(&'scope (dyn Error + 'static)),
    Profile(crate::controller_receiving::profile::BaselineFailureView<'scope>),
}

/// Borrows the actual first raw native cause without releasing its original.
pub struct ControllerOperationIntakeFailureViewV1<'scope> {
    cause: FailureCause<'scope>,
}

impl std::fmt::Debug for ControllerOperationIntakeFailureViewV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerOperationIntakeFailureViewV1").finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControllerOperationIntakeFailureViewV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            FailureCause::Financial(state, purpose) => match state.slot(*purpose).failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Controller operation admission failed"),
            },
            FailureCause::Native(cause) => std::fmt::Display::fmt(cause, f),
            FailureCause::Profile(view) => match view.cause() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Controller operation profile observation failed"),
            },
        }
    }
}

impl Error for ControllerOperationIntakeFailureViewV1<'_> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            FailureCause::Financial(state, purpose) => state.slot(*purpose).failure().map(|cause| cause as _),
            FailureCause::Native(cause) => Some(*cause),
            FailureCause::Profile(view) => view.cause(),
        }
    }
}

impl ControllerOperationIntakeOriginalV1 {
    /// Borrows the original cause from this actual native/profile interval.
    ///
    /// Same-profile association is compared without IO. The returned guard
    /// retains the selected failed raw profile scope while diagnostics borrow it.
    #[must_use]
    pub fn failure_view_v1<'scope>(&'scope self,
        profile: &'scope ControllerSelfProfileOriginalV1,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'scope>> {
        if !profile.has_same_baseline_original(&self.original) { return None; }
        if self.entry.first.is_none()
            || matches!(self.entry.first, Some(First::Financial))
            || (matches!(self.entry.first, Some(First::CompleteRequirement)) && self.failure().is_none())
        {
            // A selected reached-traffic refusal lives on the SAME slot.
            // Borrow that first actual arithmetic error under its existing
            // guard instead of inventing a replacement coarse native cause.
            let state = self.original.operation_intakes.try_lock().ok()?;
            return state.slot(self.purpose).failure().is_some().then_some(
                ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Financial(state, self.purpose) },
            );
        }
        let slot = match self.entry.first? {
            First::OriginalBefore => self.before.operation_profile_failure_slot_v1(0),
            First::OriginalAfter => self.after.operation_profile_failure_slot_v1(2),
            _ => None,
        };
        if let Some(slot) = slot {
            if let Some(view) = profile.operation_intake_failure_view_v1(self.purpose, slot) {
                return Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Profile(view) });
            }
        }
        self.failure().map(|cause| ControllerOperationIntakeFailureViewV1 {
            cause: FailureCause::Native(cause),
        })
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Borrows only this actual C's first Delete intake admission refusal.
    #[must_use]
    pub fn delete_operation_intake_failure_view_v1(&self)
        -> Option<ControllerOperationIntakeFailureViewV1<'_>>
    {
        self.operation_intake_failure_view_v1(OperationIntakePurposeV1::Delete)
    }

    /// Borrows only this actual C's first execution intake admission refusal.
    #[must_use]
    pub fn execution_operation_intake_failure_view_v1(&self)
        -> Option<ControllerOperationIntakeFailureViewV1<'_>>
    {
        self.operation_intake_failure_view_v1(OperationIntakePurposeV1::Execution)
    }

    fn operation_intake_failure_view_v1(&self, purpose: OperationIntakePurposeV1)
        -> Option<ControllerOperationIntakeFailureViewV1<'_>>
    {
        let state = self.fixed.original().operation_intakes.try_lock().ok()?;
        if state.slot(purpose).failure().is_none() { return None; }
        Some(ControllerOperationIntakeFailureViewV1 { cause: FailureCause::Financial(state, purpose) })
    }
}

// Entry failure closes the actual purpose even when checked shape arithmetic
// refuses before an owned inert flight can be constructed. No native post is
// owed before consumption; any actual entered native prefix stays on owner.
struct FailedBeginGuardV1<'entry> {
    original: &'entry ControllerReceivingOriginalV1,
    purpose: OperationIntakePurposeV1,
    completed: bool,
}

impl Drop for FailedBeginGuardV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            match self.original.operation_intakes.try_lock() {
                Ok(mut state) => state.slot_mut(self.purpose).close(),
                Err(_) => std::process::abort(),
            }
        }
    }
}

// Shared comparison only: neither subtraction issues capacity or authority.
fn checked_upper_capacity_v1(
    declared: ResourceVector,
    upper_resident: ResourceVector,
    native_resident: ResourceVector,
    native_flight: ResourceVector,
) -> Result<ResourceVector, aos_sandbox_core::AccountingError> {
    declared.checked_sub(upper_resident)?
        .checked_sub(native_resident)?
        .checked_sub(native_flight)
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn native_and_upper_costs_cannot_overlap_in_any_dimension() {
        let declared = ResourceVector::new([8; D::COUNT]);
        let upper = ResourceVector::new([2; D::COUNT]);
        let native_resident = ResourceVector::new([3; D::COUNT]);
        let native_flight = ResourceVector::new([3; D::COUNT]);
        assert_eq!(checked_upper_capacity_v1(declared, upper, native_resident, native_flight).unwrap(),
            ResourceVector::ZERO);

        for dimension in D::ALL {
            let short = declared.with(dimension, 7);
            assert!(checked_upper_capacity_v1(short, upper, native_resident, native_flight).is_err());
        }
        assert_eq!(declared, ResourceVector::new([8; D::COUNT]));
    }
}

#[cfg(test)]
mod entry_tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn declared_claim(purpose: OperationIntakePurposeV1) -> bank::Claim {
        let unit = D::ALL.into_iter().fold(ResourceVector::ZERO, |value, dimension| {
            value.with(dimension, 1_048_576_000)
        });
        let mut image = Vec::new();
        image.extend_from_slice(b"AOSRSB08");
        image.extend_from_slice(&[1; 16]);
        image.extend_from_slice(&[2; 16]);
        for scale in [40, 1, 10, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
            for dimension in D::ALL {
                image.extend_from_slice(&(unit.get(dimension) * scale).to_be_bytes());
            }
        }
        image.extend_from_slice(&Sha256::digest(&image));
        let policy = bank::decode_component_image_policy(&image).unwrap();
        let mut delivery = Vec::from(&b"AOSRSE01"[..]);
        delivery.extend_from_slice(&[1; 16]);
        delivery.extend_from_slice(&[2; 16]);
        delivery.extend_from_slice(&[3; 16]);
        delivery.extend_from_slice(&[4; 16]);
        delivery.extend_from_slice(&[5; 32]);
        delivery.extend_from_slice(&[6; 16]);
        delivery.extend_from_slice(&Sha256::digest(&delivery));
        let (identity, _) = bank::decode_pid1_delivery(&delivery).unwrap();
        match purpose {
            OperationIntakePurposeV1::Delete => bank::delete_operation_intake_claim(identity, policy),
            OperationIntakePurposeV1::Execution => bank::execution_operation_intake_claim(identity, policy),
            OperationIntakePurposeV1::LifecycleStop => panic!("Stop has no initial claim"),
        }.unwrap().unwrap()
    }

    #[test]
    fn native_entry_keeps_first_spent_traffic_refusal_before_a_larger_reentry() {
        for purpose in [OperationIntakePurposeV1::Delete, OperationIntakePurposeV1::Execution] {
            for whole_declared in [false, true] {
                let claim = declared_claim(purpose);
                let capacity = claim.native_fields().amount;
                let traffic = ResourceVector::ZERO.with(D::NetworkBytes, capacity.get(D::NetworkBytes));
                let mut slots = ControllerOperationIntakesV1::new();
                let slot = slots.slot_mut(purpose);
                slot.claim_once(purpose, claim, ResourceVector::ZERO, capacity).unwrap();
                let mut entry = OperationIntakeEntryV1::new();

                // Exercise the exact native-owner entry state without creating
                // a fake C, writer, Launch, profile or native-success original.
                if whole_declared {
                    entry.prepare_whole_requirement_v1(capacity, traffic, ResourceVector::ZERO).unwrap();
                }
                let required = if whole_declared { capacity } else { traffic };
                let prepaid = whole_declared.then_some(traffic);
                entry.begin_slot_once_v1(slot, required, prepaid).unwrap();
                for index in 0..4 {
                    slot.enter_profile_once(index).unwrap();
                    slot.prepare_profile_disposal_once(index).unwrap();
                    slot.retire_profile_after_disposal(index);
                }
                slot.prepare_disposal().unwrap();
                slot.complete_after_disposal();
                entry.retire_positive_v1();

                if whole_declared {
                    entry.prepare_whole_requirement_v1(capacity, traffic, ResourceVector::ZERO).unwrap();
                }
                assert!(entry.begin_slot_once_v1(slot, required, prepaid).is_err());
                assert!(matches!(entry.first, Some(First::Financial)));
                assert!(matches!(slot.failure(), Some(crate::controller_receiving::ControllerReceivingErrorV1::Accounting(_))));
                let first = std::ptr::from_ref(slot.failure().unwrap());
                let stored_requirement = entry.whole_required;

                // The historical regression recomputed a larger requirement
                // here and replaced the marker with CompleteRequirement.
                let larger = capacity.with(D::MemoryBytes, capacity.get(D::MemoryBytes) + 1);
                assert!(entry.prepare_whole_requirement_v1(capacity, larger, ResourceVector::ZERO).is_err());
                assert_eq!(entry.whole_required, stored_requirement);
                assert!(matches!(entry.first, Some(First::Financial)));
                assert!(entry.begin_slot_once_v1(slot, ResourceVector::ZERO, None).is_err());
                assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
                assert!(slot.enter_profile_once(0).is_err());
                assert_eq!(first, std::ptr::from_ref(slot.failure().unwrap()));
            }
        }
    }
}

mod preaccept;
pub use preaccept::{ControllerDeletePreacceptTurnOriginalV1, ControllerDeletePreacceptTurnDisposalV1};

impl ControllerOperationIntakeOriginalV1 {
    /// Binds actual completed enrollment after the upper Source/clock conjunction.
    ///
    /// No Boolean, decoded record or initial claim can supply this association.
    /// The trusted upper calls only after its full semantic enrollment succeeds.
    ///
    /// # Errors
    /// Refuses another payer, unfinished publication, reentry or changed funding.
    pub fn bind_recovered_enrollment_once_v2<P>(&mut self,
        enrolled: &super::create_provisioning::ControllerRecoveredEnrollmentReceivingV2,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.recovered_enrollment.is_some() || self.active || self.entry.first.is_some()
            || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let OperationIntakeFundingV2::RecoveredBaseline(receipt) = self.funding else {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        };
        let association = enrolled.completed_association_v1(writer, launch, profile)?;
        association.require_same_v1(&self.original, &self.identity)?;
        self.original.require_recovered_operation_funding_v2(profile, receipt)?;
        receipt.record_data_v1().require_replayed_v1(writer.fixed.bank_state_v1()?)?;
        self.recovered_enrollment = Some(association);
        Ok(())
    }

    /// Rejoins recovered provenance without broadening the initial first-use gate.
    ///
    /// # Errors
    /// Refuses initial funding, absent genuine enrollment, wrong original or row.
    pub fn require_recovered_entry_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(self.funding, OperationIntakeFundingV2::RecoveredBaseline(_)
                | OperationIntakeFundingV2::RecoveredLifecycleStop(_))
            || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original)
            || !profile.has_same_baseline_original(&self.original) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_funding_v2(writer, launch, profile)
    }
}

impl ControllerOperationIntakeOriginalV1 {
    /// Reports this actual owner's funding branch without admitting work.
    #[must_use]
    pub fn funding_kind_data_v2(&self) -> ControllerOperationIntakeFundingKindDataV2 {
        match self.funding {
            OperationIntakeFundingV2::InitialReservedClaim(_) => ControllerOperationIntakeFundingKindDataV2::InitialReservedClaim,
            OperationIntakeFundingV2::RecoveredBaseline(_) | OperationIntakeFundingV2::RecoveredLifecycleStop(_) => ControllerOperationIntakeFundingKindDataV2::RecoveredBaseline,
        }
    }
}

mod stop_seed;

mod execution_admission;
