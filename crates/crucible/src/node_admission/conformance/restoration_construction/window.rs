//! Admits one retained cold reconstruction before its complete live transaction.
//!
//! Both phases use the same actual inactive runtime, signed archive, Source
//! roster and installed authority. Cold construction grants no protocol effect.
//! Only a second full observation may enable private Prepare/Inputs/Commit
//! claims. Neither phase creates a final lineage context, Ready or Arm.

use super::*;
use crate::{
    node_adapters::cnp::{CnpSemanticLaunchGuard, OriginalRestorationColdGroup},
    node_contract::{NodeRuntime, OriginalRestorationRuntimeMemberIdentity},
};
use std::{
    cell::{Cell, OnceCell, RefCell},
    mem::size_of,
    thread::ThreadId,
};

/// Names the two distinct admissions preceding a live restoration transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRestorationConstructionPhase {
    /// Constructs the genuine grouped cold owners without protocol effects.
    ColdOwners,
    /// Funds all real current and future owners before any Prepare assignment.
    Transaction,
    /// Reobserves actual selected readiness, publication and restored custody.
    Installed,
}

/// Borrows the actual registered originals for one whole-owner observation.
pub struct OriginalRestorationConstructionScope<'a> {
    plan: &'a InstalledConformancePlan,
    inputs: &'a OriginalRestorationConstructionInputs<'a>,
    phase: OriginalRestorationConstructionPhase,
    window: Option<&'a CompleteOriginalRestorationWindow>,
}

impl OriginalRestorationConstructionScope<'_> {
    /// Borrows the exact installed plan allocation.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the same retained runtime, archive, tickets and fixed owner roster.
    pub fn inputs(&self) -> &OriginalRestorationConstructionInputs<'_> {
        self.inputs
    }

    /// Distinguishes cold construction from the complete transaction admission.
    pub fn phase(&self) -> OriginalRestorationConstructionPhase {
        self.phase
    }

    /// Compares the actual installed authority before any owning observation.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }

    /// Compares the actual retained window rather than decoded labels or totals.
    pub fn is_original_window(&self, original: &Rc<CompleteOriginalRestorationWindow>) -> bool {
        self.window
            .is_some_and(|window| std::ptr::eq(window, original.as_ref()))
    }
}

/// Carries independently installed memory and descriptor ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRestorationConstructionPolicy {
    /// Bounds the complete simultaneous owning and prospective phase sum.
    pub maximum_requested_bytes: usize,
    /// Bounds actual host descriptor views independently of memory accounting.
    pub maximum_owned_descriptors: usize,
    /// Admits all explicit Core, Source, node and concrete holder counter views.
    pub declared_observer_scratch_bytes: usize,
}

/// Reports concrete external holder and callback rows under the same policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRestorationConstructionStorage {
    /// Counts actual external holder owners, excluding independently walked Sources,
    /// archive, runtime and the window's own cold/transaction roots.
    pub retained_holder_bytes: usize,
    /// Counts complete simultaneous concrete callback construction and diagnostics.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Counts actual external host descriptors, excluding the independent Core rows.
    pub retained_descriptors: usize,
    /// Counts concrete callback temporary descriptors without inferred spare credit.
    pub maximum_simultaneous_transient_descriptors: usize,
}

/// Borrows only fixed member identities during an actual node's mutable loan.
///
/// This scope deliberately lends no runtime, cold graph, SDK, preparation or
/// Source association bank. Concrete callbacks must use their same registered
/// holder/plan/Source identities and sticky spent state. The window independently
/// repeats its genuine scheduler live fence after the callback.
pub struct OriginalRestorationMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    window: &'a CompleteOriginalRestorationWindow,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    publisher: Option<*const ()>,
}

impl OriginalRestorationMemberScope<'_> {
    /// Borrows the same installed plan allocation.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the exact retained Source handles without opening their banks.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Compares the concrete holder's original window allocation.
    pub fn is_original_window(&self, original: &Rc<CompleteOriginalRestorationWindow>) -> bool {
        std::ptr::eq(self.window, original.as_ref())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowStage {
    ColdAdmitted,
    ColdStarted,
    ColdComplete,
    TransactionStarted,
    TransactionAdmitted,
    TransactionChecking,
    Failed,
}

/// Retains the same admitted originals and every partial cold or live owner.
///
/// No public constructor, deserializer or final-context conversion exists. The
/// concrete holder stores this owner before beginning cold reconstruction. A
/// failure or unwind leaves the same spent stage and retained slots; replacing
/// the window cannot renew the archive's per-owner transaction ledger.
#[must_use = "retain the original window and every partial owner through failure"]
pub struct CompleteOriginalRestorationWindow {
    restored_captures: RefCell<restored_capture::Ledger>,
    restored_capture_in_flight: Cell<bool>,
    producer_executions: [RefCell<producer_execution::ProducerExecutionLedger>; 3],
    producer_publication: OnceCell<producer_execution::ProducerPublicationIdentity>,
    producer_next_slot: Cell<usize>,
    producer_grant_work: [Cell<Option<(usize, usize, usize)>>; 3],
    producer_grant_started: [Cell<bool>; 3],
    current_observations: [RefCell<current_observation::CurrentObservationLedger>; 3],
    initial_scheduling_work: [Cell<Option<(usize, usize, usize)>>; 3],
    process: u32,
    thread: ThreadId,
    plan: super::super::WeakInstalledConformancePlan,
    sources: [Rc<PacketCompleteSemanticSource>; 3],
    archive: CompleteOriginalRestorationSource,
    original_ticket_slots: [*const CompleteOriginalNativeTicket; 3],
    original_prepare_slots: *const [Id; 3],
    original_commit_slots: *const [Id; 3],
    original_activation_slot: *const ActivationRecord,
    group_partial:
        RefCell<Option<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>>,
    group: OnceCell<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>,
    targets_partial: [RefCell<Option<CompleteOriginalRestorationTransactionTarget>>; 3],
    targets: [OnceCell<CompleteOriginalRestorationTransactionTarget>; 3],
    runtime: OriginalRestorationRuntimeMemberIdentity,
    policy: OriginalRestorationConstructionPolicy,
    stage: Cell<WindowStage>,
    phase_in_flight: Cell<bool>,
    whole_observation: observation::OriginalRestorationWholeObservation,
    cold_requested_peak: usize,
    transaction_requested_peak: Cell<Option<usize>>,
    observed_other_retained: Cell<Option<usize>>,
    cold_partial: RefCell<Option<OriginalRestorationColdGroup>>,
    cold: OnceCell<OriginalRestorationColdGroup>,
    node_rows_partial: RefCell<[Option<OriginalRestorationNodeConstructionData>; 3]>,
    node_rows: OnceCell<[OriginalRestorationNodeConstructionData; 3]>,
    native_continuations:
        [Cell<Option<continuation::OriginalRestorationNativeContinuationIdentity>>; 3],
    final_construction: scope_storage::OriginalRestorationFinalConstructionData,
    activation_phases: [super::activation::OriginalInstalledRestorationActivationLedger; 3],
    activation_request_ids: OnceCell<[Id; 2]>,
    observation_request_ids: [OnceCell<Id>; 3],
    observation_phases: [super::observation::OriginalInstalledRestorationObservationLedger; 3],
    suffix_seeds: [continuation_suffix::SuffixLedger; 3],
    suffix_in_flight: Cell<bool>,
    context_started: Cell<bool>,
    context_issued: Cell<bool>,
    coordinator_construction: OnceCell<OriginalRestorationCoordinatorConstructionData>,
    coordinator17_construction:
        OnceCell<crate::node_contract::OriginalRestoredCoordinator17ConstructionData>,
    coordinator_target: OnceCell<ActivationRecord>,
    coordinator_owner: RefCell<coordinator_owner::OriginalRestorationCoordinatorOwner>,
    common_construction:
        OnceCell<crate::node_contract::OriginalRuntimeRestorationInstallationConstructionData>,
    paused_scheduler: RefCell<Option<crate::node_scheduling::PreparedSchedulingRestore>>,
    scheduler_started: Cell<bool>,
    install_started: Cell<bool>,
    world_roster: world_roster::OriginalRestorationWorldRoster,
    activation_world: OnceCell<crate::node_contract::WorldActivation>,
    scope_partial: RefCell<Option<scope_owner::OriginalRestorationScopeOwner>>,
    complete_scope: OnceCell<scope_owner::OriginalRestorationScopeOwner>,
}

impl InstalledConformancePlan {
    /// Names the explicit fixed views before the first restoration observation.
    ///
    /// # Errors
    /// Refuses checked layout overflow; this names DATA and issues no action.
    pub fn original_restoration_construction_counter_scratch_data() -> Result<usize, RuntimeError> {
        checked_sum(&[
            size_of::<OriginalRestorationConstructionScope<'static>>(),
            size_of::<OriginalRestorationMemberScope<'static>>(),
            size_of::<OriginalRestorationConstructionPolicy>(),
            2 * size_of::<OriginalRestorationConstructionStorage>(),
            size_of::<OriginalRestorationConstructionInputs<'static>>(),
            size_of::<OriginalRestorationNodeInputs<'static>>(),
            size_of::<OriginalRestorationSigningCollector<'static>>(),
            size_of::<OriginalRestorationNodeConstructionData>(),
            size_of::<[Option<OriginalRestorationNodeConstructionData>; 3]>(),
            size_of::<[usize; 3]>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<std::cell::Ref<'static, Option<OriginalRestorationColdGroup>>>(),
            size_of::<std::cell::RefMut<'static, Option<OriginalRestorationColdGroup>>>(),
            size_of::<std::cell::Ref<'static, [Option<OriginalRestorationNodeConstructionData>; 3]>>(),
            size_of::<std::cell::RefMut<'static, [Option<OriginalRestorationNodeConstructionData>; 3]>>(),
            size_of::<std::iter::Chain<std::iter::Flatten<std::slice::Iter<'static, Option<OriginalRestorationNodeConstructionData>>>, std::iter::Flatten<std::option::IntoIter<&'static [OriginalRestorationNodeConstructionData; 3]>>>>(),
            size_of::<Result<OriginalRestorationColdGroup, OriginalRestorationColdGroup>>(),
            size_of::<Result<[OriginalRestorationNodeConstructionData; 3], [OriginalRestorationNodeConstructionData; 3]>>(),
            size_of::<Result<OriginalRestorationNodeConstructionData, RuntimeError>>(),
            size_of::<Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError>>(),
            crate::node_contract::ConformanceRuntimeObservation::counter_scratch_data(),
            OriginalRestorationRuntimeMemberIdentity::counter_scratch_data(),
            CompleteOriginalRestorationTransactionTarget::counter_scratch_data(),
            CompleteOriginalRestorationWindow::phase_counter_scratch_data(),
            producer_execution::counter_scratch_data(),
            restored_capture::counter_scratch_data(),
            world_roster::counter_scratch_data()?,
            super::transaction_group::OriginalRestorationTransactionGroup::counter_scratch_data(),
            size_of::<super::target::OriginalRestorationTargetInputs>(),
            size_of::<Option<super::target::OriginalRestorationTargetInputs>>(),
            size_of::<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>(),
            size_of::<std::cell::Ref<'static, Option<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>>>(),
            size_of::<std::cell::RefMut<'static, Option<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>>>(),
            size_of::<std::cell::Ref<'static, Option<CompleteOriginalRestorationTransactionTarget>>>(),
            size_of::<std::cell::RefMut<'static, Option<CompleteOriginalRestorationTransactionTarget>>>(),
            size_of::<Result<CompleteOriginalRestorationTransactionTarget, CompleteOriginalRestorationTransactionTarget>>(),
            size_of::<Result<Rc<super::transaction_group::OriginalRestorationTransactionGroup>, Rc<super::transaction_group::OriginalRestorationTransactionGroup>>>(),
            size_of::<std::iter::Zip<std::slice::Iter<'static, RefCell<Option<CompleteOriginalRestorationTransactionTarget>>>, std::slice::Iter<'static, OnceCell<CompleteOriginalRestorationTransactionTarget>>>>(),
            OriginalRestorationColdGroup::counter_scratch_data(),
            installed_import::counter_scratch_data(),
            PacketCompleteSemanticSource::original_restoration_target_counter_scratch_data(),
            CompleteOriginalNativeTicket::original_restoration_journal_counter_scratch_data(),
            size_of::<OriginalRestorationNodeDispatch<'static>>(),
            size_of::<Result<OriginalRestorationNodeDispatch<'static>, RuntimeError>>(),
            crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::counter_scratch_bytes(),
            size_of::<crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics>(),
            PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
            PacketCompleteSemanticSource::original_restoration_signer_construction_counter_scratch_data(),
            CompleteOriginalRestorationWindow::continuation_counter_scratch_data(),
            scope_storage::OriginalRestorationFinalConstructionData::counter_scratch_data(),
            super::activation::OriginalInstalledRestorationActivationClaim::counter_scratch_data(),
            super::observation::OriginalInstalledRestorationObservationClaim::counter_scratch_data()?,
            observation_continuation::counter_scratch_data()?,
            continuation_suffix::OriginalRestoredSuffixConstructionData::counter_scratch_data(),
            PacketCompleteSemanticSource::original_restored_suffix_counter_scratch_data(),
            size_of::<[OnceCell<Id>; 3]>(),
            size_of::<Option<&Id>>(),
            size_of::<Result<Id, RuntimeError>>(),
            size_of::<Result<Id, crucible_node_contract::ContractError>>(),
            size_of::<Result<(), Id>>(),
            size_of::<std::slice::Iter<'static, OnceCell<Id>>>(),
            size_of::<String>(),
            size_of::<Result<(), std::collections::TryReserveError>>(),
            PacketCompleteSemanticSource::original_restoration_observation_source_construction_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restoration_observation_declaration_counter_scratch_data(),
            OriginalRestorationCoordinatorConstructionData::defining_counter_scratch_data(),
            crate::node_contract::OriginalRestoredCoordinator17ConstructionData::counter_scratch_data(),
            ConformanceRuntime::original_runtime_restoration_installation_counter_scratch_data()?,
            crate::node_scheduling::PreparedSchedulingRestore::original_retained_counter_scratch_data(),
            observation::owner_loan_result_counter_scratch_data::<Option<crate::node_scheduling::PreparedSchedulingRestore>>(),
            observation::owner_loan_result_counter_scratch_data::<coordinator_owner::OriginalRestorationCoordinatorOwner>(),
            PacketCompleteSemanticSource::original_restoration_activation_source_construction_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restoration_activation_declaration_counter_scratch_data(),
            size_of::<RefCell<Option<scope_owner::OriginalRestorationScopeOwner>>>(),
            size_of::<std::cell::Ref<'static, Option<scope_owner::OriginalRestorationScopeOwner>>>(),
            size_of::<std::cell::RefMut<'static, Option<scope_owner::OriginalRestorationScopeOwner>>>(),
            observation::owner_loan_result_counter_scratch_data::<Option<scope_owner::OriginalRestorationScopeOwner>>(),
            size_of::<host::OriginalRestorationHostContinuationInspection<'static>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<dispatch::RestorationDispatchAttempt<'static>>(),
            size_of::<observation::OriginalRestorationWholeObservation>(),
            observation::owner_loan_result_counter_scratch_data::<Option<OriginalRestorationColdGroup>>(),
            observation::owner_loan_result_counter_scratch_data::<[Option<OriginalRestorationNodeConstructionData>; 3]>(),
            observation::owner_loan_result_counter_scratch_data::<Option<Rc<super::transaction_group::OriginalRestorationTransactionGroup>>>(),
            observation::owner_loan_result_counter_scratch_data::<Option<CompleteOriginalRestorationTransactionTarget>>(),
            size_of::<Result<(), RuntimeError>>(),
        ], usize::MAX)
    }

    /// Admits only genuine grouped cold reconstruction on the same inactive target.
    ///
    /// The caller must place the returned owner in its permanent registered slot
    /// before invoking its cold constructor. No Prepare, upload, Commit, native
    /// restoration, final lineage context or execution permission is issued.
    ///
    /// # Errors
    /// Refuses unknown installed callbacks, foreign original custody or purpose,
    /// incomplete roster, unpriced owner/descriptor views or resource excess.
    pub fn reserve_original_restoration_cold_construction(
        &self,
        inputs: &OriginalRestorationConstructionInputs<'_>,
    ) -> Result<Rc<CompleteOriginalRestorationWindow>, RuntimeError> {
        inputs.authenticate_original_group_data()?;
        let scope = OriginalRestorationConstructionScope {
            plan: self,
            inputs,
            phase: OriginalRestorationConstructionPhase::ColdOwners,
            window: None,
        };
        let policy = self
            .0
            .authority
            .original_restoration_construction_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_restoration_construction_counter_scratch_data()?;
        if policy.maximum_requested_bytes == 0
            || policy.maximum_owned_descriptors == 0
            || fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let nested = inputs
            .runtime
            .original_restoration_group_counter_scratch_data(inputs, self)?;
        if checked_sum(&[fixed, nested], usize::MAX)? > policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        inputs
            .runtime
            .authenticate_original_restoration_target_data(
                inputs.archive,
                self,
                inputs.activation,
            )?;
        for index in 0..3 {
            inputs.sources[index].authenticate_original_restoration_target_data(
                inputs.tickets[index],
                inputs.archive,
                inputs.runtime.original_whole_owner_data()?,
                self,
                inputs.activation,
            )?;
        }
        let storage = self
            .0
            .authority
            .authenticate_original_restoration_construction(&self.evidence(), &scope, &policy)?;
        let requested = observe(&scope, policy, storage)?;
        let runtime = inputs
            .runtime
            .original_restoration_live_member_identity_data(
                inputs.archive,
                self,
                inputs.activation,
            )?;
        runtime.authenticate_current(&inputs.activation.world_binding_hash)?;
        let after = self
            .0
            .authority
            .authenticate_original_restoration_construction(&self.evidence(), &scope, &policy)?;
        if after != storage {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_current(&inputs.activation.world_binding_hash)?;
        let final_construction = scope_storage::OriginalRestorationFinalConstructionData::quote(
            inputs.archive,
            inputs.activation,
            policy.maximum_requested_bytes,
        )?;
        Ok(Rc::new(CompleteOriginalRestorationWindow {
            restored_captures: RefCell::new(restored_capture::Ledger::new()),
            restored_capture_in_flight: Cell::new(false),
            producer_executions: std::array::from_fn(|_| {
                RefCell::new(producer_execution::ProducerExecutionLedger::new())
            }),
            producer_publication: OnceCell::new(),
            producer_next_slot: Cell::new(0),
            producer_grant_work: std::array::from_fn(|_| Cell::new(None)),
            producer_grant_started: std::array::from_fn(|_| Cell::new(false)),
            process: std::process::id(),
            thread: std::thread::current().id(),
            plan: self.downgrade(),
            sources: std::array::from_fn(|index| Rc::clone(&inputs.sources[index])),
            archive: CompleteOriginalRestorationSource {
                inner: Rc::clone(&inputs.archive.inner),
            },
            original_ticket_slots: inputs.tickets.map(|ticket| ticket as *const _),
            original_prepare_slots: inputs.prepare_ids as *const _,
            original_commit_slots: inputs.commit_ids as *const _,
            original_activation_slot: inputs.activation as *const _,
            group_partial: RefCell::new(None),
            group: OnceCell::new(),
            targets_partial: std::array::from_fn(|_| RefCell::new(None)),
            targets: std::array::from_fn(|_| OnceCell::new()),
            runtime,
            policy,
            final_construction,
            activation_phases: std::array::from_fn(|_| {
                super::activation::OriginalInstalledRestorationActivationLedger::new()
            }),
            activation_request_ids: OnceCell::new(),
            observation_request_ids: std::array::from_fn(|_| OnceCell::new()),
            observation_phases: std::array::from_fn(|_| {
                super::observation::OriginalInstalledRestorationObservationLedger::new()
            }),
            suffix_seeds: std::array::from_fn(|_| continuation_suffix::SuffixLedger::new()),
            suffix_in_flight: Cell::new(false),
            initial_scheduling_work: std::array::from_fn(|_| Cell::new(None)),
            current_observations: std::array::from_fn(|_| {
                RefCell::new(current_observation::CurrentObservationLedger::new())
            }),
            context_started: Cell::new(false),
            context_issued: Cell::new(false),
            coordinator_construction: OnceCell::new(),
            coordinator17_construction: OnceCell::new(),
            coordinator_target: OnceCell::new(),
            coordinator_owner: RefCell::new(
                coordinator_owner::OriginalRestorationCoordinatorOwner::empty(),
            ),
            common_construction: OnceCell::new(),
            paused_scheduler: RefCell::new(None),
            scheduler_started: Cell::new(false),
            install_started: Cell::new(false),
            world_roster: world_roster::OriginalRestorationWorldRoster::new(),
            activation_world: OnceCell::new(),
            scope_partial: RefCell::new(None),
            complete_scope: OnceCell::new(),
            stage: Cell::new(WindowStage::ColdAdmitted),
            phase_in_flight: Cell::new(false),
            whole_observation: observation::OriginalRestorationWholeObservation::new_pending(),
            cold_requested_peak: requested,
            transaction_requested_peak: Cell::new(None),
            observed_other_retained: Cell::new(None),
            cold_partial: RefCell::new(None),
            cold: OnceCell::new(),
            node_rows_partial: RefCell::new(std::array::from_fn(|_| None)),
            node_rows: OnceCell::new(),
            native_continuations: std::array::from_fn(|_| Cell::new(None)),
        }))
    }
}

impl CompleteOriginalRestorationWindow {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive.inner.authenticate_birth()
    }

    fn authenticate_inputs(
        &self,
        plan: &InstalledConformancePlan,
        inputs: &OriginalRestorationConstructionInputs<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .is_same_original_plan_data(plan)
            || !Rc::ptr_eq(&self.archive.inner, &inputs.archive.inner)
            || self.original_activation_slot != inputs.activation as *const _
            || (0..3).any(|index| !Rc::ptr_eq(&self.sources[index], &inputs.sources[index]))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        inputs.authenticate_original_group_data()?;
        inputs
            .runtime
            .authenticate_original_restoration_target_data(
                inputs.archive,
                plan,
                inputs.activation,
            )?;
        self.runtime
            .authenticate_current(&inputs.activation.world_binding_hash)
    }

    /// Constructs the admitted cold owners after permanent holder retention.
    ///
    /// All partial outputs are installed in this window before construction.
    /// A busy loan, refusal or unwind leaves the same nonrenewing started phase.
    /// The whole post-construction observation runs after the mutable cold loan.
    ///
    /// # Errors
    /// Refuses an unregistered/repeated phase, changed original identity, failed
    /// grouped decoding or actual growth beyond the original cold allowance.
    pub fn construct_original_cold_owners(
        &self,
        plan: &InstalledConformancePlan,
        inputs: &OriginalRestorationConstructionInputs<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_inputs(plan, inputs)?;
        if self.stage.replace(WindowStage::ColdStarted) != WindowStage::ColdAdmitted {
            self.stage.set(WindowStage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_registered_member(plan, inputs)?;
        let _diagnostics = crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::begin();
        let scope = OriginalRestorationConstructionScope {
            plan,
            inputs,
            phase: OriginalRestorationConstructionPhase::ColdOwners,
            window: Some(self),
        };
        let storage = plan
            .0
            .authority
            .authenticate_original_restoration_construction(
                &plan.evidence(),
                &scope,
                &self.policy,
            )?;
        let before = observed_current(&scope, self.policy, storage)?;
        {
            let mut slot = self
                .cold_partial
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            OriginalRestorationColdGroup::retain_originals_into(
                inputs.archive,
                inputs.sources,
                &mut slot,
            )?;
            slot.as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .construct_original_group(inputs, before)?;
            // The immutable completed slot supports stable journal/terminal
            // loans without returning a reference through a dropped Ref guard.
            // Keep the mutable partial slot loan until set succeeds or the
            // actual owner has been put back; no callback lies in this move.
            let complete = slot.take().ok_or(RuntimeError::OwnerUnavailable)?;
            if let Err(complete) = self.cold.set(complete) {
                *slot = Some(complete);
                return Err(RuntimeError::DuplicateOperation);
            }
        }
        let storage = plan
            .0
            .authority
            .authenticate_original_restoration_construction(
                &plan.evidence(),
                &scope,
                &self.policy,
            )?;
        let after = observed_current(&scope, self.policy, storage)?;
        if after > self.cold_requested_peak {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_registered_member(plan, inputs)?;
        observation::authenticate_started_stage_data(&self.stage, WindowStage::ColdStarted)?;
        self.stage.set(WindowStage::ColdComplete);
        Ok(())
    }

    /// Admits the complete same-node transaction after real cold reconstruction.
    ///
    /// This independently repeats the installed policy and all actual owners,
    /// then quotes all three real nodes with their own Controller and Query.
    /// Source rows are retained before callbacks, and the cold mutable loan is
    /// gone before a whole-holder observation. No phase claim exists until the
    /// complete sum and terminal live-member checks pass.
    ///
    /// # Errors
    /// Refuses repeated/failed cold state, changed original policy, unsupported
    /// actual node/Source rows, incomplete owners or simultaneous resource excess.
    pub fn admit_original_transaction(
        &self,
        plan: &InstalledConformancePlan,
        inputs: &OriginalRestorationConstructionInputs<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_inputs(plan, inputs)?;
        if self.stage.replace(WindowStage::TransactionStarted) != WindowStage::ColdComplete {
            self.stage.set(WindowStage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        let scope = OriginalRestorationConstructionScope {
            plan,
            inputs,
            phase: OriginalRestorationConstructionPhase::Transaction,
            window: Some(self),
        };
        let policy = plan
            .0
            .authority
            .original_restoration_construction_policy(&plan.evidence(), &scope)?;
        if policy != self.policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let storage = plan
            .0
            .authority
            .authenticate_original_restoration_construction(&plan.evidence(), &scope, &policy)?;
        let current = observed_current(&scope, policy, storage)?;
        self.retain_original_activation_request_ids_data(inputs.activation)?;
        self.retain_original_observation_request_ids_data(inputs.activation, current)?;
        self.coordinator_target
            .set(inputs.activation.clone())
            .map_err(|_| RuntimeError::DuplicateOperation)?;
        let coordinator_target = self
            .coordinator_target
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let coordinator = OriginalRestorationCoordinatorConstructionData::quote(
            plan,
            inputs,
            coordinator_target,
            policy.maximum_requested_bytes,
        )?;
        self.coordinator_construction
            .set(coordinator)
            .map_err(|_| RuntimeError::DuplicateOperation)?;
        let common = inputs
            .runtime
            .original_runtime_restoration_installation_construction_data(
                inputs.archive.original_runtime_record_data()?,
                &inputs.archive.original_host_record_data()?.scheduling,
                coordinator_target,
                inputs.archive.content(),
                self.coordinator_construction
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                policy.maximum_requested_bytes,
            )?;
        self.common_construction
            .set(common)
            .map_err(|_| RuntimeError::DuplicateOperation)?;
        let limits = inputs.archive.original_archive_limits_data()?;
        {
            let cold = self.cold.get().ok_or(RuntimeError::OwnerUnavailable)?;
            for index in 0..3 {
                let selected = inputs.selected_inputs_data(index)?;
                let row = inputs.runtime.quote_original_restoration_signer_node_data(
                    &selected,
                    plan,
                    cold,
                    self.activation_request_ids
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    self.observation_request_ids[index].get(),
                    self.coordinator_construction
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    limits.state.maximum_record_bytes,
                    current,
                    policy.maximum_requested_bytes,
                )?;
                if row.signer.is_none()
                    || row.installed_custody.is_none()
                    || row.source_activation.is_none()
                    || row.restored_suffix.is_some() != row.source_observation.is_some()
                    || row.source_observation.is_some()
                        != self.observation_request_ids[index].get().is_some()
                {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                // A later quote/callback failure leaves every earlier actual
                // Source row and original SDK Weak association retained here.
                self.node_rows_partial
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?[index] = Some(row);
            }
        }
        {
            let mut partial = self
                .node_rows_partial
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let originals = std::mem::replace(&mut *partial, std::array::from_fn(|_| None));
            let complete = match originals {
                [Some(first), Some(second), Some(third)] => [first, second, third],
                originals => {
                    *partial = originals;
                    return Err(RuntimeError::OwnerUnavailable);
                }
            };
            if let Err(complete) = self.node_rows.set(complete) {
                *partial = complete.map(Some);
                return Err(RuntimeError::DuplicateOperation);
            }
        }
        let storage = plan
            .0
            .authority
            .authenticate_original_restoration_construction(&plan.evidence(), &scope, &policy)?;
        let requested = observe(&scope, policy, storage)?;
        let current = observed_current(&scope, policy, storage)?;
        self.authenticate_registered_member(plan, inputs)?;
        observation::authenticate_started_stage_data(&self.stage, WindowStage::TransactionStarted)?;
        self.transaction_requested_peak.set(Some(requested));
        // Future rows remain funded in requested. Constructors separately add
        // their own future row to this actual current owning observation.
        self.observed_other_retained.set(Some(current));
        self.stage.set(WindowStage::TransactionAdmitted);
        Ok(())
    }

    pub(super) fn authenticate_original_transfer_inputs_data(
        &self,
        archive: &CompleteOriginalRestorationSource,
        tickets: [&CompleteOriginalNativeTicket; 3],
        prepare_ids: &[Id; 3],
        commit_ids: &[Id; 3],
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.stage.get() != WindowStage::TransactionAdmitted
            || !Rc::ptr_eq(&self.archive.inner, &archive.inner)
            || self.original_prepare_slots != prepare_ids as *const _
            || self.original_commit_slots != commit_ids as *const _
            || (0..3).any(|index| self.original_ticket_slots[index] != tickets[index] as *const _)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for ticket in tickets {
            ticket.authenticate_source(archive)?;
        }
        // These addresses are only process-local equality witnesses before
        // the original move. They are never dereferenced or put on the wire.
        self.origin()
    }

    /// Moves the original fixed ticket and ID banks into this same admitted window.
    ///
    /// No replacement ticket or ID is accepted: the exact pre-move slots must
    /// equal those observed during admission. The group root is retained before
    /// its first move; partial failures keep every already-moved original there.
    ///
    /// # Errors
    /// Refuses an unadmitted/repeated phase, changed original slots, busy ownership
    /// or a source/plan/runtime member that no longer belongs to this window.
    pub fn retain_original_transaction_group(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
        tickets: &mut [Option<CompleteOriginalNativeTicket>; 3],
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_original_restoration_target_data(&self.archive, plan, activation)?;
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)?;
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)?;
        if self.group.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut group = self
            .group_partial
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        super::transaction_group::OriginalRestorationTransactionGroup::retain_originals_into(
            self,
            &self.archive,
            tickets,
            prepare_ids,
            commit_ids,
            &mut group,
        )?;
        let original = group.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(original) = self.group.set(original) {
            *group = Some(original);
            return Err(RuntimeError::DuplicateOperation);
        }
        drop(group);
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)
    }

    pub(super) fn authenticate_original_target_data(
        &self,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        runtime: &ConformanceRuntime,
        archive: &CompleteOriginalRestorationSource,
        ticket: &CompleteOriginalNativeTicket,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.stage.get() != WindowStage::TransactionAdmitted
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
            || !Rc::ptr_eq(&self.archive.inner, &archive.inner)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let group = self.group.get().ok_or(RuntimeError::OwnerUnavailable)?;
        group.authenticate_archive(archive)?;
        let mut selected = None;
        for index in 0..3 {
            if Rc::ptr_eq(&self.sources[index], source)
                && std::ptr::eq(group.ticket(index)?, ticket)
            {
                selected = Some(index);
            }
        }
        selected.ok_or(RuntimeError::ForeignAuthority)?;
        runtime.authenticate_original_restoration_target_data(archive, plan, activation)?;
        source.authenticate_original_restoration_target_data(
            ticket, archive, runtime, plan, activation,
        )?;
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)
    }

    /// Retains one same-node target before spending its original archive ledger.
    ///
    /// The immutable cold and transaction rows have already passed whole-window
    /// admission. This operation retains the destination before the runtime's
    /// actual once-only target binding; refusal keeps the same partial target.
    ///
    /// # Errors
    /// Refuses a foreign member, unadmitted group, repeated owner, busy target
    /// output or revoked runtime/Source/plan/activation association.
    pub fn bind_original_transaction_target(
        &self,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
        runtime: &mut ConformanceRuntime,
        activation: &ActivationRecord,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.stage.get() != WindowStage::TransactionAdmitted
            || self.original_activation_slot != activation as *const _
            || !self
                .sources
                .get(selected)
                .is_some_and(|original| Rc::ptr_eq(original, source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Even a retained partial binding changes the live coexistence bank.
        // Only the actual full observer may clear this transition boundary.
        self.whole_observation.require_observation();
        let complete = self
            .targets
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if complete.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let group = self.group.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let row = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_original_source_data(source)?;
        let mut pending = Some(super::target::OriginalRestorationTargetInputs {
            group: Rc::clone(group),
            selected,
            before_mapping: row.upload,
        });
        let mut output = self
            .targets_partial
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        CompleteOriginalRestorationTransactionTarget::bind_original_into(
            self,
            plan,
            source,
            runtime,
            &self.archive,
            activation,
            &mut pending,
            &mut output,
        )?;
        let original = output.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(original) = complete.set(original) {
            *output = Some(original);
            return Err(RuntimeError::DuplicateOperation);
        }
        drop(output);
        self.authenticate_registered_target_member(
            complete.get().ok_or(RuntimeError::OwnerUnavailable)?,
            source,
            plan,
            activation,
        )
    }

    fn authenticate_registered_target_identity(
        &self,
        target: &CompleteOriginalRestorationTransactionTarget,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let selected = target.selected_data();
        if self.stage.get() != WindowStage::TransactionAdmitted
            || self.original_activation_slot != activation as *const _
            || !self
                .sources
                .get(selected)
                .is_some_and(|original| Rc::ptr_eq(original, source))
            || !self
                .targets
                .get(selected)
                .and_then(OnceCell::get)
                .is_some_and(|original| std::ptr::eq(original, target))
            || !self
                .group
                .get()
                .is_some_and(|group| Rc::ptr_eq(group, target.group_data()))
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        target.authenticate_original_member_data(&self.runtime, plan, source, activation)?;
        Ok(())
    }

    fn authenticate_registered_target_member(
        &self,
        target: &CompleteOriginalRestorationTransactionTarget,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_registered_target_identity(target, source, plan, activation)?;
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        // This is the terminal genuine ticket ledger + scheduler liveness
        // check, not an association or runtime bank reborrow.
        target.authenticate_original_member_data(&self.runtime, plan, source, activation)
    }

    pub(super) fn authenticate_original_phase_member_data(
        &self,
        target: &CompleteOriginalRestorationTransactionTarget,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        target.authenticate_original_phase_data(phase)?;
        self.authenticate_registered_target_member(target, source, plan, activation)?;
        target.authenticate_original_phase_data(phase)
    }

    pub(super) fn authenticate_original_completed_member_data(
        &self,
        target: &CompleteOriginalRestorationTransactionTarget,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        target.authenticate_original_completed_data()?;
        self.authenticate_registered_target_member(target, source, plan, activation)?;
        target.authenticate_original_completed_data()
    }

    pub(super) fn original_signing_inputs_data<'a>(
        &'a self,
        target: &'a CompleteOriginalRestorationTransactionTarget,
        source: &'a Rc<PacketCompleteSemanticSource>,
        plan: &'a InstalledConformancePlan,
        activation: &'a ActivationRecord,
    ) -> Result<OriginalRestorationSigningInputs<'a>, RuntimeError> {
        self.origin()?;
        let selected = target.selected_data();
        let row = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let cold = self.cold.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let limits = self.archive.original_archive_limits_data()?;
        cold.original_signing_inputs_data(
            selected,
            source,
            target.ticket_data()?,
            plan,
            activation,
            target.mapping_data()?,
            row,
            target.prepare_id()?,
            target.commit_id()?,
            limits.state.maximum_record_bytes,
            self.observed_other_retained
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }

    pub(super) fn original_mapping_inputs_data<'a>(
        &'a self,
        target: &'a CompleteOriginalRestorationTransactionTarget,
        source: &'a Rc<PacketCompleteSemanticSource>,
        plan: &'a InstalledConformancePlan,
    ) -> Result<claim::OriginalRestorationMappingInputs<'a>, RuntimeError> {
        self.origin()?;
        let cold = self.cold.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let view =
            cold.original_owner_data(target.selected_data(), source, target.ticket_data()?)?;
        Ok(claim::OriginalRestorationMappingInputs {
            source,
            plan,
            host: view.host,
            native: view.native_after,
            host_reference: &view.journal.host_protocol,
            native_reference: &view.journal.native_after_protocol,
        })
    }

    pub(super) fn original_input_bodies_data<'a>(
        &'a self,
        target: &'a CompleteOriginalRestorationTransactionTarget,
    ) -> Result<[&'a [u8]; 6], RuntimeError> {
        self.origin()?;
        let source = self
            .sources
            .get(target.selected_data())
            .ok_or(RuntimeError::ForeignAuthority)?;
        let cold = self.cold.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let references = cold.original_restoration_references_data(
            target.selected_data(),
            source,
            target.ticket_data()?,
        )?;
        let body = |reference| {
            self.archive
                .content()
                .get(reference)
                .ok_or(RuntimeError::OwnerUnavailable)
        };
        Ok([
            body(references[0])?,
            body(references[1])?,
            body(references[2])?,
            body(references[3])?,
            body(references[4])?,
            target.normalization_data()?,
        ])
    }

    pub(super) fn authenticate_original_prepare_query_data(
        &self,
        target: &CompleteOriginalRestorationTransactionTarget,
        controller: &crucible_node_provider::client::CnpController,
        emitter: &crucible_node_provider::client::OriginalCanonicalBlobAckEmitter,
        query: &crucible_node_provider::client::OriginalFreshRestoreQuery,
    ) -> Result<(), RuntimeError> {
        let source = self
            .sources
            .get(target.selected_data())
            .ok_or(RuntimeError::ForeignAuthority)?;
        let references = self
            .cold
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_restoration_references_data(
                target.selected_data(),
                source,
                target.ticket_data()?,
            )?;
        target.authenticate_original_prepare_query_data(controller, emitter, query, references)
    }

    pub(super) fn authenticate_original_runtime_member_current_data(
        &self,
        world: &crucible_node_contract::HashRef,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.runtime.authenticate_current(world)
    }

    fn authenticate_registered_member(
        &self,
        plan: &InstalledConformancePlan,
        inputs: &OriginalRestorationConstructionInputs<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_inputs(plan, inputs)?;
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        // No generic callback follows this actual terminal liveness predicate.
        self.runtime
            .authenticate_current(&inputs.activation.world_binding_hash)
    }
}

#[path = "window/storage.rs"]
mod storage;
use storage::{checked_sum, observe, observed_current};

#[path = "window/transaction.rs"]
mod transaction;

#[path = "window/dispatch.rs"]
mod dispatch;
pub use dispatch::OriginalRestorationNodeDispatch;

impl CompleteOriginalRestorationWindow {
    /// Repeats the whole live observation after mutable transaction loans end.
    ///
    /// The original fixed group lends its SAME moved tickets/IDs. All actual
    /// partial/complete owners and conservative remaining future rows stay in
    /// the sum under the original installed policy. No failed requery can admit
    /// another phase: it permanently leaves the non-dispatchable checking stage.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete group, changed live runtime/Source/policy,
    /// busy actual owner or complete memory/descriptor excess. Failure does not
    /// drop, retry or reinterpret any partial or original ticket.
    pub fn recheck_original_transaction_inputs_data(
        &self,
        plan: &InstalledConformancePlan,
        sdks: [&crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        launches: &[crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;
             3],
        encoded_launches: [&[u8]; 3],
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.recheck_original_transaction_observed_inputs_data(
            plan,
            sdks,
            launches,
            encoded_launches,
            runtime.observation_data(),
            activation,
        )
    }

    /// Repeats the full census over genuine split wrapper/runtime owner loans.
    ///
    /// The writer calls this only after releasing every mutable owner loan.
    /// An observation view grants no stage transition or admission by itself.
    ///
    /// # Errors
    /// Refuses the same foreign, incomplete, busy, changed or excessive owners
    /// as the ordinary whole-wrapper entry; failed observations stay checking.
    pub(crate) fn recheck_original_transaction_observed_inputs_data(
        &self,
        plan: &InstalledConformancePlan,
        sdks: [&crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        launches: &[crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;
             3],
        encoded_launches: [&[u8]; 3],
        runtime: crate::node_contract::ConformanceRuntimeObservation<'_>,
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        if self.phase_in_flight.get() {
            self.stage.set(WindowStage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        if self.stage.replace(WindowStage::TransactionChecking) != WindowStage::TransactionAdmitted
        {
            self.stage.set(WindowStage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        let group = self.group.get().ok_or(RuntimeError::OwnerUnavailable)?;
        let journals = [
            group
                .ticket(0)?
                .original_restoration_journal_reference_data()?,
            group
                .ticket(1)?
                .original_restoration_journal_reference_data()?,
            group
                .ticket(2)?
                .original_restoration_journal_reference_data()?,
        ];
        let inputs = group.original_group_observed_inputs_data(
            &self.sources,
            sdks,
            launches,
            encoded_launches,
            runtime,
            activation,
            journals,
            0,
        )?;
        let installed = self.context_issued.get();
        if installed {
            inputs.authenticate_original_group_data()?;
            runtime.authenticate_original_installed_runtime_data(
                self,
                &self.archive,
                plan,
                activation,
            )?;
        } else {
            self.authenticate_inputs(plan, &inputs)?;
        }
        let scope = OriginalRestorationConstructionScope {
            plan,
            inputs: &inputs,
            phase: if installed {
                OriginalRestorationConstructionPhase::Installed
            } else {
                OriginalRestorationConstructionPhase::Transaction
            },
            window: Some(self),
        };
        let policy = plan
            .0
            .authority
            .original_restoration_construction_policy(&plan.evidence(), &scope)?;
        if policy != self.policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let storage = plan
            .0
            .authority
            .authenticate_original_restoration_construction(&plan.evidence(), &scope, &policy)?;
        let requested = observe(&scope, policy, storage)?;
        let high_water = phase_budget::observed_transaction_peak_data(
            self.policy,
            policy,
            self.transaction_requested_peak.get(),
            requested,
        )?;
        let current = observed_current(&scope, policy, storage)?;
        if installed {
            let member = OriginalRestorationMemberScope {
                plan,
                window: self,
                sources: &self.sources,
                publisher: None,
            };
            plan.0
                .authority
                .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
            runtime.authenticate_original_installed_runtime_data(
                self,
                &self.archive,
                plan,
                activation,
            )?;
        } else {
            self.authenticate_registered_member(plan, &inputs)?;
        }
        observation::authenticate_started_stage_data(
            &self.stage,
            WindowStage::TransactionChecking,
        )?;
        // No callback, allocation or I/O follows the terminal live fence.
        self.observed_other_retained.set(Some(current));
        self.transaction_requested_peak.set(Some(high_water));
        self.whole_observation.complete_observation();
        self.stage.set(WindowStage::TransactionAdmitted);
        Ok(requested)
    }
}

#[path = "window/continuation.rs"]
mod continuation;
pub use continuation::OriginalRestorationNodeContinuationInspection;

#[path = "window/observation.rs"]
pub(super) mod observation;

#[path = "window/host.rs"]
mod host;
pub use host::OriginalRestorationHostContinuationInspection;

#[path = "window/complete_scope.rs"]
mod complete_scope;
#[path = "window/scope_owner.rs"]
mod scope_owner;
#[path = "window/scope_storage.rs"]
mod scope_storage;

#[path = "window/activation.rs"]
mod activation;

#[path = "window/installed_context.rs"]
mod installed_context;

#[path = "window/coordinator_projection.rs"]
mod coordinator_projection;
#[path = "window/coordinator_storage.rs"]
mod coordinator_storage;
pub use coordinator_storage::OriginalRestorationCoordinatorConstructionData;

#[path = "window/coordinator_owner.rs"]
mod coordinator_owner;

impl OriginalRestorationConstructionScope<'_> {
    /// Checks the same genuine runtime for this intrinsic construction phase.
    ///
    /// # Errors
    /// Refuses another window/archive/plan/target, an unissued installed context,
    /// changed actual owner identities or revoked scheduler custody.
    pub fn authenticate_original_runtime_data(&self) -> Result<(), RuntimeError> {
        if self.phase == OriginalRestorationConstructionPhase::Installed {
            self.inputs
                .runtime
                .authenticate_original_installed_runtime_data(
                    self.window.ok_or(RuntimeError::OwnerUnavailable)?,
                    self.inputs.archive,
                    self.plan,
                    self.inputs.activation,
                )
        } else {
            self.inputs
                .runtime
                .authenticate_original_restoration_target_data(
                    self.inputs.archive,
                    self.plan,
                    self.inputs.activation,
                )
        }
    }
}

#[path = "window/common_install.rs"]
mod common_install;

#[path = "window/world_roster.rs"]
mod world_roster;

impl OriginalRestorationConstructionScope<'_> {
    /// Borrows the same concrete future coordinator row when its quote exists.
    ///
    /// Absence during cold/initial current observation authorizes no publication.
    /// A final transaction observer must retain its own concrete publisher row.
    pub fn coordinator_construction_data(
        &self,
    ) -> Option<&OriginalRestorationCoordinatorConstructionData> {
        self.window?.coordinator_construction.get()
    }
}

impl OriginalRestorationMemberScope<'_> {
    /// Distinguishes a publication-member check from other bank-free phases.
    pub fn is_original_publication_member_data(&self) -> bool {
        self.publisher.is_some()
    }

    /// Compares the actual trusted publisher allocation for this single check.
    ///
    /// A matching address is only one member predicate. It grants no budget,
    /// publication outcome, context, activation or right to dispatch a callback.
    pub fn is_original_publisher_data(&self, actual: *const ()) -> bool {
        self.publisher.is_some_and(|publisher| publisher == actual)
    }
}

#[path = "window/phase_budget.rs"]
mod phase_budget;

#[path = "window/observation_effect.rs"]
mod observation_effect;
#[path = "window/observation_ids.rs"]
mod observation_ids;

#[path = "window/observation_continuation.rs"]
mod observation_continuation;

#[path = "window/continuation_suffix.rs"]
mod continuation_suffix;
pub(crate) use continuation_suffix::{
    OriginalRestoredSuffixCheckpointData, OriginalRestoredSuffixConstructionData,
    OriginalRestoredSuffixSeedClaim,
};

#[path = "window/current_observation.rs"]
mod current_observation;
pub use current_observation::{
    OriginalRestoredInitialSchedulingAdmission, OriginalRestoredSchedulingObservationAdmission,
    OriginalRestoredSchedulingObservationClaim,
    OriginalRestoredSchedulingObservationConstructionData,
};

#[path = "window/producer_execution.rs"]
mod producer_execution;
pub use producer_execution::{
    OriginalRestoredProducerExecutionAdmission, OriginalRestoredProducerExecutionClaim,
    OriginalRestoredProducerExecutionConstructionData,
    OriginalRestoredProducerPublisherConstructionScope,
};

pub(crate) use producer_execution::ProducerExecutionPhase;

#[path = "window/installed_import.rs"]
mod installed_import;

#[path = "window/input17_construction.rs"]
mod input17_construction;
pub use input17_construction::OriginalRestoredInput17ConstructionData;
#[path = "window/restored_capture.rs"]
mod restored_capture;
pub use restored_capture::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureRequestData};
pub(crate) use restored_capture::{
    OriginalRestoredCaptureImportedOwnerInputs, OriginalRestoredCaptureSigningInputs,
};

#[path = "window/coordinator17.rs"]
mod coordinator17;
