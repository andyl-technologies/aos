//! Pays the first original Q04 entry from its disjoint image subdivision.
//!
//! Q is already Reserved in the inclusive Controller account. This owner
//! prices the whole retained observer allowance before attachment and commits
//! that same Q once. The actual Project preparation retains this owner through
//! terminal posts and LAST; closed or abandoned rows never become free credit.

use std::sync::{Arc, Mutex};

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1;

use crate::journal::{JournalShape, ProtectedJournalNamesV1};
use crate::cache_programmes::OriginalQ04CachePreflightLoanV1;
use super::bank::FAILURE_MEMORY_BYTES;
use super::service_interval::{
    ObserverAdmission, ObserverLifetime, OriginalReceiver, capacity_for, multiply,
};
use super::{
    AccountTransition, ClaimPurpose, ClaimState, ControllerResourceBankOpeningV1,
    ResourceReservationErrorV1, ReturnedAppend, bank, bootstrap,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::{Journal, JournalError};

// This is only the proved entrance lower bound through HELLO: preparation's
// producer/post (3), existing enrolled arm (4), outer profile (1), connect
// (5), Query write (2), one HELLO receive (10), and HELLO acceptance (2).
// It is not a completion bound. Further progress and every AGAIN/Interrupted
// observation consume the same prepaid retained-row quota before growth.
const ENTRANCE_OBSERVER_ROWS: usize = aos_sandbox_broker::controller_receiving::bank_launch::
    ControllerReservedObserverOriginalV1::Q04_ENTRANCE_OBSERVER_ROWS;

// Actual J: the entry producer observes twice, each of the two closed Native
// crossings observes its original producer twice (four rows), and the final
// profile post observes once. This pays only entry; later stages must extend
// the same ledger before their actual capture and retained observer growth.
const CREATE_ENTRY_OBSERVER_ROWS: usize = aos_sandbox_broker::controller_receiving::bank_launch::
    ControllerCreateContinuationLedgerOriginalV1::INITIAL_OBSERVER_ROWS;

pub(super) fn native_layout() -> super::bank::NativeLayoutDemand {
    // An unrepresentable actual provider plane makes the existing minimum
    // demand reject; it never falls back to a cheaper construction recipe.
    let create = match create_intake_control_bytes() {
        Some(bytes) => bytes,
        None => usize::MAX,
    };
    super::bank::NativeLayoutDemand::new(
        std::mem::size_of::<Q04OriginalIntakeAttemptV1>(),
        std::mem::size_of::<crate::ProjectPreparationReservationAttemptV1>(),
    )
    .with_create_intake(create)
}

fn create_intake_entry_bytes() -> usize {
    std::mem::size_of::<(
        super::CreateContinuationIntakeAttemptV1,
        CreateIntakeBankOriginalsV1<'_>, super::CreateIntakeBankAppendV1<'_>,
        Option<Result<(), crate::reconciler::EffectFailure>>,
        Option<Result<(), ResourceReservationErrorV1>>,
    )>()
}

fn create_intake_control_bytes() -> Option<usize> {
    use aos_sandbox_broker::controller_receiving::bank_launch::{
        ControllerCreateContinuationLedgerOriginalV1 as Original,
        ControllerCreateContinuationFundingLoanV1 as Loan,
        ControllerCreateContinuationClosedV1 as Closed,
    };

    std::mem::size_of::<(
        Loan<'_, '_>, Result<Loan<'_, '_>, Closed>,
        Result<Loan<'_, '_>, ResourceReservationErrorV1>,
        Result<Original, ResourceReservationErrorV1>,
        Result<aos_sandbox_broker::controller_receiving::bank_launch::
            ControllerReservedObserverOriginalV1, ResourceReservationErrorV1>,
    )>().checked_add(Original::receiving_construction_bytes_v1()?)?
        .checked_add(aos_sandbox_broker::controller_receiving::profile::
            ControllerCreateIntakeObserverGrowthLoanV1::receiving_construction_bytes_v1()?)?
        .checked_add(std::mem::size_of::<Result<
            aos_sandbox_broker::controller_receiving::profile::
                ControllerCreateIntakeObserverGrowthLoanV1<'_, '_>,
            ResourceReservationErrorV1,
        >>().checked_mul(2)?)?
        .checked_add(create_intake_entry_bytes())
}

pub(super) fn minimum_failure_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
    super::bank::minimum_q04_failure_demand(native_layout())
        .map_err(ResourceReservationErrorV1::from)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IntakePurpose {
    Q04,
    CreateContinuation,
}

// Names actual retained stage owners, not freely chosen grants. The private
// Ready coordinator derives complete bounds from its live typed role loans.
#[derive(Clone, Copy)]
pub(super) enum CreateContinuationCaptureOwnerV1 {
    ControllerIntent,
    SourceHeld,
    CacheHeld,
    Ownership,
    StorageInventory,
    RootExchange,
    Observers,
    HistoryNames,
    AssignmentPlanned,
    StorageClientSession,
    ReadyBundle,
}

mod continuation;

pub(super) struct Q04OriginalIntakeAttemptV1 {
    purpose: IntakePurpose,
    parent_lane: Option<Result<[u8; 16], ResourceReservationErrorV1>>,
    parent_owners: Option<Result<(), ResourceReservationErrorV1>>,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    original: Option<Result<aos_sandbox_broker::receiving::OriginalEnrollment, ResourceReservationErrorV1>>,
    receiver: Option<Result<OriginalReceiver, ResourceReservationErrorV1>>,
    source_shape: Option<JournalShape>,
    observation_capacity: Option<usize>,
    continuation: Option<Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateContinuationLedgerOriginalV1,
        ResourceReservationErrorV1>>,
    continuation_growth: Option<Result<(), crate::normal_root::CreateIntakeObserverGrowthErrorV1>>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    initial_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cpu: FirstGlobalCpuReadbackV1,
    append: ReturnedAppend,
    controller_post: Option<Result<(), JournalError>>,
    source_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<(), NormalRootStartupErrorV1>>,
    cpu_post: Option<Result<(), NormalRootStartupErrorV1>>,
    last_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_post: Option<Result<(), SourceGenesisErrorV1>>,
    lifetime: Option<ObserverLifetime>,
    observer_origin: Option<Result<aos_sandbox_broker::controller_receiving::bank_launch::
        ControllerReservedObserverOriginalV1, ResourceReservationErrorV1>>,
    attempted: bool,
    first: Option<FailureSite>,
}

// These fields borrow the actual once-entered engine reservoirs. Construction
// stays inside prepare_body after its genuine original and bounded admission.
// The lower bank-append loan cannot replace any field with decoded row DATA.
pub(super) struct CreateIntakeBankOriginalsV1<'entry> {
    bank: &'entry Arc<Mutex<ControllerResourceBankOpeningV1>>,
    original: &'entry Option<Result<aos_sandbox_broker::receiving::OriginalEnrollment, ResourceReservationErrorV1>>,
    receiver: &'entry Option<Result<OriginalReceiver, ResourceReservationErrorV1>>,
    capacity: &'entry Option<usize>,
    lane: &'entry Option<Result<[u8; 16], ResourceReservationErrorV1>>,
    parent_owners: &'entry Option<Result<(), ResourceReservationErrorV1>>,
    clock: &'entry Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cpu: &'entry FirstGlobalCpuReadbackV1,
    lifetime: &'entry Option<ObserverLifetime>,
    purpose: &'entry IntakePurpose,
    attempted: &'entry bool,
    profile: &'entry ProductionControllerNormalRootProfileV1,
    source: &'entry ProtectedSourceDomainJournalOwnerV1,
}

impl CreateIntakeBankOriginalsV1<'_> {
    pub(super) fn require_current(
        &self,
        parent: &super::ProjectPreparationReservationAttemptV1,
        transition: &AccountTransition,
        state: &super::State,
    ) -> Result<(), JournalError> {
        use super::create_intake_append::native_error;

        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let clock = self.clock.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let provision = original.policy.bootstrap_provisions().create_continuation_intake
            .ok_or(JournalError::ProtectedBoundary)?;
        let previous = transition.previous_claim.ok_or(JournalError::ProtectedBoundary)?;
        let id = original.identity.account_id(b"controller-create-continuation-intake-v1");
        let expected = bank::settled_pair(transition.before, previous, true).map_err(native_error)?;
        if *self.purpose != IntakePurpose::CreateContinuation || !*self.attempted
            || self.parent_owners.as_ref().is_none_or(Result::is_err)
            || self.receiver.as_ref().is_none_or(Result::is_err)
            || self.capacity.is_none_or(|capacity| capacity < CREATE_ENTRY_OBSERVER_ROWS)
            || self.cpu.failure().is_some()
            || super::service_interval::require_controller_head_cpu(&self.cpu, transition.before, original).is_err()
            || clock.host_boot_id() != original.identity.native_fields().boot
            || transition.original_clock != Some(*clock)
            || transition.before.native_fields().enrollment != original.identity
            || previous.native_fields().enrollment != original.identity
            || previous.native_fields().id != id
            || previous.native_fields().account != original.identity.account_id(b"controller")
            || previous.native_fields().purpose != ClaimPurpose::CreateContinuationIntake
            || previous.native_fields().state != ClaimState::Reserved
            || previous.native_fields().cut != super::ClaimCut::BootLifetime
            || previous.native_fields().amount != provision
            || (transition.after, transition.claim) != expected
            || transition.child.is_some() || transition.preparation.is_some() || transition.terminal.is_some()
            || self.lane.as_ref().and_then(|result| result.as_ref().ok()).copied()
                != Some(parent.create_continuation_lane(self.bank).map_err(native_error)?)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let lifetime = self.lifetime.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.profile.require_create_intake_original(lifetime).map_err(native_error)?;
        parent.require_create_continuation_state(state).map_err(native_error)
    }

    pub(super) fn require_native_position(
        &self,
        parent: &super::ProjectPreparationReservationAttemptV1,
        journal: &Journal,
    ) -> Result<(), JournalError> {
        use super::create_intake_append::native_error;

        parent.require_create_continuation_owners(journal, self.source, self.profile)
            .map_err(native_error)?;
        parent.require_create_continuation_position(journal).map_err(native_error)?;
        let lifetime = self.lifetime.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.profile.require_create_intake_original(lifetime).map_err(native_error)?;
        let actual = {
            let bank = self.bank.try_lock().map_err(|_| JournalError::ProtectedBoundary)?;
            let identity = bank.require_enrolled(journal, self.profile).map_err(native_error)?;
            let original = bank.first_global_original(journal).map_err(native_error)?;
            if identity != original.identity {
                return Err(JournalError::ProtectedBoundary);
            }
            original
        };
        if self.original.as_ref().and_then(|result| result.as_ref().ok()) != Some(&actual) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .require_same(journal, self.source, self.profile).map_err(native_error)?;
        parent.require_create_continuation_owners(journal, self.source, self.profile)
            .map_err(native_error)?;
        parent.require_create_continuation_position(journal).map_err(native_error)
    }
}

#[derive(Clone, Copy)]
enum FailureSite {
    Original,
    Parent,
    ParentOwners,
    Receiver,
    InitialClock,
    Cpu,
    Append,
    Preparation,
    ControllerPost,
    SourcePost,
    ProfilePost,
    CpuPost,
    LastClock,
    ClockPost,
}

impl Q04OriginalIntakeAttemptV1 {
    pub(super) fn begin(bank: Arc<Mutex<ControllerResourceBankOpeningV1>>) -> Self {
        Self {
            purpose: IntakePurpose::Q04,
            parent_lane: None,
            parent_owners: None,
            bank, original: None, receiver: None, source_shape: None,
            observation_capacity: None, continuation: None,
            continuation_growth: None, preparation: None,
            initial_clock: None, cpu: FirstGlobalCpuReadbackV1::default(),
            append: ReturnedAppend::new(), controller_post: None, source_post: None,
            profile_post: None, cpu_post: None, last_clock: None, clock_post: None,
            lifetime: None, observer_origin: None, attempted: false, first: None,
        }
    }

    pub(super) fn prepare_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &mut OriginalQ04CachePreflightLoanV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.prepare_with_parent(controller, source, profile, None, Some(cache))
    }

    pub(super) fn begin_create(bank: Arc<Mutex<ControllerResourceBankOpeningV1>>) -> Self {
        let mut owner = Self::begin(bank);
        owner.purpose = IntakePurpose::CreateContinuation;
        owner
    }

    pub(super) fn same_bank(&self, bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>) -> bool {
        Arc::ptr_eq(&self.bank, bank)
    }

    pub(super) fn prepare_create_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        parent: &super::ProjectPreparationReservationAttemptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.prepare_with_parent(controller, source, profile, Some(parent), None)
    }

    fn prepare_with_parent(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        parent: Option<&super::ProjectPreparationReservationAttemptV1>,
        mut cache: Option<&mut OriginalQ04CachePreflightLoanV1<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.attempted {
            self.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;
        self.original = Some(self.bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
            .and_then(|mut bank| match self.purpose {
                IntakePurpose::Q04 => bank.begin_q04_intake_once(),
                IntakePurpose::CreateContinuation => bank.begin_create_intake_once(),
            }));
        if !matches!(self.original, Some(Ok(_))) {
            // No genuine intake original was acquired. Park its first cause and refuse
            // before any receiver, kernel/profile observation or raw clock.
            self.first = Some(FailureSite::Original);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.purpose == IntakePurpose::CreateContinuation {
            self.parent_lane = Some(parent.ok_or(ResourceReservationErrorV1::Conflict)
                .and_then(|parent| parent.create_continuation_lane(&self.bank)));
            if !matches!(self.parent_lane, Some(Ok(_))) {
                self.first = Some(FailureSite::Parent);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.parent_owners = Some(parent.ok_or(ResourceReservationErrorV1::Conflict)
                .and_then(|parent| parent.require_create_continuation_owners(controller, source, profile)));
            if !matches!(self.parent_owners, Some(Ok(()))) {
                self.first = Some(FailureSite::ParentOwners);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        } else if parent.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiver = Some(OriginalReceiver::capture(controller, source, profile));
        self.preparation = Some(self.prepare_body(controller, source, profile, parent, cache.as_deref_mut()));
        self.first = if matches!(self.original, Some(Err(_))) {
            Some(FailureSite::Original)
        } else if matches!(self.receiver, Some(Err(_))) {
            Some(FailureSite::Receiver)
        } else if matches!(self.initial_clock, Some(Err(_))) {
            Some(FailureSite::InitialClock)
        } else if self.cpu.failure().is_some() {
            Some(FailureSite::Cpu)
        } else if self.append.failure().is_some() {
            Some(FailureSite::Append)
        } else if matches!(self.preparation, Some(Err(_))) {
            Some(FailureSite::Preparation)
        } else {
            None
        };

        // Available original posts run even after native Err; no bank lock
        // spans them. An unattached intake cannot fall back to P/I/Ordinary.
        self.controller_post = Some(controller.validate_held_protected_names());
        self.source_post = Some(source.journal().validate_held_protected_names());
        self.profile_post = Some(match self.purpose {
            IntakePurpose::Q04 => profile.recheck_q04_intake_profile(),
            IntakePurpose::CreateContinuation => profile.recheck_create_intake_profile(),
        });
        self.cpu_post = Some(profile.recheck_first_global_cpu(&mut self.cpu));
        self.last_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        self.clock_post = Some(match (
            self.initial_clock.as_ref().and_then(|result| result.as_ref().ok()),
            self.last_clock.as_ref().and_then(|result| result.as_ref().ok()),
        ) {
            (Some(before), Some(after)) => before.validate_later_sample(*after)
                .map_err(|_| SourceGenesisErrorV1::Stale),
            _ => Err(SourceGenesisErrorV1::Stale),
        });
        if self.first.is_none() {
            self.first = if matches!(self.controller_post, Some(Err(_))) {
                Some(FailureSite::ControllerPost)
            } else if matches!(self.source_post, Some(Err(_))) {
                Some(FailureSite::SourcePost)
            } else if matches!(self.profile_post, Some(Err(_))) {
                Some(FailureSite::ProfilePost)
            } else if matches!(self.cpu_post, Some(Err(_))) {
                Some(FailureSite::CpuPost)
            } else if matches!(self.last_clock, Some(Err(_))) {
                Some(FailureSite::LastClock)
            } else if matches!(self.clock_post, Some(Err(_))) {
                Some(FailureSite::ClockPost)
            } else {
                None
            };
        }
        if self.failure().is_some() {
            self.close();
            Err(ResourceReservationErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    fn prepare_body(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        parent: Option<&super::ProjectPreparationReservationAttemptV1>,
        mut cache: Option<&mut OriginalQ04CachePreflightLoanV1<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let (provision, purpose, role): (_, _, &[u8]) = match self.purpose {
            IntakePurpose::Q04 => (original.policy.bootstrap_provisions().q04_original_intake,
                ClaimPurpose::Q04OriginalIntake, b"controller-q04-original-intake-v1"),
            IntakePurpose::CreateContinuation => (original.policy.bootstrap_provisions().create_continuation_intake,
                ClaimPurpose::CreateContinuationIntake, b"controller-create-continuation-intake-v1"),
        };
        let provision = provision.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let id = original.identity.account_id(role);
        let state = controller.controller_resource_state_v1()?;
        let claim = super::Claim::decode(
            bank::claim_bytes(state, id).ok_or(ResourceReservationErrorV1::Conflict)?,
        )
        .map_err(ResourceReservationErrorV1::from)?;
        if claim.native_fields().purpose != purpose
            || claim.native_fields().enrollment != original.identity
            || claim.native_fields().amount != provision
            || claim.native_fields().state != ClaimState::Reserved
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut transition = AccountTransition::settle(
            bank::find_head(state, claim.native_fields().account)
                .map_err(ResourceReservationErrorV1::from)?,
            claim,
            true,
        )?;
        self.source_shape = Some(source.journal().first_global_allocation_shape_v1()?);
        let fixed = fixed_demand(&controller.first_global_allocation_shape_v1()?,
            self.source_shape.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
            provision, self.purpose, cache.as_deref_mut())?;
        let capacity = match self.purpose {
            IntakePurpose::Q04 => {
                let row = ProductionControllerNormalRootProfileV1::first_global_observer_demand()?;
                let capacity = capacity_for(provision.checked_sub(fixed)?, row)?;
                if capacity < ENTRANCE_OBSERVER_ROWS {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                provision.checked_sub(fixed.checked_add(multiply(row, capacity)?)?)?;
                capacity
            }
            IntakePurpose::CreateContinuation => {
                // This is the genuine already-Reserved J provision, selected
                // above from the original enrollment and its exact native claim.
                // Keep the same ledger for every later entered J stage; the
                // entrance archive cannot consume unentered future capacity.
                let row = ProductionControllerNormalRootProfileV1::create_intake_observer_demand()?;
                let observers = multiply(row, CREATE_ENTRY_OBSERVER_ROWS)?;
                self.continuation = Some(self.bank.lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                    .and_then(|bank| bank.begin_create_continuation_ledger_v1(controller, profile, fixed, observers)));
                self.continuation.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?
                    .require_initial_reserved_v1()?;
                CREATE_ENTRY_OBSERVER_ROWS
            }
        };
        self.observation_capacity = Some(capacity);
        if let Some(cache) = cache.as_deref_mut() {
            cache.require_shape().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        }

        // All admitted archive rows and the fixed proof/CPU/native originals
        // have a genuine already-Reserved payer before the first new capture.
        // The whole Controller owns this native rate once. Q/J are disjoint
        // suballocations under it; neither child must fund the whole cgroup.
        // The actual native observation still precedes archive growth.
        profile.observe_first_global_cpu(&mut self.cpu)?;
        super::service_interval::require_controller_head_cpu(&self.cpu, transition.before, original)?;
        self.initial_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        let clock = self.initial_clock.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        if clock.host_boot_id() != original.identity.native_fields().boot {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.lifetime = Some(match self.purpose {
            IntakePurpose::Q04 => {
                self.observer_origin = Some(self.bank.lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                    .and_then(|bank| bank.begin_q04_observers_v1(controller, profile, fixed)));
                let observers = self.observer_origin.as_ref()
                    .and_then(|returned| returned.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if observers.capacity_data_v1() != capacity {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                observers.lifetime_v1()
            },
            IntakePurpose::CreateContinuation => {
                let continuation = self.continuation.as_mut()
                    .and_then(|value| value.as_mut().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                self.observer_origin = Some(self.bank.lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                    .and_then(|bank| bank.begin_create_continuation_observers_v1(
                        controller, profile, continuation,
                    )));
                let observers = self.observer_origin.as_ref()
                    .and_then(|returned| returned.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if observers.capacity_data_v1() != capacity {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                observers.lifetime_v1()
            }
        });
        let lifetime = self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let admission = match self.purpose {
            IntakePurpose::Q04 => ObserverAdmission::for_q04_intake(profile, original, capacity, lifetime),
            IntakePurpose::CreateContinuation => ObserverAdmission::for_create_intake(profile, original, capacity, lifetime),
        };
        let origin = match self.observer_origin.take() {
            Some(Ok(origin)) => origin,
            retained => {
                self.observer_origin = retained;
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        match self.purpose {
            IntakePurpose::Q04 => profile.attach_q04_intake_observers(&admission, origin)?,
            IntakePurpose::CreateContinuation => profile.attach_create_intake_observers(&admission, origin)?,
        }
        let (recipient, producer) = profile.require_resource_producer()?;
        if recipient != original.recipient_invocation
            || producer != original.identity.native_fields().invocation
            || self
                .bank
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .first_global_original(controller)?
                != *original
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_same(controller, source, profile)?;
        if let Some(parent) = parent {
            parent.require_create_continuation_replay(controller)?;
        }
        transition.original_clock = Some(clock);
        match (self.purpose, parent) {
            (IntakePurpose::CreateContinuation, Some(parent)) => {
                let entry = CreateIntakeBankOriginalsV1 {
                    bank: &self.bank,
                    original: &self.original,
                    receiver: &self.receiver,
                    capacity: &self.observation_capacity,
                    lane: &self.parent_lane,
                    parent_owners: &self.parent_owners,
                    clock: &self.initial_clock,
                    cpu: &self.cpu,
                    lifetime: &self.lifetime,
                    purpose: &self.purpose,
                    attempted: &self.attempted,
                    profile,
                    source,
                };
                self.append.append_create_intake_into(controller, Ok(transition), parent, entry);
            }
            (IntakePurpose::Q04, None) => {
                // This is the same exclusive original loan priced above. The
                // actual initializer retains this second independent comparison.
                cache.as_deref_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                    .require_shape().map_err(|_| ResourceReservationErrorV1::Conflict)?;
                self.append.append_into(controller, Ok(transition));
            }
            _ => return Err(ResourceReservationErrorV1::Conflict),
        }
        self.append.require_committed()?;
        self.receiver.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.controller_sequence = controller.snapshot_sequence();
        if self.purpose == IntakePurpose::CreateContinuation {
            let continuation = self.continuation.as_mut().and_then(|value| value.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_create_continuation_committed_v1(controller, profile, continuation)?;
        }
        Ok(())
    }

    pub(super) fn require_original(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let lifetime = self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        match self.purpose {
            IntakePurpose::Q04 => profile.require_q04_intake_original(lifetime)?,
            IntakePurpose::CreateContinuation => profile.require_create_intake_original(lifetime)?,
        }
        self.append.require_committed().map(|_| ())
    }

    pub(super) fn require_create_storage_association(&self, controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, profile: &ProductionControllerNormalRootProfileV1)
        -> Result<(), ResourceReservationErrorV1>
    {
        if self.purpose != IntakePurpose::Q04 || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.append.require_committed()?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_create_storage_association(controller, source, profile)
    }

    pub(super) fn require_create_storage_names(&self, controller: ProtectedJournalNamesV1,
        source: ProtectedJournalNamesV1) -> Result<(), ResourceReservationErrorV1>
    {
        if self.purpose != IntakePurpose::Q04 || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.append.require_committed()?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_create_storage_names(controller, source)
    }

    pub(super) fn require_continuation_owners(
        &self,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.purpose != IntakePurpose::Q04 || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed()?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_same_owners_after_q04(controller, source, profile)
    }

    pub(super) fn require_retained_capture(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || self.purpose != IntakePurpose::CreateContinuation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed().map(|_| ())
    }

    // This is private accounting under the SAME already-entered J original,
    // not an account factory. Actual role-loan callers rejoin C/Source/profile
    // and derive their own complete shape before this boundary. All accepted
    // earlier owners stay charged; a failure closes this original lifetime.
    pub(super) fn reserve_create_capture_complete(
        &mut self,
        owner: CreateContinuationCaptureOwnerV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        self.reserve_continuation_complete_v1(owner, complete)
    }

    // The typed successful ReturnedAppend is checked by the private Ready
    // caller before this genuine same-J/native reserve-publication factory.
    pub(in crate::controller_resource_reservation) fn begin_returned_storage_use_receiving_v1(
        &mut self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        binding: bank::CreateStorageUseBindingV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::
        ControllerCreateStorageUseReceivingOriginalV1, ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        self.require_original(profile)?;
        controller.controller_coordinator_for_bank_v1()?
            .begin_create_storage_use_receiving_once_v1(
                self.continuation_original_mut_v1()?, profile.lower_original_v1(), binding,
            ).map_err(Into::into)
    }

    // Only the private actual RootValidated producer adds to this original
    // RootExchange highwater. Earlier still-resident Root flights remain paid;
    // a new smaller pair recipe cannot substitute for their existing charge.
    pub(super) fn reserve_root_validated_capture_once(
        &mut self, additional: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        self.continuation_original_mut_v1()?.reserve_root_additional_v1(additional)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    // Later exclusive purpose borrows may reuse only the same original's
    // actually funded and positively disposed C/Source observation peak.
    // The phase12/Cache/parent association is checked by the closed Ready port.
    pub(super) fn require_create_history_names_peak_v1(&self)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_retained_capture()?;
        let required = crate::journal::create_storage_name_peak_demand_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.continuation_original_v1()?.require_history_names_complete_v1(required)
            .map_err(Into::into)
    }

    // A closed concrete role supplies its actual finite observation roster.
    // Charge before Vec growth; neither a smaller later request nor disposal
    // can refund rows, replace a failed growth result or reattach the archive.
    pub(super) fn extend_create_capture_observers_once(
        &mut self, profile: &ProductionControllerNormalRootProfileV1, additional_rows: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.extend_original_observers_once(profile, additional_rows, None)
    }

    // This sibling borrower exists only after actual typed purpose15 reserve.
    // It retains the same B lifetime/archive and uses U for each new row.
    pub(super) fn extend_create_storage_use_observers_once(
        &mut self, profile: &ProductionControllerNormalRootProfileV1,
        original: &mut super::create_intake::ready::UseReceivingOriginalsV1,
        additional_rows: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        original.require_reserved_v1()?;
        self.extend_original_observers_once(profile, additional_rows, Some(original))
    }

    fn extend_original_observers_once(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
        additional_rows: usize,
        mut storage_use: Option<&mut super::create_intake::ready::UseReceivingOriginalsV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.require_retained_capture().is_err() || additional_rows == 0 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let previous = self.observation_capacity.ok_or(ResourceReservationErrorV1::Conflict)?;
        let capacity = previous.checked_add(additional_rows).ok_or(ResourceReservationErrorV1::Conflict)?;
        let lifetime = self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let growth = match storage_use.as_mut() {
            Some(original) => original.prepare_observer_growth_v1(
                profile, lifetime, previous, additional_rows,
            )?,
            None => {
                let original = self.continuation.as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                profile.lower_original_v1().prepare_create_intake_growth_from_continuation_v1(
                    original, lifetime, previous, additional_rows,
                ).map_err(ResourceReservationErrorV1::from)?
            }
        };
        profile.require_create_intake_original(lifetime)?;
        self.continuation_growth = Some(growth.grow_once_v1());
        if !matches!(self.continuation_growth, Some(Ok(()))) {
            self.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.observation_capacity = Some(capacity);
        Ok(())
    }

    // Borrows only this same actual J's whole successful append and readback.
    pub(super) fn create_storage_j_data_v1(
        &self,
    ) -> Result<super::create_intake::history::OriginalJDataV1<'_>, ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        let transaction = self.append.transaction.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        let [head, claim] = transaction.records() else { return Err(ResourceReservationErrorV1::Conflict); };
        let native = self.append.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = self.append.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let clock = self.initial_clock.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(super::create_intake::history::OriginalJDataV1 {
            transaction: *transaction.id(), names: *names, native: *native, clock: *clock,
            head_key: head.key(), head: head.value().ok_or(ResourceReservationErrorV1::Conflict)?,
            claim_key: claim.key(), claim: claim.value().ok_or(ResourceReservationErrorV1::Conflict)?,
        })
    }

    pub(super) fn create_storage_node_v1(&self) -> Result<aos_sandbox_model::NodeId, ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(aos_sandbox_model::NodeId::from_bytes(original.identity.native_fields().node))
    }

    pub(super) fn require_create_storage_original_pair_v1(
        &self,
        recipient: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.purpose != IntakePurpose::CreateContinuation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if recipient != original.recipient_invocation
            || producer != original.identity.native_fields().invocation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // Two actual bounded property observations. The live original lifetime and
    // exact original recipient/producer remain separate from copied row DATA.
    pub(super) fn require_create_capture_profile_v1(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_original(profile)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let (recipient, producer) = profile.require_resource_producer()?;
        if recipient != original.recipient_invocation
            || producer != original.identity.native_fields().invocation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // The concrete C/Source pair owner calls this once from its independent
    // post destination, even if a later dynamic admission was refused. It can
    // consume only the twelve rows prepaid before that operation's first IO;
    // it cannot grant primary entry, attach another archive or reserve again.
    pub(super) fn require_create_history_post_profile_v1(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.purpose != IntakePurpose::CreateContinuation || self.first.is_some()
            || self.observation_capacity.is_none_or(|rows| rows < CREATE_ENTRY_OBSERVER_ROWS + 12) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed()?;
        let lifetime = self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        profile.require_create_intake_original(lifetime)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let (recipient, producer) = profile.require_resource_producer()?;
        if recipient != original.recipient_invocation
            || producer != original.identity.native_fields().invocation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn create_lane(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        if self.purpose != IntakePurpose::CreateContinuation || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed()?;
        self.parent_lane.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn close(&self) {
        if let Some(lifetime) = &self.lifetime {
            lifetime.close();
        }
    }

    pub(super) fn association(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<([u8; 16], u64), ResourceReservationErrorV1> {
        self.require_original(profile)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let capacity = self
            .observation_capacity
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((
            original
                .identity
                .account_id(b"controller-q04-original-intake-v1"),
            u64::try_from(capacity).map_err(|_| ResourceReservationErrorV1::Conflict)?,
        ))
    }

    pub(super) fn preparation_source_shape(
        &self,
        original: &super::OriginalPreparationData,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&JournalShape, ResourceReservationErrorV1> {
        self.require_original(profile)?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_q04_preparation_source(original)?;
        self.source_shape.as_ref().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let first = self.first.and_then(|first| match first {
            FailureSite::Parent => self.parent_lane.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ParentOwners => self.parent_owners.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Original => self.original.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Receiver => self.receiver.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::InitialClock => self.initial_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Cpu => self.cpu.failure().map(|error| error as _),
            FailureSite::Append => self.append.failure(),
            FailureSite::Preparation => self.continuation_failure_v1()
                .or_else(|| self.observer_origin.as_ref()
                    .and_then(|returned| returned.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|error| error as _)),
            FailureSite::ControllerPost => self.controller_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::SourcePost => self.source_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ProfilePost => self.profile_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::CpuPost => self.cpu_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::LastClock => self.last_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|error| error as _),
        });
        first.or_else(|| self.continuation_failure_v1())
            .or_else(|| self.continuation_growth.as_ref()
                .and_then(|returned| returned.as_ref().err()).map(|cause| cause as _))
    }
}

impl Drop for Q04OriginalIntakeAttemptV1 {
    fn drop(&mut self) {
        self.close();
    }
}

// Both entrances replay their actual Controller/Source originals and canonical
// Q04/resource history. Only Q enters Cache initialization and credential capture;
// J instead retains its actual moved parent and short append loans.

fn fixed_demand(
    controller: &JournalShape,
    source: &JournalShape,
    provision: ResourceVector,
    purpose: IntakePurpose,
    cache: Option<&mut OriginalQ04CachePreflightLoanV1<'_>>,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let common = fixed_entry_demand(controller, source, provision)?;
    let extra = match (purpose, cache) {
        (IntakePurpose::Q04, Some(cache)) => q04_cache_capture_demand(cache)?,
        (IntakePurpose::CreateContinuation, None) => {
            let bytes = create_intake_control_bytes().ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            // The additional financial provider controls emit no wire or
            // staging payload; retain the existing entry's traffic recipe.
            let staged = u64::try_from(create_intake_entry_bytes())
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::PublicationStagingBytes, staged)
                .with(D::OutputBytes, staged)
        }
        _ => return Err(ResourceReservationErrorV1::Conflict),
    };
    common.checked_add(extra).map_err(ResourceReservationErrorV1::from)
}

fn fixed_entry_demand(
    controller: &JournalShape,
    source: &JournalShape,
    provision: ResourceVector,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    use crate::policy_compiler::create_q04::{
        MAXIMUM_CLAIM_BYTES, MAXIMUM_PREHOLD_BYTES, MAXIMUM_PREVIEW_BYTES,
    };
    let fail = || ResourceReservationErrorV1::Conflict;
    // Physical-history replay decodes the existing Q04/resource families. Its
    // bounded records and errors coexist with the retained original owners.
    let wire = MAXIMUM_CLAIM_BYTES.checked_add(MAXIMUM_PREVIEW_BYTES)
        .and_then(|bytes| bytes.checked_add(MAXIMUM_PREHOLD_BYTES))
        .and_then(|bytes| bytes.checked_add((8 + 7) * 4096)).ok_or_else(fail)?;
    let native = controller.native_bytes.checked_add(source.native_bytes)
        .and_then(|bytes| bytes.checked_add(u64::try_from(controller.maximum_transaction_bytes).ok()?.checked_mul(2)?))
        .ok_or_else(fail)?;
    let cells = controller.cells.checked_add(source.cells)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(8 + 7 + 6 + 4)).ok_or_else(fail)?;
    let memory = controller.retained_bytes.checked_add(source.retained_bytes)
        .and_then(|bytes| bytes.checked_add(usize::try_from(native).ok()?))
        .and_then(|bytes| bytes.checked_add(wire.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(cells.checked_mul(std::mem::size_of::<(ResourceVector, ResourceVector, [usize; 3])>())?))
        .and_then(|bytes| bytes.checked_add(usize::try_from(FAILURE_MEMORY_BYTES).ok()?)).ok_or_else(fail)?;
    let memory = u64::try_from(memory).map_err(|_| fail())?;
    let wire = u64::try_from(wire).map_err(|_| fail())?;
    let namespace_entries = controller.cells.checked_add(source.cells)
        .and_then(|entries| entries.checked_mul(2))
        .and_then(|entries| u64::try_from(entries).ok())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(ResourceVector::new([
        provision.get(D::CpuMicrosPerPeriod), memory, 1, 3 + 2 + 3 + 4,
        0, 0, native, 0, 0, 0, namespace_entries, 0, 0, 0, memory, 0, 0, 0,
        wire, wire, memory, 1,
    ]))
}

// Only the genuine Q caller supplies this exclusive same-owner loan. Its
// shape observation and every native failure remain in the actual initializer;
// this marker never replaces that retained cause or constructs another owner.
fn q04_cache_capture_demand(
    cache: &mut OriginalQ04CachePreflightLoanV1<'_>,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let fail = || ResourceReservationErrorV1::Conflict;
    cache.capture_shape().map_err(|_| fail())?;
    let capture = cache.fixed_capture_memory_bytes().map_err(|_| fail())?;
    // Immutable bootstrap source equality borrows its already-validated map.
    // Physical original-head checks stream through fixed typed scratch. Neither
    // consumer clones a Cache manifest nor replays/opens a Cache native journal.
    // Resident original maps/native owners stay charged under their old payer.
    let credentials = aos_sandbox_broker::systemd_credentials::ControllerQ04NativeCredentialCustodyV1::additional_geometry_v1()
        .ok_or_else(fail)?;
    let observer_controls = aos_sandbox_broker::controller_receiving::bank_launch::
        ControllerReservedObserverOriginalV1::receiving_construction_bytes_v1()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
            ResourceReservationErrorV1,
        >>()))
        .ok_or_else(fail)?;
    let memory = capture
        .checked_add(std::mem::size_of::<
            crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::public_api_session::ControllerQ04CredentialCustodyV1>()))
        .and_then(|bytes| bytes.checked_add(credentials.memory_bytes))
        .ok_or_else(fail)?;
    let memory = u64::try_from(memory).map_err(|_| fail())?;
    let observer_controls = u64::try_from(observer_controls).map_err(|_| fail())?;
    // Native control/return objects emit no staging or wire payload. Preserve
    // the old byte planes and add their actual simultaneous memory only.
    let root_controls = crate::policy_compiler::root_flight_additional_control_bytes_v1().and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(fail)?;
    let resident = memory.checked_add(observer_controls)
        .and_then(|bytes| bytes.checked_add(root_controls)).ok_or_else(fail)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, resident)
        // Both actual original/named credential flights coexist with the one
        // sequential manifest descriptor. No prior debt is refunded here.
        .with(D::OpenFiles, u64::try_from(credentials.open_files.checked_add(1).ok_or_else(fail)?)
            .map_err(|_| fail())?)
        .with(D::MetadataEntries, u64::try_from(credentials.metadata_entries).map_err(|_| fail())?)
        .with(D::PublicationStagingBytes, memory)
        .with(D::OutputBytes, memory))
}

#[cfg(test)]
mod layout_bridge_tests {
    use super::*;

    #[test]
    fn authentic_native_intake_and_preparation_fit_the_failure_allowance() {
        let actual_native_bytes = std::mem::size_of::<Q04OriginalIntakeAttemptV1>()
            .checked_add(std::mem::size_of::<
                crate::ProjectPreparationReservationAttemptV1,
            >())
            .unwrap();
        let demand = minimum_failure_demand().unwrap();

        assert!(u64::try_from(actual_native_bytes).unwrap() < demand.get(D::MemoryBytes));
        assert!(matches!(
            ResourceReservationErrorV1::from(
                bank::minimum_q04_failure_demand(bank::NativeLayoutDemand::new(usize::MAX, 1))
                    .unwrap_err(),
            ),
            ResourceReservationErrorV1::Conflict
        ));
    }

    #[test]
    fn actual_create_intake_owner_fits_its_negative_allowance() {
        println!("AOS_CREATE_INTAKE_LAYOUT {:?}", super::super::create_intake::create_intake_layout_diagnostics_v1());
        let demand = bank::minimum_create_intake_failure_demand(native_layout()).unwrap();
        let bytes = std::mem::size_of::<super::super::CreateContinuationIntakeAttemptV1>();

        assert!(u64::try_from(bytes).unwrap() < demand.get(D::MemoryBytes));
        assert!(bank::minimum_create_intake_failure_demand(
            bank::NativeLayoutDemand::new(0, 0).with_create_intake(usize::MAX),
        ).is_err());
    }

    #[test]
    fn create_entry_prices_its_actual_journals_without_q04_cache_capture() {
        let shape = || JournalShape {
            retained_bytes: 1024 * 1024,
            cells: 512,
            native_bytes: 4 * 1024 * 1024,
            maximum_transaction_bytes: 1024 * 1024,
            maximum_record_bytes: 512 * 1024,
        };
        let provision = ResourceVector::ZERO.with(D::CpuMicrosPerPeriod, 100_000);

        let create = fixed_demand(&shape(), &shape(), provision,
            IntakePurpose::CreateContinuation, None).unwrap();

        assert_eq!(create.get(D::StorageBytes), 10 * 1024 * 1024);
        assert!(create.get(D::MemoryBytes) < 256 * 1024 * 1024);
        assert_eq!(create.get(D::CpuMicrosPerPeriod), 100_000);
        // A copied passive shape cannot replace the original Cache loan.
        assert!(fixed_demand(&shape(), &shape(), provision, IntakePurpose::Q04, None).is_err());

        let mut overflow = shape();
        overflow.native_bytes = u64::MAX;
        assert!(fixed_demand(&overflow, &shape(), provision,
            IntakePurpose::CreateContinuation, None).is_err());
    }

    #[test]
    fn passive_snapshots_and_borrowed_views_remain_bounded() {
        use std::mem::{align_of, size_of};

        let snapshots = [
            (
                "EnrollmentIdentityFields",
                size_of::<bank::EnrollmentIdentityFields>(),
                size_of::<bank::EnrollmentIdentity>(),
            ),
            (
                "BootstrapProvisions",
                size_of::<bank::BootstrapProvisions>(),
                size_of::<bank::ImageBootstrapPolicy>(),
            ),
            (
                "AccountHeadFields",
                size_of::<bank::AccountHeadFields>(),
                size_of::<bank::AccountHead>(),
            ),
            (
                "ClaimFields",
                size_of::<bank::ClaimFields>(),
                size_of::<bank::Claim>(),
            ),
            (
                "CoissuanceFields",
                size_of::<bank::CoissuanceFields>(),
                size_of::<bank::CoissuanceBinding>(),
            ),
            (
                "TerminalFields",
                size_of::<bank::TerminalFields>(),
                size_of::<bank::TerminalBinding>(),
            ),
        ];

        for (name, bytes, canonical_bytes) in snapshots {
            println!("AOS_BANK_SNAPSHOT {name} bytes={bytes} canonical={canonical_bytes}");
            assert!(bytes <= canonical_bytes, "{name}");
            assert!(u64::try_from(bytes).unwrap() < FAILURE_MEMORY_BYTES, "{name}");
        }

        let views = [
            (
                "AccountMutation",
                size_of::<bank::AccountMutation<'static>>(),
                align_of::<bank::AccountMutation<'static>>(),
                // The existing eight fields plus the borrowed U binding.
                9_usize,
            ),
            (
                "EnrollmentMutation",
                size_of::<bank::EnrollmentMutation<'static>>(),
                align_of::<bank::EnrollmentMutation<'static>>(),
                // Ten original fields, D/X, two Host purposes and the carried R vector.
                15,
            ),
            (
                "CoissuanceMutation",
                size_of::<bank::CoissuanceMutation<'static>>(),
                align_of::<bank::CoissuanceMutation<'static>>(),
                5,
            ),
        ];

        for (name, bytes, alignment, references) in views {
            let expected_bytes = references.checked_mul(size_of::<&()>()).unwrap();
            println!("AOS_BANK_VIEW {name} bytes={bytes} align={alignment} references={references}");
            assert_eq!(bytes, expected_bytes, "{name}");
            assert_eq!(alignment, align_of::<&()>(), "{name}");
        }
    }
}
