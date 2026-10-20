//! Owns the once-only Controller FirstGlobal prefix inside the original bank.
//!
//! ```text
//! enrollment: Controller(C, committed=C-P, reserved=P, baseline=C-P)
//! first use:  same Controller(C, committed=C, reserved=0, baseline=C-P)
//!             + same AOSRSC04 purpose-9 claim, permanently Committed
//! ```
//!
//! Native rows are history, not constructors. The entered executor retains the
//! actual bank opening, Controller and fixed Source writers, profile, CPU
//! original and every returned cause. A short loan ends before mutable RPC
//! work; success, failure, ambiguity and Drop never free or rearm this interval.

use std::sync::{Arc, Mutex};

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use super::{
    AccountTransition, ClaimState, ControllerResourceBankOpeningV1, ResourceReservationErrorV1,
    ReturnedAppend, bank, bootstrap,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::journal::JournalShape;
use crate::{Journal, JournalError};

/// Keeps the entered FirstGlobal prefix and its native uncertainty resident.
#[must_use]
pub struct ControllerFirstGlobalPrefixAttemptV1 {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    original: Option<Result<aos_sandbox_broker::receiving::OriginalEnrollment, ResourceReservationErrorV1>>,
    receiver: Option<Result<OriginalReceiver, ResourceReservationErrorV1>>,
    initial_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    shape: Option<Result<(), ResourceReservationErrorV1>>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    cpu: aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1,
    append: ReturnedAppend,
    controller_post: Option<Result<(), JournalError>>,
    source_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    cpu_post: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    final_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    final_clock_check: Option<Result<(), SourceGenesisErrorV1>>,
    observer_capacity: usize,
    wait_capacity: usize,
    loan_taken: std::cell::Cell<bool>,
    attempted: bool,
    first_failure: Option<PrefixFailureSite>,
    observer_lifetime: Option<ObserverLifetime>,
    observer_origin: Option<Result<
        aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
        ResourceReservationErrorV1,
    >>,
}

#[derive(Clone, Copy)]
enum PrefixFailureSite {
    Shape,
    InitialClock,
    Original,
    Receiver,
    Cpu,
    Append,
    Preparation,
    ControllerPost,
    SourcePost,
    ProfilePost,
    CpuPost,
    FinalClock,
    FinalClockCheck,
}

pub(crate) struct GlobalShape {
    pub(crate) retained_bytes: usize,
    pub(crate) wire_bytes: usize,
    pub(crate) largest_payload: usize,
}

// These private identities supplement the live opening/profile conjunction;
// they never escape as a receiving token or construct a writer from DATA.
pub(super) struct OriginalReceiver {
    controller_object: usize,
    source_object: usize,
    profile_object: usize,
    controller_names: crate::journal::ProtectedJournalNamesV1,
    source_names: crate::journal::ProtectedJournalNamesV1,
    pub(super) controller_sequence: u64,
    source_sequence: u64,
}

// This lends the original physical association, not FirstGlobal payment or
// fresh currentness. Its closed archive is neither consulted nor reopened.
pub(super) struct OriginalControllerCpuContainment<'original> {
    prefix: &'original ControllerFirstGlobalPrefixAttemptV1,
}

impl OriginalControllerCpuContainment<'_> {
    pub(super) fn require_intake(
        &self,
        original: &aos_sandbox_broker::receiving::OriginalEnrollment,
    ) -> Result<(), ResourceReservationErrorV1> {
        let held = self.prefix.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.prefix.cpu.quota_and_period()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        original.policy.bootstrap_provisions().nix_original_start_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.policy.bootstrap_provisions().first_global_prefix
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if held != original {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let transition = self.prefix.append.original.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // This is the retained original association, not current CPU evidence
        // or a reopened P allowance. Fresh I capture remains independently paid.
        require_controller_head_cpu(&self.prefix.cpu, transition.before, original)
    }
}

// The genuine bank borrower supplies the original image. A child CPU slice
// prices logical obligations; it is not the installed whole-cgroup cpu.max.
// Callers retain actual capture failures and rejoin their original bank/head
// at the existing later frontier, without inserting another name observation.
pub(super) fn require_original_controller_cpu(
    cpu: &aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1,
    original: &aos_sandbox_broker::receiving::OriginalEnrollment,
) -> Result<(), ResourceReservationErrorV1> {
    if cpu.failure().is_some() {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let inclusive = original.policy.controller_envelope();
    let (quota, period) = cpu.quota_and_period()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    if period != 100_000 || quota == 0 || quota > inclusive.get(D::CpuMicrosPerPeriod) {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(())
}

// Q/J already own the actual proposed Controller head; historical P retention
// owns its original committed transition. Neither decoded head constructs the
// genuine CPU/profile/enrollment conjunction supplied by those private callers.
pub(super) fn require_controller_head_cpu(
    cpu: &aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1,
    controller: bank::AccountHead,
    original: &aos_sandbox_broker::receiving::OriginalEnrollment,
) -> Result<(), ResourceReservationErrorV1> {
    let fields = controller.native_fields();
    if fields.kind != bank::AccountKind::Controller
        || fields.enrollment != original.identity
        || fields.id != original.identity.account_id(b"controller")
        || fields.generation == 0 || fields.project != [0; 16]
        || fields.tree_revision != [0; 32]
        || controller.finite_ceilings()? != original.policy.controller_envelope()
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    require_original_controller_cpu(cpu, original)
}

impl OriginalReceiver {
    // This borrows the originally priced Source owner; it grants neither a
    // fresh receiver nor payment. The selected caller must own its Result.
    pub(super) fn require_same_source(
        &self,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.source_object != std::ptr::from_ref(source) as usize
            || self.source_sequence != source.snapshot_sequence_v1()
            || self.source_names != source.fixed_physical_names_v1()?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn require_q04_preparation_source(
        &self,
        original: &super::OriginalPreparationData,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.controller_names != original.controller_names
            || self.source_names != original.source_names
            || self.source_sequence != original.source_sequence
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn capture(
        controller: &Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        Ok(Self {
            controller_object: std::ptr::from_ref(controller) as usize,
            source_object: std::ptr::from_ref(source) as usize,
            profile_object: std::ptr::from_ref(profile) as usize,
            controller_names: controller.protected_writer_physical_names_v1()?,
            source_names: source.fixed_physical_names_v1()?,
            controller_sequence: controller.snapshot_sequence(),
            source_sequence: source.snapshot_sequence_v1(),
        })
    }

    pub(super) fn require_create_storage_association(
        &self,
        controller: &Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.matches_object_addresses(std::ptr::from_ref(controller) as usize,
            std::ptr::from_ref(source) as usize, std::ptr::from_ref(profile) as usize) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn require_create_storage_names(&self,
        controller: crate::journal::ProtectedJournalNamesV1,
        source: crate::journal::ProtectedJournalNamesV1) -> Result<(), ResourceReservationErrorV1>
    {
        if self.controller_names != controller || self.source_names != source {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // Sequences intentionally advance during Q04. Only its genuine retained
    // parent may reuse this identity/name comparison after terminal completion.
    pub(super) fn require_same_owners_after_q04(
        &self,
        controller: &Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.matches_object_addresses(
            std::ptr::from_ref(controller) as usize,
            std::ptr::from_ref(source) as usize,
            std::ptr::from_ref(profile) as usize,
        ) || self.controller_names != controller.protected_writer_physical_names_v1()?
            || self.source_names != source.fixed_physical_names_v1()?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    fn matches_object_addresses(&self, controller: usize, source: usize, profile: usize) -> bool {
        self.controller_object == controller
            && self.source_object == source
            && self.profile_object == profile
    }

    pub(super) fn require_same(
        &self,
        controller: &Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.matches_object_addresses(
            std::ptr::from_ref(controller) as usize,
            std::ptr::from_ref(source) as usize,
            std::ptr::from_ref(profile) as usize,
        ) || self.controller_sequence != controller.snapshot_sequence()
            || self.source_sequence != source.snapshot_sequence_v1()
            || self.controller_names != controller.protected_writer_physical_names_v1()?
            || self.source_names != source.fixed_physical_names_v1()?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

// No exported scalar constructor exists. Only prepare_once, while it owns the
// genuine enrolled original, can construct this short attachment borrower.
pub(crate) struct ObserverAdmission<'original> {
    profile: &'original ProductionControllerNormalRootProfileV1,
    original: &'original aos_sandbox_broker::receiving::OriginalEnrollment,
    capacity: usize,
    lifetime: &'original ObserverLifetime,
    purpose: ObserverPurpose,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ObserverPurpose {
    FirstGlobal,
    NixIntake,
    Q04Intake,
    CreateIntake,
}

// Closure DATA remains distinct from every role's paid observer admission.
pub(crate) use aos_sandbox_broker::receiving::ObservationLifetimeV1 as ObserverLifetime;

impl ObserverAdmission<'_> {
    pub(crate) fn belongs_to_q04_intake(&self, profile: &ProductionControllerNormalRootProfileV1) -> bool {
        self.purpose == ObserverPurpose::Q04Intake
            && std::ptr::eq(self.profile, profile)
            && (self
                .original
                .policy
                .bootstrap_provisions()
                .q04_original_intake)
                .is_some()
    }

    pub(super) fn for_q04_intake<'original>(
        profile: &'original ProductionControllerNormalRootProfileV1,
        original: &'original aos_sandbox_broker::receiving::OriginalEnrollment,
        capacity: usize,
        lifetime: &'original ObserverLifetime,
    ) -> ObserverAdmission<'original> {
        ObserverAdmission { profile, original, capacity, lifetime, purpose: ObserverPurpose::Q04Intake }
    }

    pub(crate) fn belongs_to_create_intake(&self, profile: &ProductionControllerNormalRootProfileV1) -> bool {
        self.purpose == ObserverPurpose::CreateIntake
            && std::ptr::eq(self.profile, profile)
            && (self
                .original
                .policy
                .bootstrap_provisions()
                .create_continuation_intake)
                .is_some()
    }

    pub(super) fn for_create_intake<'original>(
        profile: &'original ProductionControllerNormalRootProfileV1,
        original: &'original aos_sandbox_broker::receiving::OriginalEnrollment,
        capacity: usize,
        lifetime: &'original ObserverLifetime,
    ) -> ObserverAdmission<'original> {
        ObserverAdmission { profile, original, capacity, lifetime, purpose: ObserverPurpose::CreateIntake }
    }

    pub(crate) fn belongs_to(&self, profile: &ProductionControllerNormalRootProfileV1) -> bool {
        self.purpose == ObserverPurpose::FirstGlobal
            && std::ptr::eq(self.profile, profile)
            && (self
                .original
                .policy
                .bootstrap_provisions()
                .first_global_prefix)
                .is_some()
    }

    pub(crate) fn belongs_to_nix_intake(&self, profile: &ProductionControllerNormalRootProfileV1) -> bool {
        self.purpose == ObserverPurpose::NixIntake
            && std::ptr::eq(self.profile, profile)
            && (self
                .original
                .policy
                .bootstrap_provisions()
                .nix_original_start_intake)
                .is_some()
    }

    pub(super) fn for_nix_intake<'original>(
        profile: &'original ProductionControllerNormalRootProfileV1,
        original: &'original aos_sandbox_broker::receiving::OriginalEnrollment,
        capacity: usize,
        lifetime: &'original ObserverLifetime,
    ) -> ObserverAdmission<'original> {
        ObserverAdmission { profile, original, capacity, lifetime, purpose: ObserverPurpose::NixIntake }
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn lifetime(&self) -> ObserverLifetime {
        self.lifetime.clone()
    }
}

/// Borrows the same entered first-use owner without granting another interval.
pub(crate) struct FirstGlobalPrefixLoan<'original> {
    original: &'original ControllerFirstGlobalPrefixAttemptV1,
}

impl FirstGlobalPrefixLoan<'_> {
    pub(crate) const fn wait_capacity(&self) -> usize {
        self.original.wait_capacity
    }
}

impl Drop for FirstGlobalPrefixLoan<'_> {
    fn drop(&mut self) {
        // The archives and charge stay resident. Closing this one purpose
        // prevents later Project/Create/read calls spending its unused rows.
        if let Some(lifetime) = &self.original.observer_lifetime {
            lifetime.close();
        }
    }
}

impl ControllerFirstGlobalPrefixAttemptV1 {
    pub(super) fn borrow_original_cpu_containment<'original>(
        &'original self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<OriginalControllerCpuContainment<'original>, ResourceReservationErrorV1> {
        if !Arc::ptr_eq(&self.bank, bank) || self.failure().is_some()
            || self.cpu.failure().is_some() || !matches!(self.cpu_post, Some(Ok(())))
            || !matches!(self.controller_post, Some(Ok(())))
            || !matches!(self.source_post, Some(Ok(())))
            || !matches!(self.profile_post, Some(Ok(())))
            || !matches!(self.final_clock_check, Some(Ok(())))
            || !self.observer_lifetime.as_ref().is_some_and(|lifetime| !lifetime.is_open())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let receiver = self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if receiver.profile_object != std::ptr::from_ref(profile) as usize {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append.require_committed()?;
        Ok(OriginalControllerCpuContainment { prefix: self })
    }

    /// Prearms custody on the real executor before any added startup selector.
    ///
    /// This allocation-free constructor is inert. It cannot manufacture a loan
    /// from a row, vector or request, and its Arc keeps the original opening.
    #[must_use]
    pub fn new(bank: Arc<Mutex<ControllerResourceBankOpeningV1>>) -> Self {
        Self {
            bank,
            original: None,
            receiver: None,
            initial_clock: None,
            shape: None,
            preparation: None,
            cpu: aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1::default(),
            append: ReturnedAppend::new(),
            controller_post: None,
            source_post: None,
            profile_post: None,
            cpu_post: None,
            final_clock: None,
            final_clock_check: None,
            observer_capacity: 0,
            wait_capacity: 0,
            loan_taken: std::cell::Cell::new(false),
            attempted: false,
            first_failure: None,
            observer_lifetime: None,
            observer_origin: None,
        }
    }

    /// Admits only the original enrolled, fixed-writer FirstGlobal prefix.
    ///
    /// # Errors
    /// Retains source-shape, capacity, profile, CPU, clock and native failures
    /// before returning a coarse refusal. Every available independent post and
    /// raw final clock runs even when a preparation or append fails.
    pub fn prepare_once(
        &mut self,
        journal: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        shape: Result<(), ResourceReservationErrorV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;
        self.shape = Some(shape);
        self.initial_clock = Some(
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(None),
        );
        self.original = Some(
            self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|bank| bank.first_global_original(journal)),
        );
        self.receiver = Some(OriginalReceiver::capture(journal, source, profile));
        self.preparation = Some(if matches!(self.shape.as_ref(), Some(Ok(())))
            && matches!(self.receiver.as_ref(), Some(Ok(_)))
        {
            self.prepare_body(journal, source, profile)
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        });
        self.first_failure = if matches!(self.shape.as_ref(), Some(Err(_))) {
            Some(PrefixFailureSite::Shape)
        } else if matches!(self.initial_clock.as_ref(), Some(Err(_))) {
            Some(PrefixFailureSite::InitialClock)
        } else if matches!(self.original.as_ref(), Some(Err(_))) {
            Some(PrefixFailureSite::Original)
        } else if matches!(self.receiver.as_ref(), Some(Err(_))) {
            Some(PrefixFailureSite::Receiver)
        } else if self.cpu.failure().is_some() {
            Some(PrefixFailureSite::Cpu)
        } else if self.append.failure().is_some() {
            Some(PrefixFailureSite::Append)
        } else if matches!(self.preparation.as_ref(), Some(Err(_))) {
            Some(PrefixFailureSite::Preparation)
        } else {
            None
        };

        // No bank lock spans these independent owner calls. The raw clock is
        // last even after a failed initial pair or unavailable CPU/native loan.
        self.controller_post = Some(journal.validate_held_protected_names());
        self.source_post = Some(source.journal().validate_held_protected_names());
        self.profile_post = Some(profile.recheck_first_global_profile());
        self.cpu_post = Some(profile.recheck_first_global_cpu(&mut self.cpu));
        self.final_clock = Some(
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(None),
        );
        self.final_clock_check = Some(match (
            self.initial_clock.as_ref().and_then(|result| result.as_ref().ok()),
            self.final_clock.as_ref().and_then(|result| result.as_ref().ok()),
        ) {
            (Some(original), Some(current)) => original.validate_later_sample(*current)
                .map_err(|_| SourceGenesisErrorV1::Stale),
            _ => Err(SourceGenesisErrorV1::Stale),
        });
        if self.first_failure.is_none() {
            self.first_failure = if matches!(self.controller_post.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::ControllerPost)
            } else if matches!(self.source_post.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::SourcePost)
            } else if matches!(self.profile_post.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::ProfilePost)
            } else if matches!(self.cpu_post.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::CpuPost)
            } else if matches!(self.final_clock.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::FinalClock)
            } else if matches!(self.final_clock_check.as_ref(), Some(Err(_))) {
                Some(PrefixFailureSite::FinalClockCheck)
            } else {
                None
            };
        }
        if self.failure().is_some() {
            // Keep the diagnostic observations available until LAST, then
            // close any unused rows. A failed preparation cannot leave a
            // FirstGlobal allowance usable by a later operation.
            if let Some(lifetime) = &self.observer_lifetime {
                lifetime.close();
            }
            Err(ResourceReservationErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    fn prepare_body(
        &mut self,
        journal: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let original = self.original.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let Some(provision) = original.policy.bootstrap_provisions().first_global_prefix else {
            // Old image families retain their existing ordinary observation
            // recipe. They do not gain a prefix borrower from this no-op arm.
            return Ok(());
        };
        let clock = self.initial_clock.as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if clock.host_boot_id() != original.identity.native_fields().boot {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let controller = journal.first_global_allocation_shape_v1()?;
        let source_shape = source.journal().first_global_allocation_shape_v1()?;
        let global = crate::policy_compiler::OriginalConfiguredGlobalGenesisInvocationV2::
            first_global_allocation_shape()?;
        let append_bound = Journal::first_global_native_append_bound_v1(global.largest_payload)?;
        if global.largest_payload > controller.maximum_record_bytes
            || global.largest_payload > source_shape.maximum_record_bytes
            || append_bound > u64::try_from(controller.maximum_transaction_bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
            || append_bound > u64::try_from(source_shape.maximum_transaction_bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let fixed = fixed_demand(&controller, &source_shape, &global, provision, append_bound)?;
        let observer = ProductionControllerNormalRootProfileV1::first_global_observer_demand()?;
        let remaining = provision.checked_sub(fixed)?;
        let observer_capacity = capacity_for(remaining, observer)?;
        // One portion pays the real property originals; another pays the
        // existing wait archives. Neither is an independently mutable ledger.
        self.observer_capacity = observer_capacity / 2;
        if self.observer_capacity == 0 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let observations = multiply(observer, self.observer_capacity)?;
        let wait_remaining = remaining.checked_sub(observations)?;
        self.wait_capacity = capacity_for(wait_remaining, wait_demand()?)?;
        self.observer_origin = Some(
            self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|bank| bank.begin_first_global_observers_v1(journal, profile, fixed)),
        );
        let observer_origin = self.observer_origin.as_ref()
            .and_then(|returned| returned.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if observer_origin.capacity_data_v1() != self.observer_capacity {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.observer_lifetime = Some(observer_origin.lifetime_v1());
        let admission = ObserverAdmission {
            profile,
            original,
            capacity: self.observer_capacity,
            lifetime: self.observer_lifetime.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            purpose: ObserverPurpose::FirstGlobal,
        };
        let origin = match self.observer_origin.take() {
            Some(Ok(origin)) => origin,
            retained => {
                self.observer_origin = retained;
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        profile.attach_first_global_observers(&admission, origin)?;
        profile.observe_first_global_cpu(&mut self.cpu)?;
        require_original_controller_cpu(&self.cpu, original)?;
        profile.require_resource_producer()?;
        {
            let bank = self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            if bank.first_global_original(journal)? != *original {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let state = journal.controller_resource_state_v1()?;
        let id = original
            .identity
            .account_id(b"controller-first-global-prefix-v1");
        let claim = super::Claim::decode(
            bank::claim_bytes(state, id).ok_or(ResourceReservationErrorV1::Conflict)?,
        )
        .map_err(ResourceReservationErrorV1::from)?;
        let before = bank::find_head(state, claim.native_fields().account)
            .map_err(ResourceReservationErrorV1::from)?;
        if claim.native_fields().amount != provision
            || claim.native_fields().state != ClaimState::Reserved
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut transition = AccountTransition::settle(before, claim, true)?;
        transition.original_clock = Some(clock);
        self.append.append_into(journal, Ok(transition));
        self.append.require_committed()?;
        // Record only this known self-write, not a refreshed Controller cut.
        self.receiver.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .controller_sequence = journal.snapshot_sequence();
        Ok(())
    }

    pub(crate) fn borrow_for(
        &self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        controller: &Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<FirstGlobalPrefixLoan<'_>, ResourceReservationErrorV1> {
        if self.failure().is_some() || self.wait_capacity == 0 || self.loan_taken.get()
            || !Arc::ptr_eq(&self.bank, bank)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let lifetime = self.observer_lifetime.as_ref()
            .filter(|original| original.is_open())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        profile.require_first_global_original(lifetime)?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_same(controller, source, profile)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        {
            let bank = bank.try_lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            if bank.first_global_original(controller)? != *original {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        self.append.require_committed()?;
        self.loan_taken.set(true);
        Ok(FirstGlobalPrefixLoan { original: self })
    }

    /// Borrows the earliest retained outward error without releasing custody.
    ///
    /// The selected profile archive additionally retains its underlying
    /// constructor, property, cancellation and native transport results. A
    /// coarse profile refusal does not replace those resident originals.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            PrefixFailureSite::Shape => self.shape.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::InitialClock => self.initial_clock.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::Original => self.original.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::Receiver => self.receiver.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::Cpu => self.cpu.failure().map(|error| error as _),
            PrefixFailureSite::Append => self.append.failure(),
            PrefixFailureSite::Preparation => self.observer_origin.as_ref()
                .and_then(|returned| returned.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|error| error as _)),
            PrefixFailureSite::ControllerPost => self.controller_post.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::SourcePost => self.source_post.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::ProfilePost => self.profile_post.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::CpuPost => self.cpu_post.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::FinalClock => self.final_clock.as_ref()?.as_ref().err().map(|error| error as _),
            PrefixFailureSite::FinalClockCheck => self.final_clock_check.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

pub(super) fn capacity_for(
    remaining: ResourceVector,
    per_slot: ResourceVector,
) -> Result<usize, ResourceReservationErrorV1> {
    aos_sandbox_broker::receiving::FixedPropertyArchiveV1::receiving_capacity_data_v1(remaining, per_slot)
        .map_err(|_| ResourceReservationErrorV1::Conflict)
}

pub(super) fn multiply(
    vector: ResourceVector,
    count: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    aos_sandbox_broker::receiving::FixedPropertyArchiveV1::multiply_receiving_demand_data_v1(vector, count)
        .map_err(|_| ResourceReservationErrorV1::Conflict)
}

fn fixed_demand(
    controller: &JournalShape,
    source: &JournalShape,
    global: &GlobalShape,
    provision: ResourceVector,
    append: u64,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let append_bytes = usize::try_from(append).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let replay_bytes = controller.native_bytes.checked_add(source.native_bytes)
        .and_then(|bytes| bytes.checked_add(append))
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let local_bytes = controller.retained_bytes.checked_add(source.retained_bytes)
        .and_then(|bytes| bytes.checked_add(global.retained_bytes))
        .and_then(|bytes| bytes.checked_add(replay_bytes))
        .and_then(|bytes| bytes.checked_add(append_bytes))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerFirstGlobalPrefixAttemptV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
            usize, usize, std::sync::atomic::AtomicBool,
        )>()))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let local_bytes = u64::try_from(local_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    // Fixed native members and resident result slots are separate from the
    // already-held maps. Repeated canonical bookends can simultaneously hold
    // two full projections; neither is replaced with a digest-only status.
    let cells = controller.cells.checked_add(source.cells)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(14 + 8 + 3))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let cell_bytes = cells.checked_mul(std::mem::size_of::<(
        ResourceVector, ResourceVector, [usize; 3],
    )>()).ok_or(ResourceReservationErrorV1::Conflict)?;
    let local_bytes = local_bytes.checked_add(u64::try_from(cell_bytes)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let namespace_entries = controller.cells.checked_add(source.cells)
        .and_then(|entries| entries.checked_mul(2))
        .and_then(|entries| u64::try_from(entries).ok())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let native = controller.native_bytes.checked_add(source.native_bytes)
        .and_then(|bytes| bytes.checked_add(append))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(ResourceVector::ZERO
        // This is the finite aggregate rate, not a per-instruction estimate.
        // The actual same-cgroup cpu.max quota/period is checked before use.
        .with(D::CpuMicrosPerPeriod, provision.get(D::CpuMicrosPerPeriod))
        .with(D::MemoryBytes, local_bytes.checked_mul(2)
            .and_then(|bytes| bytes.checked_add(original_observer_control_bytes()?))
            .ok_or(ResourceReservationErrorV1::Conflict)?)
        .with(D::Pids, 1)
        // Three CPU OFDs; one Root stream and its pidfd; peer cgroup, fragment
        // and fresh-name originals. Sequential observer runtime/socket costs
        // are charged separately in each retained observer row.
        .with(D::OpenFiles, 3 + 2 + 3)
        .with(D::StorageBytes, native)
        .with(D::MetadataEntries, namespace_entries)
        .with(D::PublicationStagingBytes, local_bytes)
        .with(D::NetworkBytes, u64::try_from(global.wire_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        // The selected route emits only fixed termination labels. Owning
        // kernel/transport error payloads are additionally paid in the archives.
        .with(D::LogBytes, u64::try_from(global.retained_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
        .with(D::OutputBytes, local_bytes)
        .with(D::ConcurrentOperations, 1))
}

fn wait_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let owner = std::mem::size_of::<Result<(), SourceGenesisErrorV1>>();
    let clock = std::mem::size_of::<Result<RawPairedClockSample, SourceGenesisErrorV1>>();
    // The entered wait owner can retain bounded proc/status and fixed-path
    // kernel causes. It cannot enter policy decoders or journal reducers here.
    // Include their owning payload rather than charging Result's inline size.
    let payload = 64 * 1024 + 4096;
    let poll = std::mem::size_of::<Option<rustix::io::Result<usize>>>()
        .checked_add(std::mem::size_of::<Option<rustix::event::PollFlags>>())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let bytes = owner.checked_add(clock).and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(poll.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(payload * 4))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
        .with(D::OutputBytes, bytes))
}

// The retained origin is part of the compiled prefix Self above. Only its
// simultaneous native factory/return/upper projection planes are additional.
pub(super) fn original_observer_control_bytes() -> Option<u64> {
    use aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1;

    ControllerReservedObserverOriginalV1::receiving_construction_bytes_v1()?
        .checked_add(std::mem::size_of::<
            Result<ControllerReservedObserverOriginalV1, ResourceReservationErrorV1>,
        >())
        .and_then(|bytes| u64::try_from(bytes).ok())
}
