//! Owns the once-only image-paid original Nix Start intake.
//!
//! ```text
//! enrollment: Controller baseline=C-P-I(-Q), reserved=P+I(+Q)
//! intake:     same Controller head + AOSRSC06 purpose11, I permanently Committed
//! ```
//!
//! The actual bank opening, receiving writers and profile remain resident.
//! This interval prices the bounded current-Start and Source input capture.
//! It does not issue a compiled-policy operation loan, a Storage request or
//! physical permission.
//! Pure prearm precedes observations; the original FirstGlobal CPU association
//! is historical, and fresh I CPU readback precedes replay and archive growth.

use crate::journal::JournalShape;
use std::sync::{Arc, Mutex};

use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1;

use super::service_interval::{
    ControllerFirstGlobalPrefixAttemptV1, ObserverAdmission, ObserverLifetime,
    OriginalControllerCpuContainment, OriginalReceiver, capacity_for, multiply,
};
use super::{
    AccountTransition, ClaimState, ControllerResourceBankOpeningV1, ResourceReservationErrorV1,
    ReturnedAppend, bootstrap, codec, replay,
};
use crate::cli_model::authorization_adapter::{
    CurrentCapabilityDecisionV1, RetainedAuthorizationTimeFloorV1,
};
use crate::controller::ControllerProtectedClockV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::policy_compiler::{CurrentNixPreflightAttemptV1, CurrentNixPreflightOriginalsV1};
use crate::production_operation_compiler::{NixStartAdmissionCarrierV2, NixStartContinuationErrorV2};
use crate::runtime_authority::RuntimeAuthorityBindingV1;
use crate::runtime_scope::CurrentAssignmentTarget;
use crate::{EffectPlan, Journal, JournalError};

// Owned closure payload with no reference to I or the external acquisition.
// Field order preserves the old constructor's reverse local Drop order.
type AcquisitionResult<T> = Option<Result<T, NixStartContinuationErrorV2>>;

#[derive(Clone, Copy)]
pub(crate) enum AcquisitionFailureV1 {
    Intake,
    FixedWriter,
    Carrier,
    CurrentEffect,
    BoundWriter,
    Recipe,
    Binding,
    Assignment,
    Clock,
    Decision,
    Target,
    TargetBinding,
    Promotion,
    InitialRecheck,
}

#[derive(Default)]
pub(crate) struct PaidNixStartOriginalsV1 {
    pub(crate) first: Option<AcquisitionFailureV1>,
    pub(crate) target: AcquisitionResult<CurrentAssignmentTarget>,
    pub(crate) acquisition_clock: Option<RawPairedClockSample>,
    pub(crate) decision: AcquisitionResult<CurrentCapabilityDecisionV1>,
    pub(crate) clock: AcquisitionResult<ControllerProtectedClockV1>,
    pub(crate) binding: AcquisitionResult<RuntimeAuthorityBindingV1>,
    pub(crate) carrier: AcquisitionResult<NixStartAdmissionCarrierV2>,
    pub(crate) fixed_writer: AcquisitionResult<()>,
    pub(crate) current_effect: AcquisitionResult<()>,
    pub(crate) bound_writer: AcquisitionResult<()>,
    pub(crate) recipe: AcquisitionResult<()>,
    pub(crate) assignment: AcquisitionResult<()>,
    pub(crate) target_binding: AcquisitionResult<()>,
    pub(crate) intake: AcquisitionResult<()>,
    pub(crate) promotion: AcquisitionResult<()>,
    pub(crate) initial_recheck: AcquisitionResult<()>,
    pub(crate) final_sample: AcquisitionResult<RawPairedClockSample>,
    pub(crate) final_clock: AcquisitionResult<()>,
}

/// Keeps the independently paid intake and all native uncertainty resident.
#[must_use]
pub struct NixOriginalStartIntakeAttemptV1 {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    original: Option<Result<bootstrap::OriginalEnrollment, ResourceReservationErrorV1>>,
    containment: Option<Result<(), ResourceReservationErrorV1>>,
    receiver: Option<Result<OriginalReceiver, ResourceReservationErrorV1>>,
    initial_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    cpu: FirstGlobalCpuReadbackV1,
    cpu_capture: Option<Result<(), NormalRootStartupErrorV1>>,
    append: ReturnedAppend,
    controller_post: Option<Result<(), JournalError>>,
    source_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<(), NormalRootStartupErrorV1>>,
    cpu_post: Option<Result<(), NormalRootStartupErrorV1>>,
    final_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    final_clock_check: Option<Result<(), SourceGenesisErrorV1>>,
    lifetime: Option<ObserverLifetime>,
    authorization: [RetainedAuthorizationTimeFloorV1; 6],
    authorization_count: usize,
    attempted: bool,
    borrowed: bool,
    first: Option<FailureSite>,
    closed_start: Option<PaidNixStartOriginalsV1>,
    closed_input: Option<CurrentNixPreflightOriginalsV1>,
    completion_controller: Option<Result<(), JournalError>>,
    completion_source: Option<Result<(), JournalError>>,
    completion_profile: Option<Result<(), NormalRootStartupErrorV1>>,
    completion_cpu: FirstGlobalCpuReadbackV1,
    completion_cpu_capture: Option<Result<(), NormalRootStartupErrorV1>>,
    completion_cpu_post: Option<Result<(), NormalRootStartupErrorV1>>,
    completion_cpu_binding: Option<Result<(), ResourceReservationErrorV1>>,
    completion_raw_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
}

#[derive(Clone, Copy)]
enum FailureSite {
    InitialClock,
    Original,
    Containment,
    Receiver,
    Cpu,
    CpuCapture,
    Append,
    Preparation,
    ControllerPost,
    SourcePost,
    ProfilePost,
    CpuPost,
    FinalClock,
    FinalClockCheck,
}

impl NixOriginalStartIntakeAttemptV1 {
    /// Parks the same opening without observing it or allocating another bank.
    pub fn begin(bank: Arc<Mutex<ControllerResourceBankOpeningV1>>) -> Self {
        Self {
            bank,
            original: None,
            containment: None,
            receiver: None,
            initial_clock: None,
            preparation: None,
            cpu: FirstGlobalCpuReadbackV1::default(),
            cpu_capture: None,
            append: ReturnedAppend::new(),
            controller_post: None,
            source_post: None,
            profile_post: None,
            cpu_post: None,
            final_clock: None,
            final_clock_check: None,
            lifetime: None,
            authorization: std::array::from_fn(|_| Default::default()),
            authorization_count: 0,
            attempted: false,
            borrowed: false,
            first: None,
            closed_start: None,
            closed_input: None,
            completion_controller: None,
            completion_source: None,
            completion_profile: None,
            completion_cpu: FirstGlobalCpuReadbackV1::default(),
            completion_cpu_capture: None,
            completion_cpu_post: None,
            completion_cpu_binding: None,
            completion_raw_clock: None,
        }
    }

    /// Commits this separate image subdivision before current-Start growth.
    ///
    /// All returned native and independent post Results stay in this attempt.
    /// Failure, abandonment and Drop never return I to the Controller baseline.
    /// A refused pure prearm enters no observations. The prior physical CPU
    /// recipe is only historical containment; fresh I readback precedes growth.
    ///
    /// # Errors
    /// Refuses reentry, absent original enrollment/intake, insufficient complete
    /// cost, changed receiving custody, enforcement or native/readback failure.
    pub fn prepare_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        prefix: Option<&ControllerFirstGlobalPrefixAttemptV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.attempted {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;
        self.original = Some(self.bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
            .and_then(|mut bank| bank.begin_nix_intake_once()));
        if matches!(self.original, Some(Err(_))) {
            self.first = Some(FailureSite::Original);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.containment = Some((|| {
            let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let containment = prefix.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?
                .borrow_original_cpu_containment(&self.bank, profile)?;
            containment.require_intake(original)
        })());
        if matches!(self.containment, Some(Err(_))) {
            self.first = Some(FailureSite::Containment);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        // The genuine I minimum now owns every reached negative-prefix slot.
        // No clock, path, profile, CPU or replay observation preceded admission.
        self.initial_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        self.receiver = Some(OriginalReceiver::capture(controller, source, profile));
        self.preparation = Some(self.prepare_body(controller, source, profile));
        self.first = if matches!(self.initial_clock, Some(Err(_))) {
            Some(FailureSite::InitialClock)
        } else if matches!(self.original, Some(Err(_))) {
            Some(FailureSite::Original)
        } else if matches!(self.receiver, Some(Err(_))) {
            Some(FailureSite::Receiver)
        } else if self.cpu.failure().is_some() {
            Some(FailureSite::Cpu)
        } else if matches!(self.cpu_capture, Some(Err(_))) {
            Some(FailureSite::CpuCapture)
        } else if self.append.failure().is_some() {
            Some(FailureSite::Append)
        } else if matches!(self.preparation, Some(Err(_))) {
            Some(FailureSite::Preparation)
        } else {
            None
        };

        // No bank lock spans these independent posts. Missing archive custody
        // is a retained refusal, never an ambient/ordinary observation fallback.
        self.controller_post = Some(controller.validate_held_protected_names());
        self.source_post = Some(source.journal().validate_held_protected_names());
        self.profile_post = Some(profile.recheck_nix_intake_profile());
        self.cpu_post = Some(profile.recheck_first_global_cpu(&mut self.cpu));
        self.final_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        self.final_clock_check = Some(match (
            self.initial_clock.as_ref().and_then(|result| result.as_ref().ok()),
            self.final_clock.as_ref().and_then(|result| result.as_ref().ok()),
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
            } else if matches!(self.final_clock, Some(Err(_))) {
                Some(FailureSite::FinalClock)
            } else if matches!(self.final_clock_check, Some(Err(_))) {
                Some(FailureSite::FinalClockCheck)
            } else { None };
        }
        if self.first.is_some() {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
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
    ) -> Result<(), ResourceReservationErrorV1> {
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let provision = original.policy.nix_original_start_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let clock = self.initial_clock.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        if clock.host_boot_id() != original.identity.boot {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // This fixed cgroup/membership read needs no property archive rows.
        // Keep its whole returned Result, then validate the fresh rate before
        // metadata, replay, observer allocation or selected input growth.
        self.cpu_capture = Some(profile.observe_first_global_cpu(&mut self.cpu));
        if !matches!(self.cpu_capture, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let (quota, period) = self.cpu.quota_and_period().ok_or(ResourceReservationErrorV1::Conflict)?;
        if period != 100_000 || quota > provision.get(D::CpuMicrosPerPeriod) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let controller_shape = controller.first_global_allocation_shape_v1()?;
        let source_shape = source.journal().first_global_allocation_shape_v1()?;
        let fixed = fixed_demand(&controller_shape, &source_shape, provision)?;
        let per_observer = ProductionControllerNormalRootProfileV1::first_global_observer_demand()?;
        let capacity = capacity_for(provision.checked_sub(fixed)?, per_observer)?;
        if capacity == 0 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        provision.checked_sub(fixed.checked_add(multiply(per_observer, capacity)?)?)?;
        self.lifetime = Some(ObserverLifetime::begin());
        let admission = ObserverAdmission::for_nix_intake(
            profile, original, capacity,
            self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
        );
        profile.attach_nix_intake_observers(&admission)?;
        profile.require_resource_producer()?;
        if self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .first_global_original(controller)? != *original
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let state = controller.controller_resource_state_v1()?;
        let id = bootstrap::account_id(original.identity, b"controller-nix-original-start-intake-v1");
        let claim = codec::decode_claim(replay::record_bytes(state, replay::CLAIM_PREFIX, id)
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        if claim.amount != provision || claim.state != ClaimState::Reserved {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut transition = AccountTransition::settle(replay::find_head(state, claim.account)?, claim, true)?;
        transition.original_clock = Some(clock);
        self.append.append_into(controller, Ok(transition));
        self.append.require_committed()?;
        self.receiver.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.controller_sequence = controller.snapshot_sequence();
        Ok(())
    }

    /// Lends the entered interval once to the exact selected Start caller.
    ///
    /// # Errors
    /// Refuses spent/failed custody, a different bank or receiving originals,
    /// closed observations, and native ambiguity. Scalars only select the
    /// existing authenticated Start engine; they never construct a paid owner.
    pub fn borrow_original_start<'original>(
        &'original mut self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'original ProductionControllerNormalRootProfileV1,
        operation: OperationId,
        step: u32,
        plan: &'original EffectPlan,
    ) -> Result<NixOriginalStartIntakeLoanV1<'original>, ResourceReservationErrorV1> {
        if self.first.is_some() || self.borrowed || !Arc::ptr_eq(&self.bank, bank) {
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.borrowed = true;
        let checked = (|| {
            let lifetime = self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            profile.require_nix_intake_original(lifetime)?;
            self.receiver.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?.require_same(controller, source, profile)?;
            let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if self.bank.try_lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .first_global_original(controller)? != *original
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.append.require_committed()
        })();
        if let Err(error) = checked {
            // The entered borrow failed before Start D was acquired. Preserve
            // available independent originals and its boot-clock post LAST.
            self.park_completion_posts(controller, source, profile);
            self.completion_raw_clock = Some(
                crate::policy_compiler::observe_root_first_source_successor_clock_v2(None),
            );
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(error);
        }
        Ok(NixOriginalStartIntakeLoanV1 { original: self, profile, operation, step, plan })
    }

    fn park_completion_posts(
        &mut self,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        // Only the first failed entry or the consuming successful loan closes.
        // Those branches are exclusive; no returned original is overwritten.
        self.completion_controller = Some(controller.validate_held_protected_names());
        self.completion_source = Some(source.journal().validate_held_protected_names());
        self.completion_profile = Some(profile.recheck_nix_intake_profile());
        self.completion_cpu_capture = Some(profile.observe_first_global_cpu(&mut self.completion_cpu));
        self.completion_cpu_post = Some(profile.recheck_first_global_cpu(&mut self.completion_cpu));
        self.completion_cpu_binding = Some(
            if self.completion_cpu.quota_and_period() == self.cpu.quota_and_period()
                && self.cpu.quota_and_period().is_some()
            { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) },
        );
    }

    /// Borrows the first outward cause while every original remains resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.first.is_none() {
            // Added input posts may fail after acquisition. Preserve their
            // chronology before scanning the retained time-floor crossings;
            // the ordinary no-input projection below remains unchanged.
            if let Some(input) = &self.closed_input {
                if let Some(error) = self.closed_start.as_ref().and_then(PaidNixStartOriginalsV1::first_failure) {
                    return Some(error);
                }
                if let Some(error) = input.failure() {
                    return Some(error);
                }
            }
            if let Some(error) = self.authorization.iter().find_map(RetainedAuthorizationTimeFloorV1::failure) {
                return Some(error);
            }
            if let Some(error) = self.closed_start.as_ref().and_then(PaidNixStartOriginalsV1::first_failure) {
                return Some(error);
            }
            return self.completion_controller.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
                .or_else(|| self.completion_source.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.completion_profile.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.completion_cpu.failure().map(|error| error as _))
                .or_else(|| self.completion_cpu_capture.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.completion_cpu_post.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.completion_cpu_binding.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.closed_start.as_ref().and_then(PaidNixStartOriginalsV1::final_clock_failure).map(|error| error as _))
                .or_else(|| self.completion_raw_clock.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _));
        }
        match self.first? {
            FailureSite::InitialClock => self.initial_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Original => self.original.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Containment => self.containment.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Receiver => self.receiver.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Cpu => self.cpu.failure().map(|error| error as _),
            FailureSite::CpuCapture => self.cpu_capture.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Append => self.append.failure(),
            FailureSite::Preparation => self.preparation.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ControllerPost => self.controller_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::SourcePost => self.source_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ProfilePost => self.profile_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::CpuPost => self.cpu_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::FinalClock => self.final_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::FinalClockCheck => self.final_clock_check.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

impl Drop for NixOriginalStartIntakeAttemptV1 {
    fn drop(&mut self) {
        if let Some(lifetime) = &self.lifetime {
            lifetime.close();
        }
    }
}

/// Borrows the paid original intake, never a general operation allowance.
#[doc(hidden)]
pub struct NixOriginalStartIntakeLoanV1<'original> {
    original: &'original mut NixOriginalStartIntakeAttemptV1,
    profile: &'original ProductionControllerNormalRootProfileV1,
    pub(crate) operation: OperationId,
    pub(crate) step: u32,
    pub(crate) plan: &'original EffectPlan,
}

pub(crate) struct NixIntakeClosingV1<'original> {
    loan: NixOriginalStartIntakeLoanV1<'original>,
}

impl<'original> NixOriginalStartIntakeLoanV1<'original> {
    pub(crate) fn begin_closing(
        self,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        input: Option<CurrentNixPreflightOriginalsV1>,
    ) -> NixIntakeClosingV1<'original> {
        // Consuming the only non-Clone loan makes a second closure impossible.
        // No public reborrow can create or replace these completion slots.
        // Source's borrowed inventory has already become an owning payload.
        self.original.closed_input = input;
        self.original.park_completion_posts(controller, source, self.profile);
        NixIntakeClosingV1 { loan: self }
    }

    pub(crate) fn require_open(&self) -> Result<(), ResourceReservationErrorV1> {
        self.profile.require_nix_intake_original(self.original.lifetime.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        self.original.append.require_committed().map(|_| ())
    }

    // The caller checks the original I admission first. Controller floor
    // writes may have advanced its sequence; the priced Source cut may not.
    pub(crate) fn require_original_source(
        &self,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.original.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_same_source(source)
    }

    pub(crate) fn authorization_crossing(&mut self) -> Result<&mut RetainedAuthorizationTimeFloorV1, ResourceReservationErrorV1> {
        self.require_open()?;
        let index = self.original.authorization_count;
        let crossing = self.original.authorization.get_mut(index)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.original.authorization_count += 1;
        Ok(crossing)
    }
}

impl NixIntakeClosingV1<'_> {
    pub(crate) fn park_unavailable_start_clock(&mut self) {
        // This is only the original boot interval when acquisition never
        // reached genuine Start D. It is not a caller-clock replacement.
        self.loan.original.completion_raw_clock = Some(
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(None),
        );
    }

    pub(crate) fn finish(self, originals: PaidNixStartOriginalsV1) -> Result<(), ResourceReservationErrorV1> {
        // The consuming closure receives its one nonborrowing payload once.
        self.loan.original.closed_start = Some(originals);
        if let Some(lifetime) = &self.loan.original.lifetime {
            lifetime.close();
        }
        if self.loan.original.failure().is_some() {
            Err(ResourceReservationErrorV1::Conflict)
        } else { Ok(()) }
    }
}

impl Drop for NixOriginalStartIntakeLoanV1<'_> {
    fn drop(&mut self) {
        if let Some(lifetime) = &self.original.lifetime {
            lifetime.close();
        }
    }
}

fn fixed_demand(
    controller: &JournalShape,
    source: &JournalShape,
    provision: ResourceVector,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    // Quote both reached recipes before allocating either archive or entering
    // the native I commit. No Root/Source16/compiler interval is included.
    let owner_bytes = std::mem::size_of::<Option<NixOriginalStartIntakeAttemptV1>>()
        .checked_add(std::mem::size_of::<Option<Result<(), ()>>>())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let whole = crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2::
        original_start_intake_demand(controller, source, provision, owner_bytes)?;
    let input = CurrentNixPreflightAttemptV1::input_capture_demand_v1(controller, source)?;

    // Rate, process and descriptor ceilings are shared by this one interval;
    // retained negative-prefix owners coexist with the later whole recipe.
    let retained_prefix = minimum_failure_demand()?
        .with(D::CpuMicrosPerPeriod, 0)
        .with(D::Pids, 0)
        .with(D::OpenFiles, 0)
        .with(D::ConcurrentOperations, 0);
    Ok(whole.checked_add(input)?.checked_add(retained_prefix)?)
}

pub(super) fn minimum_failure_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
    // Reuse the proved clock/name/CPU/read-buffer recipe, not a second sampler
    // or byte-to-CPU estimate. Price I's additional owner/guard slots separately.
    let base = super::q04_intake::minimum_failure_demand()?;
    let bytes = std::mem::size_of::<NixOriginalStartIntakeAttemptV1>()
        .checked_add(std::mem::size_of::<OriginalControllerCpuContainment<'_>>())
        .and_then(|bytes| bytes.checked_add(3 * 128))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let supplement = ResourceVector::ZERO
        .with(D::MemoryBytes, bytes)
        .with(D::MetadataEntries, bytes)
        .with(D::PublicationStagingBytes, bytes)
        .with(D::LogBytes, bytes)
        .with(D::OutputBytes, bytes);
    Ok(base.checked_add(supplement)?)
}
