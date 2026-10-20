//! Admits original PID1 bootstrap custody into the one native resource bank.
//!
//! Image policy pays the finite trusted bootstrap interval. The bank verifies
//! those same bytes with the sole resource arithmetic before recording the
//! node and two inclusive envelopes. A capsule alone cannot enter this path:
//! the original closed Controller table and current fixed launch are required.
//! Original enrollment commits fixed Controller and Components demand, with
//! only their explicit subdivisions retained as separate reserved claims.
//! Native uncertainty retains the entire transaction and original descriptors.

mod startup;
mod create_provisioning;
mod create_continuation;
mod original_observers;
mod operator_recover;
mod lifecycle_stop;
mod recovered_sessions;
#[cfg(target_os = "linux")]
mod delete_queries;
#[cfg(target_os = "linux")]
mod delete_pending;
#[cfg(target_os = "linux")]
mod delete_candidate;
#[cfg(target_os = "linux")]
mod delete_cache;
#[cfg(target_os = "linux")]
mod delete_planning_root;
#[cfg(target_os = "linux")]
mod delete_pending_root;
#[cfg(target_os = "linux")]
pub use delete_planning_root::{ControllerDeletePlanningRootOriginalV1, ControllerDeletePlanningRootLoanV1};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use delete_pending_root::{ControllerDeleteFinalDisposalOriginalV4, ControllerDeletePendingRootClientOriginalV2,
    ControllerDeletePendingRootChallengeLoanV2, ControllerDeletePendingRootFailureViewV2, OriginalDeleteResourceSigningV2};

use super::{
    EnrollmentIdentity, ResourceReservationErrorV1, Transition, TransitionOriginal, bank,
};
use crate::{Journal, JournalError, JournalTransaction};

use aos_sandbox_broker::receiving::OriginalEnrollment;

#[derive(Clone, Copy)]
enum OriginalIntakePurpose { Q04, CreateContinuation }

/// Keeps the first bank-open transaction and every native/post result resident.
///
/// A failed opening cannot be retried or turned into a loan by replay DATA.
/// This owner keeps the actual PID1 files for its whole Controller lifetime.
#[must_use]
pub struct ControllerResourceBankOpeningV1 {
    startup: aos_sandbox_broker::controller_receiving::ControllerStartupOpeningV1,
    wrapper_debit: Option<Result<(), aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1>>,
    original: std::sync::Arc<aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1>,
    writer_opening: std::cell::RefCell<Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerWriterOpeningOriginalV1>>,
    launch: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1>,
    bank_observation: aos_sandbox_broker::controller_receiving::ControllerOriginalObservationV1,
    bank_mutation: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerPreparedBankMutationV1>,
    bank_native_post: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1>,
    bank_native_post_entry: Option<Result<(), ResourceReservationErrorV1>>,
    bank_native_post_disposition: Option<Result<(), ResourceReservationErrorV1>>,
    launch_result: Option<Result<(), ResourceReservationErrorV1>>,
    launch_admission: Option<Result<(), ResourceReservationErrorV1>>,
    selected_prefix: Option<Result<(), ResourceReservationErrorV1>>,
    runtime_startup: Option<super::runtime_receiving::ControllerRuntimeStartupAdmissionV1>,
    source_issue_debit: Option<Result<(), ResourceReservationErrorV1>>,
    source_credentials: Option<super::startup_credentials::ControllerSourceGenesisReceivingV1>,
    source_credentials_taken: bool,
    public_credentials: Option<super::startup_credentials::ControllerPublicTlsReceivingV1>,
    public_credentials_taken: bool,
    enrolled_disposition: Option<Result<(), ResourceReservationErrorV1>>,
    serving_disposition: Option<Result<(), ResourceReservationErrorV1>>,
    publisher_receiving: Option<super::publisher_receiving::ControllerPublisherReceivingV1>,
    publisher_receiving_taken: bool,
    initial_sessions: [Option<super::initial_session::ControllerInitialBrokerSessionReceivingV1>;
        super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
    initial_sessions_taken: [bool; super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
    cache_import: Option<crate::cache_residency::CacheSelectedBootstrapImportV1>,
    preopen: Option<ControllerResourcePreopenPostV1>,
    preopen_attempted: bool,
    observed: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
    prepared: Option<Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerPreparedEnrollmentMutationV1, ResourceReservationErrorV1>>,
    names: Option<Result<crate::journal::ProtectedJournalNamesV1, JournalError>>,
    native: Option<Result<crate::journal::CommitResult, JournalError>>,
    readback: Option<Result<(), ResourceReservationErrorV1>>,
    journal_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<[u8; 16], crate::normal_root::NormalRootStartupErrorV1>>,
    attempted: bool,
    nix_intake_attempted: bool,
    q04_intake_attempted: bool,
    create_intake_attempted: bool,
}

impl ControllerResourceBankOpeningV1 {
    fn baseline_opening_closed(&self) -> bool {
        self.original.is_closed()
    }

    pub(super) fn begin_q04_intake_once(
        &mut self,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        self.begin_original_intake_once(OriginalIntakePurpose::Q04)
    }

    pub(super) fn begin_create_intake_once(
        &mut self,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        self.begin_original_intake_once(OriginalIntakePurpose::CreateContinuation)
    }

    // Only these two fixed Native children can select this private disposition.
    // Selection changes the original payer and latch, never policy authority.
    fn begin_original_intake_once(
        &mut self,
        purpose: OriginalIntakePurpose,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        use OriginalIntakePurpose as Purpose;

        let attempted = match purpose {
            Purpose::Q04 => &mut self.q04_intake_attempted,
            Purpose::CreateContinuation => &mut self.create_intake_attempted,
        };
        if *attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *attempted = true;
        if self.failure().is_some() || !self.native_opened() || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let provisions = original.policy.bootstrap_provisions();
        let provision = match purpose {
            Purpose::Q04 => provisions.q04_original_intake,
            Purpose::CreateContinuation => provisions.create_continuation_intake,
        }.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if matches!(purpose, Purpose::CreateContinuation) {
            provision.checked_sub(bank::minimum_create_intake_failure_demand(
                super::q04_intake::native_layout(),
            )?)?;
        }

        // This is the actual already-enrolled owner, not replay currentness.
        // Full replay and original file/profile checks follow bounded pricing.
        Ok(original)
    }

    pub(super) fn begin_nix_intake_once(&mut self) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.nix_intake_attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Arm in the actual bank owner, not only a disposable caller attempt.
        // Failed intake and dropped attempts cannot retry a Reserved row.
        self.nix_intake_attempted = true;
        if self.failure().is_some() || !self.native_opened() || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self
            .observed
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let provision = original
            .policy
            .bootstrap_provisions()
            .nix_original_start_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        provision.checked_sub(super::nix_intake::minimum_failure_demand()?)?;

        // This is the held successful enrollment, not fresh replay or PID1
        // currentness. Even the first clock/name observation needs this I.
        Ok(original)
    }

    /// Selects a restricted recovery-only startup from actual held completion.
    ///
    /// The initial recipient returns false. A completed genuine successor may
    /// select only the recovery listener: this DATA grants no ordinary Ready,
    /// public read, operation, floor, native entry, spent interval or effect.
    /// It performs no IO and does not require TLS to have been constructed yet;
    /// the actual Recover purpose still requires the original Serving stage.
    ///
    /// # Errors
    /// Borrows the actual startup/native/profile cause, or refuses incomplete,
    /// undisposed or unavailable selected Bank/recipient custody.
    #[doc(hidden)]
    pub fn selects_operator_recover_only_v1(&self)
        -> Result<bool, &(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.failure() {
            return Err(cause);
        }
        if !self.native_opened() || self.original.is_closed()
            || !matches!(self.enrolled_disposition, Some(Ok(())))
            || !matches!(self.bank_native_post_disposition, Some(Ok(())))
            || self.runtime_startup.as_ref().is_none_or(|attempt| attempt.require_success().is_err()) {
            return Err(&CLOSED);
        }
        let Some(launch) = self.launch.as_ref() else {
            return Err(&CLOSED);
        };
        if launch.is_confirmed_operator_recover_successor_v1() {
            Ok(true)
        } else if launch.is_initial_enrollment() {
            Ok(false)
        } else {
            Err(&CLOSED)
        }
    }

    /// Reports only the already-held image family's prefix selection DATA.
    ///
    /// This allocation-free selector does not observe PID1, construct a loan,
    /// rearm first use or authorize a native effect.
    #[must_use]
    pub fn selects_first_global_prefix(&self) -> bool {
        self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .is_some_and(|original| original.policy.bootstrap_provisions().first_global_prefix.is_some())
    }

    // Only the entered FirstGlobal constructor uses this genuine held origin
    // before its newly bounded property observations. The returned DATA never
    // escapes the private bank children or substitutes for their current join.
    pub(super) fn first_global_original(
        &self,
        journal: &Journal,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        // The caller's actual FirstGlobal receiving scope owns fresh lower
        // pair/control bookends; this only rejoins their immutable original.
        let actual = self.original.observed_enrollment_data_v1()?;
        if actual != original
            || journal.protected_writer_physical_names_v1()? != *names
            || bank::validate(journal.controller_resource_state_v1()?)
                .map_err(ResourceReservationErrorV1::from)?
                != Some(original.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_launch(journal, original)?;
        Ok(original)
    }

    // The caller holds one real B profile scope across this whole operation.
    // That scope owns original pair/native receiver bookends; this checks the
    // same successful bank opening and actual held Controller writer, without
    // another ordinary original-pair reader or a new reservation.
    pub(crate) fn require_cache_baseline_controller(
        &self,
        original: &std::sync::Arc<aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1>,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::sync::Arc::ptr_eq(&self.original, original)
            || self.failure().is_some()
            || !self.native_opened()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let expected = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.require_current_launch(controller, *expected)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if controller.protected_writer_physical_names_v1()? != *names
            || bank::validate(controller.controller_resource_state_v1()?)?
                != Some(expected.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // Rechecks the original producer, not a decoded capsule or a new opener.
    pub(super) fn require_enrolled(
        &self,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<EnrollmentIdentity, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened()
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let producer = profile.require_resource_producer()?;
        let current = self.original.observed_enrollment_data_v1()?;
        if current.recipient_invocation != producer.0
            || current.identity.native_fields().invocation != producer.1
        { return Err(ResourceReservationErrorV1::Conflict); }
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if current.identity != original.identity || current.policy != original.policy
            || current.recipient_invocation != original.recipient_invocation
            || journal.protected_writer_physical_names_v1()? != *names
            || bank::validate(journal.controller_resource_state_v1()?)
                .map_err(ResourceReservationErrorV1::from)?
                != Some(original.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_launch(journal, *original)?;
        Ok(original.identity)
    }

    /// Compares a node with this bank's same successful native enrollment.
    ///
    /// The enclosing caller independently holds its current C/profile interval.
    /// This borrowed comparison performs no IO and creates no enrollment or loan.
    ///
    /// # Errors
    /// Refuses failed or incomplete opening, changed actual producer observation,
    /// or a node different from the original successful enrollment.
    pub(super) fn require_enrolled_node_data_v1(
        &self,
        node: [u8; 16],
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let expected = self.observed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let actual = self.original.observed_enrollment_data_v1()?;
        if actual != *expected || actual.identity.native_fields().node != node {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // A recipient transfer does not recreate any lost boot-lifetime P/I/Q/J
    // interval. Recovery must reconcile the actual prior entered/settled owner;
    // a Reserved history row and fresh process-local once bit are insufficient.
    fn initial_first_use_owner(&self) -> bool {
        self.launch.as_ref().is_none_or(aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1::is_initial_enrollment)
    }

    fn native_opened(&self) -> bool {
        match &self.launch {
            Some(launch) => matches!(self.launch_result, Some(Ok(()))) && launch.is_confirmed(),
            None => matches!(self.native, Some(Ok(_))) && matches!(self.readback, Some(Ok(()))),
        }
    }

    fn require_current_launch(&self, journal: &Journal, original: OriginalEnrollment)
        -> Result<(), ResourceReservationErrorV1>
    {
        match &self.launch {
            Some(launch) => journal.require_current_controller_launch_v1(launch)
                .map_err(ResourceReservationErrorV1::from),
            None if original.policy.bootstrap_provisions().storage_receiving.is_none() => Ok(()),
            None => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
        }
    }

    /// Borrows only the real current Controller conjunction for Publisher reads.
    ///
    /// The actual Domain administrative coordinator keeps the sole semantic
    /// commit engine. It drops this short role read before mutation, commits,
    /// then obtains a NEW same-original loan for independent readback.
    ///
    /// # Errors
    /// Refuses incomplete Bank/launch, foreign measured profile or writer, and
    /// failed original entry. No ordinary None/bool fallback exists here.
    pub(crate) fn borrow_publisher_current_v1<'writer, 'bank, 'profile>(
        &'bank self,
        journal: &'writer mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::PublisherControllerLoanV1<
        'writer, 'bank, 'profile, crate::journal::ControllerCoordinatorSelectionV1,
    >, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        { return Err(ResourceReservationErrorV1::Conflict); }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = journal.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        launch.require_current_controller_v1(writer)?;
        Ok(writer.borrow_publisher(launch, profile.lower_original_v1()))
    }

    /// Borrows the actual confirmed C conjunction for one Native Cache body.
    ///
    /// The caller retains this entire loan through its fixed body and owed
    /// posts. This crate-private return keeps the opaque native compaction
    /// selection within Domain; it exposes no mutable coordinator or file.
    pub(crate) fn borrow_cache_current_v1<'writer, 'bank, 'profile>(
        &'bank self,
        journal: &'writer mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConstructionLoanV1<
        'writer, 'bank, 'profile, crate::journal::ControllerCoordinatorSelectionV1,
    >, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        { return Err(ResourceReservationErrorV1::Conflict); }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = journal.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        launch.require_current_controller_v1(writer)?;
        Ok(writer.borrow_cache_construction(launch, profile.lower_original_v1()))
    }

    fn finish_bank_native_post_v1(&mut self, journal: &mut Journal) {
        self.journal_post = Some(match self.bank_native_post.as_mut() {
            Some(post) => journal.controller_coordinator_for_bank_v1()
                .and_then(|writer| writer.finish_independent_native_post_once(post)
                    .map_err(|_| JournalError::ProtectedBoundary)),
            None => Err(JournalError::ProtectedBoundary),
        });
    }

    /// Admits fixed Runtime and credential receiving before startup growth.
    ///
    /// Passive carrier widths cannot issue payment. This original selected C
    /// owns the sole B ledger, all once-only Results and both genuine profile
    /// bookends, before its existing parent or optional reader is constructed.
    ///
    /// # Errors
    /// Borrows the first actual receiving, original-file or comparison cause.
    /// Reentry creates no second admission. Interrupted, foreign-profile
    /// or exhausted entry cannot establish a successful receiving result.
    #[doc(hidden)]
    pub fn admit_runtime_startup_once(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        mut shape: super::runtime_receiving::ControllerRuntimeStartupShapeV1,
        credentials: super::runtime_receiving::ControllerRuntimeCredentialShapeV1,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.runtime_startup.is_some() || self.preopen_attempted || self.attempted
            || !matches!(self.selected_prefix, Some(Ok(())))
        {
            return Err(&CLOSED);
        }
        // This held policy DATA selects only which existing quote pays the
        // flight. It does not select a purpose or create an original loan.
        let flight_bytes = match self.original.observed_enrollment_data_v1() {
            Ok(original) if original.policy.bootstrap_provisions().first_global_prefix.is_some() => {
                // FirstGlobal's entered prefix prices its actual embedded flight.
                Some(0)
            }
            Ok(_) => crate::policy_compiler::
                root_flight_detached_construction_bytes_v1(),
            Err(_) => None,
        };
        // The selector's returned DATA, by-value policy/provision projection,
        // match inputs and checked arithmetic coexist with their destinations.
        // No old stream-buffer allowance or optimizer elision is credited.
        let selector_bytes = std::mem::size_of::<Result<
            OriginalEnrollment,
            aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1,
        >>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalEnrollment>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<bank::ImageBootstrapPolicy>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<bank::BootstrapProvisions>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<aos_sandbox_model::ResourceVector>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<bool>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                Option<usize>, Option<usize>, Option<usize>,
            )>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(usize, usize, usize)>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<usize>>().checked_mul(2)?));
        shape.fixed_destination_bytes = match (
            shape.fixed_destination_bytes, flight_bytes, selector_bytes,
        ) {
            (Some(fixed), Some(flight), Some(selector)) => fixed.checked_add(flight)
                .and_then(|bytes| bytes.checked_add(selector)),
            _ => None,
        };
        // Missing policy/overflow remains an unavailable checked shape. The
        // original lower before/task/pids gates, funding and owed posts still
        // run in their existing order; no early return or free zero is added.
        self.runtime_startup = Some(super::runtime_receiving::ControllerRuntimeStartupAdmissionV1::new());
        let attempt = self.runtime_startup.as_mut().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        attempt.observe(&self.original, profile.lower_original_v1(), shape, credentials);
        attempt.require_success()
    }

    /// Copies the same accepted task layout before actual Runtime construction.
    ///
    /// The closed lower admission checks the actual profile, full funding,
    /// native PID1/pids posts and disposal. This DATA grants no helper entry.
    #[doc(hidden)]
    #[must_use]
    pub fn admitted_runtime_task_envelope_v1(&self)
        -> Option<super::runtime_receiving::ControllerRuntimeTaskEnvelopeV1>
    {
        if self.failure().is_some() { return None; }
        self.runtime_startup.as_ref()?.admitted_task_envelope_v1()
    }

    /// Prepares the same-original initial Source receiving owner once.
    ///
    /// # Errors
    /// Retains a failed profile/original/phase claim before any credential growth.
    #[doc(hidden)]
    pub fn prepare_source_credentials_once(
        &mut self,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.source_credentials.is_some() || self.source_credentials_taken
            || self.preopen_attempted || self.attempted || self.failure().is_some()
            || self.runtime_startup.as_ref().is_none_or(|attempt| attempt.require_success().is_err())
        {
            return Err(&CLOSED);
        }
        self.source_credentials = Some(super::startup_credentials::ControllerSourceGenesisReceivingV1::new(
            std::sync::Arc::clone(&self.original), profile,
        ));
        let receiver = self.source_credentials.as_mut().ok_or(&CLOSED as &dyn std::error::Error)?;
        if receiver.prepare_once().is_err() {
            return Err(receiver.failure().unwrap_or(&CLOSED));
        }
        Ok(())
    }

    /// Moves only this opening's prepared fixed Source receiver once.
    #[doc(hidden)]
    pub fn take_source_credentials_once(&mut self) -> Option<super::startup_credentials::ControllerSourceGenesisReceivingV1> {
        if self.source_credentials_taken
            || !self.source_credentials.as_ref().is_some_and(|receiver| receiver.is_prepared())
        {
            return None;
        }
        self.source_credentials_taken = true;
        self.source_credentials.take()
    }

    /// Prepares late public TLS only after complete construction disposition.
    ///
    /// # Errors
    /// Retains failed or repeated same-original/profile/phase preparation.
    #[doc(hidden)]
    pub fn prepare_public_credentials_once(
        &mut self,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.public_credentials.is_some() || self.public_credentials_taken
            || !self.native_opened() || !matches!(self.enrolled_disposition, Some(Ok(())))
            || self.failure().is_some()
        {
            return Err(&CLOSED);
        }
        self.public_credentials = Some(super::startup_credentials::ControllerPublicTlsReceivingV1::new(
            std::sync::Arc::clone(&self.original), profile,
        ));
        let receiver = self.public_credentials.as_mut().ok_or(&CLOSED as &dyn std::error::Error)?;
        if receiver.prepare_once().is_err() {
            return Err(receiver.failure().unwrap_or(&CLOSED));
        }
        Ok(())
    }

    /// Moves only this opening's prepared fixed TLS receiver once.
    #[doc(hidden)]
    pub fn take_public_credentials_once(&mut self) -> Option<super::startup_credentials::ControllerPublicTlsReceivingV1> {
        if self.public_credentials_taken
            || !self.public_credentials.as_ref().is_some_and(|receiver| receiver.is_prepared())
        {
            return None;
        }
        self.public_credentials_taken = true;
        self.public_credentials.take()
    }

    /// Completes the fixed no-public phase without constructing TLS readers.
    ///
    /// # Errors
    /// Rejects public-enabled, incomplete, stale or repeated startup disposition.
    #[doc(hidden)]
    pub fn finish_startup_without_public_once(&mut self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.serving_disposition.is_some() || !self.native_opened()
            || !matches!(self.enrolled_disposition, Some(Ok(()))) || self.failure().is_some()
        {
            return Err(&CLOSED);
        }
        self.serving_disposition = Some(self.startup.serve_startup_without_public_once_v1()
            .map_err(ResourceReservationErrorV1::from));
        match self.serving_disposition.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(cause)) => Err(cause),
            None => Err(&CLOSED),
        }
    }

    /// Prepares the fixed recurring Publisher receiver under this SAME C/B once.
    ///
    /// Numeric identity DATA cannot construct this original. Its whole result
    /// is parked before the caller may take the completed owner. No authority
    /// lock or copied account crosses the later asynchronous native operation.
    ///
    /// # Errors
    /// Retains original capacity, profile, node or native-bank refusal. A
    /// failed or incomplete opening cannot construct a Publisher receiver.
    #[doc(hidden)]
    pub fn prepare_publisher_receiving_once(
        &mut self,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        startup: super::publisher_receiving::ControllerPublisherStartupDataV1,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.publisher_receiving.is_some() || self.publisher_receiving_taken
            || !self.native_opened() || !matches!(self.journal_post, Some(Ok(())))
            || !matches!(self.profile_post, Some(Ok(_))) || self.failure().is_some()
            || self.runtime_startup.as_ref().is_none_or(|attempt| attempt.require_success().is_err())
        {
            return Err(&CLOSED);
        }
        self.publisher_receiving = Some(super::publisher_receiving::ControllerPublisherReceivingV1::new(
            std::sync::Arc::clone(&self.original), profile, startup,
        ));
        let receiver = self.publisher_receiving.as_mut().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        if receiver.prepare_once().is_err() {
            return Err(receiver.failure().unwrap_or(&CLOSED));
        }
        Ok(())
    }

    /// Moves the SAME fully prepared fixed Publisher receiving owner once.
    #[doc(hidden)]
    pub fn take_publisher_receiving_once(
        &mut self,
    ) -> Option<super::publisher_receiving::ControllerPublisherReceivingV1> {
        if self.publisher_receiving_taken
            || !self.publisher_receiving.as_ref().is_some_and(
                super::publisher_receiving::ControllerPublisherReceivingV1::is_prepared,
            )
        {
            return None;
        }
        self.publisher_receiving_taken = true;
        self.publisher_receiving.take()
    }

    /// Prepares one fixed boot Client receiver under this same enrolled B.
    ///
    /// The shape describes concrete upper representation only. No numeric
    /// amount, replacement account, path or identity constructs this original.
    /// All later capture runs after this owner moves into its resident slot,
    /// outside the bank mutex and before any fixed endpoint or floor IO.
    ///
    /// # Errors
    /// Retains repeated-role, original-profile, enrollment and resource refusal.
    #[doc(hidden)]
    pub fn prepare_initial_broker_session_once_v1(
        &mut self,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        shape: super::initial_session::ControllerInitialBrokerSessionShapeV1,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        let index = role.index();
        if self.initial_sessions[index].is_some() || self.initial_sessions_taken[index]
            || !self.native_opened() || !matches!(self.journal_post, Some(Ok(())))
            || !matches!(self.profile_post, Some(Ok(_))) || self.failure().is_some()
            || self.runtime_startup.as_ref().is_none_or(|attempt| attempt.require_success().is_err())
            || !matches!(self.enrolled_disposition, Some(Ok(())))
        {
            return Err(&CLOSED);
        }
        self.initial_sessions[index] = Some(
            super::initial_session::ControllerInitialBrokerSessionReceivingV1::new(
                std::sync::Arc::clone(&self.original), profile, role,
            ),
        );
        let receiver = self.initial_sessions[index].as_mut().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        receiver.prepare_once(shape);
        if !receiver.is_prepared() {
            return Err(receiver.failure().unwrap_or(&CLOSED));
        }
        Ok(())
    }

    /// Moves only this opening's prepared once-role Client receiver.
    ///
    /// The intrinsic same-original role latch stays spent after this move.
    #[doc(hidden)]
    pub fn take_initial_broker_session_once_v1(
        &mut self,
        role: super::initial_session::ControllerInitialBrokerSessionRoleV1,
    ) -> Option<super::initial_session::ControllerInitialBrokerSessionReceivingV1> {
        let index = role.index();
        if self.initial_sessions_taken[index]
            || !self.initial_sessions[index].as_ref().is_some_and(
                super::initial_session::ControllerInitialBrokerSessionReceivingV1::is_prepared,
            )
        {
            return None;
        }
        self.initial_sessions_taken[index] = true;
        self.initial_sessions[index].take()
    }

    /// Imports the optional Cache credential under this same original B once.
    ///
    /// This closed selected startup route retains the shared importer and both
    /// Native source-open phases before effects. It neither issues another C
    /// claim nor replaces the ordinary importer for other supported callers.
    ///
    /// # Errors
    /// Retains actual source, model, native append/readback, resource and
    /// independent profile/currentness failures. Reentry remains closed.
    #[doc(hidden)]
    pub fn import_selected_cache_bundle_once(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        uid: u32,
        bundle: &[u8],
    ) -> Result<crate::journal::RecoveryReport, &(dyn std::error::Error + 'static)> {
        if self.cache_import.is_some() || self.preopen_attempted || self.attempted
            || self.runtime_startup.as_ref().is_none_or(|attempt| attempt.require_success().is_err())
            || self.failure().is_some()
        {
            return Err(&CLOSED);
        }
        let mut loan = self.startup.borrow_cache_prebank_import_once_v1(profile.lower_original_v1())
            .ok_or(&CLOSED as &(dyn std::error::Error + 'static))?;
        self.cache_import = Some(crate::cache_residency::CacheSelectedBootstrapImportV1::new());
        self.cache_import.as_mut().ok_or(&CLOSED as &(dyn std::error::Error + 'static))?
            .import_once(&mut loan, uid, bundle)
    }

    /// Prepays the installed issue-only retained startup on this SAME C.
    ///
    /// The compiled upper width and actual fixed credential recipe describe
    /// representation only. This creates no Runtime, source credential success,
    /// bank enrollment, launch acknowledgement or native Source writer.
    ///
    /// # Errors
    /// Retains shape/original/ledger refusal before any issue credential growth.
    #[doc(hidden)]
    pub fn prepare_source_successor_issue_once<Outer>(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        fixed_destination_bytes: Option<usize>,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.source_issue_debit.is_some() || self.preopen_attempted || self.attempted
            || self.failure().is_some() || !matches!(self.selected_prefix, Some(Ok(())))
        {
            return Err(&CLOSED);
        }
        self.source_issue_debit = Some((|| {
            let demand = crate::normal_root::ProductionControllerNormalRootProfileV1::
                source_successor_issue_receiving_demand_v2::<Outer>()?;
            let backing = fixed_destination_bytes
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let demand = demand.checked_add(aos_sandbox_model::ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, backing))
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.original.debit_source_successor_issue_startup_once_v1(profile.lower_original_v1(), demand)?;
            Ok(())
        })());
        match self.source_issue_debit.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(cause)) => Err(cause),
            None => Err(&CLOSED),
        }
    }

    /// Admits the original PID1-paid bootstrap interval before a Journal opens.
    ///
    /// This once-only admission retains independent observations even after
    /// an earlier failure. It issues neither native Bank enrollment nor an
    /// operation/read reservation, and creates no construction deadline.
    ///
    /// # Errors
    /// Borrows the first retained original recipient, file, or binding cause.
    /// Reentry and failed or interrupted admission never create another loan.
    pub fn admit_preopen_once(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.preopen_attempted || self.attempted {
            return Err(&CLOSED);
        }
        self.preopen_attempted = true;
        self.preopen = Some(ControllerResourcePreopenPostV1::new());
        let post = self.preopen.as_mut().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        post.observe(&self.original, profile, None);
        post.require_success()
    }

    /// Borrows the same live bootstrap owner without issuing native enrollment.
    ///
    /// The loan is non-Clone and remains tied to the original files/profile.
    /// It cannot expose amounts, descriptors, a new epoch, or a refund.
    ///
    /// # Errors
    /// Rejects absent, failed or spent pre-opening admission and foreign
    /// processes. Its independent current observations must precede effects.
    pub fn borrow_preopen<'owner>(
        &'owner self,
        profile: &'owner crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerResourcePreopenLoanV1<'owner>, &(dyn std::error::Error + 'static)> {
        if self.attempted || self.original.observed_enrollment_data_v1().is_err()
            || self.baseline_opening_closed()
        {
            return Err(&CLOSED);
        }
        let post = self.preopen.as_ref().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        post.require_success()?;
        profile.lower_original_v1().reserve_fixed_construction_posts_once_v1(&self.original)
            .map_err(|_| &CLOSED as &(dyn std::error::Error + 'static))?;
        Ok(ControllerResourcePreopenLoanV1 { opening: self, profile })
    }

    /// Enrolls the finite bootstrap accounts once on the original protected writer.
    ///
    /// # Errors
    /// Borrows the original observation, preparation, commit or independent
    /// post refusal. Ambiguous commits stay resident and never expose a bank.
    pub fn open_once(
        &mut self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        node: [u8; 16],
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.attempted {
            return Err(&CLOSED);
        }
        self.attempted = true;
        self.bank_native_post_entry = Some(match journal.controller_coordinator_for_bank_v1() {
            Ok(writer) => match writer.begin_independent_native_post_once() {
                Ok(post) => { self.bank_native_post = Some(post); Ok(()) }
                Err(cause) => Err(cause.into()),
            },
            Err(cause) => Err(cause.into()),
        });
        if self.bank_native_post_entry.as_ref().is_none_or(Result::is_err)
            || self.baseline_opening_closed()
            || (self.preopen_attempted
                && self.preopen.as_ref().is_none_or(|post| post.require_success().is_err()))
        {
            // Failed admission cannot reach enrollment, but the supplied
            // writer/profile still lend their independent negative posts.
            self.finish_bank_native_post_v1(journal);
            self.profile_post = Some(profile.require_resource_delivery());
            return Err(self.failure().unwrap_or(&CLOSED));
        }
        self.observed = Some(self.bank_observation.observe_once(&self.original, profile.lower_original_v1())
            .map_err(ResourceReservationErrorV1::from).and_then(|original| {
            if original.identity.native_fields().node != node {
                return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
            }
            Ok(original)
        }));
        let same_writer = journal.controller_coordinator_for_bank_v1()
            .and_then(|writer| writer.require_same_original_v1(&self.original)
                .map_err(|_| JournalError::ProtectedBoundary));
        if let Err(cause) = same_writer {
            self.native = Some(Err(cause));
        }
        self.names = Some(journal.protected_writer_physical_names_v1());
        if let Some(original) = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().filter(|_| self.names.as_ref().is_some_and(Result::is_ok))
        {
            let selected = original.policy.bootstrap_provisions().storage_receiving.is_some();
            if selected != self.launch.is_some() {
                self.launch_result = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
            } else if selected && self.native.as_ref().is_none_or(Result::is_ok) {
                let launch = self.launch.as_mut().ok_or(&CLOSED as &(dyn std::error::Error + 'static))?;
                match journal.controller_coordinator_for_bank_v1() {
                    Ok(writer) => match launch.prepare_once(writer, profile.lower_original_v1()) {
                        Ok(mutation) => self.bank_mutation = Some(mutation),
                        Err(cause) => self.launch_result = Some(Err(cause.into())),
                    },
                    Err(cause) => self.native = Some(Err(cause)),
                }
                if let Some(mutation) = self.bank_mutation.as_ref() {
                    self.native = Some(journal.commit_controller_resource_transition_v1(
                        mutation.transaction(),
                        &Transition { original: TransitionOriginal::ControllerLaunch(launch), crossing: None },
                    ));
                }
                // Independent same-native readback and posts run even after
                // the actual upper semantic/native append returned Err.
                if launch.has_owed_native_post_v1() {
                    let returned = match journal.controller_coordinator_for_bank_v1() {
                        Ok(writer) => launch.finish_native_once(writer, profile.lower_original_v1())
                            .map_err(ResourceReservationErrorV1::from),
                        Err(cause) => Err(cause.into()),
                    };
                    // Keep the earlier prepare cause; lower finish retains its
                    // own independent native/profile results on the same owner.
                    if self.launch_result.is_none() { self.launch_result = Some(returned); }
                }
            } else if !selected && self.native.as_ref().is_none_or(Result::is_ok) {
                self.prepared = Some(journal.controller_coordinator_for_bank_v1()
                    .map_err(ResourceReservationErrorV1::from)
                    .and_then(|writer| writer.prepare_initial_enrollment_once_v1()
                        .map_err(ResourceReservationErrorV1::from)));
                if let Some(Ok(prepared)) = self.prepared.as_ref() {
                    self.native = Some(journal.commit_controller_resource_transition_v1(
                        prepared.transaction(),
                        &Transition { original: TransitionOriginal::Enrollment(prepared), crossing: None },
                    ));
                    // An actual commit Err does not suppress same-writer
                    // negative readback; that cannot mint another owner.
                    self.readback = Some(journal.controller_coordinator_for_bank_v1()
                        .map_err(ResourceReservationErrorV1::from)
                        .and_then(|writer| prepared.require_returned(writer)
                            .map_err(ResourceReservationErrorV1::from)));
                }
            }
        }
        // Both independent posts run after native Err and observation Err.
        self.finish_bank_native_post_v1(journal);
        self.profile_post = Some(profile.require_resource_delivery());
        if self.failure().is_some() {
            return Err(self.failure().unwrap_or(&CLOSED));
        }
        if !self.native_opened() {
            return Err(&CLOSED);
        }
        if self.runtime_startup.is_some() {
            self.enrolled_disposition = Some(journal.controller_coordinator_for_bank_v1()
                .and_then(|writer| writer.finish_bank_startup_disposition_once_v1()
                    .map_err(|_| JournalError::ProtectedBoundary))
                .map_err(ResourceReservationErrorV1::from));
            if let Some(Err(cause)) = self.enrolled_disposition.as_ref() {
                return Err(cause);
            }
        }
        self.bank_native_post_disposition = Some(match self.bank_native_post.as_mut() {
            Some(post) => journal.controller_coordinator_for_bank_v1()
                .and_then(|writer| writer.dispose_native_post_after_upper_posts_once(post)
                    .map_err(|_| JournalError::ProtectedBoundary))
                .map_err(ResourceReservationErrorV1::from),
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if self.bank_native_post_disposition.as_ref().is_some_and(Result::is_err) {
            return Err(self.failure().unwrap_or(&CLOSED));
        }
        Ok(())
    }

    /// Borrows the earliest original cause in the fixed opening schedule.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.source_issue_debit { return Some(cause); }
        self.wrapper_debit.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.selected_prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.runtime_startup.as_ref().and_then(
                super::runtime_receiving::ControllerRuntimeStartupAdmissionV1::failure,
            ))
            .or_else(|| self.source_credentials.as_ref().and_then(|receiver| receiver.failure()))
            .or_else(|| self.cache_import.as_ref().and_then(crate::cache_residency::CacheSelectedBootstrapImportV1::failure))
            .or_else(|| self.preopen.as_ref().and_then(ControllerResourcePreopenPostV1::failure))
            .or_else(|| self.launch_admission.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.bank_native_post_entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.bank_observation.failure())
            .or_else(|| self.launch.as_ref().and_then(aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1::failure))
            .or_else(|| self.baseline_opening_closed().then_some(
                &CLOSED as &(dyn std::error::Error + 'static),
            ))
            .or_else(|| self.observed.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            )
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.launch_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|prepared| prepared.failure()))
            .or_else(|| self.prepared.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.readback.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.bank_native_post.as_ref().and_then(|post| post.failure()))
            .or_else(|| self.journal_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.profile_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.bank_native_post_disposition.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.enrolled_disposition.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.public_credentials.as_ref().and_then(|receiver| receiver.failure()))
            .or_else(|| self.serving_disposition.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.initial_sessions.iter().flatten().find_map(
                super::initial_session::ControllerInitialBrokerSessionReceivingV1::failure,
            ))
            .or_else(|| self.publisher_receiving.as_ref().and_then(
                super::publisher_receiving::ControllerPublisherReceivingV1::failure,
            ))
    }
}

/// Borrows only the original Controller's PID1 bootstrap obligation.
///
/// This owner-bound short loan is not an operation/read permit or native
/// enrollment. Dropping it refunds nothing and cannot replace the originals.
pub struct ControllerResourcePreopenLoanV1<'owner> {
    opening: &'owner ControllerResourceBankOpeningV1,
    profile: &'owner crate::normal_root::ProductionControllerNormalRootProfileV1,
}

impl<'owner> ControllerResourcePreopenLoanV1<'owner> {
    /// Arms the same actual pre-Bank Source debt before either native body.
    ///
    /// # Errors
    /// Refuses absent/failed original admission or a spent Source purpose. The
    /// returned closed loan still must enter its fixed body before Source IO.
    #[doc(hidden)]
    pub fn arm_source_construction_once_v1(&self)
        -> Result<aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'owner>, ResourceReservationErrorV1>
    {
        self.opening.preopen.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_success().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.opening.startup.arm_source_prebank_construction_once_v1(self.profile.lower_original_v1())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn lower_profile_v1(&self)
        -> &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1
    {
        self.profile.lower_original_v1()
    }

    pub(crate) fn require_fixed_controller_recipe_v1(
        &self,
        directory: &std::path::Path,
        uid: u32,
        node: [u8; 16],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_node(node)?;
        if directory != std::path::Path::new("/var/lib/aos/sandboxd")
            || uid != self.lower_profile_v1().schema().identities[0]
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }

    pub(crate) fn take_fixed_controller_opening_once_v1(&self)
        -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerWriterOpeningOriginalV1,
            ResourceReservationErrorV1>
    {
        if self.native_opening_closed() { return Err(ResourceReservationErrorV1::Conflict); }
        self.opening.writer_opening.try_borrow_mut()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?
            .take().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn require_node(&self, node: [u8; 16]) -> Result<(), ResourceReservationErrorV1> {
        let original = self.opening.preopen.as_ref()
            .and_then(|post| post.original.value())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if original.identity.native_fields().node != node {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    }

    pub(crate) fn native_opening_closed(&self) -> bool {
        self.opening.baseline_opening_closed()
    }

    pub(crate) fn observe_source_post_into(&self, post: &mut ControllerResourcePreopenPostV1) {
        if post.returned.is_some() { return; }
        post.returned = Some(self.lower_profile_v1().observe_source_construction_post_retaining_v1(
            &self.opening.original, &mut post.original,
        ));
    }

    pub(crate) fn observe_controller_post_into(&self, post: &mut ControllerResourcePreopenPostV1) {
        if post.returned.is_some() { return; }
        post.returned = Some(self.lower_profile_v1().observe_controller_construction_post_retaining_v1(
            &self.opening.original, &mut post.original,
        ));
    }

    pub(crate) fn observe_into(&self, post: &mut ControllerResourcePreopenPostV1) {
        // Independent original posts remain available after a native-budget Err.
        let admitted = self.opening.preopen.as_ref()
            .and_then(|post| post.original.value());
        post.observe(&self.opening.original, self.profile, admitted);
    }
}

/// Retains the actual fixed lower profile/pair/profile construction observation.
///
/// This carrier contains comparison DATA only. Its genuine Bank loan selects
/// the prearmed purpose; no caller File, vector or body callback is accepted.
pub struct ControllerResourcePreopenPostV1 {
    original: aos_sandbox_broker::controller_receiving::ControllerOriginalObservationV1,
    returned: Option<Result<(), aos_sandbox_broker::controller_receiving::profile::ControllerProfileErrorV1>>,
}

impl ControllerResourcePreopenPostV1 {
    pub(crate) const fn new() -> Self {
        Self { original: aos_sandbox_broker::controller_receiving::ControllerOriginalObservationV1::new(),
            returned: None }
    }

    fn observe(
        &mut self,
        original: &std::sync::Arc<aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1>,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        _admitted: Option<&OriginalEnrollment>,
    ) {
        if self.returned.is_some() { return; }
        self.returned = Some(self.original.observe_once(original, profile.lower_original_v1())
            .map(|_| ()).map_err(|_| aos_sandbox_broker::controller_receiving::profile::ControllerProfileErrorV1::Service));
    }

    pub(crate) fn require_success(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.failure() { return Err(cause); }
        if !matches!(self.returned, Some(Ok(()))) || self.original.value().is_none() { return Err(&CLOSED); }
        Ok(())
    }

    /// Borrows the earliest actual native/control/profile refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure().or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

static CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::EnrollmentUnavailable;

#[cfg(test)]
mod controller_layout_tests {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use sha2::{Digest as _, Sha256};
    use super::bank;

    fn image_with(q: ResourceVector, j: ResourceVector) -> Vec<u8> {
        let mut bytes = vec![0; bank::CREATE_STORAGE_IMAGE_POLICY_BYTES];
        bytes[..8].copy_from_slice(b"AOSRSB07");
        bytes[8..24].fill(1);
        bytes[24..40].fill(2);
        let generous = ResourceVector::new([1 << 40; D::COUNT]);
        let tiny = ResourceVector::new([1; D::COUNT]).with(D::CpuMicrosPerPeriod, 1000)
            .with(D::MemoryBytes, 4096).with(D::Pids, 2).with(D::OpenFiles, 80);
        let storage = tiny.with(D::MemoryBytes, 512 * 1024 * 1024)
            .with(D::Pids, 32).with(D::OpenFiles, 256);
        for (start, vector) in [(40, generous), (216, tiny),
            (392, ResourceVector::new([1 << 38; D::COUNT])),
            (568, ResourceVector::new([1 << 38; D::COUNT])),
            (744, tiny), (920, tiny), (1096, tiny), (1272, tiny),
            (1448, q), (1624, tiny), (1800, j), (1976, storage)] {
            for (index, dimension) in D::ALL.into_iter().enumerate() {
                let offset = start + index * 8;
                bytes[offset..offset + 8].copy_from_slice(&vector.get(dimension).to_be_bytes());
            }
        }
        let end = bytes.len() - 32;
        let checksum = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&checksum);
        bytes
    }

    #[test]
    fn actual_controller_layout_refuses_insufficient_q_and_j_even_when_component_data_is_valid() {
        let layout = crate::controller_resource_reservation::q04_intake::native_layout();
        let q = bank::minimum_q04_failure_demand(layout).unwrap().with(D::CpuMicrosPerPeriod, 1000);
        let j = bank::minimum_create_intake_failure_demand(layout).unwrap().with(D::CpuMicrosPerPeriod, 1000);
        let bytes = image_with(q, j);
        assert!(bank::decode_component_image_policy(&bytes).is_ok());
        assert!(bank::decode_image_policy(&bytes, layout).is_ok());

        for (bad_q, bad_j) in [
            (q.with(D::MemoryBytes, q.get(D::MemoryBytes) - 1), j),
            (q, j.with(D::MemoryBytes, j.get(D::MemoryBytes) - 1)),
        ] {
            let bytes = image_with(bad_q, bad_j);
            assert!(bank::decode_component_image_policy(&bytes).is_ok());
            assert!(matches!(bank::decode_image_policy(&bytes, layout),
                Err(bank::ResourceBankDataError::Accounting(_))));
        }
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Claims the actual measured C Delete subdivision beside its SAME writer.
    pub(crate) fn claim_delete_operation_intake_once_v1(
        &self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        resident: super::operation_intake::ControllerOperationIntakeDemandDataV1,
        flight_capacity: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(journal, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        journal.controller_coordinator_for_bank_v1()?
            .claim_delete_operation_intake_once_v1(launch, profile.lower_original_v1(), resident, flight_capacity)
            .map_err(Into::into)
    }

    /// Claims the actual measured C accepted-execution subdivision only.
    pub(crate) fn claim_execution_operation_intake_once_v1(
        &self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        resident: super::operation_intake::ControllerOperationIntakeDemandDataV1,
        flight_capacity: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(journal, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        journal.controller_coordinator_for_bank_v1()?
            .claim_execution_operation_intake_once_v1(launch, profile.lower_original_v1(), resident, flight_capacity)
            .map_err(Into::into)
    }

    /// Claims the same declared delete lane after actual native overhead.
    pub(crate) fn claim_declared_delete_operation_intake_once_v1(
        &self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        resident: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(journal, profile)?;
        let declared = self.original.observed_enrollment_data_v1()?.policy
            .bootstrap_provisions().delete_operation_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let capacity = super::operation_intake::ControllerOperationIntakeDemandDataV1::
            from_declared_delete_remaining_v1(declared, resident, profile.lower_original_v1())?;
        self.claim_delete_operation_intake_once_v1(journal, profile, resident, capacity)
    }

    /// Claims the same declared execution lane after actual native overhead.
    pub(crate) fn claim_declared_execution_operation_intake_once_v1(
        &self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        resident: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeOriginalV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(journal, profile)?;
        let declared = self.original.observed_enrollment_data_v1()?.policy
            .bootstrap_provisions().execution_operation_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let capacity = super::operation_intake::ControllerOperationIntakeDemandDataV1::
            from_declared_remaining_v1(declared, resident, profile.lower_original_v1())?;
        self.claim_execution_operation_intake_once_v1(journal, profile, resident, capacity)
    }

    // No profile/native IO occurs here. The actual purpose borrower pays its
    // whole currentness recipe before any raw/native observation or decoding.
    fn require_operation_intake_entry_v1(
        &self, journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some()
            || !self.native_opened()
            || !self.initial_first_use_owner()
            || self.original.is_closed()
            || !profile.lower_original_v1().has_same_baseline_original(&self.original)
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = journal.controller_coordinator_for_bank_read_v1()?;
        writer.require_same_original_v1(&self.original)?;
        launch.require_current_controller_v1(writer)?;
        Ok(())
    }

    // The actual intake selects its funding branch. This does not broaden the
    // initial first-use entrance: recovered owners must retain a completed
    // enrollment association and their full durable funding row instead.
    pub(crate) fn require_funded_operation_intake_entry_v2(
        &self,
        owner: &super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFundingKindDataV2 as Kind;

        match owner.funding_kind_data_v2() {
            Kind::InitialReservedClaim => self.require_operation_intake_entry_v1(journal, profile),
            Kind::RecoveredBaseline => {
                if self.failure().is_some() || !self.native_opened() || self.original.is_closed()
                    || !profile.lower_original_v1().has_same_baseline_original(&self.original)
                {
                    return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
                }

                let launch = self.launch.as_ref()
                    .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
                owner.require_recovered_entry_v2(
                    journal.controller_coordinator_for_bank_read_v1()?,
                    launch,
                    profile.lower_original_v1(),
                ).map_err(Into::into)
            }
        }
    }

    /// Reborrows the existing same-Journal native owner under its purpose guard.
    pub(crate) fn begin_operation_intake_receiving_v1<'owner>(
        &self,
        owner: &'owner mut super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        demand: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        self.require_funded_operation_intake_entry_v2(owner, journal, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        owner.borrow_receiving_v1(journal.controller_coordinator_for_bank_v1()?, launch,
            profile.lower_original_v1(), demand).map_err(Into::into)
    }

    /// Consumes the actual finite Delete declaration before authorization IO.
    pub(crate) fn begin_delete_whole_declared_v1<'owner>(
        &self,
        owner: &'owner mut super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        initial: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        self.require_funded_operation_intake_entry_v2(owner, journal, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        owner.borrow_delete_whole_declared_v1(journal.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), initial).map_err(Into::into)
    }

    /// Checks the complete reached shape on the same continuously held Delete.
    pub(crate) fn require_delete_complete_v1(
        &self,
        loan: &mut super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'_>,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        complete: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        loan.require_delete_complete_v1(journal.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn begin_execution_whole_declared_v1<'owner>(
        &self,
        owner: &'owner mut super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        initial: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        self.require_funded_operation_intake_entry_v2(owner, journal, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        owner.borrow_execution_whole_declared_v1(journal.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), initial).map_err(Into::into)
    }

    pub(crate) fn require_execution_complete_v1(
        &self,
        loan: &mut super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'_>,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        complete: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        loan.require_execution_complete_v1(journal.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    /// Checks the actual same writer without lending or replacing its authority.
    pub(crate) fn require_operation_intake_current_v1(
        &self,
        loan: &super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'_>,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        loan.require_active_v1(journal.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1()).map_err(Into::into)
    }

    /// Runs the already-paid final native post after either upper body outcome.
    pub(crate) fn finish_operation_intake_native_once_v1(
        &self,
        loan: &mut super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'_>,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        // Deliberately no healthy-entry check: SAME native identity is checked
        // below while the independently prepaid names/profile posts stay owed.
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        loan.finish_native_once_v1(journal.controller_coordinator_for_bank_v1()?, launch,
            profile.lower_original_v1()).map_err(Into::into)
    }

    /// Prepares positive native disposition before actual upper carrier Drop.
    pub(crate) fn prepare_operation_intake_disposal_v1<'disposal>(
        &self,
        loan: &'disposal mut super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'_>,
        journal: &'disposal Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeDisposalV1<'disposal>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        loan.prepare_positive_disposal_v1(journal.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn borrow_execution_source_scope_v1<'scope, 'original>(
        &self,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        loan: &'scope mut super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<super::operation_intake::ControllerExecutionSourceScopeV1<'scope, 'original>, ResourceReservationErrorV1> {
        self.require_operation_intake_current_v1(loan, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().borrow_source_for_execution_v1(
            loan, controller, launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    pub(crate) fn require_execution_source_read_complete_v1(
        &self,
        receiving: &mut super::operation_intake::ControllerExecutionSourceCompleteBorrowV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        complete: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_complete_v1(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn require_execution_source_complete_v1(
        &self,
        scope: &mut super::operation_intake::ControllerExecutionSourceScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        complete: super::operation_intake::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        scope.require_complete_v1(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn finish_execution_source_native_once_v1(
        &self,
        scope: &mut super::operation_intake::ControllerExecutionSourceScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        // Owed completion does not reenter the healthy admission accessor.
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        scope.finish_native_once_v1(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    /// Prepares the joint native token before the actual upper disposal cut.
    pub(crate) fn prepare_delete_source_disposal_v1<'disposal>(
        &self,
        scope: &'disposal mut super::operation_intake::ControllerDeleteSourceScopeV1<'_, '_>,
        controller: &'disposal Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<super::operation_intake::ControllerDeleteSourceDisposalV1<'disposal>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        scope.prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn prepare_execution_source_disposal_v1<'disposal>(
        &self,
        scope: &'disposal mut super::operation_intake::ControllerExecutionSourceScopeV1<'_, '_>,
        controller: &'disposal Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<super::operation_intake::ControllerExecutionSourceDisposalV1<'disposal>, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        scope.prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    /// Borrows only the actual Delete admission cause from this same bank.
    pub(crate) fn delete_operation_intake_failure_view_v1<'journal>(
        &self, journal: &'journal Journal,
    ) -> Option<super::operation_intake::ControllerOperationIntakeFailureViewV1<'journal>> {
        let writer = journal.controller_coordinator_for_bank_read_v1().ok()?;
        writer.require_same_original_v1(&self.original).ok()?;
        writer.delete_operation_intake_failure_view_v1()
    }

    /// Borrows only the actual execution admission cause from this same bank.
    pub(crate) fn execution_operation_intake_failure_view_v1<'journal>(
        &self, journal: &'journal Journal,
    ) -> Option<super::operation_intake::ControllerOperationIntakeFailureViewV1<'journal>> {
        let writer = journal.controller_coordinator_for_bank_read_v1().ok()?;
        writer.require_same_original_v1(&self.original).ok()?;
        writer.execution_operation_intake_failure_view_v1()
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Publishes the minimal Environment only through the same real Source/X cut.
    ///
    /// # Errors
    /// Preserves actual Launch/profile/C, canonical model and native refusals.
    pub(crate) fn publish_execution_environment_once_v1(
        &self, source: &mut super::operation_intake::ControllerExecutionSourceScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        client: &mut crate::normal_root::RootEnvironmentClientOriginalV1,
        publication: &mut crate::environment::deployment::EnvironmentSourcePublicationOriginalV1,
        clock: &mut crate::controller_execution_operation::ControllerExecutionClockOriginalV1,
        complete: &mut aos_sandbox_model::ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.publish_environment_once_v1(controller, launch, profile.lower_original_v1(),
            client, publication, clock, complete).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn resume_execution_admission_native_v2<'owner>(
        &self,
        owner: &'owner mut super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<super::operation_intake::ControllerOperationIntakeReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        owner.resume_execution_admission_v2(
            journal.controller_coordinator_for_bank_read_v1()?, profile.lower_original_v1(),
        ).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn require_parked_execution_admission_current_v2(
        &self,
        owner: &super::operation_intake::ControllerOperationIntakeOriginalV1,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        owner.require_parked_execution_admission_current_v2(
            journal.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }
}

mod catalog_maintenance;
