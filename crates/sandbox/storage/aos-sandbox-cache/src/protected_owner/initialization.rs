//! Retains Cache's actual fixed construction originals and native continuations.
//!
//! The five writers stay private through their complete replay, independent
//! name checks and late same-owner transfer. Controller acquisition and
//! Domain programme errors remain upper; only genuine Broker loans price the
//! native constructor. This owner accepts no writer, descriptor or map adopter.

#[cfg(target_os = "linux")]
pub(crate) mod baseline;
#[cfg(target_os = "linux")]
mod git_coverage;
#[cfg(target_os = "linux")]
mod git_operation;
#[cfg(target_os = "linux")]
pub use git_operation::CacheGitOperationOriginalV1;
#[cfg(target_os = "linux")]
mod pin_mutation;
#[cfg(target_os = "linux")]
pub(crate) mod create_storage;

#[cfg(target_os = "linux")]
pub(crate) mod original_q04;
#[cfg(target_os = "linux")]
pub(crate) mod q04_capture_pricing;
#[cfg(target_os = "linux")]
use original_q04::Q04ResidentCacheProgressV1;

use std::sync::Arc;

use super::*;
use crate::controller_bootstrap::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
    open_existing_controller_cache_source,
};
use crate::clock::read_cache_clock_floor;
use crate::journal::{Journal, JournalError, JournalLimits, RecoveryReport};
use crate::protected_transaction::ProtectedDomainJournalErrorV1;
use aos_sandbox_broker::systemd_credentials::GitCoverageCredentialCustodyV1;
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageCatalogV1, GitCoverageDataErrorV1, GitCoverageEnrollmentV1,
    GitCoverageBirthFieldsV1, GitCoverageBirthV1, GitCoverageFenceFieldsV1,
    GitCoverageJournalProfileV1,
};
use crate::journal::CacheGitCoverageObservationV1;

/// Classifies resident initialization failure without moving its actual cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheResidentUnavailableV1;

impl std::fmt::Display for CacheResidentUnavailableV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("existing resident Cache initialization is unavailable")
    }
}

impl std::error::Error for CacheResidentUnavailableV1 {}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InitializationCauseV1 {
    #[cfg(target_os = "linux")]
    #[error("selected Cache baseline admission failed")]
    Baseline,
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Source(#[from] CacheReplayControllerBootstrapErrorV1),
    #[error(transparent)]
    Target(#[from] CacheResidencyProtectedJournalErrorV1),
    #[error(transparent)]
    Recovery(#[from] crate::RecoveryError),
    #[error("existing Cache provisioning is required")]
    ProvisioningRequired,
    #[error("resident Cache initialization is closed")]
    Closed,
    #[error("resident Cache replay failed")]
    Replay,
    #[error("resident Cache authority observation failed")]
    Evidence,
    #[error("resident Cache currentness postcheck failed")]
    TargetPostcheck,
    #[error("legacy Cache transition is unsupported under resident custody")]
    UnsupportedTransition,
    #[cfg(target_os = "linux")]
    #[error("resident Cache pin mutation is unresolved")]
    Mutation,
    #[cfg(target_os = "linux")]
    #[error("resident physical Cache capture failed")]
    PhysicalOpen,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Physical(#[from] super::super::CacheOwnerErrorV1),
    #[cfg(target_os = "linux")]
    #[error("resident Q04 Cache continuation is unresolved")]
    Q04,
    #[cfg(target_os = "linux")]
    #[error("resident new Create Storage Cache Held continuation is unresolved")]
    CreateStorageHeld,
    #[cfg(target_os = "linux")]
    #[error("original Q04 Cache pricing capture is unresolved")]
    Q04Preflight,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    CoverageData(#[from] GitCoverageDataErrorV1),
    #[cfg(target_os = "linux")]
    #[error("the original fixed Git coverage inputs are unavailable")]
    CoverageInputs,
    #[cfg(target_os = "linux")]
    #[error("the original Cache cohort has unclassified or retained tenant state")]
    CoverageResidual,
    #[cfg(target_os = "linux")]
    #[error("the original Cache coverage append has unresolved custody")]
    CoverageAppend,
    #[cfg(target_os = "linux")]
    #[error("the original Git read metadata crossing has unresolved custody")]
    ReadMetadata,
}

// These comparison coordinates are derived only inside the fixed Controller
// credential recipe. They never replace the retained files or Root deployment.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct CacheGitCoverageInputsV1 {
    project: ProjectId,
    node: [u8; 16],
    epoch: [u8; 16],
    generation: u64,
    issued_seconds: u64,
    expires_seconds: u64,
    enrollment: [u8; 32],
    catalog: [u8; 32],
}

#[cfg(target_os = "linux")]
impl CacheGitCoverageInputsV1 {
    fn capture(
        original: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<Self, InitializationCauseV1> {
        original.recheck_controller_inputs_v1()
            .map_err(|_| InitializationCauseV1::CoverageInputs)?;
        let data = original.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
        let (project_pin, deployment_pin) = data.role_pins();
        enrollment.verify_role_credentials(project_pin, deployment_pin)?;
        catalog.compare_enrollment(&enrollment)?;

        let (node, epoch) = enrollment.node_epoch();
        let (generation, issued_seconds, expires_seconds) = enrollment.generation_interval();
        Ok(Self {
            project: enrollment.project(),
            node,
            epoch,
            generation,
            issued_seconds,
            expires_seconds,
            enrollment: enrollment.digest(),
            catalog: catalog.digest(),
        })
    }

    fn require_observation(
        self,
        observation: CacheGitCoverageObservationV1,
    ) -> Result<(), InitializationCauseV1> {
        let (birth, fence, _, _) = observation.original_coordinates();
        if birth.project != self.project
            || birth.node != self.node
            || birth.epoch != self.epoch
            || birth.enrollment != self.enrollment
            || birth.catalog != self.catalog
            || fence.generation != self.generation
        {
            return Err(InitializationCauseV1::CoverageInputs);
        }
        Ok(())
    }
}

#[derive(Default)]
struct CacheResidentTargetsV1 {
    authority_journal: Option<Journal>,
    authority_report: Option<RecoveryReport>,
    authority: Option<Arc<ProtectedCacheResidencyReplayAuthorityV1>>,
    // Keeps the actual initialized authority allocation alive after ownership
    // moves into the returned Cache. Later closed loans compare this original.
    #[cfg(target_os = "linux")]
    initialized_authority: Option<Arc<ProtectedCacheResidencyReplayAuthorityV1>>,
    state_journal: Option<Journal>,
    state_report: Option<RecoveryReport>,
    replay: Option<Result<CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalErrorV1>>,
    evidence: Option<Result<Vec<CacheResidencyReplayPartitionEvidenceV1>, CacheResidencyProtectedJournalErrorV1>>,
    postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
}

/// Retains every native fixed initialization original through failure.
///
/// The upper programme retains its Controller/Root/Source semantic attempts.
/// This owner keeps the actual Cache writers, physical result and precise
/// native causes; failed work cannot be reopened through another constructor.
#[derive(Default)]
pub struct CacheResidentInitializationV1 {
    #[cfg(target_os = "linux")]
    q04: Q04ResidentCacheProgressV1,
    #[cfg(target_os = "linux")]
    q04_capture_shape: Option<q04_capture_pricing::ShapeResult>,
    #[cfg(target_os = "linux")]
    q04_capture_posts: [Option<q04_capture_pricing::ShapeResult>; q04_capture_pricing::SHAPE_POSTS],
    #[cfg(target_os = "linux")]
    q04_capture_post_count: usize,
    #[cfg(target_os = "linux")]
    q04_capture_changed: Option<CacheReplayControllerBootstrapErrorV1>,

    #[cfg(target_os = "linux")]
    selected_baseline: Option<baseline::CacheSelectedInitializationV1>,
    #[cfg(target_os = "linux")]
    create_storage_held: create_storage::CacheHeldProgressV1,
    #[cfg(target_os = "linux")]
    coverage_inputs: Option<CacheGitCoverageInputsV1>,
    #[cfg(target_os = "linux")]
    original_coverage: Option<Option<CacheGitCoverageObservationV1>>,
    #[cfg(target_os = "linux")]
    coverage_append_started: bool,
    #[cfg(target_os = "linux")]
    coverage_account_capture_started: bool,
    #[cfg(target_os = "linux")]
    read_metadata: CacheClockReadMetadataProgressV1,
    #[cfg(target_os = "linux")]
    read_metadata_active: bool,
    #[cfg(target_os = "linux")]
    coverage_transaction: Option<JournalTransaction>,
    #[cfg(target_os = "linux")]
    coverage_commit: Option<Result<crate::journal::CommitResult, JournalError>>,
    #[cfg(target_os = "linux")]
    coverage_readback: Option<Result<CacheGitCoverageObservationV1, JournalError>>,
    source_open: Option<(Journal, RecoveryReport)>,
    source: Option<CacheReplayControllerBootstrapOwnerV1>,
    source_report: Option<RecoveryReport>,
    hold: Option<(Journal, RecoveryReport)>,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    clock_open: Option<(Journal, RecoveryReport)>,
    clock: Option<Arc<ProtectedCacheClockV1>>,
    clock_report: Option<RecoveryReport>,
    targets: CacheResidentTargetsV1,
    first_failure: Option<InitializationCauseV1>,
    postcheck: Option<InitializationCauseV1>,
    started: bool,
    complete: bool,
    #[cfg(target_os = "linux")]
    physical_open: crate::physical::ResidentCachePhysicalOpenV1,
    #[cfg(target_os = "linux")]
    physical_limits: Option<CacheOwnerLimitsV1>,
    #[cfg(target_os = "linux")]
    mutations: Vec<ResidentCachePinMutationV1>,
    #[cfg(target_os = "linux")]
    pin_inventory: Option<Result<Vec<CacheRecoveryInventoryV1>, CacheResidencyProtectedJournalErrorV1>>,
}

impl CacheResidentInitializationV1 {
    /// Creates only an empty destination, before any fixed open or observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether the selected fixed attempt has begun, including failure.
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }















    /// Initializes the same existing owners for fixed exclusive-cohort readback.
    ///
    /// The original credential owner remains with the installed caller. This
    /// operation checks its fixed Controller role and complete signed carriers;
    /// it grants neither enrollment, allocation nor a complete account. A
    /// persisted fence must match those original carriers exactly.
    ///
    /// # Errors
    /// Retains all returned Cache originals and permanently refuses changed
    /// inputs, failed reuse, missing provisioning or unresolved owner checks.
    #[cfg(target_os = "linux")]
    pub fn initialize_git_coverage_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.started = true;
        if destination.is_some() {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        match CacheGitCoverageInputsV1::capture(original_inputs) {
            Ok(inputs) => self.coverage_inputs = Some(inputs),
            Err(cause) => {
                self.first_failure = Some(cause);
                return Err(CacheResidentUnavailableV1);
            }
        }

        let returned = self.initialize_after_prearm(destination, owner_uid)
            .and_then(|()| match destination.as_mut() {
                Some(owner) => self.compare_fixed_git_coverage_catalog(owner, original_inputs),
                None => {
                    self.complete = false;
                    self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                    Err(CacheResidentUnavailableV1)
                }
            });
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.postcheck.get_or_insert(cause);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Initializes the exact existing source and Cache owners once.
    ///
    /// The configured service UID follows the existing fixed-owner contract.
    /// No caller path, journal, evidence, clock or factory is accepted.
    ///
    /// # Errors
    /// Permanently refuses failed reuse, occupied destinations, missing or
    /// malformed provisioning, changed originals, or incomplete reconciliation.
    pub fn initialize_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.started = true;
        // `complete` remains false on every early return and unwind.
        if destination.is_some() {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        self.initialize_after_prearm(destination, owner_uid)
    }

    fn initialize_after_prearm(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.initialize_after_prearm_priced::<()>(destination, owner_uid,
            #[cfg(target_os = "linux")] None,
            #[cfg(target_os = "linux")] None)
    }

    fn initialize_after_prearm_priced<P>(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        #[cfg(target_os = "linux")]
        receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
        #[cfg(target_os = "linux")]
        mut stages: Option<&mut [baseline::CacheNativeStageV1; 5]>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if let Err(cause) = self.capture_before_clock::<P>(owner_uid,
            #[cfg(target_os = "linux")] stages.as_deref_mut(),
            #[cfg(target_os = "linux")] receiving) {
            self.first_failure = Some(cause);
            return Err(CacheResidentUnavailableV1);
        }
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure = Some(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            #[cfg(target_os = "linux")]
            if let Some(inputs) = self.coverage_inputs {
                self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                    .recheck_existing()?;
                let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
                require_original_hold(
                    &mut hold.0, self.original_hold,
                    self.coverage_inputs, self.original_coverage,
                )?;
                let now = held_clock.current_unix_seconds()?;
                if now < inputs.issued_seconds || now >= inputs.expires_seconds {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
            }
            self.targets.capture_existing::<P>(
                destination, clock, self.source.as_mut(), owner_uid,
                #[cfg(target_os = "linux")]
                stages.as_deref_mut(),
                #[cfg(target_os = "linux")]
                receiving,
            )
        })();
        // Park the action's first cause before any final clock or source check.
        if let Err(cause) = returned {
            self.first_failure = Some(cause);
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _report)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold,
                #[cfg(target_os = "linux")]
                self.coverage_inputs,
                #[cfg(target_os = "linux")]
                self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if self.first_failure.is_some()
            || self.postcheck.is_some()
            || self.targets.postcheck.is_some()
        {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    fn capture_before_clock<P>(
        &mut self, owner_uid: u32,
        #[cfg(target_os = "linux")]
        mut stages: Option<&mut [baseline::CacheNativeStageV1; 5]>,
        #[cfg(target_os = "linux")]
        receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
    ) -> Result<(), InitializationCauseV1> {
        self.source_open = Some(open_initializer_cache_journal::<P>(
            InitializerJournal::Source, owner_uid,
            #[cfg(target_os = "linux")]
            stages.as_deref_mut(),
            #[cfg(target_os = "linux")]
            receiving,
        )?);
        #[cfg(target_os = "linux")]
        if let Some(receiving) = receiving {
            receiving.require_manifest(&self.source_open.as_ref()
                .ok_or(InitializationCauseV1::Closed)?.0, true)?;
        }
        self.source_report = self.source_open.as_ref().map(|(_journal, report)| *report);
        CacheReplayControllerBootstrapOwnerV1::capture_existing(
            &mut self.source_open, &mut self.source, owner_uid,
        )?;
        reject_legacy_cache_journals()?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        self.hold = Some(open_initializer_cache_journal::<P>(
            InitializerJournal::Hold, owner_uid,
            #[cfg(target_os = "linux")]
            stages.as_deref_mut(),
            #[cfg(target_os = "linux")]
            receiving,
        )?);
        let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
        #[cfg(target_os = "linux")]
        if let Some(inputs) = self.coverage_inputs {
            let observed = hold.0.cache_git_coverage_observation_for_writer_v1()?;
            if let Some(observation) = observed {
                inputs.require_observation(observation)?;
            }
            self.original_coverage = Some(observed);
        } else {
            self.original_hold = Some(hold.0.cache_policy_hold_for_writer()?);
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.original_hold = Some(hold.0.cache_policy_hold_for_writer()?);
        }

        self.clock_open = Some(open_initializer_cache_journal::<P>(
            InitializerJournal::Clock, owner_uid,
            #[cfg(target_os = "linux")]
            stages.as_deref_mut(),
            #[cfg(target_os = "linux")]
            receiving,
        )?);
        let opened = self.clock_open.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let retained = read_cache_clock_floor(&mut opened.0)?;
        #[cfg(target_os = "linux")]
        if self.coverage_inputs.is_some() {
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold,
                self.coverage_inputs, self.original_coverage,
            )?;
        }
        let sampled = sample_wall_clock()?;
        let floor = match retained {
            Some(floor) if floor.owner_scope == cache_owner_scope()
                && floor.observed_unix_seconds <= sampled =>
            {
                floor
            }
            Some(_) => return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into()),
            None => return Err(InitializationCauseV1::ProvisioningRequired),
        };
        let Some((journal, report)) = self.clock_open.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        self.clock_report = Some(report);
        // Same original Journal, parked before any time authority is called.
        self.clock = Some(Arc::new(ProtectedCacheClockV1::from_validated_floor(
            journal, root, cache_owner_scope(), owner_uid, floor,
        )));
        Ok(())
    }

    /// Rechecks all retained fixed originals without reopening their writers.
    ///
    /// # Errors
    /// Permanently refuses changed source, hold, clock, state or authority names.
    pub fn recheck(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure = Some(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            let owner_clock = owner.clock.as_ref().ok_or(InitializationCauseV1::Closed)?;
            if !Arc::ptr_eq(clock, owner_clock) {
                return Err(InitializationCauseV1::Closed);
            }
            #[cfg(target_os = "linux")]
            if self.coverage_inputs.is_some() {
                // Selected callbacks cannot sample through a changed Source
                // or exclusive writer; the ordinary check order stays below.
                self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                    .recheck_existing()?;
                let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
                require_original_hold(
                    &mut hold.0, self.original_hold,
                    self.coverage_inputs, self.original_coverage,
                )?;
            }
            let observed_seconds = held_clock.current_unix_seconds()?;
            #[cfg(target_os = "linux")]
            if let Some(inputs) = self.coverage_inputs {
                if observed_seconds < inputs.issued_seconds
                    || observed_seconds >= inputs.expires_seconds
                {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = observed_seconds;
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?.recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold,
                #[cfg(target_os = "linux")]
                self.coverage_inputs,
                #[cfg(target_os = "linux")]
                self.original_coverage,
            )?;
            let state = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits())?;
            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(journal, Path::new(PROTECTED_CACHE_ROOT),
                    CACHE_AUTHORITY_JOURNAL, owner.owner_uid, cache_authority_journal_limits())
            })?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure = Some(cause);
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    /// Terminally fences a legacy transition that would reopen retained writers.
    pub fn fence_unsupported_transition(&mut self) {
        self.complete = false;
        self.first_failure.get_or_insert(InitializationCauseV1::UnsupportedTransition);
    }

    /// Borrows the first native failure while independent post debt stays resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.first_failure.as_ref().or(self.postcheck.as_ref());
        match cause {
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::CreateStorageHeld) => self.create_storage_held.failure()
                .or_else(|| cause.map(|cause| cause as _)),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Q04) => self.q04.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| cause.map(|cause| cause as _)),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Q04Preflight) => self.q04_capture_failure()
                .or_else(|| cause.map(|cause| cause as _)),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Baseline) => self.selected_baseline.as_ref()
                .and_then(baseline::CacheSelectedInitializationV1::failure)
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::ReadMetadata) => self.read_metadata.failure()
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::CoverageAppend) => self.coverage_commit.as_ref()
                .and_then(|result| result.as_ref().err())
                .or_else(|| self.coverage_readback.as_ref().and_then(|result| result.as_ref().err()))
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Mutation) => self.pin_inventory.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.mutations.iter().find_map(|progress| progress.failure()))
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::PhysicalOpen) => self.selected_baseline.as_ref()
                .and_then(|selected| selected.originals.failure())
                .or_else(|| self.physical_open.failure()),
            Some(InitializationCauseV1::Replay) => self.targets.replay.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::Evidence) => self.targets.evidence.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::TargetPostcheck) => self.targets.postcheck.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(cause) => Some(cause),
            None => self.targets.postcheck.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
        }
    }
}

fn require_original_hold(
    hold: &mut Journal,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    #[cfg(target_os = "linux")] coverage_inputs: Option<CacheGitCoverageInputsV1>,
    #[cfg(target_os = "linux")] original_coverage: Option<Option<CacheGitCoverageObservationV1>>,
) -> Result<(), InitializationCauseV1> {
    #[cfg(target_os = "linux")]
    if let Some(inputs) = coverage_inputs {
        let current = hold.cache_git_coverage_observation_for_writer_v1()?;
        if let Some(observation) = current {
            inputs.require_observation(observation)?;
        }
        if Some(current) != original_coverage {
            return Err(InitializationCauseV1::Closed);
        }
        return Ok(());
    }

    if Some(hold.cache_policy_hold_for_writer()?) != original_hold {
        return Err(InitializationCauseV1::Closed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum InitializerJournal {
    Source,
    Hold,
    Clock,
    Authority,
    State,
}

impl InitializerJournal {
    pub(crate) fn recipe(self) -> (&'static Path, &'static str, JournalLimits) {
        use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1 as Role;
        let role = match self {
            Self::Source => Role::Bootstrap,
            Self::Hold => Role::Hold,
            Self::Clock => Role::Clock,
            Self::Authority => Role::Authority,
            Self::State => Role::State,
        };
        (Path::new(role.writer_directory_v1()), role.basename_v1(), role.limits_v1())
    }


}

fn open_initializer_cache_journal<P>(
    role: InitializerJournal,
    uid: u32,
    #[cfg(target_os = "linux")]
    stages: Option<&mut [baseline::CacheNativeStageV1; 5]>,
    #[cfg(target_os = "linux")]
    receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
) -> Result<(Journal, RecoveryReport), InitializationCauseV1> {
    let (root, name, limits) = role.recipe();
    #[cfg(target_os = "linux")]
    if let Some(stages) = stages {
        use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;
        let fixed_role = match role {
            InitializerJournal::Source => CacheJournalRecipeRoleV1::Bootstrap,
            InitializerJournal::Hold => CacheJournalRecipeRoleV1::Hold,
            InitializerJournal::Clock => CacheJournalRecipeRoleV1::Clock,
            InitializerJournal::Authority => CacheJournalRecipeRoleV1::Authority,
            InitializerJournal::State => CacheJournalRecipeRoleV1::State,
        };
        return receiving.ok_or(InitializationCauseV1::Baseline)?
            .open_native_once_v1(&mut stages[role as usize], fixed_role, uid, false);
    }
    if matches!(role, InitializerJournal::Source) {
        return open_existing_controller_cache_source(uid).map_err(InitializationCauseV1::from);
    }
    open_cache_journal_file(root, name, limits, uid, CacheOpenProfileV1::ExistingOnly)
        .map_err(InitializationCauseV1::from)
}

impl CacheResidentTargetsV1 {
    fn capture_existing<P>(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        clock: &Arc<ProtectedCacheClockV1>,
        source: Option<&mut CacheReplayControllerBootstrapOwnerV1>,
        owner_uid: u32,
        #[cfg(target_os = "linux")]
        mut stages: Option<&mut [baseline::CacheNativeStageV1; 5]>,
        #[cfg(target_os = "linux")]
        receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
    ) -> Result<(), InitializationCauseV1> {
        let source = source.ok_or(InitializationCauseV1::Closed)?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let (journal, report) = open_initializer_cache_journal::<P>(
            InitializerJournal::Authority, owner_uid,
            #[cfg(target_os = "linux")]
            stages.as_deref_mut(),
            #[cfg(target_os = "linux")]
            receiving,
        )?;
        self.authority_journal = Some(journal);
        self.authority_report = Some(report);
        let journal = self.authority_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
        enable_cache_journal_gate(journal, root, CACHE_AUTHORITY_JOURNAL, owner_uid)?;
        #[cfg(target_os = "linux")]
        if let Some(receiving) = receiving {
            receiving.require_manifest(journal, false)?;
        }
        let evidence = recover_cache_replay_evidence(
            journal, cache_owner_scope(), CacheRecoveryLimitsV1::default(),
        )?;
        let current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> = clock.clone();
        ProtectedCacheResidencyReplayAuthorityV1::capture_existing(
            &mut self.authority_journal, &mut self.authority, cache_owner_scope(),
            MAXIMUM_AUTHORITY_RECORD_BYTES, evidence, CacheRecoveryLimitsV1::default(), current_time,
        )?;
        let (journal, report) = open_initializer_cache_journal::<P>(
            InitializerJournal::State, owner_uid,
            #[cfg(target_os = "linux")]
            stages.as_deref_mut(),
            #[cfg(target_os = "linux")]
            receiving,
        )?;
        self.state_journal = Some(journal);
        self.state_report = Some(report);
        enable_cache_journal_gate(
            self.state_journal.as_mut().ok_or(InitializationCauseV1::Closed)?,
            root, CACHE_STATE_JOURNAL, owner_uid,
        )?;
        let Some(state_journal) = self.state_journal.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        let Some(authority) = self.authority.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        #[cfg(target_os = "linux")]
        if receiving.is_some() {
            self.initialized_authority = Some(Arc::clone(&authority));
        }
        *destination = Some(CacheResidencyProtectedOwnerV1 {
            state_journal: Some(state_journal),
            authority,
            clock: Some(clock.clone()),
            owner_uid,
            project_usage: project_usage::CacheProjectUsageProgressV1::default(),
        });
        let target = destination.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let state = target.state_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
        #[cfg(target_os = "linux")]
        if let Some(receiving) = receiving {
            target.authority.while_initializer_current_resident(
                state, receiving, &mut self.replay, &mut self.postcheck,
                |state, _owner, _now, validator| CacheResidencyProtectedJournalV1::claim(state, validator)?.replay(),
            );
        } else {
            target.authority.while_authority_current_resident(
                &mut self.replay, &mut self.postcheck,
                |_owner, _now, validator| CacheResidencyProtectedJournalV1::claim(state, validator)?.replay(),
            );
        }
        #[cfg(not(target_os = "linux"))]
        target.authority.while_authority_current_resident(
            &mut self.replay, &mut self.postcheck,
            |_owner, _now, validator| CacheResidencyProtectedJournalV1::claim(state, validator)?.replay(),
        );
        if !matches!(self.replay, Some(Ok(_))) {
            return Err(InitializationCauseV1::Replay);
        }
        if self.postcheck.is_some() {
            return Err(InitializationCauseV1::TargetPostcheck);
        }
        target.authority.capture_current_replay_partition_evidence(&mut self.evidence, &mut self.postcheck);
        let existing = self.evidence.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(InitializationCauseV1::Evidence)?;
        if self.postcheck.is_some() {
            return Err(InitializationCauseV1::TargetPostcheck);
        }
        if !source.reconcile_existing_replayed_partitions(target, existing)? {
            return Err(InitializationCauseV1::ProvisioningRequired);
        }
        Ok(())
    }
}
