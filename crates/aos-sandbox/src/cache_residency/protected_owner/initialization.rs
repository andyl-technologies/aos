//! Existing-only fixed Cache initialization with resident partial originals.
//!
//! No missing journal, clock floor, or partition is created by this route.
//! Keeping the policy-hold writer also forbids legacy reopen-based mutation.

use super::*;
use crate::cache_residency::controller_bootstrap::open_existing_controller_cache_source;
use crate::cache_residency::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
};
use crate::journal::JournalError;

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
enum InitializationCauseV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Source(#[from] CacheReplayControllerBootstrapErrorV1),
    #[error(transparent)]
    Target(#[from] CacheResidencyProtectedJournalErrorV1),
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
}

#[derive(Default)]
struct CacheResidentTargetsV1 {
    authority_journal: Option<Journal>,
    authority_report: Option<RecoveryReport>,
    authority: Option<Arc<ProtectedCacheResidencyReplayAuthorityV1>>,
    state_journal: Option<Journal>,
    state_report: Option<RecoveryReport>,
    replay: Option<Result<CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalErrorV1>>,
    evidence: Option<Result<Vec<CacheResidencyReplayPartitionEvidenceV1>, CacheResidencyProtectedJournalErrorV1>>,
    postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
}

/// Retains every returned fixed initialization original through failure.
///
/// This produces partition-local observation DATA, never a global project
/// account, operation permission, physical funding or drain evidence.
#[derive(Default)]
pub struct CacheResidentInitializationV1 {
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
        if let Err(cause) = self.capture_before_clock(owner_uid) {
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
        let returned = self.targets.capture_existing(
            destination, clock, self.source.as_mut(), owner_uid,
        );
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
            match hold.cache_policy_hold_for_writer() {
                Ok(current) if Some(current) == self.original_hold => {}
                Ok(_) => {
                    self.postcheck.get_or_insert(InitializationCauseV1::Closed);
                }
                Err(cause) => {
                    self.postcheck.get_or_insert(cause.into());
                }
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

    fn capture_before_clock(&mut self, owner_uid: u32) -> Result<(), InitializationCauseV1> {
        self.source_open = Some(open_existing_controller_cache_source(owner_uid)?);
        self.source_report = self.source_open.as_ref().map(|(_journal, report)| *report);
        CacheReplayControllerBootstrapOwnerV1::capture_existing(
            &mut self.source_open, &mut self.source, owner_uid,
        )?;
        reject_legacy_cache_journals()?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        self.hold = Some(open_cache_journal_file(
            root, CACHE_POLICY_HOLD_JOURNAL, Journal::cache_policy_hold_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?);
        let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
        self.original_hold = Some(hold.0.cache_policy_hold_for_writer()?);

        self.clock_open = Some(open_cache_journal_file(
            root, CACHE_CLOCK_JOURNAL, cache_clock_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?);
        let opened = self.clock_open.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let retained = read_cache_clock_floor(&mut opened.0)?;
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
            held_clock.current_unix_seconds()?;
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?.recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            if Some(hold.0.cache_policy_hold_for_writer()?) != self.original_hold {
                return Err(InitializationCauseV1::Closed);
            }
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

    /// Borrows the first genuine failure; separate postcheck debt stays resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.first_failure.as_ref().or(self.postcheck.as_ref());
        match cause {
            Some(InitializationCauseV1::Replay) => self.targets.replay.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::Evidence) => self.targets.evidence.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::TargetPostcheck) => self.targets.postcheck.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(cause) => Some(cause),
            None => self.targets.postcheck.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)),
        }
    }
}

impl CacheResidentTargetsV1 {
    fn capture_existing(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        clock: &Arc<ProtectedCacheClockV1>,
        source: Option<&mut CacheReplayControllerBootstrapOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), InitializationCauseV1> {
        let source = source.ok_or(InitializationCauseV1::Closed)?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let (journal, report) = open_cache_journal_file(
            root, CACHE_AUTHORITY_JOURNAL, cache_authority_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?;
        self.authority_journal = Some(journal);
        self.authority_report = Some(report);
        let journal = self.authority_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
        enable_cache_journal_gate(journal, root, CACHE_AUTHORITY_JOURNAL, owner_uid)?;
        let evidence = recover_cache_replay_evidence(
            journal, cache_owner_scope(), CacheRecoveryLimitsV1::default(),
        )?;
        let current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> = clock.clone();
        ProtectedCacheResidencyReplayAuthorityV1::capture_existing(
            &mut self.authority_journal, &mut self.authority, cache_owner_scope(),
            MAXIMUM_AUTHORITY_RECORD_BYTES, evidence, CacheRecoveryLimitsV1::default(), current_time,
        )?;
        let (journal, report) = open_cache_journal_file(
            root, CACHE_STATE_JOURNAL, cache_state_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
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
        *destination = Some(CacheResidencyProtectedOwnerV1 {
            state_journal: Some(state_journal),
            authority,
            clock: Some(clock.clone()),
            owner_uid,
            project_usage: project_usage::CacheProjectUsageProgressV1::default(),
        });
        let target = destination.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let state = target.state_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_destination_has_no_owner_or_completed_observation() {
        let attempt = CacheResidentInitializationV1::new();

        assert!(!attempt.started());
        assert!(!attempt.complete);
        assert!(attempt.source.is_none());
        assert!(attempt.hold.is_none());
        assert!(attempt.clock.is_none());
        assert!(attempt.failure().is_none());
    }

    #[test]
    fn prearmed_failure_refuses_reuse_without_an_open() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.started = true;
        attempt.first_failure = Some(InitializationCauseV1::Closed);
        let mut destination = None;

        let returned = attempt.initialize_once(&mut destination, 0);

        assert_eq!(returned, Err(CacheResidentUnavailableV1));
        assert!(destination.is_none());
        assert!(attempt.source_open.is_none());
        assert!(matches!(attempt.first_failure, Some(InitializationCauseV1::Closed)));
    }

    #[test]
    fn unsupported_transition_keeps_the_first_original_cause() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.started = true;
        attempt.first_failure = Some(InitializationCauseV1::ProvisioningRequired);

        attempt.fence_unsupported_transition();

        assert!(!attempt.complete);
        assert!(matches!(attempt.first_failure, Some(InitializationCauseV1::ProvisioningRequired)));
    }

    #[test]
    fn classified_failure_does_not_format_original_paths_or_causes() {
        assert_eq!(CacheResidentUnavailableV1.to_string(),
            "existing resident Cache initialization is unavailable");
    }
}
