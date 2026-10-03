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
    #[cfg(target_os = "linux")]
    #[error("resident Cache pin mutation is unresolved")]
    Mutation,
    #[cfg(target_os = "linux")]
    #[error("resident physical Cache capture failed")]
    PhysicalOpen,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Physical(#[from] super::super::CacheOwnerErrorV1),
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
    #[cfg(target_os = "linux")]
    physical_open: super::super::effect_owner::ResidentCachePhysicalOpenV1,
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

    /// Borrows complete current partition DATA under the original clock and hold.
    ///
    /// The result grants neither pin authority nor a physical effect. Every
    /// partition, including release tombstones, remains available to selection.
    ///
    /// # Errors
    /// Retains replay failures and refuses changed or incomplete originals.
    #[cfg(target_os = "linux")]
    pub fn existing_pin_inventories(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<&[CacheRecoveryInventoryV1], CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        self.complete = false;
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let hold = self.hold.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let state = owner.state_journal.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let returned = owner.authority.with_borrowed_mutable_authority_v1(
            state, &mut hold.0, &guard,
            |session, state| session.while_current_records(&[], |_, _, _, validator, refresh| {
                self.pin_inventory = Some((|| {
                    let projection = CacheResidencyProtectedJournalV1::claim(state, validator.clone())?.replay()?;
                    reconstruct_cache_history(projection.records(), &validator)
                })());
                refresh()?;
                Ok(())
            }),
        );
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if !matches!(self.pin_inventory.as_ref(), Some(Ok(_))) || self.postcheck.is_some() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        match self.pin_inventory.as_ref() {
            Some(Ok(inventories)) => Ok(inventories),
            _ => Err(CacheResidentUnavailableV1),
        }
    }

    /// Reconciles the original acquisition without selecting another partition.
    ///
    /// Returns `false` only for canonical state-only history; `true` requires
    /// actual protected-event and physical-manifest agreement.
    ///
    /// # Errors
    /// Retains the complete cold and physical results on ambiguity or failure.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_pin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
    ) -> Result<bool, CacheResidentUnavailableV1> {
        if consumer.acquisition_fence().is_none() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(session, state, transaction_id, consumer, operation, None, source_journal, request, physical)
        })?;
        Ok(self.mutations.last().is_some_and(|progress| !progress.cold_state_only()))
    }

    /// Reconciles one exact retained release tombstone under the same cut.
    ///
    /// # Errors
    /// Refuses foreign consumers, absent tombstones, state-only history or an
    /// unresolved physical release. Other partitions remain independent debt.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_unpin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        pin: &super::super::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let inventories = self.existing_pin_inventories(owner)?;
        let retained = inventories.iter().flat_map(|inventory| &inventory.reconstructed)
            .flat_map(|payload| &payload.released_pins)
            .any(|tombstone| &tombstone.pin == pin);
        if consumer.acquisition_fence().is_some() || !retained
            || !pin_lookup::logical_pin_matches_consumer(pin, pin.partition, consumer.object(), consumer.project(), consumer.view(), consumer.attachment())
        {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(session, state, transaction_id, consumer, operation, Some(pin), source_journal, request, physical)
        })?;
        if self.mutations.last().is_none_or(ResidentCachePinMutationV1::cold_state_only) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Captures only a healthy, provisioned physical owner under these originals.
    ///
    /// All seven limits are derived from the complete protected partition set.
    /// Changed limits fence the existing owner; this route never drops or
    /// reopens it, initializes a missing manifest, or performs orphan recovery.
    ///
    /// # Errors
    /// Keeps returned fixed descriptors and the first typed capture failure.
    #[cfg(target_os = "linux")]
    pub fn prepare_existing_physical_owner(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<super::super::DormantCacheOwnerV1>,
        node: aos_sandbox_core::NodeId,
        maximum_memory_bytes: u64,
    ) -> Result<(), CacheResidentUnavailableV1> {
        // Derive quotas from the complete selected inventory already retained
        // under the original clock/gate recipe, not another legacy full query.
        self.existing_pin_inventories(owner)?;
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure.get_or_insert(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            let quotas = match self.pin_inventory.as_ref() {
                Some(Ok(inventories)) => inventories
                    .iter()
                    .map(|inventory| inventory.global.node_quota)
                    .collect::<Vec<_>>(),
                _ => return Err(InitializationCauseV1::Mutation),
            };
            if quotas.iter().any(|quota| quota.partition.node().as_bytes() != node.as_bytes()) {
                return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
            }
            let limits = CacheOwnerLimitsV1::from_node_quotas(maximum_memory_bytes, quotas)?;
            if let Some(physical) = destination.as_ref() {
                if self.physical_limits != Some(limits) || physical.limits() != limits {
                    return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
                }
                physical.held_snapshot()?;
                return Ok(());
            }
            if self.physical_limits.is_some() {
                return Err(InitializationCauseV1::Closed);
            }
            self.physical_limits = Some(limits);
            if self.physical_open.open_once(destination, limits).is_err() {
                return Err(InitializationCauseV1::PhysicalOpen);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)
    }

    /// Pins one genuinely validated logical consumer without reopening writers.
    ///
    /// The actual acquisition proof, signed-source compiler inputs and current
    /// Controller request remain borrowed from the installed caller. Complete
    /// protected and physical results stay resident through final bookends.
    ///
    /// # Errors
    /// Permanently refuses changed originals, failed issuance, ambiguous
    /// protected append or incomplete physical settlement; no error is Drain.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn pin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        acquisition: &super::super::ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::pin_existing_under_cut(
                session, state, progress, acquisition, operation, transaction_id,
                source_journal, request, physical,
            )
        })
    }

    /// Releases one exact retained pin; the caller must select every partition.
    ///
    /// # Errors
    /// Keeps unresolved protected and physical results instead of permission to
    /// retry, release other pins or report consumer-wide completion.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn unpin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        pin: &super::super::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::unpin_existing_under_cut(
                session, state, progress, consumer, pin, operation, transaction_id,
                source_journal, request, physical,
            )
        })
    }

    #[cfg(target_os = "linux")]
    fn with_pin_mutation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        operation: OperationId,
        action: impl for<'session, 'claim, 'journal, 'gate, 'clock> FnOnce(
            &mut super::super::protected_journal::RetainedCacheAuthoritySessionV1<'claim, 'journal, 'gate, 'clock>,
            &mut Journal,
            &mut ResidentCachePinMutationV1,
            &mut super::super::DormantCacheOwnerV1,
        ) -> Result<(), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;
        let maximum = owner.state_journal.as_ref()
            .ok_or(CacheResidentUnavailableV1)?.configured_limits().maximum_materialized_bytes;
        let retained = self.mutations.iter().try_fold(0_usize, |bytes, progress| {
            bytes.checked_add(progress.retained_payload_bytes())
        });
        let Some(headroom) = retained.and_then(|bytes| maximum.checked_sub(bytes)) else {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        };
        for progress in &mut self.mutations {
            progress.release_completed_inventory();
        }
        self.mutations.push(ResidentCachePinMutationV1::for_operation(operation));
        let progress = self.mutations.last_mut().ok_or(CacheResidentUnavailableV1)?;
        progress.set_payload_headroom(headroom);
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            if owner.clock.as_ref().is_none_or(|current| !Arc::ptr_eq(clock, current)) {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            let hold = self.hold.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let state = owner.state_journal.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            owner.authority.with_borrowed_mutable_authority_v1(
                state, &mut hold.0, &guard,
                |session, state| {
                    let result = action(session, state, progress, physical);
                    if let Err(cause) = result {
                        progress.first_failure.get_or_insert(cause);
                        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                    }
                    Ok(())
                },
            )
        })();
        if let Err(cause) = returned {
            progress.postcheck.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() || !progress.complete {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        if let Err(cause) = physical.finish_resident_pin_step() {
            self.complete = false;
            self.postcheck.get_or_insert(cause.into());
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)
    }

    /// Releases completed operation DATA only after the same owners recheck.
    ///
    /// # Errors
    /// Refuses another operation, any unresolved leg or any changed original.
    #[cfg(target_os = "linux")]
    pub fn finish_existing_pin_operation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        operation: OperationId,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            return Err(CacheResidentUnavailableV1);
        }
        if let Err(cause) = physical.finish_resident_pin_operation() {
            self.postcheck.get_or_insert(cause.into());
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)?;

        // Both archives survive every fallible bookend. Only completed DATA
        // is released here; the original writers, clock and physical owner stay.
        physical.release_completed_resident_pin_data();
        self.mutations.clear();
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
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Mutation) => self.pin_inventory.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.mutations.iter().find_map(|progress| progress.failure()))
                .or_else(|| self.first_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::PhysicalOpen) => self.physical_open.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn inventory_failure_survives_an_independent_postcheck_debt() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.pin_inventory = Some(Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord));
        attempt.first_failure = Some(InitializationCauseV1::Mutation);
        attempt.postcheck = Some(InitializationCauseV1::Closed);

        let cause = attempt.failure().unwrap();

        assert_eq!(cause.to_string(), ProtectedDomainJournalErrorV1::NonCanonicalRecord.to_string());
        assert!(attempt.postcheck.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unfinished_operation_is_not_a_completed_empty_destination() {
        let mut attempt = CacheResidentInitializationV1::new();
        let operation = OperationId::from_bytes([92; 16]);
        attempt.mutations.push(ResidentCachePinMutationV1::for_operation(operation));

        assert!(!attempt.mutations[0].complete);
        assert_eq!(attempt.mutations[0].operation, Some(operation));
        assert!(!attempt.complete);
    }
}
