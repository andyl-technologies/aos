//! Restricts early worker cleanup to the actual taken State/opening interval.
//!
//! This is not the completed-startup State encoder. One continuously borrowed
//! original pays native census/entry storage and the SAME initial-post engine
//! pays every actual service observation. Positive entry/name scratch is really
//! disposed after State-name and service posts; negative owners remain parked.

use super::*;
use std::os::fd::AsFd as _;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationObservationV1, CgroupPopulationObservationRefusalV1,
    CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
    StorageRecoveryControlCgroupReadbackV1, StorageWorkerRecoveryDirectoryV1,
    StorageWorkerRecoveryDirectoryRefusalV1, StorageWorkerRecoveryQuiescenceV1,
    StorageRecoveryQuiescenceErrorV1, WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1,
};
use crate::journal::{ProtectedJournalCurrentnessOriginalsV1, StorageNativeOpeningOwnerLinkV1};

#[derive(Debug, thiserror::Error)]
pub(super) enum DemandError {
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
}

#[derive(Clone, Copy)]
enum First {
    Before,
    Parent,
    ParentMetadata,
    ParentBinding,
    Census,
    Entry,
    Population,
    Quiescence,
    Populated,
    Health,
    Names,
    Post,
    Closed,
}

pub(super) struct InitialPinQuiescenceOriginalV1 {
    before: Option<NativeResult>,
    parent: StorageRecoveryControlCgroupReadbackV1,
    parent_result: Option<Result<(), aos_sandbox_linux::Error>>,
    parent_root: Option<CgroupV2Root>,
    parent_anchor: Option<RetainedCgroupAnchor>,
    parent_metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    original_metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    parent_binding: Option<Result<(), StorageReceivingClosedV1>>,
    census: StorageWorkerRecoveryDirectoryV1,
    census_result: Option<Result<(), StorageWorkerRecoveryDirectoryRefusalV1>>,
    name: Option<String>,
    entry: WorkerCgroupOpeningV1,
    entry_result: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    population: CgroupPopulationObservationV1,
    population_result: Option<Result<(), CgroupPopulationObservationRefusalV1>>,
    quiescence: StorageWorkerRecoveryQuiescenceV1,
    quiescence_result: Option<Result<(), StorageRecoveryQuiescenceErrorV1>>,
    health: Option<Result<(), crate::JournalError>>,
    names: ProtectedJournalCurrentnessOriginalsV1,
    names_result: Option<Result<(), crate::JournalError>>,
    post: Option<NativeResult>,
    first: Option<First>,
    entered: bool,
    running: bool,
    scanned: bool,
    completed: bool,
}

impl InitialPinQuiescenceOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            before: None,
            parent: StorageRecoveryControlCgroupReadbackV1::new(),
            parent_result: None,
            parent_root: None,
            parent_anchor: None,
            parent_metadata: None,
            original_metadata: None,
            parent_binding: None,
            census: StorageWorkerRecoveryDirectoryV1::new(),
            census_result: None,
            name: None,
            entry: WorkerCgroupOpeningV1::new(),
            entry_result: None,
            population: CgroupPopulationObservationV1::new(),
            population_result: None,
            quiescence: StorageWorkerRecoveryQuiescenceV1::new(),
            quiescence_result: None,
            health: None,
            names: ProtectedJournalCurrentnessOriginalsV1::new(),
            names_result: None,
            post: None,
            first: None,
            entered: false,
            running: false,
            scanned: false,
            completed: false,
        }
    }

    pub(super) fn completed_v2(&self) -> bool { self.completed && self.first.is_none() }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
        }
        match self.first? {
            First::Before => native_failure(&self.before),
            First::Parent => self.parent.failure().or_else(|| error(&self.parent_result)),
            First::ParentMetadata => error(&self.parent_metadata).or_else(|| error(&self.original_metadata)),
            First::ParentBinding => error(&self.parent_binding),
            First::Census => self.census.failure().or_else(|| error(&self.census_result)),
            First::Entry => self.entry.failure().or_else(|| error(&self.entry_result)),
            First::Population => self.population.failure().or_else(|| error(&self.population_result)),
            First::Quiescence => self.quiescence.failure().or_else(|| error(&self.quiescence_result)),
            First::Health => error(&self.health),
            First::Names => self.names.failure().or_else(|| error(&self.names_result)),
            First::Post => native_failure(&self.post),
            First::Populated | First::Closed => Some(&StorageReceivingClosedV1 as &(dyn Error + 'static)),
        }
        .or(Some(&StorageReceivingClosedV1))
    }

    pub(super) fn files_disposed_positive_v1(&self) -> bool {
        self.completed && self.first.is_none()
            && self.parent_root.is_none() && self.parent_anchor.is_none()
            && self.census_result.is_none() && self.entry_result.is_none()
    }

    fn dispose_entry_positive(&mut self) {
        drop(self.name.take());
        self.entry = WorkerCgroupOpeningV1::new();
        self.entry_result = None;
        self.population = CgroupPopulationObservationV1::new();
        self.population_result = None;
        self.quiescence = StorageWorkerRecoveryQuiescenceV1::new();
        self.quiescence_result = None;
    }

    fn dispose_names_positive(&mut self) {
        self.health = None;
        self.names = ProtectedJournalCurrentnessOriginalsV1::new();
        self.names_result = None;
    }
}

#[derive(Clone, Copy)]
pub(super) enum QuiescencePurposeV2<'cut> {
    Initial,
    GuestRoot31 { session: &'cut crate::Journal, socket: &'cut aos_sandbox_linux::seqpacket::SeqpacketSocket },
}

/// Continuously borrows the same taken State journal and real receiving original.
///
/// The active original opening facade remains resident on the caller. This
/// scan-only stage lends no models, encoder, append or worker effect channel.
#[must_use]
pub struct StorageInitialPinQuiescenceLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    purpose: QuiescencePurposeV2<'cut>,
    journal: &'cut crate::Journal,
    writer: StorageNativeOpeningOwnerLinkV1,
    work: Option<InitialPinQuiescenceOriginalV1>,
    finished: bool,
}

pub(super) fn initial_pin_demand() -> Result<ResourceVector, DemandError> {
    let invalid = || aos_sandbox_model::AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let bytes = std::mem::size_of::<InitialPinQuiescenceOriginalV1>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<StorageInitialPinQuiescenceLoanV1<'_, '_>>()))
        .and_then(|bytes| StorageWorkerRecoveryDirectoryV1::requested_bytes_v1().and_then(|next| bytes.checked_add(next)))
        .and_then(|bytes| WorkerCgroupOpeningV1::dominant_requested_bytes_v1().and_then(|next| bytes.checked_add(next)))
        .and_then(|bytes| CgroupPopulationObservationV1::requested_bytes_v1().and_then(|next| bytes.checked_add(next)))
        .and_then(|bytes| StorageWorkerRecoveryQuiescenceV1::requested_bytes_v1().and_then(|next| bytes.checked_add(next)))
        .and_then(|bytes| bytes.checked_add(24 * 256)).ok_or_else(invalid)?;
    let names = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("storage-state.journal")?;
    ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
        // Fixed ordinary parent6, directory1, worker entry7, kill2.
        // The selected aggregate anchor is the SAME already held one.
        .with(D::OpenFiles, 6
            + StorageWorkerRecoveryDirectoryV1::OPEN_FILES_V1 as u64
            + WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1 as u64
            + aos_sandbox_linux::cgroup::CgroupKillAttemptV1::maximum_retained_files_v1() as u64)
        // The fixed parent contributes its actual hierarchy and active paths.
        // Only one census and worker entry are live: successful entry/scan
        // scratch is disposed before the next one. The basename is already in
        // the census. Add aggregate-parent procs, current worker events, and
        // the kill recipe's worker procs/kill names exactly once. Raw native,
        // parser, guard and error fields remain solely in MemoryBytes above.
        .with(D::MetadataEntries,
            StorageRecoveryControlCgroupReadbackV1::receiving_namespace_entries_v1() as u64
                + StorageWorkerRecoveryDirectoryV1::METADATA_ENTRIES_V1 as u64
                + 1 + 1
                + aos_sandbox_linux::cgroup::CgroupKillAttemptV1::METADATA_ENTRIES_V1 as u64)
        .checked_add(names).map_err(Into::into)
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Borrows once during actual State take, before later writer entry.
    ///
    /// # Errors
    /// Refuses another Journal, absent active same-State facade, later startup,
    /// repeated cleanup, earlier refusal or fixed native/post payment failure.
    pub fn borrow_initial_pin_quiescence_once_v1<'cut>(
        &'cut mut self,
        journal: &'cut crate::Journal,
    ) -> Result<StorageInitialPinQuiescenceLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.startup.state_initial_pin_quiescence_ready_v1(journal)
            || receiving.native_opening_peak.active != Some(NativeOpeningKindV1::State)
            || !receiving.native_opening_peak.owner_link.as_ref()
                .is_some_and(|writer| writer.matches_journal_v1(journal))
            || receiving.initial_pin_entered
            || !receiving.physical_worker.before_first_flight_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.initial_pin_entered = true;
        self.arm_service_acquisition_observation_post_v1()?;
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut()
        else { std::process::abort() };
        receiving.initial_pin_demand = Some(initial_pin_demand());
        if let Some(demand) = receiving.initial_pin_demand.as_ref()
            .and_then(|value| value.as_ref().ok()).copied()
        {
            receiving.initial_pin_payment = Some(receiving.reserve(demand));
            if matches!(receiving.initial_pin_payment, Some(Ok(()))) {
                // The SAME ledger already paid these files. Retain this claim
                // in the existing physical peak, but its later entry remains
                // blocked until this actual scan owner disposes all scratch.
                // Non-file scan debt remains separately held and charged.
                receiving.physical_worker.retain_initial_file_peak_v1(demand);
            }
        } else {
            receiving.first.get_or_insert(Failure::InitialPinQuiescence);
        }
        let paid = matches!(receiving.initial_pin_payment, Some(Ok(())));
        let post = self.finish_initial_observation_native_post_v1();
        let post_positive = post.is_ok();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.original.recipient.as_mut()
        else { std::process::abort() };
        receiving.initial_pin_post = Some(post);
        if !paid || !post_positive {
            return Err(StorageReceivingClosedV1);
        }
        let Some(writer) = receiving.startup.state_identity_v1() else { std::process::abort() };
        // The complete real descriptor/heap/metadata/frame bound was admitted
        // above before constructing this new native reservoir or its guard.
        let mut work = InitialPinQuiescenceOriginalV1::new();
        work.entered = true;
        Ok(StorageInitialPinQuiescenceLoanV1 {
            receiving: self,
            purpose: QuiescencePurposeV2::Initial,
            journal,
            writer,
            work: Some(work),
            finished: false,
        })
    }
}

impl StorageInitialPinQuiescenceLoanV1<'_, '_> {
    fn work(&mut self) -> &mut InitialPinQuiescenceOriginalV1 {
        let Some(work) = self.work.as_mut() else { std::process::abort() };
        work
    }

    fn arm(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if self.work().first.is_some() || !self.writer.matches_journal_v1(self.journal) {
            self.work().first.get_or_insert(First::Closed);
            return Err(StorageReceivingClosedV1);
        }
        if let QuiescencePurposeV2::GuestRoot31 { session, socket } = self.purpose {
            self.receiving.require_lifecycle_domain_current_v1(session, socket)?;
        }
        self.receiving.arm_service_acquisition_observation_post_v1()?;
        let before = self.receiving.original.recheck();
        let positive = before.is_ok();
        self.work().before = Some(before);
        if !positive {
            self.work().first.get_or_insert(First::Before);
            // No directory, kill or new phase is entered after this refusal;
            // State names and the separately paid actual post are still owed.
            let _ = self.post();
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn post(&mut self) -> Result<(), StorageReceivingClosedV1> {
        // These are independent owed observations even if the primary or
        // Journal health failed. They lend no new work or healthy reentry.
        let health = self.journal.ensure_healthy();
        self.work().health = Some(health);
        let Some(work) = self.work.as_mut() else { std::process::abort() };
        work.names_result = Some(self.journal.observe_held_names_post_retaining_v1(&mut work.names));
        if matches!(work.health, Some(Err(_))) { work.first.get_or_insert(First::Health); }
        if matches!(work.names_result, Some(Err(_))) { work.first.get_or_insert(First::Names); }
        // Select an earlier physical/health/name cause before a later service
        // post can close the ordinary receiver. The paid owed route still runs.
        if self.work().first.is_some() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            { self.purpose.latch_failure_v2(receiving); }
        }
        if let QuiescencePurposeV2::GuestRoot31 { session, socket } = self.purpose {
            self.receiving.observe_domain_state_socket_post_v1(session, socket);
        }
        let post = self.receiving.finish_initial_observation_native_post_v1();
        let work = self.work();
        work.post = Some(post);
        if matches!(work.post, Some(Err(_))) { work.first.get_or_insert(First::Post); }
        if work.first.is_some() { return Err(StorageReceivingClosedV1); }
        work.dispose_names_positive();
        Ok(())
    }

    /// Executes the two cancel scans and final empty scan in both fixed scopes.
    ///
    /// # Errors
    /// Retains the actual directory/entry/cancellation and State/service posts
    /// on the first refused interval. No further scope starts after failure.
    pub fn recover_quiescence_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if self.work().running {
            self.work().first.get_or_insert(First::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.work().running = true;
        self.arm()?;
        let parent_result = self.work().parent.capture_once();
        self.work().parent_result = Some(parent_result);
        if matches!(self.work().parent_result, Some(Ok(()))) {
            let pair = self.work().parent.take_validated_pair();
            let Some((root, parent)) = pair else { std::process::abort() };
            self.work().parent_root = Some(root);
            self.work().parent_anchor = Some(parent);
        } else { self.work().first = Some(First::Parent); }
        if self.work().first.is_none() {
            let Some(work) = self.work.as_mut() else { std::process::abort() };
            let Some(root) = work.parent_root.as_ref() else { std::process::abort() };
            let Some(original_root) = self.receiving.original.custody.cgroup_root.as_ref() else { std::process::abort() };
            work.parent_metadata = Some(rustix::fs::fstat(root.as_fd()));
            work.original_metadata = Some(rustix::fs::fstat(original_root.as_fd()));
            match (&work.parent_metadata, &work.original_metadata) {
                (Some(Ok(actual)), Some(Ok(original))) => {
                    work.parent_binding = Some(if (actual.st_dev, actual.st_ino) == (original.st_dev, original.st_ino) {
                        Ok(())
                    } else { Err(StorageReceivingClosedV1) });
                    if matches!(work.parent_binding, Some(Err(_))) { work.first = Some(First::ParentBinding); }
                }
                _ => { work.first = Some(First::ParentMetadata); }
            }
        }
        self.post()?;
        for pass in 0..3 {
            for aggregate in [false, true] {
                self.capture_census(aggregate)?;
                let count = self.work().census.names().map_or(0, <[String]>::len);
                for index in 0..count {
                    let name = self.work().census.names().and_then(|names| names.get(index)).cloned();
                    self.work().name = name;
                    self.capture_entry(aggregate, pass == 2)?;
                    self.work().dispose_entry_positive();
                }
                self.work().census = StorageWorkerRecoveryDirectoryV1::new();
                self.work().census_result = None;
            }
        }
        self.work().scanned = true;
        Ok(())
    }

    fn capture_census(&mut self, aggregate: bool) -> Result<(), StorageReceivingClosedV1> {
        self.arm()?;
        let Some(work) = self.work.as_mut() else { std::process::abort() };
        let parent = if aggregate {
            self.receiving.original.custody.aggregate.anchor().ok()
        } else { work.parent_anchor.as_ref() };
        if let Some(parent) = parent {
            work.census_result = Some(work.census.capture_once(parent));
        } else { work.first = Some(First::Closed); }

        if matches!(work.census_result, Some(Err(_))) { work.first = Some(First::Census); }
        self.post()
    }

    fn capture_entry(&mut self, aggregate: bool, require_empty: bool) -> Result<(), StorageReceivingClosedV1> {
        self.arm()?;
        let Some(work) = self.work.as_mut() else { std::process::abort() };
        let parent = if aggregate {
            self.receiving.original.custody.aggregate.anchor().ok()
        } else { work.parent_anchor.as_ref() };
        let Some(parent) = parent else {
            work.first = Some(First::Closed);
            return self.post();
        };
        let Some(name) = work.name.as_deref() else { std::process::abort() };
        work.entry_result = Some((|| {
            work.entry.capture_descendant_once(parent, std::path::Path::new(name))?;
            work.entry.observe_parent_once(parent)?;
            work.entry.capture_population_once()
        })());
        if matches!(work.entry_result, Some(Err(_))) {
            work.first = Some(First::Entry);
        } else {
            let Some(population) = work.entry.population() else { std::process::abort() };
            work.population_result = Some(population.observe_state_retaining_v1(&mut work.population));
            match work.population.state() {
                None => { work.first = Some(First::Population); }
                Some(CgroupPopulationState::Populated) if require_empty => { work.first = Some(First::Populated); }
                Some(CgroupPopulationState::Populated) => {
                    let Some(anchor) = work.entry.anchor() else { std::process::abort() };
                    work.quiescence_result = Some(work.quiescence.capture_once(anchor, population));
                    if !work.quiescence.completed() { work.first = Some(First::Quiescence); }
                }
                Some(CgroupPopulationState::Empty | CgroupPopulationState::Retired) => {}
            }
        }
        self.post()
    }

    /// Disposes only positive scan scratch after every actual interval closed.
    ///
    /// # Errors
    /// Refuses incomplete/failed work before disposal. Success performs no IO
    /// or fallible check after releasing the actual native scratch.
    pub fn complete_after_quiescence_v1(mut self) -> Result<(), StorageReceivingClosedV1> {
        let work = self.work();
        if work.first.is_some() || !work.scanned || work.census_result.is_some() || work.entry_result.is_some()
            || !matches!(work.parent_result, Some(Ok(())))
        {
            return Err(StorageReceivingClosedV1);
        }
        work.parent = StorageRecoveryControlCgroupReadbackV1::new();
        drop(work.parent_root.take());
        drop(work.parent_anchor.take());
        work.completed = true;
        self.finished = true;
        self.park();
        Ok(())
    }

    fn park(&mut self) {
        let Some(work) = self.work.take() else { return; };
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let slot = match self.purpose {
            QuiescencePurposeV2::Initial => &mut receiving.initial_pin_quiescence,
            QuiescencePurposeV2::GuestRoot31 { .. } => &mut receiving.lifecycle.state_recovery.guest_root_quiescence,
        };
        if slot.is_some() { std::process::abort(); }
        *slot = Some(work);
    }
}

impl Drop for StorageInitialPinQuiescenceLoanV1<'_, '_> {
    fn drop(&mut self) {
        self.park();
        if !self.finished {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            { self.purpose.latch_failure_v2(receiving); }
            self.receiving.original.open = false;
        }
    }
}


impl QuiescencePurposeV2<'_> {
    fn latch_failure_v2(self, receiving: &mut StorageReceivingOriginalV1) {
        match self {
            Self::Initial => { receiving.first.get_or_insert(Failure::InitialPinQuiescence); }
            Self::GuestRoot31 { .. } => {
                receiving.lifecycle.state_recovery.mark_guest_root_quiescence_failure_v2();
                receiving.first.get_or_insert(Failure::StateRecovery);
            }
        }
    }
}

/// Holds a distinct current method31 borrow of the sole remnant-scan engine.
///
/// No constructor accepts a purpose flag, native parent or financial vector.
/// This owner cannot enter or rearm the initial Pin once slot.
#[must_use]
pub struct StorageGuestRootQuiescenceLoanV2<'cut, 'original> {
    inner: StorageInitialPinQuiescenceLoanV1<'cut, 'original>,
}

impl StorageGuestRootQuiescenceLoanV2<'_, '_> {
    /// Cancels entered remnants and independently checks both native rosters.
    ///
    /// # Errors
    /// Retains the same actual directory, cancellation and owed post causes.
    pub fn recover_quiescence_once_v2(&mut self) -> Result<(), StorageReceivingClosedV1> {
        self.inner.recover_quiescence_once_v1()
    }

    /// Retires only completed scan scratch after all native/name/service posts.
    ///
    /// # Errors
    /// Refuses any incomplete or negative original without clearing its source.
    pub fn complete_after_quiescence_v2(self) -> Result<(), StorageReceivingClosedV1> {
        self.inner.complete_after_quiescence_v1()
    }
}

impl<'cut, 'original> StorageGuestRootQuiescenceLoanV2<'cut, 'original> {
    pub(super) fn from_state_v2(
        receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
        journal: &'cut crate::Journal,
        writer: StorageNativeOpeningOwnerLinkV1,
        session: &'cut crate::Journal,
        socket: &'cut aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Self {
        let mut work = InitialPinQuiescenceOriginalV1::new();
        work.entered = true;
        Self { inner: StorageInitialPinQuiescenceLoanV1 {
            receiving, purpose: QuiescencePurposeV2::GuestRoot31 { session, socket },
            journal, writer, work: Some(work), finished: false,
        } }
    }
}
