//! Captures Storage's fixed Host Session through its genuine lifecycle payer.
//!
//! The sole protected captured-writer engine owns native preparation, full
//! semantic replay, tail handling and independent name posts. This purpose
//! adapter derives its UID only after the actual Server Session is rechecked;
//! no path, account, endpoint, Host outcome or effect grant enters from DATA.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use crate::{StorageLifecycleSessionLoanV1, StorageReceivingClosedV1};

pub(super) const DIRECTORY: &str = "/var/lib/aos/sandbox-storage/broker-session/host";

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Schema(#[from] super::super::broker_session_receiving::StorageSessionGeometryRefusalV1),
    #[error("the original Host Session prefix is unavailable")]
    Prefix,
}

#[derive(Clone, Copy)]
enum Failure {
    FixedDemand,
    Preparation,
    Native,
    Demand,
    Replay,
    Take,
}

/// Retains Storage's fixed Host journal and its same-original admission results.
///
/// Mechanical replay supplies custody and historical DATA only. The actual
/// fixed endpoint, Host HELLO, protected Session schema and live Host outcome
/// remain independent prerequisites in the Security owner.
#[must_use = "retain native failures and independently owed posts"]
pub struct StorageHostSessionCapturedJournalOpenV1 {
    inner: FixedProtectedCapturedJournalOpenV1,
    payer: Option<StorageNativeOpeningOwnerLinkV1>,
    fixed_demand: Option<Result<ResourceVector, AccountingError>>,
    preparation: Option<Result<(), StorageReceivingClosedV1>>,
    demand: Option<Result<ResourceVector, DemandError>>,
    replay: Option<Result<(), StorageReceivingClosedV1>>,
    take: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<Failure>,
    opened: Option<(Journal, RecoveryReport)>,
    original_extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    original_next: Option<u64>,
}

impl StorageHostSessionCapturedJournalOpenV1 {
    /// Creates inert destinations without choosing a UID, opening or replaying.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedStorageHostSession(None)),
            payer: None,
            fixed_demand: None,
            preparation: None,
            demand: None,
            replay: None,
            take: None,
            first: None,
            opened: None,
            original_extent: None,
            original_next: None,
        }
    }

    /// Describes the compiled native preparation without paying or admitting it.
    ///
    /// # Errors
    /// Refuses unrepresentable native/append construction geometry.
    pub fn fixed_preparation_demand_v1() -> Result<ResourceVector, AccountingError> {
        // Root plus six actual directory components and the main/lock names
        // form nine namespace entries; the three FD traversals stay separately
        // priced by the existing native supplier.
        let path_bytes = u16::try_from(DIRECTORY.len() + "session.journal".len())
            .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let native = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(
            7, path_bytes,
        )?.with(D::MetadataEntries, 9);
        native.checked_add(super::super::native_interval::captured::CapturedAppendOwnerV1::construction_demand_v1()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?)
    }

    /// Pays and captures only this fixed path from the active same-F Domain.
    ///
    /// All returned native/error prefixes stay here. Another lifecycle or
    /// Server writer cannot substitute between preparation, replay and take.
    pub fn prepare_once(
        &mut self,
        limits: JournalLimits,
        mode: CapturedJournalOpenModeV1,
        lifecycle: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        session: &Journal,
        socket: &SeqpacketSocket,
    ) {
        if self.preparation.is_some() || self.first.is_some() {
            self.inner.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.prepare_inner_v1(limits, mode, lifecycle, session, socket);
    }

    fn prepare_inner_v1(
        &mut self,
        limits: JournalLimits,
        mode: CapturedJournalOpenModeV1,
        lifecycle: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        session: &Journal,
        socket: &SeqpacketSocket,
    ) {
        self.fixed_demand = Some(Self::fixed_preparation_demand_v1());
        let Some(Ok(demand)) = self.fixed_demand.as_ref() else {
            self.first = Some(Failure::FixedDemand);
            return;
        };
        self.preparation = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
        if !matches!(self.preparation, Some(Ok(()))) {
            self.first = Some(Failure::Preparation);
            return;
        }
        self.payer = Some(session.held_session_owner_link_v1());
        self.inner.recipe = ProtectedCapturedJournalRecipeV1::JoinedStorageHostSession(
            Some(rustix::process::geteuid().as_raw()));
        self.inner.prepare_once(limits, mode);
        self.original_extent = self.inner.captured_extent().copied();
        if self.inner.failure().is_some() {
            self.first = Some(Failure::Native);
        }
    }

    /// Borrows the exact held prefix for the separate upper schema supplier.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.first.is_none() { self.inner.captured_extent() } else { None }
    }

    /// Prepays the same captured native and complete Session schema before replay.
    pub fn replay_once(
        &mut self,
        lifecycle: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        session: &Journal,
        socket: &SeqpacketSocket,
    ) {
        if self.replay.is_some() || self.first.is_some()
            || !self.payer.as_ref().is_some_and(|payer| payer.same_journal(session))
        {
            self.inner.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.replay_inner_v1(lifecycle, session, socket);
    }

    fn replay_inner_v1(
        &mut self,
        lifecycle: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        session: &Journal,
        socket: &SeqpacketSocket,
    ) {
        self.demand = Some((|| {
            let extent = self.inner.captured_extent().ok_or(DemandError::Prefix)?;
            let native = extent.dominant_native_receiving_demand_v1()?;
            let semantic = extent.dominant_semantic_receiving_demand_v1()?;
            let schema = super::super::broker_session_receiving::schema_demand(extent)?;
            let initialization = super::super::broker_session_receiving::initialization_demand(extent)?;
            Ok(native.checked_add(semantic)?.checked_add(schema)?.checked_add(initialization)?)
        })());
        let Some(Ok(demand)) = self.demand.as_ref() else {
            self.first = Some(Failure::Demand);
            return;
        };
        self.replay = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
        if !matches!(self.replay, Some(Ok(()))) {
            self.first = Some(Failure::Replay);
            return;
        }
        self.inner.replay_once();
        if self.inner.failure().is_some() {
            self.first = Some(Failure::Native);
        }
    }

    /// Moves the actual replayed journal only after its final native name posts.
    #[must_use]
    pub fn take_opened(
        &mut self,
        lifecycle: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        session: &Journal,
        socket: &SeqpacketSocket,
    ) -> Option<(Journal, RecoveryReport)> {
        if self.first.is_some() || self.take.is_some() || !self.inner.replay_ready()
            || !self.payer.as_ref().is_some_and(|payer| payer.same_journal(session))
        { return None; }
        self.take = Some(lifecycle.require_current_v1(session, socket));
        if matches!(self.take, Some(Ok(()))) {
            self.opened = self.inner.take_opened();
            self.original_next = self.opened.as_ref().map(|(journal, _)| journal.snapshot_sequence());
            if self.opened.is_none() { self.first.get_or_insert(Failure::Native); }
        } else {
            self.first.get_or_insert(Failure::Take);
        }
        if self.first.is_none() { self.opened.take() } else { None }

    }

    /// Borrows the original bound only while the same exclusive writer is unchanged.
    ///
    /// Tail repair can only shrink this captured bound. Any later transaction
    /// permanently makes it unavailable; another operation must sample and pay
    /// its actual current extent instead of reusing an old opening prefix.
    #[must_use]
    pub fn unmodified_opened_prefix_bound_v1(&self, journal: &Journal)
        -> Option<&ProtectedJournalPreopenReplayExtentV1>
    {
        if !self.was_taken_positive_v1()
            || self.original_next != Some(journal.snapshot_sequence())
            || !self.inner.owner_link.as_ref().is_some_and(|owner| owner.same_journal(journal))
        { return None; }
        self.original_extent.as_ref()
    }

    /// Reports complete transfer of this exact paid native opening.
    #[must_use]
    pub fn was_taken_positive_v1(&self) -> bool {
        self.first.is_none() && self.inner.was_taken_positive() && self.opened.is_none()
    }

    /// Borrows the original failure without releasing any native custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn original(slot: &Option<Result<(), StorageReceivingClosedV1>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error)
        }
        match self.first {
            Some(Failure::FixedDemand) => self.fixed_demand.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error),
            Some(Failure::Preparation) => original(&self.preparation),
            Some(Failure::Native) => self.inner.failure(),
            Some(Failure::Demand) => self.demand.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error),
            Some(Failure::Replay) => original(&self.replay),
            Some(Failure::Take) => original(&self.take),
            None => self.inner.failure(),
        }
    }
}

impl Default for StorageHostSessionCapturedJournalOpenV1 {
    fn default() -> Self { Self::new() }
}
