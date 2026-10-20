//! Keeps finite live Root windows on the same Start resource socket.
//!
//! Construction, Session opening and resource IO are distinct once-only turns.
//! Host additionally orders its private admission, catalog and activation before
//! the same-Session rejoin: 0, 4, 6, 5, 1, 2, 3. Other resources keep 0 through 3.
//! Each joins a genuinely later native Start ordinal, the same root peer and
//! original horizon. A failed body or independently owed post forbids every
//! later turn; no borrowed DATA token can reset or replace a native original.

use super::*;
use super::super::peer_receiving::refusal::RootPeerRefusalOriginalV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind { Construction, SessionOpening, ResourceIo, FinalProof, HostPublication(RootHostPublicationTurnKindV2) }

impl Kind {
    fn index(self) -> usize {
        match self { Self::Construction => 0, Self::SessionOpening => 1, Self::ResourceIo => 2, Self::FinalProof => 3, Self::HostPublication(phase) => phase.index() }
    }
}

/// Identifies one actual Host publication window in its finite stage graph.
///
/// The phase selects a comparison only. The live Entry loan must independently
/// match the exact recorded stage and fresh native ordinal before any borrow.
#[doc(hidden)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RootHostPublicationTurnKindV2 {
    /// Admits the real private generation2 Core publication after construction.
    Admission,
    /// Opens the retained Host Session and publishes its catalog while pending.
    Catalog,
    /// Activates only that completed catalog and the same private generation2.
    Activation,
}

impl RootHostPublicationTurnKindV2 {
    fn index(self) -> usize {
        match self { Self::Admission => 4, Self::Catalog => 6, Self::Activation => 5 }
    }
}

#[derive(Clone, Copy)]
enum StageFirst { Association, Funding, BeforeClock, BeforeTime, BeforePeer,
    SigningClock, SigningTime, Body, ControllerAfter, AfterPeer, AfterClock, AfterTime,
    Settlement, Refusal, Reentry }

#[derive(Default)]
pub(super) struct ResourceTurnsV2 {
    stages: [ResourceTurnV2; 7],
    host_graph: bool,
    active: Option<usize>,
}

#[derive(Default)]
struct ResourceTurnV2 {
    entered: bool,
    native_turn: u64,
    association: Option<Result<(), ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    funding_complete: Option<ResourceVector>,
    original_funding: bool,
    original: Option<Box<ResourceTurnOriginalV2>>,
    refusal: Option<Box<RootPeerRefusalOriginalV1>>,
    first: Option<StageFirst>,
    body: Option<Result<(), RootHostLaunchClientClosedV1>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
}

struct ResourceTurnOriginalV2 {
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), HistoryErrorV1>>,
    before_peer: Option<Box<PeerSampleV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    signing_clock: RetainedKernelPairedClockAttemptV1,
    signing_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    signing_time: Option<Result<(), HistoryErrorV1>>,
    after_peer: Option<Box<PeerSampleV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), HistoryErrorV1>>,
    after_entered: bool,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl ResourceTurnOriginalV2 {
    fn new() -> Self {
        Self {before_clock: Default::default(), before_sample: None, before_time: None,
            before_peer: Some(Box::new(PeerSampleV1::new())), before: None,
            signing_clock: Default::default(), signing_sample: None, signing_time: None,
            after_peer: Some(Box::new(PeerSampleV1::new())), after: None,
            after_clock: Default::default(), after_sample: None, after_time: None,
            after_entered: false, settlement: None}
    }
}

impl ResourceTurnV2 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let original = self.original.as_deref();
        match self.first? {
            StageFirst::Association => cause(&self.association),
            StageFirst::Funding => cause(&self.funding),
            StageFirst::BeforeClock => original.and_then(|value| value.before_clock.failure().or_else(|| cause(&value.before_sample))),
            StageFirst::BeforeTime => original.and_then(|value| cause(&value.before_time)),
            StageFirst::BeforePeer => original.and_then(|value| value.before_peer.as_deref().and_then(PeerSampleV1::failure).or_else(|| cause(&value.before))),
            StageFirst::SigningClock => original.and_then(|value| value.signing_clock.failure().or_else(|| cause(&value.signing_sample))),
            StageFirst::SigningTime => original.and_then(|value| cause(&value.signing_time)),
            StageFirst::Body => cause(&self.body),
            StageFirst::ControllerAfter => cause(&self.controller_after),
            StageFirst::AfterPeer => original.and_then(|value| value.after_peer.as_deref().and_then(PeerSampleV1::failure).or_else(|| cause(&value.after))),
            StageFirst::AfterClock => original.and_then(|value| value.after_clock.failure().or_else(|| cause(&value.after_sample))),
            StageFirst::AfterTime => original.and_then(|value| cause(&value.after_time)),
            StageFirst::Settlement => original.and_then(|value| value.before_peer.as_deref().and_then(PeerSampleV1::failure)
                .or_else(|| value.after_peer.as_deref().and_then(PeerSampleV1::failure)).or_else(|| cause(&value.settlement))),
            StageFirst::Refusal => self.refusal.as_deref().and_then(RootPeerRefusalOriginalV1::failure),
            StageFirst::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED))
    }
}

impl ResourceTurnsV2 {
    fn ordered_stages(&self) -> impl Iterator<Item = &ResourceTurnV2> {
        let order = if self.host_graph { [0, 4, 6, 5, 1, 2, 3] } else { [0, 1, 2, 3, 4, 5, 6] };
        order.into_iter().map(|index| &self.stages[index])
    }

    pub(super) fn final_proof_peer_v2(&self) -> Option<&PeerSampleV1> {
        self.stages[Kind::FinalProof.index()].original.as_ref()?.before_peer.as_deref()
    }

    pub(super) fn property_failure_view_v2(&self,
        marker: &aos_systemd_client::FixedPid1PropertyErrorV1,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let selected = self.ordered_stages().find(|stage| stage.first.is_some())?;
        if let Some(original) = selected.original.as_deref() {
            for sample in [original.before_peer.as_deref(), original.after_peer.as_deref()]
                .into_iter().flatten() {
                if super::diagnostics::same_property_v2(marker, sample.failure()) {
                    return sample.property_failure_view_v1();
                }
            }
        }
        // The same selected marker, rather than equality of error text, joins
        // the independent negative original when native entry was refused.
        let refusal = selected.refusal.as_deref()?;
        if super::diagnostics::same_property_v2(marker, refusal.failure()) {
            refusal.property_failure_view_v1()
        } else { None }
    }

    pub(super) fn original_failure_is_selected_v2(&self) -> bool {
        self.ordered_stages().find(|stage| stage.first.is_some()).is_some_and(|stage|
            matches!(stage.first, Some(StageFirst::ControllerAfter))
                || matches!(stage.first, Some(StageFirst::Funding)) && stage.original_funding)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.ordered_stages().find_map(ResourceTurnV2::failure)
    }
}

impl RootHostLaunchClientOriginalV1 {
    pub(super) fn require_network_purpose_v2(&self) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::NetworkPrepare)
    }

    pub(super) fn require_resource_purpose_v2(&self, purpose: HostResourcePurposeDataV1)
        -> Result<(), RootHostLaunchClientClosedV1> {
        let expected = match purpose {
            HostResourcePurposeDataV1::NetworkPrepare => StartOpeningPurposeV2::Network,
            HostResourcePurposeDataV1::MountNamespace => StartOpeningPurposeV2::Mount,
            HostResourcePurposeDataV1::StorageGuestRoot => StartOpeningPurposeV2::Storage,
            HostResourcePurposeDataV1::HostLaunch => StartOpeningPurposeV2::Host,
        };
        match self.state.as_ref().map(|state| state.purpose) {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(CLOSED),
        }
    }

    pub(super) fn require_final_proof_turn_v2(&self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_current_turn_v2(Kind::FinalProof, loan, controller)
    }

    pub(super) fn final_proof_funding_v2(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        self.turns.stages[Kind::FinalProof.index()].funding_complete
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn require_final_proof_completed_v2(&self,
        closed: &aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::ResourceCompletionClosedDataV2,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let index = Kind::FinalProof.index();
        let turn = &self.turns.stages[index];
        let original = turn.original.as_ref().ok_or(CLOSED)?;
        let before = original.before_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let after = original.after_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.turns.active != Some(index) || !turn.complete || self.turns.failure().is_some()
            || closed.observed_boottime_ns < before.boottime_nanoseconds()
            || closed.observed_boottime_ns > after.boottime_nanoseconds()
            || closed.observed_wall_seconds < before.wall_seconds()
            || closed.observed_wall_seconds > after.wall_seconds() {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn require_completed_network_opening_v4(
        &self,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
        parent: OperationId,
        native_turn: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_resource_opening_v4(HostResourcePurposeDataV1::NetworkPrepare,
            entry, controller, parent, native_turn)
    }

    pub(crate) fn require_completed_resource_opening_v4(
        &self,
        purpose: HostResourcePurposeDataV1,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
        parent: OperationId,
        native_turn: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_purpose_v2(purpose).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = if state.purpose == StartOpeningPurposeV2::Host {
            RootHostPublicationTurnKindV2::Catalog.index()
        } else { Kind::SessionOpening.index() };
        let turn = &self.turns.stages[index];
        if self.first.is_some() || self.turns.failure().is_some()
            || self.turns.active != Some(index) || !turn.complete
            || turn.native_turn != native_turn || state.parent != parent
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        entry.require_completed_host_turn_v1(parent, native_turn, controller)
    }

    pub(crate) fn require_completed_host_publication_turn_v2(&self,
        phase: RootHostPublicationTurnKindV2, entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal, parent: OperationId, native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = phase.index();
        let turn = &self.turns.stages[index];
        if self.failure().is_some() || self.turns.active != Some(index)
            || !turn.complete || turn.native_turn != native_turn || state.parent != parent
            || !std::ptr::eq(state.profile.as_ref(), profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        entry.require_completed_host_turn_v1(parent, native_turn, controller)
    }

    pub(crate) fn require_completed_host_session_rejoin_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
        parent: OperationId, native_turn: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = Kind::SessionOpening.index();
        let turn = &self.turns.stages[index];
        if self.failure().is_some() || self.turns.active != Some(index) || !turn.complete
            || turn.native_turn != native_turn || state.parent != parent {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        entry.require_completed_host_turn_v1(parent, native_turn, controller)
    }

    pub(crate) fn retained_receiving_demand_v2(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let reply = u64::try_from(state.received.bytes().len()).ok()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut resident = self.complete.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, reply))?;
        for stage in &self.turns.stages {
            if stage.original.is_some() {
                if !stage.complete { return Err(ResourceReservationErrorV1::Conflict); }
                // Positive completion physically retired both native samplers.
                // Typed paired samples, Results and one-shot fields remain.
                let memory = size_of::<ResourceTurnOriginalV2>().checked_mul(2)
                    .and_then(|bytes| RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
                        .and_then(|clock| bytes.checked_add(clock.checked_mul(3)?)))
                    .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
                resident = resident.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))?;
            }
        }
        Ok(resident)
    }

    fn turn_receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = CreateStorageRootPeerReceivingOriginalsV1::provisioning_turn_native_peak_v1(&state.profile)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(4)).ok_or(ResourceReservationErrorV1::Conflict)?;
        let memory = size_of::<ResourceTurnOriginalV2>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<RootPeerRefusalOriginalV1>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<RootStartResourceCurrentTurnV2<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<RootStartResourceConstructionTurnV2<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(clocks)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(4)).and_then(|names| u64::try_from(names).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 4 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::MetadataEntries, names)
            .with(D::Pids, u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1())
                .map_err(|_| ResourceReservationErrorV1::Conflict)?))?)
    }

    pub(crate) fn next_turn_receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        Ok(self.retained_receiving_demand_v2()?.checked_add(self.turn_receiving_demand_v2()?)?
            .checked_add(resource_stream::peer_traffic_v1(3)?)?)
    }

    /// Opens the finite construction window before exact normalization/signing.
    ///
    /// # Errors
    /// Refuses another actual Start/current native ordinal, failed predecessor,
    /// funding, real Root peer, paired clock or unchanged original horizon.
    #[doc(hidden)]
    pub fn begin_network_construction_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_construction_once_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    /// Opens only this child's fresh Network Session opening window.
    ///
    /// # Errors
    /// Refuses incomplete construction/disposition or any changed native owner.
    #[doc(hidden)]
    pub fn begin_network_session_opening_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_session_opening_once_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    /// Opens only the exact prepared Network63 followed by fresh Inventory19.
    ///
    /// # Errors
    /// Refuses incomplete genuine opening or any current/native/temporal failure.
    #[doc(hidden)]
    pub fn begin_network_io_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_io_once_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    /// Opens only the actual Host private-admission Root interval.
    ///
    /// # Errors
    /// Refuses another opening purpose, stage, native ordinal or predecessor.
    #[doc(hidden)]
    pub fn begin_host_admission_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_host_publication_once_v2(RootHostPublicationTurnKindV2::Admission, loan, controller)
    }

    /// Opens only the actual Host catalog-publication Root interval.
    ///
    /// # Errors
    /// Refuses an incomplete admission, changed original or failed native post.
    #[doc(hidden)]
    pub fn begin_host_catalog_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_host_publication_once_v2(RootHostPublicationTurnKindV2::Catalog, loan, controller)
    }

    /// Opens only the actual Host activation Root interval after its catalog.
    ///
    /// # Errors
    /// Refuses an incomplete catalog or another actual current Entry stage.
    #[doc(hidden)]
    pub fn begin_host_activation_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_host_publication_once_v2(RootHostPublicationTurnKindV2::Activation, loan, controller)
    }

    fn begin_host_publication_once_v2(&mut self, phase: RootHostPublicationTurnKindV2,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)?;
        self.begin_turn_once_v2(Kind::HostPublication(phase), loan, controller)
    }

    /// Borrows the actual current Host publication phase after its Root before.
    ///
    /// # Errors
    /// Refuses another recorded phase or incomplete current Root/native owner.
    #[doc(hidden)]
    pub fn borrow_host_publication_turn_v2(&self, phase: RootHostPublicationTurnKindV2,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)?;
        let kind = Kind::HostPublication(phase);
        self.require_current_turn_v2(kind, loan, controller)?;
        Ok(RootStartResourceCurrentTurnV2 {client: self, kind})
    }

    pub(crate) fn begin_resource_construction_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.begin_turn_once_v2(Kind::Construction, loan, controller)
    }

    pub(crate) fn begin_resource_session_opening_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.begin_turn_once_v2(Kind::SessionOpening, loan, controller)
    }

    pub(crate) fn begin_resource_io_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.begin_turn_once_v2(Kind::ResourceIo, loan, controller)
    }

    /// Opens the same resource's final comparison after its complete IO posts.
    ///
    /// # Errors
    /// Refuses an incomplete predecessor, a changed original or any native,
    /// financial, temporal or Root peer failure without replacing the socket.
    #[doc(hidden)]
    pub fn begin_network_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_final_proof_once_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    /// Opens only the actual storage final proof's independent native interval.
    ///
    /// # Errors
    /// Refuses another selected purpose or an incomplete genuine predecessor.
    pub fn begin_storage_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_final_proof_once_v2(HostResourcePurposeDataV1::StorageGuestRoot, loan, controller)
    }

    /// Opens only the actual mount final proof's independent native interval.
    ///
    /// # Errors
    /// Refuses another selected purpose or an incomplete genuine predecessor.
    pub fn begin_mount_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_final_proof_once_v2(HostResourcePurposeDataV1::MountNamespace, loan, controller)
    }

    pub(crate) fn begin_resource_final_proof_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.begin_turn_once_v2(Kind::FinalProof, loan, controller)
    }

    fn begin_turn_once_v2(&mut self, kind: Kind,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let index = kind.index();
        let host = self.state.as_ref().is_some_and(|state| state.purpose == StartOpeningPurposeV2::Host);
        self.turns.host_graph = host;
        let predecessor = match (host, kind) {
            (_, Kind::Construction) => None,
            (true, Kind::HostPublication(RootHostPublicationTurnKindV2::Admission)) => Some(0),
            (true, Kind::HostPublication(RootHostPublicationTurnKindV2::Catalog)) => Some(4),
            (true, Kind::HostPublication(RootHostPublicationTurnKindV2::Activation)) => Some(6),
            (true, Kind::SessionOpening) => Some(5),
            (false, Kind::HostPublication(_)) => return Err(CLOSED),
            (_, _) => index.checked_sub(1),
        };
        if self.turns.stages[index].entered || self.failure().is_some()
            || predecessor.is_some_and(|previous| self.turns.active != Some(previous)
                || !self.turns.stages[previous].complete
                || !matches!(self.preparation_binding, Some(Ok(())))) {
            self.turns.stages[index].first.get_or_insert(StageFirst::Reentry);
            return Err(CLOSED);
        }
        let previous = self.turns.active.map(|previous| self.turns.stages[previous].native_turn)
            .or_else(|| self.state.as_ref().map(|state| state.native_turn)).ok_or(CLOSED)?;
        self.turns.active = Some(index);
        self.turns.stages[index].entered = true;
        self.turns.stages[index].native_turn = loan.native_turn_v1();
        self.turns.stages[index].association = Some((|| {
            let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            if self.first.is_some() || !matches!(self.outer_after, Some(Ok(())))
                || state.purpose == StartOpeningPurposeV2::AssignmentInputs || state.stable.is_none() || state.parent != loan.parent_operation_v1()
                || !std::ptr::eq(state.profile.as_ref(), loan.profile_v1())
                || loan.native_turn_v1() <= previous { return Err(ResourceReservationErrorV1::Conflict); }
            if host { loan.require_host_stage_v2(index, controller) }
            else { loan.require_current_v1(controller) }
        })());
        if !matches!(self.turns.stages[index].association, Some(Ok(()))) {
            self.turns.stages[index].first = Some(StageFirst::Association);
            return Err(CLOSED);
        }
        self.turns.stages[index].funding = Some((|| {
            let complete = self.next_turn_receiving_demand_v2()?;
            self.turns.stages[index].funding_complete = Some(complete);
            let returned = loan.require_complete_v1(controller, complete);
            if returned.is_err() && loan.failure_v1().is_some() {
                self.turns.stages[index].original_funding = true;
            }
            returned
        })());
        if !matches!(self.turns.stages[index].funding, Some(Ok(()))) {
            self.turns.stages[index].first = Some(StageFirst::Funding);
            return Err(CLOSED);
        }
        self.next_refusal = Some(Box::new(RootPeerRefusalOriginalV1::new()));
        self.turns.stages[index].original = Some(Box::new(ResourceTurnOriginalV2::new()));
        let state = self.state.as_ref().ok_or(CLOSED)?;
        let turn = &mut self.turns.stages[index];
        let original = turn.original.as_mut().ok_or(CLOSED)?;
        original.before_sample = Some(original.before_clock.observe_once(Some(state.origin)));
        let Some(Ok(before)) = original.before_sample else { turn.first = Some(StageFirst::BeforeClock); return Err(CLOSED); };
        original.before_time = Some(require_phase_time_v2(state, before));
        if !matches!(original.before_time, Some(Ok(()))) { turn.first = Some(StageFirst::BeforeTime); return Err(CLOSED); }
        original.before = Some(original.before_peer.as_mut().ok_or(CLOSED)?.observe_with_cutoff_once_v1(
            &state.profile, state.connection.stream().map_err(|_| CLOSED)?,
            state.stable.as_ref(), None, false, state.cutoff));
        if !matches!(original.before, Some(Ok(()))) { turn.first = Some(StageFirst::BeforePeer); return Err(CLOSED); }
        Ok(())
    }

    pub(crate) fn require_completed_network_construction_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
        parent: OperationId, root_commitment: [u8; 32], native_turn: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_resource_construction_v2(entry, controller,
            HostResourcePurposeDataV1::NetworkPrepare, parent, root_commitment, native_turn)
    }

    pub(crate) fn require_completed_resource_construction_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
        purpose: HostResourcePurposeDataV1,
        parent: OperationId, root_commitment: [u8; 32], native_turn: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_purpose_v2(purpose).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let state = self.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let turn = &self.turns.stages[0];
        let reply = HostResourceReplyDataV1::decode_v1(state.received.bytes())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some() || self.turns.failure().is_some()
            || self.turns.active != Some(0) || !turn.complete
            || turn.native_turn != native_turn || state.parent != parent
            || reply.digest_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != root_commitment {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        entry.require_completed_host_turn_v1(parent, native_turn, controller)
    }

    /// Retains the paid final signing sample after actual key/message preparation.
    ///
    /// # Errors
    /// Refuses another phase, reentry, changed current Start or any temporal gate.
    #[doc(hidden)]
    pub fn final_network_signing_clock_once_v2(&mut self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, RootHostLaunchClientClosedV1> {
        self.final_resource_signing_clock_once_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    pub(crate) fn final_resource_signing_clock_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.require_current_turn_v2(Kind::Construction, loan, controller)?;
        let state = self.state.as_ref().ok_or(CLOSED)?;
        let turn = &mut self.turns.stages[0];
        let original = turn.original.as_mut().ok_or(CLOSED)?;
        if original.signing_sample.is_some() { turn.first = Some(StageFirst::Reentry); return Err(CLOSED); }
        original.signing_sample = Some(original.signing_clock.observe_once(Some(state.origin)));
        let Some(Ok(sample)) = original.signing_sample else { turn.first = Some(StageFirst::SigningClock); return Err(CLOSED); };
        original.signing_time = Some(require_phase_time_v2(state, sample));
        if !matches!(original.signing_time, Some(Ok(()))) { turn.first = Some(StageFirst::SigningTime); return Err(CLOSED); }
        Ok(sample)
    }

    fn require_current_turn_v2(&self, kind: Kind,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let index = kind.index();
        let turn = &self.turns.stages[index];
        let original = turn.original.as_ref().ok_or(CLOSED)?;
        let state = self.state.as_ref().ok_or(CLOSED)?;
        if self.first.is_some() || self.turns.failure().is_some() || self.turns.active != Some(index)
            || state.purpose == StartOpeningPurposeV2::AssignmentInputs || !turn.entered || turn.complete || original.after_entered
            || !matches!(original.before, Some(Ok(()))) || !matches!(original.before_time, Some(Ok(())))
            || turn.native_turn != loan.native_turn_v1() || state.parent != loan.parent_operation_v1()
            || !std::ptr::eq(state.profile.as_ref(), loan.profile_v1()) { return Err(CLOSED); }
        if state.purpose == StartOpeningPurposeV2::Host {
            loan.require_host_stage_v2(index, controller).map_err(|_| CLOSED)
        } else {
            loan.require_current_v1(controller).map_err(|_| CLOSED)
        }
    }

    /// Borrows the actual live construction window before or after its signing clock.
    ///
    /// # Errors
    /// Refuses failed/inactive native Root/Start originals or a changed association.
    #[doc(hidden)]
    pub fn borrow_network_construction_v2(&self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceConstructionTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_construction_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    /// Borrows the actual Network Session-opening or resource-IO Root interval.
    ///
    /// # Errors
    /// Refuses construction, a failed/finished phase or changed current original.
    #[doc(hidden)]
    pub fn borrow_network_current_turn_v2(&self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_current_turn_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    pub(crate) fn borrow_resource_construction_v2(&self, purpose: HostResourcePurposeDataV1,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceConstructionTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        self.require_current_turn_v2(Kind::Construction, loan, controller)?;
        Ok(RootStartResourceConstructionTurnV2 {client: self})
    }

    pub(crate) fn borrow_resource_current_turn_v2(&self, purpose: HostResourcePurposeDataV1,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        let index = self.turns.active.ok_or(CLOSED)?;
        let kind = match index { 1 => Kind::SessionOpening, 2 => Kind::ResourceIo, _ => return Err(CLOSED) };
        self.require_current_turn_v2(kind, loan, controller)?;
        Ok(RootStartResourceCurrentTurnV2 {client: self, kind})
    }

    pub(crate) fn finish_network_turn_after_original_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal, index: usize,
        body: Result<(), RootHostLaunchClientClosedV1>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.finish_resource_turn_after_original_v2(HostResourcePurposeDataV1::NetworkPrepare,
            entry, controller, index, body)
    }

    pub(crate) fn finish_resource_turn_after_original_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal, index: usize,
        body: Result<(), RootHostLaunchClientClosedV1>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(purpose)?;
        let turn = self.turns.stages.get(index).ok_or(CLOSED)?;
        if !turn.entered {
            return self.observe_resource_entry_refusal_after_original_v2(purpose, entry, index);
        }
        if self.turns.active != Some(index) {
            return Err(CLOSED);
        }
        self.finish_current_after_original_v2(entry, controller, body)
    }

    fn observe_resource_entry_refusal_after_original_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        entry: &crate::AcceptedStartEntryOriginalV1, index: usize,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let host = self.state.as_ref().is_some_and(|state| state.purpose == StartOpeningPurposeV2::Host);
        if index >= if host { 7 } else { 4 } || self.turns.stages[index].entered { return Err(CLOSED); }
        self.turns.host_graph = host;
        let state = self.state.as_ref().ok_or(CLOSED)?;
        let previous = self.turns.active.map(|previous| self.turns.stages[previous].native_turn)
            .unwrap_or(state.native_turn);
        let actual = entry.resource_negative_entry_association_v2(purpose, state.parent, &state.profile, previous, index)
            .map_err(|_| CLOSED)?;
        let turn = &mut self.turns.stages[index];
        turn.entered = true;
        turn.native_turn = actual;
        turn.first = Some(StageFirst::Refusal);
        turn.refusal = self.next_refusal.take();
        if let Some(refusal) = turn.refusal.as_mut() {
            if let Ok(stream) = state.connection.stream() {
                refusal.observe_once(&state.profile, stream, state.stable.as_ref(), state.origin, state.cutoff);
            }
        }
        self.turns.active = Some(index);
        Err(CLOSED)
    }

    pub(crate) fn finish_current_after_original_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
        body: Result<(), RootHostLaunchClientClosedV1>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let index = self.turns.active.ok_or(CLOSED)?;
        let turn = &mut self.turns.stages[index];
        if turn.body.is_some() { turn.first.get_or_insert(StageFirst::Reentry); return Err(CLOSED); }
        let body_failed = body.is_err();
        turn.body = Some(body);
        if body_failed { turn.first.get_or_insert(StageFirst::Body); }
        let Some(original) = turn.original.as_mut() else {
            // The existing negative spare was paid by the prior successful
            // purpose. No failed funding/association can suppress this after.
            turn.refusal = self.next_refusal.take();
            if let (Some(refusal), Some(state)) = (turn.refusal.as_mut(), self.state.as_ref()) {
                if let Ok(stream) = state.connection.stream() {
                    refusal.observe_once(&state.profile, stream, state.stable.as_ref(), state.origin, state.cutoff);
                }
            }
            turn.first.get_or_insert(StageFirst::Refusal);
            return Err(CLOSED);
        };
        original.after_entered = true;
        let state = self.state.as_ref().ok_or(CLOSED)?;
        // Select an earlier C-post refusal before later Root posts can fill a
        // native failure slot. This retained result never gates those posts.
        turn.controller_after = Some(entry.require_completed_host_turn_v1(state.parent, turn.native_turn, controller));
        if !matches!(turn.controller_after, Some(Ok(()))) { turn.first.get_or_insert(StageFirst::ControllerAfter); }
        original.after = Some(match (original.after_peer.as_mut(), state.connection.stream()) {
            (Some(after), Ok(stream)) => after.observe_with_cutoff_once_v1(&state.profile,
                stream, state.stable.as_ref(), None, true, state.cutoff),
            _ => Err(NormalRootStartupErrorV1::Service),
        });
        if !matches!(original.after, Some(Ok(()))) { turn.first.get_or_insert(StageFirst::AfterPeer); }
        original.after_sample = Some(original.after_clock.observe_once(Some(state.origin)));
        if !matches!(original.after_sample, Some(Ok(_))) { turn.first.get_or_insert(StageFirst::AfterClock); }
        original.after_time = Some(match original.after_sample {
            Some(Ok(sample)) => (|| {
                let before = original.before_sample.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(HistoryErrorV1::Malformed)?;
                before.validate_later_sample(sample).map_err(|_| HistoryErrorV1::Malformed)?;
                if let Some(Ok(signing)) = original.signing_sample {
                    signing.validate_later_sample(sample).map_err(|_| HistoryErrorV1::Malformed)?;
                }
                require_phase_time_v2(state, sample)
            })(),
            _ => Err(HistoryErrorV1::Malformed),
        });
        if !matches!(original.after_time, Some(Ok(()))) { turn.first.get_or_insert(StageFirst::AfterTime); }
        // Only the positive disposal is gated. Every actual independently owed
        // Root and paired after above ran after the earlier body/C result.
        if turn.first.is_some() { return Err(CLOSED); }
        original.settlement = Some((|| {
            original.before_peer.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.settle_positive_once()?;
            original.after_peer.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.settle_positive_once()?;
            Ok(())
        })());
        if !matches!(original.settlement, Some(Ok(()))) { turn.first = Some(StageFirst::Settlement); return Err(CLOSED); }
        // Physical positive disposal, not a status flag, precedes the next
        // turn's smaller resident invoice. Failed samplers can never reach it.
        drop(original.before_peer.take());
        drop(original.after_peer.take());
        turn.complete = true;
        Ok(())
    }
}

fn require_phase_time_v2(state: &OpeningV1, sample: RawPairedClockSample) -> Result<(), HistoryErrorV1> {
    state.origin.validate_later_sample(sample).map_err(|_| HistoryErrorV1::Malformed)?;
    let StartOpeningAdmissionV2::Resource(admission) = *positive(&state.reply)? else {
        return Err(HistoryErrorV1::Malformed);
    };
    if sample.boottime_nanoseconds() >= state.cutoff
        || sample.wall_seconds() >= state.accepted_expiry
        || sample.wall_seconds() >= admission.lease_expires_seconds
        || sample.wall_seconds() >= admission.policy_expires_seconds
        || state.signed_plan_expires.is_some_and(|expires| sample.wall_seconds() >= expires) {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(())
}

/// Borrows the same genuinely current Network construction native Root window.
#[doc(hidden)]
pub struct RootStartResourceConstructionTurnV2<'flight> { client: &'flight RootHostLaunchClientOriginalV1 }

impl RootStartResourceConstructionTurnV2<'_> {
    pub(crate) fn require_admission_v2(&self, admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal, signing: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.client, admission.client) { return Err(ResourceReservationErrorV1::Conflict); }
        self.client.require_current_turn_v2(Kind::Construction, loan, controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if signing && self.client.turns.stages[0].original.as_ref()
            .is_none_or(|original| !matches!(original.signing_time, Some(Ok(())))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.client.turns.stages[0].funding_complete.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn cutoff_v2(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.client.state.as_ref().map(|state| state.cutoff).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn actual_before_clock_v2(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        let original = self.client.turns.stages[0].original.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.signing_sample.as_ref().or(original.before_sample.as_ref())
            .and_then(|sample| sample.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }
}

/// Borrows only one actual live Network opening or resource-IO Root interval.
#[doc(hidden)]
pub struct RootStartResourceCurrentTurnV2<'flight> {
    client: &'flight RootHostLaunchClientOriginalV1,
    kind: Kind,
}

impl RootStartResourceCurrentTurnV2<'_> {
    pub(crate) fn resource_purpose_data_v2(&self)
        -> Result<HostResourcePurposeDataV1, ResourceReservationErrorV1> {
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        match state.purpose {
            StartOpeningPurposeV2::Network => Ok(HostResourcePurposeDataV1::NetworkPrepare),
            StartOpeningPurposeV2::Mount => Ok(HostResourcePurposeDataV1::MountNamespace),
            StartOpeningPurposeV2::Storage => Ok(HostResourcePurposeDataV1::StorageGuestRoot),
            StartOpeningPurposeV2::Host => Ok(HostResourcePurposeDataV1::HostLaunch),
            StartOpeningPurposeV2::AssignmentInputs => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn require_opening_sample_v4(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = self.client.state.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.is_session_opening_window_v2() {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        require_phase_time_v2(state, sample)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_opening_owner_v2(
        &self,
        parent: OperationId,
        native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.is_session_opening_window_v2() { return Err(ResourceReservationErrorV1::Conflict); }
        self.require_owner_v4(self.kind, parent, native_turn, profile)
    }

    fn is_session_opening_window_v2(&self) -> bool {
        matches!((self.client.state.as_ref().map(|state| state.purpose), self.kind),
            (Some(StartOpeningPurposeV2::Host), Kind::HostPublication(RootHostPublicationTurnKindV2::Catalog)))
            || (self.kind == Kind::SessionOpening && self.client.state.as_ref()
                .is_some_and(|state| !matches!(state.purpose,
                    StartOpeningPurposeV2::AssignmentInputs | StartOpeningPurposeV2::Host)))
    }

    fn require_owner_v4(
        &self,
        kind: Kind,
        parent: OperationId,
        native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let turn = &self.client.turns.stages[kind.index()];
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = turn.original.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.kind != kind || self.client.first.is_some()
            || self.client.turns.failure().is_some() || self.client.turns.active != Some(kind.index())
            || turn.complete || original.after_entered
            || !matches!(original.before, Some(Ok(())))
            || !matches!(original.before_time, Some(Ok(())))
            || state.parent != parent || turn.native_turn != native_turn
            || !std::ptr::eq(state.profile.as_ref(), profile)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        turn.funding_complete.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_host_io_owner_v2(&self,
        parent: OperationId, native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.client.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.require_owner_v4(Kind::ResourceIo, parent, native_turn, profile)
    }

    pub(crate) fn require_host_session_rejoin_owner_v2(&self,
        parent: OperationId, native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.client.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let catalog = &self.client.turns.stages[RootHostPublicationTurnKindV2::Catalog.index()];
        let activation = &self.client.turns.stages[RootHostPublicationTurnKindV2::Activation.index()];
        if !catalog.complete || !activation.complete {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_owner_v4(Kind::SessionOpening, parent, native_turn, profile)
    }

    pub(crate) fn require_host_publication_owner_v2(&self,
        phase: RootHostPublicationTurnKindV2, parent: OperationId, native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.client.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.require_owner_v4(Kind::HostPublication(phase), parent, native_turn, profile)
    }

    pub(crate) fn require_io_preparation_v4(
        &self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        parent: OperationId,
        native_turn: u64,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let complete = self.require_owner_v4(Kind::ResourceIo, parent, native_turn, profile)?;
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let (actual_parent, digest, construction_turn, expires) = prepared.completed_root_binding_v2()?;
        let reply = HostResourceReplyDataV1::decode_v1(state.received.bytes())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if actual_parent != parent
            || self.client.turns.stages[0].native_turn != construction_turn
            || !self.client.turns.stages[0].complete
            || state.signed_plan_expires != Some(expires)
            || !matches!(self.client.preparation_binding, Some(Ok(())))
            || reply.digest_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != digest
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(complete)
    }

    pub(crate) fn original_opening_horizon_v2(&self)
        -> Result<(RawPairedClockSample, u64), ResourceReservationErrorV1> {
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        self.require_opening_owner_v2(state.parent,
            self.client.turns.stages[self.kind.index()].native_turn, state.profile.as_ref())?;
        Ok((state.origin, state.cutoff))
    }

    pub(crate) fn require_opening_v2(&self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if !self.is_session_opening_window_v2() { return Err(ResourceReservationErrorV1::Conflict); }
        self.client.require_current_turn_v2(self.kind, loan, controller).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_io_v2(&self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if self.kind != Kind::ResourceIo { return Err(ResourceReservationErrorV1::Conflict); }
        self.client.require_current_turn_v2(self.kind, loan, controller).map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootHostLaunchClientOriginalV1 {
    /// Borrows only the actual storage opening's current paid construction.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed Start or incomplete native interval.
    #[doc(hidden)]
    pub fn borrow_storage_construction_v2<'held>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceConstructionTurnV2<'held>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_construction_v2(HostResourcePurposeDataV1::StorageGuestRoot, loan, controller)
    }

    /// Borrows only the actual storage opening's current paid current turn.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed Start or incomplete native interval.
    #[doc(hidden)]
    pub fn borrow_storage_current_turn_v2<'held>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'held>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_current_turn_v2(HostResourcePurposeDataV1::StorageGuestRoot, loan, controller)
    }

    /// Samples the final signing clock only for this actual storage construction.
    ///
    /// # Errors
    /// Retains a changed opening, financial/native refusal or original expiry.
    #[doc(hidden)]
    pub fn final_storage_signing_clock_once_v2(
        &mut self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, RootHostLaunchClientClosedV1> {
        self.final_resource_signing_clock_once_v2(HostResourcePurposeDataV1::StorageGuestRoot, loan, controller)
    }

    /// Borrows only the actual mount opening's current paid construction.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed Start or incomplete native interval.
    #[doc(hidden)]
    pub fn borrow_mount_construction_v2<'held>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceConstructionTurnV2<'held>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_construction_v2(HostResourcePurposeDataV1::MountNamespace, loan, controller)
    }

    /// Borrows only the actual mount opening's current paid current turn.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed Start or incomplete native interval.
    #[doc(hidden)]
    pub fn borrow_mount_current_turn_v2<'held>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'held>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_current_turn_v2(HostResourcePurposeDataV1::MountNamespace, loan, controller)
    }

    /// Samples the final signing clock only for this actual mount construction.
    ///
    /// # Errors
    /// Retains a changed opening, financial/native refusal or original expiry.
    #[doc(hidden)]
    pub fn final_mount_signing_clock_once_v2(
        &mut self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, RootHostLaunchClientClosedV1> {
        self.final_resource_signing_clock_once_v2(HostResourcePurposeDataV1::MountNamespace, loan, controller)
    }

}

impl RootHostLaunchClientOriginalV1 {
    /// Borrows the actual Host construction before either paired signer borrow.
    ///
    /// # Errors
    /// Refuses another purpose or a failed, changed or completed native window.
    #[doc(hidden)]
    pub fn borrow_host_construction_v2(&self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceConstructionTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_construction_v2(HostResourcePurposeDataV1::HostLaunch, loan, controller)
    }

    /// Borrows only the real Host same-Session rejoin or execution IO window.
    ///
    /// # Errors
    /// Refuses another purpose, private-publication stage or changed native turn.
    #[doc(hidden)]
    pub fn borrow_host_current_turn_v2(&self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RootStartResourceCurrentTurnV2<'_>, RootHostLaunchClientClosedV1> {
        self.borrow_resource_current_turn_v2(HostResourcePurposeDataV1::HostLaunch, loan, controller)
    }

    /// Samples the final Host and Guardian preparation's original signing clock.
    ///
    /// # Errors
    /// Retains reentry, financial/native refusal or the original horizon's expiry.
    #[doc(hidden)]
    pub fn final_host_signing_clock_once_v2(&mut self,
        loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<RawPairedClockSample, RootHostLaunchClientClosedV1> {
        self.final_resource_signing_clock_once_v2(HostResourcePurposeDataV1::HostLaunch, loan, controller)
    }

    /// Opens the actual final Host proof after its complete Host1 and Inventory3.
    ///
    /// # Errors
    /// Refuses another purpose or an incomplete native predecessor/post.
    #[doc(hidden)]
    pub fn begin_host_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_final_proof_once_v2(HostResourcePurposeDataV1::HostLaunch, loan, controller)
    }
}


impl RootStartResourceCurrentTurnV2<'_> {
    /// Borrows the already observed Host IO2 clock without resampling.
    ///
    /// The actual active Host IO window, native ordinal, profile and completed
    /// before observations remain mandatory. This supplies comparison DATA for
    /// the same private Core Applying dispatch, never a new horizon or grant.
    ///
    /// # Errors
    /// Refuses another purpose/stage, a failed current owner or a missing sample.
    pub(crate) fn before_clock_data_v2(&self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.client.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let stage = &self.client.turns.stages[Kind::ResourceIo.index()];
        self.require_owner_v4(Kind::ResourceIo, state.parent, stage.native_turn, state.profile.as_ref())?;
        stage.original.as_ref().and_then(|original| original.before_sample.as_ref())
            .and_then(|sample| sample.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}
