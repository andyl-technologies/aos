//! Rejoins catalog6's actual Host Session after private generation2 activation.
//!
//! Stage1 pays distinct native before/after destinations on the same held
//! Session. An earlier comparison error never suppresses the independently
//! owed endpoint, cookie or journal-name observations. No HELLO or reopen runs.

use super::*;
use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1};
use aos_sandbox_linux::self_execution::{SelfExecutionObservationV1, SelfExecutionObservationError};

#[derive(Clone, Copy)]
enum First { Funding, Association, BeforeEndpoint, BeforeSocket, BeforeNames,
    AfterEndpoint, AfterSocket, AfterNames, Reentry }

struct Sample {
    endpoint_original: SelfExecutionObservationV1,
    endpoint: Option<Result<(), SelfExecutionObservationError>>,
    socket: Option<Result<(), StartResourceSessionCurrentnessErrorV4>>,
    names_original: ProtectedJournalCurrentnessOriginalsV1,
    names: Option<Result<(), JournalError>>,
}

impl Sample {
    fn new() -> Self {
        Self { endpoint_original: Default::default(), endpoint: None, socket: None,
            names_original: ProtectedJournalCurrentnessOriginalsV1::new(), names: None }
    }

    fn observe(&mut self, association: &StartResourceSessionAssociationV4,
        journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) {
        self.endpoint = Some(association.observe_completed_endpoint_retaining_v2(&mut self.endpoint_original));
        self.socket = Some(association.require_current_session_v4(journal, socket, transcript));
        self.names = Some(journal.observe_held_names_post_retaining_v1(&mut self.names_original));
    }
}

/// Retains the real same-Session rejoin until its C and Root posts complete.
///
/// The owner has no public positive constructor or Session adopter. Its only
/// native entry requires the actual active Host stage1 loan and catalog6 owner.
#[doc(hidden)]
#[must_use = "retain through the same Host stage1 C and Root after-observations"]
pub struct StartHostSessionRejoinOriginalV2 {
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<(), ResourceReservationErrorV1>>,
    samples: Option<Box<[Sample; 2]>>,
    parent: Option<aos_sandbox_core::OperationId>,
    native_turn: u64,
    first: Option<First>,
    retired: bool,
}

impl StartHostSessionRejoinOriginalV2 {
    /// Creates inert destinations without IO, allocation or authority.
    #[must_use]
    pub fn new() -> Self {
        Self { funding: None, association: None, samples: None, parent: None,
            native_turn: 0, first: None, retired: false }
    }

    /// Prices both actual endpoint, socket and journal-name observation planes.
    ///
    /// # Errors
    /// Refuses overflow in the compiled layout or actual native-name suppliers.
    pub fn receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let names = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("session.journal")?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<[Sample; 2]>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(SelfExecutionObservationV1::receiving_heap_bytes_v1().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        let files = SelfExecutionObservationV1::opened_file_bound_v1();
        let native = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(files.checked_mul(2).ok_or(CLOSED)?).map_err(|_| CLOSED)?)
            .with(D::MetadataEntries, u64::try_from(SelfExecutionObservationV1::native_named_read_entries_v2()).map_err(|_| CLOSED)?);
        // The two observation planes retain distinct descriptors and buffers
        // for the same named namespace; names are counted once.
        native.checked_add(names.checked_add(names.with(D::MetadataEntries, 0))?)
            .map_err(Into::into)
    }

    /// Borrows the earliest actual funding, association or native refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<E: Error + 'static>(result: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        let samples = self.samples.as_deref();
        match self.first? {
            First::Funding => cause(&self.funding),
            First::Association => cause(&self.association),
            First::BeforeEndpoint => samples.and_then(|samples| samples[0].endpoint_original.failure())
                .or_else(|| samples.and_then(|samples| cause(&samples[0].endpoint))),
            First::BeforeSocket => samples.and_then(|samples| cause(&samples[0].socket)),
            First::BeforeNames => samples.and_then(|samples| samples[0].names_original.failure())
                .or_else(|| samples.and_then(|samples| cause(&samples[0].names))),
            First::AfterEndpoint => samples.and_then(|samples| samples[1].endpoint_original.failure())
                .or_else(|| samples.and_then(|samples| cause(&samples[1].endpoint))),
            First::AfterSocket => samples.and_then(|samples| cause(&samples[1].socket)),
            First::AfterNames => samples.and_then(|samples| samples[1].names_original.failure())
                .or_else(|| samples.and_then(|samples| cause(&samples[1].names))),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED))
    }

    /// Physically retires only this positive rejoin after actual stage1 posts.
    ///
    /// # Errors
    /// Refuses an unfinished/failed rejoin or another Entry, Root or C ordinal.
    pub fn retire_positive_once_v2(&mut self, entry: &AcceptedStartEntryOriginalV1,
        root: &crate::normal_root::RootHostLaunchClientOriginalV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.retired || self.first.is_some() || self.samples.is_none()
            || !matches!(self.funding, Some(Ok(()))) || !matches!(self.association, Some(Ok(()))) {
            return Err(CLOSED);
        }
        root.require_completed_host_session_rejoin_v2(entry, controller,
            self.parent.ok_or(CLOSED)?, self.native_turn)?;
        // Every native Result is positive and the actual independent C/Root
        // posts have completed. Negative prefixes cannot reach this disposal.
        if let Some(samples) = self.samples.as_mut() {
            for sample in samples.iter_mut() { sample.names_original.settle_positive_once_v1(); }
        }
        drop(self.samples.take());
        self.retired = true;
        Ok(())
    }
}

impl Default for StartHostSessionRejoinOriginalV2 {
    fn default() -> Self { Self::new() }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Observes the same catalog Host Session within the real active stage1.
    ///
    /// # Errors
    /// Retains reentry, current Entry/Root/Source, funding, association or native
    /// failures. Every paid after-sample executes after a prior native refusal.
    #[doc(hidden)]
    pub fn observe_host_session_rejoin_once_v2(&mut self,
        root: &RootStartResourceCurrentTurnV2<'_>, opening: &super::super::network_opening::StartResourceSessionOpeningOriginalV2,
        controller: &Journal, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, owner: &mut StartHostSessionRejoinOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if owner.funding.is_some() {
            owner.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        owner.parent = Some(self.plan.operation_id());
        owner.native_turn = self.native.native_turn;
        owner.funding = Some((|| {
            self.require_host_stage_v2(1, controller)?;
            let root = root.require_host_session_rejoin_owner_v2(self.plan.operation_id(),
                self.native.native_turn, self.native.profile.as_ref())?;
            self.require_complete_v1(controller, root.checked_add(StartHostSessionRejoinOriginalV2::receiving_demand_v2()?)?)
        })());
        if !matches!(owner.funding, Some(Ok(()))) {
            owner.first = Some(First::Funding);
            return Err(CLOSED);
        }
        let Some(association) = opening.completed_session_association_v4() else {
            owner.association = Some(Err(CLOSED));
            owner.first = Some(First::Association);
            return Err(CLOSED);
        };
        owner.samples = Some(Box::new([Sample::new(), Sample::new()]));
        owner.association = Some((|| {
            if association.actual_role_v2() != StartResourceKindV2::Host.role_v2() { return Err(CLOSED); }
            association.require_start_v4(self.identity, self.plan.operation_id(), &self.native.profile)
        })());
        if !matches!(owner.association, Some(Ok(()))) { owner.first = Some(First::Association); }
        let samples = owner.samples.as_mut().ok_or(CLOSED)?;
        for (index, sample) in samples.iter_mut().enumerate() {
            sample.observe(association, journal, socket, transcript);
            let phases = if index == 0 { [First::BeforeEndpoint, First::BeforeSocket, First::BeforeNames] }
                else { [First::AfterEndpoint, First::AfterSocket, First::AfterNames] };
            for (phase, positive) in phases.into_iter().zip([
                matches!(sample.endpoint, Some(Ok(()))), matches!(sample.socket, Some(Ok(()))), matches!(sample.names, Some(Ok(())))]) {
                if !positive { owner.first.get_or_insert(phase); }
            }
        }
        if owner.first.is_some() { Err(CLOSED) } else { Ok(()) }
    }
}
