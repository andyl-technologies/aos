//! Same-original receiving for sequential operations on a retained Session.
//!
//! The actual Journal and socket stay in Security's noncloneable owner. This
//! loan continuously borrows the genuine service payer and privately captures
//! the existing Journal identity and actual socket origin. Numeric shapes are
//! DATA; independent Session admission, floor, terminal and domain checks stay
//! in their original owners. Positive disposal is deliberately two-phase.

use super::*;

mod output_after;
pub use output_after::StorageOutputOwedAfterOriginalV1;
use super::session_wire::WirePurpose;
use crate::controller_resource_reservation::component_receiving::{
    complete_bound_delta_v1,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, SeqpacketSocket, StorageSeqpacketEndAttemptV1,
    StorageSeqpacketSendAttemptV1, StorageSeqpacketSessionOriginV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Handshake,
    HandshakePaid,
    Ready,
    Request,
    Domain,
    Outcome,
    PreparedRetirement,
    OperationDisposal,
    TransportDisposal,
}

#[derive(Clone, Copy)]
enum Shape {
    Handshake,
    Request,
    Domain,
    Outcome,
}

impl Shape {
    fn slot(self) -> usize {
        match self {
            Self::Handshake => 0,
            Self::Request => 1,
            Self::Domain => 2,
            Self::Outcome => 3,
        }
    }

    fn successor(self, phase: Phase) -> Option<Phase> {
        match (self, phase) {
            (Self::Handshake, Phase::Handshake) => Some(Phase::HandshakePaid),
            (Self::Request, Phase::Ready) => Some(Phase::Request),
            (Self::Domain, Phase::Request) => Some(Phase::Domain),
            (Self::Outcome, Phase::Request | Phase::Domain) => Some(Phase::Outcome),
            _ => None,
        }
    }
}

pub(super) struct LifecycleReceivingV1 {
    phase: Phase,
    borrowed: bool,
    initial_session_entered: bool,
    high_water: [ResourceVector; 4],
    domain_bound: ResourceVector,
    output_after_pending: bool,
    domain_additional: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    preparation_retirement_entered: bool,
    origin: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    socket_current: Option<Result<(), RecordBindingError>>,
    growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    reservation: Option<Result<(), aos_sandbox_core::AccountingError>>,
    post: Option<NativeResult>,
    metadata: Option<Result<std::fs::Metadata, std::io::Error>>,
    current_extent: Option<Result<crate::journal::ProtectedJournalPreopenReplayExtentV1, crate::JournalError>>,
    sent: Option<StorageSeqpacketSendAttemptV1>,
    sent_binding: Option<Result<(), RecordBindingError>>,
    ended: Option<StorageSeqpacketEndAttemptV1>,
    end_binding: Option<Result<(), RecordBindingError>>,
    first: Option<LifecycleFailure>,
    pub(super) state_recovery: StateRecoveryEncodingOriginalV1,
    state_bound: ResourceVector,
    state_high_water: ResourceVector,
    state_growth: Option<Result<(ResourceVector, ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
}

#[derive(Clone, Copy)]
enum LifecycleFailure {
    Origin,
    Metadata,
    Extent,
    Socket,
    Growth,
    StateGrowth,
    DomainAdditional,
    Sent,
    SentBinding,
    End,
    EndBinding,
}

impl LifecycleReceivingV1 {
    pub(super) const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            borrowed: false,
            initial_session_entered: false,
            high_water: [ResourceVector::ZERO; 4],
            domain_bound: ResourceVector::ZERO,
            output_after_pending: false,
            domain_additional: None,
            preparation_retirement_entered: false,
            origin: None,
            socket_current: None,
            growth: None,
            reservation: None,
            post: None,
            metadata: None,
            current_extent: None,
            sent: None,
            sent_binding: None,
            ended: None,
            end_binding: None,
            first: None,
            state_recovery: StateRecoveryEncodingOriginalV1::new(),
            state_bound: ResourceVector::ZERO,
            state_high_water: ResourceVector::ZERO,
            state_growth: None,
        }
    }

    pub(super) fn is_parked_v1(&self) -> bool {
        !self.borrowed && self.first.is_none()
            && matches!(self.phase, Phase::Idle | Phase::Ready)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            LifecycleFailure::Origin => self.origin.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::Metadata => self.metadata.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::Extent => self.current_extent.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::Socket => self.socket_current.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::StateGrowth => self.state_growth.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::DomainAdditional => self.domain_additional.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::Growth => self.growth.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::Sent => self.sent.as_ref()
                .and_then(StorageSeqpacketSendAttemptV1::failure),
            LifecycleFailure::SentBinding => self.sent_binding.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
            LifecycleFailure::End => self.ended.as_ref()
                .and_then(StorageSeqpacketEndAttemptV1::failure),
            LifecycleFailure::EndBinding => self.end_binding.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error),
        }
    }
}

/// Continuously borrows the genuine payer across one retained Session carrier.
///
/// The same socket may serve multiple operations. Request/domain/outcome peaks
/// become reusable only through a real positive operation disposition. The
/// independently retained history, Journal and domain effects are never freed
/// or credited by that disposition. An unfinished loan closes its original.
#[must_use]
pub struct StorageLifecycleSessionLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    finished: bool,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Borrows a fresh retained-HELLO interval from the same actual Session writer.
    ///
    /// This entry does not reopen its endpoint, floor or Journal, and supplies
    /// no protocol admission. Handshake DATA must be paid before materialization.
    ///
    /// # Errors
    /// Refuses a different writer, active interval, unhealthy originals or an
    /// unavailable actual socket. Whole observations stay on the original.
    pub fn borrow_lifecycle_session_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        self.begin_lifecycle_v1(journal, socket, Phase::Handshake)
    }

    /// Resumes the same positively parked Session before its next operation.
    ///
    /// # Errors
    /// Refuses an active or unfinished borrower, a changed held writer/socket,
    /// or any prior financial/native failure. No startup or wire state resets.
    pub fn resume_lifecycle_session_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if receiving.lifecycle.borrowed || receiving.lifecycle.phase != Phase::Ready
            || !receiving.session_wire.is_between_flights_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.require_lifecycle_current_v1(journal, socket)?;
        self.receiving()?.lifecycle.borrowed = true;
        Ok(StorageLifecycleSessionLoanV1 { receiving: self, finished: false })
    }

    /// Enters the first full-method Session after its real initial HELLO disposal.
    ///
    /// # Errors
    /// Refuses another socket, repeated entry, entered Preparation outcomes or
    /// an incomplete initial HELLO. The existing writer and floor stay held.
    pub fn borrow_initial_lifecycle_session_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if receiving.lifecycle.initial_session_entered || receiving.catalog_paid
            || receiving.inventory_outcome.is_entered() || receiving.prepare_outcome.is_entered()
            || !receiving.session_wire.initial_is_complete_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.lifecycle.initial_session_entered = true;
        receiving.session_wire.require_socket(socket)?;
        self.begin_lifecycle_v1(journal, socket, Phase::Ready)
    }

    /// Borrows the first actual Prepared Session solely for transport retirement.
    ///
    /// Its original Prepare pipeline already paid its real request and outcome;
    /// this closed entry cannot receive another operation or reset those stages.
    /// Security must still establish its exact terminal/Sent/currentness proof.
    ///
    /// # Errors
    /// Refuses absent successful Prepare stages, reentry, a different writer or
    /// failed original/socket observations. No history row creates this entry.
    pub fn borrow_prepared_session_retirement_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.catalog_paid || !receiving.prepare_outcome.is_positive()
            || receiving.lifecycle.preparation_retirement_entered
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.lifecycle.preparation_retirement_entered = true;
        self.begin_lifecycle_v1(journal, socket, Phase::PreparedRetirement)
    }

    fn begin_lifecycle_v1<'cut>(
        &'cut mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        phase: Phase,
    ) -> Result<StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        self.require_retained_session_journal_v1(journal)?;
        let receiving = self.receiving()?;
        if receiving.lifecycle.phase != Phase::Idle || receiving.lifecycle.borrowed {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.lifecycle.phase = phase;
        receiving.lifecycle.borrowed = true;
        receiving.lifecycle.origin = Some(socket.capture_storage_session_origin_v1());
        let failed = !matches!(receiving.lifecycle.origin, Some(Ok(_)));
        if failed {
            receiving.lifecycle.first.get_or_insert(LifecycleFailure::Origin);
        }
        let post = self.original.recheck();
        let post_failed = post.is_err();
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            receiving.lifecycle.post = Some(post);
            if failed {
                receiving.first = Some(Failure::Lifecycle);
            }
        }
        if failed || post_failed {
            return Err(StorageReceivingClosedV1);
        }
        Ok(StorageLifecycleSessionLoanV1 { receiving: self, finished: false })
    }
}

impl StorageLifecycleSessionLoanV1<'_, '_> {
    /// Ends only this Rust borrow after actual positive carrier disposition.
    ///
    /// The same socket, Journal identity, financial debt and all consumed wire
    /// flags remain on the original. A later borrower must freshly recheck them
    /// before I/O. This pure handoff performs no late native observation.
    ///
    /// Calling this before real positive completion aborts rather than releasing
    /// an unfinished original. No fallible check follows positive disposal.
    pub fn park_between_operations_v1(mut self) {
        let receiving = match self.receiving.receiving() {
            Ok(receiving) => receiving,
            Err(_) => std::process::abort(),
        };
        if !receiving.lifecycle.borrowed || receiving.lifecycle.phase != Phase::Ready
            || !receiving.session_wire.is_between_flights_v1()
            || receiving.initial_post_pending
        {
            std::process::abort();
        }
        receiving.lifecycle.borrowed = false;
        self.finished = true;
    }

    /// Borrows the genuine original's first cause while this interval is held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.receiving.failure()
    }

    /// Rechecks the same writer, actual entry socket and original service.
    ///
    /// # Errors
    /// Refuses any prior failure, changed identity/name or native currentness.
    /// Whole socket and independent original posts remain retained.
    pub fn require_current_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.receiving.require_lifecycle_current_v1(journal, socket)
    }

    /// Captures receiving geometry from the same held Session file's current length.
    ///
    /// The initial opener extent is historical. A later operation must use this
    /// actual fresh extent, together with its real forecast append, before
    /// native/model/canonical growth. No caller scalar supplies the file length,
    /// and positive transient disposal never reclaims persistent file bytes.
    ///
    /// # Errors
    /// Refuses changed Journal/socket/service custody, an unhealthy writer,
    /// native metadata failure, invalid limits/extent or any prior failure.
    /// The whole metadata/extent Results and independent posts stay retained.
    pub fn observe_current_session_extent_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<&crate::journal::ProtectedJournalPreopenReplayExtentV1, StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        let receiving = self.receiving.receiving()?;
        receiving.lifecycle.metadata = Some(metadata);
        receiving.lifecycle.current_extent = match receiving.lifecycle.metadata.as_ref() {
            Some(Ok(metadata)) => Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                limits, metadata.len(),
            )),
            _ => None,
        };
        let failure = match receiving.lifecycle.metadata.as_ref() {
            Some(Err(_)) => Some(LifecycleFailure::Metadata),
            Some(Ok(_)) if matches!(receiving.lifecycle.current_extent, Some(Err(_))) =>
                Some(LifecycleFailure::Extent),
            _ => None,
        };
        if let Some(failure) = failure {
            receiving.lifecycle.first.get_or_insert(failure);
        }

        // Both results are already parked. Run the independent posts before
        // projecting an earlier metadata/geometry refusal into the original.
        let current = self.require_current_v1(journal, socket);
        if failure.is_some() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            {
                receiving.first = Some(Failure::Lifecycle);
            }
        }
        if failure.is_some() || current.is_err() {
            return Err(StorageReceivingClosedV1);
        }
        self.receiving.receiving()?.lifecycle.current_extent.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(StorageReceivingClosedV1)
    }

    /// Consumes the shared finite wire capacity before retained HELLO publication.
    ///
    /// # Errors
    /// Refuses a wrong phase, active predecessor, changed writer/socket or any
    /// full22 flight dimension beyond the genuine original remaining capacity.
    pub fn reserve_handshake_flight_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        if receiving.lifecycle.phase != Phase::Handshake {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let action = receiving.begin_session_wire_v1(socket, WirePurpose::RetainedHello, demand);
        let post = self.receiving.original.recheck();
        if action.is_err() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.receiving.original.recipient.as_mut() {
                receiving.first = Some(Failure::SessionWire);
            }
        }
        if action.is_err() || post.is_err() { Err(StorageReceivingClosedV1) } else { Ok(()) }
    }

    /// Pays the actual retained HELLO carriers before their first materialization.
    ///
    /// # Errors
    /// Refuses a wrong phase, owner substitution or exceeded original ceiling.
    pub fn reserve_handshake_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_shape_v1(journal, socket, Shape::Handshake, complete_bound)
    }

    /// Consumes this operation's full traffic shape before its first raw receive.
    ///
    /// The finite capacity remains permanently reserved on the SAME original
    /// ledger. It is separate from resident request/history high waters. Only
    /// actual two-phase operation disposal can admit a later flight.
    ///
    /// # Errors
    /// Refuses non-Ready/repeated entry, a replaced owner, an exceeded original
    /// ceiling, or any of the22 dimensions refusing permanent capacity growth.
    /// A completed predecessor must be actually disposed before a larger peak
    /// can reserve its positive delta on the same original ledger.
    pub fn reserve_operation_flight_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        if receiving.lifecycle.phase != Phase::Ready {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let action = receiving.begin_session_wire_v1(socket, WirePurpose::Request, demand);
        let post = self.receiving.original.recheck();
        if action.is_err() {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) = self.receiving.original.recipient.as_mut() {
                receiving.first = Some(Failure::SessionWire);
            }
        }
        if action.is_err() || post.is_err() { return Err(StorageReceivingClosedV1); }
        self.require_current_v1(journal, socket)
    }

    /// Rechecks the funded actual request interval before canonical admission.
    ///
    /// # Errors
    /// Refuses another phase, an unconsumed operation or changed actual owners.
    pub fn require_request_current_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        if receiving.lifecycle.phase != Phase::Request
            || !receiving.session_wire.is_current(WirePurpose::Request)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Extends the SAME request's resident bound before selected semantic decode.
    ///
    /// # Errors
    /// Refuses an unfunded/non-Request interval, changed owners or budget debt.
    pub fn extend_request_semantics_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_request_current_v1(journal, socket)?;
        self.reserve_shape_bound_v1(Shape::Request, complete_bound)?;
        self.require_request_current_v1(journal, socket)
    }

    /// Pays one request's complete transient bound before receive/decode growth.
    ///
    /// # Errors
    /// Refuses an unsettled preceding operation, changed owners or budget debt.
    pub fn reserve_request_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_shape_v1(journal, socket, Shape::Request, complete_bound)
    }

    /// Pays held domain geometry before semantic models or effects may grow.
    ///
    /// # Errors
    /// Refuses absent request payment, reentry, owner changes or budget debt.
    pub fn reserve_domain_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_shape_v1(journal, socket, Shape::Domain, complete_bound)?;
        self.receiving.receiving()?.lifecycle.domain_bound =
            aos_sandbox_core::component_receiving::without_operation_traffic_v1(complete_bound);
        Ok(())
    }

    /// Extends the actual live Domain before another retained stage grows.
    ///
    /// The caller supplies the complete simultaneous resident bound and this
    /// reached stage's actual finite traffic. Resident high water never falls;
    /// each call pays its traffic separately on the same original F ledger.
    /// No state, file, profile, effect permission or disposal is created here.
    ///
    /// # Errors
    /// Refuses another Journal/socket, a non-Domain or unfinished wire phase,
    /// previous debt, checked arithmetic or an exhausted declared ceiling.
    pub fn extend_domain_receiving_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        if receiving.lifecycle.phase != Phase::Domain
            || !receiving.session_wire.is_current(WirePurpose::Request)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let resident = aos_sandbox_core::component_receiving::without_operation_traffic_v1(
            complete_bound,
        );
        let held = self.receiving.receiving()?.lifecycle.domain_bound;
        let resident = held.componentwise_max(resident);
        self.reserve_shape_bound_v1(Shape::Domain, resident)?;
        self.receiving.receiving()?.lifecycle.domain_bound = resident;
        let traffic = aos_sandbox_core::component_receiving::operation_traffic_demand_v1(
            complete_bound,
        );
        self.receiving.receiving()?.reserve(traffic)?;
        self.require_current_v1(journal, socket)
    }

    /// Adds reached live Domain custody and this stage's consumable traffic.
    ///
    /// Resident allocations coexist until the actual positive operation
    /// disposition. Their complete bound accumulates here, while every reached
    /// operation-traffic term is debited again on the same original ledger.
    /// This cannot reset an earlier charge or admit semantic Capture work.
    ///
    /// # Errors
    /// Refuses a different or unpaid Session Domain, arithmetic overflow,
    /// exceeded genuine capacity, or any earlier native/currentness failure.
    /// The original arithmetic or ledger cause remains retained.
    pub fn reserve_domain_additional_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        additional: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.receiving.require_lifecycle_domain_current_v1(journal, socket)?;
        let resident = aos_sandbox_core::component_receiving::without_operation_traffic_v1(additional);
        let traffic = aos_sandbox_core::component_receiving::operation_traffic_demand_v1(additional);
        let receiving = self.receiving.receiving()?;
        receiving.lifecycle.domain_additional = Some(receiving.lifecycle.domain_bound
            .checked_add(resident).and_then(|bound| bound.checked_add(traffic)));
        let Some(Ok(bound)) = receiving.lifecycle.domain_additional.as_ref().copied() else {
            receiving.lifecycle.first.get_or_insert(LifecycleFailure::DomainAdditional);
            receiving.first.get_or_insert(Failure::Lifecycle);
            return Err(StorageReceivingClosedV1);
        };
        self.extend_domain_receiving_v1(journal, socket, bound)
    }

    /// Arms the independently paid post before request receipt or Domain entry.
    ///
    /// # Errors
    /// Refuses another writer/socket, active predecessor, wrong phase or actual
    /// observer-capacity failure. The same original owns the pending sample.
    pub fn arm_request_observation_post_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        let eligible = match receiving.lifecycle.phase {
            Phase::Ready => receiving.session_wire.is_between_flights_v1(),
            Phase::Request => receiving.session_wire.is_current(WirePurpose::Request),
            _ => false,
        };
        if !eligible {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.receiving.arm_service_acquisition_observation_post_v1()
    }

    /// Arms the independent paid service observation for this actual operation.
    ///
    /// Only the same entered Domain/Outcome and consumed wire flight can use
    /// the existing observer producer. This creates no request/effect authority.
    ///
    /// # Errors
    /// Refuses wrong phase/identity, prior debt or another pending observation.
    pub fn arm_operation_observation_post_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        if !matches!(receiving.lifecycle.phase, Phase::Domain | Phase::Outcome)
            || !receiving.session_wire.is_current(WirePurpose::Request)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.receiving.arm_service_acquisition_observation_post_v1()
    }

    /// Runs the actual armed operation observation even after primary poison.
    ///
    /// The same intrinsic Journal/socket join and genuine producer remain held;
    /// a successful post cannot erase earlier failure or allow positive reuse.
    ///
    /// # Errors
    /// Retains missing pending debt, native/RPC observation and prior failures.
    pub fn finish_operation_observation_post_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.receiving.observe_domain_state_socket_post_v1(journal, socket);
        let post = self.receiving.finish_initial_observation_native_post_v1();
        let failed = post.is_err();
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        {
            receiving.lifecycle.post = Some(post);
            if failed || receiving.first.is_some() || receiving.lifecycle.first.is_some() {
                return Err(StorageReceivingClosedV1);
            }
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        }
    }

    /// Pays copies/signing/history growth of the actual parked domain response.
    ///
    /// The bound must include all retained history and effects it describes;
    /// successful transport disposal never credits persistent history growth.
    ///
    /// # Errors
    /// Refuses absent request payment, repeat outcome entry or original failure.
    pub fn reserve_outcome_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.reserve_shape_v1(journal, socket, Shape::Outcome, complete_bound)
    }

    fn reserve_shape_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        shape: Shape,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_current_v1(journal, socket)?;
        let receiving = self.receiving.receiving()?;
        let purpose = match shape {
            Shape::Handshake => WirePurpose::RetainedHello,
            _ => WirePurpose::Request,
        };
        if !receiving.session_wire.is_current(purpose)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let Some(successor) = shape.successor(receiving.lifecycle.phase) else {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        };
        self.reserve_shape_bound_v1(shape, complete_bound)?;
        let receiving = self.receiving.receiving()?;
        receiving.lifecycle.phase = successor;
        self.require_current_v1(journal, socket)
    }

    fn reserve_shape_bound_v1(
        &mut self,
        shape: Shape,
        complete_bound: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving.receiving()?;
        let slot = shape.slot();
        receiving.lifecycle.growth = Some(complete_bound_delta_v1(
            receiving.lifecycle.high_water[slot], complete_bound,
        ));
        let Some(Ok((high_water, delta))) = receiving.lifecycle.growth.as_ref().copied() else {
            receiving.lifecycle.first.get_or_insert(LifecycleFailure::Growth);
            receiving.first.get_or_insert(Failure::Lifecycle);
            return Err(StorageReceivingClosedV1);
        };
        receiving.lifecycle.reservation = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if matches!(receiving.lifecycle.reservation, Some(Err(_))) {
            receiving.first.get_or_insert(Failure::Accounting);
            return Err(StorageReceivingClosedV1);
        }
        receiving.lifecycle.high_water[slot] = high_water;
        Ok(())
    }

}

#[derive(Clone, Copy)]
enum DisposalKind {
    Handshake,
    Operation,
    Transport,
}

#[derive(Debug)]
enum OfferedReceipt {
    Hello(StorageSeqpacketSendAttemptV1),
    Sent(StorageSeqpacketSendAttemptV1),
    End(StorageSeqpacketEndAttemptV1),
}

impl OfferedReceipt {
    fn kind(&self) -> DisposalKind {
        match self {
            Self::Hello(_) => DisposalKind::Handshake,
            Self::Sent(_) => DisposalKind::Operation,
            Self::End(_) => DisposalKind::Transport,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hello(receipt) | Self::Sent(receipt) => receipt.failure(),
            Self::End(receipt) => receipt.failure(),
        }
    }
}

/// Retains an offered receipt rejected before it could enter its original slot.
///
/// Normally the whole actual receipt is already parked on the Native original;
/// its loan's `failure()` exposes that first cause. An invalid repeated offer
/// stays in this owning error instead of replacing or dropping its predecessor.
#[derive(Debug)]
pub struct StorageLifecycleDisposalErrorV1 {
    rejected: Option<OfferedReceipt>,
}

impl std::fmt::Display for StorageLifecycleDisposalErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the original Storage lifecycle disposition is closed")
    }
}

impl Error for StorageLifecycleDisposalErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.rejected.as_ref().and_then(OfferedReceipt::failure)
    }
}

/// Holds a fully checked positive disposition before actual upper disposal.
///
/// Security's closed consuming owner must keep all its request, model, socket,
/// terminal and domain originals through its remaining fallible posts. Only
/// after every post succeeds may it actually dispose the positive transient
/// control copies and call [`Self::complete_after_disposal_v1`]. The token
/// grants no semantic, floor, peer or effect authority. Forgetting it leaves
/// the operation blocked; dropping it without completion closes the original.
#[must_use]
pub struct StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original> {
    session: &'phase mut StorageLifecycleSessionLoanV1<'cut, 'original>,
    kind: DisposalKind,
    completed: bool,
}

impl<'cut, 'original> StorageLifecycleSessionLoanV1<'cut, 'original> {
    /// Lends the same genuine payer to existing fixed domain ports after payment.
    ///
    /// This borrow cannot outlive the guard borrow or construct another owner.
    /// The actual Session writer/socket are rechecked before the loan is lent;
    /// all existing semantic, authority and Native effect checks remain required.
    ///
    /// # Errors
    /// Refuses an unpaid/wrong domain phase, replaced writer/socket or original
    /// debt. It never exposes the account, ledger or resource envelope as a grant.
    pub fn receiving_domain_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<&mut StoragePrepareReceivingLoanV1<'original>, StorageReceivingClosedV1> {
        self.receiving.require_lifecycle_domain_current_v1(journal, socket)?;
        Ok(&mut *self.receiving)
    }

    /// Checks the final actual HELLO send before successful raw/control disposal.
    ///
    /// # Errors
    /// Retains every offered receipt and refuses an unpaid/wrong HELLO interval,
    /// a substituted socket/Journal, failed send or original currentness debt.
    pub fn prepare_handshake_disposal_v1<'phase>(
        &'phase mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        sent: StorageSeqpacketSendAttemptV1,
    ) -> Result<StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>, StorageLifecycleDisposalErrorV1> {
        self.prepare_disposal_v1(journal, socket, OfferedReceipt::Hello(sent))
    }

    /// Checks the actual Sent receipt before disposing positive operation copies.
    ///
    /// All fallible Native and upper posts run while those copies remain
    /// resident. Completion of the returned continuation performs no new I/O.
    /// The same connected socket and Journal remain paid across later requests.
    ///
    /// # Errors
    /// Retains the whole actual receipt on the original, or returns a repeated
    /// offered receipt in the owning error. Refuses wrong phase, incomplete send,
    /// a different socket/writer, currentness debt or an earlier failure.
    pub fn prepare_operation_disposal_v1<'phase>(
        &'phase mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        sent: StorageSeqpacketSendAttemptV1,
    ) -> Result<
        StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        StorageLifecycleDisposalErrorV1,
    > {
        self.prepare_disposal_v1(journal, socket, OfferedReceipt::Sent(sent))
    }

    /// Checks actual shutdown before retiring this Session's transport copies.
    ///
    /// The original Journal/floor/endpoint must stay in their upper owner for
    /// the next retained handshake. A shutdown receipt does not establish peer
    /// death, effect drain or settlement of a different carrier.
    ///
    /// # Errors
    /// Preserves the whole actual receipt and all reached posts. Refuses an
    /// outstanding operation, incomplete/substituted shutdown or original debt.
    pub fn prepare_session_transport_disposal_v1<'phase>(
        &'phase mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        ended: StorageSeqpacketEndAttemptV1,
    ) -> Result<
        StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        StorageLifecycleDisposalErrorV1,
    > {
        self.prepare_disposal_v1(journal, socket, OfferedReceipt::End(ended))
    }

    fn prepare_disposal_v1<'phase>(
        &'phase mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
        offered: OfferedReceipt,
    ) -> Result<
        StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
        StorageLifecycleDisposalErrorV1,
    > {
        let kind = offered.kind();
        let receiving = match self.receiving.receiving() {
            Ok(receiving) => receiving,
            Err(_) => return Err(StorageLifecycleDisposalErrorV1 { rejected: Some(offered) }),
        };
        let eligible = match kind {
            DisposalKind::Handshake => receiving.lifecycle.phase == Phase::HandshakePaid
                && receiving.session_wire.is_current(WirePurpose::RetainedHello),
            DisposalKind::Operation => !receiving.lifecycle.output_after_pending
                && receiving.lifecycle.phase == Phase::Outcome
                && receiving.session_wire.is_current(WirePurpose::Request)
                && receiving.lifecycle.state_recovery.is_positive_or_unused_v1(),
            DisposalKind::Transport => matches!(receiving.lifecycle.phase,
                Phase::Ready | Phase::PreparedRetirement),
        };
        if !eligible {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageLifecycleDisposalErrorV1 { rejected: Some(offered) });
        }

        // Each prior positive receipt can be replaced only after the previous
        // typed disposition completed. Negative receipts permanently close this
        // original and therefore cannot be overwritten through this accessor.
        let receipt_failed = match offered {
            OfferedReceipt::Hello(sent) => {
                receiving.session_wire.sent = Some(sent);
                !receiving.session_wire.observe_sent(socket)
            }
            OfferedReceipt::Sent(sent) => {
                receiving.lifecycle.sent = Some(sent);
                let sent = receiving.lifecycle.sent.as_ref();
                let positive = sent.is_some_and(StorageSeqpacketSendAttemptV1::is_sent);
                receiving.lifecycle.sent_binding = sent.map(|sent| sent.require_same_socket(socket));
                let binding_failed = !matches!(receiving.lifecycle.sent_binding, Some(Ok(())));
                if !positive {
                    receiving.lifecycle.first.get_or_insert(LifecycleFailure::Sent);
                } else if binding_failed {
                    receiving.lifecycle.first.get_or_insert(LifecycleFailure::SentBinding);
                }
                !positive || binding_failed
            }
            OfferedReceipt::End(ended) => {
                receiving.lifecycle.ended = Some(ended);
                let ended = receiving.lifecycle.ended.as_ref();
                let positive = ended.is_some_and(StorageSeqpacketEndAttemptV1::is_complete);
                receiving.lifecycle.end_binding = ended.map(|ended| ended.require_same_socket(socket));
                let binding_failed = !matches!(receiving.lifecycle.end_binding, Some(Ok(())));
                if !positive {
                    receiving.lifecycle.first.get_or_insert(LifecycleFailure::End);
                } else if binding_failed {
                    receiving.lifecycle.first.get_or_insert(LifecycleFailure::EndBinding);
                }
                !positive || binding_failed
            }
        };

        // This independent currentness flight is owed even after an actual
        // send/end refusal. Do not mark the original closed until it has run.
        let current = self.require_current_v1(journal, socket);
        if receipt_failed {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            {
                receiving.first = Some(match kind {
                    DisposalKind::Handshake => Failure::SessionWire,
                    _ => Failure::Lifecycle,
                });
            }
        }
        if receipt_failed || current.is_err() {
            return Err(StorageLifecycleDisposalErrorV1 { rejected: None });
        }
        self.receiving.receiving().map_err(|_| StorageLifecycleDisposalErrorV1 { rejected: None })?
            .lifecycle.phase = match kind {
                DisposalKind::Handshake | DisposalKind::Operation => Phase::OperationDisposal,
                DisposalKind::Transport => Phase::TransportDisposal,
            };
        Ok(StorageLifecyclePositiveDisposalV1 { session: self, kind, completed: false })
    }
}

impl<'phase, 'cut, 'original> StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original> {
    /// Lends the same original F for the final upper transport posts.
    ///
    /// The positive native shutdown remains resident and uncompleted while
    /// its actual Session loan is briefly reborrowed. The loan keeps its
    /// TransportDisposal phase, original expiry and first debt; this port
    /// creates no new source, account, socket, settlement or effect authority.
    ///
    /// # Errors
    /// Refuses another disposal kind, completed token or changed native phase.
    pub fn borrow_transport_post_receiving_v3(&mut self)
        -> Result<&mut StorageLifecycleSessionLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        if self.completed || !matches!(self.kind, DisposalKind::Transport) {
            return Err(StorageReceivingClosedV1);
        }
        let receiving = self.session.receiving.receiving()?;
        if receiving.lifecycle.phase != Phase::TransportDisposal {
            return Err(StorageReceivingClosedV1);
        }
        Ok(&mut *self.session)
    }

    /// Checks this actual operation token's completed State interval.
    ///
    /// This borrows only already-retained DATA. It performs no I/O and grants
    /// no effect authority; upper owners still owe their actual positive drop.
    ///
    /// # Errors
    /// Refuses a HELLO/transport token, another State writer or an unfinished
    /// or negative State interval. It never changes the original's first cause.
    pub fn require_state_reconciliation_disposal_v1(
        &self,
        state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.session.receiving.original.recipient.as_ref()
        else { return Err(StorageReceivingClosedV1); };
        if !matches!(self.kind, DisposalKind::Operation)
            || !receiving.startup.state_recovery_ready_v1(state)
            || !receiving.lifecycle.state_recovery.entered_v1()
            || !receiving.lifecycle.state_recovery.is_positive_or_unused_v1()
        {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Checks an operation that never borrowed the State encoding interval.
    ///
    /// This inspects the same already-paid native owner only. The caller must
    /// still retain the actual domain response, Sent and its independent posts;
    /// it cannot retire an entered State interval through this port.
    ///
    /// # Errors
    /// Refuses another disposition kind, State writer, entered or failed State
    /// interval. No native observation, debit or first-cause replacement occurs.
    pub fn require_unused_state_disposal_v2(
        &self,
        state: &crate::Journal,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.session.receiving.original.recipient.as_ref()
        else { return Err(StorageReceivingClosedV1); };
        if !matches!(self.kind, DisposalKind::Operation)
            || !receiving.startup.state_recovery_ready_v1(state)
            || receiving.lifecycle.state_recovery.entered_v1()
            || !receiving.lifecycle.state_recovery.is_positive_or_unused_v1()
        {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Completes the already-checked interval after actual positive upper disposal.
    ///
    /// This is deliberately infallible: no observation, allocation, authority or
    /// arithmetic follows the disposal. Charged high waters and persistent
    /// history stay unchanged. Only the next closed carrier phase becomes usable.
    pub fn complete_after_disposal_v1(mut self) {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.session.receiving.original.recipient.as_mut()
        else {
            std::process::abort();
        };
        match self.kind {
            DisposalKind::Handshake | DisposalKind::Operation => {
                if matches!(self.kind, DisposalKind::Operation) {
                    // Native and upper prerequisites were checked with every
                    // carrier resident. Actual upper disposition has completed;
                    // no fallible observation or new admission follows this drop.
                    receiving.lifecycle.state_recovery = StateRecoveryEncodingOriginalV1::new();
                    receiving.lifecycle.state_bound = ResourceVector::ZERO;
                    receiving.lifecycle.domain_bound = ResourceVector::ZERO;
                    receiving.lifecycle.domain_additional = None;
                }
                receiving.session_wire.complete();
                receiving.lifecycle.phase = Phase::Ready;
            }
            DisposalKind::Transport => {
                receiving.lifecycle.phase = Phase::Idle;
                receiving.lifecycle.borrowed = false;
                self.session.finished = true;
            }
        }
        self.completed = true;
    }
}

impl Drop for StorageLifecyclePositiveDisposalV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.session.receiving.original.recipient.as_mut()
            {
                receiving.first.get_or_insert(Failure::Closed);
            }
        }
    }
}

impl Drop for StorageLifecycleSessionLoanV1<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            {
                receiving.first.get_or_insert(Failure::Closed);
            }
        }
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    fn require_lifecycle_current_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_retained_session_journal_v1(journal)?;
        let receiving = self.receiving()?;
        let Some(Ok(origin)) = receiving.lifecycle.origin.as_ref() else {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        };
        receiving.lifecycle.socket_current = Some(origin.require_same_socket(socket));
        let failed = matches!(receiving.lifecycle.socket_current, Some(Err(_)));
        if failed {
            receiving.lifecycle.first.get_or_insert(LifecycleFailure::Socket);
        }
        let post = self.original.recheck();
        let post_failed = post.is_err();
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            receiving.lifecycle.post = Some(post);
            if failed {
                receiving.first = Some(Failure::Lifecycle);
            }
        }
        if failed || post_failed {
            Err(StorageReceivingClosedV1)
        } else {
            Ok(())
        }
    }

    pub(super) fn require_lifecycle_domain_current_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_lifecycle_current_v1(journal, socket)?;
        let receiving = self.receiving()?;
        if receiving.lifecycle.phase != Phase::Domain
            || !receiving.session_wire.is_current(WirePurpose::Request)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn observe_domain_state_socket_post_v1(
        &mut self,
        journal: &crate::Journal,
        socket: &SeqpacketSocket,
    ) {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else { return; };
        let same_journal = receiving.session_identity.as_ref()
            .is_some_and(|identity| identity.same_journal(journal));
        receiving.lifecycle.socket_current = receiving.lifecycle.origin.as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|origin| origin.require_same_socket(socket));
        if !same_journal || !matches!(receiving.lifecycle.socket_current, Some(Ok(()))) {
            receiving.lifecycle.first.get_or_insert(LifecycleFailure::Socket);
            receiving.first.get_or_insert(Failure::Lifecycle);
        }
    }
}

impl StorageReceivingOriginalV1 {
    pub(super) fn reserve_domain_state_bound_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        // Each reached allocation adds to this operation's simultaneous bound.
        // Only actual terminal/Sent disposition may start another operation at
        // zero. The permanently charged highwater is never refunded; journal
        // append demand includes the actual current physical prefix each time.
        self.lifecycle.state_growth = Some(state_interval_growth_v1(
            self.lifecycle.state_high_water, self.lifecycle.state_bound, demand,
        ));
        let Some(Ok((bound, high_water, delta))) = self.lifecycle.state_growth.as_ref().copied() else {
            self.lifecycle.first.get_or_insert(LifecycleFailure::StateGrowth);
            self.first.get_or_insert(Failure::Lifecycle);
            return Err(StorageReceivingClosedV1);
        };
        self.reserve(delta)?;
        self.lifecycle.state_bound = bound;
        self.lifecycle.state_high_water = high_water;
        Ok(())
    }
}

// Every allocation reached within one live State interval coexists until its
// real upper disposition. Only the next positively completed operation starts
// with an empty interval bound; its permanent namespace/history highwater stays.
fn state_interval_growth_v1(
    high_water: ResourceVector,
    held: ResourceVector,
    demand: ResourceVector,
) -> Result<(ResourceVector, ResourceVector, ResourceVector), aos_sandbox_core::AccountingError> {
    let bound = held.checked_add(demand)?;
    let (high_water, delta) = complete_bound_delta_v1(high_water, bound)?;
    Ok((bound, high_water, delta))
}

#[cfg(test)]
mod tests {
    use super::*;
use super::session_wire::WirePurpose;

    #[test]
    fn parent_handoff_refuses_live_or_failed_session_phases() {
        // This exercises private transition DATA, not a genuine origin factory.
        let mut original = LifecycleReceivingV1::new();
        assert!(original.is_parked_v1());
        for phase in [Phase::Handshake, Phase::HandshakePaid, Phase::Request,
            Phase::Domain, Phase::Outcome, Phase::OperationDisposal, Phase::TransportDisposal]
        {
            original.phase = phase;
            assert!(!original.is_parked_v1());
        }

        original.phase = Phase::Ready;
        original.borrowed = true;
        assert!(!original.is_parked_v1());
        original.borrowed = false;
        assert!(original.is_parked_v1());
        original.first = Some(LifecycleFailure::Socket);
        assert!(!original.is_parked_v1());
    }

    #[test]
    fn state_allocations_accumulate_within_one_operation_and_keep_history_highwater() {
        let bytes = |value| ResourceVector::ZERO.with(D::MemoryBytes, value);
        let (first, high_water, delta) = state_interval_growth_v1(
            ResourceVector::ZERO, ResourceVector::ZERO, bytes(64),
        ).unwrap();
        assert_eq!(delta.get(D::MemoryBytes), 64);

        let (held, high_water, delta) = state_interval_growth_v1(high_water, first, bytes(80)).unwrap();
        assert_eq!(held.get(D::MemoryBytes), 144);
        assert_eq!(delta.get(D::MemoryBytes), 80);

        // This is the bound for a later genuinely disposed operation, not a
        // reset exposed to callers. The larger permanent payment is retained.
        let (_, later_high_water, delta) = state_interval_growth_v1(
            high_water, ResourceVector::ZERO, bytes(80),
        ).unwrap();
        assert_eq!(later_high_water, high_water);
        assert_eq!(delta, ResourceVector::ZERO);

        let (_, _, growth) = state_interval_growth_v1(
            high_water.with(D::StorageBytes, 4096), ResourceVector::ZERO,
            bytes(80).with(D::StorageBytes, 4608),
        ).unwrap();
        assert_eq!(growth.get(D::StorageBytes), 512);
    }

    #[test]
    fn state_interval_overflow_keeps_the_actual_dimension() {
        let held = ResourceVector::ZERO.with(D::MemoryBytes, u64::MAX);
        let error = state_interval_growth_v1(held, held,
            ResourceVector::ZERO.with(D::MemoryBytes, 1)).unwrap_err();
        assert_eq!(error, aos_sandbox_core::AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        });
    }

    #[test]
    fn sequential_operations_need_a_completed_disposition_but_no_new_hello() {
        let request = Shape::Request.successor(Phase::Ready).unwrap();
        assert!(Shape::Request.successor(request).is_none());
        let domain = Shape::Domain.successor(request).unwrap();
        let outcome = Shape::Outcome.successor(domain).unwrap();

        assert_eq!(outcome, Phase::Outcome);
        assert!(Shape::Request.successor(outcome).is_none());
        assert!(Shape::Request.successor(Phase::OperationDisposal).is_none());
        // Only the consumed positive upper continuation publishes Ready.
        assert!(Shape::Request.successor(Phase::Ready).is_some());
        assert_eq!(Shape::Handshake.successor(Phase::Handshake), Some(Phase::HandshakePaid));
        assert!(Shape::Handshake.successor(Phase::HandshakePaid).is_none());
        assert!(Shape::Handshake.successor(Phase::Ready).is_none());
    }

    #[test]
    fn initial_prepared_retirement_cannot_receive_a_fresh_operation() {
        for shape in [Shape::Handshake, Shape::Request, Shape::Domain, Shape::Outcome] {
            assert!(shape.successor(Phase::PreparedRetirement).is_none());
            assert!(shape.successor(Phase::TransportDisposal).is_none());
        }
        // A protocol rejection can produce an authenticated error response
        // without entering a domain effect; it still needs its actual outcome.
        assert!(Shape::Outcome.successor(Phase::Request).is_some());
    }
}

impl StorageLifecycleSessionLoanV1<'_, '_> {
    /// Prepays a physical-floor primitive from this same live original F.
    ///
    /// This is only a financial forwarding port. The private physical owner
    /// must still verify its actual pair and every native/currentness phase.
    ///
    /// # Errors
    /// Retains the original F refusal, overlap or substituted writer pair.
    pub fn begin_floor_physical_program_v2(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector)
        -> Result<super::floor_physical::StorageFloorPhysicalProgramReceivingV2, StorageReceivingClosedV1>
    {
        self.receiving.begin_floor_physical_program_v2(main, sidecar, complete)
    }

    /// Returns the same financial receipt after its private native disposition.
    ///
    /// # Errors
    /// Refuses a different pair/receipt or failed original; never refunds spend.
    pub fn finish_floor_physical_program_v2(&mut self,
        receipt: &super::floor_physical::StorageFloorPhysicalProgramReceivingV2,
        main: &crate::Journal, sidecar: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.receiving.finish_floor_physical_program_v2(receipt, main, sidecar)
    }
}


impl StorageLifecycleSessionLoanV1<'_, '_> {
    /// Forwards sidecar representation payment through this same actual F.
    ///
    /// # Errors
    /// Retains the original F refusal or a substituted held writer pair.
    pub fn reserve_floor_sidecar_v2(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.receiving.reserve_floor_sidecar_v2(main, sidecar, complete)
    }

    /// Forwards actual main-floor receiving demand to this same original F.
    ///
    /// # Errors
    /// Refuses a foreign main, prior refusal or exhausted original F before
    /// the corresponding representation grows.
    pub fn reserve_floor_main_v3(&mut self, main: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.receiving.reserve_floor_main_v3(main, complete)
    }

    /// Prepays retained canonical Session replay on the same original F.
    ///
    /// # Errors
    /// Retains another main, closed original, overflow or actual ledger refusal.
    pub fn reserve_session_replay_v3(&mut self, main: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.receiving.reserve_session_replay_v3(main, complete)
    }

    /// Prepays the remote availability capsule from this same resident source.
    ///
    /// The actual main and taken sidecar remain independently required; this
    /// forwarding loan cannot create or replace their native owners.
    ///
    /// # Errors
    /// Retains a substituted pair, prior refusal, overflow or original F debt.
    pub fn reserve_floor_availability_v3(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.receiving.reserve_floor_availability_v3(main, sidecar, complete)
    }
}
