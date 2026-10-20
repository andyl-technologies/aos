//! Closes the actual Start Network HELLO and native cold-opening handoff.
//!
//! Both native receipts are parked before validation. Distinct paid clock,
//! execution and Journal-name destinations run even when an earlier comparison
//! fails. Only the consuming token, after upper cold-control disposal, publishes
//! the association used by the later genuine Start IO loan.

mod currentness;
pub use currentness::StartResourceSessionCurrentnessErrorV4;

use super::*;
use aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyV1;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_linux::self_execution::SelfExecutionObservationError;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, SeqpacketSocket, StorageSeqpacketSendAttemptV1,
    StorageSeqpacketSessionOriginV1,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalCheckpointErrorV1, HistoricalSessionCheckpointV1,
    HistoricalSessionCheckpointVerifyCaptureV1,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

#[derive(Clone, Copy)]
enum CompletionFirst {
    Entry,
    ClockBefore,
    Origin,
    Sent,
    Received,
    Checkpoint,
    Transcript,
    Endpoint,
    Names,
    ClockAfter,
    Association,
    Abandoned,
}

/// Retains every reached native prefix of the closed Network cold completion.
///
/// Its inert constructor is private. Only the actual opening loan enters this
/// owner after the fixed complete demand has been admitted on the same Start.
#[doc(hidden)]
pub struct StartResourceColdCompletionOriginalV4 {
    entered: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
    socket: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    origin_cookie: Option<Result<u64, aos_sandbox_linux::Error>>,
    sent_cookie: Option<Result<u64, aos_sandbox_linux::Error>>,
    received_cookie: Option<Result<u64, aos_sandbox_linux::Error>>,
    sent_binding: Option<Result<(), RecordBindingError>>,
    received_binding: Option<Result<(), RecordBindingError>>,
    checkpoint: HistoricalSessionCheckpointVerifyCaptureV1,
    checkpoint_result: Option<Result<(), HistoricalCheckpointErrorV1>>,
    transcript: Option<Result<(), ResourceReservationErrorV1>>,
    endpoint_original: SelfExecutionObservationV1,
    endpoint: Option<Result<(), SelfExecutionObservationError>>,
    names_original: ProtectedJournalCurrentnessOriginalsV1,
    names: Option<Result<(), JournalError>>,
    final_extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 2],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 2],
    times: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    pending: Option<StartResourceSessionAssociationV4>,
    completed: Option<StartResourceSessionAssociationV4>,
    first: Option<CompletionFirst>,
}

impl StartResourceColdCompletionOriginalV4 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            entry: None,
            sent: None,
            received: None,
            socket: None,
            origin_cookie: None, sent_cookie: None, received_cookie: None,
            sent_binding: None,
            received_binding: None,
            checkpoint: HistoricalSessionCheckpointVerifyCaptureV1::new(),
            checkpoint_result: None,
            transcript: None,
            endpoint_original: SelfExecutionObservationV1::new(),
            endpoint: None,
            names_original: ProtectedJournalCurrentnessOriginalsV1::new(),
            names: None,
            final_extent: None,
            clocks: std::array::from_fn(|_| Default::default()),
            samples: [None, None],
            times: [None, None],
            pending: None,
            completed: None,
            first: None,
        }
    }

    fn select(&mut self, first: CompletionFirst, positive: bool) {
        if !positive {
            self.first.get_or_insert(first);
        }
    }

    /// Borrows the original earliest failure, including retained native detail.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            CompletionFirst::Entry => original_error(&self.entry),
            CompletionFirst::ClockBefore => self.clocks[0].failure()
                .or_else(|| original_error(&self.samples[0]))
                .or_else(|| original_error(&self.times[0])),
            CompletionFirst::Origin => original_error(&self.origin_cookie).or_else(|| original_error(&self.socket)),
            CompletionFirst::Sent => self.sent.as_ref().and_then(|sent| sent.failure())
                .or_else(|| original_error(&self.sent_cookie))
                .or_else(|| original_error(&self.sent_binding)),
            CompletionFirst::Received => original_error(&self.received_cookie).or_else(|| original_error(&self.received_binding)),
            CompletionFirst::Checkpoint => self.checkpoint.failure()
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| original_error(&self.checkpoint_result)),
            CompletionFirst::Transcript => original_error(&self.transcript),
            CompletionFirst::Endpoint => self.endpoint_original.failure()
                .or_else(|| original_error(&self.endpoint)),
            CompletionFirst::Names => self.names_original.failure()
                .or_else(|| original_error(&self.names))
                .or_else(|| original_error(&self.final_extent)),
            CompletionFirst::ClockAfter => self.clocks[1].failure()
                .or_else(|| original_error(&self.samples[1]))
                .or_else(|| original_error(&self.times[1])),
            CompletionFirst::Association | CompletionFirst::Abandoned => Some(&CLOSED as _),
        }
        .or(Some(&CLOSED))
    }

    pub(super) fn receiving_demand_v4() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let pair_bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(CLOSED)?;
        let native_bytes = SelfExecutionObservationV1::receiving_heap_bytes_v1()
            .checked_add(pair_bytes)
            .and_then(|bytes| bytes.checked_add(size_of::<StartResourceSessionAssociationV4>().checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(size_of::<StartResourceHelloDisposalV4<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<StartResourceHelloDisposalErrorV4>().checked_mul(2)?))
            .ok_or(CLOSED)?;
        let files = SelfExecutionObservationV1::opened_file_bound_v1()
            .checked_add(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
                .checked_mul(2).ok_or(CLOSED)?)
            .ok_or(CLOSED)?;
        // These are actual boot/proc reader names, rather than control fields.
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| names.checked_add(SelfExecutionObservationV1::opened_file_bound_v1()))
            .ok_or(CLOSED)?;

        let native = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(native_bytes).map_err(|_| CLOSED)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| CLOSED)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| CLOSED)?);
        native.checked_add(ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("session.journal")
                .map_err(|_| CLOSED)?)?
            .checked_add(geometry::start_network_checkpoint_verification_demand_v4()
                .map_err(|_| CLOSED)?)
            .map_err(Into::into)
    }
}

/// Binds only a genuinely completed Start Network Session to its actual owner.
///
/// This value cannot be constructed or cloned by callers. Its same-Session
/// comparison is one prerequisite of the later Start-native/Root/Source loan;
/// it supplies neither payment nor permission to issue a request by itself.
#[doc(hidden)]
pub struct StartResourceSessionAssociationV4 {
    link: StartResourceSessionOpeningOwnerLinkV2,
    journal: StorageNativeOpeningOwnerLinkV1,
    socket: StorageSeqpacketSessionOriginV1,
    custody: Arc<ControllerEndpointNativeCustodyV1>,
    binding: [u8; 32],
    context: [u8; 32],
    profile: Arc<ProductionControllerNormalRootProfileV1>,
}

impl StartResourceSessionAssociationV4 {
    pub(crate) fn actual_role_v2(&self) -> crate::ControllerInitialBrokerSessionRoleV1 { self.link.role }

    /// Compares the actual completed Journal identity without native IO.
    ///
    /// The shared terminal decoder still requires its live Start-native/Root
    /// loan and the SDK's sealed Session borrower before borrowing any row.
    ///
    /// # Errors
    /// Refuses another Journal or an incomplete native custody aggregate.
    pub(crate) fn require_completed_journal_v4(&self, journal: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if !self.journal.matches_journal_v1(journal)
            || self.custody.retained_open_file_count_v1().is_none()
        {
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Compares the same completed HELLO, writer and current socket by borrow.
    ///
    /// # Errors
    /// Refuses a foreign Journal, changed socket or different signed transcript.
    /// The genuine IO lender separately rejoins current Start, Bank and Source.
    pub fn require_completed_provisioning_session_v4(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.journal.matches_journal_v1(journal)
            || !matches_resource_transcript_v2(self.link.role, transcript)
            || transcript.session_binding() != self.binding
            || transcript.protected_context_digest() != self.context
            || self.custody.retained_open_file_count_v1().is_none()
        {
            return Err(CLOSED);
        }
        self.socket.require_same_socket_data_v4(socket).map_err(|_| CLOSED)
    }

    /// Repeats the same passive Session comparison for the completed SDK view.
    ///
    /// # Errors
    /// Refuses the same writer, socket or transcript mismatches as the IO gate.
    pub fn require_same_session_v4(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_provisioning_session_v4(journal, socket, transcript)
    }

    pub(crate) fn require_start_v4(
        &self,
        identity: &Arc<()>,
        parent: OperationId,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !Arc::ptr_eq(&self.link.identity, identity)
            || self.link.parent != parent
            || !Arc::ptr_eq(&self.profile, profile)
        {
            return Err(CLOSED);
        }
        Ok(())
    }
}

/// Keeps both rejected native receipts when a disposition cannot accept them.
#[doc(hidden)]
#[derive(Debug)]
pub struct StartResourceHelloDisposalErrorV4 {
    sent: Option<StorageSeqpacketSendAttemptV1>,
    received: Option<ReceivedRecord>,
}

impl std::fmt::Display for StartResourceHelloDisposalErrorV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the original Start Network HELLO handoff remains closed")
    }
}

impl Error for StartResourceHelloDisposalErrorV4 {}

/// Holds the checked handoff until the actual SDK cold controls are disposed.
#[doc(hidden)]
#[must_use = "complete only after disposing the same SDK cold-opening controls"]
pub struct StartResourceHelloDisposalV4<'phase> {
    owner: &'phase mut StartResourceSessionOpeningOriginalV2,
    completed: bool,
}

impl StartResourceHelloDisposalV4<'_> {
    /// Publishes the already checked association after actual upper disposal.
    ///
    /// No new IO, sampling, allocation, debit or health check occurs here.
    pub fn complete_after_disposal_v4(mut self) {
        self.owner.completion.names_original.settle_positive_once_v1();
        self.owner.completion.completed = self.owner.completion.pending.take();
        self.completed = true;
    }
}

impl Drop for StartResourceHelloDisposalV4<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.completion.first.get_or_insert(CompletionFirst::Abandoned);
            self.owner.first.get_or_insert(First::Completion);
        }
    }
}

impl StartResourceSessionOpeningOriginalV2 {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry)
    fn completed_resident_receiving_demand_v4(
        &self,
        identity: &Arc<()>,
        parent: OperationId,
        native_turn: u64,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        sdk: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let association = self.completed_session_association_v4().ok_or(CLOSED)?;
        association.require_start_v4(identity, parent, profile)?;
        if association.link.native_turn != native_turn {
            return Err(CLOSED);
        }
        let extent = self.completion.final_extent.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.completed_resident_from_extent_v2(extent, sdk, self.representation_prepaid.ok_or(CLOSED)?)
    }

    // The extent is supplied only by the actual retained post17 Stage owner.
    // Both old opening and Catalog6 use this one native/semantic/schema recipe.
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry)
    fn completed_host_catalog_resident_from_extent_v2(&self, identity: &Arc<()>,
        parent: OperationId, native_turn: u64, profile: &Arc<ProductionControllerNormalRootProfileV1>,
        extent: &ProtectedJournalPreopenReplayExtentV1, sdk: ResourceVector,
        catalog_receipt: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.actual_role_v2() != crate::ControllerInitialBrokerSessionRoleV1::Host { return Err(CLOSED); }
        let association = self.completed_session_association_v4().ok_or(CLOSED)?;
        association.require_start_v4(identity, parent, profile)?;
        if association.link.native_turn != native_turn { return Err(CLOSED); }
        let receipt = self.representation_prepaid.ok_or(CLOSED)?.checked_add(catalog_receipt)?;
        self.completed_resident_from_extent_v2(extent, sdk, receipt)
    }

    fn completed_resident_from_extent_v2(&self, extent: &ProtectedJournalPreopenReplayExtentV1,
        sdk: ResourceVector, receipt: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let native = extent.dominant_native_receiving_demand_v1().map_err(ResourceReservationErrorV1::Journal)?;
        let semantic = extent.dominant_semantic_receiving_demand_v1().map_err(ResourceReservationErrorV1::Journal)?;
        let schema = geometry::schema_demand(extent).map_err(|_| CLOSED)?;
        let resident = StartResourceColdCompletionOriginalV4::receiving_demand_v4()?
            .checked_add(ControllerStartResourceEndpointOriginalV2::receiving_demand_v2()?)?
            .checked_add(native)?.checked_add(semantic)?.checked_add(schema)?.checked_add(sdk)?;
        if !resident.is_within(receipt) {
            return Err(CLOSED);
        }
        Ok(resident)
    }

    /// Borrows the association only after native and SDK disposal have completed.
    #[must_use]
    pub fn completed_session_association_v4(&self) -> Option<&StartResourceSessionAssociationV4> {
        if self.first.is_some() || !matches!(self.finish, Some(Ok(()))) {
            return None;
        }
        self.completion.completed.as_ref()
    }
}

impl StartResourceSessionOpeningLoanV2<'_> {
    /// Checks the actual HELLO/native handoff before upper cold-control disposal.
    ///
    /// Both receipts enter this owner before any fallible comparison. Every
    /// independently owed native post and the final clock run after earlier
    /// failures. The returned token holds no Session or facade borrow.
    ///
    /// # Errors
    /// Retains the earliest native, protocol, original deadline or same-owner
    /// failure. Reentry returns an owning error holding both offered receipts.
    pub fn prepare_completed_hello_disposal_v4<'phase>(
        &'phase mut self,
        facade: &ControllerStartResourceSessionCapturedJournalOpenV4,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        checkpoint: &HistoricalSessionCheckpointV1,
        sent: StorageSeqpacketSendAttemptV1,
        broker_hello: ReceivedRecord,
    ) -> Result<StartResourceHelloDisposalV4<'phase>, StartResourceHelloDisposalErrorV4> {
        if self.owner.completion.entered || self.owner.finish.is_some()
            || !matches!(self.owner.fixed, Some(Ok(_)))
        {
            self.owner.first.get_or_insert(First::Reentry);
            return Err(StartResourceHelloDisposalErrorV4 {
                sent: Some(sent), received: Some(broker_hello),
            });
        }
        self.owner.completion.entered = true;
        self.owner.completion.sent = Some(sent);
        self.owner.completion.received = Some(broker_hello);

        let horizon = self.original_horizon_v2();
        let expected_node = self.expected_node_v2();
        self.owner.completion.entry = Some((|| {
            self.require_opened_journal_v2(journal)?;
            journal.ensure_healthy().map_err(|_| CLOSED)?;
            if !facade.was_taken_positive_v4()
                || !facade.receiving_owner_link_v2().is_some_and(|link| link.same_owner_v2(&self.owner_link_v2()))
                || !facade.opening_owner_link_v2().is_some_and(|opening| opening.matches_journal_v1(journal))
                || checkpoint.context().node_id() != expected_node?
            {
                return Err(CLOSED);
            }
            Ok(())
        })());
        self.owner.completion.select(CompletionFirst::Entry,
            matches!(self.owner.completion.entry, Some(Ok(()))));

        let origin = horizon.as_ref().ok().map(|(origin, _)| *origin);
        self.owner.completion.samples[0] = Some(self.owner.completion.clocks[0].observe_once(origin));
        self.owner.completion.times[0] = Some(self.require_completion_time_v4(0, horizon.as_ref().ok().copied()));
        self.owner.completion.select(CompletionFirst::ClockBefore,
            matches!(self.owner.completion.times[0], Some(Ok(()))));

        self.owner.completion.socket = Some(socket.capture_storage_session_origin_retaining_v4(&mut self.owner.completion.origin_cookie));
        self.owner.completion.select(CompletionFirst::Origin,
            matches!(self.owner.completion.socket, Some(Ok(_))));
        self.owner.completion.sent_binding = self.owner.completion.sent.as_ref()
            .map(|sent| sent.require_same_socket_retaining_v4(socket, &mut self.owner.completion.sent_cookie));
        self.owner.completion.select(CompletionFirst::Sent,
            matches!(self.owner.completion.sent_binding, Some(Ok(())))
                && self.owner.completion.sent.as_ref().is_some_and(|sent| sent.is_sent()));
        self.owner.completion.received_binding = self.owner.completion.received.as_ref()
            .map(|record| socket.compare_storage_preparation_received_original_retaining_v4(record, &mut self.owner.completion.received_cookie));
        self.owner.completion.select(CompletionFirst::Received,
            matches!(self.owner.completion.received_binding, Some(Ok(()))));

        self.owner.completion.checkpoint_result = Some(checkpoint.verify_retaining(&mut self.owner.completion.checkpoint));
        self.owner.completion.select(CompletionFirst::Checkpoint,
            matches!(self.owner.completion.checkpoint_result, Some(Ok(()))));
        self.owner.completion.transcript = Some(if self.owner.completion.checkpoint.transcript() == Some(transcript)
            && matches_resource_transcript_v2(self.owner.role, transcript)
            && self.owner.completion.received.as_ref().is_some_and(|record| record.payload() == checkpoint.broker_hello_bytes())
        { Ok(()) } else { Err(CLOSED) });
        self.owner.completion.select(CompletionFirst::Transcript,
            matches!(self.owner.completion.transcript, Some(Ok(()))));

        // These destinations were included before the SDK began any native IO.
        // Their observations remain owed when a receipt or signature fails.
        self.owner.completion.endpoint = Some(match self.owner.endpoint.completed_custody_v2() {
            Some(custody) => custody.validate_current_retaining(&mut self.owner.completion.endpoint_original),
            None => Err(SelfExecutionObservationError),
        });
        self.owner.completion.select(CompletionFirst::Endpoint,
            matches!(self.owner.completion.endpoint, Some(Ok(()))));
        self.owner.completion.names = Some(journal.observe_held_names_post_retaining_v1(
            &mut self.owner.completion.names_original));
        self.owner.completion.select(CompletionFirst::Names,
            matches!(self.owner.completion.names, Some(Ok(()))));

        // The same names post already retained this held-file length. Cold
        // HELLO creates its checkpoint in memory; it does not append a request.
        // Deriving the final extent here performs no additional native sample.
        self.owner.completion.final_extent = Some((|| {
            let (_, _, native_bytes) = self.owner.completion.names_original
                .completed_held_file_boundary_data_v1().ok_or(JournalError::ProtectedBoundary)?;
            let limits = self.owner.extent.as_ref().ok_or(JournalError::ProtectedBoundary)?.limits;
            crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(limits, native_bytes)
        })());
        self.owner.completion.select(CompletionFirst::Names,
            matches!(self.owner.completion.final_extent, Some(Ok(_))));

        self.owner.completion.samples[1] = Some(self.owner.completion.clocks[1].observe_once(origin));
        self.owner.completion.times[1] = Some(self.require_completion_time_v4(1, horizon.ok()));
        self.owner.completion.select(CompletionFirst::ClockAfter,
            matches!(self.owner.completion.times[1], Some(Ok(()))));

        if self.owner.completion.first.is_none() {
            let socket_origin = self.owner.completion.socket.take().and_then(Result::ok);
            let custody = self.owner.endpoint.completed_custody_v2().cloned();
            if let (Some(socket), Some(custody), Some(journal), Some(link)) =
                (socket_origin, custody, self.owner.opening.clone(), self.owner.link.clone())
            {
                self.owner.completion.pending = Some(StartResourceSessionAssociationV4 {
                    link, journal, socket, custody,
                    binding: transcript.session_binding(),
                    context: transcript.protected_context_digest(),
                    profile: Arc::clone(&self.native.profile),
                });
            } else {
                self.owner.completion.select(CompletionFirst::Association, false);
            }
        }
        if self.owner.completion.first.is_some() {
            self.owner.first.get_or_insert(First::Completion);
            return Err(StartResourceHelloDisposalErrorV4 { sent: None, received: None });
        }

        self.owner.finish = Some(Ok(()));
        Ok(StartResourceHelloDisposalV4 { owner: self.owner, completed: false })
    }

    fn require_completion_time_v4(&self, index: usize, horizon: Option<(RawPairedClockSample, u64)>)
        -> Result<(), ResourceReservationErrorV1> {
        let (origin, cutoff) = horizon.ok_or(CLOSED)?;
        let sample = self.owner.completion.samples[index].as_ref()
            .and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        origin.validate_later_sample(sample).map_err(|_| CLOSED)?;
        if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= self.wall_expiry {
            return Err(CLOSED);
        }
        if index == 1 {
            let before = self.owner.completion.samples[0].as_ref()
                .and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
            before.validate_later_sample(sample).map_err(|_| CLOSED)?;
        }
        self.root.require_opening_sample_v4(sample)
    }
}

impl StartResourceSessionOpeningLoanV2<'_> {
    /// Identifies an already entered original failure for first-cause routing.
    ///
    /// This diagnostic performs no IO and supplies no positive permission.
    #[doc(hidden)]
    #[must_use]
    pub fn original_failure_entered_v4(&self) -> bool {
        let selected = self.owner.first.is_some() || self.owner.endpoint.failure().is_some();
        if selected && self.owner.original_native_selected.get().is_none() {
            // The SDK calls this at its actual body refusal, before its own
            // finish and the independent outer C/Root posts. A pure Opening
            // refusal must not later adopt an unrelated native-after cause.
            self.owner.original_native_selected.set(Some(self.native.native_failure_v1().is_some()));
        }
        selected
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Formats the exact SDK-selected Opening refusal before later outer posts.
    ///
    /// The Runtime uses this only after snapshotting the actual SDK's
    /// native_original_failure_selected_v4 at its failed body boundary. The
    /// Opening separately preserves whether the underlying original was already
    /// failed then; a later C-after failure cannot replace an earlier pure or
    /// endpoint refusal. This diagnostic performs no IO or native reentry.
    ///
    /// # Errors
    /// Returns only an error reported by the supplied formatter.
    #[doc(hidden)]
    pub fn fmt_resource_opening_failure_v4(
        &self,
        opening: &StartResourceSessionOpeningOriginalV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if !opening.same_entry_for_diagnostic_v4(self) {
            return std::fmt::Display::fmt(&CLOSED, formatter);
        }
        if opening.original_native_selected.get() == Some(true) {
            if let Some(native) = self.native_state.as_ref()
                .and_then(|state| state.native.as_ref())
                .and_then(|result| result.as_ref().ok())
            {
                if let Some(view) = native.original_v1().profile_failure_view_v1() {
                    return formatter.debug_struct("OriginalStartOpeningProfileFailure")
                        .field("phase", &view.phase())
                        .field("classification", &view.classification())
                        .field("cause", &view.cause())
                        .field("property", &view.property_failure())
                        .finish();
                }
                if let Some(cause) = native.original_v1().failure() {
                    return std::fmt::Display::fmt(cause, formatter);
                }
            }
        }
        match opening.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Network opening has no selected failure"),
        }
    }
}

impl StartResourceSessionOpeningOriginalV2 {
    fn same_entry_for_diagnostic_v4(&self, entry: &AcceptedStartEntryOriginalV1) -> bool {
        self.link.as_ref().is_some_and(|link| {
            entry.identity.as_ref().is_ok_and(|identity| Arc::ptr_eq(identity, &link.identity))
                && entry.body.plan_v1().is_ok_and(|plan| plan.operation_id() == link.parent)
                && entry.native_state.as_ref().is_some_and(|state| state.native_turn == link.native_turn)
        })
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Borrows the actual SDK-selected Opening cause from the same original.
    ///
    /// This is the basic Error source companion of fmt_resource_opening_failure_v4.
    /// The guarded richer profile view remains available only while formatting.
    /// No native check or late failure selection occurs here.
    #[doc(hidden)]
    #[must_use]
    pub fn resource_opening_failure_with_original_v4<'held>(
        &'held self,
        opening: &'held StartResourceSessionOpeningOriginalV2,
    ) -> Option<&'held (dyn Error + 'static)> {
        if !opening.same_entry_for_diagnostic_v4(self) {
            return Some(&CLOSED);
        }
        if opening.original_native_selected.get() == Some(true) {
            if let Some(cause) = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1)
            {
                return Some(cause);
            }
        }
        opening.failure()
    }
}
