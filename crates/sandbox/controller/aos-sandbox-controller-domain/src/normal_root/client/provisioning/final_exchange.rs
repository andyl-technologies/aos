//! Retains the final same-socket Apply exchange and every independently owed post.
//!
//! This private native leaf cannot admit a public terminal transition. Its only
//! caller must hold the actual Completing/Applied original and the separately
//! prearmed C/Source terminal destination. Decoded 160-byte DATA never constructs
//! that original, retires the client, or renews its original cutoff.

use std::os::fd::AsFd as _;

use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::{
    CLOSED_BYTES_V1, FINAL_BYTES_V1, StorageApplyClosedDataV1, StorageApplyFinalDataV1,
};

use super::*;

#[derive(Clone, Copy)]
enum FirstV1 {
    Entry, Subject, Geometry, Funding, BeforeClock, BeforeTime, BeforePeer, Send, Shutdown,
    Prepare, Chunk, Decode, Eof, Returned, AfterPeer, AfterClock, AfterTime, Settlement, Terminal, Reentry,
}

#[derive(Default)]
pub(super) struct FinalExchangeStateV1 {
    entered: bool,
    subject: Option<Result<(), ResourceReservationErrorV1>>,
    subject_original: bool,
    association: Option<crate::CreateStoppedCompletionAssociationV1>,
    completion_borrowed: bool,
    entry: Option<Result<(), ApplyRootDataErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    authority_expiry: Option<i64>,
    returned: Option<Result<(), ResourceReservationErrorV1>>,
    terminal: Option<Result<(), ResourceReservationErrorV1>>,
    terminal_fence: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Box<FinalNativeOriginalV1>>,
    refusal: Option<Box<current_turn::RefusalOriginalV1>>,
    first: Option<FirstV1>,
    reentry: Option<Closed>,
}

struct FinalNativeOriginalV1 {
    frame: [u8; FINAL_BYTES_V1],
    frame_digest: [u8; 32],
    authority_expiry: i64,
    sender: FixedDeadlineStreamIoV1<FINAL_BYTES_V1>,
    sent: Option<Result<(), HistoryErrorV1>>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    received: RetainedSubjectStreamReadV1,
    prepared: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    decoded: Option<Result<StorageApplyClosedDataV1, ApplyRootDataErrorV1>>,
    eof_bytes: [u8; 1],
    eof: FixedDeadlineStreamIoV1<1>,
    ended: Option<Result<(), HistoryErrorV1>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), ApplyRootDataErrorV1>>,
    before_peer: PeerSampleV1,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after_peer: PeerSampleV1,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), ApplyRootDataErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    after_entered: bool,
    wire_complete: bool,
}


/// Exclusively borrows the same fully acknowledged Root client for completion.
///
/// This lender retains an opaque clone of the actual prepaid destination, not
/// a receipt or acknowledgement DATA adopter. It grants only the specific
/// post-ACK Source/public-C destination already armed before the final wire.
#[doc(hidden)]
#[must_use = "retain the same client until the specific Source and public C terminal posts finish"]
pub struct RootStorageApplyCompletionOriginalV1<'flight> {
    client: &'flight mut RootStorageApplyClientOriginalV1,
    association: crate::CreateStoppedCompletionAssociationV1,
}

impl RootStorageApplyCompletionOriginalV1<'_> {
    /// Closes this exact client only after actual Source/C terminal disposition.
    ///
    /// This final projection performs no new IO, clock capture, financial
    /// admission or turn. A refused terminal association fences the same C
    /// through its actual closed terminal owner; durable rows stay unchanged.
    ///
    /// # Errors
    /// Refuses another terminal owner, incomplete native/time disposition or a
    /// changed original C association. The actual validation/fence results stay
    /// in the client and public healthy completion remains unavailable.
    #[doc(hidden)]
    pub fn finish_create_stopped_once_v1(self,
        terminal: &crate::CreateStoppedTerminalOriginalV1<'_>,
        original: &crate::CreateProvisioningOriginalsV1, controller: &mut Journal,
    ) -> Result<(), Closed> {
        if self.client.final_exchange.terminal.is_some() {
            let _ = self.client.begin_final_reentry_v1();
            return Err(self.client.closed);
        }
        self.client.final_exchange.terminal = Some(terminal.require_same_complete_v1(
            &self.association, original, controller));
        if !matches!(self.client.final_exchange.terminal, Some(Ok(()))) {
            self.client.final_exchange.first.get_or_insert(FirstV1::Terminal);
            self.client.final_exchange.terminal_fence = Some(terminal.fence_controller_on_refusal_v1(controller));
            return Err(self.client.closed);
        }
        if self.client.final_exchange.first.is_some() { return Err(self.client.closed); }
        self.client.terminal_complete = true;
        Ok(())
    }

    pub(crate) fn require_attempt_v1(&self,
        association: &crate::CreateStoppedCompletionAssociationV1,
        original: &crate::CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = &self.client.final_exchange;
        let native = state.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.association.same_original_v1(association)
            || state.association.as_ref().is_none_or(|same| !same.same_original_v1(association))
            || state.first.is_some() || !native.wire_complete || native.after_time.as_ref().is_none_or(|v| v.is_err())
            || !matches!(state.returned, Some(Ok(())))
            || association.parent_operation_v1() != self.client.parent
            || association.native_turn_v1() != self.client.native_turn
            || original.native_turn_v1() != self.client.native_turn
            || !original.belongs_to_operation_v1(self.client.parent)
            || !original.has_same_profile_v1(&self.client.profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.require_completed_original_v1(controller)
    }

    pub(crate) fn actual_after_clock_v1(&self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        let native = self.client.final_exchange.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !native.wire_complete || self.client.final_exchange.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.after_sample.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        let native = self.client.final_exchange.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !native.wire_complete || self.client.final_exchange.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let closed = native.decoded.as_ref().and_then(|v| v.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(self.client.cutoff.min(closed.cutoff_ns))
    }

    pub(crate) fn acknowledgement_commitment_v1(&self) -> Result<aos_sandbox_model::ObjectDigest, ResourceReservationErrorV1> {
        use sha2::Digest as _;
        let native = self.client.final_exchange.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !native.wire_complete || self.client.final_exchange.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(aos_sandbox_model::ObjectDigest::from_bytes(sha2::Sha256::digest(native.received.bytes()).into()))
    }
}

impl RootStorageApplyClientOriginalV1 {
    /// Checks historical completed Create custody before a distinct Start entry.
    ///
    /// This read-only gate lends no current Create authority, deadline, payer,
    /// Host permission or new original. The separately accepted Start must pay
    /// its own native entry and bind its own original admission horizon.
    ///
    /// # Errors
    /// Refuses an unfinished/failed client, another actual terminal association
    /// or a changed native Controller baseline/profile. Later legitimate C
    /// rows are checked by the genuine historical terminal owner; the old
    /// immediate-close NEXT and old Create TTL are deliberately not reused.
    #[doc(hidden)]
    pub fn require_completed_create_stopped_original_v1(&self,
        terminal: &crate::CreateStoppedTerminalOriginalV1<'_>,
        original: &crate::CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), Closed> {
        let association = self.completed_terminal_association_v1(original)?;
        terminal.require_historical_same_complete_v1(association, original, controller)
            .map_err(|_| self.closed)
    }

    /// Checks stored original custody before paying a new Start observation.
    ///
    /// This is a mechanical predecessor only. It performs no Source graph
    /// replay, clock capture, native IO, deadline renewal or financial turn.
    /// Fresh Start must pay and finish its own full current Source/C semantic
    /// fold before authorization; this distinct type cannot replace that proof.
    ///
    /// # Errors
    /// Refuses an incomplete original client, foreign actual native association,
    /// changed C/profile affinity or unhealthy current Controller custody.
    #[doc(hidden)]
    pub fn require_completed_create_stopped_custody_v1(&self,
        terminal: &crate::CreateStoppedTerminalCustodyV1<'_>,
        original: &crate::CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), Closed> {
        let association = self.completed_terminal_association_v1(original)?;
        terminal.require_same_complete_v1(association, original, controller)
            .map_err(|_| self.closed)
    }

    // The semantic historical and mechanical custody checks share exactly the
    // same stored client/native completion gate. Neither predicate creates it.
    fn completed_terminal_association_v1(&self,
        original: &crate::CreateProvisioningOriginalsV1,
    ) -> Result<&crate::CreateStoppedCompletionAssociationV1, Closed> {
        let state = &self.final_exchange;
        if !self.terminal_complete || self.first.is_some() || self.publication.failure().is_some()
            || state.first.is_some() || !matches!(state.terminal, Some(Ok(())))
            || !matches!(state.returned, Some(Ok(())))
            || state.native.as_ref().is_none_or(|native| !native.wire_complete)
            || !original.belongs_to_operation_v1(self.parent)
            || !original.has_same_profile_v1(&self.profile)
            || original.native_turn_v1() != self.native_turn {
            return Err(self.closed);
        }
        state.association.as_ref().ok_or(self.closed)
    }

    /// Sends the genuine pre-ACK receipt only after its terminal destination is paid.
    ///
    /// # Errors
    /// Retains actual pre-ACK/currentness, funding, strict wire or temporal
    /// refusal. The caller still returns the C23 turn and invokes the after port.
    #[doc(hidden)]
    pub fn begin_create_stopped_final_once_v1(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
        pre_ack: &crate::CreateStoppedPreAckOriginalV1<'_>,
        action: &crate::cold_launch_publication::OriginalPublicationActionV1,
    ) -> Result<(), Closed> {
        if self.final_exchange.entered { return self.begin_final_reentry_v1(); }
        self.final_exchange.subject = Some(pre_ack.require_current_v1(loan, action, controller));
        if !matches!(self.final_exchange.subject, Some(Ok(()))) {
            self.final_exchange.entered = true;
            self.final_exchange.first = Some(FirstV1::Subject);
            return Err(self.closed);
        }
        let association = pre_ack.association_v1().map_err(|cause| {
            self.final_exchange.subject = Some(Err(cause));
            self.final_exchange.entered = true;
            self.final_exchange.first = Some(FirstV1::Subject);
            self.closed
        })?;
        let frame = (|| {
            let query = *positive(&self.state.query)?;
            let reply = StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())?;
            let admitted = StorageApplyAdmissionDataV1::decode_v1(reply.admission)?;
            let c = association.controller_native_v1();
            let source = association.source_native_v1();
            StorageApplyFinalDataV1 { root_nonce: admitted.root_nonce,
                controller_nonce: query.controller_nonce, query_digest: query.digest_v1()?,
                reply_digest: reply.digest_v1()?, controller_native: &c,
                source_native: &source, lifecycle_receipt: association.receipt_bytes_v1(),
            }.encode_v1(association.lane_v1())
        })();
        let frame = match frame {
            Ok(frame) => frame,
            Err(cause) => {
                self.final_exchange.entered = true;
                self.final_exchange.entry = Some(Err(cause));
                self.final_exchange.first = Some(FirstV1::Entry);
                return Err(self.closed);
            }
        };
        let complete = pre_ack.terminal_destination_receiving_demand_v1().map_err(|cause| {
            self.final_exchange.subject = Some(Err(cause));
            self.final_exchange.entered = true;
            self.final_exchange.first = Some(FirstV1::Subject);
            self.closed
        })?;
        let lane = association.lane_v1();
        self.final_exchange.association = Some(association);
        self.begin_final_bytes_once_v1(loan, controller, frame, lane, action, complete)
    }

    fn begin_final_reentry_v1(&mut self) -> Result<(), Closed> {
        self.final_exchange.reentry.get_or_insert(self.closed);
        self.final_exchange.first.get_or_insert(FirstV1::Reentry);
        Err(self.closed)
    }

    /// Observes the inherited native Root spare after a real failed final prearm.
    ///
    /// The preceding positive Root purpose paid this destination and its traffic
    /// before the attempted C23 debit. A failed payer never gates these posts.
    ///
    /// # Errors
    /// Always refuses, retaining the attempted association and negative posts.
    #[doc(hidden)]
    pub fn observe_create_stopped_final_entry_refusal_after_original_once_v1(&mut self,
        attempt: &crate::CreateStoppedCompletionAttemptV1,
        original: Option<&crate::CreateProvisioningOriginalsV1>, controller: &Journal,
    ) -> Result<(), Closed> {
        if self.final_exchange.entered { return self.begin_final_reentry_v1(); }
        let actual_next = original.filter(|original|
            original.belongs_to_operation_v1(self.parent)
                && original.has_same_profile_v1(&self.profile)
                && original.native_turn_v1() > self.native_turn);
        if !attempt.final_entry_started_v1() && actual_next.is_none() { return Err(self.closed); }
        self.final_exchange.subject_original = !attempt.final_entry_started_v1()
            && actual_next.is_some_and(|original| original.failure().is_some());
        self.final_exchange.entered = true;
        self.final_exchange.subject = Some(Err(ResourceReservationErrorV1::Conflict));
        self.final_exchange.first = Some(FirstV1::Subject);
        if let (Some(parent), Some(turn), Some(original)) = (
            attempt.final_parent_operation_v1(), attempt.final_native_turn_v1(), original,
        ) {
            if parent == self.parent && original.belongs_to_operation_v1(self.parent)
                && original.has_same_profile_v1(&self.profile) && original.native_turn_v1() == turn {
                self.native_turn = turn;
            }
        }
        if let Some(actual_next) = actual_next { self.native_turn = actual_next.native_turn_v1(); }
        self.finish_final_after_original_once_v1(original, controller)
    }

    /// Runs the independently prepaid Root/paired posts after real C23 return.
    ///
    /// # Errors
    /// Refuses an unfinished or changed C23 original, failed wire or any post.
    #[doc(hidden)]
    pub fn finish_create_stopped_final_after_original_once_v1(&mut self,
        original: Option<&crate::CreateProvisioningOriginalsV1>, controller: &Journal,
    ) -> Result<(), Closed> {
        self.finish_final_after_original_once_v1(original, controller)
    }

    /// Lends only the completed strict160/EOF/all-posts original destination.
    ///
    /// # Errors
    /// Refuses another prearmed attempt, failed current association or any
    /// incomplete wire/post. Public terminal completion remains a later step.
    #[doc(hidden)]
    pub fn borrow_create_stopped_completion_v1<'flight>(&'flight mut self,
        pre_ack: &crate::CreateStoppedPreAckOriginalV1<'_>,
        original: &crate::CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<RootStorageApplyCompletionOriginalV1<'flight>, Closed> {
        if self.final_exchange.completion_borrowed {
            let _ = self.begin_final_reentry_v1();
            return Err(self.closed);
        }
        self.final_exchange.completion_borrowed = true;
        let association = pre_ack.association_v1().map_err(|_| self.closed)?;
        let closed = self.closed;
        let completed = RootStorageApplyCompletionOriginalV1 { client: self, association };
        completed.require_attempt_v1(&completed.association, original, controller).map_err(|_| closed)?;
        Ok(completed)
    }
}

impl FinalExchangeStateV1 {
    pub(super) const fn started_v1(&self) -> bool { self.entered }
}

impl FinalNativeOriginalV1 {
    fn new(frame: [u8; FINAL_BYTES_V1], frame_digest: [u8; 32], authority_expiry: i64) -> Self {
        Self {
            frame, frame_digest, authority_expiry, sender: Default::default(), sent: None, shutdown: None,
            received: Default::default(), prepared: None, chunk: None, decoded: None,
            eof_bytes: [0; 1], eof: Default::default(), ended: None,
            before_clock: Default::default(), before_sample: None, before_time: None,
            before_peer: PeerSampleV1::new(), before: None,
            after_peer: PeerSampleV1::new(), after: None,
            after_clock: Default::default(), after_sample: None, after_time: None,
            settlement: None, after_entered: false, wire_complete: false,
        }
    }
}

impl RootStorageApplyClientOriginalV1 {
    // This private mechanical entry is not the lifecycle admission port. The
    // actual Completing producer and prearmed terminal destination must be
    // checked by its sole concrete caller before these bytes are assembled.
    pub(super) fn begin_final_bytes_once_v1(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
        frame: [u8; FINAL_BYTES_V1], lane: [u8; 16],
        action: &crate::cold_launch_publication::OriginalPublicationActionV1,
        complete_residents_and_terminal_destination: ResourceVector,
    ) -> Result<(), Closed> {
        if self.final_exchange.entered {
            self.final_exchange.reentry.get_or_insert(self.closed);
            self.final_exchange.first.get_or_insert(FirstV1::Reentry);
            return Err(self.closed);
        }
        self.final_exchange.entered = true;
        self.final_exchange.entry = Some((|| {
            if !self.admitted || self.first.is_some() || self.stable.is_none()
                || self.publication.failure().is_some()
                || loan.parent_operation_v1() != self.parent
                || !std::ptr::eq(loan.profile_v1(), self.profile.as_ref())
                || loan.native_turn_v1() <= self.native_turn {
                return Err(ApplyRootDataErrorV1::Malformed);
            }
            let value = StorageApplyFinalDataV1::decode_v1(&frame, lane)?;
            let query = *positive(&self.state.query)?;
            let reply = StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())?;
            let admission = StorageApplyAdmissionDataV1::decode_v1(reply.admission)?;
            if value.root_nonce != admission.root_nonce
                || value.controller_nonce != query.controller_nonce
                || value.query_digest != query.digest_v1()?
                || value.reply_digest != reply.digest_v1()?
                || action.parent_operation_v1() != self.parent
                || action.root_admission_commitment_v1() != reply.digest_v1()? {
                return Err(ApplyRootDataErrorV1::Malformed);
            }
            self.final_exchange.authority_expiry = Some(
                admission.policy_expires_seconds.min(admission.lease_expires_seconds)
                    .min(action.storage_apply_plan_expires_seconds_v1()
                        .map_err(|_| ApplyRootDataErrorV1::Malformed)?));
            Ok(())
        })());
        if !matches!(self.final_exchange.entry, Some(Ok(()))) {
            self.final_exchange.first = Some(FirstV1::Entry);
            return Err(self.closed);
        }

        // The actual prearm base already contains this client's old resident
        // plane. Remove that exact cost term before its completed native owner
        // is retired, then join the new same-client/final plane once below.
        // This is representation accounting only; spent traffic and ledger
        // highwater remain untouched on the same C original.
        self.final_exchange.geometry = Some(self.resident_receiving_demand_v1()
            .and_then(|prior| complete_residents_and_terminal_destination.checked_sub(prior)
                .map_err(ResourceReservationErrorV1::from)));
        let external = match self.final_exchange.geometry.as_ref() {
            Some(Ok(external)) => *external,
            _ => { self.final_exchange.first = Some(FirstV1::Geometry); return Err(self.closed); }
        };
        self.native_turn = loan.native_turn_v1();
        if self.retire_completed_turn_for_final_once_v1().is_err() {
            self.final_exchange.entry = Some(Err(ApplyRootDataErrorV1::Malformed));
            self.final_exchange.first = Some(FirstV1::Entry);
            return Err(self.closed);
        }

        // This complete plane includes still-resident Action/Session/Source
        // owners and the actual bounded post-ACK destination. The same ledger
        // keeps prior spent traffic and highwater; this establishes no refund.
        self.complete = external;
        self.final_exchange.funding = Some((|| {
            let resident = self.resident_demand_v1()?;
            let complete = self.complete.checked_add(resident)?
                .checked_add(self.final_exchange_receiving_demand_v1()?)?;
            let observations = self.observations.checked_add(2)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let traffic = Self::peer_traffic_v1(observations)?;
            let wire = self.wire.checked_add((FINAL_BYTES_V1 + CLOSED_BYTES_V1 + 1) as u64)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let output = self.output.checked_add(FINAL_BYTES_V1 as u64)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = complete.checked_add(traffic)?.checked_add(ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::NetworkBytes, wire)
                .with(aos_sandbox_model::ResourceDimension::OutputBytes, output))?;
            let result = loan.require_complete_v1(controller, complete);
            if result.is_err() && loan.failure_v1().is_some() {
                self.final_exchange.funding_original = true;
            }
            result?;
            self.complete = self.complete.checked_add(resident)?
                .checked_add(self.final_exchange_receiving_demand_v1()?)?;
            self.observations = observations;
            self.wire = wire;
            self.output = output;
            Ok(())
        })());
        if !matches!(self.final_exchange.funding, Some(Ok(()))) {
            self.final_exchange.first = Some(FirstV1::Funding);
            return Err(self.closed);
        }
        let digest = match StorageApplyFinalDataV1::decode_v1(&frame, lane)
            .and_then(|value| value.digest_v1(lane)) {
            Ok(digest) => digest,
            Err(cause) => {
                self.final_exchange.entry = Some(Err(cause));
                self.final_exchange.first = Some(FirstV1::Entry);
                return Err(self.closed);
            }
        };
        let expiry = self.final_exchange.authority_expiry.ok_or(self.closed)?;
        self.final_exchange.native = Some(Box::new(FinalNativeOriginalV1::new(frame, digest, expiry)));
        let primary = self.run_final_wire_once_v1(loan, controller);
        if let Err(first) = primary { self.final_exchange.first = Some(first); }
        if self.final_exchange.first.is_none() { Ok(()) } else { Err(self.closed) }
    }

    // The public purpose-closed entry calls this unconditionally after ending
    // its short loan and running the real C23 native Producer-after. A failed
    // original never gates either separately prepaid Root/paired destination.
    pub(super) fn finish_final_after_original_once_v1(&mut self,
        receiving: Option<&crate::CreateProvisioningOriginalsV1>, controller: &Journal,
    ) -> Result<(), Closed> {
        if !self.final_exchange.entered || self.final_exchange.returned.is_some() {
            self.final_exchange.reentry.get_or_insert(self.closed);
            self.final_exchange.first.get_or_insert(FirstV1::Reentry);
            return Err(self.closed);
        }
        self.final_exchange.returned = Some((|| {
            let receiving = receiving.ok_or(ResourceReservationErrorV1::Conflict)?;
            if !receiving.belongs_to_operation_v1(self.parent)
                || !receiving.has_same_profile_v1(&self.profile)
                || receiving.native_turn_v1() != self.native_turn {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            receiving.require_completed_original_v1(controller)
        })());
        if self.final_exchange.first.is_none()
            && !matches!(self.final_exchange.returned, Some(Ok(()))) {
            self.final_exchange.first = Some(FirstV1::Returned);
        }
        self.finish_final_posts_once_v1();
        if self.final_exchange.first.is_none()
            && self.final_exchange.native.as_ref().is_some_and(|native| native.wire_complete) {
            Ok(())
        } else { Err(self.closed) }
    }

    fn run_final_wire_once_v1(&mut self,
        loan: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), FirstV1> {
        let native = self.final_exchange.native.as_mut().ok_or(FirstV1::Entry)?;
        native.before_sample = Some(native.before_clock.observe_once(Some(self.origin)));
        let before = native.before_sample.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FirstV1::BeforeClock)?;
        native.before_time = Some(require_final_sample_v1(self.origin, self.cutoff, native.authority_expiry, before));
        if !matches!(native.before_time, Some(Ok(()))) { return Err(FirstV1::BeforeTime); }
        native.before = Some(native.before_peer.observe_with_cutoff_once_v1(
            &self.profile, self.state.connection.stream().map_err(|_| FirstV1::BeforePeer)?,
            self.stable.as_ref(), None, false, self.cutoff));
        if !matches!(native.before, Some(Ok(()))) { return Err(FirstV1::BeforePeer); }
        native.sent = Some(native.sender.run_once(
            self.state.connection.stream_mut().map_err(|_| FirstV1::Send)?,
            &mut native.frame, self.cutoff, DeadlineStreamDirectionV1::Write));
        if !matches!(native.sent, Some(Ok(()))) { return Err(FirstV1::Send); }
        native.shutdown = Some(rustix::net::shutdown(
            self.state.connection.stream().map_err(|_| FirstV1::Shutdown)?.as_fd(),
            rustix::net::Shutdown::Write));
        if !matches!(native.shutdown, Some(Ok(()))) { return Err(FirstV1::Shutdown); }
        native.prepared = Some(native.received.prepare_exact_once(CLOSED_BYTES_V1));
        if !matches!(native.prepared, Some(Ok(()))) { return Err(FirstV1::Prepare); }

        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| FirstV1::Prepare)?;
        while !self.final_exchange.native.as_ref().is_some_and(|native| native.received.completed_exact()) {
            // The independent whole after is already paid. A refused reached
            // chunk debit cannot suppress it or allocate its native capsule.
            if self.charge(loan, controller, 1, 0, 0).is_err() {
                self.final_exchange.funding_original |= self.funding_original;
                return Err(FirstV1::Funding);
            }
            let native = self.final_exchange.native.as_mut().ok_or(FirstV1::Entry)?;
            native.chunk = Some(Box::new(RootStrictChunkOriginalV1::default()));
            let chunk = native.chunk.as_mut().ok_or(FirstV1::Chunk)?;
            if chunk.receive_once(&mut native.received,
                self.state.connection.stream_mut().map_err(|_| FirstV1::Chunk)?,
                &native.before_peer, &self.profile, &geometry, self.cutoff).is_err() {
                return Err(FirstV1::Chunk);
            }
            drop(native.chunk.take());
        }
        let native = self.final_exchange.native.as_mut().ok_or(FirstV1::Entry)?;
        native.decoded = Some(StorageApplyClosedDataV1::decode_v1(native.received.bytes()));
        if !matches!(native.decoded, Some(Ok(_))) { return Err(FirstV1::Decode); }
        native.ended = Some(native.eof.run_once(
            self.state.connection.stream_mut().map_err(|_| FirstV1::Eof)?,
            &mut native.eof_bytes, self.cutoff, DeadlineStreamDirectionV1::Eof));
        if !matches!(native.ended, Some(Ok(()))) { return Err(FirstV1::Eof); }
        Ok(())
    }

    fn finish_final_posts_once_v1(&mut self) {
        let Some(native) = self.final_exchange.native.as_mut() else {
            if self.final_exchange.refusal.is_none() {
                self.final_exchange.refusal = self.next_refusal.take();
                if let (Some(refusal), Ok(stream)) = (
                    self.final_exchange.refusal.as_mut(), self.state.connection.stream()) {
                    refusal.observe_once(&self.profile, stream, self.stable.as_ref(), self.origin, self.cutoff);
                }
            }
            return;
        };
        if native.after_entered { return; }
        native.after_entered = true;
        native.after = Some(match self.state.connection.stream() {
            Ok(stream) => native.after_peer.observe_with_cutoff_once_v1(
                &self.profile, stream, self.stable.as_ref(), None, true, self.cutoff),
            Err(_) => Err(NormalRootStartupErrorV1::Service),
        });
        native.after_sample = Some(native.after_clock.observe_once(Some(self.origin)));
        if self.final_exchange.first.is_none() && !matches!(native.after, Some(Ok(()))) {
            self.final_exchange.first = Some(FirstV1::AfterPeer);
        }
        if self.final_exchange.first.is_none() && !matches!(native.after_sample, Some(Ok(_))) {
            self.final_exchange.first = Some(FirstV1::AfterClock);
        }
        native.after_time = Some((|| {
            let before = native.before_sample.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ApplyRootDataErrorV1::Malformed)?;
            let after = native.after_sample.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ApplyRootDataErrorV1::Malformed)?;
            let closed = native.decoded.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(ApplyRootDataErrorV1::Malformed)?;
            let query = *positive(&self.state.query)?;
            let reply = StorageApplyReplyDataV1::decode_v1(self.state.received.bytes())?;
            let admission = StorageApplyAdmissionDataV1::decode_v1(reply.admission)?;
            require_final_relation_v1(self.origin, self.cutoff, native.authority_expiry, before, after, query,
                admission, reply.digest_v1()?, native.frame_digest, closed)
        })());
        if !matches!(native.after_time, Some(Ok(()))) && self.final_exchange.first.is_none() {
            self.final_exchange.first = Some(FirstV1::AfterTime);
        }
        if self.final_exchange.first.is_some() { return; }
        native.settlement = Some(native.before_peer.settle_positive_once()
            .and_then(|_| native.after_peer.settle_positive_once()));
        if !matches!(native.settlement, Some(Ok(()))) {
            self.final_exchange.first = Some(FirstV1::Settlement);
            return;
        }
        native.wire_complete = true;
    }

    pub(super) fn final_failure_with_original_v1<'cause>(&'cause self,
        receiving: &'cause crate::CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if (matches!(self.final_exchange.first, Some(FirstV1::Subject))
                && self.final_exchange.subject_original
            || matches!(self.final_exchange.first, Some(FirstV1::Funding))
            && self.final_exchange.funding_original
            || matches!(self.final_exchange.first, Some(FirstV1::Returned)))
            && receiving.belongs_to_operation_v1(self.parent)
            && receiving.has_same_profile_v1(&self.profile) {
            receiving.failure().or_else(|| self.final_failure_v1())
        } else { self.final_failure_v1() }
    }

    pub(super) fn final_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let state = &self.final_exchange;
        let native = state.native.as_deref();
        let selected = match state.first? {
            FirstV1::Entry => cause(&state.entry),
            FirstV1::Subject => cause(&state.subject),
            FirstV1::Geometry => cause(&state.geometry),
            FirstV1::Funding => cause(&self.admission).or_else(|| cause(&state.funding)),
            FirstV1::BeforeClock => native.and_then(|value|
                value.before_clock.failure().or_else(|| cause(&value.before_sample))),
            FirstV1::BeforeTime => native.and_then(|value| cause(&value.before_time)),
            FirstV1::BeforePeer => native.and_then(|value|
                value.before_peer.failure().or_else(|| cause(&value.before))),
            FirstV1::Send => native.and_then(|value|
                value.sender.failure().or_else(|| cause(&value.sent))),
            FirstV1::Shutdown => native.and_then(|value| cause(&value.shutdown)),
            FirstV1::Prepare => native.and_then(|value|
                value.received.failure().or_else(|| cause(&value.prepared))),
            FirstV1::Chunk => native.and_then(|value|
                value.chunk.as_ref().and_then(|chunk| chunk.failure(&value.received))
                    .or_else(|| value.received.failure())),
            FirstV1::Decode => native.and_then(|value| cause(&value.decoded)),
            FirstV1::Eof => native.and_then(|value|
                value.eof.failure().or_else(|| cause(&value.ended))),
            FirstV1::Returned => cause(&state.returned),
            FirstV1::AfterPeer => native.and_then(|value|
                value.after_peer.failure().or_else(|| cause(&value.after))),
            FirstV1::AfterClock => native.and_then(|value|
                value.after_clock.failure().or_else(|| cause(&value.after_sample))),
            FirstV1::AfterTime => native.and_then(|value| cause(&value.after_time)),
            FirstV1::Settlement => native.and_then(|value|
                value.before_peer.failure().or_else(|| value.after_peer.failure())
                    .or_else(|| cause(&value.settlement))),
            FirstV1::Terminal => cause(&state.terminal).or_else(|| cause(&state.terminal_fence)),
            FirstV1::Reentry => state.reentry.as_ref().map(|cause| cause as _),
        };
        selected.or(Some(&self.closed as _))
    }

    pub(super) fn final_property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let marker = self.final_failure_v1()?
            .downcast_ref::<aos_systemd_client::FixedPid1PropertyErrorV1>()?;
        let native = self.final_exchange.native.as_deref()?;
        if matches!(self.final_exchange.first, Some(FirstV1::Chunk)) {
            return native.chunk.as_ref()?.property_failure_view_v1();
        }
        for sample in [&native.before_peer, &native.after_peer] {
            if super::diagnostics::same_property_marker_v1(marker, sample.failure()) {
                return sample.property_failure_view_v1();
            }
        }
        None
    }

    pub(super) fn final_exchange_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        use aos_sandbox_model::ResourceDimension as D;
        let bad = || ResourceReservationErrorV1::Conflict;
        let peer = CreateStorageRootPeerReceivingOriginalsV1::provisioning_native_peak_v1(&self.profile)
            .ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw_bytes, raw_files) = geometry.receive_obligations_v1();
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(bad)?;
        let readiness = crate::policy_compiler::RootSubjectReadinessV1::receiving_construction_bytes_v1()
            .ok_or_else(bad)?;
        // The exact producer/encoder frame temporaries coexist with the
        // caller's admitted native constructor and its heap destination.
        let bytes = std::mem::size_of::<FinalNativeOriginalV1>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(FINAL_BYTES_V1.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootStorageApplyCompletionOriginalV1<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootStrictChunkOriginalV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(CLOSED_BYTES_V1.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(raw_bytes.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(clocks))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(readiness)).ok_or_else(bad)?;
        let files = raw_files.checked_add(2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .and_then(|files| u64::try_from(files).ok()).ok_or_else(bad)?;
        Ok(peer.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files)
            .with(D::Pids, u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1())
                .map_err(|_| bad())?))?)
    }
}

fn require_final_sample_v1(origin: RawPairedClockSample, cutoff: u64, expires: i64,
    sample: RawPairedClockSample,
) -> Result<(), ApplyRootDataErrorV1> {
    origin.validate_later_sample(sample).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= expires {
        return Err(ApplyRootDataErrorV1::Malformed);
    }
    Ok(())
}

fn require_final_relation_v1(origin: RawPairedClockSample, cutoff: u64, expires: i64,
    before: RawPairedClockSample, after: RawPairedClockSample,
    query: StorageApplyQueryDataV1, admission: StorageApplyAdmissionDataV1,
    reply_digest: [u8; 32], final_digest: [u8; 32], closed: StorageApplyClosedDataV1,
) -> Result<(), ApplyRootDataErrorV1> {
    require_final_sample_v1(origin, cutoff, expires, before)?;
    before.validate_later_sample(after).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    require_final_sample_v1(origin, cutoff, expires, after)?;
    let observed = RawPairedClockSample::new_untrusted(origin.provenance(), origin.host_boot_id(),
        closed.observed_wall_seconds, closed.observed_boottime_ns)
        .map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    before.validate_later_sample(observed).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    observed.validate_later_sample(after).map_err(|_| ApplyRootDataErrorV1::Malformed)?;
    // Root can only narrow its own original declared bound. The client's
    // independent conservative translation may be stricter still; retain that
    // actual minimum without requiring Root to echo an undisclosed local value.
    let bound = cutoff.min(closed.cutoff_ns);
    if closed.root_nonce != admission.root_nonce || closed.controller_nonce != query.controller_nonce
        || closed.query_digest != query.digest_v1()? || closed.reply_digest != reply_digest
        || closed.final_digest != final_digest || closed.cutoff_ns > admission.cutoff_ns
        || after.boottime_nanoseconds() >= bound {
        return Err(ApplyRootDataErrorV1::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall: i64, seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16], wall, seconds * 1_000_000_000).unwrap()
    }

    fn subjects() -> (StorageApplyQueryDataV1, StorageApplyAdmissionDataV1, StorageApplyClosedDataV1) {
        let query = StorageApplyQueryDataV1 {
            controller_nonce: [3; 16], original_boot: [2; 16],
            original_boottime_ns: 10_000_000_000, original_cutoff_ns: 60_000_000_000,
            subject_bytes: 100, subject_digest: [4; 32], controller_next: 7, controller_end: 900,
        };
        let admission = StorageApplyAdmissionDataV1 {
            controller_nonce: query.controller_nonce, root_nonce: [5; 16], query_digest: query.digest_v1().unwrap(),
            original_boot: query.original_boot, original_boottime_ns: query.original_boottime_ns,
            original_cutoff_ns: query.original_cutoff_ns,
            observed_wall_seconds: 101, observed_boottime_ns: 11_000_000_000,
            cutoff_ns: 55_000_000_000, policy_expires_seconds: 170,
            lease_expires_seconds: 180, preparation_expires_boottime_ns: 58_000_000_000,
        };
        let closed = StorageApplyClosedDataV1 {
            root_nonce: admission.root_nonce, controller_nonce: query.controller_nonce,
            query_digest: query.digest_v1().unwrap(), reply_digest: [6; 32], final_digest: [7; 32],
            observed_wall_seconds: 104, observed_boottime_ns: 14_000_000_000,
            cutoff_ns: 55_000_000_000,
        };
        (query, admission, closed)
    }

    #[test]
    fn final_ack_is_bound_to_the_same_retained_exchange() {
        let (query, admission, closed) = subjects();
        let check = |value| require_final_relation_v1(sample(100, 10), 55_000_000_000, 200,
            sample(103, 13), sample(105, 15), query, admission, [6; 32], [7; 32], value);

        assert!(check(closed).is_ok());
        assert!(check(StorageApplyClosedDataV1 { final_digest: [8; 32], ..closed }).is_err());
        assert!(check(StorageApplyClosedDataV1 { controller_nonce: [8; 16], ..closed }).is_err());
        assert!(check(StorageApplyClosedDataV1 { query_digest: [8; 32], ..closed }).is_err());
    }

    #[test]
    fn stricter_local_cutoff_is_preserved_without_relabeling_root_data() {
        let (query, admission, closed) = subjects();

        assert!(require_final_relation_v1(sample(100, 10), 50_000_000_000, 200,
            sample(103, 13), sample(105, 15), query, admission,
            [6; 32], [7; 32], closed).is_ok());
        assert!(require_final_relation_v1(sample(100, 10), 15_000_000_000, 200,
            sample(103, 13), sample(105, 15), query, admission,
            [6; 32], [7; 32], closed).is_err());
    }

    #[test]
    fn final_ack_cannot_extend_or_escape_the_actual_clock_bracket() {
        let (query, admission, closed) = subjects();
        let check = |value, after| require_final_relation_v1(sample(100, 10), 55_000_000_000, 200,
            sample(103, 13), after, query, admission, [6; 32], [7; 32], value);

        assert!(check(StorageApplyClosedDataV1 { cutoff_ns: 56_000_000_000, ..closed }, sample(105, 15)).is_err());
        assert!(check(StorageApplyClosedDataV1 { observed_boottime_ns: 16_000_000_000,
            observed_wall_seconds: 106, ..closed }, sample(105, 15)).is_err());
        assert!(check(closed, sample(145, 55)).is_err());
    }
    #[test]
    fn final_native_clock_tolerance_cannot_extend_actual_wall_expiry() {
        let origin = sample(100, 10);
        let expired = sample(120, 28);

        assert!(origin.validate_later_sample(expired).is_ok());
        assert!(require_final_sample_v1(origin, 29_000_000_000, 120, expired).is_err());
    }

}
