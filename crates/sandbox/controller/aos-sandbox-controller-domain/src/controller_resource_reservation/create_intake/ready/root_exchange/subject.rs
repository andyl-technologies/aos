//! Retains one exact Root frame and every unresolved strict subject receive.
//!
//! Positive chunk/readiness scratch is physically disposed only after binding,
//! cumulative copy and the actual independently owed Root/J posts. Failed raw
//! chunks and native poll prefixes stay in this same original receiver.

use std::error::Error;
use std::time::Duration;
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    transport::{FrameCoordinatesV1, FrameEnvelopeV1, FRAME_HEADER_BYTES},
    continuation::SIGNED_BOUND_RECEIPT_BYTES_V1,
    current_proofs::CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1,
    outcome::{ROOT_OUTCOME_RECEIPT_BYTES_V1, ROOT_CLOSED_RECEIPT_BYTES_V1}};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::{ClockId, Timespec, clock_gettime};
use aos_sandbox_broker::bounded_stream_io::remaining;
use super::{CreateStorageRootExchangeClosedV1 as Closed, CreateStorageRootPeerReceivingOriginalsV1,
    OriginalCreateStorageRootExchangeV1, RootPostFrontierV1, RootReceivePurposeV1};

#[derive(Default)]
pub(super) struct RootReadinessOriginalsV1 {
    clock: Option<Timespec>,
    remaining: Option<Result<Duration, HistoryErrorV1>>,
    timeout: Option<Result<Timespec, HistoryErrorV1>>,
    native: Option<Result<usize, rustix::io::Errno>>,
    returned: Option<Result<(), HistoryErrorV1>>,
}

impl RootReadinessOriginalsV1 {
    fn wait_once(&mut self, stream: &RetainedUnixStream, cutoff: u64) -> Result<(), Closed> {
        if self.clock.is_some() { return Err(Closed); }
        let now = clock_gettime(ClockId::Boottime);
        self.clock = Some(now);
        self.remaining = Some(remaining(now, cutoff));
        self.timeout = Some((|| {
            let duration = self.remaining.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(HistoryErrorV1::Correlation)?;
            Ok(Timespec { tv_sec: i64::try_from(duration.as_secs()).map_err(|_| HistoryErrorV1::Extent)?,
                tv_nsec: i64::from(duration.subsec_nanos()) })
        })());
        self.returned = Some((|| {
            let timeout = self.timeout.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(HistoryErrorV1::Correlation)?;
            let mut descriptors = [PollFd::from_borrowed_fd(stream.as_fd(), PollFlags::IN)];
            self.native = Some(poll(&mut descriptors, Some(timeout)));
            match self.native { Some(Ok(value)) if value != 0 => Ok(()), _ => Err(HistoryErrorV1::Correlation) }
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(Closed) }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.remaining).or_else(|| cause(&self.timeout)).or_else(|| cause(&self.native))
            .or_else(|| cause(&self.returned))
    }
}

#[derive(Clone, Copy)]
enum FailureStageV1 { Admission, Preparation, Wait, Receive, Subject, Copy, After, Extent, Header, Extension, Frame }

#[derive(Default)]
pub(super) struct RootExactSubjectReceiveV1 {
    pub(super) buffer: RetainedSubjectStreamReadV1,
    admission: Option<Result<(), Closed>>,
    prepared: Option<Result<(), SubjectStreamReadErrorV1>>,
    wait: Option<RootReadinessOriginalsV1>,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    subject: Option<Result<(), Closed>>,
    copied: Option<Result<(), SubjectStreamReadErrorV1>>,
    after: Option<Result<(), Closed>>,
    first: Option<FailureStageV1>,
    extent: Option<Closed>,
    reached: usize,
    header: Option<Result<usize, HistoryErrorV1>>,
    extension: Option<Result<(), SubjectStreamReadErrorV1>>,
    frame: Option<Result<(), HistoryErrorV1>>,
}

impl RootExactSubjectReceiveV1 {
    pub(super) fn failure<'cause>(&'cause self, peer: &'cause CreateStorageRootPeerReceivingOriginalsV1)
        -> Option<&'cause (dyn Error + 'static)>
    {
        match self.first {
            Some(FailureStageV1::Admission) => cause(&self.admission),
            Some(FailureStageV1::Preparation) => self.buffer.failure().or_else(|| cause(&self.prepared)),
            Some(FailureStageV1::Wait) => self.wait.as_ref().and_then(RootReadinessOriginalsV1::failure),
            Some(FailureStageV1::Receive) => self.buffer.failure().or_else(|| cause(&self.received)),
            Some(FailureStageV1::Subject) => peer.failure().or_else(|| cause(&self.subject)),
            Some(FailureStageV1::Copy) => self.buffer.failure().or_else(|| cause(&self.copied)),
            Some(FailureStageV1::After) => peer.failure().or_else(|| cause(&self.after)),
            Some(FailureStageV1::Extent) => self.extent.as_ref().map(|cause| cause as _),
            Some(FailureStageV1::Header) => cause(&self.header),
            Some(FailureStageV1::Extension) => self.buffer.failure().or_else(|| cause(&self.extension)),
            Some(FailureStageV1::Frame) => cause(&self.frame),
            None => None,
        }
    }

    pub(super) fn admission_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(FailureStageV1::Admission))
    }

    pub(super) fn has_entered_attempt(&self) -> bool {
        self.admission.is_some() || self.prepared.is_some()
    }

    pub(super) fn receiving_metadata_cells_v1() -> usize {
        // Pure receive/readiness controls have byte cost but create no names.
        0
    }
}

impl<'turn, 'original, 'cache> OriginalCreateStorageRootExchangeV1<'turn, 'original, 'cache> {
    pub(super) fn receive_root_subject_once(&mut self,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1, cutoff: u64,
        geometry: &SubjectStreamReceiveGeometryV1, purpose: RootReceivePurposeV1,
    ) -> Result<(), Closed> {
        let length = match purpose { RootReceivePurposeV1::Hello => 612, RootReceivePurposeV1::Invitation => 248,
        RootReceivePurposeV1::Authorization => 972,
            RootReceivePurposeV1::UseInvitation => CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1,
            RootReceivePurposeV1::UseAdmitted => FRAME_HEADER_BYTES,
            RootReceivePurposeV1::SignedBound => FRAME_HEADER_BYTES + SIGNED_BOUND_RECEIPT_BYTES_V1,
            RootReceivePurposeV1::OutcomeAcknowledged => FRAME_HEADER_BYTES + ROOT_OUTCOME_RECEIPT_BYTES_V1,
            RootReceivePurposeV1::Closed => FRAME_HEADER_BYTES + ROOT_CLOSED_RECEIPT_BYTES_V1 };
        // An allocation/next-frontier refusal still owes its full Root post.
        // Reserve that one observation before constructing the new receiver.
        self.state.receiving = Some(purpose);
        let admission = self.prepay_root_peer_observations_v1(1);
        let receiver = self.state.receiver_transport_mut(purpose).0;
        if receiver.prepared.is_some() || receiver.first.is_some() { return Err(Closed); }
        receiver.admission = Some(admission);
        if !matches!(receiver.admission, Some(Ok(()))) {
            receiver.first = Some(FailureStageV1::Admission);
            // The preceding completed turn/chunk already prepaid this one
            // independently owed sample. A failed extension cannot erase it.
            self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
            let post = peer.recheck_once(self);
            let receiver = self.state.receiver_transport_mut(purpose).0;
            receiver.after = Some(post);
            return Err(Closed);
        }
        receiver.prepared = Some(receiver.buffer.prepare_exact_once(length));
        if !matches!(receiver.prepared, Some(Ok(()))) {
            receiver.first = Some(FailureStageV1::Preparation);
            self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
            let post = peer.recheck_once(self);
            let receiver = self.state.receiver_transport_mut(purpose).0;
            receiver.after = Some(post);
            return Err(Closed);
        }
        self.receive_root_prepared_remainder_once(peer, cutoff, geometry, purpose, length)
    }

    fn receive_root_prepared_remainder_once(&mut self,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1, cutoff: u64,
        geometry: &SubjectStreamReceiveGeometryV1, purpose: RootReceivePurposeV1,
        length: usize,
    ) -> Result<(), Closed> {
        while !self.state.receiver().ok_or(Closed)?.buffer.completed_exact() {
            // Prepay this actual subject observation, its owed Root post and
            // one remaining comparison-refusal post before native receive. No
            // unused lifetime row roster is charged or refunded.
            let admission = self.prepay_root_peer_observations_v1(3);
            let receiver = self.state.receiver_transport_mut(purpose).0;
            receiver.admission = Some(admission);
            if !matches!(receiver.admission, Some(Ok(()))) {
                receiver.first = Some(FailureStageV1::Admission);
                // The entry/last complete chunk prepaid this one observation.
                // Sticky additional admission debt cannot erase its native IO.
                self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
                let post = peer.recheck_once(self);
                let receiver = self.state.receiver_transport_mut(purpose).0;
                receiver.after = Some(post);
                return Err(Closed);
            }
            let state = &mut self.state;
            let (receiver, transport) = state.receiver_transport_mut(purpose);
            if receiver.first.is_some() || receiver.wait.is_some() || receiver.reached >= length {
                receiver.extent.get_or_insert(Closed);
                receiver.first.get_or_insert(FailureStageV1::Extent);
                return Err(Closed);
            }
            receiver.wait = Some(Default::default());
            let waited = receiver.wait.as_mut().ok_or(Closed)?.wait_once(transport.stream().map_err(|_| Closed)?, cutoff);
            if waited.is_err() { receiver.first = Some(FailureStageV1::Wait); }
            if waited.is_ok() {
                let stream = transport.stream_mut().map_err(|_| Closed)?;
                receiver.received = Some(receiver.buffer.receive_next_with_geometry_once(stream, geometry));
                if !matches!(receiver.received, Some(Ok(()))) { receiver.first = Some(FailureStageV1::Receive); }
            }
            if self.state.receiver().ok_or(Closed)?.first.is_none() {
                let result = peer.require_chunk_v1(self);
                let receiver = self.state.receiver_transport_mut(purpose).0;
                receiver.subject = Some(result);
                if !matches!(receiver.subject, Some(Ok(()))) {
                    receiver.first = Some(FailureStageV1::Subject);
                }
            }
            if self.state.receiver().ok_or(Closed)?.first.is_none() {
                let receiver = self.state.receiver_transport_mut(purpose).0;
                receiver.copied = Some(receiver.buffer.append_pending_payload_once());
                if !matches!(receiver.copied, Some(Ok(()))) { receiver.first = Some(FailureStageV1::Copy); }
            }
            // Exactly one independently owed Root observation follows any
            // entered wait/receive/subject/copy failure. Its negative-only
            // continuation remains prearmed in the genuine peer owner.
            self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
            let post = peer.recheck_once(self);
            let receiver = self.state.receiver_transport_mut(purpose).0;
            receiver.after = Some(post);
            if !matches!(receiver.after, Some(Ok(()))) {
                receiver.first.get_or_insert(FailureStageV1::After);
            }
            if receiver.first.is_some() { return Err(Closed); }
            let chunk = receiver.buffer.take_copied_chunk_once().map_err(|_| Closed)?;
            drop(chunk);
            drop(receiver.wait.take());
            receiver.received = None;
            receiver.subject = None;
            receiver.copied = None;
            receiver.after = None;
            receiver.reached = receiver.reached.checked_add(1).ok_or(Closed)?;
        }
        Ok(())
    }

    // The actual U tail chooses expected coordinates and maximum from its
    // continuously borrowed positive native U owner, never an incoming header.
    // Prefix and body share ONE reservoir and the SAME strict chunk engine.
    pub(super) fn receive_root_variable_frame_once(&mut self,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1, cutoff: u64,
        geometry: &SubjectStreamReceiveGeometryV1,
        expected: FrameCoordinatesV1, maximum_payload: usize,
    ) -> Result<(), Closed> {
        let purpose = RootReceivePurposeV1::UseAdmitted;
        self.receive_root_subject_once(peer, cutoff, geometry, purpose)?;
        // The checked prefix's last chunk prepaid one refusal post. Extend
        // before new header/allocation work to cover its post, an empty-body
        // frame post, and the following refusal post without a hidden retry.
        let admission = self.prepay_root_peer_observations_v1(3);
        let receiver = self.state.receiver_transport_mut(purpose).0;
        receiver.admission = Some(admission);
        if !matches!(receiver.admission, Some(Ok(()))) {
            receiver.first.get_or_insert(FailureStageV1::Admission);
            self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
            let post = peer.recheck_once(self);
            self.state.receiver_transport_mut(purpose).0.after = Some(post);
            return Err(Closed);
        }
        let receiver = self.state.receiver_transport_mut(purpose).0;
        receiver.header = Some((|| {
            let header = receiver.buffer.bytes().try_into().map_err(|_| HistoryErrorV1::Extent)?;
            FrameEnvelopeV1::declared_payload_bytes_v1(header, expected, maximum_payload)
        })());
        if !matches!(receiver.header, Some(Ok(_))) {
            receiver.first.get_or_insert(FailureStageV1::Header);
        }
        let total = receiver.header.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(|length| length.checked_add(FRAME_HEADER_BYTES));
        if receiver.first.is_none() {
            receiver.extension = Some(match total {
                Some(total) => receiver.buffer.extend_completed_exact_once(total),
                None => Err(SubjectStreamReadErrorV1::Extent),
            });
            if !matches!(receiver.extension, Some(Ok(()))) {
                receiver.first.get_or_insert(FailureStageV1::Extension);
            }
        }
        // Header/completed-prefix allocation refusal still owes the original
        // full Root/J native post. No healthy-entry flag suppresses this IO.
        self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
        let post = peer.recheck_once(self);
        let receiver = self.state.receiver_transport_mut(purpose).0;
        receiver.after = Some(post);
        if !matches!(receiver.after, Some(Ok(()))) {
            receiver.first.get_or_insert(FailureStageV1::After);
        }
        if receiver.first.is_some() { return Err(Closed); }
        receiver.after = None;
        self.receive_root_prepared_remainder_once(peer, cutoff, geometry, purpose, total.ok_or(Closed)?)?;

        let receiver = self.state.receiver_transport_mut(purpose).0;
        receiver.frame = Some(FrameEnvelopeV1::decode(receiver.buffer.bytes(), expected).map(|_| ()));
        if !matches!(receiver.frame, Some(Ok(()))) {
            receiver.first.get_or_insert(FailureStageV1::Frame);
        }
        self.state.owed_post = Some(RootPostFrontierV1::HelloChunk);
        let post = peer.recheck_once(self);
        let receiver = self.state.receiver_transport_mut(purpose).0;
        receiver.after = Some(post);
        if !matches!(receiver.after, Some(Ok(()))) {
            receiver.first.get_or_insert(FailureStageV1::After);
        }
        if receiver.first.is_none() { Ok(()) } else { Err(Closed) }
    }

}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
