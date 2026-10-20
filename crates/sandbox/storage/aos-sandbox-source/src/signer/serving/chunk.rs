//! Retains one real strict receive through Source and Root kernel bookends.
//!
//! The enclosing complete IO stage already holds its Root image/PID1 sample.
//! This separate exclusive F lane pays the actual bounded recvmsg/control peak
//! and both Source samples; it never uses resident highwater as traffic money.

use std::error::Error;

use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, RetainedUnixStream, SubjectStreamReceiveGeometryV1,
    SubjectStreamReadErrorV1, UnixStreamSubjectChunk,
};
use rustix::event::{PollFd, PollFlags};

use aos_sandbox_broker::receiving::ComponentReceivingOperationLoanV1;
use crate::signer::root_observation::{SourceRootChunkReadbackV1, SourceRootPeerConnectionV1};

use super::super::currentness::SourceCurrentnessSampleV1;
use super::{SourceServingOriginalLoanV1, SourceReceivingClosedV1, CLOSED};

#[derive(Clone, Copy)]
enum Failure { Consumption, Before, Deadline, Poll, Receive, Subject, Copy, Move, After, Closed }

pub(super) struct SourceChunkSampleV1 {
    consumption: Option<Result<(), SourceReceivingClosedV1>>,
    before: SourceCurrentnessSampleV1,
    before_result: Option<Result<(), SourceReceivingClosedV1>>,
    deadline: Option<Result<std::time::Duration, SourceReceivingClosedV1>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    poll_flags: PollFlags,
    receive: Option<Result<(), SubjectStreamReadErrorV1>>,
    subject: SourceRootChunkReadbackV1,
    subject_result: Option<Result<(), aos_sandbox_broker::receiving::RootObservationErrorV1>>,
    copy: Option<Result<(), SubjectStreamReadErrorV1>>,
    moved: Option<Result<UnixStreamSubjectChunk, SubjectStreamReadErrorV1>>,
    after: SourceCurrentnessSampleV1,
    after_result: Option<Result<(), SourceReceivingClosedV1>>,
    first: Option<Failure>,
}

impl SourceChunkSampleV1 {
    pub(super) fn new() -> Self {
        Self {
            consumption: None, before: Default::default(), before_result: None,
            deadline: None, poll: None, poll_flags: PollFlags::empty(), receive: None,
            subject: Default::default(), subject_result: None, copy: None, moved: None,
            after: Default::default(), after_result: None, first: None,
        }
    }

    pub(super) fn receive_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        peer: &SourceRootPeerConnectionV1,
        stream: &mut RetainedUnixStream,
        buffer: &mut RetainedSubjectStreamReadV1,
        geometry: &SubjectStreamReceiveGeometryV1,
        started: std::time::Instant,
        operation: &mut ComponentReceivingOperationLoanV1<'_>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.consumption.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(CLOSED);
        }
        self.consumption = Some(operation.consume_flight_once().map_err(|_| CLOSED));
        if !matches!(self.consumption, Some(Ok(()))) {
            self.first = Some(Failure::Consumption);
            return Err(CLOSED);
        }
        self.before_result = Some(original.observe_source_into(&mut self.before));
        if !matches!(self.before_result, Some(Ok(()))) { self.first = Some(Failure::Before); }
        if self.first.is_none() {
            self.deadline = Some(super::remaining(started));
            if !matches!(self.deadline, Some(Ok(_))) { self.first = Some(Failure::Deadline); }
        }
        if let Some(Ok(duration)) = self.deadline.as_ref() {
            let timeout = rustix::event::Timespec {
                tv_sec: duration.as_secs() as i64,
                tv_nsec: i64::from(duration.subsec_nanos()),
            };
            let fd = stream.as_fd();
            let mut fds = [PollFd::new(&fd, PollFlags::IN)];
            self.poll = Some(rustix::event::poll(&mut fds, Some(&timeout)));
            self.poll_flags = fds[0].revents();
            if !matches!(self.poll, Some(Ok(1))) || !self.poll_flags.intersects(PollFlags::IN | PollFlags::HUP)
                || self.poll_flags.intersects(PollFlags::ERR | PollFlags::NVAL)
            {
                self.first.get_or_insert(Failure::Poll);
            }
        }
        if self.first.is_none() {
            self.receive = Some(buffer.receive_next_with_geometry_once(stream, geometry));
            if !matches!(self.receive, Some(Ok(()))) { self.first = Some(Failure::Receive); }
        }
        if self.first.is_none() {
            self.subject_result = Some(match buffer.pending_chunk() {
                Ok(chunk) => self.subject.capture_once(original.inputs, peer, stream, chunk),
                Err(_) => Err(aos_sandbox_broker::receiving::RootObservationErrorV1::Service),
            });
            if !matches!(self.subject_result, Some(Ok(()))) { self.first = Some(Failure::Subject); }
        }
        if self.first.is_none() {
            self.copy = Some(buffer.append_pending_payload_once());
            if !matches!(self.copy, Some(Ok(()))) { self.first = Some(Failure::Copy); }
        }
        if self.first.is_none() {
            self.moved = Some(buffer.take_copied_chunk_once());
            if !matches!(self.moved, Some(Ok(_))) { self.first = Some(Failure::Move); }
        }
        // Keep the actual native chunk and its subject probes through the
        // independent same-Source process/limits/FD-coverage observation.
        self.after_result = Some(original.observe_source_into(&mut self.after));
        if !matches!(self.after_result, Some(Ok(()))) { self.first.get_or_insert(Failure::After); }
        if self.can_dispose() { Ok(()) } else { Err(CLOSED) }
    }

    pub(super) fn can_dispose(&self) -> bool {
        self.first.is_none() && matches!(self.moved, Some(Ok(_))) && self.subject.complete()
            && matches!(self.before_result, Some(Ok(()))) && matches!(self.after_result, Some(Ok(())))
    }

    pub(super) fn failure<'a>(&'a self, buffer: &'a RetainedSubjectStreamReadV1) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            Failure::Consumption => super::failure(&self.consumption),
            Failure::Before => self.before.failure().or_else(|| super::failure(&self.before_result)),
            Failure::Deadline => super::failure(&self.deadline),
            Failure::Poll => super::failure(&self.poll),
            Failure::Receive => buffer.failure().or_else(|| super::failure(&self.receive)),
            Failure::Subject => self.subject.failure().or_else(|| super::failure(&self.subject_result)),
            Failure::Copy => super::failure(&self.copy),
            Failure::Move => super::failure(&self.moved),
            Failure::After => self.after.failure().or_else(|| super::failure(&self.after_result)),
            Failure::Closed => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED as &(dyn Error + 'static)))
    }
}
