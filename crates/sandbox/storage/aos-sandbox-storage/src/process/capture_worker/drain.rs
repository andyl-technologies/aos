//! Drains actual anonymous pipes under the same parent's prepaid total ceiling.
//!
//! Stored output limits govern the sole file writer. Every requested pipe read,
//! including discarded output, short reads and EOF probes, consumes this finite
//! restrictive subscope before IO. Exhaustion leaves the pipes and complete
//! writer resident; it is never EOF, truncation success or terminal permission.

use super::*;
use aos_sandbox_model::ObjectDigest;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{OFlags, Stat, fcntl_getfl, fcntl_setfl, fstat};
use crate::execution_capture_writer::CaptureStreamV1;
use crate::execution_capture_zfs_worker::{PreparedDetachedCaptureWriterV1, CaptureWriterWorkerErrorV1};

const BUFFER_BYTES: usize = 8192;
type Pipe = Result<(OwnedFd, OwnedFd), rustix::io::Errno>;

#[derive(Clone, Copy)]
enum Failure { Stdout, Stderr, Flags, Identity, HandoffBefore, HandoffAck,
    HandoffSubject, HandoffMembership, HandoffGrammar, HandoffPost,
    Clock, Deadline, Poll, ReadBudget, Read, Write, WritePost }

pub(super) struct CaptureDrainOriginalV3 {
    pipes: [Option<Pipe>; 2],
    reads: [Option<OwnedFd>; 2],
    writers: [Option<OwnedFd>; 2],
    flags: [Option<Result<OFlags, rustix::io::Errno>>; 2],
    nonblocking: [Option<Result<(), rustix::io::Errno>>; 2],
    identities: [Option<Result<Stat, rustix::io::Errno>>; 2],
    handoff_clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<2>,
    handoff_clock_status: [Option<Result<(), ()>>; 2],
    handoff_ack: Option<Result<ReceivedRecord, aos_sandbox_linux::seqpacket::bounded::ZfsWorkerReceiveErrorV1>>,
    handoff_subject: Option<Result<(), ZfsWorkerError>>,
    handoff_membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1,
    handoff_membership_status: Option<Result<(), aos_sandbox_linux::cgroup::ExactCgroupMembershipRefusalV1>>,
    handoff_grammar: Option<Result<(), ZfsWorkerError>>,
    source: ObjectDigest,
    durable: ObjectDigest,
    cutoff: u64,
    remaining: u64,
    spent_requested: u64,
    stdout_eof: bool,
    stderr_eof: bool,
    buffer: [u8; BUFFER_BYTES],
    selected: Option<CaptureStreamV1>,
    clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<5>,
    clock_status: [Option<Result<(), ()>>; 5],
    clock_failure: usize,
    poll: Option<Result<usize, rustix::io::Errno>>,
    read: Option<Result<usize, rustix::io::Errno>>,
    written: Option<Result<(), CaptureWriterWorkerErrorV1>>,
    status: Option<ZfsWorkerError>,
    first: Option<Failure>,
    entered: bool,
    writers_transferred: bool,
}

// Only this module lends a completed actual read, while its exact pipe and
// buffer stay borrowed. A chunk slice, EOF bool or Source DTO cannot mint it.
pub(crate) struct CaptureDrainReadBorrowV3<'read> {
    original: &'read CaptureDrainOriginalV3,
    stream: CaptureStreamV1,
    length: usize,
}

impl CaptureDrainReadBorrowV3<'_> {
    pub(crate) fn source_v3(&self) -> ObjectDigest { self.original.source }
    pub(crate) fn durable_v3(&self) -> ObjectDigest { self.original.durable }
    pub(crate) fn cutoff_v3(&self) -> u64 { self.original.cutoff }
    pub(crate) fn stream_v3(&self) -> CaptureStreamV1 { self.stream }
    pub(crate) fn chunk_v3(&self) -> &[u8] { &self.original.buffer[..self.length] }
}

impl CaptureDrainOriginalV3 {
    pub(super) fn from_worker_v3(context: &AuthenticatedCaptureWorkerContextV3<'_>)
        -> Result<Self, ZfsWorkerError>
    {
        let (_, _, _, _, durable, boot, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)
            .map_err(|_| ZfsWorkerError::Authority)?;
        Ok(Self { pipes: std::array::from_fn(|_| None), reads: std::array::from_fn(|_| None),
            writers: std::array::from_fn(|_| None), flags: std::array::from_fn(|_| None),
            nonblocking: std::array::from_fn(|_| None), identities: std::array::from_fn(|_| None),
            handoff_clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::from_worker_v3(context, boot, cutoff),
            handoff_clock_status: std::array::from_fn(|_| None), handoff_ack: None,
            handoff_subject: None, handoff_membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::new(),
            handoff_membership_status: None, handoff_grammar: None,
            source: context.source_v3().source_digest_v2(), durable, cutoff,
            remaining: context.prepaid_drain_ceiling_v3(), spent_requested: 0,
            stdout_eof: false, stderr_eof: false, buffer: [0; BUFFER_BYTES], selected: None,
            clocks: crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::from_worker_v3(context, boot, cutoff),
            clock_status: std::array::from_fn(|_| None), clock_failure: 0, poll: None, read: None, written: None,
            status: None, first: None, entered: false, writers_transferred: false })
    }

    pub(super) fn prepare_pipes_once_v3(&mut self) -> Result<(), ZfsWorkerError> {
        if self.entered || self.remaining == 0 { return Err(ZfsWorkerError::Authority); }
        self.entered = true;
        self.first = Some(Failure::Stdout);
        self.pipes[0] = Some(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC));
        if !matches!(self.pipes[0], Some(Ok(_))) { return Err(worker_entry::retained()); }
        self.first = Some(Failure::Stderr);
        self.pipes[1] = Some(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC));
        if !matches!(self.pipes[1], Some(Ok(_))) { return Err(worker_entry::retained()); }
        for index in 0..2 {
            let Some(Ok((read, write))) = self.pipes[index].take() else { std::process::abort(); };
            self.reads[index] = Some(read);
            self.writers[index] = Some(write);
        }
        // Only the private read ends become nonblocking. The Guest receives
        // ordinary blocking stdout/stderr writers, so exhausted finite drain
        // produces backpressure rather than silently discarding an EOF claim.
        for index in 0..2 {
            self.first = Some(Failure::Flags);
            let read = self.read_fd_v3(index).ok_or(ZfsWorkerError::Authority)?;
            self.flags[index] = Some(fcntl_getfl(read));
            let Some(Ok(flags)) = self.flags[index] else { return Err(worker_entry::retained()); };
            let read = self.read_fd_v3(index).ok_or(ZfsWorkerError::Authority)?;
            self.nonblocking[index] = Some(fcntl_setfl(read, flags | OFlags::NONBLOCK));
            if !matches!(self.nonblocking[index], Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(Failure::Identity);
            let read = self.read_fd_v3(index).ok_or(ZfsWorkerError::Authority)?;
            self.identities[index] = Some(fstat(read));
            if !matches!(self.identities[index], Some(Ok(_))) { return Err(worker_entry::retained()); }
        }
        self.first = None;
        Ok(())
    }

    fn read_fd_v3(&self, index: usize) -> Option<&OwnedFd> {
        self.reads.get(index)?.as_ref()
    }

    pub(super) fn writer_fds_v3(&self) -> Option<[BorrowedFd<'_>; 2]> {
        if !self.entered || self.first.is_some() || self.writers_transferred { return None; }
        Some([self.writers[0].as_ref()?.as_fd(), self.writers[1].as_ref()?.as_fd()])
    }

    pub(super) fn identities_data_v3(&self) -> Option<[(u64, u64); 2]> {
        if !self.entered || self.first.is_some() || self.writers_transferred { return None; }
        let [Some(Ok(stdout)), Some(Ok(stderr))] = self.identities.as_ref() else { return None; };
        Some([(stdout.st_dev as u64, stdout.st_ino as u64), (stderr.st_dev as u64, stderr.st_ino as u64)])
    }

    pub(super) fn release_child_writers_after_parent_ack_v3(
        &mut self,
        socket: &mut SeqpacketSocket,
        context: &AuthenticatedCaptureWorkerContextV3<'_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.first.is_some() || !self.entered || self.writers_transferred
            || self.handoff_ack.is_some() || self.source != context.source_v3().source_digest_v2()
        { return Err(ZfsWorkerError::Authority); }
        let body = (|| {
            self.first = Some(Failure::HandoffBefore);
            self.handoff_clock_status[0] = Some(self.handoff_clocks.observe_once_v3(0));
            if !matches!(self.handoff_clock_status[0], Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(Failure::HandoffAck);
            self.handoff_ack = Some(aos_sandbox_linux::seqpacket::bounded::receive_zfs_worker_record_v1(
                socket, aos_sandbox_linux::seqpacket::bounded::ZfsWorkerRecordKindV1::Acknowledgement, self.cutoff,
            ));
            let Some(Ok(ack)) = self.handoff_ack.as_ref() else { return Err(worker_entry::retained()); };
            self.first = Some(Failure::HandoffSubject);
            self.handoff_subject = Some(verify_same_live_subject(context._parent.request_v3().subject(), ack.subject()));
            if !matches!(self.handoff_subject, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(Failure::HandoffMembership);
            self.handoff_membership_status = Some(self.handoff_membership.capture_once(
                context._parent.parent_v3(), ack.subject().pidfd(),
            ));
            if !matches!(self.handoff_membership_status, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(Failure::HandoffGrammar);
            self.handoff_grammar = Some(decode_ack(ack.payload()));
            if !matches!(self.handoff_grammar, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = None;
            Ok(())
        })();
        self.handoff_clock_status[1] = Some(self.handoff_clocks.observe_once_v3(1));
        if body.is_err() { return body; }
        if !matches!(self.handoff_clock_status[1], Some(Ok(()))) {
            self.first = Some(Failure::HandoffPost);
            return Err(worker_entry::retained());
        }
        // The exact authenticated parent now owns the transferred original
        // writer aliases. This positive local handoff closes only the child's
        // duplicate writers; Host/parent aliases and every F debt remain.
        drop(self.writers[0].take());
        drop(self.writers[1].take());
        self.writers_transferred = true;
        Ok(())
    }

    fn require_clock_v3(&mut self, index: usize) -> Result<u64, ZfsWorkerError> {
        self.clock_failure = index;
        self.clock_status[index] = Some(self.clocks.observe_once_v3(index));
        if !matches!(self.clock_status[index], Some(Ok(()))) { return Err(worker_entry::retained()); }
        self.clocks.boottime_at_v3(index).ok_or_else(worker_entry::retained)
    }

    pub(super) fn drain_to_eof_v3(&mut self, writer: &mut PreparedDetachedCaptureWriterV1)
        -> Result<(), ZfsWorkerError>
    {
        if !self.writers_transferred || self.first.is_some() { return Err(ZfsWorkerError::Authority); }
        while !self.stdout_eof || !self.stderr_eof {
            self.first = Some(Failure::Clock);
            let now = self.require_clock_v3(0)?;
            let remaining_time = self.cutoff - now;
            let duration = Duration::from_nanos(remaining_time);
            let timeout = Timespec::try_from(duration).map_err(|_| ZfsWorkerError::Authority)?;
            self.first = Some(Failure::Poll);
            let events = {
                let stdout = self.read_fd_v3(if self.stdout_eof { 1 } else { 0 })
                    .ok_or(ZfsWorkerError::Authority)?;
                let stderr = self.read_fd_v3(if self.stderr_eof { 0 } else { 1 })
                    .ok_or(ZfsWorkerError::Authority)?;
                let mut ready = [PollFd::new(stdout, PollFlags::IN), PollFd::new(stderr, PollFlags::IN)];
                let result = rustix::event::poll(&mut ready, Some(&timeout));
                let events = [ready[0].revents(), ready[1].revents()];
                (result, events)
            };
            self.poll = Some(events.0);
            // Entered poll always owes its independent clock sample. A later
            // clock refusal stays resident without replacing the poll error.
            let poll_post = self.require_clock_v3(1);
            if !matches!(self.poll, Some(Ok(_))) {
                self.first = Some(Failure::Poll);
                return Err(worker_entry::retained());
            }
            self.first = Some(Failure::Clock);
            poll_post?;
            for index in 0..2 {
                let eof = if index == 0 { self.stdout_eof } else { self.stderr_eof };
                if eof || events.1[index].is_empty() { continue; }
                self.first = Some(Failure::ReadBudget);
                let requested = self.remaining.min(BUFFER_BYTES as u64);
                if requested == 0 {
                    self.status = Some(ZfsWorkerError::Protocol("Capture prepaid drain ceiling exhausted before EOF"));
                    return Err(worker_entry::retained());
                }
                // Payment is for the actual requested capacity, not stored
                // bytes. EINTR, a short read and the final zero-byte probe do
                // not return credit. No read is entered at zero allowance.
                self.remaining -= requested;
                self.spent_requested = self.spent_requested.checked_add(requested)
                    .ok_or(ZfsWorkerError::Authority)?;
                let requested = usize::try_from(requested).map_err(|_| ZfsWorkerError::Authority)?;
                self.first = Some(Failure::Clock);
                self.require_clock_v3(2)?;
                self.first = Some(Failure::Read);
                let Some(read) = self.reads[index].as_ref() else { return Err(ZfsWorkerError::Authority); };
                self.read = Some(rustix::io::read(read, &mut self.buffer[..requested]));
                // The after-read sample remains owed on a native read error.
                // Preserve the read as first cause if that post also refuses.
                let read_post = self.require_clock_v3(3);
                let Some(Ok(length)) = self.read else {
                    self.first = Some(Failure::Read);
                    return Err(worker_entry::retained());
                };
                self.first = Some(Failure::Clock);
                read_post?;
                let stream = if index == 0 { CaptureStreamV1::Stdout } else { CaptureStreamV1::Stderr };
                self.selected = Some(stream);
                self.first = Some(Failure::Write);
                let actual_read = CaptureDrainReadBorrowV3 { original: self, stream, length };
                let result = writer.consume_native_drain_read_v3(actual_read);
                self.written = Some(result);
                // This post is independent of the reached write result. Keep
                // its native cause without replacing an earlier read/write.
                let write_post = self.require_clock_v3(4);
                if !matches!(self.written, Some(Ok(()))) {
                    self.first = Some(Failure::Write);
                    return Err(worker_entry::retained());
                }
                self.first = Some(Failure::WritePost);
                write_post?;
                if length == 0 {
                    if index == 0 { self.stdout_eof = true; } else { self.stderr_eof = true; }
                }
                // The full positive read/write/source-post subphase has no
                // outstanding owner. Retained file/model/traffic debt stays;
                // only its scalar/native-result scratch is reused next read.
                self.clocks.retire_positive_range_v3(2..5).map_err(|_| worker_entry::retained())?;
                self.read = None; self.written = None;
                for index in 2..5 { self.clock_status[index] = None; }
                self.first = None;
            }
            self.clocks.retire_positive_range_v3(0..5).map_err(|_| worker_entry::retained())?;
            self.clock_status = std::array::from_fn(|_| None);
            self.poll = None;
            self.first = None;
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Stdout => self.pipes[0].as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Stderr => self.pipes[1].as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::HandoffBefore => self.handoff_clocks.failure_at_v3(0),
            Failure::HandoffPost => self.handoff_clocks.failure_at_v3(1),
            Failure::HandoffAck => self.handoff_ack.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::HandoffSubject => self.handoff_subject.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::HandoffMembership => self.handoff_membership.failure().map(|cause| cause as _),
            Failure::HandoffGrammar => self.handoff_grammar.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Flags => self.flags.iter().find_map(|slot| slot.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.nonblocking.iter().find_map(|slot| slot.as_ref()?.as_ref().err().map(|cause| cause as _))),
            Failure::Identity => self.identities.iter().find_map(|slot| slot.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Failure::Clock => self.clocks.failure_at_v3(self.clock_failure),
            Failure::Deadline | Failure::ReadBudget => self.status.as_ref().map(|cause| cause as _),
            Failure::Poll => self.poll.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Read => self.read.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Write => self.written.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::WritePost => self.clocks.failure_at_v3(4),
        }
    }
}
