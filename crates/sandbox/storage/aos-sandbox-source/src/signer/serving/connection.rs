//! Retains a complete selected Source request through its last genuine posts.
//!
//! Positive stage samples are disposed before their same-F operation capacity
//! is reused. The request, endpoint, EOF, signed view and partial sends remain
//! separate resident owners through response and shutdown. Any refusal keeps
//! the entire connection on the original and permanently ends serving.

use std::collections::TryReserveError;
use std::error::Error;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::time::Instant;

use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, SeqpacketError};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStreamAdmissionErrorV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectEofReadbackV1;
use ed25519_dalek::SigningKey;
use rustix::event::{PollFd, PollFlags};
use rustix::net::sockopt::{Timeout, set_socket_timeout};

use aos_sandbox_broker::receiving::ObservationLifetimeV1 as ObserverLifetime;
use crate::signer::root_observation::SourceRootPeerConnectionV1;
use crate::signer::{SourceReadonlyAttemptV1, SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4};
use aos_sandbox_ledger_replay::source_signer_data::source_signer_wire::{FLIGHT_TIMEOUT, REQUEST_RESOURCE_SUCCESSOR_BYTES};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::{
    HistoryPairNativeSuffixV1, HistoryPairNativeSuffixProgressV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1, PhaseV1,
    source_current::SourceCurrentQueryDataV1};

use super::chunk::SourceChunkSampleV1;
use super::operation::SourceOperationV1;
use super::request::SourceWireRequestV1;
use super::simple::SourceAcceptSampleV1;
use super::stage::SourceStageSampleV1;
use super::{SourceReceivingClosedV1, SourceServingOriginalLoanV1, CLOSED};

pub(super) const MAXIMUM_REPLY_FRAME: usize = 8 + SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4;

#[derive(Clone, Copy)]
enum Failure {
    AcceptBefore, Accept, Adoption, Subject, Timeout, AcceptAfter,
    RootStage, Buffer, Chunk, Width, EofPoll, Eof, Decode,
    Context, View, Framing, Send, ResponsePost, Shutdown, ShutdownPost, Closed,
}

pub(super) struct SourceConnectionV1 {
    accepted: Option<io::Result<(UnixStream, SocketAddr)>>,
    address: Option<SocketAddr>,
    stream: Option<Result<RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1>>,
    subject: Option<Result<(), SeqpacketError>>,
    read_timeout: Option<Result<(), rustix::io::Errno>>,
    write_timeout: Option<Result<(), rustix::io::Errno>>,
    accept_sample: Option<SourceAcceptSampleV1>,
    peer: SourceRootPeerConnectionV1,
    stage: Option<SourceStageSampleV1>,
    chunk: Option<SourceChunkSampleV1>,
    selector: RetainedSubjectStreamReadV1,
    tail: RetainedSubjectStreamReadV1,
    selector_preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    tail_preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    width: Option<io::Result<usize>>,
    raw: [u8; REQUEST_RESOURCE_SUCCESSOR_BYTES],
    eof_deadline: Option<Result<std::time::Duration, SourceReceivingClosedV1>>,
    eof_poll: Option<Result<usize, rustix::io::Errno>>,
    eof_flags: PollFlags,
    eof: Option<Result<UnixStreamSubjectEofReadbackV1, RetainedSeqpacketReceiveErrorV1>>,
    decoded: Option<io::Result<SourceWireRequestV1>>,
    context: Option<Result<(), SourceReceivingClosedV1>>,
    current_peer: Option<io::Result<()>>,
    current_expected: Option<Result<JournalTransaction, JournalError>>,
    current_suffix: HistoryPairNativeSuffixProgressV1,
    current_attachment: Option<Result<(), SourceReceivingClosedV1>>,
    view: SourceReadonlyAttemptV1,
    observed: Option<Result<(), ()>>,
    framing: Option<io::Result<usize>>,
    reply: [u8; MAXIMUM_REPLY_FRAME],
    send_reservation: Option<Result<(), TryReserveError>>,
    sends: Vec<Result<usize, rustix::io::Errno>>,
    response_post: Option<Result<(), ()>>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    shutdown_post: Option<Result<(), ()>>,
    started: Option<Instant>,
    received: bool,
    complete: bool,
    first: Option<Failure>,
}

impl SourceConnectionV1 {
    pub(super) fn new() -> Self {
        Self {
            accepted: None, address: None, stream: None, subject: None,
            read_timeout: None, write_timeout: None, accept_sample: None,
            peer: SourceRootPeerConnectionV1::new(), stage: None, chunk: None,
            selector: RetainedSubjectStreamReadV1::new(),
            tail: RetainedSubjectStreamReadV1::new(),
            selector_preparation: None, tail_preparation: None, width: None,
            raw: [0; REQUEST_RESOURCE_SUCCESSOR_BYTES], eof_deadline: None, eof_poll: None,
            eof_flags: PollFlags::empty(), eof: None, decoded: None, context: None,
            current_peer: None, current_expected: None,
            current_suffix: HistoryPairNativeSuffixProgressV1::new(), current_attachment: None,
            view: SourceReadonlyAttemptV1::new(), observed: None, framing: None,
            reply: [0; MAXIMUM_REPLY_FRAME], send_reservation: None, sends: Vec::new(),
            response_post: None, shutdown: None, shutdown_post: None,
            started: None, received: false, complete: false, first: None,
        }
    }

    pub(super) fn accept_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.accept_sample.is_some() || self.accepted.is_some() { return self.close(); }
        operation.begin_after_positive_disposal()?;
        let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
        self.accept_sample = Some(SourceAcceptSampleV1::new());
        let sample = self.accept_sample.as_mut().ok_or(CLOSED)?;
        if sample.begin_once(original, &mut flight).is_err() {
            self.first = Some(Failure::AcceptBefore);
            // The sample itself requires successful full consumption. An
            // entered native refusal still receives its independent post;
            // financial refusal performs no native work at either frontier.
            let _ = sample.finish_once(original);
            return Err(CLOSED);
        }
        self.accepted = Some(original.listener.accept_once());
        if !matches!(self.accepted, Some(Ok(_))) {
            self.first = Some(Failure::Accept);
        } else if let Some(Ok((stream, address))) = self.accepted.take() {
            self.started = Some(Instant::now());
            self.address = Some(address);
            self.stream = Some(RetainedUnixStream::from_owned_retaining_v1(OwnedFd::from(stream)));
            if !matches!(self.stream, Some(Ok(_))) { self.first = Some(Failure::Adoption); }
        }
        if let Some(Ok(stream)) = self.stream.as_mut() {
            self.subject = Some(stream.require_inherited_subject_reporting_v1().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
            self.read_timeout = Some(set_socket_timeout(stream.as_fd(), Timeout::Recv, Some(FLIGHT_TIMEOUT)));
            self.write_timeout = Some(set_socket_timeout(stream.as_fd(), Timeout::Send, Some(FLIGHT_TIMEOUT)));
            if !matches!(self.subject, Some(Ok(()))) { self.first.get_or_insert(Failure::Subject); }
            if !matches!(self.read_timeout, Some(Ok(()))) || !matches!(self.write_timeout, Some(Ok(()))) {
                self.first.get_or_insert(Failure::Timeout);
            }
        }
        if sample.finish_once(original).is_err() { self.first.get_or_insert(Failure::AcceptAfter); }
        if self.first.is_some() || !sample.positive() { return Err(CLOSED); }

        // The accepted endpoint lives separately under the prepaid resident
        // shape; only the complete positive before/after sample is disposed.
        drop(self.accept_sample.take());
        flight.finish_positive_observation();
        Ok(())
    }

    pub(super) fn receive_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        chunk_operation: &mut SourceOperationV1,
        geometry: &SubjectStreamReceiveGeometryV1,
        lifetime: ObserverLifetime,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.first.is_some() || self.received { return self.close(); }
        operation.begin_after_positive_disposal()?;
        let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
        self.stage = Some(SourceStageSampleV1::new(lifetime));
        let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.stage.as_mut().ok_or(CLOSED)?.begin_once(original, &mut self.peer, stream, &mut flight).is_err() {
            self.first = Some(Failure::RootStage);
        }
        if self.first.is_none() {
            self.selector_preparation = Some(self.selector.prepare_exact_once(8));
            if !matches!(self.selector_preparation, Some(Ok(()))) { self.first = Some(Failure::Buffer); }
        }
        if self.first.is_none() && self.read_buffer_once(original, chunk_operation, geometry, true).is_err() {
            self.first.get_or_insert(Failure::Chunk);
        }
        if self.first.is_none() {
            let selector = self.selector.bytes();
            self.raw[..8].copy_from_slice(selector);
            self.width = Some(self.raw[..8].try_into().map_err(|_| io::Error::other("short selector"))
                .and_then(SourceWireRequestV1::width)
                .and_then(|width| if (8..=self.raw.len()).contains(&width) { Ok(width) }
                    else { Err(io::Error::other("unsupported Source frame extent")) }));
            if !matches!(self.width, Some(Ok(_))) { self.first = Some(Failure::Width); }
        }
        if let Some(Ok(width)) = self.width {
            self.tail_preparation = Some(self.tail.prepare_exact_once(width - 8));
            if !matches!(self.tail_preparation, Some(Ok(()))) { self.first.get_or_insert(Failure::Buffer); }
            if self.first.is_none() && self.read_buffer_once(original, chunk_operation, geometry, false).is_err() {
                self.first.get_or_insert(Failure::Chunk);
            }
            if self.first.is_none() {
                self.raw[8..width].copy_from_slice(self.tail.bytes());
                self.receive_eof_once(geometry);
            }
            if self.first.is_none() {
                self.decoded = Some(SourceWireRequestV1::decode(&self.raw[..width]));
                if !matches!(self.decoded, Some(Ok(_))) { self.first = Some(Failure::Decode); }
            }
        }
        let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.stage.as_mut().ok_or(CLOSED)?.finish_once(original, &mut self.peer, stream).is_err() {
            self.first.get_or_insert(Failure::RootStage);
        }
        if self.first.is_some() { return Err(CLOSED); }
        drop(self.stage.take());
        flight.finish_positive_observation();
        self.received = true;
        Ok(())
    }

    fn read_buffer_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        geometry: &SubjectStreamReceiveGeometryV1,
        selector: bool,
    ) -> Result<(), SourceReceivingClosedV1> {
        let buffer = if selector { &mut self.selector } else { &mut self.tail };
        let stream = self.stream.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        while !buffer.completed_exact() {
            operation.begin_after_positive_disposal()?;
            let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
            self.chunk = Some(SourceChunkSampleV1::new());
            let sample = self.chunk.as_mut().ok_or(CLOSED)?;
            if sample.receive_once(original, &self.peer, stream, buffer, geometry,
                self.started.ok_or(CLOSED)?, &mut flight).is_err() {
                return Err(CLOSED);
            }
            // The exact buffer retains only the funded payload copy. The actual
            // chunk, installed descriptor custody and kernel/Source sample are
            // disposed after all positive posts, before another recvmsg.
            drop(self.chunk.take());
            flight.finish_positive_observation();
        }
        Ok(())
    }

    fn receive_eof_once(&mut self, geometry: &SubjectStreamReceiveGeometryV1) {
        let Some(Ok(stream)) = self.stream.as_mut() else { self.first = Some(Failure::Closed); return; };
        let Some(started) = self.started else { self.first = Some(Failure::Closed); return; };
        self.eof_deadline = Some(super::remaining(started));
        let timeout = match self.eof_deadline.as_ref() {
            Some(Ok(timeout)) => rustix::event::Timespec {
                // remaining() restricts this value to the fixed five seconds.
                tv_sec: timeout.as_secs() as i64, tv_nsec: i64::from(timeout.subsec_nanos()),
            },
            _ => { self.first = Some(Failure::EofPoll); return; }
        };
        let fd = stream.as_fd();
        let mut polls = [PollFd::new(&fd, PollFlags::IN)];
        self.eof_poll = Some(rustix::event::poll(&mut polls, Some(&timeout)));
        self.eof_flags = polls[0].revents();
        if !matches!(self.eof_poll, Some(Ok(1))) || !self.eof_flags.intersects(PollFlags::IN | PollFlags::HUP)
            || self.eof_flags.intersects(PollFlags::ERR | PollFlags::NVAL) {
            self.first = Some(Failure::EofPoll);
            return;
        }
        self.eof = Some(aos_sandbox_linux::unix_stream::try_receive_subject_eof_with_geometry_retaining(stream, geometry));
        if !matches!(self.eof, Some(Ok(_))) { self.first = Some(Failure::Eof); }
    }

    pub(super) fn finish_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        lifetime: &ObserverLifetime,
        key: &SigningKey,
        generation: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.first.is_some() || !self.received || self.observed.is_some() { return self.close(); }
        self.observe_once(original, operation, lifetime.clone(), key, generation)?;
        self.send_once(original, operation, lifetime.clone())?;
        self.shutdown_once(original, operation, lifetime.clone())?;
        self.complete = true;
        Ok(())
    }

    fn observe_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        lifetime: ObserverLifetime,
        key: &SigningKey,
        generation: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        operation.begin_after_positive_disposal()?;
        let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
        self.stage = Some(SourceStageSampleV1::new(lifetime));
        let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.stage.as_mut().ok_or(CLOSED)?.begin_once(original, &mut self.peer, stream, &mut flight).is_err() {
            self.first = Some(Failure::RootStage);
        }
        if self.first.is_none() {
            self.context = Some(original.peak.begin());
            if !matches!(self.context, Some(Ok(()))) { self.first = Some(Failure::Context); }
        }
        if self.first.is_none() {
            if let Some(Ok(SourceWireRequestV1::CurrentCut(bytes))) = &self.decoded {
                // This is the SAME actual Root stream that passed the retained
                // stage's PID1, image, unit, cgroup and peer checks. No RootOpen
                // field is a substitute for that native authenticated original.
                self.current_peer = Some((|| {
                    let query = SourceCurrentQueryDataV1::decode(bytes).map_err(io::Error::other)?;
                    let root = query.root_body().map_err(io::Error::other)?;
                    let peer = stream.peer().credentials();
                    if root.root_pid != peer.pid().get() || root.controller_uid != original.controller_uid
                        || root.controller_gid != peer.gid() {
                        return Err(io::Error::other("Source current query differs from original Root peer"));
                    }
                    Ok(())
                })());
                if !matches!(self.current_peer, Some(Ok(()))) { self.first = Some(Failure::Context); }
                if self.first.is_none() {
                    // Fixed format geometry was admitted in SourceServing
                    // before connection construction. This same canonical pair
                    // is DATA for Native replay; it never authorizes an append.
                    self.current_expected = Some((|| {
                        let query = SourceCurrentQueryDataV1::decode(bytes).map_err(|_| JournalError::ProtectedBoundary)?;
                        let root = query.root_body().map_err(|_| JournalError::ProtectedBoundary)?;
                        let receipt = query.source_receipt().map_err(|_| JournalError::ProtectedBoundary)?;
                        prepare_history_pair_v1(
                            KeyV1::new(root.open.lane, OwnerV1::Source, 1).map_err(|_| JournalError::ProtectedBoundary)?,
                            PhaseV1::new(OwnerV1::Source, 1).map_err(|_| JournalError::ProtectedBoundary)?,
                            receipt.record, &receipt.latest_head,
                        )
                    })());
                    if !matches!(self.current_expected, Some(Ok(_))) { self.first = Some(Failure::Context); }
                }
            }
        }
        if self.first.is_none() {
            // Only the real Original constructs this typed context after its
            // full F3/profile/executable/hard-limit checks and current sample.
            let controller_uid = original.controller_uid;
            match original.borrow_readonly_context() {
                Ok(mut context) => {
                    if let Some(Ok(request)) = &self.decoded {
                        if let SourceWireRequestV1::CurrentCut(bytes) = request {
                            // Only fixed coordinate DATA leaves this pure
                            // decoder. The real mutable progress borrow starts
                            // below, outside a closure, and stays on this same
                            // checked Source context through actual replay.
                            let coordinates = SourceCurrentQueryDataV1::decode(bytes).and_then(|query| {
                                let root = query.root_body()?;
                                let receipt = query.source_receipt()?;
                                let source = receipt.body(root.open.lane)?;
                                Ok((source.source_before_next, source.source_before_end,
                                    receipt.source_after_next, receipt.source_after_end))
                            });
                            self.current_attachment = Some(match (
                                self.current_expected.as_ref().and_then(|result| result.as_ref().ok()), coordinates,
                            ) {
                                (Some(expected), Ok((before_next, before_end, after_next, after_end))) => {
                                    match HistoryPairNativeSuffixV1::new(expected, &mut self.current_suffix,
                                        before_next, before_end, after_next, after_end) {
                                        Ok(suffix) => context.attach_current_query_once(suffix, bytes),
                                        Err(_) => Err(CLOSED),
                                    }
                                }
                                _ => Err(CLOSED),
                            });
                            if !matches!(self.current_attachment, Some(Ok(()))) { self.first = Some(Failure::Context); }
                        }
                        if self.first.is_none() {
                            self.observed = Some(self.view.observe_once(&mut context, request.request(),
                                controller_uid, generation, key));
                        }
                        if !matches!(self.observed, Some(Ok(()))) { self.first.get_or_insert(Failure::View); }
                    } else {
                        self.first = Some(Failure::Context);
                    }
                }
                Err(_) => { self.first = Some(Failure::Context); }
            }
        }
        if self.stage.as_mut().ok_or(CLOSED)?.finish_once(original, &mut self.peer, stream).is_err() {
            self.first.get_or_insert(Failure::RootStage);
        }
        if self.first.is_some() { return Err(CLOSED); }
        drop(self.stage.take());
        flight.finish_positive_observation();
        Ok(())
    }

    fn send_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        lifetime: ObserverLifetime,
    ) -> Result<(), SourceReceivingClosedV1> {
        operation.begin_after_positive_disposal()?;
        let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
        self.stage = Some(SourceStageSampleV1::new(lifetime));
        let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.stage.as_mut().ok_or(CLOSED)?.begin_once(original, &mut self.peer, stream, &mut flight).is_err() {
            self.first = Some(Failure::RootStage);
        }
        if self.first.is_none() {
            self.framing = Some((|| {
                let request = self.decoded.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or_else(|| io::Error::other("missing request"))?;
                let body = self.view.reply_data().ok_or_else(|| io::Error::other("missing Source reply"))?;
                let width = body.len().checked_add(8).filter(|width| *width <= self.reply.len())
                    .ok_or_else(|| io::Error::other("oversized Source reply"))?;
                self.reply[..8].copy_from_slice(request.reply_magic());
                self.reply[8..width].copy_from_slice(body);
                Ok(width)
            })());
            if !matches!(self.framing, Some(Ok(_))) { self.first = Some(Failure::Framing); }
        }
        if let Some(Ok(width)) = self.framing {
            self.send_reservation = Some(self.sends.try_reserve_exact(width));
            if !matches!(self.send_reservation, Some(Ok(()))) { self.first.get_or_insert(Failure::Send); }
            let mut offset = 0;
            while self.first.is_none() && offset < width {
                // Every successful iteration sends at least one byte, so the
                // prepaid width bounds the complete retained Result vector.
                self.sends.push(rustix::net::send(stream.as_fd(), &self.reply[offset..width], rustix::net::SendFlags::NOSIGNAL));
                match self.sends.last() {
                    Some(Ok(sent)) if *sent > 0 && *sent <= width - offset => offset += sent,
                    _ => { self.first.get_or_insert(Failure::Send); }
                }
            }
        }
        // View name/mount posts run after either actual send outcome. The
        // actual signed result, EOF and all partial send Results stay resident.
        self.response_post = Some(self.view.recheck_after_response_once());
        if !matches!(self.response_post, Some(Ok(()))) { self.first.get_or_insert(Failure::ResponsePost); }
        if self.stage.as_mut().ok_or(CLOSED)?.finish_once(original, &mut self.peer, stream).is_err() {
            self.first.get_or_insert(Failure::RootStage);
        }
        if self.first.is_some() { return Err(CLOSED); }
        drop(self.stage.take());
        flight.finish_positive_observation();
        Ok(())
    }

    fn shutdown_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        operation: &mut SourceOperationV1,
        lifetime: ObserverLifetime,
    ) -> Result<(), SourceReceivingClosedV1> {
        operation.begin_after_positive_disposal()?;
        let mut flight = operation.flight_mut()?.borrow_once().map_err(|_| CLOSED)?;
        self.stage = Some(SourceStageSampleV1::new(lifetime));
        let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        if self.stage.as_mut().ok_or(CLOSED)?.begin_once(original, &mut self.peer, stream, &mut flight).is_err() {
            self.first = Some(Failure::RootStage);
        }
        if self.first.is_none() {
            self.shutdown = Some(rustix::net::shutdown(stream.as_fd(), rustix::net::Shutdown::Write));
            if !matches!(self.shutdown, Some(Ok(()))) { self.first = Some(Failure::Shutdown); }
        }
        self.shutdown_post = Some(self.view.recheck_after_shutdown_once());
        if !matches!(self.shutdown_post, Some(Ok(()))) { self.first.get_or_insert(Failure::ShutdownPost); }
        if self.stage.as_mut().ok_or(CLOSED)?.finish_once(original, &mut self.peer, stream).is_err() {
            self.first.get_or_insert(Failure::RootStage);
        }
        if !self.view.complete_observation_positive() { self.first.get_or_insert(Failure::ShutdownPost); }
        if self.first.is_some() { return Err(CLOSED); }
        drop(self.stage.take());
        flight.finish_positive_observation();
        Ok(())
    }

    pub(super) fn positive(&self) -> bool { self.complete && self.first.is_none() }

    fn close(&mut self) -> Result<(), SourceReceivingClosedV1> {
        self.first.get_or_insert(Failure::Closed);
        Err(CLOSED)
    }

    pub(super) fn failure<'a>(
        &'a self,
        inputs: &'a crate::signer::root_observation::SourceRootPeerInputsV1,
        ledger: &'a dyn aos_sandbox_broker::receiving::RepresentationDemandDebitV1,
        peak: &'a super::super::readonly::SourceReadonlyPeakV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        let cause = match self.first? {
            Failure::AcceptBefore => self.accept_sample.as_ref().and_then(SourceAcceptSampleV1::before_failure),
            Failure::Accept => super::failure(&self.accepted),
            Failure::Adoption => super::failure(&self.stream),
            Failure::Subject => super::failure(&self.subject),
            Failure::Timeout => super::failure(&self.read_timeout).or_else(|| super::failure(&self.write_timeout)),
            Failure::AcceptAfter => self.accept_sample.as_ref().and_then(SourceAcceptSampleV1::after_failure),
            Failure::RootStage => self.stage.as_ref().and_then(|stage| stage.failure(inputs, &self.peer)),
            Failure::Buffer => super::failure(&self.selector_preparation).or_else(|| super::failure(&self.tail_preparation)),
            Failure::Chunk => self.chunk.as_ref().and_then(|chunk| chunk.failure(
                if self.selector.completed_exact() { &self.tail } else { &self.selector })),
            Failure::Width => super::failure(&self.width),
            Failure::EofPoll => super::failure(&self.eof_deadline).or_else(|| super::failure(&self.eof_poll)),
            Failure::Eof => super::failure(&self.eof),
            Failure::Decode => super::failure(&self.decoded),
            Failure::Context | Failure::View => ledger.failure().map(|error| error as _)
                .or_else(|| peak.failure().map(|error| error as _))
                .or_else(|| self.current_peer.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.current_expected.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
                .or_else(|| self.current_suffix.failure().map(|error| error as _))
                .or_else(|| self.view.failure()).or_else(|| super::failure(&self.context)),
            Failure::Framing => super::failure(&self.framing),
            Failure::Send => super::failure(&self.send_reservation)
                .or_else(|| self.sends.iter().find_map(|result| result.as_ref().err().map(|error| error as _))),
            Failure::ResponsePost | Failure::ShutdownPost => self.view.failure(),
            Failure::Shutdown => super::failure(&self.shutdown),
            Failure::Closed => None,
        };
        cause.or(Some(&CLOSED))
    }
}

// The sole passive constructor is shared with every real native history owner.
fn prepare_history_pair_v1(
    key: KeyV1, phase: PhaseV1, record: &[u8],
    head: &[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::HEAD_BYTES],
) -> Result<JournalTransaction, JournalError> {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1;

    aos_sandbox_protocol::domain_ledger::create_storage_history::prepare_history_pair_v1(
        key, phase, record, head,
    ).map_err(|cause| match cause {
        HistoryPairPreparationErrorV1::Envelope => JournalError::ProtectedBoundary,
        HistoryPairPreparationErrorV1::Transaction(cause) => JournalError::from(cause),
    })
}
