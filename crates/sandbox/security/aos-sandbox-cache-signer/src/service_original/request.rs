//! Retains the actual accepted fixed-purpose request and kernel task subjects.
//!
//! This child is private to Cache's genuine F owner. Root and Controller are
//! fixed recipes selected by that owner, never public UID/path/role factories.
//! Each positive chunk finishes its native task/endpoint/deadline leaf before
//! temporary custody is dropped; the first task anchor and cumulative bytes
//! remain through the complete signing purpose and independent outer posts.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_broker::cache_current_signer_exchange::CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1;
use aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1;
use aos_sandbox_broker::fixed_stream_readiness::FixedStreamReadinessOriginalV1;
use aos_sandbox_broker::fixed_task_subject::{
    FixedTaskSubjectClosedV1, FixedTaskSubjectOriginalsV1,
};
use aos_sandbox_broker::receiving::FixedSignerListenerOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStreamAdmissionErrorV1;
use aos_sandbox_linux::unix_stream::RetainedUnixStreamSubjectReceiveErrorV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectEofReadbackV1;
use rustix::time::{ClockId, Timespec, clock_gettime};

use super::CacheSignerReceivingClosedV1 as Closed;

impl From<FixedTaskSubjectClosedV1> for Closed {
    fn from(_: FixedTaskSubjectClosedV1) -> Self {
        Self
    }
}

type Subject = FixedTaskSubjectOriginalsV1<Closed>;

#[derive(Clone, Copy)]
enum RequestRole {
    Root { group: u32 },
    Controller { user: u32, group: u32 },
}

/// Separates the three existing installed wire purposes as comparison DATA.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CacheRequestKindV1 {
    Diagnostic,
    Q04,
    Current,
}

#[derive(Clone, Copy)]
enum First {
    Order,
    ListenerReadiness,
    Accept,
    Admission,
    Inherited,
    Preparation,
    Before,
    Readiness,
    Receive,
    ReceiveDeadline,
    Subject,
    Sender,
    Copy,
    After,
    Deadline,
    Framing,
    AcceptDeadline,
    EofReadiness,
    Eof,
    EofDeadline,
    FinalSubject,
    FinalOriginal,
    FinalDeadline,
}

struct Anchor {
    chunk: UnixStreamSubjectChunk,
    subject: Subject,
    identity: PidFdProcessIdentity,
}

pub(super) struct CacheCurrentRequestOriginalV1 {
    accepted: Option<rustix::io::Result<Option<OwnedFd>>>,
    listener_clock: Option<Timespec>,
    listener_timeout: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    listener_poll: Option<rustix::io::Result<(usize, rustix::event::PollFlags)>>,
    listener_after_clock: Option<Timespec>,
    listener_after_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    listener_completion: Option<Result<(), Closed>>,
    role: Option<RequestRole>,
    accept_clock: Option<Timespec>,
    accept_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    stream: Option<Result<RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1>>,
    inherited: Option<Result<(), SeqpacketError>>,
    reads: [RetainedSubjectStreamReadV1; 2],
    prepared: [Option<Result<(), SubjectStreamReadErrorV1>>; 2],
    buffer: usize,
    frame: [u8; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1],
    kind: Option<CacheRequestKindV1>,
    framing: Option<Result<(), Closed>>,
    before: Option<Result<(), aos_linux_descriptors::Error>>,
    readiness: Option<FixedStreamReadinessOriginalV1>,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    receive_clock: Option<Timespec>,
    receive_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    subject: Option<Subject>,
    subject_result: Option<Result<(), Closed>>,
    sender: Option<Result<(), Closed>>,
    copied: Option<Result<(), SubjectStreamReadErrorV1>>,
    after: Option<Result<(), aos_linux_descriptors::Error>>,
    after_clock: Option<Timespec>,
    after_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    anchor: Option<Anchor>,
    eof_readiness: Option<FixedStreamReadinessOriginalV1>,
    eof: Option<Result<UnixStreamSubjectEofReadbackV1, RetainedUnixStreamSubjectReceiveErrorV1>>,
    eof_clock: Option<Timespec>,
    eof_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    final_subject: Option<Subject>,
    final_subject_result: Option<Result<(), Closed>>,
    final_original: Option<Result<(), aos_linux_descriptors::Error>>,
    final_clock: Option<Timespec>,
    final_deadline: Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    finalized: bool,
    first: Option<First>,
    complete: bool,
}

impl CacheCurrentRequestOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            accepted: None,
            listener_clock: None,
            listener_timeout: None,
            listener_poll: None,
            listener_after_clock: None,
            listener_after_deadline: None,
            listener_completion: None,
            role: None,
            accept_clock: None,
            accept_deadline: None,
            stream: None,
            inherited: None,
            reads: std::array::from_fn(|_| RetainedSubjectStreamReadV1::new()),
            prepared: [None, None],
            buffer: 0,
            frame: [0; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1],
            kind: None,
            framing: None,
            before: None,
            readiness: None,
            received: None,
            receive_clock: None,
            receive_deadline: None,
            subject: None,
            subject_result: None,
            sender: None,
            copied: None,
            after: None,
            after_clock: None,
            after_deadline: None,
            anchor: None,
            eof_readiness: None,
            eof: None,
            eof_clock: None,
            eof_deadline: None,
            final_subject: None,
            final_subject_result: None,
            final_original: None,
            final_clock: None,
            final_deadline: None,
            finalized: false,
            first: None,
            complete: false,
        }
    }

    // The purpose prepays this complete native peak before accept/allocation.
    // Endpoint admission, first anchor, one later active chunk and the actual
    // native task before/after scratch can coexist on a negative leaf.
    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        let geometry = SubjectStreamReceiveGeometryV1::for_context_bytes(255).ok()?;
        let (chunk_bytes, chunk_files) = geometry.receive_obligations_v1();
        let (eof_bytes, eof_files) = geometry.eof_receive_obligations_v1();
        let (admission_bytes, admission_files) =
            RetainedUnixStream::retained_admission_obligations_v1();
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<FixedStreamReadinessOriginalV1>())?
            .checked_add(admission_bytes)?
            .checked_add(chunk_bytes.max(eof_bytes))?
            .checked_add(CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1.checked_mul(3)?)?
            .checked_add(256)?;
        // One failed raw receive/EOF namespace, not a second hypothetical
        // namespace on the already-complete first anchor. The final task
        // sample can coexist with a failed active native leaf.
        let files = admission_files.max(chunk_files.max(eof_files).checked_add(2 + 3 + 2 + 2)?);
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            // Both exact buffers together consume at most the complete fixed
            // challenge; the hostile EOF check can additionally consume one.
            .with(
                D::NetworkBytes,
                u64::try_from(CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1.checked_add(1)?).ok()?,
            )
            .checked_add(
                Subject::receiving_demand_v1()?
                    .checked_add(Subject::receiving_demand_v1()?)
                    .ok()?
                    .checked_add(Subject::receiving_demand_v1()?)
                    .ok()?,
            )
            .ok()
    }

    pub(super) fn accept_root_once(
        &mut self,
        listener: &FixedSignerListenerOriginalV1,
        root_group: u32,
        cutoff: u64,
    ) -> Result<(), Closed> {
        self.accept_once(listener, RequestRole::Root { group: root_group }, cutoff)
    }

    pub(super) fn accept_controller_once(
        &mut self,
        listener: &FixedSignerListenerOriginalV1,
        controller_user: u32,
        controller_group: u32,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.role.is_some() || self.listener_clock.is_some() {
            return self.refuse(First::Order);
        }
        let now = clock_gettime(ClockId::Boottime);
        self.listener_clock = Some(now);
        self.listener_timeout = Some(deadline_timeout_v1(now, cutoff));
        if let Some(Ok(timeout)) = self.listener_timeout.as_ref() {
            self.listener_poll = Some(listener.poll_once(timeout));
            capture_deadline(
                &mut self.listener_after_clock,
                &mut self.listener_after_deadline,
                cutoff,
            );
        }
        self.listener_completion = Some(
            if matches!(self.listener_poll, Some(Ok((count, flags)))
            if count != 0 && flags.contains(rustix::event::PollFlags::IN)
                && !flags.contains(rustix::event::PollFlags::NVAL))
                && matches!(self.listener_after_deadline, Some(Ok(_)))
            {
                Ok(())
            } else {
                Err(Closed)
            },
        );
        if !matches!(self.listener_completion, Some(Ok(()))) {
            return self.refuse(First::ListenerReadiness);
        }
        self.accept_once(
            listener,
            RequestRole::Controller {
                user: controller_user,
                group: controller_group,
            },
            cutoff,
        )
    }

    fn accept_once(
        &mut self,
        listener: &FixedSignerListenerOriginalV1,
        role: RequestRole,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.role.is_some() {
            return self.refuse(First::Order);
        }
        self.role = Some(role);
        capture_deadline(&mut self.accept_clock, &mut self.accept_deadline, cutoff);
        if !matches!(self.accept_deadline, Some(Ok(_))) {
            return self.refuse(First::AcceptDeadline);
        }
        // The inherited listener is already nonblocking; accept4 also fixes
        // NONBLOCK|CLOEXEC on the actual returned endpoint before adoption.
        self.accepted = Some(listener.accept_cache_once().map(Some));
        let original = match self.accepted.as_mut() {
            Some(Ok(original)) => original.take().ok_or(Closed)?,
            _ => return self.refuse(First::Accept),
        };
        self.stream = Some(RetainedUnixStream::from_owned_retaining_v1(original));
        if !matches!(self.stream, Some(Ok(_))) {
            return self.refuse(First::Admission);
        }
        self.inherited = Some(self.stream_mut()?.require_inherited_subject_reporting_v1().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from));
        if !matches!(self.inherited, Some(Ok(()))) {
            return self.refuse(First::Inherited);
        }
        self.prepared[0] = Some(self.reads[0].prepare_exact_once(8));
        if !matches!(self.prepared[0], Some(Ok(()))) {
            return self.refuse(First::Preparation);
        }
        self.receive_request(role, cutoff)
    }

    fn receive_request(&mut self, role: RequestRole, cutoff: u64) -> Result<(), Closed> {
        let geometry =
            SubjectStreamReceiveGeometryV1::for_context_bytes(255).map_err(|_| Closed)?;
        while !self.reads[self.buffer].completed_exact() && self.first.is_none() {
            self.before = Some(self.stream()?.revalidate_original());
            if !matches!(self.before, Some(Ok(()))) {
                self.first = Some(First::Before);
            }
            if self.first.is_none() {
                self.readiness = Some(Default::default());
                let stream = self
                    .stream
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(Closed)?;
                if self
                    .readiness
                    .as_mut()
                    .ok_or(Closed)?
                    .observe_readable_once(stream, cutoff)
                    .is_err()
                {
                    self.first = Some(First::Readiness);
                }
            }
            if self.first.is_none() {
                let stream = self
                    .stream
                    .as_mut()
                    .and_then(|result| result.as_mut().ok())
                    .ok_or(Closed)?;
                self.received = Some(
                    self.reads[self.buffer].receive_next_with_geometry_once(stream, &geometry),
                );
                if !matches!(self.received, Some(Ok(()))) {
                    self.first = Some(First::Receive);
                }
                capture_deadline(&mut self.receive_clock, &mut self.receive_deadline, cutoff);
                if !matches!(self.receive_deadline, Some(Ok(_))) {
                    self.first.get_or_insert(First::ReceiveDeadline);
                }
            }
            if self.first.is_none() {
                self.subject = Some(Subject::new());
                let chunk = self.reads[self.buffer]
                    .pending_chunk()
                    .map_err(|_| Closed)?;
                let anchor = self
                    .anchor
                    .as_ref()
                    .map(|anchor| (&anchor.chunk, anchor.identity));
                let subject = self.subject.as_mut().ok_or(Closed)?;
                self.subject_result = Some(match role {
                    RequestRole::Root { group } => {
                        subject.observe_root_request_once(chunk, anchor, group)
                    }
                    RequestRole::Controller { user, group } => {
                        subject.observe_controller_request_once(chunk, anchor, user, group)
                    }
                });
                if !matches!(self.subject_result, Some(Ok(()))) {
                    self.first = Some(First::Subject);
                }
                self.sender = Some(self.compare_connection_sender(role));
                if !matches!(self.sender, Some(Ok(()))) {
                    self.first.get_or_insert(First::Sender);
                }
            }
            if self.first.is_none() {
                self.copied = Some(self.reads[self.buffer].append_pending_payload_once());
                if !matches!(self.copied, Some(Ok(()))) {
                    self.first = Some(First::Copy);
                }
            }
            // This actual endpoint post and late-clock refusal precede every
            // positive local take/drop, independently of earlier leaf failure.
            self.after = Some(self.stream()?.revalidate_original());
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
            capture_deadline(&mut self.after_clock, &mut self.after_deadline, cutoff);
            if !matches!(self.after_deadline, Some(Ok(_))) {
                self.first.get_or_insert(First::Deadline);
            }
            if self.first.is_some() {
                return Err(Closed);
            }

            let chunk = self.reads[self.buffer]
                .take_copied_chunk_once()
                .map_err(|_| Closed)?;
            let subject = self.subject.take().ok_or(Closed)?;
            if self.anchor.is_none() {
                let identity = subject.identity().ok_or(Closed)?;
                self.anchor = Some(Anchor {
                    chunk,
                    subject,
                    identity,
                });
            } else {
                drop(subject);
                drop(chunk);
            }
            self.before = None;
            self.readiness = None;
            self.received = None;
            self.receive_clock = None;
            self.receive_deadline = None;
            self.subject_result = None;
            self.sender = None;
            self.copied = None;
            self.after = None;
            self.after_clock = None;
            self.after_deadline = None;
        }
        if self.buffer == 0 {
            self.frame[..8].copy_from_slice(self.reads[0].bytes());
            self.framing = Some(self.select_extent(role));
            if !matches!(self.framing, Some(Ok(()))) {
                return self.refuse(First::Framing);
            }
            self.buffer = 1;
            let target = if self.kind == Some(CacheRequestKindV1::Current) {
                CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1 - 8
            } else {
                64 - 8
            };
            self.prepared[1] = Some(self.reads[1].prepare_exact_once(target));
            if !matches!(self.prepared[1], Some(Ok(()))) {
                return self.refuse(First::Preparation);
            }
            return self.receive_request(role, cutoff);
        }
        let end = 8_usize
            .checked_add(self.reads[1].bytes().len())
            .ok_or(Closed)?;
        self.frame[8..end].copy_from_slice(self.reads[1].bytes());
        self.eof_readiness = Some(Default::default());
        let stream = self
            .stream
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed)?;
        if self
            .eof_readiness
            .as_mut()
            .ok_or(Closed)?
            .observe_readable_once(stream, cutoff)
            .is_err()
        {
            return self.refuse(First::EofReadiness);
        }
        self.eof = Some(
            aos_sandbox_linux::unix_stream::try_receive_subject_eof_with_geometry_retaining(self.stream_mut()?, &geometry),
        );
        if !matches!(self.eof, Some(Ok(_))) {
            self.first = Some(First::Eof);
        }
        capture_deadline(&mut self.eof_clock, &mut self.eof_deadline, cutoff);
        if !matches!(self.eof_deadline, Some(Ok(_))) {
            self.first.get_or_insert(First::EofDeadline);
        }
        if self.first.is_some() {
            return Err(Closed);
        }
        self.complete = true;
        Ok(())
    }

    fn select_extent(&mut self, role: RequestRole) -> Result<(), Closed> {
        let magic = &self.frame[..8];
        self.kind = Some(match role {
            RequestRole::Root { .. } if magic == b"AOSCSR02" => CacheRequestKindV1::Diagnostic,
            RequestRole::Root { .. } if magic == b"AOSCSR03" => CacheRequestKindV1::Q04,
            RequestRole::Root { .. } if magic == b"AOSXKR01" => CacheRequestKindV1::Current,
            RequestRole::Controller { .. } if magic == b"AOSCSC02" => {
                CacheRequestKindV1::Diagnostic
            }
            RequestRole::Controller { .. } if magic == b"AOSCSC03" => CacheRequestKindV1::Q04,
            RequestRole::Controller { .. } if magic == b"AOSXKJ01" => CacheRequestKindV1::Current,
            _ => return Err(Closed),
        });
        Ok(())
    }

    // The entered service purpose calls this after its body and sends even on
    // failure. It accepts no body-result Boolean or disposal certificate.
    pub(super) fn finish_native_posts_once(&mut self, cutoff: u64) -> Result<(), Closed> {
        if self.finalized {
            return self.refuse(First::Order);
        }
        self.finalized = true;
        let role = self.role.ok_or(Closed)?;
        let anchor = self.anchor.as_ref();
        let chunk = anchor
            .map(|anchor| &anchor.chunk)
            .or_else(|| self.reads[self.buffer].pending_chunk().ok());
        if let Some(chunk) = chunk {
            self.final_subject = Some(Subject::new());
            let original_anchor = anchor.map(|anchor| (&anchor.chunk, anchor.identity));
            let subject = self.final_subject.as_mut().ok_or(Closed)?;
            self.final_subject_result = Some(match role {
                RequestRole::Root { group } => {
                    subject.observe_root_request_once(chunk, original_anchor, group)
                }
                RequestRole::Controller { user, group } => {
                    subject.observe_controller_request_once(chunk, original_anchor, user, group)
                }
            });
            if !matches!(self.final_subject_result, Some(Ok(()))) {
                self.first.get_or_insert(First::FinalSubject);
            }
        }
        if let Some(Ok(stream)) = self.stream.as_ref() {
            self.final_original = Some(stream.revalidate_original());
            if !matches!(self.final_original, Some(Ok(()))) {
                self.first.get_or_insert(First::FinalOriginal);
            }
        }
        capture_deadline(&mut self.final_clock, &mut self.final_deadline, cutoff);
        if !matches!(self.final_deadline, Some(Ok(_))) {
            self.first.get_or_insert(First::FinalDeadline);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    fn compare_connection_sender(&self, role: RequestRole) -> Result<(), Closed> {
        let stream = self.stream()?;
        let chunk = self.reads[self.buffer]
            .pending_chunk()
            .map_err(|_| Closed)?;
        let peer = stream.peer().credentials();
        let sender = chunk.subject();
        let expected = match role {
            RequestRole::Root { .. } => {
                aos_sandbox_broker::profile_data::schema::CONTEXT.as_bytes()
            }
            RequestRole::Controller { .. } => {
                aos_sandbox_broker::profile_data::delivery::CONTEXT.as_bytes()
            }
        };
        if sender.credentials().pid() != peer.pid()
            || sender.credentials().uid() != peer.uid()
            || sender.credentials().gid() != peer.gid()
            || !exact_context(chunk.socket_context(), expected)
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn stream(&self) -> Result<&RetainedUnixStream, Closed> {
        self.stream
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed)
    }

    fn stream_mut(&mut self) -> Result<&mut RetainedUnixStream, Closed> {
        self.stream
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(Closed)
    }

    pub(super) fn bytes(&self) -> Result<&[u8; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1], Closed> {
        if !self.complete || self.first.is_some() {
            return Err(Closed);
        }
        if self.kind != Some(CacheRequestKindV1::Current) {
            return Err(Closed);
        }
        Ok(&self.frame)
    }

    pub(super) fn legacy_frame(&self) -> Result<&[u8; 64], Closed> {
        if !self.complete || self.first.is_some() || self.kind == Some(CacheRequestKindV1::Current)
        {
            return Err(Closed);
        }
        self.frame[..64].try_into().map_err(|_| Closed)
    }

    pub(super) fn kind(&self) -> Result<CacheRequestKindV1, Closed> {
        if !self.complete || self.first.is_some() {
            return Err(Closed);
        }
        self.kind.ok_or(Closed)
    }

    fn refuse(&mut self, stage: First) -> Result<(), Closed> {
        self.first.get_or_insert(stage);
        Err(Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::ListenerReadiness => cause(&self.listener_timeout)
                .or_else(|| cause(&self.listener_poll))
                .or_else(|| cause(&self.listener_after_deadline))
                .or_else(|| cause(&self.listener_completion)),
            First::Order => Some(&Closed),
            First::Accept => cause(&self.accepted),
            First::Admission => self
                .stream
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Inherited => cause(&self.inherited),
            First::Preparation | First::Receive | First::Copy => self.reads[self.buffer].failure(),
            First::Framing => cause(&self.framing),
            First::Before => cause(&self.before),
            First::Readiness => self
                .readiness
                .as_ref()
                .and_then(FixedStreamReadinessOriginalV1::failure),
            First::ReceiveDeadline => cause(&self.receive_deadline),
            First::Subject => self.subject.as_ref().and_then(Subject::failure),
            First::Sender => cause(&self.sender),
            First::After => cause(&self.after),
            First::Deadline => cause(&self.after_deadline),
            First::AcceptDeadline => cause(&self.accept_deadline),
            First::EofReadiness => self
                .eof_readiness
                .as_ref()
                .and_then(FixedStreamReadinessOriginalV1::failure),
            First::Eof => cause(&self.eof),
            First::EofDeadline => cause(&self.eof_deadline),
            First::FinalSubject => self
                .final_subject
                .as_ref()
                .and_then(Subject::failure)
                .or_else(|| cause(&self.final_subject_result)),
            First::FinalOriginal => cause(&self.final_original),
            First::FinalDeadline => cause(&self.final_deadline),
        }
    }
}

fn capture_deadline(
    clock: &mut Option<Timespec>,
    outcome: &mut Option<
        Result<
            Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    cutoff: u64,
) {
    let now = clock_gettime(ClockId::Boottime);
    *clock = Some(now);
    *outcome = Some(deadline_timeout_v1(now, cutoff));
}

fn exact_context(actual: &[u8], expected: &[u8]) -> bool {
    actual == expected
        || actual.strip_suffix(b"\n") == Some(expected)
        || actual.strip_suffix(b"\0") == Some(expected)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}
