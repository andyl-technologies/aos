//! Retains the fixed Root-first Cache CurrentProofs transport.
//!
//! A root begin writes its complete challenge and returns before waiting for
//! Controller. A later finish retains exact reply bytes, actual signer task
//! subject and EOF. This is native transport DATA: purpose admission, genuine
//! Cache snapshot/signing and independent Root/J/Cache posts stay above it.
//!
//! ```text
//! challenge = role_magic[8] | RootHello[612] | CacheHeld[1052]
//! reply = signed_cache_current_packet[1064] | EOF
//! ```

use std::error::Error;

use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1,
    RetainedUnixStreamSubjectReceiveErrorV1, SubjectStreamReadErrorV1,
    SubjectStreamReceiveGeometryV1, UnixStreamSubjectEofReadbackV1,
};
use rustix::event::PollFd;
use rustix::time::{ClockId, Timespec, clock_gettime};

use crate::cache_signer_connection::CacheSignerConnectionOriginalsV1;

mod subject;
use subject::{SignerAnchorV1, SignerSubjectOriginalsV1};

/// Gives the exact fixed request extent before allocation or native entry.
pub const CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1: usize = 1672;
/// Gives the exact fixed signed reply extent before native receive.
pub const CACHE_CURRENT_SIGNER_PACKET_BYTES_V1: usize = 1064;

/// Classifies a retained transport refusal without replacing its original cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum CacheCurrentSignerExchangeClosedV1 {
    /// The actual once-only native action is out of order.
    #[error("Cache current signer exchange action is out of order")]
    Order,
    /// The native owner retains an earlier original refusal.
    #[error("Cache current signer exchange retains an earlier refusal")]
    Retained,
    /// The actual sender task does not match the configured signer or anchor.
    #[error("Cache current signer reply subject changed")]
    Subject,
    /// The actual deadline or native readiness observation refused entry.
    #[error("Cache current signer exchange deadline expired")]
    Deadline,
    /// Native send did not make positive bounded progress.
    #[error("Cache current signer send made invalid progress")]
    Write,
    /// Reached framing exceeds the exact compiled extent.
    #[error("Cache current signer reply has invalid extent")]
    Extent,
}
use CacheCurrentSignerExchangeClosedV1 as Closed;

use crate::fixed_stream_readiness::FixedStreamReadinessOriginalV1 as ReadinessOriginalsV1;

#[derive(Clone, Copy)]
enum Stage {
    Connection,
    Admission,
    Activation,
    Preparation,
    BeginBefore,
    WriteWait,
    Write,
    WriteProgress,
    WriteDeadline,
    Shutdown,
    BeginAfter,
    BeginDeadline,
    ReadBefore,
    ReadWait,
    Receive,
    ReceiveDeadline,
    Subject,
    SubjectDeadline,
    Copy,
    ReadAfter,
    ReadDeadline,
    EofWait,
    Eof,
    EofDeadline,
    FinalSubject,
    Final,
    FinalDeadline,
    Order,

}

/// Retains an actual Root or Controller signer flight and all failed partials.
///
/// It accepts comparison DATA and a compiled fixed socket only. No method
/// creates a service purpose, signs bytes, validates a signature or authorizes
/// a Root transition. The actual owner prepays its complete simultaneous peak
/// and keeps this carrier through its independent purpose-specific posts.
#[must_use = "keep signer native custody through all independent purpose posts"]
pub struct CacheCurrentSignerExchangeOriginalsV1 {
    connection: CacheSignerConnectionOriginalsV1,
    stream: Option<Result<RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1>>,
    activation: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    request: [u8; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1],
    sender: Option<(u32, u32)>,
    begin_before: Option<Result<(), aos_sandbox_linux::Error>>,
    write_wait: Option<ReadinessOriginalsV1>,
    write: Option<rustix::io::Result<usize>>,
    write_progress: Option<Result<(), Closed>>,
    write_clock: Option<Timespec>,
    write_deadline: Option<Result<Timespec, Closed>>,
    sent: usize,
    shutdown: Option<rustix::io::Result<()>>,
    begin_after: Option<Result<(), aos_sandbox_linux::Error>>,
    begin_clock: Option<Timespec>,
    begin_deadline: Option<Result<Timespec, Closed>>,
    read: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    read_before: Option<Result<(), aos_sandbox_linux::Error>>,
    read_wait: Option<ReadinessOriginalsV1>,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    receive_clock: Option<Timespec>,
    receive_deadline: Option<Result<Timespec, Closed>>,
    subject: Option<SignerSubjectOriginalsV1>,
    subject_result: Option<Result<(), Closed>>,
    subject_clock: Option<Timespec>,
    subject_deadline: Option<Result<Timespec, Closed>>,
    copied: Option<Result<(), SubjectStreamReadErrorV1>>,
    read_after: Option<Result<(), aos_sandbox_linux::Error>>,
    read_clock: Option<Timespec>,
    read_deadline: Option<Result<Timespec, Closed>>,
    anchor: Option<SignerAnchorV1>,
    eof_wait: Option<ReadinessOriginalsV1>,
    eof: Option<Result<UnixStreamSubjectEofReadbackV1, RetainedUnixStreamSubjectReceiveErrorV1>>,
    eof_clock: Option<Timespec>,
    eof_deadline: Option<Result<Timespec, Closed>>,
    final_subject: Option<SignerSubjectOriginalsV1>,
    final_subject_result: Option<Result<(), Closed>>,
    final_original: Option<Result<(), aos_sandbox_linux::Error>>,
    final_clock: Option<Timespec>,
    final_deadline: Option<Result<Timespec, Closed>>,
    first: Option<Stage>,
    closed: Option<Closed>,
    entered: bool,
    begun: bool,
    finished: bool,
    cutoff: Option<u64>,
}

impl CacheCurrentSignerExchangeOriginalsV1 {
    /// Creates an inert fixed request reservoir and native Result destinations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connection: CacheSignerConnectionOriginalsV1::new(),
            stream: None,
            activation: None,
            request: [0; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1],
            sender: None,
            begin_before: None,
            write_wait: None,
            write: None,
            write_progress: None,
            write_clock: None,
            write_deadline: None,
            sent: 0,
            shutdown: None,
            begin_after: None,
            begin_clock: None,
            begin_deadline: None,
            read: RetainedSubjectStreamReadV1::new(),
            preparation: None,
            read_before: None,
            read_wait: None,
            received: None,
            receive_clock: None,
            receive_deadline: None,
            subject: None,
            subject_result: None,
            subject_clock: None,
            subject_deadline: None,
            copied: None,
            read_after: None,
            read_clock: None,
            read_deadline: None,
            anchor: None,
            eof_wait: None,
            eof: None,
            eof_clock: None,
            eof_deadline: None,
            final_subject: None,
            final_subject_result: None,
            final_original: None,
            final_clock: None,
            final_deadline: None,
            first: None,
            closed: None,
            entered: false,
            begun: false,
            finished: false,
            cutoff: None,
        }
    }

    /// Sends the Root half and returns before waiting for Controller or a reply.
    ///
    /// Signer task GID is distinct from the Controller-owned socket node GID.
    /// The caller supplies its actual authenticated Hello/Held originals and
    /// genuine original cutoff; these borrowed bytes alone confer no purpose.
    ///
    /// # Errors
    /// Keeps every entered connection, admission, option, write and native post
    /// failure. Reentry closes without overwriting the original first cause.
    pub fn begin_root_half_once(&mut self, hello: &[u8; 612], held: &[u8; 1052],
        signer_uid: u32, signer_gid: u32, socket_gid: u32, cutoff: u64) -> Result<(), Closed>
    {
        self.begin_once(b"AOSXKR01", hello, held, signer_uid, signer_gid, socket_gid, cutoff)
    }

    /// Sends the matching Controller half only after its genuine invitation.
    ///
    /// # Errors
    /// Retains the same exact connection/send/native failures as the Root half.
    /// This DATA method cannot check or fabricate the caller's invitation grant.
    pub fn begin_controller_half_once(&mut self, hello: &[u8; 612], held: &[u8; 1052],
        signer_uid: u32, signer_gid: u32, socket_gid: u32, cutoff: u64) -> Result<(), Closed>
    {
        self.begin_once(b"AOSXKJ01", hello, held, signer_uid, signer_gid, socket_gid, cutoff)
    }

    fn begin_once(&mut self, magic: &[u8; 8], hello: &[u8; 612], held: &[u8; 1052],
        uid: u32, gid: u32, socket_gid: u32, cutoff: u64) -> Result<(), Closed>
    {
        if self.entered { return self.refuse(Stage::Order, Closed::Order); }
        self.entered = true;
        self.sender = Some((uid, gid));
        self.cutoff = Some(cutoff);
        self.request[..8].copy_from_slice(magic);
        self.request[8..620].copy_from_slice(hello);
        self.request[620..].copy_from_slice(held);
        if gid == 0 || cutoff == 0 { return self.refuse(Stage::Order, Closed::Subject); }
        if self.connection.connect_once(uid, socket_gid, cutoff).is_err() {
            return self.refuse(Stage::Connection, Closed::Retained);
        }
        let stream = self.connection.take_stream_once().map_err(|_| Closed::Retained)?;
        self.stream = Some(RetainedUnixStream::from_owned_retaining_v1(stream.into()));
        if !matches!(self.stream, Some(Ok(_))) { return self.refuse(Stage::Admission, Closed::Retained); }
        self.activation = Some(self.stream_mut()?.enable_subject_reporting());
        if !matches!(self.activation, Some(Ok(()))) { self.first.get_or_insert(Stage::Activation); }
        if self.first.is_none() {
            self.preparation = Some(self.read.prepare_exact_once(CACHE_CURRENT_SIGNER_PACKET_BYTES_V1));
            if !matches!(self.preparation, Some(Ok(()))) { self.first = Some(Stage::Preparation); }
        }
        self.send_prepared_request_once(cutoff)
    }

    fn send_prepared_request_once(&mut self, cutoff: u64) -> Result<(), Closed> {
        if self.first.is_none() {
            self.begin_before = Some(self.stream()?.revalidate_original());
            if !matches!(self.begin_before, Some(Ok(()))) { self.first = Some(Stage::BeginBefore); }
        }
        while self.first.is_none() && self.sent < self.request.len() {
            self.write_wait = Some(Default::default());
            let stream = self.stream.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed::Retained)?;
            if self.write_wait.as_mut().ok_or(Closed::Order)?.observe_writable_once(stream, cutoff).is_err() {
                self.first = Some(Stage::WriteWait);
                break;
            }
            self.write = Some(rustix::net::send(stream.as_fd(), &self.request[self.sent..],
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL));
            self.write_progress = Some(match self.write {
                Some(Ok(count)) if count != 0 && count <= self.request.len() - self.sent => {
                    self.sent += count;
                    Ok(())
                }
                Some(Err(_)) => { self.first = Some(Stage::Write); Err(Closed::Retained) }
                _ => { self.first = Some(Stage::WriteProgress); Err(Closed::Write) }
            });
            capture_deadline(&mut self.write_clock, &mut self.write_deadline, cutoff);
            if !matches!(self.write_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::WriteDeadline); }
            if self.first.is_some() { break; }
            // A positive send has completed its native progress comparison.
            // No fresh descriptors or unresolved independent posts live here.
            self.write_wait = None;
            self.write = None;
            self.write_progress = None;
            self.write_clock = None;
            self.write_deadline = None;
        }
        if self.first.is_none() {
            self.shutdown = Some(rustix::net::shutdown(self.stream()?.as_fd(), rustix::net::Shutdown::Write));
            if !matches!(self.shutdown, Some(Ok(()))) { self.first = Some(Stage::Shutdown); }
        }
        // The same original endpoint post is owed after any entered send or
        // option/preparation failure; it cannot replace the primary cause.
        self.begin_after = Some(self.stream()?.revalidate_original());
        if !matches!(self.begin_after, Some(Ok(()))) { self.first.get_or_insert(Stage::BeginAfter); }
        let now = clock_gettime(ClockId::Boottime);
        self.begin_clock = Some(now);
        self.begin_deadline = Some(crate::cache_signer_connection::deadline_timeout_v1(now, cutoff)
            .map_err(|_| Closed::Deadline));
        if !matches!(self.begin_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::BeginDeadline); }
        if self.first.is_some() { return Err(Closed::Retained); }
        self.begun = true;
        Ok(())
    }

    fn stream(&self) -> Result<&RetainedUnixStream, Closed> {
        self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed::Retained)
    }

    fn stream_mut(&mut self) -> Result<&mut RetainedUnixStream, Closed> {
        self.stream.as_mut().and_then(|result| result.as_mut().ok()).ok_or(Closed::Retained)
    }

    fn refuse(&mut self, stage: Stage, error: Closed) -> Result<(), Closed> {
        self.first.get_or_insert(stage);
        self.closed.get_or_insert(error);
        Err(error)
    }

    /// Receives the exact signed packet after both actual service halves join.
    ///
    /// Each chunk completes its own sender/native/copy/original-post leaf
    /// before positive scratch is reused. The actual first sender anchor,
    /// cumulative bytes and EOF stay resident for the caller's signature and
    /// independent purpose posts. No signature or snapshot is inferred here.
    ///
    /// # Errors
    /// Retains incomplete input, sender changes, native deadline/receive/EOF
    /// failures and every entered independently owed original/sender post.
    pub fn finish_once(&mut self) -> Result<(), Closed> {
        if !self.begun || self.finished || self.first.is_some() {
            return self.refuse(Stage::Order, Closed::Order);
        }
        self.finished = true;
        let cutoff = self.cutoff.ok_or(Closed::Order)?;
        let (uid, gid) = self.sender.ok_or(Closed::Order)?;
        // Socket SID is separately retained comparison DATA. The actual task
        // context is acquired through SCM_PIDFD, not inferred from this SID.
        let geometry = SubjectStreamReceiveGeometryV1::for_context_bytes(255)
            .map_err(|_| Closed::Extent)?;
        while !self.read.completed_exact() && self.first.is_none() {
            self.read_before = Some(self.stream()?.revalidate_original());
            if !matches!(self.read_before, Some(Ok(()))) { self.first = Some(Stage::ReadBefore); }
            if self.first.is_none() {
                self.read_wait = Some(Default::default());
                let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed::Retained)?;
                if self.read_wait.as_mut().ok_or(Closed::Order)?.observe_readable_once(stream, cutoff).is_err() {
                    self.first = Some(Stage::ReadWait);
                }
            }
            if self.first.is_none() {
                let stream = self.stream.as_mut().and_then(|result| result.as_mut().ok()).ok_or(Closed::Retained)?;
                self.received = Some(self.read.receive_next_with_geometry_once(stream, &geometry));
                if !matches!(self.received, Some(Ok(()))) { self.first = Some(Stage::Receive); }
                capture_deadline(&mut self.receive_clock, &mut self.receive_deadline, cutoff);
                if !matches!(self.receive_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::ReceiveDeadline); }
            }
            if self.first.is_none() {
                self.subject = Some(SignerSubjectOriginalsV1::new());
                let chunk = self.read.pending_chunk().map_err(|_| Closed::Retained)?;
                self.subject_result = Some(self.subject.as_mut().ok_or(Closed::Order)?
                    .observe_once(chunk, self.anchor.as_ref(), uid, gid));
                if !matches!(self.subject_result, Some(Ok(()))) { self.first = Some(Stage::Subject); }
                capture_deadline(&mut self.subject_clock, &mut self.subject_deadline, cutoff);
                if !matches!(self.subject_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::SubjectDeadline); }
            }
            if self.first.is_none() {
                self.copied = Some(self.read.append_pending_payload_once());
                if !matches!(self.copied, Some(Ok(()))) { self.first = Some(Stage::Copy); }
            }
            // This original endpoint post is owed after any entered chunk
            // prefix, including before/readiness/receive/subject failures.
            self.read_after = Some(self.stream()?.revalidate_original());
            if !matches!(self.read_after, Some(Ok(()))) { self.first.get_or_insert(Stage::ReadAfter); }
            capture_deadline(&mut self.read_clock, &mut self.read_deadline, cutoff);
            if !matches!(self.read_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::ReadDeadline); }
            if self.first.is_some() { break; }

            let chunk = self.read.take_copied_chunk_once().map_err(|_| Closed::Retained)?;
            let originals = self.subject.take().ok_or(Closed::Order)?;
            if self.anchor.is_none() {
                let identity = originals.identity().ok_or(Closed::Subject)?;
                self.anchor = Some(SignerAnchorV1 { chunk, _originals: originals, identity });
            } else {
                // The complete local native leaf has no outstanding post. A
                // later signature error retains full cumulative bytes and the
                // first actual sender pin, rather than fictional FD history.
                drop(originals);
                drop(chunk);
            }
            self.read_before = None;
            self.read_wait = None;
            self.received = None;
            self.subject_result = None;
            self.copied = None;
            self.read_after = None;
            self.receive_clock = None;
            self.receive_deadline = None;
            self.subject_clock = None;
            self.subject_deadline = None;
            self.read_clock = None;
            self.read_deadline = None;
        }
        if self.first.is_none() {
            self.eof_wait = Some(Default::default());
            let stream = self.stream.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed::Retained)?;
            if self.eof_wait.as_mut().ok_or(Closed::Order)?.observe_readable_once(stream, cutoff).is_err() {
                self.first = Some(Stage::EofWait);
            }
        }
        if self.first.is_none() {
            self.eof = Some(self.stream_mut()?.try_receive_subject_eof_with_geometry_retaining(&geometry));
            if !matches!(self.eof, Some(Ok(_))) { self.first = Some(Stage::Eof); }
            capture_deadline(&mut self.eof_clock, &mut self.eof_deadline, cutoff);
            if !matches!(self.eof_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::EofDeadline); }
        }
        self.finish_native_posts(uid, gid)?;
        if self.first.is_some() { Err(Closed::Retained) } else { Ok(()) }
    }

    fn finish_native_posts(&mut self, uid: u32, gid: u32) -> Result<(), Closed> {
        // A completed or pending actual subject is the only source of this
        // final task observation. No scalar PID/path can fabricate its pin.
        let chunk = self.anchor.as_ref().map(|anchor| &anchor.chunk)
            .or_else(|| self.read.pending_chunk().ok());
        if let Some(chunk) = chunk {
            self.final_subject = Some(SignerSubjectOriginalsV1::new());
            self.final_subject_result = Some(self.final_subject.as_mut().ok_or(Closed::Order)?
                .observe_once(chunk, self.anchor.as_ref(), uid, gid));
            if !matches!(self.final_subject_result, Some(Ok(()))) {
                self.first.get_or_insert(Stage::FinalSubject);
            }
        }
        self.final_original = Some(self.stream()?.revalidate_original());
        if !matches!(self.final_original, Some(Ok(()))) { self.first.get_or_insert(Stage::Final); }
        let now = clock_gettime(ClockId::Boottime);
        self.final_clock = Some(now);
        self.final_deadline = Some(crate::cache_signer_connection::deadline_timeout_v1(now, self.cutoff.ok_or(Closed::Order)?)
            .map_err(|_| Closed::Deadline));
        if !matches!(self.final_deadline, Some(Ok(_))) { self.first.get_or_insert(Stage::FinalDeadline); }
        Ok(())
    }

    /// Reports additional native construction/heap bytes, FD peak and path names.
    ///
    /// The enclosing purpose pays its embedded owner once. The exact first
    /// sender anchor, failed active leaf and independently owed final leaf can
    /// coexist; their real private suppliers are all included before entry.
    #[must_use]
    pub fn additional_receiving_shape_v1() -> Option<(usize, usize, usize)> {
        use aos_sandbox_linux::pidfd::{PidFdContextReadbackV1, PidFdIdentityReadbackV1};
        let geometry = SubjectStreamReceiveGeometryV1::for_context_bytes(255).ok()?;
        let (connection_bytes, _, connection_cells) = CacheSignerConnectionOriginalsV1::additional_receiving_shape_v1()?;
        let (admission_bytes, _) = RetainedUnixStream::retained_admission_obligations_v1();
        let (receive_bytes, receive_files) = geometry.receive_obligations_v1();
        let (eof_bytes, eof_files) = geometry.eof_receive_obligations_v1();
        let (identity_bytes, _, _) = PidFdIdentityReadbackV1::receiving_demand_v1()?;
        let (context_bytes, _, _) = PidFdContextReadbackV1::receiving_demand_v1()?;
        let sample_bytes = identity_bytes.checked_add(context_bytes)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(connection_bytes)?
            .checked_add(admission_bytes)?
            .checked_add(receive_bytes.max(eof_bytes))?
            .checked_add(CACHE_CURRENT_SIGNER_PACKET_BYTES_V1)?
            .checked_add(2usize.checked_mul(CACHE_CURRENT_SIGNER_PACKET_BYTES_V1.checked_add(256)?)?)?
            .checked_add(3usize.checked_mul(sample_bytes)?)?
            .checked_add(std::mem::size_of::<ReadinessOriginalsV1>())?
            .checked_add(std::mem::size_of::<PollFd<'static>>())?;
        // Endpoint+creator pidfd(2), retained first subject pin/stat/context(3),
        // active failed stat/context(2), and independent final stat/context(2).
        // The raw receive/EOF descriptor namespace is a mutually exclusive
        // peak: EOF runs only after complete positive chunk disposal.
        let files = receive_files.max(eof_files).checked_add(2 + 3 + 2 + 2)?;
        // Receive frames, native peer snapshots and readiness controls add no
        // names beyond the fixed connection path. Their full bytes remain.
        Some((bytes, files, connection_cells))
    }

    /// Borrows only a completed exact native packet, without authenticating it.
    ///
    /// # Errors
    /// Refuses absent/partial input, failed native posts or rejected reentry.
    /// The actual caller still verifies the independent signer key and body.
    pub fn packet(&self) -> Result<&[u8; CACHE_CURRENT_SIGNER_PACKET_BYTES_V1], Closed> {
        if !self.finished || self.first.is_some() || self.closed.is_some()
            || !self.read.completed_exact() || !matches!(self.eof, Some(Ok(_)))
            || !matches!(self.final_subject_result, Some(Ok(())))
            || !matches!(self.final_original, Some(Ok(())))
            || !matches!(self.final_deadline, Some(Ok(_)))
        {
            return Err(Closed::Retained);
        }
        self.read.bytes().try_into().map_err(|_| Closed::Extent)
    }

    /// Borrows the first actual entered native or comparison refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Stage::Connection => self.connection.failure(),
            Stage::Admission => cause(&self.stream),
            Stage::Activation => cause(&self.activation),
            Stage::Preparation => self.read.failure().or_else(|| cause(&self.preparation)),
            Stage::BeginBefore => cause(&self.begin_before),
            Stage::WriteWait => self.write_wait.as_ref().and_then(ReadinessOriginalsV1::failure),
            Stage::Write => cause(&self.write),
            Stage::WriteProgress => cause(&self.write_progress),
            Stage::WriteDeadline => cause(&self.write_deadline),
            Stage::Shutdown => cause(&self.shutdown),
            Stage::BeginAfter => cause(&self.begin_after),
            Stage::BeginDeadline => cause(&self.begin_deadline),
            Stage::ReadBefore => cause(&self.read_before),
            Stage::ReadWait => self.read_wait.as_ref().and_then(ReadinessOriginalsV1::failure),
            Stage::Receive => self.read.failure().or_else(|| cause(&self.received)),
            Stage::ReceiveDeadline => cause(&self.receive_deadline),
            Stage::Subject => self.subject.as_ref().and_then(SignerSubjectOriginalsV1::failure)
                .or_else(|| cause(&self.subject_result)),
            Stage::SubjectDeadline => cause(&self.subject_deadline),
            Stage::Copy => self.read.failure().or_else(|| cause(&self.copied)),
            Stage::ReadAfter => cause(&self.read_after),
            Stage::ReadDeadline => cause(&self.read_deadline),
            Stage::EofWait => self.eof_wait.as_ref().and_then(ReadinessOriginalsV1::failure),
            Stage::Eof => cause(&self.eof),
            Stage::EofDeadline => cause(&self.eof_deadline),
            Stage::FinalSubject => self.final_subject.as_ref().and_then(SignerSubjectOriginalsV1::failure)
                .or_else(|| cause(&self.final_subject_result)),
            Stage::Final => cause(&self.final_original),
            Stage::FinalDeadline => cause(&self.final_deadline),
            Stage::Order => self.closed.as_ref().map(|error| error as _),
        }
    }
}

impl Default for CacheCurrentSignerExchangeOriginalsV1 {
    fn default() -> Self { Self::new() }
}

fn capture_deadline(clock: &mut Option<Timespec>, result: &mut Option<Result<Timespec, Closed>>, cutoff: u64) {
    let now = clock_gettime(ClockId::Boottime);
    *clock = Some(now);
    *result = Some(crate::cache_signer_connection::deadline_timeout_v1(now, cutoff)
        .map_err(|_| Closed::Deadline));
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    fn fixture() -> (CacheCurrentSignerExchangeOriginalsV1, UnixStream) {
        let (client, peer) = UnixStream::pair().unwrap();
        let stream = RetainedUnixStream::from_owned_retaining_v1(client.into()).unwrap();
        let mut originals = CacheCurrentSignerExchangeOriginalsV1::new();
        originals.stream = Some(Ok(stream));
        originals.entered = true;
        originals.preparation = Some(originals.read.prepare_exact_once(CACHE_CURRENT_SIGNER_PACKET_BYTES_V1));
        (originals, peer)
    }

    #[test]
    fn actual_root_send_completes_before_any_reply_or_controller_join() {
        let (mut originals, mut peer) = fixture();
        originals.request[..8].copy_from_slice(b"AOSXKR01");
        originals.request[8..620].fill(17);
        originals.request[620..].fill(29);
        let now = clock_gettime(ClockId::Boottime);
        let cutoff = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(now.tv_nsec).unwrap() + 5_000_000_000;
        let reader = std::thread::spawn(move || {
            let mut received = [0; CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1];
            peer.read_exact(&mut received).unwrap();
            let mut trailing = [0];
            assert_eq!(peer.read(&mut trailing).unwrap(), 0);
            (peer, received)
        });

        originals.send_prepared_request_once(cutoff).unwrap();
        assert!(originals.begun);
        assert!(matches!(originals.begin_deadline, Some(Ok(_))));
        assert!(originals.read.bytes().is_empty());
        assert!(originals.read_wait.is_none());
        assert!(originals.eof.is_none());
        let (mut peer, received) = reader.join().unwrap();
        assert_eq!(received, originals.request);
        // The peer is still open and can reply after root begin returned.
        peer.write_all(&[3]).unwrap();
    }

    #[test]
    fn expired_real_socket_read_keeps_first_cause_and_runs_native_posts() {
        let (mut originals, _peer) = fixture();
        originals.begun = true;
        originals.cutoff = Some(1);
        originals.sender = Some((1, 1));
        let cookie = originals.stream().unwrap().peer().credentials();
        assert!(originals.finish_once().is_err());
        assert!(matches!(originals.first, Some(Stage::ReadWait)));
        assert!(originals.read_wait.as_ref().unwrap().poll.is_none());
        assert!(matches!(originals.read_after, Some(Ok(()))));
        assert!(matches!(originals.final_original, Some(Ok(()))));
        assert!(matches!(originals.final_deadline, Some(Err(Closed::Deadline))));
        assert_eq!(originals.stream().unwrap().peer().credentials(), cookie);
        assert!(originals.read.bytes().is_empty());
        let first = originals.failure().unwrap().downcast_ref::<Closed>().unwrap() as *const Closed;
        assert!(matches!(originals.failure().unwrap().downcast_ref::<Closed>(), Some(Closed::Deadline)));

        assert!(originals.finish_once().is_err());
        assert_eq!(first, originals.failure().unwrap().downcast_ref::<Closed>().unwrap() as *const Closed);
        assert!(originals.packet().is_err());
    }
}
