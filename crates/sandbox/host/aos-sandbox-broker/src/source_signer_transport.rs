//! Owns the sole fixed Source signer socket transport and bounded wire IO.
//!
//! This private mechanical owner retains every reached native result. Its
//! bytes are unauthenticated until the actual purpose owner verifies its own
//! pinned signature, query, clocks and independently owed native posts.

use crate::bounded_stream_io::{
    DeadlineStreamDirectionV1 as SourceIoDirectionV1,
    FixedDeadlineStreamIoV1 as FixedSourceCurrentIoV1,
};
use crate::source_signer_connection::{
    SOURCE_SIGNER_SOCKET_PATH_V1, SourceSignerSocketCustodyOriginalsV1,
};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use std::error::Error;
use std::io;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

/// Reports refusal while the actual fixed Source transport retains its cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum RootSourceTransportClosedV1 {
    /// The original transport is unavailable or has already been entered.
    #[error("fixed Source transport original is unavailable")]
    Original,
    /// The original wire transfer is incomplete or refused.
    #[error("fixed Source transport exchange is unavailable")]
    History,
}

/// Retains the sole fixed Source socket exchange and its actual byte progress.
///
/// Returned bytes are unauthenticated DATA. The owning purpose independently
/// checks its genuine pinned signer, query, cutoff and owed native posts; this
/// transport grants neither a Root phase nor a Source signing permission.
pub struct RootSourceSignerTransportOriginalsV1<const Q: usize, const A: usize> {
    path_before: SourceSignerSocketCustodyOriginalsV1,
    path_before_result: Option<io::Result<()>>,
    address: Option<Result<SocketAddrUnix, rustix::io::Errno>>,
    raw: Option<Result<OwnedFd, rustix::io::Errno>>,
    connect: Option<Result<(), rustix::io::Errno>>,
    stream: Option<UnixStream>,
    path_after: SourceSignerSocketCustodyOriginalsV1,
    path_after_result: Option<io::Result<()>>,
    blocking: Option<io::Result<()>>,
    request: [u8; Q],
    sent: FixedSourceCurrentIoV1<Q>,
    write_end: Option<io::Result<()>>,
    frame: [u8; A],
    received: FixedSourceCurrentIoV1<A>,
    eof_byte: [u8; 1],
    eof: FixedSourceCurrentIoV1<1>,
    entered: bool,
    closed: Option<RootSourceTransportClosedV1>,
}

impl<const Q: usize, const A: usize> Default for RootSourceSignerTransportOriginalsV1<Q, A> {
    fn default() -> Self {
        Self {
            path_before: Default::default(),
            path_before_result: None,
            address: None,
            raw: None,
            connect: None,
            stream: None,
            path_after: Default::default(),
            path_after_result: None,
            blocking: None,
            request: [0; Q],
            sent: Default::default(),
            write_end: None,
            frame: [0; A],
            received: Default::default(),
            eof_byte: [0],
            eof: Default::default(),
            entered: false,
            closed: None,
        }
    }
}

impl<const Q: usize, const A: usize> RootSourceSignerTransportOriginalsV1<Q, A> {
    /// Exchanges the original fixed query, exact reply and EOF once.
    ///
    /// # Errors
    /// Retains unsafe socket custody, failed native admission, timeout, partial
    /// or late byte IO, nonexact EOF or reentry without replacing earlier causes.
    pub fn run_once_v1(
        &mut self,
        signer_uid: u32,
        socket_gid: u32,
        request: &[u8; Q],
        cutoff: u64,
    ) -> Result<(), RootSourceTransportClosedV1> {
        if self.entered {
            self.closed
                .get_or_insert(RootSourceTransportClosedV1::Original);
            return Err(RootSourceTransportClosedV1::Original);
        }
        self.entered = true;
        if signer_uid == 0 || socket_gid == 0 {
            return Err(RootSourceTransportClosedV1::Original);
        }
        self.path_before_result = Some(self.path_before.observe_once(signer_uid, socket_gid));
        positive(&self.path_before_result)?;
        self.address = Some(SocketAddrUnix::new(SOURCE_SIGNER_SOCKET_PATH_V1));
        let address = positive(&self.address)?;
        self.raw = Some(rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        ));
        let raw = positive(&self.raw)?;
        self.connect = Some(rustix::net::connect(raw, address));
        // An unadmitted busy listener is a retained refusal, never a renewed
        // deadline or ambiguous second connection. Normal AF_UNIX admission is
        // immediate; every failed native descriptor remains in `raw`.
        positive(&self.connect)?;
        let Some(Ok(raw)) = self.raw.take() else {
            return Err(RootSourceTransportClosedV1::Original);
        };
        self.stream = Some(UnixStream::from(raw));
        let stream = self
            .stream
            .as_mut()
            .ok_or(RootSourceTransportClosedV1::Original)?;
        self.path_after_result = Some(self.path_after.observe_once(signer_uid, socket_gid));
        positive(&self.path_after_result)?;
        // The same admitted OFD becomes blocking only after admission. Each
        // read/write uses the remaining original BOOTTIME cut, and parks every
        // partial native result in a format-derived finite roster.
        self.blocking = Some(stream.set_nonblocking(false));
        positive(&self.blocking)?;
        self.request.copy_from_slice(request);
        self.sent
            .run_once(
                stream,
                &mut self.request,
                cutoff,
                SourceIoDirectionV1::Write,
            )
            .map_err(|_| RootSourceTransportClosedV1::History)?;
        self.write_end = Some(stream.shutdown(Shutdown::Write));
        positive(&self.write_end)?;
        self.received
            .run_once(stream, &mut self.frame, cutoff, SourceIoDirectionV1::Read)
            .map_err(|_| RootSourceTransportClosedV1::History)?;
        self.eof
            .run_once(stream, &mut self.eof_byte, cutoff, SourceIoDirectionV1::Eof)
            .map_err(|_| RootSourceTransportClosedV1::History)?;
        Ok(())
    }

    // This is raw transport DATA, including an incomplete frame after refusal.
    // Only the owning purpose's positive IO/signature/post conjunction is used.
    /// Borrows the untrusted reply buffer, including a refused partial prefix.
    pub fn frame_v1(&self) -> &[u8; A] {
        &self.frame
    }

    /// Borrows the first actual retained failure without repeating native IO.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.path_before
            .failure()
            .or_else(|| cause(&self.path_before_result))
            .or_else(|| cause(&self.address))
            .or_else(|| cause(&self.raw))
            .or_else(|| cause(&self.connect))
            .or_else(|| self.path_after.failure())
            .or_else(|| cause(&self.path_after_result))
            .or_else(|| cause(&self.blocking))
            .or_else(|| self.sent.failure())
            .or_else(|| cause(&self.write_end))
            .or_else(|| self.received.failure())
            .or_else(|| self.eof.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, RootSourceTransportClosedV1> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(RootSourceTransportClosedV1::History)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().err())
        .map(|cause| cause as _)
}
