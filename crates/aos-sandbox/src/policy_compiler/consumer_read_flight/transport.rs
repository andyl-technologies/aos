//! Bounds strict I/O on one original endpoint by one kernel-incarnation cutoff.
//!
//! This owns no role or policy algorithm. Application checks run before each
//! operation and on every subject chunk, followed by a deadline check after
//! potentially slow observations. Legacy PRE-ROOT callers keep their ordinary
//! failure/drop contract. The opt-in metadata carrier instead parks originals,
//! incomplete buffers and owning receives; neither profile retries an endpoint.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, SeqpacketError};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::ConsumerReadFlightErrorV1 as Error;
use super::wire::{Correlation, HEADER_BYTES, Phase};

const MAXIMUM_FLIGHT_NANOSECONDS: u64 = 60_000_000_000;
const MAXIMUM_POLL_NANOSECONDS: u64 = 100_000_000;
// Four initial reads, sixteen header/commitment checks, then RELEASED pair.
const MAXIMUM_METADATA_READS: usize = 4 + 2 * 16 + 2;

type PeerCheck<'a> =
    dyn FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), Error> + 'a;

type RetainingCheck<'a> = dyn FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>)
    -> Result<(), TransportFault> + 'a;

#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    boot: [u8; 16],
    cutoff: u64,
}

impl Deadline {
    pub(super) fn capture(cutoff: u64) -> Result<Self, Error> {
        let (boot, now) = kernel_sample()?;
        require_admissible_cutoff(now, cutoff)?;
        Ok(Self { boot, cutoff })
    }

    pub(crate) fn boot(self) -> [u8; 16] {
        self.boot
    }

    pub(super) fn remaining(self) -> Result<u64, Error> {
        let (boot, now) = kernel_sample()?;
        self.remaining_after(boot, now)
    }

    fn remaining_after(self, boot: [u8; 16], now: u64) -> Result<u64, Error> {
        if boot != self.boot {
            return Err(Error::Deadline);
        }
        self.cutoff
            .checked_sub(now)
            .filter(|remaining| *remaining != 0)
            .ok_or(Error::Deadline)
    }

    pub(crate) fn require_current(self) -> Result<(), Error> {
        self.remaining().map(|_| ())
    }

    pub(crate) fn new_metadata() -> Result<Self, Error> {
        let (boot, now) = kernel_sample()?;
        let cutoff = now.checked_add(10_000_000_000).ok_or(Error::Deadline)?;
        Ok(Self { boot, cutoff })
    }

    pub(crate) fn capture_metadata(cutoff: u64) -> Result<Self, Error> {
        let (boot, now) = kernel_sample()?;
        require_metadata_cutoff(now, cutoff)?;
        Ok(Self { boot, cutoff })
    }

    pub(crate) fn cutoff(self) -> u64 {
        self.cutoff
    }
}

fn require_metadata_cutoff(now: u64, cutoff: u64) -> Result<(), Error> {
    match cutoff.checked_sub(now) {
        Some(1..=10_000_000_000) => Ok(()),
        _ => Err(Error::Deadline),
    }
}

fn require_admissible_cutoff(now: u64, cutoff: u64) -> Result<(), Error> {
    match cutoff.checked_sub(now) {
        Some(1..=MAXIMUM_FLIGHT_NANOSECONDS) => Ok(()),
        _ => Err(Error::Deadline),
    }
}

fn kernel_sample() -> Result<([u8; 16], u64), Error> {
    let before = KernelBootId::current()?.into_bytes();
    let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let after = KernelBootId::current()?.into_bytes();
    if before != after {
        return Err(Error::Deadline);
    }
    let now = u64::try_from(sample.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(sample.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(Error::Deadline)?;
    Ok((before, now))
}

pub(super) struct Flight {
    stream: RetainedUnixStream,
    pub(super) correlation: Correlation,
    pub(super) deadline: Deadline,
}

impl Flight {
    pub(super) fn connect(correlation: Correlation, deadline: Deadline) -> Result<Self, Error> {
        deadline.require_current()?;
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(std::io::Error::from)?;
        connect_fixed(&fd, deadline)?;
        deadline.require_current()?;
        Self::adopt(fd, correlation, deadline)
    }

    pub(super) fn adopt(
        fd: OwnedFd,
        correlation: Correlation,
        deadline: Deadline,
    ) -> Result<Self, Error> {
        if correlation.deadline != deadline.cutoff || correlation.nonce == [0; 16] {
            return Err(Error::Protocol);
        }
        deadline.require_current()?;
        let flags = rustix::fs::fcntl_getfl(&fd).map_err(std::io::Error::from)?;
        rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(std::io::Error::from)?;
        let mut stream = RetainedUnixStream::from_owned(fd)?;
        stream.enable_subject_reporting()?;
        deadline.require_current()?;
        Ok(Self {
            stream,
            correlation,
            deadline,
        })
    }

    pub(super) fn stream(&self) -> &RetainedUnixStream {
        &self.stream
    }

    pub(super) fn write(&self, bytes: &[u8], check: &mut PeerCheck<'_>) -> Result<(), Error> {
        let mut cursor = 0;
        write_engine(&self.stream, self.deadline, bytes, &mut cursor, check)
    }

    pub(super) fn read_exact(
        &mut self,
        length: usize,
        check: &mut PeerCheck<'_>,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(length);
        let mut slot = ReceiveSlot::Legacy(None);
        let mut legacy_check = |stream: &_, chunk: Option<&UnixStreamSubjectChunk>| {
            check(stream, chunk).map_err(TransportFault::from)
        };
        read_engine(&mut self.stream, self.deadline, &mut bytes, length, false, &mut slot, &mut legacy_check)
            .map_err(TransportFault::legacy)?;
        Ok(bytes)
    }

    pub(super) fn header(&mut self, check: &mut PeerCheck<'_>) -> Result<(Phase, usize), Error> {
        let bytes = self.read_exact(HEADER_BYTES, check)?;
        self.correlation.decode_header(&bytes)
    }

    pub(super) fn send_header(
        &self,
        phase: Phase,
        length: usize,
        check: &mut PeerCheck<'_>,
    ) -> Result<(), Error> {
        self.write(&self.correlation.header(phase, length)?, check)
    }

    pub(super) fn finish_sending(&self) -> Result<(), Error> {
        self.deadline.require_current()?;
        rustix::net::shutdown(self.stream.as_fd(), rustix::net::Shutdown::Write)
            .map_err(std::io::Error::from)?;
        self.deadline.require_current()
    }

    pub(super) fn require_eof(&mut self, check: &mut PeerCheck<'_>) -> Result<(), Error> {
        let mut slot = ReceiveSlot::Legacy(None);
        let mut legacy_check = |stream: &_, chunk: Option<&UnixStreamSubjectChunk>| {
            check(stream, chunk).map_err(TransportFault::from)
        };
        read_engine(&mut self.stream, self.deadline, &mut Vec::new(), 1, true, &mut slot, &mut legacy_check)
            .map_err(TransportFault::legacy)
    }

    pub(super) fn checked(
        &self,
        check: &mut PeerCheck<'_>,
        chunk: Option<&UnixStreamSubjectChunk>,
    ) -> Result<(), Error> {
        checked(&self.stream, self.deadline, check, chunk)
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        // PRE-ROOT only: no pins or positive effects can be retired by this.
        let _ = rustix::net::shutdown(self.stream.as_fd(), rustix::net::Shutdown::Both);
    }
}

fn connect_fixed(fd: &OwnedFd, deadline: Deadline) -> Result<(), Error> {
    let address = SocketAddrUnix::new(
        super::super::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2,
    )
    .map_err(std::io::Error::from)?;
    match connect(fd, &address) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INPROGRESS) => {
            wait(fd.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(fd)
                .map_err(std::io::Error::from)?
                .map_err(std::io::Error::from)?;
            Ok(())
        }
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

fn checked<E: From<Error>>(
    stream: &RetainedUnixStream,
    deadline: Deadline,
    check: &mut dyn FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), E>,
    chunk: Option<&UnixStreamSubjectChunk>,
) -> Result<(), E> {
    deadline.require_current()?;
    check(stream, chunk)?;
    deadline.require_current().map_err(E::from)
}

fn write_engine<E: From<Error>>(
    stream: &RetainedUnixStream,
    deadline: Deadline,
    bytes: &[u8],
    cursor: &mut usize,
    check: &mut dyn FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), E>,
) -> Result<(), E> {
    while *cursor < bytes.len() {
        checked(stream, deadline, check, None)?;
        match rustix::net::send(stream.as_fd(), &bytes[*cursor..], rustix::net::SendFlags::NOSIGNAL) {
            Ok(0) => return Err(Error::Protocol.into()),
            Ok(count) => *cursor += count,
            Err(rustix::io::Errno::AGAIN) => wait(stream.as_fd(), PollFlags::OUT, deadline)?,
            Err(rustix::io::Errno::INTR) => deadline.require_current()?,
            Err(error) => return Err(E::from(Error::from(std::io::Error::from(error)))),
        }
        deadline.require_current()?;
    }
    checked(stream, deadline, check, None)
}

// This closed alternative changes custody, not wire decoding or peer authority.
enum ReceiveSlot {
    Legacy(Option<Result<UnixStreamSubjectChunk, SeqpacketError>>),
    Retaining(Option<Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1>>),
}

impl ReceiveSlot {
    fn receive(&mut self, stream: &mut RetainedUnixStream, maximum: usize) {
        match self {
            Self::Legacy(result) => *result = Some(stream.try_receive_subject_chunk(maximum)),
            Self::Retaining(result) => {
                // Assignment precedes every decoder, role observation and allocation.
                *result = Some(stream.try_receive_subject_chunk_retaining(maximum));
            }
        }
    }

    fn chunk(&self) -> Option<&UnixStreamSubjectChunk> {
        match self {
            Self::Legacy(Some(Ok(chunk))) | Self::Retaining(Some(Ok(chunk))) => Some(chunk),
            _ => None,
        }
    }

    fn retry(&self) -> Option<PollFlags> {
        match self {
            Self::Legacy(Some(Err(SeqpacketError::WouldBlock))) => Some(PollFlags::IN),
            Self::Legacy(Some(Err(SeqpacketError::Interrupted))) => Some(PollFlags::empty()),
            Self::Retaining(Some(Err(error))) if error.is_nonconsuming_would_block() => {
                Some(PollFlags::IN)
            }
            Self::Retaining(Some(Err(error))) if error.is_nonconsuming_interrupted() => {
                Some(PollFlags::empty())
            }
            _ => None,
        }
    }

    fn clean_closed(&self) -> bool {
        match self {
            Self::Legacy(Some(Err(SeqpacketError::Closed))) => true,
            Self::Retaining(Some(Err(error))) => {
                matches!(std::error::Error::source(error)
                    .and_then(|source| source.downcast_ref::<SeqpacketError>()),
                    Some(SeqpacketError::Closed)) && error.shutdown_failure().is_none()
            }
            _ => false,
        }
    }

    fn failure(&mut self) -> TransportFault {
        match self {
            Self::Legacy(result) => match result.take() {
                Some(Err(error)) => TransportFault::Legacy(error.into()),
                _ => TransportFault::Legacy(Error::Protocol),
            },
            Self::Retaining(_) => TransportFault::RetainedReceive,
        }
    }

    fn release_legacy_chunk(&mut self) {
        if let Self::Legacy(result) = self {
            // Preserve the old chunk's disposal before the next precheck or
            // final bookend. Retaining custody intentionally keeps its chunk.
            *result = None;
        }
    }
}

/// Private marker keeps the actual retaining receive error in its carrier slot.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportFault {
    #[error(transparent)]
    Legacy(#[from] Error),
    #[error("retained original receive failed")]
    RetainedReceive,
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Evidence(#[from] crate::git::GitProtectedEvidenceErrorV1),
}

impl TransportFault {
    fn legacy(self) -> Error {
        match self {
            Self::Legacy(error) => error,
            // Legacy callers never select retaining custody or fallible reserve.
            Self::RetainedReceive | Self::Allocation(_) | Self::Evidence(_) => Error::Protocol,
        }
    }
}

fn read_engine(
    stream: &mut RetainedUnixStream,
    deadline: Deadline,
    bytes: &mut Vec<u8>,
    length: usize,
    eof: bool,
    slot: &mut ReceiveSlot,
    check: &mut RetainingCheck<'_>,
) -> Result<(), TransportFault> {
    while eof || bytes.len() < length {
        checked(stream, deadline, check, None)?;
        slot.receive(stream, if eof { 1 } else { (length - bytes.len()).min(4096) });
        if let Some(chunk) = slot.chunk() {
            checked(stream, deadline, check, Some(chunk))?;
            if eof {
                return Err(Error::Protocol.into());
            }
            bytes.extend_from_slice(chunk.payload());
            slot.release_legacy_chunk();
        } else if let Some(interest) = slot.retry() {
            if interest.is_empty() {
                deadline.require_current()?;
            } else {
                wait(stream.as_fd(), interest, deadline)?;
            }
        } else if eof && slot.clean_closed() {
            // Only this call's exclusive Ready->Closed transition is accepted.
            // Retaining callers preserve the whole owning error and its debt.
            checked(stream, deadline, check, None)?;
            return Ok(());
        } else {
            return Err(slot.failure());
        }
    }
    checked(stream, deadline, check, None)?;
    Ok(())
}

/// Retains originals before connect/adoption, chunks before checks, and all debt.
///
/// No descriptor, peer or journal is exposed publicly. The raw alias has the
/// same OFD and exists solely to retain shutdown custody across consuming lower
/// adoption; it is never another reader. Partial lower adoption remains outside
/// the returned-owner boundary and is not claimed recovered here.
pub(crate) struct RetainedCarrier {
    raw: Option<OwnedFd>,
    stream: Option<RetainedUnixStream>,
    deadline: Option<Deadline>,
    slot: ReceiveSlot,
    buffers: Vec<Vec<u8>>,
    write_cursor: usize,
    shutdown_failure: Option<std::io::Error>,
    ended: bool,
}

impl RetainedCarrier {
    pub(crate) fn empty() -> Self {
        Self {
            raw: None,
            stream: None,
            deadline: None,
            slot: ReceiveSlot::Retaining(None),
            buffers: Vec::new(),
            write_cursor: 0,
            shutdown_failure: None,
            ended: false,
        }
    }

    pub(crate) fn accepted(original: std::os::unix::net::UnixStream) -> Self {
        Self { raw: Some(original.into()), ..Self::empty() }
    }

    pub(crate) fn connect(&mut self, deadline: Deadline) -> Result<(), Error> {
        if self.raw.is_some() || self.ended {
            return Err(Error::Protocol);
        }
        self.deadline = Some(deadline);
        deadline.require_current()?;
        self.raw = Some(socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        ).map_err(std::io::Error::from)?);
        connect_fixed(self.raw.as_ref().ok_or(Error::Protocol)?, deadline)?;
        deadline.require_current()?;
        self.adopt(deadline)
    }

    pub(crate) fn adopt(&mut self, deadline: Deadline) -> Result<(), Error> {
        if self.stream.is_some() || self.ended {
            return Err(Error::Protocol);
        }
        self.deadline = Some(deadline);
        deadline.require_current()?;
        let fd = self.raw.as_ref().ok_or(Error::Protocol)?;
        let flags = rustix::fs::fcntl_getfl(fd).map_err(std::io::Error::from)?;
        rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(std::io::Error::from)?;
        let alias = rustix::io::fcntl_dupfd_cloexec(fd, 64).map_err(std::io::Error::from)?;
        self.stream = Some(RetainedUnixStream::from_owned(alias)?);
        self.stream.as_mut().ok_or(Error::Protocol)?.enable_subject_reporting()?;
        deadline.require_current()
    }

    pub(crate) fn stream(&self) -> Result<&RetainedUnixStream, Error> {
        self.stream.as_ref().ok_or(Error::Protocol)
    }

    pub(crate) fn deadline(&self) -> Result<Deadline, Error> {
        self.deadline.ok_or(Error::Protocol)
    }

    pub(crate) fn checked(&self, check: &mut RetainingCheck<'_>) -> Result<(), TransportFault> {
        checked(self.stream()?, self.deadline()?, check, None)
    }

    pub(crate) fn write(&mut self, bytes: &[u8], check: &mut RetainingCheck<'_>) -> Result<(), TransportFault> {
        let deadline = self.deadline()?;
        self.write_cursor = 0;
        write_engine(self.stream.as_ref().ok_or(Error::Protocol)?, deadline,
            bytes, &mut self.write_cursor, check)
    }

    pub(crate) fn read_exact(&mut self, length: usize, check: &mut RetainingCheck<'_>)
        -> Result<usize, TransportFault>
    {
        let deadline = self.deadline()?;
        // Refuse before collecting another allocation in the closed profile.
        if self.buffers.len() >= MAXIMUM_METADATA_READS {
            return Err(Error::Protocol.into());
        }
        self.buffers.try_reserve(1)?;
        let index = self.buffers.len();
        self.buffers.push(Vec::new());
        self.buffers[index].try_reserve_exact(length)?;
        read_engine(self.stream.as_mut().ok_or(Error::Protocol)?, deadline,
            &mut self.buffers[index], length, false, &mut self.slot, check)?;
        Ok(index)
    }

    pub(crate) fn bytes(&self, index: usize) -> Result<&[u8], Error> {
        self.buffers.get(index).map(Vec::as_slice).ok_or(Error::Protocol)
    }

    pub(crate) fn finish_sending(&self) -> Result<(), Error> {
        let deadline = self.deadline()?;
        deadline.require_current()?;
        rustix::net::shutdown(self.stream()?.as_fd(), rustix::net::Shutdown::Write)
            .map_err(std::io::Error::from)?;
        deadline.require_current()
    }

    pub(crate) fn require_eof(&mut self, check: &mut RetainingCheck<'_>) -> Result<(), TransportFault> {
        let deadline = self.deadline()?;
        read_engine(self.stream.as_mut().ok_or(Error::Protocol)?, deadline,
            &mut Vec::new(), 1, true, &mut self.slot, check)
    }

    pub(crate) fn receive_failure(&self) -> Option<&RetainedSeqpacketReceiveErrorV1> {
        match &self.slot {
            ReceiveSlot::Retaining(Some(Err(error))) => Some(error),
            _ => None,
        }
    }

    pub(crate) fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.receive_failure().and_then(|error| error.shutdown_failure())
            .or(self.shutdown_failure.as_ref())
    }

    pub(crate) fn end(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        if let Some(fd) = &self.raw {
            self.shutdown_failure = rustix::net::shutdown(fd, rustix::net::Shutdown::Both)
                .err().map(std::io::Error::from);
        }
    }
}

impl Drop for RetainedCarrier {
    fn drop(&mut self) {
        self.end();
    }
}

fn wait(fd: BorrowedFd<'_>, interest: PollFlags, deadline: Deadline) -> Result<(), Error> {
    loop {
        let remaining = deadline.remaining()?.min(MAXIMUM_POLL_NANOSECONDS);
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: remaining as i64,
        };
        let mut descriptors = [PollFd::new(&fd, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => {
                deadline.require_current()?;
                continue;
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        deadline.require_current()?;
        let observed = descriptors[0].revents();
        // IN/HUP is permitted to reach strict recvmsg to distinguish exact EOF
        // from trailing DATA. Writes never accept HUP as useful readiness.
        if observed.intersects(PollFlags::ERR | PollFlags::NVAL)
            || (interest == PollFlags::OUT && observed.contains(PollFlags::HUP))
        {
            return Err(Error::Protocol);
        }
        if observed.intersects(interest | PollFlags::HUP) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    // These are raw carrier/clock mechanics, never selected service peers or
    // installed Ready/request authority. No role checker is fabricated here.
    fn pair() -> (Flight, UnixStream) {
        let (_, now) = kernel_sample().unwrap();
        let deadline = Deadline::capture(now + 2_000_000_000).unwrap();
        let correlation = Correlation {
            nonce: [1; 16],
            deadline: deadline.cutoff,
        };
        let (left, right) = UnixStream::pair().unwrap();
        (
            Flight::adopt(left.into(), correlation, deadline).unwrap(),
            right,
        )
    }

    #[test]
    fn metadata_cutoff_has_its_own_nonrenewing_ten_second_bound() {
        assert!(require_metadata_cutoff(100, 100).is_err());
        assert!(require_metadata_cutoff(100, 99).is_err());
        assert!(require_metadata_cutoff(100, 101).is_ok());
        assert!(require_metadata_cutoff(100, 100 + 10_000_000_000).is_ok());
        assert!(require_metadata_cutoff(100, 101 + 10_000_000_000).is_err());
        assert!(require_metadata_cutoff(u64::MAX, 0).is_err());
        assert!(require_admissible_cutoff(100, 100 + MAXIMUM_FLIGHT_NANOSECONDS).is_ok());
    }

    #[test]
    fn original_cutoff_is_exclusive_and_never_clamped_or_renewed() {
        assert!(require_admissible_cutoff(100, 100).is_err());
        assert!(require_admissible_cutoff(100, 99).is_err());
        assert!(require_admissible_cutoff(100, 101).is_ok());
        assert!(require_admissible_cutoff(100, 100 + MAXIMUM_FLIGHT_NANOSECONDS).is_ok());
        assert!(require_admissible_cutoff(100, 101 + MAXIMUM_FLIGHT_NANOSECONDS).is_err());
        assert!(Deadline::capture(1).is_err());
        let original = Deadline {
            boot: [1; 16],
            cutoff: 100,
        };
        assert_eq!(original.remaining_after([1; 16], 99).unwrap(), 1);
        assert!(original.remaining_after([1; 16], 100).is_err());
        assert!(original.remaining_after([2; 16], 99).is_err());
        assert_eq!(original.cutoff, 100);
    }

    #[test]
    fn expiry_after_slow_checker_prevents_the_first_write() {
        let (mut flight, mut peer) = pair();
        let (_, now) = kernel_sample().unwrap();
        flight.deadline.cutoff = now + 20_000_000;
        peer.set_nonblocking(true).unwrap();
        let mut slow = |_: &RetainedUnixStream, _: Option<&UnixStreamSubjectChunk>| {
            std::thread::sleep(std::time::Duration::from_millis(40));
            Ok(())
        };
        assert!(matches!(
            flight.write(b"must-not-send", &mut slow),
            Err(Error::Deadline)
        ));
        let mut byte = [0];
        assert_eq!(
            peer.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn eof_is_terminal_only_and_trailing_data_never_acknowledges() {
        let (mut flight, peer) = pair();
        let mut mechanics = |_: &RetainedUnixStream, _: Option<&UnixStreamSubjectChunk>| Ok(());
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(flight.read_exact(1, &mut mechanics).is_err());
        // Failure poisoned that original receive profile; it is never retried
        // as a new terminal exchange by any application caller.
        drop(flight);

        let (mut flight, mut peer) = pair();
        peer.write_all(b"trailing").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(flight.require_eof(&mut mechanics).is_err());
        let (mut flight, peer) = pair();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        flight.require_eof(&mut mechanics).unwrap();
    }

    #[test]
    fn descriptor_bearing_chunk_is_refused_before_assembly() {
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
        use std::io::IoSlice;
        use std::mem::MaybeUninit;

        let (mut flight, peer) = pair();
        let descriptor = std::fs::File::open("/proc/self/status").unwrap();
        let descriptors = [descriptor.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            peer.as_fd(),
            &[IoSlice::new(b"x")],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        let mut mechanics = |_: &RetainedUnixStream, _: Option<&UnixStreamSubjectChunk>| Ok(());
        assert!(matches!(
            flight.read_exact(1, &mut mechanics),
            Err(Error::Subject(_))
        ));
    }

    #[test]
    fn bounded_original_write_cursor_preserves_bytes_under_backpressure() {
        let (flight, mut peer) = pair();
        rustix::net::sockopt::set_socket_send_buffer_size(flight.stream.as_fd(), 4096).unwrap();
        let payload = vec![0x6b; 128 * 1024];
        let length = payload.len();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let mut bytes = vec![0; length];
            peer.read_exact(&mut bytes).unwrap();
            bytes
        });
        let mut checks = 0;
        let mut mechanics = |_: &RetainedUnixStream, _: Option<&UnixStreamSubjectChunk>| {
            checks += 1;
            Ok(())
        };
        flight.write(&payload, &mut mechanics).unwrap();
        assert!(checks > 2);
        assert_eq!(reader.join().unwrap(), payload);
    }
}
