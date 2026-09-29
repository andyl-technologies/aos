//! Bounds strict I/O on one original endpoint by one kernel-incarnation cutoff.
//!
//! This owns no role or policy algorithm. Application checks run before each
//! operation and on every subject chunk, followed by a deadline check after
//! potentially slow observations. Any failure drops/shuts down this PRE-ROOT
//! endpoint; no retry can adopt another connection inside the flight.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::ConsumerReadFlightErrorV1 as Error;
use super::wire::{Correlation, HEADER_BYTES, Phase};

const MAXIMUM_FLIGHT_NANOSECONDS: u64 = 60_000_000_000;
const MAXIMUM_POLL_NANOSECONDS: u64 = 100_000_000;

type PeerCheck<'a> =
    dyn FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), Error> + 'a;

#[derive(Clone, Copy)]
pub(super) struct Deadline {
    boot: [u8; 16],
    cutoff: u64,
}

impl Deadline {
    pub(super) fn capture(cutoff: u64) -> Result<Self, Error> {
        let (boot, now) = kernel_sample()?;
        require_admissible_cutoff(now, cutoff)?;
        Ok(Self { boot, cutoff })
    }

    pub(super) fn boot(self) -> [u8; 16] {
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

    pub(super) fn require_current(self) -> Result<(), Error> {
        self.remaining().map(|_| ())
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
        let address = SocketAddrUnix::new(
            super::super::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2,
        )
        .map_err(std::io::Error::from)?;
        match connect(&fd, &address) {
            Ok(()) => {}
            Err(rustix::io::Errno::INPROGRESS) => {
                wait(fd.as_fd(), PollFlags::OUT, deadline)?;
                rustix::net::sockopt::socket_error(&fd)
                    .map_err(std::io::Error::from)?
                    .map_err(std::io::Error::from)?;
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
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

    pub(super) fn write(&self, mut bytes: &[u8], check: &mut PeerCheck<'_>) -> Result<(), Error> {
        while !bytes.is_empty() {
            self.checked(check, None)?;
            match rustix::net::send(self.stream.as_fd(), bytes, rustix::net::SendFlags::NOSIGNAL) {
                Ok(0) => return Err(Error::Protocol),
                Ok(count) => bytes = &bytes[count..],
                Err(rustix::io::Errno::AGAIN) => {
                    wait(self.stream.as_fd(), PollFlags::OUT, self.deadline)?
                }
                Err(rustix::io::Errno::INTR) => self.deadline.require_current()?,
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            self.deadline.require_current()?;
        }
        self.checked(check, None)
    }

    pub(super) fn read_exact(
        &mut self,
        length: usize,
        check: &mut PeerCheck<'_>,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            self.checked(check, None)?;
            match self
                .stream
                .try_receive_subject_chunk((length - bytes.len()).min(4096))
            {
                Ok(chunk) => {
                    self.checked(check, Some(&chunk))?;
                    bytes.extend_from_slice(chunk.payload());
                }
                Err(SeqpacketError::WouldBlock) => {
                    wait(self.stream.as_fd(), PollFlags::IN, self.deadline)?
                }
                Err(SeqpacketError::Interrupted) => self.deadline.require_current()?,
                Err(error) => return Err(error.into()),
            }
        }
        self.checked(check, None)?;
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
        loop {
            self.checked(check, None)?;
            match self.stream.try_receive_subject_chunk(1) {
                Ok(chunk) => {
                    self.checked(check, Some(&chunk))?;
                    return Err(Error::Protocol);
                }
                // No previous receive failure is recoverable in this Flight.
                // Ready->Closed here is the actual zero-byte recvmsg, not an ACK.
                Err(SeqpacketError::Closed) => {
                    self.checked(check, None)?;
                    return Ok(());
                }
                Err(SeqpacketError::WouldBlock) => {
                    wait(self.stream.as_fd(), PollFlags::IN, self.deadline)?
                }
                Err(SeqpacketError::Interrupted) => self.deadline.require_current()?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(super) fn checked(
        &self,
        check: &mut PeerCheck<'_>,
        chunk: Option<&UnixStreamSubjectChunk>,
    ) -> Result<(), Error> {
        self.deadline.require_current()?;
        check(&self.stream, chunk)?;
        self.deadline.require_current()
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        // PRE-ROOT only: no pins or positive effects can be retired by this.
        let _ = rustix::net::shutdown(self.stream.as_fd(), rustix::net::Shutdown::Both);
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
