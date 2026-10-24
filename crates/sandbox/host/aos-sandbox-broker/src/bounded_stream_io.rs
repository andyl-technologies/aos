//! Transfers admitted fixed or variable frames under one original deadline.
//!
//! One shared loop retains the current native step. Positive payload operations
//! advance the actual byte cursor before their completed DTOs are disposed;
//! refusal or zero progress keeps that step resident and closes the flight.
//! The caller retains frame/socket/effect custody and owes its original posts.
//! No retries, allocations, new deadline or receiving grant originate here.

use std::error::Error;
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::time::Duration;

use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use rustix::time::{ClockId, Timespec, clock_gettime};

/// Owns one deadline-bounded IO flight without allocating per-byte probes.
///
/// The caller retains the admitted frame and actual socket through its outer
/// posts. A positive step is disposed only after its byte cursor advances;
/// failed and non-progressing steps remain resident and close the flight.
#[derive(Default)]
pub struct SliceDeadlineStreamIoV1 {
    step: DeadlineStreamStepV1,
    entered: bool,
    progress: usize,
    result: Option<Result<(), HistoryErrorV1>>,
    closed: Option<HistoryErrorV1>,
}

#[derive(Default)]
struct DeadlineStreamStepV1 {
    clock: Option<Timespec>,
    remaining: Option<Result<Duration, HistoryErrorV1>>,
    timeout: Option<io::Result<()>>,
    native: Option<io::Result<usize>>,
    after_clock: Option<Timespec>,
    after_remaining: Option<Result<Duration, HistoryErrorV1>>,
}

impl DeadlineStreamStepV1 {
    // Every payload direction, including EOF, crosses this same boundary
    // before cursor advancement or positive disposal.
    fn require_timely_native_result(&self) -> Result<usize, HistoryErrorV1> {
        let reached = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(HistoryErrorV1::Correlation)?;
        if !matches!(self.after_remaining, Some(Ok(_))) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(reached)
    }
}

/// Adapts an existing fixed frame to the same bounded-slice engine.
pub struct FixedDeadlineStreamIoV1<const N: usize> {
    inner: SliceDeadlineStreamIoV1,
}

/// Selects the original concrete byte operation without granting a role.
#[derive(Clone, Copy)]
pub enum DeadlineStreamDirectionV1 {
    /// Writes exactly the requested payload prefix.
    Write,
    /// Reads exactly the requested payload prefix.
    Read,
    /// Requires the original one-byte EOF observation to return zero.
    Eof,
}

impl<const N: usize> Default for FixedDeadlineStreamIoV1<N> {
    fn default() -> Self {
        Self { inner: SliceDeadlineStreamIoV1::default() }
    }
}

impl<const N: usize> FixedDeadlineStreamIoV1<N> {
    // Clock/results/cursors have byte cost, but introduce no namespace entry.
    /// Returns the unchanged zero namespace-cell charge for control fields.
    pub const fn receiving_metadata_cells_v1() -> usize { 0 }

    /// Transfers the existing fixed frame under the original cutoff.
    ///
    /// # Errors
    /// Retains invalid extent, native timeout or byte IO, late return, zero
    /// progress, EOF mismatch or reentry without replacing earlier causes.
    pub fn run_once<S: DeadlineStreamV1>(
        &mut self, stream: &mut S, bytes: &mut [u8; N], cutoff: u64,
        direction: DeadlineStreamDirectionV1,
    ) -> Result<(), HistoryErrorV1> {
        self.inner.run_once(stream, bytes, cutoff, direction)
    }

    /// Transfers only the checked original fixed-frame prefix.
    ///
    /// # Errors
    /// Retains invalid extent, native timeout or byte IO, late return, zero
    /// progress, EOF mismatch or reentry without transferring padding.
    pub fn run_prefix_once<S: DeadlineStreamV1>(
        &mut self, stream: &mut S, bytes: &mut [u8; N], length: usize,
        cutoff: u64, direction: DeadlineStreamDirectionV1,
    ) -> Result<(), HistoryErrorV1> {
        self.inner.run_prefix_once(stream, bytes, length, cutoff, direction)
    }

    /// Reports completion of this same original byte flight.
    pub fn completed_exact(&self) -> bool { self.inner.completed_exact() }

    /// Borrows the first retained native or protocol cause without new IO.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> { self.inner.failure() }
}

impl SliceDeadlineStreamIoV1 {
    /// Transfers exactly the actual admitted slice under the original cutoff.
    ///
    /// # Errors
    /// Retains timeout, syscall, extent, non-progress or repeated-entry failure.
    pub fn run_once<S: DeadlineStreamV1>(
        &mut self, stream: &mut S, bytes: &mut [u8], cutoff: u64,
        direction: DeadlineStreamDirectionV1,
    ) -> Result<(), HistoryErrorV1> {
        let length = bytes.len();
        self.run_prefix_once(stream, bytes, length, cutoff, direction)
    }

    /// Transfers a checked prefix without sending or reading its padding.
    ///
    /// # Errors
    /// Retains invalid lengths, timeout, syscall, non-progress or reentry.
    pub fn run_prefix_once<S: DeadlineStreamV1>(
        &mut self, stream: &mut S, bytes: &mut [u8], length: usize,
        cutoff: u64, direction: DeadlineStreamDirectionV1,
    ) -> Result<(), HistoryErrorV1> {
        if self.entered {
            self.closed.get_or_insert(HistoryErrorV1::Correlation);
            return Err(HistoryErrorV1::Correlation);
        }
        self.entered = true;
        self.result = Some(self.run_inner(stream, bytes, length, cutoff, direction));
        if self.failure().is_none() && matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(HistoryErrorV1::Correlation) }
    }

    fn run_inner<S: DeadlineStreamV1>(
        &mut self, stream: &mut S, bytes: &mut [u8], length: usize,
        cutoff: u64, direction: DeadlineStreamDirectionV1,
    ) -> Result<(), HistoryErrorV1> {
        if length == 0 || length > bytes.len()
            || (matches!(direction, DeadlineStreamDirectionV1::Eof) && length != 1)
        {
            return Err(HistoryErrorV1::Extent);
        }
        // Every successful payload call consumes at least one byte. Failure,
        // zero progress and EOF stop immediately, so this is the actual wire
        // extent's bound rather than an independent retry allowance.
        for _ in 0..length {
            let now = clock_gettime(ClockId::Boottime);
            self.step.clock = Some(now);
            self.step.remaining = Some(remaining(now, cutoff));
            let remaining_duration = self.step.remaining.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(HistoryErrorV1::Correlation)?;
            self.step.timeout = Some(match direction {
                DeadlineStreamDirectionV1::Write => stream.write_timeout(remaining_duration),
                DeadlineStreamDirectionV1::Read | DeadlineStreamDirectionV1::Eof => stream.read_timeout(remaining_duration),
            });
            if !matches!(self.step.timeout, Some(Ok(()))) { return Err(HistoryErrorV1::Correlation); }
            self.step.native = Some(match direction {
                DeadlineStreamDirectionV1::Write => stream.write_bytes(&bytes[self.progress..length]),
                DeadlineStreamDirectionV1::Read => stream.read_bytes(&mut bytes[self.progress..length]),
                DeadlineStreamDirectionV1::Eof => stream.read_bytes(&mut bytes[..length]),
            });
            // The same absolute deadline also bounds the returned native
            // effect. Park this independently reached clock even on IO error;
            // neither a late positive payload nor EOF can dispose its step.
            let after = clock_gettime(ClockId::Boottime);
            self.step.after_clock = Some(after);
            self.step.after_remaining = Some(remaining(after, cutoff));
            let reached = self.step.require_timely_native_result()?;
            if matches!(direction, DeadlineStreamDirectionV1::Eof) {
                if reached != 0 { return Err(HistoryErrorV1::Extent); }
                // A completed EOF observation needs no future borrower of its
                // pure clock/timeout/native DTOs. The outer result stays here.
                self.step = DeadlineStreamStepV1::default();
                return Ok(());
            }
            if reached == 0 || reached > length - self.progress { return Err(HistoryErrorV1::Extent); }
            self.progress += reached;
            // The actual frame and committed cursor now carry this step's
            // completed effect. Disposing its positive DTOs releases no permit,
            // resets no flight and changes none of the caller's owed posts.
            self.step = DeadlineStreamStepV1::default();
            if self.progress == length { return Ok(()); }
        }
        Err(HistoryErrorV1::Extent)
    }

    /// Reports completion of this same original byte flight.
    pub fn completed_exact(&self) -> bool {
        self.closed.is_none() && matches!(self.result, Some(Ok(())))
    }

    /// Borrows the first retained native or protocol cause without new IO.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.step.remaining.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &dyn Error)
            .or_else(|| self.step.timeout.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.step.native.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.step.after_remaining.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Borrows one of the original concrete native stream implementations.
///
/// This mechanical adapter is sealed to the existing UnixStream, its borrowed
/// form and RetainedUnixStream. It selects no purpose, amount, authenticated
/// peer or role; external code cannot install a synthetic IO implementation.
pub trait DeadlineStreamV1: sealed::Sealed {
    /// Sets the same native read timeout.
    ///
    /// # Errors
    /// Preserves the native socket timeout error.
    fn read_timeout(&mut self, timeout: Duration) -> io::Result<()>;
    /// Sets the same native write timeout.
    ///
    /// # Errors
    /// Preserves the native socket timeout error.
    fn write_timeout(&mut self, timeout: Duration) -> io::Result<()>;
    /// Reads from the original native stream.
    ///
    /// # Errors
    /// Preserves the original native byte-read error.
    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<usize>;
    /// Writes to the original native stream.
    ///
    /// # Errors
    /// Preserves the original native byte-write error.
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<usize>;
}

impl sealed::Sealed for UnixStream {}

impl DeadlineStreamV1 for UnixStream {
    fn read_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.set_read_timeout(Some(timeout)) }
    fn write_timeout(&mut self, timeout: Duration) -> io::Result<()> { self.set_write_timeout(Some(timeout)) }
    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.read(bytes) }
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> { self.write(bytes) }
}

// Borrows the same actual server stream without cloning its description or
// constructing another endpoint. Root's closed purpose retains the original
// flight and performs its native/peer posts around this shared byte engine.
impl sealed::Sealed for &UnixStream {}

impl DeadlineStreamV1 for &UnixStream {
    fn read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }

    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        std::io::Read::read(self, bytes)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> {
        std::io::Write::write(self, bytes)
    }
}

impl sealed::Sealed for RetainedUnixStream {}

impl DeadlineStreamV1 for RetainedUnixStream {
    fn read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        rustix::net::sockopt::set_socket_timeout(self.as_fd(), rustix::net::sockopt::Timeout::Recv, Some(timeout)).map_err(io::Error::from)
    }
    fn write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        rustix::net::sockopt::set_socket_timeout(self.as_fd(), rustix::net::sockopt::Timeout::Send, Some(timeout)).map_err(io::Error::from)
    }
    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<usize> { rustix::io::read(self.as_fd(), bytes).map_err(io::Error::from) }
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> { rustix::net::send(self.as_fd(), bytes, rustix::net::SendFlags::NOSIGNAL).map_err(io::Error::from) }
}

/// Computes the same bounded timeout from supplied clock comparison DATA.
///
/// The actual transport supplies its own observed BOOTTIME value. This pure
/// conversion cannot establish a new origin, extend a cutoff or admit work.
///
/// # Errors
/// Rejects malformed, overflowing or expired times, including an exact cutoff.
pub fn remaining(now: Timespec, cutoff: u64) -> Result<Duration, HistoryErrorV1> {
    let now = u64::try_from(now.tv_sec).ok().and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| u64::try_from(now.tv_nsec).ok().filter(|value| *value < 1_000_000_000)
            .and_then(|fraction| seconds.checked_add(fraction)))
        .ok_or(HistoryErrorV1::Correlation)?;
    cutoff.checked_sub(now).filter(|remaining| *remaining > 0)
        .map(|remaining| Duration::from_nanos(remaining).min(Duration::from_secs(5)))
        .ok_or(HistoryErrorV1::Correlation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_positive_native_counts_including_eof_remain_refused() {
        for reached in [0, 1, 16] {
            let step = DeadlineStreamStepV1 {
                native: Some(Ok(reached)),
                after_clock: Some(Timespec { tv_sec: 5, tv_nsec: 0 }),
                after_remaining: Some(remaining(Timespec { tv_sec: 5, tv_nsec: 0 }, 5_000_000_000)),
                ..Default::default()
            };

            assert!(step.require_timely_native_result().is_err());
            assert!(matches!(step.native, Some(Ok(actual)) if actual == reached));
            assert!(step.after_clock.is_some());
        }
    }

    #[test]
    fn actual_native_error_precedes_its_independently_owed_late_clock() {
        let mut owner = SliceDeadlineStreamIoV1::default();
        owner.step.native = Some(Err(io::Error::from_raw_os_error(5)));
        owner.step.after_remaining = Some(Err(HistoryErrorV1::Correlation));

        assert!(owner.step.require_timely_native_result().is_err());
        let original = owner.step.native.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(owner.failure().unwrap().downcast_ref::<io::Error>().unwrap(), original));
    }

    #[test]
    fn timeout_uses_original_boottime_cutoff_including_partial_second() {
        assert_eq!(remaining(Timespec { tv_sec: 4, tv_nsec: 999_999_999 }, 5_000_000_000).unwrap(), Duration::from_nanos(1));
        assert!(remaining(Timespec { tv_sec: 5, tv_nsec: 0 }, 5_000_000_000).is_err());
        assert!(remaining(Timespec { tv_sec: 4, tv_nsec: 1_000_000_000 }, 5_000_000_000).is_err());
    }

    #[test]
    fn borrowed_stream_uses_the_same_retained_deadline_engine() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let mut borrowed = &sender;
        let mut original = FixedDeadlineStreamIoV1::<3>::default();
        let mut bytes = *b"abc";

        original.run_once(&mut borrowed, &mut bytes, u64::MAX,
            DeadlineStreamDirectionV1::Write).unwrap();
        let mut received = [0; 3];
        receiver.read_exact(&mut received).unwrap();

        assert_eq!(&received, b"abc");
        assert!(original.completed_exact());
        assert!(original.failure().is_none());
    }

    #[test]
    fn expired_cut_keeps_native_socket_and_does_not_issue_the_first_write() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut original = FixedDeadlineStreamIoV1::<3>::default();
        let mut bytes = *b"abc";

        assert!(original.run_once(&mut sender, &mut bytes, 0, DeadlineStreamDirectionV1::Write).is_err());
        assert!(original.inner.step.native.is_none());
        assert!(original.failure().is_some());
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(receiver.read(&mut [0; 3]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn short_final_prefix_never_sends_padding_and_reentry_keeps_original() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut original = FixedDeadlineStreamIoV1::<8>::default();
        let mut bytes = *b"abcXXXXX";

        original.run_prefix_once(&mut sender, &mut bytes, 3, u64::MAX,
            DeadlineStreamDirectionV1::Write).unwrap();
        let mut received = [0; 3];
        receiver.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"abc");
        assert!(original.completed_exact());
        assert_eq!(original.inner.progress, 3);
        assert!(original.run_prefix_once(&mut sender, &mut bytes, 8, u64::MAX,
            DeadlineStreamDirectionV1::Write).is_err());
        assert_eq!(original.inner.progress, 3);
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(receiver.read(&mut [0; 8]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn short_native_read_keeps_actual_partial_prefix_and_failed_step() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"ab").unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        let mut original = FixedDeadlineStreamIoV1::<4>::default();
        let mut bytes = [0; 4];

        assert!(original.run_once(&mut receiver, &mut bytes, u64::MAX,
            DeadlineStreamDirectionV1::Read).is_err());
        assert_eq!(&bytes[..2], b"ab");
        assert_eq!(original.inner.progress, 2);
        // The completed two-byte step retired after committing progress.
        // The actual non-progressing syscall remains in the same owner.
        assert!(matches!(original.inner.step.native, Some(Ok(0))));
        assert!(original.inner.step.clock.is_some());
        assert!(!original.completed_exact());
        assert!(original.failure().is_some());
    }


    struct ShortWriter {
        limit: usize,
        calls: usize,
        timeouts: usize,
        fail_on: Option<usize>,
        written: Vec<u8>,
    }

    impl sealed::Sealed for ShortWriter {}

    impl DeadlineStreamV1 for ShortWriter {
        fn read_timeout(&mut self, _: Duration) -> io::Result<()> { unreachable!() }
        fn write_timeout(&mut self, _: Duration) -> io::Result<()> {
            self.timeouts += 1;
            Ok(())
        }
        fn read_bytes(&mut self, _: &mut [u8]) -> io::Result<usize> { unreachable!() }
        fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.fail_on == Some(self.calls) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "actual late write"));
            }
            let reached = bytes.len().min(self.limit);
            self.written.extend_from_slice(&bytes[..reached]);
            Ok(reached)
        }
    }

    #[test]
    fn variable_extent_uses_constant_owner_and_exact_positive_call_bound() {
        assert_eq!(std::mem::size_of::<FixedDeadlineStreamIoV1<1>>(),
            std::mem::size_of::<FixedDeadlineStreamIoV1<16_777_216>>());
        assert_eq!(FixedDeadlineStreamIoV1::<16_777_216>::receiving_metadata_cells_v1(), 0);
        let mut stream = ShortWriter { limit: 1, calls: 0, timeouts: 0, fail_on: None, written: Vec::new() };
        let mut bytes = vec![37; 8192];
        let mut original = SliceDeadlineStreamIoV1::default();

        original.run_once(&mut stream, &mut bytes, u64::MAX, DeadlineStreamDirectionV1::Write).unwrap();

        assert_eq!(stream.calls, bytes.len());
        assert_eq!(stream.timeouts, stream.calls);
        assert_eq!(stream.written, bytes);
        assert_eq!(original.progress, bytes.len());
        assert!(original.completed_exact());
        assert!(original.step.clock.is_none());
        assert!(original.step.native.is_none());
        assert!(original.failure().is_none());
    }

    #[test]
    fn variable_late_native_failure_keeps_cursor_frame_and_original_cause_on_reentry() {
        let mut stream = ShortWriter { limit: 1, calls: 0, timeouts: 0, fail_on: Some(3), written: Vec::new() };
        let mut bytes = *b"abcdef";
        let mut original = SliceDeadlineStreamIoV1::default();

        assert!(original.run_once(&mut stream, &mut bytes, u64::MAX, DeadlineStreamDirectionV1::Write).is_err());
        let first = original.failure().unwrap() as *const dyn Error as *const ();
        assert_eq!(original.failure().unwrap().to_string(), "actual late write");
        assert_eq!(original.progress, 2);
        assert_eq!(stream.written, b"ab");
        assert_eq!(&bytes, b"abcdef");
        assert!(matches!(original.step.native, Some(Err(ref error)) if error.kind() == io::ErrorKind::BrokenPipe));

        assert!(original.run_once(&mut stream, &mut bytes, u64::MAX, DeadlineStreamDirectionV1::Write).is_err());
        assert_eq!(stream.calls, 3);
        assert_eq!(first, original.failure().unwrap() as *const dyn Error as *const ());
        assert_eq!(original.progress, 2);
    }

    #[test]
    fn variable_zero_progress_and_eof_keep_their_distinct_native_frontiers() {
        let mut stream = ShortWriter { limit: 0, calls: 0, timeouts: 0, fail_on: None, written: Vec::new() };
        let mut bytes = [17; 2];
        let mut original = SliceDeadlineStreamIoV1::default();
        assert!(original.run_once(&mut stream, &mut bytes, u64::MAX, DeadlineStreamDirectionV1::Write).is_err());
        assert_eq!(stream.calls, 1);
        assert_eq!(original.progress, 0);
        assert!(matches!(original.step.native, Some(Ok(0))));

        let (sender, mut receiver) = UnixStream::pair().unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        let mut eof = SliceDeadlineStreamIoV1::default();
        eof.run_once(&mut receiver, &mut [0], u64::MAX, DeadlineStreamDirectionV1::Eof).unwrap();
        assert!(eof.completed_exact());
        assert!(eof.step.native.is_none());
    }

}
