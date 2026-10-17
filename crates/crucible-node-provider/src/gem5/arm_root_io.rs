//! One opaque absolute host budget for a complete native frame or exchange.
//!
//! Each fragment receives only the remaining original allowance. Progress never
//! renews the exchange and its host deadline never becomes simulated time.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

// crucible-lint: allow host-nondeterminism-state -- Only the private transport imports opaque operational timeout state.
use crate::{ProviderError, operational_time::OperationalDeadline};

// crucible-lint: allow host-nondeterminism-state -- Returns one original exchange allowance, without a modeled timestamp or receipt field.
pub(crate) fn deadline(timeout: Duration) -> Result<OperationalDeadline, ProviderError> {
    // crucible-lint: allow host-nondeterminism-state -- Creates the exchange deadline once; individual fragments cannot renew it.
    OperationalDeadline::after(timeout).ok_or(ProviderError::ResourceExhausted(
        "ARM original I/O deadline",
    ))
}

pub(crate) struct NativeDeadlineIo<'a> {
    stream: &'a mut UnixStream,
    // crucible-lint: allow host-nondeterminism-state -- This private socket wrapper retains only the original timeout budget.
    deadline: OperationalDeadline,
}

impl<'a> NativeDeadlineIo<'a> {
    // crucible-lint: allow host-nondeterminism-state -- Borrows the same opaque allowance for every fragment of this exchange.
    pub(crate) fn new(stream: &'a mut UnixStream, deadline: OperationalDeadline) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .remaining()
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ARM original exchange budget exhausted",
                )
            })
    }
}

impl Read for NativeDeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for NativeDeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

#[cfg(test)]
// The negative socket fixture deliberately fails assertions if a budget renews.
// crucible-lint: allow rust-allow -- invalid deadline fixture must fail assertions.
// crucible-lint: allow panic-shortcut -- operational socket assertions are test-only.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn successful_fragment_does_not_renew_original_exchange() {
        let (mut stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&[1]).unwrap();
        let original = deadline(Duration::from_millis(30)).unwrap();
        let mut io = NativeDeadlineIo::new(&mut stream, original);
        assert_eq!(io.read(&mut [0]).unwrap(), 1);
        std::thread::sleep(Duration::from_millis(40));
        peer.write_all(&[2]).unwrap();
        assert_eq!(
            io.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(io.write(&[1]).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(io.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
