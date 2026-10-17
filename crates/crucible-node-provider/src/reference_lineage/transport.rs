//! Bounds original native transport and readiness with one opaque host allowance.
//!
//! No clock coordinate leaves this module. Every frame fragment receives the
//! remaining original allowance; socket progress cannot renew the deadline.

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Child,
    time::Duration,
};

use crate::ProviderError;
// crucible-lint: allow host-nondeterminism-state -- This private transport imports only opaque operational expiry and remaining I/O allowance.
use crate::operational_time::OperationalDeadline;

#[derive(Clone, Copy)]
// crucible-lint: allow host-nondeterminism-state -- This nonserialized transport budget has no raw clock-coordinate getter.
pub(crate) struct ExchangeBudget(OperationalDeadline);

impl ExchangeBudget {
    pub(crate) fn after(timeout: Duration) -> Result<Self, ProviderError> {
        // crucible-lint: allow host-nondeterminism-state -- Creates one checked original allowance before connection or frame effects.
        OperationalDeadline::after(timeout)
            .map(Self)
            .ok_or(ProviderError::ResourceExhausted("lineage deadline extent"))
    }

    pub(crate) fn is_expired(self) -> bool {
        self.0.is_expired()
    }

    pub(super) fn require_current(self) -> std::io::Result<()> {
        self.remaining().map(|_| ())
    }

    fn remaining(self) -> std::io::Result<Duration> {
        self.0
            .remaining()
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "lineage original exchange deadline",
                )
            })
    }
}

pub(super) fn connect(
    listener: &UnixListener,
    child: &Child,
    timeout: Duration,
) -> Result<UnixStream, ProviderError> {
    let budget = ExchangeBudget::after(timeout)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer =
                    rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
                if u32::try_from(peer.pid.as_raw_nonzero().get()).ok() != Some(child.id()) {
                    return Err(ProviderError::Correlation("lineage native peer mismatch"));
                }
                budget.require_current()?;
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if super::kernel::exited_without_reaping(child)? {
            return Err(ProviderError::Correlation(
                "lineage native exited before readiness",
            ));
        }
        if budget.is_expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "lineage native readiness deadline",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    budget: ExchangeBudget,
}

impl<'a> DeadlineIo<'a> {
    pub(super) fn new(stream: &'a mut UnixStream, budget: ExchangeBudget) -> Self {
        Self { stream, budget }
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.budget.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.budget.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
