//! Absolute exchange deadlines shared by every clone of one Unix transport.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::connection::ProviderStream;

/// Bounds a whole exchange instead of renewing its budget on every byte.
#[derive(Clone)]
pub struct ExchangeDeadline(Rc<Cell<Instant>>);

impl ExchangeDeadline {
    /// Installs a positive finite budget for the next complete exchange.
    ///
    /// # Errors
    /// Rejects zero or unrepresentable deadlines without changing the old cut.
    pub fn reset(&self, budget: Duration) -> io::Result<()> {
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero exchange budget",
            ));
        }
        let deadline = transport_now().checked_add(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "exchange deadline overflow")
        })?;
        self.0.set(deadline);
        Ok(())
    }

    /// Tightens the current exchange without granting another period of host time.
    ///
    /// # Errors
    /// Rejects an already expired deadline, zero budget or deadline overflow.
    pub fn tighten(&self, budget: Duration) -> io::Result<()> {
        self.remaining()?;
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero evidence budget",
            ));
        }
        let limit = transport_now().checked_add(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "evidence deadline overflow")
        })?;
        self.0.set(self.0.get().min(limit));
        Ok(())
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.0
            .get()
            .checked_duration_since(transport_now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "exchange deadline expired"))
    }
}

/// Owns a Unix stream whose blocking I/O observes one absolute exchange cut.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: ExchangeDeadline,
}

impl DeadlineStream {
    /// Installs the first bounded exchange and returns its independent budget handle.
    ///
    /// # Errors
    /// Rejects zero or unrepresentable budgets before exposing the stream.
    pub fn new(stream: UnixStream, budget: Duration) -> io::Result<(Self, ExchangeDeadline)> {
        let deadline = ExchangeDeadline(Rc::new(Cell::new(transport_now())));
        deadline.reset(budget)?;
        Ok((
            Self {
                stream,
                deadline: deadline.clone(),
            },
            deadline,
        ))
    }

    /// Clones native transport custody while preserving the same absolute cut.
    ///
    /// # Errors
    /// Reports inability to duplicate the native socket descriptor.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            deadline: self.deadline.clone(),
        })
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deadline.remaining()?;
        self.stream.flush()
    }
}

impl ProviderStream for DeadlineStream {
    fn fence(&mut self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }
}

// Host time only bounds blocking transport. It never supplies modeled time,
// execution progress, event ordering, persisted state or a provider guarantee.
// crucible-lint: allow rust-allow -- operational socket deadline outside modeled state.
// crucible-lint: allow clippy-disallowed-method -- Operational socket deadlines bound blocking I/O and never supply modeled state or progress.
#[allow(clippy::disallowed_methods)]
fn transport_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid socket/deadline fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- These deadline tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn clones_do_not_renew_an_expired_absolute_exchange() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let (mut original, deadline) = DeadlineStream::new(stream, Duration::from_secs(1)).unwrap();
        let mut cloned = original.try_clone().unwrap();
        deadline.0.set(transport_now() - Duration::from_millis(1));

        assert_eq!(
            original.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            cloned.write(&[1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(deadline.reset(Duration::ZERO).is_err());
        assert!(deadline.tighten(Duration::from_secs(1)).is_err());
    }
}
