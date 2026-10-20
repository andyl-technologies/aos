//! Absolute exchange deadlines shared by every clone of one Unix transport.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Duration;

use crate::operational_time::OperationalDeadline;

use crate::connection::ProviderStream;

#[cfg(test)]
#[path = "original_deadline_tests.rs"]
mod original_deadline_tests;

/// Bounds a whole exchange instead of renewing its budget on every byte.
#[derive(Clone)]
pub struct ExchangeDeadline(Rc<Cell<OperationalDeadline>>);

impl ExchangeDeadline {
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), crate::ProviderError> {
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::OperationalDeadline,
            self.0.as_ref(),
        )
    }

    pub(crate) fn original_cut(&self) -> OperationalDeadline {
        self.0.get()
    }

    /// Starts an original whole-exchange budget without exposing host coordinates.
    ///
    /// This budget covers physical preparation and transport only; it is never
    /// a simulation Position, qualification, or permission for native work.
    ///
    /// # Errors
    /// Refuses zero or an unrepresentable original operational deadline.
    pub fn start(budget: Duration) -> io::Result<Self> {
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero exchange budget",
            ));
        }
        let deadline = OperationalDeadline::after(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "exchange deadline overflow")
        })?;
        Ok(Self(Rc::new(Cell::new(deadline))))
    }

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
        let deadline = OperationalDeadline::after(budget).ok_or_else(|| {
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
        let limit = OperationalDeadline::after(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "evidence deadline overflow")
        })?;
        self.0.set(self.0.get().min(limit));
        Ok(())
    }

    /// Returns only the remaining allowance under the same original physical cut.
    ///
    /// # Errors
    /// Refuses expiration without renewing the original budget.
    pub fn remaining(&self) -> io::Result<Duration> {
        self.0
            .get()
            .remaining()
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "exchange deadline expired"))
    }
}

/// Owns a Unix stream whose blocking I/O observes one absolute exchange cut.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: ExchangeDeadline,
}

/// Retains the exact socket and original deadline after a complete-source refusal.
///
/// The refusal neither closes the socket nor starts another exchange period.
pub struct DeadlineStreamBirthRefusal {
    stream: UnixStream,
    deadline: ExchangeDeadline,
    error: io::Error,
}

impl DeadlineStreamBirthRefusal {
    /// Borrows the original deadline admission failure.
    pub fn error(&self) -> &io::Error {
        &self.error
    }

    /// Returns the same socket and nonrenewed original deadline to its owner.
    pub fn into_original(self) -> (UnixStream, ExchangeDeadline) {
        (self.stream, self.deadline)
    }
}

impl DeadlineStream {
    pub(crate) fn observe_original_host_live_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), crate::ProviderError> {
        let Self {
            stream: _,
            deadline,
        } = self;
        // The selected std UnixStream owns its descriptor inline. Kernel socket
        // storage is a separate resource, not Rust requested heap backing.
        deadline.observe_owned11_metadata(observer)
    }

    pub(crate) fn authenticate_original_deadline(
        &self,
        deadline: &ExchangeDeadline,
    ) -> Result<(), crate::ProviderError> {
        if !Rc::ptr_eq(&self.deadline.0, &deadline.0)
            || self.deadline.original_cut() != deadline.original_cut()
        {
            return Err(crate::ProviderError::Correlation(
                "original stream deadline differs",
            ));
        }
        deadline.remaining()?;
        Ok(())
    }

    /// Retains the original socket when its existing complete-source cut refuses.
    ///
    /// The caller starts this absolute deadline before native birth effects.
    /// No failure path resets it, closes the socket, or clones transport custody.
    ///
    /// # Errors
    /// Returns both original inputs on an expired deadline.
    pub fn with_original_deadline_owned(
        stream: UnixStream,
        deadline: ExchangeDeadline,
    ) -> Result<Self, DeadlineStreamBirthRefusal> {
        if let Err(error) = deadline.remaining() {
            return Err(DeadlineStreamBirthRefusal {
                stream,
                deadline,
                error,
            });
        }
        Ok(Self { stream, deadline })
    }

    /// Retains a previously started original exchange cut without renewing it.
    ///
    /// # Errors
    /// Refuses an expired deadline before exposing any stream I/O.
    pub fn with_deadline(stream: UnixStream, deadline: ExchangeDeadline) -> io::Result<Self> {
        deadline.remaining()?;
        Ok(Self { stream, deadline })
    }

    /// Installs the first bounded exchange and returns its independent budget handle.
    ///
    /// # Errors
    /// Rejects zero or unrepresentable budgets before exposing the stream.
    pub fn new(stream: UnixStream, budget: Duration) -> io::Result<(Self, ExchangeDeadline)> {
        let deadline = ExchangeDeadline(Rc::new(Cell::new(OperationalDeadline::at_current())));
        deadline.reset(budget)?;
        Ok((
            Self {
                stream,
                deadline: deadline.clone(),
            },
            deadline,
        ))
    }

    /// Waits for an idle socket without reading bytes or renewing an exchange.
    ///
    /// The source service starts its next absolute cut only after readiness.
    /// The original authenticated socket remains the sole parser authority.
    pub(crate) fn wait_for_request(&self) -> io::Result<()> {
        let mut descriptors = [rustix::event::PollFd::new(
            &self.stream,
            rustix::event::PollFlags::IN,
        )];
        loop {
            match rustix::event::poll(&mut descriptors, None) {
                Err(rustix::io::Errno::INTR) => continue,
                Ok(_) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
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
        deadline.0.set(OperationalDeadline::expired_fixture());

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

mod native5_birth_cut;
pub use native5_birth_cut::{
    OriginalNative5BirthCut, OriginalNative5BirthStream, OriginalNative5BirthStreamRefusal,
};

impl DeadlineStream {
    pub(crate) fn retain_original_operation_deadline(
        &self,
    ) -> Result<ExchangeDeadline, crate::ProviderError> {
        self.deadline.remaining()?;
        Ok(self.deadline.clone())
    }
}

impl ExchangeDeadline {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), crate::ProviderError> {
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::OperationalDeadline,
            self.0.as_ref(),
        )?;
        Ok(())
    }
}

impl DeadlineStream {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), crate::ProviderError> {
        let Self {
            stream: _,
            deadline,
        } = self;
        deadline.observe_unique_capture_metadata(roots, observer)
    }
}

impl ExchangeDeadline {
    pub(crate) fn original_host_startup_allocation_layout_data()
    -> Result<usize, crate::ProviderError> {
        std::mem::size_of::<Cell<OperationalDeadline>>()
            .checked_add(
                crate::retained_metadata::requested_storage::shared_header_storage_data(
                    1,
                    std::mem::align_of::<Cell<OperationalDeadline>>(),
                )?,
            )
            .ok_or(crate::ProviderError::ResourceExhausted(
                "original host deadline layout",
            ))
    }
}

impl DeadlineStream {
    pub(crate) fn authenticate_settled_history_deadline_data(
        &self,
        deadline: &ExchangeDeadline,
    ) -> Result<(), crate::ProviderError> {
        if !Rc::ptr_eq(&self.deadline.0, &deadline.0)
            || self.deadline.original_cut() != deadline.original_cut()
        {
            return Err(crate::ProviderError::Correlation(
                "current17 stream deadline parent differs",
            ));
        }
        Ok(())
    }
}
