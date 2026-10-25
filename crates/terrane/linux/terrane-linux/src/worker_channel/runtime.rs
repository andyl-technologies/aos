//! Waits for authenticated worker packets without blocking the serving executor.

use super::{PendingRequest, WorkerChannel, socket::Endpoint};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
    sync::Arc,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

impl WorkerChannel {
    /// Receives one authenticated request under a finite kernel-readiness deadline.
    ///
    /// Returns the original exclusive request guard before repository selection
    /// or physical preparation. The caller separately bounds that subsequent
    /// work. Timeout, cancellation and failure after registration disconnect this
    /// channel without discharging its exposure pins or retained kernel backing.
    /// Successful receipt transfers cancellation custody to [`PendingRequest`].
    ///
    /// # Errors
    /// Refuses a zero timeout or one exceeding 300 seconds before registration
    /// or consumption. Preserves authentication, context, sequence and native
    /// failures from [`Self::receive`], and returns reactor or deadline errors.
    /// The caller supplies a Tokio I/O and time driver.
    ///
    /// # Panics
    /// Panics when invoked without a Tokio I/O or time driver after validation.
    pub async fn receive_bounded(&mut self, timeout: Duration) -> io::Result<PendingRequest<'_>> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker receive requires a positive timeout of at most 300 seconds",
            ));
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker receive deadline overflow",
            )
        })?;
        tokio::time::timeout_at(deadline, self.receive_ready())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    /// Waits for the next actual packet without imposing an idle-mount deadline.
    ///
    /// Cancellation still faults the channel; the retained serving task owns
    /// this wait until receipt or explicit shutdown, independently of opens.
    pub(super) async fn receive_ready(&mut self) -> io::Result<PendingRequest<'_>> {
        let mut socket = AsyncFd::new(Receiving {
            endpoint: Arc::clone(&self.endpoint),
            transferred: false,
        })?;
        let request = loop {
            let mut ready = socket.readable_mut().await?;
            match ready.try_io(|_| self.receive_inner()) {
                Ok(result) => break result?,
                Err(_) => continue,
            }
        };

        // There is no suspension between disarming this guard and transferring
        // the same connection into its original pending-request guard.
        socket.get_mut().transferred = true;
        Ok(PendingRequest {
            channel: self,
            request,
            completed: false,
        })
    }
}

struct Receiving {
    endpoint: Arc<Endpoint>,
    transferred: bool,
}

impl AsRawFd for Receiving {
    fn as_raw_fd(&self) -> RawFd {
        self.endpoint.as_fd().as_raw_fd()
    }
}

impl Drop for Receiving {
    fn drop(&mut self) {
        if !self.transferred {
            self.endpoint.abort();
        }
    }
}
