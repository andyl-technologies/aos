//! Bounds one backing exchange while retaining the original connection custody.

use super::{BackingReply, PendingBacking, RequestedBacking, WorkerClient};
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

impl WorkerClient {
    /// Requests and validates one backing descriptor under a whole-exchange deadline.
    ///
    /// Kernel readiness drives both send backpressure and reply receipt. Success
    /// retains this connection for its next sequence. Timeout, cancellation or
    /// failure after registration disconnects it, including retained descriptor
    /// aliases. Accepted physical work and previously received kernel references
    /// keep their original custody; disconnection never acknowledges release.
    ///
    /// # Errors
    /// Refuses a zero timeout or one exceeding 300 seconds before registration
    /// or sending. Preserves request validation and authenticated reply failures
    /// from [`Self::request`] and [`PendingBacking::receive`], and returns reactor
    /// or deadline errors. The caller supplies a Tokio I/O and time driver.
    ///
    /// # Panics
    /// Panics when invoked without a Tokio I/O or time driver after validation.
    pub async fn request_bounded(
        &mut self,
        backing: RequestedBacking,
        timeout: Duration,
    ) -> io::Result<BackingReply> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker backing requires a positive timeout of at most 300 seconds",
            ));
        }
        let (next, expected) = self.prepare(backing)?;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "worker deadline overflow")
        })?;
        // The existing pending-request guard owns cancellation before send too.
        // Register that borrow directly; no duplicated descriptor can outlive it.
        let mut socket = AsyncFd::new(Exchange(PendingBacking {
            client: self,
            expected,
            completed: false,
        }))?;
        tokio::time::timeout_at(deadline, async {
            loop {
                let mut ready = socket.writable_mut().await?;
                match ready.try_io(|socket| {
                    let pending = &mut socket.get_mut().0;
                    pending.client.send(&pending.expected)
                }) {
                    Ok(result) => {
                        result?;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            socket.get_mut().0.client.next_sequence = next;

            loop {
                let mut ready = socket.readable_mut().await?;
                match ready.try_io(|socket| socket.get_mut().0.receive()) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

struct Exchange<'client>(PendingBacking<'client>);

impl AsRawFd for Exchange<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.client.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests;
