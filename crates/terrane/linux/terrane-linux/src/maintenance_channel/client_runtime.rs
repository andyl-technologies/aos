//! Completes one authenticated GC exchange under a whole-operation deadline.
//!
//! The future owns its connection. Timeout, cancellation and every result close
//! that connection, while accepted physical work remains with the serving owner.

use super::{MaintenanceClient, wire};
use crate::host_cache::NativeExposureReconciliation;
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

impl MaintenanceClient {
    /// Requests one reconciliation with a finite deadline and closes the connection.
    ///
    /// Consumes the authenticated connection, including on cancellation or a
    /// valid remote refusal. Kernel readiness drives both send and receive;
    /// the deadline includes send backpressure and the complete reply wait.
    /// Closing the connection cannot cancel work already accepted by the
    /// original physical owner or discharge its retained obligations.
    ///
    /// # Errors
    /// Refuses a zero timeout or one longer than 300 seconds before registering
    /// the socket. Returns sequence, reactor, transport, authenticated reply and
    /// native refusal errors. Deadline expiry returns [`io::ErrorKind::TimedOut`].
    ///
    /// # Panics
    /// Panics when invoked without a Tokio I/O or time driver.
    pub async fn reconcile_draining_once(
        self,
        timeout: Duration,
    ) -> io::Result<NativeExposureReconciliation> {
        let connection = Connection(self);
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "maintenance requires a positive timeout of at most 300 seconds",
            ));
        }
        connection
            .0
            .sequence
            .checked_add(1)
            .ok_or_else(|| wire::invalid("maintenance sequence exhausted"))?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| wire::invalid("maintenance deadline overflow"))?;
        let mut socket = AsyncFd::new(connection)?;

        tokio::time::timeout_at(deadline, exchange(&mut socket))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

struct Connection(MaintenanceClient);

impl Drop for Connection {
    fn drop(&mut self) {
        // Disconnect even if a launcher accidentally retains another descriptor
        // for this socket. Closing one descriptor alone cannot fault its aliases.
        self.0.endpoint.abort();
    }
}

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.0.endpoint.descriptor().as_raw_fd()
    }
}

async fn exchange(socket: &mut AsyncFd<Connection>) -> io::Result<NativeExposureReconciliation> {
    let sequence = socket.get_ref().0.sequence;
    let request = wire::encode_request(sequence);
    loop {
        let mut ready = socket.writable_mut().await?;
        match ready.try_io(|socket| socket.get_mut().0.endpoint.send(&request)) {
            Ok(result) => {
                result?;
                break;
            }
            Err(_) => continue,
        }
    }

    loop {
        let mut ready = socket.readable_mut().await?;
        match ready.try_io(|socket| {
            socket
                .get_mut()
                .0
                .endpoint
                .receive()?
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
        }) {
            Ok(result) => return wire::decode_reply(&result?, sequence)?,
            Err(_) => continue,
        }
    }
}
