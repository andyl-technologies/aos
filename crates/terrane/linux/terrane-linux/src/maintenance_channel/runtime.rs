//! Bounds protected-listener connections while retaining the original owner.
//!
//! Every connection has a fixed lifetime, a whole-request deadline and a finite
//! request count. Cancellation closes connections; work already accepted by the
//! physical owner remains in its queue with the original durable obligations.

use super::{MaintenanceListener, MaintenanceServer};
use crate::host_cache::NativeMetadataOwner;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    future::Future,
    io,
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

/// Supplies finite resources for the serving role's maintenance listener.
///
/// These limits govern transport resources, not native closure authority. A
/// request still reconciles only the original owner's bounded durable inventory.
#[derive(Clone, Copy, Debug)]
pub struct MaintenanceLimits {
    /// Maximum accepted active connections, from one through 1024.
    pub max_connections: usize,
    /// Maximum successful requests per connection, from one through 4096.
    pub max_requests: usize,
    /// Positive whole connection lifetime, at most 300 seconds.
    pub connection_timeout: Duration,
    /// Positive request deadline, including idle wait, no longer than the lifetime.
    pub request_timeout: Duration,
}

impl MaintenanceLimits {
    fn check(self) -> io::Result<()> {
        if !(1..=1024).contains(&self.max_connections)
            || !(1..=4096).contains(&self.max_requests)
            || self.connection_timeout.is_zero()
            || self.connection_timeout > Duration::from_secs(300)
            || self.request_timeout.is_zero()
            || self.request_timeout > self.connection_timeout
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "maintenance requires finite connection, request and deadline limits",
            ));
        }
        Ok(())
    }
}

impl MaintenanceListener {
    /// Serves bounded authenticated connections against the original cache owner.
    ///
    /// The caller retains native readiness, process confinement and the trusted
    /// launch context for the entire call. All accepted connections borrow the
    /// same owner; there is no replacement owner or detached service task.
    /// Wrong peers, malformed packets, connection expiry and individual native
    /// failures close only their connection. Native failures retain their actual
    /// bounded wire response; no success is synthesized.
    ///
    /// Shutdown and cancellation close every accepted connection. Already queued
    /// physical work retains its original custody and funding. The listener's
    /// pathname is never removed, replaced or rebound. This service provides
    /// draining reconciliation, not host-local garbage collection.
    ///
    /// # Errors
    /// Refuses invalid limits before reactor registration or accepting peers.
    /// Returns reactor, listener or changed-role failures. The caller supplies
    /// a Tokio runtime with I/O and time enabled.
    ///
    /// # Panics
    /// Panics when invoked without a Tokio I/O or time driver.
    pub async fn serve_until(
        &self,
        owner: &NativeMetadataOwner,
        limits: MaintenanceLimits,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        limits.check()?;
        self.check_current()?;
        let listener = AsyncFd::new(Listener(self))?;
        let connections = FuturesUnordered::new();
        tokio::pin!(shutdown, connections);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                Some(_) = connections.next(), if !connections.is_empty() => {},
                accepted = accept(&listener), if connections.len() < limits.max_connections => {
                    match accepted {
                        Ok(server) => connections.push(connection(
                            server,
                            owner,
                            limits,
                            deadline(limits.connection_timeout)?,
                        )),
                        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                            // Peer refusal must not hide a changed serving identity.
                            self.check_current()?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}

struct Listener<'listener>(&'listener MaintenanceListener);

impl AsRawFd for Listener<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.descriptor().as_raw_fd()
    }
}

struct Connection(MaintenanceServer);

impl AsRawFd for Connection {
    fn as_raw_fd(&self) -> RawFd {
        self.0.endpoint.descriptor().as_raw_fd()
    }
}

async fn accept(listener: &AsyncFd<Listener<'_>>) -> io::Result<MaintenanceServer> {
    loop {
        let mut ready = listener.readable().await?;
        match ready.try_io(|listener| {
            listener
                .get_ref()
                .0
                .accept()?
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn connection(
    server: MaintenanceServer,
    owner: &NativeMetadataOwner,
    limits: MaintenanceLimits,
    lifetime: Instant,
) -> io::Result<()> {
    let mut socket = AsyncFd::new(Connection(server))?;
    for _ in 0..limits.max_requests {
        let expires = lifetime.min(deadline(limits.request_timeout)?);
        tokio::time::timeout_at(expires, receive(&mut socket, owner))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    }
    Ok(())
}

async fn receive(socket: &mut AsyncFd<Connection>, owner: &NativeMetadataOwner) -> io::Result<()> {
    loop {
        let mut ready = socket.readable_mut().await?;
        match ready.get_inner_mut().0.process_next(owner).await? {
            Some(_) => return Ok(()),
            None => ready.clear_ready(),
        }
    }
}

fn deadline(duration: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "maintenance deadline overflow"))
}
