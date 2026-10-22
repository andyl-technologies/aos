//! Routes authenticated GC maintenance to the original serving cache owner.
//!
//! A trusted launcher supplies private connected Unix sequenced-packet endpoints,
//! or roles connect beneath a protected operator path using [`MaintenanceListener`].
//! Distinct configured identities bind peers. The channel accepts no descriptors,
//! row identifiers or closure evidence. Each request reconciles the original
//! owner's finite draining inventory through its existing physical queue.
//! Socket operations are nonblocking; callers supply event loops and deadlines.
//! Configured role startup separately owns connection limits and deadlines.

mod listener;
mod socket;
#[cfg(test)]
mod tests;
mod wire;

pub use listener::MaintenanceListener;

use crate::host_cache::{NativeExposureReconciliation, NativeMetadataOwner};
use socket::{Endpoint, Exchange};
use std::{io, os::fd::OwnedFd};

/// Creates private endpoints with credentials enabled before either role sends.
///
/// Both descriptors are close-on-exec. The launcher explicitly arranges their
/// inheritance and closes unrelated copies before starting the role loops.
///
/// # Errors
/// Returns native socket creation or option failures.
pub fn channel_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    socket::pair()
}

/// Selects the distinct configured identities on one private maintenance channel.
#[derive(Clone, Copy, Debug)]
pub struct MaintenanceRoles {
    /// Effective UID of the original serving cache owner.
    pub serve_uid: u32,
    /// Effective UID allowed to request draining-exposure reconciliation.
    pub gc_uid: u32,
}

impl MaintenanceRoles {
    fn check(self, current: u32) -> io::Result<()> {
        if self.serve_uid == self.gc_uid
            || [self.serve_uid, self.gc_uid].contains(&u32::MAX)
            || rustix::process::geteuid().as_raw() != current
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "maintenance role identities differ",
            ));
        }
        Ok(())
    }
}

/// Owns the serving side of a launcher's private maintenance channel.
///
/// An authenticated request grants no release authority: the original owner
/// independently checks every native inode and durable obligation. Kernel
/// message credentials authenticate the configured role, not a worker process
/// incarnation or repository capability.
pub struct MaintenanceServer {
    endpoint: Endpoint,
    sequence: u64,
}

impl MaintenanceServer {
    /// Binds the private connected endpoint as the configured serving identity.
    ///
    /// # Errors
    /// Refuses colliding or incorrect identities, disconnected endpoints,
    /// another socket family or type and native option failures.
    pub fn bind(socket: OwnedFd, roles: MaintenanceRoles) -> io::Result<Self> {
        roles.check(roles.serve_uid)?;
        Ok(Self {
            endpoint: Endpoint::new(socket, roles.gc_uid)?,
            sequence: 1,
        })
    }

    /// Processes one queued authenticated request through the original owner.
    ///
    /// Returns `None` when no request is available. A malformed packet faults
    /// the connection before enqueue. Cancellation after enqueue disconnects
    /// the channel while the original physical owner retains the queued work.
    ///
    /// # Errors
    /// Refuses wrong credentials, descriptors, truncation, replay, unsupported
    /// packets, sequence exhaustion and native transport failures. Owner errors
    /// retain their original obligations and return a bounded failure code to GC.
    pub async fn process_next(
        &mut self,
        owner: &NativeMetadataOwner,
    ) -> io::Result<Option<NativeExposureReconciliation>> {
        let Some(packet) = self.endpoint.receive()? else {
            return Ok(None);
        };
        let mut exchange = Exchange::start(&mut self.endpoint);
        wire::request(&packet, self.sequence)?;
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| wire::invalid("maintenance sequence exhausted"))?;

        let result = owner.reconcile_draining_surface_exposures().await;
        exchange.send(&wire::reply(self.sequence, &result)?)?;
        exchange.complete();
        self.sequence = next;
        result.map(Some)
    }
}

/// Owns the GC side of one launcher's private maintenance channel.
///
/// Only one request can be outstanding. Dropping an incomplete request faults
/// the connection; reconnecting cannot undo work already queued at the owner.
pub struct MaintenanceClient {
    endpoint: Endpoint,
    sequence: u64,
}

impl MaintenanceClient {
    /// Binds the private connected endpoint as the configured GC identity.
    ///
    /// # Errors
    /// Refuses colliding or incorrect identities, disconnected endpoints,
    /// another socket family or type and native option failures.
    pub fn bind(socket: OwnedFd, roles: MaintenanceRoles) -> io::Result<Self> {
        roles.check(roles.gc_uid)?;
        Ok(Self {
            endpoint: Endpoint::new(socket, roles.serve_uid)?,
            sequence: 1,
        })
    }

    /// Requests reconciliation without supplying record data or native evidence.
    ///
    /// # Errors
    /// Refuses a faulted channel, sequence exhaustion and native send failures.
    /// `WouldBlock` before sending leaves the original sequence available.
    pub fn reconcile_draining(&mut self) -> io::Result<PendingReconciliation<'_>> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| wire::invalid("maintenance sequence exhausted"))?;
        self.endpoint.send(&wire::encode_request(self.sequence))?;
        let sequence = self.sequence;
        self.sequence = next;
        Ok(PendingReconciliation {
            exchange: Exchange::start(&mut self.endpoint),
            sequence,
            finished: false,
        })
    }
}

/// Retains exclusive custody of one outstanding maintenance reply.
///
/// The caller must enforce its finite deadline. Dropping this value before a
/// complete authenticated reply disconnects the channel, including on timeout.
pub struct PendingReconciliation<'client> {
    exchange: Exchange<'client>,
    sequence: u64,
    finished: bool,
}

impl PendingReconciliation<'_> {
    /// Receives an authenticated result without blocking.
    ///
    /// Returns `None` while no packet is queued. A completed request cannot be
    /// received again, including after a valid remote failure response.
    ///
    /// # Errors
    /// Refuses wrong credentials, descriptors, truncation, a changed sequence,
    /// invalid counts, unsupported results and native transport failures. A
    /// valid remote failure preserves the connection's next sequence.
    pub fn try_receive(&mut self) -> io::Result<Option<NativeExposureReconciliation>> {
        if self.finished {
            return Err(wire::invalid("maintenance reply already consumed"));
        }
        let Some(packet) = self.exchange.receive()? else {
            return Ok(None);
        };
        let result = match wire::decode_reply(&packet, self.sequence) {
            Ok(result) => result,
            Err(error) => {
                self.exchange.refuse();
                return Err(error);
            }
        };
        self.finished = true;
        self.exchange.complete();
        result.map(Some)
    }
}
