//! Reserves one original backing slot per touched canonical FUSE node.
//!
//! A worker reserves a slot before submitting the corresponding open ticket.
//! Only that ticket may install its checked descriptor or fail the reservation.
//! Repeated opens and hardlinks borrow the same installed backing. Retirement
//! follows `fuse_lifetime::Table::next_unreferenced`, after every lookup, handle
//! and pending-work pin has gone. Neither retirement nor dropping this table
//! proves physical custody closure or authorizes a tier release acknowledgement.

use crate::{fuse_open::Ticket, fuse_read::Backing};
use std::{fmt, mem::size_of, num::NonZeroU64};

/// Bounds simultaneous pending and installed original backing records.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum touched canonical nodes with a reserved or installed backing.
    pub nodes: u32,
    /// Maximum actual vector allocation, excluding resources owned by backings.
    pub bytes: usize,
}

/// Refuses invalid storage, duplicate nodes and stale handoff transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Startup limits are zero, overflow or exceed their byte budget.
    Budget,
    /// Startup cannot reserve the complete storage.
    Allocation,
    /// No slot remains for another original canonical node.
    Capacity,
    /// The node already has an original reservation or installed backing.
    Duplicate,
    /// The ticket does not name an original pending reservation.
    Stale,
    /// Retirement would discard a still-pending original fetch.
    Pending,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Budget => "invalid FUSE backing storage budget",
            Self::Allocation => "cannot reserve FUSE backing storage",
            Self::Capacity => "FUSE backing storage is full",
            Self::Duplicate => "FUSE node already owns a backing slot",
            Self::Stale => "FUSE backing completion belongs to a stale ticket",
            Self::Pending => "FUSE backing fetch remains pending",
        })
    }
}

impl std::error::Error for Error {}

/// Returns a refused installation with its original resource still owned.
#[derive(Debug)]
pub struct Rejected<B> {
    /// The reason the table could not install the backing.
    pub error: Error,
    /// The original backing, which has not replaced or dropped any table entry.
    pub backing: B,
}

struct Entry<B> {
    ticket: Ticket,
    started: bool,
    backing: Option<B>,
}

/// Owns bounded pending reservations and one installed resource per node.
///
/// The default resource is a checked sealed fallback descriptor. A caller may
/// instead own a composite resource that also retains its original passthrough
/// registration. The table never authenticates resources or creates authority;
/// the worker must validate them against its original prepared file before
/// installation. All transitions allocate nothing after construction.
pub struct Table<B = Backing> {
    entries: Vec<Entry<B>>,
    maximum: usize,
}

impl<B> Table<B> {
    /// Reserves complete storage independently of the immutable tree's size.
    ///
    /// # Errors
    /// Refuses zero counts, overflowing sizes, insufficient byte budgets and
    /// allocation failures. Actual reserved capacity must fit the byte budget.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let maximum = usize::try_from(limits.nodes).map_err(|_| Error::Budget)?;
        let bytes = maximum
            .checked_mul(size_of::<Entry<B>>())
            .ok_or(Error::Budget)?;
        if maximum == 0 || bytes > limits.bytes {
            return Err(Error::Budget);
        }

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Allocation)?;
        if entries
            .capacity()
            .checked_mul(size_of::<Entry<B>>())
            .is_none_or(|bytes| bytes > limits.bytes)
        {
            return Err(Error::Budget);
        }

        Ok(Self { entries, maximum })
    }

    /// Reserves a new queue ticket before the worker submits physical work.
    ///
    /// Only `fuse_open::Enqueued::Start` needs a slot. Joined waiters retain the
    /// original reservation. If reservation fails, the caller fails that queue
    /// ticket without submitting backing work; a later open may retry.
    ///
    /// # Errors
    /// Refuses a duplicate canonical node or exhausted storage without mutation.
    pub fn reserve(&mut self, ticket: Ticket) -> Result<(), Error> {
        if self.position(ticket.node()).is_some() {
            return Err(Error::Duplicate);
        }
        if self.entries.len() >= self.maximum {
            return Err(Error::Capacity);
        }
        self.entries.push(Entry {
            ticket,
            started: false,
            backing: None,
        });
        Ok(())
    }

    /// Claims one original reserved ticket for submission exactly once.
    ///
    /// A worker with a serial backing channel calls this only when that channel
    /// is idle. Further distinct nodes remain reserved while metadata requests
    /// and open deadlines continue to run. Expired kernel waiters do not cancel
    /// this queued physical work. A failed submission must fail the original
    /// reservation and queue ticket, or fault the exposure.
    pub fn next_fetch(&mut self) -> Option<Ticket> {
        let entry = self.entries.iter_mut().find(|entry| !entry.started)?;
        entry.started = true;
        Some(entry.ticket)
    }

    /// Installs a checked backing under its exact original pending ticket.
    ///
    /// The caller installs before completing the open queue with `Ready`.
    /// Expired waiters do not remove reservations, so late successful work can
    /// still install the original backing and serve a subsequent open.
    ///
    /// # Errors
    /// Returns unsubmitted, stale, repeated or mismatched installations with
    /// the supplied resource intact. An installed backing is never replaced.
    pub fn install(&mut self, ticket: Ticket, backing: B) -> Result<(), Rejected<B>> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.ticket == ticket && entry.started && entry.backing.is_none());
        match entry {
            Some(entry) => {
                entry.backing = Some(backing);
                Ok(())
            }
            None => Err(Rejected {
                error: Error::Stale,
                backing,
            }),
        }
    }

    /// Removes a failed original reservation before completing its open queue.
    ///
    /// # Errors
    /// Refuses foreign, repeated or already installed tickets without mutation.
    pub fn fail(&mut self, ticket: Ticket) -> Result<(), Error> {
        let position = self
            .entries
            .iter()
            .position(|entry| entry.ticket == ticket && entry.backing.is_none())
            .ok_or(Error::Stale)?;
        self.entries.swap_remove(position);
        Ok(())
    }

    /// Borrows the shared installed resource for one original canonical node.
    pub fn get(&self, node: NonZeroU64) -> Option<&B> {
        self.entries.get(self.position(node)?)?.backing.as_ref()
    }

    /// Returns a backing after the caller retires its unreferenced lifetime row.
    ///
    /// The caller supplies only nodes returned by the original lifetime table's
    /// `next_unreferenced`. A peer handle release alone is insufficient. The
    /// returned resource retains ownership for any explicit registration-close
    /// protocol; this operation does not acknowledge physical release.
    ///
    /// # Errors
    /// Refuses a pending fetch without removing its reservation. An absent
    /// backing, including a directory node, returns `Ok(None)`.
    pub fn retire(&mut self, node: NonZeroU64) -> Result<Option<B>, Error> {
        let Some(position) = self.position(node) else {
            return Ok(None);
        };
        if self.entries[position].backing.is_none() {
            return Err(Error::Pending);
        }
        Ok(self.entries.swap_remove(position).backing)
    }

    fn position(&self, node: NonZeroU64) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.ticket.node() == node)
    }
}

#[cfg(test)]
mod tests;
