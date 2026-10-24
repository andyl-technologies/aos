//! Coalesces bounded pending opens without cancelling original backing work.
//!
//! The worker calls this queue only for nodes without an installed backing.
//! It submits one backing request for each returned `Start`, installs successful
//! backing replies before completing their tickets, and sends every extracted
//! reply on the original connection. The queue performs no IO or allocation
//! after construction and grants no descriptor, handle or exposure authority.
//! Expiring or abandoning a waiter never cancels the shared fetch. The serve
//! process retains responsibility for sealing and caching late content.

use std::{
    fmt,
    mem::size_of,
    num::NonZeroU64,
    time::{Duration, Instant},
};

/// Identifies one original in-flight backing request without reusing its sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    node: NonZeroU64,
    sequence: u64,
}

impl Ticket {
    /// Returns the original canonical kernel node whose backing was requested.
    pub const fn node(self) -> NonZeroU64 {
        self.node
    }
}

/// Distinguishes a newly required backing request from another waiter on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Enqueued {
    /// Requires submission of exactly one request for this original ticket.
    Start(Ticket),
    /// Joins the existing request without fetching or registering another file.
    Joined(Ticket),
}

/// Reports one ready kernel response without sending it or creating a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    /// Correlates the response to its original outstanding kernel request.
    pub unique: NonZeroU64,
    /// Identifies the original shared handoff and its canonical node.
    pub ticket: Ticket,
    /// Selects a successful installed backing or the required open error.
    pub outcome: Outcome,
}

/// Resolves one open waiter independently of other waiters and the shared fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Uses the original backing installed for this ticket before completion.
    Ready,
    /// Returns EIO because the backing request failed or this waiter expired.
    IoError,
}

/// Bounds startup storage for independently pending nodes and kernel waiters.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum distinct original backing requests still in flight.
    pub nodes: u32,
    /// Maximum retained kernel open responses, including completed responses.
    pub waiters: u32,
    /// Maximum combined allocated element storage for both reserved vectors.
    pub bytes: usize,
}

/// Refuses invalid startup bounds, request state or a stale handoff completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Startup storage cannot fit its explicit nonzero bounds.
    Budget,
    /// The allocator cannot reserve the complete startup storage.
    Allocation,
    /// The node or waiter count has reached its configured bound.
    Capacity,
    /// A response ID already belongs to another retained open waiter.
    Duplicate,
    /// The deadline is zero or cannot be represented by the supplied clock.
    Deadline,
    /// The monotonic ticket sequence cannot advance without reuse.
    Sequence,
    /// A completion does not name an original request still in flight.
    Stale,
    /// Draining has stopped admission of new kernel open requests.
    Draining,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Budget => "invalid FUSE pending-open storage budget",
            Self::Allocation => "cannot reserve FUSE pending-open storage",
            Self::Capacity => "FUSE pending-open storage is full",
            Self::Duplicate => "FUSE open response ID is already pending",
            Self::Deadline => "invalid FUSE open deadline",
            Self::Sequence => "FUSE backing ticket sequence is exhausted",
            Self::Stale => "FUSE backing completion belongs to a stale ticket",
            Self::Draining => "FUSE exposure is draining",
        })
    }
}

impl std::error::Error for Error {}

struct Waiter {
    unique: NonZeroU64,
    ticket: Ticket,
    deadline: Instant,
    outcome: Option<Outcome>,
}

/// Retains bounded per-waiter deadlines and one original handoff per pending node.
pub struct Queue {
    pending: Vec<Ticket>,
    waiters: Vec<Waiter>,
    limits: Limits,
    next_sequence: u64,
    draining: bool,
}

impl Queue {
    /// Reserves the complete queue before the worker accepts its first open.
    ///
    /// # Errors
    /// Refuses zero or overflowing counts, insufficient byte budgets and failed
    /// allocation. Actual reserved vector capacities must fit the byte budget.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let nodes = usize::try_from(limits.nodes).map_err(|_| Error::Budget)?;
        let waiters = usize::try_from(limits.waiters).map_err(|_| Error::Budget)?;
        if nodes == 0 || waiters == 0 || storage_bytes(nodes, waiters)? > limits.bytes {
            return Err(Error::Budget);
        }

        let mut pending = Vec::new();
        let mut retained = Vec::new();
        pending
            .try_reserve_exact(nodes)
            .map_err(|_| Error::Allocation)?;
        retained
            .try_reserve_exact(waiters)
            .map_err(|_| Error::Allocation)?;
        if storage_bytes(pending.capacity(), retained.capacity())? > limits.bytes {
            return Err(Error::Budget);
        }

        Ok(Self {
            pending,
            waiters: retained,
            limits,
            next_sequence: 1,
            draining: false,
        })
    }

    /// Retains an open with its own deadline, coalescing an existing node fetch.
    ///
    /// `now` is the original open's arrival time on this connection. The caller
    /// checks its installed backing table first; a completed cached backing
    /// requires no enqueue. A node whose earlier waiters expired still joins
    /// its original in-flight ticket. Only `Start` submits new physical work.
    ///
    /// # Errors
    /// Refuses draining, a duplicate response ID, invalid deadlines, exhausted
    /// storage or ticket sequences. Refusal changes no queue or sequence state.
    pub fn enqueue(
        &mut self,
        node: NonZeroU64,
        unique: NonZeroU64,
        now: Instant,
        timeout: Duration,
    ) -> Result<Enqueued, Error> {
        if self.draining {
            return Err(Error::Draining);
        }
        let deadline = now
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::Deadline)?;
        if self.waiters.iter().any(|waiter| waiter.unique == unique) {
            return Err(Error::Duplicate);
        }
        if self.waiters.len() >= self.limits.waiters as usize {
            return Err(Error::Capacity);
        }

        let result = if let Some(ticket) = self.pending.iter().find(|ticket| ticket.node == node) {
            Enqueued::Joined(*ticket)
        } else {
            if self.pending.len() >= self.limits.nodes as usize {
                return Err(Error::Capacity);
            }
            let next = self.next_sequence.checked_add(1).ok_or(Error::Sequence)?;
            let ticket = Ticket {
                node,
                sequence: self.next_sequence,
            };
            self.pending.push(ticket);
            self.next_sequence = next;
            Enqueued::Start(ticket)
        };
        let ticket = match result {
            Enqueued::Start(ticket) | Enqueued::Joined(ticket) => ticket,
        };
        self.waiters.push(Waiter {
            unique,
            ticket,
            deadline,
            outcome: None,
        });
        Ok(result)
    }

    /// Completes the original fetch without discarding expired or abandoned work.
    ///
    /// Before `Ready`, the caller installs the original checked backing under
    /// this exact ticket. A late success remains usable for later opens even
    /// if this queue has no waiters. Failure permits a later new ticket for the
    /// node; old response IDs retain their failed outcome independently.
    ///
    /// # Errors
    /// Refuses stale, repeated or foreign ticket completions without mutation.
    pub fn complete(&mut self, ticket: Ticket, outcome: Outcome) -> Result<(), Error> {
        let position = self
            .pending
            .iter()
            .position(|pending| *pending == ticket)
            .ok_or(Error::Stale)?;
        self.pending.swap_remove(position);
        for waiter in &mut self.waiters {
            if waiter.ticket == ticket {
                waiter.outcome = Some(outcome);
            }
        }
        Ok(())
    }

    /// Extracts one completed or expired response, returning EIO at its deadline.
    ///
    /// The worker drains ready responses before waiting for more events and
    /// faults the connection if sending one fails. Removing a waiter never
    /// cancels its original pending fetch or acknowledges physical release.
    pub fn next_reply(&mut self, now: Instant) -> Option<Reply> {
        let position = self
            .waiters
            .iter()
            .position(|waiter| waiter.deadline <= now || waiter.outcome.is_some())?;
        let waiter = self.waiters.swap_remove(position);
        Some(Reply {
            unique: waiter.unique,
            ticket: waiter.ticket,
            outcome: if waiter.deadline <= now {
                Outcome::IoError
            } else {
                waiter.outcome?
            },
        })
    }

    /// Returns the earliest retained waiter deadline for the worker's event loop.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.waiters.iter().map(|waiter| waiter.deadline).min()
    }

    /// Abandons one original response while leaving its shared fetch in flight.
    ///
    /// The caller separately handles the kernel's interruption/reply protocol.
    /// This operation neither sends a response nor cancels accepted physical work.
    pub fn abandon(&mut self, unique: NonZeroU64) -> bool {
        let Some(position) = self
            .waiters
            .iter()
            .position(|waiter| waiter.unique == unique)
        else {
            return false;
        };
        self.waiters.swap_remove(position);
        true
    }

    /// Stops new admission while retaining existing waiters and original fetches.
    ///
    /// The caller owns the bounded drain grace, device close and durable exposure
    /// transition. This flag never acknowledges backing or kernel reference release.
    pub fn drain(&mut self) {
        self.draining = true;
    }

    /// Returns the number of original backing requests still in flight.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of kernel response obligations retained by this queue.
    pub fn waiting(&self) -> usize {
        self.waiters.len()
    }
}

fn storage_bytes(nodes: usize, waiters: usize) -> Result<usize, Error> {
    nodes
        .checked_mul(size_of::<Ticket>())
        .and_then(|bytes| {
            waiters
                .checked_mul(size_of::<Waiter>())
                .and_then(|waiting| bytes.checked_add(waiting))
        })
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Budget)
}

#[cfg(test)]
mod tests;
