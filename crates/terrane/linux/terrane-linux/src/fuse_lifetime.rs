//! Accounts for kernel lookups, original open handles and pending worker work.
//!
//! Storage is reserved at startup and populated only for touched canonical nodes.
//! Successful LOOKUP replies add references; ordinary READDIR and GETATTR do not.
//! FORGET removes lookup references, RELEASE removes one original handle, and
//! pending work holds explicit pins until its last response no longer needs the
//! node. None of these counts proves physical custody closure or permits a tier
//! release acknowledgement. The caller separately owns backing registrations,
//! sealed descriptors, the permanent presented-inode table and the connection.

use crate::fuse_protocol::Request;
use std::{fmt, mem::size_of, num::NonZeroU64};

/// Bounds touched nodes, simultaneously open handles and their reserved storage.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum canonical nodes retained by lookups, handles or pending work.
    pub nodes: u32,
    /// Maximum simultaneous file and directory handles.
    pub handles: u32,
    /// Maximum actual combined vector allocation in bytes.
    pub bytes: usize,
}

/// Distinguishes file and directory handles even when their node is identical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A read-only file handle.
    File,
    /// A directory enumeration handle.
    Directory,
}

/// Refuses exhausted bounds, malformed records and stale kernel references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Startup limits are zero, overflow or exceed the byte budget.
    Budget,
    /// Startup cannot reserve its complete bounded storage.
    Allocation,
    /// The touched-node or simultaneous-handle limit has been reached.
    Capacity,
    /// A lookup, pin or never-reused handle sequence would overflow.
    Overflow,
    /// A node has no retained state or a count would underflow.
    References,
    /// A handle is stale or belongs to a different node or kind.
    Handle,
    /// A FORGET record has malformed framing or exceeds its record limit.
    Protocol,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Budget => "invalid FUSE lifetime storage budget",
            Self::Allocation => "cannot reserve FUSE lifetime storage",
            Self::Capacity => "FUSE lifetime storage is full",
            Self::Overflow => "FUSE lifetime counter or handle sequence is exhausted",
            Self::References => "FUSE node references are absent or insufficient",
            Self::Handle => "FUSE handle is stale or belongs to another node or kind",
            Self::Protocol => "invalid bounded FUSE forget record",
        })
    }
}

impl std::error::Error for Error {}

struct Node {
    id: NonZeroU64,
    lookups: u64,
    pins: u64,
    handles: u32,
}

struct Handle {
    id: NonZeroU64,
    node: NonZeroU64,
    kind: Kind,
}

/// Retains lazy connection-local references without recycling handle identities.
pub struct Table {
    nodes: Vec<Node>,
    handles: Vec<Handle>,
    limits: Limits,
    next_handle: u64,
}

impl Table {
    /// Reserves complete bounded storage before accepting kernel requests.
    ///
    /// Root has an implicit connection lifetime and need not receive LOOKUP
    /// before OPENDIR. Other nodes must first be retained by a successful LOOKUP
    /// or an explicit pending-work pin. Canonical node identity is supplied by
    /// the original checked namespace, never by untrusted request body fields.
    ///
    /// # Errors
    /// Refuses invalid limits, overflowing storage sizes and allocation failures.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let nodes = usize::try_from(limits.nodes).map_err(|_| Error::Budget)?;
        let handles = usize::try_from(limits.handles).map_err(|_| Error::Budget)?;
        if nodes == 0 || handles == 0 || storage_bytes(nodes, handles)? > limits.bytes {
            return Err(Error::Budget);
        }
        let mut retained = Vec::new();
        let mut opened = Vec::new();
        retained
            .try_reserve_exact(nodes)
            .map_err(|_| Error::Allocation)?;
        opened
            .try_reserve_exact(handles)
            .map_err(|_| Error::Allocation)?;
        if storage_bytes(retained.capacity(), opened.capacity())? > limits.bytes {
            return Err(Error::Budget);
        }
        Ok(Self {
            nodes: retained,
            handles: opened,
            limits,
            next_handle: 1,
        })
    }

    /// Adds one positive LOOKUP reply for the original canonical node.
    ///
    /// Call only after metadata encoding succeeds and before sending its reply.
    /// A failed send faults the connection; it never rolls this count back into
    /// a still-serving connection. Negative LOOKUP replies add no reference.
    ///
    /// # Errors
    /// Refuses exhausted node storage or an overflowing lookup count.
    pub fn lookup(&mut self, node: NonZeroU64) -> Result<(), Error> {
        let retained = self.retain(node)?;
        retained.lookups = retained.lookups.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Pins a node for pending work independently of kernel lookup references.
    ///
    /// Each queued response and each shared backing fetch owns its own pin.
    /// Expiring a response removes only that response's pin; the original fetch
    /// stays pinned until completion even after the last waiter disappears.
    ///
    /// # Errors
    /// Refuses exhausted node storage or an overflowing pin count.
    pub fn pin(&mut self, node: NonZeroU64) -> Result<(), Error> {
        let retained = self.retain(node)?;
        retained.pins = retained.pins.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Releases one original pending-work pin without changing kernel handles.
    ///
    /// # Errors
    /// Refuses an absent node or a pin count that would underflow.
    pub fn unpin(&mut self, node: NonZeroU64) -> Result<(), Error> {
        let retained = self.node_mut(node)?;
        retained.pins = retained.pins.checked_sub(1).ok_or(Error::References)?;
        Ok(())
    }

    /// Allocates a distinct original file or directory handle for an open reply.
    ///
    /// The caller validates type, access flags and installed backing first.
    /// Closing a handle never makes its numeric identity available for reuse.
    ///
    /// # Errors
    /// Refuses unknown nodes, exhausted handle/node storage or sequence overflow.
    /// Refusals do not consume a sequence or modify retained reference counts.
    pub fn open(&mut self, node: NonZeroU64, kind: Kind) -> Result<NonZeroU64, Error> {
        if self.handles.len() >= self.limits.handles as usize {
            return Err(Error::Capacity);
        }
        let id = NonZeroU64::new(self.next_handle).ok_or(Error::Overflow)?;
        let next = self.next_handle.checked_add(1).ok_or(Error::Overflow)?;
        let retained = if node.get() == 1 {
            self.retain(node)?
        } else {
            self.node_mut(node)?
        };
        let count = retained.handles.checked_add(1).ok_or(Error::Overflow)?;

        retained.handles = count;
        self.handles.push(Handle { id, node, kind });
        self.next_handle = next;
        Ok(id)
    }

    /// Checks a still-open handle against its original canonical node and kind.
    ///
    /// # Errors
    /// Refuses unknown, released or mismatched handles.
    pub fn check(&self, handle: NonZeroU64, node: NonZeroU64, kind: Kind) -> Result<(), Error> {
        self.handle_position(handle, node, kind).map(|_| ())
    }

    /// Closes exactly one original handle while retaining its lookup references.
    ///
    /// # Errors
    /// Refuses released, unknown or mismatched handles without changing state.
    pub fn close(&mut self, handle: NonZeroU64, node: NonZeroU64, kind: Kind) -> Result<(), Error> {
        let position = self.handle_position(handle, node, kind)?;
        let retained = self.node_mut(node)?;
        retained.handles = retained.handles.checked_sub(1).ok_or(Error::References)?;
        self.handles.swap_remove(position);
        Ok(())
    }

    /// Applies one native FORGET or BATCH_FORGET after validating the whole body.
    ///
    /// These operations never receive a reply, even when their unique ID is
    /// nonzero. Duplicate nodes in a batch are summed before any mutation, so
    /// an over-forget cannot partially release earlier entries. Validation uses
    /// bounded quadratic scans instead of allocating request-sized scratch;
    /// `max_records` caps that work independently of the connection byte limit.
    /// Root's implicit lifetime is independent of explicit lookup counts.
    ///
    /// # Errors
    /// Refuses malformed fields, excessive record counts, missing nodes, summed
    /// count overflow or over-forget. Every refusal leaves all counts unchanged.
    pub fn forget(&mut self, request: Request<'_>, max_records: u32) -> Result<(), Error> {
        let records = Forgets::parse(request, max_records)?;
        for (node, _) in records {
            let total = records
                .into_iter()
                .filter(|(other, _)| *other == node)
                .try_fold(0u64, |total, (_, count)| total.checked_add(count))
                .ok_or(Error::Overflow)?;
            let retained = self
                .nodes
                .iter()
                .find(|entry| entry.id == node)
                .ok_or(Error::References)?;
            if total > retained.lookups {
                return Err(Error::References);
            }
        }
        for (node, count) in records {
            self.node_mut(node)?.lookups -= count;
        }
        Ok(())
    }

    /// Removes one nonroot node with no lookups, open handles or pending pins.
    ///
    /// The caller now unregisters or drops its own backing for this node. This
    /// is not a physical-custody acknowledgement: retained kernel descriptors or
    /// mappings and tier charges follow their separate native closure protocol.
    /// Permanent presented inode numbers are never removed by this operation.
    pub fn next_unreferenced(&mut self) -> Option<NonZeroU64> {
        let position = self.nodes.iter().position(|node| {
            node.id.get() != 1 && node.lookups == 0 && node.handles == 0 && node.pins == 0
        })?;
        Some(self.nodes.swap_remove(position).id)
    }

    fn retain(&mut self, id: NonZeroU64) -> Result<&mut Node, Error> {
        let position = match self.nodes.iter().position(|node| node.id == id) {
            Some(position) => position,
            None => {
                if self.nodes.len() >= self.limits.nodes as usize {
                    return Err(Error::Capacity);
                }
                self.nodes.push(Node {
                    id,
                    lookups: 0,
                    pins: 0,
                    handles: 0,
                });
                self.nodes.len() - 1
            }
        };
        Ok(&mut self.nodes[position])
    }

    fn node_mut(&mut self, id: NonZeroU64) -> Result<&mut Node, Error> {
        self.nodes
            .iter_mut()
            .find(|node| node.id == id)
            .ok_or(Error::References)
    }

    fn handle_position(
        &self,
        id: NonZeroU64,
        node: NonZeroU64,
        kind: Kind,
    ) -> Result<usize, Error> {
        self.handles
            .iter()
            .position(|handle| handle.id == id && handle.node == node && handle.kind == kind)
            .ok_or(Error::Handle)
    }
}

#[derive(Clone, Copy)]
struct Forgets<'a> {
    body: &'a [u8],
    single: Option<NonZeroU64>,
    remaining: u32,
}

impl<'a> Forgets<'a> {
    fn parse(request: Request<'a>, max_records: u32) -> Result<Self, Error> {
        let body = request.body();
        let (single, count, records) = match request.opcode() {
            2 if body.len() == 8 => (
                Some(NonZeroU64::new(request.node()).ok_or(Error::Protocol)?),
                1,
                body,
            ),
            42 if body.len() >= 8 => {
                let count = request.body_u32(0).map_err(|_| Error::Protocol)?;
                let bytes = usize::try_from(count)
                    .ok()
                    .and_then(|count| count.checked_mul(16))
                    .and_then(|count| count.checked_add(8))
                    .ok_or(Error::Protocol)?;
                if request.body_u32(4).map_err(|_| Error::Protocol)? != 0 || body.len() != bytes {
                    return Err(Error::Protocol);
                }
                (None, count, &body[8..])
            }
            _ => return Err(Error::Protocol),
        };
        if count > max_records {
            return Err(Error::Protocol);
        }
        let result = Self {
            body: records,
            single,
            remaining: count,
        };
        // Validate every raw node/count before the infallible checked iterator.
        if single.is_some() {
            if read_u64(records) == 0 {
                return Err(Error::Protocol);
            }
        } else {
            for record in records.as_chunks::<16>().0 {
                if read_u64(record) == 0 || read_u64(&record[8..]) == 0 {
                    return Err(Error::Protocol);
                }
            }
        }
        Ok(result)
    }
}

impl Iterator for Forgets<'_> {
    type Item = (NonZeroU64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        if let Some(node) = self.single {
            return Some((node, read_u64(self.body)));
        }
        let (record, rest) = self.body.split_at(16);
        self.body = rest;
        Some((NonZeroU64::new(read_u64(record))?, read_u64(&record[8..])))
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_ne_bytes(value)
}

fn storage_bytes(nodes: usize, handles: usize) -> Result<usize, Error> {
    nodes
        .checked_mul(size_of::<Node>())
        .and_then(|bytes| {
            handles
                .checked_mul(size_of::<Handle>())
                .and_then(|other| bytes.checked_add(other))
        })
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Budget)
}

#[cfg(test)]
mod tests;
