//! One-use custody of an already reserved provider GET slot.
//!
//! A guarded copy first reserves both GET and PUT atomically. Its source guard
//! may run in the same isolate; reacquiring that GET slot would self-wait. The
//! ticket moves the real permit, never provider or business authority. Callers
//! authenticate the exact private request before accepting its ticket.
//!
//! ```text
//! ticket = {origin_isolate, pool_generation, ticket_id, request_digest}
//! request_digest = SHA256(canonical private request with ticket omitted)
//! ```

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{Class, Permit, ISOLATE, POOL};

const MAX_TRANSFERS: usize = 128;

thread_local! {
    static TRANSFERS: RefCell<BTreeMap<String, Entry>> = RefCell::new(BTreeMap::new());
}

/// Correlates one real source-slot reservation with an exact private request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    /// Actual origin isolate, independent of a caller's operation identifiers.
    pub(crate) origin_isolate: String,
    /// Identity of the exact pool which admitted the two-slot reservation.
    pub(crate) pool_generation: String,
    /// Fresh one-use registry identity.
    pub(crate) ticket_id: String,
    /// Canonical exact request with this ticket omitted.
    pub(crate) request_digest: String,
}

impl Ticket {
    /// Checks the bounded token shape without accepting capacity or authority.
    ///
    /// # Errors
    /// Refuses malformed identities or a noncanonical SHA-256 commitment.
    pub(crate) fn validate(&self) -> Result<()> {
        for identity in [&self.origin_isolate, &self.pool_generation, &self.ticket_id] {
            ensure!(
                uuid::Uuid::parse_str(identity)?.to_string() == *identity,
                "provider transfer identity malformed"
            );
        }
        ensure!(
            self.request_digest.len() == 64
                && self
                    .request_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "provider transfer request commitment malformed"
        );
        Ok(())
    }
}

struct Entry {
    ticket: Ticket,
    permit: Permit,
    canceled: Rc<Cell<bool>>,
}

/// Invalidates unused or consumed capacity when the real origin is canceled.
#[derive(Clone)]
pub(crate) struct Cancellation {
    ticket_id: String,
    canceled: Rc<Cell<bool>>,
}

impl Cancellation {
    /// Refuses continued source work after its actual origin has closed.
    ///
    /// # Errors
    /// Returns an error once the origin drops or cancels its reservation.
    pub(crate) fn check(&self) -> Result<()> {
        ensure!(!self.canceled.get(), "provider transfer origin closed");
        Ok(())
    }

    /// Cancels only the matching entry and marks any consumed source owner closed.
    pub(crate) fn cancel(&self) {
        self.canceled.set(true);
        TRANSFERS.with(|entries| {
            let mut entries = entries.borrow_mut();
            if entries
                .get(&self.ticket_id)
                .is_some_and(|entry| Rc::ptr_eq(&entry.canceled, &self.canceled))
            {
                entries.remove(&self.ticket_id);
            }
        });
    }
}

/// Owns one transfer until the actual range future completes or is dropped.
pub(crate) struct Reservation {
    ticket: Ticket,
    cancellation: Cancellation,
}

impl Reservation {
    /// Returns the exact closed token for the authenticated private request.
    pub(crate) fn ticket(&self) -> Ticket {
        self.ticket.clone()
    }

    /// Returns a cancellation hook for the origin's immediate signal cleanup.
    pub(crate) fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// Retains the consumed GET slot and its actual origin's cancellation state.
pub(crate) struct SourcePermit {
    pub(crate) permit: Permit,
    pub(crate) cancellation: Cancellation,
}

/// Splits a real atomic two-slot Bulk reservation without changing occupancy.
///
/// # Errors
/// Refuses any other count, class, pool or already changed pool generation.
pub(crate) fn split(mut permit: Permit) -> Result<(Permit, Permit)> {
    ensure!(
        permit.count == 2
            && permit.class == Class::Bulk
            && POOL.with(|current| Rc::ptr_eq(&permit.pool, &current.borrow())),
        "provider transfer requires the actual atomic copy reservation"
    );
    permit.count = 1;
    let source = Permit {
        pool: Rc::clone(&permit.pool),
        count: 1,
        class: Class::Bulk,
    };
    Ok((permit, source))
}

/// Registers one actual source permit for an exact authenticated range.
///
/// # Errors
/// Refuses another count/class/pool, malformed digest or an exhausted registry.
pub(crate) fn register(permit: Permit, request_digest: String) -> Result<Reservation> {
    ensure!(
        permit.count == 1
            && permit.class == Class::Bulk
            && POOL.with(|current| Rc::ptr_eq(&permit.pool, &current.borrow())),
        "provider source transfer differs from admitted capacity"
    );
    let ticket = Ticket {
        origin_isolate: ISOLATE.with(Clone::clone),
        pool_generation: permit.pool.generation.clone(),
        ticket_id: uuid::Uuid::new_v4().to_string(),
        request_digest,
    };
    ticket.validate()?;
    let cancellation = Cancellation {
        ticket_id: ticket.ticket_id.clone(),
        canceled: Rc::new(Cell::new(false)),
    };
    TRANSFERS.with(|entries| -> Result<()> {
        let mut entries = entries.borrow_mut();
        ensure!(
            entries.len() < MAX_TRANSFERS && !entries.contains_key(&ticket.ticket_id),
            "provider transfer registry bound reached"
        );
        entries.insert(
            ticket.ticket_id.clone(),
            Entry {
                ticket: ticket.clone(),
                permit,
                canceled: Rc::clone(&cancellation.canceled),
            },
        );
        Ok(())
    })?;
    Ok(Reservation {
        ticket,
        cancellation,
    })
}

/// Consumes a local actual slot once, or requires a distinct isolate's own admission.
///
/// This function supplies no authentication. The caller first verifies the
/// private request MAC, original, physical source, installed profile and lease.
/// A stale local ticket never falls back to acquiring another slot.
///
/// # Errors
/// Refuses changed commitments, local pool/registry identity or canceled/reused tokens.
pub(crate) fn accept(ticket: &Ticket, request_digest: &str) -> Result<Option<SourcePermit>> {
    ticket.validate()?;
    ensure!(
        ticket.request_digest == request_digest,
        "provider transfer request changed"
    );
    if ticket.origin_isolate != ISOLATE.with(Clone::clone) {
        return Ok(None);
    }
    ensure!(
        POOL.with(|current| current.borrow().generation == ticket.pool_generation),
        "provider transfer local pool changed"
    );
    TRANSFERS.with(|entries| -> Result<Option<SourcePermit>> {
        let mut entries = entries.borrow_mut();
        let entry = entries
            .get(&ticket.ticket_id)
            .ok_or_else(|| anyhow::anyhow!("provider transfer absent or consumed"))?;
        ensure!(
            entry.ticket == *ticket && !entry.canceled.get(),
            "provider transfer identity changed"
        );
        let entry = entries
            .remove(&ticket.ticket_id)
            .ok_or_else(|| anyhow::anyhow!("provider transfer absent or consumed"))?;
        Ok(Some(SourcePermit {
            permit: entry.permit,
            cancellation: Cancellation {
                ticket_id: ticket.ticket_id.clone(),
                canceled: entry.canceled,
            },
        }))
    })
}

#[cfg(test)]
mod tests;
