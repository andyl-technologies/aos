//! Latches native sealed-read failures without entering policy or publisher locks.
//!
//! A failed signal retains the original authenticated body, never a caller-selected
//! pathname or token. One bounded registry survives disappearing readers and
//! queue saturation. Its deny latch is shared by every view of that incarnation.

use crate::publisher_local::client::PeerPublishedObject;
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Distinguishes the actual native observation that refused a sealed read.
#[derive(Clone, Copy)]
pub(super) enum Failure {
    Custody = 1,
    Read = 2,
    Identity = 3,
    Boundary = 4,
}

/// Retains original physical custody and a permanently denying failure latch.
pub(super) struct Signal {
    token: [u8; 32],
    rejected: Mutex<Option<Arc<PeerPublishedObject<HostDomainLocation>>>>,
    failure: AtomicU8,
}

impl Signal {
    /// Records the first actual failure without blocking on any command queue.
    pub(super) fn reject(
        &self,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
        failure: Failure,
    ) {
        // Healthy observations retain no body descriptor. Only a real failed
        // read transfers its original body into recovery custody, before the
        // release of the deny latch makes the report visible to the executor.
        let mut rejected = match self.rejected.lock() {
            Ok(rejected) => rejected,
            Err(poisoned) => poisoned.into_inner(),
        };
        if rejected.is_none() {
            *rejected = Some(Arc::clone(body));
        }
        let _ = self
            .failure
            .compare_exchange(0, failure as u8, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Refuses every alias after any original read reports failed verification.
    ///
    /// # Errors
    /// Refuses a permanently rejected original incarnation.
    pub(super) fn check_readable(&self) -> io::Result<()> {
        if self.failure.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original sealed incarnation rejected",
            ));
        }
        Ok(())
    }
}

/// Bounds original sealed-body observations by the owner's configured record budget.
#[derive(Default)]
pub(super) struct Registry {
    entries: Vec<Entry>,
}

struct Entry {
    signal: Arc<Signal>,
    attempted: bool,
}

impl Registry {
    /// Shares one deny latch across all views of the actual publisher incarnation.
    ///
    /// # Errors
    /// Refuses an exhausted finite bound, allocation failure or a conflicting body.
    pub(super) fn register(
        &mut self,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
        limit: usize,
    ) -> io::Result<Arc<Signal>> {
        self.entries.retain(|entry| {
            Arc::strong_count(&entry.signal) > 1 || entry.signal.failure.load(Ordering::SeqCst) != 0
        });
        for entry in &self.entries {
            let signal = &entry.signal;
            if &signal.token != body.incarnation() {
                continue;
            }
            signal.check_readable()?;
            return Ok(Arc::clone(signal));
        }
        if self.entries.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "sealed failure registry exhausted",
            ));
        }
        self.entries.try_reserve(1).map_err(io::Error::other)?;
        let signal = Arc::new(Signal {
            token: *body.incarnation(),
            rejected: Mutex::new(None),
            failure: AtomicU8::new(0),
        });
        self.entries.push(Entry {
            signal: Arc::clone(&signal),
            attempted: false,
        });
        Ok(signal)
    }

    /// Retains the first failed original body without automatically retrying effects.
    ///
    /// # Errors
    /// Refuses a deny latch lacking its original retained failed body.
    pub(super) fn next(
        &mut self,
    ) -> io::Result<Option<(Arc<PeerPublishedObject<HostDomainLocation>>, u8)>> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| !entry.attempted && entry.signal.failure.load(Ordering::SeqCst) != 0)
        else {
            return Ok(None);
        };
        let rejected = match entry.signal.rejected.lock() {
            Ok(rejected) => rejected,
            Err(poisoned) => poisoned.into_inner(),
        };
        let body = Arc::clone(
            rejected
                .as_ref()
                .ok_or_else(|| io::Error::other("sealed failure lost original body custody"))?,
        );
        // An uncertain channel outcome is reconciled, never blindly retried.
        entry.attempted = true;
        Ok(Some((body, entry.signal.failure.load(Ordering::SeqCst))))
    }
}

/// Counts conservative per-source failure custody, including registry vector overlap.
pub(super) fn storage_bytes() -> usize {
    std::mem::size_of::<Signal>() + 4 * std::mem::size_of::<Arc<Signal>>()
}
