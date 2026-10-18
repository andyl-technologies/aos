//! Retains bounded verified read operations independently of embedded state locks.
//!
//! Revocation closes the view's backing slot. Already-started reads keep their
//! actual source until completion, and signal quiescence only after dropping it.

use super::{NativeConsumerLease, clock::Deadline};
use crate::host_cache::{NativeLeaseAccounting, NativeResidentChunkSource};
use std::{
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use terrane_core::identity::Identity;

const CLOSED: u64 = 1 << 63;

/// Bounds actual simultaneous consumer reads across one physical owner.
pub(in crate::host_cache::owner) struct ReadBudget {
    active: AtomicUsize,
    limit: usize,
}

impl ReadBudget {
    /// Starts a finite counter selected from validated owner configuration.
    pub(in crate::host_cache::owner) fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn acquire(&self) -> io::Result<ReadPermit<'_>> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_add(1).filter(|next| *next <= self.limit)
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "consumer read budget exhausted")
            })?;
        Ok(ReadPermit { budget: self })
    }
}

struct ReadPermit<'a> {
    budget: &'a ReadBudget,
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        self.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Shares actual immutable backing and short atomic grant updates with readers.
pub(in crate::host_cache::owner) struct ReadView {
    /// Original independently verified chunk identity.
    pub(super) identity: Identity,
    /// Original durable lease owner label, never serving authority alone.
    pub(super) owner: String,
    source: Mutex<Option<Arc<NativeResidentChunkSource>>>,
    budget: Arc<ReadBudget>,
    active_reads: AtomicUsize,
    epoch: AtomicU64,
    expires: AtomicU64,
    monotonic_end: AtomicU64,
    released_accounting: OnceLock<NativeLeaseAccounting>,
}

impl ReadView {
    /// Retains an actual registered source without granting a pending reader access.
    pub(super) fn pending(
        source: Arc<NativeResidentChunkSource>,
        owner: String,
        budget: Arc<ReadBudget>,
    ) -> Self {
        Self {
            identity: source.identity().clone(),
            owner,
            source: Mutex::new(Some(source)),
            budget,
            active_reads: AtomicUsize::new(0),
            epoch: AtomicU64::new(0),
            expires: AtomicU64::new(0),
            monotonic_end: AtomicU64::new(0),
            released_accounting: OnceLock::new(),
        }
    }

    /// Checks that the next short atomic publication can be represented.
    ///
    /// # Errors
    /// Refuses a revoked view or exhausted generation counter.
    pub(super) fn check_publish_slot(&self) -> io::Result<()> {
        self.publish_epoch().map(|_| ())
    }

    fn publish_epoch(&self) -> io::Result<u64> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        if epoch & (CLOSED | 1) != 0 || epoch.checked_add(2).is_none_or(|next| next >= CLOSED) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "consumer view revoked or exhausted",
            ));
        }
        Ok(epoch)
    }

    /// Publishes an actually synchronized grant without holding a lock during IO.
    ///
    /// # Errors
    /// Refuses elapsed deadlines, revocation or counter exhaustion.
    pub(super) fn publish(&self, deadline: Deadline) -> io::Result<()> {
        deadline.check_live()?;
        let epoch = self.publish_epoch()?;
        self.epoch
            .compare_exchange(epoch, epoch + 1, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "consumer view changed before publication",
                )
            })?;
        self.expires.store(deadline.expires, Ordering::SeqCst);
        self.monotonic_end
            .store(deadline.monotonic_end, Ordering::SeqCst);
        self.epoch
            .compare_exchange(epoch + 1, epoch + 2, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "consumer view revoked during publication",
                )
            })?;
        Ok(())
    }

    /// Revokes reads and relinquishes this view's actual backing reference.
    pub(in crate::host_cache::owner) fn close(&self) {
        self.epoch.fetch_or(CLOSED, Ordering::SeqCst);
        // A poisoned read-slot mutex never prevents removing authority. No
        // native IO or embedded/RPC lock is involved in draining this Arc.
        let mut source = match self.source.lock() {
            Ok(source) => source,
            Err(poisoned) => poisoned.into_inner(),
        };
        source.take();
    }

    /// Recognizes the actual shared owner-wide read budget for routing only.
    pub(super) fn belongs_to(&self, budget: &Arc<ReadBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }

    /// Borrows the actual completed release observation, if one was recorded.
    pub(super) fn released_accounting(&self) -> Option<NativeLeaseAccounting> {
        self.released_accounting.get().copied()
    }

    /// Retains the first completed release accounting for idempotent replies.
    pub(super) fn record_release(&self, accounting: NativeLeaseAccounting) {
        let _ = self.released_accounting.set(accounting);
    }

    /// Recognizes actual completion after every started read drops its source.
    pub(super) fn reads_quiescent(&self) -> bool {
        self.active_reads.load(Ordering::Acquire) == 0
    }

    /// Observes one consistent active grant without consulting embedded state.
    ///
    /// # Errors
    /// Refuses a pending/revoked/expired grant or a concurrent atomic update.
    pub(super) fn live_deadline(&self) -> io::Result<Deadline> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        if epoch < 2 || epoch & (CLOSED | 1) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "consumer lease is not active",
            ));
        }
        let deadline = Deadline {
            expires: self.expires.load(Ordering::SeqCst),
            monotonic_end: self.monotonic_end.load(Ordering::SeqCst),
        };
        if self.epoch.load(Ordering::SeqCst) != epoch {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "consumer grant changed during observation",
            ));
        }
        deadline.check_live()?;
        Ok(deadline)
    }

    fn begin_read(&self) -> io::Result<ActiveRead<'_>> {
        let permit = self.budget.acquire()?;
        let source = self
            .source
            .lock()
            .map_err(|_| io::Error::other("consumer backing slot poisoned"))?;
        self.live_deadline()?;
        let retained = source
            .as_ref()
            .ok_or_else(|| io::Error::other("consumer backing revoked"))?;
        self.active_reads
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_add(1)
            })
            .map_err(|_| io::Error::other("consumer read counter overflows"))?;
        Ok(ActiveRead {
            source: Some(Arc::clone(retained)),
            active: &self.active_reads,
            _permit: permit,
        })
    }
}

/// Keeps actual backing and both finite read counters through the real operation.
struct ActiveRead<'a> {
    source: Option<Arc<NativeResidentChunkSource>>,
    active: &'a AtomicUsize,
    _permit: ReadPermit<'a>,
}

impl Drop for ActiveRead<'_> {
    fn drop(&mut self) {
        // Quiescence means the actual source reference has already closed.
        drop(self.source.take());
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl NativeConsumerLease {
    /// Borrows the original identity selected through verified native custody.
    pub fn identity(&self) -> &Identity {
        &self.view.identity
    }

    /// Borrows the durable owner name for this exact lease.
    pub fn owner(&self) -> &str {
        &self.view.owner
    }

    /// Returns the current acknowledged live expiry in Unix seconds.
    ///
    /// # Errors
    /// Refuses pending, revoked, expired or concurrently changing grants.
    pub fn expires_at(&self) -> io::Result<u64> {
        Ok(self.view.live_deadline()?.expires)
    }

    /// Borrows independent accounting observations at the initial grant boundary.
    pub fn initial_accounting(&self) -> &NativeLeaseAccounting {
        &self.initial_accounting
    }

    /// Reads verified plaintext under a live grant without an embedded-store lock.
    ///
    /// A short private slot lock only clones original immutable backing. Actual
    /// IO holds no slot, embedded, worker-job or publisher-RPC mutex. Renewal
    /// leaves the old grant readable until the synchronized new grant publishes.
    ///
    /// # Errors
    /// Refuses a revoked/expired grant, exhausted read budget, changed native
    /// backing or invalid plaintext, and propagates native read failures.
    pub fn read_verified(&self) -> io::Result<Vec<u8>> {
        let read = self.view.begin_read()?;
        let bytes = read
            .source
            .as_ref()
            .ok_or_else(|| io::Error::other("consumer read lost backing"))?
            .read_verified()?;
        self.view.live_deadline()?;
        Ok(bytes)
    }
}
