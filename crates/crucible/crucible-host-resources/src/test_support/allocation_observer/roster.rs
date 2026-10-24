//! Captures a fixed process-wide roster of original native allocation extents.
//!
//! Setup and report extraction run outside allocation hooks. Hooks append only
//! scalar layouts under a nonblocking claim; contention, overflow or poisoned
//! state prevents using a partial roster as an allocation witness.

use std::alloc::Layout;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::nodes::{MemoryNodeCounters, MemoryNodeReport};
use super::trace::AllocationTrace;
use super::{AllocationIdentity, TestAllocationObserver};

const CAPACITY: usize = 64;
const ARMED: u64 = 1;
const CONTENDED: u64 = 2;
const UNAVAILABLE: u64 = 3;
const PAUSED: u64 = 4;

// The existing global64 roster stays inline: boxing would allocate while
// counting original requests. The32 mode borrows its caller's fixed storage.
// One registry excludes overlaps between both process-wide observations.
// crucible-lint: allow rust-allow -- One inline process-wide roster retains mutually exclusive finite observations without allocation in allocator hooks; its full fixed storage remains a caller funding obligation.
#[allow(clippy::large_enum_variant)]
enum RosterWatch {
    Roster(AllocationRoster),
    Directory(DirectoryTrace),
    Nodes(&'static MemoryNodeCounters),
}

struct DirectoryTrace {
    trace: &'static AllocationTrace<32>,
    source_live: &'static AtomicBool,
    funded: &'static [AtomicBool; 32],
}

static ROSTER: Mutex<Option<RosterWatch>> = Mutex::new(None);
static STATUS: AtomicU64 = AtomicU64::new(0);
static NODE_GENERATION: AtomicU64 = AtomicU64::new(0);
// A permanent safe reference identifies the original static live-slot storage.
// It is not an active watch: generation and ROSTER still own every observation.
// This avoids claiming the registry for unrelated global physical frees.
static NODE_ORIGINAL: OnceLock<&'static MemoryNodeCounters> = OnceLock::new();

thread_local! {
    static NODE_OWNER: Cell<u64> = const { Cell::new(0) };
}

/// Identifies one successful original allocation by its scalar extent.
#[derive(Clone, Copy, Debug)]
pub struct AllocationExtent {
    address: usize,
    bytes: usize,
    alignment: usize,
}

impl AllocationExtent {
    /// Identifies the actual allocation base without accessing its contents.
    pub const fn identity(self) -> AllocationIdentity {
        AllocationIdentity(self.address)
    }

    /// Returns the original requested allocation size.
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns the original requested native alignment.
    pub const fn alignment(self) -> usize {
        self.alignment
    }

    /// Checks whether an original field address lies inside this allocation.
    ///
    /// A contained scalar address alone does not establish ownership or funding.
    pub const fn contains_address(self, address: usize) -> bool {
        self.address != 0 && address >= self.address && address - self.address < self.bytes
    }
}

const EMPTY_EXTENT: AllocationExtent = AllocationExtent {
    address: 0,
    bytes: 0,
    alignment: 0,
};

/// Distinguishes a complete original roster from nonblocking refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationRosterOutcome {
    /// Every successful allocation entry was observed without lock refusal.
    Complete,
    /// A hook could not acquire the watch; the partial roster proves nothing.
    Contended,
    /// Poisoned or missing state prevents using the roster.
    Unavailable,
}

/// Owns at most 64 recorded original allocation extents from one action.
///
/// Entries are scalar identities rather than references into allocations. The
/// caller retains actual owners and joins all allocating workers before the
/// action returns. More than 64 allocations, reallocations or any refusal must
/// be rejected before selecting an original extent.
#[derive(Debug)]
pub struct AllocationRoster {
    entries: [AllocationExtent; CAPACITY],
    /// Successful allocation and zeroed-allocation entries, including overflow.
    pub allocations: usize,
    /// Native reallocation entries; these invalidate a fixed-extent witness.
    pub reallocations: usize,
    /// Indicates roster capacity or scalar count saturation.
    pub overflow: bool,
    /// Reports whether every allocator entry acquired its original watch.
    pub outcome: AllocationRosterOutcome,
}

impl AllocationRoster {
    /// Iterates over the retained original entries in recording order.
    pub fn entries(&self) -> impl Iterator<Item = AllocationExtent> + '_ {
        self.entries
            .iter()
            .take(self.allocations.min(CAPACITY))
            .copied()
    }
}

/// Refuses overlapping or unavailable process-wide roster capture.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocationRosterSetupError {
    /// A preceding action still owns the global roster.
    #[error("an allocation roster is already armed")]
    AlreadyArmed,
    /// Poisoned or exhausted original watch state prevents capture.
    #[error("allocation roster capture is unavailable")]
    Unavailable,
}

struct Reset {
    armed: bool,
}

impl Drop for Reset {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut slot = match ROSTER.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        STATUS.fetch_and(!7, Ordering::Release);
        NODE_GENERATION.store(0, Ordering::Release);
        let _ = NODE_OWNER.try_with(|owner| owner.set(0));
        if let Some(RosterWatch::Directory(directory)) = slot.as_ref() {
            directory.trace.disarm();
        }
        *slot = None;
    }
}

impl TestAllocationObserver {
    /// Captures a fixed process-wide roster during one synchronous action.
    ///
    /// The action runs outside allocator hooks and joins every allocating worker
    /// before returning. Hooks record only successful allocation layouts with a
    /// nonblocking lock. The returned roster is invalid on refusal, overflow or
    /// reallocation; scalar entries do not establish owner provenance or funding.
    /// Setup, extraction and unwind teardown may wait outside hooks only.
    ///
    /// # Errors
    /// Refuses overlapping capture, poisoned state or generation exhaustion.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and clearing the roster.
    pub fn capture_allocation_roster<T>(
        action: impl FnOnce() -> T,
    ) -> Result<(T, AllocationRoster), AllocationRosterSetupError> {
        {
            let mut slot = ROSTER
                .lock()
                .map_err(|_| AllocationRosterSetupError::Unavailable)?;
            if slot.is_some() {
                return Err(AllocationRosterSetupError::AlreadyArmed);
            }
            let generation = (STATUS.load(Ordering::Relaxed) & !7)
                .checked_add(8)
                .ok_or(AllocationRosterSetupError::Unavailable)?;
            *slot = Some(RosterWatch::Roster(AllocationRoster {
                entries: [EMPTY_EXTENT; CAPACITY],
                allocations: 0,
                reallocations: 0,
                overflow: false,
                outcome: AllocationRosterOutcome::Complete,
            }));
            STATUS.store(generation | ARMED, Ordering::Release);
        }
        let mut reset = Reset { armed: true };
        let value = action();
        let mut slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        let Some(RosterWatch::Roster(mut report)) = slot.take() else {
            return Err(AllocationRosterSetupError::Unavailable);
        };
        report.outcome = close_roster_status();
        // Extraction ends custody under the same lock. The destructor must not
        // clear a later arm after this lock is released.
        reset.armed = false;
        drop(slot);
        Ok((value, report))
    }
}

pub(super) fn record_allocation(address: usize, layout: Layout, reallocation: bool) {
    if address == 0 && !reallocation {
        return;
    }
    let status = STATUS.load(Ordering::Acquire);
    if status & 7 != ARMED {
        return;
    }
    let node_generation = NODE_GENERATION.load(Ordering::Acquire);
    if node_generation != 0 && NODE_OWNER.try_with(Cell::get).unwrap_or(0) != node_generation {
        return;
    }
    match ROSTER.try_lock() {
        Ok(mut slot) => {
            if STATUS.load(Ordering::Acquire) != status {
                return;
            }
            if let Some(RosterWatch::Roster(roster)) = slot.as_mut() {
                if reallocation {
                    roster.overflow |= roster.reallocations == usize::MAX;
                    roster.reallocations = roster.reallocations.saturating_add(1);
                } else {
                    let index = roster.allocations;
                    roster.overflow |= index >= CAPACITY;
                    roster.allocations = index.saturating_add(1);
                    if index < CAPACITY {
                        roster.entries[index] = AllocationExtent {
                            address,
                            bytes: layout.size(),
                            alignment: layout.align(),
                        };
                    }
                }
            } else if let Some(RosterWatch::Directory(directory)) = slot.as_ref() {
                let index = directory.trace.allocation_count();
                if !reallocation && let Some(funded) = directory.funded.get(index) {
                    funded.store(
                        directory.source_live.load(Ordering::SeqCst),
                        Ordering::SeqCst,
                    );
                }
                directory.trace.record(address, layout, reallocation);
            } else if let Some(RosterWatch::Nodes(nodes)) = slot.as_ref() {
                nodes.record_allocation(address, layout, reallocation);
            } else {
                let _ = STATUS.compare_exchange(
                    status,
                    (status & !7) | UNAVAILABLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => CONTENDED,
                std::sync::TryLockError::Poisoned(_) => UNAVAILABLE,
            };
            // A delayed refusal cannot invalidate a successor generation.
            let _ = STATUS.compare_exchange(
                status,
                (status & !7) | outcome,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

/// Borrows one process-wide32 capture until its original action finishes.
///
/// This token only stops capture under its original generation. It cannot
/// replace a trace, create resources or retain storage past the owning action.
/// The caller joins all allocating workers before outer teardown.
pub struct GlobalAllocationTraceSession {
    generation: u64,
}

impl GlobalAllocationTraceSession {
    /// Stops request recording without ending original capture custody.
    ///
    /// Constructor callbacks use this before a real unwind creates runtime
    /// allocations. Already recorded extents and original funded-at-request
    /// flags remain intact, while independent physical-close watches stay armed.
    /// A contended or unavailable original capture remains refused.
    ///
    /// # Errors
    /// Refuses stale sessions, poisoned state or an unrelated capture mode.
    pub fn pause(&self) -> Result<AllocationRosterOutcome, AllocationRosterSetupError> {
        let slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        let status = STATUS.load(Ordering::Acquire);
        if status & !7 != self.generation
            || !matches!(slot.as_ref(), Some(RosterWatch::Directory(_)))
        {
            return Err(AllocationRosterSetupError::Unavailable);
        }
        Ok(pause_roster_status(status))
    }
}

// A competing nonblocking refusal owns its observed status transition. Pause
// must not erase that refusal between reading ARMED and ending capture.
fn pause_roster_status(observed: u64) -> AllocationRosterOutcome {
    if observed & 7 == ARMED {
        let _ = STATUS.compare_exchange(
            observed,
            (observed & !7) | PAUSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    global_trace_outcome(STATUS.load(Ordering::Acquire))
}

// The atomic close returns the final admitted interval's status. A separate
// read followed by disarm could erase a refusal arriving between the two.
fn close_roster_status() -> AllocationRosterOutcome {
    global_trace_outcome(STATUS.fetch_and(!7, Ordering::AcqRel))
}

fn global_trace_outcome(status: u64) -> AllocationRosterOutcome {
    match status & 7 {
        ARMED | PAUSED => AllocationRosterOutcome::Complete,
        CONTENDED => AllocationRosterOutcome::Contended,
        _ => AllocationRosterOutcome::Unavailable,
    }
}

impl TestAllocationObserver {
    /// Captures process-wide requests in the original32 caller-owned trace.
    ///
    /// This finite mode reuses the existing global64 roster registry. Every
    /// successful request on every thread records its exact scalar extent and
    /// samples the same original static source-live flag at that request index.
    /// The32 funded flags belong to the original caller; neither32 storage nor
    /// the existing64 roster grows to512 entries. Native reallocation, overflow
    /// or lock refusal invalidates the witness. The action retains actual owners
    /// and joins all allocating workers before return. It runs outside hooks.
    ///
    /// # Errors
    /// Refuses overlapping global or same-storage capture, poisoned state or
    /// generation exhaustion. The outcome separately reports hook refusal.
    ///
    /// # Panics
    /// Propagates an action panic after clearing registry and trace custody.
    pub fn capture_global_allocation_trace32<T>(
        trace: &'static AllocationTrace<32>,
        source_live: &'static AtomicBool,
        funded: &'static [AtomicBool; 32],
        action: impl FnOnce(&GlobalAllocationTraceSession) -> T,
    ) -> Result<(T, AllocationRosterOutcome), AllocationRosterSetupError> {
        let generation;
        {
            let mut slot = ROSTER
                .lock()
                .map_err(|_| AllocationRosterSetupError::Unavailable)?;
            if slot.is_some() {
                return Err(AllocationRosterSetupError::AlreadyArmed);
            }
            generation = (STATUS.load(Ordering::Relaxed) & !7)
                .checked_add(8)
                .ok_or(AllocationRosterSetupError::Unavailable)?;
            if !trace.arm() {
                return Err(AllocationRosterSetupError::AlreadyArmed);
            }
            for value in funded {
                value.store(false, Ordering::SeqCst);
            }
            *slot = Some(RosterWatch::Directory(DirectoryTrace {
                trace,
                source_live,
                funded,
            }));
            STATUS.store(generation | ARMED, Ordering::Release);
        }
        let mut reset = Reset { armed: true };
        let value = action(&GlobalAllocationTraceSession { generation });
        let mut slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        if !matches!(slot.as_ref(), Some(RosterWatch::Directory(_))) {
            return Err(AllocationRosterSetupError::Unavailable);
        }
        let outcome = close_roster_status();
        trace.disarm();
        *slot = None;
        reset.armed = false;
        drop(slot);
        Ok((value, outcome))
    }
}

/// Retains the original node generation across publication and physical closes.
///
/// This token can end owner-thread request tracking without ending global close
/// custody. The caller retains the original counters and joins all borrowers
/// before the synchronous action returns.
pub struct MemoryNodeSession {
    generation: u64,
}

impl MemoryNodeSession {
    /// Ends allocation recording while preserving global physical-close tracking.
    ///
    /// # Errors
    /// Refuses stale, poisoned or unrelated registry custody, another calling
    /// thread, or an owner whose allocation capture has already been paused.
    pub fn pause_allocations(&self) -> Result<(), AllocationRosterSetupError> {
        let slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        if STATUS.load(Ordering::Acquire) & !7 != self.generation
            || !matches!(slot.as_ref(), Some(RosterWatch::Nodes(_)))
        {
            return Err(AllocationRosterSetupError::Unavailable);
        }
        NODE_OWNER
            .try_with(|owner| {
                if owner.get() != self.generation {
                    return Err(AllocationRosterSetupError::Unavailable);
                }
                owner.set(0);
                Ok(())
            })
            .map_err(|_| AllocationRosterSetupError::Unavailable)?
    }
}

impl TestAllocationObserver {
    /// Tracks the original64 live Memory namespace nodes through actual frees.
    ///
    /// Only this thread's successful544/640-byte, alignment8 requests occupy the
    /// original caller's reusable64 live slots. Physical frees on every thread
    /// consume those same identities and sample the original namespace flag
    /// before System frees storage. This finite mode shares roster custody;
    /// it creates no allocator, resource account or allocation owner.
    /// The action joins every freeing worker before returning. Lock refusal,
    /// native reallocation, overflow or remaining live slots invalidates proof.
    /// A complete observation may report unfunded closes as a negative control.
    ///
    /// # Errors
    /// Refuses overlap, nonempty original state, unavailable TLS, poison or
    /// generation exhaustion, or a different permanently bound original counter
    /// object. The report separately retains hook refusal.
    ///
    /// # Panics
    /// Propagates action panics after disarming and clearing registry custody.
    pub fn observe_memory_nodes64<T>(
        original: &'static MemoryNodeCounters,
        action: impl FnOnce(&MemoryNodeSession) -> T,
    ) -> Result<(T, MemoryNodeReport), AllocationRosterSetupError> {
        let generation;
        {
            let mut slot = ROSTER
                .lock()
                .map_err(|_| AllocationRosterSetupError::Unavailable)?;
            if slot.is_some() {
                return Err(AllocationRosterSetupError::AlreadyArmed);
            }
            if !original.is_empty() {
                return Err(AllocationRosterSetupError::Unavailable);
            }
            match NODE_ORIGINAL.get() {
                Some(bound) if !std::ptr::eq(*bound, original) => {
                    return Err(AllocationRosterSetupError::Unavailable);
                }
                Some(_) => {}
                None => NODE_ORIGINAL
                    .set(original)
                    .map_err(|_| AllocationRosterSetupError::Unavailable)?,
            }
            generation = (STATUS.load(Ordering::Relaxed) & !7)
                .checked_add(8)
                .ok_or(AllocationRosterSetupError::Unavailable)?;
            NODE_OWNER
                .try_with(|owner| owner.set(generation))
                .map_err(|_| AllocationRosterSetupError::Unavailable)?;
            *slot = Some(RosterWatch::Nodes(original));
            NODE_GENERATION.store(generation, Ordering::Release);
            STATUS.store(generation | ARMED, Ordering::Release);
        }
        let mut reset = Reset { armed: true };
        let value = action(&MemoryNodeSession { generation });
        let mut slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        if !matches!(slot.as_ref(), Some(RosterWatch::Nodes(_))) {
            return Err(AllocationRosterSetupError::Unavailable);
        }
        let report = original.report(close_roster_status());
        NODE_GENERATION.store(0, Ordering::Release);
        let _ = NODE_OWNER.try_with(|owner| owner.set(0));
        *slot = None;
        reset.armed = false;
        drop(slot);
        Ok((value, report))
    }
}

fn refuse_node_generation(generation: u64, outcome: u64) {
    let _ = STATUS.compare_exchange(
        generation | ARMED,
        generation | outcome,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

// Invalidates the original generation before realloc can move tracked storage.
// The subsequent ordinary request observer still records its own real result.
pub(super) fn invalidate_node_reallocation(address: usize) {
    let generation = NODE_GENERATION.load(Ordering::Acquire);
    if generation == 0 {
        return;
    }
    let selected = NODE_ORIGINAL
        .get()
        .is_some_and(|original| original.is_live(address));
    let owner = NODE_OWNER.try_with(Cell::get).unwrap_or(0) == generation;
    if !selected {
        if owner {
            refuse_node_generation(generation, UNAVAILABLE);
        }
        return;
    }
    let guard = match ROSTER.try_lock() {
        Ok(guard) => guard,
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => CONTENDED,
                std::sync::TryLockError::Poisoned(_) => UNAVAILABLE,
            };
            refuse_node_generation(generation, outcome);
            return;
        }
    };
    if NODE_GENERATION.load(Ordering::Acquire) != generation
        || STATUS.load(Ordering::Acquire) & !7 != generation
    {
        return;
    }
    let Some(RosterWatch::Nodes(original)) = guard.as_ref() else {
        refuse_node_generation(generation, UNAVAILABLE);
        return;
    };
    if !NODE_ORIGINAL
        .get()
        .is_some_and(|bound| std::ptr::eq(*bound, *original))
        || !original.is_live(address)
    {
        refuse_node_generation(generation, UNAVAILABLE);
        return;
    }
    // Exact selected storage is refused before System can move it, including
    // on a worker or after owner-thread request capture has been paused.
    refuse_node_generation(generation, UNAVAILABLE);
}

pub(super) struct NodeCloseClaim {
    _guard: MutexGuard<'static, Option<RosterWatch>>,
}

pub(super) fn claim_node_close(address: usize) -> Option<NodeCloseClaim> {
    let generation = NODE_GENERATION.load(Ordering::Acquire);
    if generation == 0 || address == 0 {
        return None;
    }
    let original = NODE_ORIGINAL.get()?;
    if !original.is_live(address) {
        return None;
    }
    let guard = match ROSTER.try_lock() {
        Ok(guard) => guard,
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => CONTENDED,
                std::sync::TryLockError::Poisoned(_) => UNAVAILABLE,
            };
            refuse_node_generation(generation, outcome);
            return None;
        }
    };
    if NODE_GENERATION.load(Ordering::Acquire) != generation
        || STATUS.load(Ordering::Acquire) & !7 != generation
    {
        return None;
    }
    let Some(RosterWatch::Nodes(original)) = guard.as_ref() else {
        refuse_node_generation(generation, UNAVAILABLE);
        return None;
    };
    if !NODE_ORIGINAL
        .get()
        .is_some_and(|bound| std::ptr::eq(*bound, *original))
        || !original.claim_before_free(address)
    {
        refuse_node_generation(generation, UNAVAILABLE);
        return None;
    }
    // Holding the same original guard through Systemfree prevents publication
    // of a reused address between consuming the old slot and physical close.
    Some(NodeCloseClaim { _guard: guard })
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static NODE_ADDRESSES: [std::sync::atomic::AtomicUsize; 64] =
        [const { std::sync::atomic::AtomicUsize::new(0) }; 64];
    static NODE_ALLOCATIONS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static NODE_FREES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static NODE_OVERFLOW: AtomicBool = AtomicBool::new(false);
    static NODE_FUNDED: AtomicBool = AtomicBool::new(true);
    static NODE_CLOSED: AtomicBool = AtomicBool::new(false);
    static NODE_COUNTERS: MemoryNodeCounters = MemoryNodeCounters {
        addresses: &NODE_ADDRESSES,
        allocations: &NODE_ALLOCATIONS,
        deallocations: &NODE_FREES,
        overflow: &NODE_OVERFLOW,
        funded: &NODE_FUNDED,
        namespace_closed: &NODE_CLOSED,
    };

    #[test]
    fn nonblocking_roster_contention_is_not_complete_capture() {
        let _serial = TEST_LOCK.lock().unwrap();
        let (_, report) = TestAllocationObserver::capture_allocation_roster(|| {
            let _guard = ROSTER.lock().unwrap();
            // Scalar-only refusal control: no native allocation or deallocation.
            record_allocation(1, Layout::new::<u64>(), false);
        })
        .unwrap();

        assert_eq!(report.outcome, AllocationRosterOutcome::Contended);
        assert_eq!(report.allocations, 0);
        assert!(ROSTER.lock().unwrap().is_none());
        static TRACE32: AllocationTrace<32> = AllocationTrace::new();
        static LIVE: AtomicBool = AtomicBool::new(true);
        static FUNDED: [AtomicBool; 32] = [const { AtomicBool::new(false) }; 32];
        let (_, outcome) = TestAllocationObserver::capture_global_allocation_trace32(
            &TRACE32,
            &LIVE,
            &FUNDED,
            |session| {
                {
                    let _guard = ROSTER.lock().unwrap();
                    record_allocation(1, Layout::new::<u64>(), false);
                }
                assert_eq!(session.pause().unwrap(), AllocationRosterOutcome::Contended);
            },
        )
        .unwrap();
        assert_eq!(outcome, AllocationRosterOutcome::Contended);
        assert_eq!(TRACE32.allocation_count(), 0);
        assert!(ROSTER.lock().unwrap().is_none());
        assert_eq!(STATUS.load(Ordering::Acquire) & 7, 0);
        let (_, report) = TestAllocationObserver::observe_memory_nodes64(&NODE_COUNTERS, |_| {
            {
                let _guard = ROSTER.lock().unwrap();
                // An unrelated global free never attempts the node registry,
                // even while this original claim is held by another operation.
                assert!(claim_node_close(usize::MAX).is_none());
                assert_eq!(STATUS.load(Ordering::Acquire) & 7, ARMED);
                record_allocation(1, Layout::from_size_align(544, 8).unwrap(), false);
            }
            assert!(
                NODE_ADDRESSES
                    .iter()
                    .all(|entry| entry.load(Ordering::SeqCst) == 0)
            );
        })
        .unwrap();
        assert_eq!(report.outcome, AllocationRosterOutcome::Contended);
        assert_eq!(report.allocations, 0);
        assert_eq!(NODE_GENERATION.load(Ordering::Acquire), 0);
        assert_eq!(NODE_OWNER.with(Cell::get), 0);
    }

    #[test]
    fn delayed_refusal_cannot_overwrite_successor_roster_generation() {
        let _serial = TEST_LOCK.lock().unwrap();
        let mut old_status = 0;
        TestAllocationObserver::capture_allocation_roster(|| {
            old_status = STATUS.load(Ordering::Acquire);
        })
        .unwrap();
        let (_, report) = TestAllocationObserver::capture_allocation_roster(|| {
            assert!(
                STATUS
                    .compare_exchange(
                        old_status,
                        (old_status & !7) | CONTENDED,
                        Ordering::AcqRel,
                        Ordering::Acquire
                    )
                    .is_err()
            );
        })
        .unwrap();
        assert_eq!(report.outcome, AllocationRosterOutcome::Complete);

        let mut old_generation = 0;
        TestAllocationObserver::observe_memory_nodes64(&NODE_COUNTERS, |_| {
            old_generation = NODE_GENERATION.load(Ordering::Acquire);
        })
        .unwrap();
        let (_, nodes) = TestAllocationObserver::observe_memory_nodes64(&NODE_COUNTERS, |_| {
            refuse_node_generation(old_generation, CONTENDED);
            assert_eq!(
                MemoryNodeSession {
                    generation: old_generation
                }
                .pause_allocations(),
                Err(AllocationRosterSetupError::Unavailable)
            );
        })
        .unwrap();
        assert_eq!(nodes.outcome, AllocationRosterOutcome::Complete);

        eprintln!(
            "roster geometry extent={} report={} mutex={} status={}",
            std::mem::size_of::<AllocationExtent>(),
            std::mem::size_of::<AllocationRoster>(),
            std::mem::size_of_val(&ROSTER),
            std::mem::size_of::<AtomicU64>()
        );
    }

    #[test]
    fn pause_and_atomic_close_preserve_refusals_at_the_exact_transition() {
        let _serial = TEST_LOCK.lock().unwrap();
        let slot = ROSTER.lock().unwrap();
        assert!(slot.is_none());
        let generation = (STATUS.load(Ordering::Acquire) & !7)
            .checked_add(8)
            .unwrap();

        // Deterministically place the real refusal after pause's initial read.
        // The same private transition used by the session cannot overwrite it.
        let observed = generation | ARMED;
        STATUS.store(observed, Ordering::Release);
        STATUS
            .compare_exchange(
                observed,
                generation | CONTENDED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .unwrap();
        assert_eq!(
            pause_roster_status(observed),
            AllocationRosterOutcome::Contended
        );
        assert_eq!(close_roster_status(), AllocationRosterOutcome::Contended);
        assert!(
            STATUS
                .compare_exchange(
                    observed,
                    generation | CONTENDED,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_err()
        );

        // Atomic extraction observes any refusal before disarm and rejects late
        // stale attempts after the admitted interval ends, including successors.
        STATUS.store(observed, Ordering::Release);
        assert_eq!(
            pause_roster_status(observed),
            AllocationRosterOutcome::Complete
        );
        assert_eq!(close_roster_status(), AllocationRosterOutcome::Complete);
        assert!(
            STATUS
                .compare_exchange(
                    observed,
                    generation | UNAVAILABLE,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_err()
        );
        let successor = generation.checked_add(8).unwrap() | ARMED;
        STATUS.store(successor, Ordering::Release);
        assert!(
            STATUS
                .compare_exchange(
                    observed,
                    generation | CONTENDED,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_err()
        );
        assert_eq!(close_roster_status(), AllocationRosterOutcome::Complete);
        assert_eq!(STATUS.load(Ordering::Acquire) & 7, 0);
        drop(slot);
    }

    #[test]
    fn poisoned_watch_refuses_complete_roster_and_teardown_clears_owned_state() {
        let _serial = TEST_LOCK.lock().unwrap();
        // Other roster tests finish their short claims before this arm. This
        // test owns the same registry through the action and its actual refusal.
        let result = TestAllocationObserver::capture_allocation_roster(|| {
            let panic = std::panic::catch_unwind(|| {
                let _guard = ROSTER.lock().unwrap();
                panic!("intentional roster lock poisoning");
            });
            assert!(panic.is_err());
        });
        assert!(matches!(
            result,
            Err(AllocationRosterSetupError::Unavailable)
        ));
        let poisoned = match ROSTER.lock() {
            Err(poisoned) => poisoned,
            Ok(_) => panic!("the original deliberate poison must remain present"),
        };
        assert!(poisoned.into_inner().is_none());
        ROSTER.clear_poison();
        assert_eq!(STATUS.load(Ordering::Acquire) & 7, 0);
        let result = TestAllocationObserver::observe_memory_nodes64(&NODE_COUNTERS, |_| {
            let panic = std::panic::catch_unwind(|| {
                let _guard = ROSTER.lock().unwrap();
                panic!("intentional original node lock poison");
            });
            assert!(panic.is_err());
        });
        assert!(matches!(
            result,
            Err(AllocationRosterSetupError::Unavailable)
        ));
        let poisoned = match ROSTER.lock() {
            Err(poisoned) => poisoned,
            Ok(_) => panic!("the original node poison must remain present"),
        };
        assert!(poisoned.into_inner().is_none());
        ROSTER.clear_poison();
        assert_eq!(NODE_GENERATION.load(Ordering::Acquire), 0);
        assert_eq!(NODE_OWNER.with(Cell::get), 0);
    }
}
