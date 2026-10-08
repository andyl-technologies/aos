//! Captures a fixed process-wide roster of original native allocation extents.
//!
//! Setup and report extraction run outside allocation hooks. Hooks append only
//! scalar layouts under a nonblocking claim; contention, overflow or poisoned
//! state prevents using a partial roster as an allocation witness.

use std::alloc::Layout;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{AllocationIdentity, TestAllocationObserver};

const CAPACITY: usize = 64;
const ARMED: u64 = 1;
const CONTENDED: u64 = 2;
const UNAVAILABLE: u64 = 3;

static ROSTER: Mutex<Option<AllocationRoster>> = Mutex::new(None);
static STATUS: AtomicU64 = AtomicU64::new(0);

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
            *slot = Some(AllocationRoster {
                entries: [EMPTY_EXTENT; CAPACITY],
                allocations: 0,
                reallocations: 0,
                overflow: false,
                outcome: AllocationRosterOutcome::Complete,
            });
            STATUS.store(generation | ARMED, Ordering::Release);
        }
        let mut reset = Reset { armed: true };
        let value = action();
        let mut slot = ROSTER
            .lock()
            .map_err(|_| AllocationRosterSetupError::Unavailable)?;
        let mut report = slot.take().ok_or(AllocationRosterSetupError::Unavailable)?;
        report.outcome = match STATUS.load(Ordering::Acquire) & 7 {
            ARMED => AllocationRosterOutcome::Complete,
            CONTENDED => AllocationRosterOutcome::Contended,
            _ => AllocationRosterOutcome::Unavailable,
        };
        STATUS.fetch_and(!7, Ordering::Release);
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
    match ROSTER.try_lock() {
        Ok(mut slot) => {
            if STATUS.load(Ordering::Acquire) != status {
                return;
            }
            if let Some(roster) = slot.as_mut() {
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

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
        assert_eq!(STATUS.load(Ordering::Acquire) & 7, 0);
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

        eprintln!(
            "roster geometry extent={} report={} mutex={} status={}",
            std::mem::size_of::<AllocationExtent>(),
            std::mem::size_of::<AllocationRoster>(),
            std::mem::size_of::<Mutex<Option<AllocationRoster>>>(),
            std::mem::size_of::<AtomicU64>()
        );
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
        assert!(ROSTER.lock().unwrap_err().into_inner().is_none());
        ROSTER.clear_poison();
        assert_eq!(STATUS.load(Ordering::Acquire) & 7, 0);
    }
}
