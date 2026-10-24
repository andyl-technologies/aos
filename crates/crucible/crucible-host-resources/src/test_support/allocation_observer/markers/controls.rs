//! Retains two original counter slots across independently concurrent frees.
//!
//! The parent registry excludes observation modes. Each fixed slot has separate
//! nonblocking hook custody; setup/report/reset lock registry then slot0/slot1.
//! Hooks take one slot only and retain it across actual Systemfree and samples.

use std::cell::Cell;
use std::sync::atomic::AtomicU8;

use super::*;

/// Selects one of the two fixed original-control slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalControlSlot {
    /// The first original control.
    First,
    /// The second original control.
    Second,
}

impl OriginalControlSlot {
    fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }
}

/// Identifies an explicit extent or the first original constructor request.
#[derive(Clone, Copy, Debug)]
pub enum OriginalControlSelection {
    /// A separately established original allocation identity.
    Explicit(AllocationIdentity),
    /// The first successful request of this size on the observation thread.
    FirstThreadExtent(std::num::NonZeroUsize),
    /// The first request matching the original constructor's current charge.
    FirstThreadRequestedExtent(&'static AtomicU64),
}

/// Retains exact original static counters for fixed allocator observations.
///
/// These closed cases read the original counter objects with sequential
/// consistency. They cannot call user code, reserve resources or access an
/// allocation's contents. A snapshot alone establishes no funding or provenance.
#[derive(Clone, Copy, Debug)]
pub enum OriginalStaticCounters {
    /// One original loan-closed or live flag.
    Bool(&'static AtomicBool),
    /// Two distinct original loan flags for the same enclosing control.
    BothFlags {
        /// The first original flag.
        first: &'static AtomicBool,
        /// The second original flag.
        second: &'static AtomicBool,
    },
    /// One particular original grant's paid amount.
    U64(&'static AtomicU64),
    /// Original usage, preconstruction baseline, selected extent and value drops.
    UsageAndDrops {
        /// The original outstanding usage.
        used: &'static AtomicUsize,
        /// The original usage before the selected constructor.
        baseline: &'static AtomicUsize,
        /// The selected actual enclosing control extent.
        extent: &'static AtomicUsize,
        /// The original payload drop count.
        drops: &'static AtomicUsize,
    },
}

/// Contains raw values sampled from the same original static objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalControlSnapshot {
    /// The original Boolean value.
    Bool(bool),
    /// The two distinct original flag values.
    BothFlags {
        /// The first original value.
        first: bool,
        /// The second original value.
        second: bool,
    },
    /// The particular original grant's value.
    U64(u64),
    /// The original usage and payload observations.
    UsageAndDrops {
        /// Original outstanding usage at the physical close.
        used: usize,
        /// Original preconstruction usage.
        baseline: usize,
        /// Selected actual enclosing control extent.
        extent: usize,
        /// Original payload drops at the physical close.
        drops: usize,
    },
}

impl OriginalStaticCounters {
    fn sample(self) -> OriginalControlSnapshot {
        match self {
            Self::Bool(original) => OriginalControlSnapshot::Bool(original.load(Ordering::SeqCst)),
            Self::BothFlags { first, second } => OriginalControlSnapshot::BothFlags {
                first: first.load(Ordering::SeqCst),
                second: second.load(Ordering::SeqCst),
            },
            Self::U64(original) => OriginalControlSnapshot::U64(original.load(Ordering::SeqCst)),
            Self::UsageAndDrops {
                used,
                baseline,
                extent,
                drops,
            } => OriginalControlSnapshot::UsageAndDrops {
                used: used.load(Ordering::SeqCst),
                baseline: baseline.load(Ordering::SeqCst),
                extent: extent.load(Ordering::SeqCst),
                drops: drops.load(Ordering::SeqCst),
            },
        }
    }
}

/// Records original custody around one exact physical System deallocation.
#[derive(Clone, Copy, Debug)]
pub struct OriginalControlObservation {
    /// The actual selected scalar allocation identity.
    pub identity: AllocationIdentity,
    /// The original counters immediately before System free.
    pub before: OriginalControlSnapshot,
    /// The same original counters after free when through-free sampling was armed.
    pub after: Option<OriginalControlSnapshot>,
    /// One-based publication order after each observed physical close.
    ///
    /// Concurrent publications do not prove a total order of System frees.
    pub ordinal: u8,
}

/// Distinguishes actual completion from absent or refused control observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalControlsOutcome {
    /// Every explicitly armed control physically closed and was sampled.
    Complete,
    /// No control was armed, or an armed target did not close during the action.
    Missing,
    /// A nonblocking hook claim was busy; no complete ordering is established.
    Contended,
    /// Original watch state was unavailable; no complete ordering is established.
    Unavailable,
}

/// Retains the fixed scalar result for at most two original controls.
#[derive(Clone, Copy, Debug)]
pub struct OriginalControlReport {
    /// Completion or explicit failure to establish complete original observations.
    pub outcome: OriginalControlsOutcome,
    /// Actual observations in their caller-selected slots.
    pub controls: [Option<OriginalControlObservation>; 2],
}

#[derive(Clone, Copy)]
struct ControlSlot {
    selection: OriginalControlSelection,
    original: OriginalStaticCounters,
    through_free: bool,
    identity: Option<AllocationIdentity>,
    before: Option<OriginalControlSnapshot>,
    observation: Option<OriginalControlObservation>,
}

pub(super) struct OriginalControls {
    pub(super) generation: u64,
}

struct ControlState {
    generation: u64,
    slot: Option<ControlSlot>,
}

static SLOTS: [Mutex<ControlState>; 2] = [const {
    Mutex::new(ControlState {
        generation: 0,
        slot: None,
    })
}; 2];
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ORDINAL: AtomicU8 = AtomicU8::new(0);

thread_local! {
    // Low bits name only pending original constructor selectors.
    static AUTO: Cell<u64> = const { Cell::new(0) };
}

/// Borrows the current fixed original-control observation outside allocator hooks.
///
/// This token cannot create resources or extend its generation. The observation
/// joins all workers and completes outer teardown before a successor can arm.
/// Counter references are static; the caller separately retains the actual
/// owners and original credit through their selected physical closes.
pub struct OriginalControlSession {
    generation: u64,
}

impl OriginalControlSession {
    /// Arms one empty slot without replacing an earlier target or observation.
    ///
    /// Explicit identities come from the caller's original allocation trace.
    /// Constructor selection accepts its first matching request on this action's
    /// thread before callbacks can close the object. Neither selection alone
    /// establishes that the actual owner or incoming value was originally funded.
    /// This method executes outside allocator hooks.
    ///
    /// # Errors
    /// Refuses occupied slots, duplicate identities, stale sessions or poisoned state.
    pub fn arm(
        &self,
        slot: OriginalControlSlot,
        selection: OriginalControlSelection,
        original: OriginalStaticCounters,
        through_free: bool,
    ) -> Result<(), CloseMarkerSetupError> {
        let mut watch = CLOSE_MARKER
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        let Some(CloseWatch::Controls(controls)) = watch.as_mut() else {
            return Err(CloseMarkerSetupError::Unavailable);
        };
        if controls.generation != self.generation {
            return Err(CloseMarkerSetupError::Unavailable);
        }
        let index = slot.index();
        let mut first = SLOTS[0]
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        let mut second = SLOTS[1]
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        if first.generation != self.generation || second.generation != self.generation {
            return Err(CloseMarkerSetupError::Unavailable);
        }
        let identity = match selection {
            OriginalControlSelection::Explicit(identity) => Some(identity),
            _ => None,
        };
        if let Some(identity) = identity
            && [first.slot, second.slot]
                .iter()
                .flatten()
                .any(|other| other.identity.is_some_and(|other| other.0 == identity.0))
        {
            return Err(CloseMarkerSetupError::AlreadyArmed);
        }
        let selected = if index == 0 { &mut first } else { &mut second };
        if selected.slot.is_some() {
            return Err(CloseMarkerSetupError::AlreadyArmed);
        }
        selected.slot = Some(ControlSlot {
            selection,
            original,
            through_free,
            identity,
            before: None,
            observation: None,
        });
        if let Some(identity) = identity {
            target(index).store(identity.0, Ordering::Release);
        } else {
            AUTO.try_with(|pending| {
                let previous = pending.get();
                let mask = if previous & !7 == self.generation {
                    previous & 3
                } else {
                    0
                };
                pending.set(self.generation | mask | (1 << index));
            })
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        }
        Ok(())
    }

    /// Reads fixed scalar observations for the original generation.
    ///
    /// A live report can verify an intermediate original alias-close order.
    /// Complete requires every armed target's actual physical free; refused or
    /// missing observations never establish original funding. This method runs
    /// outside allocator hooks and does not allocate.
    ///
    /// # Errors
    /// Refuses stale sessions or unavailable original state.
    pub fn report(&self) -> Result<OriginalControlReport, CloseMarkerSetupError> {
        let watch = CLOSE_MARKER
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        let Some(CloseWatch::Controls(controls)) = watch.as_ref() else {
            return Err(CloseMarkerSetupError::Unavailable);
        };
        if controls.generation != self.generation {
            return Err(CloseMarkerSetupError::Unavailable);
        }
        controls.report()
    }
}

impl OriginalControls {
    fn report(&self) -> Result<OriginalControlReport, CloseMarkerSetupError> {
        let first = SLOTS[0]
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        let second = SLOTS[1]
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        if first.generation != self.generation || second.generation != self.generation {
            return Err(CloseMarkerSetupError::Unavailable);
        }
        let slots = [first.slot, second.slot];
        let outcome = match CLOSE_STATUS.load(Ordering::Acquire) & 7 {
            CLOSE_CONTENDED => OriginalControlsOutcome::Contended,
            CLOSE_UNAVAILABLE => OriginalControlsOutcome::Unavailable,
            _ if slots.iter().flatten().count() > 0
                && slots
                    .iter()
                    .flatten()
                    .all(|slot| slot.observation.is_some()) =>
            {
                OriginalControlsOutcome::Complete
            }
            _ => OriginalControlsOutcome::Missing,
        };
        Ok(OriginalControlReport {
            outcome,
            controls: slots.map(|slot| slot.and_then(|slot| slot.observation)),
        })
    }
}

impl TestAllocationObserver {
    /// Observes at most two original controls under the existing marker registry.
    ///
    /// The action arms exact scalar identities or the first original constructor
    /// request, retains all actual owners, and joins every closing worker inside
    /// the action. A claimed nonblocking guard spans System free and fixed
    /// original samples. No admission, callback or original-counter mutation
    /// occurs in allocator observation. Static references prevent dangling
    /// counters; they establish neither original owner provenance nor funding.
    /// Legacy marker modes share this same arm and refuse overlap.
    ///
    /// # Errors
    /// Refuses overlapping, poisoned, exhausted or unavailable original state.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and completing outer teardown.
    pub fn observe_original_controls<T>(
        action: impl FnOnce(&OriginalControlSession) -> T,
    ) -> Result<(T, OriginalControlReport), CloseMarkerSetupError> {
        let mut watch = CLOSE_MARKER
            .lock()
            .map_err(|_| CloseMarkerSetupError::Unavailable)?;
        if watch.is_some() {
            return Err(CloseMarkerSetupError::AlreadyArmed);
        }
        let generation = next_generation()?;
        for state in &SLOTS {
            let mut state = state
                .lock()
                .map_err(|_| CloseMarkerSetupError::Unavailable)?;
            state.generation = generation;
            state.slot = None;
        }
        ORDINAL.store(0, Ordering::Release);
        GENERATION.store(generation, Ordering::Release);
        *watch = Some(CloseWatch::Controls(OriginalControls { generation }));
        CLOSE_STATUS.store(generation | CLOSE_ARMED, Ordering::Release);
        let _reset = CloseMarkerReset(generation);
        drop(watch);

        let session = OriginalControlSession { generation };
        let value = action(&session);
        Ok((value, session.report()?))
    }
}

/// Drains both selected hook guards before the registry admits a successor.
/// The caller holds the registry; hooks acquire a slot only, so no cycle exists.
pub(super) fn reset(generation: u64) {
    let mut first = SLOTS[0]
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut second = SLOTS[1]
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for state in [&mut *first, &mut *second] {
        if state.generation == generation {
            state.slot = None;
            state.generation = 0;
        }
    }
    let _ = GENERATION.compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire);
    let _ = AUTO.try_with(|pending| {
        if pending.get() & !7 == generation {
            pending.set(0);
        }
    });
}

pub(super) fn active(status: u64) -> bool {
    GENERATION.load(Ordering::Acquire) == status & !7
}

pub(super) struct ControlClaim {
    state: MutexGuard<'static, ControlState>,
}

pub(super) fn claim(pointer: usize, index: usize, status: u64) -> Option<ControlClaim> {
    match SLOTS[index].try_lock() {
        Ok(state) => {
            if CLOSE_STATUS.load(Ordering::Acquire) != status
                || !active(status)
                || state.generation != status & !7
                || !state.slot.is_some_and(|slot| {
                    slot.identity.is_some_and(|identity| identity.0 == pointer)
                        && slot.before.is_none()
                        && slot.observation.is_none()
                })
                || target(index).load(Ordering::Acquire) != pointer
            {
                return None;
            }
            // The existing scalar target retains identity until outer reset, so
            // another constructor cannot reuse it for a second control. The
            // before sample consumes this slot while its guard spans the free.
            Some(ControlClaim { state })
        }
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => CLOSE_CONTENDED,
                std::sync::TryLockError::Poisoned(_) => CLOSE_UNAVAILABLE,
            };
            let _ = CLOSE_STATUS.compare_exchange(
                status,
                (status & !7) | outcome,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            None
        }
    }
}

impl ControlClaim {
    pub(super) fn sample_before_free(&mut self) {
        if let Some(slot) = self.state.slot.as_mut() {
            slot.before = Some(slot.original.sample());
        }
    }

    pub(super) fn sample_after_free(&mut self) {
        if let Some(slot) = self.state.slot.as_mut()
            && let Some(identity) = slot.identity
            && let Some(before) = slot.before
        {
            let after = slot.through_free.then(|| slot.original.sample());
            // This orders completed samples after free, not concurrent System frees.
            let ordinal = ORDINAL.fetch_add(1, Ordering::AcqRel) + 1;
            slot.observation = Some(OriginalControlObservation {
                identity,
                before,
                after,
                ordinal,
            });
        }
    }
}

pub(super) fn record_allocation(address: usize, layout: Layout, reallocation: bool) {
    if address == 0 || reallocation {
        return;
    }
    let status = CLOSE_STATUS.load(Ordering::Acquire);
    let pending = AUTO.try_with(Cell::get).unwrap_or(0);
    if status & 7 != CLOSE_ARMED
        || pending & 3 == 0
        || pending & !7 != status & !7
        || !active(status)
    {
        return;
    }
    for (index, state) in SLOTS.iter().enumerate() {
        if pending & (1 << index) == 0 {
            continue;
        }
        match state.try_lock() {
            Ok(mut state) => {
                if CLOSE_STATUS.load(Ordering::Acquire) != status || state.generation != status & !7
                {
                    return;
                }
                let Some(slot) = state.slot else {
                    continue;
                };
                if slot.identity.is_some() {
                    continue;
                }
                let matches = match slot.selection {
                    OriginalControlSelection::Explicit(_) => false,
                    OriginalControlSelection::FirstThreadExtent(bytes) => {
                        bytes.get() == layout.size()
                    }
                    OriginalControlSelection::FirstThreadRequestedExtent(original) => {
                        original.load(Ordering::SeqCst) == layout.size() as u64
                    }
                };
                if !matches {
                    continue;
                }
                if target(1 - index).load(Ordering::Acquire) == address {
                    let _ = CLOSE_STATUS.compare_exchange(
                        status,
                        (status & !7) | CLOSE_UNAVAILABLE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    return;
                }
                let Some(nonzero) = std::num::NonZeroUsize::new(address) else {
                    return;
                };
                if let Some(slot) = state.slot.as_mut() {
                    slot.identity = Some(AllocationIdentity::from_address(nonzero));
                }
                target(index).store(address, Ordering::Release);
                let _ = AUTO.try_with(|current| {
                    if current.get() & !7 == status & !7 {
                        let remaining = current.get() & 3 & !(1 << index);
                        current.set(if remaining == 0 {
                            0
                        } else {
                            (status & !7) | remaining
                        });
                    }
                });
            }
            Err(error) => {
                let outcome = match error {
                    std::sync::TryLockError::WouldBlock => CLOSE_CONTENDED,
                    std::sync::TryLockError::Poisoned(_) => CLOSE_UNAVAILABLE,
                };
                let _ = CLOSE_STATUS.compare_exchange(
                    status,
                    (status & !7) | outcome,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return;
            }
        }
    }
}

#[cfg(test)]
pub(super) fn hold_first_for_test() -> impl Drop {
    SLOTS[0].lock().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_control_claims_and_explicit_request_routing_are_independent() {
        let _serial = TEST_SERIAL.lock().unwrap();
        static ORIGINAL: AtomicBool = AtomicBool::new(true);
        let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
            for (slot, address) in [
                (OriginalControlSlot::First, 1),
                (OriginalControlSlot::Second, 2),
            ] {
                session
                    .arm(
                        slot,
                        OriginalControlSelection::Explicit(AllocationIdentity(address)),
                        OriginalStaticCounters::Bool(&ORIGINAL),
                        true,
                    )
                    .unwrap();
            }
            let mut first = claim_close_marker(1).unwrap();
            // An unrelated allocation has no pending constructor selector.
            record_allocation(7, Layout::new::<u64>(), false);
            assert_eq!(CLOSE_STATUS.load(Ordering::Acquire) & 7, CLOSE_ARMED);
            // The original second slot remains claimable while first is held.
            let mut second = claim_close_marker(2).unwrap();
            first.sample_before_free();
            second.sample_before_free();
            first.sample_after_free();
            second.sample_after_free();
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
        for (index, observed) in report.controls.into_iter().enumerate() {
            let observed = observed.unwrap();
            assert_eq!(observed.before, OriginalControlSnapshot::Bool(true));
            assert_eq!(observed.after, Some(OriginalControlSnapshot::Bool(true)));
            assert_eq!(usize::from(observed.ordinal), index + 1);
        }
    }

    #[test]
    fn pending_constructor_request_disarms_without_tainting_later_allocations() {
        let _serial = TEST_SERIAL.lock().unwrap();
        static ORIGINAL: AtomicBool = AtomicBool::new(true);
        let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
            session
                .arm(
                    OriginalControlSlot::First,
                    OriginalControlSelection::FirstThreadExtent(
                        std::num::NonZeroUsize::new(8).unwrap(),
                    ),
                    OriginalStaticCounters::Bool(&ORIGINAL),
                    false,
                )
                .unwrap();
            assert_ne!(AUTO.with(Cell::get), 0);
            record_allocation(1, Layout::new::<u64>(), false);
            assert_eq!(AUTO.with(Cell::get), 0);
            let mut selected = claim_close_marker(1).unwrap();
            record_allocation(7, Layout::new::<u64>(), false);
            assert_eq!(CLOSE_STATUS.load(Ordering::Acquire) & 7, CLOSE_ARMED);
            selected.sample_before_free();
            selected.sample_after_free();
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
        assert_eq!(report.controls[0].unwrap().ordinal, 1);
    }

    #[test]
    fn outer_reset_drains_both_slots_before_releasing_the_generation() {
        let _serial = TEST_SERIAL.lock().unwrap();
        static ORIGINAL: AtomicBool = AtomicBool::new(true);
        let refused = TestAllocationObserver::observe_original_controls(|session| {
            for (slot, address) in [
                (OriginalControlSlot::First, 1),
                (OriginalControlSlot::Second, 2),
            ] {
                session
                    .arm(
                        slot,
                        OriginalControlSelection::Explicit(AllocationIdentity(address)),
                        OriginalStaticCounters::Bool(&ORIGINAL),
                        true,
                    )
                    .unwrap();
            }
            let first = claim_close_marker(1).unwrap();
            let second = claim_close_marker(2).unwrap();
            let generation = session.generation;
            let (started, receive) = std::sync::mpsc::sync_channel(0);
            let (finished, completed) = std::sync::mpsc::sync_channel(0);
            let reset = std::thread::spawn(move || {
                let mut registry = CLOSE_MARKER.lock().unwrap();
                started.send(()).unwrap();
                super::reset(generation);
                target(0).store(0, Ordering::Release);
                target(1).store(0, Ordering::Release);
                CLOSE_STATUS.store(generation, Ordering::Release);
                *registry = None;
                drop(registry);
                finished.send(()).unwrap();
            });
            receive.recv().unwrap();
            assert!(CLOSE_MARKER.try_lock().is_err());
            assert_eq!(GENERATION.load(Ordering::Acquire), generation);
            assert!(completed.try_recv().is_err());
            drop(first);
            // Reset cannot clear either original reference while second is held.
            assert!(SLOTS[1].try_lock().is_err());
            assert_eq!(GENERATION.load(Ordering::Acquire), generation);
            assert!(completed.try_recv().is_err());
            drop(second);
            completed.recv().unwrap();
            reset.join().unwrap();
            assert_eq!(GENERATION.load(Ordering::Acquire), 0);
            for slot in &SLOTS {
                let state = slot.lock().unwrap();
                assert_eq!(state.generation, 0);
                assert!(state.slot.is_none());
            }
        });
        // This private control deliberately closed the registry from outside
        // the hooks. Its old session cannot report or establish completion.
        assert!(matches!(refused, Err(CloseMarkerSetupError::Unavailable)));
        let ((), successor) = TestAllocationObserver::observe_original_controls(|_| ()).unwrap();
        assert_eq!(successor.outcome, OriginalControlsOutcome::Missing);
    }

    #[test]
    fn stale_constructor_selector_bits_cannot_enter_a_successor() {
        let _serial = TEST_SERIAL.lock().unwrap();
        static ORIGINAL: AtomicBool = AtomicBool::new(true);
        let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
            // A different worker's old TLS cannot arm an unrequested second slot.
            AUTO.with(|pending| pending.set((session.generation - 8) | 2));
            session
                .arm(
                    OriginalControlSlot::First,
                    OriginalControlSelection::FirstThreadExtent(
                        std::num::NonZeroUsize::new(8).unwrap(),
                    ),
                    OriginalStaticCounters::Bool(&ORIGINAL),
                    false,
                )
                .unwrap();
            assert_eq!(AUTO.with(Cell::get), session.generation | 1);
            record_allocation(1, Layout::new::<u64>(), false);
            assert_eq!(AUTO.with(Cell::get), 0);
            let mut selected = claim_close_marker(1).unwrap();
            selected.sample_before_free();
            selected.sample_after_free();
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
        assert!(report.controls[1].is_none());
    }

    #[test]
    fn constructor_address_reuse_cannot_rebind_a_closed_original_control() {
        let _serial = TEST_SERIAL.lock().unwrap();
        static ORIGINAL: AtomicBool = AtomicBool::new(true);
        let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
            for (slot, bytes) in [
                (OriginalControlSlot::First, 8),
                (OriginalControlSlot::Second, 16),
            ] {
                session
                    .arm(
                        slot,
                        OriginalControlSelection::FirstThreadExtent(
                            std::num::NonZeroUsize::new(bytes).unwrap(),
                        ),
                        OriginalStaticCounters::Bool(&ORIGINAL),
                        true,
                    )
                    .unwrap();
            }
            record_allocation(1, Layout::new::<u64>(), false);
            {
                let mut first = claim_close_marker(1).unwrap();
                first.sample_before_free();
                first.sample_after_free();
            }
            assert!(claim_close_marker(1).is_none());
            // A different-sized request cannot select the retained old identity.
            record_allocation(1, Layout::new::<[u64; 2]>(), false);
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Unavailable);
        assert!(report.controls[0].is_some());
        assert!(report.controls[1].is_none());
    }
}
