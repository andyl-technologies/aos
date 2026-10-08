//! Observes control deallocation against synchronously borrowed original counters.
//!
//! Native test binaries may select this System allocator. Fixed thread-local
//! state identifies an allocation without accessing its contents. The observed
//! original counters are sampled without allocating. A separate fixed resident
//! probe uses the same owned account after deallocation, with nonblocking locks.
//! Its accepted concrete lease remains owned until teardown outside the hook.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

mod events;
mod roster;

pub use events::{AllocationEvent, AllocationEvents, AllocationEventsSetupError};

pub use roster::{
    AllocationExtent, AllocationRoster, AllocationRosterOutcome, AllocationRosterSetupError,
};

use crate::host_services::{HostServiceAllocator, HostServiceError, ResidentProbe};

#[derive(Clone, Copy)]
struct Watch {
    capture_bytes: usize,
    capture_alignment: usize,
    target: usize,
    account: *const HostServiceAllocator,
    original_atomic: *const AtomicU64,
    observed: Option<u64>,
    capture_extents: [usize; 3],
    control_targets: [usize; 3],
    accounts: [*const HostServiceAllocator; 2],
    occupied: *const AtomicBool,
    controls: [Option<ControlObservation>; 3],
    ordinal: u8,
    counting: bool,
    counts: AllocationCounts,
}

const EMPTY: Watch = Watch {
    capture_bytes: 0,
    capture_alignment: 0,
    target: 0,
    account: std::ptr::null(),
    original_atomic: std::ptr::null(),
    observed: None,
    capture_extents: [0; 3],
    control_targets: [0; 3],
    accounts: [std::ptr::null(); 2],
    occupied: std::ptr::null(),
    controls: [None; 3],
    ordinal: 0,
    counting: false,
    counts: AllocationCounts {
        allocations: 0,
        reallocations: 0,
        overflow: false,
    },
};

thread_local! {
    static WATCH: Cell<Watch> = const { Cell::new(EMPTY) };
    static IN_RESIDENT_PROBE: Cell<bool> = const { Cell::new(false) };
}

struct OwnedResidentProbe {
    account: HostServiceAllocator,
    result: Option<ResidentProbe>,
}

static RESIDENT_PROBE: Mutex<Option<OwnedResidentProbe>> = Mutex::new(None);
static RESIDENT_TARGET: AtomicUsize = AtomicUsize::new(0);
static RESIDENT_STATUS: AtomicU64 = AtomicU64::new(0);
static RESIDENT_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static RESIDENT_REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static RESIDENT_COUNT_OVERFLOW: AtomicBool = AtomicBool::new(false);
static RESIDENT_ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(0);
static RESIDENT_ALLOCATION_ALIGNMENT: AtomicUsize = AtomicUsize::new(0);

const PROBE_ARMED: u64 = 1;
const PROBE_COMPLETE: u64 = 2;
const PROBE_CONTENDED: u64 = 3;
const PROBE_UNAVAILABLE: u64 = 4;

struct ResidentProbeReset;

impl Drop for ResidentProbeReset {
    fn drop(&mut self) {
        // Teardown may wait only outside allocator calls. Moving the watch out
        // preserves its account and grant until every acquired hook guard exits.
        let mut slot = match RESIDENT_PROBE.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        RESIDENT_TARGET.store(0, Ordering::Release);
        let watch = slot.take();
        // Keep setup excluded until the old lease and account finish teardown.
        // Nested deallocation sees the already disarmed global target.
        drop(watch);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseMarkerMode {
    PublishAfter,
    SampleBefore,
}

struct CloseMarker {
    original: &'static AtomicBool,
    generation: u64,
    mode: CloseMarkerMode,
}

static CLOSE_MARKER: Mutex<Option<CloseMarker>> = Mutex::new(None);
static CLOSE_TARGET: AtomicUsize = AtomicUsize::new(0);
static CLOSE_STATUS: AtomicU64 = AtomicU64::new(0);

const CLOSE_ARMED: u64 = 1;
const CLOSE_PUBLISHED: u64 = 2;
const CLOSE_CONTENDED: u64 = 3;
const CLOSE_UNAVAILABLE: u64 = 4;
const CLOSE_BEFORE_OPEN: u64 = 5;
const CLOSE_BEFORE_CLOSED: u64 = 6;

struct CloseMarkerReset;

impl Drop for CloseMarkerReset {
    fn drop(&mut self) {
        // Only outer teardown waits. The original marker is static, and a
        // claimed guard must finish its actual free and publication first.
        let mut slot = match CLOSE_MARKER.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        CLOSE_TARGET.store(0, Ordering::Release);
        *slot = None;
    }
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        let _ = WATCH.try_with(|cell| cell.set(EMPTY));
    }
}

/// Identifies an observed test allocation without exposing its control.
#[derive(Clone, Copy, Debug)]
pub struct AllocationIdentity(usize);

impl AllocationIdentity {
    /// Identifies a separately verified original allocation by its base address.
    ///
    /// This scalar identity neither reads storage nor creates an ownership alias.
    /// The caller derives the base using the original checked allocation layout
    /// and retains its real owner until observation. A nonzero address alone
    /// establishes neither allocation provenance nor funding.
    pub const fn from_address(address: NonZeroUsize) -> Self {
        Self(address.get())
    }
}

/// Original paired-account and optional occupancy state at one control close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlSample {
    /// Retained bytes in the two synchronously borrowed original accounts.
    pub original_bytes: [Option<u64>; 2],
    /// Occupancy while a separately retained original owner keeps it live.
    pub occupied: Option<bool>,
}

/// Distinguishes original custody before and after actual System deallocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlObservation {
    /// Original custody immediately before the allocation closes.
    pub before: ControlSample,
    /// Original custody immediately after the allocation closes.
    pub after: ControlSample,
    /// One-based order among the observed control closes in this action.
    pub ordinal: u8,
}

/// Native allocator entry counts during one synchronous test action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationCounts {
    /// Calls to `System.alloc` or `System.alloc_zeroed`.
    pub allocations: u64,
    /// Calls to `System.realloc`, separately from allocation calls.
    pub reallocations: u64,
    /// Indicates that a counter saturated; callers must reject this result.
    pub overflow: bool,
}

/// Actual layout of the first nested allocation made by the fixed probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeAllocationLayout {
    /// Requested allocation size, including the concrete Arc control.
    pub bytes: usize,
    /// Requested native allocation alignment.
    pub alignment: usize,
}

/// Causal outcome after an observed control has actually been freed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentProbeOutcome {
    /// The selected control did not close during the action.
    Missing,
    /// The original account granted one byte, retained until outer teardown.
    Granted,
    /// The original account refused the real fixed reservation.
    Refused(HostServiceError),
    /// An observer or original-account lock was busy; no custody is proved.
    Contended,
    /// Observer state or allocator thread-local state was unavailable.
    Unavailable,
}

/// Fixed probe outcome and its actual nested allocator geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidentProbeReport {
    /// Original reservation result; only explicit exhaustion witnesses custody.
    pub outcome: ResidentProbeOutcome,
    /// Nested allocation and reallocation entries while observation is disarmed.
    pub counts: AllocationCounts,
    /// First nested allocation layout, absent on the exhausted path.
    pub first_allocation: Option<ProbeAllocationLayout>,
}

/// Refuses arming an ambiguous or unavailable global test observation.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResidentProbeSetupError {
    /// Another owned observation has not completed its outer teardown.
    #[error("a fixed resident probe is already armed")]
    AlreadyArmed,
    /// Poisoned observer state prevents establishing original custody.
    #[error("fixed resident probe observation is unavailable")]
    Unavailable,
}

/// Reports publication of the original static flag after physical close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseMarkerOutcome {
    /// The exact selected allocation did not close during the action.
    Missing,
    /// The original flag was set after the selected System deallocation.
    Published,
    /// The nonblocking watch lock was busy; no ordering is established.
    Contended,
    /// Watch state was unavailable; no ordering is established.
    Unavailable,
}

/// Samples the original static flag immediately before physical close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeforeFreeMarkerOutcome {
    /// The exact selected allocation did not close during the action.
    Missing,
    /// The original flag was false immediately before System deallocation.
    Open,
    /// The original flag was already true immediately before deallocation.
    Closed,
    /// A nonblocking lock refused the sample; no ordering is established.
    Contended,
    /// Watch state was unavailable; no ordering is established.
    Unavailable,
}

/// Refuses ambiguous or unavailable original close-marker observation.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CloseMarkerSetupError {
    /// A preceding marker observation has not completed outer teardown.
    #[error("a close-marker observation is already armed")]
    AlreadyArmed,
    /// Poisoned or exhausted watch state cannot establish publication.
    #[error("close-marker observation is unavailable")]
    Unavailable,
}

/// Delegates test allocations to System and observes a scoped control close.
///
/// This helper exists only with `test-support`. A test binary selects it with
/// `#[global_allocator]`; ordinary builds retain their existing allocator.
pub struct TestAllocationObserver;

impl TestAllocationObserver {
    /// Publishes the original static marker immediately after one physical close.
    ///
    /// The allocation hook sets `original` to true with sequential consistency
    /// after System deallocation and before returning to payload or loan drop.
    /// Setup preserves the caller's original flag value. The fixed watch uses
    /// a nonblocking claim and retains its guard through free and publication;
    /// missing, contended and unavailable outcomes do not prove ordering.
    ///
    /// The action must join every borrower that may close the selected target.
    /// Static marker lifetime prevents an escaped action from creating a dangling
    /// borrow, but does not establish owner provenance or original funding.
    /// Nested or overlapping marker observations refuse without replacing state.
    /// No resource admission or allocator callback occurs in this observation.
    ///
    /// # Errors
    /// Refuses an overlapping arm, poisoned state or exhausted generation.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and completing outer teardown.
    pub fn observe_close_marker_after_free<T>(
        original: &'static AtomicBool,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> Result<(T, CloseMarkerOutcome), CloseMarkerSetupError> {
        let _reset = arm_close_marker(original, identity, CloseMarkerMode::PublishAfter)?;
        let value = action();
        let outcome = match CLOSE_STATUS.load(Ordering::Acquire) & 7 {
            CLOSE_ARMED => CloseMarkerOutcome::Missing,
            CLOSE_PUBLISHED => CloseMarkerOutcome::Published,
            CLOSE_CONTENDED => CloseMarkerOutcome::Contended,
            _ => CloseMarkerOutcome::Unavailable,
        };
        Ok((value, outcome))
    }

    /// Samples the original static flag before one exact physical deallocation.
    ///
    /// The allocation hook disarms its identity under a nonblocking guard and
    /// reads the same original flag with sequential consistency immediately
    /// before System free. It never modifies that flag. The caller retains the
    /// actual owner and joins every closing worker inside the action. A scalar
    /// identity alone establishes neither provenance nor original funding.
    /// This shares the existing global marker arm with after-free publication;
    /// overlapping modes refuse rather than replace one another.
    ///
    /// # Errors
    /// Refuses an overlapping arm, poisoned state or exhausted generation.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and completing outer teardown.
    pub fn observe_close_marker_before_free<T>(
        original: &'static AtomicBool,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> Result<(T, BeforeFreeMarkerOutcome), CloseMarkerSetupError> {
        let _reset = arm_close_marker(original, identity, CloseMarkerMode::SampleBefore)?;
        let value = action();
        let outcome = match CLOSE_STATUS.load(Ordering::Acquire) & 7 {
            CLOSE_ARMED => BeforeFreeMarkerOutcome::Missing,
            CLOSE_BEFORE_OPEN => BeforeFreeMarkerOutcome::Open,
            CLOSE_BEFORE_CLOSED => BeforeFreeMarkerOutcome::Closed,
            CLOSE_CONTENDED => BeforeFreeMarkerOutcome::Contended,
            _ => BeforeFreeMarkerOutcome::Unavailable,
        };
        Ok((value, outcome))
    }

    /// Captures one exact native layout and counts its complete constructor action.
    ///
    /// Size and alignment must both match the first selected allocation. Counts
    /// include allocation and zeroed-allocation entries, with reallocations
    /// reported separately. A missing identity or overflowing count is not a
    /// constructor witness. The action executes outside allocator calls and
    /// must not nest another thread-local observer. State clears on return and
    /// unwind; this measurements-only API admits no resources.
    ///
    /// # Panics
    /// Propagates an action panic after clearing all capture and count state.
    pub fn capture_layout_and_count<T>(
        layout: Layout,
        action: impl FnOnce() -> T,
    ) -> (T, Option<AllocationIdentity>, AllocationCounts) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                capture_bytes: layout.size(),
                capture_alignment: layout.align(),
                counting: true,
                ..EMPTY
            })
        });
        let value = action();
        let state = WATCH.with(Cell::get);
        (
            value,
            (state.target != 0).then_some(AllocationIdentity(state.target)),
            state.counts,
        )
    }

    /// Probes one original resident byte after a selected control is freed.
    ///
    /// Setup clones the same account outside allocator calls. The fixed hook
    /// claims the identity once and uses only nonblocking locks. A grant retains
    /// its real lease until outer teardown, so the predecessor control temporarily
    /// holds one extra original byte and one lease allocation. This differs from
    /// the historical probe that immediately dropped its accepted lease.
    ///
    /// The action must join every worker that may close the target, including
    /// panicking workers, before returning. Missing closes, contention and
    /// unavailable state cannot establish funding. Unwind disarms the target
    /// and waits for any acquired hook guard before releasing the owned account.
    /// Counts and layout measurements do not establish timing parity.
    ///
    /// # Errors
    /// Refuses overlapping observations or poisoned observer state.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and releasing observation.
    pub fn observe_resident_after_free<T>(
        account: &HostServiceAllocator,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> Result<(T, ResidentProbeReport), ResidentProbeSetupError> {
        {
            let mut watch = RESIDENT_PROBE
                .lock()
                .map_err(|_| ResidentProbeSetupError::Unavailable)?;
            if watch.is_some() {
                return Err(ResidentProbeSetupError::AlreadyArmed);
            }
            let generation = (RESIDENT_STATUS.load(Ordering::Relaxed) & !7)
                .checked_add(8)
                .ok_or(ResidentProbeSetupError::Unavailable)?;
            *watch = Some(OwnedResidentProbe {
                account: account.clone(),
                result: None,
            });
            RESIDENT_ALLOCATIONS.store(0, Ordering::Relaxed);
            RESIDENT_REALLOCATIONS.store(0, Ordering::Relaxed);
            RESIDENT_COUNT_OVERFLOW.store(false, Ordering::Relaxed);
            RESIDENT_ALLOCATION_BYTES.store(0, Ordering::Relaxed);
            RESIDENT_ALLOCATION_ALIGNMENT.store(0, Ordering::Relaxed);
            RESIDENT_STATUS.store(generation | PROBE_ARMED, Ordering::Release);
            RESIDENT_TARGET.store(identity.0, Ordering::Release);
        }

        let reset = ResidentProbeReset;
        let value = action();
        let outcome = match RESIDENT_STATUS.load(Ordering::Acquire) & 7 {
            PROBE_COMPLETE => {
                let watch = RESIDENT_PROBE
                    .lock()
                    .map_err(|_| ResidentProbeSetupError::Unavailable)?;
                match watch.as_ref().and_then(|watch| watch.result.as_ref()) {
                    Some(ResidentProbe::Granted(lease)) if lease.resident_bytes() == 1 => {
                        ResidentProbeOutcome::Granted
                    }
                    Some(ResidentProbe::Refused(error)) => ResidentProbeOutcome::Refused(*error),
                    Some(ResidentProbe::Contended) => ResidentProbeOutcome::Contended,
                    _ => ResidentProbeOutcome::Unavailable,
                }
            }
            PROBE_CONTENDED => ResidentProbeOutcome::Contended,
            PROBE_UNAVAILABLE => ResidentProbeOutcome::Unavailable,
            _ => ResidentProbeOutcome::Missing,
        };
        let bytes = RESIDENT_ALLOCATION_BYTES.load(Ordering::Relaxed);
        let report = ResidentProbeReport {
            outcome,
            counts: AllocationCounts {
                allocations: RESIDENT_ALLOCATIONS.load(Ordering::Relaxed),
                reallocations: RESIDENT_REALLOCATIONS.load(Ordering::Relaxed),
                overflow: RESIDENT_COUNT_OVERFLOW.load(Ordering::Relaxed),
            },
            first_allocation: (bytes != 0).then(|| ProbeAllocationLayout {
                bytes,
                alignment: RESIDENT_ALLOCATION_ALIGNMENT.load(Ordering::Relaxed),
            }),
        };
        drop(reset);
        Ok((value, report))
    }

    /// Captures the first allocation of the specified extent during an action.
    ///
    /// The returned identity contains no dereferenceable ownership. Observation
    /// resets on return or unwind. The action executes outside allocator calls.
    ///
    /// # Panics
    /// Propagates a panic from the action after resetting observation.
    pub fn capture<T>(bytes: usize, action: impl FnOnce() -> T) -> (T, Option<AllocationIdentity>) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                capture_bytes: bytes,
                ..EMPTY
            })
        });
        let value = action();
        let target = WATCH.with(|cell| cell.get().target);
        (value, (target != 0).then_some(AllocationIdentity(target)))
    }

    /// Reads original retained bytes immediately before one control is freed.
    ///
    /// The account is borrowed through the synchronous action; neither the
    /// account nor the allocation ownership escapes. The nonblocking counter
    /// read creates no reservation. Missing deallocation or unavailable
    /// accounting yields `None`. Observation resets on return and unwind.
    ///
    /// # Panics
    /// Propagates a panic from the action after resetting observation.
    pub fn observe<T>(
        account: &HostServiceAllocator,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> (T, Option<u64>) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                target: identity.0,
                account,
                ..EMPTY
            })
        });
        let value = action();
        (value, WATCH.with(|cell| cell.get().observed))
    }

    /// Samples an original atomic immediately after one control is freed.
    ///
    /// The original counter borrow remains live through the complete synchronous
    /// action. Each scoped worker may observe its own close using this thread's
    /// state, with the original owner retained until every worker joins. The
    /// target disarms before System deallocation; its counter is then sampled
    /// with sequential consistency without accessing allocation contents.
    ///
    /// Missing closes yield `None`; a scalar sample alone proves neither original
    /// admission nor funding. The action runs outside allocator calls and must
    /// not nest another thread-local observer. State clears on return and unwind.
    ///
    /// # Panics
    /// Propagates an action panic after clearing the borrowed observation state.
    pub fn observe_atomic_after_free<T>(
        original: &AtomicU64,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> (T, Option<u64>) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                target: identity.0,
                original_atomic: std::ptr::from_ref(original),
                ..EMPTY
            })
        });
        let value = action();
        (value, WATCH.with(|cell| cell.get().observed))
    }

    /// Captures up to three control identities by their actual allocation extent.
    ///
    /// Repeated extents select successive allocations. The fixed identities
    /// carry no ownership or dereferenceable pointer. This observer is
    /// thread-local; observation actions must not nest on the same thread.
    ///
    /// # Panics
    /// Propagates an action panic after clearing all capture state.
    pub fn capture_controls<T>(
        extents: [usize; 3],
        action: impl FnOnce() -> T,
    ) -> (T, [Option<AllocationIdentity>; 3]) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                capture_extents: extents,
                ..EMPTY
            })
        });
        let value = action();
        let targets = WATCH.with(|cell| cell.get().control_targets);
        (
            value,
            targets.map(|target| (target != 0).then_some(AllocationIdentity(target))),
        )
    }

    /// Samples both original accounts at up to three actual control closes.
    ///
    /// The accounts and optional occupancy borrow outlive the entire action.
    /// Occupancy therefore requires an independent safe owner retained across
    /// the action; final service destruction uses `None`. Scoped concurrent
    /// actions may arm copied identities on each thread, with borrows retained
    /// through join. Each target disarms before its close and sampling. Missing
    /// closes or unavailable nonblocking accounting yield `None`.
    ///
    /// This fixed sampler does not replace causal loan-drop flags, allocation
    /// rosters or detached-worker reservation witnesses.
    ///
    /// # Panics
    /// Propagates an action panic after clearing all borrowed observation state.
    pub fn observe_controls<T>(
        accounts: [&HostServiceAllocator; 2],
        occupied: Option<&AtomicBool>,
        identities: [Option<AllocationIdentity>; 3],
        action: impl FnOnce() -> T,
    ) -> (T, [Option<ControlObservation>; 3]) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                accounts: accounts.map(std::ptr::from_ref),
                occupied: occupied.map_or(std::ptr::null(), std::ptr::from_ref),
                control_targets: identities
                    .map(|identity| identity.map_or(0, |identity| identity.0)),
                ..EMPTY
            })
        });
        let value = action();
        (value, WATCH.with(|cell| cell.get().controls))
    }

    /// Counts native allocation and reallocation entries without pointer tracking.
    ///
    /// Counts saturate with an explicit overflow flag. The action executes
    /// outside the allocator and must not nest another observer on this thread.
    /// Instrumented allocator counts do not establish native timing parity.
    ///
    /// # Panics
    /// Propagates an action panic after clearing count state.
    pub fn count<T>(action: impl FnOnce() -> T) -> (T, AllocationCounts) {
        let _reset = Reset;
        WATCH.with(|cell| {
            cell.set(Watch {
                counting: true,
                ..EMPTY
            })
        });
        let value = action();
        (value, WATCH.with(|cell| cell.get().counts))
    }
}

fn record_allocation(pointer: *mut u8, layout: Layout, reallocation: bool) {
    events::record(true, layout, reallocation);
    roster::record_allocation(pointer as usize, layout, reallocation);
    if IN_RESIDENT_PROBE.try_with(Cell::get).unwrap_or(false) {
        let count = if reallocation {
            &RESIDENT_REALLOCATIONS
        } else {
            &RESIDENT_ALLOCATIONS
        };
        let before = count.load(Ordering::Relaxed);
        RESIDENT_COUNT_OVERFLOW.fetch_or(before == u64::MAX, Ordering::Relaxed);
        count.store(before.saturating_add(1), Ordering::Relaxed);
        if !reallocation && before == 0 {
            RESIDENT_ALLOCATION_BYTES.store(layout.size(), Ordering::Relaxed);
            RESIDENT_ALLOCATION_ALIGNMENT.store(layout.align(), Ordering::Relaxed);
        }
        return;
    }
    let bytes = layout.size();
    let _ = WATCH.try_with(|cell| {
        let mut state = cell.get();
        if state.counting {
            let counter = if reallocation {
                &mut state.counts.reallocations
            } else {
                &mut state.counts.allocations
            };
            state.counts.overflow |= *counter == u64::MAX;
            *counter = counter.saturating_add(1);
        }
        if !reallocation
            && state.capture_bytes != 0
            && bytes == state.capture_bytes
            && (state.capture_alignment == 0 || state.capture_alignment == layout.align())
        {
            state.capture_bytes = 0;
            state.target = pointer as usize;
        }
        if !reallocation {
            for index in 0..3 {
                if state.capture_extents[index] != 0 && bytes == state.capture_extents[index] {
                    state.capture_extents[index] = 0;
                    state.control_targets[index] = pointer as usize;
                    break;
                }
            }
        }
        cell.set(state);
    });
}

fn arm_close_marker(
    original: &'static AtomicBool,
    identity: AllocationIdentity,
    mode: CloseMarkerMode,
) -> Result<CloseMarkerReset, CloseMarkerSetupError> {
    let mut slot = CLOSE_MARKER
        .lock()
        .map_err(|_| CloseMarkerSetupError::Unavailable)?;
    if slot.is_some() {
        return Err(CloseMarkerSetupError::AlreadyArmed);
    }
    let generation = (CLOSE_STATUS.load(Ordering::Relaxed) & !7)
        .checked_add(8)
        .ok_or(CloseMarkerSetupError::Unavailable)?;
    *slot = Some(CloseMarker {
        original,
        generation,
        mode,
    });
    CLOSE_STATUS.store(generation | CLOSE_ARMED, Ordering::Release);
    CLOSE_TARGET.store(identity.0, Ordering::Release);
    Ok(CloseMarkerReset)
}

fn sample_close_marker_before_free(slot: &Option<CloseMarker>) {
    if let Some(watch) = slot
        && watch.mode == CloseMarkerMode::SampleBefore
    {
        let sampled = if watch.original.load(Ordering::SeqCst) {
            CLOSE_BEFORE_CLOSED
        } else {
            CLOSE_BEFORE_OPEN
        };
        CLOSE_STATUS.store(watch.generation | sampled, Ordering::Release);
    }
}

fn claim_close_marker(pointer: usize) -> Option<MutexGuard<'static, Option<CloseMarker>>> {
    let status = CLOSE_STATUS.load(Ordering::Acquire);
    if pointer == 0 || status & 7 != CLOSE_ARMED || CLOSE_TARGET.load(Ordering::Acquire) != pointer
    {
        return None;
    }
    match CLOSE_MARKER.try_lock() {
        Ok(slot) => {
            if CLOSE_STATUS.load(Ordering::Acquire) == status
                && CLOSE_TARGET
                    .compare_exchange(pointer, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                Some(slot)
            } else {
                None
            }
        }
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => CLOSE_CONTENDED,
                std::sync::TryLockError::Poisoned(_) => CLOSE_UNAVAILABLE,
            };
            // A delayed refusal belongs only to its original generation.
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

fn publish_close_marker(slot: &Option<CloseMarker>) {
    if let Some(watch) = slot
        && watch.mode == CloseMarkerMode::PublishAfter
    {
        watch.original.store(true, Ordering::SeqCst);
        CLOSE_STATUS.store(watch.generation | CLOSE_PUBLISHED, Ordering::Release);
    }
}

fn claim_resident_probe(pointer: usize) -> Option<MutexGuard<'static, Option<OwnedResidentProbe>>> {
    let status = RESIDENT_STATUS.load(Ordering::Acquire);
    if pointer == 0
        || status & 7 != PROBE_ARMED
        || RESIDENT_TARGET.load(Ordering::Acquire) != pointer
    {
        return None;
    }
    match RESIDENT_PROBE.try_lock() {
        Ok(slot) => {
            if RESIDENT_STATUS.load(Ordering::Acquire) == status
                && RESIDENT_TARGET
                    .compare_exchange(pointer, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                Some(slot)
            } else {
                None
            }
        }
        Err(error) => {
            let outcome = match error {
                std::sync::TryLockError::WouldBlock => PROBE_CONTENDED,
                std::sync::TryLockError::Poisoned(_) => PROBE_UNAVAILABLE,
            };
            // Bind refusal to this arm, so late contention cannot overwrite a
            // successor observation. A refused arm cannot claim another close.
            let _ = RESIDENT_STATUS.compare_exchange(
                status,
                (status & !7) | outcome,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            None
        }
    }
}

fn run_resident_probe(slot: &mut Option<OwnedResidentProbe>) {
    let generation = RESIDENT_STATUS.load(Ordering::Relaxed) & !7;
    let entered = IN_RESIDENT_PROBE.try_with(|active| !active.replace(true));
    if entered != Ok(true) {
        RESIDENT_STATUS.store(generation | PROBE_UNAVAILABLE, Ordering::Release);
        return;
    }
    if let Some(watch) = slot.as_mut()
        && watch.result.is_none()
    {
        // A single target claim prevents replacing and dropping a previous
        // grant inside this allocation hook. Its owned guard spans System free.
        watch.result = Some(watch.account.probe_one_resident_byte());
        RESIDENT_STATUS.store(generation | PROBE_COMPLETE, Ordering::Release);
    } else {
        RESIDENT_STATUS.store(generation | PROBE_UNAVAILABLE, Ordering::Release);
    }
    let _ = IN_RESIDENT_PROBE.try_with(|active| active.set(false));
}

fn sample_controls(state: &Watch) -> ControlSample {
    let original_bytes = state.accounts.map(|account| {
        if account.is_null() {
            None
        } else {
            // SAFETY: observe_controls retains both synchronous borrows through
            // the complete action and Reset clears them on return or unwind.
            unsafe { &*account }.observed_resident_bytes()
        }
    });
    let occupied = if state.occupied.is_null() {
        None
    } else {
        // SAFETY: A separate live owner retains this synchronous atomic borrow
        // through the complete action; final owner destruction passes None.
        Some(unsafe { &*state.occupied }.load(Ordering::Acquire))
    };
    ControlSample {
        original_bytes,
        occupied,
    }
}

// SAFETY: Original pointers/layouts are delegated unchanged to System. TLS
// stores scalar identities and synchronous borrows established by observe.
// A fixed resident claim disarms under its nonblocking owned guard before free.
// Its same-account reservation stores the real grant until outer teardown;
// nested allocator entries record geometry without reentering observation.
unsafe impl GlobalAlloc for TestAllocationObserver {
    /// # Safety
    /// The caller supplies a nonzero valid allocation layout under GlobalAlloc.
    /// System receives it unchanged; observation never accesses allocation data.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The original allocation layout is passed unchanged to System.
        let pointer = unsafe { System.alloc(layout) };
        record_allocation(pointer, layout, false);
        pointer
    }

    /// # Safety
    /// The caller supplies a nonzero valid allocation layout under GlobalAlloc.
    /// System receives the original zeroed request and retains allocation ownership.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller's exact zeroed allocation request is delegated.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_allocation(pointer, layout, false);
        pointer
    }

    /// # Safety
    /// The pointer and layout identify one live System allocation. The caller's
    /// nonzero new size obeys GlobalAlloc's size and unchanged-alignment contract.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // This explicit delegate observes native reallocation instead of the
        // GlobalAlloc default allocate-copy-free test-observer behavior.
        // SAFETY: The original pointer/layout and requested size are unchanged.
        let next = unsafe { System.realloc(pointer, layout, new_size) };
        if let Ok(next_layout) = Layout::from_size_align(new_size, layout.align()) {
            record_allocation(next, next_layout, true);
        }
        next
    }

    /// # Safety
    /// The pointer and original layout identify one live System allocation that
    /// has not been freed. It is delegated exactly once; identities are compared
    /// without dereferencing its data, and observed accounts retain safe custody.
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let resident = claim_resident_probe(pointer as usize);
        let close_marker = claim_close_marker(pointer as usize);
        let mut original_atomic = std::ptr::null();
        let group = WATCH
            .try_with(|cell| {
                let mut state = cell.get();
                if state.target != 0
                    && state.target == pointer as usize
                    && !state.original_atomic.is_null()
                {
                    state.target = 0;
                    original_atomic = state.original_atomic;
                    cell.set(state);
                }
                if state.target != 0 && state.target == pointer as usize && !state.account.is_null()
                {
                    state.target = 0;
                    cell.set(state);
                    // SAFETY: observe retains this borrow across the synchronous
                    // action. The target has disarmed before the counter read.
                    state.observed = unsafe { &*state.account }.observed_resident_bytes();
                    cell.set(state);
                }
                let index = state
                    .control_targets
                    .iter()
                    .position(|target| *target != 0 && *target == pointer as usize)?;
                state.control_targets[index] = 0;
                cell.set(state);
                Some((index, state, sample_controls(&state)))
            })
            .ok()
            .flatten();

        if let Some(slot) = close_marker.as_ref() {
            sample_close_marker_before_free(slot);
        }

        // SAFETY: The original pointer and layout are freed exactly once.
        unsafe { System.dealloc(pointer, layout) };
        events::record(false, layout, false);

        if let Some(slot) = close_marker {
            publish_close_marker(&slot);
        }

        if !original_atomic.is_null() {
            // SAFETY: The safe observation retains this original atomic borrow
            // through the synchronous action. Its target disarmed before free;
            // Reset clears the borrow on return or unwind after this hook exits.
            let sample = unsafe { &*original_atomic }.load(Ordering::SeqCst);
            let _ = WATCH.try_with(|cell| {
                let mut state = cell.get();
                state.observed = Some(sample);
                cell.set(state);
            });
        }

        if let Some(mut resident) = resident {
            run_resident_probe(&mut resident);
        }

        if let Some((index, state, before)) = group {
            let after = sample_controls(&state);
            let _ = WATCH.try_with(|cell| {
                let mut current = cell.get();
                current.ordinal = current.ordinal.saturating_add(1);
                current.controls[index] = Some(ControlObservation {
                    before,
                    after,
                    ordinal: current.ordinal,
                });
                cell.set(current);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_disarmed() {
        WATCH.with(|cell| {
            let state = cell.get();
            assert_eq!(state.capture_bytes, 0);
            assert_eq!(state.capture_alignment, 0);
            assert_eq!(state.target, 0);
            assert!(state.account.is_null());
            assert!(state.original_atomic.is_null());
            assert_eq!(state.observed, None);
            assert_eq!(state.capture_extents, [0; 3]);
            assert_eq!(state.control_targets, [0; 3]);
            assert!(state.accounts.iter().all(|account| account.is_null()));
            assert!(state.occupied.is_null());
            assert_eq!(state.controls, [None; 3]);
            assert!(!state.counting);
        });
    }

    #[test]
    fn original_atomic_observation_clears_on_return_and_action_unwind() {
        let original = AtomicU64::new(7);
        let identity = AllocationIdentity::from_address(NonZeroUsize::new(1).unwrap());
        let (_, sample) =
            TestAllocationObserver::observe_atomic_after_free(&original, identity, || {
                WATCH.with(|cell| {
                    assert_eq!(cell.get().original_atomic, std::ptr::from_ref(&original));
                });
            });

        assert_eq!(sample, None);
        assert_disarmed();

        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::observe_atomic_after_free(&original, identity, || {
                panic!("intentional original-atomic observation unwind");
            })
        });

        assert!(result.is_err());
        assert_disarmed();
    }

    #[test]
    fn exact_layout_and_count_state_clears_on_return_and_action_unwind() {
        let layout = Layout::from_size_align(64, 64).unwrap();
        let (value, identity, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, || 7);
        assert_eq!(value, 7);
        assert!(identity.is_none());
        assert_eq!(counts, AllocationCounts::default());
        assert_disarmed();

        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::capture_layout_and_count(layout, || {
                panic!("intentional exact-layout observation unwind");
            });
        });
        assert!(result.is_err());
        assert_disarmed();
    }

    #[test]
    fn owned_probe_registry_contention_is_not_a_reservation_witness() {
        let account = HostServiceAllocator::new(1, 1, 48).unwrap();
        let (_, report) = TestAllocationObserver::observe_resident_after_free(
            &account,
            AllocationIdentity(1),
            || {
                let guard = RESIDENT_PROBE.lock().unwrap();
                assert_eq!(guard.as_ref().unwrap().account, account);
                // This scalar-only unit control exercises refusal, not a native
                // deallocation. The integration binary binds actual free order.
                assert!(claim_resident_probe(1).is_none());
                assert_eq!(RESIDENT_STATUS.load(Ordering::Acquire) & 7, PROBE_CONTENDED);
            },
        )
        .unwrap();

        assert_eq!(report.outcome, ResidentProbeOutcome::Contended);
        assert_eq!(report.counts.allocations, 0);
        assert_eq!(report.first_allocation, None);
        assert!(RESIDENT_PROBE.lock().unwrap().is_none());
        assert_eq!(RESIDENT_TARGET.load(Ordering::Acquire), 0);

        eprintln!(
            "fixed resident probe geometry TLS={} recursionTLS={} ownedWatch={} originalAllocator={} privateOutcome={} globalMutex={} status={} target={} allocationCounters={} overflowFlag={} firstLayoutAtomics={}",
            std::mem::size_of::<Watch>(),
            std::mem::size_of::<Cell<bool>>(),
            std::mem::size_of::<OwnedResidentProbe>(),
            std::mem::size_of::<HostServiceAllocator>(),
            std::mem::size_of::<ResidentProbe>(),
            std::mem::size_of_val(&RESIDENT_PROBE),
            std::mem::size_of_val(&RESIDENT_STATUS),
            std::mem::size_of_val(&RESIDENT_TARGET),
            std::mem::size_of_val(&RESIDENT_ALLOCATIONS)
                + std::mem::size_of_val(&RESIDENT_REALLOCATIONS),
            std::mem::size_of_val(&RESIDENT_COUNT_OVERFLOW),
            std::mem::size_of_val(&RESIDENT_ALLOCATION_BYTES)
                + std::mem::size_of_val(&RESIDENT_ALLOCATION_ALIGNMENT),
        );
    }

    #[test]
    fn static_marker_refuses_contention_stale_generation_and_poisoned_setup() {
        static ORIGINAL: AtomicBool = AtomicBool::new(false);
        // This private control tests refusal only; the scalar is never freed.
        // External controls separately exercise real System close ordering.
        let ((), outcome) = TestAllocationObserver::observe_close_marker_after_free(
            &ORIGINAL,
            AllocationIdentity(1),
            || {
                let _held = CLOSE_MARKER.lock().unwrap();
                assert!(claim_close_marker(1).is_none());
            },
        )
        .unwrap();
        assert_eq!(outcome, CloseMarkerOutcome::Contended);
        assert!(!ORIGINAL.load(Ordering::SeqCst));
        let predecessor = CLOSE_STATUS.load(Ordering::Acquire);

        let ((), outcome) = TestAllocationObserver::observe_close_marker_after_free(
            &ORIGINAL,
            AllocationIdentity(1),
            || {
                assert!(
                    CLOSE_STATUS
                        .compare_exchange(
                            predecessor,
                            (predecessor & !7) | CLOSE_CONTENDED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                );
            },
        )
        .unwrap();
        assert_eq!(outcome, CloseMarkerOutcome::Missing);
        assert!(!ORIGINAL.load(Ordering::SeqCst));

        let poison = std::panic::catch_unwind(|| {
            let _held = CLOSE_MARKER.lock().unwrap();
            panic!("intentional static-marker setup poison outside the hook");
        });
        assert!(poison.is_err());
        let refused = TestAllocationObserver::observe_close_marker_after_free(
            &ORIGINAL,
            AllocationIdentity(1),
            || (),
        );
        assert_eq!(refused, Err(CloseMarkerSetupError::Unavailable));
        CLOSE_MARKER.clear_poison();
        assert!(CLOSE_MARKER.lock().unwrap().is_none());
        assert_eq!(CLOSE_TARGET.load(Ordering::Acquire), 0);
        eprintln!(
            "static close marker owned={} mutex={} target={} status={}",
            std::mem::size_of::<CloseMarker>(),
            std::mem::size_of_val(&CLOSE_MARKER),
            std::mem::size_of_val(&CLOSE_TARGET),
            std::mem::size_of_val(&CLOSE_STATUS),
        );
    }

    #[test]
    fn capture_disarms_on_return_and_valid_action_unwind() {
        let (value, _) = TestAllocationObserver::capture(72, || 7);
        assert_eq!(value, 7);
        assert_disarmed();

        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::capture(72, || {
                panic!("intentional test-action unwind outside the allocator");
            });
        });
        assert!(result.is_err());
        assert_disarmed();
    }

    #[test]
    fn borrowed_observation_disarms_on_valid_action_unwind() {
        let account = HostServiceAllocator::new(1, 1, 512)
            .unwrap_or_else(|error| panic!("original test capacity: {error}"));
        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::observe(&account, AllocationIdentity(1), || {
                panic!("intentional borrowed test-action unwind outside the allocator");
            });
        });

        assert!(result.is_err());
        assert_disarmed();
        assert!(account.verify_live().is_ok());
    }

    #[test]
    fn fixed_group_and_count_state_disarms_on_return_and_unwind() {
        let (value, _) = TestAllocationObserver::capture_controls([24, 48, 72], || 11);
        assert_eq!(value, 11);
        assert_disarmed();
        let first = HostServiceAllocator::new(1, 1, 512).unwrap();
        let second = HostServiceAllocator::new(1, 1, 512).unwrap();
        let occupied = AtomicBool::new(true);
        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::observe_controls(
                [&first, &second],
                Some(&occupied),
                [Some(AllocationIdentity(1)), None, None],
                || panic!("intentional paired observer action unwind"),
            );
        });
        assert!(result.is_err());
        assert_disarmed();
        let result = std::panic::catch_unwind(|| {
            TestAllocationObserver::count(|| panic!("intentional counter action unwind"));
        });
        assert!(result.is_err());
        assert_disarmed();
        eprintln!(
            "observer fixed TLS={} sample={} observation={} counts={}",
            std::mem::size_of::<Watch>(),
            std::mem::size_of::<ControlSample>(),
            std::mem::size_of::<ControlObservation>(),
            std::mem::size_of::<AllocationCounts>()
        );
    }
}
