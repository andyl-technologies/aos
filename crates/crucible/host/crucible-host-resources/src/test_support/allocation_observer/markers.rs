//! Owns static original-credit samples around exact physical control closes.
//!
//! One global arm serves legacy Boolean publication/sampling and the two fixed
//! original-control slots. A claimed nonblocking guard spans the actual System
//! free. Counter references are static and closed typed cases; neither memory
//! contents nor caller callbacks enter the allocator hook.

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use super::{AllocationIdentity, TestAllocationObserver};

mod controls;

#[cfg(test)]
static TEST_SERIAL: Mutex<()> = Mutex::new(());

use controls::OriginalControls;
pub use controls::{
    OriginalControlObservation, OriginalControlReport, OriginalControlSelection,
    OriginalControlSession, OriginalControlSlot, OriginalControlSnapshot, OriginalControlsOutcome,
    OriginalStaticCounters,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseMarkerMode {
    PublishAfter,
    SampleBefore,
    SampleThrough,
}

struct CloseMarker {
    original: &'static AtomicBool,
    generation: u64,
    mode: CloseMarkerMode,
    through_before: Option<bool>,
    through_after: Option<bool>,
}

// The registry excludes legacy marker and fixed original-control modes.
enum CloseWatch {
    Marker(CloseMarker),
    Controls(OriginalControls),
}

static CLOSE_MARKER: Mutex<Option<CloseWatch>> = Mutex::new(None);
static CLOSE_TARGET: AtomicUsize = AtomicUsize::new(0);
static OTHER_TARGET: AtomicUsize = AtomicUsize::new(0);
static CLOSE_STATUS: AtomicU64 = AtomicU64::new(0);

const CLOSE_ARMED: u64 = 1;
const CLOSE_PUBLISHED: u64 = 2;
const CLOSE_CONTENDED: u64 = 3;
const CLOSE_UNAVAILABLE: u64 = 4;
const CLOSE_BEFORE_OPEN: u64 = 5;
const CLOSE_BEFORE_CLOSED: u64 = 6;

struct CloseMarkerReset(u64);

impl Drop for CloseMarkerReset {
    fn drop(&mut self) {
        // Teardown alone may wait. It cannot release static sample custody or
        // admit a successor until every claimed physical free finishes.
        let mut slot = match CLOSE_MARKER.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        controls::reset(self.0);
        CLOSE_TARGET.store(0, Ordering::Release);
        OTHER_TARGET.store(0, Ordering::Release);
        *slot = None;
    }
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

/// Samples the same original flag on both sides of physical System close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThroughFreeMarkerOutcome {
    /// The selected allocation did not close during the action.
    Missing,
    /// Both sequentially consistent original samples surround the same free.
    Sampled {
        /// The original flag immediately before System free.
        before: bool,
        /// The original flag immediately after System free.
        after: bool,
    },
    /// The nonblocking guard was busy; no ordering is established.
    Contended,
    /// State was unavailable; no ordering is established.
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

    /// Samples the same original static flag around one physical System free.
    ///
    /// The existing marker guard spans both reads and the actual free. Neither
    /// sample modifies the original flag. The action joins all possible closing
    /// workers and retains its original owner until close. Missing or refused
    /// observations do not prove original credit survives the physical extent.
    ///
    /// # Errors
    /// Refuses overlapping, poisoned or exhausted original marker state.
    ///
    /// # Panics
    /// Propagates an action panic after disarming and completing outer teardown.
    pub fn observe_close_marker_through_free<T>(
        original: &'static AtomicBool,
        identity: AllocationIdentity,
        action: impl FnOnce() -> T,
    ) -> Result<(T, ThroughFreeMarkerOutcome), CloseMarkerSetupError> {
        let _reset = arm_close_marker(original, identity, CloseMarkerMode::SampleThrough)?;
        let value = action();
        let outcome = match CLOSE_STATUS.load(Ordering::Acquire) & 7 {
            CLOSE_ARMED => ThroughFreeMarkerOutcome::Missing,
            CLOSE_CONTENDED => ThroughFreeMarkerOutcome::Contended,
            CLOSE_PUBLISHED => match CLOSE_MARKER.lock() {
                Ok(slot) => match slot.as_ref().and_then(|watch| match watch {
                    CloseWatch::Marker(watch) => {
                        Some((watch.through_before?, watch.through_after?))
                    }
                    CloseWatch::Controls(_) => None,
                }) {
                    Some((before, after)) => ThroughFreeMarkerOutcome::Sampled { before, after },
                    None => ThroughFreeMarkerOutcome::Unavailable,
                },
                Err(_) => ThroughFreeMarkerOutcome::Unavailable,
            },
            _ => ThroughFreeMarkerOutcome::Unavailable,
        };
        Ok((value, outcome))
    }
}

fn target(index: usize) -> &'static AtomicUsize {
    if index == 0 {
        &CLOSE_TARGET
    } else {
        &OTHER_TARGET
    }
}

fn next_generation() -> Result<u64, CloseMarkerSetupError> {
    (CLOSE_STATUS.load(Ordering::Relaxed) & !7)
        .checked_add(8)
        .ok_or(CloseMarkerSetupError::Unavailable)
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
    let generation = next_generation()?;
    *slot = Some(CloseWatch::Marker(CloseMarker {
        original,
        generation,
        mode,
        through_before: None,
        through_after: None,
    }));
    CLOSE_STATUS.store(generation | CLOSE_ARMED, Ordering::Release);
    CLOSE_TARGET.store(identity.0, Ordering::Release);
    Ok(CloseMarkerReset(generation))
}

fn record_refusal(status: u64, error: std::sync::TryLockError<MutexGuard<'_, Option<CloseWatch>>>) {
    let outcome = match error {
        std::sync::TryLockError::WouldBlock => CLOSE_CONTENDED,
        std::sync::TryLockError::Poisoned(_) => CLOSE_UNAVAILABLE,
    };
    // A delayed refusal cannot overwrite an unrelated successor's generation.
    let _ = CLOSE_STATUS.compare_exchange(
        status,
        (status & !7) | outcome,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

enum ClaimKind {
    Marker(MutexGuard<'static, Option<CloseWatch>>),
    Original(controls::ControlClaim),
}

pub(super) struct ClaimedControl {
    kind: ClaimKind,
}

pub(super) fn claim_close_marker(pointer: usize) -> Option<ClaimedControl> {
    let status = CLOSE_STATUS.load(Ordering::Acquire);
    if pointer == 0 || status & 7 != CLOSE_ARMED {
        return None;
    }
    let index = (0..2).find(|index| target(*index).load(Ordering::Acquire) == pointer)?;
    if controls::active(status) {
        return controls::claim(pointer, index, status).map(|claim| ClaimedControl {
            kind: ClaimKind::Original(claim),
        });
    }
    match CLOSE_MARKER.try_lock() {
        Ok(slot) => {
            if CLOSE_STATUS.load(Ordering::Acquire) == status
                && target(index)
                    .compare_exchange(pointer, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                Some(ClaimedControl {
                    kind: ClaimKind::Marker(slot),
                })
            } else {
                None
            }
        }
        Err(error) => {
            record_refusal(status, error);
            None
        }
    }
}

impl ClaimedControl {
    pub(super) fn sample_before_free(&mut self) {
        match &mut self.kind {
            ClaimKind::Original(claim) => claim.sample_before_free(),
            ClaimKind::Marker(slot) => {
                let Some(CloseWatch::Marker(watch)) = slot.as_mut() else {
                    return;
                };
                match watch.mode {
                    CloseMarkerMode::SampleThrough => {
                        watch.through_before = Some(watch.original.load(Ordering::SeqCst));
                    }
                    CloseMarkerMode::SampleBefore => {
                        let sampled = if watch.original.load(Ordering::SeqCst) {
                            CLOSE_BEFORE_CLOSED
                        } else {
                            CLOSE_BEFORE_OPEN
                        };
                        CLOSE_STATUS.store(watch.generation | sampled, Ordering::Release);
                    }
                    CloseMarkerMode::PublishAfter => {}
                }
            }
        }
    }

    pub(super) fn sample_after_free(&mut self) {
        match &mut self.kind {
            ClaimKind::Original(claim) => claim.sample_after_free(),
            ClaimKind::Marker(slot) => {
                let Some(CloseWatch::Marker(watch)) = slot.as_mut() else {
                    return;
                };
                match watch.mode {
                    CloseMarkerMode::PublishAfter => {
                        watch.original.store(true, Ordering::SeqCst);
                        CLOSE_STATUS.store(watch.generation | CLOSE_PUBLISHED, Ordering::Release);
                    }
                    CloseMarkerMode::SampleThrough => {
                        watch.through_after = Some(watch.original.load(Ordering::SeqCst));
                        CLOSE_STATUS.store(watch.generation | CLOSE_PUBLISHED, Ordering::Release);
                    }
                    CloseMarkerMode::SampleBefore => {}
                }
            }
        }
    }
}

pub(super) fn record_allocation(address: usize, layout: Layout, reallocation: bool) {
    controls::record_allocation(address, layout, reallocation);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_marker_refuses_contention_stale_generation_and_poisoned_setup() {
        let _serial = TEST_SERIAL.lock().unwrap();
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

        let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
            session
                .arm(
                    OriginalControlSlot::First,
                    OriginalControlSelection::Explicit(AllocationIdentity(1)),
                    OriginalStaticCounters::Bool(&ORIGINAL),
                    false,
                )
                .unwrap();
            {
                let _held = controls::hold_first_for_test();
                assert!(claim_close_marker(1).is_none());
            }
            assert_eq!(
                session.report().unwrap().outcome,
                OriginalControlsOutcome::Contended
            );
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Contended);
        assert!(report.controls[0].is_none());
        let previous = CLOSE_STATUS.load(Ordering::Acquire);
        let ((), report) = TestAllocationObserver::observe_original_controls(|_| {
            assert!(
                CLOSE_STATUS
                    .compare_exchange(
                        previous,
                        (previous & !7) | CLOSE_UNAVAILABLE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
            );
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Missing);
        assert_eq!(OTHER_TARGET.load(Ordering::Acquire), 0);

        eprintln!(
            "static close marker owned={} mutex={} target={} status={}",
            std::mem::size_of::<CloseMarker>(),
            std::mem::size_of_val(&CLOSE_MARKER),
            std::mem::size_of_val(&CLOSE_TARGET),
            std::mem::size_of_val(&CLOSE_STATUS),
        );
    }
}
