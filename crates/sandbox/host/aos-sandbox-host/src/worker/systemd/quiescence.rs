//! Shares payload freeze/inspection/thaw with retained native destinations.
//!
//! Complete positive freezer reads physically retire their exact temporary
//! owners before another sample. Failed samples remain resident; a separately
//! prearmed thaw attempt still runs, under the same original Launch deadline.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use aos_sandbox_linux::cgroup::{
    CgroupChildOriginalV2, CgroupRootOriginalV2, FreezerReadOriginalV2,
    FreezerRequestOriginalV2,
};

use super::*;

const FREEZER_INTERVAL: Duration = Duration::from_millis(5);
const FREEZER_TIMEOUT: Duration = Duration::from_secs(15);
// One initial observation and every 5ms opportunity, including both endpoints.
const MAXIMUM_FREEZER_SAMPLES: usize = 1 + 15_000 / 5 + 1;

// The mechanical lower callback receives no payer or role grant. Its only
// production source is this opaque borrower of the resident same-Launch clock.
// Actual samples and their native errors remain on that original clock; this
// owner retains each returned authority result at its precise write frontier.
struct FreezerWriteClockV2 {
    clock: crate::broker::HostLaunchWriteClockV2,
    results: [Option<Result<aos_sandbox_model::RawPairedClockSample>>; 2],
    used: usize,
}

impl FreezerWriteClockV2 {
    fn new(clock: crate::broker::HostLaunchWriteClockV2) -> Self {
        Self { clock, results: std::array::from_fn(|_| None), used: 0 }
    }

    fn before_write(&mut self) -> aos_linux_descriptors::Result<()> {
        let Some(slot) = self.results.get_mut(self.used) else {
            return Err(aos_linux_descriptors::Error::InvalidInput {
                field: "Launch freezer write clock",
                message: "prepaid write sample roster is exhausted".to_owned(),
            });
        };
        self.used += 1;
        *slot = Some(self.clock.sample_before_write_v2());
        if matches!(slot, Some(Ok(_))) { Ok(()) } else {
            Err(aos_linux_descriptors::Error::InvalidInput {
                field: "Launch freezer write clock",
                message: "original authority refusal is retained".to_owned(),
            })
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.results.iter().find_map(|result| error(result))
    }
}

struct FreezerSampleDisposedV2 {
    origin: Arc<()>,
    slot: usize,
    state: CgroupFreezerState,
}

struct FreezerSampleV2 {
    original: Option<Box<FreezerReadOriginalV2>>,
    disposed: Option<FreezerSampleDisposedV2>,
}

struct FreezerSamplesV2 {
    origin: Arc<()>,
    samples: Vec<FreezerSampleV2>,
    refusal: Option<HostError>,
}

impl FreezerSamplesV2 {
    fn new() -> Self {
        Self {
            origin: Arc::new(()),
            samples: Vec::with_capacity(MAXIMUM_FREEZER_SAMPLES),
            refusal: None,
        }
    }

    fn observe_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        deadline: Instant,
    ) -> Result<CgroupFreezerState> {
        if self.refusal.is_some() || self.samples.len() == MAXIMUM_FREEZER_SAMPLES {
            self.refusal.get_or_insert_with(|| closed("freezer sample roster is exhausted"));
            return Err(closed("freezer sample roster is exhausted"));
        }
        if self.samples.last().is_some_and(|previous| {
            !previous.disposed.as_ref().is_some_and(|proof| {
                proof.slot + 1 == self.samples.len()
                    && Arc::ptr_eq(&proof.origin, &self.origin)
                    && previous.original.is_none()
            })
        }) {
            self.refusal.get_or_insert_with(|| closed("earlier freezer native sample remains occupied"));
            return Err(closed("earlier freezer native sample remains occupied"));
        }
        if let Err(error) = require_deadline(deadline) {
            self.refusal = Some(error);
            return Err(closed("original Launch deadline expired before freezer read"));
        }

        // This actual receiver is parked before the first native observation.
        let slot = self.samples.len();
        self.samples.push(FreezerSampleV2 {
            original: Some(Box::new(FreezerReadOriginalV2::new())),
            disposed: None,
        });
        let sample = self.samples.last_mut()
            .ok_or_else(|| closed("freezer sample destination is absent"))?;
        let original = sample.original.as_mut()
            .ok_or_else(|| closed("freezer native sample is absent"))?;
        original.observe_once(anchor)
            .map_err(|_| closed("freezer native read failed; original retained"))?;
        let state = original.take_completed_once()
            .ok_or_else(|| closed("freezer sample has no complete parsed state"))?;

        // The lower owner has completed every active/open/read/parse predicate.
        // No upper/global post consumes this read's Files or buffer. Consume
        // the exact owner now, then record its same-pool/slot physical disposal;
        // the separately retained anchor and real payload pins are unchanged.
        drop(sample.original.take());
        sample.disposed = Some(FreezerSampleDisposedV2 {
            origin: Arc::clone(&self.origin),
            slot,
            state,
        });
        Ok(state)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.samples.iter().find_map(|sample| sample.original.as_ref()?.failure())
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let native = FreezerReadOriginalV2::receiving_obligations_v2()?;
        let frames = std::mem::size_of::<FreezerSampleV2>()
            .checked_mul(MAXIMUM_FREEZER_SAMPLES)?.checked_mul(2)?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(frames)?.checked_add(native.0)?;
        Some((memory, native.1, native.2.checked_mul(MAXIMUM_FREEZER_SAMPLES)?))
    }
}

// The same loop retains Local's native error and consuming File disposition.
// Selected bounds every new read/sleep by the previously captured Launch cutoff.
macro_rules! freezer_poll_sample {
    (Local, $anchor:ident, $original:ident, $deadline:ident) => {
        $anchor.freezer_state().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $anchor:ident, $original:ident, $deadline:ident) => {
        $original.observe_once($anchor, $deadline)?
    };
}

macro_rules! freezer_poll_sleep {
    (Local, $deadline:ident) => { std::thread::sleep(FREEZER_INTERVAL) };
    (Retained, $deadline:ident) => {{
        require_deadline($deadline)?;
        std::thread::sleep(FREEZER_INTERVAL.min($deadline.saturating_duration_since(Instant::now())));
    }};
}

macro_rules! freezer_poll_recipe {
    ($anchor:ident, $expected:ident, $mode:ident, $original:ident, $outer_deadline:ident) => {{
        let deadline = freezer_poll_deadline!($mode, $outer_deadline);
        loop {
            let observed = freezer_poll_sample!($mode, $anchor, $original, deadline);
            if observed == $expected {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err(HostError::Worker(format!(
                    "payload cgroup did not reach {:?} freezer state", $expected,
                )));
            }
            freezer_poll_sleep!($mode, deadline);
        }
    }};
}

macro_rules! freezer_poll_deadline {
    (Local, $outer_deadline:ident) => { Instant::now() + FREEZER_TIMEOUT };
    (Retained, $outer_deadline:ident) => {
        $outer_deadline.min(Instant::now() + FREEZER_TIMEOUT)
    };
}

pub(super) fn await_local(
    anchor: &RetainedCgroupAnchor,
    expected: CgroupFreezerState,
) -> Result<()> {
    freezer_poll_recipe!(anchor, expected, Local, unused, unused)
}

fn await_retaining(
    anchor: &RetainedCgroupAnchor,
    expected: CgroupFreezerState,
    original: &mut FreezerSamplesV2,
    deadline: Instant,
) -> Result<()> {
    freezer_poll_recipe!(anchor, expected, Retained, original, deadline)
}

macro_rules! quiescence_root {
    (Local, $input:ident, $original:ident) => {
        CgroupV2Root::from_owned($input.as_fd().try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?)
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $input:ident, $original:ident) => {{
        require_deadline($original.deadline)?;
        $original.duplicate = Some($input.as_fd().try_clone_to_owned());
        require_deadline($original.deadline)?;
        let descriptor = match $original.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            Some(Err(error)) => {
                $original.duplicate = Some(Err(error));
                return Err(closed("payload freeze root duplicate failed; original retained"));
            }
            None => return Err(closed("payload freeze root duplicate is absent")),
        };
        $original.root.admit_once(descriptor)
            .map_err(|_| closed("payload freeze root failed; original retained"))?;
        $original.completed_root = Some($original.root.take_completed_once()
            .ok_or_else(|| closed("payload freeze root is incomplete"))?);
        $original.completed_root.as_ref()
            .ok_or_else(|| closed("payload freeze root is absent"))?
    }};
}

macro_rules! quiescence_anchor {
    (Local, $root:ident, $original:ident) => {
        $root.resolve(Path::new(".")).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $root:ident, $original:ident) => {{
        require_deadline($original.deadline)?;
        $original.child.resolve_once($root, Path::new("."))
            .map_err(|_| closed("payload freeze anchor failed; original retained"))?;
        $original.anchor = Some($original.child.take_completed_once()
            .ok_or_else(|| closed("payload freeze anchor is incomplete"))?);
        $original.anchor.as_ref().ok_or_else(|| closed("payload freeze anchor is absent"))?
    }};
}

macro_rules! quiescence_initial {
    (Local, $anchor:ident, $original:ident) => {
        $anchor.freezer_state().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $anchor:ident, $original:ident) => {
        $original.freeze_samples.observe_once($anchor, $original.deadline)?
    };
}

macro_rules! quiescence_freeze {
    (Local, Before, $anchor:ident, $initial:ident, $original:ident) => {
        if $initial == CgroupFreezerState::Thawed {
            $anchor.request_freezer_state(CgroupFreezerState::Frozen)
                .map_err(|error| HostError::Worker(error.to_string()))?;
            await_local(&$anchor, CgroupFreezerState::Frozen)?;
        }
    };
    (Local, Inside, $anchor:ident, $initial:ident, $original:ident) => {};
    (Retained, Before, $anchor:ident, $initial:ident, $original:ident) => {};
    (Retained, Inside, $anchor:ident, $initial:ident, $original:ident) => {
        if $initial == CgroupFreezerState::Thawed {
            // Both request/poll reservoirs were paid before root/native entry.
            // Arm the independent thaw obligation before the freeze attempt.
            $original.thaw_armed = true;
            require_deadline($original.deadline)?;
            $original.freeze_request.request_checked_once_v2(
                $anchor, CgroupFreezerState::Frozen,
                &mut || $original.freeze_clock.before_write(),
            )
                .map_err(|_| closed("payload freeze request failed; original retained"))?;
            await_retaining($anchor, CgroupFreezerState::Frozen,
                &mut $original.freeze_samples, $original.deadline)?;
        }
    };
}

macro_rules! quiescence_inspect {
    (Local, $input:ident, $inspect:ident, $original:ident) => {
        $inspect(&LinuxPayloadInspector { payload_root: $input })
    };
    (Retained, $input:ident, $inspect:ident, $original:ident) => {{
        require_deadline($original.deadline)?;
        $original.inspected = Some($inspect(&mut $original.inspector));
        match $original.inspected.as_ref() {
            Some(Ok(_)) => Ok(()),
            _ => Err(closed("payload inspection failed; original retained")),
        }
    }};
}

macro_rules! quiescence_thaw {
    (Local, $anchor:ident, $original:ident) => {
        $anchor.request_freezer_state(CgroupFreezerState::Thawed)
            .map_err(|error| HostError::Worker(error.to_string()))
            .and_then(|()| await_local(&$anchor, CgroupFreezerState::Thawed))
    };
    (Retained, $anchor:ident, $original:ident) => {{
        $original.thaw = Some((|| {
            // Thaw can resume execution: an expired original must refuse the
            // write. Still enter this owed destination and keep its refusal.
            require_deadline($original.deadline)?;
            $original.thaw_request.request_checked_once_v2(
                $anchor, CgroupFreezerState::Thawed,
                &mut || $original.thaw_clock.before_write(),
            )
                .map_err(|_| closed("payload thaw request failed; original retained"))?;
            await_retaining($anchor, CgroupFreezerState::Thawed,
                &mut $original.thaw_samples, $original.deadline)
        })());
        match $original.thaw.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(closed("payload thaw remains unresolved; original retained")),
        }
    }};
}

macro_rules! quiescence_record_primary {
    (Local, $original:ident, $result:ident) => { $result };
    (Retained, $original:ident, $result:ident) => {{
        $original.body = Some($result);
        if matches!($original.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed("payload inspection primary failed; original retained"))
        }
    }};
}

macro_rules! quiescence_recipe {
    ($input:ident, $inspect:ident, $mode:ident, $original:ident) => {{
        let root = quiescence_root!($mode, $input, $original);
        let anchor = quiescence_anchor!($mode, root, $original);
        let initial = quiescence_initial!($mode, anchor, $original);
        quiescence_freeze!($mode, Before, anchor, initial, $original);

        let result = (|| {
            quiescence_freeze!($mode, Inside, anchor, initial, $original);
            quiescence_inspect!($mode, $input, $inspect, $original)
        })();
        let result = quiescence_record_primary!($mode, $original, result);
        if initial == CgroupFreezerState::Frozen {
            result
        } else {
            let thaw = quiescence_thaw!($mode, anchor, $original);
            match (result, thaw) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(error)) => Err(error),
                (Err(primary), Err(cleanup)) => Err(HostError::Worker(format!(
                    "{primary}; additionally failed to thaw payload after inspection: {cleanup}"
                ))),
            }
        }
    }};
}

pub(super) fn inspect_local<T>(
    input: &BeneathRoot,
    inspect: impl FnOnce(&LinuxPayloadInspector<'_>) -> Result<T>,
) -> Result<T> {
    quiescence_recipe!(input, inspect, Local, unused)
}

struct QuiescenceNativeDisposedV4 {
    original: Weak<()>,
}

/// Holds one prepaid inspection and its independently owed thaw attempt.
pub(in crate::worker) struct PayloadInspectionQuiescenceOriginalV2 {
    deadline: Instant,
    entered: bool,
    native_disposed: Option<QuiescenceNativeDisposedV4>,
    thaw_armed: bool,
    duplicate: Option<std::io::Result<OwnedFd>>,
    root: CgroupRootOriginalV2,
    completed_root: Option<CgroupV2Root>,
    child: CgroupChildOriginalV2,
    anchor: Option<RetainedCgroupAnchor>,
    freeze_samples: FreezerSamplesV2,
    freeze_request: FreezerRequestOriginalV2,
    freeze_clock: FreezerWriteClockV2,
    thaw_samples: FreezerSamplesV2,
    thaw_request: FreezerRequestOriginalV2,
    thaw_clock: FreezerWriteClockV2,
    inspector: HostPayloadInspectionOriginalV2,
    inspected: Option<Result<PinnedPayloadLeader>>,
    body: Option<Result<()>>,
    thaw: Option<Result<()>>,
    primary: Option<Result<()>>,
    refusal: Option<HostError>,
}

impl PayloadInspectionQuiescenceOriginalV2 {
    pub(in crate::worker) fn new(
        deadline: tokio::time::Instant,
        clock: crate::broker::HostLaunchWriteClockV2,
    ) -> Self {
        Self {
            deadline: deadline.into_std(),
            entered: false,
            native_disposed: None,
            thaw_armed: false,
            duplicate: None,
            root: CgroupRootOriginalV2::new(),
            completed_root: None,
            child: CgroupChildOriginalV2::new(),
            anchor: None,
            freeze_samples: FreezerSamplesV2::new(),
            freeze_request: FreezerRequestOriginalV2::new(),
            freeze_clock: FreezerWriteClockV2::new(clock.clone()),
            thaw_samples: FreezerSamplesV2::new(),
            thaw_request: FreezerRequestOriginalV2::new(),
            thaw_clock: FreezerWriteClockV2::new(clock),
            inspector: HostPayloadInspectionOriginalV2::new(),
            inspected: None,
            body: None,
            thaw: None,
            primary: None,
            refusal: None,
        }
    }

    pub(in crate::worker) fn discover_once(
        &mut self,
        input: &BeneathRoot,
        supervisor_pid: u32,
        expected_root: (u64, u64),
        expected_network: (u64, u64),
        limits: PayloadInspectionLimitsV2,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("payload quiescence cannot reenter"));
            return Err(closed("payload quiescence cannot reenter"));
        }
        self.entered = true;
        let inspect = |inspector: &mut HostPayloadInspectionOriginalV2| {
            inspector.discover_once(input, supervisor_pid, expected_root, expected_network, limits)
        };
        self.primary = Some((|| quiescence_recipe!(input, inspect, Retained, self))());
        if matches!(self.primary, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed("payload quiescence failed; actual originals retained"))
        }
    }

    pub(in crate::worker) fn payload(&self) -> Option<&PinnedPayloadLeader> {
        self.inspected.as_ref()?.as_ref().ok()
    }

    pub(in crate::worker) fn take_payload_once(&mut self) -> Option<PinnedPayloadLeader> {
        if !matches!(self.primary, Some(Ok(()))) || self.refusal.is_some() {
            return None;
        }
        self.inspected.take()?.ok()
    }

    pub(in crate::worker) fn dispose_completed_native_once_v4(&mut self) -> Result<()> {
        if !self.entered || self.native_disposed.is_some()
            || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.body, Some(Ok(())))
            || (self.thaw_armed && !matches!(self.thaw, Some(Ok(()))))
            || self.inspected.is_some()
            || self.failure().is_some()
        {
            self.refusal.get_or_insert_with(|| closed("quiescence native prefix is not disposable"));
            return Err(closed("quiescence native prefix is not disposable"));
        }

        // The payload pins have moved into the actual bound readback. The full
        // freeze/discovery/independent-thaw flight has completed; later checks
        // consume those pins, never these temporary traversal/active Files.
        // Empty replacement destinations cannot reenter: entered stays true.
        drop(std::mem::replace(&mut self.inspector, HostPayloadInspectionOriginalV2::new()));
        drop(std::mem::replace(&mut self.freeze_request, FreezerRequestOriginalV2::new()));
        drop(std::mem::replace(&mut self.thaw_request, FreezerRequestOriginalV2::new()));
        drop(self.anchor.take());
        drop(std::mem::replace(&mut self.child, CgroupChildOriginalV2::new()));
        drop(self.completed_root.take());
        drop(std::mem::replace(&mut self.root, CgroupRootOriginalV2::new()));
        self.native_disposed = Some(QuiescenceNativeDisposedV4 {
            original: Arc::downgrade(&self.freeze_samples.origin),
        });
        Ok(())
    }

    pub(in crate::worker) fn native_is_disposed_v4(&self) -> bool {
        self.native_disposed.as_ref().is_some_and(|proof| {
            Weak::ptr_eq(&proof.original, &Arc::downgrade(&self.freeze_samples.origin))
        }) && self.completed_for_parent_disposal_v4()
    }

    pub(in crate::worker) fn completed_for_parent_disposal_v4(&self) -> bool {
        matches!(self.primary, Some(Ok(()))) && self.refusal.is_none()
            && self.inspected.is_none() && self.failure().is_none()
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.duplicate)
            .or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| self.child.failure().map(|cause| cause as _))
            .or_else(|| self.freeze_samples.failure())
            .or_else(|| self.freeze_clock.failure())
            .or_else(|| self.freeze_request.failure())
            .or_else(|| self.inspector.failure())
            .or_else(|| error(&self.inspected))
            .or_else(|| error(&self.body))
            .or_else(|| self.thaw_clock.failure())
            .or_else(|| self.thaw_request.failure())
            .or_else(|| self.thaw_samples.failure())
            .or_else(|| error(&self.thaw))
            .or_else(|| error(&self.primary))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2(
        limits: PayloadInspectionLimitsV2,
    ) -> Option<(usize, usize, usize)> {
        let mut result = (std::mem::size_of::<Self>().checked_mul(2)?, 0_usize, 0_usize);
        for next in [
            CgroupRootOriginalV2::receiving_obligations_v2()?,
            CgroupChildOriginalV2::receiving_obligations_v2(1)?,
            FreezerSamplesV2::receiving_obligations_v2()?,
            FreezerSamplesV2::receiving_obligations_v2()?,
            FreezerRequestOriginalV2::receiving_obligations_v2()?,
            FreezerRequestOriginalV2::receiving_obligations_v2()?,
            limits.receiving_obligations_v2()?,
        ] {
            result = (
                result.0.checked_add(next.0)?,
                result.1.checked_add(next.1)?,
                result.2.checked_add(next.2)?,
            );
        }
        Some(result)
    }
}

fn require_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(closed("original Launch worker deadline expired"))
    } else {
        Ok(())
    }
}

fn closed(message: &'static str) -> HostError {
    HostError::Fence(message)
}

fn error<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_foreign_root_refusal_cannot_dispose_its_original_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let input = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = PayloadInspectionQuiescenceOriginalV2::new(
            tokio::time::Instant::now() + Duration::from_secs(1),
            crate::broker::HostLaunchWriteClockV2::absent_for_test(),
        );
        let limits = PayloadInspectionLimitsV2::new(1, 1, 1, 1).unwrap();

        assert!(original.discover_once(&input, 1, (0, 0), (0, 0), limits).is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.root.failure().is_some());
        assert!(original.dispose_completed_native_once_v4().is_err());

        assert!(!original.native_is_disposed_v4());
        assert!(original.root.failure().is_some());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        assert!(original.take_payload_once().is_none());
    }

    #[test]
    fn expired_independent_thaw_parks_refusal_without_entering_native_write() {
        let descriptor = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let retained_anchor = root.resolve(Path::new(".")).unwrap();
        let anchor = &retained_anchor;
        let deadline = tokio::time::Instant::from_std(Instant::now() - Duration::from_secs(1));
        let mut original = PayloadInspectionQuiescenceOriginalV2::new(
            deadline, crate::broker::HostLaunchWriteClockV2::absent_for_test(),
        );
        original.thaw_armed = true;

        let outcome: Result<()> = quiescence_thaw!(Retained, anchor, original);

        assert!(outcome.is_err());
        assert!(matches!(original.thaw, Some(Err(HostError::Fence(
            "original Launch worker deadline expired"
        )))));
        // A real root request would fail NOENT and leave a native cause. This
        // owner's absence of native failure establishes the pre-write gate.
        assert!(original.thaw_request.failure().is_none());
        assert!(original.thaw_samples.samples.is_empty());
        assert!(original.inspected.is_none());
        assert!(original.take_payload_once().is_none());
    }
}
