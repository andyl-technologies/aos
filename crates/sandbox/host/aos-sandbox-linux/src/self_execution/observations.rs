//! Owns the native prefixes of one selected self-execution observation.
//!
//! The actual guard lends its original pidfd. This destination reuses the
//! existing bounded boot-ID/proc-stat owners and the common execution-baseline
//! predicate; no caller PID, descriptor, path or supplied observation is accepted.
//! Ordinary self-execution observation retains its original native disposition.

use super::*;
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;
use crate::pidfd::PidFdProcObservationsV1;

/// Retains one complete selected execution observation and its partial natives.
///
/// Construction creates empty observation slots without IO or authority. A
/// genuine guard must supply its own original pidfd to the private observer.
/// Failure, repeated entry and interrupted observation permanently close this
/// destination. The owner must retain it through the enclosing negative result.
pub struct SelfExecutionObservationV1 {
    boot: [RootOriginalKernelBootIdAttemptV1; 2],
    information: [Option<aos_linux_descriptors::Result<PidFdInfo>>; 2],
    proc: Option<PidFdProcObservationsV1>,
    identity: Option<aos_linux_descriptors::Result<PidFdProcessIdentity>>,
    liveness: Option<aos_linux_descriptors::Result<bool>>,
    baseline: Option<Result<ExecutionBaseline, SelfExecutionObservationError>>,
    comparison: Option<Result<(), SelfExecutionObservationError>>,
    entered: bool,
    repeated: bool,
}

impl SelfExecutionObservationV1 {
    /// Creates fixed empty slots without allocation or native observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            boot: [RootOriginalKernelBootIdAttemptV1::new(), RootOriginalKernelBootIdAttemptV1::new()],
            information: [None, None],
            proc: None,
            identity: None,
            liveness: None,
            baseline: None,
            comparison: None,
            entered: false,
            repeated: false,
        }
    }

    /// Bounds additional heap/scratch of the reached fixed native recipe.
    ///
    /// The caller counts this owner's actual inline layout separately. This
    /// conservative permit includes the proc parser's borrowed-field table,
    /// raw capacities and fixed read/path/error scratch; it is not a claim
    /// about exact allocator metadata or physical fit.
    #[must_use]
    pub const fn receiving_heap_bytes_v1() -> usize {
        PidFdProcObservationsV1::stat_receiving_footprint_v1().0
    }

    /// Bounds fresh files simultaneously retained by a failed observation.
    #[must_use]
    pub const fn opened_file_bound_v1() -> usize {
        // Actual before/after boot files and one actual proc-stat descriptor.
        2 + 1
    }

    /// Counts the two named reads of the fixed self-execution recipe.
    ///
    /// Both scalar observations read the same boot-ID path. The process
    /// identity reads only the stat path of the actual retained pidfd. Repeated
    /// file descriptions and parser/control fields add no namespace entries.
    #[must_use]
    pub const fn native_named_read_entries_v2() -> usize {
        2
    }

    /// Bounds representation cells, including the fixed native read slots.
    #[must_use]
    pub const fn metadata_cell_bound_v1() -> usize {
        PidFdProcObservationsV1::stat_receiving_footprint_v1().1
            + 2 * RootOriginalKernelBootIdAttemptV1::native_cell_bound_v1()
    }

    /// Borrows the earliest reached native or execution-comparison failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.boot[0].failure()
            .or_else(|| self.information[0].as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.identity.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.information[1].as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.liveness.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.boot[1].failure())
            .or_else(|| self.baseline.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.repeated.then_some(&SelfExecutionObservationError as _))
    }

    /// Reports completed comparison and actual positive native disposition.
    ///
    /// Only the existing complete native validator sets this comparison.
    /// Its success branch disposes boot/proc descriptors before returning.
    /// An inert, failed, partial or repeated destination never satisfies it.
    #[doc(hidden)]
    pub fn completed_positive_native_disposition_v1(&self) -> bool {
        self.entered && !self.repeated
            && matches!(self.comparison, Some(Ok(())))
            && self.proc.is_none() && self.failure().is_none()
    }

    pub(super) fn observe_baseline_once(
        &mut self,
        original: &PidFd,
    ) -> Result<ExecutionBaseline, SelfExecutionObservationError> {
        if self.entered {
            self.repeated = true;
            return Err(SelfExecutionObservationError);
        }
        self.entered = true;

        let mut source = RetainingObservationSource {
            original,
            destination: self,
            scalar_index: 0,
            information_index: 0,
        };
        let observed = source.scalars().and_then(|before| {
            observe_after_scalars(&mut source, &(), before)
        });
        self.baseline = Some(observed.clone());
        observed
    }

    pub(super) fn validate_once(
        &mut self,
        original: &PidFd,
        expected: ExecutionBaseline,
    ) -> Result<(), SelfExecutionObservationError> {
        let actual = self.observe_baseline_once(original)?;
        self.comparison = Some(if actual == expected {
            Ok(())
        } else {
            Err(SelfExecutionObservationError)
        });
        let result = self.comparison.as_ref().ok_or(SelfExecutionObservationError)?.clone();
        if result.is_ok() {
            self.dispose_positive_originals();
        }
        result
    }

    pub(super) fn dispose_positive_originals(&mut self) {
        // This helper is reached only after this native observation's entire
        // baseline predicate is positive. Boot/proc files are local scratch,
        // with no spawned work or pending IO; their actual disposal completes
        // before success returns. A later outer file comparison grants no
        // permission to reuse a failed observation or its native originals.
        self.boot = [RootOriginalKernelBootIdAttemptV1::new(), RootOriginalKernelBootIdAttemptV1::new()];
        self.proc = None;
    }
}

impl Default for SelfExecutionObservationV1 {
    fn default() -> Self {
        Self::new()
    }
}

struct RetainingObservationSource<'original, 'destination> {
    original: &'original PidFd,
    destination: &'destination mut SelfExecutionObservationV1,
    scalar_index: usize,
    information_index: usize,
}

impl ExecutionObservationSource for RetainingObservationSource<'_, '_> {
    type Process = ();

    fn scalars(&mut self) -> Result<ScalarObservation, SelfExecutionObservationError> {
        let index = self.scalar_index;
        self.scalar_index += 1;
        let slot = self.destination.boot.get_mut(index).ok_or(SelfExecutionObservationError)?;
        let boot_id = slot.observe_once().map_err(|_| SelfExecutionObservationError)?.into_bytes();
        let process_id = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| SelfExecutionObservationError)?;
        Ok(ScalarObservation {
            boot_id,
            process_id,
            effective_user_id: rustix::process::geteuid().as_raw(),
            effective_group_id: rustix::process::getegid().as_raw(),
        })
    }

    fn open_self(&mut self, _process_id: NonZeroU32) -> Result<(), SelfExecutionObservationError> {
        // This source observes only an already owned guard. It cannot capture
        // a replacement process through the common trait's ordinary open port.
        Err(SelfExecutionObservationError)
    }

    fn information(&mut self, _process: &()) -> Result<InformationObservation, SelfExecutionObservationError> {
        let index = self.information_index;
        self.information_index += 1;
        let slot = self.destination.information.get_mut(index).ok_or(SelfExecutionObservationError)?;
        *slot = Some(self.original.info());
        slot.as_ref().and_then(|result| result.as_ref().ok())
            .copied().map(information_from_pidfd).ok_or(SelfExecutionObservationError)
    }

    fn identity(&mut self, _process: &()) -> Result<IdentityObservation, SelfExecutionObservationError> {
        self.destination.proc = Some(crate::pidfd::prepare_proc_observations_v1(&(self.original)));
        let Some(proc) = self.destination.proc.as_mut() else {
            std::process::abort()
        };
        self.destination.identity = Some(proc.capture_stat(self.original));
        self.destination.identity.as_ref().and_then(|result| result.as_ref().ok())
            .copied().map(identity_from_pidfd).ok_or(SelfExecutionObservationError)
    }

    fn alive(&mut self, _process: &()) -> Result<bool, SelfExecutionObservationError> {
        self.destination.liveness = Some(self.original.is_alive());
        self.destination.liveness.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(SelfExecutionObservationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_selected_baseline_keeps_actual_native_observation_originals() {
        let guard = RetainedSelfExecutionGuard::capture().unwrap();
        let mut expected = guard.baseline;
        expected.start_time_ticks = expected.start_time_ticks.checked_add(1).unwrap();
        let mut observed = SelfExecutionObservationV1::new();

        let result = observed.validate_once(guard.original_pidfd().unwrap(), expected);

        assert!(result.is_err());
        assert!(observed.failure().is_some());
        assert!(matches!(observed.baseline, Some(Ok(_))));
        assert!(matches!(observed.comparison, Some(Err(_))));
        assert!(observed.proc.is_some());
        assert!(matches!(observed.identity, Some(Ok(_))));
        assert!(observed.information.iter().all(|result| matches!(result, Some(Ok(_)))));
        assert!(matches!(observed.liveness, Some(Ok(true))));
    }

    #[test]
    fn completed_selected_observation_disposes_scratch_and_cannot_reenter() {
        let guard = RetainedSelfExecutionGuard::capture_retaining().unwrap();
        let mut observed = SelfExecutionObservationV1::new();

        guard.validate_current_retaining(&mut observed).unwrap();

        assert!(observed.proc.is_none());
        assert!(matches!(observed.comparison, Some(Ok(()))));
        assert!(observed.failure().is_none());
        assert!(guard.validate_current_retaining(&mut observed).is_err());
        assert!(observed.repeated);
        assert!(observed.failure().is_some());
        assert!(matches!(observed.comparison, Some(Ok(()))));
    }
}
