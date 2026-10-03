//! Original fixed-Mount startup ownership and PID1 image bookends.
//!
//! The exclusive Linux scan finishes before any observer runtime exists. The
//! fixed observer owns both native image replies; the shared Linux measurer
//! joins them to the actual retained direct-parent kernel observation. Neither
//! reply DATA nor a caller-supplied descriptor can construct this owner.

use aos_sandbox_linux::startup_fd_table::{
    PendingInitialProcessFdTableV2, RetainedStartupImageMeasurementV2,
    StartupExecutableObservationV1, StartupProcessObservationV1,
};
use aos_systemd::{CompletedOwnUnitPid1ImageV1, OwnUnitPid1ImageAttemptV1};

use super::authority::StagedMountManagerStartupCaptureV1;
use super::MountManagerSourceInventoryError;

/// Reports a permanently ended selected startup without copying its cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedMountStartupEndedV2;

impl std::fmt::Display for SelectedMountStartupEndedV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected Mount startup ended")
    }
}

impl std::error::Error for SelectedMountStartupEndedV2 {}

/// Borrows the actual first selected startup failure reservoir.
pub enum SelectedMountStartupFailureRefV2<'owner> {
    /// The exclusive table or retained kernel observation failed.
    Kernel(&'owner aos_sandbox_linux::Error),
    /// The fixed native observer retains its actual protocol and transport cause.
    Observer(&'owner OwnUnitPid1ImageAttemptV1),
    /// Constructing the original observer runtime returned this error.
    Runtime(&'owner std::io::Error),
    /// Measuring an actual reply image failed.
    Measurement(&'owner aos_sandbox_linux::Error),
    /// The protected startup recipe or an owner association failed.
    Admission(&'owner MountManagerSourceInventoryError),
    /// The genuine capture append returned this native protected-store error.
    Journal(&'owner crate::JournalError),
    /// Cancellation or unwind ended the original before a cause was returned.
    Ended,
}

impl std::fmt::Debug for SelectedMountStartupFailureRefV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedMountStartupFailureRefV2([borrowed original cause])")
    }
}

#[derive(Clone, Copy)]
enum FailureStage {
    Kernel,
    Observer,
    Runtime,
    Measurement(usize),
    Admission,
    Commit(usize),
    Recovery(usize),
}

/// Retains the selected Mount's initial table, process and original image flight.
///
/// Construction is inert. This owner is not a startup authority until the sole
/// protected capture recipe admits its complete table. The original standard
/// descriptors remain resident at numbers zero, one and two. Returned errors
/// do not release the table, native image messages or measurement prefixes.
/// Allocation failure and unreturned lower syscall prefixes are not closed by
/// this owner; process death is not a terminal-drain proof.
pub struct SelectedMountStartupV2 {
    pub(super) table: PendingInitialProcessFdTableV2,
    runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    image_attempt: Option<OwnUnitPid1ImageAttemptV1>,
    original_image: Option<CompletedOwnUnitPid1ImageV1>,
    fresh_image: Option<CompletedOwnUnitPid1ImageV1>,
    measurements: [RetainedStartupImageMeasurementV2; 2],
    launcher: Option<StartupProcessObservationV1>,
    image_identity: Option<StartupExecutableObservationV1>,
    pub(super) control_policy:
        Option<aos_sandbox_protocol::mount_manager_startup::ManagerControlPolicyWitnessV1>,
    pub(super) descriptor_prefix: Vec<std::os::fd::OwnedFd>,
    pub(super) pending_descriptor: Option<std::os::fd::OwnedFd>,
    pub(super) staged: Option<StagedMountManagerStartupCaptureV1>,
    pub(super) commits: [Option<Result<
        crate::journal::MountManagerStartupCaptureReceiptV1,
        crate::JournalError,
    >>; 2],
    pub(super) recoveries: [Option<Result<
        crate::journal::MountManagerStartupCaptureRecoveryV1,
        MountManagerSourceInventoryError,
    >>; 2],
    pub(super) admission_error: Option<MountManagerSourceInventoryError>,
    first_stage: Option<FailureStage>,
    initial_attempted: bool,
    pub(super) admitted: bool,
    ended: bool,
}

impl std::fmt::Debug for SelectedMountStartupV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedMountStartupV2([resident initial originals])")
    }
}

pub(super) struct SelectedBoundary<'owner> {
    pub(super) owner: &'owner mut SelectedMountStartupV2,
    pub(super) completed: bool,
}

impl Drop for SelectedBoundary<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl Default for SelectedMountStartupV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectedMountStartupV2 {
    /// Creates an inert destination for the one selected initial capture.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: PendingInitialProcessFdTableV2::new(),
            runtime: None,
            image_attempt: None,
            original_image: None,
            fresh_image: None,
            measurements: std::array::from_fn(|_| RetainedStartupImageMeasurementV2::new()),
            launcher: None,
            image_identity: None,
            control_policy: None,
            descriptor_prefix: Vec::new(),
            pending_descriptor: None,
            staged: None,
            commits: [None, None],
            recoveries: [None, None],
            admission_error: None,
            first_stage: None,
            initial_attempted: false,
            admitted: false,
            ended: false,
        }
    }

    /// Captures the exclusive initial table before starting the fixed observer.
    ///
    /// # Safety
    ///
    /// This must be called at the single-threaded process entrypoint, before
    /// any Rust owner represents an inherited descriptor. It consumes the same
    /// process-wide one-shot claim as the ordinary Linux startup API.
    ///
    /// # Errors
    ///
    /// Permanently refuses a repeated capture, partial table, parent mismatch,
    /// native image failure or changed initial bookend. The cause stays owned.
    pub unsafe fn capture_initial_once(&mut self) -> Result<(), SelectedMountStartupEndedV2> {
        if self.initial_attempted || self.ended {
            self.end();
            return Err(SelectedMountStartupEndedV2);
        }
        self.initial_attempted = true;
        let mut boundary = SelectedBoundary {
            owner: self,
            completed: false,
        };

        // SAFETY: the caller supplies the same exclusive process-entry contract
        // as the sole Linux scanner. No runtime or observer exists yet.
        if unsafe { boundary.owner.table.capture_once() }.is_err() {
            boundary.owner.note_failure(FailureStage::Kernel);
            return Err(SelectedMountStartupEndedV2);
        }
        if !boundary.owner.observe_image(true) {
            return Err(SelectedMountStartupEndedV2);
        }
        if boundary.owner.table.finish_image_join_interval().is_err() {
            boundary.owner.note_failure(FailureStage::Kernel);
            return Err(SelectedMountStartupEndedV2);
        }
        boundary.completed = true;
        Ok(())
    }

    /// Rechecks the same kernel originals and a fresh fixed PID1 image flight.
    ///
    /// # Errors
    ///
    /// Refuses an ended or incomplete owner and permanently ends both original
    /// queues after any failed kernel, image or invocation bookend. It never
    /// reads the parent executable through procfs or renews the capture interval.
    pub fn recheck(&mut self) -> Result<(), SelectedMountStartupEndedV2> {
        if self.ended || !self.initial_attempted || self.original_image.is_none() {
            self.end();
            return Err(SelectedMountStartupEndedV2);
        }
        let mut boundary = SelectedBoundary {
            owner: self,
            completed: false,
        };
        if boundary.owner.table.recheck_kernel_and_table().is_err() {
            boundary.owner.note_failure(FailureStage::Kernel);
            return Err(SelectedMountStartupEndedV2);
        }
        if !boundary.owner.observe_image(false) {
            return Err(SelectedMountStartupEndedV2);
        }
        if boundary.owner.table.recheck_kernel_and_table().is_err() {
            boundary.owner.note_failure(FailureStage::Kernel);
            return Err(SelectedMountStartupEndedV2);
        }
        boundary.completed = true;
        Ok(())
    }

    fn observe_image(&mut self, initial: bool) -> bool {
        if self.ended || self.image_attempt.is_some() {
            return false;
        }
        if initial {
            if self.runtime.is_some() || self.original_image.is_some() || self.launcher.is_some() {
                self.refuse_association();
                return false;
            }
            self.runtime = Some(tokio::runtime::Builder::new_current_thread().enable_all().build());
        } else {
            // Only a previous successful bookend is superseded. Failed image
            // prefixes are never cleared or retried.
            self.fresh_image = None;
            self.measurements = std::array::from_fn(|_| RetainedStartupImageMeasurementV2::new());
        }
        let Some(Ok(runtime)) = self.runtime.as_ref() else {
            self.note_failure(FailureStage::Runtime);
            return false;
        };
        self.image_attempt = Some(OwnUnitPid1ImageAttemptV1::mount());
        let Some(attempt) = self.image_attempt.as_mut() else {
            self.refuse_association();
            return false;
        };
        if runtime.block_on(attempt.capture_once()).is_err() {
            self.note_failure(FailureStage::Observer);
            return false;
        }
        if (initial && self.original_image.is_some()) || (!initial && self.fresh_image.is_some()) {
            self.refuse_association();
            return false;
        }
        // into_completed observes nothing and allocates nothing. Either result
        // is immediately returned to a resident same-owner destination.
        match self.image_attempt.take() {
            Some(attempt) => match attempt.into_completed() {
                Ok(image) if initial => self.original_image = Some(image),
                Ok(image) => self.fresh_image = Some(image),
                Err(attempt) => {
                    self.image_attempt = Some(attempt);
                    self.note_failure(FailureStage::Observer);
                    return false;
                }
            },
            None => {
                self.refuse_association();
                return false;
            }
        }
        let image = if initial {
            self.original_image.as_ref()
        } else {
            self.fresh_image.as_ref()
        };
        let Some(image) = image else {
            self.refuse_association();
            return false;
        };
        let (Some(first), Some(second)) = (image.first_image(), image.second_image()) else {
            self.refuse_association();
            return false;
        };
        for (index, descriptor) in [first, second].into_iter().enumerate() {
            if self.measurements[index].measure_once(descriptor).is_err() {
                if self.first_stage.is_none() {
                    self.first_stage = Some(FailureStage::Measurement(index));
                }
                return false;
            }
        }
        let (Some(first), Some(second)) = (
            self.measurements[0].observation(), self.measurements[1].observation(),
        ) else {
            self.refuse_association();
            return false;
        };
        if first != second {
            self.refuse_association();
            return false;
        }
        if initial {
            let (Some(execution), Some(kernel)) = (self.table.execution(), self.table.launcher_kernel()) else {
                self.refuse_association();
                return false;
            };
            if kernel.process.pid() != 1 || execution.process.parent_pid() != 1
                || kernel.kernel_boot_id != execution.kernel_boot_id
            {
                self.refuse_association();
                return false;
            }
            self.launcher = Some(StartupProcessObservationV1 {
                kernel_boot_id: kernel.kernel_boot_id,
                process: kernel.process,
                credentials: kernel.credentials,
                cgroup_id: kernel.cgroup_id,
                cgroup_path: kernel.cgroup_path.clone(),
                unit: kernel.unit.clone(),
                executable: first,
            });
            self.image_identity = Some(first);
        } else if self.image_identity != Some(first)
            || self.original_image.as_ref().map(CompletedOwnUnitPid1ImageV1::invocation)
                != self.fresh_image.as_ref().map(CompletedOwnUnitPid1ImageV1::invocation)
        {
            self.refuse_association();
            return false;
        }
        true
    }

    pub(super) fn launcher(&self) -> Option<&StartupProcessObservationV1> {
        self.launcher.as_ref()
    }

    /// Bookends the genuine fixed held writer with fresh kernel and PID1 checks.
    ///
    /// This accepts a journal only for fixed-name physical validation against
    /// this owner's already admitted capture. It cannot create startup, Source
    /// or write authority from a journal supplied by a caller.
    ///
    /// # Errors
    ///
    /// Permanently refuses wrong names, changed history, stale process/image
    /// observations or an ended owner. The original first cause stays resident.
    pub fn recheck_held_capture(
        &mut self,
        journal: &mut crate::Journal,
    ) -> Result<(), SelectedMountStartupEndedV2> {
        let mut boundary = SelectedBoundary {
            owner: self,
            completed: false,
        };
        let result = boundary.owner.recheck_held_capture_inner(journal);
        boundary.completed = result.is_ok();
        result
    }

    fn recheck_held_capture_inner(
        &mut self,
        journal: &mut crate::Journal,
    ) -> Result<(), SelectedMountStartupEndedV2> {
        if !self.is_open() || !self.admitted {
            self.end();
            return Err(SelectedMountStartupEndedV2);
        }
        if let Err(error) = self.check_held_capture(journal) {
            self.record_admission_failure(error);
            return Err(SelectedMountStartupEndedV2);
        }
        self.recheck()?;
        if let Err(error) = self.check_held_capture(journal) {
            self.record_admission_failure(error);
            return Err(SelectedMountStartupEndedV2);
        }
        Ok(())
    }

    pub(super) fn check_held_capture(
        &self,
        journal: &mut crate::Journal,
    ) -> Result<(), MountManagerSourceInventoryError> {
        let witness = self.control_policy
            .as_ref()
            .ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
        super::owner::validate_selected_capture_journal(journal, witness)
    }

    pub(super) fn refuse_association(&mut self) {
        self.record_admission_failure(MountManagerSourceInventoryError::InvalidCapture);
    }

    pub(super) fn record_admission_failure(&mut self, error: MountManagerSourceInventoryError) {
        if self.first_stage.is_none() {
            self.admission_error = Some(error);
            self.note_failure(FailureStage::Admission);
        }
        self.end();
    }

    pub(super) fn record_commit_failure(&mut self, index: usize) {
        self.note_failure(FailureStage::Commit(index));
        self.end();
    }

    pub(super) fn record_recovery_failure(&mut self, index: usize) {
        self.note_failure(FailureStage::Recovery(index));
        self.end();
    }

    fn note_failure(&mut self, stage: FailureStage) {
        if self.first_stage.is_none() {
            self.first_stage = Some(stage);
        }
    }

    /// Borrows the resident first cause without observation, recovery or copying.
    #[must_use]
    pub fn failure(&self) -> Option<SelectedMountStartupFailureRefV2<'_>> {
        match self.first_stage {
            Some(FailureStage::Kernel) => self.table
                .failure()
                .map(SelectedMountStartupFailureRefV2::Kernel),
            Some(FailureStage::Observer) => self.image_attempt
                .as_ref()
                .map(SelectedMountStartupFailureRefV2::Observer),
            Some(FailureStage::Runtime) => self.runtime
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(SelectedMountStartupFailureRefV2::Runtime),
            Some(FailureStage::Measurement(index)) => self.measurements[index].failure()
                .map(SelectedMountStartupFailureRefV2::Measurement),
            Some(FailureStage::Admission) => self.admission_error
                .as_ref()
                .map(SelectedMountStartupFailureRefV2::Admission),
            Some(FailureStage::Commit(index)) => self.commits[index].as_ref()
                .and_then(|result| result.as_ref().err())
                .map(SelectedMountStartupFailureRefV2::Journal),
            Some(FailureStage::Recovery(index)) => self.recoveries[index].as_ref()
                .and_then(|result| result.as_ref().err())
                .map(SelectedMountStartupFailureRefV2::Admission),
            None if self.ended => Some(SelectedMountStartupFailureRefV2::Ended),
            None => None,
        }
    }

    /// Borrows the actual append outcomes, including resolved ambiguous errors.
    ///
    /// These historical native results authorize no retry, effect or drain.
    #[must_use]
    pub fn append_outcomes(&self) -> [Option<&Result<crate::journal::MountManagerStartupCaptureReceiptV1, crate::JournalError>>; 2] {
        [self.commits[0].as_ref(), self.commits[1].as_ref()]
    }

    /// Borrows separate recovery debt without replacing an earlier append cause.
    #[must_use]
    pub fn recovery_failures(&self) -> [Option<&MountManagerSourceInventoryError>; 2] {
        self.recoveries.each_ref().map(|slot| slot.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Borrows native shutdown debt from the original, fresh and pending flights.
    ///
    /// Each pair contains original-socket and rejected-socket outcomes, in that
    /// order. This performs no observation. Missing outcomes are unavailable,
    /// and successful shutdown proves neither peer acknowledgement nor Drain.
    #[must_use]
    pub fn image_shutdown_outcomes(&self) -> [(
        Option<&std::io::Result<()>>,
        Option<&std::io::Result<()>>,
    ); 3] {
        [
            self.original_image
                .as_ref()
                .map(CompletedOwnUnitPid1ImageV1::shutdown_outcomes)
                .unwrap_or((None, None)),
            self.fresh_image
                .as_ref()
                .map(CompletedOwnUnitPid1ImageV1::shutdown_outcomes)
                .unwrap_or((None, None)),
            self.image_attempt
                .as_ref()
                .map(OwnUnitPid1ImageAttemptV1::shutdown_outcomes)
                .unwrap_or((None, None)),
        ]
    }

    /// Permanently ends all retained image queues before their fields can drop.
    pub fn end(&mut self) {
        self.ended = true;
        if let Some(attempt) = self.image_attempt.as_ref() {
            attempt.end();
        }
        if let Some(image) = self.original_image.as_ref() {
            image.end();
        }
        if let Some(image) = self.fresh_image.as_ref() {
            image.end();
        }
    }

    pub(super) fn is_open(&self) -> bool {
        !self.ended && self.first_stage.is_none() && self.original_image.is_some()
    }
}

impl Drop for SelectedMountStartupV2 {
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests {
    use super::{SelectedMountStartupFailureRefV2, SelectedMountStartupV2};

    #[test]
    fn incomplete_owner_ends_without_starting_an_observer() {
        let mut owner = SelectedMountStartupV2::new();

        assert!(owner.recheck().is_err());
        assert!(owner.recheck().is_err());

        assert!(owner.runtime.is_none());
        assert!(owner.image_attempt.is_none());
        assert!(owner.original_image.is_none());
        assert!(matches!(owner.failure(), Some(SelectedMountStartupFailureRefV2::Ended)));
    }

    #[test]
    fn an_ended_empty_owner_cannot_observe_or_create_a_capture() {
        let mut owner = SelectedMountStartupV2::new();
        owner.end();

        assert!(owner.recheck().is_err());

        assert!(!owner.initial_attempted);
        assert!(owner.runtime.is_none());
        assert!(owner.control_policy.is_none());
        assert!(owner.staged.is_none());
    }
}
