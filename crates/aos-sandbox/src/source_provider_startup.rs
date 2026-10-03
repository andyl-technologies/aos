//! Owns the fixed Source process's original INITIAL table and image bookends.
//!
//! The one Linux scanner completes before runtime, credential or listener
//! effects. Actual PID1 image messages remain resident beside the independent
//! self/kernel owners. This mechanical join grants neither Source signing
//! authority nor a Mount startup row, current floor, settlement or Drain.

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::seqpacket::{
    ListenerAdmissionFailureRefV1, RecordSubjectListener,
    RecordSubjectListenerAdmissionAttemptV1,
};
use aos_sandbox_linux::startup_fd_table::{
    PendingInitialProcessFdTableV2, RetainedStartupImageMeasurementV2,
    StartupExecutableObservationV1,
};
use aos_systemd::{CompletedOwnUnitPid1ImageV1, OwnUnitPid1ImageAttemptV1};

const SOURCE_UNIT: &str = "aos-source-providerd.service";
const LISTENER_PATH: &str = "/run/aos/source-provider/control.sock";

/// Reports permanent refusal while the actual owning cause remains resident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStartupEndedV1;

impl std::fmt::Display for SourceStartupEndedV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original Source startup ended")
    }
}

impl std::error::Error for SourceStartupEndedV1 {}

/// Identifies an actual closed-purpose Source startup association refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStartupAdmissionErrorV1 {
    /// The complete original table or fixed activation hints did not match.
    Inventory,
    /// The actual self/direct-PID1 kernel identities did not match this purpose.
    Parent,
    /// Original image observations, invocation or resident slots disagreed.
    Association,
}

/// Borrows the actual first cause without copying an error or lending a FD.
pub enum SourceStartupFailureRefV1<'owner> {
    /// The same Linux table retains the native/kernel cause.
    Kernel(&'owner aos_sandbox_linux::Error),
    /// The fixed native image attempt retains its protocol and transport cause.
    Observer(&'owner OwnUnitPid1ImageAttemptV1),
    /// The actual runtime constructor returned this error.
    Runtime(&'owner std::io::Error),
    /// The original image measurement retains its native cause.
    Measurement(&'owner aos_sandbox_linux::Error),
    /// Safe duplication of original FD3 returned this native cause.
    Duplicate(&'owner rustix::io::Errno),
    /// The same listener admission attempt retains its typed cause.
    Listener(ListenerAdmissionFailureRefV1<'owner>),
    /// The actual closed-purpose association failed.
    Admission(&'owner SourceStartupAdmissionErrorV1),
    /// Cancellation or an incomplete/repeated step ended this original.
    Ended,
}

impl std::fmt::Debug for SourceStartupFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SourceStartupFailureRefV1([borrowed original cause])")
    }
}

#[derive(Clone, Copy)]
enum FailureStage {
    Kernel,
    Observer,
    Runtime,
    Measurement(usize),
    Duplicate,
    Listener,
    Admission,
}

/// Retains the fixed Source original table, listener and actual PID1 image flight.
///
/// Construction is inert. Original stdio remains at numbers 0/1/2; FD3 is the
/// sole permitted serving listener. The same table keeps an OFD anchor while
/// a single safe duplicate enters the existing listener admission engine.
/// Returned failures and native shutdown debt remain resident. Lower calls
/// that never return custody and allocation/funding failures remain excluded.
#[must_use = "retain the whole Source startup through failed invocation"]
pub struct OriginalSourceStartupV1 {
    table: PendingInitialProcessFdTableV2,
    runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    image_attempt: Option<OwnUnitPid1ImageAttemptV1>,
    original_image: Option<CompletedOwnUnitPid1ImageV1>,
    fresh_image: Option<CompletedOwnUnitPid1ImageV1>,
    measurements: [RetainedStartupImageMeasurementV2; 2],
    image_identity: Option<StartupExecutableObservationV1>,
    duplicate: Option<rustix::io::Result<OwnedFd>>,
    admission: Option<RecordSubjectListenerAdmissionAttemptV1>,
    listener: Option<RecordSubjectListener>,
    listener_shutdown: std::cell::OnceCell<rustix::io::Result<()>>,
    shutdown_attempted: std::cell::Cell<bool>,
    admission_error: Option<SourceStartupAdmissionErrorV1>,
    first_stage: Option<FailureStage>,
    attempted: bool,
    ended: std::cell::Cell<bool>,
}

impl std::fmt::Debug for OriginalSourceStartupV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OriginalSourceStartupV1([resident originals])")
    }
}

struct StartupBoundary<'owner> {
    owner: &'owner mut OriginalSourceStartupV1,
    completed: bool,
}

impl Drop for StartupBoundary<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl Default for OriginalSourceStartupV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl OriginalSourceStartupV1 {
    /// Creates empty resident destinations without observing or claiming a role.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: PendingInitialProcessFdTableV2::new(),
            runtime: None,
            image_attempt: None,
            original_image: None,
            fresh_image: None,
            measurements: std::array::from_fn(|_| RetainedStartupImageMeasurementV2::new()),
            image_identity: None,
            duplicate: None,
            admission: None,
            listener: None,
            listener_shutdown: std::cell::OnceCell::new(),
            shutdown_attempted: std::cell::Cell::new(false),
            admission_error: None,
            first_stage: None,
            attempted: false,
            ended: std::cell::Cell::new(false),
        }
    }

    /// Captures the sole initial table, then observes the fixed Source PID1 image.
    ///
    /// # Safety
    ///
    /// Requires exclusive single-threaded process entry ownership of inherited
    /// descriptors before any runtime, thread, protected file or activation
    /// adoption. It consumes the same process-wide Linux one-shot capture.
    ///
    /// # Errors
    ///
    /// Refuses partial/extra inventory, wrong parent or fixed unit, image drift,
    /// a repeated attempt or native failure; actual prefixes remain in this owner.
    pub unsafe fn capture_initial_once(&mut self) -> Result<(), SourceStartupEndedV1> {
        if self.attempted || self.ended.get() {
            self.end();
            return Err(SourceStartupEndedV1);
        }
        self.attempted = true;
        let mut boundary = StartupBoundary {
            owner: self,
            completed: false,
        };

        // SAFETY: forwarding the caller's exclusive original-entry contract to
        // the sole shared scanner, before constructing a runtime or observer.
        if unsafe { boundary.owner.table.capture_once() }.is_err() {
            boundary.owner.note(FailureStage::Kernel);
            return Err(SourceStartupEndedV1);
        }
        if !boundary.owner.require_source_inventory() || !boundary.owner.observe_image(true) {
            return Err(SourceStartupEndedV1);
        }
        if boundary.owner.table.finish_image_join_interval().is_err() {
            boundary.owner.note(FailureStage::Kernel);
            return Err(SourceStartupEndedV1);
        }
        boundary.completed = true;
        Ok(())
    }

    fn require_source_inventory(&mut self) -> bool {
        let (Some(descriptors), Some(execution), Some(parent), Some(hints)) = (
            self.table.descriptors(),
            self.table.execution(),
            self.table.launcher_kernel(),
            self.table.activation_hints(),
        ) else {
            return self.refuse(SourceStartupAdmissionErrorV1::Inventory);
        };
        if descriptors.len() != 4
            || descriptors.iter().enumerate()
                .any(|(number, descriptor)| descriptor.original_number() != number as u32)
            || descriptors.get(3).is_none_or(|descriptor| {
                descriptor.observation().status_flags & rustix::fs::OFlags::NONBLOCK.bits() == 0
            })
            || hints.listen_pid.as_deref() != Some(std::process::id().to_string().as_bytes())
            || hints.listen_fds.as_deref() != Some(b"1")
            || hints.listen_fdnames.as_deref() != Some(b"aos-source-provider")
        {
            return self.refuse(SourceStartupAdmissionErrorV1::Inventory);
        }
        if execution.process.pid() != std::process::id()
            || execution.process.parent_pid() != 1
            || parent.process.pid() != 1
            || execution.kernel_boot_id != parent.kernel_boot_id
            || execution.unit != SOURCE_UNIT
            || parent.unit != "init.scope"
            || !root_credentials(execution.credentials)
            || !root_credentials(parent.credentials)
        {
            return self.refuse(SourceStartupAdmissionErrorV1::Parent);
        }
        true
    }

    /// Admits one safe duplicate of the actual captured listener in place.
    ///
    /// # Errors
    ///
    /// Refuses incomplete startup, duplicate/admission failure or any changed
    /// final bookend. No listener escapes a failed attempt.
    pub fn admit_listener_once(&mut self) -> Result<(), SourceStartupEndedV1> {
        if self.ended.get()
            || self.original_image.is_none()
            || self.duplicate.is_some()
            || self.admission.is_some()
            || self.listener.is_some()
        {
            self.end();
            return Err(SourceStartupEndedV1);
        }
        let mut boundary = StartupBoundary {
            owner: self,
            completed: false,
        };
        let Some(original) = boundary.owner.table.descriptors()
            .and_then(|descriptors| descriptors.get(3))
        else {
            boundary.owner.refuse(SourceStartupAdmissionErrorV1::Inventory);
            return Err(SourceStartupEndedV1);
        };
        boundary.owner.duplicate = Some(rustix::io::fcntl_dupfd_cloexec(AsFd::as_fd(original), 0));
        if !matches!(boundary.owner.duplicate.as_ref(), Some(Ok(_))) {
            boundary.owner.note(FailureStage::Duplicate);
            return Err(SourceStartupEndedV1);
        }
        // All destination checks precede this closed, nonobserving ownership move.
        match boundary.owner.duplicate.take() {
            Some(Ok(original)) => {
                boundary.owner.admission = Some(
                    RecordSubjectListenerAdmissionAttemptV1::new(original),
                );
            }
            other => {
                boundary.owner.duplicate = other;
                boundary.owner.refuse(SourceStartupAdmissionErrorV1::Association);
                return Err(SourceStartupEndedV1);
            }
        }
        let Some(admission) = boundary.owner.admission.as_mut() else {
            boundary.owner.refuse(SourceStartupAdmissionErrorV1::Association);
            return Err(SourceStartupEndedV1);
        };
        if admission.admit_once(Path::new(LISTENER_PATH)).is_err() {
            boundary.owner.note(FailureStage::Listener);
            return Err(SourceStartupEndedV1);
        }
        // The sole lower move cannot allocate or observe. Park before recheck.
        boundary.owner.listener = admission.take_completed_listener();
        if boundary.owner.listener.is_none() {
            boundary.owner.refuse(SourceStartupAdmissionErrorV1::Association);
            return Err(SourceStartupEndedV1);
        }
        boundary.owner.recheck()?;
        boundary.completed = true;
        Ok(())
    }

    /// Rechecks original kernel/table owners and a fresh fixed Source PID1 image.
    ///
    /// # Errors
    ///
    /// Permanently refuses incomplete/ended state or failed kernel/image/unit
    /// bookends. No parent proc-exe read, replacement expected image or retry occurs.
    pub fn recheck(&mut self) -> Result<(), SourceStartupEndedV1> {
        if self.ended.get() || !self.attempted || self.original_image.is_none() {
            self.end();
            return Err(SourceStartupEndedV1);
        }
        let mut boundary = StartupBoundary {
            owner: self,
            completed: false,
        };
        if boundary.owner.table.recheck_kernel_and_table().is_err() {
            boundary.owner.note(FailureStage::Kernel);
            return Err(SourceStartupEndedV1);
        }
        if !boundary.owner.observe_image(false) {
            return Err(SourceStartupEndedV1);
        }
        if boundary.owner.table.recheck_kernel_and_table().is_err() {
            boundary.owner.note(FailureStage::Kernel);
            return Err(SourceStartupEndedV1);
        }
        boundary.completed = true;
        Ok(())
    }

    fn observe_image(&mut self, initial: bool) -> bool {
        if self.ended.get() || self.image_attempt.is_some() {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        }
        if initial {
            if self.runtime.is_some() || self.original_image.is_some() {
                return self.refuse(SourceStartupAdmissionErrorV1::Association);
            }
            self.runtime = Some(tokio::runtime::Builder::new_current_thread().enable_all().build());
        } else {
            // Only successful comparison prefixes may be superseded. A failed
            // prefix ends the whole original and is never cleared or retried.
            self.fresh_image = None;
            self.measurements = std::array::from_fn(|_| RetainedStartupImageMeasurementV2::new());
        }
        let Some(Ok(runtime)) = self.runtime.as_ref() else {
            self.note(FailureStage::Runtime);
            return false;
        };
        self.image_attempt = Some(OwnUnitPid1ImageAttemptV1::source());
        let Some(attempt) = self.image_attempt.as_mut() else {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        };
        if runtime.block_on(attempt.capture_once()).is_err() {
            self.note(FailureStage::Observer);
            return false;
        }
        if (initial && self.original_image.is_some()) || (!initial && self.fresh_image.is_some()) {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        }
        match self.image_attempt.take() {
            Some(attempt) => match attempt.into_completed() {
                Ok(image) if initial => self.original_image = Some(image),
                Ok(image) => self.fresh_image = Some(image),
                Err(attempt) => {
                    self.image_attempt = Some(attempt);
                    self.note(FailureStage::Observer);
                    return false;
                }
            },
            None => return self.refuse(SourceStartupAdmissionErrorV1::Association),
        }
        let image = if initial {
            self.original_image.as_ref()
        } else {
            self.fresh_image.as_ref()
        };
        let Some(image) = image else {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        };
        let (Some(first), Some(second)) = (image.first_image(), image.second_image()) else {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        };
        for (index, descriptor) in [first, second].into_iter().enumerate() {
            if self.measurements[index].measure_once(descriptor).is_err() {
                self.note(FailureStage::Measurement(index));
                return false;
            }
        }
        let (Some(first), Some(second)) = (
            self.measurements[0].observation(),
            self.measurements[1].observation(),
        ) else {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        };
        if first != second
            || (!initial && (self.image_identity != Some(first)
                || self.original_image.as_ref().map(CompletedOwnUnitPid1ImageV1::invocation)
                    != self.fresh_image.as_ref().map(CompletedOwnUnitPid1ImageV1::invocation)))
        {
            return self.refuse(SourceStartupAdmissionErrorV1::Association);
        }
        if initial {
            self.image_identity = Some(first);
        }
        true
    }

    /// Lends only the genuine completed listener while the original remains open.
    ///
    /// # Errors
    ///
    /// Refuses an ended, incomplete or failed startup without any observation.
    pub fn listener_mut(&mut self) -> Result<&mut RecordSubjectListener, SourceStartupEndedV1> {
        if self.ended.get() || self.first_stage.is_some() || self.listener.is_none() {
            self.end();
            return Err(SourceStartupEndedV1);
        }
        self.listener.as_mut().ok_or(SourceStartupEndedV1)
    }

    /// Borrows the actual first cause without rechecking, resetting or extracting custody.
    #[must_use]
    pub fn failure(&self) -> Option<SourceStartupFailureRefV1<'_>> {
        match self.first_stage {
            Some(FailureStage::Kernel) => self.table.failure().map(SourceStartupFailureRefV1::Kernel),
            Some(FailureStage::Observer) => self.image_attempt.as_ref().map(SourceStartupFailureRefV1::Observer),
            Some(FailureStage::Runtime) => self.runtime.as_ref()
                .and_then(|result| result.as_ref().err()).map(SourceStartupFailureRefV1::Runtime),
            Some(FailureStage::Measurement(index)) => self.measurements[index].failure()
                .map(SourceStartupFailureRefV1::Measurement),
            Some(FailureStage::Duplicate) => self.duplicate.as_ref()
                .and_then(|result| result.as_ref().err()).map(SourceStartupFailureRefV1::Duplicate),
            Some(FailureStage::Listener) => self.admission.as_ref()
                .and_then(RecordSubjectListenerAdmissionAttemptV1::first_failure)
                .map(SourceStartupFailureRefV1::Listener),
            Some(FailureStage::Admission) => self.admission_error.as_ref().map(SourceStartupFailureRefV1::Admission),
            None if self.ended.get() => Some(SourceStartupFailureRefV1::Ended),
            None => None,
        }
    }

    fn note(&mut self, stage: FailureStage) {
        if self.first_stage.is_none() {
            self.first_stage = Some(stage);
        }
    }

    fn refuse(&mut self, cause: SourceStartupAdmissionErrorV1) -> bool {
        if self.admission_error.is_none() {
            self.admission_error = Some(cause);
        }
        self.note(FailureStage::Admission);
        false
    }

    /// Permanently ends the listener OFD and image queues before any field drops.
    pub fn end(&self) {
        self.ended.set(true);
        if !self.shutdown_attempted.replace(true) {
            if let Some(original) = self.table.descriptors().and_then(|table| table.get(3)) {
                let outcome = rustix::net::shutdown(AsFd::as_fd(original), rustix::net::Shutdown::Both);
                let _stored = self.listener_shutdown.set(outcome);
            }
        }
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

    /// Borrows the actual one-shot listener shutdown outcome, not a Drain proof.
    #[must_use]
    pub fn listener_shutdown_outcome(&self) -> Option<&rustix::io::Result<()>> {
        self.listener_shutdown.get()
    }

    /// Borrows original/fresh/pending image shutdown results without observation.
    #[must_use]
    pub fn image_shutdown_outcomes(&self) -> [(Option<&std::io::Result<()>>, Option<&std::io::Result<()>>); 3] {
        [
            self.original_image.as_ref().map(CompletedOwnUnitPid1ImageV1::shutdown_outcomes).unwrap_or((None, None)),
            self.fresh_image.as_ref().map(CompletedOwnUnitPid1ImageV1::shutdown_outcomes).unwrap_or((None, None)),
            self.image_attempt.as_ref().map(OwnUnitPid1ImageAttemptV1::shutdown_outcomes).unwrap_or((None, None)),
        ]
    }
}

impl Drop for OriginalSourceStartupV1 {
    fn drop(&mut self) {
        self.end();
    }
}

fn root_credentials(credentials: aos_sandbox_linux::pidfd::PidFdCredentials) -> bool {
    credentials.real_user_id() == 0
        && credentials.effective_user_id() == 0
        && credentials.saved_user_id() == 0
        && credentials.filesystem_user_id() == 0
        && credentials.real_group_id() == 0
        && credentials.effective_group_id() == 0
        && credentials.saved_group_id() == 0
        && credentials.filesystem_group_id() == 0
}

#[cfg(test)]
mod tests {
    use super::{OriginalSourceStartupV1, SourceStartupFailureRefV1};

    #[test]
    fn inert_owner_cannot_lend_a_listener_or_revive_after_end() {
        let mut owner = OriginalSourceStartupV1::new();

        assert!(owner.listener_mut().is_err());
        assert!(owner.recheck().is_err());
        assert!(matches!(owner.failure(), Some(SourceStartupFailureRefV1::Ended)));
        assert!(owner.listener_shutdown_outcome().is_none());
    }

    #[test]
    fn shared_negative_end_does_not_fabricate_a_native_shutdown() {
        let owner = OriginalSourceStartupV1::new();

        owner.end();
        owner.end();

        assert!(matches!(owner.failure(), Some(SourceStartupFailureRefV1::Ended)));
        assert!(owner.listener_shutdown_outcome().is_none());
    }
}
