//! Owned pidfds and namespace descriptors.
//!
//! Namespace descriptors are acquired from a pinned pidfd with Linux 6.18's
//! pidfs ioctls. The wrapper records the namespace `(device, inode)` identity
//! at acquisition so callers can detect replacement across observations.
//!
//! Current-self custody retains a fresh pidfd and bounded original stat bytes
//! through failed or interrupted observations. That reservoir is DATA, not a
//! role, currentness, launch or drain authority.

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::rc::Rc;

use crate::uapi::{self, NamespaceIoctl};
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;
use aos_linux_descriptors::pidfd::{PidFd, PidFdInfo, PidFdCredentials, PidFdOwnedAdmissionFailureV3, PidFdAdmissionSlotV1};

mod identity;
mod proc_observations;

pub use identity::{PidFdProcessIdentity, PidFdProcessIdentityOriginalV1, process_identity};
pub use proc_observations::{
    prepare_proc_observations_v1,
    HostCanaryLocalChildOriginalsV1, HostCanaryReceivedChildErrorV1,
    HostCanaryReceivedChildOriginalsV1, PidFdContextReadbackV1, PidFdIdentityReadbackV1,
    PidFdNegativeContextOriginalV1,
    PidFdNegativeIdentityOriginalV1,
    PidFdProcObservationsV1, PidFdProcOriginalsV1,
};

mod current_network;
pub use current_network::CurrentNetworkNamespaceOriginalV4;
mod single_thread_original;
pub use single_thread_original::SingleThreadedProcessOriginalV2;




#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentSelfPhaseV1 {
    Fresh,
    Ready,
    Closed,
}

/// Retains the calling process's original pidfd and bounded stat observations.
///
/// The move-only owner selects only the current process. It parks each actual
/// descriptor before fallible validation, retains failed partial observations
/// until drop, and permanently fences interrupted operations. Returned identity
/// bytes are DATA: an independent purpose owner must compare its original role,
/// credentials and membership. This type grants no launch or process authority.
pub struct CurrentSelfPidFdCustodyV1 {
    raw: Option<PidFdAdmissionSlotV1>,
    process: Option<PidFd>,
    observations: Option<PidFdProcObservationsV1>,
    phase: CurrentSelfPhaseV1,
}

impl CurrentSelfPidFdCustodyV1 {
    /// Creates empty move-only slots without allocation or process observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            raw: None,
            process: None,
            observations: None,
            phase: CurrentSelfPhaseV1::Fresh,
        }
    }

    /// Captures the current process once while retaining every acquired original.
    ///
    /// # Errors
    ///
    /// Returns the actual syscall, descriptor-validation or bounded stat error.
    /// Repeated or interrupted capture is refused. Error and unwind leave this
    /// instance fenced; its descriptors and partial bytes remain owned.
    pub fn capture_current(&mut self) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(CurrentSelfPhaseV1::Fresh)?;
        let result = operation.custody.capture_current_inner();
        operation.finish(result)
    }

    fn capture_current_inner(&mut self) -> Result<PidFdProcessIdentity> {
        self.raw = Some(PidFdAdmissionSlotV1::new(aos_linux_descriptors::native::pidfd_open_current_original()?));

        // Preserve the original fd_result pass, then the sole typed validator's
        // second CLOEXEC pass. Both now borrow the already-resident fresh pin.
        let raw = self.raw.as_ref().ok_or_else(current_self_closed)?;
        aos_linux_descriptors::native::ensure_cloexec(raw.as_fd())?;
        self.raw.as_mut().ok_or_else(current_self_closed)?.validate_once()?;

        // Removal is followed only by an infallible same-owner typed transfer.
        match self.raw.take() {
            Some(fd) => self.process = Some(match fd.into_validated() { Ok(pin) => pin, Err(_still_owned) => std::process::abort() }),
            None => return Err(current_self_closed()),
        }

        let process = self.process.as_ref().ok_or_else(current_self_closed)?;
        self.observations = Some(crate::pidfd::prepare_proc_observations_v1(process));
        self.observations
            .as_mut()
            .ok_or_else(current_self_closed)?
            .capture_stat(process)
    }

    /// Rereads identity using the same original pidfd and stat descriptor.
    ///
    /// Original identity equality remains the purpose owner's comparison. This
    /// route needs no context capture and never reopens a procfs pathname.
    ///
    /// # Errors
    ///
    /// Refuses incomplete or fenced custody, or returns the actual bounded-read,
    /// pidfd-consistency or liveness error. Err and unwind fence this instance.
    pub fn observe_identity(&mut self) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(CurrentSelfPhaseV1::Ready)?;
        let result = operation.custody.observe_identity_inner();
        operation.finish(result)
    }

    fn observe_identity_inner(&mut self) -> Result<PidFdProcessIdentity> {
        let process = self.process.as_ref().ok_or_else(current_self_closed)?;
        self.observations
            .as_mut()
            .ok_or_else(current_self_closed)?
            .observe_stat_identity(process)
    }

    /// Prearms one negative comparison from this same healthy original stat OFD.
    ///
    /// The caller retains and prepays the destination before its primary
    /// observation. Preparation duplicates only the already-held stat File;
    /// it does not open a name, replace the pidfd or create a healthy grant.
    /// [`PidFdNegativeIdentityOriginalV1::receiving_demand_v1`] supplies the
    /// actual byte and one-descriptor requirement. Its diagnostic control
    /// census does not represent resident namespace metadata entries.
    ///
    /// # Errors
    /// Refuses incomplete or closed current-self custody, unavailable original
    /// stat custody, repeated destination preparation or native duplication.
    /// The caller keeps the same destination and its original native cause.
    pub fn prepare_negative_identity_once_into_v1(
        &self,
        original: &mut PidFdNegativeIdentityOriginalV1,
    ) -> Result<()> {
        if self.phase != CurrentSelfPhaseV1::Ready {
            return Err(current_self_closed());
        }
        self.observations.as_ref().ok_or_else(current_self_closed)?
            .prepare_negative_identity_once_into(original)
    }

    /// Observes a prearmed negative comparison on this same retained pidfd.
    ///
    /// This route may inspect the actual held pin after healthy custody was
    /// fenced. Only the destination's original once-preparation permits its
    /// native read. It never restores either healthy phase, exposes a pin or
    /// returns role, currentness, receiving or retry authority. The caller
    /// retains all native originals through its independently owed interval.
    ///
    /// # Errors
    /// Refuses an absent original pidfd, unprepared or reused destination,
    /// native failure, changed original identity or process exit. A successful
    /// comparison leaves closed healthy custody closed.
    pub fn observe_negative_identity_once_v1(
        &self,
        original: &mut PidFdNegativeIdentityOriginalV1,
    ) -> Result<()> {
        original.observe_once(self.process.as_ref().ok_or_else(current_self_closed)?)
    }

    /// Borrows the actual original pidfd only after completed capture.
    ///
    /// The short borrow is a process pin, not a purpose approval or a freshness
    /// claim after the last observation.
    ///
    /// # Errors
    ///
    /// Refuses empty, interrupted or permanently fenced custody.
    pub fn pidfd(&self) -> Result<&PidFd> {
        if self.phase != CurrentSelfPhaseV1::Ready {
            return Err(current_self_closed());
        }
        self.process.as_ref().ok_or_else(current_self_closed)
    }

    pub(crate) fn completed_stat_native_file_count_v1(&self) -> Option<usize> {
        if self.phase != CurrentSelfPhaseV1::Ready || self.raw.is_some()
            || self.process.is_none()
        { return None; }
        1usize.checked_add(self.observations.as_ref()?.completed_stat_native_file_count_v1()?)
    }

    /// Permanently closes this instance without releasing retained originals.
    ///
    /// The purpose owner calls this on an outer failure. It creates no terminal
    /// outcome, drain proof or resident copy of a previously returned cause.
    pub fn fence(&mut self) {
        self.phase = CurrentSelfPhaseV1::Closed;
        if let Some(observations) = &mut self.observations {
            observations.fence();
        }
    }

    fn begin(&mut self, expected: CurrentSelfPhaseV1) -> Result<CurrentSelfOperationV1<'_>> {
        if self.phase != expected {
            self.fence();
            return Err(current_self_closed());
        }

        // Arm before syscall, validation or reread. A dropped/forgotten borrow
        // cannot restore usable custody after a caught unwind.
        self.phase = CurrentSelfPhaseV1::Closed;
        Ok(CurrentSelfOperationV1 { custody: self })
    }
}

struct CurrentSelfOperationV1<'observation> {
    custody: &'observation mut CurrentSelfPidFdCustodyV1,
}

impl CurrentSelfOperationV1<'_> {
    fn finish<T>(self, result: Result<T>) -> Result<T> {
        if result.is_ok() {
            self.custody.phase = CurrentSelfPhaseV1::Ready;
        } else {
            self.custody.fence();
        }
        result
    }
}

fn current_self_closed() -> Error {
    Error::invalid(
        "current-self custody",
        "original observation is permanently closed",
    )
}

/// Retains one received pidfd through the existing typed descriptor admission.
///
/// This is kernel DATA custody, not Host identity, scope or role authority.
/// No descriptor is duplicated or reopened and no process is nominated by PID.
#[derive(Debug, Default)]
pub struct RuntimeScopeReceivedPidFdOriginalV1 {
    raw: Option<PidFdAdmissionSlotV1>,
    validation: Option<Result<()>>,
    pin: Option<PidFd>,
    attempted: bool,
}

impl RuntimeScopeReceivedPidFdOriginalV1 {
    /// Creates empty received-pin custody without native IO.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Validates the same received descriptor before its once-only typed move.
    ///
    /// # Errors
    /// Retains actual CLOEXEC/pidfs/GET_INFO failure; refuses reentry.
    pub fn capture_once(&mut self, fd: OwnedFd) -> Result<()> {
        if self.attempted { return Err(current_self_closed()); }
        self.attempted = true;
        self.raw = Some(PidFdAdmissionSlotV1::new(fd));
        self.validation = Some(match self.raw.as_mut() {
            Some(raw) => raw.validate_once(),
            None => Err(current_self_closed()),
        });
        if !matches!(self.validation, Some(Ok(()))) { return Err(current_self_closed()); }
        let Some(fd) = self.raw.take() else { std::process::abort(); };
        self.pin = Some(match fd.into_validated() { Ok(pin) => pin, Err(_still_owned) => std::process::abort() });
        Ok(())
    }

    /// Moves only the same fully validated received pin once.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<PidFd> {
        if !matches!(self.validation, Some(Ok(()))) { return None; }
        self.pin.take()
    }

    /// Borrows the original actual admission error.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.validation.as_ref()?.as_ref().err()
    }

    /// Returns fixed byte and one-descriptor representation DATA.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(2048)?, 1))
    }
}

/// Reports that an original pidfd opening remains incomplete or fenced.
///
/// The actual native first cause remains in [`PidFdOpenAttemptV1`]. This marker
/// supplies no process identity, authority or permission to reopen a pidfd.
#[derive(Debug, thiserror::Error)]
#[error("original pidfd opening is incomplete or fenced")]
pub struct PidFdOpenRefusalV1;







/// Retains one original kernel pidfd through validation and once-only transfer.
///
/// This is passive kernel custody. The caller independently authenticates the
/// actual PID selector and checks membership, credentials and current liveness.
/// It must fund this reservoir before acquisition and retain it on failure.
pub struct PidFdOpenAttemptV1 {
    open: Option<Result<PidFdAdmissionSlotV1>>,
    flags: Option<Result<()>>,
    validation: Option<Result<()>>,
    process: Option<PidFd>,
    closed: Option<Error>,
    entered: bool,
    complete: bool,
}

impl PidFdOpenAttemptV1 {
    /// Creates empty storage without opening or duplicating a descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            open: None, flags: None, validation: None, process: None, closed: None,
            entered: false, complete: false,
        }
    }

    /// Opens once and runs the sole ordinary pidfd-kind validator by borrow.
    ///
    /// The returned raw FD is parked before CLOEXEC/type validation. Native
    /// failure keeps that same raw descriptor and whole Result resident.
    ///
    /// # Errors
    /// Returns a negative marker while [`Self::failure`] borrows the actual
    /// open/validation cause. Reentry fences even an earlier completed opening.
    pub fn capture_once(&mut self, pid: NonZeroU32) -> std::result::Result<(), PidFdOpenRefusalV1> {
        if self.entered {
            self.complete = false;
            self.closed.get_or_insert_with(|| Error::invalid("original pidfd opening", "already entered"));
            return Err(PidFdOpenRefusalV1);
        }
        self.entered = true;
        self.open = Some(aos_linux_descriptors::native::pidfd_open_original(pid.get()).map(PidFdAdmissionSlotV1::new));
        let Some(Ok(raw)) = self.open.as_ref() else {
            return Err(PidFdOpenRefusalV1);
        };
        self.flags = Some(aos_linux_descriptors::native::ensure_cloexec(raw.as_fd()));
        if !matches!(self.flags, Some(Ok(()))) {
            return Err(PidFdOpenRefusalV1);
        }
        self.validation = Some(match self.open.as_mut() {
            Some(Ok(raw)) => raw.validate_once(),
            _ => std::process::abort(),
        });
        if !matches!(self.validation, Some(Ok(()))) {
            return Err(PidFdOpenRefusalV1);
        }
        // Validation borrows the original. Only this infallible owning move
        // follows; no new syscall or duplicate can lose the validated prefix.
        match self.open.take() {
            Some(Ok(fd)) => self.process = Some(match fd.into_validated() { Ok(pin) => pin, Err(_still_owned) => std::process::abort() }),
            _ => std::process::abort(),
        }
        self.complete = true;
        Ok(())
    }

    /// Moves the same fully validated pidfd once, without reopening or IO.
    #[must_use]
    pub fn take_validated(&mut self) -> Option<PidFd> {
        if !self.complete {
            return None;
        }
        self.complete = false;
        self.process.take()
    }

    /// Borrows the earliest original native or permanent-entry error.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.open.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.flags.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.validation.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.closed.as_ref())
    }
}

impl Default for PidFdOpenAttemptV1 {
    fn default() -> Self {
        Self::new()
    }
}



fn namespace_request_v2(kind: NamespaceKind) -> NamespaceIoctl {
    match kind {
        NamespaceKind::Mount => NamespaceIoctl::Mount,
        NamespaceKind::Network => NamespaceIoctl::Network,
        NamespaceKind::Pid => NamespaceIoctl::Pid,
        NamespaceKind::User => NamespaceIoctl::User,
        NamespaceKind::Uts => NamespaceIoctl::Uts,
    }
}

mod namespace_original;
pub use namespace_original::PidFdNamespaceOriginalV2;


/// Namespace kinds exposed by the sandbox Linux boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NamespaceKind {
    /// Mount namespace.
    Mount,
    /// Network namespace.
    Network,
    /// PID namespace used by the process.
    Pid,
    /// User namespace.
    User,
    /// UTS namespace.
    Uts,
}

impl NamespaceKind {
    fn clone_flag(self) -> i32 {
        match self {
            Self::Mount => libc::CLONE_NEWNS,
            Self::Network => libc::CLONE_NEWNET,
            Self::Pid => libc::CLONE_NEWPID,
            Self::User => libc::CLONE_NEWUSER,
            Self::Uts => libc::CLONE_NEWUTS,
        }
    }
}

/// Stable identity of an `nsfs` namespace object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NamespaceIdentity {
    /// Device containing the `nsfs` inode.
    pub device: u64,
    /// Namespace inode number.
    pub inode: u64,
}

/// An owned, type-checked namespace descriptor.
#[derive(Debug)]
pub struct NamespaceFd {
    fd: OwnedFd,
    kind: NamespaceKind,
    identity: NamespaceIdentity,
}

/// Retains a rejected namespace descriptor and its original native error.
///
/// This mechanical failure owns only the descriptor supplied to the existing
/// adoption boundary. It supplies no admitted namespace, resource allowance or
/// permission to retry acquisition.
#[derive(Debug)]
pub struct NamespaceAdoptionFailureV2 {
    fd: OwnedFd,
    cause: Error,
}

impl NamespaceAdoptionFailureV2 {
    /// Borrows the actual validation error while keeping its descriptor owned.
    #[must_use]
    pub const fn cause(&self) -> &Error { &self.cause }

    /// Borrows the same rejected descriptor without extracting or duplicating it.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> { self.fd.as_fd() }

    /// Transfers the same rejected descriptor and its actual cause together.
    ///
    /// This mechanical custody move grants no namespace or permission to retry
    /// adoption. Retained owners keep both parts through their owed posts.
    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, Error) { (self.fd, self.cause) }
}

impl NamespaceFd {
    /// Opens and type-checks the calling process's current Network namespace.
    ///
    /// The fixed `/proc/self/ns/net` source carries no caller-selected name or
    /// PID. Callers retain the returned descriptor before any namespace entry
    /// and use its captured device/inode identity for later revalidation.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed procfs namespace entry cannot be opened or
    /// is not an `nsfs` Network namespace descriptor.
    pub fn current_network() -> Result<Self> {
        current_network::capture_local()
    }

    /// Checks whether this descriptor is the calling process's current namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if this is not a Network namespace or if the fixed
    /// current-namespace descriptor cannot be opened and inspected.
    pub fn validate_current_network(&self) -> Result<()> {
        current_network::compare_local(self)
    }

    /// Validates and adopts an owned `nsfs` descriptor with its expected kind.
    ///
    /// The constructor verifies both the `nsfs` filesystem type and the exact
    /// namespace kind with `NS_GET_NSTYPE`.
    ///
    /// # Errors
    ///
    /// Returns an error if `fd` is not an `nsfs` descriptor, has a different
    /// namespace kind, or cannot be inspected.
    pub fn from_owned(fd: OwnedFd, kind: NamespaceKind) -> Result<Self> {
        Self::from_owned_retaining_v2(fd, kind).map_err(|failure| failure.cause)
    }

    /// Retains the original descriptor if namespace validation fails.
    ///
    /// This uses the same close-on-exec, nsfs, namespace-kind and identity
    /// checks as [`Self::from_owned`]. The failure owns the supplied descriptor
    /// before any check; neither outcome establishes role or launch authority.
    ///
    /// # Errors
    /// Returns the descriptor and its actual validation error without reopening
    /// or replacing a failed original.
    pub fn from_owned_retaining_v2(
        fd: OwnedFd,
        kind: NamespaceKind,
    ) -> std::result::Result<Self, NamespaceAdoptionFailureV2> {
        match Self::validate_original_kind(fd.as_fd(), kind) {
            Ok(identity) => Ok(Self { fd, kind, identity }),
            Err(cause) => Err(NamespaceAdoptionFailureV2 { fd, cause }),
        }
    }

    // Selected received records keep their raw descriptors resident until all
    // roles pass this same strict checker. No raw descriptor factory escapes.
    pub(crate) fn validate_original_kind(
        fd: BorrowedFd<'_>,
        kind: NamespaceKind,
    ) -> Result<NamespaceIdentity> {
        aos_linux_descriptors::native::ensure_cloexec(fd)?;
        if !uapi::is_namespace(fd)? {
            return Err(Error::WrongDescriptorType {
                expected: "nsfs namespace",
            });
        }
        if uapi::namespace_type(fd)? != kind.clone_flag() {
            return Err(Error::WrongDescriptorType {
                expected: "requested namespace kind",
            });
        }
        let stat = uapi::fstat(fd)?;
        Ok(NamespaceIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    /// Borrows the namespace descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Returns the kernel-verified namespace kind.
    #[must_use]
    pub const fn kind(&self) -> NamespaceKind {
        self.kind
    }

    /// Returns the namespace device/inode identity captured at construction.
    #[must_use]
    pub const fn identity(&self) -> NamespaceIdentity {
        self.identity
    }

    /// Enters this namespace from a verified single-threaded worker process.
    ///
    /// The caller must not create another thread after obtaining `worker`.
    /// The token is deliberately neither `Send` nor `Sync`, which prevents
    /// moving the operation onto a runtime worker thread. Sandbox mount helpers
    /// call this only in their short-lived process before starting any runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace cannot be entered, access is denied,
    /// or the descriptor became invalid.
    pub fn enter(&self, _worker: &SingleThreadedProcess) -> Result<()> {
        uapi::setns(self.fd.as_fd(), self.kind.clone_flag())
    }
}

/// Runtime proof that the current helper process has exactly one thread.
///
/// This token is a semantic guard for process-global namespace transitions; it
/// is not a general synchronization primitive. It is intentionally `!Send` and
/// `!Sync` so namespace entry cannot migrate across executor threads.
#[derive(Debug)]
pub struct SingleThreadedProcess {
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl SingleThreadedProcess {
    /// Verifies `/proc/self/task` contains exactly the calling thread.
    ///
    /// # Errors
    ///
    /// Returns an error if procfs cannot be inspected or the process has zero
    /// or more than one visible task.
    pub fn verify() -> Result<Self> {
        single_thread_original::verify_local()
    }

    /// Disables core dumps for this short-lived namespace worker process.
    ///
    /// This process-global setting intentionally has no restoration operation.
    /// A worker that crosses namespace boundaries must not serialize retained
    /// descriptors or privileged observation state into a core file.
    ///
    /// # Errors
    ///
    /// Returns an error if Linux cannot disable or verify process dumpability.
    pub fn disable_core_dumps(&self) -> Result<()> {
        crate::process::disable_core_dumps()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn failed_owned_pidfd_admission_keeps_the_exact_input_file() {
        use std::os::fd::AsRawFd as _;
        let file = tempfile::tempfile().unwrap();
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());

        let failed = super::PidFd::from_owned_retaining_v3(file.into()).unwrap_err();

        assert!(std::fs::read_link(&path).is_ok());
        assert!(std::error::Error::source(&failed).is_some());
        drop(failed);
        assert!(std::fs::read_link(path).is_err());
    }

    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::io::Write as _;
    #[cfg(feature = "kernel-tests")]
    use std::io::{BufRead as _, BufReader};
    #[cfg(feature = "kernel-tests")]
    use std::os::fd::AsRawFd as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn refused_received_pidfd_keeps_same_owned_file_and_first_cause() {
        let file = tempfile::tempfile().unwrap();
        let descriptor = std::os::fd::AsRawFd::as_raw_fd(&file);
        let mut original = RuntimeScopeReceivedPidFdOriginalV1::new();

        assert!(original.capture_once(file.into()).is_err());
        let cause = std::ptr::from_ref(original.failure().unwrap());
        assert!(original.take_completed_once().is_none());
        let retained = original.raw.as_ref().unwrap();
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(retained), descriptor);
        assert!(rustix::fs::fcntl_getfl(retained).is_ok());

        assert!(original.capture_once(tempfile::tempfile().unwrap().into()).is_err());
        assert_eq!(std::ptr::from_ref(original.failure().unwrap()), cause);
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(original.raw.as_ref().unwrap()), descriptor);
    }

    const LIVENESS_TARGET_ENV: &str = "AOS_PIDFD_LIVENESS_TARGET_V1";

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn original_open_moves_the_exact_validated_self_pin_once() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let mut opening = PidFdOpenAttemptV1::new();

        opening.capture_once(pid).unwrap();
        let process = opening.take_validated().unwrap();

        assert_eq!(process.info().unwrap().pid(), pid.get());
        assert!(process.is_alive().unwrap());
        assert!(opening.take_validated().is_none());
        assert!(opening.failure().is_none());
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn repeated_original_open_keeps_the_first_pin_and_refuses_transfer() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let mut opening = PidFdOpenAttemptV1::new();
        opening.capture_once(pid).unwrap();
        let original = opening.process.as_ref().unwrap().as_fd().as_raw_fd();

        assert!(opening.capture_once(pid).is_err());

        assert!(opening.take_validated().is_none());
        assert!(opening.failure().is_some());
        assert_eq!(opening.process.as_ref().unwrap().as_fd().as_raw_fd(), original);
        assert!(opening.process.as_ref().unwrap().is_alive().unwrap());
    }
    #[cfg(feature = "kernel-tests")]
    const LIVENESS_OBSERVER_ENV: &str = "AOS_PIDFD_CROSS_UID_OBSERVER_V1";
    #[cfg(feature = "kernel-tests")]
    const LIVE_MARKER: &str = "AOS_PIDFD_CROSS_UID_LIVE";

    #[test]
    fn empty_current_self_custody_exposes_no_pin() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();

        assert!(custody.pidfd().is_err());
        assert!(custody.observe_identity().is_err());
        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert!(custody.raw.is_none());
        assert!(custody.process.is_none());
        assert!(custody.observations.is_none());
        assert!(custody.capture_current().is_err());
    }

    #[test]
    fn prearmed_current_self_negative_observation_preserves_closed_healthy_source() {
        use std::os::fd::AsRawFd as _;

        let mut custody = CurrentSelfPidFdCustodyV1::new();
        let captured = custody.capture_current().unwrap();
        let descriptor = custody.process.as_ref().unwrap().as_fd().as_raw_fd();
        let mut owed = PidFdNegativeIdentityOriginalV1::new();
        custody.prepare_negative_identity_once_into_v1(&mut owed).unwrap();
        custody.fence();
        assert!(custody.observe_identity().is_err());
        assert!(custody.pidfd().is_err());

        custody.observe_negative_identity_once_v1(&mut owed).unwrap();

        assert!(owed.is_complete());
        assert!(owed.failure().is_none());
        let actual = owed.completed_info_v1().unwrap();
        assert_eq!(actual.pid(), captured.pid());
        assert_eq!(actual.parent_pid(), captured.parent_pid());
        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert_eq!(custody.process.as_ref().unwrap().as_fd().as_raw_fd(), descriptor);
        assert!(custody.observe_identity().is_err());
        assert!(custody.pidfd().is_err());
        assert!(custody.observe_negative_identity_once_v1(&mut owed).is_err());
        assert_eq!(owed.completed_info_v1(), Some(actual));
    }

    #[test]
    fn closed_current_self_cannot_prepare_a_new_negative_destination() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();
        custody.capture_current().unwrap();
        custody.fence();
        let mut unprepared = PidFdNegativeIdentityOriginalV1::new();

        assert!(custody.prepare_negative_identity_once_into_v1(&mut unprepared).is_err());
        assert!(custody.observe_negative_identity_once_v1(&mut unprepared).is_err());

        assert!(!unprepared.is_complete());
        assert!(unprepared.completed_info_v1().is_none());
        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
    }

    #[test]
    fn interrupted_current_self_borrow_stays_closed() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();
        let operation = custody.begin(CurrentSelfPhaseV1::Fresh).unwrap();
        drop(operation);

        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert!(custody.pidfd().is_err());
        assert!(custody.begin(CurrentSelfPhaseV1::Fresh).is_err());
    }

    #[test]
    fn forgotten_current_self_borrow_stays_closed() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();
        std::mem::forget(custody.begin(CurrentSelfPhaseV1::Fresh).unwrap());

        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert!(custody.pidfd().is_err());
        assert!(custody.begin(CurrentSelfPhaseV1::Fresh).is_err());
    }

    #[test]
    fn current_self_returned_cause_is_not_replaced_by_fencing() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();
        let operation = custody.begin(CurrentSelfPhaseV1::Fresh).unwrap();
        let result = operation.finish::<()>(Err(Error::WrongDescriptorType {
            expected: "pure failure sentinel",
        }));

        assert!(matches!(
            result,
            Err(Error::WrongDescriptorType {
                expected: "pure failure sentinel",
            }),
        ));
        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert!(custody.pidfd().is_err());
    }

    #[test]
    fn caught_current_self_unwind_stays_closed() {
        let mut custody = CurrentSelfPidFdCustodyV1::new();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _operation = custody.begin(CurrentSelfPhaseV1::Fresh).unwrap();
            panic!("pure current-self observation unwind");
        }));

        assert!(caught.is_err());
        assert_eq!(custody.phase, CurrentSelfPhaseV1::Closed);
        assert!(custody.pidfd().is_err());
        assert!(custody.capture_current().is_err());
    }

    fn spawn_liveness_target() -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pidfd::tests::liveness_target_fixture",
                "--nocapture",
            ])
            .env(LIVENESS_TARGET_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn ordinary_file_cannot_become_namespace() {
        let file = File::open(".").unwrap();
        let fd: OwnedFd = file.into();
        assert!(matches!(
            NamespaceFd::from_owned(fd, NamespaceKind::Mount),
            Err(Error::WrongDescriptorType { .. })
        ));
    }

    #[test]
    fn namespace_kind_is_verified_by_kernel() {
        let mount_namespace = File::open("/proc/self/ns/mnt").unwrap();
        let fd: OwnedFd = mount_namespace.into();
        let namespace = NamespaceFd::from_owned(fd, NamespaceKind::Mount).unwrap();
        assert_eq!(namespace.kind(), NamespaceKind::Mount);
        assert_ne!(namespace.identity().inode, 0);

        let mount_namespace = File::open("/proc/self/ns/mnt").unwrap();
        let fd: OwnedFd = mount_namespace.into();
        assert!(matches!(
            NamespaceFd::from_owned(fd, NamespaceKind::User),
            Err(Error::WrongDescriptorType { .. })
        ));
    }

    #[test]
    fn ordinary_file_cannot_become_pidfd() {
        let file: OwnedFd = File::open(".").unwrap().into();
        assert!(matches!(
            PidFd::from_owned(file),
            Err(Error::WrongDescriptorType { .. })
        ));
    }



    #[test]
    fn current_process_pidfd_is_pinned_when_kernel_supports_info() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        match PidFd::open(pid) {
            Ok(pidfd) => {
                assert!(pidfd.is_alive().unwrap());
                assert_eq!(pidfd.info().unwrap().pid(), pid.get());
                match crate::pidfd::namespace(&(pidfd), NamespaceKind::Mount) {
                    Ok(namespace) => assert_eq!(namespace.kind(), NamespaceKind::Mount),
                    Err(Error::Syscall { source, .. })
                        if matches!(
                            source.raw_os_error(),
                            Some(libc::ENOTTY | libc::ENOSYS | libc::EINVAL | libc::EPERM)
                        ) => {}
                    Err(error) => panic!("unexpected namespace ioctl failure: {error}"),
                }
            }
            Err(Error::Syscall { source, .. })
                if matches!(source.raw_os_error(), Some(libc::ENOTTY | libc::ENOSYS)) => {}
            Err(Error::WrongDescriptorType { .. }) => {}
            Err(error) => panic!("unexpected pidfd failure: {error}"),
        }
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn current_process_pidfd_reports_effective_credentials() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let credentials = PidFd::open(pid)
            .unwrap()
            .info()
            .unwrap()
            .credentials()
            .expect("Linux 6.18 PIDFD_GET_INFO must return requested credentials");

        assert_eq!(
            credentials.effective_user_id(),
            rustix::process::geteuid().as_raw()
        );
        assert_eq!(
            credentials.effective_group_id(),
            rustix::process::getegid().as_raw()
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "host time only bounds a disposable child-process fixture"
    )]
    fn child_pidfd_reports_exit_without_requiring_reap_state() {
        let mut child = spawn_liveness_target();
        let pid = NonZeroU32::new(child.id()).unwrap();
        let pidfd = PidFd::open(pid).unwrap();
        assert!(pidfd.is_alive().unwrap());

        child.kill().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while pidfd.is_alive().unwrap() {
            assert!(Instant::now() < deadline, "child did not become exited");
            std::thread::yield_now();
        }
        assert!(!pidfd.is_alive().unwrap());

        child.wait().unwrap();

        assert!(!pidfd.is_alive().unwrap());
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "host time only bounds a disposable cross-UID kernel fixture"
    )]
    fn cross_uid_pidfd_liveness_does_not_require_signal_permission() {
        use std::os::unix::process::CommandExt as _;

        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let mut target = spawn_liveness_target();
        let target_pid = NonZeroU32::new(target.id()).unwrap();
        let pidfd = PidFd::open(target_pid).unwrap();
        let observer_pidfd = pidfd.as_fd().try_clone_to_owned().unwrap();
        let mut observer = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pidfd::tests::cross_uid_observer_fixture",
                "--nocapture",
            ])
            .env(LIVENESS_OBSERVER_ENV, "1")
            .uid(65_534)
            .gid(65_534)
            .stdin(Stdio::from(observer_pidfd))
            // Keep the control marker off libtest's stdout status line.
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut control = BufReader::new(observer.stderr.take().unwrap());
        let mut observed_live = false;
        loop {
            let mut line = String::new();
            if control.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.trim() == LIVE_MARKER {
                observed_live = true;
                break;
            }
        }

        target.kill().unwrap();
        target.wait().unwrap();
        assert!(
            observed_live,
            "cross-UID observer did not report live pidfd"
        );
        assert!(observer.wait().unwrap().success());
        assert!(!pidfd.is_alive().unwrap());
    }

    #[test]
    #[ignore = "launched alone by pidfd liveness tests"]
    fn liveness_target_fixture() {
        if std::env::var_os(LIVENESS_TARGET_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    #[ignore = "launched as an unprivileged cross-UID pidfd observer"]
    #[allow(
        clippy::disallowed_methods,
        reason = "host time only bounds a disposable cross-UID kernel fixture"
    )]
    fn cross_uid_observer_fixture() {
        if std::env::var_os(LIVENESS_OBSERVER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        let stdin = std::io::stdin();
        let pidfd = PidFd::from_owned(stdin.as_fd().try_clone_to_owned().unwrap()).unwrap();
        assert!(matches!(
            aos_linux_descriptors::native::pidfd_send_signal_zero_for_test(pidfd.as_fd()),
            Err(Error::Syscall { source, .. }) if source.raw_os_error() == Some(libc::EPERM)
        ));
        assert!(pidfd.is_alive().unwrap());
        eprintln!("{LIVE_MARKER}");
        std::io::stderr().flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while pidfd.is_alive().unwrap() {
            assert!(Instant::now() < deadline, "target did not become exited");
            std::thread::yield_now();
        }
    }
}



pub(crate) fn require_ancestor_host_original(fd: BorrowedFd<'_>) -> Result<(u64, u64)> {
    if !cfg!(all(target_pointer_width = "64", any(target_arch = "x86_64", target_arch = "aarch64"))) {
        return Err(Error::invalid("ancestor Host pin", "unsupported pidfs inode width"));
    }
    aos_linux_descriptors::native::ensure_cloexec(fd)?;
    match aos_linux_descriptors::native::pidfd_info(fd) {
        Err(Error::Syscall { source, .. }) if source.raw_os_error() == Some(libc::EREMOTE) => {}
        Err(cause) => return Err(cause),
        Ok(_) => return Err(Error::invalid("ancestor Host pin", "process is visible in this PID namespace")),
    }
    let stat = uapi::fstat(fd)?;
    if stat.st_ino == 0 || !PidFd::poll_original_liveness(fd)? {
        return Err(Error::invalid("ancestor Host pin", "original process is unavailable"));
    }
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}


/// Acquires a typed namespace descriptor from this pinned process.
///
/// # Errors
///
/// Returns an error if the process exited, access is denied, the requested
/// namespace is unavailable, or the returned descriptor is not `nsfs`.
pub fn namespace(process: &PidFd, kind: NamespaceKind) -> Result<NamespaceFd> {
    NamespaceFd::from_owned(acquire_namespace_original(process, kind)?, kind)
}



fn acquire_namespace_original(process: &PidFd, kind: NamespaceKind) -> Result<OwnedFd> {
    uapi::pidfd_namespace(process.as_fd(), namespace_request_v2(kind))
}



fn acquire_namespace_retaining_v2(process: &PidFd, kind: NamespaceKind, original: &mut Option<OwnedFd>) -> Result<()> {
    uapi::pidfd_namespace_retaining_v2(process.as_fd(), namespace_request_v2(kind), original)
}

/// Transfers one actual private kernel slot after the sole borrowed validator.
pub(crate) fn adopt_received_slot(slot: &mut Option<uapi::RawAncillary>) -> Result<PidFd> {
    let Some(uapi::RawAncillary::PidFd(fd)) = slot.as_mut() else {
        return Err(Error::WrongDescriptorType { expected: "pidfd" });
    };
    fd.validate_once()?;
    match slot.take() {
        Some(uapi::RawAncillary::PidFd(fd)) => match fd.into_validated() {
            Ok(pin) => Ok(pin),
            Err(_still_owned) => std::process::abort(),
        },
        other => {
            *slot = other;
            Err(Error::WrongDescriptorType { expected: "pidfd" })
        }
    }
}
