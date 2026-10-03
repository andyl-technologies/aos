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
use crate::{Error, Result};

mod identity;
mod proc_observations;

pub use identity::PidFdProcessIdentity;
pub use proc_observations::PidFdProcObservationsV1;

const LIVENESS_POLL_INTERRUPT_LIMIT: usize = 8;

/// A process pinned against PID reuse by an owned pidfd.
#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
}

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
    raw: Option<OwnedFd>,
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
        self.raw = Some(uapi::pidfd_open_current_original()?);

        // Preserve the original fd_result pass, then the sole typed validator's
        // second CLOEXEC pass. Both now borrow the already-resident fresh pin.
        let raw = self.raw.as_ref().ok_or_else(current_self_closed)?;
        uapi::ensure_cloexec(raw.as_fd())?;
        PidFd::validate_owned_kind(raw.as_fd())?;

        // Removal is followed only by an infallible same-owner typed transfer.
        match self.raw.take() {
            Some(fd) => self.process = Some(PidFd { fd }),
            None => return Err(current_self_closed()),
        }

        let process = self.process.as_ref().ok_or_else(current_self_closed)?;
        self.observations = Some(process.prepare_proc_observations_v1());
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

impl PidFd {
    /// Opens and validates a pidfd for `pid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be pinned, the kernel lacks the
    /// required pidfd operations, or the returned descriptor is not a pidfd.
    pub fn open(pid: NonZeroU32) -> Result<Self> {
        Self::from_owned(uapi::pidfd_open(pid.get())?)
    }

    /// Validates and adopts an already-owned pidfd.
    ///
    /// The `PIDFD_GET_INFO` validation prevents an arbitrary caller-supplied
    /// descriptor from crossing the typed boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is not a live pidfd supported by the
    /// Linux 6.18 pidfs UAPI.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        Self::validate_owned_kind(fd.as_fd())?;
        Ok(Self { fd })
    }

    // All callers use this sole checker and its original error precedence.
    // The retaining caller leaves ownership in its guarded received slot.
    fn validate_owned_kind(fd: BorrowedFd<'_>) -> Result<()> {
        uapi::ensure_cloexec(fd)?;
        match uapi::pidfd_info(fd) {
            Ok(info) if info.mask & PidFdInfo::PID_PRESENT != 0 => Ok(()),
            Ok(_) => Err(Error::MalformedKernelResponse {
                object: "pidfd info",
                message: "kernel omitted mandatory PID information".to_string(),
            }),
            Err(Error::Syscall { source, .. })
                if matches!(source.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) =>
            {
                Err(Error::WrongDescriptorType { expected: "pidfd" })
            }
            Err(error) => Err(error),
        }
    }

    /// Adopts only an actual staged kernel slot after the same borrowed check.
    pub(crate) fn adopt_received_slot(
        slot: &mut Option<uapi::RawAncillary>,
    ) -> Result<Self> {
        let Some(uapi::RawAncillary::PidFd(fd)) = slot.as_ref() else {
            return Err(Error::WrongDescriptorType { expected: "pidfd" });
        };
        Self::validate_owned_kind(fd.as_fd())?;

        // No fallible operation follows removal. The caller installs the
        // resulting typed pin directly in the same receive-attempt owner.
        match slot.take() {
            Some(uapi::RawAncillary::PidFd(fd)) => Ok(Self { fd }),
            other => {
                *slot = other;
                Err(Error::WrongDescriptorType { expected: "pidfd" })
            }
        }
    }

    /// Borrows the underlying pidfd for descriptor-oriented APIs.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Reads process identity, credentials, and cgroup ID with one pidfs ioctl.
    ///
    /// The fields are one observation of the pinned process, not a globally
    /// atomic process snapshot. The process may exit immediately afterward.
    /// Retain this `PidFd` and call [`PidFd::is_alive`] after related
    /// observations.
    ///
    /// # Errors
    ///
    /// Returns an error if `PIDFD_GET_INFO` fails or omits mandatory PID data.
    pub fn info(&self) -> Result<PidFdInfo> {
        decode_pidfd_info(uapi::pidfd_info(self.fd.as_fd())?)
    }

    /// Delivers a Linux signal to the thread group pinned by this descriptor.
    ///
    /// Explicit thread-group scope prevents an inherited thread pidfd from
    /// silently selecting one thread or a mutable process group. The descriptor
    /// and signal are not authorization: the owner must retain its current
    /// policy, execution membership and effect reservation through the call.
    ///
    /// # Errors
    /// Rejects a signal outside `1..=64`, stale custody, missing permission, or
    /// a kernel failure. An error does not authorize automatic redispatch.
    pub fn send_thread_group_signal(&self, signal: u8) -> Result<()> {
        if !(1..=64).contains(&signal) {
            return Err(Error::invalid("signal", "must be in 1..=64"));
        }
        uapi::pidfd_send_thread_group_signal(self.fd.as_fd(), signal)
    }

    /// Tests whether the pinned process has not exited without sending a signal.
    ///
    /// Pidfd exit readiness is independent of signal permissions. An exited
    /// process reports `false` even while it remains waitable as a zombie or
    /// while this descriptor continues to pin its identity.
    ///
    /// # Errors
    ///
    /// Returns an error when polling fails, is interrupted too many times, or
    /// reports invalid or unexpected readiness flags.
    pub fn is_alive(&self) -> Result<bool> {
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        for attempt in 0..LIVENESS_POLL_INTERRUPT_LIMIT {
            let mut descriptors = [rustix::event::PollFd::new(
                &self.fd,
                rustix::event::PollFlags::IN | rustix::event::PollFlags::RDNORM,
            )];
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Ok(0) => return Ok(true),
                Ok(_) => {
                    let readiness = descriptors[0].revents();
                    let exit_readiness = rustix::event::PollFlags::IN
                        | rustix::event::PollFlags::RDNORM
                        | rustix::event::PollFlags::HUP;
                    if readiness
                        .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
                    {
                        return Err(Error::MalformedKernelResponse {
                            object: "pidfd poll",
                            message: "kernel reported an invalid descriptor state".to_owned(),
                        });
                    }
                    if !readiness.difference(exit_readiness).is_empty() {
                        return Err(Error::MalformedKernelResponse {
                            object: "pidfd poll",
                            message: "kernel reported unexpected readiness flags".to_owned(),
                        });
                    }
                    if readiness.intersects(exit_readiness) {
                        return Ok(false);
                    }
                    return Err(Error::MalformedKernelResponse {
                        object: "pidfd poll",
                        message: "kernel reported unexpected readiness flags".to_owned(),
                    });
                }
                Err(source)
                    if source == rustix::io::Errno::INTR
                        && attempt + 1 < LIVENESS_POLL_INTERRUPT_LIMIT =>
                {
                    continue;
                }
                Err(source) => {
                    return Err(Error::Syscall {
                        operation: "poll pidfd liveness",
                        source: source.into(),
                    });
                }
            }
        }
        Err(Error::MalformedKernelResponse {
            object: "pidfd poll",
            message: "bounded liveness poll exhausted without a result".to_owned(),
        })
    }

    /// Duplicates one descriptor from the pinned process with `pidfd_getfd`.
    ///
    /// This operation remains subject to the kernel's ptrace access check.
    ///
    /// # Errors
    ///
    /// Returns an error when the target descriptor does not exist, access is
    /// denied, the process exited, or the syscall is unavailable.
    pub fn duplicate_target_fd(&self, target: RawFd) -> Result<OwnedFd> {
        if target < 0 {
            return Err(Error::invalid("target descriptor", "must be non-negative"));
        }
        uapi::pidfd_getfd(self.fd.as_fd(), target)
    }

    /// Acquires a typed namespace descriptor from this pinned process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process exited, access is denied, the requested
    /// namespace is unavailable, or the returned descriptor is not `nsfs`.
    pub fn namespace(&self, kind: NamespaceKind) -> Result<NamespaceFd> {
        let request = match kind {
            NamespaceKind::Mount => NamespaceIoctl::Mount,
            NamespaceKind::Network => NamespaceIoctl::Network,
            NamespaceKind::Pid => NamespaceIoctl::Pid,
            NamespaceKind::User => NamespaceIoctl::User,
            NamespaceKind::Uts => NamespaceIoctl::Uts,
        };
        NamespaceFd::from_owned(uapi::pidfd_namespace(self.fd.as_fd(), request)?, kind)
    }
}

/// Information returned by one `PIDFD_GET_INFO` ioctl observation.
///
/// Credentials, cgroup membership, and process identifiers are read separately
/// during the ioctl. This value does not assert that they form a globally
/// atomic snapshot or that any mutable field remains current afterward. Callers
/// making an authorization decision must retain the pidfd and repeat the
/// observations required at their effect boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidFdInfo {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    credentials: Option<PidFdCredentials>,
    cgroup_id: Option<u64>,
}

impl PidFdInfo {
    const PID_PRESENT: u64 = 1 << 0;
    const CREDENTIALS_PRESENT: u64 = 1 << 1;
    const CGROUP_PRESENT: u64 = 1 << 2;

    /// Returns the process ID in the caller's PID namespace.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Returns the thread-group leader ID.
    #[must_use]
    pub const fn thread_group_id(self) -> u32 {
        self.thread_group_id
    }

    /// Returns the parent process ID observed by the kernel.
    #[must_use]
    pub const fn parent_pid(self) -> u32 {
        self.parent_pid
    }

    /// Returns the task credentials when the kernel supplied them.
    #[must_use]
    pub const fn credentials(self) -> Option<PidFdCredentials> {
        self.credentials
    }

    /// Returns the cgroup-v2 kernfs ID when the kernel supplied it.
    #[must_use]
    pub const fn cgroup_id(self) -> Option<u64> {
        self.cgroup_id
    }
}

/// Credentials captured from one coherent task credential snapshot.
///
/// The kernel maps these IDs into the caller's current user namespace. Real,
/// effective, saved-set, and filesystem IDs are distinct mutable process
/// attributes. This value reports all eight fields from the same credential
/// object but makes no freshness claim after the ioctl returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidFdCredentials {
    real_user_id: u32,
    real_group_id: u32,
    effective_user_id: u32,
    effective_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    filesystem_user_id: u32,
    filesystem_group_id: u32,
}

impl PidFdCredentials {
    /// Returns the real user ID.
    #[must_use]
    pub const fn real_user_id(self) -> u32 {
        self.real_user_id
    }

    /// Returns the real group ID.
    #[must_use]
    pub const fn real_group_id(self) -> u32 {
        self.real_group_id
    }

    /// Returns the effective user ID.
    #[must_use]
    pub const fn effective_user_id(self) -> u32 {
        self.effective_user_id
    }

    /// Returns the effective group ID.
    #[must_use]
    pub const fn effective_group_id(self) -> u32 {
        self.effective_group_id
    }

    /// Returns the saved-set user ID.
    #[must_use]
    pub const fn saved_user_id(self) -> u32 {
        self.saved_user_id
    }

    /// Returns the saved-set group ID.
    #[must_use]
    pub const fn saved_group_id(self) -> u32 {
        self.saved_group_id
    }

    /// Returns the filesystem user ID used for filesystem access checks.
    #[must_use]
    pub const fn filesystem_user_id(self) -> u32 {
        self.filesystem_user_id
    }

    /// Returns the filesystem group ID used for filesystem access checks.
    #[must_use]
    pub const fn filesystem_group_id(self) -> u32 {
        self.filesystem_group_id
    }
}

fn decode_pidfd_info(raw: uapi::RawPidfdInfo) -> Result<PidFdInfo> {
    if raw.mask & PidFdInfo::PID_PRESENT == 0 {
        return Err(Error::MalformedKernelResponse {
            object: "pidfd info",
            message: "kernel omitted mandatory PID information".to_string(),
        });
    }

    let credentials =
        (raw.mask & PidFdInfo::CREDENTIALS_PRESENT != 0).then_some(PidFdCredentials {
            real_user_id: raw.ruid,
            real_group_id: raw.rgid,
            effective_user_id: raw.euid,
            effective_group_id: raw.egid,
            saved_user_id: raw.suid,
            saved_group_id: raw.sgid,
            filesystem_user_id: raw.fsuid,
            filesystem_group_id: raw.fsgid,
        });

    Ok(PidFdInfo {
        pid: raw.pid,
        thread_group_id: raw.tgid,
        parent_pid: raw.ppid,
        credentials,
        cgroup_id: (raw.mask & PidFdInfo::CGROUP_PRESENT != 0).then_some(raw.cgroup_id),
    })
}

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
        let descriptor = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open /proc/self/ns/net",
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Self::from_owned(descriptor, NamespaceKind::Network)
    }

    /// Checks whether this descriptor is the calling process's current namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if this is not a Network namespace or if the fixed
    /// current-namespace descriptor cannot be opened and inspected.
    pub fn validate_current_network(&self) -> Result<()> {
        if self.kind != NamespaceKind::Network {
            return Err(Error::WrongDescriptorType {
                expected: "Network namespace",
            });
        }
        if Self::current_network()?.identity != self.identity {
            return Err(Error::invalid(
                "current Network namespace",
                "retained descriptor does not identify the current namespace",
            ));
        }
        Ok(())
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
        uapi::ensure_cloexec(fd.as_fd())?;
        if !uapi::is_namespace(fd.as_fd())? {
            return Err(Error::WrongDescriptorType {
                expected: "nsfs namespace",
            });
        }
        if uapi::namespace_type(fd.as_fd())? != kind.clone_flag() {
            return Err(Error::WrongDescriptorType {
                expected: "requested namespace kind",
            });
        }
        let stat = uapi::fstat(fd.as_fd())?;
        Ok(Self {
            fd,
            kind,
            identity: NamespaceIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
            },
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
        let tasks = std::fs::read_dir("/proc/self/task").map_err(|source| Error::Syscall {
            operation: "read /proc/self/task",
            source,
        })?;
        let mut count = 0usize;
        for task in tasks {
            task.map_err(|source| Error::Syscall {
                operation: "read /proc/self/task entry",
                source,
            })?;
            count += 1;
            if count > 1 {
                return Err(Error::invalid(
                    "namespace worker",
                    "process has more than one thread",
                ));
            }
        }
        if count != 1 {
            return Err(Error::invalid(
                "namespace worker",
                "process has no visible calling thread",
            ));
        }
        Ok(Self {
            not_send_or_sync: PhantomData,
        })
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
    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::io::Write as _;
    #[cfg(feature = "kernel-tests")]
    use std::io::{BufRead as _, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    const LIVENESS_TARGET_ENV: &str = "AOS_PIDFD_LIVENESS_TARGET_V1";
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
    fn pidfd_info_maps_all_credential_fields_and_mask_omission() {
        let raw = uapi::RawPidfdInfo {
            mask: PidFdInfo::PID_PRESENT
                | PidFdInfo::CREDENTIALS_PRESENT
                | PidFdInfo::CGROUP_PRESENT,
            cgroup_id: 19,
            pid: 11,
            tgid: 12,
            ppid: 13,
            ruid: 21,
            rgid: 22,
            euid: 23,
            egid: 24,
            suid: 25,
            sgid: 26,
            fsuid: 27,
            fsgid: 28,
            ..uapi::RawPidfdInfo::default()
        };
        let info = decode_pidfd_info(raw).unwrap();
        let credentials = info.credentials().unwrap();

        assert_eq!(info.pid(), 11);
        assert_eq!(info.thread_group_id(), 12);
        assert_eq!(info.parent_pid(), 13);
        assert_eq!(info.cgroup_id(), Some(19));
        assert_eq!(credentials.real_user_id(), 21);
        assert_eq!(credentials.real_group_id(), 22);
        assert_eq!(credentials.effective_user_id(), 23);
        assert_eq!(credentials.effective_group_id(), 24);
        assert_eq!(credentials.saved_user_id(), 25);
        assert_eq!(credentials.saved_group_id(), 26);
        assert_eq!(credentials.filesystem_user_id(), 27);
        assert_eq!(credentials.filesystem_group_id(), 28);

        let without_credentials = decode_pidfd_info(uapi::RawPidfdInfo {
            mask: PidFdInfo::PID_PRESENT,
            pid: 11,
            ..raw
        })
        .unwrap();
        assert_eq!(without_credentials.credentials(), None);
        assert_eq!(without_credentials.cgroup_id(), None);
    }

    #[test]
    fn current_process_pidfd_is_pinned_when_kernel_supports_info() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        match PidFd::open(pid) {
            Ok(pidfd) => {
                assert!(pidfd.is_alive().unwrap());
                assert_eq!(pidfd.info().unwrap().pid(), pid.get());
                match pidfd.namespace(NamespaceKind::Mount) {
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
            uapi::pidfd_send_signal_zero_for_test(pidfd.as_fd()),
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
