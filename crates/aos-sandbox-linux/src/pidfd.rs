//! Owned pidfds and namespace descriptors.
//!
//! Namespace descriptors are acquired from a pinned pidfd with Linux 6.18's
//! pidfs ioctls. The wrapper records the namespace `(device, inode)` identity
//! at acquisition so callers can detect replacement across observations.

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::rc::Rc;

use crate::uapi::{self, NamespaceIoctl};
use crate::{Error, Result};

/// A process pinned against PID reuse by an owned pidfd.
#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
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
        uapi::ensure_cloexec(fd.as_fd())?;
        match uapi::pidfd_info(fd.as_fd()) {
            Ok(info) if info.mask & PidFdInfo::PID_PRESENT != 0 => Ok(Self { fd }),
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

    /// Borrows the underlying pidfd for descriptor-oriented APIs.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Reads the process identity and cgroup ID atomically from pidfs.
    ///
    /// The information was correct for the pinned process when the ioctl ran,
    /// but the process may exit immediately afterward. Retain this `PidFd` and
    /// call [`PidFd::is_alive`] after related observations.
    ///
    /// # Errors
    ///
    /// Returns an error if `PIDFD_GET_INFO` fails or omits mandatory PID data.
    pub fn info(&self) -> Result<PidFdInfo> {
        let raw = uapi::pidfd_info(self.fd.as_fd())?;
        if raw.mask & PidFdInfo::PID_PRESENT == 0 {
            return Err(Error::MalformedKernelResponse {
                object: "pidfd info",
                message: "kernel omitted mandatory PID information".to_string(),
            });
        }
        Ok(PidFdInfo {
            pid: raw.pid,
            thread_group_id: raw.tgid,
            parent_pid: raw.ppid,
            cgroup_id: (raw.mask & PidFdInfo::CGROUP_PRESENT != 0).then_some(raw.cgroup_id),
        })
    }

    /// Tests whether the pinned process still exists without sending a signal.
    ///
    /// # Errors
    ///
    /// Returns an error for failures other than the expected `ESRCH` after
    /// process exit.
    pub fn is_alive(&self) -> Result<bool> {
        match uapi::pidfd_send_signal_zero(self.fd.as_fd()) {
            Ok(()) => Ok(true),
            Err(Error::Syscall { source, .. }) if source.raw_os_error() == Some(libc::ESRCH) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
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

/// Atomic information returned by `PIDFD_GET_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidFdInfo {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: Option<u64>,
}

impl PidFdInfo {
    const PID_PRESENT: u64 = 1 << 0;
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

    /// Returns the cgroup-v2 kernfs ID when the kernel supplied it.
    #[must_use]
    pub const fn cgroup_id(self) -> Option<u64> {
        self.cgroup_id
    }
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
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

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
}
