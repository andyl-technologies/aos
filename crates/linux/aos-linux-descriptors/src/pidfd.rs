//! Owned process pins and bounded pidfs identity mechanics.

use std::num::NonZeroU32;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use crate::{Error, Result, native as uapi};

const LIVENESS_POLL_INTERRUPT_LIMIT: usize = 8;

/// A process pinned against PID reuse by an owned pidfd.
#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
}

/// Retains a transferred descriptor rejected by the sole kernel-pin validator.
///
/// No descriptor getter, retry or process authority is supplied.
#[derive(Debug)]
pub struct PidFdOwnedAdmissionFailureV3 {
    cause: Error,
    _input: Option<OwnedFd>,
}

impl std::fmt::Display for PidFdOwnedAdmissionFailureV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for PidFdOwnedAdmissionFailureV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl PidFd {
    /// Validates a transferred original while retaining its descriptor on error.
    ///
    /// This mechanical admission identifies a kernel pin only. The caller
    /// independently verifies the received subject, role, ancestry and scope.
    ///
    /// # Errors
    /// Preserves the actual same-validator error and raw input descriptor.
    pub fn from_owned_retaining_v3(fd: OwnedFd) -> std::result::Result<Self, PidFdOwnedAdmissionFailureV3> {
        let mut input = Some(fd);
        Self::adopt_owned_slot_v2(&mut input).map_err(|cause| PidFdOwnedAdmissionFailureV3 { cause, _input: input })
    }

    /// Opens and validates a pidfd for `pid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be pinned, the kernel lacks the
    /// required pidfd operations, or the returned descriptor is not a pidfd.
    pub fn open(pid: NonZeroU32) -> Result<Self> {
        Self::from_owned(uapi::pidfd_open(pid.get())?)
    }

    /// Opens the same pidfd while retaining any raw typed-admission failure.
    ///
    /// The existing kernel open and CLOEXEC/pidfs checker remain shared. The
    /// failure owns any returned original descriptor; it grants no identity,
    /// process membership or permission to observe a different task.
    ///
    /// # Errors
    /// Retains the original syscall or typed descriptor validation cause and
    /// any raw descriptor acquired before that validation failed.
    pub fn open_retaining_v4(pid: NonZeroU32) -> std::result::Result<Self, PidFdOwnedAdmissionFailureV3> {
        let descriptor = uapi::pidfd_open(pid.get()).map_err(|cause| PidFdOwnedAdmissionFailureV3 {
            cause, _input: None,
        })?;
        Self::from_owned_retaining_v3(descriptor)
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
        Self::adopt_owned_slot_v2(&mut Some(fd))
    }

    /// Validates a resident raw descriptor before its infallible typed move.
    ///
    /// # Errors
    /// Leaves the same descriptor in the supplied slot on native or kind failure.
    pub fn adopt_owned_slot_v2(slot: &mut Option<OwnedFd>) -> Result<Self> {
        let fd = slot.as_ref().ok_or_else(current_self_closed)?;
        Self::validate_owned_kind(fd.as_fd())?;
        match slot.take() {
            Some(fd) => Ok(Self { fd }),
            None => std::process::abort(),
        }
    }

    /// Checks CLOEXEC and the kernel pidfs object kind by borrowing a descriptor.
    ///
    /// # Errors
    /// Returns the original flag, ioctl, missing-PID or wrong-kind failure.
    pub fn validate_owned_kind(fd: BorrowedFd<'_>) -> Result<()> {
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
        Self::poll_original_liveness(self.fd.as_fd())
    }

    // The selected namespace-local channel shares the exact exit-poll engine;
    // it never constructs a strict PidFd or synthesizes visible PID information.
    /// Polls the same original descriptor for exit with the bounded EINTR law.
    ///
    /// # Errors
    /// Returns native poll errors, exhausted interrupts or unexpected readiness.
    pub fn poll_original_liveness(fd: BorrowedFd<'_>) -> Result<bool> {
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        for attempt in 0..LIVENESS_POLL_INTERRUPT_LIMIT {
            let mut descriptors = [rustix::event::PollFd::new(
                &fd,
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


fn current_self_closed() -> Error {
    Error::invalid(
        "current-self custody",
        "original observation is permanently closed",
    )
}

mod admission_slot;
pub use admission_slot::PidFdAdmissionSlotV1;

#[cfg(test)]
mod tests {
    use super::*;
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
}
