//! Actual startup admission for the image-owned five-role filesystem worker.
//!
//! The sole constructor captures the process's original table, checks its
//! enforcing subject and immutable EROFS executable, and retains the actual
//! objects. These startup checks are not Controller, Root, lease, fresh FUSE
//! connection or content-read authority. Mount must independently retain and
//! join its original fresh OFD and authenticated held dispatch.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags};

use crate::fuse_worker_objects::{
    FUSE_WORKER_CANCEL_CONTEXT_V1, FUSE_WORKER_CHANNEL_CONTEXT_V1, FUSE_WORKER_CONTEXT_V1,
    FUSE_WORKER_DEVICE_CONTEXT_V1, FUSE_WORKER_EXECUTABLE_CONTEXT_V1, FUSE_WORKER_PLAN_CONTEXT_V1,
    context_matches, require_object_context,
};
use crate::{Error, Result, uapi};

const EROFS_SUPER_MAGIC: i64 = 0xe0f5_e1e2;
const MAXIMUM_STATUS_BYTES: usize = 16 * 1024;

/// Retains the original role objects after closed startup admission.
///
/// No factory accepts arbitrary received descriptors or scalar identities.
/// The inherited executable is measured as a physical EROFS image inode, not
/// as a per-file fs-verity Cache object; those proof domains are distinct.
pub struct FixedFuseWorkerStartupV1 {
    executable: OwnedFd,
    plan: OwnedFd,
    connection: OwnedFd,
    records: OwnedFd,
    cancellation: OwnedFd,
}

impl FixedFuseWorkerStartupV1 {
    /// Captures and admits the actual fixed launch's complete role table.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded image-owned worker entry before
    /// creating any owner for FDs 3 through 7 or installing signal handlers.
    /// No other code may mutate the initial descriptor table during capture.
    ///
    /// # Errors
    ///
    /// Returns an error for extra/missing roles, an unsafe execution subject,
    /// a writable/foreign executable, incorrect labels or role flags, an
    /// unsealed plan, or a kernel observation failure. The worker must exit.
    pub unsafe fn capture() -> Result<Self> {
        // SAFETY: the entry's exclusive original-table ownership is forwarded
        // unchanged; the lower boundary fences signals and rejects extra FDs.
        let [executable, plan, connection, records, cancellation] =
            unsafe { crate::inherited_fd::claim_fuse_worker_descriptor_table() }?;
        require_subject()?;
        require_executable(executable.as_fd())?;
        require_object_context(plan.as_fd(), FUSE_WORKER_PLAN_CONTEXT_V1)?;
        require_object_context(connection.as_fd(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        require_object_context(records.as_fd(), FUSE_WORKER_CHANNEL_CONTEXT_V1)?;
        require_object_context(cancellation.as_fd(), FUSE_WORKER_CANCEL_CONTEXT_V1)?;
        require_role_shapes(
            plan.as_fd(),
            connection.as_fd(),
            records.as_fd(),
            cancellation.as_fd(),
        )?;
        require_subject()?;
        Ok(Self {
            executable,
            plan,
            connection,
            records,
            cancellation,
        })
    }

    /// Consumes only the original sealed plan for a scoped immutable mapping.
    ///
    /// The remaining execution, connection, channel and cancellation objects
    /// stay owned for the worker lifetime. Mapping bytes conveys no authority.
    pub fn into_plan_and_session(self) -> (OwnedFd, FixedFuseWorkerSessionV1) {
        (
            self.plan,
            FixedFuseWorkerSessionV1 {
                executable: self.executable,
                connection: self.connection,
                records: self.records,
                cancellation: self.cancellation,
            },
        )
    }
}

/// Retains the original kernel session objects without issuing a read grant.
pub struct FixedFuseWorkerSessionV1 {
    executable: OwnedFd,
    connection: OwnedFd,
    records: OwnedFd,
    cancellation: OwnedFd,
}

impl FixedFuseWorkerSessionV1 {
    /// Rechecks the same executing inode, enforcing SID and inherited labels.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed execution profile or object label.
    pub fn recheck(&self) -> Result<()> {
        require_subject()?;
        require_executable(self.executable.as_fd())?;
        require_object_context(self.connection.as_fd(), FUSE_WORKER_DEVICE_CONTEXT_V1)?;
        require_object_context(self.records.as_fd(), FUSE_WORKER_CHANNEL_CONTEXT_V1)?;
        require_object_context(self.cancellation.as_fd(), FUSE_WORKER_CANCEL_CONTEXT_V1)
    }

    /// Sends a bounded preparation record on the actual inherited endpoint.
    ///
    /// No peer pidfd is inspected by the worker: doing so against current
    /// init_t Mount would require forbidden Root task-file read permissions.
    /// The retained Mount receiver instead correlates the generated record
    /// pidfd with Host's original worker and actual post-exec SID readback.
    /// This operation cannot acknowledge backing, readiness or a Root claim.
    ///
    /// # Errors
    ///
    /// Returns an error for changed startup state, an oversized/empty record,
    /// backpressure, or an incomplete atomic send.
    pub fn send_preparation_record(&self, record: &[u8]) -> Result<()> {
        self.recheck()?;
        if record.is_empty() || record.len() > 512 {
            return Err(Error::invalid(
                "worker preparation record",
                "exceeds closed bounds",
            ));
        }
        uapi::validate_connected_seqpacket(self.records.as_fd())?;
        uapi::require_seqpacket_identity(self.records.as_fd())?;
        let cookie = uapi::socket_cookie(self.records.as_fd())?;
        if cookie == 0 || uapi::send_seqpacket(self.records.as_fd(), record)? != record.len() {
            return Err(Error::invalid(
                "worker preparation send",
                "missing carrier or partial send",
            ));
        }
        if uapi::socket_cookie(self.records.as_fd())? != cookie {
            return Err(Error::invalid("worker preparation send", "carrier changed"));
        }
        self.recheck()
    }

    /// Borrows only the original cancellation reader for bounded polling.
    pub fn cancellation(&self) -> BorrowedFd<'_> {
        self.cancellation.as_fd()
    }

    /// Borrows the originally captured FUSE role for trusted transport setup.
    ///
    /// This borrow does not establish a fresh connection, completed INIT,
    /// idmapped mount, or content authority. The fixed entry's sole transport
    /// owner must retain this session and prevent any second request reader.
    pub fn connection(&self) -> BorrowedFd<'_> {
        self.connection.as_fd()
    }

    /// Retains the prepared connection until actual owner cancellation or loss.
    ///
    /// No FUSE or content record is consumed while the genuine Root/Mount
    /// grant dispatcher is absent. Expiry is not a teardown proof and does
    /// not erase Mount's uncertain reservation or backing obligations.
    ///
    /// # Errors
    ///
    /// Returns an error for changed execution or failed bounded polling/read.
    pub fn wait_for_owner_cancellation(self) -> Result<()> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        loop {
            self.recheck()?;
            let mut poll_fds = [PollFd::new(self.cancellation.as_fd(), PollFlags::IN)];
            let timeout = Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            poll(&mut poll_fds, Some(&timeout))
                .map_err(|source| kernel_error("poll original worker cancellation", source))?;
            let events = poll_fds[0].revents();
            if events.intersects(PollFlags::IN | PollFlags::HUP) {
                let mut signal = [0; 1];
                let count = rustix::io::read(&self.cancellation, &mut signal)
                    .map_err(|source| kernel_error("read original worker cancellation", source))?;
                if count == 0 || signal == [1] {
                    return Ok(());
                }
                return Err(Error::invalid(
                    "worker cancellation",
                    "unexpected cancellation bytes",
                ));
            }
            if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                return Err(Error::invalid(
                    "worker cancellation",
                    "original owner channel failed",
                ));
            }
        }
    }
}

fn require_subject() -> Result<()> {
    let context = read_bounded("/proc/self/attr/current", 256)?;
    let expected = FUSE_WORKER_CONTEXT_V1.as_bytes();
    if !context_matches(&context, expected) {
        return Err(Error::invalid(
            "worker execution SID",
            "not the fixed worker domain",
        ));
    }
    let enforcing = read_bounded("/sys/fs/selinux/enforce", 2)?;
    if enforcing != b"1" && enforcing != b"1\n" {
        return Err(Error::invalid(
            "worker execution SID",
            "SELinux is not enforcing",
        ));
    }
    let status = read_bounded("/proc/self/status", MAXIMUM_STATUS_BYTES)?;
    let status = std::str::from_utf8(&status)
        .map_err(|_| Error::invalid("worker process status", "not UTF-8"))?;
    require_status(status)
}

fn require_status(status: &str) -> Result<()> {
    let field = |name: &str| {
        let mut entries = status.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim())
        });
        let value = entries.next()?;
        entries.next().is_none().then_some(value)
    };
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if field(name) != Some("0000000000000000") {
            return Err(Error::invalid(
                "worker capabilities",
                "nonempty or missing capability field",
            ));
        }
    }
    if field("NoNewPrivs") != Some("1")
        || field("Seccomp") != Some("2")
        || !field("Seccomp_filters")
            .and_then(|count| count.parse::<u32>().ok())
            .is_some_and(|count| count > 0)
    {
        return Err(Error::invalid(
            "worker process restrictions",
            "missing NNP or active seccomp filter",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_status;

    const STATUS: &str = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";

    #[test]
    fn accepts_only_capability_empty_nnp_filtered_subject() {
        assert!(require_status(STATUS).is_ok());

        for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let elevated = STATUS.replace(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000000001"),
            );
            assert!(require_status(&elevated).is_err(), "{field}");
        }
    }

    #[test]
    fn rejects_missing_duplicate_or_disabled_restrictions() {
        for (old, new) in [
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("Seccomp:\t2", "Seccomp:\t0"),
            ("Seccomp_filters:\t1", "Seccomp_filters:\t0"),
            ("Seccomp_filters:\t1", "Seccomp_filters:\tinvalid"),
            ("CapAmb:\t0000000000000000\n", ""),
        ] {
            assert!(require_status(&STATUS.replace(old, new)).is_err(), "{old}");
        }
        assert!(require_status(&format!("{STATUS}NoNewPrivs:\t1\n")).is_err());
    }
}

fn require_executable(pin: BorrowedFd<'_>) -> Result<()> {
    require_object_context(pin, FUSE_WORKER_EXECUTABLE_CONTEXT_V1)?;
    if uapi::get_status_flags(pin)? & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(Error::invalid("worker executable pin", "not read-only"));
    }
    // This is the running task's own magic link, not an authority-bearing
    // pathname supplied by a caller. Compare the open object with the pin.
    let actual = rustix::fs::open(
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| kernel_error("open executing worker image", source))?;
    let root = rustix::fs::stat("/")
        .map_err(|source| kernel_error("inspect worker image root", source))?;
    let held = rustix::fs::fstat(pin)
        .map_err(|source| kernel_error("inspect worker executable pin", source))?;
    let running = rustix::fs::fstat(&actual)
        .map_err(|source| kernel_error("inspect executing worker image", source))?;
    let mount = rustix::fs::fstatvfs(pin)
        .map_err(|source| kernel_error("inspect worker executable mount", source))?;
    if held.st_dev != running.st_dev
        || held.st_ino != running.st_ino
        || held.st_dev != root.st_dev
        || held.st_uid != 0
        || held.st_gid != 0
        || held.st_mode & 0o222 != 0
        || held.st_mode & 0o111 == 0
        || FileType::from_raw_mode(held.st_mode) != FileType::RegularFile
        || uapi::filesystem_type(pin)? != EROFS_SUPER_MAGIC
        || !mount.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
        || mount.f_flag.contains(rustix::fs::StatVfsMountFlags::NOEXEC)
    {
        return Err(Error::invalid(
            "worker executable pin",
            "not the same immutable physical EROFS image inode",
        ));
    }
    require_object_context(actual.as_fd(), FUSE_WORKER_EXECUTABLE_CONTEXT_V1)
}

fn require_role_shapes(
    plan: BorrowedFd<'_>,
    connection: BorrowedFd<'_>,
    records: BorrowedFd<'_>,
    cancellation: BorrowedFd<'_>,
) -> Result<()> {
    let plan_stat =
        rustix::fs::fstat(plan).map_err(|source| kernel_error("inspect worker plan", source))?;
    if FileType::from_raw_mode(plan_stat.st_mode) != FileType::RegularFile
        || plan_stat.st_nlink != 0
        || plan_stat.st_uid != 0
        || plan_stat.st_size <= 0
        || plan_stat.st_size > 4096
        || uapi::get_status_flags(plan)? & libc::O_ACCMODE != libc::O_RDONLY
        || uapi::get_seals(plan)? & uapi::REQUIRED_IMMUTABLE_SEALS != uapi::REQUIRED_IMMUTABLE_SEALS
    {
        return Err(Error::invalid(
            "worker plan role",
            "not a fully sealed root-owned read-only anonymous plan",
        ));
    }
    let device = rustix::fs::fstat(connection)
        .map_err(|source| kernel_error("inspect worker FUSE role", source))?;
    let flags = uapi::get_status_flags(connection)?;
    if FileType::from_raw_mode(device.st_mode) != FileType::CharacterDevice
        || rustix::fs::major(device.st_rdev) != 10
        || rustix::fs::minor(device.st_rdev) != 229
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & libc::O_NONBLOCK == 0
    {
        return Err(Error::invalid(
            "worker FUSE role",
            "not the nonblocking 10:229 device role",
        ));
    }
    uapi::validate_connected_seqpacket(records)?;
    uapi::require_seqpacket_identity(records)?;
    let cancelled = rustix::fs::fstat(cancellation)
        .map_err(|source| kernel_error("inspect worker cancellation role", source))?;
    let flags = uapi::get_status_flags(cancellation)?;
    if FileType::from_raw_mode(cancelled.st_mode) != FileType::Fifo
        || cancelled.st_nlink != 0
        || cancelled.st_uid != 0
        || cancelled.st_gid != 0
        || cancelled.st_mode & 0o7777 != 0o600
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & libc::O_NONBLOCK == 0
    {
        return Err(Error::invalid(
            "worker cancellation role",
            "not the original unlinked read-only FIFO",
        ));
    }
    Ok(())
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| Error::Syscall {
        operation: "open fixed worker readback",
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Syscall {
            operation: "read fixed worker readback",
            source,
        })?;
    if bytes.len() > maximum {
        return Err(Error::invalid("worker readback", "exceeds fixed bound"));
    }
    Ok(bytes)
}

fn kernel_error(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}
