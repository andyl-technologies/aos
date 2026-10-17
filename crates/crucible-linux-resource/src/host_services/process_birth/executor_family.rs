//! Pins the normal service's authenticated guardian and workload siblings.
//!
//! This witness owns checked leases from the existing main process. It proves
//! containment and liveness, never a native allocation grant or a new bank.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use super::{
    AuthenticatedProcessResources, HostServiceLease, HostServiceLeasePair, ServiceBirthError,
};

/// Retains the actual normal main's enclosing kernel family and original credit.
///
/// There is no public constructor or descriptor extraction. Callers retain this
/// value until all host workers and descendant processes physically retire.
pub struct AuthenticatedServiceFamily {
    guardian: File,
    workload: File,
    _descriptors: HostServiceLease,
    _controls: HostServiceLeasePair,
    owner: &'static AuthenticatedProcessResources,
    native_limits: OnceLock<NativeFamilyLimits>,
    native_limits_ready: AtomicBool,
}

/// Keeps an attempted aggregate assignment even after partial controller failure.
struct NativeFamilyLimits {
    cpu_quota_micros: u64,
    tasks: u64,
}

impl AuthenticatedProcessResources {
    /// Pins delegated siblings beneath this actual authenticated service root.
    ///
    /// The original counters reserve the complete witness and descriptor peak
    /// before any open. A matching directory alone never grants resources.
    ///
    /// # Errors
    /// Refuses absent delegation, expired original, exhausted remaining capacity,
    /// incompatible controls, changed membership or unsafe sibling directories.
    pub fn retain_executor_family(
        &'static self,
    ) -> Result<Arc<AuthenticatedServiceFamily>, ServiceBirthError> {
        if !self.is_live() || !self.birth.delegated_executor {
            return Err(ServiceBirthError::policy(
                "normal executor has no live delegated service birth",
            ));
        }
        let extent = AuthenticatedServiceFamily::control_bytes()?;
        let controls = self
            .reserve_metadata(extent)
            .map_err(ServiceBirthError::from)?;
        let descriptors = self
            .reserve_resident(0, 3, 0)
            .map_err(ServiceBirthError::from)?;
        // Failed partial opens close before the checked financing is released.
        let guardian = open_directory(self.birth._cgroup.as_fd(), "guardian")?;
        let workload = open_directory(self.birth._cgroup.as_fd(), "workload")?;
        let family = Arc::new(AuthenticatedServiceFamily {
            guardian,
            workload,
            _descriptors: descriptors,
            _controls: controls,
            owner: self,
            native_limits: OnceLock::new(),
            native_limits_ready: AtomicBool::new(false),
        });
        family.check()?;
        require_value(family.workload.as_fd(), "cgroup.procs", b"")?;
        // Empty direct membership alone misses surviving descendant processes.
        // Only initial issuance requires a wholly unpopulated, unfrozen workload;
        // later checks deliberately allow this purpose's live descendants.
        require_value(
            family.workload.as_fd(),
            "cgroup.events",
            b"populated 0\nfrozen 0\n",
        )?;
        Ok(family)
    }
}

impl AuthenticatedServiceFamily {
    fn control_bytes() -> Result<u64, ServiceBirthError> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Self>())
        .map_err(super::message)?;
        u64::try_from(layout.pad_to_align().size())
            .ok()
            .and_then(|n| n.checked_add(HostServiceLease::metadata_bytes().checked_mul(3)?))
            .ok_or_else(|| ServiceBirthError::policy("normal family control extent overflows"))
    }

    /// Checks the original main, host membership and all retained kernel pins.
    ///
    /// # Errors
    /// Refuses expiry, replaced siblings, changed complete limits or a caller
    /// outside the exact guardian. Successful checks do not renew the end.
    pub fn check(&self) -> Result<(), ServiceBirthError> {
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy("normal family original expired"));
        }
        self.check_retained_custody()?;
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy(
                "normal family original expired after check",
            ));
        }
        Ok(())
    }

    // Physical return checks the same pins and limits without renewing work
    // or requiring the birth interval to remain live. The caller must hold its
    // already-entered Cleanup before and after this structural observation.
    pub(super) fn check_retained_custody(&self) -> Result<(), ServiceBirthError> {
        if self.owner.birth.invocation == [0; 16] {
            return Err(ServiceBirthError::policy(
                "normal family invocation is absent",
            ));
        }
        let root = self.owner.birth._cgroup.as_fd();
        require_identity(
            self.guardian.as_fd(),
            open_directory(root, "guardian")?.as_fd(),
        )?;
        require_identity(
            self.workload.as_fd(),
            open_directory(root, "workload")?.as_fd(),
        )?;
        require_number(root, "memory.max", self.owner.birth.memory_max_bytes)?;
        require_number(root, "pids.max", self.owner.birth.tasks)?;
        require_value(root, "memory.swap.max", b"0\n")?;
        require_value(root, "cgroup.procs", b"")?;
        require_value(self.guardian.as_fd(), "memory.swap.max", b"0\n")?;
        require_value(self.workload.as_fd(), "memory.swap.max", b"0\n")?;
        let mut cpu = [0; 128];
        let body = read_control(root, "cpu.max", &mut cpu)?;
        let text = std::str::from_utf8(body).map_err(super::message)?;
        let mut fields = text.split_whitespace();
        if fields.next().and_then(|x| x.parse::<u64>().ok())
            != self.owner.birth.cpu_quota_percent.checked_mul(1000)
            || fields.next() != Some("100000")
            || fields.next().is_some()
        {
            return Err(ServiceBirthError::policy("normal family CPU bound changed"));
        }
        if let Some(limits) = self.native_limits.get() {
            if !self.native_limits_ready.load(Ordering::Acquire) {
                return Err(ServiceBirthError::policy(
                    "normal native family limit installation is incomplete",
                ));
            }
            require_native_limits(self.workload.as_fd(), limits)?;
        }
        let mut own = [0; 4096];
        let mut file = File::open("/proc/self/cgroup").map_err(super::message)?;
        let length = file.read(&mut own).map_err(super::message)?;
        let mut eof = [0];
        if file.read(&mut eof).map_err(super::message)? != 0
            || !super::matches_service_membership(
                std::str::from_utf8(&own[..length]).map_err(super::message)?,
                &self.owner.birth.group,
                true,
            )
        {
            return Err(ServiceBirthError::policy(
                "normal family host is outside its original guardian",
            ));
        }
        Ok(())
    }

    /// Installs the sole native subdivision's combined task and CPU ceilings.
    ///
    /// The already pinned workload is the common parent of source and target
    /// cgroups. Its aggregate limits conserve the original subdivision while
    /// permitting a lone source to use its full CPU rate. The caller permanently
    /// assigns the vector before entering this cut; no kernel value issues credit.
    /// Partial writes retain the attempted assignment and close future admission.
    ///
    /// # Errors
    /// Refuses invalid or increased limits, occupied custody, populated workload,
    /// original expiry, or failed controller writes and exact readback.
    pub(super) fn install_native_limits(
        &self,
        request: crate::ram_policy::HostResourceVector,
        original: &crate::host_supervision::HostOperationGuard,
    ) -> Result<(), ServiceBirthError> {
        self.check()?;
        original.wait_slice().map_err(ServiceBirthError::from)?;
        let limits = NativeFamilyLimits::new(request.cpu_slots, request.task_slots)?;
        require_value(self.workload.as_fd(), "cgroup.procs", b"")?;
        require_value(
            self.workload.as_fd(),
            "cgroup.events",
            b"populated 0\nfrozen 0\n",
        )?;
        require_monotonic_native_limits(self.workload.as_fd(), &limits)?;
        self.native_limits.set(limits).map_err(|_| {
            ServiceBirthError::policy("normal native family assignment is occupied")
        })?;
        let limits = self.native_limits.get().ok_or_else(|| {
            ServiceBirthError::policy("normal native family assignment is missing")
        })?;

        original.wait_slice().map_err(ServiceBirthError::from)?;

        // The same paid owner holds the provisional assignment before writes.
        // Never restore broader controls after an ambiguous or partial result.
        write_control(
            self.workload.as_fd(),
            "pids.max",
            format!("{}\n", limits.tasks).as_bytes(),
        )?;
        original.wait_slice().map_err(ServiceBirthError::from)?;
        write_control(
            self.workload.as_fd(),
            "cpu.max",
            format!("{} 100000\n", limits.cpu_quota_micros).as_bytes(),
        )?;
        original.wait_slice().map_err(ServiceBirthError::from)?;
        require_native_limits(self.workload.as_fd(), limits)?;
        original.wait_slice().map_err(ServiceBirthError::from)?;
        self.native_limits_ready.store(true, Ordering::Release);
        self.check()
    }

    /// Reads the installed native parent identity and aggregate kernel ceilings.
    ///
    /// The fixed fields are directory device, inode, CPU quota in microseconds,
    /// CPU period in microseconds, and task ceiling. They corroborate this same
    /// retained family and issue no account, descriptor or process permission.
    ///
    /// # Errors
    /// Refuses expired custody, incomplete installation, changed parent limits
    /// or unavailable actual directory identity.
    pub fn native_containment_readback(&self) -> Result<[u64; 5], ServiceBirthError> {
        self.check()?;
        let limits = self.native_limits.get().ok_or_else(|| {
            ServiceBirthError::policy("normal native parent limits were not installed")
        })?;
        let metadata = rustix::fs::fstat(&self.workload).map_err(super::message)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
            || metadata.st_ino == 0
        {
            return Err(ServiceBirthError::policy(
                "normal native parent identity is unavailable",
            ));
        }
        let fields = [
            metadata.st_dev,
            metadata.st_ino,
            limits.cpu_quota_micros,
            100_000,
            limits.tasks,
        ];
        self.check()?;
        Ok(fields)
    }

    /// Matches a factory's actual opened workload before any watcher birth.
    ///
    /// # Errors
    /// Refuses changed host custody or a directory from any other family.
    pub fn verify_workload_directory(&self, directory: impl AsFd) -> Result<(), ServiceBirthError> {
        self.check()?;
        require_identity(self.workload.as_fd(), directory.as_fd())?;
        self.check()
    }
}

fn open_directory(parent: BorrowedFd<'_>, name: &str) -> Result<File, ServiceBirthError> {
    let file = File::from(
        rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(super::message)?,
    );
    if rustix::fs::fstatfs(&file).map_err(super::message)?.f_type as u64
        != libc::CGROUP2_SUPER_MAGIC as u64
    {
        return Err(ServiceBirthError::policy(
            "normal family directory is not cgroup v2",
        ));
    }
    Ok(file)
}

fn require_identity(
    first: BorrowedFd<'_>,
    second: BorrowedFd<'_>,
) -> Result<(), ServiceBirthError> {
    let first = rustix::fs::fstat(first).map_err(super::message)?;
    let second = rustix::fs::fstat(second).map_err(super::message)?;
    if first.st_dev != second.st_dev || first.st_ino != second.st_ino {
        return Err(ServiceBirthError::policy(
            "normal family directory identity differs",
        ));
    }
    Ok(())
}

fn read_control<'a>(
    directory: BorrowedFd<'_>,
    name: &str,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], ServiceBirthError> {
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(super::message)?,
    );
    let length = file.read(buffer).map_err(super::message)?;
    let mut eof = [0];
    if file.read(&mut eof).map_err(super::message)? != 0 {
        return Err(ServiceBirthError::policy(
            "normal family control exceeds its bound",
        ));
    }
    Ok(&buffer[..length])
}

fn require_value(
    directory: BorrowedFd<'_>,
    name: &str,
    expected: &[u8],
) -> Result<(), ServiceBirthError> {
    let mut buffer = [0; 128];
    if read_control(directory, name, &mut buffer)? != expected {
        return Err(ServiceBirthError::policy(
            "normal family kernel control differs",
        ));
    }
    Ok(())
}

fn require_number(
    directory: BorrowedFd<'_>,
    name: &str,
    expected: u64,
) -> Result<(), ServiceBirthError> {
    let mut buffer = [0; 128];
    let body = read_control(directory, name, &mut buffer)?;
    if std::str::from_utf8(body)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        != Some(expected)
    {
        return Err(ServiceBirthError::policy(
            "normal family numeric kernel control differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

impl NativeFamilyLimits {
    fn new(cpu_slots: u64, tasks: u64) -> Result<Self, ServiceBirthError> {
        let cpu_quota_micros = cpu_slots
            .checked_mul(100_000)
            .filter(|quota| *quota != 0 && tasks != 0)
            .ok_or_else(|| ServiceBirthError::policy("normal native family limits overflow"))?;
        Ok(Self {
            cpu_quota_micros,
            tasks,
        })
    }
}

fn require_native_limits(
    directory: BorrowedFd<'_>,
    limits: &NativeFamilyLimits,
) -> Result<(), ServiceBirthError> {
    require_number(directory, "pids.max", limits.tasks)?;
    let mut buffer = [0; 128];
    let body = read_control(directory, "cpu.max", &mut buffer)?;
    let fields = cpu_limit_fields(body)?;
    if fields != (Some(limits.cpu_quota_micros), 100_000) {
        return Err(ServiceBirthError::policy(
            "normal native family CPU limit differs",
        ));
    }
    Ok(())
}

fn require_monotonic_native_limits(
    directory: BorrowedFd<'_>,
    requested: &NativeFamilyLimits,
) -> Result<(), ServiceBirthError> {
    let mut buffer = [0; 128];
    let body = read_control(directory, "pids.max", &mut buffer)?;
    let tasks = std::str::from_utf8(body)
        .map_err(super::message)?
        .trim_ascii_end();
    if tasks != "max"
        && tasks
            .parse::<u64>()
            .ok()
            .is_none_or(|prior| requested.tasks > prior)
    {
        return Err(ServiceBirthError::policy(
            "normal native family task limit would increase",
        ));
    }
    let body = read_control(directory, "cpu.max", &mut buffer)?;
    let (quota, period) = cpu_limit_fields(body)?;
    if quota.is_some_and(|prior| {
        u128::from(requested.cpu_quota_micros) * u128::from(period) > u128::from(prior) * 100_000
    }) {
        return Err(ServiceBirthError::policy(
            "normal native family CPU rate would increase",
        ));
    }
    Ok(())
}

fn cpu_limit_fields(body: &[u8]) -> Result<(Option<u64>, u64), ServiceBirthError> {
    let text = std::str::from_utf8(body).map_err(super::message)?;
    let mut fields = text.split_ascii_whitespace();
    let quota = match fields.next() {
        Some("max") => None,
        Some(number) => Some(number.parse::<u64>().map_err(super::message)?),
        None => {
            return Err(ServiceBirthError::policy(
                "normal family CPU quota is missing",
            ));
        }
    };
    let period = fields
        .next()
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| ServiceBirthError::policy("normal family CPU period is invalid"))?;
    if quota == Some(0) || fields.next().is_some() {
        return Err(ServiceBirthError::policy(
            "normal family CPU limit is malformed",
        ));
    }
    Ok((quota, period))
}

fn write_control(
    directory: BorrowedFd<'_>,
    name: &str,
    value: &[u8],
) -> Result<(), ServiceBirthError> {
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|source| ServiceBirthError::Kernel {
            operation: "open normal native family controller",
            source: source.into(),
        })?,
    );
    file.write_all(value)
        .map_err(|source| ServiceBirthError::Kernel {
            operation: "install normal native family controller",
            source,
        })
}
