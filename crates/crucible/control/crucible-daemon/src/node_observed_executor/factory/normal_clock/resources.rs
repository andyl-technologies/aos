//! Retains genuine aggregate process ceilings and the Clock writable project.
//!
//! CPU, address space and descriptors belong to the shared daemon process,
//! including its other actors; they are never presented as exclusive per-node
//! quotas. RLIMIT_AS conservatively bounds that process's mapped resident and
//! reserved address space. Subprocesses need their own admitted owners. The
//! separately pinned ext4 project bounds aggregate blocks/inodes in the Clock
//! archive/branch tree, not arbitrary writes elsewhere in the daemon.
//!
//! Binding reads actual kernel enforcement. Deployment may configure those
//! process limits at the single-threaded entry point using the separate
//! bootstrap operation. Neither a ResourceLimits DTO nor an address-space
//! observation mints a source, class or native execution permission.
//!
//! Current mapped pages and every existing descriptor index are admitted as
//! well: lowering a ceiling cannot remove preexisting over-limit resources.

use std::{
    cell::Cell,
    fs::File,
    path::{Path, PathBuf},
    thread::ThreadId,
};

use aos_linux_project_quota::LinuxProjectQuotaBinding;
use crucible_engine::node_contract::RuntimeError;
use crucible_node_format::ResourceLimits;
use rustix::process::{Resource, Rlimit, getrlimit};

#[path = "resources/bootstrap.rs"]
mod bootstrap;

#[path = "resources/current.rs"]
mod current;

pub use bootstrap::OriginalClockProcessBootstrap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessCeilings {
    cpu: Rlimit,
    address_space: Rlimit,
    descriptors: Rlimit,
}

impl ProcessCeilings {
    fn current() -> Self {
        Self {
            cpu: getrlimit(Resource::Cpu),
            address_space: getrlimit(Resource::As),
            descriptors: getrlimit(Resource::Nofile),
        }
    }

    fn authenticate(&self, limits: &ResourceLimits) -> Result<(), RuntimeError> {
        // CPU limits are total hardware execution of this process since birth,
        // in whole seconds. Rounding down never increases the admitted budget.
        bounded(self.cpu, limits.cpu_budget_ns.get() / 1_000_000_000)?;
        bounded(self.address_space, limits.memory_bytes.get())?;
        bounded(self.descriptors, limits.descriptors.get())
    }
}

fn bounded(actual: Rlimit, maximum: u64) -> Result<(), RuntimeError> {
    match (actual.current, actual.maximum) {
        (Some(soft), Some(hard)) if maximum > 0 && soft > 0 && soft <= hard && hard <= maximum => {
            Ok(())
        }
        _ => Err(RuntimeError::ResourceLimit),
    }
}

/// Owns original kernel enforcement for the shared host and Clock writable tree.
///
/// The service actor retains this noncloneable owner through refusal and unwind.
/// Its failure is sticky. Dropping read-only quota pins never removes kernel
/// limits or releases the operator's project quota. Other actors' writable
/// roots and any actual subprocesses remain separately admitted obligations.
#[must_use = "retain original aggregate enforcement through all Clock ownership"]
pub struct OriginalClockAggregateResources {
    process: u32,
    thread: ThreadId,
    limits: ResourceLimits,
    ceilings: ProcessCeilings,
    root: PathBuf,
    quota: Option<LinuxProjectQuotaBinding>,
    root_file: Option<File>,
    project_id: u32,
    maximum_inodes: u64,
    state_attempted: bool,
    state_directories: [Option<File>; 4],
    failed: Cell<bool>,
}

impl OriginalClockAggregateResources {
    pub(super) fn charge_origin_storage_data(
        &self,
    ) -> Result<(), crate::node_qualification::QualificationError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(crate::node_qualification::QualificationError::Refused(
                "foreign Clock aggregate storage owner",
            ));
        }
        Ok(())
    }

    /// Lends the actual original writable environment, without a host pathname.
    pub(super) fn environment_data(&self) -> Result<(u64, u64, u32, u64), RuntimeError> {
        use std::os::unix::fs::MetadataExt;
        self.authenticate_current()?;
        let metadata = self
            .root_file
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?
            .metadata()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok((
            metadata.dev(),
            metadata.ino(),
            self.project_id,
            self.maximum_inodes,
        ))
    }

    /// Retains the actual owner before acquiring its original quota descriptor.
    ///
    /// The process must already have finite hard CPU/address-space/descriptor
    /// limits no greater than the supplied aggregate policy. The project must
    /// already enforce the given writable block and inode ceilings. This method
    /// installs no kernel policy and never treats a per-file limit as aggregate.
    ///
    /// # Errors
    /// Refuses an occupied slot, unbounded process limits, invalid policy/path,
    /// missing original quota, or changed creator/enforcement. Partial owners
    /// remain in the supplied slot; failure cannot reset their attempt.
    pub fn bind_current_into(
        slot: &mut Option<Self>,
        limits: &ResourceLimits,
        writable_root: &Path,
        project_id: u32,
        maximum_inodes: u64,
    ) -> Result<(), RuntimeError> {
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        use std::os::unix::ffi::OsStrExt;
        if !limits.extensions.is_empty()
            || limits.processes.get() == 0
            || limits.maximum_operations.get() == 0
            || limits.writable_bytes.get() < 1024
            || !writable_root.is_absolute()
            || writable_root.as_os_str().as_bytes().len() > 4096
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let ceilings = ProcessCeilings::current();
        ceilings.authenticate(limits)?;
        current::authenticate(ceilings)?;
        if ProcessCeilings::current() != ceilings {
            return Err(RuntimeError::ForeignAuthority);
        }
        *slot = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            limits: limits.clone(),
            ceilings,
            root: writable_root.to_owned(),
            quota: None,
            root_file: None,
            project_id,
            maximum_inodes,
            state_attempted: false,
            state_directories: [None, None, None, None],
            failed: Cell::new(true),
        });
        let owner = slot.as_mut().ok_or(RuntimeError::OutstandingObligations)?;
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt;
        owner.root_file = Some(File::from(
            open(
                &owner.root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RuntimeError::UnsupportedFacet)?,
        ));
        let metadata = owner
            .root_file
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .metadata()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        owner.quota = Some(
            LinuxProjectQuotaBinding::bind_existing(
                &owner.root,
                project_id,
                limits.writable_bytes.get(),
                maximum_inodes,
            )
            .map_err(|_| RuntimeError::UnsupportedFacet)?,
        );
        owner.failed.set(false);
        owner.authenticate_current()
    }

    /// Checks same-process aggregate enforcement and the same pinned project.
    ///
    /// This operational check never changes exact timestamps. It does not
    /// release a runtime, renew an attempt or authorize a new allocation.
    ///
    /// # Errors
    /// Refuses foreign origin, any prior failure, changed kernel limits, changed
    /// root/quota or exhausted quota. Failure permanently poisons this owner.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.failed.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.failed.set(true);
        let actual = ProcessCeilings::current();
        if actual != self.ceilings {
            return Err(RuntimeError::ForeignAuthority);
        }
        actual.authenticate(&self.limits)?;
        current::authenticate(actual)?;
        if ProcessCeilings::current() != actual {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.quota
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .verify()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        use std::os::unix::fs::MetadataExt;
        let original = self
            .root_file
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .metadata()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        let current =
            std::fs::symlink_metadata(&self.root).map_err(|_| RuntimeError::UnsupportedFacet)?;
        if !current.is_dir()
            || current.dev() != original.dev()
            || current.ino() != original.ino()
            || current.uid() != rustix::process::geteuid().as_raw()
            || current.mode() & 0o077 != 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.state_attempted {
            self.authenticate_state_directories()?;
        }
        self.failed.set(false);
        Ok(())
    }

    /// Checks actual retained runtime backing and named counter scratch.
    ///
    /// The kernel AS ceiling simultaneously covers all other mapped owners in
    /// the shared process. This additional owning walk refuses unknown nodes;
    /// it is not a refund, allocator peak certificate or prospective allocation
    /// grant. The same actor retains runtime and guard throughout the loan.
    ///
    /// # Errors
    /// Refuses stale enforcement, unsupported owner/scratch or exhausted bound.
    pub fn authenticate_runtime_data(
        &self,
        runtime: &crucible_engine::node_contract::NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current()?;
        self.failed.set(true);
        let maximum = usize::try_from(self.limits.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scratch = runtime.original_retained_requested_storage_precredit_scratch_data()?;
        let available = maximum
            .checked_sub(scratch)
            .ok_or(RuntimeError::ResourceLimit)?;
        runtime.original_retained_requested_storage_precredit_data(available)?;
        self.failed.set(false);
        self.authenticate_current()
    }

    /// Returns exact current hard/soft process ceiling data under the original guard.
    ///
    /// Rows are CPU seconds, address-space bytes and descriptors. This explicit
    /// aggregate scope is part of source environment identity, not a per-node
    /// resource lease or a replacement for independent source enrollment.
    ///
    /// # Errors
    /// Refuses a stale original process/project or any unbounded ceiling.
    pub fn process_ceiling_data(&self) -> Result<[(u64, u64); 3], RuntimeError> {
        self.authenticate_current()?;
        let rows = [
            self.ceilings.cpu,
            self.ceilings.address_space,
            self.ceilings.descriptors,
        ];
        let mut result = [(0, 0); 3];
        for (index, row) in rows.into_iter().enumerate() {
            result[index] = (
                row.current.ok_or(RuntimeError::ResourceLimit)?,
                row.maximum.ok_or(RuntimeError::ResourceLimit)?,
            );
        }
        Ok(result)
    }

    /// Borrows the original aggregate policy without issuing a quota or grant.
    pub fn limits_data(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Creates and retains the four private state/publication directories exactly once.
    ///
    /// Fixed children are created relative to the already pinned project root.
    /// Existing names refuse, including symlinks. Every new directory's actual
    /// inherited project assignment and same aggregate quota are reverified.
    /// Partial directories/descriptors remain retained through failure; this
    /// method never removes data or releases quota while a runtime exists.
    ///
    /// # Errors
    /// Refuses previous attempts, stale root, existing names, failed creation or
    /// missing inheritance. A failure poisons the same original guard.
    pub fn prepare_state_directories_once(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_current()?;
        if self.state_attempted {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.state_attempted = true;
        self.failed.set(true);
        use rustix::fs::{Mode, OFlags, mkdirat, openat};
        let root = self
            .root_file
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        for (index, name) in [
            "clock-archive",
            "clock-left",
            "clock-right",
            "clock-publications",
        ]
        .into_iter()
        .enumerate()
        {
            mkdirat(root, name, Mode::from_raw_mode(0o700))
                .map_err(|_| RuntimeError::ResourceLimit)?;
            self.state_directories[index] = Some(File::from(
                openat(
                    root,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| RuntimeError::UnsupportedFacet)?,
            ));
            LinuxProjectQuotaBinding::bind_existing(
                &self.root.join(name),
                self.project_id,
                self.limits.writable_bytes.get(),
                self.maximum_inodes,
            )
            .map_err(|_| RuntimeError::UnsupportedFacet)?
            .verify()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        }
        self.failed.set(false);
        self.authenticate_current()
    }

    fn authenticate_state_directories(&self) -> Result<(), RuntimeError> {
        self.failed.set(true);
        use std::os::unix::fs::MetadataExt;
        for (pin, name) in self.state_directories.iter().zip([
            "clock-archive",
            "clock-left",
            "clock-right",
            "clock-publications",
        ]) {
            let original = pin
                .as_ref()
                .ok_or(RuntimeError::OutstandingObligations)?
                .metadata()
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            let current = std::fs::symlink_metadata(self.root.join(name))
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            if !current.is_dir()
                || current.dev() != original.dev()
                || current.ino() != original.ino()
                || current.uid() != rustix::process::geteuid().as_raw()
                || current.mode() & 0o077 != 0
            {
                self.failed.set(true);
                return Err(RuntimeError::ForeignAuthority);
            }
            LinuxProjectQuotaBinding::bind_existing(
                &self.root.join(name),
                self.project_id,
                self.limits.writable_bytes.get(),
                self.maximum_inodes,
            )
            .map_err(|_| RuntimeError::UnsupportedFacet)?
            .verify()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        }
        self.failed.set(false);
        Ok(())
    }

    /// Returns the fixed archive path under the verified aggregate project.
    ///
    /// Caller-selected paths never replace this route. NativeArchive opens and
    /// retains its own NOFOLLOW directory descriptor under this private root.
    ///
    /// # Errors
    /// Refuses stale original process/root enforcement.
    pub fn archive_path_data(&self) -> Result<PathBuf, RuntimeError> {
        self.authenticate_current()?;
        self.authenticate_state_directories()?;
        Ok(self.root.join("clock-archive"))
    }

    /// Returns the fixed publication-store directory under the same real project.
    ///
    /// # Errors
    /// Refuses stale process/project or missing original directory ownership.
    pub fn publication_path_data(&self) -> Result<PathBuf, RuntimeError> {
        self.authenticate_current()?;
        self.authenticate_state_directories()?;
        Ok(self.root.join("clock-publications"))
    }

    /// Returns the two fixed independent branch namespaces under that project.
    ///
    /// # Errors
    /// Refuses stale original process/root enforcement.
    pub fn branch_paths_data(&self) -> Result<[PathBuf; 2], RuntimeError> {
        self.authenticate_current()?;
        self.authenticate_state_directories()?;
        Ok([self.root.join("clock-left"), self.root.join("clock-right")])
    }
}

#[cfg(test)]
#[path = "resources/tests.rs"]
mod tests;

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockAggregateResources {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), crate::node_qualification::QualificationError> {
        use crate::node_qualification::QualificationError;
        let Self {
            process,
            thread,
            limits,
            ceilings: _,
            root,
            quota,
            root_file: _,
            project_id: _,
            maximum_inodes: _,
            state_attempted: _,
            state_directories: _,
            failed: _,
        } = self;
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(QualificationError::Refused(
                "foreign Clock aggregate storage owner",
            ));
        }
        // Kernel enforcement/currentness remains a separate permission check.
        // File/OwnedFd slots are inline; this observes requested userspace data.
        counter.charge(limits)?;
        counter.charge(root)?;
        if let Some(quota) = quota {
            counter.add(quota.retained_requested_storage_data())?;
        }
        Ok(())
    }
}
