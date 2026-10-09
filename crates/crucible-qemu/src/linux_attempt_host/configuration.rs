//! Owns the exact validated process and storage configuration contract.
//!
//! Configuration validation precedes all namespace effects. This focused child
//! preserves the original field layout, constructors and fixed limit getters.

use super::*;

/// Validated configuration for one combined Linux QEMU attempt namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxQemuAttemptHostConfig {
    pub(super) process: LinuxQemuAttemptProcessConfig,
    pub(super) storage: LinuxQemuAttemptStorageConfig,
    maximum_node_host_service_tasks: u64,
    maximum_node_host_service_file_descriptors: u64,
    maximum_node_host_service_resident_bytes: u64,
    watcher_service_resident_bytes: u64,
}

impl LinuxQemuAttemptHostConfig {
    /// Validates one paired cgroup and project-quota namespace.
    ///
    /// The same daemon-incarnation name and distinct non-root child credentials
    /// are sealed into both allocators. Validation completes before either path
    /// is accessed.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] when any namespace,
    /// credential, task, project-ID, timeout, or inode bound is invalid.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        run_root: impl Into<PathBuf>,
        attempt_namespace: impl Into<String>,
        first_project_id: u32,
        project_id_count: u32,
        child_user_id: u32,
        child_group_id: u32,
        maximum_tasks: u32,
        maximum_file_descriptors: u64,
        maximum_node_host_service_tasks: u64,
        maximum_node_host_service_file_descriptors: u64,
        maximum_node_host_service_resident_bytes: u64,
        watcher_service_resident_bytes: u64,
        maximum_inodes: u64,
        finish_timeout: Duration,
    ) -> Result<Self, QemuVmRealizationError> {
        if maximum_node_host_service_tasks == 0
            || maximum_node_host_service_file_descriptors == 0
            || maximum_node_host_service_resident_bytes == 0
            || watcher_service_resident_bytes == 0
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "configure Linux node host-service resources",
                message: String::from(
                    "node host-service task and descriptor ceilings must be nonzero",
                ),
            });
        }
        let attempt_namespace = attempt_namespace.into();
        let process = LinuxQemuAttemptProcessConfig::new(
            cgroup_root,
            attempt_namespace.clone(),
            child_user_id,
            child_group_id,
            maximum_tasks,
            maximum_file_descriptors,
            finish_timeout,
        )?;
        let storage = LinuxQemuAttemptStorageConfig::new(
            run_root,
            attempt_namespace,
            first_project_id,
            project_id_count,
            child_user_id,
            child_group_id,
            maximum_inodes,
        )
        .map_err(|error| map_storage_error("configure QEMU attempt storage", &error))?;
        Ok(Self {
            process,
            storage,
            maximum_node_host_service_tasks,
            maximum_node_host_service_file_descriptors,
            maximum_node_host_service_resident_bytes,
            watcher_service_resident_bytes,
        })
    }

    /// Returns the delegated cgroup-v2 root.
    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        self.process.cgroup_root()
    }

    /// Returns the private ext4 attempt run root.
    #[must_use]
    pub fn run_root(&self) -> &Path {
        self.storage.run_root()
    }

    /// Returns the shared daemon-incarnation namespace.
    #[must_use]
    pub fn attempt_namespace(&self) -> &str {
        self.process.attempt_namespace()
    }

    /// Returns the distinct unprivileged QEMU user identifier.
    #[must_use]
    pub const fn child_user_id(&self) -> u32 {
        self.process.child_user_id()
    }

    /// Returns the distinct unprivileged QEMU group identifier.
    #[must_use]
    pub const fn child_group_id(&self) -> u32 {
        self.process.child_group_id()
    }

    /// Returns the hard cgroup task ceiling.
    #[must_use]
    pub const fn maximum_tasks(&self) -> u32 {
        self.process.maximum_tasks()
    }

    /// Sets the independently authored child memory-lock entitlement.
    ///
    /// # Errors
    /// Refuses the kernel infinity sentinel rather than grant an unbounded lock.
    pub fn with_maximum_locked_bytes(
        mut self,
        maximum_locked_bytes: u64,
    ) -> Result<Self, QemuVmRealizationError> {
        self.process = self
            .process
            .with_maximum_locked_bytes(maximum_locked_bytes)?;
        Ok(self)
    }

    /// Returns the exact hard and soft child memory-lock limit.
    #[must_use]
    pub const fn maximum_locked_bytes(&self) -> u64 {
        self.process.maximum_locked_bytes()
    }

    /// Returns the hard per-process file-descriptor ceiling.
    #[must_use]
    pub const fn maximum_file_descriptors(&self) -> u64 {
        self.process.maximum_file_descriptors()
    }

    /// Returns the explicitly retained per-node host-service task entitlement.
    #[must_use]
    pub const fn maximum_node_host_service_tasks(&self) -> u64 {
        self.maximum_node_host_service_tasks
    }

    /// Returns the explicitly retained per-node host-service descriptor entitlement.
    #[must_use]
    pub const fn maximum_node_host_service_file_descriptors(&self) -> u64 {
        self.maximum_node_host_service_file_descriptors
    }

    /// Returns the explicitly retained per-node host-service resident allowance.
    #[must_use]
    pub const fn maximum_node_host_service_resident_bytes(&self) -> u64 {
        self.maximum_node_host_service_resident_bytes
    }

    /// Returns the explicit resident allowance for each operational watcher.
    #[must_use]
    pub const fn watcher_service_resident_bytes(&self) -> u64 {
        self.watcher_service_resident_bytes
    }

    /// Returns the hard attempt artifact-entry and inode ceiling.
    #[must_use]
    pub const fn maximum_inodes(&self) -> u64 {
        self.storage.maximum_inodes()
    }
}
