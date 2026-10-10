//! Explicit deployed capacity for process tasks, descriptors, and paging I/O.

/// Immutable deployed host limits independent of campaign policy identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostOperationalCapacity {
    maximum_paging_io_slots: u64,
    maximum_task_slots: u64,
    maximum_file_descriptors: u64,
    maximum_metadata_bytes: u64,
    maximum_staging_bytes: u64,
}

/// Invalid deployed host resource capacity.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("host paging I/O, task, descriptor, metadata, and staging ceilings must all be nonzero")]
pub struct HostOperationalCapacityError;

impl HostOperationalCapacity {
    /// Validates independent explicit paging, task, and descriptor ceilings.
    ///
    /// # Errors
    /// Refuses any zero ceiling; no resource count is inferred from guest CPUs.
    pub fn new(
        maximum_paging_io_slots: u64,
        maximum_task_slots: u64,
        maximum_file_descriptors: u64,
        maximum_metadata_bytes: u64,
        maximum_staging_bytes: u64,
    ) -> Result<Self, HostOperationalCapacityError> {
        if [
            maximum_paging_io_slots,
            maximum_task_slots,
            maximum_file_descriptors,
            maximum_metadata_bytes,
            maximum_staging_bytes,
        ]
        .contains(&0)
        {
            return Err(HostOperationalCapacityError);
        }
        Ok(Self {
            maximum_paging_io_slots,
            maximum_task_slots,
            maximum_file_descriptors,
            maximum_metadata_bytes,
            maximum_staging_bytes,
        })
    }

    /// Returns the independently bounded metadata subset of the resident peak.
    pub const fn maximum_metadata_bytes(self) -> u64 {
        self.maximum_metadata_bytes
    }

    /// Returns the independently bounded transient resident and disk staging subset.
    pub const fn maximum_staging_bytes(self) -> u64 {
        self.maximum_staging_bytes
    }

    /// Returns the complete simultaneous paging-I/O ceiling.
    pub const fn maximum_paging_io_slots(self) -> u64 {
        self.maximum_paging_io_slots
    }

    /// Returns the complete host process and worker-task ceiling.
    pub const fn maximum_task_slots(self) -> u64 {
        self.maximum_task_slots
    }

    /// Returns the complete independently admitted descriptor ceiling.
    pub const fn maximum_file_descriptors(self) -> u64 {
        self.maximum_file_descriptors
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct HostOperationalUse {
    pub(super) paging_io_slots: u64,
    pub(super) task_slots: u64,
    pub(super) file_descriptors: u64,
    pub(super) metadata_bytes: u64,
    pub(super) staging_bytes: u64,
}

impl HostOperationalUse {
    pub(super) fn add(
        self,
        resources: crucible_linux_resource::ram_policy::HostResourceVector,
    ) -> Result<Self, crucible_api::host_operational::HostOperationalError> {
        Ok(Self {
            metadata_bytes: self
                .metadata_bytes
                .checked_add(resources.metadata_bytes)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            staging_bytes: self
                .staging_bytes
                .checked_add(resources.staging_bytes)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            paging_io_slots: self
                .paging_io_slots
                .checked_add(resources.paging_io_slots)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            task_slots: self
                .task_slots
                .checked_add(resources.task_slots)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            file_descriptors: self
                .file_descriptors
                .checked_add(resources.file_descriptors)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
        })
    }

    pub(super) fn subtract(
        self,
        resources: crucible_linux_resource::ram_policy::HostResourceVector,
    ) -> Result<Self, crucible_api::host_operational::HostOperationalError> {
        Ok(Self {
            metadata_bytes: self
                .metadata_bytes
                .checked_sub(resources.metadata_bytes)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            staging_bytes: self
                .staging_bytes
                .checked_sub(resources.staging_bytes)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            paging_io_slots: self
                .paging_io_slots
                .checked_sub(resources.paging_io_slots)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            task_slots: self
                .task_slots
                .checked_sub(resources.task_slots)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
            file_descriptors: self
                .file_descriptors
                .checked_sub(resources.file_descriptors)
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?,
        })
    }

    pub(super) fn fits(self, capacity: HostOperationalCapacity) -> bool {
        self.metadata_bytes <= capacity.maximum_metadata_bytes
            && self.staging_bytes <= capacity.maximum_staging_bytes
            && self.paging_io_slots <= capacity.maximum_paging_io_slots
            && self.task_slots <= capacity.maximum_task_slots
            && self.file_descriptors <= capacity.maximum_file_descriptors
    }
}
