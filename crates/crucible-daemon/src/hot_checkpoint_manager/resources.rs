//! Retained-resource dimensions, hard ceilings, aggregate usage, and pressure.

use super::*;

/// Exact resource cost attributed to one retained hot checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointResourceProfile {
    pub(super) template_bytes: u64,
    pub(super) expected_private_dirty_bytes: u64,
    pub(super) process_count: u32,
    pub(super) virtual_cpu_count: u32,
    pub(super) descriptor_count: u32,
    pub(super) overlay_count: u32,
}

impl HotCheckpointResourceProfile {
    /// Constructs one nonempty retained-template resource profile.
    ///
    /// Expected dirty bytes and overlay count may be zero. A live retained
    /// template must account at least one byte, process, virtual CPU, and
    /// descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointResourceProfileError`] when a required resource
    /// dimension is zero.
    pub const fn new(
        template_bytes: u64,
        expected_private_dirty_bytes: u64,
        process_count: u32,
        virtual_cpu_count: u32,
        descriptor_count: u32,
        overlay_count: u32,
    ) -> Result<Self, HotCheckpointResourceProfileError> {
        if template_bytes == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroTemplateBytes);
        }
        if process_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroProcesses);
        }
        if virtual_cpu_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroVirtualCpus);
        }
        if descriptor_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroDescriptors);
        }
        Ok(Self {
            template_bytes,
            expected_private_dirty_bytes,
            process_count,
            virtual_cpu_count,
            descriptor_count,
            overlay_count,
        })
    }

    /// Returns retained source-template bytes.
    #[must_use]
    pub const fn template_bytes(self) -> u64 {
        self.template_bytes
    }

    /// Returns expected private dirty bytes across admitted children.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> u64 {
        self.expected_private_dirty_bytes
    }

    /// Returns retained process count.
    #[must_use]
    pub const fn process_count(self) -> u32 {
        self.process_count
    }

    /// Returns retained virtual CPU count.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> u32 {
        self.virtual_cpu_count
    }

    /// Returns retained descriptor count.
    #[must_use]
    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }

    /// Returns retained writable-overlay count.
    #[must_use]
    pub const fn overlay_count(self) -> u32 {
        self.overlay_count
    }
}

/// Invalid retained-template resource profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointResourceProfileError {
    /// A retained template must occupy nonzero measured storage.
    #[error("hot-checkpoint template byte cost is zero")]
    ZeroTemplateBytes,
    /// A retained template must own at least one process.
    #[error("hot-checkpoint process count is zero")]
    ZeroProcesses,
    /// A retained template must account at least one virtual CPU.
    #[error("hot-checkpoint virtual-CPU count is zero")]
    ZeroVirtualCpus,
    /// A retained template must account at least one descriptor.
    #[error("hot-checkpoint descriptor count is zero")]
    ZeroDescriptors,
}

/// Process-wide ceilings for retained hot checkpoints and fork starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointLimits {
    pub(super) maximum_templates: usize,
    pub(super) maximum_resources: HotCheckpointResourceProfile,
    pub(super) maximum_forks_per_window: u32,
    pub(super) fork_rate_window_nanos: u64,
}

impl HotCheckpointLimits {
    /// Constructs reviewed process-wide hot-checkpoint ceilings.
    ///
    /// The resource profile supplies aggregate maxima rather than the cost of
    /// an individual template.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointLimitsError`] when the template ceiling is zero
    /// or above the daemon's static worker bound, or when the fork-rate ceiling
    /// or monotonic nanosecond window width is zero.
    pub const fn new(
        maximum_templates: usize,
        maximum_resources: HotCheckpointResourceProfile,
        maximum_forks_per_window: u32,
        fork_rate_window_nanos: u64,
    ) -> Result<Self, HotCheckpointLimitsError> {
        if maximum_templates == 0 {
            return Err(HotCheckpointLimitsError::ZeroTemplates);
        }
        if maximum_templates > MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS {
            return Err(HotCheckpointLimitsError::TooManyTemplates {
                requested: maximum_templates,
            });
        }
        if maximum_forks_per_window == 0 {
            return Err(HotCheckpointLimitsError::ZeroForkRate);
        }
        if fork_rate_window_nanos == 0 {
            return Err(HotCheckpointLimitsError::ZeroForkRateWindow);
        }
        Ok(Self {
            maximum_templates,
            maximum_resources,
            maximum_forks_per_window,
            fork_rate_window_nanos,
        })
    }

    /// Returns the retained-template count ceiling.
    #[must_use]
    pub const fn maximum_templates(self) -> usize {
        self.maximum_templates
    }

    /// Returns all aggregate retained-resource ceilings.
    #[must_use]
    pub const fn maximum_resources(self) -> HotCheckpointResourceProfile {
        self.maximum_resources
    }

    /// Returns the fork-start ceiling within one caller-defined rate window.
    #[must_use]
    pub const fn maximum_forks_per_window(self) -> u32 {
        self.maximum_forks_per_window
    }

    /// Returns the configured fixed window width in monotonic nanoseconds.
    #[must_use]
    pub const fn fork_rate_window_nanos(self) -> u64 {
        self.fork_rate_window_nanos
    }
}

/// Invalid process-wide hot-checkpoint limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointLimitsError {
    /// At least one hot-template slot is required.
    #[error("hot-checkpoint template limit is zero")]
    ZeroTemplates,
    /// The requested ceiling exceeds the daemon's static worker bound.
    #[error(
        "hot-checkpoint template limit {requested} exceeds {MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS}"
    )]
    TooManyTemplates {
        /// Rejected requested template count.
        requested: usize,
    },
    /// A rate window must admit at least one fork start.
    #[error("hot-checkpoint fork-rate limit is zero")]
    ZeroForkRate,
    /// A rate window must span at least one monotonic nanosecond.
    #[error("hot-checkpoint fork-rate window is zero nanoseconds")]
    ZeroForkRateWindow,
}

/// Aggregate resources currently retained by the manager.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointUsage {
    pub(super) templates: usize,
    pub(super) template_bytes: u64,
    pub(super) expected_private_dirty_bytes: u64,
    pub(super) process_count: u32,
    pub(super) virtual_cpu_count: u32,
    pub(super) descriptor_count: u32,
    pub(super) overlay_count: u32,
}

impl HotCheckpointUsage {
    /// Returns the retained-template count.
    #[must_use]
    pub const fn templates(self) -> usize {
        self.templates
    }

    /// Returns aggregate source-template bytes.
    #[must_use]
    pub const fn template_bytes(self) -> u64 {
        self.template_bytes
    }

    /// Returns aggregate expected private dirty bytes.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> u64 {
        self.expected_private_dirty_bytes
    }

    /// Returns aggregate retained processes.
    #[must_use]
    pub const fn process_count(self) -> u32 {
        self.process_count
    }

    /// Returns aggregate retained virtual CPUs.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> u32 {
        self.virtual_cpu_count
    }

    /// Returns aggregate retained descriptors.
    #[must_use]
    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }

    /// Returns aggregate retained writable overlays.
    #[must_use]
    pub const fn overlay_count(self) -> u32 {
        self.overlay_count
    }

    pub(super) fn add(self, profile: HotCheckpointResourceProfile) -> Option<Self> {
        Some(Self {
            templates: self.templates.checked_add(1)?,
            template_bytes: self.template_bytes.checked_add(profile.template_bytes)?,
            expected_private_dirty_bytes: self
                .expected_private_dirty_bytes
                .checked_add(profile.expected_private_dirty_bytes)?,
            process_count: self.process_count.checked_add(profile.process_count)?,
            virtual_cpu_count: self
                .virtual_cpu_count
                .checked_add(profile.virtual_cpu_count)?,
            descriptor_count: self
                .descriptor_count
                .checked_add(profile.descriptor_count)?,
            overlay_count: self.overlay_count.checked_add(profile.overlay_count)?,
        })
    }

    pub(super) fn remove(self, profile: HotCheckpointResourceProfile) -> Option<Self> {
        Some(Self {
            templates: self.templates.checked_sub(1)?,
            template_bytes: self.template_bytes.checked_sub(profile.template_bytes)?,
            expected_private_dirty_bytes: self
                .expected_private_dirty_bytes
                .checked_sub(profile.expected_private_dirty_bytes)?,
            process_count: self.process_count.checked_sub(profile.process_count)?,
            virtual_cpu_count: self
                .virtual_cpu_count
                .checked_sub(profile.virtual_cpu_count)?,
            descriptor_count: self
                .descriptor_count
                .checked_sub(profile.descriptor_count)?,
            overlay_count: self.overlay_count.checked_sub(profile.overlay_count)?,
        })
    }

    pub(super) fn fits(self, limits: HotCheckpointLimits) -> bool {
        let resources = limits.maximum_resources;
        self.templates <= limits.maximum_templates
            && self.template_bytes <= resources.template_bytes
            && self.expected_private_dirty_bytes <= resources.expected_private_dirty_bytes
            && self.process_count <= resources.process_count
            && self.virtual_cpu_count <= resources.virtual_cpu_count
            && self.descriptor_count <= resources.descriptor_count
            && self.overlay_count <= resources.overlay_count
    }
}

/// Resource dimensions exceeding the configured hot-retention limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointPressure {
    pub(super) templates: bool,
    pub(super) template_bytes: bool,
    pub(super) expected_private_dirty_bytes: bool,
    pub(super) process_count: bool,
    pub(super) virtual_cpu_count: bool,
    pub(super) descriptor_count: bool,
    pub(super) overlay_count: bool,
}

impl HotCheckpointPressure {
    pub(super) fn for_usage(usage: HotCheckpointUsage, limits: HotCheckpointLimits) -> Self {
        let resources = limits.maximum_resources;
        Self {
            templates: usage.templates > limits.maximum_templates,
            template_bytes: usage.template_bytes > resources.template_bytes,
            expected_private_dirty_bytes: usage.expected_private_dirty_bytes
                > resources.expected_private_dirty_bytes,
            process_count: usage.process_count > resources.process_count,
            virtual_cpu_count: usage.virtual_cpu_count > resources.virtual_cpu_count,
            descriptor_count: usage.descriptor_count > resources.descriptor_count,
            overlay_count: usage.overlay_count > resources.overlay_count,
        }
    }

    /// Returns whether retained-template count is over limit.
    #[must_use]
    pub const fn templates(self) -> bool {
        self.templates
    }

    /// Returns whether source-template bytes are over limit.
    #[must_use]
    pub const fn template_bytes(self) -> bool {
        self.template_bytes
    }

    /// Returns whether expected private dirty bytes are over limit.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> bool {
        self.expected_private_dirty_bytes
    }

    /// Returns whether process count is over limit.
    #[must_use]
    pub const fn process_count(self) -> bool {
        self.process_count
    }

    /// Returns whether virtual CPU count is over limit.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> bool {
        self.virtual_cpu_count
    }

    /// Returns whether descriptor count is over limit.
    #[must_use]
    pub const fn descriptor_count(self) -> bool {
        self.descriptor_count
    }

    /// Returns whether writable-overlay count is over limit.
    #[must_use]
    pub const fn overlay_count(self) -> bool {
        self.overlay_count
    }

    /// Returns whether any resource dimension is over limit.
    #[must_use]
    pub const fn any(self) -> bool {
        self.templates
            || self.template_bytes
            || self.expected_private_dirty_bytes
            || self.process_count
            || self.virtual_cpu_count
            || self.descriptor_count
            || self.overlay_count
    }
}
