//! Retained QEMU process measurement for managed hot-source admission.

use std::fs;
use std::path::PathBuf;

use super::*;

impl ProductionVmHotForkSourceWorld {
    /// Measures the stopped source world's retained QEMU process footprint.
    ///
    /// The measurement authenticates every prepared process incarnation, then
    /// accounts its total resident process memory, full configured guest-memory
    /// dirty budget in addition to current private dirties, open descriptors,
    /// vCPUs, and writable overlays. Daemon-side continuation allocations are
    /// outside this process profile. The result is an operational admission
    /// input and never enters campaign evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when a source incarnation changed, procfs
    /// usage cannot be read, or aggregate accounting overflows.
    pub fn measure_retained_resources(
        &mut self,
    ) -> Result<ProductionVmHotForkSourceWorldResourceUsage, LifecycleApiError> {
        self.validate_source_ownership()
            .map_err(|error| loop_factory_error(error.to_string()))?;
        let mut usage = ProductionVmHotForkSourceWorldResourceUsage::default();
        for prepared in &self.prepared {
            let identity = prepared.source_process_identity();
            let observed = crucible_qemu::linux_process_identity(identity.process_id)
                .map_err(|error| loop_factory_error(error.to_string()))?
                .ok_or_else(|| loop_factory_error("prepared source process disappeared"))?;
            if &observed != identity {
                return Err(loop_factory_error(
                    "prepared source process incarnation changed during resource measurement",
                ));
            }

            let process = PathBuf::from("/proc").join(identity.process_id.to_string());
            let status = fs::read_to_string(process.join("status")).map_err(|error| {
                loop_factory_error(format!("read prepared source process status: {error}"))
            })?;
            let resident_bytes = required_proc_status_kib(&status, "VmRSS:")?
                .checked_mul(1024)
                .ok_or_else(|| loop_factory_error("source resident-byte accounting overflowed"))?;
            let rollup = fs::read_to_string(process.join("smaps_rollup")).map_err(|error| {
                loop_factory_error(format!(
                    "read prepared source process memory rollup: {error}"
                ))
            })?;
            let private_dirty_bytes = required_proc_status_kib(&rollup, "Private_Dirty:")?
                .checked_mul(1024)
                .ok_or_else(|| loop_factory_error("source dirty-byte accounting overflowed"))?;
            let descriptor_count = fs::read_dir(process.join("fd"))
                .map_err(|error| {
                    loop_factory_error(format!("read prepared source descriptors: {error}"))
                })?
                .try_fold(0_u32, |count, entry| {
                    entry.map_err(|error| {
                        loop_factory_error(format!("inspect prepared source descriptor: {error}"))
                    })?;
                    count
                        .checked_add(1)
                        .ok_or_else(|| loop_factory_error("source descriptor count overflowed"))
                })?;

            let resources = prepared.launch_resources();
            usage.template_bytes = usage
                .template_bytes
                .checked_add(resident_bytes.max(resources.guest_memory_bytes()))
                .ok_or_else(|| loop_factory_error("source template-byte accounting overflowed"))?;
            let dirty_budget = private_dirty_bytes
                .checked_add(resources.guest_memory_bytes())
                .ok_or_else(|| loop_factory_error("source dirty-byte accounting overflowed"))?;
            usage.expected_private_dirty_bytes = usage
                .expected_private_dirty_bytes
                .checked_add(dirty_budget)
                .ok_or_else(|| loop_factory_error("source dirty-byte accounting overflowed"))?;
            usage.process_count = usage
                .process_count
                .checked_add(1)
                .ok_or_else(|| loop_factory_error("source process count overflowed"))?;
            usage.virtual_cpu_count = usage
                .virtual_cpu_count
                .checked_add(resources.virtual_cpus())
                .ok_or_else(|| loop_factory_error("source virtual-CPU count overflowed"))?;
            usage.descriptor_count = usage
                .descriptor_count
                .checked_add(descriptor_count)
                .ok_or_else(|| loop_factory_error("source descriptor count overflowed"))?;
            usage.overlay_count = usage
                .overlay_count
                .checked_add(u32::from(resources.has_root_overlay()))
                .ok_or_else(|| loop_factory_error("source overlay count overflowed"))?;
        }
        Ok(usage)
    }
}

fn required_proc_status_kib(status: &str, key: &str) -> Result<u64, LifecycleApiError> {
    let rest = status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or_else(|| loop_factory_error(format!("process accounting field `{key}` is absent")))?;
    let mut fields = rest.split_whitespace();
    let value = fields
        .next()
        .ok_or_else(|| loop_factory_error(format!("process accounting field `{key}` is empty")))?
        .parse::<u64>()
        .map_err(|error| {
            loop_factory_error(format!(
                "process accounting field `{key}` is not an unsigned integer: {error}"
            ))
        })?;
    if fields.next() != Some("kB") || fields.next().is_some() {
        return Err(loop_factory_error(format!(
            "process accounting field `{key}` must use the exact `kB` unit"
        )));
    }
    Ok(value)
}

/// Measured retained QEMU process resource usage used for hot admission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionVmHotForkSourceWorldResourceUsage {
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
}

impl ProductionVmHotForkSourceWorldResourceUsage {
    /// Returns retained source template bytes.
    #[must_use]
    pub const fn template_bytes(self) -> u64 {
        self.template_bytes
    }

    /// Returns the conservative private-dirty byte budget.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> u64 {
        self.expected_private_dirty_bytes
    }

    /// Returns the number of retained source processes.
    #[must_use]
    pub const fn process_count(self) -> u32 {
        self.process_count
    }

    /// Returns aggregate retained virtual CPUs.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> u32 {
        self.virtual_cpu_count
    }

    /// Returns the measured open descriptor count.
    #[must_use]
    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }

    /// Returns the number of retained writable root overlays.
    #[must_use]
    pub const fn overlay_count(self) -> u32 {
        self.overlay_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_accounting_requires_present_well_formed_kib_fields() {
        assert_eq!(
            required_proc_status_kib("VmRSS:\t1234 kB\n", "VmRSS:")
                .unwrap_or_else(|error| panic!("valid procfs accounting field: {error}")),
            1234
        );
        assert!(required_proc_status_kib("Name:\tqemu\n", "VmRSS:").is_err());
        assert!(required_proc_status_kib("VmRSS:\tunknown kB\n", "VmRSS:").is_err());
        assert!(required_proc_status_kib("VmRSS:\t1234 bytes\n", "VmRSS:").is_err());
        assert!(required_proc_status_kib("VmRSS:\t1234 kB trailing\n", "VmRSS:").is_err());
    }
}
