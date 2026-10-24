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
            let resources = prepared.launch_resources();
            let smaps = fs::read_to_string(process.join("smaps")).map_err(|error| {
                loop_factory_error(format!("read prepared source process mappings: {error}"))
            })?;
            let regions = SourceMemoryRegions::from_smaps(&smaps, resources.guest_memory_bytes())?;
            usage.regions = usage
                .regions
                .checked_add(regions)
                .ok_or_else(|| loop_factory_error("source memory-region accounting overflowed"))?;
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
    regions: SourceMemoryRegions,
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

    /// Returns the measured memory breakdown by QEMU region class.
    #[must_use]
    pub const fn regions(self) -> SourceMemoryRegions {
        self.regions
    }
}

/// Retained QEMU memory split into guest RAM, TCG code buffer, and the rest.
///
/// Sums cover every prepared process of one source world. Guest RAM is each
/// private anonymous writable mapping at least as large as the configured
/// guest memory; the TCG code buffer is the executable anonymous or JIT memfd
/// mapping. Everything else is QEMU and plugin state. Resident and dirty
/// figures come from `/proc/<pid>/smaps`; proportional bytes divide pages
/// still shared with an ancestor template among its sharers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceMemoryRegions {
    /// Total resident bytes.
    pub resident_bytes: u64,
    /// Total proportional-set bytes.
    pub proportional_bytes: u64,
    /// Total private dirty bytes.
    pub private_dirty_bytes: u64,
    /// Resident bytes of guest RAM mappings.
    pub guest_resident_bytes: u64,
    /// Private dirty bytes of guest RAM mappings.
    pub guest_private_dirty_bytes: u64,
    /// Mapped size of the TCG code buffer.
    pub code_buffer_bytes: u64,
    /// Resident bytes of the TCG code buffer.
    pub code_resident_bytes: u64,
    /// Private dirty bytes of the TCG code buffer.
    pub code_private_dirty_bytes: u64,
}

impl SourceMemoryRegions {
    /// Classifies one process's `smaps` text.
    fn from_smaps(smaps: &str, guest_memory_bytes: u64) -> Result<Self, LifecycleApiError> {
        let mut regions = Self::default();
        let mut class = RegionClass::Other;
        for line in smaps.lines() {
            if let Some(header) = SmapsHeader::parse(line) {
                class = header.class(guest_memory_bytes);
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let field = match key {
                "Size" | "Rss" | "Pss" | "Private_Dirty" => key,
                _ => continue,
            };
            let bytes =
                required_proc_status_kib(&format!("{field}:{value}"), &format!("{field}:"))?
                    .checked_mul(1024)
                    .ok_or_else(|| loop_factory_error("source mapping accounting overflowed"))?;
            regions
                .record(class, field, bytes)
                .ok_or_else(|| loop_factory_error("source mapping accounting overflowed"))?;
        }
        Ok(regions)
    }

    fn record(&mut self, class: RegionClass, field: &str, bytes: u64) -> Option<()> {
        let add = |total: &mut u64| -> Option<()> {
            *total = total.checked_add(bytes)?;
            Some(())
        };
        match (field, class) {
            ("Size", RegionClass::Code) => add(&mut self.code_buffer_bytes),
            ("Size", _) => Some(()),
            ("Rss", class) => {
                add(&mut self.resident_bytes)?;
                match class {
                    RegionClass::Guest => add(&mut self.guest_resident_bytes),
                    RegionClass::Code => add(&mut self.code_resident_bytes),
                    RegionClass::Other => Some(()),
                }
            }
            ("Pss", _) => add(&mut self.proportional_bytes),
            ("Private_Dirty", class) => {
                add(&mut self.private_dirty_bytes)?;
                match class {
                    RegionClass::Guest => add(&mut self.guest_private_dirty_bytes),
                    RegionClass::Code => add(&mut self.code_private_dirty_bytes),
                    RegionClass::Other => Some(()),
                }
            }
            _ => Some(()),
        }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            resident_bytes: self.resident_bytes.checked_add(other.resident_bytes)?,
            proportional_bytes: self
                .proportional_bytes
                .checked_add(other.proportional_bytes)?,
            private_dirty_bytes: self
                .private_dirty_bytes
                .checked_add(other.private_dirty_bytes)?,
            guest_resident_bytes: self
                .guest_resident_bytes
                .checked_add(other.guest_resident_bytes)?,
            guest_private_dirty_bytes: self
                .guest_private_dirty_bytes
                .checked_add(other.guest_private_dirty_bytes)?,
            code_buffer_bytes: self
                .code_buffer_bytes
                .checked_add(other.code_buffer_bytes)?,
            code_resident_bytes: self
                .code_resident_bytes
                .checked_add(other.code_resident_bytes)?,
            code_private_dirty_bytes: self
                .code_private_dirty_bytes
                .checked_add(other.code_private_dirty_bytes)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegionClass {
    Guest,
    Code,
    Other,
}

/// One `smaps` mapping header: `start-end perms offset dev inode [path]`.
struct SmapsHeader<'a> {
    size: u64,
    perms: &'a str,
    inode: &'a str,
    path: &'a str,
}

impl<'a> SmapsHeader<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next()?.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        let perms = fields.next()?;
        if perms.len() != 4 {
            return None;
        }
        let _offset = fields.next()?;
        let _device = fields.next()?;
        let inode = fields.next()?;
        let path = fields.next().unwrap_or("");
        Some(Self {
            size: end.checked_sub(start)?,
            perms,
            inode,
            path,
        })
    }

    fn class(&self, guest_memory_bytes: u64) -> RegionClass {
        let anonymous =
            self.inode == "0" && (self.path.is_empty() || self.path.starts_with("[anon"));
        // Split-W^X code buffers alias one JIT memfd; otherwise TCG maps its
        // buffer as one private executable anonymous region.
        if self.path.contains("tcg-jit") || (anonymous && self.perms == "rwxp") {
            return RegionClass::Code;
        }
        if anonymous && self.perms == "rw-p" && self.size >= guest_memory_bytes {
            return RegionClass::Guest;
        }
        RegionClass::Other
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

    #[test]
    fn smaps_regions_split_guest_ram_code_buffer_and_the_rest() {
        let mebibyte = 1024 * 1024;
        // Guest RAM (512 MiB rw-p anonymous), an executable code buffer, a
        // smaller anonymous heap, and a file mapping.
        let smaps = "\
7f0000000000-7f0020000000 rw-p 00000000 00:00 0 \n\
Size:             524288 kB\n\
Rss:              204800 kB\n\
Pss:              102400 kB\n\
Private_Dirty:     51200 kB\n\
7f0040000000-7f0050000000 rwxp 00000000 00:00 0 \n\
Size:             262144 kB\n\
Rss:               65536 kB\n\
Pss:               65536 kB\n\
Private_Dirty:     65536 kB\n\
55aa00000000-55aa04000000 rw-p 00000000 00:00 0                          [heap]\n\
Size:              65536 kB\n\
Rss:               10240 kB\n\
Pss:               10240 kB\n\
Private_Dirty:     10240 kB\n\
55ab00000000-55ab00100000 r-xp 00000000 08:01 1234                       /qemu\n\
Size:               1024 kB\n\
Rss:                1024 kB\n\
Pss:                 512 kB\n\
Private_Dirty:         0 kB\n";

        let regions = SourceMemoryRegions::from_smaps(smaps, 512 * mebibyte)
            .unwrap_or_else(|error| panic!("well-formed smaps: {error}"));

        assert_eq!(regions.guest_resident_bytes, 200 * mebibyte);
        assert_eq!(regions.guest_private_dirty_bytes, 50 * mebibyte);
        assert_eq!(regions.code_buffer_bytes, 256 * mebibyte);
        assert_eq!(regions.code_resident_bytes, 64 * mebibyte);
        assert_eq!(regions.code_private_dirty_bytes, 64 * mebibyte);
        assert_eq!(regions.resident_bytes, (200 + 64 + 10 + 1) * mebibyte);
        assert_eq!(regions.private_dirty_bytes, (50 + 64 + 10) * mebibyte);
        assert_eq!(
            regions.proportional_bytes,
            (100 + 64 + 10) * mebibyte + mebibyte / 2
        );
    }

    #[test]
    fn smaps_regions_count_a_split_jit_memfd_as_code() {
        let smaps = "\
7f0040000000-7f0041000000 rw-s 00000000 00:01 77                         /memfd:tcg-jit (deleted)\n\
Size:              16384 kB\n\
Rss:                4096 kB\n\
Pss:                4096 kB\n\
Private_Dirty:         0 kB\n";

        let regions = SourceMemoryRegions::from_smaps(smaps, 512 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("well-formed smaps: {error}"));

        assert_eq!(regions.code_buffer_bytes, 16 * 1024 * 1024);
        assert_eq!(regions.code_resident_bytes, 4 * 1024 * 1024);
        assert_eq!(regions.guest_resident_bytes, 0);
    }
}
