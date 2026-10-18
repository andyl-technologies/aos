//! Runtime application and verification of the bounded OpenZFS memory policy.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};

const MIB: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPolicy {
    pub max_bytes: u64,
    pub max_percent: u64,
    pub arc_percent: u64,
    pub dnode_percent: u64,
    pub scrub_percent: u64,
    pub dirty_data_percent: u64,
    pub system_free_reserve: u64,
    pub committed_percent_limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedPolicy {
    memory_bytes: u64,
    budget: u64,
    arc_max: u64,
    dnode_limit: u64,
    dirty_data_max: u64,
    scan_divisor: u64,
}

impl MemoryPolicy {
    pub fn parse(arguments: &[String]) -> Result<Self> {
        ensure!(
            arguments.len() == 8,
            "expected eight bounded memory-policy values"
        );
        let values = arguments
            .iter()
            .map(|value| value.parse::<u64>().context("parsing memory-policy value"))
            .collect::<Result<Vec<_>>>()?;
        let policy = Self {
            max_bytes: values[0],
            max_percent: values[1],
            arc_percent: values[2],
            dnode_percent: values[3],
            scrub_percent: values[4],
            dirty_data_percent: values[5],
            system_free_reserve: values[6],
            committed_percent_limit: values[7],
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn apply(&self) -> Result<()> {
        let resolved = self.resolve(read_memory_bytes()?)?;
        lower_parameter("/sys/module/zfs/parameters/zfs_arc_max", resolved.arc_max)?;
        lower_parameter(
            "/sys/module/zfs/parameters/zfs_arc_dnode_limit",
            resolved.dnode_limit,
        )?;
        lower_parameter(
            "/sys/module/zfs/parameters/zfs_dirty_data_max",
            resolved.dirty_data_max,
        )?;
        write_parameter(
            "/sys/module/zfs/parameters/zfs_scan_mem_lim_fact",
            resolved.scan_divisor,
        )?;
        let soft_limit = Path::new("/sys/module/zfs/parameters/zfs_scan_mem_lim_soft_fact");
        if soft_limit.exists() {
            write_parameter(soft_limit, resolved.scan_divisor)?;
        }
        println!(
            "OpenZFS memory budget {} MiB (ARC {} MiB, dirty data {} MiB, scan divisor {})",
            resolved.budget / MIB,
            resolved.arc_max / MIB,
            resolved.dirty_data_max / MIB,
            resolved.scan_divisor
        );
        Ok(())
    }

    pub fn verify(&self, package_version: &str) -> Result<()> {
        let resolved = self.resolve(read_memory_bytes()?)?;
        check_exact("/sys/module/spl/parameters/spl_kmem_cache_obj_per_slab", 1)?;
        check_at_most("/sys/module/zfs/parameters/zfs_arc_max", resolved.arc_max)?;
        check_at_most(
            "/sys/module/zfs/parameters/zfs_arc_dnode_limit",
            resolved.dnode_limit,
        )?;
        check_at_most(
            "/sys/module/zfs/parameters/zfs_dirty_data_max",
            resolved.dirty_data_max,
        )?;
        check_exact(
            "/sys/module/zfs/parameters/zfs_arc_sys_free",
            self.system_free_reserve,
        )?;
        check_exact(
            "/sys/module/zfs/parameters/zfs_scan_mem_lim_fact",
            resolved.scan_divisor,
        )?;
        reject_zvol_swap()?;
        verify_memory_commitment(resolved, self.committed_percent_limit)?;
        verify_module_version(package_version)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.max_bytes >= 512 * MIB, "max_bytes is below 512 MiB");
        ensure!(
            (1..=80).contains(&self.max_percent),
            "max_percent is invalid"
        );
        ensure!(
            (1..=100).contains(&self.arc_percent),
            "arc_percent is invalid"
        );
        ensure!(
            (1..=100).contains(&self.dnode_percent),
            "dnode_percent is invalid"
        );
        ensure!(
            (1..=100).contains(&self.scrub_percent),
            "scrub_percent is invalid"
        );
        ensure!(
            (1..=100).contains(&self.dirty_data_percent),
            "dirty_data_percent is invalid"
        );
        ensure!(
            self.arc_percent + self.scrub_percent + self.dirty_data_percent <= 100,
            "memory-policy shares exceed 100 percent"
        );
        ensure!(
            self.system_free_reserve < self.max_bytes,
            "system free reserve exceeds the memory ceiling"
        );
        ensure!(
            self.max_percent <= self.committed_percent_limit && self.committed_percent_limit <= 90,
            "committed memory limit is invalid"
        );
        Ok(())
    }

    fn resolve(&self, memory_bytes: u64) -> Result<ResolvedPolicy> {
        ensure!(memory_bytes > 0, "installed memory is zero");
        let proportional = percentage(memory_bytes, self.max_percent)?;
        let budget = self.max_bytes.min(proportional);
        let arc_max = percentage(budget, self.arc_percent)?;
        let dnode_limit = percentage(arc_max, self.dnode_percent)?;
        let dirty_data_max = percentage(budget, self.dirty_data_percent)?;
        let scrub_budget = percentage(budget, self.scrub_percent)?.max(1);
        let scan_divisor = (memory_bytes / scrub_budget).clamp(2, 10_000);
        Ok(ResolvedPolicy {
            memory_bytes,
            budget,
            arc_max,
            dnode_limit,
            dirty_data_max,
            scan_divisor,
        })
    }
}

fn percentage(value: u64, percent: u64) -> Result<u64> {
    value
        .checked_div(100)
        .and_then(|whole| whole.checked_mul(percent))
        .context("computing bounded memory-policy percentage")
}

fn read_memory_bytes() -> Result<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;
    let kilobytes = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .context("locating MemTotal in /proc/meminfo")?
        .parse::<u64>()
        .context("parsing MemTotal")?;
    kilobytes.checked_mul(1024).context("converting MemTotal")
}

fn read_parameter(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parsing {}", path.display()))
}

fn write_parameter(path: impl AsRef<Path>, value: u64) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, format!("{value}\n")).with_context(|| format!("writing {}", path.display()))
}

fn lower_parameter(path: impl AsRef<Path>, desired: u64) -> Result<()> {
    let path = path.as_ref();
    let current = read_parameter(path)?;
    if current == 0 || desired < current {
        write_parameter(path, desired)?;
    }
    Ok(())
}

fn check_exact(path: impl AsRef<Path>, expected: u64) -> Result<()> {
    let path = path.as_ref();
    let observed = read_parameter(path)?;
    ensure!(
        observed == expected,
        "{} is {observed}, expected {expected}",
        path.display()
    );
    Ok(())
}

fn check_at_most(path: impl AsRef<Path>, ceiling: u64) -> Result<()> {
    let path = path.as_ref();
    let observed = read_parameter(path)?;
    ensure!(
        observed > 0 && observed <= ceiling,
        "{} is {observed}, expected at most {ceiling}",
        path.display()
    );
    Ok(())
}

fn reject_zvol_swap() -> Result<()> {
    let swaps = fs::read_to_string("/proc/swaps").context("reading /proc/swaps")?;
    for device in swaps
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
    {
        ensure!(
            !device.starts_with("/dev/zvol/") && !is_zd_device(device),
            "swap device {device} is backed by OpenZFS and can deadlock under memory pressure"
        );
    }
    Ok(())
}

fn is_zd_device(device: &str) -> bool {
    device.strip_prefix("/dev/zd").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn verify_memory_commitment(resolved: ResolvedPolicy, limit_percent: u64) -> Result<()> {
    let mut committed = resolved.budget;
    let zram = Path::new("/sys/block");
    if zram.is_dir() {
        for entry in fs::read_dir(zram).context("reading /sys/block")? {
            let entry = entry.context("reading /sys/block entry")?;
            if entry.file_name().to_string_lossy().starts_with("zram") {
                committed = committed
                    .checked_add(read_parameter(entry.path().join("disksize"))?)
                    .context("summing ZFS and zram commitments")?;
            }
        }
    }
    let limit = percentage(resolved.memory_bytes, limit_percent)?;
    ensure!(
        committed <= limit,
        "OpenZFS and zram commit {} MiB above the {} MiB host limit",
        committed / MIB,
        limit / MIB
    );
    Ok(())
}

fn verify_module_version(package_version: &str) -> Result<()> {
    ensure!(
        !package_version.is_empty(),
        "packaged OpenZFS version is empty"
    );
    let running = fs::read_to_string("/sys/module/zfs/version")
        .context("reading running OpenZFS module version")?;
    ensure!(
        running.trim() == package_version,
        "running OpenZFS module {} differs from packaged version {package_version}",
        running.trim()
    );
    Ok(())
}

pub fn run(arguments: &[String], package_version: &str) -> Result<()> {
    let (action, values) = arguments
        .split_first()
        .context("expected apply or verify action")?;
    let policy = MemoryPolicy::parse(values)?;
    match action.as_str() {
        "apply" => policy.apply(),
        "verify" => policy.verify(package_version),
        _ => bail!("unsupported OpenZFS memory-policy action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MemoryPolicy {
        MemoryPolicy {
            max_bytes: 8 * 1024 * MIB,
            max_percent: 25,
            arc_percent: 70,
            dnode_percent: 25,
            scrub_percent: 10,
            dirty_data_percent: 15,
            system_free_reserve: 1024 * MIB,
            committed_percent_limit: 60,
        }
    }

    #[test]
    fn proportional_budget_binds_on_small_hosts() {
        let resolved = policy().resolve(4 * 1024 * MIB).expect("policy resolves");

        let budget = 4 * 1024 * MIB / 100 * 25;
        assert_eq!(resolved.budget, budget);
        assert_eq!(resolved.arc_max, budget / 100 * 70);
        assert_eq!(resolved.dnode_limit, resolved.arc_max / 100 * 25);
        assert_eq!(resolved.dirty_data_max, budget / 100 * 15);
        assert_eq!(resolved.scan_divisor, 40);
    }

    #[test]
    fn absolute_budget_binds_on_large_hosts() {
        let resolved = policy().resolve(128 * 1024 * MIB).expect("policy resolves");

        assert_eq!(resolved.budget, 8 * 1024 * MIB);
        assert_eq!(resolved.scan_divisor, 160);
    }

    #[test]
    fn rejects_collective_overcommit() {
        let mut policy = policy();
        policy.dirty_data_percent = 25;

        assert!(policy.validate().is_err());
    }
}
