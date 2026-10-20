//! Shares the fixed sandbox resource fold without creating a unit or cgroup.
//!
//! The optional numeric inputs are inert DATA. Compilation uses the existing
//! typed systemd resource validators in their original Host order; transport,
//! native readiness, pins and authority remain with their actual callers.

use std::time::Duration;

use crate::{Error, SandboxResources};

/// Describes the six numeric resource properties used by the nspawn recipe.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SandboxResourceRecipeV1 {
    /// The finite hard memory ceiling in bytes.
    pub memory_max_bytes: Option<u64>,
    /// The finite payload task ceiling.
    pub tasks_max: Option<u64>,
    /// The relative cgroup CPU weight.
    pub cpu_weight: Option<u64>,
    /// The finite open-file descriptor ceiling.
    pub open_files: Option<u64>,
    /// The optional allowed CPU runtime per second, in microseconds.
    pub cpu_quota_micros_per_second: Option<u64>,
    /// The optional relative block-I/O weight.
    pub io_weight: Option<u64>,
}

/// Preserves resource-shape refusal or the actual existing systemd validator.
#[derive(Debug, thiserror::Error)]
pub enum SandboxResourceRecipeErrorV1 {
    /// A mandatory numeric property is absent.
    #[error("mandatory {0} limit is absent")]
    Missing(&'static str),
    /// A mandatory numeric property is zero.
    #[error("mandatory {0} limit is zero")]
    Zero(&'static str),
    /// The optional CPU quota exceeds the unchanged Host range.
    #[error("CPU quota must be in 1..=1000000 microseconds")]
    CpuQuota,
    /// An existing typed transient-unit validator refused the same value.
    #[error(transparent)]
    Unit(#[from] Error),
}

impl SandboxResourceRecipeV1 {
    /// Bounds this pure fold's fixed carriers and bounded error text as bytes.
    ///
    /// The existing numeric validators produce only fixed-label messages here;
    /// two retained/display String growth lanes fit within the additional KiB.
    /// No namespace entries, descriptor, IO or financial authority is created.
    #[must_use]
    pub fn compilation_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<SandboxResources>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<SandboxResourceRecipeErrorV1>().checked_mul(2)?)?
            .checked_add(1024)
    }

    /// Compiles the existing fixed resource properties without native effects.
    ///
    /// The memory-high value retains the original ten-percent headroom rule.
    /// No I/O bandwidth limit is represented by this recipe.
    ///
    /// # Errors
    /// Preserves memory/task/CPU, open-file, quota, then I/O-weight refusal order.
    pub fn compile_v1(self) -> Result<SandboxResources, SandboxResourceRecipeErrorV1> {
        let memory_max = required(self.memory_max_bytes, "memory")?;
        let memory_high = memory_max.saturating_sub(memory_max / 10).max(1);
        let tasks_max = required(self.tasks_max, "process")?;
        let cpu_weight = required(self.cpu_weight, "CPU weight")?;
        let mut resources = SandboxResources::new(memory_high, memory_max, tasks_max, cpu_weight)?;
        resources = resources.with_open_file_limit(required(self.open_files, "open-file")?)?;
        if let Some(quota) = self.cpu_quota_micros_per_second {
            if quota == 0 || quota > 1_000_000 {
                return Err(SandboxResourceRecipeErrorV1::CpuQuota);
            }
            resources = resources.with_cpu_quota(Duration::from_micros(quota))?;
        }
        if let Some(weight) = self.io_weight {
            resources = resources.with_io_weight(weight)?;
        }
        Ok(resources)
    }
}

fn required(value: Option<u64>, label: &'static str)
    -> Result<u64, SandboxResourceRecipeErrorV1>
{
    let value = value.ok_or(SandboxResourceRecipeErrorV1::Missing(label))?;
    if value == 0 {
        return Err(SandboxResourceRecipeErrorV1::Zero(label));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> SandboxResourceRecipeV1 {
        SandboxResourceRecipeV1 {
            memory_max_bytes: Some(4096), tasks_max: Some(2), cpu_weight: Some(100),
            open_files: Some(32), cpu_quota_micros_per_second: Some(1), io_weight: Some(100),
        }
    }

    #[test]
    fn earlier_cpu_validator_precedes_a_later_missing_descriptor_limit() {
        let recipe = SandboxResourceRecipeV1 { cpu_weight: Some(10_001), open_files: None, ..valid() };

        let cause = recipe.compile_v1().unwrap_err();

        assert!(matches!(cause, SandboxResourceRecipeErrorV1::Unit(_)));
        assert!(cause.to_string().contains("CPU weight"));
    }

    #[test]
    fn quota_and_io_weight_keep_their_existing_inclusive_boundaries() {
        assert!(valid().compile_v1().is_ok());
        assert!(SandboxResourceRecipeV1 { cpu_quota_micros_per_second: Some(1_000_000),
            io_weight: Some(10_000), ..valid() }.compile_v1().is_ok());
        assert!(matches!(SandboxResourceRecipeV1 { cpu_quota_micros_per_second: Some(1_000_001),
            ..valid() }.compile_v1(), Err(SandboxResourceRecipeErrorV1::CpuQuota)));
        assert!(SandboxResourceRecipeV1 { io_weight: Some(10_001), ..valid() }.compile_v1().is_err());
    }
}
