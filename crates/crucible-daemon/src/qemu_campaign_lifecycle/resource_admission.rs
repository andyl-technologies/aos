//! Fixed fresh-QEMU scenario resource admission.
//!
//! The check aggregates the launch material every scenario node needs before a
//! guarded lifecycle can create a guest process or writable artifact.

use crucible::ScenarioDefForm;
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::QemuLaunchResourceRequirements;
use thiserror::Error;

/// Failure to admit a scenario's fixed fresh-QEMU launch baseline.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuFreshScenarioResourceError {
    /// Summing a fixed per-node requirement exceeded its integer domain.
    #[error("fresh QEMU scenario {0} requirement overflowed")]
    Overflow(&'static str),
    /// The guarded attempt ceiling is below the scenario's fixed baseline.
    #[error(
        "fresh QEMU scenario requires {required} {field}, but the guarded attempt admits {admitted}"
    )]
    Capacity {
        /// Stable resource-field label.
        field: &'static str,
        /// Checked sum required before any guest launch.
        required: u64,
        /// Exact guarded attempt ceiling.
        admitted: u64,
    },
}

/// Validates a fresh scenario's fixed launch baseline before guest launch.
///
/// Every production node uses one writable root overlay and one exact-VMState
/// container. The resident baseline covers guest RAM; the admitted ceiling must
/// additionally reserve QEMU and plugin overhead, which the concrete cgroup
/// enforces for the complete attempt lifetime.
///
/// # Errors
///
/// Returns [`QemuFreshScenarioResourceError`] when checked aggregation
/// overflows or the admitted vCPU, resident-memory, or aggregate writable-byte
/// ceiling is below the scenario's fixed launch baseline.
pub fn validate_fresh_qemu_scenario_resources(
    source: &ScenarioDefForm,
    resources: AttemptResourceLimits,
) -> Result<(), QemuFreshScenarioResourceError> {
    let mut required_vcpus = 0_u64;
    let mut required_resident_bytes = 0_u64;
    let mut required_writable_bytes = 0_u64;

    for node in source.world().vm_nodes() {
        let requirements =
            QemuLaunchResourceRequirements::from_vm_shape(node.memory_mib, node.smp_vcpus, true);
        required_vcpus = required_vcpus
            .checked_add(u64::from(requirements.virtual_cpus()))
            .ok_or(QemuFreshScenarioResourceError::Overflow("vCPU"))?;
        required_resident_bytes = required_resident_bytes
            .checked_add(requirements.guest_memory_bytes())
            .ok_or(QemuFreshScenarioResourceError::Overflow("resident-memory"))?;
        required_writable_bytes = required_writable_bytes
            .checked_add(requirements.minimum_writable_bytes())
            .ok_or(QemuFreshScenarioResourceError::Overflow("writable-byte"))?;
    }

    require_capacity(
        "vCPUs",
        required_vcpus,
        u64::from(resources.maximum_vcpus()),
    )?;
    require_capacity(
        "resident bytes",
        required_resident_bytes,
        resources.maximum_resident_bytes(),
    )?;
    require_capacity(
        "writable bytes",
        required_writable_bytes,
        resources.maximum_disk_bytes(),
    )
}

fn require_capacity(
    field: &'static str,
    required: u64,
    admitted: u64,
) -> Result<(), QemuFreshScenarioResourceError> {
    if required > admitted {
        return Err(QemuFreshScenarioResourceError::Capacity {
            field,
            required,
            admitted,
        });
    }
    Ok(())
}
