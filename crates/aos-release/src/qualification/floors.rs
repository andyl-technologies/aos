//! Non-negotiable admission floors of the qualification contract.
//!
//! These are not a second configurable catalog. An operator cannot select a
//! contract with only an easy smoke gate, drop the QEMU/security baseline, or
//! weaken the cycle measurements below the release baseline.

use anyhow::{Result, bail};

use super::environment::{Accelerator, Backend};
use super::{QualificationContract, QualificationPhase, QualificationScope, TargetKind};
use crate::platform::Platform;

/// Mandatory requirement identities at their phase and scope.
const SHARED_REQUIREMENT_FLOORS: [(&str, QualificationPhase, QualificationScope); 9] = [
    (
        "build-integrity",
        QualificationPhase::Build,
        QualificationScope::Release,
    ),
    (
        "package-function",
        QualificationPhase::Staging,
        QualificationScope::Packages,
    ),
    (
        "image-installation",
        QualificationPhase::Staging,
        QualificationScope::Images,
    ),
    (
        "image-lifecycle",
        QualificationPhase::Staging,
        QualificationScope::Images,
    ),
    (
        "image-update-recovery",
        QualificationPhase::Staging,
        QualificationScope::Images,
    ),
    (
        "container-lifecycle",
        QualificationPhase::Staging,
        QualificationScope::Containers,
    ),
    (
        "staging-delivery",
        QualificationPhase::Staging,
        QualificationScope::Release,
    ),
    (
        "rollout-health",
        QualificationPhase::Rollout,
        QualificationScope::Release,
    ),
    (
        "rollout-observation",
        QualificationPhase::Complete,
        QualificationScope::Release,
    ),
];

/// Requires every mandatory requirement at its phase and scope.
///
/// # Errors
/// Returns an error when a mandatory requirement is absent or reclassified.
pub(super) fn validate_requirement_floors(contract: &QualificationContract) -> Result<()> {
    for (id, phase, scope) in SHARED_REQUIREMENT_FLOORS {
        if !contract
            .requirements
            .iter()
            .any(|gate| gate.id == id && gate.phase == phase && gate.scope == scope)
        {
            bail!("qualification contract lacks mandatory requirement {id}");
        }
    }
    Ok(())
}

/// Requires the typed QEMU/security baseline and observation measurements.
///
/// # Errors
/// Returns an error when a required image target lacks its accelerator or
/// security baseline, a per-configuration observation requirement is absent,
/// or a cycle measurement is weaker than the release baseline.
pub(super) fn validate_assurance_floors(contract: &QualificationContract) -> Result<()> {
    for (platform, accelerator) in [
        (Platform::X86_64Linux, Accelerator::Kvm),
        (Platform::Aarch64Linux, Accelerator::Tcg),
    ] {
        if !contract.targets.iter().any(|target| {
            target.required
                && target.platform == platform
                && target.kind == TargetKind::Image
                && target.environment.layers.last().is_some_and(|layer| {
                    matches!(&layer.backend,
                        Backend::Qemu { accelerator: actual, .. } if *actual == accelerator)
                })
                && target.environment.security.secure_boot
                && target.environment.security.measured_boot
                && target.environment.security.verity
                && target.environment.security.encrypted_state
                && target.environment.security.persistent_firmware
        }) {
            bail!("required QEMU/security baseline is missing for {platform}");
        }
    }
    for (id, scope) in [
        ("image-observation", QualificationScope::Images),
        ("container-observation", QualificationScope::Containers),
    ] {
        if !contract.requirements.iter().any(|gate| {
            gate.id == id && gate.scope == scope && gate.phase == QualificationPhase::Complete
        }) {
            bail!("qualification contract lacks per-configuration observation: {id}");
        }
    }
    for (requirement, measurement, minimum, maximum) in [
        ("image-installation", "reboot_cycles", 10, None),
        ("image-installation", "cold_boot_cycles", 3, None),
        ("image-update-recovery", "update_rollback_cycles", 3, None),
        ("container-lifecycle", "lifecycle_cycles", 10, None),
        ("image-observation", "workload_operations", 1, None),
        ("container-observation", "workload_operations", 1, None),
        ("image-observation", "data_integrity_failures", 0, Some(0)),
        (
            "container-observation",
            "data_integrity_failures",
            0,
            Some(0),
        ),
    ] {
        let bound = contract
            .requirements
            .iter()
            .find(|gate| gate.id == requirement)
            .and_then(|gate| gate.measurements.get(measurement))
            .ok_or_else(|| {
                anyhow::anyhow!("missing required measurement {requirement}/{measurement}")
            })?;
        if bound.minimum < minimum
            || maximum.is_some_and(|maximum| bound.maximum.is_none_or(|actual| actual > maximum))
        {
            bail!("measurement weakens the release baseline: {requirement}/{measurement}");
        }
    }
    Ok(())
}
