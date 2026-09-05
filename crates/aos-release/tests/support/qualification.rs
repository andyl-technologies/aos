//! Synthetic qualification records for protocol and rejection tests only.
//!
//! These fixtures are not measurements of an AOS image or a support claim.

use std::collections::BTreeMap;

use anyhow::Result;
use aos_release::digest::Sha256Digest;
use aos_release::qualification::capabilities::{
    CapabilityEvidence, ImageCapabilities, StageCapabilities,
};
use aos_release::qualification::claims::{AssessmentReference, CompatibilityAssessment};
use aos_release::qualification::environment::{
    Backend, CpuIdentity, DeviceInventory, EnvironmentInventory, LayerInventory,
};
use aos_release::qualification_evidence::QualificationCase;
use serde_json::{Value, json};

pub fn metadata() -> Result<Value> {
    let capabilities = ImageCapabilities {
        schema_version: "aos.image.capabilities/v1".into(),
        kernel_release: "synthetic-kernel".into(),
        kernel_config_digest: Sha256Digest::of_bytes("synthetic-kernel-config"),
        kernel_options: BTreeMap::from([("CONFIG_EFI".into(), "y".into())]),
        builtin_drivers: vec!["virtio_blk".into(), "virtio_net".into()],
        stages: ["runtime", "initrd", "recovery-a", "recovery-b"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    StageCapabilities {
                        modules: BTreeMap::new(),
                        firmware: BTreeMap::new(),
                    },
                )
            })
            .collect(),
    };
    Ok(
        json!({"schema_version":"aos.image.metadata/v2", "synthetic_protocol_fixture":true, "capabilities":capabilities}),
    )
}

pub fn capabilities(case: &QualificationCase) -> Result<Option<CapabilityEvidence>> {
    if !case
        .target
        .as_ref()
        .is_some_and(|target| target.kind == aos_release::qualification::TargetKind::Image)
    {
        return Ok(None);
    }
    let artifact = case.subjects.iter().find(|id| id.ends_with("/metadata"));
    artifact
        .map(|artifact| {
            Ok(CapabilityEvidence {
                metadata_artifact: artifact.clone(),
                metadata: metadata()?,
            })
        })
        .transpose()
}

pub fn environment(case: &QualificationCase) -> Result<Option<EnvironmentInventory>> {
    let Some(scope) = case
        .target
        .as_ref()
        .and_then(|target| target.environment.as_ref())
    else {
        return Ok(None);
    };
    let mut layers = Vec::new();
    for profile in &scope.layers {
        let mut backend = profile.backend.clone();
        let fields = match &mut backend {
            Backend::Physical { board, chipset } => vec![board, chipset],
            Backend::Qemu {
                machine_version,
                version,
                cpu_model,
                ..
            } => vec![machine_version, version, cpu_model],
            Backend::Cloud { region, .. } => vec![region],
            Backend::Container {
                version,
                cgroup,
                network,
                volume,
                ..
            } => vec![version, cgroup, network, volume],
        };
        for field in fields {
            field.get_or_insert_with(|| "synthetic".into());
        }
        layers.push(LayerInventory {
            platform: profile
                .platform
                .unwrap_or(aos_release::platform::Platform::X86_64Linux),
            backend,
            cpu: CpuIdentity {
                vendor: "synthetic-vendor".into(),
                model: "synthetic-model".into(),
                sku: Some("synthetic-sku".into()),
                revision: Some("synthetic-revision".into()),
                microcode: Some("synthetic-microcode".into()),
                features: Vec::new(),
            },
            kernel_release: Some("synthetic-kernel".into()),
        });
    }
    let capability_digest = if case
        .target
        .as_ref()
        .is_some_and(|target| target.kind == aos_release::qualification::TargetKind::Image)
    {
        let capabilities: ImageCapabilities =
            serde_json::from_value(metadata()?["capabilities"].clone())?;
        Some(capabilities.digest()?)
    } else {
        None
    };
    Ok(Some(EnvironmentInventory {
        schema_version: "aos.release.environment-inventory/v1".into(),
        layers,
        boot: scope.boot,
        firmware: Some("synthetic-firmware".into()),
        security: scope.security.clone(),
        resources: aos_release::qualification::environment::Resources {
            cpus: scope.resources.cpus.max(2),
            memory_mib: scope.resources.memory_mib.max(8192),
            disk_mib: scope.resources.disk_mib.max(32768),
        },
        devices: scope
            .devices
            .iter()
            .enumerate()
            .map(|(index, device)| DeviceInventory {
                address: format!("synthetic/{index}"),
                bus: device.bus.clone().unwrap_or("synthetic-bus".into()),
                vendor: device.vendor.clone(),
                product: device.product.clone(),
                revision: device.revision.clone(),
                driver: device.driver.clone(),
                firmware_revision: Some("synthetic-firmware".into()),
            })
            .collect(),
        image_capabilities_digest: capability_digest,
    }))
}

pub fn measurements() -> BTreeMap<String, u64> {
    [
        ("reboot_cycles", 10),
        ("cold_boot_cycles", 3),
        ("update_rollback_cycles", 3),
        ("lifecycle_cycles", 10),
        ("workload_operations", 100),
        ("data_integrity_failures", 0),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect()
}

pub fn assessment(case: &QualificationCase) -> Result<Option<CompatibilityAssessment>> {
    case.target
        .as_ref()
        .and_then(|target| target.environment.as_ref())
        .map(|scope| {
            Ok(CompatibilityAssessment {
                scope_digest: Sha256Digest::of_canonical(
                    "aos.release.environment-profile/v1",
                    scope,
                )?,
                rationale: "Synthetic protocol fixture; no compatibility assessment was performed"
                    .into(),
                reviewer: "synthetic-fixture".into(),
                references: vec![AssessmentReference {
                    digest: Sha256Digest::of_bytes("synthetic-reference"),
                    location: "synthetic-reference".into(),
                }],
            })
        })
        .transpose()
}
