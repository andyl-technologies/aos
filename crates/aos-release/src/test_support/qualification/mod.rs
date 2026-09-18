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
use aos_release::qualification_evidence::{NativeAdapterMatrixSpec, QualificationCase};
use serde_json::{Value, json};

mod contract;

pub use contract::contract;

/// Builds the smallest matrix fixture that exercises cross-adapter references.
///
/// Two adapters make ordering, duplicate-reference, and cross-cell replay tests
/// meaningful. The qualification contract and focused matrix tests share this
/// constructor so the synthetic matrix is authored only once.
pub(crate) fn native_adapter_matrix_spec() -> NativeAdapterMatrixSpec {
    let applicability = json!({
        "required_resource_lifetimes": [],
        "requires_state_format": false,
    });
    let disposition = json!({
        "kind": "exact",
        "value": "rejected-before-acquisition",
    });
    let postcondition_names = [
        "durable-attempt-state-classified",
        "at-most-one-resource-owner",
        "foreign-resources-unchanged",
        "dependent-effects-not-executed",
    ];
    let postcondition_kinds = BTreeMap::from([
        ("at-most-one-resource-owner", "ownership-inventory"),
        ("dependent-effects-not-executed", "dependency-barrier"),
        ("durable-attempt-state-classified", "journal-timeline"),
        ("foreign-resources-unchanged", "foreign-resource-snapshot"),
    ]);
    let postconditions = postcondition_kinds
        .iter()
        .map(|(name, evidence_kind)| {
            json!({
                "evidence_kind": evidence_kind,
                "name": name,
            })
        })
        .collect::<Vec<_>>();
    let adapters = [("fixture-a", 'a'), ("fixture-z", 'c')].map(|(name, digest_character)| {
        let descriptor = format!("sha256:{}", digest_character.to_string().repeat(64));
        json!({
            "adapter": name,
            "conformance_families": ["durability-recovery"],
            "interface_abi": 1,
            "interface_descriptor": descriptor,
            "interface_name": format!("aos.{name}-effects"),
            "methods": [{
                "required_target_access": "exclusive-write",
                "method": "apply",
            }],
            "observation_kind": "fixture-observation",
            "provider_contract": {
                "lifecycle": {"persistent_delete_method": null},
                "resource_lifetimes": ["persistent"],
                "state_format": format!("sha256:{}", "b".repeat(64)),
            },
            "provider_implementation": {
                "contract": format!(
                    "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{name}-abilities"
                ),
                "implementation": format!("{name}-implementation"),
                "observer": {
                    "artifact": {
                        "path": format!(
                            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{name}-observer"
                        ),
                        "selector": {
                            "_type": "aos-package-output-selector",
                            "output": "out",
                            "package": format!("{name}-observer"),
                        },
                    },
                    "entry_point": "bin/fixture-observer",
                    "arguments": {"kind": "record"},
                    "result": {"kind": "record"},
                },
            },
            "scope": "host-resource",
        })
    });
    let cells = adapters
        .iter()
        .map(|adapter| {
            let name = adapter["adapter"]
                .as_str()
                .expect("synthetic adapter name is a string");
            let interface = adapter["interface_name"]
                .as_str()
                .expect("synthetic interface name is a string");
            json!({
                "id": format!(
                    "{name}/{interface}/abi-1/apply/interrupt-before-acquisition"
                ),
                "matrix_schema": "aos.qualification.native-adapter-matrix/v1",
                "adapter": name,
                "interface": {
                    "name": interface,
                    "abi": 1,
                    "descriptor": adapter["interface_descriptor"],
                },
                "method": "apply",
                "required_target_access": "exclusive-write",
                "scope": "host-resource",
                "boundary": "before-acquisition",
                "failure": "injected-interruption",
                "predecessor": "same",
                "candidate": "same",
                "disposition": disposition,
                "applicability": applicability,
                "postconditions": postcondition_names,
                "postcondition_kinds": postcondition_kinds,
                "invalidated_by": ["subject", "policy", "executor", "environment"],
            })
        })
        .collect::<Vec<_>>();
    let applicable_cell_ids = cells
        .iter()
        .map(|cell| cell["id"].clone())
        .collect::<Vec<_>>();
    let scenario = json!({
        "applicability": applicability,
        "boundary": "before-acquisition",
        "candidate": "same",
        "disposition": disposition,
        "failure": "injected-interruption",
        "family": "durability-recovery",
        "id": "interrupt-before-acquisition",
        "postconditions": postconditions,
        "predecessor": "same",
    });
    let value = json!({
        "schema": "aos.qualification.native-adapter-matrix-spec/v1",
        "surface": {
            "adapters": adapters,
            "families": ["durability-recovery"],
            "invalidation_dimensions": ["subject", "policy", "executor", "environment"],
            "matrix_schema": "aos.qualification.native-adapter-matrix/v1",
            "scenarios": [scenario],
            "schema": "aos.qualification.native-adapter-surface/v1",
        },
        "cells": cells,
        "applicability": {
            "schema": "aos.qualification.native-adapter-matrix-applicability/v1",
            "applicable_cell_ids": applicable_cell_ids,
            "inapplicable_cells": [],
        },
    });

    serde_json::from_value(value).expect("the synthetic native adapter matrix is valid")
}

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
