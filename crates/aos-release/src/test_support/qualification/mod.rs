//! Synthetic qualification records for protocol and rejection tests only.
//!
//! These fixtures are not measurements of an AOS image or a support claim.

use std::collections::BTreeMap;

use anyhow::Result;
use aos_ability_model::{AccessMode, LifecycleSemantics, ResourceLifetime};
use aos_release::digest::Sha256Digest;
use aos_release::qualification::capabilities::{
    CapabilityEvidence, ImageCapabilities, StageCapabilities,
};
use aos_release::qualification::claims::{AssessmentReference, CompatibilityAssessment};
use aos_release::qualification::environment::{
    Backend, CpuIdentity, DeviceInventory, EnvironmentInventory, LayerInventory,
};
use aos_release::qualification_evidence::{
    NativeAdapterClaimHandler, NativeAdapterDispositionPolicy, NativeAdapterImplementationClaim,
    NativeAdapterPostconditionPolicy, NativeAdapterProviderContract,
    NativeAdapterScenarioApplicability, NativeAdapterSurfaceAdapter, NativeAdapterSurfaceLimits,
    NativeAdapterSurfaceMethod, NativeAdapterSurfaceScenario, NativeAdapterSurfaceSpec,
    QualificationCase,
};
use serde_json::{Value, json};

mod contract;

pub use contract::contract;

/// Builds a small semantic native-adapter surface for verifier rejection tests.
pub(crate) fn native_adapter_surface() -> NativeAdapterSurfaceSpec {
    let digest = |label: &str| Sha256Digest::of_bytes(label);
    let artifact = |package: &str| {
        serde_json::json!({
            "path": format!("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{package}"),
            "selector": {
                "_type": "aos-package-output-selector",
                "package": package,
                "output": "out",
            },
        })
    };
    let adapter = |descriptor: Sha256Digest, adapter: &str, interface_name: &str| {
        NativeAdapterSurfaceAdapter {
            adapter: adapter.into(),
            conformance_families: vec!["durability-recovery".into()],
            interface_abi: 1,
            interface_descriptor: descriptor,
            interface_name: interface_name.into(),
            methods: vec![NativeAdapterSurfaceMethod {
                required_target_access: AccessMode::ExclusiveWrite,
                method: "apply".into(),
            }],
            observation_kind: "fixture-observation".into(),
            provider_contract: NativeAdapterProviderContract {
                lifecycle: LifecycleSemantics {
                    persistent_delete_method: None,
                },
                resource_lifetimes: vec![ResourceLifetime::Persistent],
                state_format: Some(digest("state format")),
            },
            provider_implementation: NativeAdapterImplementationClaim {
                contract: format!(
                    "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{adapter}-abilities"
                ),
                implementation: format!("{adapter}-implementation"),
                observer: NativeAdapterClaimHandler {
                    artifact: artifact(&format!("{adapter}-observer")),
                    entry_point: "bin/fixture-observer".into(),
                    arguments: serde_json::json!({"kind": "record"}),
                    result: serde_json::json!({"kind": "record"}),
                },
            },
            scope: "host-resource".into(),
        }
    };
    let probe_kind = |postcondition: &str| match postcondition {
        "durable-attempt-state-classified" => "journal-timeline",
        "at-most-one-resource-owner" => "ownership-inventory",
        "foreign-resources-unchanged" => "foreign-resource-snapshot",
        "dependent-effects-not-executed" => "dependency-barrier",
        _ => panic!("fixture postcondition has no probe kind"),
    };
    let disposition = |scenario: &str| match scenario {
        "interrupt-before-acquisition" => "rejected-before-acquisition",
        "lose-external-result" => "reconciled-completed",
        _ => panic!("fixture scenario has no disposition"),
    };
    let scenario = |id: &str, boundary: &str, failure: &str| {
        let postconditions = [
            "durable-attempt-state-classified",
            "at-most-one-resource-owner",
            "foreign-resources-unchanged",
            "dependent-effects-not-executed",
        ]
        .into_iter()
        .map(|name| NativeAdapterPostconditionPolicy {
            evidence_kind: probe_kind(name).into(),
            name: name.into(),
        })
        .collect();

        NativeAdapterSurfaceScenario {
            applicability: NativeAdapterScenarioApplicability {
                required_resource_lifetimes: Vec::new(),
                requires_state_format: false,
            },
            boundary: boundary.into(),
            candidate: "same".into(),
            disposition: NativeAdapterDispositionPolicy::Exact {
                value: disposition(id).into(),
            },
            failure: failure.into(),
            family: "durability-recovery".into(),
            id: id.into(),
            postconditions,
            predecessor: "same".into(),
        }
    };

    NativeAdapterSurfaceSpec {
        adapters: vec![
            adapter(digest("interface a"), "fixture-a", "aos.fixture-a-effects"),
            adapter(digest("interface z"), "fixture-z", "aos.fixture-z-effects"),
        ],
        families: vec!["durability-recovery".into()],
        invalidation_dimensions: vec![
            "subject".into(),
            "policy".into(),
            "executor".into(),
            "environment".into(),
        ],
        limits: NativeAdapterSurfaceLimits {
            max_adapters: 2,
            max_methods: 2,
            max_scenarios: 2,
        },
        matrix_schema: "aos.qualification.native-adapter-matrix/v1".into(),
        scenarios: vec![
            scenario(
                "interrupt-before-acquisition",
                "before-acquisition",
                "injected-interruption",
            ),
            scenario(
                "lose-external-result",
                "after-external-return",
                "lost-result",
            ),
        ],
        schema: "aos.qualification.native-adapter-surface/v1".into(),
        subject_schema: "aos.qualification.native-adapter-subject/v1".into(),
    }
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
