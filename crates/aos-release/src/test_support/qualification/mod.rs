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
        "required_actions": [],
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
    let postconditions = postcondition_names
        .iter()
        .map(|name| {
            json!({
                "evidence_kind": postcondition_kinds[name],
                "name": name,
            })
        })
        .collect::<Vec<_>>();
    let adapters = ["fixture-a", "fixture-z"].map(|name| {
        let identity = vec!["fixture", "host", name, "fixture", name, "subject"];
        let identity_digest = Sha256Digest::of_bytes(
            aos_release::canonical::to_vec(&identity).expect("synthetic effect identity serializes")
        ).to_string();
        let effect_id = identity_digest.strip_prefix("sha256:")
            .expect("canonical digest contains its algorithm");
        let artifact = format!("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-{name}-handler");
        json!({
            "adapter": name,
            "conformance_families": ["durability-recovery"],
            "operation": {
                "ability": "fixture",
                "name": name,
                "input_type": {"kind":"submodule","fields":{},"open":false},
                "result_type": {"kind":"submodule","fields":{},"open":false},
            },
            "handler": {"kind":"process","artifact":artifact,"executable":format!("{artifact}/bin/handler")},
            "effects": [{"id":effect_id,"identity":identity,"revision":"d".repeat(64),"lifetime":"persistent","dependencies":[]}],
            "actions": ["apply"],
            "state_contract": {
                "resource_lifetimes": ["persistent"],
                "state_format": format!("sha256:{}", "b".repeat(64)),
            },
            "scope": ["fixture","host"],
        })
    });
    let cells = adapters
        .iter()
        .map(|adapter| {
            let name = adapter["adapter"]
                .as_str()
                .expect("synthetic adapter name is a string");
            json!({
                "id": format!(
                    "{name}/fixture/{name}/apply/durability-recovery/interrupt-before-acquisition"
                ),
                "matrix_schema": "aos.qualification.native-operation-matrix",
                "adapter": name,
                "operation": {"ability":"fixture","name":name},
                "action": "apply",
                "scenario": {"family":"durability-recovery","id":"interrupt-before-acquisition"},
                "scope": ["fixture","host"],
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
        "schema": "aos.qualification.native-operation-matrix-spec",
        "required_operations": [
            {"ability":"fixture","name":"fixture-a"},
            {"ability":"fixture","name":"fixture-z"},
        ],
        "surface": {
            "adapters": adapters,
            "families": ["durability-recovery"],
            "invalidation_dimensions": ["subject", "policy", "executor", "environment"],
            "matrix_schema": "aos.qualification.native-operation-matrix",
            "scenarios": [scenario],
            "schema": "aos.qualification.native-operation-matrix-surface",
        },
        "cells": cells,
        "applicability": {
            "schema": "aos.qualification.native-operation-matrix-applicability",
            "applicable_cell_ids": applicable_cell_ids,
            "inapplicable_cells": [],
        },
    });

    serde_json::from_value(value).expect("the synthetic native adapter matrix is valid")
}

pub fn metadata() -> Result<Value> {
    let capabilities = ImageCapabilities {
        configuration: Vec::new(),
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
    let Some(scope) = case.target.as_ref().map(|target| &target.environment) else {
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
        .map(|target| &target.environment)
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

/// Builds an authored one-cohort qualification specification for protocol tests.
pub(crate) fn native_operation_spec()
-> aos_release::qualification_evidence::NativeOperationQualificationSpec {
    let matrix_spec = native_adapter_matrix_spec();
    aos_release::qualification_evidence::NativeOperationQualificationSpec {
        schema: "aos.qualification.native-operation-spec".into(),
        required_operations: matrix_spec.required_operations.clone(),
        cohorts: vec![aos_release::qualification_evidence::NativeOperationCohortSpec {
            id: "synthetic-cohort".into(),
            matrix_spec,
            selected_evaluation: aos_release::qualification_evidence::NativeSelectedEvaluation {
                role: aos_release::qualification_evidence::NativeEvaluationRole::CandidateBaseline,
                locator: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-synthetic-evaluation".into(),
                scenario_sources: Vec::new(),
            },
            adoption_evaluation: aos_release::qualification_evidence::NativeSelectedEvaluation {
                role: aos_release::qualification_evidence::NativeEvaluationRole::CandidateBaseline,
                locator: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-synthetic-evaluation".into(),
                scenario_sources: Vec::new(),
            },
        }],
    }
}

/// Retains an observation in its exact synthetic authored cohort context.
pub(crate) fn native_cohort_observation(
    authored: &aos_release::qualification_evidence::NativeOperationCohortSpec,
    cells: Vec<aos_release::qualification_evidence::NativeAdapterCellObservation>,
) -> aos_release::qualification_evidence::NativeOperationCohortObservation {
    aos_release::qualification_evidence::NativeOperationCohortObservation {
        id: authored.id.clone(),
        matrix_spec: authored.matrix_spec.clone(),
        selected_evaluation: authored.selected_evaluation.clone(),
        adoption_evaluation: authored.adoption_evaluation.clone(),
        spec_digest: Sha256Digest::of_bytes(
            aos_release::canonical::to_vec(&authored.matrix_spec)
                .expect("synthetic matrix serializes"),
        ),
        adoption_digest: aos_contract::Sha256Digest::of_bytes("synthetic adopted baseline"),
        candidate_digest: Sha256Digest::of_bytes("synthetic candidate bytes"),
        cells,
    }
}
