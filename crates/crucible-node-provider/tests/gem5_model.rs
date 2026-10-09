//! Model-aware codec checks; parsing never creates native authority.

// crucible-lint: allow rust-allow -- These inert model codec fixtures must fail on invalid setup or an unmet assertion.
// crucible-lint: allow panic-shortcut -- Unwraps are confined to these single-shot model tests.
#![allow(clippy::unwrap_used)]

pub use crucible_node_provider::ProviderError;

pub use crucible_node_provider::gem5::{
    GEM5_NATIVE_FRAME_BYTES, Gem5Boundary, Gem5ExactRange, Gem5Run,
};

#[path = "../src/gem5/model.rs"]
pub mod model;

#[path = "../src/gem5/refusal.rs"]
pub mod refusal;

#[path = "support/gem5_arm_manifest_validation.rs"]
pub mod installed;

#[path = "support/gem5_model_continuation.rs"]
pub mod continuation;

mod codecs {
    pub use super::{Gem5Run, continuation, installed, model, refusal};

    pub fn validate_arm_scope(value: &serde_json::Value) -> Result<(), super::ProviderError> {
        installed::validate_scope(value)
    }
}

use codecs::model::*;
use crucible_node_contract::{Phase, Position, U64, canonical};
use serde_json::json;

fn asset(name: &str) -> Gem5ModelAsset {
    Gem5ModelAsset {
        file: name.into(),
        content: canonical::content_ref(b"fixed role bytes", "application/octet-stream").unwrap(),
        sha256: "a".repeat(64),
    }
}

fn arm() -> Gem5ModelSelection {
    Gem5ModelSelection::ArmLinux {
        kernel: Box::new(asset("kernel.elf")),
        initramfs: Box::new(asset("initrd.img")),
        firmware: Box::new(asset("boot_v2.arm64")),
        configuration: Gem5ConfigurationTree {
            files: 168.into(),
            bytes: 1319943.into(),
            sha256: "a".repeat(64),
        },
    }
}

fn boundary(ordinal: u64) -> Gem5Boundary {
    Gem5Boundary {
        tick: 1166530000.into(),
        ordinal: ordinal.into(),
        tick_ordinal: 1.into(),
        logical_position: Position::new(1166530000.into(), 1.into(), Phase::Publication),
        has_next_event: true,
        next_tick: 1166540000.into(),
        next_priority: 0,
        inventory: json!({"complete":false}),
    }
}

fn serial() -> Gem5SerialPublication {
    Gem5SerialPublication {
        output_id: 1.into(),
        tick: 1166530000.into(),
        event_ordinal: 116654.into(),
        tick_ordinal: 1.into(),
        causal_parent: 17.into(),
        facet: "serial".into(),
        terminal: "system.terminal".into(),
        payload: vec![91],
    }
}

fn ready() -> Gem5ArmNativeReady {
    let binding = |name| {
        let asset = asset(name);
        Gem5NativeAssetBinding {
            bytes: asset.content.length,
            sha256: asset.sha256,
        }
    };
    Gem5ArmNativeReady {
        kind: "ready".into(),
        schema: Gem5ModelDialect::ArmLinux,
        owner: crucible_node_contract::Id::new("serial-node").unwrap(),
        incarnation: crucible_node_contract::Id::new("source").unwrap(),
        generation: 1.into(),
        continuation: "original".into(),
        boundary: boundary(0),
        diagnostic_credit_policy: codecs::refusal::Gem5DiagnosticCreditPolicy {
            schema: "crucible.gem5.diagnostic-credit-policy.v1".into(),
            maximum_object_bytes: (64 * 1024 * 1024).into(),
            maximum_total_bytes: (256 * 1024 * 1024).into(),
            maximum_files: 1024.into(),
            refusal_schema: "crucible.gem5.run-refused.v1".into(),
        },
        model_scope: Gem5ArmNativeScope {
            schema: "crucible.gem5.model-scope.v1".into(),
            model_id: "arm-linux-vexpress-atomic-functional-v1".into(),
            full_system: true,
            complete_process_closure_qualified: false,
            cpu_timing_qualified: false,
            guest_readiness_qualified: false,
            guest_assets: Gem5ArmNativeAssets {
                kernel: binding("kernel.elf"),
                initramfs: binding("initrd.img"),
                firmware: binding("boot_v2.arm64"),
            },
            configuration_tree: Gem5ConfigurationTree {
                files: 168.into(),
                bytes: 1319943.into(),
                sha256: "a".repeat(64),
            },
        },
    }
}

#[test]
fn ready_requires_exact_original_owner_model_and_diagnostic_policy() {
    let original = ready();
    assert!(
        original
            .validate_selection(&arm(), &original.owner, &original.incarnation, 1.into())
            .is_ok()
    );
    let mut altered = original.clone();
    altered.diagnostic_credit_policy.maximum_files = 2048.into();
    assert!(
        altered
            .validate_selection(&arm(), &original.owner, &original.incarnation, 1.into())
            .is_err()
    );
    let mut altered = original.clone();
    altered.model_scope.guest_assets.kernel.sha256 = "b".repeat(64);
    assert!(
        altered
            .validate_selection(&arm(), &original.owner, &original.incarnation, 1.into())
            .is_err()
    );
    assert!(
        original
            .validate_selection(&arm(), &original.owner, &original.incarnation, 2.into())
            .is_err()
    );
}

#[test]
fn native_metadata_cannot_promote_its_own_admission() {
    let original = ready();
    let mut altered = original.clone();
    altered.model_scope.complete_process_closure_qualified = true;
    assert!(
        altered
            .validate_selection(&arm(), &original.owner, &original.incarnation, 1.into())
            .is_err()
    );
    let mut value = serde_json::to_value(original).unwrap();
    value["schema"] = json!("crucible.gem5.native/2");
    let old: Gem5ArmNativeReady = serde_json::from_value(value).unwrap();
    assert!(
        old.validate_selection(&arm(), &old.owner, &old.incarnation, 1.into())
            .is_err()
    );
}

#[test]
fn missing_credit_or_unknown_ready_fields_refuse_without_defaults() {
    let original = serde_json::to_value(ready()).unwrap();
    let mut altered = original.clone();
    altered
        .as_object_mut()
        .unwrap()
        .remove("diagnostic_credit_policy");
    assert!(serde_json::from_value::<Gem5ArmNativeReady>(altered).is_err());
    let mut altered = original;
    altered["optional_operator_admission"] = json!(true);
    assert!(serde_json::from_value::<Gem5ArmNativeReady>(altered).is_err());
}

#[test]
fn model_requires_its_explicit_dialect() {
    assert!(arm().validate_for(Gem5ModelDialect::ArmLinux).is_ok());
    for dialect in [Gem5ModelDialect::LegacySe, Gem5ModelDialect::ReservedSe] {
        assert!(arm().validate_for(dialect).is_err());
    }
    let se = Gem5ModelSelection::FreestandingO3 {
        guest_isa: "aarch64".into(),
        executable: asset("guest.elf"),
    };
    assert!(se.validate_for(Gem5ModelDialect::LegacySe).is_ok());
    assert!(se.validate_for(Gem5ModelDialect::ReservedSe).is_ok());
    assert!(se.validate_for(Gem5ModelDialect::ArmLinux).is_err());
}

#[test]
fn unknown_architecture_and_operator_asset_paths_refuse() {
    let se = Gem5ModelSelection::FreestandingO3 {
        guest_isa: "arbitrary".into(),
        executable: asset("guest.elf"),
    };
    assert!(se.validate_for(Gem5ModelDialect::ReservedSe).is_err());
    let mut model = arm();
    if let Gem5ModelSelection::ArmLinux { kernel, .. } = &mut model {
        kernel.file = "../caller.elf".into();
    }
    assert!(model.validate_for(Gem5ModelDialect::ArmLinux).is_err());
}

#[test]
fn asset_and_configuration_credit_precede_admission() {
    let mut model = arm();
    if let Gem5ModelSelection::ArmLinux { kernel, .. } = &mut model {
        kernel.content.length = U64::new(1024 * 1024 * 1024 + 1);
    }
    assert!(model.validate_for(Gem5ModelDialect::ArmLinux).is_err());
    let mut model = arm();
    if let Gem5ModelSelection::ArmLinux { configuration, .. } = &mut model {
        configuration.files = 4097.into();
    }
    assert!(model.validate_for(Gem5ModelDialect::ArmLinux).is_err());
}

#[test]
fn synthetic_stdout_fields_are_not_serial_receipts() {
    let mut value = serde_json::to_value(serial()).unwrap();
    value["guest_fd"] = json!(1);
    value["guest_pid"] = json!(100);
    assert!(serde_json::from_value::<Gem5SerialPublication>(value).is_err());
}

#[test]
fn actual_serial_birth_and_exact_original_parent_are_required() {
    let before = boundary(116653);
    let after = boundary(116654);
    assert!(
        serial()
            .validate_birth(&before, &after, 1.into(), 17.into())
            .is_ok()
    );
    let mut altered = serial();
    altered.event_ordinal = 116655.into();
    assert!(
        altered
            .validate_birth(&before, &after, 1.into(), 17.into())
            .is_err()
    );
    assert!(
        serial()
            .validate_birth(&before, &after, 2.into(), 17.into())
            .is_err()
    );
    assert!(
        serial()
            .validate_birth(&before, &after, 1.into(), 18.into())
            .is_err()
    );
    assert!(
        serial()
            .validate_birth(&after, &after, 1.into(), 17.into())
            .is_err()
    );
}

#[test]
fn embedded_nul_is_an_original_serial_byte() {
    let mut original = serial();
    original.payload[0] = 0;
    assert!(
        original
            .validate_birth(&boundary(116653), &boundary(116654), 1.into(), 17.into())
            .is_ok()
    );
    original.payload.clear();
    assert!(
        original
            .validate_birth(&boundary(116653), &boundary(116654), 1.into(), 17.into())
            .is_err()
    );
}

#[test]
fn actual_source_installed_arm_bundle_remeasures_and_never_grants_admission() {
    let mechanism = codecs::installed::InstalledArmMechanism::load().unwrap();
    assert_eq!(
        mechanism.document()["policy_id"],
        "arm-linux-vexpress-atomic-functional-v1"
    );
    assert!(mechanism.require_execution_admission().is_err());
}

#[test]
fn installed_model_or_admission_metadata_change_refuses() {
    let mechanism = codecs::installed::InstalledArmMechanism::load().unwrap();
    let original = mechanism.document();
    for pointer in [
        "/qualification/execution_admission_qualified",
        "/qualification/full_system_admission_qualified",
        "/qualification/cpu_timing_qualified",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(true);
        assert!(codecs::validate_arm_scope(&changed).is_err());
    }
    let mut changed = original.clone();
    changed["model"]["width"] = json!("32");
    assert!(codecs::validate_arm_scope(&changed).is_err());
    let mut changed = original.clone();
    changed["native_dialect"] = json!("crucible.gem5.native/3");
    assert!(codecs::validate_arm_scope(&changed).is_err());
}

fn continuation_fixture() -> codecs::continuation::ArmModelContinuation {
    let profile = canonical::content_ref(b"installed profile", "application/json").unwrap();
    let ready = ready();
    let operation = crucible_node_contract::Id::new("serial-prefix/1").unwrap();
    codecs::continuation::ArmModelContinuation {
        schema: "crucible.gem5.arm-model-continuation.v1".into(),
        installed_profile: profile,
        native_image: canonical::content_ref(b"native opaque image", "application/octet-stream")
            .unwrap(),
        model: arm(),
        dialect: Gem5ModelDialect::ArmLinux,
        diagnostic_policy: ready.diagnostic_credit_policy,
        common_operation: crucible_node_contract::Id::new("original/common").unwrap(),
        boundary: boundary(116654),
        held_prefix: Some(operation.clone()),
        last_acknowledged_prefix: None,
        refused_prefixes: vec![],
        successful_prefixes: vec![codecs::continuation::RetainedSerialPrefix {
            original: codecs::Gem5Run {
                kind: "run".into(),
                operation,
                exclusive_tick: 1166540000.into(),
                maximum_events: 1.into(),
                exact_range: None,
            },
            before: boundary(116653),
            after: boundary(116654),
            processed_events: 1.into(),
            publications: vec![serial()],
        }],
    }
}

#[test]
fn model_continuation_preserves_original_held_serial_without_authority() {
    let original = continuation_fixture();
    let raw = serde_json::to_vec(&original).unwrap();
    let restored: codecs::continuation::ArmModelContinuation =
        serde_json::from_slice(&raw).unwrap();
    assert_eq!(restored, original);
    assert!(
        restored
            .validate_originals(&original.installed_profile)
            .is_ok()
    );
}

#[test]
fn foreign_model_profile_and_duplicate_original_prefix_refuse() {
    let original = continuation_fixture();
    let other = canonical::content_ref(b"different installed profile", "application/json").unwrap();
    assert!(original.validate_originals(&other).is_err());
    let mut altered = original.clone();
    altered.dialect = Gem5ModelDialect::ReservedSe;
    assert!(
        altered
            .validate_originals(&original.installed_profile)
            .is_err()
    );
    let mut altered = original.clone();
    altered
        .successful_prefixes
        .push(altered.successful_prefixes[0].clone());
    assert!(
        altered
            .validate_originals(&original.installed_profile)
            .is_err()
    );
}

#[test]
fn continuation_cannot_fabricate_original_ack_or_callback_progress() {
    let original = continuation_fixture();
    let mut altered = original.clone();
    altered.last_acknowledged_prefix = altered.held_prefix.clone();
    assert!(
        altered
            .validate_originals(&original.installed_profile)
            .is_err()
    );
    let mut altered = original.clone();
    altered.successful_prefixes[0].processed_events = 0.into();
    assert!(
        altered
            .validate_originals(&original.installed_profile)
            .is_err()
    );
    let mut altered = original.clone();
    altered.successful_prefixes[0].publications[0].event_ordinal = 116655.into();
    assert!(
        altered
            .validate_originals(&original.installed_profile)
            .is_err()
    );
}
