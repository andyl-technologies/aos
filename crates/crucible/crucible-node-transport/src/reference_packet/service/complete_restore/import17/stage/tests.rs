//! Exercises all stage domains, exact assignments and closed predecessor DATA.

use super::*;
use crate::envelope::{Envelope, MessageKind};
use crucible_node_format::{Bytes, ContentRef, U64};
use serde_json::{Value, json};

pub(super) const PHASES: [PacketNativeImport17Stage; 3] = [
    PacketNativeImport17Stage::Arm,
    PacketNativeImport17Stage::World,
    PacketNativeImport17Stage::FirstObserve,
];

pub(super) fn reference(name: &str) -> ContentRef {
    canonical::content_ref(name.as_bytes(), "application/json").unwrap()
}

fn pair(name: &str) -> Value {
    json!({"original":reference(&format!("{name}-original")),
        "terminal":reference(&format!("{name}-terminal"))})
}

pub(super) fn bytes(byte: u8) -> Bytes {
    Bytes::new(vec![byte; 32])
}

fn fixture(phase: PacketNativeImport17Stage) -> Value {
    let prepare = json!({
        "schema": "source-owned.packet-native-import-prepare-receipt/17",
        "algorithm":PACKET_COMPLETE_RESTORE_ALGORITHM,
        "import_binding_digest": bytes(1), "context_digest": bytes(2),
        "prepare_digest":bytes(3), "input_roster":bytes(4), "transfer_token":bytes(5),
        "generation":"1", "native_sequence":"2", "assigned_response":bytes(6), "mac":bytes(7),
    });
    let commit = json!({
        "schema":"source-owned.packet-native-import-commit-receipt/17",
        "algorithm":PACKET_COMPLETE_RESTORE_ALGORITHM,
        "import_binding_digest":bytes(1), "context_digest":bytes(8), "commit_digest":bytes(9),
        "installed_mapping":reference("normalization18"), "transfer_token":bytes(5),
        "native_sequence":"3", "assigned_response":bytes(10), "mac":bytes(11),
    });
    json!({
        "schema":NATIVE_IMPORT17_STAGE_EXTENSION, "phase":phase,
        "import_binding_digest":bytes(1), "source_birth":reference("SourceBinding18"),
        "source_runtime":reference("Runtime"), "scope_proof":reference("Scope"),
        "target": {
            "native_pid":"1", "session":"stage-session", "incarnation":"stage-incarnation",
            "node":"stage-node", "owner":"stage-owner", "owner_generation":"1",
            "binding_hash":canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
            "world":canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
            "activation":"stage-activation", "generation":"1", "prepared_token":"stage-token",
            "gate":"stage-gate", "admission":"stage-admission", "transaction":"stage-transaction",
        },
        "prepare":{"pair":pair("prepare"), "receipt":prepare},
        "commit":{"pair":pair("commit"), "receipt":commit}, "hold":reference("held-record18"),
        "arm": if phase == PacketNativeImport17Stage::Arm {Value::Null} else {pair("arm")},
        "world":if phase == PacketNativeImport17Stage::FirstObserve {pair("world")} else {Value::Null},
        "native_allocation":{"retained_requested_bytes":"1",
            "maximum_simultaneous_transient_bytes":"2", "declared_counter_scratch_bytes":"3"},
    })
}

pub(super) fn binding(phase: PacketNativeImport17Stage) -> PacketNativeImport17StageBinding {
    serde_json::from_value(fixture(phase)).unwrap()
}

pub(super) fn original(binding: &PacketNativeImport17StageBinding) -> Envelope {
    let target = &binding.target;
    let mut original = crate::envelope::tests::request();
    original.method = binding.phase.method_data();
    original.operation_id.0 = None;
    original.session_id.0 = Some(target.session.clone());
    original.incarnation_id.0 = Some(target.incarnation.clone());
    original.node_id.0 = Some(target.node.clone());
    original.execution_owner_id.0 = Some(target.owner.clone());
    original.body = match binding.phase {
        PacketNativeImport17Stage::Arm => json!({
            "admission_id":target.admission, "activation_id":target.activation,
            "world_generation":target.generation, "prepared_token":target.prepared_token,
            "world_binding_hash":target.world, "gate_id":target.gate, "extensions":{},
        }),
        PacketNativeImport17Stage::World => json!({
            "transaction_id":target.transaction, "activation_id":target.activation,
            "world_generation":target.generation, "prepared_token":target.prepared_token,
            "world_binding_hash":target.world, "gate_id":target.gate,
            "activation_manifest":reference("World"), "extensions":{},
        }),
        PacketNativeImport17Stage::FirstObserve => json!({
            "binding_hash":target.binding_hash, "owner_generation":target.owner_generation,
            "after_observation_sequence":"0", "maximum_items":"1", "extensions":{},
        }),
    }
    .as_object()
    .unwrap()
    .clone();
    original.extensions.insert(
        NATIVE_IMPORT17_STAGE_EXTENSION.into(),
        serde_json::to_value(binding).unwrap(),
    );
    original
}

pub(super) fn context(
    binding: &PacketNativeImport17StageBinding,
    original: &Envelope,
) -> PacketNativeImport17StageContext {
    PacketNativeImport17StageContext {
        schema: "source-owned.packet-native-import-stage-context/17".into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        phase: binding.phase,
        birth_context_digest: bytes(12),
        stage_binding_digest: Bytes::new(binding.digest_data().unwrap().to_vec()),
        assigned_original_digest: Bytes::new(
            native_import18_stage_assigned_request_digest(original, binding.phase, 65536)
                .unwrap()
                .to_vec(),
        ),
    }
}

#[test]
fn all_three_complete_bindings_round_trip_with_mandatory_nullable_history() {
    for phase in PHASES {
        let value = fixture(phase);
        let binding = binding(phase);
        binding.validate_data().unwrap();
        assert_eq!(serde_json::to_value(&binding).unwrap(), value);
        for key in value.as_object().unwrap().keys() {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<PacketNativeImport17StageBinding>(missing).is_err(),
                "{phase:?}: {key}"
            );
        }
        for (arm, world) in [
            (Value::Null, Value::Null),
            (pair("arm"), Value::Null),
            (pair("arm"), pair("world")),
            (Value::Null, pair("world")),
        ] {
            let mut changed = value.clone();
            changed["arm"] = arm;
            changed["world"] = world;
            let parsed: PacketNativeImport17StageBinding = serde_json::from_value(changed).unwrap();
            let correct = match phase {
                PacketNativeImport17Stage::Arm => parsed.arm.is_none() && parsed.world.is_none(),
                PacketNativeImport17Stage::World => parsed.arm.is_some() && parsed.world.is_none(),
                PacketNativeImport17Stage::FirstObserve => {
                    parsed.arm.is_some() && parsed.world.is_some()
                }
            };
            assert_eq!(parsed.validate_data().is_ok(), correct);
        }
    }
}

#[test]
fn binding_refuses_foreign_receipts_tokens_targets_and_unknown_fields() {
    for phase in PHASES {
        let value = fixture(phase);
        for (path, replacement) in [
            (
                vec!["schema"],
                json!("source-owned.packet-restoration-activation/1"),
            ),
            (vec!["target", "native_pid"], json!("0")),
            (
                vec!["target", "native_pid"],
                json!((i32::MAX as u64 + 1).to_string()),
            ),
            (vec!["target", "owner_generation"], json!("0")),
            (
                vec!["prepare", "receipt", "schema"],
                json!("source-owned.packet-complete-restore-prepare-receipt/12"),
            ),
            (
                vec!["commit", "receipt", "transfer_token"],
                json!(bytes(20)),
            ),
            (
                vec!["commit", "receipt", "import_binding_digest"],
                json!(bytes(20)),
            ),
            (
                vec!["prepare", "receipt", "import_binding_digest"],
                json!(bytes(20)),
            ),
            (
                vec!["prepare", "pair", "terminal"],
                value["prepare"]["pair"]["original"].clone(),
            ),
            (vec!["hold", "media_type"], json!("application/cbor")),
            (
                vec!["native_allocation", "retained_requested_bytes"],
                json!("0"),
            ),
        ] {
            let mut changed = value.clone();
            let mut field = &mut changed;
            for key in path {
                field = &mut field[key];
            }
            *field = replacement;
            let parsed: PacketNativeImport17StageBinding = serde_json::from_value(changed).unwrap();
            assert!(parsed.validate_data().is_err());
        }
        for path in [
            vec![],
            vec!["target"],
            vec!["prepare"],
            vec!["prepare", "pair"],
            vec!["prepare", "receipt"],
            vec!["commit", "receipt"],
        ] {
            let mut changed = value.clone();
            let mut object = &mut changed;
            for key in path {
                object = &mut object[key];
            }
            object["unknown"] = json!(true);
            assert!(serde_json::from_value::<PacketNativeImport17StageBinding>(changed).is_err());
        }
    }
}

#[test]
fn context_joins_full_binding_birth_and_exact_baseline_target_assignment() {
    for phase in PHASES {
        let binding = binding(phase);
        let original = original(&binding);
        let context = context(&binding, &original);
        context
            .authenticate_stage18_data(&binding, &[12; 32], &original, 65536)
            .unwrap();
        assert!(
            context
                .authenticate_stage18_data(&binding, &[13; 32], &original, 65536)
                .is_err()
        );
        for (field, replacement) in [
            ("sequence", json!("2")),
            ("session_id", json!("other-session")),
            ("incarnation_id", json!("other-incarnation")),
            ("node_id", json!("other-node")),
            ("execution_owner_id", json!("other-owner")),
            ("request_id", json!("other-request")),
        ] {
            let mut changed = serde_json::to_value(&original).unwrap();
            changed[field] = replacement;
            let changed: Envelope = serde_json::from_value(changed).unwrap();
            assert!(
                context
                    .authenticate_stage18_data(&binding, &[12; 32], &changed, 65536)
                    .is_err()
            );
        }
        let mut changed = original.clone();
        changed
            .extensions
            .get_mut(NATIVE_IMPORT17_STAGE_EXTENSION)
            .unwrap()["hold"] = json!(reference("foreign-hold"));
        assert!(
            context
                .authenticate_stage18_data(&binding, &[12; 32], &changed, 65536)
                .is_err()
        );
        let field = if phase == PacketNativeImport17Stage::FirstObserve {
            "owner_generation"
        } else {
            "gate_id"
        };
        changed = original.clone();
        changed.body.insert(field.into(), json!("2"));
        assert!(
            context
                .authenticate_stage18_data(&binding, &[12; 32], &changed, 65536)
                .is_err()
        );
    }
}

#[test]
fn every_context_field_and_stage_domain_binds_proof_and_receipt() {
    for phase in PHASES {
        let binding = binding(phase);
        let original = original(&binding);
        let context = context(&binding, &original);
        let proof = native_import17_stage_proof_data(&[13; 32], &context).unwrap();
        let receipt = native_import17_stage_receipt_data(&[13; 32], &context, &[14; 32]).unwrap();
        verify_native_import17_stage_proof_data(&[13; 32], &context, &proof).unwrap();
        verify_native_import17_stage_receipt_data(&[13; 32], &context, &[14; 32], &receipt)
            .unwrap();
        assert!(verify_native_import17_stage_proof_data(&[14; 32], &context, &proof).is_err());
        assert!(
            verify_native_import17_stage_receipt_data(&[14; 32], &context, &[14; 32], &receipt)
                .is_err()
        );
        assert!(
            verify_native_import17_stage_receipt_data(&[13; 32], &context, &[15; 32], &receipt)
                .is_err()
        );
        for field in [
            "birth_context_digest",
            "stage_binding_digest",
            "assigned_original_digest",
        ] {
            let mut changed = serde_json::to_value(&context).unwrap();
            changed[field] = json!(bytes(20));
            let changed = serde_json::from_value(changed).unwrap();
            assert!(verify_native_import17_stage_proof_data(&[13; 32], &changed, &proof).is_err());
            assert!(
                verify_native_import17_stage_receipt_data(&[13; 32], &changed, &[14; 32], &receipt)
                    .is_err()
            );
        }
        for other in PHASES.into_iter().filter(|other| *other != phase) {
            let mut changed = serde_json::to_value(&context).unwrap();
            changed["phase"] = json!(other);
            let changed = serde_json::from_value(changed).unwrap();
            assert!(verify_native_import17_stage_proof_data(&[13; 32], &changed, &proof).is_err());
            assert!(
                verify_native_import17_stage_receipt_data(&[13; 32], &changed, &[14; 32], &receipt)
                    .is_err()
            );
        }
        for field in [
            "schema",
            "algorithm",
            "context_digest",
            "assigned_response",
            "physical_gate_held",
            "mac",
        ] {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            changed[field] = if field == "physical_gate_held" {
                json!(!receipt.physical_gate_held)
            } else if field == "schema" || field == "algorithm" {
                json!("foreign")
            } else {
                json!(bytes(20))
            };
            let changed = serde_json::from_value(changed).unwrap();
            assert!(
                verify_native_import17_stage_receipt_data(&[13; 32], &context, &[14; 32], &changed)
                    .is_err()
            );
        }
    }
}

#[test]
fn assignment_excludes_only_own_proof_and_receipt_and_requires_completed_terminal() {
    for phase in PHASES {
        let binding = binding(phase);
        let mut original = original(&binding);
        let digest =
            native_import18_stage_assigned_request_digest(&original, phase, 65536).unwrap();
        original
            .extensions
            .insert(phase.proof_extension().into(), json!({"inert":"proof"}));
        assert_eq!(
            native_import18_stage_assigned_request_digest(&original, phase, 65536).unwrap(),
            digest
        );
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(2);
        response.extensions.clear();
        response.body = json!({"status":"completed", "operation_state":"completed", "result":{}, "extensions":{}}).as_object().unwrap().clone();
        let terminal =
            native_import18_stage_assigned_response_digest(&original, &response, phase, 65536)
                .unwrap();
        response
            .extensions
            .insert(phase.receipt_extension().into(), json!({"inert":"receipt"}));
        assert_eq!(
            native_import18_stage_assigned_response_digest(&original, &response, phase, 65536)
                .unwrap(),
            terminal
        );
        for key in [
            "source-owned.packet-restoration-activation/1",
            "source-owned.packet-restoration-observation/1",
            "foreign",
        ] {
            let mut changed = original.clone();
            changed.extensions.insert(key.into(), json!({}));
            assert!(native_import18_stage_assigned_request_digest(&changed, phase, 65536).is_err());
            let mut changed = response.clone();
            changed.extensions.insert(key.into(), json!({}));
            assert!(
                native_import18_stage_assigned_response_digest(&original, &changed, phase, 65536)
                    .is_err()
            );
        }
        response
            .body
            .insert("operation_state".into(), json!("running"));
        assert!(
            native_import18_stage_assigned_response_digest(&original, &response, phase, 65536)
                .is_err()
        );
        original.extensions.remove(phase.proof_extension());
        assert!(
            native_import18_stage_assigned_response_digest(&original, &response, phase, 65536)
                .is_err()
        );
    }
}

#[test]
fn invalid_retained_predecessor_backing_remains_in_the_actual_census() {
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    let backing = |binding: &PacketNativeImport17StageBinding| {
        let mut observer = MetadataObserver::new();
        observer.observe(binding).unwrap();
        requested_metadata_backing_storage_data(&observer.finish()).unwrap()
    };
    for phase in PHASES {
        let mut binding = binding(phase);
        let before = backing(&binding);
        let prior = binding.prepare.receipt.schema.capacity();
        binding.prepare.receipt.schema.reserve(513);
        let delta = binding.prepare.receipt.schema.capacity() - prior;
        let removed = binding.prepare.receipt.transfer_token.allocation_capacity();
        binding.prepare.receipt.transfer_token = Bytes::default();
        // Release of the removed Vec is observed at its actual requested capacity.
        assert!(binding.validate_data().is_err());
        assert_eq!(backing(&binding), before + delta - removed);
    }
}

#[test]
fn compiled_stage18_field_rosters_match_every_complete_inner_record() {
    let contract: Value = serde_json::from_slice(
        &super::super::super::import18::native_import18_stage_contract_data().unwrap(),
    )
    .unwrap();
    for phase in PHASES {
        let binding = binding(phase);
        let original = original(&binding);
        let context = context(&binding, &original);
        let proof = native_import17_stage_proof_data(&[13; 32], &context).unwrap();
        let receipt = native_import17_stage_receipt_data(&[13; 32], &context, &[14; 32]).unwrap();
        for (name, value) in [
            ("binding", serde_json::to_value(&binding).unwrap()),
            ("target", serde_json::to_value(&binding.target).unwrap()),
            (
                "completed_prepare",
                serde_json::to_value(&binding.prepare).unwrap(),
            ),
            (
                "completed_commit",
                serde_json::to_value(&binding.commit).unwrap(),
            ),
            ("pair", serde_json::to_value(&binding.prepare.pair).unwrap()),
            ("context", serde_json::to_value(&context).unwrap()),
            ("proof", serde_json::to_value(&proof).unwrap()),
            ("receipt", serde_json::to_value(&receipt).unwrap()),
        ] {
            let declared: std::collections::BTreeSet<_> = contract[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| field.as_str().unwrap())
                .collect();
            let actual: std::collections::BTreeSet<_> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(actual, declared, "{name}");
        }
    }
}

#[test]
fn first_observe_requires_one_item_after_zero_even_with_a_recomputed_assignment() {
    let binding = binding(PacketNativeImport17Stage::FirstObserve);
    let original = original(&binding);
    for (field, replacement) in [
        ("after_observation_sequence", json!("1")),
        ("maximum_items", json!("0")),
        ("maximum_items", json!("2")),
        ("owner_generation", json!("2")),
    ] {
        let mut changed = original.clone();
        changed.body.insert(field.into(), replacement);
        let context = context(&binding, &changed);
        assert!(
            context
                .authenticate_stage18_data(&binding, &[12; 32], &changed, 65536)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn baseline_target_is_checked_independently_of_a_valid_assignment_digest() {
    for phase in [
        PacketNativeImport17Stage::Arm,
        PacketNativeImport17Stage::World,
    ] {
        let binding = binding(phase);
        let original = original(&binding);
        for field in [
            "activation_id",
            "world_generation",
            "prepared_token",
            "gate_id",
        ] {
            let mut changed = original.clone();
            changed.body.insert(field.into(), json!("2"));
            let context = context(&binding, &changed);
            assert!(
                context
                    .authenticate_stage18_data(&binding, &[12; 32], &changed, 65536)
                    .is_err(),
                "{phase:?}: {field}"
            );
        }
    }
}
