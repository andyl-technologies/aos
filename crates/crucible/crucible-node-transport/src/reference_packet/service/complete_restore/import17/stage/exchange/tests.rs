//! Exercises complete carried exchanges and independently linked predecessor DATA.

use super::super::tests::{PHASES, binding, bytes, context, original};
use super::*;
use crate::envelope::MessageKind;
use crucible_node_format::U64;
use serde_json::json;

const KEY: [u8; 32] = [13; 32];
const BIRTH: [u8; 32] = [12; 32];
const MAXIMUM: usize = 65536;

struct Exchange {
    binding: PacketNativeImport17StageBinding,
    context: PacketNativeImport17StageContext,
    proof: PacketNativeImport17StageProof,
    receipt: PacketNativeImport17StageReceipt,
    original: Envelope,
    terminal: Envelope,
}

impl Exchange {
    fn complete(binding: PacketNativeImport17StageBinding) -> Self {
        let mut original = original(&binding);
        let context = context(&binding, &original);
        let proof = native_import17_stage_proof_data(&KEY, &context).unwrap();
        original
            .extensions
            .insert(binding.phase.proof_extension().into(), json!(proof));

        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        terminal.sequence = U64::new(2);
        terminal.extensions.clear();
        terminal.body = json!({"status":"completed", "operation_state":"completed",
            "result":baseline_result(&binding, &original), "extensions":{}})
        .as_object()
        .unwrap()
        .clone();
        let assigned = native_import18_stage_assigned_response_digest(
            &original,
            &terminal,
            binding.phase,
            MAXIMUM,
        )
        .unwrap();
        let receipt = native_import17_stage_receipt_data(&KEY, &context, &assigned).unwrap();
        terminal
            .extensions
            .insert(binding.phase.receipt_extension().into(), json!(receipt));
        Self {
            binding,
            context,
            proof,
            receipt,
            original,
            terminal,
        }
    }

    fn view(&self) -> PacketNativeImport18StageExchangeData<'_> {
        PacketNativeImport18StageExchangeData {
            binding: &self.binding,
            context: &self.context,
            proof: &self.proof,
            receipt: &self.receipt,
            original: &self.original,
            terminal: &self.terminal,
        }
    }

    fn pair(&self) -> PacketNativeImport17StagePairData {
        PacketNativeImport17StagePairData {
            original: canonical::content_ref(
                &bounded(&self.original, MAXIMUM).unwrap(),
                "application/json",
            )
            .unwrap(),
            terminal: canonical::content_ref(
                &bounded(&self.terminal, MAXIMUM).unwrap(),
                "application/json",
            )
            .unwrap(),
        }
    }
}

fn baseline_result(
    binding: &PacketNativeImport17StageBinding,
    original: &Envelope,
) -> serde_json::Value {
    let target = &binding.target;
    match binding.phase {
        PacketNativeImport17Stage::Arm => json!({
            "staged":true, "gate_id":target.gate, "staged_owner_ids":[target.owner],
            "activation_receipt":super::super::tests::reference("arm-evidence"),
        }),
        PacketNativeImport17Stage::World => json!({
            "armed_owner_ids":[target.owner], "gate_id":target.gate,
            "activation_receipt":super::super::tests::reference("world-evidence"),
        }),
        PacketNativeImport17Stage::FirstObserve => json!({
            "observations":[{
                "schema_version":1, "execution_owner_id":target.owner,
                "owner_binding_hash":target.binding_hash, "world_binding_hash":target.world,
                "activation_id":target.activation, "world_generation":target.generation,
                "owner_generation":target.owner_generation, "operation_id":original.request_id,
                "grant_id":null, "first_sequence":"0", "last_sequence":"0", "events":[],
                "visibility":"staged", "measurement_ref":super::super::tests::reference("native-proof"),
                "extensions":{},
            }], "next_sequence":"1", "complete":true,
            "inventory_hash":canonical::hash("source-owned.packet-inventory.v1", b"inventory").unwrap(),
        }),
    }
}

#[test]
fn complete_exchanges_require_the_actual_carried_proof_and_receipt() {
    for phase in PHASES {
        let mut exchange = Exchange::complete(binding(phase));
        exchange
            .view()
            .authenticate_data(&KEY, &BIRTH, MAXIMUM)
            .unwrap();
        exchange
            .view()
            .authenticate_pair_data(&exchange.pair(), &KEY, &BIRTH, MAXIMUM)
            .unwrap();
        assert!(
            exchange
                .view()
                .authenticate_data(&[14; 32], &BIRTH, MAXIMUM)
                .is_err()
        );
        assert!(
            exchange
                .view()
                .authenticate_data(&KEY, &[14; 32], MAXIMUM)
                .is_err()
        );
        assert!(exchange.view().authenticate_data(&KEY, &BIRTH, 1).is_err());

        let proof = exchange
            .original
            .extensions
            .remove(phase.proof_extension())
            .unwrap();
        assert!(
            exchange
                .view()
                .authenticate_data(&KEY, &BIRTH, MAXIMUM)
                .is_err()
        );
        let mut foreign = proof.clone();
        foreign["mac"] = json!(bytes(30));
        exchange
            .original
            .extensions
            .insert(phase.proof_extension().into(), foreign);
        // The separately supplied typed proof is still valid; the carried one is not.
        verify_native_import17_stage_proof_data(&KEY, &exchange.context, &exchange.proof).unwrap();
        assert!(
            exchange
                .view()
                .authenticate_data(&KEY, &BIRTH, MAXIMUM)
                .is_err()
        );
        exchange
            .original
            .extensions
            .insert(phase.proof_extension().into(), proof);

        let receipt = exchange
            .terminal
            .extensions
            .remove(phase.receipt_extension())
            .unwrap();
        assert!(
            exchange
                .view()
                .authenticate_data(&KEY, &BIRTH, MAXIMUM)
                .is_err()
        );
        let mut foreign = receipt.clone();
        foreign["mac"] = json!(bytes(30));
        exchange
            .terminal
            .extensions
            .insert(phase.receipt_extension().into(), foreign);
        assert!(
            exchange
                .view()
                .authenticate_data(&KEY, &BIRTH, MAXIMUM)
                .is_err()
        );
        exchange
            .terminal
            .extensions
            .insert(phase.receipt_extension().into(), receipt);
        exchange
            .view()
            .authenticate_data(&KEY, &BIRTH, MAXIMUM)
            .unwrap();
    }
}

#[test]
fn canonical_pair_checks_every_full_reference_field_and_both_frames() {
    for phase in PHASES {
        let exchange = Exchange::complete(binding(phase));
        for original in [true, false] {
            for field in ["algorithm", "domain", "digest", "length", "media_type"] {
                let mut pair = exchange.pair();
                let reference = if original {
                    &mut pair.original
                } else {
                    &mut pair.terminal
                };
                match field {
                    "algorithm" => reference.hash.algorithm = "foreign".into(),
                    "domain" => reference.hash.domain = "foreign".into(),
                    "digest" => reference.hash.digest = "a".repeat(64),
                    "length" => reference.length = U64::new(reference.length.get() + 1),
                    "media_type" => reference.media_type = "text/plain".into(),
                    _ => unreachable!(),
                }
                assert!(
                    exchange
                        .view()
                        .authenticate_pair_data(&pair, &KEY, &BIRTH, MAXIMUM)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn predecessors_require_the_same_completed_arm_and_world_chain() {
    let arm = Exchange::complete(binding(PacketNativeImport17Stage::Arm));
    let mut world_binding = binding(PacketNativeImport17Stage::World);
    world_binding.arm = Some(arm.pair());
    let world = Exchange::complete(world_binding);
    let mut observe = binding(PacketNativeImport17Stage::FirstObserve);
    observe.arm = Some(arm.pair());
    observe.world = Some(world.pair());

    arm.binding
        .authenticate_predecessors_data(None, None, &KEY, &BIRTH, MAXIMUM)
        .unwrap();
    world
        .binding
        .authenticate_predecessors_data(Some(&arm.view()), None, &KEY, &BIRTH, MAXIMUM)
        .unwrap();
    observe
        .authenticate_predecessors_data(
            Some(&arm.view()),
            Some(&world.view()),
            &KEY,
            &BIRTH,
            MAXIMUM,
        )
        .unwrap();
    for (arm_input, world_input) in [
        (None, None),
        (Some(arm.view()), None),
        (None, Some(world.view())),
    ] {
        assert!(
            observe
                .authenticate_predecessors_data(
                    arm_input.as_ref(),
                    world_input.as_ref(),
                    &KEY,
                    &BIRTH,
                    MAXIMUM
                )
                .is_err()
        );
    }
    assert!(
        world
            .binding
            .authenticate_predecessors_data(Some(&world.view()), None, &KEY, &BIRTH, MAXIMUM)
            .is_err()
    );
    assert!(
        arm.binding
            .authenticate_predecessors_data(Some(&arm.view()), None, &KEY, &BIRTH, MAXIMUM)
            .is_err()
    );

    // A second valid Arm proof and pair cannot replace World's recorded Arm.
    let mut other_arm_binding = binding(PacketNativeImport17Stage::Arm);
    other_arm_binding.native_allocation.retained_requested_bytes = U64::new(2);
    let other_arm = Exchange::complete(other_arm_binding);
    other_arm
        .view()
        .authenticate_data(&KEY, &BIRTH, MAXIMUM)
        .unwrap();
    observe.arm = Some(other_arm.pair());
    assert!(
        observe
            .authenticate_predecessors_data(
                Some(&other_arm.view()),
                Some(&world.view()),
                &KEY,
                &BIRTH,
                MAXIMUM
            )
            .is_err()
    );
}

#[test]
fn valid_macs_and_matching_pair_refs_cannot_splice_foreign_predecessor_history() {
    let baseline = binding(PacketNativeImport17Stage::Arm);
    let value = json!(baseline);
    for path in [
        vec!["import_binding_digest"],
        vec!["source_birth"],
        vec!["source_runtime"],
        vec!["scope_proof"],
        vec!["target", "native_pid"],
        vec!["target", "transaction"],
        vec!["hold"],
        vec!["prepare", "pair", "original"],
        vec!["prepare", "receipt", "mac"],
        vec!["commit", "pair", "terminal"],
        vec!["commit", "receipt", "mac"],
    ] {
        let mut changed = value.clone();
        let mut field = &mut changed;
        for name in &path {
            field = &mut field[*name];
        }
        *field = if path.last() == Some(&"native_pid") {
            json!("2")
        } else if path.last() == Some(&"transaction") {
            json!("foreign-transaction")
        } else if field.is_object() {
            json!(super::super::tests::reference("foreign"))
        } else {
            json!(bytes(30))
        };
        if path == ["import_binding_digest"] {
            changed["prepare"]["receipt"]["import_binding_digest"] =
                changed["import_binding_digest"].clone();
            changed["commit"]["receipt"]["import_binding_digest"] =
                changed["import_binding_digest"].clone();
        }
        let foreign = Exchange::complete(serde_json::from_value(changed).unwrap());
        foreign
            .view()
            .authenticate_data(&KEY, &BIRTH, MAXIMUM)
            .unwrap();
        let mut world = binding(PacketNativeImport17Stage::World);
        world.arm = Some(foreign.pair());
        assert!(
            world
                .authenticate_predecessors_data(Some(&foreign.view()), None, &KEY, &BIRTH, MAXIMUM)
                .is_err(),
            "{path:?}"
        );
    }
}

#[test]
fn a_recomputed_valid_receipt_cannot_replace_the_exact_baseline_result() {
    for phase in PHASES {
        let changes = match phase {
            PacketNativeImport17Stage::Arm => vec![
                (vec!["staged"], json!(false)),
                (vec!["gate_id"], json!("foreign-gate")),
                (vec!["staged_owner_ids"], json!(["foreign-owner"])),
            ],
            PacketNativeImport17Stage::World => vec![
                (vec!["gate_id"], json!("foreign-gate")),
                (vec!["armed_owner_ids"], json!(["foreign-owner"])),
            ],
            PacketNativeImport17Stage::FirstObserve => vec![
                (vec!["complete"], json!(false)),
                (vec!["next_sequence"], json!("2")),
                (
                    vec!["observations", "0", "execution_owner_id"],
                    json!("foreign-owner"),
                ),
                (
                    vec!["observations", "0", "world_binding_hash"],
                    json!(canonical::hash("cnp.world-binding.v1", b"foreign").unwrap()),
                ),
                (
                    vec!["observations", "0", "activation_id"],
                    json!("foreign-activation"),
                ),
                (vec!["observations", "0", "world_generation"], json!("2")),
                (vec!["observations", "0", "owner_generation"], json!("2")),
                (
                    vec!["observations", "0", "operation_id"],
                    json!("foreign-operation"),
                ),
                (
                    vec!["observations", "0", "grant_id"],
                    json!("foreign-grant"),
                ),
                (vec!["observations", "0", "visibility"], json!("committed")),
            ],
        };
        for (path, replacement) in changes {
            let mut exchange = Exchange::complete(binding(phase));
            let mut result = exchange.terminal.body["result"].clone();
            let mut field = &mut result;
            for name in &path {
                field = if *name == "0" {
                    &mut field[0]
                } else {
                    &mut field[*name]
                };
            }
            *field = replacement;
            exchange.terminal.body.insert("result".into(), result);
            let assigned = native_import18_stage_assigned_response_digest(
                &exchange.original,
                &exchange.terminal,
                phase,
                MAXIMUM,
            )
            .unwrap();
            exchange.receipt =
                native_import17_stage_receipt_data(&KEY, &exchange.context, &assigned).unwrap();
            exchange
                .terminal
                .extensions
                .insert(phase.receipt_extension().into(), json!(exchange.receipt));

            verify_native_import17_stage_receipt_data(
                &KEY,
                &exchange.context,
                &assigned,
                &exchange.receipt,
            )
            .unwrap();
            assert!(
                exchange
                    .view()
                    .authenticate_data(&KEY, &BIRTH, MAXIMUM)
                    .is_err(),
                "{phase:?}: {path:?}"
            );
        }
    }
}
