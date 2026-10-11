//! Actual source-local staging, unsupported restoration and lost global reply.
//!
//! These native mechanism witnesses do not qualify common all-owner activation:
//! their authored coordinator marker is deliberately not a common opaque token.

#![cfg(test)]

use super::*;

#[test]
fn actual_immediate_staged_restore_refusal_keeps_native_gate_closed() {
    let mut fixture = Fixture::launch_immediate();
    let world = fixture.prepare_staged();
    let selection = fixture.bootstrap.selection.clone();

    let refused = fixture.call(
        "unsupported-staged-restore",
        Some("unsupported-restore-operation"),
        Method::Begin,
        BeginRequest {
            kind: BeginKind::PrepareRestore,
            binding_hash: selection.realization.owner_bindings[0].identity().unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(Some(world.activation_id.clone())),
            world_generation: world.world_generation,
            arguments: object(PrepareRestoreArguments {
                transaction_id: id("unsupported-restore-transaction"),
                capture_manifest: world.activation_manifest.clone(),
                expected_world_binding_hash: selection.world,
                expected_owner_binding_hash: selection.realization.owner_bindings[0]
                    .identity()
                    .unwrap(),
                destination_owner_ids: vec![id("packet-owner")],
            }),
            extensions: Extensions::new(),
        },
    );
    assert!(matches!(
        refused.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                effect: EffectCertainty::NotStarted,
                ..
            },
            ..
        }
    ));
    let before_global = fixture.begin(
        "staged-cannot-run",
        initial_position(),
        Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl),
    );
    assert!(matches!(
        before_global.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ..
        }
    ));
    assert!(fixture.effects_now().is_empty());

    let response = fixture.call("source-world", None, Method::WorldActivate, world);
    let Some(MethodResult::WorldActivate(response)) = response.result else {
        panic!("original native global activation absent")
    };
    let opened: PacketNativeRecord = serde_json::from_slice(
        fixture
            .controller
            .content(&response.activation_receipt)
            .unwrap(),
    )
    .unwrap();
    assert!(!opened.inventory.gate_closed);
    assert_eq!(opened.inventory.pending, fixture.bootstrap.events);
    assert_eq!(opened.inventory.private_mutations.get(), 0);
    assert_eq!(opened.inventory.packet_effects.get(), 0);

    fixture.begin(
        "unchanged-after-restore-refusal",
        initial_position(),
        Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl),
    );
    let original = fixture.poll("unchanged-after-restore-refusal");
    assert_eq!(original.inventory.private_mutations.get(), 1);
    assert_eq!(original.inventory.packet_effects.get(), 1);
    assert_eq!(
        fixture.effects_now(),
        vec![vec![0], [vec![1], b"actual\0packet\xff".to_vec()].concat()]
    );
    fixture.retire("unchanged-after-restore-refusal", &[id("packet-native-1")]);
}

#[test]
fn actual_immediate_lost_global_reply_retains_original_opened_native_and_fence() {
    let mut fixture = Fixture::launch_with_faults(false, true, true);
    let world = fixture.prepare_staged();
    let result = fixture.controller.call(
        id("source-world"),
        None,
        Method::WorldActivate,
        true,
        &world,
    );
    assert!(result.is_err());
    let original = fixture.controller.original(&id("source-world")).unwrap();
    assert!(original.response.is_none());
    assert!(fixture.child.try_wait().unwrap().is_none());

    let bytes = std::fs::read(&fixture.bootstrap.retained_native).unwrap();
    let native: PacketNativeRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(native.schema, "source-owned.packet-native/2");
    assert_eq!(native.original, original.request);
    assert_eq!(native.native_pid.get(), u64::from(fixture.child.id()));
    assert!(!native.inventory.gate_closed);
    assert_eq!(native.inventory.pending, fixture.bootstrap.events);
    assert_eq!(native.inventory.private_mutations.get(), 0);
    assert_eq!(native.inventory.packet_effects.get(), 0);
    assert!(native.grant.is_none());
    assert!(fixture.effects_now().is_empty());

    // The same living native owner remains held; a lost receipt is neither
    // rollback nor permission for retrying activation or starting native work.
    assert!(
        fixture
            .controller
            .call(
                id("source-world"),
                None,
                Method::WorldActivate,
                true,
                &world,
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(&fixture.bootstrap.retained_native).unwrap(),
        bytes
    );
    assert!(fixture.effects_now().is_empty());
}

#[test]
fn actual_reply_preflight_refusal_keeps_original_global_native_gate_closed() {
    let mut fixture = Fixture::launch_with_preflight_refusal(Method::WorldActivate);
    let world = fixture.prepare_staged();
    let result = fixture.controller.call(
        id("source-world"),
        None,
        Method::WorldActivate,
        true,
        &world,
    );
    assert!(result.is_err());
    let original = fixture.controller.original(&id("source-world")).unwrap();
    assert!(original.response.is_none());

    let native: PacketNativeRecord =
        serde_json::from_slice(&std::fs::read(&fixture.bootstrap.retained_native).unwrap())
            .unwrap();
    assert_eq!(native.original, original.request);
    assert_eq!(native.native_pid.get(), u64::from(fixture.child.id()));
    assert!(native.inventory.gate_closed);
    assert_eq!(native.inventory.pending, fixture.bootstrap.events);
    assert_eq!(native.inventory.private_mutations.get(), 0);
    assert_eq!(native.inventory.packet_effects.get(), 0);
    assert!(native.inventory.retained_outputs.is_empty());
    assert!(fixture.effects_now().is_empty());
    assert!(fixture.child.try_wait().unwrap().is_none());
    assert!(
        fixture
            .controller
            .call(
                id("source-world"),
                None,
                Method::WorldActivate,
                true,
                &world
            )
            .is_err()
    );
    assert!(fixture.effects_now().is_empty());
}

#[test]
fn actual_reply_preflight_refusal_keeps_original_begin_callbacks_unexecuted() {
    assert_original_begin_preflight_held(Fixture::launch_with_preflight_refusal(Method::Begin));
}

#[test]
fn actual_reply_preflight_unwind_keeps_original_begin_callbacks_and_new_dispatch_fenced() {
    assert_original_begin_preflight_held(Fixture::launch_with_preflight_panic(Method::Begin));
}

fn assert_original_begin_preflight_held(mut fixture: Fixture) {
    fixture.prepare_and_open();
    let original_limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    let operation = id("refused-native-preparation");
    let authorization =
        fixture.common_authorization(operation.as_str(), initial_position(), original_limit);
    let begin = fixture.begin_request(
        operation.as_str(),
        initial_position(),
        original_limit,
        authorization,
    );
    let result = fixture.controller.call(
        id("refused-native-begin"),
        Some(operation),
        Method::Begin,
        true,
        &begin,
    );
    assert!(result.is_err());
    let original = fixture
        .controller
        .original(&id("refused-native-begin"))
        .unwrap();
    assert!(original.response.is_none());

    let native: PacketNativeRecord =
        serde_json::from_slice(&std::fs::read(&fixture.bootstrap.retained_native).unwrap())
            .unwrap();
    assert_eq!(native.original, original.request);
    assert_eq!(native.native_pid.get(), u64::from(fixture.child.id()));
    assert!(!native.inventory.gate_closed);
    assert_eq!(native.inventory.pending, fixture.bootstrap.events);
    assert_eq!(native.inventory.private_mutations.get(), 0);
    assert_eq!(native.inventory.packet_effects.get(), 0);
    assert!(native.inventory.retained_outputs.is_empty());
    assert!(fixture.effects_now().is_empty());
    assert!(fixture.child.try_wait().unwrap().is_none());
}
