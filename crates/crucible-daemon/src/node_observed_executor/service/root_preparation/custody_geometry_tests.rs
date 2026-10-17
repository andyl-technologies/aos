//! Checks finite simultaneous staging/runtime custody without native authority.

// crucible-lint: allow panic-shortcut -- These custody models stop at the original failed assertion and never qualify a native world.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible::node_contract::{
    ActivationRecord, RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeError, RuntimeLimits,
};
use crucible_node_contract::{Id, Phase, Position, canonical};

fn record() -> ActivationRecord {
    ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("geometry/original").unwrap(),
        world_binding_hash: canonical::json_hash(
            "cnp.world-binding.v1",
            &serde_json::json!({"model":1}),
        )
        .unwrap(),
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        owners: Vec::new(),
    }
}

#[test]
fn restoration_owns_two_independent_capsules_and_third_is_refused() {
    let source = canonical::content_ref(b"model", "application/octet-stream").unwrap();
    let count = slots(&RootPreparationAction::ContinueHeldUart { source }, 1).unwrap();
    let queue = RuntimeCustodyQueue::new(count).unwrap();
    let original = record();
    let staging = queue
        .reserve_world(&original, RuntimeLimits::default())
        .unwrap();
    let runtime = queue
        .reserve_world(&original, RuntimeLimits::default())
        .unwrap();

    assert_eq!(queue.reserved_worlds(), 2);
    assert!(matches!(
        queue.reserve_world(&original, RuntimeLimits::default()),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(queue.reserved_worlds(), 2);
    staging
        .validate_world(&original, RuntimeLimits::default())
        .unwrap();
    runtime
        .validate_world(&original, RuntimeLimits::default())
        .unwrap();
    drop(staging);
    assert_eq!(queue.reserved_worlds(), 1);
    runtime
        .validate_world(&original, RuntimeLimits::default())
        .unwrap();
    drop(runtime);
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn second_reservation_refusal_precedes_staging_effects_and_releases_unused_credit() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let original = record();
    let effects = std::cell::Cell::new(0);
    let attempt = || {
        let _staging = queue.reserve_world(&original, RuntimeLimits::default())?;
        let _runtime = queue.reserve_world(&original, RuntimeLimits::default())?;
        effects.set(effects.get() + 1);
        Ok::<(), RuntimeError>(())
    };

    assert!(matches!(attempt(), Err(RuntimeError::ResourceLimit)));
    assert_eq!(effects.get(), 0);
    assert_eq!(queue.reserved_worlds(), 0);
    assert_eq!(queue.retained_worlds(), 0);
}

#[test]
fn public_world_quota_and_initial_capsule_count_remain_unchanged() {
    for maximum in [1, 64] {
        assert_eq!(
            slots(&RootPreparationAction::DescribeHeldUart {}, maximum).unwrap(),
            1
        );
        assert_eq!(
            slots(&RootPreparationAction::CaptureHeldUart {}, maximum).unwrap(),
            1
        );
    }
}

#[test]
fn invalid_aggregate_credit_refuses_before_any_catalog_effect() {
    let effects = std::cell::Cell::new(0);
    for maximum in [0, 65, usize::MAX] {
        let result = slots(&RootPreparationAction::CaptureHeldUart {}, maximum).map(|_| {
            effects.set(effects.get() + 1);
        });
        assert!(result.is_err());
    }
    assert_eq!(effects.get(), 0);
}
