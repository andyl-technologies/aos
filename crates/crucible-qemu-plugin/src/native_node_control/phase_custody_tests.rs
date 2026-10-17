//! Model-only original phase custody regressions, without native qualification.

// crucible-lint: allow panic-shortcut -- These phase custody tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};

use crucible_node_contract::{HashRef, Id, Phase, Position};
use crucible_protocol::node_control::{
    NativeInitializationPreparation, NativePhaseMapping, NativePreparation, OwnerScope,
};

use super::*;

thread_local! {
    static SOURCE: RefCell<NativeTimerBirthInventoryAbi> = RefCell::new(NativeTimerBirthInventoryAbi::default());
    static QUERIES: Cell<u32> = const { Cell::new(0) };
    static RESULT: Cell<i32> = const { Cell::new(0) };
}

extern "C" fn register(_policy: *const NativePhasePolicyAbi) -> i32 {
    0
}

extern "C" fn query(
    scope: *const u8,
    generation: u64,
    summary: *mut NativeTimerBirthInventoryAbi,
    _lists: *mut NativeTimerList,
    list_capacity: u32,
    _timers: *mut NativeTimerBirthAbi,
    timer_capacity: u32,
) -> i32 {
    QUERIES.with(|queries| queries.set(queries.get() + 1));
    assert_eq!(list_capacity, 64);
    assert_eq!(timer_capacity, 4096);
    let result = RESULT.with(Cell::get);
    if result != 0 {
        return result;
    }
    SOURCE.with(|source| {
        let source = *source.borrow();
        assert_eq!(generation, source.gate_generation);
        // SAFETY: The synchronous model callback receives live bounded buffers
        // from observe_original. Its empty roster writes only the fixed summary.
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(scope, 32),
                source.prepared_scope_hash
            );
            summary.write(source);
        }
    });
    0
}

fn fixture() -> PhaseProjectionCustody {
    let id = |text| Id::new(text).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    let preparation = NativePhasePreparation {
        initialization: NativeInitializationPreparation {
            preparation: NativePreparation {
                scope: OwnerScope {
                    session: id("session"),
                    incarnation: id("incarnation"),
                    activation: id("activation"),
                    node: id("node"),
                    owner: id("owner"),
                    world_generation: U64::new(1),
                    owner_generation: U64::new(1),
                    world_binding: hash("cnp.world-binding.v1"),
                    owner_binding: hash("cnp.owner-binding.v1"),
                },
                boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
                maximum_commands: U64::new(20),
            },
            realize_operation: id("realize"),
            realize_request_digest: [1; 32],
            policy_digest: [2; 32],
            class_mask: 7,
            maximum_callbacks: 64,
        },
        policy_digest: [3; 32],
        mapping: NativePhaseMapping::InstructionReaction,
        maximum_microstep: U64::new(16),
    };
    let custody = PhaseProjectionCustody::new(preparation, query).unwrap();
    SOURCE.with(|source| {
        *source.borrow_mut() = NativeTimerBirthInventoryAbi {
            version: 1,
            size: 112,
            gate_generation: 5,
            prepared_scope_hash: custody.policy.prepared_scope_hash,
            ..Default::default()
        };
    });
    QUERIES.with(|queries| queries.set(0));
    RESULT.with(|result| result.set(0));
    custody
}

fn initial_query(custody: &PhaseProjectionCustody) -> NativePhaseTimerQuery {
    NativePhaseTimerQuery {
        prepared_scope_hash: custody.policy.prepared_scope_hash,
        sequence: U64::new(0),
        offset: U64::new(0),
    }
}

#[test]
fn native_registration_is_required_before_any_observation_or_commitment() {
    let custody = fixture();

    assert!(custody.registered_commitment().is_none());
    assert!(
        custody
            .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
            .is_err()
    );
    assert!(custody.chunk(&initial_query(&custody)).unwrap().is_none());
    QUERIES.with(|queries| assert_eq!(queries.get(), 0));

    custody.register(register).unwrap();
    assert_eq!(
        custody.registered_commitment(),
        Some(custody.preparation.identity_digest().unwrap())
    );
    assert!(custody.register(register).is_err());
}

#[test]
fn original_retry_preserves_bytes_after_live_native_state_changes() {
    let custody = fixture();
    custody.register(register).unwrap();
    custody
        .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
        .unwrap();
    let original = custody.chunk(&initial_query(&custody)).unwrap().unwrap();

    SOURCE.with(|source| source.borrow_mut().current_ps = 50);
    custody
        .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
        .unwrap();

    assert_eq!(
        custody.chunk(&initial_query(&custody)).unwrap(),
        Some(original)
    );
    QUERIES.with(|queries| assert_eq!(queries.get(), 1));
}

#[test]
fn cached_original_rejects_changed_digest_time_or_hold_lifetime() {
    let custody = fixture();
    custody.register(register).unwrap();
    custody
        .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
        .unwrap();
    let original = custody.chunk(&initial_query(&custody)).unwrap();

    for (digest, time, generation) in [([1; 32], 0, 5), ([0; 32], 1, 5), ([0; 32], 0, 6)] {
        assert!(
            custody
                .observe_original(U64::new(0), digest, U64::new(time), generation)
                .is_err()
        );
    }

    assert_eq!(custody.chunk(&initial_query(&custody)).unwrap(), original);
    QUERIES.with(|queries| assert_eq!(queries.get(), 1));
}

#[test]
fn unsupported_native_query_and_malformed_facts_never_create_original_bytes() {
    let custody = fixture();
    custody.register(register).unwrap();
    RESULT.with(|result| result.set(-libc::EAGAIN));
    custody
        .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
        .unwrap();
    assert!(custody.chunk(&initial_query(&custody)).unwrap().is_none());

    RESULT.with(|result| result.set(0));
    SOURCE.with(|source| source.borrow_mut().source_original_digest = [4; 32]);
    assert!(
        custody
            .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
            .is_err()
    );
    assert!(custody.chunk(&initial_query(&custody)).unwrap().is_none());
}

#[test]
fn foreign_slice_and_offset_refuse_without_overwriting_original() {
    let custody = fixture();
    custody.register(register).unwrap();
    custody
        .observe_original(U64::new(0), [0; 32], U64::new(0), 5)
        .unwrap();
    let original = custody.chunk(&initial_query(&custody)).unwrap();
    let mut query = initial_query(&custody);
    query.prepared_scope_hash[0] ^= 1;
    assert!(custody.chunk(&query).is_err());
    query = initial_query(&custody);
    query.offset = U64::new(112);
    assert!(custody.chunk(&query).is_err());

    assert_eq!(custody.chunk(&initial_query(&custody)).unwrap(), original);
}
