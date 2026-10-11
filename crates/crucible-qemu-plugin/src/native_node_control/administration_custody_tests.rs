//! Model-only original source-record custody, without native reader qualification.

// crucible-lint: allow panic-shortcut -- These administration custody tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeInitializationPreparation, NativePhaseMapping, NativePhasePreparation, NativePreparation,
    OwnerScope,
};
use std::cell::{Cell, RefCell};

thread_local! {
    static RAW: RefCell<Option<NativeAdministrationFacts>> = const { RefCell::new(None) };
    static REGISTER_CALLS: Cell<u32> = const { Cell::new(0) };
    static QUERY_CALLS: Cell<u32> = const { Cell::new(0) };
    static STATUS: Cell<i32> = const { Cell::new(0) };
}

extern "C" fn register(
    _policy: *const NativeAdministrationPolicy,
    facts: *mut NativeAdministrationFacts,
) -> i32 {
    REGISTER_CALLS.with(|count| count.set(count.get() + 1));
    write_facts(facts)
}

extern "C" fn query(
    _scope: *const u8,
    _commitment: *const u8,
    facts: *mut NativeAdministrationFacts,
) -> i32 {
    QUERY_CALLS.with(|count| count.set(count.get() + 1));
    write_facts(facts)
}

fn write_facts(facts: *mut NativeAdministrationFacts) -> i32 {
    RAW.with(|raw| {
        // SAFETY: The synchronous model caller owns this exact writable ABI slot.
        unsafe { facts.write(raw.borrow().unwrap()) };
    });
    STATUS.with(Cell::get)
}

fn custody() -> AdministrationCustody {
    let preparation = preparation();
    RAW.with(|raw| {
        *raw.borrow_mut() = Some(super::super::administration_abi::model_record(
            &preparation,
            1,
            7,
        ))
    });
    REGISTER_CALLS.with(|count| count.set(0));
    QUERY_CALLS.with(|count| count.set(0));
    STATUS.with(|status| status.set(0));
    AdministrationCustody::new(preparation, register, query).unwrap()
}

#[test]
fn lost_reply_recovers_original_but_registration_retry_still_checks_source_tls() {
    let custody = custody();
    let original = custody.register_current_reader().unwrap();
    assert_eq!(custody.register_current_reader().unwrap(), original);
    assert_eq!(custody.query_original().unwrap(), original);
    REGISTER_CALLS.with(|count| assert_eq!(count.get(), 2));
    QUERY_CALLS.with(|count| assert_eq!(count.get(), 1));
    assert_eq!(custody.try_original().unwrap().facts, Some(original));
}

#[test]
fn zero_refusal_retains_original_but_changed_success_is_sticky_even_if_zero() {
    let custody = custody();
    let original = custody.register_current_reader().unwrap();
    RAW.with(|raw| *raw.borrow_mut() = Some(NativeAdministrationFacts::default()));
    STATUS.with(|status| status.set(-1));
    assert!(custody.register_current_reader().is_err());
    assert_eq!(
        custody.try_original().unwrap().facts,
        Some(original.clone())
    );
    assert!(!custody.try_original().unwrap().failed);

    STATUS.with(|status| status.set(0));
    assert!(custody.query_original().is_err());
    assert!(custody.try_original().unwrap().failed);
    assert_eq!(custody.try_original().unwrap().facts, Some(original));
    assert_eq!(
        custody.try_original().unwrap().divergent_raw,
        Some(NativeAdministrationFacts::default())
    );
}

#[test]
fn nonzero_failure_outputs_and_invalid_unknown_flags_retain_diagnostics() {
    for failure in [false, true] {
        let custody = custody();
        if failure {
            STATUS.with(|status| status.set(-1));
        } else {
            RAW.with(|raw| {
                *raw.borrow_mut() = Some(super::super::administration_abi::model_record(
                    &custody.preparation,
                    1,
                    3,
                ))
            });
        }
        assert!(custody.register_current_reader().is_err());
        assert!(custody.try_original().unwrap().failed);
        assert!(custody.register_current_reader().is_err());
        REGISTER_CALLS.with(|count| assert_eq!(count.get(), 1));
    }
}

fn preparation() -> NativeAdministrativePreparation {
    let id = |value| Id::new(value).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    NativeAdministrativePreparation {
        phase: NativePhasePreparation {
            initialization: NativeInitializationPreparation {
                preparation: NativePreparation {
                    scope: OwnerScope {
                        session: id("model/session"),
                        incarnation: id("model/incarnation"),
                        activation: id("model/activation"),
                        node: id("model/node"),
                        owner: id("model/owner"),
                        world_generation: U64::new(1),
                        owner_generation: U64::new(1),
                        world_binding: hash("cnp.world-binding.v1"),
                        owner_binding: hash("cnp.owner-binding.v1"),
                    },
                    boundary: Position {
                        time_ps: U64::new(0),
                        microstep: U64::new(0),
                        phase: Phase::BoundaryControl,
                    },
                    maximum_commands: U64::new(8),
                },
                realize_operation: id("model/realize"),
                realize_request_digest: [11; 32],
                policy_digest: [12; 32],
                class_mask: 7,
                maximum_callbacks: 64,
            },
            policy_digest: [13; 32],
            mapping: NativePhaseMapping::InstructionReaction,
            maximum_microstep: U64::new(1024),
        },
        policy_digest: [14; 32],
        descriptor_slot: 23,
        socket_device: 9,
        socket_inode: 31,
    }
}

#[test]
fn manifest_metadata_remains_available_during_original_reply_custody() {
    let custody = custody();
    let original = custody.register_current_reader().unwrap();
    let held = custody.try_original().unwrap();

    // A query reply holds mutable journal custody after reader startup. The
    // installer still needs the immutable already validated original record.
    assert_eq!(custody.retained_original(), Some(original));
    QUERY_CALLS.with(|count| assert_eq!(count.get(), 0));
    drop(held);
}

#[test]
fn published_manifest_metadata_is_withdrawn_after_original_source_divergence() {
    let custody = custody();
    let original = custody.register_current_reader().unwrap();
    assert_eq!(custody.retained_original(), Some(original.clone()));
    RAW.with(|raw| *raw.borrow_mut() = Some(NativeAdministrationFacts::default()));

    assert!(custody.query_original().is_err());
    assert!(custody.retained_original().is_none());
    let held = custody.try_original().unwrap();
    assert_eq!(held.facts, Some(original));
    assert!(held.failed);
}

#[test]
fn poisoned_reply_custody_cannot_supply_published_manifest_metadata() {
    let custody = custody();
    custody.register_current_reader().unwrap();
    let failure = std::panic::catch_unwind(|| {
        let _held = custody.try_original().unwrap();
        panic!("intentional original reply custody failure");
    });

    assert!(failure.is_err());
    assert!(custody.retained_original().is_none());
    assert!(custody.query_original().is_err());
}
