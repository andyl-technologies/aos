//! Original construction result correlation and unknown-effects regressions.

// crucible-lint: allow panic-shortcut -- These initialization command tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;

use super::{NativeInitializationCommand, NativeInitializationReceipt, NativeInitializationStatus};
use crate::node_control::initialization_cut::{
    NativeInitializationClass, NativeInitializationCut, NativeInitializationRow,
};

fn originals() -> (
    NativeInitializationCommand,
    NativeInitializationCut,
    NativeInitializationReceipt,
) {
    let preparation = crate::node_control::initialization::test_preparation();
    let mut cut = NativeInitializationCut {
        hold_generation: U64::new(1),
        prepared_scope_hash: preparation.preparation.scope.identity_digest().unwrap(),
        initialization_commitment: preparation.identity_digest().unwrap(),
        original_cut_digest: [0; 32],
        rows: vec![NativeInitializationRow {
            class: NativeInitializationClass::QmpDispatcherStartup,
            callback_id: U64::new(1),
            arm_generation: U64::new(1),
            context_id: U64::new(1),
        }],
    };
    cut.original_cut_digest = cut.computed_digest().unwrap();
    let command = NativeInitializationCommand {
        sequence: U64::new(1),
        class_mask: preparation.class_mask,
        maximum_callbacks: preparation.maximum_callbacks,
        prepared_scope_hash: cut.prepared_scope_hash,
        initialization_commitment: cut.initialization_commitment,
        realize_request_digest: preparation.realize_request_digest,
        policy_digest: preparation.policy_digest,
        original_cut_digest: cut.original_cut_digest,
    };
    command.validate_against(&preparation, &cut).unwrap();
    let receipt = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 1,
        sequence: command.sequence,
        hold_generation: cut.hold_generation,
        prepared_scope_hash: cut.prepared_scope_hash,
        initialization_commitment: cut.initialization_commitment,
        original_cut_digest: cut.original_cut_digest,
        realize_request_digest: preparation.realize_request_digest,
    };
    (command, cut, receipt)
}

#[test]
fn portable_command_and_receipt_keep_distinct_lengths_and_exact_original_fields() {
    let (command, cut, receipt) = originals();
    let command_bytes = command.encode().unwrap();
    let receipt_bytes = receipt.encode().unwrap();

    assert_eq!(&command_bytes[..8], &[0, 0, 0, 1, 0, 0, 0, 184]);
    assert_eq!(&receipt_bytes[..8], &[0, 0, 0, 1, 0, 0, 0, 160]);
    assert_eq!(
        NativeInitializationCommand::decode(&command_bytes).unwrap(),
        command
    );
    assert_eq!(
        NativeInitializationReceipt::decode(&receipt_bytes).unwrap(),
        receipt
    );
    receipt.validate_against(&command, &cut).unwrap();
}

#[test]
fn changed_original_scope_sequence_cut_or_realize_cannot_replace_a_receipt() {
    let (command, cut, receipt) = originals();
    for field in 0..6 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.sequence = U64::new(2),
            1 => changed.hold_generation = U64::new(2),
            2 => changed.prepared_scope_hash[0] ^= 1,
            3 => changed.initialization_commitment[0] ^= 1,
            4 => changed.original_cut_digest[0] ^= 1,
            _ => changed.realize_request_digest[0] ^= 1,
        }
        assert!(changed.validate_against(&command, &cut).is_err());
    }
}

#[test]
fn pre_effect_refusals_never_claim_applied_callbacks_and_unknown_stays_explicit() {
    let (command, cut, receipt) = originals();
    for status in [
        NativeInitializationStatus::Unsupported,
        NativeInitializationStatus::Stale,
        NativeInitializationStatus::Invalid,
    ] {
        let mut changed = receipt.clone();
        changed.status = status;
        assert!(changed.validate_against(&command, &cut).is_err());
        changed.applied_callbacks = 0;
        changed.validate_against(&command, &cut).unwrap();
    }

    let mut unknown = receipt;
    unknown.status = NativeInitializationStatus::EffectsUnknown;
    unknown.validate_against(&command, &cut).unwrap();
    assert_eq!(
        NativeInitializationReceipt::decode(&unknown.encode().unwrap())
            .unwrap()
            .status,
        NativeInitializationStatus::EffectsUnknown
    );
    unknown.applied_callbacks = 2;
    assert!(unknown.validate_against(&command, &cut).is_err());
}

#[test]
fn fixed_payloads_refuse_all_truncation_trailing_and_open_status_values() {
    let (command, _, receipt) = originals();
    let command_bytes = command.encode().unwrap();
    let receipt_bytes = receipt.encode().unwrap();
    for length in 0..command_bytes.len() {
        assert!(NativeInitializationCommand::decode(&command_bytes[..length]).is_err());
    }
    for length in 0..receipt_bytes.len() {
        assert!(NativeInitializationReceipt::decode(&receipt_bytes[..length]).is_err());
    }
    let mut trailing = receipt_bytes.to_vec();
    trailing.push(0);
    assert!(NativeInitializationReceipt::decode(&trailing).is_err());
    let mut changed = receipt_bytes;
    changed[8..12].copy_from_slice(&6u32.to_be_bytes());
    assert!(NativeInitializationReceipt::decode(&changed).is_err());
}
