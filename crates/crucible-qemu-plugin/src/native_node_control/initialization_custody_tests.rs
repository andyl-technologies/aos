//! Model-only original construction custody regressions, without native qualification.

use super::*;
use crucible_node_contract::{HashRef, Id, Phase, Position};
use crucible_protocol::node_control::{NativePreparation, OwnerScope};
use std::cell::{Cell, RefCell};

thread_local! {
    static SOURCE_CUT: RefCell<Option<NativeInitializationCut>> = const { RefCell::new(None) };
    static QUERY_COUNT: Cell<u32> = const { Cell::new(0) };
}

extern "C" fn query(
    scope: *const u8,
    commitment: *const u8,
    summary: *mut SourceCut,
    _rows: *mut SourceRow,
    capacity: u32,
) -> i32 {
    QUERY_COUNT.with(|count| count.set(count.get() + 1));
    assert_eq!(capacity, 64);
    SOURCE_CUT.with(|cell| {
        let cut = cell.borrow();
        let cut = cut.as_ref().unwrap();
        // SAFETY: This model callback is invoked synchronously with live ABI
        // pointers owned by observe_original_cut; it writes only its summary.
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(scope, 32),
                cut.prepared_scope_hash
            );
            assert_eq!(
                std::slice::from_raw_parts(commitment, 32),
                cut.initialization_commitment
            );
            summary.write(SourceCut {
                version: 1,
                size: 120,
                row_count: 0,
                flags: 0,
                hold_generation: cut.hold_generation.get(),
                prepared_scope_hash: cut.prepared_scope_hash,
                initialization_commitment: cut.initialization_commitment,
                original_cut_digest: cut.original_cut_digest,
            });
        }
        0
    })
}

pub(crate) fn fixture() -> (
    InitializationCustody,
    NativeInitializationCommand,
    SourceReceipt,
) {
    let id = |text| Id::new(text).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    let preparation = NativeInitializationPreparation {
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
            boundary: Position {
                time_ps: U64::new(0),
                microstep: U64::new(0),
                phase: Phase::BoundaryControl,
            },
            maximum_commands: U64::new(4),
        },
        realize_operation: id("realize"),
        realize_request_digest: [11; 32],
        policy_digest: [12; 32],
        class_mask: 7,
        maximum_callbacks: 64,
    };
    let custody = InitializationCustody::new(preparation.clone(), query).unwrap();
    let mut cut = NativeInitializationCut {
        hold_generation: U64::new(5),
        prepared_scope_hash: custody.scope,
        initialization_commitment: custody.commitment,
        original_cut_digest: [0; 32],
        rows: Vec::new(),
    };
    cut.original_cut_digest = cut.computed_digest().unwrap();
    SOURCE_CUT.with(|cell| *cell.borrow_mut() = Some(cut.clone()));
    QUERY_COUNT.with(|count| count.set(0));
    assert_eq!(custody.observe_original_cut().unwrap(), Some(cut.clone()));
    let command = NativeInitializationCommand {
        sequence: U64::new(1),
        class_mask: preparation.class_mask,
        maximum_callbacks: preparation.maximum_callbacks,
        prepared_scope_hash: custody.scope,
        initialization_commitment: custody.commitment,
        realize_request_digest: preparation.realize_request_digest,
        policy_digest: preparation.policy_digest,
        original_cut_digest: cut.original_cut_digest,
    };
    let receipt = SourceReceipt {
        version: 1,
        size: 160,
        status: 1,
        applied_callbacks: 0,
        sequence: 1,
        hold_generation: 5,
        prepared_scope_hash: custody.scope,
        initialization_commitment: custody.commitment,
        original_cut_digest: cut.original_cut_digest,
        realize_request_digest: preparation.realize_request_digest,
    };
    (custody, command, receipt)
}

#[test]
fn original_ack_custody_cannot_be_minted_from_applied_or_adopted_by_equal_initializer() {
    let (custody, command, receipt) = fixture();
    custody.retain(command.clone()).unwrap();
    custody.record_receipt(receipt).unwrap();
    assert!(custody.acknowledged_original().is_err());
    let acknowledgement = NativeInitializationAcknowledgement {
        prepared_scope_hash: custody.scope,
        initialization_commitment: custody.commitment,
        sequence: command.sequence,
        command_digest: command.identity_digest().unwrap(),
    };
    custody.acknowledge(&acknowledgement).unwrap();
    let original = custody.acknowledged_original().unwrap();
    assert_eq!(original.acknowledgement(), &acknowledgement);
    original.validate_original(&custody).unwrap();

    let (foreign, foreign_command, foreign_receipt) = fixture();
    foreign.retain(foreign_command).unwrap();
    foreign.record_receipt(foreign_receipt).unwrap();
    foreign.acknowledge(&acknowledgement).unwrap();
    assert_eq!(
        foreign.acknowledged_original().unwrap().receipt(),
        original.receipt()
    );
    assert!(original.validate_original(&foreign).is_err());

    custody.fail();
    assert!(original.validate_original(&custody).is_err());
    assert_eq!(original.acknowledgement(), &acknowledgement);
}

#[test]
fn actual_ack_identity_survives_a_busy_original_journal_without_becoming_authority() {
    let (custody, command, receipt) = fixture();
    custody.retain(command.clone()).unwrap();
    custody.record_receipt(receipt).unwrap();
    custody
        .acknowledge(&NativeInitializationAcknowledgement {
            prepared_scope_hash: custody.scope,
            initialization_commitment: custody.commitment,
            sequence: command.sequence,
            command_digest: command.identity_digest().unwrap(),
        })
        .unwrap();
    let original = custody.try_acknowledged_original().unwrap().unwrap();
    let guard = custody.state.lock().unwrap();

    assert!(custody.try_acknowledged_original().unwrap().is_none());
    assert!(!original.try_validate_original(&custody).unwrap());
    drop(guard);

    assert!(original.try_validate_original(&custody).unwrap());
    assert_eq!(
        custody
            .try_acknowledged_original()
            .unwrap()
            .unwrap()
            .receipt(),
        original.receipt()
    );
}

fn ack(command: &NativeInitializationCommand) -> NativeInitializationAcknowledgement {
    NativeInitializationAcknowledgement {
        prepared_scope_hash: command.prepared_scope_hash,
        initialization_commitment: command.initialization_commitment,
        sequence: command.sequence,
        command_digest: command.identity_digest().unwrap(),
    }
}

#[test]
fn original_cut_is_queried_once_and_lost_ack_never_reexecutes_callbacks() {
    let (custody, original, source_receipt) = fixture();
    let cut = custody.original_cut().unwrap();
    assert_eq!(custody.observe_original_cut().unwrap(), Some(cut));
    QUERY_COUNT.with(|count| assert_eq!(count.get(), 1));
    assert!(!custody.permits_execution_transport());
    assert!(custody.acknowledge(&ack(&original)).is_err());
    assert_eq!(
        custody.retain(original.clone()).unwrap(),
        CommandJournalDisposition::New
    );
    assert_eq!(custody.command().unwrap().sequence, 1);
    let receipt = custody.record_receipt(source_receipt).unwrap();
    assert!(custody.command().is_none());
    assert_eq!(
        custody.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Stopped
    );
    assert!(!custody.permits_execution_transport());
    custody.acknowledge(&ack(&original)).unwrap();
    custody.acknowledge(&ack(&original)).unwrap();
    assert!(custody.permits_execution_transport());
    assert_eq!(
        custody.retain(original).unwrap(),
        CommandJournalDisposition::Acknowledged
    );
    assert_eq!(custody.original_receipt(), Some(receipt));
    QUERY_COUNT.with(|count| assert_eq!(count.get(), 1));
}

#[test]
fn unknown_effects_recover_original_receipt_but_keep_all_execution_closed() {
    let (custody, original, mut receipt) = fixture();
    custody.retain(original.clone()).unwrap();
    receipt.status = 5;
    let retained = custody.record_receipt(receipt).unwrap();
    assert_eq!(retained.status, NativeInitializationStatus::EffectsUnknown);
    assert!(custody.command().is_none());
    assert!(custody.acknowledge(&ack(&original)).is_err());
    assert_eq!(
        custody.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Stopped
    );
    let mut changed = original;
    changed.sequence = U64::new(2);
    assert!(custody.retain(changed).is_err());
    assert!(!custody.permits_execution_transport());
    assert_eq!(custody.original_receipt(), Some(retained));
    assert!(custody.original_cut().is_some());
}

#[test]
fn changed_original_receipt_quarantines_while_preserving_prior_receipt_and_cut() {
    let (custody, original, receipt) = fixture();
    custody.retain(original.clone()).unwrap();
    let retained = custody.record_receipt(receipt).unwrap();
    let cut = custody.original_cut().unwrap();
    let mut changed = receipt;
    changed.hold_generation += 1;
    assert!(custody.record_receipt(changed).is_err());
    assert!(custody.acknowledge(&ack(&original)).is_err());
    assert!(custody.command().is_none());
    assert_eq!(custody.original_receipt(), Some(retained));
    assert_eq!(custody.original_cut(), Some(cut));
}
