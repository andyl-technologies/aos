//! Keeps canonical range rows separate from genuine completed Recover custody.
//!
//! These fixtures use the actual closed codecs, framing and replay, but only an
//! ordinary DATA journal. Neither the fixture bank nor a terminal Operation is
//! an actual Controller launch or a completed native Recover original.

use std::collections::BTreeMap;
use std::io::Write as _;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::operation::{
    OperationRecord, decode_operation, encode_operation_record,
};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
use aos_sandbox_protocol::domain_ledger::resource_bank as bank;
use sha2::{Digest as _, Sha256};

use super::*;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

fn finite_vector_data(amount: u64) -> ResourceVector {
    // Installed service CPU envelopes require whole 1000-microsecond units.
    // Preserve each finite subdivision's ordering without rounding it upward.
    ResourceVector::new([amount; D::COUNT]).with(D::CpuMicrosPerPeriod, amount / 1000 * 1000)
}

fn range_policy_data() -> (bank::ImageBootstrapPolicy, bank::EnrollmentIdentity) {
    // Explicit finite DATA values leave every declared subdivision disjoint.
    // These bytes are never installed as a profile or used to claim native fit.
    let amounts = [
        1_u64 << 60,
        0,
        1 << 55,
        1 << 50,
        1 << 45,
        1 << 44,
        1 << 40,
        1 << 40,
        1 << 40,
        1 << 39,
        1 << 40,
        1 << 44,
        1 << 38,
        1 << 38,
        1 << 40,
        1 << 40,
        1 << 37,
    ]
    .map(finite_vector_data);
    bank::require_root_service_envelope(amounts[9]).unwrap();
    bank::require_storage_service_envelope(amounts[11]).unwrap();

    let mut image = Vec::from(*b"AOSRSB11");
    image.extend_from_slice(&[1; 16]);
    image.extend_from_slice(&[2; 16]);
    for amount in amounts {
        for dimension in D::ALL {
            image.extend_from_slice(&amount.get(dimension).to_be_bytes());
        }
    }
    image.extend_from_slice(&3_u64.to_be_bytes());
    let allowance = finite_vector_data(1_u64 << 35);
    for dimension in D::ALL {
        image.extend_from_slice(&allowance.get(dimension).to_be_bytes());
    }
    image.extend_from_slice(&Sha256::digest(&image));
    assert_eq!(
        image.len(),
        bank::CONTROLLER_RECIPIENT_RANGE_IMAGE_POLICY_BYTES
    );
    let policy = bank::decode_image_policy(&image, bank::NativeLayoutDemand::new(0, 0)).unwrap();
    assert_eq!(policy.controller_recovery_range_v1(), Some((3, allowance)));

    let mut delivery = Vec::from(*b"AOSRSE01");
    for field in [[1; 16], [2; 16], [3; 16], [4; 16]] {
        delivery.extend_from_slice(&field);
    }
    delivery.extend_from_slice(&Sha256::digest(&image));
    delivery.extend_from_slice(&[10; 16]);
    delivery.extend_from_slice(&Sha256::digest(&delivery));
    let (enrollment, _) = bank::decode_pid1_delivery(&delivery).unwrap();
    (policy, enrollment)
}

fn apply_data(state: &mut State, transaction: &JournalTransaction) {
    for record in transaction.records() {
        state.insert(
            (record.namespace(), record.key().to_vec()),
            record.value().unwrap().to_vec(),
        );
    }
}

fn canonical_bank_data(ordinal: u64) -> Vec<JournalTransaction> {
    let (policy, enrollment) = range_policy_data();
    let layout = bank::NativeLayoutDemand::new(0, 0);
    let (heads, host, p, i, q, root, create, storage) =
        bank::prepare_enrollment_subdivisions(enrollment, policy, layout).unwrap();
    let claims = bank::initial_enrollment_claims(enrollment, policy, &heads);
    let delete = bank::delete_operation_intake_claim(enrollment, policy).unwrap();
    let execution = bank::execution_operation_intake_claim(enrollment, policy).unwrap();
    let prepare = bank::host_execution_prepare_claim(enrollment, policy).unwrap();
    let accept = bank::host_execution_accept_claim(enrollment, policy).unwrap();
    let recipient = bank::initial_recipient_precharge_v1(enrollment, policy, [10; 16]).unwrap();
    let id = [6; 16];
    let initial = bank::EnrollmentMutation::new((
        &id, &heads, &claims, &host, &p, &i, &q, &root, &create, &storage,
    ))
    .with_delete_operation_intake(delete.as_ref())
    .with_execution_operation_intake(execution.as_ref())
    .with_host_execution_prepare(prepare.as_ref())
    .with_host_execution_accept(accept.as_ref())
    .with_recipient_precharge_v1(recipient.as_ref());
    let transaction = initial.transaction().unwrap();
    let mut state = State::new();
    bank::validate_recipient_transaction_v1(&state, &transaction).unwrap();
    apply_data(&mut state, &transaction);
    initial.require_returned_rows(&state).unwrap();
    let mut transactions = vec![transaction];
    if ordinal > 0 {
        let commitment =
            bank::controller_recipient_range_commitment_v1(enrollment, policy).unwrap();
        let successor = bank::RecipientSuccessorMutation::new_range_v2(
            &state, enrollment, [11; 16], ordinal, commitment, 0, [10; 16], [12; 32],
        )
        .unwrap();
        let transaction = successor.transaction([13; 16]).unwrap();
        bank::validate_recipient_transaction_v1(&state, &transaction).unwrap();
        apply_data(&mut state, &transaction);
        successor.require_returned_rows(&state).unwrap();
        transactions.push(transaction);
    }
    assert_eq!(bank::validate(&state).unwrap(), Some(enrollment));
    transactions
}

fn passive_corpus(path: &std::path::Path, transactions: &[JournalTransaction]) -> Journal {
    // Raw native frames are confined to this negative fixture. Production
    // generic bank append is intentionally never invoked or weakened.
    let mut file = std::fs::File::create(path).unwrap();
    let mut sequence = 1_u64;
    for transaction in transactions {
        let frames = aos_sandbox_journal::transaction::encode_transaction(
            *transaction.id(),
            sequence,
            transaction.records().iter().map(|record| {
                aos_sandbox_journal::transaction::NativeRecordRef {
                    namespace_byte: record.namespace() as u8,
                    key: record.key(),
                    value: record.value(),
                }
            }),
        )
        .unwrap();
        for frame in frames {
            file.write_all(&frame).unwrap();
        }
        sequence += transaction.records().len() as u64 + 2;
    }
    file.sync_all().unwrap();
    drop(file);
    Journal::open(path, JournalLimits::default()).unwrap().0
}

#[test]
fn canonical_first_and_later_range_rows_cannot_replace_completed_native_recover() {
    let directory = tempfile::tempdir().unwrap();
    for ordinal in [1, 2, 3] {
        let path = directory
            .path()
            .join(format!("recipient-{ordinal}.journal"));
        let journal = passive_corpus(&path, &canonical_bank_data(ordinal));

        assert!(journal.operator_recovery.is_none());
        assert!(matches!(
            journal.catalog_maintenance_source_family_data_v2(),
            Err(JournalError::ProtectedBoundary)
        ));
    }
}

#[test]
fn terminal_operation_data_does_not_create_a_completed_recover_original() {
    let directory = tempfile::tempdir().unwrap();
    let mut transactions = canonical_bank_data(2);
    let terminal = encode_operation_record(OperationRecord::new(
        OperationState::Succeeded,
        0,
        false,
        None,
        None,
    ));
    assert_eq!(
        decode_operation(&terminal).unwrap().state(),
        OperationState::Succeeded
    );
    transactions.push(
        JournalTransaction::new(
            [14; 16],
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                vec![15; 16],
                terminal,
            )],
        )
        .unwrap(),
    );
    let journal = passive_corpus(
        &directory.path().join("terminal-data.journal"),
        &transactions,
    );

    assert!(journal.operator_recovery.is_none());
    assert!(matches!(
        journal.catalog_maintenance_source_family_data_v2(),
        Err(JournalError::ProtectedBoundary)
    ));
}
