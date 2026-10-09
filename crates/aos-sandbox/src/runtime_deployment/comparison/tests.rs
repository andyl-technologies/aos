//! UNRUN inert comparison/factoring vectors, never synthetic production owners.

use std::error::Error as _;

use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::journal::{JournalRecord, RecordNamespace};
use crate::runtime_deployment::genesis::GENESIS_KEY;
use crate::runtime_deployment::preparation::{tests::Fixture, validated_append_rows_v1};

fn fixture_scope(fixture: &Fixture) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.tpm-floor.closed-purpose.scope.v1\0")
        .chain_update(&fixture.exact)
        .finalize()
        .into()
}

fn transaction(row: &(Vec<u8>, Vec<u8>)) -> JournalTransaction {
    let identity = row.1[160..176].try_into().unwrap();
    JournalTransaction::new(
        identity,
        vec![JournalRecord::put(NAMESPACE, row.0.clone(), row.1.clone())],
    )
    .unwrap()
}

#[test]
fn unrun_successful_append_returns_only_original_borrowed_rows() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let original = BTreeMap::from([(GENESIS_KEY, fixture.exact.as_slice())]);
    let transaction = transaction(&steps[0]);

    let (sequence, after) = validated_append_rows_v1(
        4,
        &original,
        &transaction,
        &fixture.exact,
        &fixture.genesis,
        fixture.signer.verifying_key(),
        fixture_scope(&fixture),
    )
    .unwrap();

    assert_eq!(sequence, 7);
    assert_eq!(original.len(), 1);
    assert_eq!(after.len(), 2);
    assert!(std::ptr::eq(after[GENESIS_KEY], fixture.exact.as_slice()));
    let record = &transaction.records()[0];
    let (key, value) = after.get_key_value(record.key()).unwrap();
    assert!(std::ptr::eq(*key, record.key()));
    assert!(std::ptr::eq(*value, record.value().unwrap()));
}

#[test]
fn unrun_every_canonical_prefix_retains_exact_target_sequence_and_head() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();

    for (index, row) in steps.iter().enumerate() {
        let mut original = BTreeMap::from([(GENESIS_KEY, fixture.exact.as_slice())]);
        for (key, value) in &steps[..index] {
            original.insert(key.as_slice(), value.as_slice());
        }
        let sequence = 4 + index as u64 * 3;
        let transaction = transaction(row);
        let scope = fixture_scope(&fixture);

        let (next, after) = validated_append_rows_v1(
            sequence,
            &original,
            &transaction,
            &fixture.exact,
            &fixture.genesis,
            fixture.signer.verifying_key(),
            scope,
        )
        .unwrap();

        let actual = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment, scope, next, &after,
        )
        .unwrap();
        let mut expected = original.clone();
        expected.insert(row.0.as_slice(), row.1.as_slice());
        let expected = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment, scope, sequence + 3, &expected,
        )
        .unwrap();

        assert_eq!(next, sequence + 3);
        assert_eq!(actual, expected);
        assert_eq!(original.len(), index + 1);
    }
}

#[test]
fn unrun_factored_append_keeps_current_map_error_precedence() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let transaction = transaction(&steps[0]);
    let validate = |rows: &BTreeMap<&[u8], &[u8]>| {
        validated_append_rows_v1(
            4, rows, &transaction, &fixture.exact, &fixture.genesis,
            fixture.signer.verifying_key(), fixture_scope(&fixture),
        )
        .map(|_| ())
    };

    assert_eq!(validate(&BTreeMap::new()), Err(NvCustodyErrorV1::Encoding));
    let substituted = [0_u8; 468];
    let wrong_genesis = BTreeMap::from([(GENESIS_KEY, substituted.as_slice())]);
    assert_eq!(validate(&wrong_genesis), Err(NvCustodyErrorV1::Provisioning));
    let canonical = BTreeMap::from([(GENESIS_KEY, fixture.exact.as_slice())]);
    assert!(validate(&canonical).is_ok());
}

#[test]
fn unrun_closed_append_refuses_foreign_delete_batch_repeated_key_and_wrong_uuid() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let original = BTreeMap::from([(GENESIS_KEY, fixture.exact.as_slice())]);
    let row = &steps[0];
    let make = |records| JournalTransaction::new([91; 16], records).unwrap();
    let cases = [
        (
            "foreign namespace",
            make(vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic, row.0.clone(), row.1.clone(),
            )]),
            NvCustodyErrorV1::Provisioning,
        ),
        (
            "delete",
            make(vec![JournalRecord::delete(NAMESPACE, row.0.clone())]),
            NvCustodyErrorV1::Encoding,
        ),
        (
            "batch",
            make(vec![
                JournalRecord::put(NAMESPACE, row.0.clone(), row.1.clone()),
                JournalRecord::put(NAMESPACE, b"another".to_vec(), row.1.clone()),
            ]),
            NvCustodyErrorV1::Encoding,
        ),
        (
            "repeat genesis",
            make(vec![JournalRecord::put(
                NAMESPACE, GENESIS_KEY.to_vec(), fixture.exact.clone(),
            )]),
            NvCustodyErrorV1::Provisioning,
        ),
        (
            "wrong native UUID",
            make(vec![JournalRecord::put(NAMESPACE, row.0.clone(), row.1.clone())]),
            NvCustodyErrorV1::Provisioning,
        ),
    ];

    for (name, transaction, error) in cases {
        let observed = validated_append_rows_v1(
            4, &original, &transaction, &fixture.exact, &fixture.genesis,
            fixture.signer.verifying_key(), fixture_scope(&fixture),
        )
        .map(|_| ());
        assert_eq!(observed, Err(error), "{name}");
    }
}

#[test]
fn unrun_factored_append_refuses_oversize_before_decoding_unknown_rows() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let transaction = transaction(&steps[0]);
    let unknown = (0_u32..322).map(u32::to_be_bytes).collect::<Vec<_>>();
    let records = unknown
        .iter()
        .map(|key| (key.as_slice(), b"not signed".as_slice()))
        .collect::<BTreeMap<_, _>>();

    let observed = validated_append_rows_v1(
        4, &records, &transaction, &fixture.exact, &fixture.genesis,
        fixture.signer.verifying_key(), fixture_scope(&fixture),
    )
    .map(|_| ());

    assert_eq!(observed, Err(NvCustodyErrorV1::Encoding));
    assert_eq!(MAIN_LIMITS.maximum_materialized_records, 321);
    assert_eq!(MAIN_LIMITS.maximum_transactions, 321);
}

#[test]
fn unrun_target_corruption_or_valid_signature_on_wrong_predecessor_refuses() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let original = BTreeMap::from([(GENESIS_KEY, fixture.exact.as_slice())]);
    let mut bad_signature = steps[0].clone();
    bad_signature.1[552] ^= 1;
    let mut wrong_predecessor = steps[0].clone();
    wrong_predecessor.1[128] ^= 1;
    let message = [
        b"aos.runtime-deployment.preparation-step.v1\0".as_slice(),
        &wrong_predecessor.1[..552],
    ]
    .concat();
    let signature = fixture.signer.sign(&message);
    wrong_predecessor.1[552..].copy_from_slice(&signature.to_bytes());

    for (name, row) in [
        ("invalid signature", bad_signature),
        ("signed wrong predecessor", wrong_predecessor),
        ("skipped Prepared", steps[1].clone()),
    ] {
        let transaction = transaction(&row);
        let observed = validated_append_rows_v1(
            4, &original, &transaction, &fixture.exact, &fixture.genesis,
            fixture.signer.verifying_key(), fixture_scope(&fixture),
        )
        .map(|_| ());

        assert_eq!(observed, Err(NvCustodyErrorV1::Provisioning), "{name}");
    }
}

#[test]
fn unrun_prepared_data_uses_sole_native_codec_and_derived_actual_bounds() {
    let fixture = Fixture::new();
    let steps = fixture.canonical_steps();
    let transaction = transaction(&steps[0]);

    let maximum = JournalTransaction::maximum_prepared_bytes_v1(MAIN_LIMITS).unwrap();
    let bytes = transaction.encode_prepared_v1(MAIN_LIMITS).unwrap();
    let decoded = JournalTransaction::decode_prepared_v1(&bytes, MAIN_LIMITS).unwrap();

    assert_eq!(maximum, 1060);
    assert_eq!(bytes.len(), 669);
    assert_eq!(&bytes[..8], b"AOSJPT01");
    assert_eq!(decoded.id(), transaction.id());
    assert_eq!(decoded.records().len(), 1);
    assert_eq!(decoded.records()[0].namespace(), NAMESPACE);
    assert_eq!(decoded.records()[0].key(), transaction.records()[0].key());
    assert_eq!(decoded.records()[0].value(), transaction.records()[0].value());
    assert_eq!(decoded.encode_prepared_v1(MAIN_LIMITS).unwrap(), bytes);
}

#[test]
fn unrun_private_comparison_latch_never_resets_after_a_failed_operation() {
    let mut usable = true;
    assert!(require_usable(usable).is_ok());
    assert_eq!(latch_failure(&mut usable, Ok::<_, RuntimeDeploymentComparisonErrorV1>(7)).unwrap(), 7);
    assert!(usable);

    let error = latch_failure::<()>(&mut usable, Err(changed_comparison())).unwrap_err();

    assert!(!usable);
    assert!(error.source().is_some());
    assert!(matches!(require_usable(usable).unwrap_err().cause, ComparisonFailureV1::Unusable));
    assert!(latch_failure(&mut usable, Ok::<_, RuntimeDeploymentComparisonErrorV1>(())).is_ok());
    assert!(!usable);
    assert!(require_usable(usable).is_err());
}

fn original_native_fixture_transactions(fixture: &Fixture) -> Vec<JournalTransaction> {
    let mut transactions = vec![JournalTransaction::new(
        super::super::genesis::genesis_native_transaction_v1(&fixture.exact).unwrap(),
        vec![JournalRecord::put(NAMESPACE, GENESIS_KEY.to_vec(), fixture.exact.clone())],
    ).unwrap()];
    transactions.extend(fixture.canonical_steps().iter().map(transaction));
    transactions
}

fn inert_sidecar_limits() -> JournalLimits {
    // Fixed comparison-test DATA, not a derived store or provisioned owner.
    JournalLimits {
        maximum_journal_bytes: MAIN_LIMITS.maximum_journal_bytes,
        maximum_record_bytes: 1078,
        maximum_key_bytes: 11,
        maximum_records_per_transaction: 3,
        maximum_transaction_bytes: 1415,
        maximum_transactions: 643,
        maximum_materialized_bytes: 1567,
        maximum_materialized_records: 3,
    }
}

#[test]
fn unrun_retained_native_prefix_reconstructs_only_one_exact_original_map() {
    use super::super::preparation::deployment_native_prefix_rows_v1;

    let fixture = Fixture::new();
    let transactions = original_native_fixture_transactions(&fixture);
    let history = crate::journal::observed_native_fixture_v1(&transactions, MAIN_LIMITS).unwrap();

    for (index, native) in history.transactions().iter().enumerate() {
        let prefix = deployment_native_prefix_rows_v1(
            history.transactions(), native.next_sequence(),
        ).unwrap();

        assert_eq!(prefix.len(), index + 1);
        assert_eq!(prefix[GENESIS_KEY], fixture.exact.as_slice());
        let record = &native.transaction().records()[0];
        assert_eq!(prefix[record.key()], record.value().unwrap());
        assert_eq!(native.begin_sequence(), 1 + index as u64 * 3);
        assert_eq!(native.commit_sequence(), 3 + index as u64 * 3);
        assert_eq!(native.next_sequence(), 4 + index as u64 * 3);
        assert!(std::ptr::eq(prefix[record.key()], record.value().unwrap()));
    }
}

#[test]
fn unrun_retained_phase_validates_at_actual_old_prefix_not_current_map() {
    use super::super::preparation::deployment_native_prefix_rows_v1;

    let fixture = Fixture::new();
    let transactions = original_native_fixture_transactions(&fixture);
    let history = crate::journal::observed_native_fixture_v1(&transactions, MAIN_LIMITS).unwrap();
    let latest = history.transactions().last().unwrap().next_sequence();
    let current = deployment_native_prefix_rows_v1(history.transactions(), latest).unwrap();

    for native in &history.transactions()[1..] {
        let original = deployment_native_prefix_rows_v1(
            history.transactions(), native.begin_sequence(),
        ).unwrap();
        let actual = deployment_native_prefix_rows_v1(
            history.transactions(), native.next_sequence(),
        ).unwrap();
        let (next, target) = validated_append_rows_v1(
            native.begin_sequence(), &original, native.transaction(), &fixture.exact,
            &fixture.genesis, fixture.signer.verifying_key(), fixture_scope(&fixture),
        ).unwrap();

        assert_eq!(next, native.next_sequence());
        assert_eq!(target, actual);
        assert!(validated_append_rows_v1(
            latest, &current, native.transaction(), &fixture.exact, &fixture.genesis,
            fixture.signer.verifying_key(), fixture_scope(&fixture),
        ).is_err());
    }
}

#[test]
fn unrun_native_prefix_rejects_absent_and_midframe_cuts() {
    use super::super::preparation::deployment_native_prefix_rows_v1;

    let fixture = Fixture::new();
    let transactions = original_native_fixture_transactions(&fixture);
    let history = crate::journal::observed_native_fixture_v1(&transactions, MAIN_LIMITS).unwrap();
    let latest = history.transactions().last().unwrap().next_sequence();

    for sequence in [0, 1, 2, 3, 5, latest + 1, latest + 3, u64::MAX] {
        assert_eq!(
            deployment_native_prefix_rows_v1(history.transactions(), sequence),
            Err(NvCustodyErrorV1::Provisioning),
            "sequence {sequence}",
        );
    }
}

#[test]
fn unrun_sidecar_same_parser_accepts_two_then_three_records_and_preserves_deletes() {
    let prepare = JournalTransaction::new([81; 16], vec![
        JournalRecord::put(NAMESPACE, b"intent".to_vec(), vec![1]),
        JournalRecord::put(NAMESPACE, b"transaction".to_vec(), vec![2]),
    ]).unwrap();
    let finalize = JournalTransaction::new([82; 16], vec![
        JournalRecord::put(NAMESPACE, b"checkpoint".to_vec(), vec![3]),
        JournalRecord::delete(NAMESPACE, b"intent".to_vec()),
        JournalRecord::delete(NAMESPACE, b"transaction".to_vec()),
    ]).unwrap();
    let history = crate::journal::observed_native_fixture_v1(
        &[prepare.clone(), finalize.clone()], inert_sidecar_limits(),
    ).unwrap();

    assert_eq!(history.transactions().len(), 2);
    assert_eq!(history.transactions()[0].transaction(), &prepare);
    assert_eq!(history.transactions()[1].transaction(), &finalize);
    assert_eq!(history.transactions()[0].next_sequence(), 5);
    assert_eq!(history.transactions()[1].begin_sequence(), 5);
    assert_eq!(history.transactions()[1].next_sequence(), 10);
    assert!(history.transactions()[1].transaction().records()[1].value().is_none());
    // This deliberately lacks canonical init/intent bytes; it is native DATA
    // only and cannot construct the genuine pair or future typed Host store.
}

#[test]
fn unrun_sidecar_native_capture_refuses_foreign_namespace_and_compaction_uuid() {
    let mut compaction = [0; 16];
    compaction[..8].copy_from_slice(&1_u64.to_le_bytes());
    compaction[8..].copy_from_slice(b"compact1");
    let cases = [
        JournalTransaction::new([83; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"checkpoint".to_vec(), vec![1],
        )]).unwrap(),
        JournalTransaction::new(compaction, vec![JournalRecord::put(
            NAMESPACE, b"checkpoint".to_vec(), vec![1],
        )]).unwrap(),
    ];

    for transaction in cases {
        assert!(matches!(
            crate::journal::observed_native_fixture_v1(&[transaction], inert_sidecar_limits()),
            Err(JournalError::ProtectedBoundary),
        ));
    }
}

#[test]
fn unrun_sidecar_resource_limits_refuse_large_allocation_claims_before_parser() {
    let mut limits = inert_sidecar_limits();
    assert!(crate::journal::require_sidecar_capture_limits_for_test(limits).is_ok());
    limits.maximum_records_per_transaction = usize::MAX;
    assert!(crate::journal::require_sidecar_capture_limits_for_test(limits).is_err());
    limits = inert_sidecar_limits();
    limits.maximum_record_bytes = usize::MAX;
    assert!(crate::journal::require_sidecar_capture_limits_for_test(limits).is_err());
    limits = inert_sidecar_limits();
    limits.maximum_journal_bytes = MAIN_LIMITS.maximum_journal_bytes + 1;
    assert!(crate::journal::require_sidecar_capture_limits_for_test(limits).is_err());
}

#[test]
fn unrun_capture_refuses_oversized_physical_extent_before_retaining_transactions() {
    let transaction = JournalTransaction::new([84; 16], vec![JournalRecord::put(
        NAMESPACE, b"checkpoint".to_vec(),
        vec![1; usize::try_from(MAIN_LIMITS.maximum_journal_bytes).unwrap()],
    )]).unwrap();

    assert!(matches!(
        crate::journal::observed_native_fixture_v1(&[transaction], inert_sidecar_limits()),
        Err(JournalError::JournalTooLarge),
    ));
}

#[test]
fn unrun_original_compaction_selection_adds_only_the_fixed_host_sidecar() {
    use std::path::Path;
    use crate::journal::deployment_original_compaction_selected_for_test as selected;
    use crate::runtime_deployment::{MAIN_DIRECTORY_V1, MAIN_NAME, SIDECAR_NAME};

    assert!(selected(Path::new(MAIN_DIRECTORY_V1), MAIN_NAME));
    assert!(selected(Path::new(MAIN_DIRECTORY_V1), SIDECAR_NAME));
    assert!(!selected(Path::new(MAIN_DIRECTORY_V1), "other.journal"));
    assert!(!selected(Path::new("/different"), SIDECAR_NAME));
    assert!(!selected(Path::new("/different"), "session-floor.journal"));
}
