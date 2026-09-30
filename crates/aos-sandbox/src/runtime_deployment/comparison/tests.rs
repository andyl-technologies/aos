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
