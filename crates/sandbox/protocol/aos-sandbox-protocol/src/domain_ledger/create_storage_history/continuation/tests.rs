//! Checks canonical continuation DATA without constructing Root or Controller grants.

use super::super::super::protected_names::ProtectedJournalNamesV1;
use super::super::{
    KEY_BYTES, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
};
use super::*;
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

fn admitted(plan: &[u8], statement: &[u8]) -> UseAdmittedBodyDataV1 {
    UseAdmittedBodyDataV1 {
        use_reserved: [1; 32],
        current_proofs: [2; 32],
        source_current: [3; 32],
        cache_current: [4; 32],
        use_claim: [5; 16],
        unsigned_plan: Sha256::digest(plan).into(),
        signing_statement: Sha256::digest(statement).into(),
    }
}

fn signed_bound(data: SignedPreparationBundleDataV1<'_>) -> SignedBoundBodyDataV1 {
    SignedBoundBodyDataV1 {
        bundle: data.commitment().unwrap(),
        bundle_bytes: data.encoded_bytes().unwrap() as u64,
        request_id: [6; 16],
        request_body: Sha256::digest(data.request_body).into(),
        plan: Sha256::digest(data.plan).into(),
        signature: Sha256::digest(data.signature).into(),
    }
}

#[test]
fn admitted_body_keeps_both_exact_unsigned_signing_inputs() {
    let value = admitted(b"original-plan", b"original-statement");
    let bytes = value.encode().unwrap();

    assert_eq!(bytes.len(), 216);
    assert_eq!(&bytes[..8], b"AOSXUM01");
    assert_eq!(&bytes[136..152], &[5; 16]);
    assert_eq!(&bytes[152..184], &Sha256::digest(b"original-plan")[..]);
    assert_eq!(&bytes[184..], &Sha256::digest(b"original-statement")[..]);
    assert_eq!(UseAdmittedBodyDataV1::decode(&bytes).unwrap(), value);
    for end in 0..bytes.len() {
        assert!(UseAdmittedBodyDataV1::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(UseAdmittedBodyDataV1::decode(&trailing).is_err());
    for range in [
        8..40,
        40..72,
        72..104,
        104..136,
        136..152,
        152..184,
        184..216,
    ] {
        let mut absent = bytes;
        absent[range].fill(0);
        assert!(UseAdmittedBodyDataV1::decode(&absent).is_err());
    }
}

#[test]
fn signed_bundle_has_one_exact_wire_form_and_retains_borrowed_originals() {
    // These opaque test fields exercise framing only. No decoder treats them as
    // a canonical plan, signature artifact, authenticated request or authority.
    let data = SignedPreparationBundleDataV1 {
        plan: b"plan",
        signature: b"signature",
        request_body: b"request",
    };
    let mut encoded = vec![0; data.encoded_bytes().unwrap()];
    data.encode_into(&mut encoded).unwrap();
    let golden = [
        b"AOSXSB01".as_slice(),
        &4_u32.to_be_bytes(),
        &9_u32.to_be_bytes(),
        &7_u32.to_be_bytes(),
        b"plan",
        b"signature",
        b"request",
    ]
    .concat();

    assert_eq!(encoded, golden);
    let borrowed = SignedPreparationBundleDataV1::decode(&encoded, [4, 9, 7]).unwrap();
    assert_eq!(borrowed.plan.as_ptr(), encoded[20..].as_ptr());
    assert_eq!(borrowed.signature.as_ptr(), encoded[24..].as_ptr());
    assert_eq!(borrowed.request_body.as_ptr(), encoded[33..].as_ptr());
    assert_eq!(
        borrowed.commitment().unwrap(),
        <[u8; 32]>::from(
            Sha256::new()
                .chain_update(b"aos.sandbox.create-storage.signed-bundle.v1\0")
                .chain_update(&golden)
                .finalize()
        )
    );
    data.require_bound(signed_bound(data)).unwrap();
    for end in 0..encoded.len() {
        assert!(SignedPreparationBundleDataV1::decode(&encoded[..end], [4, 9, 7]).is_err());
    }
    encoded.push(0);
    assert!(SignedPreparationBundleDataV1::decode(&encoded, [4, 9, 7]).is_err());
    encoded.pop();
    assert!(SignedPreparationBundleDataV1::decode(&encoded, [3, 9, 7]).is_err());
    encoded[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(SignedPreparationBundleDataV1::decode(&encoded, [4, 9, 7]).is_err());
}

#[test]
fn signing_binding_rejects_a_changed_plan_signature_request_or_bundle() {
    let data = SignedPreparationBundleDataV1 {
        plan: b"original-plan",
        signature: b"original-signature",
        request_body: b"original-request",
    };
    let bound = signed_bound(data);
    let bytes = bound.encode().unwrap();

    assert_eq!(bytes.len(), 160);
    assert_eq!(SignedBoundBodyDataV1::decode(&bytes).unwrap(), bound);
    for end in 0..bytes.len() {
        assert!(SignedBoundBodyDataV1::decode(&bytes[..end]).is_err());
    }
    for changed in [
        SignedPreparationBundleDataV1 {
            plan: b"changed",
            ..data
        },
        SignedPreparationBundleDataV1 {
            signature: b"changed",
            ..data
        },
        SignedPreparationBundleDataV1 {
            request_body: b"changed",
            ..data
        },
    ] {
        assert!(changed.require_bound(bound).is_err());
    }
    assert!(
        data.require_bound(SignedBoundBodyDataV1 {
            bundle_bytes: bound.bundle_bytes + 1,
            ..bound
        })
        .is_err()
    );
    assert!(
        SignedBoundBodyDataV1 {
            request_id: [0; 16],
            ..bound
        }
        .encode()
        .is_err()
    );
}

fn admitted_receipt(
    plan: &[u8],
    statement: &[u8],
) -> ([u8; USE_ADMITTED_RECORD_BYTES_V1], [u8; HEAD_BYTES], u64) {
    let lane = [7; 16];
    let mut record = [0; USE_ADMITTED_RECORD_BYTES_V1];
    let checksum = RecordEnvelopeV1::encode_into(
        RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Root, 3).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 3).unwrap(),
            predecessor: [8; 32],
            correlation: [9; 32],
        },
        &admitted(plan, statement).encode().unwrap(),
        &mut record,
    )
    .unwrap();
    let append = encoded_transaction_append_bytes(
        [
            RecordShape {
                key_bytes: KEY_BYTES,
                value_bytes: Some(record.len()),
            },
            RecordShape {
                key_bytes: KEY_BYTES,
                value_bytes: Some(HEAD_BYTES),
            },
        ]
        .into_iter(),
    )
    .unwrap();
    (
        record,
        LatestHeadV1::new(3, checksum).unwrap().encode(),
        append,
    )
}

#[test]
fn root_receipt_requires_exact_original_names_seed_and_four_frame_position() {
    let (record, head, append) = admitted_receipt(b"plan", b"statement");
    let names = ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap();
    let receipt = ContinuationNativeReceiptDataV1 {
        record: &record,
        latest_head: head,
        names,
        after_next: 13,
        after_end: 123 + append,
    };
    let kind = ContinuationKindV1::UseAdmitted;
    let mut encoded = [0; USE_ADMITTED_RECEIPT_BYTES_V1];
    receipt.encode_into([7; 16], kind, &mut encoded).unwrap();
    let parsed = ContinuationNativeReceiptDataV1::decode(&encoded, [7; 16], kind).unwrap();

    assert_eq!(parsed.record.as_ptr(), encoded.as_ptr());
    parsed
        .require_successor([7; 16], kind, [8; 32], [9; 32], names, 9, 123)
        .unwrap();
    for (predecessor, correlation, before_next, before_end) in [
        ([10; 32], [9; 32], 9, 123),
        ([8; 32], [10; 32], 9, 123),
        ([8; 32], [9; 32], 8, 123),
        ([8; 32], [9; 32], 9, 122),
        ([8; 32], [9; 32], u64::MAX, 123),
    ] {
        assert!(
            parsed
                .require_successor(
                    [7; 16],
                    kind,
                    predecessor,
                    correlation,
                    names,
                    before_next,
                    before_end
                )
                .is_err()
        );
    }
    assert!(
        parsed
            .require_successor(
                [7; 16],
                kind,
                [8; 32],
                [9; 32],
                ProtectedJournalNamesV1::from_bytes(&[2; 48]).unwrap(),
                9,
                123
            )
            .is_err()
    );
    assert!(
        ContinuationNativeReceiptDataV1::decode(&encoded, [7; 16], ContinuationKindV1::SignedBound)
            .is_err()
    );
}

#[test]
fn use_admission_carries_exact_unsigned_bytes_and_cannot_accept_signed_bundle() {
    let (record, head, append) = admitted_receipt(b"original-plan", b"original-statement");
    let receipt = ContinuationNativeReceiptDataV1 {
        record: &record,
        latest_head: head,
        names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
        after_next: 13,
        after_end: 123 + append,
    };
    let mut original = [0; USE_ADMITTED_RECEIPT_BYTES_V1];
    receipt
        .encode_into([7; 16], ContinuationKindV1::UseAdmitted, &mut original)
        .unwrap();
    let transfer = UseAdmissionTransferDataV1 {
        receipt: &original,
        plan: b"original-plan",
        statement: b"original-statement",
    };
    let mut bytes = vec![0; transfer.encoded_bytes([7; 16]).unwrap()];
    transfer.encode_into([7; 16], &mut bytes).unwrap();

    let decoded = UseAdmissionTransferDataV1::decode(&bytes, [7; 16], 13, 18).unwrap();
    assert_eq!(decoded.plan, transfer.plan);
    assert_eq!(decoded.statement, transfer.statement);
    assert_eq!(decoded.receipt.as_ptr(), bytes[20..].as_ptr());
    assert!(SignedPreparationBundleDataV1::decode(&bytes, [usize::MAX; 3]).is_err());
    assert!(
        UseAdmissionTransferDataV1 {
            plan: b"changed-plan",
            ..transfer
        }
        .body([7; 16])
        .is_err()
    );
    assert!(
        UseAdmissionTransferDataV1 {
            statement: b"changed-statement",
            ..transfer
        }
        .body([7; 16])
        .is_err()
    );
    for end in 0..bytes.len() {
        assert!(UseAdmissionTransferDataV1::decode(&bytes[..end], [7; 16], 13, 18).is_err());
    }
    assert!(UseAdmissionTransferDataV1::decode(&bytes, [7; 16], 12, 18).is_err());
}
