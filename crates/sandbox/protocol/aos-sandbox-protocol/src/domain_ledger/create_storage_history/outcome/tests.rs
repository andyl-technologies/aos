//! Tests strict framing, substitution resistance and exact native DATA joins.
//!
//! Fixtures manufacture only inert bytes. They never enroll a bank, authenticate
//! a Session packet, acquire an original owner or demonstrate native disposal.

use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::super::{
    HEAD_BYTES, KEY_BYTES, KeyV1, LatestHeadV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
};
use super::*;

const LANE: [u8; 16] = [7; 16];

fn names() -> ProtectedJournalNamesV1 {
    ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6))
}

fn controller_outcome(bundle: OutcomeBundleDataV1<'_>) -> ControllerOutcomeBodyDataV1 {
    ControllerOutcomeBodyDataV1 {
        signed_bound: [1; 32],
        use_admitted: [2; 32],
        use_claim: [3; 16],
        request_packet: Sha256::digest(bundle.request).into(),
        outcome_packet: Sha256::digest(bundle.outcome).into(),
        signed_request: [4; 32],
        prepared_receipt: [5; 32],
        session_names: names(),
        session_after_next: 100,
        session_after_end: 200,
        session_head: [6; 32],
        session_generation: 7,
        session_revision: 8,
        session_commitment: [9; 32],
        request_id: [10; 16],
    }
}

#[test]
fn outcome_transfer_retains_both_original_packets_and_refuses_substitution() {
    let bundle = OutcomeBundleDataV1 {
        request: b"original-signed-request",
        outcome: b"original-signed-outcome",
    };
    let mut bytes = vec![0; bundle.encoded_bytes().unwrap()];
    bundle.encode_into(&mut bytes).unwrap();
    let decoded =
        OutcomeBundleDataV1::decode(&bytes, [bundle.request.len(), bundle.outcome.len()]).unwrap();

    assert_eq!(decoded.request.as_ptr(), bytes[16..].as_ptr());
    assert_eq!(
        decoded.outcome.as_ptr(),
        bytes[16 + bundle.request.len()..].as_ptr()
    );
    assert_eq!(
        bundle.commitment().unwrap(),
        <[u8; 32]>::from(
            Sha256::new()
                .chain_update(b"aos.sandbox.create-storage.outcome-bundle.v1\0")
                .chain_update(&bytes)
                .finalize()
        )
    );
    decoded
        .require_recorded(controller_outcome(bundle))
        .unwrap();
    for changed in [
        OutcomeBundleDataV1 {
            request: b"substituted",
            ..bundle
        },
        OutcomeBundleDataV1 {
            outcome: b"substituted",
            ..bundle
        },
    ] {
        assert_eq!(
            changed.require_recorded(controller_outcome(bundle)),
            Err(HistoryErrorV1::Correlation)
        );
    }
    for end in 0..bytes.len() {
        assert!(OutcomeBundleDataV1::decode(&bytes[..end], [usize::MAX; 2]).is_err());
    }
    bytes.push(0);
    assert!(OutcomeBundleDataV1::decode(&bytes, [usize::MAX; 2]).is_err());
    bytes.pop();
    assert!(OutcomeBundleDataV1::decode(&bytes, [bundle.request.len() - 1, usize::MAX]).is_err());
    assert!(OutcomeBundleDataV1::decode(&bytes, [usize::MAX, bundle.outcome.len() - 1]).is_err());
    bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(OutcomeBundleDataV1::decode(&bytes, [usize::MAX; 2]).is_err());
}

#[test]
fn outcome_body_keeps_actual_terminal_snapshot_separate_from_expected_inputs() {
    let value = controller_outcome(OutcomeBundleDataV1 {
        request: b"request",
        outcome: b"outcome",
    });
    let bytes = value.encode().unwrap();

    assert_eq!(bytes.len(), 376);
    assert_eq!(&bytes[216..264], &names().to_bytes());
    assert_eq!(&bytes[264..272], &100_u64.to_be_bytes());
    assert_eq!(&bytes[312..320], &7_u64.to_be_bytes());
    assert_eq!(&bytes[320..328], &8_u64.to_be_bytes());
    assert_eq!(&bytes[328..360], &[9; 32]);
    assert_eq!(ControllerOutcomeBodyDataV1::decode(&bytes).unwrap(), value);
    for end in 0..bytes.len() {
        assert!(ControllerOutcomeBodyDataV1::decode(&bytes[..end]).is_err());
    }
    for range in [
        8..40,
        40..72,
        72..88,
        88..120,
        120..152,
        152..184,
        184..216,
        216..224,
        264..272,
        272..280,
        280..312,
        312..320,
        320..328,
        328..360,
        360..376,
    ] {
        let mut changed = bytes;
        changed[range].fill(0);
        assert!(ControllerOutcomeBodyDataV1::decode(&changed).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(ControllerOutcomeBodyDataV1::decode(&trailing).is_err());
    assert!(
        ControllerOutcomeBodyDataV1 {
            session_names: ProtectedJournalNamesV1::from_historical_fields((0, 2), (3, 4), (5, 6)),
            ..value
        }
        .encode()
        .is_err()
    );
}

#[test]
fn released_owner_and_final_outcome_are_distinct_closed_schemas() {
    let released = ReleasedBodyDataV1 {
        root_outcome: [1; 32],
        held: [2; 32],
        controller_outcome: [3; 32],
    };
    let source = released.encode(OwnerV1::Source).unwrap();
    let cache = released.encode(OwnerV1::Cache).unwrap();

    assert_ne!(&source[..8], &cache[..8]);
    assert_eq!(
        ReleasedBodyDataV1::decode(&source, OwnerV1::Source).unwrap(),
        released
    );
    assert!(ReleasedBodyDataV1::decode(&source, OwnerV1::Cache).is_err());
    assert!(ReleasedBodyDataV1::decode(&cache, OwnerV1::Source).is_err());
    for owner in [OwnerV1::Root, OwnerV1::Controller] {
        assert!(released.encode(owner).is_err());
        assert!(ReleasedBodyDataV1::decode(&source, owner).is_err());
    }
    let root = RootOutcomeBodyDataV1 {
        controller_outcome: [3; 32],
        prepared_receipt: [4; 32],
        outcome_bundle: [5; 32],
    };
    assert_eq!(
        RootOutcomeBodyDataV1::decode(&root.encode().unwrap()).unwrap(),
        root
    );
    assert!(RootOutcomeBodyDataV1::decode(&source).is_err());
    let closed = RootClosedBodyDataV1 {
        handoff_retained: [6; 32],
        source_released: [7; 32],
        cache_released: [8; 32],
        committed_use_claim: [9; 32],
    };
    assert_eq!(
        RootClosedBodyDataV1::decode(&closed.encode().unwrap()).unwrap(),
        closed
    );
    for bytes in [
        &source[..],
        &cache[..],
        &root.encode().unwrap()[..],
        &closed.encode().unwrap()[..],
    ] {
        let mut changed = bytes.to_vec();
        changed[8..40].fill(0);
        assert!(match bytes.len() {
            136 => RootClosedBodyDataV1::decode(&changed).is_err(),
            _ if bytes[..8] == *b"AOSXRO01" => RootOutcomeBodyDataV1::decode(&changed).is_err(),
            _ => ReleasedBodyDataV1::decode(&changed, OwnerV1::Source).is_err(),
        });
    }
}

fn make_receipt(
    kind: ContinuationKindV1,
    body: &[u8],
    predecessor: [u8; 32],
) -> (Vec<u8>, [u8; 32], u64) {
    let phase = match kind {
        ContinuationKindV1::ControllerOutcomeRecorded => 8,
        ContinuationKindV1::HandoffRetained => 9,
        _ => kind.revision(),
    };
    let mut record = vec![0; kind.record_bytes()];
    let checksum = RecordEnvelopeV1::encode_into(
        RecordCoordinatesV1 {
            key: KeyV1::new(LANE, kind.owner(), kind.revision().into()).unwrap(),
            phase: PhaseV1::new(kind.owner(), phase).unwrap(),
            predecessor,
            correlation: [11; 32],
        },
        body,
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
    let receipt = ContinuationNativeReceiptDataV1 {
        record: &record,
        latest_head: LatestHeadV1::new(kind.revision().into(), checksum)
            .unwrap()
            .encode(),
        names: names(),
        after_next: 104,
        after_end: 200 + append,
    };
    let mut bytes = vec![0; kind.receipt_bytes()];
    receipt.encode_into(LANE, kind, &mut bytes).unwrap();
    (bytes, checksum, append)
}

#[test]
fn shared_receipt_distinguishes_controller_revision_from_phase_and_exact_position() {
    let body = controller_outcome(OutcomeBundleDataV1 {
        request: b"request",
        outcome: b"outcome",
    });
    let kind = ContinuationKindV1::ControllerOutcomeRecorded;
    let (bytes, _, append) = make_receipt(kind, &body.encode().unwrap(), [12; 32]);
    let receipt = ContinuationNativeReceiptDataV1::decode(&bytes, LANE, kind).unwrap();
    let row = receipt.record_data(LANE, kind).unwrap();

    assert_eq!(row.coordinates().key.revision(), 9);
    assert_eq!(row.coordinates().phase.state(), 8);
    receipt
        .require_successor(LANE, kind, [12; 32], [11; 32], names(), 100, 200)
        .unwrap();
    for (before_next, before_end) in [(101, 200), (100, 201), (u64::MAX, 200), (100, u64::MAX)] {
        assert!(
            receipt
                .require_successor(
                    LANE,
                    kind,
                    [12; 32],
                    [11; 32],
                    names(),
                    before_next,
                    before_end
                )
                .is_err()
        );
    }
    assert_eq!(receipt.after_end, 200 + append);
    assert!(
        ContinuationNativeReceiptDataV1::decode(&bytes, LANE, ContinuationKindV1::OutcomeRecorded)
            .is_err()
    );
    assert!(
        receipt
            .require_successor(LANE, kind, [13; 32], [11; 32], names(), 100, 200)
            .is_err()
    );
    assert!(
        receipt
            .require_successor(LANE, kind, [12; 32], [13; 32], names(), 100, 200)
            .is_err()
    );
    for end in 0..bytes.len() {
        assert!(ContinuationNativeReceiptDataV1::decode(&bytes[..end], LANE, kind).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ContinuationNativeReceiptDataV1::decode(&trailing, LANE, kind).is_err());
}

#[test]
fn release_proofs_require_actual_original_held_and_terminal_links() {
    let root = [20; 32];
    let outcome = [21; 32];
    let source_held = [22; 32];
    let cache_held = [23; 32];
    let (source, source_checksum, _) = make_receipt(
        ContinuationKindV1::SourceReleased,
        &ReleasedBodyDataV1 {
            root_outcome: root,
            held: source_held,
            controller_outcome: outcome,
        }
        .encode(OwnerV1::Source)
        .unwrap(),
        source_held,
    );
    let (cache, cache_checksum, _) = make_receipt(
        ContinuationKindV1::CacheReleased,
        &ReleasedBodyDataV1 {
            root_outcome: root,
            held: cache_held,
            controller_outcome: outcome,
        }
        .encode(OwnerV1::Cache)
        .unwrap(),
        cache_held,
    );
    let terminal = HandoffRetainedBodyDataV1 {
        root_outcome: root,
        source_released: source_checksum,
        cache_released: cache_checksum,
        committed_use_claim: [24; 32],
        use_binding: [25; 32],
        bank_commit: [26; 16],
        bank_names: names(),
        bank_after_next: 90,
        bank_after_end: 190,
    };
    let (controller, _, _) = make_receipt(
        ContinuationKindV1::HandoffRetained,
        &terminal.encode().unwrap(),
        outcome,
    );
    let data = ReleaseProofsDataV1 {
        controller: controller.as_slice().try_into().unwrap(),
        source: source.as_slice().try_into().unwrap(),
        cache: cache.as_slice().try_into().unwrap(),
    };
    let mut bytes = [0; RELEASE_PROOFS_BYTES_V1];
    data.encode_into(LANE, &mut bytes).unwrap();
    let decoded = ReleaseProofsDataV1::decode(&bytes, LANE).unwrap();

    assert_eq!(bytes.len(), 1208);
    assert_eq!(decoded.controller.as_ptr(), bytes[20..].as_ptr());
    assert_eq!(
        decoded
            .require_links(LANE, root, outcome, source_held, cache_held)
            .unwrap(),
        terminal
    );
    for (root, outcome, source_held, cache_held) in [
        ([27; 32], outcome, source_held, cache_held),
        (root, [27; 32], source_held, cache_held),
        (root, outcome, [27; 32], cache_held),
        (root, outcome, source_held, [27; 32]),
    ] {
        assert!(
            decoded
                .require_links(LANE, root, outcome, source_held, cache_held)
                .is_err()
        );
    }
    let swapped = ReleaseProofsDataV1 {
        source: data.cache,
        cache: data.source,
        ..data
    };
    assert!(swapped.encode_into(LANE, &mut bytes).is_err());
    for end in [0, 19, 20, 511, 512, 859, 860, 1207] {
        assert!(ReleaseProofsDataV1::decode(&bytes[..end], LANE).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(ReleaseProofsDataV1::decode(&trailing, LANE).is_err());
}
