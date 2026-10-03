//! Actual canonical v2 admission, cut and framing regression vectors.
//!
//! Every original v1 fixture remains separate. These source vectors are authored
//! without invoking a runtime owner, protected signer, journal or FD factory.

mod recovery;
mod pending;

use super::*;
use crate::mount_source_acquisition_state::{RecordRefV2, record_digest};

fn legacy(
    fixture: &Fixture,
) -> crate::mount_source_acquisition_state::MountSourceAcquisitionStateV2 {
    validate_mount_source_state_graph_v2(
        fixture
            .legacy
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap()
}

fn admission(fixture: &Fixture) -> RootNativeCutV1 {
    super::super::cut::RootNativeCutV1::capture(
        RootNativeCutKindV1::Admission,
        [100; 16],
        &legacy(fixture),
        fixture.attempt.attempt_id,
    )
    .unwrap()
}

fn sidecar(
    fixture: &Fixture,
    claims: &RootNativeHeldSidecarV1,
    disposition: Option<RootNativeCutV1>,
) -> RootNativeHeldSidecarV2 {
    RootNativeHeldSidecarV2::new(
        *claims.original_scope(),
        claims.response_transaction(),
        claims.disposition().cloned(),
        claims.settlement().copied(),
        claims.terminal_verifier().cloned(),
        claims.suffix().clone(),
        admission(fixture),
        disposition,
        None,
    )
    .unwrap()
}

fn checked_v2(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> crate::mount_source_acquisition_state::Result<RootNativeHeldGraphV2> {
    validate_native_root_graph_v2(
        rows.iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
}

#[test]
fn admission_cut_reproduces_actual_four_canonical_records_and_seven_lengths() {
    let fixture = Fixture::new(true);
    let cut = admission(&fixture);
    let bytes = cut.to_canonical_bytes().unwrap();
    let head = serde_json::to_vec(cut.head()).unwrap();
    let acquisition = serde_json::to_vec(cut.acquisition()).unwrap();
    let reconstructed = cut
        .reconstruct(&legacy(&fixture), fixture.attempt.attempt_id)
        .unwrap();

    assert_eq!(bytes.len(), 152 + head.len() + acquisition.len());
    assert_eq!(&bytes[..16], b"AOSMNC01\0\x01\x01\x01\0\0\0\0");
    assert_eq!(&bytes[16..32], &[100; 16]);
    assert_eq!(&bytes[144..148], &(head.len() as u32).to_be_bytes());
    assert_eq!(&bytes[148..152], &(acquisition.len() as u32).to_be_bytes());
    assert_eq!(&bytes[152..152 + head.len()], &head);
    assert_eq!(&bytes[152 + head.len()..], &acquisition);
    assert_eq!(reconstructed.witnesses(), &fixture.witness.records);
    for (key, value) in reconstructed.canonical_records() {
        assert_eq!(fixture.legacy.get(key), Some(value));
    }
    assert_eq!(RootNativeCutV1::from_canonical_bytes(&bytes).unwrap(), cut);
    assert!(head.len() <= MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1);
    assert!(acquisition.len() <= MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1);

    let value = sidecar(&fixture, &fixture.phase0(), None);
    let encoded = value.to_canonical_bytes().unwrap();
    let suffix = value.suffix().to_canonical_bytes().unwrap();
    assert_eq!(encoded.len(), 284 + suffix.len() + bytes.len());
    assert_eq!(&encoded[..16], b"AOSMHC02\0\x02\0\0\0\0\0\0");
    assert_eq!(&encoded[256..268], &[0; 12]);
    assert_eq!(&encoded[268..272], &(suffix.len() as u32).to_be_bytes());
    assert_eq!(&encoded[272..276], &(bytes.len() as u32).to_be_bytes());
    assert_eq!(&encoded[276..284], &[0; 8]);
    assert_eq!(MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1, 152 + 8_192 + 16_384);
    assert_eq!(
        MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2,
        284 + 722 + 104 + 2_156 + 106_648 + 2 * 24_728 + 272
    );
}

#[test]
fn atomic_v2_admission_binds_actual_post_reservation_cut_and_transaction() {
    let fixture = Fixture::new(true);
    let value = sidecar(&fixture, &fixture.phase0(), None);
    let key = native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap();
    let mut rows = fixture.legacy.clone();
    rows.insert(key.clone(), value.to_canonical_bytes().unwrap());
    let initial = checked_v2(&BTreeMap::new()).unwrap();
    let reserved = checked_v2(&rows).unwrap();

    let proposal = validate_native_root_transition_v2(
        &initial,
        &reserved,
        fixture.attempt.attempt_id,
        [100; 16],
    )
    .unwrap();
    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV2::PreparedAssertionRecorded
    );
    assert_eq!(proposal.puts.len(), 6);
    assert_eq!(proposal.maximum_remaining_transactions, 7);
    assert!(proposal.before_images.values().all(Option::is_none));
    assert_eq!(
        reserved.data_class(fixture.attempt.attempt_id),
        Some(RootNativeDataClassV2::LiveOriginal)
    );
    assert_eq!(
        proposal
            .admission_binding
            .as_ref()
            .unwrap()
            .original
            .reserved_head_digest,
        value.admission_cut().head().record_digest
    );
    assert!(
        validate_native_root_transition_v2(
            &initial,
            &reserved,
            fixture.attempt.attempt_id,
            [101; 16]
        )
        .is_err()
    );
    assert!(
        validate_native_root_cold_transition_v2(
            &initial,
            &reserved,
            fixture.attempt.attempt_id,
            [100; 16]
        )
        .is_err()
    );

    let mut prior = value.admission_cut().clone();
    // A captured Head body is never repaired by sealing it during reconstruction.
    let bytes = prior.to_canonical_bytes().unwrap();
    let mut changed = bytes;
    changed[112] ^= 1;
    prior = RootNativeCutV1::from_canonical_bytes(&changed).unwrap();
    assert!(
        prior
            .reconstruct(reserved.legacy(), fixture.attempt.attempt_id)
            .is_err()
    );
}

#[test]
fn v2_rejects_cut_tags_lengths_noncanonical_json_self_digest_and_trailing_bytes() {
    let fixture = Fixture::new(true);
    let cut = admission(&fixture);
    let original = cut.to_canonical_bytes().unwrap();
    for offset in [0, 8, 9, 10, 11, 12, 15] {
        let mut changed = original.clone();
        changed[offset] ^= 0x80;
        assert!(
            RootNativeCutV1::from_canonical_bytes(&changed).is_err(),
            "offset {offset}"
        );
    }
    for (offset, length) in [(144, 8_193_u32), (148, 16_385_u32), (144, u32::MAX)] {
        let mut changed = original.clone();
        changed[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
        assert!(
            RootNativeCutV1::from_canonical_bytes(&changed).is_err(),
            "length {length}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(RootNativeCutV1::from_canonical_bytes(&trailing).is_err());
    let mut noncanonical = original.clone();
    let length = u32::from_be_bytes(noncanonical[144..148].try_into().unwrap()) + 1;
    noncanonical[144..148].copy_from_slice(&length.to_be_bytes());
    noncanonical.insert(152, b' ');
    assert!(RootNativeCutV1::from_canonical_bytes(&noncanonical).is_err());
    let mut changed = original;
    changed[72] ^= 1;
    let bad_stamp = RootNativeCutV1::from_canonical_bytes(&changed).unwrap();
    assert!(
        bad_stamp
            .reconstruct(&legacy(&fixture), fixture.attempt.attempt_id)
            .is_err()
    );

    let value = sidecar(&fixture, &fixture.phase0(), None);
    let key = native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap();
    let encoded = value.to_canonical_bytes().unwrap();
    for offset in [0, 8, 9, 10, 11, 12, 15] {
        let mut changed = encoded.clone();
        changed[offset] ^= 0x80;
        assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&key, &changed).is_err());
    }
    for (index, bound) in [722_u32, 104, 2_156, 106_648, 24_728, 24_728, 272]
        .into_iter()
        .enumerate()
    {
        let mut changed = encoded.clone();
        let offset = 256 + index * 4;
        changed[offset..offset + 4].copy_from_slice(&(bound + 1).to_be_bytes());
        assert!(
            RootNativeHeldSidecarV2::from_canonical_bytes(&key, &changed).is_err(),
            "component {index}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&key, &trailing).is_err());
    assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&key, &vec![0; 159_643]).is_err());
}

#[test]
fn v1_bytes_remain_exact_and_cannot_be_inferred_into_v2_or_mixed() {
    let fixture = Fixture::new(true);
    let old = fixture.phase0();
    let old_bytes = old.to_canonical_bytes().unwrap();
    let old_key = native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap();
    let new_key = native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap();
    let new = sidecar(&fixture, &old, None);
    let new_bytes = new.to_canonical_bytes().unwrap();

    assert_eq!(MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1, 109_902);
    assert_eq!(
        RootNativeHeldSidecarV1::from_canonical_bytes(&old_key, &old_bytes).unwrap(),
        old
    );
    assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&new_key, &old_bytes).is_err());
    assert!(RootNativeHeldSidecarV1::from_canonical_bytes(&old_key, &new_bytes).is_err());
    assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&old_key, &new_bytes).is_err());
    let mut rows = fixture.legacy.clone();
    rows.insert(old_key, old_bytes);
    rows.insert(new_key.clone(), new_bytes.clone());
    assert!(checked_v2(&rows).is_err());
    let mut near = new_key;
    near.push(0);
    assert!(RootNativeHeldSidecarV2::from_canonical_bytes(&near, &new_bytes).is_err());
}

#[test]
fn pre_cas_closed_terminal_has_only_one_native_ack_continuation() {
    let fixture = Fixture::new(true);
    let one = sign(fixture.prepared());
    let disposition = fixture.closed();
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        [140; 16],
        &legacy(&fixture),
        fixture.attempt.attempt_id,
    )
    .unwrap();
    let closed = fixture.sidecar(10, None, vec![one.clone()], Some(disposition.clone()));
    let (seven, ack, settlement) = super::terminal::terminal(&fixture, &one, &disposition);
    let make = |phase, prepared, controls| {
        RootNativeHeldSidecarV1::new(
            fixture.scope,
            [0; 16],
            Some(disposition.clone()),
            Some(settlement),
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Root,
                phase,
                fixture.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let graph = |claims| {
        let value = sidecar(&fixture, &claims, Some(cut.clone()));
        let mut records = fixture.legacy.clone();
        records.insert(
            native_root_sidecar_key_v2(fixture.attempt.attempt_id).unwrap(),
            value.to_canonical_bytes().unwrap(),
        );
        checked_v2(&records).unwrap()
    };
    let before = graph(closed);
    let after = graph(make(
        12,
        Some(ack.clone()),
        vec![one.clone(), seven.clone()],
    ));
    let terminal = graph(make(13, None, vec![one, seven, sign(ack)]));

    // Today's original attempt remains Reserved: native terminal counting must
    // not import its independent ordinary replacement/Inventory obligations.
    assert_eq!(
        before.data_class(fixture.attempt.attempt_id),
        Some(RootNativeDataClassV2::LiveOriginal)
    );
    assert!(matches!(
        after.legacy().provider_attempts[&fixture.attempt.attempt_id].state,
        crate::mount_source_acquisition_state::ProviderAttemptStateV2::Reserved
    ));
    let retained =
        validate_native_root_transition_v2(&before, &before, fixture.attempt.attempt_id, [141; 16])
            .unwrap();
    assert_eq!(retained.maximum_remaining_transactions, 4);
    let recorded =
        validate_native_root_transition_v2(&before, &after, fixture.attempt.attempt_id, [142; 16])
            .unwrap();
    assert_eq!(recorded.kind, RootNativeTransitionKindV2::TerminalRecorded);
    assert_eq!(recorded.maximum_remaining_transactions, 1);
    assert!(
        after.sidecars()[&fixture.attempt.attempt_id]
            .suffix()
            .control(Kind::ProviderHeld)
            .is_none()
    );
    assert_eq!(
        after.sidecars()[&fixture.attempt.attempt_id].response_transaction(),
        [0; 16]
    );
    let acknowledged = validate_native_root_transition_v2(
        &after,
        &terminal,
        fixture.attempt.attempt_id,
        [143; 16],
    )
    .unwrap();
    assert_eq!(
        acknowledged.kind,
        RootNativeTransitionKindV2::TerminalAckStored
    );
    assert_eq!(acknowledged.maximum_remaining_transactions, 0);
}

#[test]
fn local_no_interest_marker_uses_actual_fixed_encoder_and_refuses_substitution() {
    let fixture = Fixture::new(true);
    let attempt = RecordRefV2 {
        id: fixture.attempt.attempt_id,
        revision: 3,
        record_digest: fixture.attempt.record_digest,
    };
    let graph = legacy(&fixture);
    let row = graph.acquisitions[&fixture.attempt.owner.owner_id()].clone();
    let record = StoredRecordV2::Acquisition { value: row.clone() };
    assert_eq!(record_digest(&record).unwrap(), row.record_digest);
    let marker = super::super::codec_v2::RootNativeNoInterestTerminalV1 {
        cleanup_transaction: [120; 16],
        closed_disposition: fixture.closed().digest().unwrap(),
        settled_attempt: attempt,
        faulted_acquisition: RecordRefV2 {
            id: row.acquisition_id,
            revision: row.revision,
            record_digest: row.record_digest,
        },
        retired_capacity_id: [121; 32],
        retired_capacity_digest: [122; 32],
    };
    let bytes = marker.to_canonical_bytes().unwrap();
    assert_eq!(bytes.len(), ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1);
    assert_eq!(&bytes[..16], b"AOSMNT01\0\x01\x01\0\0\0\0\0");
    assert_eq!(&bytes[16..32], &[120; 16]);
    assert_eq!(&bytes[208..240], &[121; 32]);
    assert_eq!(&bytes[240..272], &[122; 32]);
    assert_eq!(
        RootNativeNoInterestTerminalV1::from_canonical_bytes(&bytes).unwrap(),
        marker
    );
    let mut bad = bytes.clone();
    bad[10] = 2;
    assert!(RootNativeNoInterestTerminalV1::from_canonical_bytes(&bad).is_err());
    let mut bad = bytes;
    bad[96..104].copy_from_slice(&2_u64.to_be_bytes());
    assert!(RootNativeNoInterestTerminalV1::from_canonical_bytes(&bad).is_err());
    // These marker bytes alone are intentionally insufficient for a graph.
    let mut value = sidecar(&fixture, &fixture.phase0(), None);
    value.no_interest_terminal = Some(marker);
    assert!(value.to_canonical_bytes().is_err());
}
