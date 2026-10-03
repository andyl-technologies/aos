//! Synthetic exact-carrier codec tests, never live descriptor or signing authority.

use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::ledger::format::decode_record;
use crate::ledger::model::DecodedRecordV1;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

pub(crate) fn requested() -> NativeAcquireCompletionRecordV2 {
    let mut template = Vec::new();
    for tag in 1_u8..=27 {
        let value = match tag {
            1 => b"AOSMSEM1".to_vec(),
            2 => 1_u16.to_be_bytes().to_vec(),
            _ => vec![tag, tag + 1],
        };
        template.push(tag);
        template.extend_from_slice(&(value.len() as u32).to_be_bytes());
        template.extend_from_slice(&value);
    }
    let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
    let binding = b"retained-native-request".to_vec();
    let binding_digest = digest_logical_binding_bytes(&binding);
    let root = AcquireSourceRequestV1::new_v2(
        d(1),
        2,
        [3; 16],
        4,
        template,
        template_digest,
        SourceUseV1::MountCreate,
        [5; 16],
        [6; 16],
        [7; 16],
        8,
        d(9),
        binding,
        binding_digest,
        1_000,
        60,
        d(10),
        false,
        0,
        false,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[51; 32]);
    let root_signer = SourceProviderSigningKeyV1::for_signing_key(
        [7; 16],
        8,
        d(9),
        [11; 16],
        12,
        SourceProviderKeyUsageV1::RootMountRecord,
        &key,
    )
    .unwrap();
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        root_signer,
        &key,
    )
    .unwrap();
    let snapshot =
        ZfsHeldSnapshotProofV1::new([13; 32], 14, 15, 16, 17, [18; 16], 19, d(20), d(21), d(22))
            .unwrap();
    let catalog = ProviderHeldSnapshotCatalogV1::new(
        23,
        d(24),
        vec![
            ProviderHeldSnapshotRowV1::new(
                binding_digest,
                [25; 32],
                26,
                d(27),
                28,
                d(29),
                snapshot,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        [31; 32],
        d(32),
        [33; 16],
        root.holder_authority_id(),
        root.session_binding(),
        root.acquisition_id(),
        binding_digest,
        d(34),
        900,
        930,
        catalog,
    )
    .unwrap();
    let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        35,
        d(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &key,
    )
    .unwrap();
    let request = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap(),
        provider_signer,
        &key,
    )
    .unwrap();
    let initial = aos_sandbox_core::RawPairedClockSample::new_untrusted(
        aos_sandbox_core::RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
        root.boot_id(),
        900,
        1_000_000_000,
    )
    .unwrap();
    let anchor = NativeAcquireClockAnchorV1::new_untrusted(initial, &request).unwrap();
    NativeAcquireCompletionRecordV2::requested(request, d(39), anchor).unwrap()
}

pub(crate) fn prepared() -> NativeAcquireCompletionRecordV2 {
    let requested = requested();
    let signed = requested.canonical_request.as_ref().unwrap();
    let claims = signed.request().claims();
    let catalog = claims.catalog();
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            requested.binding_digest,
        )
        .unwrap();
    let signer = StorageZfsHoldSignerV1::new([61; 16], 62, d(63), [64; 16], 65).unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    let head = StorageZfsHoldHeadV1::new(67, d(68), 62, d(63), 69, d(70), d(71)).unwrap();
    let subject = StorageZfsHoldReceiptV1::new(
        requested.challenge,
        requested.attempt_digest,
        requested.binding_digest,
        resource,
        snapshot,
        head,
        900,
        930,
    )
    .unwrap();
    let unsigned = SignedStorageZfsHoldReceiptV1::new(subject.clone(), signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        subject,
        signer,
        key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let descriptor = SourceRootObservationV1::new([6; 16], 72, 73, 74, true, true, true).unwrap();
    let topology =
        storage_native_nonrecursive_topology_v1(signed, &receipt, &descriptor, 2, 75).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [76; 16],
        signed.digest(),
        receipt.digest(),
        descriptor.clone(),
        topology,
    )
    .unwrap();
    let reply = StorageNativeAcquireReplyV3::new(
        SignedStorageNativeAcceptanceV3::sign(acceptance, signer, &key),
        receipt,
    )
    .unwrap();
    let verified = verify_reply(signed, &reply);
    requested.prepare_accepted(reply, &verified).unwrap()
}

fn verify_reply(
    request: &SignedStorageNativeAcquireRequestV2,
    reply: &StorageNativeAcquireReplyV3,
) -> VerifiedStorageNativeAcquireV3 {
    let original_key = SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes();
    let key = SigningKey::from_bytes(&[66; 32]);
    reply
        .verify_for(StorageNativeAcquireVerificationV3 {
            request,
            provider_signer: request.signer(),
            provider_key: &original_key,
            root_signer: request.request().signed_root_request().signer(),
            root_key: &original_key,
            storage_verifier: StorageZfsHoldVerifierV1::new(
                reply.acceptance().signer(),
                key.verifying_key().to_bytes(),
            )
            .unwrap(),
            expected_receipt: reply.receipt().receipt(),
            observed_descriptor: reply.acceptance().acceptance().descriptor(),
            descriptor_roles: &[SourceProviderDescriptorRole::SourceRoot],
            now_seconds: 910,
        })
        .unwrap()
}

#[test]
fn native_prepared_v3_roundtrip_retains_exact_bundle_and_spent_crash_cut() {
    let requested = requested();
    let prepared = prepared();
    requested.validate_successor(&prepared).unwrap();
    let key = native_completion_key_v2(prepared.acquisition_id);
    let bytes = super::super::format::encode_native_completion_v2(&prepared);
    assert_eq!(
        bytes.len(),
        64 + BODY_BYTES
            + 40
            + clock::CLOCK_BYTES
            + prepared
                .canonical_request
                .as_ref()
                .unwrap()
                .to_canonical_bytes()
                .len()
            + STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3
    );
    let DecodedRecordV1::NativeCompletion(decoded) = decode_record(&key, &bytes).unwrap() else {
        panic!("wrong record family");
    };
    assert_eq!(decoded, prepared);
    assert_eq!(
        decoded
            .accepted_reply
            .as_ref()
            .unwrap()
            .to_canonical_bytes(),
        prepared
            .accepted_reply
            .as_ref()
            .unwrap()
            .to_canonical_bytes()
    );

    let session = Some(prepared.session_binding);
    let custody = Some((prepared.original_root, prepared.descriptor_commitment));
    assert_eq!(
        reduce_native_acquire_recovery_v2(
            &decoded,
            Some(decoded.receipt_digest),
            false,
            session,
            custody,
        ),
        Ok(NativeAcquireRecoveryDecisionV2::OriginalCompletionPending)
    );
    // The live path writes no Provider Spent checkpoint. Atomic Active may
    // resume this exact Prepared + separately spent challenge cut directly.
    let active = decoded
        .advance(NativeAcquireCompletionStateV2::Active)
        .unwrap();
    decoded.validate_successor(&active).unwrap();
    assert_eq!(active.revision, decoded.revision + 1);
    assert_eq!(active.challenge, requested.challenge);
    assert_eq!(active.canonical_request, requested.canonical_request);
    assert_eq!(active.accepted_reply, prepared.accepted_reply);

    assert_eq!(
        reduce_native_acquire_recovery_v2(
            &prepared,
            Some(prepared.receipt_digest),
            false,
            session,
            None,
        ),
        Ok(NativeAcquireRecoveryDecisionV2::OriginalCustodyUnavailable)
    );
    assert!(
        reduce_native_acquire_recovery_v2(&prepared, Some(d(77)), false, session, custody,)
            .is_err()
    );
    assert!(
        reduce_native_acquire_recovery_v2(
            &prepared,
            Some(prepared.receipt_digest),
            false,
            Some(d(77)),
            custody,
        )
        .is_err()
    );
    let remount = SourceRootIdentityV1::new([6; 16], 72, 73, 78).unwrap();
    assert!(
        reduce_native_acquire_recovery_v2(
            &prepared,
            Some(prepared.receipt_digest),
            false,
            session,
            Some((remount, prepared.descriptor_commitment)),
        )
        .is_err()
    );
}

#[test]
fn native_prepared_rejects_signed_artifact_and_original_scope_substitution() {
    let prepared = prepared();
    type Mutation = fn(&mut NativeAcquireCompletionRecordV2);
    let mutations: &[Mutation] = &[
        |row| row.receipt_digest = d(80),
        |row| row.acceptance_digest = d(80),
        |row| row.acceptance_payload_digest = d(80),
        |row| row.issuance_id = [80; 16],
        |row| row.original_root = SourceRootIdentityV1::new([6; 16], 72, 73, 80).unwrap(),
        |row| row.accepted_reply = None,
        |row| row.canonical_request = None,
        |row| row.session_binding = d(80),
        |row| row.attempt_digest = d(80),
    ];
    for mutation in mutations {
        let mut changed = prepared.clone();
        mutation(&mut changed);
        assert!(changed.validate_canonical_artifacts().is_err());
        assert!(prepared.validate_successor(&changed).is_err());
    }
    let mut truncated = super::super::format::encode_native_completion_v2(&prepared);
    truncated.pop();
    assert!(
        decode_record(
            &native_completion_key_v2(prepared.acquisition_id),
            &truncated
        )
        .is_err()
    );
}

#[test]
fn native_requested_freezes_other_owner_heads_until_the_atomic_cut() {
    use std::collections::BTreeMap;

    let requested = requested();
    let prepared = prepared();
    let key = native_completion_key_v2(requested.acquisition_id);
    let current = BTreeMap::from([(
        key.clone(),
        super::super::format::encode_native_completion_v2(&requested),
    )]);
    let next = BTreeMap::from([(
        key.clone(),
        super::super::format::encode_native_completion_v2(&prepared),
    )]);
    crate::require_native_suffix_progress(&requested, &prepared, &key, &current, &next).unwrap();

    // This directly tests the transition fence's exact changed-key geometry.
    // Whole-graph admission still independently validates every encoded row.
    for other in [b"catalog".as_slice(), b"authority", b"session", b"attempt"] {
        let mut changed = next.clone();
        changed.insert(other.to_vec(), vec![1]);
        assert!(
            crate::require_native_suffix_progress(&requested, &prepared, &key, &current, &changed,)
                .is_err()
        );
    }
    let mut unrelated = current.clone();
    unrelated.insert(b"another-owner".to_vec(), vec![1]);
    assert!(
        crate::require_native_suffix_progress(&requested, &requested, &key, &current, &unrelated,)
            .is_err()
    );
}

#[test]
fn native_atomic_active_fence_requires_all_six_rows_and_no_extra_row() {
    use super::super::format::{
        acquisition_key, attempt_key, authority_key, session_history_key, session_key,
    };
    use super::super::model::{AcquisitionKeyV1, AttemptKeyV1};
    use std::collections::BTreeMap;

    let prepared = prepared();
    let active = prepared
        .advance(NativeAcquireCompletionStateV2::Active)
        .unwrap();
    let key = native_completion_key_v2(prepared.acquisition_id);
    let current = BTreeMap::from([(
        key.clone(),
        super::super::format::encode_native_completion_v2(&prepared),
    )]);
    let original = prepared
        .canonical_request
        .as_ref()
        .unwrap()
        .request()
        .signed_root_request();
    let keys = [
        key.clone(),
        acquisition_key(&AcquisitionKeyV1 {
            provider_id: prepared.provider_id,
            holder_id: prepared.holder_id,
            acquisition_id: prepared.acquisition_id,
        }),
        attempt_key(&AttemptKeyV1 {
            provider_id: prepared.provider_id,
            holder_id: prepared.holder_id,
            root_record_key_id: original.signer().key_id(),
            method: SourceProviderMethod::Acquire as u8,
            request_id: prepared.root_request_id,
        }),
        authority_key(prepared.provider_id),
        session_key(prepared.provider_id, prepared.holder_id),
        session_history_key(
            prepared.provider_id,
            prepared.holder_id,
            prepared.session_binding,
        ),
    ];
    let mut atomic = BTreeMap::new();
    for owner_key in &keys {
        atomic.insert(owner_key.clone(), vec![1]);
    }
    atomic.insert(
        key.clone(),
        super::super::format::encode_native_completion_v2(&active),
    );
    crate::require_native_suffix_progress(&prepared, &active, &key, &current, &atomic).unwrap();
    for omitted in &keys {
        let mut partial = atomic.clone();
        partial.remove(omitted);
        assert!(
            crate::require_native_suffix_progress(&prepared, &active, &key, &current, &partial)
                .is_err()
        );
    }
    let mut extra = atomic.clone();
    extra.insert(b"other-catalog-cut".to_vec(), vec![1]);
    assert!(
        crate::require_native_suffix_progress(&prepared, &active, &key, &current, &extra).is_err()
    );
    let spent = prepared
        .advance(NativeAcquireCompletionStateV2::Spent)
        .unwrap();
    let spent_cut = BTreeMap::from([(
        key.clone(),
        super::super::format::encode_native_completion_v2(&spent),
    )]);
    assert!(
        crate::require_native_suffix_progress(&prepared, &spent, &key, &current, &spent_cut)
            .is_err()
    );
}

#[test]
fn native_full_width_geometry_exceeds_no_dispatch_budget_and_fits_owner_limit() {
    use super::super::format::{
        MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2,
        NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2,
    };

    assert_eq!(NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2.len(), 6);
    assert_eq!(
        NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2
            .iter()
            .sum::<usize>(),
        MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2
    );
    // The immutable no-dispatch owner uses a separate three-MiB terminal floor.
    assert!(MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 > 3 * 1024 * 1024);
    assert!(
        MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 + 128
            < crate::limits::MAXIMUM_TRANSACTION_BYTES
    );
    assert_eq!(
        MAXIMUM_BODY_BYTES,
        BODY_BYTES
            + 40
            + clock::CLOCK_BYTES
            + MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2
            + STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3
    );
}

#[test]
fn native_requested_retains_canonical_bytes_and_explicit_version() {
    let record = requested();
    let signed = record
        .canonical_request
        .as_ref()
        .unwrap()
        .to_canonical_bytes();
    let key = native_completion_key_v2(record.acquisition_id);
    let encoded = crate::ledger::format::encode_native_completion_v2(&record);
    assert_eq!(&encoded[8..10], &7_u16.to_be_bytes());
    assert_eq!(&encoded[64..72], CLOCKED_BODY_MAGIC);
    assert_eq!(
        encoded.len(),
        64 + BODY_BYTES + 40 + clock::CLOCK_BYTES + signed.len()
    );
    let crate::ledger::model::DecodedRecordV1::NativeCompletion(decoded) =
        crate::ledger::format::decode_record(&key, &encoded).unwrap()
    else {
        panic!("wrong family");
    };
    assert_eq!(decoded, record);
    assert_eq!(
        decoded.canonical_request.unwrap().to_canonical_bytes(),
        signed
    );
    assert_eq!(
        reduce_native_acquire_recovery_v2(&record, None, false, None, None),
        Ok(NativeAcquireRecoveryDecisionV2::AwaitOriginalAcceptance)
    );

    let mut wrong_version = encoded.clone();
    wrong_version[8..10].copy_from_slice(&5_u16.to_be_bytes());
    assert!(crate::ledger::format::decode_record(&key, &wrong_version).is_err());
    for length in [
        BODY_BYTES - 1,
        BODY_BYTES,
        BODY_BYTES + 39,
        encoded.len() - 65,
    ] {
        assert!(decode_body(&key, &encoded[64..64 + length], 1, 0).is_err());
    }
    let mut over_bound = vec![0; MAXIMUM_BODY_BYTES + 1];
    over_bound[..8].copy_from_slice(REQUESTED_BODY_MAGIC);
    assert!(decode_body(&key, &over_bound, 1, 0).is_err());
}

#[test]
fn native_original_clock_is_canonical_immutable_and_no_clock_v6_stays_closed() {
    let requested = requested();
    let prepared = prepared();
    let anchor = requested.original_clock.unwrap();
    assert_eq!(anchor.initial().wall_seconds(), 900);
    assert_eq!(anchor.initial().boottime_nanoseconds(), 1_000_000_000);
    assert_eq!(anchor.deadline(), 30_000_000_000);
    assert_eq!(prepared.original_clock, Some(anchor));
    for phase in [
        NativeAcquireCompletionStateV2::Active,
        NativeAcquireCompletionStateV2::CleanupRequired,
    ] {
        assert_eq!(
            prepared.advance(phase).unwrap().original_clock,
            Some(anchor)
        );
    }

    let body = encode_body(&requested);
    let key = native_completion_key_v2(requested.acquisition_id);
    let clock_start = BODY_BYTES + 32;
    // No sentinels, boot substitution, wall-after-issue or arbitrary deadline.
    for offset in [0, 16, 32, 40, 48] {
        let mut changed = body.clone();
        let width = if offset < 32 { 16 } else { 8 };
        if offset < 32 {
            changed[clock_start + offset..clock_start + offset + width].fill(0);
        } else {
            changed[clock_start + offset + width - 1] ^= 1;
        }
        assert!(
            decode_body(&key, &changed, 1, 0).is_err(),
            "clock offset {offset}"
        );
    }
    assert!(decode_body(&key, &body[..clock_start + clock::CLOCK_BYTES - 1], 1, 0).is_err());

    let mut historical = requested.clone();
    historical.original_clock = None;
    let bytes = crate::ledger::format::encode_native_completion_v2(&historical);
    assert_eq!(&bytes[8..10], &6_u16.to_be_bytes());
    let DecodedRecordV1::NativeCompletion(decoded) = decode_record(&key, &bytes).unwrap() else {
        panic!("wrong native family");
    };
    assert_eq!(decoded.original_clock, None);
    assert!(requested.validate_successor(&decoded).is_err());
    assert!(decoded.validate_successor(&requested).is_err());
    let reply = prepared.accepted_reply.clone().unwrap();
    let verified = verify_reply(decoded.canonical_request.as_ref().unwrap(), &reply);
    assert!(decoded.prepare_accepted(reply, &verified).is_err());
}

#[test]
fn native_clock_wrong_boot_version_pairs_and_legacy_width_hole_are_closed() {
    let row = requested();
    let key = native_completion_key_v2(row.acquisition_id);
    let bytes = crate::ledger::format::encode_native_completion_v2(&row);
    let mut wrong_envelope = bytes.clone();
    wrong_envelope[8..10].copy_from_slice(&6_u16.to_be_bytes());
    assert!(decode_record(&key, &wrong_envelope).is_err());

    let mut wrong_boot = encode_body(&row);
    wrong_boot[BODY_BYTES + 32 + 16] ^= 1;
    assert!(decode_body(&key, &wrong_boot, 1, 0).is_err());
    let request = row.canonical_request.as_ref().unwrap();
    let initial = row.original_clock.unwrap().initial();
    let overflow = aos_sandbox_core::RawPairedClockSample::new_untrusted(
        initial.provenance(),
        initial.host_boot_id(),
        initial.wall_seconds(),
        u64::MAX,
    )
    .unwrap();
    assert!(NativeAcquireClockAnchorV1::new_untrusted(overflow, request).is_err());

    let mut historical = row;
    historical.original_clock = None;
    let mut old_envelope = crate::ledger::format::encode_native_completion_v2(&historical);
    old_envelope[8..10].copy_from_slice(&7_u16.to_be_bytes());
    assert!(decode_record(&key, &old_envelope).is_err());
    // Adding body-4 capacity must not admit a body-3 record in the old/new
    // width gap. Reject before attempting any large nested request decoding.
    for width in MAXIMUM_BODY_BYTES - clock::CLOCK_BYTES + 1..=MAXIMUM_BODY_BYTES {
        let mut old_body = vec![0; width];
        old_body[..8].copy_from_slice(REQUESTED_BODY_MAGIC);
        assert!(decode_body(&key, &old_body, 1, 0).is_err());
    }
}

#[test]
fn native_requested_rejects_rewritten_nonce_request_scope_and_premature_active() {
    let original = requested();
    type Mutation = fn(&mut NativeAcquireCompletionRecordV2);
    let mutations: &[Mutation] = &[
        |row| row.challenge = [60; 32],
        |row| row.session_binding = d(60),
        |row| row.attempt_digest = d(60),
        |row| row.root_request_digest = d(60),
        |row| row.native_request_digest = d(60),
        |row| row.challenge_valid_until_seconds += 1,
        |row| row.canonical_request = None,
        |row| row.reservation_acquisition_digest = None,
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.validate_canonical_artifacts().is_err());
        assert!(original.validate_successor(&changed).is_err());
    }
    let active = original
        .advance(NativeAcquireCompletionStateV2::Active)
        .unwrap();
    assert!(active.validate_canonical_artifacts().is_err());
    assert!(reduce_native_acquire_recovery_v2(&original, Some(d(60)), false, None, None).is_err());
    assert_eq!(
        original
            .advance(NativeAcquireCompletionStateV2::Requested)
            .unwrap(),
        original
    );
}
