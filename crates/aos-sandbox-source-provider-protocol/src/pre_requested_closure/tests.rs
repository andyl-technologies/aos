//! Pure closure codec and cryptographic vectors; no protected owner fixtures.

use super::*;
use crate::SourceProviderMethod;
use sha2::Digest as _;

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn signer(key: &SigningKey) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        [1; 16],
        1,
        digest(90),
        [3; 16],
        1,
        SourceProviderKeyUsageV1::ProviderOutcome,
        key,
    )
    .unwrap()
}

fn terminal_witness(family: Family, byte: u8) -> NativeHeldByteWitnessV1 {
    let mut key = match family {
        Family::ProviderAttempt => b"aos.source-provider.attempt.v1\0".to_vec(),
        Family::ProviderAcquisition => b"aos.source-provider.acquisition.v1\0".to_vec(),
        Family::ProviderHolder => b"aos.source-provider.session.v1\0".to_vec(),
        Family::ProviderHistory => b"aos.source-provider.session-history.v1\0".to_vec(),
        _ => panic!("fixture terminal family"),
    };
    key.extend_from_slice(&[1; 16]);
    key.extend_from_slice(&[2; 16]);
    match family {
        Family::ProviderAttempt => {
            key.extend_from_slice(&[7; 16]);
            key.push(SourceProviderMethod::Acquire as u8);
            key.extend_from_slice(&[8; 16]);
        }
        Family::ProviderAcquisition => key.extend_from_slice(digest(4).as_bytes()),
        Family::ProviderHistory => key.extend_from_slice(digest(3).as_bytes()),
        Family::ProviderHolder => {}
        _ => panic!("fixture terminal family"),
    }
    NativeHeldByteWitnessV1::new(family, key, digest(byte)).unwrap()
}

fn claims() -> SourceNoEscapeClosureClaimsV1 {
    let mut challenge_key = b"AOSZHK01".to_vec();
    challenge_key.extend_from_slice(&[9; 32]);
    let challenge_absence = NativeHeldByteWitnessV1::new(
        Family::Challenge,
        challenge_key,
        digest(0),
    )
    .unwrap();

    SourceNoEscapeClosureClaimsV1 {
        provider_id: [1; 16],
        holder_id: [2; 16],
        original_session: digest(3),
        acquisition_id: digest(4),
        original_signed_request: digest(5),
        original_attempt: digest(6),
        original_source_floor: digest(7),
        original_root_prepared: digest(8),
        original_applying: digest(9),
        admission_transaction: [10; 16],
        admission_sequence: 7,
        first_cold_transaction: [11; 16],
        first_cold_sequence: 16,
        challenge_cut: digest(12),
        challenge_sequence: 0,
        staged_claims: digest(13),
        challenge_absence,
        faulted_acquisition: digest(14),
        retired_attempt: digest(15),
        cleared_session: digest(16),
        session_history_successor: digest(17),
        terminal_records: [
            terminal_witness(Family::ProviderAttempt, 21),
            terminal_witness(Family::ProviderAcquisition, 22),
            terminal_witness(Family::ProviderHolder, 23),
            terminal_witness(Family::ProviderHistory, 24),
        ],
    }
}

fn prepared() -> PreparedSourceNoEscapeClosureV1 {
    PreparedSourceNoEscapeClosureV1::new_untrusted(claims(), signer(&signing_key())).unwrap()
}

fn signed() -> SignedSourceNoEscapeClosureV1 {
    SignedSourceNoEscapeClosureV1::sign(&prepared(), &signing_key()).unwrap()
}

#[test]
fn corrected_widths_and_golden_field_offsets_are_exact() {
    let prepared = prepared();
    let bytes = prepared.as_canonical_bytes();

    assert_eq!(SUBJECT_BYTES, 1101);
    assert_eq!(bytes.len(), 1221);
    assert_eq!(SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1, 1285);
    assert_eq!(&bytes[..16], b"AOSPSC01\x01\x01\0\0\0\0\0\0");
    assert_eq!(&bytes[16..32], &[1; 16]);
    assert_eq!(&bytes[32..48], &[2; 16]);
    for (offset, byte) in [
        (48, 3), (80, 4), (112, 5), (144, 6), (176, 7), (208, 8), (240, 9),
    ] {
        assert_eq!(&bytes[offset..offset + 32], &[byte; 32], "offset {offset}");
    }
    assert_eq!(&bytes[272..288], &[10; 16]);
    assert_eq!(&bytes[288..296], &7_u64.to_be_bytes());
    assert_eq!(&bytes[296..312], &[11; 16]);
    assert_eq!(&bytes[312..320], &16_u64.to_be_bytes());
    assert_eq!(&bytes[320..352], &[12; 32]);
    assert_eq!(&bytes[352..360], &[0; 8]);
    assert_eq!(&bytes[360..392], &[13; 32]);
    assert_eq!(
        &bytes[392..468],
        prepared.claims().challenge_absence.to_canonical_bytes(),
    );
    for (offset, byte) in [(468, 14), (500, 15), (532, 16), (564, 17)] {
        assert_eq!(&bytes[offset..offset + 32], &[byte; 32], "offset {offset}");
    }
    for (index, (start, end)) in [(596, 728), (728, 863), (863, 962), (962, 1101)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            &bytes[start..end],
            prepared.claims().terminal_records[index].to_canonical_bytes(),
        );
    }
    let mut expected_signer = Vec::new();
    encode_signer(&mut expected_signer, prepared.signer());
    assert_eq!(&bytes[1101..1221], expected_signer);
}

#[test]
fn round_trips_preserve_prepared_and_signed_bytes() {
    let prepared = prepared();
    let signed = SignedSourceNoEscapeClosureV1::sign(&prepared, &signing_key()).unwrap();
    let bytes = signed.to_canonical_bytes();

    assert_eq!(
        PreparedSourceNoEscapeClosureV1::from_canonical_bytes(prepared.as_canonical_bytes()).unwrap(),
        prepared,
    );
    assert_eq!(
        SignedSourceNoEscapeClosureV1::from_canonical_bytes(&bytes).unwrap(),
        signed,
    );
    assert_eq!(signed.prepared(), &prepared);
    assert_eq!(&bytes[..1221], prepared.as_canonical_bytes());
    assert_eq!(&bytes[1221..1285], signed.signature().as_bytes());
    signed
        .verify(prepared.signer(), &signing_key().verifying_key().to_bytes())
        .unwrap();
}

#[test]
fn signature_message_and_digest_use_exact_independent_domain_layouts() {
    let signed = signed();
    let canonical = signed.prepared().as_canonical_bytes();
    let mut message = b"aos-source-provider-pre-requested-closure.v1\0".to_vec();
    message.push(1);
    message.extend_from_slice(&canonical[1101..1221]);
    message.extend_from_slice(&1101_u32.to_be_bytes());
    message.extend_from_slice(&canonical[..1101]);

    let signature = ed25519_dalek::Signature::from_bytes(signed.signature().as_bytes());
    signing_key()
        .verifying_key()
        .verify_strict(&message, &signature)
        .unwrap();
    for changed_offset in [
        0,
        SIGNATURE_DOMAIN.len(),
        SIGNATURE_DOMAIN.len() + 1,
        message.len() - 1,
    ] {
        let mut changed = message.clone();
        changed[changed_offset] ^= 1;
        assert!(
            signing_key()
                .verifying_key()
                .verify_strict(&changed, &signature)
                .is_err(),
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(b"aos-source-provider-pre-requested-closure-digest.v1\0");
    hasher.update(1285_u32.to_be_bytes());
    hasher.update(signed.to_canonical_bytes());
    assert_eq!(
        signed.digest(),
        ObjectDigest::from_bytes(hasher.finalize().into()),
    );
    assert_eq!(
        SignedSourceNoEscapeClosureV1::sign(signed.prepared(), &signing_key()).unwrap(),
        signed,
    );
}

#[test]
fn every_truncation_and_foreign_width_is_rejected() {
    let prepared = prepared().to_canonical_bytes();
    let signed = signed().to_canonical_bytes();

    for length in 0..prepared.len() {
        assert!(
            PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&prepared[..length]).is_err(),
            "prepared length {length}",
        );
    }
    for length in 0..signed.len() {
        assert!(
            SignedSourceNoEscapeClosureV1::from_canonical_bytes(&signed[..length]).is_err(),
            "signed length {length}",
        );
    }
    for width in [400, 624, 712, 1321, 1385, 8192] {
        let mut foreign = vec![0; width];
        foreign[..16].copy_from_slice(&prepared[..16]);
        assert!(PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&foreign).is_err());
        assert!(SignedSourceNoEscapeClosureV1::from_canonical_bytes(&foreign).is_err());
    }
    let mut trailing = signed.clone();
    trailing.push(0);
    assert!(SignedSourceNoEscapeClosureV1::from_canonical_bytes(&trailing).is_err());
    assert!(PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&signed).is_err());
    assert!(SignedSourceNoEscapeClosureV1::from_canonical_bytes(&prepared).is_err());
}

#[test]
fn header_and_signer_reserved_byte_changes_are_rejected() {
    let bytes = prepared().to_canonical_bytes();
    for offset in (0..16).chain(1214..1221) {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&changed).is_err(),
            "offset {offset}",
        );
    }
}

#[test]
fn all_sentinel_identity_and_record_commitment_fields_are_rejected() {
    let bytes = prepared().to_canonical_bytes();
    let fields = [
        (16, 16), (32, 16), (272, 16), (296, 16),
        (48, 32), (80, 32), (112, 32), (144, 32), (176, 32), (208, 32), (240, 32),
        (320, 32), (360, 32), (468, 32), (500, 32), (532, 32), (564, 32),
        (600, 32), (732, 32), (867, 32), (966, 32),
        (436, 32), (695, 16), (712, 16),
    ];
    for (start, length) in fields {
        let mut changed = bytes.clone();
        changed[start..start + length].fill(0);
        assert!(
            PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&changed).is_err(),
            "offset {start}",
        );
    }
}

#[test]
fn sequence_claims_reject_overflow_and_allow_independent_intervening_appends() {
    let cases: [(&str, fn(&mut SourceNoEscapeClosureClaimsV1)); 4] = [
        ("zero admission", |claims| claims.admission_sequence = 0),
        ("early cold", |claims| claims.first_cold_sequence = 15),
        ("overflow", |claims| claims.admission_sequence = u64::MAX),
        ("same transaction", |claims| {
            claims.first_cold_transaction = claims.admission_transaction;
        }),
    ];
    for (name, mutate) in cases {
        let mut changed = claims();
        mutate(&mut changed);
        assert!(
            PreparedSourceNoEscapeClosureV1::new_untrusted(changed, signer(&signing_key())).is_err(),
            "{name}",
        );
    }

    let mut later = claims();
    later.first_cold_sequence = 102;
    let later =
        PreparedSourceNoEscapeClosureV1::new_untrusted(later, signer(&signing_key())).unwrap();
    assert_eq!(later.claims().challenge_sequence, 0);
    assert_eq!(later.claims().first_cold_sequence, 102);
}

#[test]
fn foreign_role_authority_pin_and_signing_key_are_rejected() {
    for role in [
        SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderKeyUsageV1::ProviderHello,
        SourceProviderKeyUsageV1::RootMountRecord,
        SourceProviderKeyUsageV1::CatalogPublisher,
    ] {
        let foreign = SourceProviderSigningKeyV1::for_signing_key(
            [1; 16],
            1,
            digest(90),
            [3; 16],
            1,
            role,
            &signing_key(),
        )
        .unwrap();
        assert!(PreparedSourceNoEscapeClosureV1::new_untrusted(claims(), foreign).is_err());
    }
    let foreign_authority = SourceProviderSigningKeyV1::for_signing_key(
        [99; 16],
        1,
        digest(90),
        [3; 16],
        1,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &signing_key(),
    )
    .unwrap();
    assert!(
        PreparedSourceNoEscapeClosureV1::new_untrusted(claims(), foreign_authority.clone()).is_err(),
    );

    let signed = signed();
    assert_eq!(
        signed.verify(&foreign_authority, &signing_key().verifying_key().to_bytes()),
        Err(SourceNoEscapeClosureErrorV1::SignerMismatch),
    );
    let other_key = SigningKey::from_bytes(&[43; 32]);
    assert!(SignedSourceNoEscapeClosureV1::sign(signed.prepared(), &other_key).is_err());
    assert!(matches!(
        signed.verify(signed.prepared().signer(), &other_key.verifying_key().to_bytes()),
        Err(SourceNoEscapeClosureErrorV1::Signature(
            SourceProviderSignatureError::PublicKeyMismatch,
        ))
    ));
}

#[test]
fn witness_family_encoding_and_absence_sentinel_are_checked() {
    let bytes = prepared().to_canonical_bytes();
    for offset in [
        392, 394, 428, 596, 598, 632, 728, 730, 764, 863, 865, 899, 962, 964, 998,
    ] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&changed).is_err(),
            "offset {offset}",
        );
    }
    let mut changed = bytes.clone();
    changed[396] = 1;
    assert!(PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&changed).is_err());

    let mut wrong_family = claims();
    wrong_family.terminal_records.swap(0, 1);
    assert!(
        PreparedSourceNoEscapeClosureV1::new_untrusted(wrong_family, signer(&signing_key())).is_err(),
    );

    let mut wrong_namespace = bytes;
    wrong_namespace[392..394].copy_from_slice(&42_u16.to_be_bytes());
    assert!(matches!(
        PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&wrong_namespace),
        Err(SourceNoEscapeClosureErrorV1::Witness(_)),
    ));
}

#[test]
fn terminal_witness_source_acquisition_and_history_joins_are_checked() {
    let original = claims();
    for (index, tail_offset) in [
        (0, 0), (0, 16), (1, 0), (1, 16), (1, 32),
        (2, 0), (2, 16), (3, 0), (3, 16), (3, 32),
    ] {
        let mut changed = original.clone();
        let witness = &changed.terminal_records[index];
        let mut key = witness.key().to_vec();
        let subject_start = key.len() - TERMINAL_KEY_SUBJECT_BYTES[index];
        key[subject_start + tail_offset] ^= 1;
        let replacement =
            NativeHeldByteWitnessV1::new(witness.family(), key, witness.digest()).unwrap();
        changed.terminal_records[index] = replacement;
        assert!(
            PreparedSourceNoEscapeClosureV1::new_untrusted(changed, signer(&signing_key())).is_err(),
            "record {index}, offset {tail_offset}",
        );
    }
}

#[test]
fn decoder_does_not_invent_absent_original_artifact_or_record_byte_joins() {
    let mut bytes = prepared().to_canonical_bytes();
    // The raw stage and Acquire are absent: these nonzero claims still need
    // actual owner joins, and changing them must not create a protected permit.
    bytes[460] ^= 1;
    bytes[710] ^= 1;
    let decoded = PreparedSourceNoEscapeClosureV1::from_canonical_bytes(&bytes).unwrap();

    assert_ne!(
        decoded.claims().faulted_acquisition,
        decoded.claims().terminal_records[1].digest(),
    );
    assert_eq!(decoded.claims().challenge_absence.digest(), digest(0));
    assert_eq!(decoded.to_canonical_bytes(), bytes);
}

#[test]
fn signature_claims_parse_without_verification_and_tampering_is_detected() {
    let signed = signed();
    let expected_signer = signed.prepared().signer();
    let public_key = signing_key().verifying_key().to_bytes();
    for offset in [112, 320, 360, 468, 600, 1221, 1284] {
        let mut changed = signed.to_canonical_bytes();
        changed[offset] ^= 1;
        let parsed = SignedSourceNoEscapeClosureV1::from_canonical_bytes(&changed).unwrap();
        assert!(parsed.verify(expected_signer, &public_key).is_err(), "offset {offset}");
        assert_ne!(parsed.digest(), signed.digest());
    }
    let mut zero_signature = signed.to_canonical_bytes();
    zero_signature[1221..].fill(0);
    let parsed = SignedSourceNoEscapeClosureV1::from_canonical_bytes(&zero_signature).unwrap();
    assert!(parsed.verify(expected_signer, &public_key).is_err());
}

#[test]
fn weak_key_material_is_rejected_by_existing_crypto_verifier() {
    let weak_public_key = [0; 32];
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(weak_public_key).into());
    let weak_signer = SourceProviderSigningKeyV1::new(
        [1; 16],
        1,
        digest(90),
        [3; 16],
        1,
        fingerprint,
        SourceProviderKeyUsageV1::ProviderOutcome,
    )
    .unwrap();
    let prepared =
        PreparedSourceNoEscapeClosureV1::new_untrusted(claims(), weak_signer.clone()).unwrap();
    let mut bytes = prepared.to_canonical_bytes();
    bytes.resize(SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1, 0);
    let signed = SignedSourceNoEscapeClosureV1::from_canonical_bytes(&bytes).unwrap();

    assert!(matches!(
        signed.verify(&weak_signer, &weak_public_key),
        Err(SourceNoEscapeClosureErrorV1::Signature(
            SourceProviderSignatureError::InvalidPublicKey,
        ))
    ));
}
