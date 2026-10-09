//! Descriptor-free metadata vectors using the shared native cryptographic fixture.

use super::*;
use crate::crypto::sign_bytes;

fn query(fixture: &Fixture) -> SignedStorageNativeAcceptanceReadbackQueryV1 {
    SignedStorageNativeAcceptanceReadbackQueryV1::sign(
        StorageNativeAcceptanceReadbackQueryV1::new(63, d(61), [62; 32], &fixture.request).unwrap(),
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap()
}

fn answer(
    fixture: &Fixture,
    query: &SignedStorageNativeAcceptanceReadbackQueryV1,
) -> SignedStorageNativeAcceptanceReadbackV1 {
    SignedStorageNativeAcceptanceReadbackV1::sign(
        query,
        64,
        Some(fixture.acceptance.acceptance().clone()),
        fixture.receipt.signer(),
        &fixture.storage_key,
    )
    .unwrap()
}

fn resign_query(bytes: &mut [u8], fixture: &Fixture) {
    let signature = sign_bytes(
        b"aos.sandbox.provider.native-acceptance-readback.query.signature.v1\0",
        1,
        &bytes[..184],
        fixture.request.signer(),
        &fixture.provider_key,
    )
    .unwrap();
    bytes[304..].copy_from_slice(signature.as_bytes());
}

fn resign_answer(bytes: &mut [u8], fixture: &Fixture, domain: &[u8]) {
    let message = super::super::acceptance::storage_signing_message(
        domain,
        &bytes[..280],
        fixture.receipt.signer(),
    );
    bytes[368..].copy_from_slice(&fixture.storage_key.sign(&message).to_bytes());
}

#[test]
fn native_acceptance_readback_round_trip_preserves_original_unsigned_metadata() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    let answer = answer(&fixture, &query);
    let query_bytes = query.to_canonical_bytes();
    let answer_bytes = answer.to_canonical_bytes();

    assert_eq!(
        query_bytes.len(),
        SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_QUERY_BYTES_V1
    );
    assert_eq!(
        answer_bytes.len(),
        SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1
    );
    assert_eq!(&query_bytes[..10], b"AOSZNR01\0\x01");
    assert_eq!(&answer_bytes[..10], b"AOSZNS01\0\x01");
    assert_eq!(query.query().carrier(), (63, d(61), [62; 32]));
    assert_eq!(
        query.query().scope(),
        (
            fixture.request.request().claims().provider_acquisition().0,
            fixture.request.request().claims().holder_session().0,
            fixture.request.request().claims().provider_acquisition().1,
        )
    );
    assert_eq!(query.query().request_digest(), fixture.request.digest());
    assert_eq!(answer.observed_issuance_sequence(), 64);
    assert_eq!(answer.acceptance(), Some(fixture.acceptance.acceptance()));
    assert_eq!(
        &answer_bytes[64..64 + STORAGE_NATIVE_ACCEPTANCE_BYTES_V3],
        &fixture.acceptance.acceptance().to_canonical_bytes()
    );
    assert_eq!(
        SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&query_bytes).unwrap(),
        query
    );
    assert_eq!(
        SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&answer_bytes).unwrap(),
        answer
    );
    query
        .verify(
            fixture.request.signer(),
            &fixture.provider_key.verifying_key().to_bytes(),
        )
        .unwrap();
    answer.verify_for(&query, fixture.verifier).unwrap();

    // The identical query can reobserve another held cut. Neither signature
    // promotes its diagnostic sequence to a latest-state freshness authority.
    let reobserved = SignedStorageNativeAcceptanceReadbackV1::sign(
        &query,
        65,
        Some(fixture.acceptance.acceptance().clone()),
        fixture.receipt.signer(),
        &fixture.storage_key,
    )
    .unwrap();
    reobserved.verify_for(&query, fixture.verifier).unwrap();
    assert_eq!(reobserved.acceptance(), answer.acceptance());
    assert_eq!(reobserved.observed_issuance_sequence(), 65);
    assert_ne!(reobserved.digest(), answer.digest());

    // An empty journal cut is allowed only as a transient NotFound observation.
    for sequence in [0, 64] {
        let not_found = SignedStorageNativeAcceptanceReadbackV1::sign(
            &query,
            sequence,
            None,
            fixture.receipt.signer(),
            &fixture.storage_key,
        )
        .unwrap();
        not_found.verify_for(&query, fixture.verifier).unwrap();
        assert_eq!(not_found.acceptance(), None);
        assert_eq!(not_found.observed_issuance_sequence(), sequence);
        assert_eq!(
            &not_found.to_canonical_bytes()[64..280],
            &[0; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3]
        );
    }
}

#[test]
fn native_acceptance_readback_canonical_golden_metadata_domains() {
    // These claimed-signature vectors test decoding, not authentication. Their
    // documented fixed fields were hashed independently with AOS OpenSSL 4.0.2.
    let query_bytes = hex::decode(concat!(
        "414f535a4e5230310001000000000000",
        "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d",
        "3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e",
        "000000000000003f2121212121212121212121212121212107070707070707070707070707070707",
        "4040404040404040404040404040404040404040404040404040404040404040",
        "4141414141414141414141414141414141414141414141414141414141414141",
        "212121212121212121212121212121210000000000000023",
        "2424242424242424242424242424242424242424242424242424242424242424",
        "252525252525252525252525252525250000000000000026",
        "4242424242424242424242424242424242424242424242424242424242424242",
        "0400000000000000",
        "4343434343434343434343434343434343434343434343434343434343434343",
        "4343434343434343434343434343434343434343434343434343434343434343",
    ))
    .unwrap();
    let query =
        SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&query_bytes).unwrap();
    assert_eq!(query.to_canonical_bytes(), query_bytes);
    assert_eq!(query.query().carrier(), (63, d(61), [62; 32]));
    assert_eq!(query.query().scope(), ([33; 16], [7; 16], d(64)));
    assert_eq!(query.query().request_digest(), d(65));
    assert_eq!(
        query.digest().as_bytes().as_slice(),
        hex::decode("9d4e4a643b0d23ff415fca6b404870fe6a86b604f6cb8388d5a9e2311714eb53").unwrap()
    );

    let mut answer_bytes = hex::decode(concat!(
        "414f535a4e5330310001000000000000",
        "9d4e4a643b0d23ff415fca6b404870fe6a86b604f6cb8388d5a9e2311714eb53",
        "00000000000000000200000000000000",
    ))
    .unwrap();
    answer_bytes.extend_from_slice(&[0; STORAGE_NATIVE_ACCEPTANCE_BYTES_V3]);
    answer_bytes.extend_from_slice(
        &hex::decode(concat!(
            "414f535a485347312e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e0000000000000029",
            "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
            "2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f0000000000000030",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "4444444444444444444444444444444444444444444444444444444444444444",
        ))
        .unwrap(),
    );
    let answer =
        SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&answer_bytes).unwrap();
    assert_eq!(answer.to_canonical_bytes(), answer_bytes);
    assert_eq!(answer.acceptance(), None);
    assert_eq!(answer.observed_issuance_sequence(), 0);
    assert_eq!(
        answer.digest().as_bytes().as_slice(),
        hex::decode("8d9f218f9aa9e02640e1ec484329646dbd5ad559b8641bebecc2073259a03601").unwrap()
    );
    assert_ne!(
        query.digest(),
        digest(
            b"aos.sandbox.provider.native-cleanup.digest.v2\0",
            &query_bytes
        )
    );
    assert_ne!(
        answer.digest(),
        digest(
            b"aos.sandbox.storage.native-acceptance.signed-digest.v3\0",
            &answer_bytes
        )
    );
}

#[test]
fn native_acceptance_readback_rejects_query_sentinels_padding_and_versions() {
    let fixture = Fixture::new();
    let bytes = query(&fixture).to_canonical_bytes();
    for (start, width) in [
        (16, 32),
        (48, 32),
        (80, 8),
        (88, 16),
        (104, 16),
        (120, 32),
        (152, 32),
        (304, 64),
    ] {
        let mut changed = bytes.clone();
        changed[start..start + width].fill(0);
        assert!(
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&changed).is_err()
        );
    }
    for offset in [0, 7, 8, 9, 10, 15, 296, 297, 303] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&changed).is_err()
        );
    }
    assert!(
        SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes[..367]).is_err()
    );
    let mut padded = bytes;
    padded.push(0);
    assert!(SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&padded).is_err());

    for (sequence, binding, nonce) in [
        (0, d(61), [62; 32]),
        (63, d(0), [62; 32]),
        (63, d(61), [0; 32]),
    ] {
        assert!(
            StorageNativeAcceptanceReadbackQueryV1::new(sequence, binding, nonce, &fixture.request)
                .is_err()
        );
    }
}

#[test]
fn native_acceptance_readback_rejects_answer_sentinels_dispositions_and_payloads() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    let bytes = answer(&fixture, &query).to_canonical_bytes();
    for (start, width) in [
        (16, 32),
        (48, 8),
        (64, STORAGE_NATIVE_ACCEPTANCE_BYTES_V3),
        (368, 64),
    ] {
        let mut changed = bytes.clone();
        changed[start..start + width].fill(0);
        assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&changed).is_err());
    }
    for offset in [0, 7, 8, 9, 10, 15, 57, 63, 64, 72, 73, 74, 79, 280] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&changed).is_err());
    }
    for disposition in [0, 2, 3, u8::MAX] {
        let mut changed = bytes.clone();
        changed[56] = disposition;
        assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&changed).is_err());
    }
    assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes[..431]).is_err());
    let mut padded = bytes;
    padded.push(0);
    assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&padded).is_err());
    assert_eq!(
        SignedStorageNativeAcceptanceReadbackV1::sign(
            &query,
            0,
            Some(fixture.acceptance.acceptance().clone()),
            fixture.receipt.signer(),
            &fixture.storage_key
        ),
        Err(StorageNativeAcquireErrorV2::Noncanonical)
    );

    let not_found = SignedStorageNativeAcceptanceReadbackV1::sign(
        &query,
        0,
        None,
        fixture.receipt.signer(),
        &fixture.storage_key,
    )
    .unwrap();
    let mut changed = not_found.to_canonical_bytes();
    changed[64] = 1;
    assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&changed).is_err());
}

#[test]
fn native_acceptance_readback_requires_provider_purpose_and_independent_pin() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    for (authority, usage) in [
        ([33; 16], SourceProviderKeyUsageV1::RootMountRecord),
        ([66; 16], SourceProviderKeyUsageV1::ProviderOutcome),
    ] {
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            authority,
            35,
            d(36),
            [37; 16],
            38,
            usage,
            &fixture.provider_key,
        )
        .unwrap();
        assert_eq!(
            SignedStorageNativeAcceptanceReadbackQueryV1::sign(
                query.query().clone(),
                signer,
                &fixture.provider_key
            ),
            Err(StorageNativeAcquireErrorV2::Authority)
        );
    }
    assert_eq!(
        SignedStorageNativeAcceptanceReadbackQueryV1::sign(
            query.query().clone(),
            fixture.request.signer().clone(),
            &fixture.root_key
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    assert_eq!(
        query.verify(
            fixture.request.signer(),
            &fixture.root_key.verifying_key().to_bytes()
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    let foreign_pin = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        36,
        d(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &fixture.provider_key,
    )
    .unwrap();
    assert_eq!(
        query.verify(
            &foreign_pin,
            &fixture.provider_key.verifying_key().to_bytes()
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );

    let mut bytes = query.to_canonical_bytes();
    let signature = sign_bytes(
        b"aos.sandbox.provider.native-cleanup.signature.v2\0",
        2,
        &bytes[..184],
        query.signer(),
        &fixture.provider_key,
    )
    .unwrap();
    bytes[304..].copy_from_slice(signature.as_bytes());
    let wrong_purpose =
        SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(
        wrong_purpose.verify(
            query.signer(),
            &fixture.provider_key.verifying_key().to_bytes()
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
}

#[test]
fn native_acceptance_readback_requires_storage_purpose_and_independent_pin() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    let answer = answer(&fixture, &query);
    let foreign_signer = StorageZfsHoldSignerV1::new([67; 16], 41, d(42), [47; 16], 48).unwrap();
    let foreign_pin = StorageZfsHoldVerifierV1::new(
        foreign_signer,
        fixture.storage_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        answer.verify_for(&query, foreign_pin),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    let wrong_key = StorageZfsHoldVerifierV1::new(
        fixture.receipt.signer(),
        fixture.root_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        answer.verify_for(&query, wrong_key),
        Err(StorageNativeAcquireErrorV2::Authority)
    );

    for domain in [
        b"aos.sandbox.storage.native-acceptance.signature.v3\0".as_slice(),
        b"aos.sandbox.storage.native-cleanup.signature.v2\0".as_slice(),
    ] {
        let mut bytes = answer.to_canonical_bytes();
        resign_answer(&mut bytes, &fixture, domain);
        let wrong_purpose =
            SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            wrong_purpose.verify_for(&query, fixture.verifier),
            Err(StorageNativeAcquireErrorV2::Authority)
        );
    }
}

#[test]
fn native_acceptance_readback_binds_every_query_field_and_original_acceptance() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    let answer = answer(&fixture, &query);
    for offset in [16, 48, 87, 104, 120, 152] {
        let mut bytes = query.to_canonical_bytes();
        bytes[offset] ^= 1;
        resign_query(&mut bytes, &fixture);
        let changed =
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes).unwrap();
        changed
            .verify(
                query.signer(),
                &fixture.provider_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(
            answer.verify_for(&changed, fixture.verifier),
            Err(StorageNativeAcquireErrorV2::Mismatch)
        );
    }

    // Even a correctly signed wrapper cannot crosslink another original request.
    let mut bytes = answer.to_canonical_bytes();
    bytes[96] ^= 1;
    resign_answer(
        &mut bytes,
        &fixture,
        b"aos.sandbox.storage.native-acceptance-readback.answer.signature.v1\0",
    );
    let changed = SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(
        changed.verify_for(&query, fixture.verifier),
        Err(StorageNativeAcquireErrorV2::Mismatch)
    );
    assert_eq!(
        SignedStorageNativeAcceptanceReadbackV1::sign(
            &query,
            64,
            changed.acceptance().cloned(),
            fixture.receipt.signer(),
            &fixture.storage_key
        ),
        Err(StorageNativeAcquireErrorV2::Mismatch)
    );

    for offset in [16, 55, 96, 112, 136, 160, 200] {
        let mut bytes = answer.to_canonical_bytes();
        bytes[offset] ^= 1;
        let changed =
            SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            changed.verify_for(&query, fixture.verifier),
            Err(StorageNativeAcquireErrorV2::Authority)
        );
    }
}

#[test]
fn native_acceptance_readback_fresh_key_does_not_reissue_historical_request() {
    let fixture = Fixture::new();
    let old_bytes = fixture.request.to_canonical_bytes();
    let fresh_key = SigningKey::from_bytes(&[68; 32]);
    let fresh_signer = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        69,
        d(70),
        [71; 16],
        72,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &fresh_key,
    )
    .unwrap();
    let query = SignedStorageNativeAcceptanceReadbackQueryV1::sign(
        StorageNativeAcceptanceReadbackQueryV1::new(73, d(74), [75; 32], &fixture.request).unwrap(),
        fresh_signer.clone(),
        &fresh_key,
    )
    .unwrap();
    query
        .verify(&fresh_signer, &fresh_key.verifying_key().to_bytes())
        .unwrap();
    assert_eq!(
        query.verify(
            fixture.request.signer(),
            &fixture.provider_key.verifying_key().to_bytes()
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    let answer = answer(&fixture, &query);
    answer.verify_for(&query, fixture.verifier).unwrap();
    assert_eq!(query.query().request_digest(), fixture.request.digest());
    assert_eq!(fixture.request.to_canonical_bytes(), old_bytes);
    assert_eq!(answer.acceptance(), Some(fixture.acceptance.acceptance()));
}

#[test]
fn native_acceptance_readback_rejects_acquire_cleanup_and_positive_conversion() {
    let fixture = Fixture::new();
    let query = query(&fixture);
    let answer = answer(&fixture, &query);
    let cleanup = SignedStorageNativeCleanupRequestV2::sign(
        StorageNativeCleanupRequestV2::new(
            63,
            d(61),
            [62; 32],
            StorageNativeCleanupReasonV2::CustodyLost,
            &fixture.request,
            fixture.acceptance.acceptance(),
        )
        .unwrap(),
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap();
    let cleanup_receipt = SignedStorageNativeCleanupReceiptV2::sign(
        StorageNativeCleanupReceiptV2::new(
            &cleanup,
            d(76),
            StorageNativeCleanupDispositionV2::Absent,
        )
        .unwrap(),
        fixture.receipt.signer(),
        &fixture.storage_key,
    );
    for mut bytes in [
        fixture.request.to_canonical_bytes(),
        fixture.reply().to_canonical_bytes(),
        cleanup.to_canonical_bytes(),
        cleanup_receipt.to_canonical_bytes(),
        fixture.acceptance.to_canonical_bytes(),
    ] {
        assert!(
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes).is_err()
        );
        assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes).is_err());
        bytes.resize(SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_QUERY_BYTES_V1, 0);
        assert!(
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes).is_err()
        );
        bytes.resize(SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1, 0);
        assert!(SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&bytes).is_err());
    }
    assert!(
        SignedStorageNativeAcceptanceV3::from_canonical_bytes(&query.to_canonical_bytes()).is_err()
    );
    assert!(
        SignedStorageNativeAcceptanceV3::from_canonical_bytes(&answer.to_canonical_bytes())
            .is_err()
    );
    assert!(
        StorageNativeAcquireReplyV3::from_canonical_bytes(&answer.to_canonical_bytes()).is_err()
    );
    assert!(
        SignedStorageNativeCleanupRequestV2::from_canonical_bytes(&query.to_canonical_bytes())
            .is_err()
    );

    assert!(
        SignedStorageNativeCleanupReceiptV2::from_canonical_bytes(&answer.to_canonical_bytes())
            .is_err()
    );
}
