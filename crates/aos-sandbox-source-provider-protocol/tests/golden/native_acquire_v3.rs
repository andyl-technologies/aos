//! Native V3 data, independent wire layout, and signed substitution regressions.

use super::*;

const CATALOG_BLOCK_BYTES: usize = 176;
const SIGNED_SUBJECT_OFFSET: usize = 140;

fn catalog() -> NativeAcquireCatalogBindingV3 {
    NativeAcquireCatalogBindingV3::new(
        digest(61),
        9,
        digest(62),
        7,
        digest(63),
        digest(64),
        digest(65),
    )
    .unwrap()
}

fn request_v2(kernel_coupled: bool) -> AcquireSourceRequestV1 {
    let original = acquire_with([1; 16], DEADLINE, 600, true, 4, kernel_coupled);
    AcquireSourceRequestV1::new_v2(
        original.session_binding(),
        original.sequence(),
        original.request_id(),
        17,
        original.prospective_apply_template().to_vec(),
        original.prospective_apply_template_digest(),
        original.source_use(),
        original.node_id(),
        original.boot_id(),
        original.holder_authority_id(),
        original.holder_generation(),
        original.holder_authority_digest(),
        original.binding().to_vec(),
        original.binding_digest(),
        original.deadline_seconds(),
        original.requested_lease_seconds(),
        original.revocation_digest(),
        original.recursive(),
        original.requested_maximum_submounts(),
        original.kernel_coupled(),
    )
    .unwrap()
}

fn request_v3() -> AcquireSourceRequestV1 {
    AcquireSourceRequestV1::new_native_v3(request_v2(false), catalog()).unwrap()
}

fn replace_signed_subject(
    original: &SignedSourceProviderRequestV1,
    subject: &[u8],
) -> SignedSourceProviderRequestV1 {
    let original_bytes = original.to_canonical_bytes();
    let mut bytes = original_bytes[..SIGNED_SUBJECT_OFFSET].to_vec();
    bytes[136..140].copy_from_slice(&(subject.len() as u32).to_be_bytes());
    bytes.extend_from_slice(subject);
    bytes.extend_from_slice(&original_bytes[original_bytes.len() - 64..]);
    SignedSourceProviderRequestV1::from_canonical_bytes(&bytes).unwrap()
}

#[test]
fn native_v3_shares_exact_legacy_tail_and_explicit_sequence_identity() {
    let legacy = acquire_with([1; 16], DEADLINE, 600, true, 4, false);
    let legacy_bytes = encode_acquire_request(&legacy);
    let v2 = request_v2(false);
    let v2_bytes = encode_acquire_request(&v2);
    let v3 = request_v3();

    // Reconstruct V2 independently from the original untagged layout. Only
    // its holder-derived acquisition ID and explicit sequence are different.
    let mut expected_v2 = vec![0, 2, 0, 0, 0, 0, 0, 0];
    expected_v2.extend_from_slice(&legacy_bytes[..56]);
    expected_v2.extend_from_slice(v2.acquisition_id().as_bytes());
    expected_v2.extend_from_slice(&17_u64.to_be_bytes());
    expected_v2.extend_from_slice(&legacy_bytes[88..]);
    assert_eq!(v2_bytes, expected_v2);

    // Literal field widths/order pin the new catalog block independently of
    // the encoder and accessors; the entire existing V2 payload is reused.
    let mut expected_v3 = vec![0, 3, 1, 0, 0, 0, 0, 0];
    expected_v3.extend_from_slice(&[61; 32]);
    expected_v3.extend_from_slice(&9_u64.to_be_bytes());
    expected_v3.extend_from_slice(&[62; 32]);
    expected_v3.extend_from_slice(&7_u64.to_be_bytes());
    expected_v3.extend_from_slice(&[63; 32]);
    expected_v3.extend_from_slice(&[64; 32]);
    expected_v3.extend_from_slice(&[65; 32]);
    expected_v3.extend_from_slice(&v2_bytes[8..]);
    assert_eq!(encode_acquire_request(&v3), expected_v3);
    assert_eq!(expected_v3.len(), v2_bytes.len() + CATALOG_BLOCK_BYTES);

    assert_eq!(decode_acquire_request(&legacy_bytes).unwrap(), legacy);
    assert_eq!(decode_acquire_request(&v2_bytes).unwrap(), v2);
    assert_eq!(decode_acquire_request(&expected_v3).unwrap(), v3);
    assert_eq!(v3.acquisition_version(), ACQUIRE_SOURCE_REQUEST_VERSION_V3);
    assert_eq!(v3.acquisition_id(), v2.acquisition_id());
    assert_eq!(v3.acquisition_sequence(), 17);
    assert_eq!(v3.native_catalog(), Some(&catalog()));
    assert!(legacy.native_catalog().is_none());
    assert!(v2.native_catalog().is_none());
}

#[test]
fn native_v3_requires_every_catalog_claim_and_an_unforked_floor() {
    let bytes = encode_acquire_request(&request_v3());
    for field in [8..40, 40..48, 48..80, 80..88, 88..120, 120..152, 152..184] {
        let mut malformed = bytes.clone();
        malformed[field.clone()].fill(0);
        assert!(
            decode_acquire_request(&malformed).is_err(),
            "zero {field:?}"
        );
    }

    let mut higher_floor = bytes.clone();
    higher_floor[80..88].copy_from_slice(&10_u64.to_be_bytes());
    assert!(decode_acquire_request(&higher_floor).is_err());

    let mut equal_generation_fork = bytes.clone();
    equal_generation_fork[80..88].copy_from_slice(&9_u64.to_be_bytes());
    assert!(decode_acquire_request(&equal_generation_fork).is_err());
    equal_generation_fork[88..120].copy_from_slice(&[62; 32]);
    assert!(decode_acquire_request(&equal_generation_fork).is_ok());
}

#[test]
fn native_v3_rejects_unknown_tags_reserved_bytes_and_missing_catalog() {
    let bytes = encode_acquire_request(&request_v3());
    for version in [0_u16, 1, 2, 4, u16::MAX] {
        let mut malformed = bytes.clone();
        malformed[..2].copy_from_slice(&version.to_be_bytes());
        assert!(
            decode_acquire_request(&malformed).is_err(),
            "version {version}"
        );
    }
    for kind in [0, 2, u8::MAX] {
        let mut malformed = bytes.clone();
        malformed[2] = kind;
        assert!(
            decode_acquire_request(&malformed).is_err(),
            "profile {kind}"
        );
    }
    for offset in 3..8 {
        let mut malformed = bytes.clone();
        malformed[offset] = 1;
        assert!(
            decode_acquire_request(&malformed).is_err(),
            "reserved {offset}"
        );
    }

    let mut missing_catalog = bytes[..8].to_vec();
    missing_catalog.extend_from_slice(&bytes[184..]);
    assert!(decode_acquire_request(&missing_catalog).is_err());
    for length in 0..bytes.len() {
        assert!(
            decode_acquire_request(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_acquire_request(&trailing).is_err());
}

#[test]
fn native_v3_rejects_kernel_coupling_and_implicit_version_conversion() {
    assert!(AcquireSourceRequestV1::new_native_v3(acquire(), catalog()).is_err());
    assert!(AcquireSourceRequestV1::new_native_v3(request_v3(), catalog()).is_err());
    assert!(AcquireSourceRequestV1::new_native_v3(request_v2(true), catalog()).is_err());

    let mut kernel_coupled = encode_acquire_request(&request_v3());
    let flags_offset = kernel_coupled.len() - 8;
    kernel_coupled[flags_offset] |= 2;
    assert!(decode_acquire_request(&kernel_coupled).is_err());
}

#[test]
fn native_v3_signed_catalog_fields_cannot_be_substituted() {
    let request = request_v3();
    let key = SigningKey::from_bytes(&[50; 32]);
    let signed = signed_request(&request, &key);
    let key_bytes = key.verifying_key().to_bytes();
    aos_sandbox_source_provider_protocol::verify_request(&signed, &key_bytes).unwrap();

    for offset in [39, 47, 79, 87, 119, 151, 183] {
        let mut subject = encode_acquire_request(&request);
        subject[offset] ^= 1;
        let changed = decode_acquire_request(&subject).unwrap();
        assert_ne!(
            digest_acquire_request(&changed),
            digest_acquire_request(&request)
        );
        assert_ne!(
            source_provider_acquire_intent_digest_v1(&changed),
            source_provider_acquire_intent_digest_v1(&request)
        );

        let substituted = replace_signed_subject(&signed, &subject);
        assert!(
            aos_sandbox_source_provider_protocol::verify_request(&substituted, &key_bytes).is_err()
        );
    }
}

#[test]
fn native_v3_cannot_be_downgraded_under_the_original_signature() {
    let key = SigningKey::from_bytes(&[50; 32]);
    let signed = signed_request(&request_v3(), &key);
    let key_bytes = key.verifying_key().to_bytes();

    // V1/V2 remain valid distinct profiles. Removing the mandatory V3 block
    // cannot turn the original signature into an authenticated old request.
    for subject in [
        encode_acquire_request(&request_v2(false)),
        encode_acquire_request(&acquire()),
    ] {
        let downgraded = replace_signed_subject(&signed, &subject);
        assert!(
            aos_sandbox_source_provider_protocol::verify_request(&downgraded, &key_bytes).is_err()
        );
    }
}

#[test]
fn native_v3_intent_is_distinct_while_original_v1_v2_projection_is_unchanged() {
    let legacy = acquire_with([1; 16], DEADLINE, 600, true, 4, false);
    let v2 = request_v2(false);
    let v3 = request_v3();

    // Freeze the original deadline-free schema independently of the production
    // projection. Neither old acquisition identity nor version is in it.
    let template = mount_template();
    let binding = b"binding-v1";
    let mut old_preimage = b"aos-source-provider-acquire-intent-v1\0".to_vec();
    old_preimage.extend_from_slice(&(template.len() as u32).to_be_bytes());
    old_preimage.extend_from_slice(&template);
    old_preimage.extend_from_slice(legacy.prospective_apply_template_digest().as_bytes());
    old_preimage.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    old_preimage.extend_from_slice(&[4; 16]);
    old_preimage.extend_from_slice(&[5; 16]);
    old_preimage.extend_from_slice(&[31; 16]);
    old_preimage.extend_from_slice(&32_u64.to_be_bytes());
    old_preimage.extend_from_slice(&[33; 32]);
    old_preimage.extend_from_slice(&(binding.len() as u32).to_be_bytes());
    old_preimage.extend_from_slice(binding);
    old_preimage.extend_from_slice(legacy.binding_digest().as_bytes());
    old_preimage.extend_from_slice(&600_u64.to_be_bytes());
    old_preimage.extend_from_slice(&[90; 32]);
    old_preimage.extend_from_slice(&[1, 0, 0, 0]);
    old_preimage.extend_from_slice(&4_u32.to_be_bytes());
    let old_digest = ObjectDigest::from_bytes(Sha256::digest(&old_preimage).into());

    assert_eq!(
        source_provider_acquire_intent_digest_v1(&legacy),
        old_digest
    );
    assert_eq!(source_provider_acquire_intent_digest_v1(&v2), old_digest);
    assert_ne!(source_provider_acquire_intent_digest_v1(&v3), old_digest);

    // Independently pin V3's distinct domain, explicit profile, all seven
    // catalog fields, and the unchanged common semantic projection.
    let wire = encode_acquire_request(&v3);
    let mut native_preimage = b"aos-source-provider-native-acquire-intent-v3\0".to_vec();
    native_preimage.extend_from_slice(&wire[..184]);
    native_preimage
        .extend_from_slice(&old_preimage[b"aos-source-provider-acquire-intent-v1\0".len()..]);
    assert_eq!(
        source_provider_acquire_intent_digest_v1(&v3),
        ObjectDigest::from_bytes(Sha256::digest(native_preimage).into())
    );
}

#[test]
fn native_v3_intent_remains_stable_across_transport_and_deadline_renewal() {
    let original = request_v3();
    let mut bytes = encode_acquire_request(&original);
    bytes[184..216].copy_from_slice(&[66; 32]);
    bytes[216..224].copy_from_slice(&2_u64.to_be_bytes());
    bytes[224..240].copy_from_slice(&[8; 16]);
    let changed_acquisition = source_acquisition_id_v2([31; 16], 32, digest(33), 18);
    bytes[240..272].copy_from_slice(changed_acquisition.as_bytes());
    bytes[272..280].copy_from_slice(&18_u64.to_be_bytes());
    let deadline_offset = bytes.len() - 56;
    bytes[deadline_offset..deadline_offset + 8].copy_from_slice(&(DEADLINE + 100).to_be_bytes());
    let renewed = decode_acquire_request(&bytes).unwrap();

    assert_ne!(
        digest_acquire_request(&renewed),
        digest_acquire_request(&original)
    );
    assert_eq!(renewed.native_catalog(), original.native_catalog());
    assert_eq!(
        source_provider_acquire_intent_digest_v1(&renewed),
        source_provider_acquire_intent_digest_v1(&original)
    );
}

#[test]
fn legacy_normalized_intent_rejects_native_v3_without_discarding_catalog() {
    let key = SigningKey::from_bytes(&[51; 32]);
    let provider = provider_authority(&key);
    let holder = SourceProviderAuthorityV1::new([31; 16], 32, digest(33)).unwrap();
    let normalize = |request: &AcquireSourceRequestV1| {
        NormalizedAcquisitionIntentV2::from_acquire_request(
            request,
            provider.clone(),
            holder.clone(),
            [4; 16],
            [5; 16],
            [55; 16],
            56,
            digest(57),
            digest(61),
            91,
            digest(90),
        )
    };

    let original = normalize(&request_v2(false)).unwrap();
    assert_eq!(
        NormalizedAcquisitionIntentV2::from_canonical_bytes(&original.to_canonical_bytes())
            .unwrap(),
        original
    );
    assert_eq!(
        normalize(&request_v3()),
        Err(NormalizedAcquisitionIntentError::Invalid)
    );
}
