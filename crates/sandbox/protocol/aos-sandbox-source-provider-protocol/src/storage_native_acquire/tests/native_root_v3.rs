//! Synthetic original-Root V3 envelope tests; no protected owner proof is created.

use super::*;

fn native_binding(fixture: &Fixture) -> NativeAcquireCatalogBindingV3 {
    let claims = fixture.request.request().claims();
    let catalog = claims.catalog();
    NativeAcquireCatalogBindingV3::new(
        catalog.namespace_digest(),
        catalog.generation(),
        catalog.digest(),
        catalog.generation() - 1,
        d(76),
        claims.selection().1,
        d(77),
    )
    .unwrap()
}

fn signed_root(fixture: &Fixture, root: &AcquireSourceRequestV1) -> SignedSourceProviderRequestV1 {
    sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(root),
        fixture
            .request
            .request()
            .signed_root_request()
            .signer()
            .clone(),
        &fixture.root_key,
    )
    .unwrap()
}

fn v3_root(fixture: &Fixture) -> AcquireSourceRequestV1 {
    let root =
        decode_acquire_request(fixture.request.request().signed_root_request().subject()).unwrap();
    AcquireSourceRequestV1::new_native_v3(root, native_binding(fixture)).unwrap()
}

fn signed_native(
    fixture: &Fixture,
    root: &AcquireSourceRequestV1,
) -> SignedStorageNativeAcquireRequestV2 {
    let request = StorageNativeAcquireRequestV2::new_native_v3(
        fixture.request.request().claims().clone(),
        signed_root(fixture, root),
    )
    .unwrap();
    SignedStorageNativeAcquireRequestV2::sign(
        request,
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap()
}

fn verify(fixture: &Fixture, request: &SignedStorageNativeAcquireRequestV2) {
    request
        .verify(
            fixture.request.signer(),
            &fixture.provider_key.verifying_key().to_bytes(),
            fixture.request.request().signed_root_request().signer(),
            &fixture.root_key.verifying_key().to_bytes(),
        )
        .unwrap();
}

// Builds an untrusted envelope to exercise decoder admission independently of
// constructors. Its signatures need not verify when structural admission fails.
fn wire_with_root(
    fixture: &Fixture,
    claims: &StorageZfsHoldTransportRequestV1,
    root: &SignedSourceProviderRequestV1,
) -> Vec<u8> {
    let original = fixture.request.to_canonical_bytes();
    let claims = claims.to_canonical_bytes();
    let root = root.to_canonical_bytes();
    let mut bytes = original[..16].to_vec();
    bytes.extend_from_slice(&(claims.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&claims);
    bytes.extend_from_slice(&(root.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&original[original.len() - 184..]);
    bytes
}

#[test]
fn exact_v2_bytes_and_explicit_constructor_versions_remain_distinct() {
    let fixture = Fixture::new();
    let original = fixture.request.request();
    let bytes = fixture.request.to_canonical_bytes();
    assert_eq!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&bytes)
            .unwrap()
            .to_canonical_bytes(),
        bytes
    );
    // The independently reviewed existing topology vector commits these exact
    // signed V2 bytes. Changes require review of that vector, not regeneration.
    let expected_digest =
        hex::decode("df7644deba326b0089a20c2b9bcfa910df1b09194b981154aaafcea86b9bc3bf").unwrap();
    assert_eq!(
        fixture.request.digest().as_bytes(),
        expected_digest.as_slice()
    );
    assert_eq!(
        StorageNativeAcquireRequestV2::new_native_v3(
            original.claims().clone(),
            original.signed_root_request().clone(),
        ),
        Err(StorageNativeAcquireErrorV2::Noncanonical)
    );

    let root = v3_root(&fixture);
    let signed = signed_root(&fixture, &root);
    assert_eq!(
        StorageNativeAcquireRequestV2::new(original.claims().clone(), signed),
        Err(StorageNativeAcquireErrorV2::Noncanonical)
    );
    let native = signed_native(&fixture, &root);
    let bytes = native.to_canonical_bytes();
    assert_eq!(&bytes[..16], &fixture.request.to_canonical_bytes()[..16]);
    let decoded = SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, native);
    assert_eq!(decoded.to_canonical_bytes(), bytes);
    assert_eq!(decoded.request().claims(), original.claims());
    assert_eq!(
        decoded.request().signed_root_request(),
        &signed_root(&fixture, &root)
    );
    let decoded_root =
        decode_acquire_request(decoded.request().signed_root_request().subject()).unwrap();
    assert_eq!(decoded_root, root);
    assert_eq!(
        decoded_root.native_catalog(),
        Some(&native_binding(&fixture))
    );
    assert_eq!(root.sequence(), 2);
    assert_eq!(decoded.request().claims().sequence(), 30);
    assert_eq!(
        decoded.request().claims().attempt(),
        original.claims().attempt()
    );
    verify(&fixture, &decoded);
}

#[test]
fn native_v3_constructor_and_decoder_reject_each_catalog_crosslink_mismatch() {
    let fixture = Fixture::new();
    let claims = fixture.request.request().claims();
    let root =
        decode_acquire_request(fixture.request.request().signed_root_request().subject()).unwrap();
    let catalog = claims.catalog();
    for (name, namespace, generation, digest, current) in [
        (
            "namespace",
            d(78),
            catalog.generation(),
            catalog.digest(),
            claims.selection().1,
        ),
        (
            "head generation",
            catalog.namespace_digest(),
            catalog.generation() + 1,
            catalog.digest(),
            claims.selection().1,
        ),
        (
            "head digest",
            catalog.namespace_digest(),
            catalog.generation(),
            d(78),
            claims.selection().1,
        ),
        (
            "current head",
            catalog.namespace_digest(),
            catalog.generation(),
            catalog.digest(),
            d(78),
        ),
    ] {
        let binding = NativeAcquireCatalogBindingV3::new(
            namespace,
            generation,
            digest,
            1,
            d(76),
            current,
            d(77),
        )
        .unwrap();
        let changed = AcquireSourceRequestV1::new_native_v3(root.clone(), binding).unwrap();
        let signed = signed_root(&fixture, &changed);
        assert_eq!(
            StorageNativeAcquireRequestV2::new_native_v3(claims.clone(), signed.clone()),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
        assert_eq!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&wire_with_root(
                &fixture, claims, &signed
            )),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
    }
}

#[test]
fn native_v3_constructor_and_decoder_reject_original_identity_and_interval_mismatch() {
    let fixture = Fixture::new();
    let claims = fixture.request.request().claims();
    let root = v3_root(&fixture);
    let signed = signed_root(&fixture, &root);
    for (name, offset, replacement) in [
        ("holder", 104, vec![78; 16]),
        ("session", 120, vec![78; 32]),
        ("acquisition", 152, vec![78; 32]),
        ("interval", 256, 1001_i64.to_be_bytes().to_vec()),
    ] {
        let mut bytes = claims.to_canonical_bytes();
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        // Keep the claims interval well-formed in its own sixty-second domain.
        if name == "interval" {
            bytes[248..256].copy_from_slice(&971_i64.to_be_bytes());
        }
        let changed = StorageZfsHoldTransportRequestV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            StorageNativeAcquireRequestV2::new_native_v3(changed.clone(), signed.clone()),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
        assert_eq!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&wire_with_root(
                &fixture, &changed, &signed
            )),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
    }

    let mut binding = root.clone();
    binding.binding.push(78);
    binding.binding_digest = digest_logical_binding_bytes(&binding.binding);
    let mut lease = root.clone();
    lease.requested_lease_seconds = 29;
    let mut deadline = root.clone();
    deadline.deadline_seconds = 899;
    for (name, changed) in [
        ("binding", binding),
        ("lease interval", lease),
        ("deadline", deadline),
    ] {
        let signed = signed_root(&fixture, &changed);
        assert_eq!(
            StorageNativeAcquireRequestV2::new_native_v3(claims.clone(), signed.clone()),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
        assert_eq!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&wire_with_root(
                &fixture, claims, &signed
            )),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
    }

    let mut local_live =
        decode_acquire_request(fixture.request.request().signed_root_request().subject()).unwrap();
    local_live.kernel_coupled = true;
    assert!(
        AcquireSourceRequestV1::new_native_v3(local_live.clone(), native_binding(&fixture))
            .is_err()
    );
    assert_eq!(
        StorageNativeAcquireRequestV2::new_native_v3(
            claims.clone(),
            signed_root(&fixture, &local_live)
        ),
        Err(StorageNativeAcquireErrorV2::Noncanonical)
    );
}

#[test]
fn native_floor_and_publication_bytes_are_committed_without_independent_owner_proof() {
    let fixture = Fixture::new();
    let original = v3_root(&fixture);
    let native = signed_native(&fixture, &original);
    let binding = native_binding(&fixture);
    for (name, floor, publication) in [
        (
            "floor generation",
            (binding.floor().0 - 1, binding.floor().1),
            binding.canonical_publication_digest(),
        ),
        (
            "floor digest",
            (binding.floor().0, d(78)),
            binding.canonical_publication_digest(),
        ),
        ("publication", binding.floor(), d(78)),
    ] {
        let mut changed = original.clone();
        changed.native_catalog = Some(
            NativeAcquireCatalogBindingV3::new(
                binding.resource_namespace_digest(),
                binding.head().0,
                binding.head().1,
                floor.0,
                floor.1,
                binding.current_head_commitment(),
                publication,
            )
            .unwrap(),
        );
        // No independent floor/publication authority is supplied by this fixture.
        // Structural admission succeeds while both signature commitments change.
        let changed = signed_native(&fixture, &changed);
        verify(&fixture, &changed);
        assert_ne!(
            changed.request().signed_root_request(),
            native.request().signed_root_request(),
            "{name}"
        );
        assert_ne!(changed.digest(), native.digest(), "{name}");
        assert_eq!(
            changed.require_exact_replay(&native),
            Err(StorageNativeAcquireErrorV2::ReplayConflict),
            "{name}"
        );

        let mut wire = changed.to_canonical_bytes();
        let old = native.to_canonical_bytes();
        let signature_offset = wire.len() - 64;
        wire[signature_offset..].copy_from_slice(&old[old.len() - 64..]);
        let tampered = SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&wire).unwrap();
        assert_eq!(
            tampered.verify(
                fixture.request.signer(),
                &fixture.provider_key.verifying_key().to_bytes(),
                fixture.request.request().signed_root_request().signer(),
                &fixture.root_key.verifying_key().to_bytes()
            ),
            Err(StorageNativeAcquireErrorV2::Authority),
            "{name}"
        );
    }
}

#[test]
fn native_v3_attempt_and_both_sequence_spaces_remain_exact_replay_inputs() {
    let fixture = Fixture::new();
    let root = v3_root(&fixture);
    let native = signed_native(&fixture, &root);
    let claims = native.request().claims();
    for (name, offset, replacement) in [
        ("carrier sequence", 16, 31_u64.to_be_bytes().to_vec()),
        ("challenge", 24, vec![78; 32]),
        ("attempt", 56, vec![78; 32]),
    ] {
        let mut bytes = claims.to_canonical_bytes();
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        let changed = StorageZfsHoldTransportRequestV1::from_canonical_bytes(&bytes).unwrap();
        let changed = StorageNativeAcquireRequestV2::new_native_v3(
            changed,
            native.request().signed_root_request().clone(),
        )
        .unwrap();
        let changed = SignedStorageNativeAcquireRequestV2::sign(
            changed,
            native.signer().clone(),
            &fixture.provider_key,
        )
        .unwrap();
        verify(&fixture, &changed);
        assert_eq!(
            changed.request().signed_root_request(),
            native.request().signed_root_request(),
            "{name}"
        );
        assert_eq!(
            changed.require_exact_replay(&native),
            Err(StorageNativeAcquireErrorV2::ReplayConflict),
            "{name}"
        );
    }

    let mut changed_root = root.clone();
    changed_root.sequence += 1;
    let changed = signed_native(&fixture, &changed_root);
    verify(&fixture, &changed);
    assert_eq!(changed.request().claims(), claims);
    assert_eq!(
        changed.require_exact_replay(&native),
        Err(StorageNativeAcquireErrorV2::ReplayConflict)
    );
}

#[test]
fn native_v3_nested_versions_signatures_tails_and_frame_bounds_fail_closed() {
    let fixture = Fixture::new();
    let native = signed_native(&fixture, &v3_root(&fixture));
    let bytes = native.to_canonical_bytes();
    let claims_length = native.request().claims().to_canonical_bytes().len();
    let root_offset = 24 + claims_length;
    let root = native.request().signed_root_request();
    let subject_offset = root_offset + root.to_canonical_bytes().len() - 64 - root.subject().len();

    for (name, offset, replacement) in [
        (
            "V3 body tagged V2",
            subject_offset,
            2_u16.to_be_bytes().to_vec(),
        ),
        (
            "unknown Root version",
            subject_offset,
            4_u16.to_be_bytes().to_vec(),
        ),
        ("missing native profile", subject_offset + 2, vec![0]),
        (
            "kernel/LocalLive",
            subject_offset + root.subject().len() - 8,
            vec![2],
        ),
        (
            "claims bound",
            16,
            (MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1 as u32 + 1)
                .to_be_bytes()
                .to_vec(),
        ),
        (
            "Root bound",
            20 + claims_length,
            (MAXIMUM_FRAME_BYTES as u32 + 1).to_be_bytes().to_vec(),
        ),
    ] {
        let mut changed = bytes.clone();
        changed[offset..offset + replacement.len()].copy_from_slice(&replacement);
        assert_eq!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&changed),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
    }
    let v2_bytes = fixture.request.to_canonical_bytes();
    let v2_root = fixture.request.request().signed_root_request();
    let v2_subject_offset =
        root_offset + v2_root.to_canonical_bytes().len() - 64 - v2_root.subject().len();
    let mut cross_version = v2_bytes;
    cross_version[v2_subject_offset..v2_subject_offset + 2].copy_from_slice(&3_u16.to_be_bytes());
    assert!(SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&cross_version).is_err());

    for (name, length_offset, end, length) in [
        ("claims tail", 16, 20 + claims_length, claims_length),
        (
            "Root tail",
            20 + claims_length,
            root_offset + root.to_canonical_bytes().len(),
            root.to_canonical_bytes().len(),
        ),
    ] {
        let mut changed = bytes.clone();
        changed.splice(end..end, [1]);
        changed[length_offset..length_offset + 4]
            .copy_from_slice(&((length + 1) as u32).to_be_bytes());
        assert_eq!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&changed),
            Err(StorageNativeAcquireErrorV2::Noncanonical),
            "{name}"
        );
    }

    for offset in [
        root_offset + root.to_canonical_bytes().len() - 1,
        bytes.len() - 1,
    ] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let changed = SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&changed).unwrap();
        assert_eq!(
            changed.verify(
                fixture.request.signer(),
                &fixture.provider_key.verifying_key().to_bytes(),
                fixture.request.request().signed_root_request().signer(),
                &fixture.root_key.verifying_key().to_bytes()
            ),
            Err(StorageNativeAcquireErrorV2::Authority)
        );
        assert_eq!(
            changed.require_exact_replay(&native),
            Err(StorageNativeAcquireErrorV2::ReplayConflict)
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(1);
    assert!(SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&trailing).is_err());
    assert!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&bytes[..bytes.len() - 1])
            .is_err()
    );
    assert!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&vec![
            0;
            MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2
                + 1
        ])
        .is_err()
    );
    assert!(native.require_exact_replay(&native).is_ok());
}
