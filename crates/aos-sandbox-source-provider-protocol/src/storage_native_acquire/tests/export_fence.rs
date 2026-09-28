//! Native fence wire tests reuse the existing signed native artifact fixture.
//!
//! These claims and signatures confer no protected owner, Root acceptance or
//! descriptor authority. Generic V1 response semantics remain unchanged.

use super::*;

fn subject(fixture: &Fixture) -> SourceProviderNativeExportFenceV1 {
    let signed_root = fixture.request.request().signed_root_request();
    let root = decode_acquire_request(signed_root.subject()).unwrap();
    SourceProviderNativeExportFenceV1::new(
        NativeExportFenceReleaseV1 {
            provider: SourceProviderAuthorityV1::new([33; 16], 35, d(36)).unwrap(),
            holder: SourceProviderAuthorityV1::new([7; 16], 8, d(9)).unwrap(),
            request_id: [61; 16],
            signed_request_digest: d(62),
            typed_request_digest: d(63),
            attempt_digest: d(64),
            session_binding: d(65),
            request_sequence: 2,
            response_sequence: 2,
            provider_process_instance: [66; 16],
        },
        NativeExportFenceAcquireV1 {
            acquisition_id: root.acquisition_id(),
            acquisition_sequence: root.acquisition_sequence(),
            root_request_digest: digest_signed_request(signed_root),
            attempt_digest: source_provider_request_attempt_digest_v1(
                signed_root.signer(),
                SourceProviderMethod::Acquire,
                root.request_id(),
            ),
            session_binding: root.session_binding(),
            backend_id: [67; 32],
            lease_id: [68; 16],
            lease_digest: d(69),
        },
        fixture.request.digest(),
        fixture.acceptance.digest(),
        fixture.acceptance.acceptance().clone(),
        NativeExportFenceCutV1 {
            sequence: 70,
            admission_transaction_id: [71; 16],
            reservation_id: [72; 32],
            fence_digest: d(73),
        },
    )
    .unwrap()
}

fn signed(fixture: &Fixture) -> SignedSourceProviderNativeExportFenceV1 {
    SignedSourceProviderNativeExportFenceV1::sign(
        subject(fixture),
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap()
}

fn status(
    fixture: &Fixture,
    fence: &SignedSourceProviderNativeExportFenceV1,
    disposition: SourceProviderStatus,
    descriptor: ObjectDigest,
) -> SignedSourceProviderStatusV1 {
    let release = fence.subject().release();
    sign_response_status(
        SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Release,
            release.request_id,
            release.signed_request_digest,
            disposition,
            release.provider_process_instance,
            release.session_binding,
            release.response_sequence,
            response_result_digest_v1(
                SourceProviderMethod::Release,
                disposition,
                Some(&fence.to_canonical_bytes()),
            ),
            descriptor,
        )
        .unwrap(),
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap()
}

#[test]
fn native_export_fence_exact_width_roundtrip_and_signatures() {
    let fixture = Fixture::new();
    let fence = signed(&fixture);
    let response = ReleaseSourceResponseV2::new(
        status(
            &fixture,
            &fence,
            SourceProviderStatus::Pending,
            empty_descriptor_set_commitment_v1(),
        ),
        fence.clone(),
    )
    .unwrap();
    let bytes = response.to_canonical_bytes();

    assert_eq!(fence.subject().to_canonical_bytes().len(), 888);
    assert_eq!(fence.to_canonical_bytes().len(), 1088);
    assert_eq!(response.signed_status().to_canonical_bytes().len(), 380);
    assert_eq!(bytes.len(), 1488);
    assert_eq!(bytes.len(), MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2);
    assert_eq!(
        ReleaseSourceResponseV2::from_canonical_bytes(&bytes).unwrap(),
        response
    );
    let profile = ReleaseSourceResponseProfileV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(profile.status(), SourceProviderStatus::Pending);
    assert_eq!(profile.native_fence(), Some(&fence));
    assert_eq!(profile.to_canonical_bytes(), bytes);
    fence
        .verify(fixture.provider_key.verifying_key().as_bytes())
        .unwrap();
    verify_response_status(
        response.signed_status(),
        fixture.provider_key.verifying_key().as_bytes(),
    )
    .unwrap();
}

#[test]
fn native_export_fence_binds_independent_nonzero_directional_sequences() {
    let fixture = Fixture::new();
    let original = subject(&fixture);
    let with_release = |release| {
        SourceProviderNativeExportFenceV1::new(
            release,
            original.acquire().clone(),
            original.native_request_digest(),
            original.signed_acceptance_digest(),
            original.acceptance().clone(),
            original.cut().clone(),
        )
    };
    let mut release = original.release().clone();
    release.request_sequence = 3;
    release.response_sequence = 2;
    let fence = SignedSourceProviderNativeExportFenceV1::sign(
        with_release(release.clone()).unwrap(),
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap();
    let signed_status = status(
        &fixture,
        &fence,
        SourceProviderStatus::Pending,
        empty_descriptor_set_commitment_v1(),
    );
    let response = ReleaseSourceResponseV2::new(signed_status.clone(), fence.clone()).unwrap();
    let reopened =
        ReleaseSourceResponseV2::from_canonical_bytes(&response.to_canonical_bytes()).unwrap();

    assert_eq!(reopened, response);
    assert_eq!(reopened.fence().subject().release().request_sequence, 3);
    assert_eq!(reopened.fence().subject().release().response_sequence, 2);
    fence
        .verify(fixture.provider_key.verifying_key().as_bytes())
        .unwrap();

    for direction in 0..2 {
        let mut zero = release.clone();
        if direction == 0 {
            zero.request_sequence = 0;
        } else {
            zero.response_sequence = 0;
        }
        assert!(with_release(zero).is_err());

        // Even a valid Provider re-signature cannot substitute either head
        // beneath the original exact signed status/result commitment.
        let mut changed = release.clone();
        if direction == 0 {
            changed.request_sequence += 1;
        } else {
            changed.response_sequence += 1;
        }
        let changed = SignedSourceProviderNativeExportFenceV1::sign(
            with_release(changed).unwrap(),
            fixture.request.signer().clone(),
            &fixture.provider_key,
        )
        .unwrap();
        changed
            .verify(fixture.provider_key.verifying_key().as_bytes())
            .unwrap();
        assert!(ReleaseSourceResponseV2::new(signed_status.clone(), changed).is_err());
    }
}

#[test]
fn native_export_fence_never_widens_legacy_pending_or_complete() {
    let fixture = Fixture::new();
    let fence = signed(&fixture);
    let pending = status(
        &fixture,
        &fence,
        SourceProviderStatus::Pending,
        empty_descriptor_set_commitment_v1(),
    );
    assert!(
        ReleaseSourceResponseV1::new(pending.clone(), Some(fence.to_canonical_bytes())).is_err()
    );
    let response = ReleaseSourceResponseV2::new(pending, fence.clone()).unwrap();
    assert!(decode_release_response(&response.to_canonical_bytes()).is_err());
    assert!(
        ReleaseSourceResponseV2::new(
            status(
                &fixture,
                &fence,
                SourceProviderStatus::Complete,
                empty_descriptor_set_commitment_v1()
            ),
            fence.clone()
        )
        .is_err()
    );
    assert!(
        ReleaseSourceResponseV2::new(
            status(&fixture, &fence, SourceProviderStatus::Pending, d(74)),
            fence
        )
        .is_err()
    );
}

#[test]
fn native_export_fence_strict_versions_bounds_and_signature_tampering() {
    let fixture = Fixture::new();
    let fence = signed(&fixture);
    let response = ReleaseSourceResponseV2::new(
        status(
            &fixture,
            &fence,
            SourceProviderStatus::Pending,
            empty_descriptor_set_commitment_v1(),
        ),
        fence.clone(),
    )
    .unwrap();
    let bytes = response.to_canonical_bytes();
    for end in [0, 15, 19, 399, bytes.len() - 1] {
        assert!(ReleaseSourceResponseV2::from_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut oversized = bytes.clone();
    oversized.push(0);
    assert!(ReleaseSourceResponseV2::from_canonical_bytes(&oversized).is_err());
    for offset in [0, 9, 10, 19] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(ReleaseSourceResponseV2::from_canonical_bytes(&changed).is_err());
    }
    let mut changed = fence.to_canonical_bytes();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        SignedSourceProviderNativeExportFenceV1::from_canonical_bytes(&changed)
            .unwrap()
            .verify(fixture.provider_key.verifying_key().as_bytes())
            .is_err()
    );
}

#[test]
fn native_export_fence_purpose_and_acceptance_substitution_reject() {
    let fixture = Fixture::new();
    let wrong = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        35,
        d(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderHello,
        &fixture.provider_key,
    )
    .unwrap();
    assert!(
        SignedSourceProviderNativeExportFenceV1::sign(
            subject(&fixture),
            wrong,
            &fixture.provider_key
        )
        .is_err()
    );
    let wrong = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        36,
        d(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &fixture.provider_key,
    )
    .unwrap();
    assert!(
        SignedSourceProviderNativeExportFenceV1::sign(
            subject(&fixture),
            wrong,
            &fixture.provider_key
        )
        .is_err()
    );
    let original = subject(&fixture);
    assert!(
        SourceProviderNativeExportFenceV1::new(
            original.release().clone(),
            original.acquire().clone(),
            d(99),
            original.signed_acceptance_digest(),
            original.acceptance().clone(),
            original.cut()
        )
        .is_err()
    );
}

#[test]
fn native_export_fence_original_topology_commitments_cannot_be_substituted() {
    let fixture = Fixture::new();
    let acceptance = fixture.acceptance.acceptance();
    let topology = acceptance.topology();
    let content = fixture
        .receipt
        .receipt()
        .snapshot()
        .read_only_content_digest();
    let tuple = [
        fixture.request.digest(),
        fixture.receipt.digest(),
        acceptance.descriptor_commitment(),
        content,
    ];
    validate_storage_native_topology_commitments_v1(
        topology, tuple[0], tuple[1], tuple[2], tuple[3],
    )
    .unwrap();
    for index in 0..tuple.len() {
        let mut changed = tuple;
        changed[index] = d(99);
        assert!(
            validate_storage_native_topology_commitments_v1(
                topology, changed[0], changed[1], changed[2], changed[3]
            )
            .is_err()
        );
    }
}
