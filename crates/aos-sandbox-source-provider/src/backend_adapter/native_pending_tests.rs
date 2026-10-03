//! DATA-only matching of the single retained original no-dispatch recovery.
//!
//! These fixtures test the scheduling barrier, not installed packet brands,
//! live catalog/clock custody, or backend effect authority.

use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NativeAcquireCatalogBindingV3, decode_acquire_request,
    encode_acquire_request, sign_request, source_provider_request_attempt_digest_v1,
};
use ed25519_dalek::SigningKey;

use super::*;

fn original_request(native: bool) -> SignedSourceProviderRequestV1 {
    let retained = crate::native_completion::fixture_requested(
        [1; 32],
        500,
        ObjectDigest::from_bytes([2; 32]),
    );
    let original = retained
        .canonical_request
        .as_ref()
        .unwrap()
        .request()
        .signed_root_request();
    if !native {
        return original.clone();
    }
    let legacy = decode_acquire_request(original.subject()).unwrap();
    let claims = NativeAcquireCatalogBindingV3::new(
        ObjectDigest::from_bytes([24; 32]),
        2,
        ObjectDigest::from_bytes([25; 32]),
        1,
        ObjectDigest::from_bytes([26; 32]),
        ObjectDigest::from_bytes([27; 32]),
        ObjectDigest::from_bytes([28; 32]),
    )
    .unwrap();
    let request = AcquireSourceRequestV1::new_native_v3(legacy, claims).unwrap();
    sign_request(
        original.method(),
        encode_acquire_request(&request),
        original.signer().clone(),
        &SigningKey::from_bytes(&[51; 32]),
    )
    .unwrap()
}

fn pending(signed: &SignedSourceProviderRequestV1) -> FixedProviderBackendRecoveryV1 {
    let request = decode_acquire_request(signed.subject()).unwrap();
    let attempt = source_provider_request_attempt_digest_v1(
        signed.signer(),
        signed.method(),
        request.request_id(),
    );
    FixedProviderBackendRecoveryV1 {
        work: ProviderRecoveryWorkV1::ObserveApplying {
            acquisition_id: request.acquisition_id(),
            effect_id: crate::acquire::derive_acquire_effect_id(request.acquisition_id(), attempt)
                .unwrap(),
        },
        original_request: signed.clone(),
        descriptor_roles: Vec::new(),
        fresh_request: None,
        fresh_request_in_flight: false,
        successor_session_ready: false,
        quarantined: false,
    }
}

#[test]
fn exact_native_pending_matches_without_mutating_original_markers() {
    let signed = original_request(true);
    let original = vec![pending(&signed)];
    let original_address = &original[0] as *const _;
    let work = original[0].work.clone();
    let bytes = original[0].original_request.to_canonical_bytes();

    for _ in 0..2 {
        assert!(matches_original_native_pending(
            &original, &signed, None, None
        ));
        assert_eq!(&original[0] as *const _, original_address);
        assert_eq!(original[0].work, work);
        assert_eq!(original[0].original_request.to_canonical_bytes(), bytes);
        assert!(!original[0].has_fresh_request());
        assert!(!original[0].successor_session_ready());
    }
}

#[test]
fn pending_barrier_refuses_changed_lineage_and_every_other_priority() {
    let signed = original_request(true);
    assert!(!matches_original_native_pending(&[], &signed, None, None));
    let extra = vec![pending(&signed), pending(&signed)];
    assert!(!matches_original_native_pending(
        &extra, &signed, None, None
    ));
    for (retry, rearm) in [(Some([1; 32]), None), (None, Some([1; 32]))] {
        assert!(!matches_original_native_pending(
            &[pending(&signed)],
            &signed,
            retry,
            rearm,
        ));
    }
    let legacy = original_request(false);
    assert!(!matches_original_native_pending(
        &[pending(&legacy)],
        &legacy,
        None,
        None
    ));

    for case in 0..8 {
        let mut original = pending(&signed);
        match case {
            0 => original.quarantined = true,
            1 => original.fresh_request = Some(signed.clone()),
            2 => original.fresh_request_in_flight = true,
            3 => original.successor_session_ready = true,
            4 => original
                .descriptor_roles
                .push(SourceProviderDescriptorRole::SourceRoot),
            5 => {
                let ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. } =
                    &mut original.work
                else {
                    unreachable!()
                };
                *acquisition_id = ObjectDigest::from_bytes([99; 32]);
            }
            6 => {
                let ProviderRecoveryWorkV1::ObserveApplying { effect_id, .. } = &mut original.work
                else {
                    unreachable!()
                };
                *effect_id = [99; 16];
            }
            7 => {
                original.work = ProviderRecoveryWorkV1::ObserveInventoryReservation {
                    attempt_digest: ObjectDigest::from_bytes([99; 32]),
                }
            }
            _ => unreachable!(),
        }
        assert!(
            !matches_original_native_pending(&[original], &signed, None, None),
            "case {case}"
        );
    }

    // Same semantic subject with different canonical signature bytes is not
    // the original signed request retained by the pending owner.
    let mut different_bytes = signed.to_canonical_bytes();
    *different_bytes.last_mut().unwrap() ^= 1;
    let different = SignedSourceProviderRequestV1::from_canonical_bytes(&different_bytes).unwrap();
    assert_ne!(different.to_canonical_bytes(), signed.to_canonical_bytes());
    assert!(!matches_original_native_pending(
        &[pending(&signed)],
        &different,
        None,
        None
    ));
}
