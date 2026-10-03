//! UNRUN original Attempt/provenance joins using existing pure graph DATA.
//!
//! Test signatures do not authenticate a production signer. These joins supply
//! no journal admission, whole current owner, live clock, custody, or route.

use super::*;
use crate::ledger::model::{AcquisitionKeyV1, AttemptKeyV1, AttemptRecordV1};
use crate::ledger::native_completion::{
    NativeAcquireClockAnchorV1, OriginalSourceProvenanceClaimsV5, OriginalSourceProvenanceV5,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_source_provider_protocol::{digest_acquire_request, digest_signed_request};

fn byte_witness(family: Family, key: Vec<u8>, bytes: Vec<u8>) -> NativeHeldByteWitnessV1 {
    let digest = native_held_record_byte_digest_v1(family, &key, &bytes).unwrap();
    NativeHeldByteWitnessV1::new(family, key, digest).unwrap()
}

fn attempt_witness(attempt: &AttemptRecordV1) -> NativeHeldByteWitnessV1 {
    let key = format::attempt_key(&AttemptKeyV1 {
        provider_id: attempt.provider.authority_id(),
        holder_id: attempt.holder.authority_id(),
        root_record_key_id: attempt.root_record_signer.key_id(),
        method: attempt.method as u8,
        request_id: attempt.request_id,
    });
    byte_witness(Family::ProviderAttempt, key, format::encode_attempt(attempt))
}

fn fixture() -> (OriginalSourceProvenanceClaimsV5, AttemptRecordV1) {
    let graph = fixtures::Graph::applying();
    let native = graph.native.canonical_request.as_ref().unwrap();
    let claims = native.request().claims().clone();
    let catalog = claims.catalog();
    let original = decode_acquire_request(native.request().signed_root_request().subject()).unwrap();
    let binding = NativeAcquireCatalogBindingV3::new(
        catalog.namespace_digest(),
        catalog.generation(),
        catalog.digest(),
        catalog.generation() - 1,
        d(100),
        claims.selection().1,
        d(101),
    )
    .unwrap();
    let root = AcquireSourceRequestV1::new_native_v3(original, binding).unwrap();
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        native.request().signed_root_request().signer().clone(),
        &SigningKey::from_bytes(&[51; 32]),
    )
    .unwrap();
    let signed_native = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new_native_v3(claims.clone(), signed_root.clone()).unwrap(),
        native.signer().clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap();
    let initial = graph.native.original_clock.unwrap().initial();
    let anchor = NativeAcquireClockAnchorV1::new_untrusted(initial, &signed_native).unwrap();
    let original = Original::requested(signed_native, d(39), anchor).unwrap();
    let mut attempt = graph.attempts[0].clone();
    attempt.signed_request_digest = digest_signed_request(&signed_root);
    attempt.signed_request_digest_again = attempt.signed_request_digest;
    attempt.typed_request_digest = digest_acquire_request(&root);
    attempt.signed_request = signed_root.to_canonical_bytes();

    let session = &graph.sessions[0];
    let intent = crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
        &root,
        session.provider.clone(),
        session.holder.clone(),
        session.root_process_instance,
        session.boot_id,
        session.route_id,
        session.route_generation,
        session.route_digest,
        session.resource_namespace_digest,
        session.revocation_generation,
        session.revocation_digest,
    )
    .unwrap();
    attempt.operation_intent_digest = intent.digest();

    let acquisition = &graph.acquisition;
    let acquisition_key = format::acquisition_key(&AcquisitionKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    });
    let holder_key = format::session_key(
        session.provider.authority_id(),
        session.holder.authority_id(),
    );
    let history_key = format::session_history_key(
        session.provider.authority_id(),
        session.holder.authority_id(),
        session.session_binding,
    );
    let data = OriginalSourceProvenanceClaimsV5 {
        root_prepared: root_prepared(&original),
        claims,
        initial,
        // Literal existing fixture wall 500/BOOTTIME 1s and Root expiry 1100.
        original_deadline: 600_000_000_000,
        narrowed_deadline: 60_000_000_000,
        journal_sequence: 1,
        configuration: d(102),
        records: [
            attempt_witness(&attempt),
            byte_witness(
                Family::ProviderAcquisition,
                acquisition_key,
                format::encode_acquisition(acquisition),
            ),
            byte_witness(
                Family::ProviderHolder,
                holder_key,
                format::encode_session(session),
            ),
            byte_witness(
                Family::ProviderHistory,
                history_key,
                format::encode_session_history(session),
            ),
        ],
    };
    (data, attempt)
}

#[test]
fn original_canonical_reserved_v3_attempt_joins_exact_archive_and_cutoff() {
    let (data, attempt) = fixture();
    let provenance = OriginalSourceProvenanceV5::new_untrusted(data).unwrap();
    let bytes = provenance.to_canonical_bytes();
    let decoded = OriginalSourceProvenanceV5::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(decoded, provenance);
    decoded.validate_original_attempt_claims(&attempt).unwrap();
    assert_eq!(attempt.revision, 1);
    assert_eq!(attempt.deadline_seconds, 1_100);
    assert_eq!(decoded.claims().original_deadline, 600_000_000_000);
}

#[test]
fn original_request_id_boot_authorization_expiry_and_witness_are_separate_joins() {
    let (data, attempt) = fixture();
    let mut changed = data.clone();
    let witness = &changed.records[0];
    let mut key = witness.key().to_vec();
    key[95] ^= 1;
    changed.records[0] =
        NativeHeldByteWitnessV1::new(Family::ProviderAttempt, key, witness.digest()).unwrap();
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed).unwrap();

    assert!(provenance.validate_original_attempt_claims(&attempt).is_err());

    let mut changed = data.clone();
    changed.initial = RawPairedClockSample::new_untrusted(
        data.initial.provenance(),
        [0x80; 16],
        data.initial.wall_seconds(),
        data.initial.boottime_nanoseconds(),
    )
    .unwrap();
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed).unwrap();

    assert!(provenance.validate_original_attempt_claims(&attempt).is_err());

    let mut shortened = attempt.clone();
    shortened.current_valid_until_seconds -= 1;
    let mut changed = data.clone();
    changed.records[0] = attempt_witness(&shortened);
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed.clone()).unwrap();

    // The old canonical Attempt rejects authorization ending before Root's deadline.
    assert!(provenance.validate_original_attempt_claims(&shortened).is_err());

    let mut extended = attempt.clone();
    extended.current_valid_until_seconds += 1;
    let mut changed = data.clone();
    changed.records[0] = attempt_witness(&extended);
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed.clone()).unwrap();

    // A valid later authorization cannot extend the earlier signed Root cutoff.
    provenance.validate_original_attempt_claims(&extended).unwrap();
    changed.original_deadline -= 1_000_000_000;
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed).unwrap();
    assert!(provenance.validate_original_attempt_claims(&extended).is_err());

    let mut changed = data;
    changed.records[0] = NativeHeldByteWitnessV1::new(
        Family::ProviderAttempt,
        changed.records[0].key().to_vec(),
        d(103),
    )
    .unwrap();
    let provenance = OriginalSourceProvenanceV5::new_untrusted(changed).unwrap();

    assert!(provenance.validate_original_attempt_claims(&attempt).is_err());

    let mut changed = attempt;
    changed.signed_request_digest = d(104);
    assert!(provenance.validate_original_attempt_claims(&changed).is_err());
}
