//! Retained direct control correlation without live permission or authentication.

use super::*;

fn baseline_lookup() -> DirectAuthorityLookup {
    let (admission, complete, evidence, context) = fixture();
    let witness = witness(&evidence);
    DirectAuthorityLookup {
        deployment_id: context.deployment_id,
        request_nonce: context.request_nonce,
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        operation: DirectAuthorityLookupOperation::Baseline {
            admission,
            complete,
            evidence,
            witness,
        },
    }
}

fn final_lookup() -> DirectFinalGuardLookup {
    let (admission, complete, evidence, context) = fixture();
    let selected = DirectSelectedCompleteCommitment {
        version: 1,
        session: complete.session.clone(),
        operation_id: complete.operation_id.clone(),
        expected_resource_version: complete.expected_resource_version,
        complete_intent_digest: complete.fingerprint().unwrap(),
        manifest: complete.manifests[0].clone(),
        protected_profile_digest: evidence.binding.protected_profile_digest.clone(),
    };
    let expected = DirectFinalGuardRecord {
        version: 1,
        reservation: evidence.binding,
        selected,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        source_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "fixture-source-version".into(),
        },
        final_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "fixture-final-version".into(),
        },
        final_etag: "\"fixture-final-etag\"".into(),
    };
    DirectFinalGuardLookup {
        admission,
        complete,
        expected,
        request_nonce: context.request_nonce,
        issued_at: context.issued_at,
        expires_at: context.expires_at,
    }
}

#[test]
fn retained_baseline_observation_does_not_renew_lookup_or_witness() {
    let key = StorageWorkKey::new([17; 32]).unwrap();
    let original = baseline_lookup();
    let reply = DirectAuthorityLookupReply {
        request: original.clone(),
    };
    let signed = sign_direct_authority_lookup_reply(&key, &reply).unwrap();

    reply.validate_observation_for(&original).unwrap();
    verify_direct_authority_lookup_reply(&key, &signed.signature, &signed.body, &original, 202)
        .unwrap();
    for now in [199, 220, 230, 10_000] {
        assert!(verify_direct_authority_lookup_reply(
            &key,
            &signed.signature,
            &signed.body,
            &original,
            now,
        )
        .is_err());
    }
    assert!(verify_direct_authority_lookup_reply(
        &key,
        &"00".repeat(32),
        &signed.body,
        &original,
        202,
    )
    .is_err());
}

#[test]
fn baseline_observation_retains_audience_lifetimes_and_original_proof() {
    let original = baseline_lookup();
    assert!(original
        .validate_observation_shape("other-deployment")
        .is_err());
    let mut changed = original.clone();
    changed.expires_at = WireInteger::new(231);
    assert!(changed.validate_observation_shape("deployment").is_err());
    changed = original.clone();
    if let DirectAuthorityLookupOperation::Baseline { witness, .. } = &mut changed.operation {
        witness.expires_at = witness.issued_at;
    }
    assert!(changed.validate_observation_shape("deployment").is_err());
    changed = original.clone();
    if let DirectAuthorityLookupOperation::Baseline { witness, .. } = &mut changed.operation {
        witness.baseline_digest = "cc".repeat(32);
    }
    assert!(changed.validate_observation_shape("deployment").is_err());

    let mut reply = DirectAuthorityLookupReply {
        request: original.clone(),
    };
    reply.request.request_nonce = "dd".repeat(32);
    assert!(reply.validate_observation_for(&original).is_err());
}

#[test]
fn retained_final_observation_does_not_renew_live_challenge() {
    let key = StorageWorkKey::new([17; 32]).unwrap();
    let original = final_lookup();
    let reply = DirectFinalGuardReply {
        request: original.clone(),
        record: original.expected.clone(),
    };
    let signed = sign_direct_final_guard_reply(&key, &reply).unwrap();

    reply.validate_observation_for(&original).unwrap();
    verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &original, 202).unwrap();
    for now in [199, 230, 10_000] {
        assert!(verify_direct_final_guard_reply(
            &key,
            &signed.signature,
            &signed.body,
            &original,
            now,
        )
        .is_err());
    }
    assert!(
        verify_direct_final_guard_reply(&key, &"00".repeat(32), &signed.body, &original, 202,)
            .is_err()
    );
}

#[test]
fn final_observation_refuses_changed_record_cas_and_lifetime() {
    let original = final_lookup();
    let mut reply = DirectFinalGuardReply {
        request: original.clone(),
        record: original.expected.clone(),
    };
    reply.record.final_incarnation = DirectObjectIncarnation::ProviderVersion {
        version: "different-final-version".into(),
    };
    assert!(reply.validate_observation_for(&original).is_err());
    reply.record = original.expected.clone();
    reply.request.request_nonce = "dd".repeat(32);
    assert!(reply.validate_observation_for(&original).is_err());

    let mut changed = original.clone();
    changed.complete.expected_resource_version = WireInteger::new(8);
    assert!(changed.validate_observation_shape("deployment").is_err());
    changed = original.clone();
    changed.expires_at = WireInteger::new(231);
    assert!(changed.validate_observation_shape("deployment").is_err());
    assert!(original
        .validate_observation_shape("other-deployment")
        .is_err());
}

#[test]
fn observation_decoders_refuse_unknown_fields_and_oversized_controls() {
    let original = baseline_lookup();
    let reply = DirectAuthorityLookupReply {
        request: original.clone(),
    };
    let mut value = serde_json::to_value(&reply).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(decode_direct_control::<DirectAuthorityLookupReply>(
        &serde_json::to_vec(&value).unwrap()
    )
    .is_err());
    let oversized = vec![b' '; MAX_DIRECT_CONTROL_BYTES + 1];
    assert!(decode_direct_control::<DirectAuthorityLookupReply>(&oversized).is_err());
}
