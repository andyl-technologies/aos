//! Current-role Root1 signature comparisons using the existing signed Hello fixture.
//!
//! These are DATA vectors, not protected Session, Root funding or carrier custody.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldScopeV1, NativeHeldSectionTagV1,
    frame::{
        NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
        SignedNativeHeldControlV1,
    },
    native_held_flight_digest_v1,
    witness::{
        NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
        NativeHeldRecordFamilyV1, ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1,
    },
};
use ed25519_dalek::Signer as _;

fn root_prepared(session: ObjectDigest, key: &SigningKey) -> SignedNativeHeldControlV1 {
    let records = ROOT_NATIVE_WITNESS_FAMILIES_V1.map(|family| {
        let prefix: &[u8] = match family {
            NativeHeldRecordFamilyV1::RootSession => b"aos.mount.source-provider-session.v2\0",
            NativeHeldRecordFamilyV1::RootAttempt => {
                b"aos.mount.source-provider-query-attempt.v2\0"
            }
            NativeHeldRecordFamilyV1::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
            NativeHeldRecordFamilyV1::RootHead => b"aos.mount.source-provider-head.v2\0",
            _ => unreachable!(),
        };
        let mut key = prefix.to_vec();
        key.resize(family.key_bytes(), 1);
        NativeHeldByteWitnessV1::new(family, key, digest(2)).unwrap()
    });
    let generation = NativeHeldGenerationClaimV1 {
        generation: 3,
        digest: digest(4),
    };
    let witness = NativeHeldOwnerWitnessV1::Root(RootNativeHeldWitnessV1 {
        local_socket_cookie: 5,
        journal_sequence: 6,
        planning_sequence: 7,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: digest(8),
        records,
    });
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(digest(9), digest(10), session),
        original_source_session: session,
        mount_attempt: digest(10),
        provider_attempt: digest(0),
        provider_acquisition: digest(11),
        original_root_request: digest(9),
        original_native_request: digest(0),
    };
    let prepared = PreparedNativeHeldControlV1::new(
        NativeHeldControlKindV1::RootPrepared,
        scope,
        digest(0),
        vec![
            NativeHeldSectionV1::new(
                NativeHeldSectionTagV1::Witness,
                witness.to_canonical_bytes().unwrap(),
            )
            .unwrap(),
        ],
        NativeHeldSignerV1::SourceProvider(root_signer(key)),
    )
    .unwrap();
    let signature = key.sign(&prepared.signature_message()).to_bytes();
    prepared.with_signature(signature)
}

fn trust(root_key: &SigningKey) -> FixtureTrust {
    let root = trust_anchor(&root_signer(root_key), root_key, 0, false, None);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let provider = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );
    fixture_trust(&root, &provider, &route()).unwrap()
}

fn ingress(process_instance: [u8; 16]) -> SourceProviderIngressSessionV1 {
    let transcript = session(process_instance);
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let trust = trust(&root_key);
    let identity = process_identity(4000, 5000, digest(73));
    let policy = ProtectedRootMountPeerV1::new([31; 16], 1000, 1001, digest(73)).unwrap();
    SourceProviderIngressSessionV1::authenticate(
        [53; 32],
        NOW,
        transcript.signed_root_mount_hello().clone(),
        transcript.signed_provider_hello().clone(),
        &trust.trust_set,
        &trust.root_current,
        &trust.provider_current,
        identity.clone(),
        identity,
        &policy,
        &route(),
    )
    .unwrap()
}

#[test]
fn root1_requires_the_exact_current_hello_traffic_pin_and_role() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let session = ingress([52; 16]);
    let control = root_prepared(session.binding(), &root_key);
    let trust = trust(&root_key);

    verify_current_root_prepared_v1(
        &control,
        &session,
        &trust.trust_set,
        &trust.root_current,
        NOW,
    )
    .unwrap();
    assert!(
        verify_current_root_prepared_v1(
            &control,
            &session,
            &trust.trust_set,
            &trust.provider_current,
            NOW
        )
        .is_err()
    );

    let replacement_key = SigningKey::from_bytes(&[60; 32]);
    let replacement = self::trust(&replacement_key);
    let replacement_control = root_prepared(session.binding(), &replacement_key);
    assert!(
        verify_current_root_prepared_v1(
            &replacement_control,
            &session,
            &replacement.trust_set,
            &replacement.root_current,
            NOW
        )
        .is_err()
    );
}

#[test]
fn root1_rejects_inactive_or_expired_current_trust_despite_a_valid_claim_signature() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let session = ingress([52; 16]);
    let control = root_prepared(session.binding(), &root_key);
    let eligible = trust(&root_key);
    let root = trust_anchor(&root_signer(&root_key), &root_key, 0, true, None);
    let provider_key = SigningKey::from_bytes(&[42; 32]);
    let provider = trust_anchor(
        &provider_signer(&provider_key),
        &provider_key,
        ALL_PROOF_CLASS_CAPABILITIES,
        false,
        None,
    );

    // The existing current-role constructor itself refuses a revoked traffic
    // key; no new historical/self-claimed selector can bypass that predicate.
    assert!(fixture_trust(&root, &provider, &route()).is_err());
    assert!(
        verify_current_root_prepared_v1(
            &control,
            &session,
            &eligible.trust_set,
            &eligible.root_current,
            i64::MAX
        )
        .is_err()
    );
}

#[test]
fn root1_cannot_move_to_a_successor_session_or_forge_signature_bytes() {
    let root_key = SigningKey::from_bytes(&[50; 32]);
    let original = ingress([52; 16]);
    let successor = ingress([53; 16]);
    let trust = trust(&root_key);
    let control = root_prepared(original.binding(), &root_key);
    assert!(
        verify_current_root_prepared_v1(
            &control,
            &successor,
            &trust.trust_set,
            &trust.root_current,
            NOW
        )
        .is_err()
    );

    let mut changed = control.to_canonical_bytes();
    let signature_offset = changed.len() - 64;
    changed[signature_offset] ^= 1;
    let changed = SignedNativeHeldControlV1::from_canonical_bytes(&changed).unwrap();
    assert!(
        verify_current_root_prepared_v1(
            &changed,
            &original,
            &trust.trust_set,
            &trust.root_current,
            NOW
        )
        .is_err()
    );
    assert_eq!(control.scope().original_source_session, original.binding());
}
