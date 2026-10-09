//! Signed terminal/ACK vectors with synthetic Source-owned settlement claims.
//!
//! Root verifies Source's original signature and catalog claims, not Storage's
//! separately owned trust. None of these fixture signatures proves live custody.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    assertion::NativeHeldSettlementV1,
    recovery::{
        NativeHeldColdCustodyV1, NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1,
        NativeHeldRecoveryTargetV1, NativeHeldRuntimeStatusV1, RootNativeRecoveryAssertionV1,
    },
    witness::{
        NativeHeldRecordFamilyV1 as Family, PROVIDER_NATIVE_WITNESS_FAMILIES_V1,
        ProviderNativeHeldWitnessV1,
    },
};
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderAuthorityV1, SourceProviderMethod,
    source_provider_request_attempt_digest_v1,
};
use ed25519_dalek::Signer as _;

pub(super) fn provider_witness(family: Family) -> NativeHeldByteWitnessV1 {
    let prefix: &[u8] = match family {
        Family::ProviderAuthority => b"aos.source-provider.authority.v1\0",
        Family::ProviderAttempt => b"aos.source-provider.attempt.v1\0",
        Family::ProviderAcquisition => b"aos.source-provider.acquisition.v1\0",
        Family::ProviderHolder => b"aos.source-provider.session.v1\0",
        Family::ProviderHistory => b"aos.source-provider.session-history.v1\0",
        Family::ProviderNative => b"AOSNCK02",
        Family::Challenge => b"AOSZHK01",
        _ => panic!("Source fixture family"),
    };
    let mut key = prefix.to_vec();
    key.resize(family.key_bytes(), 90);
    if family == Family::ProviderAttempt {
        key[prefix.len() + 48] = SourceProviderMethod::Acquire as u8;
    }
    NativeHeldByteWitnessV1::new(family, key, digest(90)).unwrap()
}

pub(super) fn terminal(
    fixture: &Fixture,
    one: &SignedNativeHeldControlV1,
    r: &RootNativeDispositionAssertionV1,
) -> (
    SignedNativeHeldControlV1,
    PreparedNativeHeldControlV1,
    NativeHeldSettlementV1,
) {
    let request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&fixture.attempt.signed_request)
            .unwrap();
    let full = NativeHeldScopeV1 {
        provider_attempt: source_provider_request_attempt_digest_v1(
            request.signer(),
            SourceProviderMethod::Acquire,
            fixture.attempt.request_id,
        ),
        original_native_request: digest(88),
        ..fixture.scope
    };
    let claim = |byte| NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: digest(byte),
    };
    let w = ProviderNativeHeldWitnessV1 {
        root_local_cookie: 9,
        storage_local_cookie: 10,
        completion_sequence: 11,
        challenge_sequence: 12,
        authority: SourceProviderAuthorityV1::new([2; 16], 1, digest(8)).unwrap(),
        native_namespace: digest(10),
        catalog_head: claim(62),
        catalog_floor: claim(62),
        head_commitment: digest(63),
        publication: digest(64),
        selected_manifest: digest(65),
        backend_manifest: digest(66),
        verifier_manifest: digest(67),
        records: PROVIDER_NATIVE_WITNESS_FAMILIES_V1.map(provider_witness),
    };
    let s = NativeHeldSettlementV1 {
        disposition: NativeHeldDispositionV1::Closed,
        root_disposition: r.digest().unwrap(),
        storage_settlement: digest(77),
        provider_settlement: digest(78),
    };
    let seven = PreparedNativeHeldControlV1::new(
        Kind::ProviderSettled,
        full,
        digest(76),
        vec![
            NativeHeldSectionV1::new(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Provider(w)
                    .to_canonical_bytes()
                    .unwrap(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(Tag::Settlement, s.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
        ],
        NativeHeldSignerV1::SourceProvider(fixture::signer(
            [2; 16],
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &SigningKey::from_bytes(&[14; 32]),
        )),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[14; 32])
        .sign(&seven.signature_message())
        .to_bytes();
    let seven = seven.with_signature(signature);
    let thirteen = PreparedNativeHeldControlV1::new(
        Kind::RootTerminalRecorded,
        full,
        seven.digest(),
        vec![
            fixture.w(),
            NativeHeldSectionV1::new(Tag::Settlement, s.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
        ],
        one.prepared().signer().clone(),
    )
    .unwrap();
    (seven, thirteen, s)
}

#[test]
fn cold_settlement_skips_missing_hot_eight_and_acks_only_with_current_mode3() {
    let fixture = Fixture::new(true);
    let one = sign(fixture.prepared());
    let r = fixture.closed();
    let closed = fixture.sidecar(10, None, vec![one.clone()], Some(r.clone()));
    let before = fixture.graph(&closed);
    let (seven, thirteen, s) = terminal(&fixture, &one, &r);
    let make = |phase, prepared, controls| {
        RootNativeHeldSidecarV1::new(
            fixture.scope,
            [0; 16],
            Some(r.clone()),
            Some(s),
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Root,
                phase,
                fixture.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let recorded = make(12, Some(thirteen.clone()), vec![one.clone(), seven.clone()]);
    let after = fixture.graph(&recorded);
    let proposal = validate_native_root_cold_transition_v1(
        &before,
        &after,
        fixture.attempt.attempt_id,
        [87; 16],
    )
    .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV1::TerminalRecorded);
    assert_eq!(proposal.maximum_remaining_transactions, 1);
    assert!(recorded.suffix().control(Kind::RootClosed).is_none());

    let hot_ack = fixture.graph(&make(
        13,
        None,
        vec![one.clone(), seven.clone(), sign(thirteen)],
    ));
    assert!(
        validate_native_root_transition_v1(&after, &hot_ack, fixture.attempt.attempt_id, [88; 16])
            .is_ok()
    );
    assert!(
        validate_native_root_cold_transition_v1(
            &after,
            &hot_ack,
            fixture.attempt.attempt_id,
            [88; 16]
        )
        .is_err()
    );

    let q = NativeHeldRecoveryQueryV1 {
        recovery_session: digest(93),
        nonce: [94; 32],
        sequence: 1,
        mode: NativeHeldRecoveryModeV1::RecordRootTerminal,
        target: NativeHeldRecoveryTargetV1::RootScope,
        original_prepared: one.digest(),
        parent_root_query: digest(0),
    };
    let k = RootNativeRecoveryAssertionV1 {
        phase: 12,
        runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
        cold_custody: NativeHeldColdCustodyV1::Unavailable,
        diagnostic_sequence: 15,
        records: fixture.witness.records.clone(),
        disposition: Some(r.clone()),
        hot_archive: None,
        settlement: Some(s),
    };
    let current_key = SigningKey::from_bytes(&[95; 32]);
    let nine = PreparedNativeHeldControlV1::new(
        Kind::RootRecoveryQuery,
        fixture.scope,
        digest(0),
        vec![
            NativeHeldSectionV1::new(Tag::RecoveryQuery, q.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
            NativeHeldSectionV1::new(Tag::RootRecoveryAssertion, k.to_canonical_bytes().unwrap())
                .unwrap(),
        ],
        NativeHeldSignerV1::SourceProvider(fixture::signer(
            [1; 16],
            [96; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &current_key,
        )),
    )
    .unwrap();
    let signature = current_key.sign(&nine.signature_message()).to_bytes();
    let current_ack = fixture.graph(&make(
        13,
        None,
        vec![one, seven, nine.with_signature(signature)],
    ));
    let proposal = validate_native_root_cold_transition_v1(
        &after,
        &current_ack,
        fixture.attempt.attempt_id,
        [89; 16],
    )
    .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV1::TerminalAckStored);
    assert_eq!(proposal.maximum_remaining_transactions, 0);
    // Current signing eligibility is deliberately an owner-IO obligation;
    // this synthetic rotated reference is not enrolled by graph validation.
}

#[test]
fn terminal_stable_id_substitution_is_rejected_before_any_proposal() {
    let fixture = Fixture::new(true);
    let one = sign(fixture.prepared());
    let r = fixture.closed();
    let (seven, thirteen, mut s) = terminal(&fixture, &one, &r);
    s.provider_settlement = digest(99);
    let sidecar = RootNativeHeldSidecarV1::new(
        fixture.scope,
        [0; 16],
        Some(r),
        Some(s),
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            12,
            fixture.scope.flight,
            Some(thirteen),
            vec![one, seven],
        )
        .unwrap(),
    )
    .unwrap();
    let mut rows = fixture.legacy.clone();
    rows.insert(
        native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap(),
        sidecar.to_canonical_bytes().unwrap(),
    );
    assert!(checked(&rows).is_err());
}
