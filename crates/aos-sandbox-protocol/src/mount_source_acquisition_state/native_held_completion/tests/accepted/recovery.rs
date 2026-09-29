//! Current Source10 receipt vectors over the genuine Accepted/CAS prefix.
//!
//! The complete child/assertion/signature graph is DATA. Tests do not enroll
//! the rotated key or prove a real current query or protected trust cut.

use super::*;
use ed25519_dalek::Signer as _;

struct TerminalReceipt {
    ten: SignedNativeHeldControlV1,
    verifier: RootNativeTerminalVerifierV1,
    settlement: NativeHeldSettlementV1,
    thirteen: PreparedNativeHeldControlV1,
}

fn current_terminal(prefix: &AcceptedPrefix) -> TerminalReceipt {
    let q = NativeHeldRecoveryQueryV1 {
        recovery_session: digest(106),
        nonce: [107; 32],
        sequence: 1,
        mode: NativeHeldRecoveryModeV1::SettleRecordedDisposition,
        target: NativeHeldRecoveryTargetV1::RootScope,
        original_prepared: prefix.one.digest(),
        parent_root_query: digest(0),
    };
    let k = RootNativeRecoveryAssertionV1 {
        phase: 4,
        runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
        cold_custody: NativeHeldColdCustodyV1::Unavailable,
        diagnostic_sequence: 16,
        records: prefix.r.records.clone(),
        disposition: Some(prefix.r.clone()),
        hot_archive: None,
        settlement: None,
    };
    let nine = sign(
        PreparedNativeHeldControlV1::new(
            Kind::RootRecoveryQuery,
            prefix.fixture.scope,
            digest(0),
            vec![
                NativeHeldSectionV1::new(
                    Tag::RecoveryQuery,
                    q.to_canonical_bytes().unwrap().to_vec(),
                )
                .unwrap(),
                NativeHeldSectionV1::new(
                    Tag::RootRecoveryAssertion,
                    k.to_canonical_bytes().unwrap(),
                )
                .unwrap(),
            ],
            prefix.one.prepared().signer().clone(),
        )
        .unwrap(),
    );
    let child_q = NativeHeldRecoveryQueryV1 {
        nonce: [108; 32],
        target: NativeHeldRecoveryTargetV1::NativeScope,
        parent_root_query: nine.digest(),
        ..q
    };
    let eleven = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderStorageRecoveryQuery,
            prefix.r.scope,
            nine.digest(),
            vec![
                NativeHeldSectionV1::new(
                    Tag::RecoveryQuery,
                    child_q.to_canonical_bytes().unwrap().to_vec(),
                )
                .unwrap(),
                NativeHeldSectionV1::new(Tag::RootRecoveryControl, nine.to_canonical_bytes())
                    .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(prefix.capture.request.signer().clone()),
        )
        .unwrap(),
    );

    let storage = StorageNativeSettlementAssertionV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        scope: prefix.r.scope,
        root_disposition: prefix.r.digest().unwrap(),
        acceptance: prefix.capture.acceptance.clone(),
    };
    let provider = ProviderNativeSettlementAssertionV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        scope: prefix.r.scope,
        root_disposition: storage.root_disposition,
        storage_settlement: storage.digest().unwrap(),
        source_artifact: prefix.r.source_artifact,
    };
    let s = NativeHeldSettlementV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        root_disposition: storage.root_disposition,
        storage_settlement: storage.digest().unwrap(),
        provider_settlement: provider.digest().unwrap(),
    };
    let mut issuance_key = vec![78; 16];
    issuance_key.extend_from_slice(prefix.capture.request_digest.as_bytes());
    let storage_state = StorageNativeRecoveryStateV1 {
        fields: NativeHeldRecoveryFieldsV1 {
            phase: 4,
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            row_class: NativeHeldRecoveryRowClassV1::Native,
            child_status: NativeHeldRecoveryChildStatusV1::NotQueried,
            diagnostic_sequence: 17,
            native_request: prefix.capture.request_digest,
            acceptance: prefix.capture.acceptance.digest(),
            root_disposition: s.root_disposition,
            storage_settlement: s.storage_settlement,
            provider_settlement: digest(0),
            witness: Some(
                NativeHeldByteWitnessV1::new(Family::StorageIssuance, issuance_key, digest(109))
                    .unwrap(),
            ),
            disposition: Some(prefix.r.clone()),
            own_assertion: storage.to_canonical_bytes().unwrap().to_vec(),
            hot_terminal: None,
            child: None,
        },
    };
    let twelve = PreparedNativeHeldControlV1::new(
        Kind::StorageRecoveryState,
        prefix.r.scope,
        eleven.digest(),
        vec![
            NativeHeldSectionV1::new(
                Tag::RecoveryQuery,
                child_q.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(
                Tag::StorageRecoveryState,
                storage_state.to_canonical_bytes().unwrap(),
            )
            .unwrap(),
        ],
        NativeHeldSignerV1::Storage(prefix.capture.reply.acceptance().signer()),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[77; 32])
        .sign(&twelve.signature_message())
        .to_bytes();
    let twelve = twelve.with_signature(signature);
    let native_key = [
        b"AOSNCK02".as_slice(),
        prefix.capture.request_digest.as_bytes(),
    ]
    .concat();
    let state = ProviderNativeRecoveryStateV1 {
        fields: NativeHeldRecoveryFieldsV1 {
            phase: 9,
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            row_class: NativeHeldRecoveryRowClassV1::Native,
            child_status: NativeHeldRecoveryChildStatusV1::VerifiedState,
            diagnostic_sequence: 18,
            native_request: prefix.capture.request_digest,
            acceptance: prefix.capture.acceptance.digest(),
            root_disposition: s.root_disposition,
            storage_settlement: s.storage_settlement,
            provider_settlement: s.provider_settlement,
            witness: Some(
                NativeHeldByteWitnessV1::new(Family::ProviderNative, native_key, digest(110))
                    .unwrap(),
            ),
            disposition: Some(prefix.r.clone()),
            own_assertion: provider.to_canonical_bytes().unwrap().to_vec(),
            hot_terminal: None,
            child: Some(twelve.to_canonical_bytes()),
        },
    };
    let key = SigningKey::from_bytes(&[111; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        [2; 16],
        1,
        digest(8),
        [112; 16],
        2,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &key,
    )
    .unwrap();
    let ten = PreparedNativeHeldControlV1::new(
        Kind::ProviderRecoveryState,
        prefix.r.scope,
        nine.digest(),
        vec![
            NativeHeldSectionV1::new(Tag::RecoveryQuery, q.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
            NativeHeldSectionV1::new(
                Tag::ProviderRecoveryState,
                state.to_canonical_bytes().unwrap(),
            )
            .unwrap(),
        ],
        NativeHeldSignerV1::SourceProvider(signer.clone()),
    )
    .unwrap();
    let signature = key.sign(&ten.signature_message()).to_bytes();
    let ten = ten.with_signature(signature);
    let mut snapshot = prefix.fixture.session.signers[3].clone();
    snapshot.key_id = signer.key_id();
    snapshot.key_generation = signer.key_generation();
    snapshot.public_key = key.verifying_key().to_bytes();
    snapshot.public_key_fingerprint = *signer.public_key_digest().as_bytes();
    let verifier = RootNativeTerminalVerifierV1 {
        trust_generation: 2,
        trust_digest: digest(113),
        revocation_generation: 2,
        revocation_digest: digest(114),
        verified_at_seconds: 150,
        signer: snapshot,
    };
    let thirteen = PreparedNativeHeldControlV1::new(
        Kind::RootTerminalRecorded,
        prefix.r.scope,
        ten.digest(),
        vec![
            root_w(&prefix.fixture, prefix.r.records.clone()),
            NativeHeldSectionV1::new(Tag::Settlement, s.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
        ],
        prefix.one.prepared().signer().clone(),
    )
    .unwrap();
    TerminalReceipt {
        ten,
        verifier,
        settlement: s,
        thirteen,
    }
}

fn terminal_graph(
    prefix: &AcceptedPrefix,
    receipt: &TerminalReceipt,
    verifier: Option<RootNativeTerminalVerifierV1>,
    ten: SignedNativeHeldControlV1,
) -> crate::mount_source_acquisition_state::Result<RootNativeHeldGraphV1> {
    let sidecar = RootNativeHeldSidecarV1::new(
        prefix.fixture.scope,
        prefix.cas_id,
        Some(prefix.r.clone()),
        Some(receipt.settlement),
        verifier,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            6,
            prefix.fixture.scope.flight,
            Some(receipt.thirteen.clone()),
            vec![prefix.one.clone(), prefix.three.clone(), ten],
        )
        .unwrap(),
    )
    .unwrap();
    let mut canonical = prefix.accepted.canonical_records().clone();
    canonical.insert(
        native_root_sidecar_key_v1(prefix.fixture.attempt.attempt_id).unwrap(),
        sidecar.to_canonical_bytes().unwrap(),
    );
    checked(&canonical)
}

#[test]
fn current_source10_full_receipt_is_terminal_only_and_retains_native_verifier_pin() {
    let prefix = accepted_prefix();
    let receipt = current_terminal(&prefix);
    let after = terminal_graph(
        &prefix,
        &receipt,
        Some(receipt.verifier.clone()),
        receipt.ten.clone(),
    )
    .unwrap();
    let proposal = validate_native_root_cold_transition_v1(
        &prefix.accepted,
        &after,
        prefix.fixture.attempt.attempt_id,
        [115; 16],
    )
    .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV1::TerminalRecorded);
    assert_eq!(proposal.maximum_remaining_transactions, 1);
    let sidecar = &after.sidecars()[&prefix.fixture.attempt.attempt_id];
    assert!(sidecar.suffix().control(Kind::RootAccepted).is_none());
    assert!(sidecar.suffix().control(Kind::ProviderSettled).is_none());
    assert_eq!(sidecar.terminal_verifier(), Some(&receipt.verifier));
    let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(
        receipt.ten.section(Tag::ProviderRecoveryState).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state.fields.child_status,
        NativeHeldRecoveryChildStatusV1::VerifiedState
    );
    assert!(state.fields.child.is_some());
    assert_eq!(
        state.fields.provider_settlement,
        receipt.settlement.provider_settlement
    );
    assert!(
        after.legacy().acquisitions[&prefix.fixture.attempt.owner.owner_id()]
            .manager_custody
            .is_none()
    );

    assert!(terminal_graph(&prefix, &receipt, None, receipt.ten.clone()).is_err());
    let mut wrong_pin = receipt.verifier.clone();
    wrong_pin.signer = prefix.fixture.session.signers[3].clone();
    assert!(terminal_graph(&prefix, &receipt, Some(wrong_pin), receipt.ten.clone()).is_err());
    let forged = receipt.ten.prepared().clone().with_signature([1; 64]);
    assert!(terminal_graph(&prefix, &receipt, Some(receipt.verifier.clone()), forged).is_err());
}

#[test]
fn accepted_terminal_current_mode3_ack_preserves_cas_r_s_and_received_source_pin() {
    let prefix = accepted_prefix();
    let receipt = current_terminal(&prefix);
    let before = terminal_graph(
        &prefix,
        &receipt,
        Some(receipt.verifier.clone()),
        receipt.ten.clone(),
    )
    .unwrap();
    let q = NativeHeldRecoveryQueryV1 {
        recovery_session: digest(116),
        nonce: [117; 32],
        sequence: 1,
        mode: NativeHeldRecoveryModeV1::RecordRootTerminal,
        target: NativeHeldRecoveryTargetV1::RootScope,
        original_prepared: prefix.one.digest(),
        parent_root_query: digest(0),
    };
    let k = RootNativeRecoveryAssertionV1 {
        phase: 6,
        runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
        cold_custody: NativeHeldColdCustodyV1::Unavailable,
        diagnostic_sequence: 19,
        records: prefix.r.records.clone(),
        disposition: Some(prefix.r.clone()),
        hot_archive: None,
        settlement: Some(receipt.settlement),
    };
    let key = SigningKey::from_bytes(&[118; 32]);
    let signer = fixture::signer(
        [1; 16],
        [119; 16],
        SourceProviderKeyUsageV1::RootMountRecord,
        &key,
    );
    let nine = PreparedNativeHeldControlV1::new(
        Kind::RootRecoveryQuery,
        prefix.fixture.scope,
        digest(0),
        vec![
            NativeHeldSectionV1::new(Tag::RecoveryQuery, q.to_canonical_bytes().unwrap().to_vec())
                .unwrap(),
            NativeHeldSectionV1::new(Tag::RootRecoveryAssertion, k.to_canonical_bytes().unwrap())
                .unwrap(),
        ],
        NativeHeldSignerV1::SourceProvider(signer),
    )
    .unwrap();
    let signature = key.sign(&nine.signature_message()).to_bytes();
    let sidecar = RootNativeHeldSidecarV1::new(
        prefix.fixture.scope,
        prefix.cas_id,
        Some(prefix.r.clone()),
        Some(receipt.settlement),
        Some(receipt.verifier.clone()),
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            7,
            prefix.fixture.scope.flight,
            None,
            vec![
                prefix.one.clone(),
                prefix.three.clone(),
                receipt.ten.clone(),
                nine.with_signature(signature),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let mut canonical = before.canonical_records().clone();
    canonical.insert(
        native_root_sidecar_key_v1(prefix.fixture.attempt.attempt_id).unwrap(),
        sidecar.to_canonical_bytes().unwrap(),
    );
    let after = checked(&canonical).unwrap();
    let proposal = validate_native_root_cold_transition_v1(
        &before,
        &after,
        prefix.fixture.attempt.attempt_id,
        [120; 16],
    )
    .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV1::TerminalAckStored);
    assert_eq!(proposal.maximum_remaining_transactions, 0);
    let retained = &after.sidecars()[&prefix.fixture.attempt.attempt_id];
    assert_eq!(retained.response_transaction(), prefix.cas_id);
    assert_eq!(retained.disposition(), Some(&prefix.r));
    assert_eq!(retained.settlement(), Some(&receipt.settlement));
    assert_eq!(retained.terminal_verifier(), Some(&receipt.verifier));
}
