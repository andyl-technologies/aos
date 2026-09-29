//! Original two-cut CAS/terminal vectors with genuine signed legacy completion.

use super::super::super::cut::RootNativeCutV1;
use super::*;

fn convert(prefix: &AcceptedPrefix, old: &RootNativeHeldGraphV1) -> RootNativeHeldGraphV2 {
    let attempt = prefix.fixture.attempt.attempt_id;
    let claims = &old.sidecars()[&attempt];
    let original = validate_mount_source_state_graph_v2(
        prefix
            .fixture
            .legacy
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();
    let admission = RootNativeCutV1::capture(
        RootNativeCutKindV1::Admission,
        [100; 16],
        &original,
        attempt,
    )
    .unwrap();
    let disposition = claims.disposition().map(|_| {
        RootNativeCutV1::capture(
            RootNativeCutKindV1::Disposition,
            [123; 16],
            old.legacy(),
            attempt,
        )
        .unwrap()
    });
    let sidecar = RootNativeHeldSidecarV2::new(
        *claims.original_scope(),
        claims.response_transaction(),
        claims.disposition().cloned(),
        claims.settlement().copied(),
        claims.terminal_verifier().cloned(),
        claims.suffix().clone(),
        admission,
        disposition,
        None,
    )
    .unwrap();
    let mut canonical = old.canonical_records().clone();
    canonical.remove(&native_root_sidecar_key_v1(attempt).unwrap());
    canonical.insert(
        native_root_sidecar_key_v2(attempt).unwrap(),
        sidecar.to_canonical_bytes().unwrap(),
    );
    checked_v2(&canonical).unwrap()
}

fn checked_v2(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> crate::mount_source_acquisition_state::Result<RootNativeHeldGraphV2> {
    validate_native_root_graph_v2(
        rows.iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
}

fn terminal_claims(prefix: &AcceptedPrefix) -> [RootNativeHeldSidecarV1; 3] {
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
    let settlement = NativeHeldSettlementV1 {
        disposition: NativeHeldDispositionV1::Accepted,
        root_disposition: storage.root_disposition,
        storage_settlement: storage.digest().unwrap(),
        provider_settlement: provider.digest().unwrap(),
    };
    let two = SignedNativeHeldControlV1::from_canonical_bytes(
        prefix.three.section(Tag::StorageHeld).unwrap(),
    )
    .unwrap();
    let four = sign(prefix.four.clone());
    let five = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderRelay,
            prefix.r.scope,
            four.digest(),
            vec![
                provider_w(&prefix.fixture),
                NativeHeldSectionV1::new(Tag::RootDispositionControl, four.to_canonical_bytes())
                    .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(prefix.capture.request.signer().clone()),
        )
        .unwrap(),
    );
    let six = PreparedNativeHeldControlV1::new(
        Kind::StorageSettled,
        prefix.r.scope,
        five.digest(),
        vec![
            NativeHeldSectionV1::new(Tag::Witness, two.section(Tag::Witness).unwrap().to_vec())
                .unwrap(),
            NativeHeldSectionV1::new(
                Tag::Settlement,
                NativeHeldSettlementV1 {
                    provider_settlement: digest(0),
                    ..settlement
                }
                .to_canonical_bytes()
                .unwrap()
                .to_vec(),
            )
            .unwrap(),
        ],
        NativeHeldSignerV1::Storage(prefix.capture.reply.acceptance().signer()),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[77; 32])
        .sign(&six.signature_message())
        .to_bytes();
    let six = six.with_signature(signature);
    let seven = sign_source(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderSettled,
            prefix.r.scope,
            six.digest(),
            vec![
                provider_w(&prefix.fixture),
                NativeHeldSectionV1::new(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                )
                .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(prefix.capture.request.signer().clone()),
        )
        .unwrap(),
    );
    let thirteen = PreparedNativeHeldControlV1::new(
        Kind::RootTerminalRecorded,
        prefix.r.scope,
        seven.digest(),
        vec![
            root_w(&prefix.fixture, prefix.r.records.clone()),
            NativeHeldSectionV1::new(
                Tag::Settlement,
                settlement.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        prefix.one.prepared().signer().clone(),
    )
    .unwrap();
    let make = |phase, prepared, controls, terminal| {
        RootNativeHeldSidecarV1::new(
            prefix.fixture.scope,
            prefix.cas_id,
            Some(prefix.r.clone()),
            terminal,
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Root,
                phase,
                prefix.fixture.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    };
    [
        make(
            5,
            None,
            vec![prefix.one.clone(), prefix.three.clone(), four.clone()],
            None,
        ),
        make(
            6,
            Some(thirteen.clone()),
            vec![
                prefix.one.clone(),
                prefix.three.clone(),
                four.clone(),
                seven.clone(),
            ],
            Some(settlement),
        ),
        make(
            7,
            None,
            vec![
                prefix.one.clone(),
                prefix.three.clone(),
                four,
                seven,
                sign(thirteen),
            ],
            Some(settlement),
        ),
    ]
}

fn with_claims(prefix: &AcceptedPrefix, claims: RootNativeHeldSidecarV1) -> RootNativeHeldGraphV2 {
    let mut canonical = prefix.accepted.canonical_records().clone();
    canonical.insert(
        native_root_sidecar_key_v1(prefix.fixture.attempt.attempt_id).unwrap(),
        claims.to_canonical_bytes().unwrap(),
    );
    convert(prefix, &checked(&canonical).unwrap())
}

fn idle_successor(graph: &RootNativeHeldGraphV2) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut successor = fixture::signed_session([20; 16], 32);
    let previous_head = graph.legacy().provider_heads[&([1; 16], [2; 16])].clone();
    successor.predecessor_session_id = Some(previous_head.current_session_id);
    let successor = seal_record(StoredRecordV2::ProviderSession { value: successor }).unwrap();
    let StoredRecordV2::ProviderSession { value: session } = &successor else {
        panic!("successor session");
    };
    let mut head = previous_head;
    head.revision += 1;
    head.current_session_id = session.session_id;
    head.current_session_record_digest = session.record_digest;
    head.next_request_sequence = 1;
    head.next_response_sequence = 1;
    head.last_reconciliation = None;
    let head = seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap();
    let mut canonical = graph.canonical_records().clone();
    for record in [successor, head] {
        let (key, value) = encode_mount_source_state_record_v2(&record).unwrap();
        canonical.insert(key, value);
    }
    canonical
}

#[test]
fn v2_normal_cas_retains_distinct_cuts_and_actual_eight_append_geometry() {
    let prefix = accepted_prefix();
    let attempt = prefix.fixture.attempt.attempt_id;
    let phase0 = convert(&prefix, &prefix.fixture.graph(&prefix.fixture.phase0()));
    let phase1 = convert(&prefix, &prefix.fixture.graph(&prefix.fixture.phase1()));
    let phase2 = convert(&prefix, &prefix.before_cas);
    let phase3 = convert(&prefix, &prefix.after_cas);
    let phase4 = convert(&prefix, &prefix.accepted);
    let [five, six, seven] = terminal_claims(&prefix);
    let phase5 = with_claims(&prefix, five);
    let phase6 = with_claims(&prefix, six);
    let phase7 = with_claims(&prefix, seven);
    let empty = checked_v2(&BTreeMap::new()).unwrap();
    let sequence = [
        &empty, &phase0, &phase1, &phase2, &phase3, &phase4, &phase5, &phase6, &phase7,
    ];
    let transactions = [
        [100; 16],
        [121; 16],
        [122; 16],
        prefix.cas_id,
        [123; 16],
        [124; 16],
        [125; 16],
        [126; 16],
    ];

    for (index, pair) in sequence.windows(2).enumerate() {
        let proposal =
            validate_native_root_transition_v2(pair[0], pair[1], attempt, transactions[index])
                .unwrap();
        assert_eq!(proposal.maximum_remaining_transactions, 7 - index as u32);
        assert_eq!(
            proposal.puts.len(),
            if index == 0 {
                6
            } else if index == 3 {
                4
            } else {
                1
            }
        );
    }
    let original = phase0.sidecars()[&attempt]
        .admission_cut()
        .to_canonical_bytes()
        .unwrap();
    let retained = &phase7.sidecars()[&attempt];
    assert_eq!(
        retained.admission_cut().to_canonical_bytes().unwrap(),
        original
    );
    assert_ne!(
        retained
            .disposition_cut()
            .unwrap()
            .to_canonical_bytes()
            .unwrap(),
        original
    );
    assert_eq!(
        retained
            .disposition_cut()
            .unwrap()
            .reconstruct(phase7.legacy(), attempt)
            .unwrap()
            .witnesses(),
        &prefix.r.records
    );
    assert_eq!(
        phase7.data_class(attempt),
        Some(RootNativeDataClassV2::BarrierTerminal)
    );
    assert!(validate_native_root_transition_v2(&phase3, &phase4, attempt, [127; 16]).is_err());
}

#[test]
fn terminal_history_survives_genuine_current_session_successor_and_refuses_invalid_current_graph() {
    let prefix = accepted_prefix();
    let attempt = prefix.fixture.attempt.attempt_id;
    let [_, _, seven] = terminal_claims(&prefix);
    let terminal = with_claims(&prefix, seven);
    let original_sidecar = terminal.sidecars()[&attempt].to_canonical_bytes().unwrap();
    let canonical = idle_successor(&terminal);
    let advanced = checked_v2(&canonical).unwrap();

    assert_eq!(
        advanced.data_class(attempt),
        Some(RootNativeDataClassV2::BarrierTerminal)
    );
    assert_eq!(
        advanced.sidecars()[&attempt].to_canonical_bytes().unwrap(),
        original_sidecar
    );
    assert_eq!(
        advanced.sidecars()[&attempt]
            .disposition_cut()
            .unwrap()
            .reconstruct(advanced.legacy(), attempt)
            .unwrap()
            .witnesses(),
        &prefix.r.records
    );
    assert!(
        advanced.legacy().acquisitions[&prefix.fixture.attempt.owner.owner_id()]
            .manager_custody
            .is_none()
    );

    let mut bad = canonical;
    let original_session_key = provider_session_key(prefix.fixture.session.session_id);
    bad.remove(&original_session_key);
    assert!(checked_v2(&bad).is_err());
    let mut bad = idle_successor(&terminal);
    let mut head = advanced.legacy().provider_heads[&([1; 16], [2; 16])].clone();
    head.current_session_record_digest = [99; 32];
    let (key, value) = encode_mount_source_state_record_v2(
        &seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap(),
    )
    .unwrap();
    bad.insert(key, value);
    assert!(checked_v2(&bad).is_err());
}

#[test]
fn advanced_current_head_cannot_recreate_fresh_hot13_but_historical_mode3_joins_exact_r() {
    let prefix = accepted_prefix();
    let attempt = prefix.fixture.attempt.attempt_id;
    let [_, six, seven] = terminal_claims(&prefix);
    let recorded = with_claims(&prefix, six);
    let original_ack = with_claims(&prefix, seven);
    let advanced = checked_v2(&idle_successor(&recorded)).unwrap();
    let mut hot = idle_successor(&recorded);
    hot.insert(
        native_root_sidecar_key_v2(attempt).unwrap(),
        original_ack.sidecars()[&attempt]
            .to_canonical_bytes()
            .unwrap(),
    );
    let hot_ack = checked_v2(&hot).unwrap();

    assert!(validate_native_root_transition_v2(&advanced, &hot_ack, attempt, [126; 16]).is_err());
    assert!(
        validate_native_root_cold_transition_v2(&advanced, &hot_ack, attempt, [126; 16]).is_err()
    );
    let old = &advanced.sidecars()[&attempt];
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
        diagnostic_sequence: 33,
        records: prefix.r.records.clone(),
        disposition: Some(prefix.r.clone()),
        hot_archive: Some(sign(prefix.four.clone()).to_canonical_bytes()),
        settlement: old.settlement().copied(),
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
    let mut controls = old.suffix().controls().to_vec();
    controls.push(nine.with_signature(signature));
    let cold = RootNativeHeldSidecarV2::new(
        *old.original_scope(),
        old.response_transaction(),
        old.disposition().cloned(),
        old.settlement().copied(),
        old.terminal_verifier().cloned(),
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            7,
            old.original_scope().flight,
            None,
            controls,
        )
        .unwrap(),
        old.admission_cut().clone(),
        old.disposition_cut().cloned(),
        None,
    )
    .unwrap();
    let mut rows = advanced.canonical_records().clone();
    rows.insert(
        native_root_sidecar_key_v2(attempt).unwrap(),
        cold.to_canonical_bytes().unwrap(),
    );
    let acknowledged = checked_v2(&rows).unwrap();
    let proposal =
        validate_native_root_cold_transition_v2(&advanced, &acknowledged, attempt, [126; 16])
            .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV2::TerminalAckStored);
    assert_eq!(proposal.maximum_remaining_transactions, 0);
    assert_eq!(
        acknowledged.sidecars()[&attempt].disposition_cut(),
        old.disposition_cut()
    );
}
