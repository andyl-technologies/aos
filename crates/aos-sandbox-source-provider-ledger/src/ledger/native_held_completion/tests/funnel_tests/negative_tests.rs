//! Full proposal-funnel refusal vectors against canonical companion graphs.
//!
//! These are cryptographic DATA and pure reducers only, not installed owner,
//! current signature, challenge custody, physical admission or runtime evidence.

use super::*;

fn replace_section(
    control: &PreparedNativeHeldControlV1,
    tag: Tag,
    bytes: Vec<u8>,
) -> PreparedNativeHeldControlV1 {
    let sections = control
        .sections()
        .iter()
        .map(|value| {
            if value.tag() == tag {
                section(tag, bytes.clone())
            } else {
                value.clone()
            }
        })
        .collect();
    PreparedNativeHeldControlV1::new(
        control.kind(),
        *control.scope(),
        control.predecessor(),
        sections,
        control.signer().clone(),
    )
    .unwrap()
}

fn candidate_suffix(
    before: &SourceNativeHeldCompletionRecordV1,
    phase: u8,
    prepared: Option<PreparedNativeHeldControlV1>,
    controls: Vec<SignedNativeHeldControlV1>,
) -> (Original, Vec<u8>) {
    let mut original = before.original.clone();
    original.revision += 1;
    // Independently frame unvalidated claims so scope/slot refusals are also
    // exercised by the full decoder/proposal path rather than a setup unwrap.
    let prepared = prepared
        .map(|control| control.to_canonical_bytes())
        .unwrap_or_default();
    let mut bytes = b"AOSNHS01".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[Owner::Provider as u8, phase, 0, 0, 0, 0]);
    bytes.extend_from_slice(before.suffix.flight().as_bytes());
    bytes.extend_from_slice(&(prepared.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(controls.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&prepared);
    for control in controls {
        let encoded = control.to_canonical_bytes();
        bytes.extend_from_slice(&[control.kind() as u8, 0, 0, 0]);
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    (original, bytes)
}

#[test]
fn full_requested_funnel_rejects_actual_no_dispatch_and_changed_original_lineage() {
    for no_dispatch in [false, true] {
        let mut fixture = fixtures::Graph::applying();
        if no_dispatch {
            fixture.acquisition.backend_id = crate::identity::acquire_native_no_dispatch_id_v1(
                fixture.acquisition.normalized_intent.digest(),
                fixture.acquisition.catalog_generation,
                fixture.acquisition.catalog_digest,
            );
            fixture.acquisition.backend_lineage_digest =
                graph::original_lineage(&fixture.acquisition, fixture.native.session_binding);
        } else {
            fixture.acquisition.backend_lineage_digest = d(127);
        }
        fixture.native.reservation_acquisition_digest =
            Some(format::record_digest(&format::encode_acquisition(&fixture.acquisition)).unwrap());
        fixture.refresh_inventory();
        let next = initial(fixture.native.clone());
        let key = native_completion::native_completion_key_v2(next.original.acquisition_id);
        let mut before = fixture.rows();
        before.remove(&key);
        let mut after = before.clone();
        after.insert(key, next.to_canonical_bytes().unwrap());
        assert!(
            propose_native_held_transition_v1(
                before
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                after
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                next.original.acquisition_id,
                SourceNativeHeldStepV1::Requested,
                None,
            )
            .is_err()
        );
    }
}

#[test]
fn full_graph_requires_exact_before_witness_and_completed_response_artifact() {
    let flight = Flight::complete();
    let storage = flight.record.suffix.control(Kind::StorageHeld).unwrap();
    let challenge = challenge_bytes(&flight.record.original, true);
    let prototype = PreparedNativeHeldControlV1::new(
        Kind::ProviderHeld,
        evidence::full_scope(&flight.record).unwrap(),
        storage.digest(),
        vec![
            section(Tag::Witness, flight.witness(Some(&challenge))),
            section(Tag::StorageHeld, storage.to_canonical_bytes()),
            section(Tag::SourceArtifact, flight.artifact().as_bytes().to_vec()),
        ],
        NativeHeldSignerV1::SourceProvider(
            flight
                .record
                .original
                .canonical_request
                .as_ref()
                .unwrap()
                .signer()
                .clone(),
        ),
    )
    .unwrap();
    for index in 0..7 {
        let NativeHeldOwnerWitnessV1::Provider(mut witness) =
            NativeHeldOwnerWitnessV1::from_canonical_bytes(
                Owner::Provider,
                prototype.section(Tag::Witness).unwrap(),
            )
            .unwrap()
        else {
            panic!("Source witness")
        };
        let old = &witness.records[index];
        witness.records[index] =
            NativeHeldByteWitnessV1::new(old.family(), old.key().to_vec(), d(128)).unwrap();
        let candidate = replace_section(
            &prototype,
            Tag::Witness,
            NativeHeldOwnerWitnessV1::Provider(witness)
                .to_canonical_bytes()
                .unwrap(),
        );
        let next = changed(
            &flight.record,
            5,
            Some(candidate),
            flight.record.suffix.controls().to_vec(),
        );
        assert!(
            flight
                .check(
                    SourceNativeHeldStepV1::HeldPrepared,
                    &next,
                    Some(&challenge)
                )
                .is_err(),
            "before witness {index}"
        );
    }
    let candidate = replace_section(&prototype, Tag::SourceArtifact, d(129).as_bytes().to_vec());
    let next = changed(
        &flight.record,
        5,
        Some(candidate),
        flight.record.suffix.controls().to_vec(),
    );
    assert!(
        flight
            .check(
                SourceNativeHeldStepV1::HeldPrepared,
                &next,
                Some(&challenge)
            )
            .is_err()
    );
    let mut wrong_response = flight.clone();
    let keys = graph::companion_keys(&wrong_response.record).unwrap();
    let crate::ledger::model::DecodedRecordV1::Attempt(mut attempt) =
        format::decode_record(&keys[1], &wrong_response.rows[&keys[1]]).unwrap()
    else {
        panic!("Attempt")
    };
    let last = attempt.completed_response.len() - 1;
    attempt.completed_response[last] ^= 1;
    wrong_response
        .rows
        .insert(keys[1].clone(), format::encode_attempt(&attempt));
    assert!(
        wrong_response
            .check(
                SourceNativeHeldStepV1::HeldPrepared,
                &changed(
                    &flight.record,
                    5,
                    Some(prototype),
                    flight.record.suffix.controls().to_vec()
                ),
                Some(&challenge)
            )
            .is_err()
    );
}

#[test]
fn full_graph_cannot_erase_wrong3_or_signed3_under_a_closed_root_query() {
    let flight = Flight::held_prepared();
    let root9 = recovery_query(&flight.record, flight.root_disposition(false));
    let mut controls = flight.record.suffix.controls().to_vec();
    controls.push(root9.clone());
    let (original, suffix) = candidate_suffix(&flight.record, 7, None, controls.clone());
    let mut wrong_before = flight.clone();
    let wrong3 = replace_section(
        flight.record.suffix.prepared().unwrap(),
        Tag::SourceArtifact,
        d(130).as_bytes().to_vec(),
    );
    let wrong_record = SourceNativeHeldCompletionRecordV1::new(
        flight.record.original.clone(),
        NativeHeldCompletionSuffixV1::new(
            Owner::Provider,
            5,
            flight.record.suffix.flight(),
            Some(wrong3),
            flight.record.suffix.controls().to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let key = native_completion::native_completion_key_v2(wrong_record.original.acquisition_id);
    wrong_before
        .rows
        .insert(key, wrong_record.to_canonical_bytes().unwrap());
    wrong_before.record = wrong_record;
    assert!(
        wrong_before
            .check_suffix_claim(
                SourceNativeHeldStepV1::RootRecoveryRecorded,
                &original,
                &suffix
            )
            .is_err()
    );

    for accepted in [true, false] {
        let mut disposition = flight.root_disposition(accepted);
        if !accepted {
            disposition.observation = RootNativeObservationV1::ProviderHeldObserved;
            disposition.scope = evidence::full_scope(&flight.record).unwrap();
            disposition.source_artifact = flight.artifact();
        }
        let mut controls = flight.record.suffix.controls().to_vec();
        controls.push(recovery_query(&flight.record, disposition));
        let (original, suffix) = candidate_suffix(&flight.record, 7, None, controls);
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::RootRecoveryRecorded,
                    &original,
                    &suffix
                )
                .is_err()
        );
    }

    let mut stored = flight;
    stored.store(SourceNativeHeldStepV1::HeldStored, 6);
    let mut controls = stored.record.suffix.controls().to_vec();
    controls.retain(|control| control.kind() != Kind::ProviderHeld);
    controls.push(recovery_query(
        &stored.record,
        stored.root_disposition(false),
    ));
    let (original, suffix) = candidate_suffix(&stored.record, 7, None, controls);
    assert!(
        stored
            .check_suffix_claim(
                SourceNativeHeldStepV1::RootRecoveryRecorded,
                &original,
                &suffix
            )
            .is_err()
    );
}

#[test]
fn full_recovery_funnel_rejects_rewritten_archives_originals_and_queries() {
    let mut flight = Flight::held_prepared();
    flight.store(SourceNativeHeldStepV1::HeldStored, 6);
    flight.root_recorded(false);
    flight.first_query(false);
    let parent = flight
        .record
        .suffix
        .control(Kind::RootRecoveryQuery)
        .unwrap();
    let child = child_query(&flight.record, parent);
    let (original, suffix) = candidate_suffix(
        &flight.record,
        7,
        Some(child.clone()),
        flight.record.suffix.controls().to_vec(),
    );
    for delta in [0, 2] {
        let mut wrong = original.clone();
        wrong.revision = flight.record.original.revision + delta;
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::StorageRecoveryPrepared,
                    &wrong,
                    &suffix
                )
                .is_err()
        );
    }
    let mut wrong_outer = original.clone();
    wrong_outer.state = Outer::Prepared;
    assert!(
        flight
            .check_suffix_claim(
                SourceNativeHeldStepV1::StorageRecoveryPrepared,
                &wrong_outer,
                &suffix
            )
            .is_err()
    );
    let mut controls = flight.record.suffix.controls().to_vec();
    controls[0] = controls[0].prepared().clone().with_signature([131; 64]);
    let (_, rewritten) = candidate_suffix(&flight.record, 7, Some(child.clone()), controls);
    assert!(
        flight
            .check_suffix_claim(
                SourceNativeHeldStepV1::StorageRecoveryPrepared,
                &original,
                &rewritten
            )
            .is_err()
    );

    let mut query = evidence::query(parent.prepared()).unwrap();
    query.original_prepared = d(132);
    let wrong9 = replace_section(
        parent.prepared(),
        Tag::RecoveryQuery,
        query.to_canonical_bytes().unwrap().to_vec(),
    )
    .with_signature([133; 64]);
    let wrong_child = child_query(&flight.record, &wrong9);
    let mut controls = flight.record.suffix.controls().to_vec();
    let last = controls.len() - 1;
    controls[last] = wrong9;
    let (_, wrong_query) = candidate_suffix(&flight.record, 7, Some(wrong_child), controls);
    assert!(
        flight
            .check_suffix_claim(
                SourceNativeHeldStepV1::StorageRecoveryPrepared,
                &original,
                &wrong_query
            )
            .is_err()
    );

    let mut stored_relay = Flight::held_prepared();
    stored_relay.store(SourceNativeHeldStepV1::HeldStored, 6);
    stored_relay.root_recorded(false);
    stored_relay.store(SourceNativeHeldStepV1::RelayStored, 7);
    stored_relay.first_query(false);
    let child = child_query(
        &stored_relay.record,
        stored_relay
            .record
            .suffix
            .control(Kind::RootRecoveryQuery)
            .unwrap(),
    );
    let mut controls = stored_relay.record.suffix.controls().to_vec();
    controls.retain(|control| control.kind() != Kind::ProviderRelay);
    let (original, suffix) = candidate_suffix(&stored_relay.record, 7, Some(child), controls);
    assert!(
        stored_relay
            .check_suffix_claim(
                SourceNativeHeldStepV1::StorageRecoveryPrepared,
                &original,
                &suffix
            )
            .is_err()
    );
}

#[test]
fn full_cold_terminal_funnel_cannot_erase_complete_a_or_forge_before_witness() {
    use aos_sandbox_source_provider_protocol::native_held_completion::recovery::ProviderNativeRecoveryStateV1;
    let mut flight = Flight::held_prepared();
    flight.first_query(true);
    flight.record_cold_storage();
    assert_eq!(flight.record.original.state, Outer::Active);
    assert!(flight.record.suffix.control(Kind::ProviderHeld).is_none());

    for artifact in [d(0), d(138)] {
        let prepared = provider_terminal(&flight.record, artifact);
        let (original, suffix) = candidate_suffix(
            &flight.record,
            8,
            Some(prepared),
            flight.record.suffix.controls().to_vec(),
        );
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::ProviderRecoveryPrepared,
                    &original,
                    &suffix
                )
                .is_err()
        );
    }
    let prototype = provider_terminal(&flight.record, flight.artifact());
    let mut state = ProviderNativeRecoveryStateV1::from_canonical_bytes(
        prototype.section(Tag::ProviderRecoveryState).unwrap(),
    )
    .unwrap();
    let old = state.fields.witness.as_ref().unwrap();
    state.fields.witness =
        Some(NativeHeldByteWitnessV1::new(old.family(), old.key().to_vec(), d(139)).unwrap());
    let prepared = replace_section(
        &prototype,
        Tag::ProviderRecoveryState,
        state.to_canonical_bytes().unwrap(),
    );
    let next = changed(
        &flight.record,
        8,
        Some(prepared),
        flight.record.suffix.controls().to_vec(),
    );
    assert!(
        flight
            .check(
                SourceNativeHeldStepV1::ProviderRecoveryPrepared,
                &next,
                None
            )
            .is_err()
    );
}

#[test]
fn requested_cold12_funnel_requires_original_request_query_and_predecessor() {
    use aos_sandbox_source_provider_protocol::{
        StorageNativeAcceptanceV3,
        native_held_completion::{
            assertion::StorageNativeSettlementAssertionV1, recovery::StorageNativeRecoveryStateV1,
        },
    };
    let mut flight = Flight::requested();
    flight.first_query(false);
    flight.prepare_child();
    flight.store(SourceNativeHeldStepV1::StorageRecoveryQueryStored, 7);
    let reply = fixtures::prepared(&flight.record.original)
        .accepted_reply
        .unwrap();
    let control = storage_recovery_control(&flight.record, &reply);
    for change in 0..3 {
        let mut scope = *control.scope();
        let mut query = evidence::query(control.prepared()).unwrap();
        let mut state = StorageNativeRecoveryStateV1::from_canonical_bytes(
            control
                .prepared()
                .section(Tag::StorageRecoveryState)
                .unwrap(),
        )
        .unwrap();
        let mut predecessor = control.prepared().predecessor();
        if change == 0 {
            predecessor = d(134);
        }
        if change == 1 {
            query.nonce = [135; 32];
        }
        if change == 2 {
            scope.original_native_request = d(136);
            let mut assertion = StorageNativeSettlementAssertionV1::from_canonical_bytes(
                &state.fields.own_assertion,
            )
            .unwrap();
            let old = assertion.acceptance;
            assertion.scope = scope;
            assertion.acceptance = StorageNativeAcceptanceV3::new(
                old.issuance_id(),
                d(136),
                old.receipt_digest(),
                old.descriptor().clone(),
                old.topology().clone(),
            )
            .unwrap();
            state.fields.native_request = d(136);
            state.fields.acceptance = assertion.acceptance.digest();
            state.fields.storage_settlement = assertion.digest().unwrap();
            state.fields.own_assertion = assertion.to_canonical_bytes().unwrap().to_vec();
        }
        let candidate = PreparedNativeHeldControlV1::new(
            Kind::StorageRecoveryState,
            scope,
            predecessor,
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(
                    Tag::StorageRecoveryState,
                    state.to_canonical_bytes().unwrap(),
                ),
            ],
            control.prepared().signer().clone(),
        )
        .unwrap()
        .with_signature([137; 64]);
        let mut controls = flight.record.suffix.controls().to_vec();
        controls.push(candidate);
        let (original, suffix) = candidate_suffix(&flight.record, 8, None, controls);
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::StorageRecoveryRecorded,
                    &original,
                    &suffix
                )
                .is_err(),
            "cold12 change {change}"
        );
    }
}

#[test]
fn full_root_query_funnel_requires_recorded_mode_and_unchanged_disposition() {
    use aos_sandbox_source_provider_protocol::native_held_completion::recovery::{
        NativeHeldRecoveryModeV1, RootNativeRecoveryAssertionV1,
    };
    let mut flight = Flight::held_prepared();
    flight.store(SourceNativeHeldStepV1::HeldStored, 6);
    flight.root_recorded(false);
    let prototype = recovery_query(&flight.record, flight.root_disposition(false));
    for changed_r in [false, true] {
        let candidate = if changed_r {
            let mut state = RootNativeRecoveryAssertionV1::from_canonical_bytes(
                prototype
                    .prepared()
                    .section(Tag::RootRecoveryAssertion)
                    .unwrap(),
            )
            .unwrap();
            let old = &state.records[0];
            state.records[0] =
                NativeHeldByteWitnessV1::new(old.family(), old.key().to_vec(), d(140)).unwrap();
            state.disposition.as_mut().unwrap().records = state.records.clone();
            state.hot_archive = None;
            replace_section(
                prototype.prepared(),
                Tag::RootRecoveryAssertion,
                state.to_canonical_bytes().unwrap(),
            )
        } else {
            let mut query = evidence::query(prototype.prepared()).unwrap();
            query.mode = NativeHeldRecoveryModeV1::Observe;
            replace_section(
                prototype.prepared(),
                Tag::RecoveryQuery,
                query.to_canonical_bytes().unwrap().to_vec(),
            )
        }
        .with_signature([141; 64]);
        let mut controls = flight.record.suffix.controls().to_vec();
        controls.push(candidate);
        let (original, suffix) = candidate_suffix(
            &flight.record,
            7,
            flight.record.suffix.prepared().cloned(),
            controls,
        );
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::RootRecoveryRecorded,
                    &original,
                    &suffix
                )
                .is_err()
        );
    }
}

#[test]
fn full_normal_settlement_funnel_checks_scope_and_stable_ids_before_signing_data() {
    let mut flight = Flight::held_prepared();
    flight.store(SourceNativeHeldStepV1::HeldStored, 6);
    flight.root_recorded(true);
    flight.record_normal_storage();
    let challenge = challenge_bytes(&flight.record.original, true);
    let prototype = evidence::settlement(&flight.record).unwrap().unwrap();
    for changed_id in 0..4 {
        let mut scope = evidence::full_scope(&flight.record).unwrap();
        let mut settlement = prototype;
        match changed_id {
            0 => settlement.root_disposition = d(142),
            1 => settlement.storage_settlement = d(143),
            2 => settlement.provider_settlement = d(144),
            _ => scope.provider_attempt = d(145),
        }
        let prepared = PreparedNativeHeldControlV1::new(
            Kind::ProviderSettled,
            scope,
            flight
                .record
                .suffix
                .control(Kind::StorageSettled)
                .unwrap()
                .digest(),
            vec![
                section(Tag::Witness, flight.witness(Some(&challenge))),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            NativeHeldSignerV1::SourceProvider(
                flight
                    .record
                    .original
                    .canonical_request
                    .as_ref()
                    .unwrap()
                    .signer()
                    .clone(),
            ),
        )
        .unwrap();
        let (original, suffix) = candidate_suffix(
            &flight.record,
            8,
            Some(prepared),
            flight.record.suffix.controls().to_vec(),
        );
        assert!(
            flight
                .check_suffix_claim(
                    SourceNativeHeldStepV1::ProviderSettledPrepared,
                    &original,
                    &suffix
                )
                .is_err()
        );
    }
}
