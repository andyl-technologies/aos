//! Full canonical lifecycle DATA fixtures; no owner, cancellation or IO proof.

use super::super::super::{
    SourceNativeHeldLifecycleV1 as Lifecycle, native_held_release_status_binding_v1,
    propose_native_held_lifecycle_v1,
};
use super::*;
use crate::ledger::{completion, model::*};
use aos_sandbox_source_provider_protocol::native_held_completion::recovery::*;
use aos_sandbox_source_provider_protocol::*;

fn propose_lifecycle(
    before: &graph::Records,
    after: &graph::Records,
    record: &SourceNativeHeldCompletionRecordV1,
    step: Lifecycle,
) -> Result<super::super::super::SourceNativeHeldLifecycleTransactionV1, crate::LedgerFormatErrorV1>
{
    propose_native_held_lifecycle_v1(
        before.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        after.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        record.original.acquisition_id,
        step,
    )
}

fn cold_prefix(prepared: bool) -> Flight {
    let mut flight = if prepared {
        Flight::prepared()
    } else {
        Flight::requested()
    };
    flight.first_query(false);
    flight.settle_cold();
    flight
}

fn root_terminal(flight: &Flight, metadata: bool) -> SourceNativeHeldCompletionRecordV1 {
    let old = &flight.record;
    let root = old.suffix.control(Kind::RootPrepared).unwrap();
    let settlement = evidence::settlement(old).unwrap().unwrap();
    let control = if metadata {
        let disposition = evidence::root_disposition(old).unwrap().unwrap();
        let query = NativeHeldRecoveryQueryV1 {
            recovery_session: d(141),
            nonce: [142; 32],
            sequence: 2,
            mode: NativeHeldRecoveryModeV1::RecordRootTerminal,
            target: NativeHeldRecoveryTargetV1::RootScope,
            original_prepared: root.digest(),
            parent_root_query: d(0),
        };
        let assertion = RootNativeRecoveryAssertionV1 {
            phase: if disposition.disposition == NativeHeldDispositionV1::Closed {
                13
            } else {
                7
            },
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            cold_custody: NativeHeldColdCustodyV1::Unavailable,
            diagnostic_sequence: 2,
            records: disposition.records.clone(),
            disposition: Some(disposition),
            hot_archive: None,
            settlement: Some(settlement),
        };
        PreparedNativeHeldControlV1::new(
            Kind::RootRecoveryQuery,
            *root.scope(),
            d(0),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(
                    Tag::RootRecoveryAssertion,
                    assertion.to_canonical_bytes().unwrap(),
                ),
            ],
            root.prepared().signer().clone(),
        )
        .unwrap()
    } else {
        let predecessor = old
            .suffix
            .controls()
            .iter()
            .rev()
            .find(|control| {
                matches!(
                    control.kind(),
                    Kind::ProviderSettled | Kind::ProviderRecoveryState
                )
            })
            .unwrap();
        PreparedNativeHeldControlV1::new(
            Kind::RootTerminalRecorded,
            evidence::full_scope(old).unwrap(),
            predecessor.digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Root(root_witness())
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            root.prepared().signer().clone(),
        )
        .unwrap()
    }
    .with_signature([0xCD; 64]);
    let mut controls = old.suffix.controls().to_vec();
    controls.push(control);
    changed(old, 10, None, controls)
}

fn retirement_candidate(
    flight: &Flight,
    next: &SourceNativeHeldCompletionRecordV1,
) -> graph::Records {
    let mut rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();
    rows.attempt.revision += 1;
    rows.attempt.state = ProviderAttemptStateV1::Retired;
    rows.acquisition.revision += 1;
    rows.acquisition.state = ProviderAcquisitionStateV1::Faulted;
    rows.holder.revision += 1;
    rows.holder.pending_attempt_digest = None;
    let mut result = flight.proposed_rows(next);
    result.insert(rows.keys[1].clone(), format::encode_attempt(&rows.attempt));
    result.insert(
        rows.keys[2].clone(),
        format::encode_acquisition(&rows.acquisition),
    );
    result.insert(rows.keys[3].clone(), format::encode_session(&rows.holder));
    result.insert(
        rows.keys[4].clone(),
        format::encode_session_history(&rows.holder),
    );
    result
}

fn retire(flight: &mut Flight, metadata: bool) {
    let next = root_terminal(flight, metadata);
    let after = retirement_candidate(flight, &next);
    let proposal = propose_native_held_transition_v1(
        flight
            .rows
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice())),
        after.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        next.original.acquisition_id,
        SourceNativeHeldStepV1::RootTerminalRecorded,
        None,
    )
    .unwrap();
    assert_eq!(proposal.mutations().len(), 5);
    flight.rows = after;
    flight.record = next;
}

#[test]
fn cold_terminal_retires_exact_five_owners_for_requested_prepared_and_both_root_proofs() {
    for prepared in [false, true] {
        for metadata in [false, true] {
            let mut flight = cold_prefix(prepared);
            let before = flight.rows.clone();
            let original = flight.record.original.clone();
            let prior = graph::Companions::read(&before, &flight.record).unwrap();
            retire(&mut flight, metadata);
            let rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();

            let mut expected_original = original;
            expected_original.revision += 1;
            assert_eq!(flight.record.original, expected_original);
            assert_eq!(flight.record.suffix.phase(), 10);
            assert_eq!(rows.attempt.state, ProviderAttemptStateV1::Retired);
            assert_eq!(rows.attempt.signed_request, prior.attempt.signed_request);
            assert_eq!(rows.attempt.completed_response, Vec::<u8>::new());
            assert_eq!(rows.acquisition.state, ProviderAcquisitionStateV1::Faulted);
            assert_eq!(
                rows.holder.next_request_sequence,
                prior.holder.next_request_sequence
            );
            assert_eq!(
                rows.holder.next_response_sequence,
                prior.holder.next_response_sequence
            );
            assert_eq!(
                rows.holder.last_completed_attempt_digest,
                prior.holder.last_completed_attempt_digest
            );
            assert_eq!(rows.holder.pending_attempt_digest, None);
            assert_eq!(rows.holder, rows.history);
            assert_eq!(before[&rows.keys[0]], flight.rows[&rows.keys[0]]);
            assert_eq!(evidence::artifact(&flight.record).unwrap(), d(0));
            assert_eq!(
                evidence::storage_assertion(&flight.record)
                    .unwrap()
                    .unwrap()
                    .to_canonical_bytes()
                    .unwrap()[11],
                1
            );
            graph::validate(&flight.rows).unwrap();
        }
    }
}

#[test]
fn cold_terminal_reserved_pending_and_inexact_inverse_are_retained_negatives() {
    let flight = cold_prefix(false);
    let next = root_terminal(&flight, true);
    let unretired = flight.proposed_rows(&next);
    assert!(graph::validate(&unretired).is_err());
    let good = retirement_candidate(&flight, &next);
    let keys = graph::companion_keys(&next).unwrap();

    for change in 0..6 {
        let mut bad = good.clone();
        let mut rows = graph::Companions::read(&bad, &next).unwrap();
        match change {
            0 => rows.acquisition.revision += 1,
            1 => rows.acquisition.backend_lineage_digest = d(201),
            2 => rows.attempt.signed_request.clear(),
            3 => rows.holder.next_response_sequence += 1,
            4 => rows.holder.last_completed_attempt_digest = Some(rows.attempt.attempt_digest),
            _ => rows.holder.pending_attempt_digest = Some(rows.attempt.attempt_digest),
        }
        bad.insert(keys[1].clone(), format::encode_attempt(&rows.attempt));
        bad.insert(
            keys[2].clone(),
            format::encode_acquisition(&rows.acquisition),
        );
        bad.insert(keys[3].clone(), format::encode_session(&rows.holder));
        bad.insert(
            keys[4].clone(),
            format::encode_session_history(&rows.holder),
        );
        assert!(
            propose_native_held_transition_v1(
                flight
                    .rows
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice())),
                bad.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                next.original.acquisition_id,
                SourceNativeHeldStepV1::RootTerminalRecorded,
                None,
            )
            .is_err(),
            "cold retirement case {change}"
        );
    }
    let mut forged = good;
    forged.insert(keys[5].clone(), flight.record.to_canonical_bytes().unwrap());
    assert!(graph::validate(&forged).is_err());
}

fn add_fresh_acquire(flight: &Flight, successor: bool) -> Flight {
    add_acquire(flight, successor.then_some(70), [144; 16], [145; 32])
}

fn add_acquire(
    flight: &Flight,
    successor: Option<u8>,
    request_id: [u8; 16],
    nonce: [u8; 32],
) -> Flight {
    let rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();
    let mut session = successor
        .map(fixtures::session)
        .unwrap_or_else(|| rows.holder.clone());
    if successor.is_some() {
        session.session_generation = rows.holder.session_generation + 1;
        session.predecessor_session_binding = Some(rows.holder.session_binding);
        session.supersession_evidence_digest = Some(d(143));
        session.acquisition_sequence_floor = rows.holder.acquisition_sequence_floor;
        session.next_acquisition_sequence = rows.holder.next_acquisition_sequence;
    }
    session.revision += 1;
    let request_sequence = if successor.is_some() {
        1
    } else {
        session.next_request_sequence
    };
    let acquisition_sequence = session.next_acquisition_sequence;
    let fresh = fixtures::Graph::applying_for_session(
        session,
        request_sequence,
        request_id,
        acquisition_sequence,
        nonce,
    );
    let record = initial(fresh.native.clone());
    let mut after = flight.rows.clone();
    for (key, value) in fresh.rows() {
        if matches!(
            format::decode_record(&key, &value).unwrap(),
            DecodedRecordV1::Attempt(_)
                | DecodedRecordV1::Acquisition(_)
                | DecodedRecordV1::Session(_)
                | DecodedRecordV1::SessionHistory(_)
        ) {
            after.insert(key, value);
        }
    }
    after.insert(
        native_completion::native_completion_key_v2(record.original.acquisition_id),
        record.to_canonical_bytes().unwrap(),
    );
    propose_lifecycle(
        &flight.rows,
        &after,
        &flight.record,
        Lifecycle::CurrentOwnersAdvanced,
    )
    .unwrap();
    Flight {
        rows: after,
        record,
    }
}

#[test]
fn same_session_successor_and_two_retained_flights_keep_original_history_separate() {
    for successor in [false, true] {
        let mut first = cold_prefix(false);
        retire(&mut first, true);
        let original_keys = graph::companion_keys(&first.record).unwrap();
        let original_attempt = first.rows[&original_keys[1]].clone();
        let original_native = first.rows[&original_keys[5]].clone();
        let mut second = add_fresh_acquire(&first, successor);
        second.first_query(false);
        second.settle_cold();
        retire(&mut second, false);

        graph::validate(&second.rows).unwrap();
        assert_eq!(second.rows[&original_keys[1]], original_attempt);
        assert_eq!(second.rows[&original_keys[5]], original_native);
        let old = graph::Companions::read(&second.rows, &first.record).unwrap();
        if successor {
            assert_ne!(old.holder.session_binding, old.history.session_binding);
        } else {
            assert_eq!(old.holder, old.history);
        }
        assert_eq!(
            second
                .rows
                .values()
                .filter(|bytes| graph::is_held(bytes))
                .count(),
            2
        );
    }
}

#[test]
fn terminal_retention_rejects_each_original_dependency_and_current_pair_forgery() {
    let mut flight = cold_prefix(false);
    retire(&mut flight, true);
    let rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();
    let mut keys = rows.keys.to_vec();
    keys.push(format::catalog_key(
        flight.record.original.provider_id,
        rows.acquisition.catalog_generation,
    ));
    for key in keys {
        let mut missing = flight.rows.clone();
        missing.remove(&key);
        assert!(graph::validate(&missing).is_err());
    }
    let mut forged = flight.rows.clone();
    let mut history = rows.history;
    history.revision += 1;
    forged.insert(
        rows.keys[4].clone(),
        format::encode_session_history(&history),
    );
    assert!(graph::validate(&forged).is_err());
    let duplicate = flight
        .rows
        .iter()
        .chain(flight.rows.iter())
        .map(|(k, v)| (k.as_slice(), v.as_slice()));
    assert!(validate_native_held_records_v1(duplicate).is_err());
}

fn completed_terminal() -> Flight {
    let mut flight = Flight::held_prepared();
    flight.store(SourceNativeHeldStepV1::HeldStored, 6);
    flight.root_recorded(true);
    flight.settle_normal();
    flight
}

fn marker(flight: &Flight) -> Flight {
    cleanup_marker(flight, Lifecycle::OriginalCustodyMarked)
}

fn cleanup_marker(flight: &Flight, lifecycle: Lifecycle) -> Flight {
    let record = SourceNativeHeldCompletionRecordV1::new(
        flight
            .record
            .original
            .advance(Outer::CleanupRequired)
            .unwrap(),
        flight.record.suffix.clone(),
    )
    .unwrap();
    let rows = flight.proposed_rows(&record);
    let proposal = propose_lifecycle(&flight.rows, &rows, &flight.record, lifecycle).unwrap();
    assert_eq!(proposal.mutations().len(), 1);
    assert_eq!(proposal.lifecycle(), lifecycle);
    assert_eq!(proposal.status_binding(), None);
    let key = graph::companion_keys(&flight.record).unwrap()[5].clone();
    assert_eq!(proposal.mutations()[0].key(), key.as_slice());
    assert_eq!(
        proposal.mutations()[0].before(),
        Some(flight.rows[&key].as_slice())
    );
    assert_eq!(proposal.mutations()[0].after(), rows[&key].as_slice());
    assert_eq!(
        proposal.original_custody_required(),
        Some(flight.rows[&graph::companion_keys(&flight.record).unwrap()[5]].as_slice())
    );
    Flight { rows, record }
}

#[test]
fn cold_cleanup_marks_requested_and_prepared_originals_without_releasing_storage_interest() {
    for prepared in [false, true] {
        for metadata in [false, true] {
            let mut flight = cold_prefix(prepared);
            retire(&mut flight, metadata);
            let marked = cleanup_marker(&flight, Lifecycle::ColdTerminalCleanupMarked);
            let key = graph::companion_keys(&flight.record).unwrap()[5].clone();
            let rows = graph::Companions::read(&marked.rows, &marked.record).unwrap();

            assert_eq!(
                marked.record.original,
                flight
                    .record
                    .original
                    .advance(Outer::CleanupRequired)
                    .unwrap()
            );
            assert_eq!(marked.record.suffix, flight.record.suffix);
            for (owner, bytes) in &flight.rows {
                if owner != &key {
                    assert_eq!(marked.rows[owner], *bytes);
                }
            }
            assert_eq!(
                graph::cold_unleased_original(&marked.record, &rows)
                    .unwrap()
                    .as_deref(),
                Some(&flight.record.original)
            );
            assert_eq!(rows.attempt.state, ProviderAttemptStateV1::Retired);
            assert_eq!(rows.acquisition.state, ProviderAcquisitionStateV1::Faulted);
            assert_eq!(evidence::artifact(&marked.record).unwrap(), d(0));
            let storage = evidence::storage_assertion(&marked.record)
                .unwrap()
                .unwrap();
            assert_eq!(
                storage.to_canonical_bytes().unwrap(),
                evidence::storage_assertion(&flight.record)
                    .unwrap()
                    .unwrap()
                    .to_canonical_bytes()
                    .unwrap()
            );
            assert_eq!(storage.to_canonical_bytes().unwrap()[11], 1);
            graph::validate(&marked.rows).unwrap();
            assert!(
                completion::original_native_complete_artifact(
                    &marked.record.original,
                    &rows.attempt,
                    &rows.acquisition,
                )
                .is_err()
            );
            assert!(
                propose_lifecycle(
                    &marked.rows,
                    &marked.rows,
                    &marked.record,
                    Lifecycle::ColdTerminalCleanupMarked,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn marked_cold_original_survives_current_work_but_freezes_its_retired_acquisition() {
    for prepared in [false, true] {
        for successor in [false, true] {
            let mut flight = cold_prefix(prepared);
            retire(&mut flight, successor);
            let marked = cleanup_marker(&flight, Lifecycle::ColdTerminalCleanupMarked);
            let current = add_fresh_acquire(&marked, successor);
            let keys = graph::companion_keys(&marked.record).unwrap();
            for index in [1, 2, 5] {
                assert_eq!(current.rows[&keys[index]], marked.rows[&keys[index]]);
            }
            graph::validate(&current.rows).unwrap();

            let mut rewritten = current.rows.clone();
            let mut rows = graph::Companions::read(&rewritten, &marked.record).unwrap();
            rows.acquisition.revision += 1;
            rewritten.insert(
                keys[2].clone(),
                format::encode_acquisition(&rows.acquisition),
            );
            assert!(
                graph::validate_retained_transition(
                    &current.rows,
                    &rewritten,
                    &keys[5],
                    &current.rows[&keys[5]],
                    &rewritten[&keys[5]],
                )
                .is_err()
            );
            assert!(
                propose_lifecycle(
                    &current.rows,
                    &rewritten,
                    &marked.record,
                    Lifecycle::CurrentOwnersAdvanced,
                )
                .is_err()
            );
            assert!(graph::validate(&rewritten).is_err());
        }
    }
}

#[test]
fn cold_cleanup_rejects_nonterminal_hot_legacy_and_incomplete_retired_cuts() {
    let mut flight = cold_prefix(false);
    retire(&mut flight, true);
    let marked = cleanup_marker(&flight, Lifecycle::ColdTerminalCleanupMarked);
    let rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();

    for case in 0..8 {
        let mut before = flight.rows.clone();
        match case {
            0 => {
                let mut attempt = rows.attempt.clone();
                attempt.state = ProviderAttemptStateV1::Reserved;
                before.insert(rows.keys[1].clone(), format::encode_attempt(&attempt));
            }
            1 => {
                let mut attempt = rows.attempt.clone();
                attempt.state = ProviderAttemptStateV1::Completed;
                before.insert(rows.keys[1].clone(), format::encode_attempt(&attempt));
            }
            2 => {
                let mut acquisition = rows.acquisition.clone();
                acquisition.lease_id = Some([201; 16]);
                before.insert(
                    rows.keys[2].clone(),
                    format::encode_acquisition(&acquisition),
                );
            }
            3 => {
                before.remove(&rows.keys[4]);
            }
            4 => {
                before.remove(&format::catalog_key(
                    flight.record.original.provider_id,
                    rows.acquisition.catalog_generation,
                ));
            }
            5 => {
                before.insert(
                    rows.keys[5].clone(),
                    format::encode_native_completion_v2(&flight.record.original),
                );
            }
            6 => {
                let mut acquisition = rows.acquisition.clone();
                acquisition.backend_lineage_digest = d(201);
                before.insert(
                    rows.keys[2].clone(),
                    format::encode_acquisition(&acquisition),
                );
            }
            _ => {
                before.insert(b"extra-owner".to_vec(), vec![0; 64]);
            }
        }
        assert!(
            propose_lifecycle(
                &before,
                &marked.rows,
                &flight.record,
                Lifecycle::ColdTerminalCleanupMarked,
            )
            .is_err(),
            "cold cleanup before case {case}"
        );
    }
    for other in [cold_prefix(false), completed_terminal()] {
        let record = SourceNativeHeldCompletionRecordV1::new(
            other
                .record
                .original
                .advance(Outer::CleanupRequired)
                .unwrap(),
            other.record.suffix.clone(),
        )
        .unwrap();
        assert!(
            propose_lifecycle(
                &other.rows,
                &other.proposed_rows(&record),
                &other.record,
                Lifecycle::ColdTerminalCleanupMarked,
            )
            .is_err()
        );
    }
}

#[test]
fn cold_cleanup_rejects_changed_revision_original_archive_and_extra_owner() {
    let mut flight = cold_prefix(true);
    retire(&mut flight, false);
    let marked = cleanup_marker(&flight, Lifecycle::ColdTerminalCleanupMarked);
    let key = graph::companion_keys(&flight.record).unwrap()[5].clone();

    for case in 0..7 {
        let mut original = marked.record.original.clone();
        let mut suffix = marked.record.suffix.clone();
        let mut after = marked.rows.clone();
        match case {
            0 => original.revision -= 1,
            1 => original.revision += 1,
            2 => original.original_clock = None,
            3 => original.canonical_request = None,
            4 => original.accepted_reply = None,
            5 => {
                let mut controls = suffix.controls().to_vec();
                let last = controls.pop().unwrap();
                controls.push(last.prepared().clone().with_signature([0xCE; 64]));
                suffix = NativeHeldCompletionSuffixV1::new(
                    Owner::Provider,
                    suffix.phase(),
                    suffix.flight(),
                    None,
                    controls,
                )
                .unwrap();
            }
            _ => {
                let mut rows = graph::Companions::read(&after, &marked.record).unwrap();
                rows.authority.revision += 1;
                after.insert(
                    rows.keys[0].clone(),
                    format::encode_authority(&rows.authority),
                );
            }
        }
        let mut body = original_body(&original, b"AOSNCR05");
        body.extend_from_slice(&suffix.to_canonical_bytes().unwrap());
        after.insert(key.clone(), independent_envelope(&original, 8, &body));
        assert!(
            propose_lifecycle(
                &flight.rows,
                &after,
                &flight.record,
                Lifecycle::ColdTerminalCleanupMarked,
            )
            .is_err(),
            "cold cleanup after case {case}"
        );
    }
    let mut invalid_revision = marked.record.original.clone();
    invalid_revision.revision = 1;
    let mut body = original_body(&invalid_revision, b"AOSNCR05");
    body.extend_from_slice(&marked.record.suffix.to_canonical_bytes().unwrap());
    let mut invalid = marked.rows;
    invalid.insert(key, independent_envelope(&invalid_revision, 8, &body));
    assert!(graph::validate(&invalid).is_err());

    let mut original = flight.record.original.clone();
    original.revision = u64::MAX;
    let before_record =
        SourceNativeHeldCompletionRecordV1::new(original.clone(), flight.record.suffix.clone())
            .unwrap();
    let before = flight.proposed_rows(&before_record);
    original.state = Outer::CleanupRequired;
    let after_record =
        SourceNativeHeldCompletionRecordV1::new(original, flight.record.suffix.clone()).unwrap();
    let after = flight.proposed_rows(&after_record);
    graph::validate(&before).unwrap();
    graph::validate(&after).unwrap();
    assert!(
        propose_lifecycle(
            &before,
            &after,
            &before_record,
            Lifecycle::ColdTerminalCleanupMarked,
        )
        .is_err()
    );
}

fn refresh_inventory(rows: &mut graph::Records, authority: &mut AuthorityHeadRecordV1) {
    let (digest, count) = crate::ledger::reducer::inventory_state_digest(
        authority.provider.authority_id(),
        authority.catalog_generation,
        authority.catalog_digest,
        rows.iter()
            .filter(|(_, bytes)| !graph::is_held(bytes))
            .map(|(k, v)| (k.as_slice(), v.as_slice())),
        crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
    )
    .unwrap();
    authority.inventory_state_digest = digest;
    authority.active_lease_count = count;
    rows.insert(
        format::authority_key(authority.provider.authority_id()),
        format::encode_authority(authority),
    );
}

fn release_admission(flight: &Flight) -> graph::Records {
    let rows = graph::Companions::read(&flight.rows, &flight.record).unwrap();
    let holder = &rows.holder;
    let acquisition = &rows.acquisition;
    let request = ReleaseSourceRequestV1::new(
        holder.session_binding,
        holder.next_request_sequence,
        [151; 16],
        acquisition.acquisition_id,
        holder.holder.authority_id(),
        holder.holder.authority_generation(),
        holder.holder.authority_digest(),
        acquisition.lease_id.unwrap(),
        acquisition.lease_digest.unwrap(),
        1000,
    )
    .unwrap();
    let signed = sign_request(
        SourceProviderMethod::Release,
        encode_release_request(&request),
        holder.signers[1].clone(),
        &SigningKey::from_bytes(&[51; 32]),
    )
    .unwrap();
    let mut attempt = rows.attempt.clone();
    attempt.revision = 1;
    attempt.state = ProviderAttemptStateV1::Reserved;
    attempt.method = SourceProviderMethod::Release;
    attempt.status = None;
    attempt.request_id = request.request_id();
    attempt.signed_request_digest = digest_signed_request(&signed);
    attempt.signed_request_digest_again = attempt.signed_request_digest;
    attempt.typed_request_digest = digest_release_request(&request);
    attempt.operation_intent_digest = source_provider_release_intent_digest_v1(&request);
    attempt.attempt_digest = source_provider_request_attempt_digest_v1(
        &holder.signers[1],
        SourceProviderMethod::Release,
        request.request_id(),
    );
    attempt.session_binding = holder.session_binding;
    attempt.request_sequence = holder.next_request_sequence;
    attempt.response_sequence = None;
    attempt.deadline_seconds = 1000;
    attempt.verified_at_seconds = 502;
    attempt.completed_at_seconds = None;
    attempt.current_valid_until_seconds = 1100;
    attempt.response_digest = None;
    attempt.descriptor_commitment = empty_descriptor_set_commitment_v1();
    attempt.result_digest = None;
    attempt.signed_request = signed.to_canonical_bytes();
    attempt.completed_response.clear();
    let generation = rows.authority.last_release_generation + 1;
    let effect = crate::identity::release_effect_id_v1(
        acquisition.acquisition_id,
        attempt.attempt_digest,
        generation,
    )
    .unwrap();
    let mut acquisition = acquisition.clone();
    acquisition.revision += 1;
    acquisition.state = ProviderAcquisitionStateV1::Releasing;
    acquisition.current_attempt_digest = attempt.attempt_digest;
    acquisition.release_effect_id = Some(effect);
    let bytes = format::encode_acquisition(&acquisition);
    let lineage = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.release-lineage.v1\0")
            .chain_update(acquisition.provider.authority_id())
            .chain_update(acquisition.holder.authority_id())
            .chain_update(attempt.session_binding.as_bytes())
            .chain_update(attempt.attempt_digest.as_bytes())
            .chain_update(acquisition.acquisition_id.as_bytes())
            .chain_update(effect)
            .chain_update(acquisition.lease_id.unwrap())
            .chain_update(acquisition.lease_digest.unwrap().as_bytes())
            .chain_update(acquisition.backend_id)
            .finalize()
            .into(),
    );
    let release = ReleaseRecordV1 {
        revision: 1,
        state: ProviderReleaseStateV1::Intent,
        provider: acquisition.provider.clone(),
        holder: acquisition.holder.clone(),
        acquisition_id: acquisition.acquisition_id,
        acquisition_sequence: acquisition.acquisition_sequence,
        lease_id: acquisition.lease_id.unwrap(),
        lease_digest: acquisition.lease_digest.unwrap(),
        effect_id: effect,
        release_generation: generation,
        effect_attempt_digest: attempt.attempt_digest,
        attempt_digest: attempt.attempt_digest,
        backend_id: acquisition.backend_id,
        backend_lineage_digest: lineage,
        backend_evidence: None,
        release_observation_digest: None,
        released_seconds: None,
        receipt_digest: None,
        signed_receipt: Vec::new(),
        acquisition_record_digest: format::record_digest(&bytes).unwrap(),
    };
    let mut after = flight.rows.clone();
    after.insert(rows.keys[2].clone(), bytes);
    after.insert(
        format::attempt_key(&AttemptKeyV1 {
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            root_record_key_id: attempt.root_record_signer.key_id(),
            method: SourceProviderMethod::Release as u8,
            request_id: attempt.request_id,
        }),
        format::encode_attempt(&attempt),
    );
    let release_key = format::release_key(&ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    });
    assert_eq!(release_key.len(), 95);
    after.insert(release_key, format::encode_release(&release));
    let mut holder = holder.clone();
    holder.revision += 1;
    holder.next_request_sequence += 1;
    holder.pending_attempt_digest = Some(attempt.attempt_digest);
    after.insert(rows.keys[3].clone(), format::encode_session(&holder));
    after.insert(
        format::session_history_key(
            holder.provider.authority_id(),
            holder.holder.authority_id(),
            holder.session_binding,
        ),
        format::encode_session_history(&holder),
    );
    let mut authority = rows.authority;
    authority.revision += 1;
    authority.inventory_generation += 1;
    authority.last_release_generation = generation;
    refresh_inventory(&mut after, &mut authority);
    if flight.record.original.state == Outer::Active {
        let next = SourceNativeHeldCompletionRecordV1::new(
            flight
                .record
                .original
                .advance(Outer::CleanupRequired)
                .unwrap(),
            flight.record.suffix.clone(),
        )
        .unwrap();
        after.insert(rows.keys[5].clone(), next.to_canonical_bytes().unwrap());
    }
    after
}

#[test]
fn both_release_predecessors_use_actual_owner_counts_and_envelope8_status_provenance() {
    let complete = completed_terminal();
    let artifact = complete.artifact();
    for cleanup in [false, true] {
        let flight = if cleanup {
            marker(&complete)
        } else {
            complete.clone()
        };
        let after = release_admission(&flight);
        let proposal = propose_lifecycle(
            &flight.rows,
            &after,
            &flight.record,
            Lifecycle::ReleaseAdmitted,
        )
        .unwrap();
        assert_eq!(proposal.mutations().len(), if cleanup { 6 } else { 7 });
        let key = graph::companion_keys(&flight.record).unwrap()[5].clone();
        let native =
            SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &after[&key]).unwrap();
        assert_eq!(native.suffix, flight.record.suffix);
        if cleanup {
            assert_eq!(after[&key], flight.rows[&key]);
        }
        let expected = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.source-provider.native-release-status-carrier.v1\0")
                .chain_update(format::record_digest(&after[&key]).unwrap().as_bytes())
                .finalize()
                .into(),
        );
        assert_eq!(proposal.status_binding().unwrap().owner_digest, expected);
        assert_eq!(
            native_held_release_status_binding_v1(
                after.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                native.original.acquisition_id,
            )
            .unwrap(),
            *proposal.status_binding().unwrap()
        );
        assert_eq!(evidence::artifact(&native).unwrap(), artifact);
        assert!(proposal.original_custody_required().is_some());
        assert!(
            crate::validate_prospective_records(
                after.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
            )
            .is_err()
        );
        assert!(
            native_completion::release_fence::validate_native_release_admission_v1(
                &flight.rows,
                &after
            )
            .is_err()
        );
    }
}

fn release_completion(
    before: &graph::Records,
    record: &SourceNativeHeldCompletionRecordV1,
    status: SourceProviderStatus,
    recovery: bool,
) -> graph::Records {
    let rows = graph::Companions::read(before, record).unwrap();
    let release_key = format::release_key(&ReleaseKeyV1 {
        provider_id: record.original.provider_id,
        holder_id: record.original.holder_id,
        acquisition_id: record.original.acquisition_id,
    });
    let DecodedRecordV1::Release(mut release) =
        format::decode_record(&release_key, &before[&release_key]).unwrap()
    else {
        panic!("Release");
    };
    let (attempt_key, mut attempt) = before
        .iter()
        .find_map(
            |(key, bytes)| match format::decode_record(key, bytes).ok()? {
                DecodedRecordV1::Attempt(attempt)
                    if attempt.attempt_digest == release.attempt_digest =>
                {
                    Some((key.clone(), attempt))
                }
                _ => None,
            },
        )
        .unwrap();
    let terminal = status == SourceProviderStatus::Complete || recovery;
    let receipt = terminal.then(|| {
        sign_release_receipt(
            SourceReleaseReceiptV1::new(
                attempt.request_id,
                attempt.typed_request_digest,
                release.lease_id,
                release.lease_digest,
                release.provider.clone(),
                attempt.provider_process_instance,
                release.release_generation,
                504,
            )
            .unwrap(),
            rows.holder.signers[3].clone(),
            &SigningKey::from_bytes(&[54; 32]),
        )
        .unwrap()
    });
    let mut after = before.clone();
    if !recovery {
        let result = receipt
            .as_ref()
            .map(SignedSourceReleaseReceiptV1::to_canonical_bytes);
        let status_subject = SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Release,
            attempt.request_id,
            attempt.signed_request_digest,
            status,
            attempt.provider_process_instance,
            attempt.session_binding,
            rows.holder.next_response_sequence,
            response_result_digest_v1(SourceProviderMethod::Release, status, result.as_deref()),
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap();
        let response = encode_release_response(
            &ReleaseSourceResponseV1::new(
                sign_response_status(
                    status_subject,
                    rows.holder.signers[3].clone(),
                    &SigningKey::from_bytes(&[54; 32]),
                )
                .unwrap(),
                result,
            )
            .unwrap(),
        );
        attempt.revision += 1;
        attempt.state = ProviderAttemptStateV1::Completed;
        attempt.status = Some(status);
        attempt.response_sequence = Some(rows.holder.next_response_sequence);
        attempt.completed_at_seconds = Some(504);
        attempt.response_digest = Some(provider_response_artifact_digest_v1(
            SourceProviderMethod::Release,
            &response,
        ));
        attempt.result_digest = Some(
            decode_release_response(&response)
                .unwrap()
                .signed_status()
                .subject()
                .result_digest(),
        );
        attempt.completed_response = response;
        after.insert(attempt_key, format::encode_attempt(&attempt));
        let mut holder = rows.holder.clone();
        holder.revision += 1;
        holder.pending_attempt_digest = None;
        holder.last_completed_attempt_digest = Some(attempt.attempt_digest);
        holder.next_response_sequence += 1;
        after.insert(rows.keys[3].clone(), format::encode_session(&holder));
        after.insert(
            format::session_history_key(
                holder.provider.authority_id(),
                holder.holder.authority_id(),
                holder.session_binding,
            ),
            format::encode_session_history(&holder),
        );
    }
    if terminal {
        let acquired = rows.acquisition.backend_evidence.as_ref().unwrap();
        let observed = crate::BackendEvidenceV1::new_released(
            acquired.class(),
            acquired.backend_authority_id(),
            acquired.backend_generation(),
            acquired.backend_digest(),
            acquired.observation_generation() + 1,
            d(152),
            acquired.observation_generation(),
            acquired.observation_digest(),
            Vec::new(),
        )
        .unwrap();
        let receipt = receipt.unwrap();
        release.revision += 1;
        release.state = ProviderReleaseStateV1::Tombstone;
        release.backend_evidence = Some(observed);
        release.release_observation_digest = Some(d(152));
        release.released_seconds = Some(504);
        release.receipt_digest = Some(digest_signed_release_receipt(&receipt));
        release.signed_receipt = receipt.to_canonical_bytes();
        let mut acquisition = rows.acquisition;
        acquisition.revision += 1;
        acquisition.state = ProviderAcquisitionStateV1::Released;
        let bytes = format::encode_acquisition(&acquisition);
        release.acquisition_record_digest = format::record_digest(&bytes).unwrap();
        after.insert(rows.keys[2].clone(), bytes);
        after.insert(release_key, format::encode_release(&release));
        let mut authority = rows.authority;
        authority.revision += 1;
        authority.inventory_generation += 1;
        refresh_inventory(&mut after, &mut authority);
    }
    after
}

#[test]
fn release_status_genuine_terminal_recovery_and_compaction_preserve_original_complete_a() {
    let complete = completed_terminal();
    let flight = marker(&complete);
    let admitted = release_admission(&flight);
    for status in [
        SourceProviderStatus::Pending,
        SourceProviderStatus::Unavailable,
        SourceProviderStatus::Complete,
    ] {
        let status_rows = release_completion(&admitted, &flight.record, status, false);
        let step = if status == SourceProviderStatus::Complete {
            Lifecycle::ReleaseCompleted
        } else {
            Lifecycle::ReleaseStatusCompleted
        };
        let proposal = propose_lifecycle(&admitted, &status_rows, &flight.record, step).unwrap();
        assert_eq!(
            proposal.mutations().len(),
            if status == SourceProviderStatus::Complete {
                6
            } else {
                3
            }
        );
        let released = if status == SourceProviderStatus::Complete {
            status_rows
        } else {
            let after = release_completion(&status_rows, &flight.record, status, true);
            assert_eq!(
                propose_lifecycle(
                    &status_rows,
                    &after,
                    &flight.record,
                    Lifecycle::ReleaseCompleted
                )
                .unwrap()
                .mutations()
                .len(),
                3
            );
            after
        };
        let rows = graph::Companions::read(&released, &flight.record).unwrap();
        assert_eq!(
            completion::original_native_complete_artifact(
                &flight.record.original,
                &rows.attempt,
                &rows.acquisition
            )
            .unwrap(),
            complete.artifact()
        );
        let mut compacted = released.clone();
        let mut acquisition = rows.acquisition;
        acquisition.revision += 1;
        acquisition.lease_history.clear();
        acquisition.signed_lease.clear();
        acquisition.reopen_identity = None;
        let bytes = format::encode_acquisition(&acquisition);
        let release_key = format::release_key(&ReleaseKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        });
        let DecodedRecordV1::Release(mut release) =
            format::decode_record(&release_key, &released[&release_key]).unwrap()
        else {
            panic!("Tombstone");
        };
        release.revision += 1;
        release.acquisition_record_digest = format::record_digest(&bytes).unwrap();
        compacted.insert(rows.keys[2].clone(), bytes);
        compacted.insert(release_key.clone(), format::encode_release(&release));
        propose_lifecycle(
            &released,
            &compacted,
            &flight.record,
            Lifecycle::ReleasedArtifactsCompacted,
        )
        .unwrap();
        graph::validate(&compacted).unwrap();
        let mut corrupted = compacted.clone();
        let mut retained = graph::Companions::read(&corrupted, &flight.record).unwrap();
        retained.acquisition.resource_commitment = d(201);
        let bytes = format::encode_acquisition(&retained.acquisition);
        let DecodedRecordV1::Release(mut release) =
            format::decode_record(&release_key, &corrupted[&release_key]).unwrap()
        else {
            panic!("Tombstone");
        };
        release.acquisition_record_digest = format::record_digest(&bytes).unwrap();
        corrupted.insert(retained.keys[2].clone(), bytes);
        corrupted.insert(release_key, format::encode_release(&release));
        refresh_inventory(&mut corrupted, &mut retained.authority);
        assert!(graph::validate(&corrupted).is_err());
        let mut erased = compacted;
        erased.remove(&rows.keys[1]);
        assert!(graph::validate(&erased).is_err());
    }
}

// Independent full-response construction binds the actual carrier and status
// reservation DATA, not a legacy projection or a protected signing producer.
fn fenced_status_rows(
    before: &graph::Records,
    record: &SourceNativeHeldCompletionRecordV1,
    status: SourceProviderStatus,
    projected_cut: bool,
) -> graph::Records {
    let mut after = release_completion(before, record, status, false);
    let proposal =
        propose_lifecycle(before, &after, record, Lifecycle::ReleaseStatusCompleted).unwrap();
    let binding = proposal.status_binding().unwrap();
    let rows = graph::Companions::read(&after, record).unwrap();
    let release_key = format::release_key(&ReleaseKeyV1 {
        provider_id: record.original.provider_id,
        holder_id: record.original.holder_id,
        acquisition_id: record.original.acquisition_id,
    });
    let DecodedRecordV1::Release(release) =
        format::decode_record(&release_key, &after[&release_key]).unwrap()
    else {
        panic!("Release");
    };
    let (attempt_key, mut attempt) = after
        .iter()
        .find_map(
            |(key, bytes)| match format::decode_record(key, bytes).ok()? {
                DecodedRecordV1::Attempt(attempt)
                    if attempt.attempt_digest == release.attempt_digest =>
                {
                    Some((key.clone(), attempt))
                }
                _ => None,
            },
        )
        .unwrap();
    let carrier = if projected_cut {
        format::encode_native_completion_v2(&record.original)
    } else {
        after[&rows.keys[5]].clone()
    };
    let sequence = 150_u64;
    let admission_transaction_id = [151; 16];
    let reservation_id = [152; 32];
    let cut_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.native-export-fence-cut.v1\0")
            .chain_update(sequence.to_be_bytes())
            .chain_update(admission_transaction_id)
            .chain_update(reservation_id)
            .chain_update((carrier.len() as u32).to_be_bytes())
            .chain_update(&carrier)
            .chain_update(binding.owner_id)
            .chain_update(binding.owner_digest.as_bytes())
            .chain_update(binding.operation_id)
            .chain_update(binding.artifact_digest.as_bytes())
            .chain_update(binding.checkpoint_digest.as_bytes())
            .chain_update(binding.chain_head_digest.as_bytes())
            .finalize()
            .into(),
    );
    let fence = SignedSourceProviderNativeExportFenceV1::sign(
        SourceProviderNativeExportFenceV1::new(
            NativeExportFenceReleaseV1 {
                provider: attempt.provider.clone(),
                holder: attempt.holder.clone(),
                request_id: attempt.request_id,
                signed_request_digest: attempt.signed_request_digest,
                typed_request_digest: attempt.typed_request_digest,
                attempt_digest: attempt.attempt_digest,
                session_binding: attempt.session_binding,
                request_sequence: attempt.request_sequence,
                response_sequence: attempt.response_sequence.unwrap(),
                provider_process_instance: attempt.provider_process_instance,
            },
            NativeExportFenceAcquireV1 {
                acquisition_id: rows.acquisition.acquisition_id,
                acquisition_sequence: rows.acquisition.acquisition_sequence,
                root_request_digest: record.original.root_request_digest,
                attempt_digest: record.original.attempt_digest,
                session_binding: record.original.session_binding,
                backend_id: rows.acquisition.backend_id,
                lease_id: release.lease_id,
                lease_digest: release.lease_digest,
            },
            record.original.native_request_digest,
            record.original.acceptance_digest,
            record
                .original
                .accepted_reply
                .as_ref()
                .unwrap()
                .acceptance()
                .acceptance()
                .clone(),
            NativeExportFenceCutV1 {
                sequence,
                admission_transaction_id,
                reservation_id,
                fence_digest: cut_digest,
            },
        )
        .unwrap(),
        rows.holder.signers[3].clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap();
    let signed_status = sign_response_status(
        SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Release,
            attempt.request_id,
            attempt.signed_request_digest,
            status,
            attempt.provider_process_instance,
            attempt.session_binding,
            attempt.response_sequence.unwrap(),
            response_result_digest_v1(
                SourceProviderMethod::Release,
                status,
                Some(&fence.to_canonical_bytes()),
            ),
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap(),
        rows.holder.signers[3].clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap();
    attempt.result_digest = Some(signed_status.subject().result_digest());
    attempt.completed_response = ReleaseSourceResponseV2::new(signed_status, fence)
        .unwrap()
        .to_canonical_bytes();
    attempt.response_digest = Some(provider_response_artifact_digest_v1(
        SourceProviderMethod::Release,
        &attempt.completed_response,
    ));
    after.insert(attempt_key, format::encode_attempt(&attempt));
    after
}

#[test]
fn actual_held_status_fence_survives_genuine_release_and_refuses_projected_cut() {
    let flight = marker(&completed_terminal());
    let admitted = release_admission(&flight);
    for status in [
        SourceProviderStatus::Pending,
        SourceProviderStatus::Unavailable,
    ] {
        let status_rows = fenced_status_rows(&admitted, &flight.record, status, false);
        let proposal = propose_lifecycle(
            &admitted,
            &status_rows,
            &flight.record,
            Lifecycle::ReleaseStatusCompleted,
        )
        .unwrap();
        assert_eq!(proposal.mutations().len(), 3);
        assert!(proposal.status_binding().is_some());
        let released = release_completion(&status_rows, &flight.record, status, true);
        propose_lifecycle(
            &status_rows,
            &released,
            &flight.record,
            Lifecycle::ReleaseCompleted,
        )
        .unwrap();
        graph::validate(&released).unwrap();

        let projected = fenced_status_rows(&admitted, &flight.record, status, true);
        assert!(
            propose_lifecycle(
                &admitted,
                &projected,
                &flight.record,
                Lifecycle::ReleaseStatusCompleted,
            )
            .is_err()
        );
    }
}

#[test]
fn retained_status_uses_release_history_independently_of_acquire_and_current_sessions() {
    for release_successor in [false, true] {
        let mut complete = completed_terminal();
        if release_successor {
            let mut fresh = add_fresh_acquire(&complete, true);
            fresh.first_query(false);
            fresh.settle_cold();
            retire(&mut fresh, true);
            complete.rows = fresh.rows;
        }
        let flight = marker(&complete);
        let admitted = release_admission(&flight);
        let binding = *propose_lifecycle(
            &flight.rows,
            &admitted,
            &flight.record,
            Lifecycle::ReleaseAdmitted,
        )
        .unwrap()
        .status_binding()
        .unwrap();
        assert_eq!(
            binding.chain_head_digest == flight.record.original.session_binding,
            !release_successor
        );

        for status in [
            SourceProviderStatus::Pending,
            SourceProviderStatus::Unavailable,
        ] {
            let status_rows = fenced_status_rows(&admitted, &flight.record, status, false);
            let released = release_completion(&status_rows, &flight.record, status, true);
            propose_lifecycle(
                &status_rows,
                &released,
                &flight.record,
                Lifecycle::ReleaseCompleted,
            )
            .unwrap();
            let released = Flight {
                rows: released,
                record: flight.record.clone(),
            };

            for successor in [None, Some(71)] {
                let current = add_acquire(&released, successor, [146; 16], [147; 32]);
                let rows = graph::Companions::read(&current.rows, &flight.record).unwrap();
                assert_eq!(
                    rows.holder.session_binding == binding.chain_head_digest,
                    successor.is_none()
                );
                assert_eq!(
                    native_held_release_status_binding_v1(
                        current
                            .rows
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice())),
                        flight.record.original.acquisition_id,
                    )
                    .unwrap(),
                    binding
                );
            }
        }
    }
}

#[test]
fn retained_status_rejects_missing_associations_wrong_history_and_nonstatus_outcomes() {
    let flight = marker(&completed_terminal());
    let admitted = release_admission(&flight);
    let status = SourceProviderStatus::Pending;
    let status_rows = fenced_status_rows(&admitted, &flight.record, status, false);
    let released = Flight {
        rows: release_completion(&status_rows, &flight.record, status, true),
        record: flight.record.clone(),
    };
    let current = add_fresh_acquire(&released, true);
    let binding = *propose_lifecycle(
        &flight.rows,
        &admitted,
        &flight.record,
        Lifecycle::ReleaseAdmitted,
    )
    .unwrap()
    .status_binding()
    .unwrap();
    let associate = |records: &graph::Records| {
        native_held_release_status_binding_v1(
            records.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            flight.record.original.acquisition_id,
        )
    };
    let rows = graph::Companions::read(&current.rows, &flight.record).unwrap();
    let history_key = format::session_history_key(
        flight.record.original.provider_id,
        flight.record.original.holder_id,
        binding.chain_head_digest,
    );
    let mut required = vec![
        history_key.clone(),
        format::release_key(&ReleaseKeyV1 {
            provider_id: flight.record.original.provider_id,
            holder_id: flight.record.original.holder_id,
            acquisition_id: flight.record.original.acquisition_id,
        }),
        rows.keys[1].clone(),
        rows.keys[5].clone(),
    ];
    required.extend(current.rows.iter().filter_map(|(key, bytes)| {
        matches!(format::decode_record(key, bytes), Ok(DecodedRecordV1::Attempt(attempt))
            if attempt.attempt_digest == binding.artifact_digest)
        .then(|| key.clone())
    }));
    for key in required {
        let mut missing = current.rows.clone();
        missing.remove(&key);
        assert!(associate(&missing).is_err());
    }

    let mut wrong_history = current.rows.clone();
    wrong_history.insert(history_key, format::encode_session_history(&rows.holder));
    assert!(associate(&wrong_history).is_err());
    let mut legacy = current.rows.clone();
    legacy.insert(
        rows.keys[5].clone(),
        format::encode_native_completion_v2(&flight.record.original),
    );
    assert!(associate(&legacy).is_err());
    let nonterminal = marker(&Flight::held_prepared());
    assert!(associate(&nonterminal.rows).is_err());
    assert!(
        associate(&release_completion(
            &admitted,
            &flight.record,
            SourceProviderStatus::Complete,
            false,
        ))
        .is_err()
    );
    assert!(associate(&flight.rows).is_err());
    assert!(
        native_held_release_status_binding_v1(
            current
                .rows
                .iter()
                .chain(current.rows.iter())
                .map(|(k, v)| (k.as_slice(), v.as_slice())),
            flight.record.original.acquisition_id,
        )
        .is_err()
    );
}

#[test]
fn release_admission_rejects_missing_complete_wrong_revision_extra_owner_and_authority_patch() {
    let flight = marker(&completed_terminal());
    let valid = release_admission(&flight);
    let keys = graph::companion_keys(&flight.record).unwrap();
    for case in 0..5 {
        let mut before = flight.rows.clone();
        let mut after = valid.clone();
        match case {
            0 => {
                let mut original = graph::Companions::read(&before, &flight.record)
                    .unwrap()
                    .attempt;
                original.completed_response.clear();
                before.insert(keys[1].clone(), format::encode_attempt(&original));
                after.insert(keys[1].clone(), format::encode_attempt(&original));
            }
            1 => {
                let mut original = flight.record.original.clone();
                original.revision += 1;
                after.insert(
                    keys[5].clone(),
                    SourceNativeHeldCompletionRecordV1::new(original, flight.record.suffix.clone())
                        .unwrap()
                        .to_canonical_bytes()
                        .unwrap(),
                );
            }
            2 => {
                let mut authority = graph::Companions::read(&after, &flight.record)
                    .unwrap()
                    .authority;
                authority.revision += 1;
                after.insert(keys[0].clone(), format::encode_authority(&authority));
            }
            3 => {
                let DecodedRecordV1::Session(mut session) =
                    format::decode_record(&keys[3], &after[&keys[3]]).unwrap()
                else {
                    panic!("Holder");
                };
                session.next_response_sequence += 1;
                after.insert(keys[3].clone(), format::encode_session(&session));
                after.insert(
                    format::session_history_key(
                        session.provider.authority_id(),
                        session.holder.authority_id(),
                        session.session_binding,
                    ),
                    format::encode_session_history(&session),
                );
            }
            _ => {
                after.insert(b"extra-owner".to_vec(), vec![0; 64]);
            }
        }
        assert!(
            propose_lifecycle(&before, &after, &flight.record, Lifecycle::ReleaseAdmitted).is_err(),
            "Release case {case}"
        );
    }
    let mut cold = cold_prefix(false);
    retire(&mut cold, true);
    assert!(
        propose_lifecycle(&cold.rows, &valid, &cold.record, Lifecycle::ReleaseAdmitted).is_err()
    );
}

#[test]
fn completed_archive_allows_current_successor_and_valid_faulted_graph_without_zeroing_a() {
    let complete = completed_terminal();
    let artifact = complete.artifact();
    for successor in [false, true] {
        let next = add_fresh_acquire(&complete, successor);
        let rows = graph::Companions::read(&next.rows, &complete.record).unwrap();
        assert_eq!(
            completion::original_native_complete_artifact(
                &complete.record.original,
                &rows.attempt,
                &rows.acquisition
            )
            .unwrap(),
            artifact
        );
    }
    let closed = marker(&complete);
    let admitted = release_admission(&closed);
    let binding = native_held_release_status_binding_v1(
        admitted.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        closed.record.original.acquisition_id,
    )
    .unwrap();
    let mut faulted = admitted;
    let mut rows = graph::Companions::read(&faulted, &closed.record).unwrap();
    rows.acquisition.revision += 1;
    rows.acquisition.state = ProviderAcquisitionStateV1::Faulted;
    let bytes = format::encode_acquisition(&rows.acquisition);
    faulted.insert(rows.keys[2].clone(), bytes.clone());
    let key = format::release_key(&ReleaseKeyV1 {
        provider_id: closed.record.original.provider_id,
        holder_id: closed.record.original.holder_id,
        acquisition_id: closed.record.original.acquisition_id,
    });
    let DecodedRecordV1::Release(mut release) =
        format::decode_record(&key, &faulted[&key]).unwrap()
    else {
        panic!("Release");
    };
    release.revision += 1;
    release.acquisition_record_digest = format::record_digest(&bytes).unwrap();
    faulted.insert(key, format::encode_release(&release));
    rows.authority.revision += 1;
    rows.authority.inventory_generation += 1;
    refresh_inventory(&mut faulted, &mut rows.authority);
    graph::validate(&faulted).unwrap();
    assert_eq!(
        native_held_release_status_binding_v1(
            faulted.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            closed.record.original.acquisition_id,
        )
        .unwrap(),
        binding
    );
    assert_eq!(
        completion::original_native_complete_artifact(
            &closed.record.original,
            &rows.attempt,
            &rows.acquisition
        )
        .unwrap(),
        artifact
    );
    // This valid historical observation is DATA, not a new fault/cleanup producer.
    assert!(
        propose_lifecycle(
            &closed.rows,
            &faulted,
            &closed.record,
            Lifecycle::ReleaseCompleted
        )
        .is_err()
    );
}

#[test]
fn closed_custody_marker_before_root_ack_keeps_complete_and_denies_hot_continuation() {
    let flight = Flight::held_prepared();
    let closed = marker(&flight);
    let challenge = challenge_bytes(&closed.record.original, true);
    let suffix = closed.record.suffix.clone();
    let original = closed.record.original.clone();
    let mut unsigned = original.clone();
    unsigned.revision += 1;
    let signed = suffix
        .prepared()
        .unwrap()
        .clone()
        .with_signature([0xA3; 64]);
    let mut controls = suffix.controls().to_vec();
    controls.push(signed);
    let next = SourceNativeHeldCompletionRecordV1::new(
        unsigned,
        NativeHeldCompletionSuffixV1::new(Owner::Provider, 6, suffix.flight(), None, controls)
            .unwrap(),
    )
    .unwrap();
    assert!(
        closed
            .check(SourceNativeHeldStepV1::HeldStored, &next, Some(&challenge))
            .is_err()
    );
    assert_eq!(
        completion::original_native_complete_artifact(
            &original,
            &graph::Companions::read(&closed.rows, &closed.record)
                .unwrap()
                .attempt,
            &graph::Companions::read(&closed.rows, &closed.record)
                .unwrap()
                .acquisition
        )
        .unwrap(),
        flight.artifact()
    );
}
