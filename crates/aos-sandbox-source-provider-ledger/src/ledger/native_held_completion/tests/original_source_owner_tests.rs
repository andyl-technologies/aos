//! UNRUN complete original Applying/Requested owner DATA and exact PUT vectors.
//!
//! Synthetic signatures, configuration and clock archives grant no protected
//! admission, live custody, floor accounting, signer, writer or dispatch route.

use super::*;
use crate::ledger::{
    model::{AttemptKeyV1, ProviderAuthorityStateV1},
    native_completion::{
        NativeAcquireClockAnchorV1, OriginalSourceOwnerPrefixV5 as Prefix,
        OriginalSourceProvenanceClaimsV5, OriginalSourceProvenanceV5,
        classify_original_source_owner_v5, propose_original_source_applying_v5,
        propose_original_source_requested_v5,
    },
};
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, digest_acquire_request, digest_signed_request,
};

type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

#[path = "original_source_continuation_tests.rs"]
mod continuation_tests;

mod source_capacity_tests;

struct Flight {
    graph: fixtures::Graph,
    before: Rows,
    applying: Rows,
    held: SourceNativeHeldCompletionRecordV1,
    provenance: OriginalSourceProvenanceV5,
}

fn views(rows: &Rows) -> impl Iterator<Item = (&[u8], &[u8])> {
    rows.iter()
        .map(|(key, bytes)| (key.as_slice(), bytes.as_slice()))
}

fn puts<'row>(
    rows: &'row Rows,
    keys: &'row [Vec<u8>],
) -> impl Iterator<Item = (&'row [u8], Option<&'row [u8]>)> {
    keys.iter()
        .map(|key| (key.as_slice(), Some(rows[key].as_slice())))
}

fn applying_rows(graph: &fixtures::Graph) -> Rows {
    let mut rows = graph.rows();
    rows.remove(&native_completion::native_completion_key_v2(graph.native.acquisition_id));
    rows
}

fn witness(family: Family, key: Vec<u8>, rows: &Rows) -> NativeHeldByteWitnessV1 {
    let digest = native_held_record_byte_digest_v1(family, &key, &rows[&key]).unwrap();
    NativeHeldByteWitnessV1::new(family, key, digest).unwrap()
}

fn provenance(graph: &fixtures::Graph, rows: &Rows) -> OriginalSourceProvenanceV5 {
    let attempt = &graph.attempts[0];
    let session = &graph.sessions[0];
    let acquisition = &graph.acquisition;
    let original = &graph.native;
    let keys = [
        format::attempt_key(&AttemptKeyV1 {
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            root_record_key_id: attempt.root_record_signer.key_id(),
            method: attempt.method as u8,
            request_id: attempt.request_id,
        }),
        format::acquisition_key(&crate::ledger::model::AcquisitionKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        }),
        format::session_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
        ),
        format::session_history_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
    ];
    let families = [
        Family::ProviderAttempt,
        Family::ProviderAcquisition,
        Family::ProviderHolder,
        Family::ProviderHistory,
    ];
    let records = std::array::from_fn(|index| witness(families[index], keys[index].clone(), rows));

    OriginalSourceProvenanceV5::new_untrusted(OriginalSourceProvenanceClaimsV5 {
        root_prepared: root_prepared(original),
        claims: original
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .claims()
            .clone(),
        initial: original.original_clock.unwrap().initial(),
        original_deadline: 600_000_000_000,
        narrowed_deadline: 60_000_000_000,
        journal_sequence: 1,
        configuration: d(102),
        records,
    })
    .unwrap()
}

fn refresh_dispatch(graph: &mut fixtures::Graph) {
    let acquisition = &mut graph.acquisition;
    let attempt = &mut graph.attempts[0];
    attempt.operation_intent_digest = acquisition.normalized_intent.digest();
    acquisition.backend_id = crate::identity::acquire_native_dispatch_id_v2(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
        attempt.attempt_digest,
    );
    acquisition.backend_lineage_digest =
        graph::original_lineage(acquisition, graph.sessions[0].session_binding);
}

impl Flight {
    fn applying() -> Self {
        let mut graph = fixtures::Graph::applying();
        let native = graph.native.canonical_request.as_ref().unwrap();
        let claims = native.request().claims().clone();
        let old_root =
            decode_acquire_request(native.request().signed_root_request().subject()).unwrap();
        let distinct_node_root = AcquireSourceRequestV1::new_v2(
            old_root.session_binding(),
            old_root.sequence(),
            old_root.request_id(),
            old_root.acquisition_sequence(),
            old_root.prospective_apply_template().to_vec(),
            old_root.prospective_apply_template_digest(),
            old_root.source_use(),
            [99; 16],
            old_root.boot_id(),
            old_root.holder_authority_id(),
            old_root.holder_generation(),
            old_root.holder_authority_digest(),
            old_root.binding().to_vec(),
            old_root.binding_digest(),
            old_root.deadline_seconds(),
            old_root.requested_lease_seconds(),
            old_root.revocation_digest(),
            old_root.recursive(),
            old_root.requested_maximum_submounts(),
            old_root.kernel_coupled(),
        )
        .unwrap();

        let catalog = &graph.catalog;
        let head = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0")
                .chain_update(format::encode_catalog(catalog))
                .finalize()
                .into(),
        );
        let publication =
            ObjectDigest::from_bytes(Sha256::digest(&catalog.canonical_publication).into());
        let binding = NativeAcquireCatalogBindingV3::new(
            catalog.resource_namespace_digest,
            catalog.catalog_generation,
            catalog.catalog_digest,
            catalog.catalog_floor_generation,
            catalog.catalog_floor_digest,
            head,
            publication,
        )
        .unwrap();
        let root = AcquireSourceRequestV1::new_native_v3(distinct_node_root, binding).unwrap();
        let signed_root = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root),
            native.request().signed_root_request().signer().clone(),
            &SigningKey::from_bytes(&[51; 32]),
        )
        .unwrap();
        let signed_native = SignedStorageNativeAcquireRequestV2::sign(
            StorageNativeAcquireRequestV2::new_native_v3(claims, signed_root.clone()).unwrap(),
            native.signer().clone(),
            &SigningKey::from_bytes(&[54; 32]),
        )
        .unwrap();

        let session = &mut graph.sessions[0];
        // Real reservation increments the initial idle revision, unlike the
        // older graph-only fixture which starts directly at a pending head.
        session.revision = 2;
        graph.acquisition.normalized_intent =
            crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
                &root,
                session.provider.clone(),
                session.holder.clone(),
                root.node_id(),
                session.boot_id,
                session.route_id,
                session.route_generation,
                session.route_digest,
                session.resource_namespace_digest,
                session.revocation_generation,
                session.revocation_digest,
            )
            .unwrap();
        let attempt = &mut graph.attempts[0];
        attempt.signed_request = signed_root.to_canonical_bytes();
        attempt.signed_request_digest = digest_signed_request(&signed_root);
        attempt.signed_request_digest_again = attempt.signed_request_digest;
        attempt.typed_request_digest = digest_acquire_request(&root);
        refresh_dispatch(&mut graph);

        let anchor = NativeAcquireClockAnchorV1::new_untrusted(
            graph.native.original_clock.unwrap().initial(),
            &signed_native,
        )
        .unwrap();
        let reservation =
            format::record_digest(&format::encode_acquisition(&graph.acquisition)).unwrap();
        graph.native = Original::requested(signed_native, reservation, anchor).unwrap();
        graph.refresh_inventory();
        let applying = applying_rows(&graph);
        let provenance = provenance(&graph, &applying);
        let held = initial(graph.native.clone());

        let keys = provenance
            .claims()
            .records
            .each_ref()
            .map(|record| record.key().to_vec());
        let mut before = applying.clone();
        before.remove(&keys[0]);
        before.remove(&keys[1]);
        let mut idle = graph.sessions[0].clone();
        idle.revision = 1;
        idle.pending_attempt_digest = None;
        idle.next_request_sequence = graph.attempts[0].request_sequence;
        idle.next_acquisition_sequence = graph.attempts[0].acquisition_sequence;
        before.insert(keys[2].clone(), format::encode_session(&idle));
        before.insert(keys[3].clone(), format::encode_session_history(&idle));

        Self {
            graph,
            before,
            applying,
            held,
            provenance,
        }
    }

    fn keys(&self) -> Vec<Vec<u8>> {
        self.provenance
            .claims()
            .records
            .iter()
            .map(|record| record.key().to_vec())
            .collect()
    }

    fn requested_rows(&self) -> Rows {
        let mut rows = self.applying.clone();
        rows.insert(
            native_completion::native_completion_key_v2(self.held.original().acquisition_id),
            self.held.to_canonical_bytes().unwrap(),
        );
        rows
    }
}

#[test]
fn complete_original_applying_and_requested_use_exact_existing_owner_reducer() {
    let flight = Flight::applying();
    let keys = flight.keys();
    let applying = classify_original_source_owner_v5(
        views(&flight.applying),
        &flight.provenance,
        d(102),
    )
    .unwrap();
    let admission = propose_original_source_applying_v5(
        views(&flight.before),
        puts(&flight.applying, &keys),
        &flight.provenance,
        d(102),
    )
    .unwrap();

    assert_eq!(applying.prefix, Prefix::Applying);
    let signed_root = SignedSourceProviderRequestV1::from_canonical_bytes(
        &flight.graph.attempts[0].signed_request,
    )
    .unwrap();
    let root = decode_acquire_request(signed_root.subject()).unwrap();

    assert_eq!(root.node_id(), [99; 16]);
    assert_eq!(flight.graph.sessions[0].root_process_instance, [5; 16]);
    assert_ne!(root.node_id(), flight.graph.sessions[0].root_process_instance);
    assert_eq!(applying.native_request_digest, None);
    assert_eq!(applying.operation_id, flight.graph.acquisition.effect_id);
    assert_eq!(applying.backend_id, flight.graph.acquisition.backend_id);
    assert_eq!(admission.data(), &applying);
    assert_eq!(admission.mutations().len(), 4);
    for mutation in admission.mutations() {
        assert_eq!(
            mutation.before(),
            flight.before.get(mutation.key()).map(Vec::as_slice),
        );
        assert_eq!(mutation.after(), flight.applying[mutation.key()].as_slice());
    }

    let requested = flight.requested_rows();
    let key = native_completion::native_completion_key_v2(applying.acquisition_id);
    let proposal = propose_original_source_requested_v5(
        views(&flight.applying),
        [(key.as_slice(), Some(requested[&key].as_slice()))],
        &flight.provenance,
        d(102),
    )
    .unwrap();
    let existing = propose_native_held_transition_v1(
        views(&flight.applying),
        views(&requested),
        applying.acquisition_id,
        SourceNativeHeldStepV1::Requested,
        None,
    )
    .unwrap();

    assert_eq!(proposal.data().prefix, Prefix::Requested);
    assert_eq!(
        proposal.data().native_request_digest,
        Some(flight.held.original().native_request_digest),
    );
    assert_eq!(proposal.mutations(), existing.mutations());
    assert_eq!(proposal.mutations().len(), 1);
    assert_eq!(proposal.mutations()[0].before(), None);
}

#[test]
fn first_absent_session_is_generation_one_revision_two_and_cannot_replace_history() {
    let flight = Flight::applying();
    let keys = flight.keys();
    let mut absent = flight.before.clone();
    absent.remove(&keys[2]);
    absent.remove(&keys[3]);

    let proposed = propose_original_source_applying_v5(
        views(&absent),
        puts(&flight.applying, &keys),
        &flight.provenance,
        d(102),
    )
    .unwrap();

    assert_eq!(proposed.mutations().len(), 4);
    assert!(
        proposed
            .mutations()
            .iter()
            .all(|mutation| mutation.before().is_none())
    );

    let retained = fixtures::session(60);
    let history_key = format::session_history_key(
        retained.provider.authority_id(),
        retained.holder.authority_id(),
        retained.session_binding,
    );
    absent.insert(history_key, format::encode_session_history(&retained));

    assert!(
        propose_original_source_applying_v5(
            views(&absent),
            puts(&flight.applying, &keys),
            &flight.provenance,
            d(102),
        )
        .is_err()
    );
}

#[test]
fn explicit_owner_puts_do_not_hide_deletion_duplicates_noops_foreign_or_missing_keys() {
    let flight = Flight::applying();
    let keys = flight.keys();
    let valid: Vec<_> = puts(&flight.applying, &keys).collect();
    let check = |changes: Vec<(&[u8], Option<&[u8]>)>| {
        propose_original_source_applying_v5(
            views(&flight.before),
            changes,
            &flight.provenance,
            d(102),
        )
    };

    let mut changes = valid.clone();
    changes[0].1 = None;
    assert!(check(changes).is_err());

    let mut changes = valid.clone();
    changes.push(valid[0]);
    assert!(check(changes).is_err());

    let mut changes = valid.clone();
    changes[2].1 = Some(&flight.before[&keys[2]]);
    assert!(check(changes).is_err());

    let mut changes = valid.clone();
    changes.push((b"foreign-owner", Some(b"foreign-value")));
    assert!(check(changes).is_err());

    assert!(check(valid[..3].to_vec()).is_err());
    let oversized = vec![0; crate::limits::MAXIMUM_TRANSACTION_BYTES];
    assert!(matches!(
        check(vec![(keys[0].as_slice(), Some(oversized.as_slice()))]),
        Err(crate::LedgerFormatErrorV1::LimitExceeded(_))
    ));
}

#[test]
fn canonical_reserved_head_cannot_skip_revision_or_existing_acquisition_floor() {
    let flight = Flight::applying();
    let keys = flight.keys();
    let mut changed = flight.graph.clone();
    changed.sessions[0].revision += 1;
    let rows = applying_rows(&changed);
    let archive = provenance(&changed, &rows);

    // Classification is comparison DATA. Only the exact reducer join binds
    // this canonical after graph to the caller's particular before graph.
    classify_original_source_owner_v5(views(&rows), &archive, d(102)).unwrap();

    assert!(propose_original_source_applying_v5(
        views(&flight.before),
        puts(&rows, &keys),
        &archive,
        d(102),
    )
    .is_err());

    let mut ahead = flight.graph.sessions[0].clone();
    ahead.revision = 1;
    ahead.pending_attempt_digest = None;
    ahead.next_request_sequence = flight.graph.attempts[0].request_sequence;
    ahead.next_acquisition_sequence = flight.graph.attempts[0].acquisition_sequence + 1;
    let mut before = flight.before.clone();
    before.insert(keys[2].clone(), format::encode_session(&ahead));
    before.insert(keys[3].clone(), format::encode_session_history(&ahead));

    assert!(propose_original_source_applying_v5(
        views(&before),
        puts(&flight.applying, &keys),
        &flight.provenance,
        d(102),
    )
    .is_err());
}

#[test]
fn every_row_and_configuration_are_checked_before_original_selection() {
    let flight = Flight::applying();
    let mut unrelated = flight.applying.clone();
    unrelated.insert(b"foreign-malformed-owner".to_vec(), vec![0; 10]);

    assert!(
        classify_original_source_owner_v5(views(&unrelated), &flight.provenance, d(102)).is_err()
    );
    assert!(
        classify_original_source_owner_v5(views(&flight.applying), &flight.provenance, d(103))
            .is_err()
    );

    let mut closed = flight.graph.clone();
    closed.authority.state = ProviderAuthorityStateV1::AcquireClosed;
    let rows = applying_rows(&closed);

    assert!(classify_original_source_owner_v5(views(&rows), &flight.provenance, d(102)).is_err());
}

#[test]
fn retained_intent_route_and_revocation_coordinates_cannot_replace_actual_holder_projection() {
    for change_route in [true, false] {
        let mut flight = Flight::applying();
        let attempt = &flight.graph.attempts[0];
        let signed =
            SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request).unwrap();
        let root = decode_acquire_request(signed.subject()).unwrap();
        let session = &flight.graph.sessions[0];
        let session_binding = session.session_binding;
        let route_generation = session.route_generation + u64::from(change_route);
        let revocation_generation = session.revocation_generation + u64::from(!change_route);
        flight.graph.acquisition.normalized_intent =
            crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
                &root,
                session.provider.clone(),
                session.holder.clone(),
                root.node_id(),
                session.boot_id,
                session.route_id,
                route_generation,
                session.route_digest,
                session.resource_namespace_digest,
                revocation_generation,
                session.revocation_digest,
            )
            .unwrap();
        refresh_dispatch(&mut flight.graph);
        let rows = applying_rows(&flight.graph);
        let archive = provenance(&flight.graph, &rows);

        // Refresh all dependent DATA, so neither a stale witness nor a broken
        // dispatch/lineage explains the rejection of the actual Holder join.
        crate::validate_current_records(&rows).unwrap();
        graph::validate_dispatch(
            &flight.graph.acquisition,
            session_binding,
            flight.graph.attempts[0].attempt_digest,
        )
        .unwrap();
        archive
            .validate_original_attempt_claims(&flight.graph.attempts[0])
            .unwrap();

        assert!(matches!(
            classify_original_source_owner_v5(views(&rows), &archive, d(102)),
            Err(crate::LedgerFormatErrorV1::Corrupt(
                "original Source exact Applying/current projection",
            ))
        ));
    }
}

#[test]
fn requested_requires_held8_phase_zero_and_exact_original_archive() {
    let flight = Flight::applying();
    let key = native_completion::native_completion_key_v2(flight.held.original().acquisition_id);
    let mut legacy = flight.applying.clone();
    legacy.insert(
        key.clone(),
        format::encode_native_completion_v2(&flight.graph.native),
    );

    assert!(classify_original_source_owner_v5(views(&legacy), &flight.provenance, d(102)).is_err());

    let mut issued = flight.applying.clone();
    issued.insert(
        key.clone(),
        advance(&flight.held, 1).to_canonical_bytes().unwrap(),
    );

    assert!(classify_original_source_owner_v5(views(&issued), &flight.provenance, d(102)).is_err());

    let root = flight.held.suffix().controls()[0]
        .prepared()
        .clone()
        .with_signature([0xB1; 64]);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        0,
        root.scope().flight,
        None,
        vec![root],
    )
    .unwrap();
    let changed_root =
        SourceNativeHeldCompletionRecordV1::new(flight.graph.native.clone(), suffix).unwrap();
    let mut changed_rows = flight.applying.clone();
    changed_rows.insert(key.clone(), changed_root.to_canonical_bytes().unwrap());

    assert!(
        classify_original_source_owner_v5(views(&changed_rows), &flight.provenance, d(102))
            .is_err()
    );

    let mut changed_original = flight.graph.native.clone();
    let actual = changed_original.original_clock.unwrap().initial();
    let changed_sample = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([0x90; 16]).unwrap(),
        actual.host_boot_id(),
        actual.wall_seconds(),
        actual.boottime_nanoseconds(),
    )
    .unwrap();
    changed_original.original_clock = Some(
        NativeAcquireClockAnchorV1::new_untrusted(
            changed_sample,
            changed_original.canonical_request.as_ref().unwrap(),
        )
        .unwrap(),
    );
    let changed_clock =
        SourceNativeHeldCompletionRecordV1::new(changed_original, flight.held.suffix().clone())
            .unwrap();
    changed_rows.insert(key.clone(), changed_clock.to_canonical_bytes().unwrap());

    assert!(
        classify_original_source_owner_v5(views(&changed_rows), &flight.provenance, d(102))
            .is_err()
    );

    let mut changed = flight.provenance.claims().clone();
    changed.records[1] = NativeHeldByteWitnessV1::new(
        Family::ProviderAcquisition,
        changed.records[1].key().to_vec(),
        d(103),
    )
    .unwrap();
    let changed = OriginalSourceProvenanceV5::new_untrusted(changed).unwrap();

    assert!(
        classify_original_source_owner_v5(views(&flight.requested_rows()), &changed, d(102))
            .is_err()
    );

    let requested = flight.requested_rows();
    let duplicate = [
        (key.as_slice(), Some(requested[&key].as_slice())),
        (key.as_slice(), Some(requested[&key].as_slice())),
    ];

    assert!(
        propose_original_source_requested_v5(
            views(&flight.applying),
            duplicate,
            &flight.provenance,
            d(102),
        )
        .is_err()
    );
    assert!(
        propose_original_source_requested_v5(
            views(&requested),
            [(key.as_slice(), Some(requested[&key].as_slice()))],
            &flight.provenance,
            d(102),
        )
        .is_err()
    );
}

#[test]
fn catalog_publication_data_must_match_all_retained_original_v3_fields() {
    let flight = Flight::applying();
    let mut changed = flight.graph.clone();
    let catalog = &mut changed.catalog;
    let last = catalog.canonical_publication.len() - 1;
    catalog.canonical_publication[last] ^= 1;
    catalog.publication_receipt_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.catalog-publication-receipt.v1\0")
            .chain_update(&catalog.canonical_publication)
            .finalize()
            .into(),
    );
    let rows = applying_rows(&changed);

    // Canonical publication DATA is not signature authentication. Its current
    // graph remains structural, but original Root's exact seven fields differ.
    crate::validate_current_records(&rows).unwrap();

    assert!(matches!(
        classify_original_source_owner_v5(views(&rows), &flight.provenance, d(102)),
        Err(crate::LedgerFormatErrorV1::Corrupt(
            "held original seven catalog claims",
        ))
    ));
}
