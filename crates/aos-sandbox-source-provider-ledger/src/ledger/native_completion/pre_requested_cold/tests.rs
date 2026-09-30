//! UNRUN cold archive, exact owner and immutable-history DATA vectors.
//!
//! This cfg(test)-only module is hosted under the held graph so its unchanged
//! private canonical fixtures can be reused. No protected token, live clock,
//! writer, Journal, challenge owner, current ACK or production route is created.

use super::*;
use crate::ledger::{
    format,
    model::*,
    native_completion::{
        self, NativeAcquireClockAnchorV1, NativeAcquireCompletionRecordV2 as Original,
        NativeAcquireCompletionStateV2 as Outer, OriginalSourceProvenanceClaimsV5,
        OriginalSourceProvenanceV5, derive_original_source_pre_requested_retirement_v1,
        pre_requested_cold::{self as cold, *},
    },
    native_held_completion::{SourceNativeHeldCompletionRecordV1, graph},
};
use aos_sandbox_source_provider_protocol::{
    *,
    native_held_completion::{
        NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner,
        NativeHeldScopeV1, NativeHeldSectionTagV1 as Tag,
        frame::{
            NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
            SignedNativeHeldControlV1,
        },
        native_held_flight_digest_v1,
        suffix::NativeHeldCompletionSuffixV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
            NativeHeldRecordFamilyV1 as Family, ROOT_NATIVE_WITNESS_FAMILIES_V1,
            RootNativeHeldWitnessV1, native_held_record_byte_digest_v1,
        },
    },
    recovery_currentness::RecoveryCurrentnessQueryV1,
    recovery_pre_requested::{
        NoEscapeRecordReferenceV1, RootNoEscapeAckFactsV1, SignedRootNoEscapeAckV1,
    },
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[path = "../../native_held_completion/tests/fixtures.rs"]
mod fixtures;

type Rows = BTreeMap<Vec<u8>, Vec<u8>>;
type Archive = SourcePreRequestedColdArchiveV1;
type Phase = SourcePreRequestedColdPhaseV1;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn views(rows: &Rows) -> impl Iterator<Item = (&[u8], &[u8])> {
    rows.iter().map(|(key, bytes)| (key.as_slice(), bytes.as_slice()))
}

fn puts<'row>(
    rows: &'row Rows,
    keys: &'row [Vec<u8>],
) -> impl Iterator<Item = (&'row [u8], Option<&'row [u8]>)> {
    keys.iter().map(|key| (key.as_slice(), Some(rows[key].as_slice())))
}

fn witness(family: Family, key: Vec<u8>, rows: &Rows) -> NativeHeldByteWitnessV1 {
    let digest = native_held_record_byte_digest_v1(family, &key, &rows[&key]).unwrap();
    NativeHeldByteWitnessV1::new(family, key, digest).unwrap()
}

fn root_prepared(original: &Original) -> SignedNativeHeldControlV1 {
    let records = ROOT_NATIVE_WITNESS_FAMILIES_V1.map(|family| {
        let prefix: &[u8] = match family {
            Family::RootSession => b"aos.mount.source-provider-session.v2\0",
            Family::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
            Family::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
            Family::RootHead => b"aos.mount.source-provider-head.v2\0",
            _ => unreachable!("fixed Root families"),
        };
        let mut key = prefix.to_vec();
        key.resize(family.key_bytes(), 91);
        NativeHeldByteWitnessV1::new(family, key, d(92)).unwrap()
    });
    let generation = NativeHeldGenerationClaimV1 { generation: 1, digest: d(93) };
    let witness = NativeHeldOwnerWitnessV1::Root(RootNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        journal_sequence: 1,
        planning_sequence: 1,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: d(94),
        records,
    }).to_canonical_bytes().unwrap();
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(original.root_request_digest, d(95), original.session_binding),
        original_source_session: original.session_binding,
        mount_attempt: d(95),
        provider_attempt: d(0),
        provider_acquisition: original.acquisition_id,
        original_root_request: original.root_request_digest,
        original_native_request: d(0),
    };
    let signer = original.canonical_request.as_ref().unwrap()
        .request().signed_root_request().signer().clone();

    PreparedNativeHeldControlV1::new(
        Kind::RootPrepared, scope, d(0),
        vec![NativeHeldSectionV1::new(Tag::Witness, witness).unwrap()],
        NativeHeldSignerV1::SourceProvider(signer),
    ).unwrap().with_signature([0xA1; 64])
}

struct Flight {
    graph: fixtures::Graph,
    before: Rows,
    closed: Rows,
    archive: Archive,
    provenance: OriginalSourceProvenanceV5,
    owner_keys: Vec<Vec<u8>>,
    native_key: Vec<u8>,
}

impl Flight {
    fn new() -> Self {
        let mut graph = fixtures::Graph::applying();
        let native = graph.native.canonical_request.as_ref().unwrap();
        let old_root = decode_acquire_request(native.request().signed_root_request().subject()).unwrap();
        let catalog = &graph.catalog;
        let head = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0")
                .chain_update(format::encode_catalog(catalog)).finalize().into(),
        );
        let publication = ObjectDigest::from_bytes(Sha256::digest(&catalog.canonical_publication).into());
        let binding = NativeAcquireCatalogBindingV3::new(
            catalog.resource_namespace_digest, catalog.catalog_generation, catalog.catalog_digest,
            catalog.catalog_floor_generation, catalog.catalog_floor_digest, head, publication,
        ).unwrap();
        let root = AcquireSourceRequestV1::new_native_v3(old_root, binding).unwrap();
        let signed_root = sign_request(
            SourceProviderMethod::Acquire, encode_acquire_request(&root),
            native.request().signed_root_request().signer().clone(),
            &SigningKey::from_bytes(&[51; 32]),
        ).unwrap();
        let signed_native = SignedStorageNativeAcquireRequestV2::sign(
            StorageNativeAcquireRequestV2::new_native_v3(
                native.request().claims().clone(), signed_root.clone(),
            ).unwrap(),
            native.signer().clone(), &SigningKey::from_bytes(&[54; 32]),
        ).unwrap();
        let session = &mut graph.sessions[0];
        session.revision = 2;
        graph.acquisition.normalized_intent = crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
            &root, session.provider.clone(), session.holder.clone(), root.node_id(), session.boot_id,
            session.route_id, session.route_generation, session.route_digest,
            session.resource_namespace_digest, session.revocation_generation, session.revocation_digest,
        ).unwrap();
        let attempt = &mut graph.attempts[0];
        attempt.signed_request = signed_root.to_canonical_bytes();
        attempt.signed_request_digest = digest_signed_request(&signed_root);
        attempt.signed_request_digest_again = attempt.signed_request_digest;
        attempt.typed_request_digest = digest_acquire_request(&root);
        attempt.operation_intent_digest = graph.acquisition.normalized_intent.digest();
        graph.acquisition.backend_id = crate::identity::acquire_native_dispatch_id_v2(
            graph.acquisition.normalized_intent.digest(), graph.acquisition.catalog_generation,
            graph.acquisition.catalog_digest, attempt.attempt_digest,
        );
        graph.acquisition.backend_lineage_digest = graph::original_lineage(
            &graph.acquisition, session.session_binding,
        );
        let anchor = NativeAcquireClockAnchorV1::new_untrusted(
            graph.native.original_clock.unwrap().initial(), &signed_native,
        ).unwrap();
        let reservation = format::record_digest(&format::encode_acquisition(&graph.acquisition)).unwrap();
        graph.native = Original::requested(signed_native, reservation, anchor).unwrap();
        graph.refresh_inventory();
        let native_key = native_completion::native_completion_key_v2(graph.native.acquisition_id);
        let mut before = graph.rows();
        before.remove(&native_key);

        let attempt = &graph.attempts[0];
        let session = &graph.sessions[0];
        let families = [
            Family::ProviderAttempt,
            Family::ProviderAcquisition,
            Family::ProviderHolder,
            Family::ProviderHistory,
        ];
        let owner_keys = vec![
            format::attempt_key(&AttemptKeyV1 {
                provider_id: attempt.provider.authority_id(), holder_id: attempt.holder.authority_id(),
                root_record_key_id: attempt.root_record_signer.key_id(),
                method: attempt.method as u8, request_id: attempt.request_id,
            }),
            format::acquisition_key(&AcquisitionKeyV1 {
                provider_id: session.provider.authority_id(), holder_id: session.holder.authority_id(),
                acquisition_id: graph.acquisition.acquisition_id,
            }),
            format::session_key(session.provider.authority_id(), session.holder.authority_id()),
            format::session_history_key(
                session.provider.authority_id(), session.holder.authority_id(), session.session_binding,
            ),
        ];
        let records = std::array::from_fn(|index| witness(families[index], owner_keys[index].clone(), &before));
        let provenance = OriginalSourceProvenanceV5::new_untrusted(OriginalSourceProvenanceClaimsV5 {
            root_prepared: root_prepared(&graph.native),
            claims: graph.native.canonical_request.as_ref().unwrap().request().claims().clone(),
            initial: graph.native.original_clock.unwrap().initial(),
            original_deadline: 600_000_000_000,
            narrowed_deadline: 60_000_000_000,
            journal_sequence: 1,
            configuration: d(102),
            records,
        }).unwrap();
        let retirement = derive_original_source_pre_requested_retirement_v1(
            views(&before), &provenance, d(102),
        ).unwrap();
        let mut closed = before.clone();
        for mutation in retirement.mutations() {
            closed.insert(mutation.key().to_vec(), mutation.after().to_vec());
        }
        let terminal_records = std::array::from_fn(|index| witness(
            families[index], owner_keys[index].clone(), &closed,
        ));
        let staged = provenance.claims().claims.to_canonical_bytes();
        let staged_claims = ObjectDigest::from_bytes(
            Sha256::new().chain_update(b"aos-source-provider-pre-requested-staged-claims.v1\0")
                .chain_update((staged.len() as u32).to_be_bytes()).chain_update(staged).finalize().into(),
        );
        let original = retirement.original();
        let mut challenge_key = b"AOSZHK01".to_vec();
        challenge_key.extend_from_slice(&provenance.claims().claims.attempt().0);
        let claims = SourceNoEscapeClosureClaimsV1 {
            provider_id: session.provider.authority_id(),
            holder_id: session.holder.authority_id(),
            original_session: original.session_binding,
            acquisition_id: original.acquisition_id,
            original_signed_request: original.root_request_digest,
            original_attempt: original.attempt_digest,
            original_source_floor: d(120),
            original_root_prepared: original.root_prepared_digest,
            original_applying: original.reservation_acquisition_digest,
            admission_transaction: [121; 16],
            admission_sequence: 7,
            first_cold_transaction: [122; 16],
            first_cold_sequence: 16,
            challenge_cut: d(123),
            challenge_sequence: 0,
            staged_claims,
            challenge_absence: NativeHeldByteWitnessV1::new(Family::Challenge, challenge_key, d(0)).unwrap(),
            faulted_acquisition: format::record_digest(&closed[&owner_keys[1]]).unwrap(),
            retired_attempt: format::record_digest(&closed[&owner_keys[0]]).unwrap(),
            cleared_session: format::record_digest(&closed[&owner_keys[2]]).unwrap(),
            session_history_successor: format::record_digest(&closed[&owner_keys[3]]).unwrap(),
            terminal_records,
        };
        let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(claims, session.signers[3].clone()).unwrap();
        let archive = Archive::new_untrusted(vec![0; 907], prepared, None, None).unwrap();
        closed.insert(native_key.clone(), archive.to_canonical_bytes());

        Self { graph, before, closed, archive, provenance, owner_keys, native_key }
    }

    fn stored(&self) -> Archive {
        let signed = SignedSourceNoEscapeClosureV1::sign(
            self.archive.prepared(), &SigningKey::from_bytes(&[54; 32]),
        ).unwrap();
        Archive::new_untrusted(
            self.archive.initial_source_floor_bytes().to_vec(),
            self.archive.prepared().clone(), Some(signed), None,
        ).unwrap()
    }

    fn acknowledged(&self) -> Archive {
        let stored = self.stored();
        let claims = stored.prepared().claims();
        let query = RecoveryCurrentnessQueryV1::new(
            d(130), [131; 32], 1, claims.provider_id, claims.holder_id,
            claims.acquisition_id, claims.original_signed_request, claims.original_attempt,
        ).unwrap();
        let reference = NoEscapeRecordReferenceV1 { id: [132; 32], revision: 3, record_digest: [133; 32] };
        let facts = RootNoEscapeAckFactsV1 {
            current_session: query.session_binding(), live_query: query.digest(),
            accepted_source_answer: d(134), signed_source_archive: stored.signed().unwrap().digest(),
            original_root_prepared: claims.original_root_prepared, closed_disposition: d(135),
            original_source_floor: claims.original_source_floor, retired_root_floor: d(136),
            retired_root_floor_value: d(137), terminal_sidecar: d(138), terminal_head: d(139),
            cleanup_transaction: [140; 16], settled_attempt: reference, faulted_acquisition: reference,
        };
        let acknowledgement = SignedRootNoEscapeAckV1::sign(
            &query, facts, self.graph.sessions[0].signers[1].clone(),
            &SigningKey::from_bytes(&[51; 32]),
        ).unwrap();

        Archive::new_untrusted(
            stored.initial_source_floor_bytes().to_vec(), stored.prepared().clone(),
            stored.signed().cloned(), Some(acknowledgement),
        ).unwrap()
    }

    fn rows_with(&self, archive: &Archive) -> Rows {
        let mut rows = self.closed.clone();
        rows.insert(self.native_key.clone(), archive.to_canonical_bytes());
        rows
    }

    fn first_keys(&self) -> Vec<Vec<u8>> {
        let mut keys = self.owner_keys.clone();
        keys.push(self.native_key.clone());
        keys
    }
}

fn replace_body(archive: &Archive, body: &[u8]) -> Vec<u8> {
    format::encode_envelope_version(
        RecordKind::NativeCompletion, archive.phase() as u8,
        archive.phase() as u64,
        &native_completion::native_completion_key_v2(archive.prepared().claims().acquisition_id),
        body, 9,
    )
}

#[test]
fn all_three_profiles_round_trip_with_independent_widths_and_stable_data() {
    let flight = Flight::new();
    let archives = [flight.archive.clone(), flight.stored(), flight.acknowledged()];
    assert_eq!(SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1, [1317, 2602, 3314]);

    for (index, archive) in archives.iter().enumerate() {
        let bytes = archive.to_canonical_bytes();
        assert_eq!(bytes.len(), 907 + [1317, 2602, 3314][index]);
        assert_eq!(&bytes[..8], b"AOSSPL01");
        assert_eq!(&bytes[8..10], &9_u16.to_be_bytes());
        assert_eq!(bytes[10], 8);
        assert_eq!(bytes[11], (index + 1) as u8);
        assert_eq!(&bytes[64..72], b"AOSNPC01");
        assert_eq!(Archive::from_canonical_bytes(&flight.native_key, &bytes).unwrap(), *archive);
        assert_eq!(archive.prepared(), flight.archive.prepared());
        assert_eq!(archive.initial_source_floor_bytes(), &[0; 907]);
        let rows = flight.rows_with(archive);
        assert_eq!(classify_original_source_pre_requested_cold_v1(
            views(&rows), flight.graph.acquisition.acquisition_id,
        ).unwrap(), *archive);
    }
}

#[test]
fn opaque_floor_bounds_do_not_claim_a_floor_codec() {
    let flight = Flight::new();
    for length in [907, 30_413] {
        let archive = Archive::new_untrusted(
            vec![0; length], flight.archive.prepared().clone(), None, None,
        ).unwrap();
        let bytes = archive.to_canonical_bytes();
        assert_eq!(Archive::from_canonical_bytes(&flight.native_key, &bytes).unwrap(), archive);
    }
    for length in [0, 906, 30_414] {
        assert!(Archive::new_untrusted(
            vec![0; length], flight.archive.prepared().clone(), None, None,
        ).is_err());
    }
    assert_eq!(MAXIMUM_SOURCE_PRE_REQUESTED_COLD_ARCHIVE_BYTES_V1, 33_727);
}

#[test]
fn truncation_trailing_bytes_and_envelope_corruption_are_rejected() {
    let flight = Flight::new();
    for archive in [flight.archive.clone(), flight.stored(), flight.acknowledged()] {
        let bytes = archive.to_canonical_bytes();
        for length in 0..bytes.len() {
            assert!(Archive::from_canonical_bytes(&flight.native_key, &bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Archive::from_canonical_bytes(&flight.native_key, &trailing).is_err());

        for offset in [0, 8, 10, 11, 12, 16, 20, 24, 32, 64, 72, 74, 75, 76] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(Archive::from_canonical_bytes(&flight.native_key, &corrupt).is_err(), "offset {offset}");
        }
        let foreign_key = native_completion::native_completion_key_v2(d(201));
        assert!(Archive::from_canonical_bytes(&foreign_key, &bytes).is_err());
    }
}

#[test]
fn valid_envelope_does_not_hide_noncanonical_inner_lengths_or_headers() {
    let flight = Flight::new();
    for archive in [flight.archive.clone(), flight.stored(), flight.acknowledged()] {
        let canonical = archive.to_canonical_bytes();
        let body = &canonical[64..];
        let prepared_length = 16 + 4 + 907;
        let signed_length = prepared_length + 4 + 1221;
        let acknowledgement_length = signed_length + 4
            + if archive.signed().is_some() { 1285 } else { 0 };
        for (offset, widths) in [
            (16, vec![0, 906, 30_414, u32::MAX]),
            (prepared_length, vec![1220, 1222, 1321, u32::MAX]),
            (signed_length, vec![1, 1284, 1286, 1385, u32::MAX]),
            (acknowledgement_length, vec![1, 711, 713, u32::MAX]),
        ] {
            for width in widths {
                let mut changed = body.to_vec();
                changed[offset..offset + 4].copy_from_slice(&width.to_be_bytes());
                assert!(Archive::from_canonical_bytes(
                    &flight.native_key, &replace_body(&archive, &changed),
                ).is_err(), "field {offset}, width {width}");
            }
        }
        for offset in [0, 8, 9, 10, 11, 12, 13, 14, 15] {
            let mut changed = body.to_vec();
            changed[offset] ^= 1;
            assert!(Archive::from_canonical_bytes(
                &flight.native_key, &replace_body(&archive, &changed),
            ).is_err());
        }
    }
}

#[test]
fn old_profiles_and_public_legacy_seals_refuse_cold_bytes() {
    let flight = Flight::new();
    let bytes = flight.archive.to_canonical_bytes();
    assert!(format::decode_record(&flight.native_key, &bytes).is_err());
    assert!(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&flight.native_key, &bytes).is_err());
    assert!(crate::validate_prospective_records(views(&flight.closed)).is_err());
    assert!(crate::validate_prospective_transition(views(&flight.before), views(&flight.closed)).is_err());

    let old_bytes = native_completion::encode_native_completion_v2(&flight.graph.native);
    assert!(Archive::from_canonical_bytes(&flight.native_key, &old_bytes).is_err());

    let requested = flight.graph.rows();
    assert!(derive_original_source_pre_requested_retirement_v1(
        views(&requested), &flight.provenance, d(102),
    ).is_err());
    let keys = flight.first_keys();
    assert!(propose_original_source_pre_requested_closed_v1(
        views(&requested), puts(&flight.closed, &keys), &flight.provenance, d(102),
    ).is_err());
}

#[test]
fn quartet_is_preparation_only_and_first_proposal_has_exact_sorted_five_puts() {
    let flight = Flight::new();
    let retirement = derive_original_source_pre_requested_retirement_v1(
        views(&flight.before), &flight.provenance, d(102),
    ).unwrap();
    let widths = retirement.mutations().each_ref().map(|mutation| mutation.key().len());
    assert_eq!(widths, [96, 99, 63, 103]);
    for (mutation, key) in retirement.mutations().iter().zip(&flight.owner_keys) {
        assert_eq!(mutation.key(), key);
        assert_eq!(mutation.before(), Some(flight.before[key].as_slice()));
        assert_eq!(mutation.after(), flight.closed[key].as_slice());
    }
    let mut quartet_only = flight.closed.clone();
    quartet_only.remove(&flight.native_key);
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&quartet_only)).is_err());

    let keys = flight.first_keys();
    let proposal = propose_original_source_pre_requested_closed_v1(
        views(&flight.before), puts(&flight.closed, &keys), &flight.provenance, d(102),
    ).unwrap();
    assert_eq!(proposal.phase(), Phase::ClosedPrepared);
    assert_eq!(proposal.archive(), &flight.archive);
    assert_eq!(proposal.mutations().len(), 5);
    assert!(proposal.mutations().windows(2).all(|pair| pair[0].key() < pair[1].key()));
}

#[test]
fn first_proposal_rejects_missing_duplicate_deleting_noop_and_foreign_puts() {
    let flight = Flight::new();
    let keys = flight.first_keys();
    let good: Vec<_> = puts(&flight.closed, &keys).collect();
    let rejected = |changes: Vec<(&[u8], Option<&[u8]>)>| {
        assert!(propose_original_source_pre_requested_closed_v1(
            views(&flight.before), changes, &flight.provenance, d(102),
        ).is_err());
    };
    for index in 0..good.len() {
        let mut missing = good.clone();
        missing.remove(index);
        rejected(missing);
        let mut duplicate = good.clone();
        duplicate.push(good[index]);
        rejected(duplicate);
        let mut deletion = good.clone();
        deletion[index].1 = None;
        rejected(deletion);
    }
    let mut noop = good.clone();
    noop[0].1 = Some(flight.before[&keys[0]].as_slice());
    rejected(noop);
    let authority = format::authority_key(flight.graph.authority.provider.authority_id());
    let mut foreign = good.clone();
    foreign.push((authority.as_slice(), Some(flight.before[&authority].as_slice())));
    rejected(foreign);
}

#[test]
fn first_proposal_rejects_foreign_provenance_claims_and_config() {
    let flight = Flight::new();
    let keys = flight.first_keys();
    assert!(propose_original_source_pre_requested_closed_v1(
        views(&flight.before), puts(&flight.closed, &keys), &flight.provenance, d(103),
    ).is_err());

    for field in 0..3 {
        let mut claims = flight.archive.prepared().claims().clone();
        match field {
            0 => claims.original_root_prepared = d(203),
            1 => claims.staged_claims = d(204),
            _ => {
                let mut key = b"AOSZHK01".to_vec();
                key.extend_from_slice(&[205; 32]);
                claims.challenge_absence = NativeHeldByteWitnessV1::new(Family::Challenge, key, d(0)).unwrap();
            }
        }
        let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
            claims, flight.archive.prepared().signer().clone(),
        ).unwrap();
        let archive = Archive::new_untrusted(vec![0; 907], prepared, None, None).unwrap();
        let changed = flight.rows_with(&archive);
        assert!(propose_original_source_pre_requested_closed_v1(
            views(&flight.before), puts(&changed, &keys), &flight.provenance, d(102),
        ).is_err());
    }
}

#[test]
fn exact_phase_edges_are_singletons_and_not_idempotent_rewrites() {
    let flight = Flight::new();
    let stored = flight.stored();
    let stored_rows = flight.rows_with(&stored);
    let keys = [flight.native_key.clone()];
    let proposal = propose_original_source_pre_requested_closure_stored_v1(
        views(&flight.closed), puts(&stored_rows, &keys), flight.graph.acquisition.acquisition_id,
    ).unwrap();
    assert_eq!(proposal.phase(), Phase::ClosureStored);
    assert_eq!(proposal.mutations().len(), 1);

    let acknowledged = flight.acknowledged();
    let acknowledged_rows = flight.rows_with(&acknowledged);
    let proposal = propose_original_source_pre_requested_root_acknowledged_v1(
        views(&stored_rows), puts(&acknowledged_rows, &keys), flight.graph.acquisition.acquisition_id,
    ).unwrap();
    assert_eq!(proposal.phase(), Phase::RootAcknowledged);
    assert_eq!(proposal.mutations().len(), 1);
    assert!(propose_original_source_pre_requested_closure_stored_v1(
        views(&stored_rows), puts(&stored_rows, &keys), flight.graph.acquisition.acquisition_id,
    ).is_err());
    assert!(propose_original_source_pre_requested_root_acknowledged_v1(
        views(&flight.closed), puts(&acknowledged_rows, &keys), flight.graph.acquisition.acquisition_id,
    ).is_err());
    assert!(crate::validate_transition_structure(&acknowledged_rows, &stored_rows).is_err());
}

#[test]
fn floor_and_unsigned_preparation_cannot_change_on_successors() {
    let flight = Flight::new();
    let stored = flight.stored();
    let changed_floor = Archive::new_untrusted(
        vec![1; 907], stored.prepared().clone(), stored.signed().cloned(), None,
    ).unwrap();
    let keys = [flight.native_key.clone()];
    let changed = flight.rows_with(&changed_floor);
    assert!(propose_original_source_pre_requested_closure_stored_v1(
        views(&flight.closed), puts(&changed, &keys), flight.graph.acquisition.acquisition_id,
    ).is_err());

    let mut claims = stored.prepared().claims().clone();
    claims.challenge_cut = d(206);
    let other_prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
        claims, stored.prepared().signer().clone(),
    ).unwrap();
    assert!(Archive::new_untrusted(
        vec![0; 907], other_prepared, stored.signed().cloned(), None,
    ).is_err());
    assert!(Archive::new_untrusted(
        vec![0; 907], stored.prepared().clone(), None,
        flight.acknowledged().acknowledgement().cloned(),
    ).is_err());
}

#[test]
fn all_three_stable_ack_source_references_are_joined() {
    let flight = Flight::new();
    let acknowledged = flight.acknowledged();
    let stored = flight.stored();
    let mut bytes = acknowledged.acknowledgement().unwrap().to_canonical_bytes();
    for offset in [16 + 3 * 32, 16 + 4 * 32, 16 + 6 * 32] {
        let original = bytes[offset];
        bytes[offset] ^= 1;
        let changed = SignedRootNoEscapeAckV1::from_canonical_bytes(&bytes).unwrap();
        assert!(Archive::new_untrusted(
            vec![0; 907], stored.prepared().clone(), stored.signed().cloned(), Some(changed),
        ).is_err());
        bytes[offset] = original;
    }
}

#[test]
fn byte_decoding_never_verifies_a_claimed_signature() {
    let flight = Flight::new();
    let mut bytes = flight.stored().signed().unwrap().to_canonical_bytes();
    bytes[1221..].fill(0);
    let unsigned_claim = SignedSourceNoEscapeClosureV1::from_canonical_bytes(&bytes).unwrap();
    let archive = Archive::new_untrusted(
        vec![0; 907], flight.archive.prepared().clone(), Some(unsigned_claim.clone()), None,
    ).unwrap();
    let parsed = Archive::from_canonical_bytes(&flight.native_key, &archive.to_canonical_bytes()).unwrap();
    assert_eq!(parsed.signed(), Some(&unsigned_claim));
    assert!(unsigned_claim.verify(
        flight.archive.prepared().signer(),
        &SigningKey::from_bytes(&[54; 32]).verifying_key().to_bytes(),
    ).is_err());
}

#[test]
fn current_graph_requires_actual_terminal_rows_and_matching_inverse_applying() {
    let flight = Flight::new();
    validate_original_source_pre_requested_cold_records_v1(views(&flight.closed)).unwrap();
    for key in &flight.owner_keys {
        let mut absent = flight.closed.clone();
        absent.remove(key);
        assert!(validate_original_source_pre_requested_cold_records_v1(views(&absent)).is_err());
    }
    let mut changed = flight.closed.clone();
    let DecodedRecordV1::Attempt(mut attempt) = format::decode_record(
        &flight.owner_keys[0], &changed[&flight.owner_keys[0]],
    ).unwrap() else { panic!("Attempt"); };
    attempt.revision += 1;
    changed.insert(flight.owner_keys[0].clone(), format::encode_attempt(&attempt));
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&changed)).is_err());

    let mut claims = flight.archive.prepared().claims().clone();
    claims.original_applying = d(207);
    let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
        claims, flight.archive.prepared().signer().clone(),
    ).unwrap();
    let archive = Archive::new_untrusted(vec![0; 907], prepared, None, None).unwrap();
    assert!(validate_original_source_pre_requested_cold_records_v1(
        views(&flight.rows_with(&archive)),
    ).is_err());
}

#[test]
fn frozen_original_history_overrides_the_was_current_rewrite_exception() {
    let flight = Flight::new();
    let stored = flight.stored();
    let before = flight.rows_with(&stored);
    let mut after = before.clone();
    let DecodedRecordV1::SessionHistory(mut history) = format::decode_record(
        &flight.owner_keys[3], &before[&flight.owner_keys[3]],
    ).unwrap() else { panic!("History"); };
    history.revision += 1;
    after.insert(flight.owner_keys[2].clone(), format::encode_session(&history));
    after.insert(flight.owner_keys[3].clone(), format::encode_session_history(&history));

    assert!(cold::graph::validate_retained_transition(
        &before, &after, &flight.native_key, &stored, &stored,
    ).is_err());
    assert!(crate::validate_transition_structure(&before, &after).is_err());
}

#[test]
fn malformed_hint_cannot_be_filtered_from_graph_or_owner_accounting() {
    let flight = Flight::new();
    let mut malformed = flight.closed.clone();
    let mut bytes = flight.archive.to_canonical_bytes();
    bytes[32] ^= 1;
    malformed.insert(flight.native_key.clone(), bytes);
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&malformed)).is_err());

    let mut orphan = flight.closed.clone();
    orphan.insert(native_completion::native_completion_key_v2(d(208)), flight.archive.to_canonical_bytes());
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&orphan)).is_err());
    let mut absent = flight.closed.clone();
    absent.remove(&flight.native_key);
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&absent)).is_err());
    assert!(crate::validate_transition_structure(&flight.closed, &absent).is_err());
}

#[test]
fn quartet_extraction_preserves_the_existing_retirement_bytes() {
    let flight = Flight::new();
    let mut attempt = flight.graph.attempts[0].clone();
    let mut acquisition = flight.graph.acquisition.clone();
    let mut holder = flight.graph.sessions[0].clone();
    attempt.revision += 1;
    attempt.state = ProviderAttemptStateV1::Retired;
    acquisition.revision += 1;
    acquisition.state = ProviderAcquisitionStateV1::Faulted;
    holder.revision += 1;
    holder.pending_attempt_digest = None;
    let independent = [
        format::encode_attempt(&attempt), format::encode_acquisition(&acquisition),
        format::encode_session(&holder), format::encode_session_history(&holder),
    ];

    assert_eq!(graph::retire_pending_quartet(
        &flight.graph.attempts[0], &flight.graph.acquisition, &flight.graph.sessions[0],
    ).unwrap(), independent);
}

#[test]
fn phase_two_historical_holder_is_not_the_later_current_head() {
    let flight = Flight::new();
    let stored = flight.stored();
    let before = flight.rows_with(&stored);
    let mut later = fixtures::session(60);
    later.revision = 1;
    later.session_generation = 2;
    later.predecessor_session_binding = Some(flight.graph.sessions[0].session_binding);
    later.supersession_evidence_digest = Some(d(209));
    later.pending_attempt_digest = None;
    let mut after = before.clone();
    after.insert(flight.owner_keys[2].clone(), format::encode_session(&later));
    after.insert(
        format::session_history_key(
            later.provider.authority_id(), later.holder.authority_id(), later.session_binding,
        ),
        format::encode_session_history(&later),
    );

    // This independently checks historical commitments rather than current
    // Holder bytes. The shared core still checks every new Session's own rules.
    cold::graph::validate_companions(&after, &stored).unwrap();
    cold::graph::validate_retained_transition(
        &before, &after, &flight.native_key, &stored, &stored,
    ).unwrap();
    validate_original_source_pre_requested_cold_records_v1(views(&after)).unwrap();
    crate::validate_transition_structure(&before, &after).unwrap();
    assert_ne!(after[&flight.owner_keys[2]], before[&flight.owner_keys[2]]);
    assert_eq!(after[&flight.owner_keys[3]], before[&flight.owner_keys[3]]);

    let mut phase_one = after;
    phase_one.insert(flight.native_key.clone(), flight.archive.to_canonical_bytes());
    assert!(validate_original_source_pre_requested_cold_records_v1(views(&phase_one)).is_err());
}

#[test]
fn valid_envelopes_still_reject_malformed_nested_closure_and_ack_claims() {
    let flight = Flight::new();
    let prepared_start = 16 + 4 + 907 + 4;

    for archive in [flight.archive.clone(), flight.stored(), flight.acknowledged()] {
        let canonical = archive.to_canonical_bytes();
        let mut body = canonical[64..].to_vec();
        // The first closure identity is nonzero. A fresh envelope digest must
        // not conceal a nested codec failure after all lengths passed.
        body[prepared_start + 16..prepared_start + 32].fill(0);
        assert!(Archive::from_canonical_bytes(
            &flight.native_key,
            &replace_body(&archive, &body),
        ).is_err());
    }

    let acknowledged = flight.acknowledged();
    let canonical = acknowledged.to_canonical_bytes();
    let mut body = canonical[64..].to_vec();
    let ack_start = prepared_start + 1221 + 4 + 1285 + 4;
    body[ack_start + 16..ack_start + 48].fill(0);
    assert!(Archive::from_canonical_bytes(
        &flight.native_key,
        &replace_body(&acknowledged, &body),
    ).is_err());
}

#[test]
fn ledger_record_and_family_byte_commitments_cannot_be_substituted() {
    let flight = Flight::new();

    for index in 0..4 {
        let mut claims = flight.archive.prepared().claims().clone();
        let ledger_digest = format::record_digest(&flight.closed[&flight.owner_keys[index]])
            .unwrap();
        let original_witness = &claims.terminal_records[index];
        claims.terminal_records[index] = NativeHeldByteWitnessV1::new(
            original_witness.family(),
            original_witness.key().to_vec(),
            ledger_digest,
        ).unwrap();
        let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
            claims,
            flight.archive.prepared().signer().clone(),
        ).unwrap();
        let archive = Archive::new_untrusted(vec![0; 907], prepared, None, None).unwrap();

        assert!(validate_original_source_pre_requested_cold_records_v1(
            views(&flight.rows_with(&archive)),
        ).is_err(), "terminal byte domain {index}");
    }

    for index in 0..4 {
        let mut claims = flight.archive.prepared().claims().clone();
        let byte_digest = claims.terminal_records[index].digest();
        match index {
            0 => claims.retired_attempt = byte_digest,
            1 => claims.faulted_acquisition = byte_digest,
            2 => claims.cleared_session = byte_digest,
            _ => claims.session_history_successor = byte_digest,
        }
        let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
            claims,
            flight.archive.prepared().signer().clone(),
        ).unwrap();
        let archive = Archive::new_untrusted(vec![0; 907], prepared, None, None).unwrap();

        assert!(validate_original_source_pre_requested_cold_records_v1(
            views(&flight.rows_with(&archive)),
        ).is_err(), "terminal ledger domain {index}");
    }
}

#[test]
fn coherently_recommitted_terminal_history_still_cannot_replace_retained_origin() {
    let flight = Flight::new();
    let stored = flight.stored();
    let before = flight.rows_with(&stored);
    let mut after = before.clone();
    let DecodedRecordV1::SessionHistory(mut history) = format::decode_record(
        &flight.owner_keys[3],
        &before[&flight.owner_keys[3]],
    ).unwrap() else {
        panic!("History");
    };
    history.revision += 1;
    after.insert(flight.owner_keys[2].clone(), format::encode_session(&history));
    after.insert(flight.owner_keys[3].clone(), format::encode_session_history(&history));

    let mut claims = stored.prepared().claims().clone();
    claims.cleared_session = format::record_digest(&after[&flight.owner_keys[2]]).unwrap();
    claims.session_history_successor = format::record_digest(&after[&flight.owner_keys[3]])
        .unwrap();
    for index in [2, 3] {
        claims.terminal_records[index] = witness(
            claims.terminal_records[index].family(),
            flight.owner_keys[index].clone(),
            &after,
        );
    }
    let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
        claims,
        stored.prepared().signer().clone(),
    ).unwrap();
    let signed = SignedSourceNoEscapeClosureV1::sign(
        &prepared,
        &SigningKey::from_bytes(&[54; 32]),
    ).unwrap();
    let replacement = Archive::new_untrusted(
        stored.initial_source_floor_bytes().to_vec(),
        prepared,
        Some(signed),
        None,
    ).unwrap();
    after.insert(flight.native_key.clone(), replacement.to_canonical_bytes());

    // Standalone DATA can be coherent without preserving a prior physical
    // history. Replay must additionally reject rewriting the frozen origin.
    validate_original_source_pre_requested_cold_records_v1(views(&after)).unwrap();
    assert!(crate::validate_transition_structure(&before, &after).is_err());
}

#[test]
fn acknowledged_archive_cannot_replace_ack_or_reenter_a_hot_profile() {
    let flight = Flight::new();
    let acknowledged = flight.acknowledged();
    let before = flight.rows_with(&acknowledged);
    let mut bytes = acknowledged.acknowledgement().unwrap().to_canonical_bytes();
    bytes[80] ^= 1;
    let changed_ack = SignedRootNoEscapeAckV1::from_canonical_bytes(&bytes).unwrap();
    let replacement = Archive::new_untrusted(
        acknowledged.initial_source_floor_bytes().to_vec(),
        acknowledged.prepared().clone(),
        acknowledged.signed().cloned(),
        Some(changed_ack),
    ).unwrap();
    let after = flight.rows_with(&replacement);

    validate_original_source_pre_requested_cold_records_v1(views(&after)).unwrap();
    assert!(crate::validate_transition_structure(&before, &after).is_err());

    let mut hot = before.clone();
    hot.insert(
        flight.native_key.clone(),
        native_completion::encode_native_completion_v2(&flight.graph.native),
    );
    assert!(crate::validate_transition_structure(&before, &hot).is_err());
    assert!(crate::validate_transition_structure(&flight.graph.rows(), &before).is_err());
}

#[test]
fn singleton_proposals_reject_duplicates_deletions_and_companion_puts() {
    let flight = Flight::new();
    let stored_rows = flight.rows_with(&flight.stored());
    let key = flight.native_key.as_slice();
    let bytes = stored_rows[&flight.native_key].as_slice();
    let acquisition = flight.graph.acquisition.acquisition_id;

    for changes in [
        vec![(key, Some(bytes)), (key, Some(bytes))],
        vec![(key, None)],
        vec![
            (key, Some(bytes)),
            (
                flight.owner_keys[0].as_slice(),
                Some(flight.closed[&flight.owner_keys[0]].as_slice()),
            ),
        ],
    ] {
        assert!(propose_original_source_pre_requested_closure_stored_v1(
            views(&flight.closed),
            changes,
            acquisition,
        ).is_err());
    }

    let acknowledged_rows = flight.rows_with(&flight.acknowledged());
    let bytes = acknowledged_rows[&flight.native_key].as_slice();
    for changes in [
        vec![(key, Some(bytes)), (key, Some(bytes))],
        vec![(key, None)],
        vec![
            (key, Some(bytes)),
            (
                flight.owner_keys[3].as_slice(),
                Some(stored_rows[&flight.owner_keys[3]].as_slice()),
            ),
        ],
    ] {
        assert!(propose_original_source_pre_requested_root_acknowledged_v1(
            views(&stored_rows),
            changes,
            acquisition,
        ).is_err());
    }
}

#[test]
fn every_cold_byte_participates_in_the_existing_complete_graph_commitment() {
    let flight = Flight::new();
    let validated = crate::validate_current_records(&flight.closed).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.ledger.validated-graph.v1\0");
    for (key, bytes) in &flight.closed {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    assert_eq!(validated.graph_digest(), ObjectDigest::from_bytes(hasher.finalize().into()));

    let changed_floor = Archive::new_untrusted(
        vec![1; 907],
        flight.archive.prepared().clone(),
        None,
        None,
    ).unwrap();
    let after = flight.rows_with(&changed_floor);
    let changed = crate::validate_current_records(&after).unwrap();

    assert_ne!(validated.graph_digest(), changed.graph_digest());
    assert!(crate::validate_transition_structure(&flight.closed, &after).is_err());
}

#[test]
fn cold_owner_geometry_uses_existing_record_bounds_without_journal_floor_owners() {
    let framed_quartet: usize = format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[..4]
        .iter()
        .sum();
    let quartet = framed_quartet - (96 + 99 + 63 + 103) - 4 * 9;
    let floor = MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1;
    let archive = SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1.map(|fixed| fixed + floor);
    let owners = [framed_quartet + archive[0] + 40 + 9, archive[1] + 49, archive[2] + 49];

    assert_eq!(quartet, 2_604_380);
    assert_eq!(owners, [2_636_556, 33_064, 33_776]);
    assert!(owners.into_iter().all(|bytes| bytes <= crate::limits::MAXIMUM_TRANSACTION_BYTES));
    assert!(5 <= crate::limits::MAXIMUM_TRANSACTION_RECORDS);

    // These independently account for the future Journal's additional
    // floor DEL/PUT rows. They do not enter Ledger's five/one/one owner lists.
    let journal = [quartet + 2605 + 2 * floor, 3213 + 2 * floor, 3771 + floor];
    assert_eq!(journal, [2_667_811, 64_039, 34_184]);
    assert_eq!(journal.into_iter().sum::<usize>(), quartet + 9589 + 5 * floor);
    assert_eq!(journal[1] + journal[2], 6984 + 3 * floor);
}

#[test]
fn retained_cold_origin_coexists_with_later_legacy_or_held_native_owner() {
    let flight = Flight::new();
    let before = flight.rows_with(&flight.stored());
    let mut session = fixtures::session(60);
    session.session_generation = 2;
    session.predecessor_session_binding = Some(flight.graph.sessions[0].session_binding);
    session.supersession_evidence_digest = Some(d(210));
    let later = fixtures::Graph::applying_for_session(session, 3, [211; 16], 5, [212; 32]);
    let key = native_completion::native_completion_key_v2(later.native.acquisition_id);
    let root = root_prepared(&later.native);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        0,
        root.scope().flight,
        None,
        vec![root],
    ).unwrap();
    let held = SourceNativeHeldCompletionRecordV1::new(later.native.clone(), suffix).unwrap();
    let held_bytes = held.to_canonical_bytes().unwrap();
    assert!(Archive::from_canonical_bytes(&key, &held_bytes).is_err());

    for native_bytes in [
        native_completion::encode_native_completion_v2(&later.native),
        held_bytes,
    ] {
        let mut after = before.clone();
        after.extend(later.rows());
        after.insert(key.clone(), native_bytes);

        validate_original_source_pre_requested_cold_records_v1(views(&after)).unwrap();
        crate::validate_transition_structure(&before, &after).unwrap();
        assert_eq!(after[&flight.native_key], before[&flight.native_key]);
        assert_eq!(after[&flight.owner_keys[3]], before[&flight.owner_keys[3]]);

        let mut missing_origin = after;
        missing_origin.remove(&flight.owner_keys[3]);
        assert!(validate_original_source_pre_requested_cold_records_v1(
            views(&missing_origin),
        ).is_err());
    }
}
