//! Independent canonical preimages and pure owner-predicate regressions.
//!
//! All fixtures are synthetic DATA, including untrusted clock and signatures.
//! They create no protected journal, current trust, original admission, dispatch
//! bridge, FD, challenge writer or live signing authority. Predicate tests do not
//! substitute for full protected graph/transaction/runtime qualification.

use super::*;
use crate::ledger::{
    format,
    native_completion::{
        self, NativeAcquireCompletionRecordV2 as Original, NativeAcquireCompletionStateV2 as Outer,
        request_tests,
    },
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NativeAcquireCatalogBindingV3, SignedStorageNativeAcquireRequestV2,
    SourceProviderAuthorityV1, SourceProviderMethod, StorageNativeAcquireRequestV2,
    decode_acquire_request, encode_acquire_request,
    native_held_completion::{
        NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner, NativeHeldScopeV1,
        NativeHeldSectionTagV1 as Tag,
        assertion::{
            NativeHeldDispositionV1, RootNativeDispositionAssertionV1, RootNativeObservationV1,
        },
        frame::{
            NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
            SignedNativeHeldControlV1,
        },
        native_held_flight_digest_v1,
        suffix::NativeHeldCompletionSuffixV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
            NativeHeldRecordFamilyV1 as Family, ProviderNativeHeldWitnessV1,
            ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1, StorageNativeHeldWitnessV1,
            native_held_record_byte_digest_v1,
        },
    },
    sign_request,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod fixtures;
mod funnel_tests;
mod original_provenance_tests;
mod original_source_owner_tests;
mod recovery_tests;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn root_witness() -> RootNativeHeldWitnessV1 {
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
    let generation = NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: d(93),
    };
    RootNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        journal_sequence: 1,
        planning_sequence: 1,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: d(94),
        records,
    }
}

fn section(tag: Tag, bytes: Vec<u8>) -> NativeHeldSectionV1 {
    NativeHeldSectionV1::new(tag, bytes).unwrap()
}

fn root_prepared(original: &Original) -> SignedNativeHeldControlV1 {
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(
            original.root_request_digest,
            d(95),
            original.session_binding,
        ),
        original_source_session: original.session_binding,
        mount_attempt: d(95),
        provider_attempt: d(0),
        provider_acquisition: original.acquisition_id,
        original_root_request: original.root_request_digest,
        original_native_request: d(0),
    };
    let witness = NativeHeldOwnerWitnessV1::Root(root_witness())
        .to_canonical_bytes()
        .unwrap();
    PreparedNativeHeldControlV1::new(
        Kind::RootPrepared,
        scope,
        d(0),
        vec![section(Tag::Witness, witness)],
        NativeHeldSignerV1::SourceProvider(
            original
                .canonical_request
                .as_ref()
                .unwrap()
                .request()
                .signed_root_request()
                .signer()
                .clone(),
        ),
    )
    .unwrap()
    .with_signature([0xA1; 64])
}

fn initial(original: Original) -> SourceNativeHeldCompletionRecordV1 {
    let root = root_prepared(&original);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        0,
        root.scope().flight,
        None,
        vec![root],
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

fn advance(
    record: &SourceNativeHeldCompletionRecordV1,
    phase: u8,
) -> SourceNativeHeldCompletionRecordV1 {
    let mut original = record.original.clone();
    original.revision += 1;
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        phase,
        record.suffix.flight(),
        record.suffix.prepared().cloned(),
        record.suffix.controls().to_vec(),
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

fn storage_prepared(
    issued: &SourceNativeHeldCompletionRecordV1,
) -> SourceNativeHeldCompletionRecordV1 {
    let mut original = request_tests::prepared();
    original.revision = issued.original.revision + 1;
    let full = evidence::full_scope(issued).unwrap();
    let root = issued.suffix.controls()[0].clone();
    let witness = StorageNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        primary_sequence: 1,
        workspace_sequence: 1,
        request_trust_sequence: 1,
        issuance_sequence: 1,
        request_trust_generation: 1,
        request_trust_file: d(97),
        issuance: NativeHeldByteWitnessV1::new(Family::StorageIssuance, vec![98; 48], d(99))
            .unwrap(),
    };
    let reply = original.accepted_reply.as_ref().unwrap();
    let control = PreparedNativeHeldControlV1::new(
        Kind::StorageHeld,
        full,
        root.digest(),
        vec![
            section(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Storage(witness)
                    .to_canonical_bytes()
                    .unwrap(),
            ),
            section(Tag::RootPrepared, root.to_canonical_bytes()),
            section(Tag::NativeReply, reply.to_canonical_bytes()),
        ],
        NativeHeldSignerV1::Storage(reply.acceptance().signer()),
    )
    .unwrap()
    .with_signature([0xA2; 64]);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        2,
        root.scope().flight,
        None,
        vec![root, control],
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

fn held_prepared(artifact: ObjectDigest) -> SourceNativeHeldCompletionRecordV1 {
    let requested = initial(request_tests::requested());
    let issued = advance(&requested, 1);
    let prepared = storage_prepared(&issued);
    let spent = advance(&prepared, 3);
    let mut original = spent.original.advance(Outer::Active).unwrap();
    original.revision += 1;
    let storage = spent.suffix.control(Kind::StorageHeld).unwrap();
    let held = PreparedNativeHeldControlV1::new(
        Kind::ProviderHeld,
        evidence::full_scope(&spent).unwrap(),
        storage.digest(),
        vec![
            section(Tag::Witness, provider_witness(&spent)),
            section(Tag::StorageHeld, storage.to_canonical_bytes()),
            section(Tag::SourceArtifact, artifact.as_bytes().to_vec()),
        ],
        NativeHeldSignerV1::SourceProvider(
            original
                .canonical_request
                .as_ref()
                .unwrap()
                .signer()
                .clone(),
        ),
    )
    .unwrap();
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        5,
        spent.suffix.flight(),
        Some(held),
        spent.suffix.controls().to_vec(),
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

// Independent old body assembly; no production body/envelope encoder is used.
fn original_body(original: &Original, magic: &[u8; 8]) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&original.provider_id);
    bytes.extend_from_slice(&original.holder_id);
    for value in [
        original.session_binding,
        original.attempt_digest,
        original.acquisition_id,
    ] {
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&original.challenge);
    bytes.extend_from_slice(&original.challenge_issued_seconds.to_be_bytes());
    bytes.extend_from_slice(&original.challenge_valid_until_seconds.to_be_bytes());
    bytes.extend_from_slice(original.root_request_digest.as_bytes());
    bytes.extend_from_slice(&original.root_request_id);
    for value in [
        original.typed_request_digest,
        original.native_request_digest,
        original.receipt_digest,
        original.acceptance_digest,
        original.acceptance_payload_digest,
    ] {
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&original.issuance_id);
    bytes.extend_from_slice(original.binding_digest.as_bytes());
    bytes.extend_from_slice(original.publication_head.as_bytes());
    bytes.extend_from_slice(&original.original_root.kernel_boot_id);
    for value in [
        original.original_root.device,
        original.original_root.inode,
        original.original_root.unique_mount_id,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(original.descriptor_commitment.as_bytes());
    assert_eq!(bytes.len(), 544);
    if let Some(request) = &original.canonical_request {
        bytes.extend_from_slice(original.reservation_acquisition_digest.unwrap().as_bytes());
        if let Some(clock) = original.original_clock {
            let pair = clock.initial();
            bytes.extend_from_slice(&pair.provenance().as_bytes());
            bytes.extend_from_slice(&pair.host_boot_id());
            bytes.extend_from_slice(&pair.wall_seconds().to_be_bytes());
            bytes.extend_from_slice(&pair.boottime_nanoseconds().to_be_bytes());
            bytes.extend_from_slice(&clock.deadline().to_be_bytes());
        }
        let request = request.to_canonical_bytes();
        bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&request);
        let reply = original
            .accepted_reply
            .as_ref()
            .map(|value| value.to_canonical_bytes())
            .unwrap_or_default();
        bytes.extend_from_slice(&(reply.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&reply);
    }
    bytes
}

fn independent_envelope(original: &Original, version: u16, body: &[u8]) -> Vec<u8> {
    let key = [b"AOSNCK02".as_slice(), original.acquisition_id.as_bytes()].concat();
    let mut header = b"AOSSPL01".to_vec();
    header.extend_from_slice(&version.to_be_bytes());
    header.extend_from_slice(&[8, original.state as u8]);
    header.extend_from_slice(&[0; 4]);
    header.extend_from_slice(&(body.len() as u32).to_be_bytes());
    header.extend_from_slice(&[0; 4]);
    header.extend_from_slice(&original.revision.to_be_bytes());
    assert_eq!(header.len(), 32);
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.source-provider.ledger.native-completion.v2\0")
        .chain_update(40_u32.to_be_bytes())
        .chain_update(&key)
        .chain_update(((32 + body.len()) as u32).to_be_bytes())
        .chain_update(&header)
        .chain_update(body)
        .finalize();
    [header.as_slice(), digest.as_slice(), body].concat()
}

#[test]
fn independent_legacy_5_6_7_preimages_and_digests_remain_exact() {
    let mut inert = request_tests::prepared();
    inert.canonical_request = None;
    inert.accepted_reply = None;
    inert.reservation_acquisition_digest = None;
    inert.original_clock = None;
    let mut historical = request_tests::requested();
    historical.original_clock = None;
    for (version, magic, original) in [
        (5, b"AOSNCR02", inert),
        (6, b"AOSNCR03", historical),
        (7, b"AOSNCR04", request_tests::requested()),
    ] {
        let expected = independent_envelope(&original, version, &original_body(&original, magic));
        assert_eq!(format::encode_native_completion_v2(&original), expected);
        assert_eq!(
            format::decode_record(
                &native_completion::native_completion_key_v2(original.acquisition_id),
                &expected
            )
            .unwrap(),
            crate::ledger::model::DecodedRecordV1::NativeCompletion(original)
        );
    }
}

#[test]
fn explicit_held_preimage_preserves_every_original_byte_and_closed_routing() {
    let record = initial(request_tests::requested());
    let root = record.suffix.controls()[0].to_canonical_bytes();
    let mut suffix = b"AOSNHS01".to_vec();
    suffix.extend_from_slice(&1_u16.to_be_bytes());
    suffix.extend_from_slice(&[2, 0]);
    suffix.extend_from_slice(&[0; 4]);
    suffix.extend_from_slice(record.suffix.flight().as_bytes());
    suffix.extend_from_slice(&0_u32.to_be_bytes());
    suffix.extend_from_slice(&1_u16.to_be_bytes());
    suffix.extend_from_slice(&[0; 2]);
    suffix.extend_from_slice(&[1, 0, 0, 0]);
    suffix.extend_from_slice(&(root.len() as u32).to_be_bytes());
    suffix.extend_from_slice(&root);
    assert_eq!(record.suffix.to_canonical_bytes().unwrap(), suffix);
    let mut body = original_body(&record.original, b"AOSNCR05");
    body.extend_from_slice(&suffix);
    let expected = independent_envelope(&record.original, 8, &body);
    assert_eq!(record.to_canonical_bytes().unwrap(), expected);
    let key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    assert_eq!(
        SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &expected).unwrap(),
        record
    );
    assert!(format::decode_record(&key, &expected).is_err());
    let old = format::encode_native_completion_v2(&record.original);
    assert!(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &old).is_err());
    let mut wrong = key.clone();
    wrong[39] ^= 1;
    assert!(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&wrong, &expected).is_err());
}

#[test]
fn new_held_geometry_does_not_enlarge_legacy_dispatch_or_release_floors() {
    assert_eq!(native_completion::MAXIMUM_BODY_BYTES, 1_071_930);
    assert_eq!(
        format::MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2,
        3_677_574
    );
    let old_dispatch_floor =
        format::MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 + 7 + 72 + 72 * (7 + 2) + 40;
    assert_eq!(old_dispatch_floor, 3_678_341);
    assert_eq!(MAXIMUM_NATIVE_HELD_BODY_BYTES_V1, 1_178_578);
    assert_eq!(MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1, 1_178_642);
    assert_eq!(MAXIMUM_NATIVE_HELD_CARRIER_MUTATION_BYTES_V1, 1_178_691);
    assert_eq!(MAXIMUM_NATIVE_HELD_COMPLETION_OWNER_BYTES_V1, 3_784_222);
    assert_eq!(
        NATIVE_HELD_COMPLETION_OWNER_RECORD_BOUNDS_V1
            .iter()
            .sum::<usize>(),
        3_784_222
    );
    assert_eq!(
        &NATIVE_HELD_COMPLETION_OWNER_RECORD_BOUNDS_V1[..5],
        &format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[..5]
    );
    assert_eq!(
        NATIVE_HELD_COMPLETION_OWNER_RECORD_BOUNDS_V1[5]
            - format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[5],
        106_648
    );
    assert_eq!(
        format::MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1,
        3_677_574 + 131_720 + 99 + 9
    );
}

#[test]
fn original_clock_and_canonical_request_cannot_be_inferred_from_historical_rows() {
    let record = initial(request_tests::requested());
    let mut original = record.original.clone();
    original.original_clock = None;
    assert!(SourceNativeHeldCompletionRecordV1::new(original, record.suffix.clone()).is_err());
    let mut original = record.original.clone();
    original.canonical_request = None;
    assert!(SourceNativeHeldCompletionRecordV1::new(original, record.suffix.clone()).is_err());
    let mut changed = record.original.clone();
    changed.challenge[0] ^= 1;
    assert!(SourceNativeHeldCompletionRecordV1::new(changed, record.suffix.clone()).is_err());
}

#[test]
fn original_root_v2_and_v3_are_data_compatible_not_dispatch_producers() {
    let original = request_tests::requested();
    let native = original.canonical_request.as_ref().unwrap();
    let root = decode_acquire_request(native.request().signed_root_request().subject()).unwrap();
    let claims = native.request().claims();
    let catalog = claims.catalog();
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
    let root = AcquireSourceRequestV1::new_native_v3(root, binding).unwrap();
    let key = SigningKey::from_bytes(&[51; 32]);
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        native.request().signed_root_request().signer().clone(),
        &key,
    )
    .unwrap();
    let native = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new_native_v3(claims.clone(), signed_root).unwrap(),
        native.signer().clone(),
        &key,
    )
    .unwrap();
    let clock = native_completion::NativeAcquireClockAnchorV1::new_untrusted(
        original.original_clock.unwrap().initial(),
        &native,
    )
    .unwrap();
    let record = initial(Original::requested(native, d(39), clock).unwrap());
    let encoded = record.to_canonical_bytes().unwrap();
    let native_key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    assert_eq!(
        SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&native_key, &encoded).unwrap(),
        record
    );
    // A well-shaped record by itself has none of the mandatory actual companions.
    assert!(
        validate_native_held_records_v1([(native_key.as_slice(), encoded.as_slice())]).is_err()
    );
}

#[test]
fn checkpoint_predicates_preserve_original_outer_phase_and_reject_skips() {
    let requested = initial(request_tests::requested());
    let issued = advance(&requested, 1);
    transition::validate_step(
        Some(&requested),
        &issued,
        SourceNativeHeldStepV1::ChallengeIssued,
    )
    .unwrap();
    transition::validate_original(&requested, &issued, SourceNativeHeldStepV1::ChallengeIssued)
        .unwrap();
    assert_eq!(issued.original.state, Outer::Requested);
    let prepared = storage_prepared(&issued);
    transition::validate_step(
        Some(&issued),
        &prepared,
        SourceNativeHeldStepV1::StoragePrepared,
    )
    .unwrap();
    transition::validate_original(&issued, &prepared, SourceNativeHeldStepV1::StoragePrepared)
        .unwrap();
    let spent = advance(&prepared, 3);
    transition::validate_step(
        Some(&prepared),
        &spent,
        SourceNativeHeldStepV1::ChallengeSpent,
    )
    .unwrap();
    transition::validate_original(&prepared, &spent, SourceNativeHeldStepV1::ChallengeSpent)
        .unwrap();
    assert_eq!(spent.original.state, Outer::Prepared);
    assert!(
        transition::validate_step(
            Some(&requested),
            &prepared,
            SourceNativeHeldStepV1::StoragePrepared
        )
        .is_err()
    );
    assert!(
        transition::validate_step(
            Some(&prepared),
            &prepared,
            SourceNativeHeldStepV1::ChallengeSpent
        )
        .is_err()
    );
    let mut rewritten = issued.clone();
    rewritten.original.reservation_acquisition_digest = Some(d(102));
    assert!(
        transition::validate_original(
            &requested,
            &rewritten,
            SourceNativeHeldStepV1::ChallengeIssued
        )
        .is_err()
    );
}

#[test]
fn exact_mutation_comparison_measures_actual_bytes_and_forbids_unrelated_rows() {
    let original = initial(request_tests::requested());
    let next = advance(&original, 1);
    let key = native_completion::native_completion_key_v2(original.original.acquisition_id);
    let old = original.to_canonical_bytes().unwrap();
    let new = next.to_canonical_bytes().unwrap();
    let before = BTreeMap::from([(key.clone(), old.clone())]);
    let mut after = BTreeMap::from([(key.clone(), new.clone())]);
    let expected = BTreeSet::from([key.clone()]);
    let mutations = transition::exact_mutations(&before, &after, &expected).unwrap();
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].before(), Some(old.as_slice()));
    assert_eq!(mutations[0].after(), new.as_slice());
    after.insert(vec![1; 40], vec![2; 64]);
    assert!(transition::exact_mutations(&before, &after, &expected).is_err());
    after.remove(&key);
    assert!(transition::exact_mutations(&before, &after, &expected).is_err());
}

#[test]
fn before_witness_commits_real_held_bytes_not_legacy_projection() {
    let record = initial(request_tests::requested());
    let key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    let bytes = record.to_canonical_bytes().unwrap();
    let digest = native_held_record_byte_digest_v1(Family::ProviderNative, &key, &bytes).unwrap();
    let witness =
        NativeHeldByteWitnessV1::new(Family::ProviderNative, key.clone(), digest).unwrap();
    graph::require_witness(&witness, Family::ProviderNative, &key, Some(&bytes)).unwrap();
    let legacy = format::encode_native_completion_v2(&record.original);
    assert!(graph::require_witness(&witness, Family::ProviderNative, &key, Some(&legacy)).is_err());
    assert!(graph::require_witness(&witness, Family::ProviderNative, &key, None).is_err());
}

fn applying() -> crate::ledger::model::AcquisitionRecordV1 {
    let original = request_tests::requested();
    let signed = original.canonical_request.as_ref().unwrap();
    let root = decode_acquire_request(signed.request().signed_root_request().subject()).unwrap();
    let catalog = signed.request().claims().catalog();
    let (resource, _) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            original.binding_digest,
        )
        .unwrap();
    let provider = SourceProviderAuthorityV1::new(original.provider_id, 35, d(36)).unwrap();
    let holder = SourceProviderAuthorityV1::new(original.holder_id, 8, d(9)).unwrap();
    let intent = crate::NormalizedAcquisitionIntentV1::from_acquire_request(
        &root,
        provider.clone(),
        holder.clone(),
        root.node_id(),
        root.boot_id(),
        [103; 16],
        104,
        d(105),
        resource.resource_namespace_digest(),
        106,
        d(10),
    )
    .unwrap();
    let mut value = crate::ledger::model::AcquisitionRecordV1 {
        revision: 1,
        state: crate::ledger::model::ProviderAcquisitionStateV1::Applying,
        provider,
        holder,
        acquisition_id: original.acquisition_id,
        acquisition_sequence: root.acquisition_sequence(),
        effect_id: crate::identity::acquire_effect_id_v1(
            original.acquisition_id,
            original.attempt_digest,
        )
        .unwrap(),
        normalized_intent: intent,
        effect_attempt_digest: original.attempt_digest,
        current_attempt_digest: original.attempt_digest,
        lease_attempt_digest: None,
        lease_issue_generation: 0,
        lease_id: None,
        lease_digest: None,
        lease_history: vec![],
        resource_namespace_digest: resource.resource_namespace_digest(),
        resource_id: resource.resource_id(),
        resource_generation: resource.resource_generation(),
        resource_digest: resource.resource_digest(),
        catalog_generation: resource.catalog_generation(),
        catalog_digest: resource.catalog_digest(),
        selection_generation: resource.selection_generation(),
        selection_digest: resource.selection_digest(),
        proof_class: 0,
        proof_digest: d(0),
        resource_commitment: d(0),
        backend_id: [0; 32],
        backend_lineage_digest: d(0),
        native_no_dispatch_reservation_digest: None,
        backend_evidence: None,
        reopen_identity: None,
        source_root: None,
        release_effect_id: None,
        signed_lease: vec![],
    };
    value.backend_id = crate::identity::acquire_native_dispatch_id_v2(
        value.normalized_intent.digest(),
        value.catalog_generation,
        value.catalog_digest,
        original.attempt_digest,
    );
    value.backend_lineage_digest = graph::original_lineage(&value, original.session_binding);
    value
}

#[test]
fn canonical_applying_dispatch_identity_cannot_upgrade_no_dispatch_or_change_lineage() {
    let original = request_tests::requested();
    let value = applying();
    let key = format::acquisition_key(&crate::ledger::model::AcquisitionKeyV1 {
        provider_id: value.provider.authority_id(),
        holder_id: value.holder.authority_id(),
        acquisition_id: value.acquisition_id,
    });
    let bytes = format::encode_acquisition(&value);
    let crate::ledger::model::DecodedRecordV1::Acquisition(decoded) =
        format::decode_record(&key, &bytes).unwrap()
    else {
        panic!("canonical Applying row kind");
    };
    graph::validate_dispatch(&decoded, original.session_binding, original.attempt_digest).unwrap();
    let mut no_dispatch = decoded.clone();
    no_dispatch.backend_id = crate::identity::acquire_native_no_dispatch_id_v1(
        no_dispatch.normalized_intent.digest(),
        no_dispatch.catalog_generation,
        no_dispatch.catalog_digest,
    );
    no_dispatch.backend_lineage_digest =
        graph::original_lineage(&no_dispatch, original.session_binding);
    assert!(
        graph::validate_dispatch(
            &no_dispatch,
            original.session_binding,
            original.attempt_digest
        )
        .is_err()
    );
    for changed in [
        ObjectDigest::from_bytes([107; 32]),
        ObjectDigest::from_bytes([108; 32]),
    ] {
        let mut next = decoded.clone();
        next.backend_lineage_digest = changed;
        assert!(
            graph::validate_dispatch(&next, original.session_binding, original.attempt_digest)
                .is_err()
        );
    }
    assert!(graph::validate_dispatch(&decoded, d(109), original.attempt_digest).is_err());
    assert!(graph::validate_dispatch(&decoded, original.session_binding, d(110)).is_err());
}

fn provider_witness(record: &SourceNativeHeldCompletionRecordV1) -> Vec<u8> {
    let keys = graph::companion_keys(record).unwrap();
    let families = [
        Family::ProviderAuthority,
        Family::ProviderAttempt,
        Family::ProviderAcquisition,
        Family::ProviderHolder,
        Family::ProviderHistory,
        Family::ProviderNative,
        Family::Challenge,
    ];
    let records = core::array::from_fn(|index| {
        let key = if index < 6 {
            keys[index].clone()
        } else {
            graph::challenge_key(record)
        };
        NativeHeldByteWitnessV1::new(families[index], key, d(111)).unwrap()
    });
    let generation = NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: d(112),
    };
    NativeHeldOwnerWitnessV1::Provider(ProviderNativeHeldWitnessV1 {
        root_local_cookie: 1,
        storage_local_cookie: 1,
        completion_sequence: 1,
        challenge_sequence: 1,
        authority: SourceProviderAuthorityV1::new(record.original.provider_id, 35, d(36)).unwrap(),
        native_namespace: d(113),
        catalog_head: generation,
        catalog_floor: generation,
        head_commitment: d(114),
        publication: d(115),
        selected_manifest: d(116),
        backend_manifest: d(117),
        verifier_manifest: d(118),
        records,
    })
    .to_canonical_bytes()
    .unwrap()
}

fn cold_closed(record: &SourceNativeHeldCompletionRecordV1) -> SourceNativeHeldCompletionRecordV1 {
    let root = record.suffix.controls()[0].clone();
    let assertion = RootNativeDispositionAssertionV1 {
        disposition: NativeHeldDispositionV1::Closed,
        observation: RootNativeObservationV1::PreparedOnly,
        scope: *root.scope(),
        source_artifact: d(0),
        descriptor_commitment: d(0),
        records: root_witness().records,
    };
    let closed = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        *root.scope(),
        root.digest(),
        vec![
            section(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Root(root_witness())
                    .to_canonical_bytes()
                    .unwrap(),
            ),
            section(Tag::RootPrepared, root.to_canonical_bytes()),
            section(
                Tag::RootDispositionAssertion,
                assertion.to_canonical_bytes().unwrap().to_vec(),
            ),
        ],
        root.prepared().signer().clone(),
    )
    .unwrap()
    .with_signature([0xA8; 64]);
    let relay = PreparedNativeHeldControlV1::new(
        Kind::ProviderRelay,
        evidence::full_scope(record).unwrap(),
        closed.digest(),
        vec![
            section(Tag::Witness, provider_witness(record)),
            section(Tag::RootDispositionControl, closed.to_canonical_bytes()),
        ],
        NativeHeldSignerV1::SourceProvider(
            record
                .original
                .canonical_request
                .as_ref()
                .unwrap()
                .signer()
                .clone(),
        ),
    )
    .unwrap();
    let mut original = record.original.clone();
    original.revision += 1;
    let mut controls = record.suffix.controls().to_vec();
    controls.push(closed);
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        7,
        record.suffix.flight(),
        Some(relay),
        controls,
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

#[test]
fn cold_closed_preserves_requested_or_prepared_outer_bytes_without_spend_or_active() {
    let requested = initial(request_tests::requested());
    let issued = advance(&requested, 1);
    let prepared = storage_prepared(&issued);
    for original in [requested, prepared] {
        let closed = cold_closed(&original);
        transition::validate_step(
            Some(&original),
            &closed,
            SourceNativeHeldStepV1::RootDispositionPrepared,
        )
        .unwrap();
        transition::validate_original(
            &original,
            &closed,
            SourceNativeHeldStepV1::RootDispositionPrepared,
        )
        .unwrap();
        let mut expected = original.original.clone();
        expected.revision += 1;
        assert_eq!(closed.original, expected);
        assert_ne!(closed.original.state, Outer::Active);
        let bytes = closed.to_canonical_bytes().unwrap();
        assert_eq!(
            SourceNativeHeldCompletionRecordV1::from_canonical_bytes(
                &native_completion::native_completion_key_v2(closed.original.acquisition_id),
                &bytes
            )
            .unwrap(),
            closed
        );
    }
}

#[test]
fn own_signature_storage_requires_exact_prepared_bytes_and_single_append() {
    let original = initial(request_tests::requested());
    let closed = cold_closed(&original);
    let prepared = closed.suffix.prepared().unwrap().clone();
    let mut controls = closed.suffix.controls().to_vec();
    controls.push(prepared.clone().with_signature([0xA5; 64]));
    let mut next_original = closed.original.clone();
    next_original.revision += 1;
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        7,
        closed.suffix.flight(),
        None,
        controls,
    )
    .unwrap();
    let stored = SourceNativeHeldCompletionRecordV1::new(next_original, suffix).unwrap();
    transition::validate_step(Some(&closed), &stored, SourceNativeHeldStepV1::RelayStored).unwrap();
    transition::validate_original(&closed, &stored, SourceNativeHeldStepV1::RelayStored).unwrap();
    assert!(
        transition::validate_step(
            Some(&original),
            &stored,
            SourceNativeHeldStepV1::RelayStored
        )
        .is_err()
    );
    assert!(
        transition::validate_step(Some(&stored), &closed, SourceNativeHeldStepV1::RelayStored)
            .is_err()
    );
    assert!(
        transition::validate_step(Some(&stored), &stored, SourceNativeHeldStepV1::RelayStored)
            .is_err()
    );
}

// Independent layout of the existing separate challenge journal value. This
// fixture creates bytes only, not that journal's issue/spend writer or token.
fn challenge_bytes(original: &Original, spent: bool) -> Vec<u8> {
    let mut bytes = vec![0; 296];
    bytes[..8].copy_from_slice(b"AOSZHC01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(&original.challenge);
    bytes[48..64].copy_from_slice(&original.provider_id);
    bytes[64..80].copy_from_slice(&original.holder_id);
    for (offset, value) in [
        (80, original.session_binding),
        (112, original.attempt_digest),
        (144, original.acquisition_id),
        (176, original.binding_digest),
        (208, original.publication_head),
    ] {
        bytes[offset..offset + 32].copy_from_slice(value.as_bytes());
    }
    bytes[240..248].copy_from_slice(&original.challenge_issued_seconds.to_be_bytes());
    bytes[248..256].copy_from_slice(&original.challenge_valid_until_seconds.to_be_bytes());
    bytes[256] = if spent { 2 } else { 1 };
    if spent {
        bytes[264..296].copy_from_slice(original.receipt_digest.as_bytes());
    }
    bytes
}

#[test]
fn challenge_checkpoints_join_exact_original_issue_and_spend_bytes() {
    let requested = initial(request_tests::requested());
    let issued = advance(&requested, 1);
    let prepared = storage_prepared(&issued);
    let spent = advance(&prepared, 3);
    for (record, is_spent) in [(&issued, false), (&spent, true)] {
        let bytes = challenge_bytes(&record.original, is_spent);
        graph::validate_challenge(record, Some(&bytes), is_spent).unwrap();
        assert!(graph::validate_challenge(record, None, is_spent).is_err());
        assert!(graph::validate_challenge(record, Some(&bytes), !is_spent).is_err());
        assert_eq!(
            graph::challenge_key(record),
            [b"AOSZHK01".as_slice(), &record.original.challenge].concat()
        );

        for offset in [
            0, 8, 10, 16, 48, 64, 80, 112, 144, 176, 208, 240, 248, 256, 257, 264,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                graph::validate_challenge(record, Some(&changed), is_spent).is_err(),
                "changed challenge field at {offset}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(graph::validate_challenge(record, Some(&trailing), is_spent).is_err());
        assert!(graph::validate_challenge(record, Some(&bytes[..295]), is_spent).is_err());
    }

    // The row comparison also checks the existing challenge lifetime contract;
    // matching supplied bytes cannot make an impossible original interval valid.
    let mut too_long = issued.clone();
    too_long.original.challenge_valid_until_seconds =
        too_long.original.challenge_issued_seconds + 61;
    assert!(
        graph::validate_challenge(
            &too_long,
            Some(&challenge_bytes(&too_long.original, false)),
            false
        )
        .is_err()
    );
}

#[test]
fn held_decoder_rejects_rehashed_wrong_profiles_and_truncated_artifacts() {
    let record = initial(request_tests::requested());
    let key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    let mut body = original_body(&record.original, b"AOSNCR05");
    body.extend_from_slice(&record.suffix.to_canonical_bytes().unwrap());
    for version in [0, 5, 6, 7, 9] {
        let bytes = independent_envelope(&record.original, version, &body);
        assert!(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &bytes).is_err());
    }
    for changed_body in [
        {
            let mut changed = body.clone();
            changed[..8].copy_from_slice(b"AOSNCR04");
            changed
        },
        {
            let mut changed = body.clone();
            changed[632..636].copy_from_slice(&u32::MAX.to_be_bytes());
            changed
        },
        body[..635].to_vec(),
        body[..body.len() - 1].to_vec(),
        {
            let mut changed = body.clone();
            changed.push(0);
            changed
        },
    ] {
        let bytes = independent_envelope(&record.original, 8, &changed_body);
        assert!(SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &bytes).is_err());
    }
    let mut changed_digest = record.to_canonical_bytes().unwrap();
    changed_digest[32] ^= 1;
    assert!(
        SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &changed_digest).is_err()
    );
}
