//! Pure canonical, whole-graph, signature and before/after regression vectors.
//!
//! These tests use genuine signed canonical legacy rows but no live descriptor,
//! protected journal, owner initializer, currentness factory or dispatch gate.

mod accepted;
mod fixture;
mod terminal;
mod v2;

use std::collections::BTreeMap;

use crate as protocol;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
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
        ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1,
        native_held_record_byte_digest_v1,
    },
};
use aos_sandbox_source_provider_protocol::{
    NativeAcquireCatalogBindingV3, SourceProviderKeyUsageV1,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::mount_source_acquisition_state::{
    SourceProviderQueryAttemptV2, SourceProviderSessionV2, StoredRecordV2, acquisition_key,
    encode_mount_source_state_record_v2, provider_attempt_key, provider_head_key,
    provider_session_key, validate_mount_source_state_graph_v2,
};

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

struct Fixture {
    legacy: BTreeMap<Vec<u8>, Vec<u8>>,
    session: SourceProviderSessionV2,
    attempt: SourceProviderQueryAttemptV2,
    scope: NativeHeldScopeV1,
    witness: RootNativeHeldWitnessV1,
}

impl Fixture {
    fn new(native: bool) -> Self {
        let catalog = native.then(|| {
            NativeAcquireCatalogBindingV3::new(
                digest(10),
                1,
                digest(62),
                1,
                digest(62),
                digest(63),
                digest(64),
            )
            .unwrap()
        });
        Self::with_catalog(catalog, [62; 32])
    }

    fn with_catalog(
        catalog: Option<NativeAcquireCatalogBindingV3>,
        catalog_digest: [u8; 32],
    ) -> Self {
        let session = fixture::signed_session([19; 16], 31);
        let catalog_claim = NativeHeldGenerationClaimV1 {
            generation: 1,
            digest: ObjectDigest::from_bytes(catalog_digest),
        };
        let rows = fixture::initial_signed_graph_with_catalog(
            session.clone(),
            500,
            catalog_digest,
            [63; 32],
            catalog,
        );
        let StoredRecordV2::ProviderQueryAttempt { value: attempt } = &rows[1] else {
            panic!("attempt fixture");
        };
        let legacy: BTreeMap<_, _> = rows
            .iter()
            .map(|row| encode_mount_source_state_record_v2(row).unwrap())
            .collect();
        let keys = [
            provider_session_key(session.session_id),
            provider_attempt_key(attempt.attempt_id),
            acquisition_key(attempt.owner.owner_id()),
            provider_head_key(
                session.scope.holder_authority_id,
                session.scope.provider_authority_id,
            ),
        ];
        let records: Vec<_> = keys
            .into_iter()
            .zip(ROOT_NATIVE_WITNESS_FAMILIES_V1)
            .map(|(key, family)| {
                let commitment =
                    native_held_record_byte_digest_v1(family, &key, &legacy[&key]).unwrap();
                NativeHeldByteWitnessV1::new(family, key, commitment).unwrap()
            })
            .collect();
        let root_request = ObjectDigest::from_bytes(attempt.signed_request_digest);
        let mount_attempt = ObjectDigest::from_bytes(attempt.attempt_id);
        let source_session = ObjectDigest::from_bytes(session.session_binding);
        let scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(root_request, mount_attempt, source_session),
            original_source_session: source_session,
            mount_attempt,
            provider_attempt: digest(0),
            provider_acquisition: ObjectDigest::from_bytes(
                attempt.provider_acquisition.unwrap().acquisition_id,
            ),
            original_root_request: root_request,
            original_native_request: digest(0),
        };
        let claim = |byte| NativeHeldGenerationClaimV1 {
            generation: 1,
            digest: digest(byte),
        };
        let witness = RootNativeHeldWitnessV1 {
            local_socket_cookie: 7,
            journal_sequence: 1,
            planning_sequence: 1,
            trust: claim(16),
            revocation: claim(17),
            provider_head: catalog_claim,
            provider_floor: catalog_claim,
            publication: digest(64),
            records: records.try_into().unwrap(),
        };
        Self {
            legacy,
            session,
            attempt: attempt.clone(),
            scope,
            witness,
        }
    }

    fn prepared(&self) -> PreparedNativeHeldControlV1 {
        PreparedNativeHeldControlV1::new(
            Kind::RootPrepared,
            self.scope,
            digest(0),
            vec![self.w()],
            NativeHeldSignerV1::SourceProvider(fixture::signer(
                [1; 16],
                [22; 16],
                SourceProviderKeyUsageV1::RootMountRecord,
                &SigningKey::from_bytes(&[12; 32]),
            )),
        )
        .unwrap()
    }

    fn w(&self) -> NativeHeldSectionV1 {
        NativeHeldSectionV1::new(
            Tag::Witness,
            NativeHeldOwnerWitnessV1::Root(self.witness.clone())
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap()
    }

    fn sidecar(
        &self,
        phase: u8,
        prepared: Option<PreparedNativeHeldControlV1>,
        controls: Vec<SignedNativeHeldControlV1>,
        r: Option<RootNativeDispositionAssertionV1>,
    ) -> RootNativeHeldSidecarV1 {
        RootNativeHeldSidecarV1::new(
            self.scope,
            [0; 16],
            r,
            None,
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Root,
                phase,
                self.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn phase0(&self) -> RootNativeHeldSidecarV1 {
        self.sidecar(0, Some(self.prepared()), Vec::new(), None)
    }

    fn phase1(&self) -> RootNativeHeldSidecarV1 {
        self.sidecar(1, None, vec![sign(self.prepared())], None)
    }

    fn closed(&self) -> RootNativeDispositionAssertionV1 {
        RootNativeDispositionAssertionV1 {
            disposition: NativeHeldDispositionV1::Closed,
            observation: RootNativeObservationV1::PreparedOnly,
            scope: self.scope,
            source_artifact: digest(0),
            descriptor_commitment: digest(0),
            records: self.witness.records.clone(),
        }
    }

    fn graph(&self, sidecar: &RootNativeHeldSidecarV1) -> RootNativeHeldGraphV1 {
        let mut rows = self.legacy.clone();
        rows.insert(
            native_root_sidecar_key_v1(self.attempt.attempt_id).unwrap(),
            sidecar.to_canonical_bytes().unwrap(),
        );
        checked(&rows).unwrap()
    }
}

fn sign(prepared: PreparedNativeHeldControlV1) -> SignedNativeHeldControlV1 {
    let signature = SigningKey::from_bytes(&[12; 32])
        .sign(&prepared.signature_message())
        .to_bytes();
    prepared.with_signature(signature)
}

fn checked(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> crate::mount_source_acquisition_state::Result<RootNativeHeldGraphV1> {
    validate_native_root_graph_v1(
        rows.iter()
            .map(|(key, bytes)| (key.as_slice(), bytes.as_slice())),
    )
}

#[test]
fn exact_binary_header_lengths_key_and_bound() {
    let fixture = Fixture::new(true);
    let sidecar = fixture.phase0();
    let suffix = sidecar.suffix().to_canonical_bytes().unwrap();
    let mut golden = b"AOSMHC01".to_vec();
    golden.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    golden.extend_from_slice(&fixture.scope.to_canonical_bytes());
    golden.extend_from_slice(&[0; 16]);
    golden.extend_from_slice(&[0; 12]);
    golden.extend_from_slice(&(suffix.len() as u32).to_be_bytes());
    golden.extend_from_slice(&suffix);

    let key = native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap();
    assert_eq!(key.len(), 68);
    assert_eq!(sidecar.to_canonical_bytes().unwrap(), golden);
    assert_eq!(
        RootNativeHeldSidecarV1::from_canonical_bytes(&key, &golden).unwrap(),
        sidecar
    );
    assert_eq!(
        MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1,
        16 + 224 + 16 + 16 + 722 + 104 + 2_156 + 106_648
    );
    assert!(native_root_sidecar_key_v1([0; 32]).is_err());
}

#[test]
fn rejects_reserved_lengths_trailing_wrong_key_and_oversize() {
    let fixture = Fixture::new(true);
    let bytes = fixture.phase0().to_canonical_bytes().unwrap();
    let key = native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap();
    for offset in [0, 8, 9, 10, 11, 12, 15, 256, 260, 264, 268] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            RootNativeHeldSidecarV1::from_canonical_bytes(&key, &changed).is_err(),
            "offset {offset}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RootNativeHeldSidecarV1::from_canonical_bytes(&key, &trailing).is_err());
    assert!(
        RootNativeHeldSidecarV1::from_canonical_bytes(
            &native_root_sidecar_key_v1([99; 32]).unwrap(),
            &bytes
        )
        .is_err()
    );
    assert!(RootNativeHeldSidecarV1::from_canonical_bytes(&key, &vec![0; 109_903]).is_err());
}

#[test]
fn whole_legacy_graph_is_preserved_and_unknown_near_keys_fail() {
    let fixture = Fixture::new(true);
    let original = validate_mount_source_state_graph_v2(
        fixture
            .legacy
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let graph = fixture.graph(&fixture.phase0());
    assert_eq!(graph.legacy().provider_attempts, original.provider_attempts);
    for (key, bytes) in &fixture.legacy {
        assert_eq!(graph.canonical_records().get(key), Some(bytes));
    }

    let mut extra = graph.canonical_records().clone();
    let mut near = native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap();
    near.push(0);
    extra.insert(near, vec![1]);
    assert!(checked(&extra).is_err());
    extra = graph.canonical_records().clone();
    extra.remove(&provider_session_key(fixture.session.session_id));
    assert!(checked(&extra).is_err());
}

#[test]
fn native_sidecar_does_not_upgrade_legacy_v2_request() {
    let fixture = Fixture::new(false);
    assert!(checked(&fixture.legacy).is_ok());
    let mut rows = fixture.legacy.clone();
    rows.insert(
        native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap(),
        fixture.phase0().to_canonical_bytes().unwrap(),
    );
    assert!(checked(&rows).is_err());
}

#[test]
fn atomic_admission_contains_actual_reservation_and_before_images() {
    let fixture = Fixture::new(true);
    let before = checked(&BTreeMap::new()).unwrap();
    let after = fixture.graph(&fixture.phase0());
    let proposal =
        validate_native_root_transition_v1(&before, &after, fixture.attempt.attempt_id, [80; 16])
            .unwrap();
    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV1::PreparedAssertionRecorded
    );
    assert_eq!(proposal.puts, *after.canonical_records());
    assert_eq!(proposal.puts.len(), 6);
    assert!(proposal.before_images.values().all(Option::is_none));
    assert_eq!(proposal.maximum_remaining_transactions, 7);
    let binding = proposal.admission_binding.unwrap();
    assert_eq!(binding.mount_attempt, fixture.attempt.attempt_id);
    assert_eq!(binding.provider_request_id, fixture.attempt.request_id);
    assert_eq!(
        binding.reserved_attempt_digest,
        fixture.attempt.record_digest
    );
    assert_eq!(binding.prepared_root_digest, fixture.prepared().digest());

    let already_reserved = checked(&fixture.legacy).unwrap();
    assert!(
        validate_native_root_transition_v1(
            &already_reserved,
            &after,
            fixture.attempt.attempt_id,
            [80; 16]
        )
        .is_err()
    );
    assert!(
        validate_native_root_cold_transition_v1(
            &before,
            &after,
            fixture.attempt.attempt_id,
            [80; 16]
        )
        .is_err()
    );
}

#[test]
fn exact_original_signature_store_and_cold_refusal() {
    let fixture = Fixture::new(true);
    let before = fixture.graph(&fixture.phase0());
    let after = fixture.graph(&fixture.phase1());
    let proposal =
        validate_native_root_transition_v1(&before, &after, fixture.attempt.attempt_id, [81; 16])
            .unwrap();
    assert_eq!(proposal.kind, RootNativeTransitionKindV1::PreparedStored);
    assert_eq!(proposal.puts.len(), 1);
    assert_eq!(proposal.maximum_remaining_transactions, 6);
    assert!(proposal.admission_binding.is_none());
    assert!(
        validate_native_root_cold_transition_v1(
            &before,
            &after,
            fixture.attempt.attempt_id,
            [81; 16]
        )
        .is_err()
    );

    let forged = fixture.sidecar(
        1,
        None,
        vec![fixture.prepared().with_signature([1; 64])],
        None,
    );
    let mut rows = fixture.legacy.clone();
    rows.insert(
        native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap(),
        forged.to_canonical_bytes().unwrap(),
    );
    assert!(checked(&rows).is_err());
}

#[test]
fn signed_store_cannot_substitute_another_valid_prepared_body() {
    let mut fixture = Fixture::new(true);
    let before = fixture.graph(&fixture.phase0());
    fixture.witness.journal_sequence += 1;
    let after = fixture.graph(&fixture.phase1());
    assert!(
        validate_native_root_transition_v1(&before, &after, fixture.attempt.attempt_id, [81; 16])
            .is_err()
    );
}

#[test]
fn nonzero_cas_identity_cannot_replace_actual_complete_attempt_evidence() {
    let fixture = Fixture::new(true);
    let sidecar = RootNativeHeldSidecarV1::new(
        fixture.scope,
        [97; 16],
        Some(fixture.closed()),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            Owner::Root,
            10,
            fixture.scope.flight,
            None,
            vec![sign(fixture.prepared())],
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

#[test]
fn before_byte_witness_and_original_trust_cut_are_not_replaceable() {
    let mut fixture = Fixture::new(true);
    fixture.witness.trust.digest = digest(90);
    let mut rows = fixture.legacy.clone();
    rows.insert(
        native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap(),
        fixture.phase0().to_canonical_bytes().unwrap(),
    );
    assert!(checked(&rows).is_err());

    let mut fixture = Fixture::new(true);
    let key = provider_attempt_key(fixture.attempt.attempt_id);
    fixture.witness.records[1] =
        NativeHeldByteWitnessV1::new(ROOT_NATIVE_WITNESS_FAMILIES_V1[1], key, digest(91)).unwrap();
    rows = fixture.legacy.clone();
    rows.insert(
        native_root_sidecar_key_v1(fixture.attempt.attempt_id).unwrap(),
        fixture.phase0().to_canonical_bytes().unwrap(),
    );
    assert!(checked(&rows).is_err());
}

#[test]
fn cold_unsigned_prefix_closes_without_inventing_signed_original_or_terminal() {
    let fixture = Fixture::new(true);
    let before = fixture.graph(&fixture.phase0());
    let closed = fixture.sidecar(10, None, Vec::new(), Some(fixture.closed()));
    let after = fixture.graph(&closed);
    let proposal = validate_native_root_cold_transition_v1(
        &before,
        &after,
        fixture.attempt.attempt_id,
        [82; 16],
    )
    .unwrap();
    assert_eq!(
        proposal.kind,
        RootNativeTransitionKindV1::ClosedAssertionRecorded
    );
    assert_eq!(proposal.maximum_remaining_transactions, 3);
    assert!(closed.suffix().controls().is_empty());
    assert!(closed.settlement().is_none());
    assert!(
        validate_native_root_transition_v1(&after, &before, fixture.attempt.attempt_id, [83; 16])
            .is_err()
    );
}

#[test]
fn signed_prepared_closed_assertion_is_exact_append_once() {
    let fixture = Fixture::new(true);
    let one = sign(fixture.prepared());
    let r = fixture.closed();
    let eight = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        fixture.scope,
        one.digest(),
        vec![
            fixture.w(),
            NativeHeldSectionV1::new(Tag::RootPrepared, one.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        one.prepared().signer().clone(),
    )
    .unwrap();
    let before = fixture.graph(&fixture.phase1());
    let closed = fixture.sidecar(10, Some(eight.clone()), vec![one.clone()], Some(r.clone()));
    let after = fixture.graph(&closed);
    validate_native_root_cold_transition_v1(&before, &after, fixture.attempt.attempt_id, [84; 16])
        .unwrap();
    let stored = fixture.sidecar(11, None, vec![one, sign(eight)], Some(r));
    let last = fixture.graph(&stored);
    assert_eq!(
        validate_native_root_transition_v1(&after, &last, fixture.attempt.attempt_id, [85; 16])
            .unwrap()
            .kind,
        RootNativeTransitionKindV1::DispositionStored
    );
    assert!(
        validate_native_root_cold_transition_v1(
            &after,
            &last,
            fixture.attempt.attempt_id,
            [85; 16]
        )
        .is_err()
    );
    assert!(
        validate_native_root_transition_v1(&last, &after, fixture.attempt.attempt_id, [86; 16])
            .is_err()
    );
}

#[test]
fn duplicate_has_no_puts_and_new_append_requires_actual_transaction_identity() {
    let fixture = Fixture::new(true);
    let before = fixture.graph(&fixture.phase0());
    let duplicate =
        validate_native_root_transition_v1(&before, &before, fixture.attempt.attempt_id, [0; 16])
            .unwrap();
    assert_eq!(duplicate.kind, RootNativeTransitionKindV1::Duplicate);
    assert!(duplicate.puts.is_empty());
    assert!(duplicate.before_images.is_empty());
    assert!(
        validate_native_root_transition_v1(
            &before,
            &fixture.graph(&fixture.phase1()),
            fixture.attempt.attempt_id,
            [0; 16]
        )
        .is_err()
    );
}

#[test]
fn verifier_projection_roundtrip_rejects_role_expiry_supersession_and_raw_key() {
    let fixture = Fixture::new(true);
    let verifier = RootNativeTerminalVerifierV1 {
        trust_generation: 1,
        trust_digest: digest(16),
        revocation_generation: 1,
        revocation_digest: digest(17),
        verified_at_seconds: 100,
        signer: fixture.session.signers[3].clone(),
    };
    let bytes = verifier.to_canonical_bytes().unwrap();
    assert_eq!(
        RootNativeTerminalVerifierV1::from_canonical_bytes(&bytes).unwrap(),
        verifier
    );
    assert!(bytes.len() <= MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1);
    let mut wrong = verifier.clone();
    wrong.signer = fixture.session.signers[1].clone();
    assert!(wrong.to_canonical_bytes().is_err());
    let mut wrong = verifier.clone();
    wrong.verified_at_seconds = 1000;
    assert!(wrong.to_canonical_bytes().is_err());
    let mut wrong = verifier.clone();
    wrong.signer.superseded_by_key_generation = 2;
    assert!(wrong.to_canonical_bytes().is_err());
    let mut wrong = verifier.clone();
    wrong.signer.public_key[0] ^= 1;
    assert!(wrong.to_canonical_bytes().is_err());
    let mut wrong = bytes;
    wrong[12] = 1;
    assert!(RootNativeTerminalVerifierV1::from_canonical_bytes(&wrong).is_err());
}
