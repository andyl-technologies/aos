//! Synthetic canonical/reducer/geometry fixtures, never live owner evidence.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::assertion::*;
use aos_sandbox_source_provider_protocol::native_held_completion::frame::*;
use aos_sandbox_source_provider_protocol::native_held_completion::native_held_flight_digest_v1;
use aos_sandbox_source_provider_protocol::native_held_completion::recovery::*;
use aos_sandbox_source_provider_protocol::native_held_completion::witness::*;
use aos_sandbox_source_provider_protocol::{SourceProviderAuthorityV1, StorageZfsHoldSignerV1};
use sha2::{Digest as _, Sha256};

use super::*;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn section(tag: Tag, bytes: Vec<u8>) -> NativeHeldSectionV1 {
    NativeHeldSectionV1::new(tag, bytes).unwrap()
}

fn witness(family: NativeHeldRecordFamilyV1) -> NativeHeldByteWitnessV1 {
    let prefix: &[u8] = match family {
        NativeHeldRecordFamilyV1::RootSession => b"aos.mount.source-provider-session.v2\0",
        NativeHeldRecordFamilyV1::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
        NativeHeldRecordFamilyV1::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
        NativeHeldRecordFamilyV1::RootHead => b"aos.mount.source-provider-head.v2\0",
        NativeHeldRecordFamilyV1::ProviderAuthority => b"aos.source-provider.authority.v1\0",
        NativeHeldRecordFamilyV1::ProviderAttempt => b"aos.source-provider.attempt.v1\0",
        NativeHeldRecordFamilyV1::ProviderAcquisition => b"aos.source-provider.acquisition.v1\0",
        NativeHeldRecordFamilyV1::ProviderHolder => b"aos.source-provider.session.v1\0",
        NativeHeldRecordFamilyV1::ProviderHistory => b"aos.source-provider.session-history.v1\0",
        NativeHeldRecordFamilyV1::ProviderNative => b"AOSNCK02",
        NativeHeldRecordFamilyV1::Challenge => b"AOSZHK01",
        NativeHeldRecordFamilyV1::StorageIssuance => b"",
    };
    let mut key = prefix.to_vec();
    key.resize(family.key_bytes(), 1);
    NativeHeldByteWitnessV1::new(family, key, d(1)).unwrap()
}

fn generation() -> NativeHeldGenerationClaimV1 {
    NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: d(1),
    }
}

struct Fixture {
    original: NativeIssuanceRowV1,
    root_scope: NativeHeldScopeV1,
    scope: NativeHeldScopeV1,
    root_witness: RootNativeHeldWitnessV1,
    root_prepared: SignedNativeHeldControlV1,
    root: RootNativeDispositionAssertionV1,
    relay: SignedNativeHeldControlV1,
}

impl Fixture {
    fn new(sequence: u8) -> Self {
        let original = super::super::super::tests::fixture(sequence, sequence + 1).row;
        Self::from_original(original)
    }

    fn from_original(original: NativeIssuanceRowV1) -> Self {
        let claims = original.request.request().claims();
        let root_request = digest_signed_request(original.request.request().signed_root_request());
        let root_scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(root_request, d(70), claims.holder_session().1),
            original_source_session: claims.holder_session().1,
            mount_attempt: d(70),
            provider_attempt: d(0),
            provider_acquisition: claims.provider_acquisition().1,
            original_root_request: root_request,
            original_native_request: d(0),
        };
        let scope = NativeHeldScopeV1 {
            provider_attempt: claims.attempt().1,
            original_native_request: original.request.digest(),
            ..root_scope
        };
        let root_witness = RootNativeHeldWitnessV1 {
            local_socket_cookie: 1,
            journal_sequence: 1,
            planning_sequence: 1,
            trust: generation(),
            revocation: generation(),
            provider_head: generation(),
            provider_floor: generation(),
            publication: d(1),
            records: ROOT_NATIVE_WITNESS_FAMILIES_V1.map(witness),
        };
        let root_signer = NativeHeldSignerV1::SourceProvider(
            original
                .request
                .request()
                .signed_root_request()
                .signer()
                .clone(),
        );
        let root_prepared = PreparedNativeHeldControlV1::new(
            Kind::RootPrepared,
            root_scope,
            d(0),
            vec![section(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Root(root_witness.clone())
                    .to_canonical_bytes()
                    .unwrap(),
            )],
            root_signer.clone(),
        )
        .unwrap()
        .with_signature([1; 64]);
        let root = RootNativeDispositionAssertionV1 {
            disposition: NativeHeldDispositionV1::Closed,
            observation: RootNativeObservationV1::PreparedOnly,
            scope: root_scope,
            source_artifact: d(0),
            descriptor_commitment: d(0),
            records: root_witness.records.clone(),
        };
        let closed = PreparedNativeHeldControlV1::new(
            Kind::RootClosed,
            root_scope,
            root_prepared.digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Root(root_witness.clone())
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(Tag::RootPrepared, root_prepared.to_canonical_bytes()),
                section(
                    Tag::RootDispositionAssertion,
                    root.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            root_signer,
        )
        .unwrap()
        .with_signature([2; 64]);
        let provider_witness = ProviderNativeHeldWitnessV1 {
            root_local_cookie: 1,
            storage_local_cookie: 2,
            completion_sequence: 3,
            challenge_sequence: 4,
            authority: SourceProviderAuthorityV1::new([1; 16], 1, d(1)).unwrap(),
            native_namespace: d(1),
            catalog_head: generation(),
            catalog_floor: generation(),
            head_commitment: d(1),
            publication: d(1),
            selected_manifest: d(1),
            backend_manifest: d(1),
            verifier_manifest: d(1),
            records: PROVIDER_NATIVE_WITNESS_FAMILIES_V1.map(witness),
        };
        let relay = PreparedNativeHeldControlV1::new(
            Kind::ProviderRelay,
            scope,
            closed.digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Provider(provider_witness)
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(Tag::RootDispositionControl, closed.to_canonical_bytes()),
            ],
            NativeHeldSignerV1::SourceProvider(original.request.signer().clone()),
        )
        .unwrap()
        .with_signature([3; 64]);
        Self {
            original,
            root_scope,
            scope,
            root_witness,
            root_prepared,
            root,
            relay,
        }
    }

    fn row(
        &self,
        phase: u8,
        prepared: Option<PreparedNativeHeldControlV1>,
        controls: Vec<SignedNativeHeldControlV1>,
    ) -> StorageHeldIssuanceRowV2 {
        StorageHeldIssuanceRowV2::new(
            self.original.request.clone(),
            self.original.acceptance.clone(),
            None,
            NativeHeldCompletionSuffixV1::new(
                Owner::Storage,
                phase,
                self.scope.flight,
                prepared,
                controls,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn initial(&self) -> StorageHeldIssuanceRowV2 {
        self.row(0, None, vec![self.root_prepared.clone()])
    }

    fn original_v3() -> Self {
        use aos_sandbox_source_provider_protocol::{
            AcquireSourceRequestV1, NativeAcquireCatalogBindingV3, SourceProviderMethod,
            StorageNativeAcquireRequestV2, decode_acquire_request, encode_acquire_request,
            sign_request,
        };
        let mut original = super::super::super::tests::fixture(1, 2).row;
        let request = original.request.request();
        let claims = request.claims();
        let catalog = claims.catalog();
        let native = NativeAcquireCatalogBindingV3::new(
            catalog.namespace_digest(),
            catalog.generation(),
            catalog.digest(),
            catalog.generation(),
            catalog.digest(),
            claims.selection().1,
            d(77),
        )
        .unwrap();
        let root = AcquireSourceRequestV1::new_native_v3(
            decode_acquire_request(request.signed_root_request().subject()).unwrap(),
            native,
        )
        .unwrap();
        let signed_root = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root),
            request.signed_root_request().signer().clone(),
            &ed25519_dalek::SigningKey::from_bytes(&[28; 32]),
        )
        .unwrap();
        original.request = SignedStorageNativeAcquireRequestV2::sign(
            StorageNativeAcquireRequestV2::new_native_v3(claims.clone(), signed_root).unwrap(),
            original.request.signer().clone(),
            &ed25519_dalek::SigningKey::from_bytes(&[32; 32]),
        )
        .unwrap();
        let old = &original.acceptance;
        original.acceptance = StorageNativeAcceptanceV3::new(
            old.issuance_id(),
            original.request.digest(),
            old.receipt_digest(),
            old.descriptor().clone(),
            old.topology().clone(),
        )
        .unwrap();
        Self::from_original(original)
    }

    fn with_reply(
        mut self,
    ) -> (
        Self,
        aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3,
    ) {
        use aos_sandbox_source_provider_protocol::{
            SignedStorageNativeAcceptanceV3, SignedStorageZfsHoldReceiptV1,
            StorageNativeAcquireReplyV3, StorageZfsHoldHeadV1, StorageZfsHoldReceiptV1,
            storage_native_nonrecursive_topology_v1,
        };
        let claims = self.original.request.request().claims();
        let catalog = claims.catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                claims.selection().0,
            )
            .unwrap();
        let NativeHeldSignerV1::Storage(signer) = self.storage_signer() else {
            unreachable!()
        };
        let receipt = SignedStorageZfsHoldReceiptV1::new(
            StorageZfsHoldReceiptV1::new(
                claims.attempt().0,
                claims.attempt().1,
                claims.selection().0,
                resource,
                snapshot,
                StorageZfsHoldHeadV1::new(
                    catalog.generation(),
                    catalog.digest(),
                    1,
                    d(1),
                    1,
                    d(1),
                    d(1),
                )
                .unwrap(),
                100,
                150,
            )
            .unwrap(),
            signer,
            [9; 64],
        );
        let descriptor = self.original.acceptance.descriptor().clone();
        let topology = storage_native_nonrecursive_topology_v1(
            &self.original.request,
            &receipt,
            &descriptor,
            2,
            55,
        )
        .unwrap();
        self.original.acceptance = StorageNativeAcceptanceV3::new(
            self.original.acceptance.issuance_id(),
            self.original.request.digest(),
            receipt.digest(),
            descriptor,
            topology,
        )
        .unwrap();
        let acceptance = SignedStorageNativeAcceptanceV3::sign(
            self.original.acceptance.clone(),
            signer,
            &ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
        );
        let reply = StorageNativeAcquireReplyV3::new(acceptance, receipt).unwrap();
        (self, reply)
    }

    fn held_prepared(
        &self,
        before: &StorageHeldIssuanceRowV2,
        reply: &aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3,
    ) -> PreparedNativeHeldControlV1 {
        let witness = StorageNativeHeldWitnessV1 {
            local_socket_cookie: 1,
            primary_sequence: 1,
            workspace_sequence: 1,
            request_trust_sequence: 1,
            issuance_sequence: 1,
            request_trust_generation: 1,
            request_trust_file: d(1),
            issuance: self.byte_witness(before),
        };
        PreparedNativeHeldControlV1::new(
            Kind::StorageHeld,
            self.scope,
            self.root_prepared.digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Storage(witness)
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(Tag::RootPrepared, self.root_prepared.to_canonical_bytes()),
                section(Tag::NativeReply, reply.to_canonical_bytes()),
            ],
            self.storage_signer(),
        )
        .unwrap()
    }

    fn disposition(&self) -> StorageHeldIssuanceRowV2 {
        self.row(
            3,
            None,
            vec![self.root_prepared.clone(), self.relay.clone()],
        )
    }

    fn storage_signer(&self) -> NativeHeldSignerV1 {
        NativeHeldSignerV1::Storage(
            StorageZfsHoldSignerV1::new([1; 16], 1, d(1), [2; 16], 1).unwrap(),
        )
    }

    fn byte_witness(&self, before: &StorageHeldIssuanceRowV2) -> NativeHeldByteWitnessV1 {
        NativeHeldByteWitnessV1::new(
            NativeHeldRecordFamilyV1::StorageIssuance,
            before.key().to_vec(),
            native_held_record_byte_digest_v1(
                NativeHeldRecordFamilyV1::StorageIssuance,
                &before.key(),
                &before.to_canonical_bytes().unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn normal_prepared(
        &self,
        before: &StorageHeldIssuanceRowV2,
        sequence: u64,
    ) -> PreparedNativeHeldControlV1 {
        let own = before.settlement().unwrap().unwrap();
        let witness = StorageNativeHeldWitnessV1 {
            local_socket_cookie: 1,
            primary_sequence: 1,
            workspace_sequence: 1,
            request_trust_sequence: 1,
            issuance_sequence: sequence,
            request_trust_generation: 1,
            request_trust_file: d(1),
            issuance: self.byte_witness(before),
        };
        let settlement = NativeHeldSettlementV1 {
            disposition: own.disposition,
            root_disposition: own.root_disposition,
            storage_settlement: own.digest().unwrap(),
            provider_settlement: d(0),
        };
        PreparedNativeHeldControlV1::new(
            Kind::StorageSettled,
            self.scope,
            self.relay.digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Storage(witness)
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            self.storage_signer(),
        )
        .unwrap()
    }

    fn settled(&self) -> StorageHeldIssuanceRowV2 {
        let before = self.disposition();
        let signed = self.normal_prepared(&before, 7).with_signature([4; 64]);
        let mut controls = before.suffix.controls().to_vec();
        controls.push(signed);
        self.row(4, None, controls)
    }

    fn query(&self, nonce: u8) -> SignedNativeHeldControlV1 {
        let query = NativeHeldRecoveryQueryV1 {
            recovery_session: d(80),
            nonce: [nonce; 32],
            sequence: 1,
            mode: NativeHeldRecoveryModeV1::SettleRecordedDisposition,
            target: NativeHeldRecoveryTargetV1::RootScope,
            original_prepared: self.root_prepared.digest(),
            parent_root_query: d(0),
        };
        let state = RootNativeRecoveryAssertionV1 {
            phase: 10,
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            cold_custody: NativeHeldColdCustodyV1::Unavailable,
            diagnostic_sequence: 10,
            records: self.root_witness.records.clone(),
            disposition: Some(self.root.clone()),
            hot_archive: None,
            settlement: None,
        };
        let root = PreparedNativeHeldControlV1::new(
            Kind::RootRecoveryQuery,
            self.root_scope,
            d(0),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(
                    Tag::RootRecoveryAssertion,
                    state.to_canonical_bytes().unwrap(),
                ),
            ],
            NativeHeldSignerV1::SourceProvider(
                self.original
                    .request
                    .request()
                    .signed_root_request()
                    .signer()
                    .clone(),
            ),
        )
        .unwrap()
        .with_signature([5; 64]);
        let child = NativeHeldRecoveryQueryV1 {
            target: NativeHeldRecoveryTargetV1::NativeScope,
            parent_root_query: root.digest(),
            ..query
        };
        PreparedNativeHeldControlV1::new(
            Kind::ProviderStorageRecoveryQuery,
            self.scope,
            root.digest(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    child.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(Tag::RootRecoveryControl, root.to_canonical_bytes()),
            ],
            NativeHeldSignerV1::SourceProvider(self.original.request.signer().clone()),
        )
        .unwrap()
        .with_signature([6; 64])
    }

    fn recovery(
        &self,
        before: &StorageHeldIssuanceRowV2,
        query: &SignedNativeHeldControlV1,
        sequence: u64,
        forged: bool,
    ) -> PreparedNativeHeldControlV1 {
        let own = before.settlement().unwrap().unwrap();
        let witness = if forged {
            NativeHeldByteWitnessV1::new(
                NativeHeldRecordFamilyV1::StorageIssuance,
                before.key().to_vec(),
                d(99),
            )
            .unwrap()
        } else {
            self.byte_witness(before)
        };
        let state = StorageNativeRecoveryStateV1 {
            fields: NativeHeldRecoveryFieldsV1 {
                phase: before.suffix.phase(),
                runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
                row_class: NativeHeldRecoveryRowClassV1::Native,
                child_status: NativeHeldRecoveryChildStatusV1::NotQueried,
                diagnostic_sequence: sequence,
                native_request: self.original.request.digest(),
                acceptance: self.original.acceptance.digest(),
                root_disposition: own.root_disposition,
                storage_settlement: own.digest().unwrap(),
                provider_settlement: d(0),
                witness: Some(witness),
                disposition: Some(self.root.clone()),
                own_assertion: own.to_canonical_bytes().unwrap().to_vec(),
                hot_terminal: before
                    .suffix
                    .control(Kind::StorageSettled)
                    .map(SignedNativeHeldControlV1::to_canonical_bytes),
                child: None,
            },
        };
        PreparedNativeHeldControlV1::new(
            Kind::StorageRecoveryState,
            self.scope,
            query.digest(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.section(Tag::RecoveryQuery).unwrap().to_vec(),
                ),
                section(
                    Tag::StorageRecoveryState,
                    state.to_canonical_bytes().unwrap(),
                ),
            ],
            self.storage_signer(),
        )
        .unwrap()
    }

    fn r4(&self, before: &StorageHeldIssuanceRowV2, sequence: u64) -> StorageHeldIssuanceRowV2 {
        let query = self.query(81);
        let response = self
            .recovery(before, &query, sequence, false)
            .with_signature([7; 64]);
        let mut controls = before.suffix.controls().to_vec();
        controls.extend([query, response]);
        self.row(4, None, controls)
    }
}

fn state(row: &StorageHeldIssuanceRowV2) -> BTreeMap<[u8; 48], Vec<u8>> {
    BTreeMap::from([(row.key(), row.to_canonical_bytes().unwrap())])
}

#[test]
fn legacy_bytes_and_identity_remain_exact_and_cannot_be_upgraded() {
    let fixture = Fixture::new(1);
    let row = &fixture.original;
    // Independent literal framing; none of the new codecs supplies the golden.
    let mut golden = b"AOSNSI01".to_vec();
    golden.extend_from_slice(&1_u16.to_be_bytes());
    golden.extend_from_slice(&[0; 70]);
    golden.extend_from_slice(&(row.request.to_canonical_bytes().len() as u32).to_be_bytes());
    golden.extend_from_slice(&216_u32.to_be_bytes());
    golden.extend_from_slice(&row.request.to_canonical_bytes());
    golden.extend_from_slice(&row.acceptance.to_canonical_bytes());
    assert_eq!(row.encode().unwrap(), golden);
    let decoded = StorageIssuanceValueV1::from_canonical_bytes(&golden).unwrap();
    assert_eq!(decoded.to_canonical_bytes().unwrap(), golden);
    assert_eq!(decoded.original().key(), row.key());
    let claims = row.request.request().claims();
    let mut key = claims.provider_acquisition().0.to_vec();
    key.extend_from_slice(claims.provider_acquisition().1.as_bytes());
    assert_eq!(row.key().as_slice(), key);
    let expected_id = Sha256::new()
        .chain_update(b"aos.sandbox.storage.native-issuance.transaction.v1\0")
        .chain_update(&key)
        .chain_update(&golden)
        .finalize();
    assert_eq!(
        row.transaction().unwrap().id().as_slice(),
        &expected_id[..16]
    );
    assert!(StorageHeldIssuanceRowV2::from_canonical_bytes(&golden).is_err());
    assert!(
        reduce(
            &BTreeMap::from([(row.key(), golden)]),
            &state(&fixture.initial()),
            0,
            StorageHeldStepV1::InterestRecorded
        )
        .is_err()
    );
}

#[test]
fn held_codec_retains_original_nested_bytes_and_has_no_extra_length() {
    let fixture = Fixture::new(1);
    let row = fixture.initial();
    let bytes = row.to_canonical_bytes().unwrap();
    let original = fixture.original.encode().unwrap();
    assert_eq!(&bytes[..8], b"AOSNSI02");
    assert_eq!(&bytes[10..original.len()], &original[10..]);
    let mut suffix = b"AOSNHS01".to_vec();
    suffix.extend_from_slice(&[0, 1, 3, 0, 0, 0, 0, 0]);
    suffix.extend_from_slice(fixture.scope.flight.as_bytes());
    suffix.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0]);
    suffix.extend_from_slice(&[1, 0, 0, 0]);
    suffix.extend_from_slice(
        &(fixture.root_prepared.to_canonical_bytes().len() as u32).to_be_bytes(),
    );
    suffix.extend_from_slice(&fixture.root_prepared.to_canonical_bytes());
    assert_eq!(&bytes[original.len()..], suffix);
    let decoded = StorageHeldIssuanceRowV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, row);
    assert_eq!(decoded.original.request, fixture.original.request);
    assert_eq!(decoded.original.acceptance, fixture.original.acceptance);
    assert!(NativeIssuanceRowV1::decode(&bytes).is_err());
}

#[test]
fn original_v3_data_and_both_pinned_signatures_are_preserved_without_admission() {
    let fixture = Fixture::original_v3();
    let row = fixture.initial();
    let decoded =
        StorageHeldIssuanceRowV2::from_canonical_bytes(&row.to_canonical_bytes().unwrap()).unwrap();
    let root = decoded.original.request.request().signed_root_request();
    assert_eq!(
        aos_sandbox_source_provider_protocol::decode_acquire_request(root.subject())
            .unwrap()
            .version(),
        3
    );
    assert_eq!(decoded.original.request, fixture.original.request);
    decoded
        .original
        .request
        .verify(
            decoded.original.request.signer(),
            &ed25519_dalek::SigningKey::from_bytes(&[32; 32])
                .verifying_key()
                .to_bytes(),
            root.signer(),
            &ed25519_dalek::SigningKey::from_bytes(&[28; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
    // An unrelated original request cannot inherit another row's signed controls.
    assert!(
        StorageHeldIssuanceRowV2::new(
            fixture.original.request.clone(),
            fixture.original.acceptance.clone(),
            None,
            Fixture::new(1).initial().suffix
        )
        .is_err()
    );
}

#[test]
fn actual_normal_recovery_retirement_chain_has_eight_distinct_data_appends() {
    let (fixture, reply) = Fixture::new(1).with_reply();
    let initial = fixture.initial();
    let held = fixture.held_prepared(&initial, &reply);
    let held_prepared = fixture.row(1, Some(held.clone()), initial.suffix.controls().to_vec());
    let mut controls = initial.suffix.controls().to_vec();
    controls.push(held.with_signature([8; 64]));
    let held_stored = fixture.row(2, None, controls.clone());
    controls.push(fixture.relay.clone());
    let root = fixture.row(3, None, controls.clone());
    let prepared = fixture.normal_prepared(&root, 10);
    let settlement_prepared = fixture.row(3, Some(prepared.clone()), controls.clone());
    controls.push(prepared.with_signature([4; 64]));
    let settled = fixture.row(4, None, controls);
    let recovered = fixture.r4(&settled, 16);
    let retired = StorageHeldIssuanceRowV2::new(
        recovered.original.request.clone(),
        recovered.original.acceptance.clone(),
        Some((d(91), d(92))),
        NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            5,
            fixture.scope.flight,
            None,
            recovered.suffix.controls().to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let rows = [
        initial,
        held_prepared,
        held_stored,
        root,
        settlement_prepared,
        settled,
        recovered,
        retired,
    ];
    let steps = [
        StorageHeldStepV1::InterestRecorded,
        StorageHeldStepV1::HeldPrepared,
        StorageHeldStepV1::HeldStored,
        StorageHeldStepV1::RootDispositionRecorded,
        StorageHeldStepV1::SettlementPrepared,
        StorageHeldStepV1::SettlementStored,
        StorageHeldStepV1::AlreadySettledRecoveryProofRecorded,
        StorageHeldStepV1::RetirementRecorded,
    ];
    let sequences = [0, 1, 4, 7, 10, 13, 16, 19];
    let mut before = BTreeMap::new();
    let mut identities = std::collections::BTreeSet::new();
    for (index, ((row, step), sequence)) in rows.iter().zip(steps).zip(sequences).enumerate() {
        let after = state(row);
        let transaction = reduce(&before, &after, sequence, step)
            .unwrap()
            .transaction
            .unwrap();
        assert!(identities.insert(*transaction.id()));
        assert_eq!(
            remaining_capacity_profile(&after)
                .unwrap()
                .remaining_transactions,
            7 - index
        );
        before = after;
    }
    assert_eq!(identities.len(), 8);
    assert!(
        reduce(
            &before,
            &before,
            22,
            StorageHeldStepV1::AlreadySettledRecoveryProofRecorded
        )
        .is_err()
    );
}

#[test]
fn canonical_decoder_rejects_tails_versions_bounds_and_nested_mutations() {
    let row = Fixture::new(1).initial();
    let bytes = row.to_canonical_bytes().unwrap();
    for offset in [0, 8, 10, 80, 84, HEADER_BYTES, bytes.len() - 65] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            StorageHeldIssuanceRowV2::from_canonical_bytes(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut tail = bytes.clone();
    tail.push(0);
    assert!(StorageHeldIssuanceRowV2::from_canonical_bytes(&tail).is_err());
    assert!(StorageHeldIssuanceRowV2::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(
        StorageHeldIssuanceRowV2::from_canonical_bytes(&vec![
            0;
            MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2
                + 1
        ])
        .is_err()
    );
    assert_eq!(
        MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2,
        super::super::super::MAXIMUM_VALUE_BYTES + 106_648
    );
}

#[test]
fn exact_prepared_successor_replay_and_unrelated_rows_are_checked() {
    let fixture = Fixture::new(1);
    let before = fixture.disposition();
    let prepared = fixture.normal_prepared(&before, 7);
    let preparing = fixture.row(3, Some(prepared.clone()), before.suffix.controls().to_vec());
    reduce(
        &state(&before),
        &state(&preparing),
        7,
        StorageHeldStepV1::SettlementPrepared,
    )
    .unwrap();
    assert!(
        reduce(
            &state(&before),
            &state(&preparing),
            8,
            StorageHeldStepV1::SettlementPrepared
        )
        .is_err()
    );
    let mut controls = before.suffix.controls().to_vec();
    controls.push(prepared.with_signature([4; 64]));
    let stored = fixture.row(4, None, controls);
    reduce(
        &state(&preparing),
        &state(&stored),
        10,
        StorageHeldStepV1::SettlementStored,
    )
    .unwrap();
    assert!(
        reduce(
            &state(&before),
            &state(&stored),
            7,
            StorageHeldStepV1::SettlementStored
        )
        .is_err()
    );
    assert!(
        reduce(
            &state(&stored),
            &state(&stored),
            13,
            StorageHeldStepV1::ExactReplay
        )
        .unwrap()
        .transaction
        .is_none()
    );
    assert!(
        reduce(
            &state(&before),
            &state(&stored),
            7,
            StorageHeldStepV1::ExactReplay
        )
        .is_err()
    );
    let other = Fixture::new(3).initial();
    let mut after = state(&stored);
    after.extend(state(&other));
    assert!(
        reduce(
            &state(&preparing),
            &after,
            10,
            StorageHeldStepV1::SettlementStored
        )
        .is_err()
    );
    let mut both_before = state(&preparing);
    both_before.extend(state(&other));
    reduce(
        &both_before,
        &after,
        10,
        StorageHeldStepV1::SettlementStored,
    )
    .unwrap();
}

#[test]
fn r4_is_exact_before_minus_only_two_slots_and_diagnostic_sequence() {
    let fixture = Fixture::new(1);
    let before = fixture.settled();
    let after = fixture.r4(&before, 13);
    let result = reduce(
        &state(&before),
        &state(&after),
        13,
        StorageHeldStepV1::AlreadySettledRecoveryProofRecorded,
    )
    .unwrap();
    assert_eq!(result.transaction.unwrap().records().len(), 1);
    assert_eq!(before.settlement().unwrap(), after.settlement().unwrap());
    assert_eq!(before.original, after.original);
    assert_eq!(
        after.suffix.controls()[before.suffix.controls().len()].kind(),
        Kind::ProviderStorageRecoveryQuery
    );
    assert_eq!(
        after.suffix.controls().last().unwrap().kind(),
        Kind::StorageRecoveryState
    );
    assert_eq!(
        StorageHeldIssuanceRowV2::from_canonical_bytes(&after.to_canonical_bytes().unwrap())
            .unwrap(),
        after
    );
    assert!(
        reduce(
            &state(&before),
            &state(&after),
            14,
            StorageHeldStepV1::AlreadySettledRecoveryProofRecorded
        )
        .is_err()
    );
    assert!(
        reduce(
            &state(&after),
            &state(&after),
            16,
            StorageHeldStepV1::AlreadySettledRecoveryProofRecorded
        )
        .is_err()
    );
    let query = fixture.query(81);
    let response = fixture
        .recovery(&before, &query, 13, true)
        .with_signature([7; 64]);
    let mut controls = before.suffix.controls().to_vec();
    controls.extend([query, response]);
    let forged = StorageHeldIssuanceRowV2 {
        original: before.original.clone(),
        suffix: NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            4,
            fixture.scope.flight,
            None,
            controls,
        )
        .unwrap(),
    };
    assert!(forged.to_canonical_bytes().is_err());

    let occupied = after.suffix.controls().last().unwrap();
    let mut controls = after.suffix.controls().to_vec();
    *controls.last_mut().unwrap() = occupied.prepared().clone().with_signature([42; 64]);
    let replaced = fixture.row(4, None, controls);
    assert!(
        reduce(
            &state(&after),
            &state(&replaced),
            16,
            StorageHeldStepV1::AlreadySettledRecoveryProofRecorded
        )
        .is_err()
    );

    let original_query = fixture.query(81);
    let different_query = fixture.query(82);
    let wrong_response = fixture
        .recovery(&before, &different_query, 13, false)
        .with_signature([7; 64]);
    let mut controls = before.suffix.controls().to_vec();
    controls.extend([original_query, wrong_response]);
    let mismatch = StorageHeldIssuanceRowV2 {
        original: before.original.clone(),
        suffix: NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            4,
            fixture.scope.flight,
            None,
            controls,
        )
        .unwrap(),
    };
    assert!(mismatch.to_canonical_bytes().is_err());
}

#[test]
fn cold_after_alone_is_not_historical_provenance_and_reducer_rejects_forgery() {
    let fixture = Fixture::new(1);
    let root = fixture.disposition();
    let old = fixture.row(
        3,
        Some(fixture.normal_prepared(&root, 7)),
        root.suffix.controls().to_vec(),
    );
    let query = fixture.query(81);
    let mut controls = old.suffix.controls().to_vec();
    controls.push(query.clone());
    let mut direct_controls = root.suffix.controls().to_vec();
    direct_controls.push(query.clone());
    let direct = fixture.row(
        3,
        Some(fixture.recovery(&root, &query, 7, false)),
        direct_controls,
    );
    reduce(
        &state(&root),
        &state(&direct),
        7,
        StorageHeldStepV1::ColdCarrierPrepared,
    )
    .unwrap();
    let next = fixture.row(
        3,
        Some(fixture.recovery(&old, &query, 10, false)),
        controls.clone(),
    );
    assert_eq!(
        remaining_capacity_profile(&state(&old))
            .unwrap()
            .remaining_transactions,
        3
    );
    assert_eq!(
        remaining_capacity_profile(&state(&next))
            .unwrap()
            .remaining_transactions,
        2
    );
    reduce(
        &state(&old),
        &state(&next),
        10,
        StorageHeldStepV1::ColdCarrierPrepared,
    )
    .unwrap();
    let forged = fixture.row(3, Some(fixture.recovery(&old, &query, 10, true)), controls);
    // Canonical historical DATA cannot recover the deliberately removed unsigned6.
    assert!(
        StorageHeldIssuanceRowV2::from_canonical_bytes(&forged.to_canonical_bytes().unwrap())
            .is_ok()
    );
    assert!(
        reduce(
            &state(&old),
            &state(&forged),
            10,
            StorageHeldStepV1::ColdCarrierPrepared
        )
        .is_err()
    );
    let mut controls = next.suffix.controls().to_vec();
    controls.push(
        next.suffix
            .prepared()
            .unwrap()
            .clone()
            .with_signature([7; 64]),
    );
    let terminal = fixture.row(4, None, controls);
    assert_eq!(
        remaining_capacity_profile(&state(&terminal))
            .unwrap()
            .remaining_transactions,
        1
    );
    reduce(
        &state(&next),
        &state(&terminal),
        13,
        StorageHeldStepV1::SettlementStored,
    )
    .unwrap();
    assert!(
        reduce(
            &state(&terminal),
            &state(&terminal),
            16,
            StorageHeldStepV1::AlreadySettledRecoveryProofRecorded
        )
        .is_err()
    );
}

#[test]
fn retirement_preserves_all_archives_and_never_recycles_identity() {
    let fixture = Fixture::new(1);
    let before = fixture.r4(&fixture.settled(), 13);
    let after = StorageHeldIssuanceRowV2::new(
        before.original.request.clone(),
        before.original.acceptance.clone(),
        Some((d(91), d(92))),
        NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            5,
            fixture.scope.flight,
            None,
            before.suffix.controls().to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    reduce(
        &state(&before),
        &state(&after),
        16,
        StorageHeldStepV1::RetirementRecorded,
    )
    .unwrap();
    assert_eq!(before.suffix.controls(), after.suffix.controls());
    assert!(
        reduce(
            &state(&after),
            &state(&before),
            19,
            StorageHeldStepV1::RetirementRecorded
        )
        .is_err()
    );
    assert!(
        reduce(
            &state(&after),
            &state(&fixture.initial()),
            19,
            StorageHeldStepV1::InterestRecorded
        )
        .is_err()
    );
    assert_eq!(
        remaining_capacity_profile(&state(&after))
            .unwrap()
            .remaining_transactions,
        0
    );
}

#[test]
fn capacity_covers_eight_writes_all_other_rows_and_actual_append_framing() {
    let fixture = Fixture::new(1);
    let initial = fixture.initial();
    let profile = remaining_capacity_profile(&state(&initial)).unwrap();
    assert_eq!(1 + profile.remaining_transactions, 8);
    assert_eq!(
        super::super::super::journal_limits().maximum_transactions,
        1024 * 2
    );
    let settled = fixture.settled();
    assert_eq!(
        remaining_capacity_profile(&state(&settled))
            .unwrap()
            .remaining_transactions,
        2
    );
    let recovered = fixture.r4(&settled, 13);
    assert_eq!(
        remaining_capacity_profile(&state(&recovered))
            .unwrap()
            .remaining_transactions,
        1
    );
    let other = Fixture::new(3).initial();
    let other_profile = remaining_capacity_profile(&state(&other)).unwrap();
    let mut all = state(&initial);
    all.extend(state(&other));
    let sum = remaining_capacity_profile(&all).unwrap();
    assert_eq!(sum.remaining_transactions, 14);
    assert_eq!(
        sum.remaining_append_bytes,
        profile.remaining_append_bytes + other_profile.remaining_append_bytes
    );
    assert_eq!(
        sum.peak_materialized_bytes,
        profile.peak_materialized_bytes + other_profile.peak_materialized_bytes
    );
    let bytes = initial.to_canonical_bytes().unwrap();
    let actual =
        aos_sandbox::journal::encoded_transaction_append_bytes(&initial.transaction().unwrap())
            .unwrap();
    // Independent actual Journal framing: BEGIN72+4, record72+7+key48+value,
    // COMMIT72+36. No record-only byte count substitutes for this append.
    assert_eq!(
        actual,
        (72 + 4 + 72 + 7 + 48 + bytes.len() + 72 + 36) as u64
    );
    assert!(profile.remaining_append_bytes >= actual * 7);
    let legacy = &Fixture::new(5).original;
    all.insert(legacy.key(), legacy.encode().unwrap());
    assert_eq!(
        remaining_capacity_profile(&all)
            .unwrap()
            .remaining_transactions,
        15
    );
}
